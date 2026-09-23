"""``spring_boot``: the fourth emitter, category 3's Atlassian pick
(`CC-LAB-0130`, TrackerNest).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Java/Spring Boot by
assembling :mod:`fuzzlab.labgen.emitters.spring_boot.modules` fragments per
cell -- the same module-composition architecture
:mod:`fuzzlab.labgen.emitters.python_fastapi` uses, reimplemented
independently for this stack (``docs/LAB_IMPLEMENTATION_PLAN.md`` Phase 3's
"no stack's emitter package imports another's" rule).

**Scope, stated plainly (one cell only, per `CC-LAB-0130`'s pre-change
review).** This emitter supports exactly one shape as of this entry:
``(vuln_class="ssti", sink_context.family="template_render")``, TrackerNest's
``/wiki/pages/render`` cell (see
``docs/research/category3-saas-functionality-and-cwe-research.md`` sec 6b).
The XXE and insecure-deserialization cells for the same app are deliberately
deferred to a follow-on entry, not silently unfinished -- see
``docs/components/01-target-lab/change-control.md``'s `CC-LAB-0130` "Out of
scope" section.

**No route accumulator, unlike `php_laravel`/`node_express`.** Spring Boot's
own classpath component scan discovers every ``@RestController`` under
``com.fuzzlab.trackernest`` at boot time -- :meth:`SpringBootEmitter.render`
therefore returns exactly one file per cell (its generated controller class)
and there is no second, whole-manifest accumulation step a caller must also
run, the same shape :mod:`fuzzlab.labgen.emitters.python_fastapi` already
established for this project (its own static package-discovery scaffold
replacing a routes-accumulator file).

**A fourth shape, ported in (`CC-LAB-0173`, the §9.2a Java/Spring Boot
consolidation).** ``(vuln_class="insecure_deserialization",
sink_context.family="object_deserialization")`` now has **two** real
mechanisms behind it: TrackerNest's own Java-native
``ObjectInputStream.readObject()`` pair (``function_executing_deserialize``/
``handler_registry_lookup``, `CC-LAB-0132`) and category 4's ported
Jackson-polymorphic-typing pair
(``jackson_default_typing_deserialize``/``jackson_typed_allowlist_deserialize``,
originally `CC-LAB-0171` on `java_spring_boot`, retired). These need
genuinely different **source** modules for the same shape tuple
(``request_stream`` publishes the raw ``HttpServletRequest`` itself;
``jackson_body`` reads the body into a ``byte[]``) -- see
:data:`_SOURCE_OVERRIDE_BY_OP` for how :meth:`render` picks between them.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SINKS, SOURCES


class _ModuleSet(NamedTuple):
    source: str
    complexity: str


#: (vuln_class, sink_context.family) -> which source/complexity modules
#: render this shape. The sink module is selected separately, by
#: `cell.transform.ops`'s one op (see `modules.py`'s own docstring for why).
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("ssti", "template_render"): _ModuleSet("query_param", "single_handler"),
    ("xxe", "xml_parse_input"): _ModuleSet("raw_body", "single_handler"),
    ("insecure_deserialization", "object_deserialization"): _ModuleSet("request_stream", "single_handler"),
    ("spel_injection", "spel_expression_evaluate"): _ModuleSet("query_param", "single_handler"),
    # CC-LAB-0187: Netflix's fourth real page, this stack's first
    # access_control/IDOR instance -- reuses lab/safety_matrix.yaml's
    # existing db_row_by_id_lookup sink family and no_ownership_check/
    # identity_match_before_fetch ops (CC-LAB-0063), already instantiated on
    # go_net_http (CC-LAB-0178). No new safety-matrix entry needed.
    ("access_control", "db_row_by_id_lookup"): _ModuleSet(
        "read_account_id_and_caller_header", "single_handler"
    ),
    # CC-LAB-0188: Netflix's fifth real page, this stack's first
    # price_integrity_bypass instance -- reuses lab/safety_matrix.yaml's
    # existing payment_charge_amount sink family and client_trusted_amount/
    # server_recomputed_amount ops (CC-LAB-0063), already instantiated on
    # php_laravel (CC-LAB-0212). No new safety-matrix entry needed.
    ("price_integrity_bypass", "payment_charge_amount"): _ModuleSet(
        "read_plan_change_request", "single_handler"
    ),
    # CC-LAB-0191: Netflix's sixth real page, this stack's first
    # unrestricted_file_upload instance -- reuses lab/safety_matrix.yaml's
    # existing fs_web_root_write sink family and no_extension_check/
    # extension_allowlist_mime_check ops (CC-LAB-0063), already
    # instantiated on go_net_http (CC-LAB-0186). No new safety-matrix
    # entry needed. Uses "single_handler_binary", not "single_handler" --
    # this shape's own sink must serve the uploaded file's real bytes back
    # byte-for-byte (see SingleHandlerBinaryComplexity's own docstring).
    ("unrestricted_file_upload", "fs_web_root_write"): _ModuleSet(
        "read_uploaded_avatar_file", "single_handler_binary"
    ),
    # CC-LAB-0192: Netflix's seventh real page, this stack's first
    # mass_assignment instance -- reuses lab/safety_matrix.yaml's existing
    # orm_entity_bulk_assign sink family and unfiltered_object_assign/
    # typed_schema_allowlist ops (CC-LAB-0063), already instantiated on
    # php_current/ruby_rails/php_laravel/go_net_http (CC-LAB-0182). No new
    # safety-matrix entry needed. Reuses the pre-existing raw_body source
    # verbatim (like the XXE shape) -- this shape's own point is that the
    # ENTIRE body reaches the sink unfiltered, which raw_body already
    # publishes as a whole UTF-8 String, so no new source module is
    # needed.
    ("mass_assignment", "orm_entity_bulk_assign"): _ModuleSet("raw_body", "single_handler"),
    # CC-LAB-0193: Netflix's eighth real page, this stack's first
    # jwt_algorithm_confusion instance -- reuses lab/safety_matrix.yaml's
    # existing jwt_signature_verification sink family and
    # jwt_alg_none_default/jwt_none_alg_opt_in ops (CC-LAB-0063), already
    # instantiated on go_net_http (CC-LAB-0180). No new safety-matrix
    # entry needed.
    ("jwt_algorithm_confusion", "jwt_signature_verification"): _ModuleSet(
        "read_authorization_bearer_token", "single_handler"
    ),
}

#: Per-route static render context, the same "render-only information, not
#: verdict-relevant" split every other stack's emitter uses.
_PAGE_PARAMS: dict[str, dict[str, Any]] = {
    "/wiki/pages/render": {"var_name": "macroExpr", "param_name": "macroExpr"},
    "/issues/import": {"var_name": "xmlBody"},
    "/integrations/webhook-payload": {"var_name": "request"},
    "/api/playback/resume": {},
    "/api/hotels/search-sort": {"var_name": "sortExpr", "param_name": "sortBy"},
    "/api/content/import": {"var_name": "contentFeedXml"},
    # CC-LAB-0184: Netflix's third real page, a second insecure_deserialization
    # instance reusing LABGEN-JV-0001/0002's own jackson_body/jackson_default_
    # typing_deserialize/jackson_typed_allowlist_deserialize modules verbatim
    # (via `_SOURCE_OVERRIDE_BY_OP`, unchanged) -- no var_name/param_name
    # needed, matching "/api/playback/resume"'s own whole-body-JSON `{}`.
    "/api/profiles/switch": {},
    # CC-LAB-0187: Netflix's fourth real page, an account-billing-details
    # lookup keyed by an attacker-visible account_id query param -- this
    # stack's first access_control/IDOR page.
    "/api/account/billing": {"param_name": "account_id"},
    # CC-LAB-0188: Netflix's fifth real page, a subscription plan-upgrade/
    # downgrade endpoint -- this stack's first price_integrity_bypass page.
    # `plan_prices` is the secure twin's own fixed, server-owned rate table
    # (the vulnerable twin never reads it, its op is client_trusted_amount).
    "/api/subscription/change-plan": {
        "plan_prices": (
            ("basic", "6.99"),
            ("standard", "15.49"),
            ("premium", "22.99"),
        ),
    },
    # CC-LAB-0191: Netflix's sixth real page, a per-profile avatar-image
    # upload endpoint -- this stack's first unrestricted_file_upload page.
    # No var_name/param_name needed: the tainted material is the multipart
    # "file" part itself, read directly off the raw request by
    # ReadUploadedAvatarFileSource, not a query param/header/JSON field.
    "/api/profiles/avatar": {},
    # CC-LAB-0192: Netflix's seventh real page, an account-settings-update
    # endpoint -- this stack's first mass_assignment page. `var_name` is
    # the raw_body source's own Java local variable name for the whole
    # request body String; no param_name needed, the tainted material is
    # the entire JSON body, not a single named field.
    "/api/account/settings": {"var_name": "accountSettingsBody"},
    # CC-LAB-0193: Netflix's eighth real page, a viewing-preferences lookup
    # gated by a Bearer JWT in the Authorization header -- this stack's
    # first jwt_algorithm_confusion page. No var_name/param_name needed:
    # the tainted material is the Authorization header itself, read
    # directly by ReadAuthorizationBearerTokenSource.
    "/api/account/preferences": {},
}

#: Per-op source override (`CC-LAB-0173`) -- checked *after* the shape-level
#: default source (`_MODULE_SET_BY_SHAPE[...].source`) is looked up: if
#: `cell.transform.ops[0]` (the op that also selects the sink, per this
#: package's own convention) names an entry here, that source renders
#: instead of the shape's default. Only the two ported Jackson ops are
#: present here; every pre-existing op/shape keeps using its shape-level
#: default untouched. **Known narrowing (stated, not silently assumed
#: away):** this overrides only the *source* -- `_ModuleSet.complexity`
#: stays shape-level/fixed, which is sufficient today (every op for every
#: shape this emitter supports uses `single_handler`) but would need
#: widening (e.g. to a `(vuln_class, sink_context.family, op)`-keyed
#: discriminator) if a future op needed a different complexity module for
#: an already-supported shape, or if this shape needed a third distinct
#: source.
_SOURCE_OVERRIDE_BY_OP: dict[str, str] = {
    "jackson_default_typing_deserialize": "jackson_body",
    "jackson_typed_allowlist_deserialize": "jackson_body",
}

_CLASS_NAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9]+")

#: Spring's per-HTTP-method mapping annotations (`CC-LAB-0131`: the first
#: entry to need anything but GET -- the XXE cell's `/issues/import` is a
#: POST).
_MAPPING_ANNOTATION_BY_METHOD: dict[str, str] = {
    "GET": "GetMapping",
    "POST": "PostMapping",
}


def _class_name_for(cell_id: str) -> str:
    """A valid, deterministic Java class identifier from a cell id (e.g.
    ``"LABGEN-SSTI-0001"`` -> ``"LabgenSsti0001Controller"``) -- title-cased
    per ``-``/``_``-delimited segment, matching this project's general
    "derive, never hand-maintain a second id" discipline."""
    parts = [p for p in _CLASS_NAME_SANITIZE_RE.split(cell_id) if p]
    return "".join(p[:1].upper() + p[1:].lower() for p in parts) + "Controller"


class SpringBootEmitter(Emitter):
    """Renders a :class:`Cell` to one Spring Boot ``@RestController`` class
    via module composition. Mirrors ``PythonFastapiEmitter``'s fail-loud
    discipline: an unsupported shape or an unknown route/op raises rather
    than guessing at a default.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for spring_boot "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _PAGE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: spring_boot has no route profile for {cell.route.path!r} "
                f"-- known routes: {sorted(_PAGE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_PAGE_PARAMS[cell.route.path])
        class_name = _class_name_for(cell.cell_id)
        ctx["class_name"] = class_name
        ctx["route_path"] = cell.route.path
        ctx["handler_name"] = f"handle_{cell.cell_id.lower().replace('-', '_')}"
        method = cell.route.method.upper()
        if method not in _MAPPING_ANNOTATION_BY_METHOD:
            raise ValueError(
                f"{cell.cell_id}: spring_boot has no mapping annotation for HTTP method "
                f"{method!r} -- known methods: {sorted(_MAPPING_ANNOTATION_BY_METHOD)}"
            )
        ctx["mapping_annotation"] = _MAPPING_ANNOTATION_BY_METHOD[method]

        ops = list(cell.transform.ops)
        if len(ops) != 1 or ops[0] not in SINKS:
            raise ValueError(
                f"{cell.cell_id}: spring_boot's ssti/template_render shape requires exactly one "
                f"transform op naming which sink module to render (see modules.py's docstring for "
                f"why the op selects the sink here) -- got {ops!r}, known sinks: {sorted(SINKS)}"
            )

        # CC-LAB-0173: the op may also override which SOURCE renders, for a
        # shape whose different ops need genuinely different source
        # material (see _SOURCE_OVERRIDE_BY_OP's own docstring).
        source_name = _SOURCE_OVERRIDE_BY_OP.get(ops[0], modules.source)
        source_result = SOURCES[source_name].render(ctx)
        ctx = source_result.context

        sink_result = SINKS[ops[0]].render(ctx)

        body = source_result.code + sink_result.code
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        java_source = (
            "// Generated by fuzzlab.labgen.emitters.spring_boot for cell "
            f"{cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {source_name} -> {ops[0]} -> {modules.complexity}\n"
            "package com.fuzzlab.trackernest.generated;\n"
            "\n"
            f"{complexity_result.code}"
        )
        path = f"src/main/java/com/fuzzlab/trackernest/generated/{class_name}.java"
        return (EmittedFile(path=path, content=java_source.encode("utf-8"), role="controller"),)
