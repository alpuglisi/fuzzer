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

from .app_site import APP_REGISTRY, nav_html_for
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
    # CC-LAB-0194: Netflix's ninth real page, this stack's first ssrf
    # instance -- reuses lab/safety_matrix.yaml's existing
    # server_side_http_fetch sink family and unchecked_url_fetch/
    # scheme_and_resolved_ip_allowlist ops (CC-LAB-0063), already
    # instantiated on go_net_http (CC-LAB-0172/CC-LAB-0185). No new
    # safety-matrix entry needed. Reuses the pre-existing query_param
    # source verbatim (already used by ssti/spel_injection) -- the same
    # query-param-carried-URL contract go_net_http's own
    # read_url_query_param source established, so a generic
    # Candidate(location="query") probe drives this shape identically to
    # go_net_http's SSRF cells (zero new sender/candidate plumbing needed
    # for SsrfInBandMarkerStrategy/SsrfOobStrategy to generalize here).
    ("ssrf", "server_side_http_fetch"): _ModuleSet("query_param", "single_handler"),
    # CC-LAB-0195: Netflix's tenth real page, this stack's first
    # weak_token_entropy instance -- reuses lab/safety_matrix.yaml's
    # existing session_token_generation sink family and
    # predictable_token_source/csprng_token ops (CC-LAB-0063), already
    # instantiated on go_net_http (CC-LAB-0181). No new safety-matrix
    # entry needed. Genuinely no tainted request input at all (like
    # go_net_http's own port of this shape) -- the vulnerability is
    # entirely in how the sink generates its own output, so this uses a
    # new, no-op source (NoOpTokenRequestSource) rather than any
    # pre-existing one; the manifest's one op still selects the sink
    # directly, this package's own single, uniform convention (unlike
    # go_net_http, this is not a "new, third convention" for this stack --
    # see NoOpTokenRequestSource's own docstring).
    ("weak_token_entropy", "session_token_generation"): _ModuleSet(
        "no_op_token_request", "single_handler"
    ),
}

#: Per-route static render context, the same "render-only information, not
#: verdict-relevant" split every other stack's emitter uses.
#: CC-LAB-0244: the closed vocabulary of `absent_input` declarations
#: (plan §2e), each rendered in the source region, before any sink, on both
#: twins alike. `form_when_absent` is the one value outside PA-0053's
#: literal "default or 4xx" -- accepted in round-1 review (plan §2e).
ABSENT_INPUT_KINDS: frozenset[str] = frozenset(
    {
        "form_when_absent",   # a page route: no input -> the form alone, 200
        "required_param",     # a named query param: absent/empty -> 400
        "default_value",      # a named query param: absent/empty -> a real default
        "required_header",    # a required header: absent/empty -> 401 + WWW-Authenticate
        "required_multipart", # a required multipart part: missing -> 400
        "empty_body_400",     # a whole-body source: empty -> 400
        "no_input",           # the source reads no request input at all
    }
)

_PAGE_PARAMS: dict[str, dict[str, Any]] = {
    "/wiki/pages/render": {
        "var_name": "macroExpr", "param_name": "macroExpr",
        "app": "trackernest", "classification": "page",
        "absent_input": "form_when_absent", "page_title": "Wiki page",
        "form_html": (
            '<h2>Wiki page</h2><form method="get">'
            '<p><label>Macro expression<br>'
            '<input type="text" name="macroExpr"></label></p>'
            '<p><button type="submit">Render</button></p></form>'
        ),
    },
    "/issues/import": {
        "var_name": "xmlBody", "app": "trackernest", "classification": "api",
        "absent_input": "empty_body_400",
    },
    "/integrations/webhook-payload": {
        "var_name": "request", "app": "trackernest", "classification": "api",
        "absent_input": "empty_body_400",
    },
    "/api/playback/resume": {
        "app": "reelqueue", "classification": "api", "absent_input": "empty_body_400",
    },
    "/api/hotels/search-sort": {
        "var_name": "sortExpr", "param_name": "sortBy",
        "app": "wanderfare", "classification": "api",
        "absent_input": "default_value",
        # A SpEL *string literal*, not a bare identifier (plan §2e: "a SpEL
        # string literal: 'Sort result: recommended' on both twins") -- an
        # unquoted `recommended` is an unresolvable SpEL property reference
        # and throws on both twins (confirmed live: 400, not the declared
        # 200) instead of evaluating to the sink's own concatenated string.
        "default_value_java": "'recommended'",
    },
    "/api/trips/restore": {
        "app": "wanderfare", "classification": "api", "absent_input": "empty_body_400",
    },
    "/api/content/import": {
        "var_name": "contentFeedXml", "app": "reelqueue", "classification": "api",
        "absent_input": "empty_body_400",
    },
    # CC-LAB-0184: Netflix's third real page, a second insecure_deserialization
    # instance reusing LABGEN-JV-0001/0002's own jackson_body/jackson_default_
    # typing_deserialize/jackson_typed_allowlist_deserialize modules verbatim
    # (via `_SOURCE_OVERRIDE_BY_OP`, unchanged) -- no var_name/param_name
    # needed, matching "/api/playback/resume"'s own whole-body-JSON `{}`.
    "/api/profiles/switch": {
        "app": "reelqueue", "classification": "api", "absent_input": "empty_body_400",
    },
    # CC-LAB-0187: Netflix's fourth real page, an account-billing-details
    # lookup keyed by an attacker-visible account_id query param -- this
    # stack's first access_control/IDOR page.
    "/api/account/billing": {
        "param_name": "account_id", "app": "reelqueue", "classification": "api",
        "absent_input": "required_param",
    },
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
        "app": "reelqueue", "classification": "api", "absent_input": "empty_body_400",
    },
    # CC-LAB-0191: Netflix's sixth real page, a per-profile avatar-image
    # upload endpoint -- this stack's first unrestricted_file_upload page.
    # No var_name/param_name needed: the tainted material is the multipart
    # "file" part itself, read directly off the raw request by
    # ReadUploadedAvatarFileSource, not a query param/header/JSON field.
    "/api/profiles/avatar": {
        "app": "reelqueue", "classification": "api", "absent_input": "required_multipart",
    },
    # CC-LAB-0192: Netflix's seventh real page, an account-settings-update
    # endpoint -- this stack's first mass_assignment page. `var_name` is
    # the raw_body source's own Java local variable name for the whole
    # request body String; no param_name needed, the tainted material is
    # the entire JSON body, not a single named field.
    "/api/account/settings": {
        "var_name": "accountSettingsBody", "app": "reelqueue", "classification": "api",
        "absent_input": "empty_body_400",
    },
    # CC-LAB-0193: Netflix's eighth real page, a viewing-preferences lookup
    # gated by a Bearer JWT in the Authorization header -- this stack's
    # first jwt_algorithm_confusion page. No var_name/param_name needed:
    # the tainted material is the Authorization header itself, read
    # directly by ReadAuthorizationBearerTokenSource.
    "/api/account/preferences": {
        "app": "reelqueue", "classification": "api", "absent_input": "required_header",
    },
    # CC-LAB-0194: Netflix's ninth real page, a partner-content thumbnail-
    # import endpoint (importing a thumbnail image from a partner-supplied
    # URL for newly-ingested partner content -- a real, plausible feature
    # given Netflix's own confirmed B2B content-ingestion surface,
    # /api/content/import, CC-LAB-0179) that server-side-fetches a
    # caller-supplied thumbnail_url query parameter -- this stack's first
    # ssrf page. Reuses query_param's own var_name/param_name contract
    # verbatim (the same shape ssti/spel_injection already use).
    "/api/content/thumbnail-import": {
        "var_name": "thumbnailUrl", "param_name": "thumbnail_url",
        "app": "reelqueue", "classification": "api", "absent_input": "required_param",
    },
    # CC-LAB-0195: Netflix's tenth real page, a session-refresh endpoint --
    # this stack's first weak_token_entropy page. No var_name/param_name
    # needed: there is no tainted request material at all
    # (NoOpTokenRequestSource publishes nothing), matching
    # "/api/profiles/avatar"'s own empty-dict shape for a different
    # reason.
    "/api/session/refresh": {
        "app": "reelqueue", "classification": "api", "absent_input": "no_input",
    },
    # CC-LAB-0197: Netflix's eleventh real page, a customer-support-agent
    # template-preview endpoint for personalized notification messages --
    # this stack's first ssti/template_render instance on THIS app identity
    # (TrackerNest, category 3, already has this shape at
    # /wiki/pages/render, CC-LAB-0130). Reuses query_param's own var_name/
    # param_name contract verbatim (the same shape ssrf/spel_injection
    # already use on this stack).
    "/api/support/template-preview": {
        "var_name": "previewExpr", "param_name": "expr",
        "app": "reelqueue", "classification": "api", "absent_input": "required_param",
    },
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


#: CC-LAB-0244 (FR-LAB-164, R1 -- mirrors `django`'s/`go_net_http`'s own
#: `_REAL_PAGE_CELL_IDS`): every real route's **vulnerable** cell, declared
#: explicitly (never inferred from odd/even IDs, though it happens to be
#: the odd-numbered half of each pair -- plan §1.3's manifests).
_REAL_PAGE_CELL_IDS: frozenset[str] = frozenset(
    {
        "LABGEN-SSTI-0001", "LABGEN-XXE-0001", "LABGEN-DESER-0001",
        "LABGEN-JV-0001", "LABGEN-JV-0003", "LABGEN-JV-0005", "LABGEN-JV-0007",
        "LABGEN-JV-0009", "LABGEN-JV-0011", "LABGEN-JV-0013", "LABGEN-JV-0015",
        "LABGEN-JV-0017", "LABGEN-JV-0019", "LABGEN-JV-0021",
        "LABGEN-EXP-0001", "LABGEN-EXP-0003",
    }
)

#: CC-LAB-0244: each vulnerable cell's own secure twin -- same route, the
#: other half of the pair.
_REAL_PAGE_TWIN_CELL_IDS: frozenset[str] = frozenset(
    {
        "LABGEN-SSTI-0002", "LABGEN-XXE-0002", "LABGEN-DESER-0002",
        "LABGEN-JV-0002", "LABGEN-JV-0004", "LABGEN-JV-0006", "LABGEN-JV-0008",
        "LABGEN-JV-0010", "LABGEN-JV-0012", "LABGEN-JV-0014", "LABGEN-JV-0016",
        "LABGEN-JV-0018", "LABGEN-JV-0020", "LABGEN-JV-0022",
        "LABGEN-EXP-0002", "LABGEN-EXP-0004",
    }
)


def _twin_url_for(real_url: str, cell_id: str) -> str:
    """``/wiki/pages/render`` + ``LABGEN-SSTI-0002`` ->
    ``/wiki/pages/render.labgen-ssti-0002`` -- the same suffix shape
    `django`'s/`go_net_http`'s own ``_twin_url_for`` produce."""
    return f"{real_url}.{cell_id.lower()}"


def served_url_for(cell: Cell, *, site_build: bool) -> str:
    """The URL path ``cell`` is actually served at (CC-LAB-0244, plan
    §2d) -- the one shared derivation (PA-0003/PA-0021):

    * **single-cell build** (``site_build=False``, the historical
      default): both twins keep today's behavior, served at
      ``cell.route.path`` unchanged (plan S1) -- both twins of a pair
      share one route, which is exactly why a single-cell build only ever
      renders one cell at a time.
    * **site build** (``site_build=True``): the vulnerable cell
      (:data:`_REAL_PAGE_CELL_IDS`) at its own ``route.path``; its secure
      twin (:data:`_REAL_PAGE_TWIN_CELL_IDS`) at the twin-suffixed variant.
    """
    if not site_build:
        return cell.route.path
    if cell.cell_id in _REAL_PAGE_CELL_IDS:
        return cell.route.path
    if cell.cell_id in _REAL_PAGE_TWIN_CELL_IDS:
        return _twin_url_for(cell.route.path, cell.cell_id)
    raise ValueError(
        f"{cell.cell_id}: spring_boot site build has no twin-URL classification for this "
        "cell -- every cell must be in _REAL_PAGE_CELL_IDS or _REAL_PAGE_TWIN_CELL_IDS"
    )


def _java_string_literal_escape(text: str) -> str:
    """Escapes ``text`` so it is safe to interpolate, verbatim, inside a
    double-quoted Java string literal (CC-LAB-0244's per-app site content:
    static, hand-authored strings only, never request-derived)."""
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


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

    def __init__(self, site_build: bool = False) -> None:
        """``site_build=True`` (CC-LAB-0244, plan §2d) renders every cell's
        twin at its site-mode URL (:func:`served_url_for`) instead of the
        historical single-cell ``route.path``-for-both-twins behavior,
        which stays the default so every existing single-cell caller is
        unaffected."""
        self.site_build = site_build

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
        # CC-LAB-0244 (plan §2d): the URL this cell's @-Mapping annotation
        # actually binds -- unchanged (cell.route.path) for a single-cell
        # build; the twin-suffixed variant for a secure twin in a site
        # build, so the two twins of a pair never register one ambiguous
        # Spring mapping.
        ctx["route_path"] = served_url_for(cell, site_build=self.site_build)
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

        # CC-LAB-0244 (plan §2b, S8): a `page`-classified route is selected
        # by the route profile, never by the sink module -- the same sink
        # templates also serve an `api` route unchanged (TrackerNest's
        # `/wiki/pages/render` is a page, Netflix's
        # `/api/support/template-preview` an api, same sink family).
        complexity_name = modules.complexity
        if ctx.get("classification") == "page":
            complexity_name = "page_handler"
            app_key = ctx["app"]
            site = APP_REGISTRY[app_key]
            ctx["app_name_java"] = _java_string_literal_escape(site.name)
            ctx["app_brand_java"] = _java_string_literal_escape(site.brand)
            ctx["nav_html_java"] = _java_string_literal_escape(nav_html_for(app_key))
            ctx["page_title_java"] = _java_string_literal_escape(ctx["page_title"])
            ctx["form_html_java"] = _java_string_literal_escape(ctx["form_html"])
        complexity_result = COMPLEXITIES[complexity_name].render({**ctx, "body": body})

        java_source = (
            "// Generated by fuzzlab.labgen.emitters.spring_boot for cell "
            f"{cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {source_name} -> {ops[0]} -> {complexity_name}\n"
            "package com.fuzzlab.trackernest.generated;\n"
            "\n"
            f"{complexity_result.code}"
        )
        path = f"src/main/java/com/fuzzlab/trackernest/generated/{class_name}.java"
        return (EmittedFile(path=path, content=java_source.encode("utf-8"), role="controller"),)
