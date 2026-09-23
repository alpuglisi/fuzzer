"""``go_net_http``: this project's first Go stack (category 4 pilot,
``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §9.4/§9.5, Twitch pick;
``CC-LAB-0170``/``FR-LAB-76``).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Go's standard-library
``net/http`` (no third-party router/framework — matching Twitch's own
documented "Go-centric microservices, new API edge" architecture, per
``docs/research/site-architecture-survey.md`` Category 4 and
``docs/research/site-architecture-survey-functionality-twitch.md``) by
assembling :mod:`fuzzlab.labgen.emitters.go_net_http.modules` fragments per
cell, following ``node_express``'s module-composition shape.

**Phase A scope, stated plainly.** Exactly one shape:
``("webhook_signature", "webhook_signature_verification")`` — an
EventSub-webhook-receiver-shaped handler that reads a request body plus a
digest header and either compares the two HMAC-SHA256 digests with Go's
``==`` (vulnerable, CWE-347, data-dependent-time comparison) or
``crypto/hmac.Equal`` (secure, constant-time) — the simplest illustrative
cell for this stack's first live-boot proof, matching every other stack's
own Phase-A "exactly one shape" scope. CWE-918 (SSRF) and CWE-862 (GraphQL
field authorization, on the sibling Netflix/Java pick) stay deferred to
Phase B, per this pilot's own research note.

**Phase B, first increment (``CC-LAB-0172``/``FR-LAB-78``): a second
shape**, ``("ssrf", "server_side_http_fetch")`` — a clip-thumbnail-fetch
proxy handler that server-side-fetches a caller-supplied URL either with
no validation at all (vulnerable, CWE-918, ``unchecked_url_fetch``) or
after rejecting any scheme but ``https`` and rejecting a resolved IP that
is loopback/private/link-local (secure, ``scheme_and_resolved_ip_
allowlist`` -- closes the DNS-rebinding gap a hostname-string-only
allowlist would leave open). **A deliberate module-composition divergence
from the webhook-signature shape, decided during implementation:** the
vulnerable/secure difference here lives entirely in *which sink module
renders* (the validation-then-fetch logic is one inseparable operation,
not a value transform composed before a shared downstream sink), so this
shape's single manifest op names a **sink** directly rather than a
transform -- ``_ModuleSet.sink is None`` is this module's signal for that
convention; see :meth:`GoEmitter.render`'s own comment at the branch point.
Each shape also declares its own Go ``import`` list now (the fixed,
webhook-only import block became per-shape once a second shape needed a
different set).

**Multi-file output, like every other routed emitter.** Per this project's
routed-emitter convention (``node_express``, ``ruby_rails``), a ``route``-
category *accumulator* module (``net/http.ServeMux`` registration lines)
is fed by one fragment per cell, sorted by cell ID at render time — never
by append/iteration order, so the whole-lab regeneration determinism gate
stays meaningful. :meth:`render` therefore returns only the per-cell
handler file for a cell; :meth:`render_route_accumulator` builds the
accumulator separately, over the whole supported cell set at once.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS, render_route_line

__all__ = ["GoEmitter"]


class _ModuleSet(NamedTuple):
    source: str
    #: The fixed sink module name for shapes where the manifest's
    #: transform ops modify a *value* the sink then renders unconditionally
    #: (the webhook-signature shape). ``None`` signals the other
    #: convention this stack now has two of: the manifest's one op names a
    #: **sink** module directly (the SSRF shape) -- see
    #: :meth:`GoEmitter.render`.
    sink: str | None
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("webhook_signature", "webhook_signature_verification"): _ModuleSet(
        "read_webhook_signature", "webhook_signature_verification", "render_only"
    ),
    ("ssrf", "server_side_http_fetch"): _ModuleSet("read_url_query_param", None, "render_only"),
    ("access_control", "db_row_by_id_lookup"): _ModuleSet(
        "read_channel_id_and_broadcaster_header", "object_lookup_authorization_check", "render_only"
    ),
    ("jwt_algorithm_confusion", "jwt_signature_verification"): _ModuleSet(
        "read_authorization_bearer_token", "jwt_claims_response", "render_only"
    ),
    # A third convention (neither 1 nor 2 above): the manifest's one op
    # names a sink directly (like convention 2), but the source itself has
    # no tainted input to read at all -- see `NoOpTokenRequestSource`'s own
    # docstring in modules.py for why this genuinely differs from the SSRF
    # shape's own convention 2 (which still has a real source).
    ("weak_token_entropy", "session_token_generation"): _ModuleSet(
        "no_op_token_request", None, "render_only"
    ),
    # Convention 2 again (like SSRF): the manifest's one op names a sink
    # directly (`unfiltered_object_assign`/`typed_schema_allowlist`) --
    # the vulnerable/secure difference is one inseparable
    # unmarshal-onto-the-live-record-vs-unmarshal-into-a-narrow-DTO
    # operation, not a value rewrite feeding a shared sink, same reasoning
    # as `UncheckedUrlFetchSink`/`SchemeAndResolvedIpAllowlistSink`'s own
    # docstrings (CC-LAB-0182).
    ("mass_assignment", "orm_entity_bulk_assign"): _ModuleSet(
        "read_channel_profile_body", None, "render_only"
    ),
    # Convention 2 again (like SSRF/mass-assignment): the manifest's one op
    # names a sink directly -- the vulnerable/secure difference is one
    # inseparable write-and-serve operation (which filename/content-type to
    # trust when writing to and serving from a web-served directory), not a
    # value rewrite feeding a shared sink. This stack's first
    # `unrestricted_file_upload`/`fs_web_root_write` instance on any stack
    # in this project (`CC-LAB-0186`).
    ("unrestricted_file_upload", "fs_web_root_write"): _ModuleSet(
        "read_uploaded_file", None, "render_only"
    ),
}

#: Per-module (source/transform-op/sink name) -> the extra Go standard-
#: library packages that module's own rendered code references, beyond
#: ``net/http`` (always included -- every handler signature needs it).
#: Keyed per-module rather than per-shape (``CC-LAB-0172``'s own fix,
#: found while assembling the SSRF shape's vulnerable twin: that twin's
#: sink, ``unchecked_url_fetch``, does not use ``net``/``net/url`` at all,
#: so a shape-level fixed import list -- covering the union every sink a
#: shape *could* pick needs -- fails `go build`/`gofmt` with an "imported
#: and not used" error the moment a shape has two sinks with different
#: import needs). :meth:`GoEmitter.render` unions exactly the modules a
#: given cell actually renders with, never a shape-wide superset.
_MODULE_IMPORTS: dict[str, tuple[str, ...]] = {
    "read_webhook_signature": ("crypto/hmac", "crypto/sha256", "encoding/hex", "io"),
    "webhook_signature_verification": (),
    "read_url_query_param": (),
    "unchecked_url_fetch": ("io", "time"),
    "scheme_and_resolved_ip_allowlist": ("io", "net", "net/url", "time"),
    "read_channel_id_and_broadcaster_header": (),
    "no_ownership_check": (),
    "identity_match_before_fetch": (),
    "object_lookup_authorization_check": ("io",),
    "read_authorization_bearer_token": (
        "crypto/hmac", "crypto/sha256", "encoding/base64", "encoding/json", "strings",
    ),
    "jwt_alg_none_default": (),
    "jwt_none_alg_opt_in": (),
    "jwt_claims_response": ("encoding/json", "io"),
    "no_op_token_request": (),
    "predictable_token_source": ("fmt", "io", "time"),
    "csprng_token": ("crypto/rand", "encoding/hex", "io"),
    "read_channel_profile_body": ("io",),
    "unfiltered_object_assign": ("encoding/json",),
    "typed_schema_allowlist": ("encoding/json",),
    "read_uploaded_file": ("io",),
    "no_extension_check": ("mime", "os", "path/filepath"),
    "extension_allowlist_mime_check": ("os", "path/filepath", "strings"),
}

#: Per-route static context this Phase A emitter needs beyond the
#: verdict-relevant Cell IR -- same render-only-information separation
#: rationale as every other stack's own per-route params table.
_ROUTE_PARAMS: dict[str, dict[str, Any]] = {
    "/webhooks/eventsub": {},
    "/api/clips/thumbnail": {"var_name": "targetUrl", "param_name": "url"},
    "/channels/analytics": {"param_name": "channel_id"},
    "/channels/settings": {},
    "/sessions/refresh": {},
    "/channels/profile": {},
    # CC-LAB-0183: second instance of the access_control/db_row_by_id_lookup
    # shape (CC-LAB-0178's own /channels/analytics), zero new generator
    # code -- just this route-profile entry.
    "/channels/subscribers": {"param_name": "channel_id"},
    # CC-LAB-0185: second instance of the ssrf/server_side_http_fetch shape
    # (CC-LAB-0172's own /api/clips/thumbnail), zero new generator code --
    # just this route-profile entry.
    "/clips/download": {"var_name": "sourceUrl", "param_name": "source_url"},
    # CC-LAB-0186: this stack's first unrestricted_file_upload/
    # fs_web_root_write instance -- no per-route var_name/param_name needed
    # (ReadUploadedFileSource publishes its own default identifiers),
    # matching /webhooks/eventsub's/`/channels/settings`'s own empty entries.
    "/channels/emotes/upload": {},
}


class GoEmitter(Emitter):
    """Renders a :class:`Cell` to a single Go handler file (plus a shared
    route accumulator) via module composition, Phase A shape only.

    ``render()`` never falls back to a default sink/transform/route-profile
    silently, matching every other stack's "fail loud on an authoring gap"
    discipline.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for go_net_http "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _ROUTE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: go_net_http has no route profile for route {cell.route.path!r} "
                f"-- known routes: {sorted(_ROUTE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_ROUTE_PARAMS[cell.route.path])
        ctx["handler_name"] = f"handle{_pascal_case(cell.cell_id)}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["naive_string_compare"]

        if modules.sink is not None:
            # Convention 1 (webhook-signature): every op is a transform
            # that modifies a value the fixed sink then renders.
            transform_code_blocks: list[str] = []
            for op in applied_ops:
                if op not in TRANSFORMS:
                    raise ValueError(
                        f"{cell.cell_id}: go_net_http has no transform module for op {op!r} "
                        f"-- known ops: {sorted(TRANSFORMS)}"
                    )
                transform_result = TRANSFORMS[op].render(ctx)
                ctx = transform_result.context
                transform_code_blocks.append(transform_result.code)
            sink_result = SINKS[modules.sink].render(ctx)
            body_parts = (source_result.code, *transform_code_blocks, sink_result.code)
            sink_name_for_composition = modules.sink
        else:
            # Convention 2 (SSRF, CC-LAB-0172): the manifest's one op names
            # a SINK module directly -- there is no separate transform
            # stage, since the vulnerable/secure difference here is one
            # inseparable validate-then-fetch operation, not a value
            # rewrite feeding a shared sink. See the module docstring.
            if len(applied_ops) != 1:
                raise ValueError(
                    f"{cell.cell_id}: go_net_http's sink-selecting shapes take exactly one op "
                    f"(the sink module name), got {applied_ops!r}"
                )
            (sink_op,) = applied_ops
            if sink_op not in SINKS:
                raise ValueError(
                    f"{cell.cell_id}: go_net_http has no sink module for op {sink_op!r} "
                    f"-- known sinks: {sorted(SINKS)}"
                )
            sink_result = SINKS[sink_op].render(ctx)
            body_parts = (source_result.code, sink_result.code)
            sink_name_for_composition = sink_op

        body = _indent_block("\n".join(body_parts), "\t")
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        # For convention 2 (sink is None), `applied_ops` already names the
        # sink module -- adding it again here would render a redundant
        # "... -> unchecked_url_fetch -> unchecked_url_fetch -> ...".
        composition_sink_part = (sink_name_for_composition,) if modules.sink is not None else ()
        composition = " -> ".join((modules.source, *applied_ops, *composition_sink_part, modules.complexity))

        used_module_names = {modules.source, sink_name_for_composition, *applied_ops}
        extra_imports: set[str] = set()
        for name in used_module_names:
            extra_imports.update(_MODULE_IMPORTS.get(name, ()))
        all_imports = sorted({"net/http", *extra_imports})
        import_lines = "".join(f'\t"{pkg}"\n' for pkg in all_imports)
        go_source = (
            "package main\n"
            "\n"
            f"// Generated by fuzzlab.labgen.emitters.go_net_http for cell {cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {composition}\n"
            "\n"
            "import (\n"
            f"{import_lines}"
            ")\n"
            "\n"
            f"{complexity_result.code}"
        )
        path = f"{cell.cell_id.lower().replace('-', '_')}.go"
        return (EmittedFile(path=path, content=go_source.encode("utf-8"), role="controller"),)

    def render_route_accumulator(self, cells: list[Cell]) -> EmittedFile:
        """Build ``routes_generated.go`` -- the ``route``-category
        accumulator (cardinality ``accumulator``) -- fed by one fragment
        per **supported** cell, sorted by ``cell_id`` at render time.

        Deliberately not part of :meth:`render` (see the module docstring):
        the accumulator's real cardinality is "one file, fed by every cell,"
        which a single ``render(cell)`` call cannot express without either
        re-emitting a growing file on every single-cell call (breaking the
        generic Tier-3 harness's "no two cells emit the same path"
        invariant) or silently overwriting it. Two calls with an equal
        ``cells`` sequence (as a set -- order of the input iterable does not
        matter, only sorted ``cell_id`` does) produce byte-identical output.
        """
        supported = [c for c in cells if self.supports(c.vuln_class, c.sink_context)]
        by_id = sorted(supported, key=lambda c: c.cell_id)
        route_lines = [
            render_route_line(
                method=c.route.method,
                # Cell-ID-derived, not `c.route.path` directly: a vulnerable/
                # secure twin pair shares one `route.path` (both illustrate
                # the same conceptual endpoint), so registering both at the
                # literal manifest path would double-register the same
                # `net/http.ServeMux` pattern. Matches `node_express`'s own
                # `render_route_accumulator` convention
                # (`/generated/{cell_id.lower()}`) exactly, for the same
                # reason.
                path=f"/generated/{c.cell_id.lower()}",
                handler_name=f"handle{_pascal_case(c.cell_id)}",
            )
            for c in by_id
        ]
        go_source = (
            "package main\n"
            "\n"
            "// Generated by fuzzlab.labgen.emitters.go_net_http -- route accumulator.\n"
            "// Route lines below are sorted by cell ID at render time, never by\n"
            "// append/iteration order, so adding one cell can never reshuffle this\n"
            "// file (the whole-lab regeneration determinism gate).\n"
            "\n"
            'import "net/http"\n'
            "\n"
            "func registerRoutes(mux *http.ServeMux) {\n"
            f"{''.join(route_lines)}"
            "}\n"
        )
        return EmittedFile(path="routes_generated.go", content=go_source.encode("utf-8"), role="route")


def _pascal_case(cell_id: str) -> str:
    """``LABGEN-GO-0001`` -> ``LabgenGo0001`` -- a valid Go identifier
    fragment derived deterministically from the cell ID."""
    return "".join(part.capitalize() for part in cell_id.replace("_", "-").split("-"))


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free, same convention as every other stack's own
    ``_indent_block``."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
