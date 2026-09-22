"""``go_net_http``: this project's first Go stack (category 4 pilot,
``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §9.4/§9.5, Twitch pick;
``CC-LAB-0090``/``FR-LAB-64``).

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
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Exactly one entry in this Phase A dispatch -- see the module docstring.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("webhook_signature", "webhook_signature_verification"): _ModuleSet(
        "read_webhook_signature", "webhook_signature_verification", "render_only"
    ),
}

#: Per-route static context this Phase A emitter needs beyond the
#: verdict-relevant Cell IR -- same render-only-information separation
#: rationale as every other stack's own per-route params table.
_ROUTE_PARAMS: dict[str, dict[str, Any]] = {
    "/webhooks/eventsub": {},
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

        body = _indent_block(
            "\n".join((source_result.code, *transform_code_blocks, sink_result.code)),
            "\t",
        )
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        go_source = (
            "package main\n"
            "\n"
            f"// Generated by fuzzlab.labgen.emitters.go_net_http for cell {cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {composition}\n"
            "\n"
            "import (\n"
            '\t"crypto/hmac"\n'
            '\t"crypto/sha256"\n'
            '\t"encoding/hex"\n'
            '\t"io"\n'
            '\t"net/http"\n'
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
