"""``node_express``: the second (Tier-A) emitter (L-P3.1, ``CR-LAB-0001``
Addendum D).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Node/Express by
assembling :mod:`fuzzlab.labgen.emitters.node_express.modules` fragments per
cell, following ``php_current``'s module-composition shape (Addendum C) --
the actual JS/Express code is new.

**Scope, stated plainly (Tier-A only):** per the pacing decision in
``docs/LAB_IMPLEMENTATION_PLAN.md`` Sec 4 ("stack 1 to full depth, stacks
2-3 to Tier-A-only depth"), this emitter supports exactly three
well-documented, value-context shapes -- ``sqli``/``sql_numeric_literal``,
``sqli``/``sql_string_literal``, ``xss``/``html_body`` -- the same three
``php_current`` proves on its real-page sample. It does **not** support
identifier/alias/connector-position SQLi or escaping-context-mismatch XSS
on this stack; those stay deferred for Node/Express.

CC-LAB-0070 adds a fourth shape, ``prototype_pollution``/
``object_property_bulk_set`` (CWE-1321) -- genuinely new to this project's
corpus and specific to the JS/Node runtime (an unguarded recursive merge
that can write onto ``Object.prototype``), grounded in the Walmart
(Node/Express BFF) functionality/CWE research (see
``docs/research/site-architecture-survey-functionality-walmart.md``).

**Multi-file output, unlike ``php_current``.** Per Addendum D, a routed,
multi-file emitter needs a ``route``-category *accumulator* module
(``app.js``'s route-registration lines) fed by one fragment per cell,
sorted by cell ID at render time -- never by append/iteration order, or the
whole-lab regeneration determinism gate fails the moment a second cell is
added. :meth:`Emitter.render` (the ABC's one per-cell entry point) therefore
returns **only** the per-cell controller file for a cell -- never a
re-rendering of the shared ``app.js`` -- so that
:func:`fuzzlab.labgen.conformance.tier3.render_whole_sample`'s existing
"two cells must not emit the same path" invariant (a generic, shared-owned
check this lane does not modify) stays meaningful for controller files.
The accumulator itself is built by the separate
:meth:`NodeExpressEmitter.render_route_accumulator` method below, over the
**whole** supported cell set at once (matching the accumulator's real
cardinality, "fed by every cell" -- a single ``render(cell)`` call
structurally cannot do this for one cell in isolation). Callers building a
full app tree call both: :meth:`render` per supported cell for the
controllers, then :meth:`render_route_accumulator` once for ``app.js``.
This is a deliberate, documented extension of the per-emitter contract
beyond the shared :class:`~fuzzlab.labgen.emitter.Emitter` ABC (which this
lane does not modify) -- flagged here for whichever lane next generalizes
Tier 3/the CLI to routed, multi-file emitters, since Laravel's own
``routes/web.php`` accumulator (L-P3.3a) will need the identical shape.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS, render_route_line

# A small, fixed helper every generated controller includes unconditionally
# (JS has no built-in equivalent of PHP's htmlspecialchars()) -- present
# identically in every generated file regardless of whether that cell's own
# transform pipeline uses it, so its presence never breaks the minimal-pair
# invariant (the diff between a vulnerable/secure twin stays confined to the
# transform region -- CR-LAB-0001 Addendum D). Named generically; naming it
# does not itself leak a vulnerability-class name (the build's name-leak
# scanner, fuzzlab.labgen.gates, is not in this lane's scope to re-run here
# but this follows the same discipline).
_ESCAPE_HTML_HELPER = (
    "function escapeHtml(value) {\n"
    "    return String(value).replace(/[&<>\"']/g, (c) => ({\n"
    "        '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;',\n"
    "    }[c]));\n"
    "}\n"
)


class _ModuleSet(NamedTuple):
    """Same shape as ``php_current``'s ``_ModuleSet``: which source/sink/
    complexity module a ``(vuln_class, sink_context.family)`` shape renders
    with. The transform is never fixed here -- it always comes from the
    cell's own ``transform`` pipeline, per op."""

    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Tier-A scope only -- any pair not listed here is declared unsupported via
#: supports().
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("sqli", "sql_numeric_literal"): _ModuleSet("get_query_param", "sql_numeric_lookup", "single_statement"),
    ("sqli", "sql_string_literal"): _ModuleSet("post_body_param", "sql_string_literal_lookup", "single_statement"),
    ("xss", "html_body"): _ModuleSet("read_stored_field", "html_body_echo", "render_only"),
    # CC-LAB-0070: prototype pollution (CWE-1321) -- a genuinely new,
    # JS/Node-runtime-specific shape, not part of the original Tier-A
    # baseline above.
    ("prototype_pollution", "object_property_bulk_set"): _ModuleSet(
        "post_body_json", "object_property_bulk_set", "render_only"
    ),
}

#: Per-route static context (table/column/param names, or the stored field
#: expression an HTML-sink cell reads) an emitter needs beyond the
#: verdict-relevant Cell IR -- same separation rationale as
#: ``php_current._PAGE_PARAMS``: table/column naming is render-only
#: information, not verdict-relevant, so it lives here rather than growing
#: the shared IR. Keyed by ``cell.route.path``, since a vulnerable cell and
#: its secure twin share one route profile.
_ROUTE_PARAMS: dict[str, dict[str, Any]] = {
    "/api/products": {"var_name": "id", "param_name": "id", "table": "products", "column": "id"},
    "/api/posts": {"var_name": "id", "param_name": "id", "table": "posts", "column": "id"},
    "/api/login": {
        "var_name": "username",
        "param_name": "username",
        "table": "users",
        "column": "username",
        "password_var": "passwordHash",
        "password_param": "password",
    },
    "/api/profile": {"var_name": "bio", "stored_expr": "currentUser.bio", "css_class": "bio"},
    # CC-LAB-0070: a BFF-style "update account/cart preferences" endpoint
    # (Walmart functionality research), deep-merging the whole request body
    # onto a live preferences object -- target_var/target_literal are this
    # shape's render-only metadata, the object_property_bulk_set transforms'
    # own analogue of the mass-assignment family's `allowed_fields`.
    "/api/preferences": {
        "var_name": "incomingPreferences",
        "target_var": "currentPreferences",
        "target_literal": "{ theme: 'light', notifications: true }",
    },
}


class NodeExpressEmitter(Emitter):
    """Renders a :class:`Cell` to a single Express controller (route
    handler) module via module composition, Tier-A shapes only.

    ``render()`` never falls back to a default sink/transform/route-profile
    silently, matching ``php_current``'s "fail loud on an authoring gap"
    discipline.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for node_express "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _ROUTE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: node_express has no route profile for route {cell.route.path!r} "
                f"-- known routes: {sorted(_ROUTE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_ROUTE_PARAMS[cell.route.path])
        ctx["handler_name"] = f"handle{_pascal_case(cell.cell_id)}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: node_express has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)

        body = _indent_block(
            "\n".join((source_result.code, *transform_code_blocks, sink_result.code)),
            "    ",
        )
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        js_source = (
            "'use strict';\n"
            f"// Generated by fuzzlab.labgen.emitters.node_express for cell {cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {composition}\n"
            "\n"
            "const pool = require('../db');\n"
            "\n"
            f"{_ESCAPE_HTML_HELPER}"
            "\n"
            f"{complexity_result.code}\n"
            f"module.exports = {ctx['handler_name']};\n"
        )
        path = f"routes/{cell.cell_id.lower()}.js"
        return (EmittedFile(path=path, content=js_source.encode("utf-8"), role="controller"),)

    def render_route_accumulator(self, cells: list[Cell]) -> EmittedFile:
        """Build ``app.js`` -- the ``route``-category accumulator
        (cardinality ``accumulator`` per Addendum D) -- fed by one fragment
        per **supported** cell, sorted by ``cell_id`` at render time.

        Deliberately not part of :meth:`render` (see the module docstring):
        the accumulator's real cardinality is "one file, fed by every cell,"
        which a single ``render(cell)`` call cannot express without either
        re-emitting a growing ``app.js`` on every single-cell call (breaking
        the generic Tier-3 harness's "no two cells emit the same path"
        invariant) or silently overwriting it. Two calls with an equal
        ``cells`` sequence (as a set -- order of the input iterable does not
        matter, only sorted ``cell_id`` does) produce byte-identical output.
        """
        supported = [c for c in cells if self.supports(c.vuln_class, c.sink_context)]
        by_id = sorted(supported, key=lambda c: c.cell_id)
        route_lines = [
            render_route_line(
                method=c.route.method,
                path=f"/generated/{c.cell_id.lower()}",
                handler_module=c.cell_id.lower(),
            )
            for c in by_id
        ]
        app_js = (
            "'use strict';\n"
            "// Generated by fuzzlab.labgen.emitters.node_express -- route accumulator\n"
            "// (CR-LAB-0001 Addendum D). Route lines below are sorted by cell ID at\n"
            "// render time, never by append/iteration order, so adding one cell can\n"
            "// never reshuffle this file (the whole-lab regeneration determinism gate).\n"
            "\n"
            "const express = require('express');\n"
            "\n"
            "const app = express();\n"
            "app.use(express.json());\n"
            "app.use(express.urlencoded({ extended: false }));\n"
            "\n"
            f"{''.join(route_lines)}"
            "\n"
            "if (require.main === module) {\n"
            "    const port = Number(process.env.PORT || 3000);\n"
            "    app.listen(port, '127.0.0.1');\n"
            "}\n"
            "\n"
            "module.exports = app;\n"
        )
        return EmittedFile(path="app.js", content=app_js.encode("utf-8"), role="route")


def _pascal_case(cell_id: str) -> str:
    """``LABGEN-NE-0001`` -> ``LabgenNe0001`` -- a valid JS identifier
    fragment derived deterministically from the cell ID (Addendum D's
    "per-cell identifiers are derived from the cell ID" rule)."""
    return "".join(part.capitalize() for part in cell_id.replace("_", "-").split("-"))


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free, same convention as ``php_current._indent_block``."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
