"""``php_current``: the first (reproduction) emitter (T-LAB0.4).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for PHP by assembling
:mod:`fuzzlab.labgen.modules` fragments per cell, per ``CR-LAB-0001``
Addendum C's module-composition correction.

**Scope, stated plainly:** this emitter does **not** reproduce all ~30 of
today's real ``puppy-fort-factory/`` pages -- that migration is separate,
later, larger work (tracked in ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.7/
Phase 3). It renders:

- one illustrative pair (``/example/product.php``, `sql_numeric_literal`,
  the original T-LAB0.4 proof-of-composition cells), and
- a small **real** sample of four actual ``puppy-fort-factory/`` pages --
  ``product.php`` (SQLi, GET, numeric-literal), ``blog_post.php`` (SQLi,
  GET, numeric-literal -- a second real page reusing the exact same module
  set as ``product.php``, proving the composition generalizes across real
  pages, not just within one illustrative shape), ``login.php`` (SQLi,
  POST, string-literal -- a distinct sink-context family and source
  origin), and ``profile.php`` (stored XSS, HTML body -- a distinct
  vulnerability class, source origin, and sink), matching
  ``puppy-fort-factory/VULNERABILITIES.md`` and
  ``lab/ground-truth/labels.json`` (``PFF-0001``, ``PFF-0004``,
  ``PFF-0005``, ``PFF-0006``) -- see
  ``lab/manifests/phase0_real_pages_sample.yaml``.

Since `CC-LAB-0040` it also renders a cell's ``context_depth`` (§3.5): a
``same_file_helper``/``cross_file`` cell's tainted value travels through a
pass-through helper (defined in this page, or in a second emitted
``role="helper"`` file pulled in by ``require_once``) before reaching the
sink, while ``direct`` renders the inline body unchanged and
``stored_second_order``'s depth is already expressed by ``sink_endpoint``
routing this emitter to the sink page.

Two things this emitter does **not** attempt, deliberately, for this real
sample: it does not model ``blog_post.php``'s error-suppression nuance
(`@mysqli_query`, "blind" vs. "error-based") -- the safety matrix/verdict
model has no concept for that distinction yet, so both pages render via the
same ``sql_numeric_lookup`` sink; and ``login.php``'s ``password`` field is
rendered as sink boilerplate, not a separate injection-point cell (it is
already correctly labelled non-vulnerable in ``lab/ground-truth/labels.json``,
``PFF-1008``). Both are noted here rather than silently glossed over.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.modules import COMPLEXITIES, DEPTHS, SINKS, SOURCES, TRANSFORMS
from fuzzlab.labgen.schema import Cell, SinkContext


class _ModuleSet(NamedTuple):
    """Which source/sink/complexity module a ``(vuln_class, sink_context.family)``
    shape renders with. The transform is never fixed here -- it always comes
    from the cell's own ``transform`` pipeline, per op, exactly like
    ``fuzzlab.labgen.verdict.verdict()``'s own ordered walk."""

    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Any pair not listed here is declared unsupported via `supports()`.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("sqli", "sql_numeric_literal"): _ModuleSet("get_param", "sql_numeric_lookup", "single_statement"),
    ("sqli", "sql_string_literal"): _ModuleSet("post_param", "sql_string_literal_lookup", "single_statement"),
    ("xss", "html_body"): _ModuleSet("read_stored_field", "html_body_echo", "render_only"),
}

#: Per-real-page static context (table/column/param names, or the stored
#: field expression an HTML-sink cell reads) an emitter needs beyond the
#: verdict-relevant Cell IR (`fuzzlab.labgen.schema.Cell` deliberately
#: carries only what `verdict()` needs -- table/column naming is
#: render-only information, not verdict-relevant, so it lives here rather
#: than growing the IR). Keyed by `cell.route.path`, since a vulnerable cell
#: and its secure twin share one real page and therefore one profile.
_PAGE_PARAMS: dict[str, dict[str, Any]] = {
    # The original T-LAB0.4 illustrative pair (unchanged, kept working).
    "/example/product.php": {"var_name": "id", "param_name": "id", "table": "products", "column": "id"},
    # BUG-0022 fix: the illustrative manifest's xss/html_body cell
    # (LABGEN-EX-0004) predates php_current's xss/html_body support
    # (added in CC-LAB-0020/CC-LAB-0022's real-pages extension) but was
    # never given a page profile, so supports() started returning True
    # for it while render() still raised -- see docs/bugs/BUG-0022-*.md.
    "/example/profile.php": {"var_name": "bio", "stored_expr": "$currentUser['bio']", "css_class": "bio"},
    # Real puppy-fort-factory/ pages (see module docstring above).
    "/product.php": {"var_name": "id", "param_name": "id", "table": "products", "column": "id"},
    "/blog_post.php": {"var_name": "id", "param_name": "id", "table": "posts", "column": "id"},
    "/login.php": {
        "var_name": "username",
        "param_name": "username",
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    },
    "/profile.php": {"var_name": "bio", "stored_expr": "$currentUser['bio']", "css_class": "bio"},
}


class PhpCurrentEmitter(Emitter):
    """Renders a :class:`Cell` to a single PHP page via module composition.

    ``render()`` never falls back to a default sink/transform/page-profile
    silently: a shape or op this emitter has no module or profile for
    raises, rather than guessing -- the same "fail loud on an authoring
    gap" discipline ``fuzzlab.labgen.verdict`` already uses for the safety
    matrix.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for php_current "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        # This emitter renders the page the tainted value actually executes
        # on (the module docstrings above are explicit that e.g.
        # `read_stored_field` renders "the sink side only"). For a
        # same-endpoint cell that page is `route`; for a stored/second-order
        # cell with a distinct `sink_endpoint` (CC-LAB-0029), it is the sink
        # page instead -- `route` there is the injection point, a different
        # real page this emitter is never asked to render on its own.
        render_route = cell.sink_endpoint if cell.sink_endpoint is not None else cell.route

        if render_route.path not in _PAGE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: php_current has no page profile for route {render_route.path!r} "
                f"-- known routes: {sorted(_PAGE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_PAGE_PARAMS[render_route.path])
        ctx["handler_name"] = f"handle_{cell.cell_id.lower().replace('-', '_')}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        # An empty transform pipeline means "identity" (the raw value is
        # used as-is) -- every op in a non-empty pipeline runs in order,
        # each free to publish new context keys for the next module/the
        # sink (mirrors fuzzlab.labgen.verdict.verdict()'s own ordered walk
        # over pipeline.ops).
        # Context-depth hop (§3.5, L-P2.5), rendered *between* the source and
        # the cell's own transform pipeline so the value that reaches the sink
        # has provably travelled through it. `direct` adds nothing (today's
        # inline body, byte-identical to before this axis existed);
        # `stored_second_order` also adds nothing here -- its depth is already
        # expressed structurally, by `sink_endpoint` routing this emitter to
        # the sink page above, where the value is read from storage rather
        # than from the request.
        depth_prelude, depth_defs, depth_requires, depth_files = self._render_depth(cell, ctx)

        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: php_current has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)

        body = _indent_block(
            "\n".join(
                (source_result.code, *depth_prelude, *transform_code_blocks, sink_result.code)
            ),
            "    ",
        )
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        depth_modules = ("passthrough_helper", "helper_call") if depth_prelude else ()
        composition = " -> ".join(
            (
                modules.source,
                *depth_modules,
                *applied_ops,
                modules.sink,
                modules.complexity,
            )
        )
        # A `direct` cell's header is byte-identical to what this emitter
        # produced before the depth axis existed -- the whole pre-existing
        # corpus regenerates unchanged (and is regression-tested to).
        depth_comment = (
            "" if cell.context_depth == "direct" else f"// Context depth: {cell.context_depth}\n"
        )
        php_source = (
            "<?php\n"
            f"// Generated by fuzzlab.labgen.emitters.php_current for cell {cell.cell_id}\n"
            f"// Real page: {render_route.path}\n"
            f"// Module composition: {composition}\n"
            f"{depth_comment}"
            "\n"
            + "".join(f"{line}\n" for line in depth_requires)
            + ("\n" if depth_requires else "")
            + "".join(f"{block}\n" for block in depth_defs)
            + f"{complexity_result.code}"
        )
        path = f"generated/{cell.cell_id.lower()}.php"
        page = EmittedFile(path=path, content=php_source.encode("utf-8"), role="page")
        return (page, *depth_files)

    def _render_depth(
        self, cell: Cell, ctx: dict[str, Any]
    ) -> tuple[list[str], list[str], list[str], list[EmittedFile]]:
        """Render a cell's ``context_depth`` fragments (§3.5).

        Returns ``(prelude_lines, top_level_definitions, require_lines,
        extra_files)``. ``same_file_helper`` and ``cross_file`` render the
        *same* helper and call site and differ only in whether the definition
        lands in this page or in a second emitted file -- which is exactly the
        distinction the axis exists to measure, so it is a placement decision
        here, not two separate module sets.
        """
        if cell.context_depth in ("direct", "stored_second_order"):
            return ([], [], [], [])

        helper_name = f"{ctx['handler_name']}_helper"
        helper_ctx = {**ctx, "helper_name": helper_name, "context_depth": cell.context_depth}
        helper_code = DEPTHS["passthrough_helper"].render(helper_ctx).code
        prelude = [DEPTHS["helper_call"].render(helper_ctx).code.rstrip("\n")]

        if cell.context_depth == "same_file_helper":
            return (prelude, [helper_code], [], [])

        helper_file_name = f"{cell.cell_id.lower()}_helper.php"
        require = DEPTHS["cross_file_require"].render(
            {**helper_ctx, "helper_file_name": helper_file_name}
        )
        helper_source = (
            "<?php\n"
            f"// Generated by fuzzlab.labgen.emitters.php_current for cell {cell.cell_id}\n"
            f"// Context depth: {cell.context_depth} (helper file)\n"
            "\n"
            f"{helper_code}"
        )
        helper_file = EmittedFile(
            path=f"generated/{helper_file_name}",
            content=helper_source.encode("utf-8"),
            role="helper",
        )
        return (prelude, [], [require.code.rstrip("\n")], [helper_file])


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free -- no reliance on a Jinja2 filter's own defaults."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
