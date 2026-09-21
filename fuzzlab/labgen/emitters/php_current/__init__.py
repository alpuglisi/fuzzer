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
from fuzzlab.labgen.modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS
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

        if cell.route.path not in _PAGE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: php_current has no page profile for route {cell.route.path!r} "
                f"-- known routes: {sorted(_PAGE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_PAGE_PARAMS[cell.route.path])
        ctx["handler_name"] = f"handle_{cell.cell_id.lower().replace('-', '_')}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        # An empty transform pipeline means "identity" (the raw value is
        # used as-is) -- every op in a non-empty pipeline runs in order,
        # each free to publish new context keys for the next module/the
        # sink (mirrors fuzzlab.labgen.verdict.verdict()'s own ordered walk
        # over pipeline.ops).
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
            "\n".join((source_result.code, *transform_code_blocks, sink_result.code)),
            "    ",
        )
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        php_source = (
            "<?php\n"
            f"// Generated by fuzzlab.labgen.emitters.php_current for cell {cell.cell_id}\n"
            f"// Real page: {cell.route.path}\n"
            f"// Module composition: {composition}\n"
            "\n"
            f"{complexity_result.code}"
        )
        path = f"generated/{cell.cell_id.lower()}.php"
        return (EmittedFile(path=path, content=php_source.encode("utf-8"), role="page"),)


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free -- no reliance on a Jinja2 filter's own defaults."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
