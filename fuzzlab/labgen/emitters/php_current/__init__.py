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

**L-P1.2b extension (``docs/LAB_IMPLEMENTATION_PLAN.md`` §2.2).** Four
harder shapes were added on top of the above, per the plan's
"highest value-per-hour" finding -- moving off textbook ``?id=1`` cells:

- ``(sqli, sql_identifier)`` -- ``/catalog.php?sort=``: the tainted value is
  an ``ORDER BY`` *column identifier*.
- ``(sqli, sql_join_alias)`` -- ``/inventory.php?alias=``: a JOIN alias, a
  connector position substituted three times in one statement.
- ``(xss, url_javascript_scheme)`` -- ``/share_link.php?url=``: the value is
  echoed inside a ``javascript:`` URL, where HTML-entity escaping is
  correct escaping for the *wrong* context.
- ``(xss, html_attribute_unquoted)`` -- ``/theme.php?theme=`` and the
  illustrative manifest's long-unrenderable ``LABGEN-EX-0003`` (stored
  ``bio`` into an unquoted attribute).

For the two identifier shapes, ``fuzzlab.labgen.identifier_sqli_assertion``
wires lane L-P1.2a's ``run_identifier_sqli_oracle`` in as the real
build-time security assertion (which is what that oracle exists for); see
that module for what it can and cannot confirm. These four shapes are
rendered on **illustrative** pages (``/catalog.php`` etc.), not claimed as
real ``puppy-fort-factory/`` pages -- today's PHP app has no
identifier-position or ``javascript:``-URL page to reproduce, so these are
new lab cells, and no ``lab/ground-truth/`` label claims otherwise.

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
    # --- L-P1.2b: the harder shapes (docs/LAB_IMPLEMENTATION_PLAN.md §2.2) ---
    # Identifier/alias/connector-position SQLi: the tainted value is a
    # column identifier or a JOIN alias, never a literal value.
    ("sqli", "sql_identifier"): _ModuleSet("get_param", "sql_identifier_order_by", "single_statement"),
    ("sqli", "sql_join_alias"): _ModuleSet("get_param", "sql_join_alias_lookup", "single_statement"),
    # Escaping-context-mismatch XSS: correct escaping applied for the wrong
    # context -- a value HTML-escaped into a `javascript:` URL, or into an
    # unquoted attribute whose boundary htmlspecialchars() does not protect.
    ("xss", "url_javascript_scheme"): _ModuleSet("get_param", "html_js_url_echo", "render_only"),
    ("xss", "html_attribute_unquoted"): _ModuleSet(
        "get_param", "html_attribute_unquoted_echo", "render_only"
    ),
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
    # L-P1.2b: this page's stored `bio` is now also rendered into an
    # *unquoted attribute* cell (LABGEN-EX-0003, which the illustrative
    # manifest has carried since Phase 0 while php_current could not render
    # it at all). Its taint is a stored field, not a request parameter, so it
    # overrides the (xss, html_attribute_unquoted) shape's default
    # `get_param` source -- see `_SOURCE_OVERRIDE_KEY`.
    "/example/profile.php": {
        "var_name": "bio",
        "stored_expr": "$currentUser['bio']",
        "css_class": "bio",
        "attr_name": "bio",
        "attr_default": "empty",
        "source_override": "read_stored_field",
    },
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
    # --- L-P1.2b harder-shape pages (lab/manifests/phase1_harder_shapes_sample.yaml) ---
    # catalog.php: `?sort=` selects an ORDER BY *column identifier*.
    # `allowed_identifiers` is what the `identifier_allowlist` transform
    # allows (first entry doubles as its safe fallback); `column_a`/`column_b`
    # are the two real, value-differing columns the build-time
    # identifier-SQLi oracle probes with (see
    # fuzzlab.labgen.identifier_sqli_assertion) -- render/probe metadata the
    # Cell IR deliberately does not carry.
    "/catalog.php": {
        "var_name": "sort",
        "param_name": "sort",
        "table": "products",
        "column": "name",
        "allowed_identifiers": ("id", "name", "price"),
        "column_a": "name",
        "column_b": "price",
    },
    # inventory.php: `?alias=` names a JOIN alias -- a connector position,
    # substituted three times in one statement.
    "/inventory.php": {
        "var_name": "alias",
        "param_name": "alias",
        "table": "inventory",
        "join_table": "inventory",
        "column": "sku",
        "join_column": "parent_id",
        "allowed_identifiers": ("i2", "i3"),
        "column_a": "i2",
        "column_b": "i3",
    },
    # share_link.php: `?url=` is echoed inside a `javascript:` URL.
    "/share_link.php": {"var_name": "link", "param_name": "url", "css_class": "share"},
    # theme.php: `?theme=` is echoed into an unquoted HTML attribute.
    "/theme.php": {
        "var_name": "theme",
        "param_name": "theme",
        "css_class": "theme",
        "attr_name": "theme",
        "attr_default": "default",
    },
}

#: Page-profile key that overrides a shape's default *source* module. Needed
#: because one ``(vuln_class, sink_context.family)`` shape can be reached by
#: two different taint origins on two different real pages (a request
#: parameter on one, an already-stored field on another) -- e.g.
#: ``(xss, html_attribute_unquoted)`` is a ``?theme=`` GET parameter on
#: ``/theme.php`` but the stored ``bio`` on ``/example/profile.php``. Keeping
#: this as a page-profile override, rather than splitting the shape key,
#: keeps the verdict-relevant shape vocabulary (``class`` x
#: ``sink_context.family``) exactly as the safety matrix and
#: ``fuzzlab.labgen.verdict`` define it -- source origin is render-only
#: metadata and must not fork it.
_SOURCE_OVERRIDE_KEY = "source_override"


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

        source_name = ctx.pop(_SOURCE_OVERRIDE_KEY, modules.source)
        if source_name not in SOURCES:
            raise ValueError(
                f"{cell.cell_id}: php_current page profile for {render_route.path!r} names an "
                f"unknown source module {source_name!r} -- known sources: {sorted(SOURCES)}"
            )
        source_result = SOURCES[source_name].render(ctx)
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

        composition = " -> ".join((source_name, *applied_ops, modules.sink, modules.complexity))
        php_source = (
            "<?php\n"
            f"// Generated by fuzzlab.labgen.emitters.php_current for cell {cell.cell_id}\n"
            f"// Real page: {render_route.path}\n"
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
