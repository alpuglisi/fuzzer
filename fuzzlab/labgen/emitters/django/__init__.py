"""``django``: category 2's new-stack pick (Instagram/Python-Django,
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9), Phase A
(`CC-LAB-0090`).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Django by assembling
:mod:`fuzzlab.labgen.emitters.django.modules` fragments per cell, following
``fuzzlab.labgen.emitters.node_express``'s own port of ``php_current``'s
module-composition shape (Addendum C) as the closer structural template --
both are Phase-A/Tier-A-scoped ports, unlike ``php_laravel``'s full-depth
build. The actual Python/Django code is new.

**Scope, stated plainly (Phase A only, `CC-LAB-0090`):** exactly one
well-documented, value-context shape -- ``sqli``/``sql_numeric_literal`` --
the same first shape ``php_laravel``'s own L-P3.3a foundation lane and
``node_express``'s Phase A plan both picked, proving the scaffold renders
and passes Tier 0 + Tier 3 end to end. The full module-inventory depth
(mirroring ``node_express``'s own three Tier-A shapes, let alone
``php_laravel``'s full nine) is a separate, later Phase B -- not attempted
here.

**Multi-file output, like ``node_express``.** Per Addendum D, a routed,
multi-file emitter needs a ``route``-category *accumulator* module
(``fuzlab_django_lab/urls.py``'s route-registration lines) fed by one
fragment per cell, sorted by cell ID at render time. :meth:`Emitter.render`
therefore returns **only** the per-cell view file for a cell -- never a
re-rendering of the shared ``urls.py`` -- exactly ``node_express``'s own
documented extension of the per-emitter contract
(:meth:`DjangoEmitter.render_route_accumulator` is called once, separately,
over the whole supported cell set).

**No separate Django "app" needed for this shape.** The one illustrative
shape uses a raw ``connection.cursor()`` sink on *both* twins (never the
ORM), so it needs no model/migration of its own -- views live directly in
the project package (``fuzlab_django_lab/views/``), a documented
simplification from `CC-LAB-0090`'s original draft sketch (see
``fuzzlab.labgen.emitters.django.stack_env`` module docstring for the
divergence note, reflected back per the pre-change review gate's own rule).
"""

from __future__ import annotations

from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS, render_route_import_line

__all__ = ["DjangoEmitter"]


class _ModuleSet(NamedTuple):
    """Same shape as ``php_current``'s/``node_express``'s ``_ModuleSet``:
    which source/sink/complexity module a ``(vuln_class,
    sink_context.family)`` shape renders with. The transform is never fixed
    here -- it always comes from the cell's own ``transform`` pipeline, per
    op."""

    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Phase A scope only -- any pair not listed here is declared unsupported
#: via supports().
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("sqli", "sql_numeric_literal"): _ModuleSet("get_param", "sql_numeric_lookup", "single_statement"),
}

#: Per-route static context (table/column/param names) an emitter needs
#: beyond the verdict-relevant Cell IR -- same separation rationale as
#: ``php_current._PAGE_PARAMS``/``node_express._ROUTE_PARAMS``: table/column
#: naming is render-only information, not verdict-relevant, so it lives
#: here rather than growing the shared IR. Keyed by ``cell.route.path``,
#: since a vulnerable cell and its secure twin share one route profile.
_ROUTE_PARAMS: dict[str, dict[str, Any]] = {
    "/api/products": {"var_name": "id", "param_name": "id", "table": "products", "column": "id"},
}


class DjangoEmitter(Emitter):
    """Renders a :class:`Cell` to a single Django view module via module
    composition, Phase A's one shape only.

    ``render()`` never falls back to a default sink/transform/route-profile
    silently, matching ``php_current``'s/``node_express``'s "fail loud on
    an authoring gap" discipline.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for django "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _ROUTE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: django has no route profile for route {cell.route.path!r} "
                f"-- known routes: {sorted(_ROUTE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_ROUTE_PARAMS[cell.route.path])
        ctx["handler_name"] = f"handle_{_snake_case(cell.cell_id)}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: django has no transform module for op {op!r} "
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
        py_source = (
            f"# Generated by fuzzlab.labgen.emitters.django for cell {cell.cell_id}\n"
            f"# Route: {cell.route.method} {cell.route.path}\n"
            f"# Module composition: {composition}\n"
            "\n"
            "from django.db import connection\n"
            "from django.http import HttpResponse, JsonResponse\n"
            "\n"
            "\n"
            f"{complexity_result.code}"
        )
        cell_slug = _snake_case(cell.cell_id)
        path = f"fuzlab_django_lab/views/{cell_slug}.py"
        return (EmittedFile(path=path, content=py_source.encode("utf-8"), role="view"),)

    def render_route_accumulator(self, cells: list[Cell]) -> EmittedFile:
        """Build ``fuzlab_django_lab/urls.py`` -- the ``route``-category
        accumulator (cardinality ``accumulator`` per Addendum D) -- fed by
        one fragment per **supported** cell, sorted by ``cell_id`` at
        render time. Mirrors
        ``NodeExpressEmitter.render_route_accumulator`` exactly (deliberately
        not part of :meth:`render`, for the same reason that module's
        docstring gives: the accumulator's real cardinality is "one file,
        fed by every cell," which a single ``render(cell)`` call cannot
        express without either breaking the shared Tier-3 "no two cells
        emit the same path" invariant, or silently overwriting the file).
        Two calls with an equal ``cells`` sequence (as a set -- input order
        does not matter, only sorted ``cell_id`` does) produce
        byte-identical output.
        """
        supported = [c for c in cells if self.supports(c.vuln_class, c.sink_context)]
        by_id = sorted(supported, key=lambda c: c.cell_id)

        import_lines: list[str] = []
        urlpattern_lines: list[str] = []
        for c in by_id:
            cell_slug = _snake_case(c.cell_id)
            handler_name = f"handle_{cell_slug}"
            import_lines.append(
                render_route_import_line(handler_module=cell_slug, handler_name=handler_name).rstrip("\n")
            )
            url_path = f"generated/{cell_slug}/"
            urlpattern_lines.append(
                f'    path("{url_path}", {handler_name}, name="{cell_slug}"),  # cell: {c.cell_id}\n'
            )

        urls_py = (
            "# Generated by fuzzlab.labgen.emitters.django -- fuzlab_django_lab/urls.py\n"
            "# (route accumulator, CR-LAB-0001 Addendum D). Route lines below are sorted\n"
            "# by cell ID at render time, never by append/iteration order, so adding one\n"
            "# cell can never reshuffle this file (the whole-lab regeneration determinism\n"
            "# gate).\n"
            "\n"
            "from django.urls import path\n"
            + ("".join(f"{line}\n" for line in import_lines) if import_lines else "")
            + "\n"
            "urlpatterns = [\n"
            + "".join(urlpattern_lines)
            + "]\n"
        )
        return EmittedFile(
            path="fuzlab_django_lab/urls.py", content=urls_py.encode("utf-8"), role="route"
        )


def _snake_case(cell_id: str) -> str:
    """``LABGEN-DJ-0001`` -> ``labgen_dj_0001`` -- a valid Python
    identifier/module-name fragment derived deterministically from the cell
    ID (Addendum D's "per-cell identifiers are derived from the cell ID"
    rule; Python module names cannot contain hyphens, unlike JS's
    ``_pascal_case``/PHP's class-name convention)."""
    return cell_id.lower().replace("-", "_")


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free, same convention as ``php_current._indent_block``/
    ``node_express._indent_block``."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
