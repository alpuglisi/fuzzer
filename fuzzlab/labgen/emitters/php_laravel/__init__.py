"""``php_laravel``: the second PHP emitter, Laravel/Eloquent/Blade idiom
(lane L-P3.3a, ``docs/LAB_IMPLEMENTATION_PLAN.md`` §4.3 steps 1/3/4/5).

**Foundation-only lane, stated plainly (mirrors ``php_current``'s own
module docstring convention).** This emitter does **not** yet carry the
full module inventory (``php_current``'s ported shapes plus the harder
identifier/alias/connector-position SQLi and escaping-context-mismatch XSS
shapes from Phase 1) -- that is lane **L-P3.3b**, which depends on this
landing first. It does not migrate any real ``puppy-fort-factory/`` page --
that is lane **L-P3.3c**, which depends on L-P3.3b. What this lane builds,
per the task brief:

1. :class:`~fuzzlab.labgen.emitters.php_laravel.stack_env.StackEnv` for
   ``php_laravel`` (``fuzzlab.labgen.emitters.php_laravel.stack_env``) --
   pinned framework version, digest-pinned base image, ``is_multi_file``,
   and the scaffold's ``.env`` with debug mode forced off.
2. A ``route``-category accumulator module for ``routes/web.php``
   (:mod:`fuzzlab.labgen.emitters.php_laravel.route_accumulator`), sorted by
   cell ID at render time per ``CR-LAB-0001`` Addendum D.
3. :class:`LaravelEmitter` itself -- exactly **one** trivial shape
   supported (``sqli``/``sql_numeric_literal``, the same shape
   ``php_current``'s first illustrative pair proves, in Laravel/Eloquent
   idiom instead of plain PHP/PDO), enough to prove the scaffold renders and
   the conformance suite (Tier 0 + Tier 3) passes against a deliberately
   minimal manifest -- not a real page, not the full shape inventory.

Every module this emitter composes with is its **own**, new to this
directory -- nothing is imported from :mod:`fuzzlab.labgen.modules` (that
package is ``php_current``'s plain-PHP-idiom inventory; Addendum C is
explicit that Laravel is "not reusable... its PHP is procedural, not
Laravel/Eloquent/Blade idiom" when describing VTSG, and the same reasoning
applies to reusing ``php_current``'s own plain-PHP fragments here) and
nothing is added to that shared package, per this lane's scope discipline.
"""

from __future__ import annotations

import re

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import RouteAccumulator
from fuzzlab.labgen.emitters.php_laravel.stack_env import PHP_LARAVEL_STACK_ENV, StackEnv
from fuzzlab.labgen.schema import Cell, SinkContext

__all__ = ["LaravelEmitter", "PHP_LARAVEL_STACK_ENV", "StackEnv"]

#: (vuln_class, sink_context.family) -> True this emitter supports. A dict
#: (not a set) so a later lane (L-P3.3b) can extend it with per-shape
#: metadata the way ``php_current``'s ``_MODULE_SET_BY_SHAPE`` does, without
#: changing this dict's shape -- deliberately not built out further here,
#: per this lane's scope (see module docstring).
_SUPPORTED_SHAPES: dict[tuple[str, str], bool] = {
    ("sqli", "sql_numeric_literal"): True,
}

#: Transform ops this emitter's one sink module knows how to branch on.
#: Mirrors ``php_current``'s ``bound`` flag -- an empty pipeline means
#: "identity" (raw, unmediated value), exactly one non-empty op
#: (``param_bind``) is understood; anything else raises rather than
#: guessing, matching this project's "fail loud on an authoring gap"
#: discipline (see ``fuzzlab.labgen.emitters.php_current``).
_KNOWN_OPS = frozenset({"param_bind"})

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _cell_slug(cell_id: str) -> str:
    """A lowercase, hyphen-free slug derived from ``cell_id``, e.g.
    ``LABGEN-PL-0001`` -> ``labgen-pl-0001``. Used for both the controller
    class name and the route URL, so both are traceable to the same cell
    and, per Addendum D's per-cell-identifier rule, never a generic/shared
    name -- every cell (including a secure twin, a distinct cell in its own
    right) gets its own slug from its own ID, the same precedent
    ``php_current``'s ``handler_name`` already sets."""
    return _SLUG_RE.sub("-", cell_id.lower()).strip("-")


def _controller_class_for(cell_id: str) -> str:
    """PascalCase controller class name derived from ``cell_id``, e.g.
    ``LABGEN-PL-0001`` -> ``LabgenPl0001Controller``."""
    parts = _cell_slug(cell_id).split("-")
    return "".join(p.capitalize() for p in parts if p) + "Controller"


def _url_path_for(cell_id: str) -> str:
    """The route URL this cell is served at. Derived from ``cell_id``, not
    ``cell.route.path`` verbatim -- see
    ``fuzzlab.labgen.emitters.php_laravel.route_accumulator``'s module
    docstring for why a twin needs its own URL to coexist in one build."""
    return f"/cell/{_cell_slug(cell_id)}"


class LaravelEmitter(Emitter):
    """Renders a :class:`Cell` to a Laravel controller (``EmittedFiles``)
    plus a route fragment for the ``routes/web.php`` accumulator.

    Like ``php_current``, ``render()`` never falls back to a default
    transform silently -- an op this emitter has no branch for raises
    rather than guessing.
    """

    stack_env: StackEnv = PHP_LARAVEL_STACK_ENV

    def __init__(self) -> None:
        self._route_accumulator = RouteAccumulator()

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _SUPPORTED_SHAPES

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for php_laravel "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )

        applied_ops = tuple(cell.transform.ops)
        if len(applied_ops) > 1 or (applied_ops and applied_ops[0] not in _KNOWN_OPS):
            raise ValueError(
                f"{cell.cell_id}: php_laravel has no transform module for pipeline {applied_ops!r} "
                f"-- known ops: {sorted(_KNOWN_OPS)} (or an empty pipeline)"
            )
        bound = applied_ops == ("param_bind",)

        controller_class = _controller_class_for(cell.cell_id)
        composition = "get_query_param -> " + (applied_ops[0] if applied_ops else "identity") + " -> db_select_raw"

        if bound:
            sink_body = (
                '        $rows = DB::select("SELECT * FROM products WHERE id = ?", [$id]);\n'
                "        return response()->json($rows);\n"
            )
        else:
            sink_body = (
                '        $rows = DB::select("SELECT * FROM products WHERE id = " . $id);\n'
                "        return response()->json($rows);\n"
            )

        php_source = (
            "<?php\n"
            f"// Generated by fuzzlab.labgen.emitters.php_laravel for cell {cell.cell_id}\n"
            f"// Manifest cell.route.path: {cell.route.path}\n"
            f"// Module composition: {composition}\n"
            "\n"
            "namespace App\\Http\\Controllers;\n"
            "\n"
            "use Illuminate\\Http\\Request;\n"
            "use Illuminate\\Support\\Facades\\DB;\n"
            "\n"
            f"class {controller_class} extends Controller\n"
            "{\n"
            "    public function show(Request $request)\n"
            "    {\n"
            "        $id = $request->query('id');\n"
            f"{sink_body}"
            "    }\n"
            "}\n"
        )
        path = self.stack_env.file_roles["controller"].format(cell_slug=controller_class[: -len("Controller")])
        return (EmittedFile(path=path, content=php_source.encode("utf-8"), role="controller"),)

    def route_fragment_for(self, cell: Cell) -> str:
        """This cell's ``routes/web.php`` fragment (accumulator category,
        one per cell -- see ``route_accumulator.py``'s module docstring for
        why this is not part of :meth:`render`'s own return value)."""
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(f"{cell.cell_id}: unsupported for php_laravel -- see render() for the same check")
        controller_class = _controller_class_for(cell.cell_id)
        return self._route_accumulator.fragment_for_cell(
            cell_id=cell.cell_id,
            controller_class=controller_class,
            url_path=_url_path_for(cell.cell_id),
        )

    def render_scaffold(self) -> EmittedFiles:
        """The per-stack scaffold files (rendered once per build, never per
        cell) -- ``StackEnv.scaffold_files`` names the paths; this method is
        what actually renders their content."""
        return (
            EmittedFile(path=".env", content=self.stack_env.env_file_content(), role="scaffold"),
            EmittedFile(path="public/index.php", content=self.stack_env.index_php_content(), role="scaffold"),
        )
