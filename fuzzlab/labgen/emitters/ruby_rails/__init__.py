"""``ruby_rails`` -- the Ruby-on-Rails :class:`~fuzzlab.labgen.emitter.Emitter`
(category 1 / e-commerce pilot, ``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md``
§2/§9.4a/§9.5). This project's first Ruby-on-Rails stack.

**Scope of this dispatch (Phase A only -- see the plan's §2, written for
node_express but structurally reused here).** This module, together with
``modules.py``/``route_accumulator.py`` and the checked-in real skeleton
under ``stack/skeleton/``, is the minimum real, working emitter needed to
prove the pipeline end to end: assemble a manifest cell into real
controller/view/route files, boot a real Rails app, and serve a real HTTP
request. It renders exactly one illustrative shape
(``("xss", "html_body")`` -- "reflect a request parameter into the response
body", the same bar ``php_laravel``'s very first live-boot test set) and
nothing else.

**Explicitly out of scope here** (a separate, later lane, per the plan's own
"What to build"/"Explicitly OUT of scope" split): the real Rails-idiom
vulnerability modules Shopify's own functionality/CWE research shortlisted
(``docs/research/site-architecture-survey-functionality-shopify.md`` /
plan §9.4a) -- a ``webhook-signature`` naive-``==``-vs-``ActiveSupport::
SecurityUtils.secure_compare`` idiom, CWE-915 mass assignment via Rails'
``permit!``, and CWE-502 insecure deserialization via ``Marshal.load``/
``YAML.unsafe_load``. Building those is Phase B's job, against the harness
this dispatch builds; deepening this emitter's ``_MODULE_SET_BY_SHAPE``-
equivalent registry to carry them is that lane's responsibility, not this
one's.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.emitters.ruby_rails.modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS
from fuzzlab.labgen.emitters.ruby_rails.route_accumulator import RouteAccumulator
from fuzzlab.labgen.schema import Cell, SinkContext

__all__ = ["RailsEmitter", "SUPPORTED_CONTEXT_DEPTHS", "controller_name_for", "url_path_for"]

#: The one ``Cell.context_depth`` this Phase A emitter renders. Widening this
#: (``stored_second_order``, the pass-through-helper depths) is Phase B/a
#: later lane's job, exactly like ``php_laravel``'s own
#: ``SUPPORTED_CONTEXT_DEPTHS`` was widened incrementally rather than built
#: complete on day one.
SUPPORTED_CONTEXT_DEPTHS: tuple[str, ...] = ("direct",)


class _ModuleSet(NamedTuple):
    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Exactly one entry in this Phase A dispatch -- see the module docstring.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("xss", "html_body"): _ModuleSet("get_param", "html_body_echo", "render_only"),
}

_METHOD_NAME = "show"

#: A cell ID like ``LABGEN-RR-0001`` -> a Rails-legal, unique, lowercase
#: snake_case identifier (``labgen_rr_0001``) safe to use in both a
#: controller class name and a route/controller-path string. Anchored,
#: exact-charset (PA-0022): a cell ID this cannot losslessly slugify is a
#: caller bug, not silently coerced.
_CELL_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


def _slug_for(cell_id: str) -> str:
    if not _CELL_ID_RE.match(cell_id):
        raise ValueError(
            f"ruby_rails cannot slugify cell_id {cell_id!r} -- expected "
            f"{_CELL_ID_RE.pattern!r}"
        )
    return cell_id.lower().replace("-", "_")


def controller_name_for(cell_id: str) -> str:
    """The Rails controller path (after ``#`` in ``to: 'x#show'``, and the
    ``app/controllers/<this>_controller.rb`` file stem) for a cell -- the one
    place this mapping is computed, so the emitted route and the emitted
    controller file can never name two different things
    (PA-0003/PA-0021)."""
    return f"cell_{_slug_for(cell_id)}"


def _controller_class_for(cell_id: str) -> str:
    """The Ruby class name for :func:`controller_name_for`'s controller path
    -- ``cell_labgen_rr_0001`` -> ``CellLabgenRr0001Controller``, Rails'
    own ``String#camelize``-equivalent convention (applied here in Python,
    not by shelling out to Ruby, since this is pure, deterministic string
    logic the generator must be able to run without a Ruby runtime
    present)."""
    camel = "".join(part.capitalize() for part in controller_name_for(cell_id).split("_"))
    return f"{camel}Controller"


def url_path_for(cell_id: str) -> str:
    """The illustrative URL a Phase A cell is served at -- cell-ID-derived,
    exactly like ``php_laravel``'s own illustrative (non-``real_page``)
    cells (``/cell/<slug>``). No real-page URL-pinning mechanism exists for
    this stack yet (that is real-page-migration work, out of this
    dispatch's scope, and this stack has no real target app to migrate
    pages from in the first place -- Shopify/Walmart are external sites,
    not a checked-in ``puppy-fort-factory``-style fixture)."""
    return f"/cell/{_slug_for(cell_id)}"


def _view_name_for(cell_id: str) -> str:
    return _METHOD_NAME


class RailsEmitter(Emitter):
    """Renders a resolved :class:`~fuzzlab.labgen.schema.Cell` into a real
    Rails controller + view, plus a route fragment a caller accumulates into
    ``config/routes.rb`` via :class:`RouteAccumulator`
    (:meth:`route_fragment_for`) -- the same controller/view/route split
    ``LaravelEmitter`` uses, per ``CR-LAB-0001`` Addendum D."""

    def __init__(self) -> None:
        self._route_accumulator = RouteAccumulator()

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for ruby_rails "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        if cell.context_depth not in SUPPORTED_CONTEXT_DEPTHS:
            raise ValueError(
                f"{cell.cell_id}: ruby_rails renders context_depth "
                f"{list(SUPPORTED_CONTEXT_DEPTHS)} only (Phase A), got {cell.context_depth!r}"
            )

        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]
        controller_name = controller_name_for(cell.cell_id)
        controller_class = _controller_class_for(cell.cell_id)
        view_name = _view_name_for(cell.cell_id)

        ctx: dict[str, Any] = {
            "var_name": "value",
            "param_name": cell.route.path.rsplit("/", 1)[-1] or "q",
            "method_name": _METHOD_NAME,
            "view_name": view_name,
        }
        # The param name a cell's source reads is not itself part of the
        # verdict-relevant shape vocabulary -- fixed to a stable, readable
        # name (`q`) rather than derived from `cell.route.path` for any cell
        # whose path has no trailing segment to reuse.
        ctx["param_name"] = "q"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: ruby_rails has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)

        raw_body = source_result.code + "".join(transform_code_blocks)
        # Indent every source/transform line under the controller method's
        # own `def`/`end` (cosmetic -- Ruby is whitespace-insensitive -- but
        # matches this project's other emitters' convention of emitting
        # source that reads like a human wrote it, not a diagnostic aid to
        # skip).
        body = "\n".join(f"    {line}" if line else line for line in raw_body.splitlines()) + "\n"
        complexity_result = COMPLEXITIES[modules.complexity].render(
            {**ctx, "body": body, "view_template": f"{controller_name}/{view_name}"}
        )

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        # Zeitwerk (Rails' autoloader) expects exactly one top-level constant
        # per file, matching the file's own path -- this controller file
        # must define only `controller_class`, never a second
        # `ApplicationController` definition of its own; the skeleton's real
        # `app/controllers/application_controller.rb` already defines it.
        controller_content = (
            "# Generated by fuzzlab.labgen.emitters.ruby_rails. Do not edit by hand.\n"
            f"# Module composition: {composition}\n"
            f"# cell: {cell.cell_id}\n"
            f"class {controller_class} < ApplicationController\n"
            f"{complexity_result.code}"
            "end\n"
        )

        view_dir = f"app/views/{controller_name}"
        view_content = (
            f"<%# Generated by fuzzlab.labgen.emitters.ruby_rails -- cell: {cell.cell_id} %>\n"
            + sink_result.code
        )

        return (
            EmittedFile(
                path=f"app/controllers/{controller_name}_controller.rb",
                content=controller_content.encode("utf-8"),
                role="controller",
            ),
            EmittedFile(
                path=f"{view_dir}/{view_name}.html.erb",
                content=view_content.encode("utf-8"),
                role="view",
            ),
        )

    def route_fragment_for(self, cell: Cell) -> str:
        """One ``config/routes.rb`` fragment for ``cell`` -- accumulated
        across every cell of a build via :class:`RouteAccumulator`, mirroring
        ``LaravelEmitter.route_fragment_for``'s role exactly (Addendum D:
        the accumulator category lives outside a per-cell ``render()``
        return value)."""
        return self._route_accumulator.fragment_for_cell(
            cell_id=cell.cell_id,
            controller_name=controller_name_for(cell.cell_id),
            url_path=url_path_for(cell.cell_id),
            method=cell.route.method,
            action=_METHOD_NAME,
        )
