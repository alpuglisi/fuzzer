"""``spring_boot``: the fourth emitter, category 3's Atlassian pick
(`CC-LAB-0090`, TrackerNest).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Java/Spring Boot by
assembling :mod:`fuzzlab.labgen.emitters.spring_boot.modules` fragments per
cell -- the same module-composition architecture
:mod:`fuzzlab.labgen.emitters.python_fastapi` uses, reimplemented
independently for this stack (``docs/LAB_IMPLEMENTATION_PLAN.md`` Phase 3's
"no stack's emitter package imports another's" rule).

**Scope, stated plainly (one cell only, per `CC-LAB-0090`'s pre-change
review).** This emitter supports exactly one shape as of this entry:
``(vuln_class="ssti", sink_context.family="template_render")``, TrackerNest's
``/wiki/pages/render`` cell (see
``docs/research/category3-saas-functionality-and-cwe-research.md`` sec 6b).
The XXE and insecure-deserialization cells for the same app are deliberately
deferred to a follow-on entry, not silently unfinished -- see
``docs/components/01-target-lab/change-control.md``'s `CC-LAB-0090` "Out of
scope" section.

**No route accumulator, unlike `php_laravel`/`node_express`.** Spring Boot's
own classpath component scan discovers every ``@RestController`` under
``com.fuzzlab.trackernest`` at boot time -- :meth:`SpringBootEmitter.render`
therefore returns exactly one file per cell (its generated controller class)
and there is no second, whole-manifest accumulation step a caller must also
run, the same shape :mod:`fuzzlab.labgen.emitters.python_fastapi` already
established for this project (its own static package-discovery scaffold
replacing a routes-accumulator file).
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

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
}

#: Per-route static render context, the same "render-only information, not
#: verdict-relevant" split every other stack's emitter uses.
_PAGE_PARAMS: dict[str, dict[str, Any]] = {
    "/wiki/pages/render": {"var_name": "macroExpr", "param_name": "macroExpr"},
    "/issues/import": {"var_name": "xmlBody"},
}

_CLASS_NAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9]+")

#: Spring's per-HTTP-method mapping annotations (`CC-LAB-0091`: the first
#: entry to need anything but GET -- the XXE cell's `/issues/import` is a
#: POST).
_MAPPING_ANNOTATION_BY_METHOD: dict[str, str] = {
    "GET": "GetMapping",
    "POST": "PostMapping",
}


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
        ctx["route_path"] = cell.route.path
        ctx["handler_name"] = f"handle_{cell.cell_id.lower().replace('-', '_')}"
        method = cell.route.method.upper()
        if method not in _MAPPING_ANNOTATION_BY_METHOD:
            raise ValueError(
                f"{cell.cell_id}: spring_boot has no mapping annotation for HTTP method "
                f"{method!r} -- known methods: {sorted(_MAPPING_ANNOTATION_BY_METHOD)}"
            )
        ctx["mapping_annotation"] = _MAPPING_ANNOTATION_BY_METHOD[method]

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        ops = list(cell.transform.ops)
        if len(ops) != 1 or ops[0] not in SINKS:
            raise ValueError(
                f"{cell.cell_id}: spring_boot's ssti/template_render shape requires exactly one "
                f"transform op naming which sink module to render (see modules.py's docstring for "
                f"why the op selects the sink here) -- got {ops!r}, known sinks: {sorted(SINKS)}"
            )
        sink_result = SINKS[ops[0]].render(ctx)

        body = source_result.code + sink_result.code
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        java_source = (
            "// Generated by fuzzlab.labgen.emitters.spring_boot for cell "
            f"{cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {modules.source} -> {ops[0]} -> {modules.complexity}\n"
            "package com.fuzzlab.trackernest.generated;\n"
            "\n"
            f"{complexity_result.code}"
        )
        path = f"src/main/java/com/fuzzlab/trackernest/generated/{class_name}.java"
        return (EmittedFile(path=path, content=java_source.encode("utf-8"), role="controller"),)
