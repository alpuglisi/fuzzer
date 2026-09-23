"""``java_spring_boot``: this project's first JVM/Java stack (category 4
pilot, ``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §9.4/§9.5, Netflix
pick; ``CC-LAB-0171``/``FR-LAB-77``).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Spring Boot 3.4.1 /
Spring MVC (plain ``@RestController``/``@PostMapping`` — **no
`spring-boot-starter-graphql`/Netflix DGS dependency in this Phase A**; see
``CC-LAB-0171``'s explicit scope call) by assembling
:mod:`fuzzlab.labgen.emitters.java_spring_boot.modules` fragments per cell.

**Phase A scope, stated plainly.** Exactly one shape:
``("insecure_deserialization", "object_deserialization")`` — a
``/api/playback/resume``-shaped POST handler that Jackson-deserializes its
request body either polymorphically (vulnerable, CWE-502,
``activateDefaultTyping``) or into a single fixed DTO class (secure, no
polymorphism). CWE-862 (GraphQL field authorization) and the GraphQL/DGS
federation layer itself stay deferred to Phase B.

**No route accumulator — a genuine architectural difference from every
other routed emitter, not a shortcut.** ``node_express``/``ruby_rails``/
``go_net_http`` all need a shared accumulator file because their router
requires explicit registration lines. Spring Boot's component scanning
(``@RestController``-annotated classes are auto-discovered on the
classpath at boot, rooted at ``Application.java``'s package,
``com.fuzzlab.lab``, and every subpackage) needs no equivalent — each
cell's rendered controller class is a fully self-contained file. This
emitter therefore has no ``render_route_accumulator`` method at all (that
method was never part of the base :class:`~fuzzlab.labgen.emitter.Emitter`
ABC for any stack — every routed emitter added it as an ad-hoc extension
the ABC does not require).

**The package/file-layout guarantee this relies on, made explicit
(``CC-LAB-0171``'s own adequacy-review correction).** Every generated cell
controller is rendered to a **fixed** path,
``src/main/java/com/fuzzlab/lab/cells/Cell<PascalCaseCellId>.java``,
declaring ``package com.fuzzlab.lab.cells;`` — a subpackage of the scanned
root, hardcoded here, never derived from anything manifest-supplied. A
controller landing outside the scanned package would 404 silently at boot
with no startup error; :mod:`fuzzlab.labgen.conformance.java_live_boot`'s
own test asserts a real ``200``/expected-body response from the actual
route, not just "the process started," so a future regression of this
guarantee fails loud rather than silently.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS

__all__ = ["GENERATED_PACKAGE", "JavaEmitter"]

#: The fixed Java package every generated cell controller declares -- a
#: subpackage of the skeleton's scanned root (``com.fuzzlab.lab``), so
#: Spring Boot's default component scan always finds it. See the module
#: docstring's "package/file-layout guarantee" section.
GENERATED_PACKAGE = "com.fuzzlab.lab.cells"


class _ModuleSet(NamedTuple):
    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Exactly one entry in this Phase A dispatch -- see the module docstring.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("insecure_deserialization", "object_deserialization"): _ModuleSet(
        "read_playback_event_body", "object_deserialization", "render_only"
    ),
}

#: Per-route static context this Phase A emitter needs beyond the
#: verdict-relevant Cell IR -- same render-only-information separation
#: rationale as every other stack's own per-route params table.
_ROUTE_PARAMS: dict[str, dict[str, Any]] = {
    "/api/playback/resume": {},
}


class JavaEmitter(Emitter):
    """Renders a :class:`Cell` to a single Spring MVC controller class via
    module composition, Phase A shape only.

    ``render()`` never falls back to a default sink/transform/route-profile
    silently, matching every other stack's "fail loud on an authoring gap"
    discipline.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for java_spring_boot "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _ROUTE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: java_spring_boot has no route profile for route "
                f"{cell.route.path!r} -- known routes: {sorted(_ROUTE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_ROUTE_PARAMS[cell.route.path])
        class_name = f"Cell{_pascal_case(cell.cell_id)}"
        ctx["class_name"] = class_name
        # Cell-ID-derived, not `cell.route.path` directly: a vulnerable/
        # secure twin pair shares one semantic `route.path` (both illustrate
        # the same conceptual endpoint), so mapping both controllers to the
        # literal manifest path would make Spring Boot's handler-mapping
        # registration ambiguous at boot (two `@PostMapping`s on the same
        # method+path). Matches `go_net_http`'s own accumulator convention
        # (`/generated/{cell_id.lower()}`) exactly, for the same reason --
        # this stack has no accumulator step to do it in separately, so it
        # happens here in `render()` instead.
        ctx["path"] = f"/generated/{cell.cell_id.lower()}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["jackson_default_typing_deserialize"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: java_spring_boot has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)

        body = _indent_block(
            "\n".join((source_result.code, *transform_code_blocks, sink_result.code)),
            "        ",
        )
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        java_source = (
            f"package {GENERATED_PACKAGE};\n"
            "\n"
            f"// Generated by fuzzlab.labgen.emitters.java_spring_boot for cell {cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {composition}\n"
            "\n"
            "import com.fasterxml.jackson.databind.ObjectMapper;\n"
            "import com.fuzzlab.lab.PlaybackResumeRequest;\n"
            "import jakarta.servlet.http.HttpServletRequest;\n"
            "import java.io.IOException;\n"
            "import org.springframework.http.ResponseEntity;\n"
            "import org.springframework.web.bind.annotation.PostMapping;\n"
            "import org.springframework.web.bind.annotation.RestController;\n"
            "\n"
            f"{complexity_result.code}"
        )
        path = f"src/main/java/com/fuzzlab/lab/cells/{class_name}.java"
        return (EmittedFile(path=path, content=java_source.encode("utf-8"), role="controller"),)


def _pascal_case(cell_id: str) -> str:
    """``LABGEN-JV-0001`` -> ``LabgenJv0001`` -- a valid Java identifier
    fragment derived deterministically from the cell ID."""
    return "".join(part.capitalize() for part in cell_id.replace("_", "-").split("-"))


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free, same convention as every other stack's own
    ``_indent_block``."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
