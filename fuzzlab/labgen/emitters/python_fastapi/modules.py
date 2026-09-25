"""Composable rendering modules for the ``python_fastapi`` emitter (L-P3.2).

Mirrors ``fuzzlab.labgen.modules``'s module-composition architecture
(``CR-LAB-0001`` Addendum C: a small inventory of independently authored,
independently testable ``source``/``transform``/``sink``/``complexity``
Jinja2 fragments an emitter composes per cell) but is a **fully independent
implementation**, scoped to this package -- not an extension of
``fuzzlab.labgen.modules`` (out of scope for this lane; see this package's
``__init__.py`` module docstring for why: every Phase 3 stack lane is
required to be independently buildable with zero cross-lane coordination
beyond not editing shared read-only files, and ``fuzzlab.labgen.modules``'s
``.php.j2`` templates and registries are PHP-specific, not generalizable to
Python source without editing that shared file).

Same determinism discipline as the PHP module system: every
:class:`jinja2.Environment` here sets ``trim_blocks=True,
lstrip_blocks=True, keep_trailing_newline=True`` explicitly, and templates
are only ever given already-computed, already-ordered values.

Op-name vocabulary is shared with ``lab/safety_matrix.yaml`` and with
``php_current``'s modules (``identity``/``param_bind``/``html_entity_escape``
as transform names) -- these are the generic, stack-agnostic op-name
vocabulary ``fuzzlab.labgen.verdict.verdict()`` looks up by
``(op, sink_context.family)``, not PHP-specific names; reusing them here is
required, not merely convenient, since ``verdict()`` derives the same label
for the same ``(pipeline, sink_context)`` regardless of stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_ROOT = Path(__file__).parent / "templates"


def _make_env(subdir: str) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_ROOT / subdir)),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        autoescape=False,
    )


SOURCE_ENV = _make_env("sources")
TRANSFORM_ENV = _make_env("transforms")
SINK_ENV = _make_env("sinks")
COMPLEXITY_ENV = _make_env("complexities")
SCAFFOLD_ENV = _make_env("scaffold")


@dataclass(frozen=True)
class RenderResult:
    code: str
    context: dict[str, Any]


class Module:
    name: str
    category: str
    cardinality: str = "per_cell"

    def render(self, ctx: dict[str, Any]) -> RenderResult:  # pragma: no cover - abstract
        raise NotImplementedError


class TemplateModule(Module):
    def __init__(self, name: str, category: str, env: Environment, template_name: str):
        self.name = name
        self.category = category
        self._env = env
        self._template_name = template_name

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(**ctx)
        return RenderResult(code=code, context=dict(ctx))


class GetParamSource(TemplateModule):
    """Extracts one query parameter via ``request.query_params.get(...)``
    (deliberately not a typed/coerced FastAPI path/query parameter -- a
    ``: int`` annotation would make FastAPI/Pydantic reject non-numeric
    input at the framework boundary before the handler body ever runs,
    closing off the numeric-literal SQLi shape this module exists to
    reproduce; manual ``request.query_params`` access is itself a real,
    common FastAPI anti-pattern, not a contrivance). Publishes
    ``value_expr``/``bound=False`` -- same contract as
    ``fuzzlab.labgen.modules.GetParamSource``."""

    def __init__(self) -> None:
        super().__init__("get_param", "source", SOURCE_ENV, "get_param.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class PostParamSource(TemplateModule):
    """Extracts one form field via ``await request.form()`` -- the POST-body
    analogue of :class:`GetParamSource`."""

    def __init__(self) -> None:
        super().__init__("post_param", "source", SOURCE_ENV, "post_param.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class ReadStoredFieldSource(TemplateModule):
    """A source that is **not** a request parameter -- reads an already
    resolved value (e.g. the stub ``current_user`` dict a stored-XSS cell's
    view reads). Mirrors ``fuzzlab.labgen.modules.ReadStoredFieldSource``."""

    def __init__(self) -> None:
        super().__init__("read_stored_field", "source", SOURCE_ENV, "read_stored_field.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        return RenderResult(code=result.code, context=new_ctx)


class IdentityTransform(TemplateModule):
    def __init__(self) -> None:
        super().__init__("identity", "transform", TRANSFORM_ENV, "identity.py.j2")


class ParamBindTransform(TemplateModule):
    def __init__(self) -> None:
        super().__init__("param_bind", "transform", TRANSFORM_ENV, "param_bind.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["bound"] = True
        return RenderResult(code=result.code, context=new_ctx)


class HtmlEntityEscapeTransform(TemplateModule):
    def __init__(self) -> None:
        super().__init__("html_entity_escape", "transform", TRANSFORM_ENV, "html_entity_escape.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"html.escape({ctx['value_expr']})"
        return RenderResult(code=result.code, context=new_ctx)


class SqlNumericLookupSink(TemplateModule):
    def __init__(self) -> None:
        super().__init__("sql_numeric_lookup", "sink", SINK_ENV, "sql_numeric_lookup.py.j2")


class SqlStringLiteralLookupSink(TemplateModule):
    def __init__(self) -> None:
        super().__init__("sql_string_literal_lookup", "sink", SINK_ENV, "sql_string_literal_lookup.py.j2")


class HtmlBodyEchoSink(TemplateModule):
    def __init__(self) -> None:
        super().__init__("html_body_echo", "sink", SINK_ENV, "html_body_echo.py.j2")


class SingleStatementComplexity(TemplateModule):
    def __init__(self) -> None:
        super().__init__("single_statement", "complexity", COMPLEXITY_ENV, "single_statement.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        # CC-LAB-0246: the HTML detail view's heading (the route's nav label).
        extra = {"nav_label": ctx["nav_label"]} if "nav_label" in ctx else {}
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"], **extra)
        return RenderResult(code=code, context=dict(ctx))


class RenderOnlyComplexity(TemplateModule):
    def __init__(self) -> None:
        super().__init__("render_only", "complexity", COMPLEXITY_ENV, "render_only.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "get_param": GetParamSource(),
    "post_param": PostParamSource(),
    "read_stored_field": ReadStoredFieldSource(),
}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "param_bind": ParamBindTransform(),
    "html_entity_escape": HtmlEntityEscapeTransform(),
}
SINKS: dict[str, Module] = {
    "sql_numeric_lookup": SqlNumericLookupSink(),
    "sql_string_literal_lookup": SqlStringLiteralLookupSink(),
    "html_body_echo": HtmlBodyEchoSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "single_statement": SingleStatementComplexity(),
    "render_only": RenderOnlyComplexity(),
}
