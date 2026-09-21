"""Composable JS rendering modules for the ``node_express`` emitter (L-P3.1).

Mirrors ``fuzzlab.labgen.modules``' module-composition shape (source/
transform/sink/complexity categories, a ``Module``/``TemplateModule`` base
pair, an explicit-flags Jinja2 environment per category) exactly, per
``CR-LAB-0001`` Addendum C's instruction to reuse ``php_current``'s module
*categories* as the porting template. The actual code is new: this module
owns its own template directory and its own registries, entirely inside
``fuzzlab/labgen/emitters/node_express/`` -- it does not import from or
register into ``fuzzlab.labgen.modules`` (that package's registries are
PHP/Jinja2-specific and out of this lane's scope to edit, per the task's
scope-discipline instructions).

Tier-A scope only (per the pacing decision in
``docs/LAB_IMPLEMENTATION_PLAN.md`` Sec 4): the three well-documented,
value-context shapes already proven on ``php_current`` --
``sql_numeric_literal`` SQLi, ``sql_string_literal`` SQLi, ``html_body``
reflected XSS. No identifier/alias/connector-position SQLi or escaping-
context-mismatch XSS modules exist here -- those stay deferred for this
stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_ROOT = Path(__file__).parent / "templates"


def _make_env(subdir: str) -> Environment:
    """Same determinism-relevant flags as ``fuzzlab.labgen.modules._make_env``,
    set explicitly rather than left at Jinja2's defaults, so two renders of
    the same inputs are byte-identical (NFR-LAB-reproducible)."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_ROOT / subdir)),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        autoescape=False,
    )


_SOURCE_ENV = _make_env("sources")
_TRANSFORM_ENV = _make_env("transforms")
_SINK_ENV = _make_env("sinks")
_COMPLEXITY_ENV = _make_env("complexities")
_ROUTE_ENV = _make_env(".")  # route.js.j2 lives directly under templates/


@dataclass(frozen=True)
class RenderResult:
    """Same shape as ``fuzzlab.labgen.modules.RenderResult``: the rendered
    code plus the (possibly updated) assembly context passed to the next
    module."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable JS rendering fragment. ``cardinality``
    is ``"per_cell"`` for every module in this inventory except the route
    accumulator, which is rendered separately by
    :func:`render_route_accumulator` in ``__init__.py`` (cardinality
    ``"accumulator"`` per ``CR-LAB-0001`` Addendum D) rather than through
    this per-cell registry."""

    name: str
    category: str
    cardinality: str = "per_cell"

    def render(self, ctx: dict[str, Any]) -> RenderResult:  # pragma: no cover - abstract
        raise NotImplementedError


class TemplateModule(Module):
    """A module whose rendering is exactly one Jinja2 template call."""

    def __init__(self, name: str, category: str, env: Environment, template_name: str):
        self.name = name
        self.category = category
        self._env = env
        self._template_name = template_name

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(**ctx)
        return RenderResult(code=code, context=dict(ctx))


class GetQueryParamSource(TemplateModule):
    """Extracts one Express ``req.query`` parameter and publishes
    ``value_expr``/``bound=False`` -- the Express analogue of
    ``fuzzlab.labgen.modules.GetParamSource``."""

    def __init__(self) -> None:
        super().__init__("get_query_param", "source", _SOURCE_ENV, "get_query_param.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class PostBodyParamSource(TemplateModule):
    """Extracts one Express ``req.body`` parameter -- the Express analogue
    of ``fuzzlab.labgen.modules.PostParamSource``."""

    def __init__(self) -> None:
        super().__init__("post_body_param", "source", _SOURCE_ENV, "post_body_param.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class ReadStoredFieldSource(TemplateModule):
    """Reads an already-stored value rather than a request parameter -- the
    Express analogue of ``fuzzlab.labgen.modules.ReadStoredFieldSource``,
    used for the ``html_body`` stored-XSS shape's sink side."""

    def __init__(self) -> None:
        super().__init__("read_stored_field", "source", _SOURCE_ENV, "read_stored_field.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        return RenderResult(code=result.code, context=new_ctx)


class IdentityTransform(TemplateModule):
    """The empty-pipeline transform: the tainted value used as-is."""

    def __init__(self) -> None:
        super().__init__("identity", "transform", _TRANSFORM_ENV, "identity.js.j2")


class ParamBindTransform(TemplateModule):
    """The ``param_bind`` op: flags the value as bound so the sink renders a
    parameterized ``mysql2`` query instead of concatenating the value into
    SQL text."""

    def __init__(self) -> None:
        super().__init__("param_bind", "transform", _TRANSFORM_ENV, "param_bind.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["bound"] = True
        return RenderResult(code=result.code, context=new_ctx)


class HtmlEntityEscapeTransform(TemplateModule):
    """The ``html_entity_escape`` op: wraps ``value_expr`` in a call to
    ``escapeHtml`` (a small, fixed helper this emitter's ``render()``
    includes unconditionally in every generated controller's header --
    see ``__init__.py`` -- since JS has no built-in equivalent of PHP's
    ``htmlspecialchars()``). Applied inline at the point of use, exactly
    like ``fuzzlab.labgen.modules.HtmlEntityEscapeTransform``."""

    def __init__(self) -> None:
        super().__init__("html_entity_escape", "transform", _TRANSFORM_ENV, "html_entity_escape.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"escapeHtml({ctx['value_expr']})"
        return RenderResult(code=result.code, context=new_ctx)


class SqlNumericLookupSink(TemplateModule):
    """A single-row lookup by a numeric-literal-position column, via
    ``mysql2/promise``'s ``pool.query``. Branches on ``bound`` (published by
    a transform) exactly like ``fuzzlab.labgen.modules.SqlNumericLookupSink``."""

    def __init__(self) -> None:
        super().__init__("sql_numeric_lookup", "sink", _SINK_ENV, "sql_numeric_lookup.js.j2")


class SqlStringLiteralLookupSink(TemplateModule):
    """A single-row lookup by a quoted-string-literal-position column, with
    a second, non-tainted, already-hashed condition (a login-style password
    check) folded in as sink boilerplate -- the Express analogue of
    ``fuzzlab.labgen.modules.SqlStringLiteralLookupSink``."""

    def __init__(self) -> None:
        super().__init__("sql_string_literal_lookup", "sink", _SINK_ENV, "sql_string_literal_lookup.js.j2")


class HtmlBodyEchoSink(TemplateModule):
    """Writes ``value_expr`` into an HTML response body via ``res.send``.
    Does not itself know or care whether ``value_expr`` was escaped
    upstream -- the Express analogue of
    ``fuzzlab.labgen.modules.HtmlBodyEchoSink``."""

    def __init__(self) -> None:
        super().__init__("html_body_echo", "sink", _SINK_ENV, "html_body_echo.js.j2")


class SingleStatementComplexity(TemplateModule):
    """Wraps the composed source/transform/sink body as the entire body of
    one async Express handler that responds with the looked-up row --
    the Express analogue of
    ``fuzzlab.labgen.modules.SingleStatementComplexity``."""

    def __init__(self) -> None:
        super().__init__("single_statement", "complexity", _COMPLEXITY_ENV, "single_statement.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


class RenderOnlyComplexity(TemplateModule):
    """A complexity wrapper for cells with no DB row to return -- the
    Express analogue of ``fuzzlab.labgen.modules.RenderOnlyComplexity``,
    used by the ``html_body`` XSS shape."""

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "get_query_param": GetQueryParamSource(),
    "post_body_param": PostBodyParamSource(),
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


def render_route_line(*, method: str, path: str, handler_module: str) -> str:
    """Render one ``app.js`` route-registration line (the ``route``-category
    accumulator fragment, ``CR-LAB-0001`` Addendum D). Kept as a pure,
    single-purpose function -- not a class -- since a route line has no
    downstream context to publish, unlike the per-cell modules above."""
    template = _ROUTE_ENV.get_template("route.js.j2")
    return template.render(method=method.lower(), path=path, handler_module=handler_module)
