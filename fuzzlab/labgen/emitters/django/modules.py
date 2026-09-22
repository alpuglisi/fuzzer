"""Composable Python/Django rendering modules for the ``django`` emitter
(category 2 pilot, `CC-LAB-0090`).

Mirrors ``fuzzlab.labgen.modules``' module-composition shape (source/
transform/sink/complexity categories, a ``Module``/``TemplateModule`` base
pair, an explicit-flags Jinja2 environment per category) exactly, following
``fuzzlab.labgen.emitters.node_express.modules``' own port of that shape as
the closer structural template (both are Tier-A/Phase-A-scoped ports, unlike
``php_laravel``'s full-depth build) -- per ``CR-LAB-0001`` Addendum C's
instruction to reuse the module *categories* as the porting template, never
the rendered code itself. This module owns its own template directory and
its own registries entirely inside
``fuzzlab/labgen/emitters/django/`` -- it does not import from or register
into ``fuzzlab.labgen.modules`` or any sibling emitter's own registry.

**Phase A scope only** (`CC-LAB-0090`): exactly the one shape --
``sqli``/``sql_numeric_literal`` -- that ``php_laravel``'s own L-P3.3a
foundation lane and ``node_express``'s Phase A plan both picked as the first
shape to prove the scaffold end to end. The full module-inventory depth
(mirroring ``node_express``'s own three Tier-A shapes, let alone
``php_laravel``'s full nine) is explicitly out of scope here -- a separate,
later Phase B.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_ROOT = Path(__file__).parent / "templates"


def _make_env(subdir: str) -> Environment:
    """Same determinism-relevant flags as ``fuzzlab.labgen.modules._make_env``
    and ``node_express.modules._make_env``, set explicitly rather than left
    at Jinja2's defaults, so two renders of the same inputs are
    byte-identical (NFR-LAB-reproducible)."""
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
_ROUTE_ENV = _make_env(".")  # route.py.j2 lives directly under templates/


@dataclass(frozen=True)
class RenderResult:
    """Same shape as ``fuzzlab.labgen.modules.RenderResult``: the rendered
    code plus the (possibly updated) assembly context passed to the next
    module."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable Python rendering fragment.
    ``cardinality`` is ``"per_cell"`` for every module in this inventory
    except the route accumulator, which is rendered separately by
    :meth:`~fuzzlab.labgen.emitters.django.DjangoEmitter.render_route_accumulator`
    (cardinality ``"accumulator"`` per ``CR-LAB-0001`` Addendum D)."""

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


class GetParamSource(TemplateModule):
    """Extracts one Django ``request.GET`` parameter and publishes
    ``value_expr``/``bound=False`` -- the Django analogue of
    ``fuzzlab.labgen.modules.GetParamSource``."""

    def __init__(self) -> None:
        super().__init__("get_param", "source", _SOURCE_ENV, "get_param.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class IdentityTransform(TemplateModule):
    """The empty-pipeline transform: the tainted value used as-is."""

    def __init__(self) -> None:
        super().__init__("identity", "transform", _TRANSFORM_ENV, "identity.py.j2")


class ParamBindTransform(TemplateModule):
    """The ``param_bind`` op: flags the value as bound so the sink renders a
    parameterized ``cursor.execute()`` placeholder instead of concatenating
    the value into SQL text."""

    def __init__(self) -> None:
        super().__init__("param_bind", "transform", _TRANSFORM_ENV, "param_bind.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["bound"] = True
        return RenderResult(code=result.code, context=new_ctx)


class SqlNumericLookupSink(TemplateModule):
    """A single-row lookup by a numeric-literal-position column, via
    Django's ``connection.cursor()`` (deliberately the raw DB-API cursor,
    never the ORM, on *both* twins -- the vulnerable/secure distinction is
    string concatenation vs. a parameterized ``%s`` placeholder, exactly the
    same axis ``php_current``/``node_express`` already prove; not "ORM vs.
    raw SQL," which would confound two different variables). Branches on
    ``bound`` (published by a transform), same contract as
    ``fuzzlab.labgen.modules.SqlNumericLookupSink``/
    ``node_express.modules.SqlNumericLookupSink``."""

    def __init__(self) -> None:
        super().__init__("sql_numeric_lookup", "sink", _SINK_ENV, "sql_numeric_lookup.py.j2")


class SingleStatementComplexity(TemplateModule):
    """Wraps the composed source/transform/sink body as the entire body of
    one Django function-based view that responds with the looked-up row --
    the Django analogue of
    ``fuzzlab.labgen.modules.SingleStatementComplexity``/
    ``node_express.modules.SingleStatementComplexity``."""

    def __init__(self) -> None:
        super().__init__("single_statement", "complexity", _COMPLEXITY_ENV, "single_statement.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "get_param": GetParamSource(),
}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "param_bind": ParamBindTransform(),
}
SINKS: dict[str, Module] = {
    "sql_numeric_lookup": SqlNumericLookupSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "single_statement": SingleStatementComplexity(),
}


def render_route_import_line(*, handler_module: str, handler_name: str) -> str:
    """Render one ``urls.py`` accumulator import line (the ``route``-category
    accumulator fragment's import half, ``CR-LAB-0001`` Addendum D). Kept as
    a pure, single-purpose function -- not a class -- mirroring
    ``node_express.modules.render_route_line``; the ``urlpatterns`` entry
    half is built directly in
    :meth:`~fuzzlab.labgen.emitters.django.DjangoEmitter.render_route_accumulator`
    (Django's ``path(...)`` call needs no template of its own -- it is one
    deterministic f-string, the same judgment call ``node_express`` made for
    parts of ``app.js`` it did not template)."""
    template = _ROUTE_ENV.get_template("route.py.j2")
    return template.render(handler_module=handler_module, handler_name=handler_name)
