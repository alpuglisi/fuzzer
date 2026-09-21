"""Composable rendering modules (T-LAB0.4 / ``CR-LAB-0001`` Addendum C).

Per Addendum C's architecture correction, an emitter is built as **module
composition, not one template per cell**: a small inventory of independently
authored, independently testable ``source``/``transform``/``sink``/
``complexity`` fragments (following NIST VTSG's schema, not its PHP code)
that an emitter assembles per :class:`~fuzzlab.labgen.schema.Cell`. This
keeps the unit of authoring effort at "a handful of modules" rather than
"one template per ``(class, sink_context, stack)`` combination."

This Phase-0 inventory is deliberately small -- enough to prove the
composition model end to end for one illustrative vulnerable/secure SQLi
pair (a raw string-concatenation numeric-literal lookup and its
``param_bind``-secured twin) -- not exhaustive coverage of every
vulnerability class. Authoring the rest of the inventory is Phase 1/3 work.

Every module is a small Jinja2-rendered unit. Per the Phase-0 plan's own
determinism rule, every :class:`jinja2.Environment` here sets
``trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True``
explicitly -- never Jinja2's defaults -- and templates are always given
already-computed, already-ordered values (never asked to iterate a raw
``dict``/``set``), so two renders of the same inputs are byte-identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

MODULES_ROOT = Path(__file__).parent


def _make_env(subdir: str) -> Environment:
    """Build one Jinja2 environment scoped to a module category's own
    template directory, with the determinism-relevant flags always set
    explicitly (never left at Jinja2's defaults, per the Phase-0 plan)."""
    return Environment(
        loader=FileSystemLoader(str(MODULES_ROOT / subdir)),
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


@dataclass(frozen=True)
class RenderResult:
    """The code a module fragment rendered, plus the (possibly updated)
    assembly context passed on to the next module in the composition
    (e.g. a source module publishes ``value_expr``; a transform module may
    flag ``bound=True`` for a downstream sink to branch on)."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable rendering fragment.

    ``cardinality`` is fixed at ``"per_cell"`` for every module in this
    Phase-0 inventory -- ``CR-LAB-0001`` Addendum D reserves
    ``"per_stack"``/``"accumulator"``/``"per_fixture"`` for Phase 3's routed,
    multi-file emitters (a shared ``routes/web.php``-style file fed one
    fragment per cell); ``php_current`` needs none of those since today's PHP
    app is filesystem-routed with no central routes file.
    """

    name: str
    category: str
    cardinality: str = "per_cell"

    def render(self, ctx: dict[str, Any]) -> RenderResult:  # pragma: no cover - abstract
        raise NotImplementedError


class TemplateModule(Module):
    """A module whose rendering is exactly one Jinja2 template call. Most
    modules are this; a module that needs to publish new context keys for
    downstream modules subclasses this and overrides :meth:`render`."""

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
    """Extracts one GET parameter into a PHP variable and publishes
    ``value_expr`` (the PHP expression downstream modules read the tainted
    value from) and ``bound=False`` (the default, until a transform says
    otherwise) into the assembly context."""

    def __init__(self) -> None:
        super().__init__("get_param", "source", _SOURCE_ENV, "get_param.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class IdentityTransform(TemplateModule):
    """The empty-pipeline transform: the tainted value is used as-is. Used
    whenever a cell's ``transform`` pipeline has no ops."""

    def __init__(self) -> None:
        super().__init__("identity", "transform", _TRANSFORM_ENV, "identity.php.j2")


class ParamBindTransform(TemplateModule):
    """The ``param_bind`` op: flags the value as bound so the sink module
    renders a prepared-statement placeholder instead of concatenating the
    value into the SQL string."""

    def __init__(self) -> None:
        super().__init__("param_bind", "transform", _TRANSFORM_ENV, "param_bind.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["bound"] = True
        return RenderResult(code=result.code, context=new_ctx)


class SqlNumericLookupSink(TemplateModule):
    """A single-row lookup by a numeric-literal-position column. Branches on
    ``bound`` (published by a transform) to render either a raw
    concatenated query (vulnerable) or a prepared statement (secure) --
    the same sink fragment serves both twins of a minimal pair, since the
    only permitted difference between them is the transform region."""

    def __init__(self) -> None:
        super().__init__("sql_numeric_lookup", "sink", _SINK_ENV, "sql_numeric_lookup.php.j2")


class SingleStatementComplexity(TemplateModule):
    """The simplest complexity wrapper: the composed source/transform/sink
    body as the entire body of one function. Later complexity modules
    (Phase 1+) can introduce a file-count multiplier per ``CR-LAB-0001``
    Addendum D without this one changing."""

    def __init__(self) -> None:
        super().__init__("single_statement", "complexity", _COMPLEXITY_ENV, "single_statement.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {"get_param": GetParamSource()}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "param_bind": ParamBindTransform(),
}
SINKS: dict[str, Module] = {"sql_numeric_lookup": SqlNumericLookupSink()}
COMPLEXITIES: dict[str, Module] = {"single_statement": SingleStatementComplexity()}
