"""Composable Rails rendering modules for the ``ruby_rails`` emitter (Phase A
foundation only -- see this package's ``__init__.py`` module docstring for
scope: the actual vulnerability module inventory, CWE-915/502/webhook-
signature idioms Shopify's own research (``docs/research/site-architecture-
survey-functionality-shopify.md``) shortlisted, is explicitly a later, separate
lane's work).

Mirrors :mod:`fuzzlab.labgen.modules`' composition shape (the
``source``/``transform``/``sink``/``complexity`` categories, a
``Module``/``TemplateModule`` base pair, one explicit-flags Jinja2
environment per category) and reuses that shared vocabulary's module *names*
(``get_param``, ``identity``, ``html_entity_escape``, ``html_body_echo``,
``render_only``) exactly, per the same reasoning
``fuzzlab.labgen.emitters.php_laravel.modules`` documents for Laravel: the
shared minimal-pair checker (:mod:`fuzzlab.labgen.minimal_pair`) classifies
a cell's provenance line by looking each name up in
:mod:`fuzzlab.labgen.modules`' registries, so a new stack that wants to be
minimal-pair-checkable some day must speak that vocabulary from the start,
even though this Phase A dispatch does not yet wire this emitter into that
checker.

Only the one shape this dispatch's illustrative cell needs is registered
here (``("xss", "html_body")``) -- deepening this inventory to the other
shapes ``php_current``/``php_laravel`` support, and to the Rails-specific
CWE-915 (``permit!``)/CWE-502 (unsafe ``Marshal.load``/``YAML.unsafe_load``)/
webhook-signature idioms the plan's Shopify research names, is Phase B's
explicit, separate scope.

Determinism: the one :class:`jinja2.Environment` this module builds sets
``trim_blocks``, ``lstrip_blocks`` and ``keep_trailing_newline`` explicitly
(never Jinja2's defaults) and templates are handed already-computed values,
so two renders of the same inputs are byte-identical (NFR-LAB-reproducible).
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


_SOURCE_ENV = _make_env("sources")
_TRANSFORM_ENV = _make_env("transforms")
_SINK_ENV = _make_env("sinks")
_COMPLEXITY_ENV = _make_env("complexities")


@dataclass(frozen=True)
class RenderResult:
    """Same shape as :class:`fuzzlab.labgen.modules.RenderResult`: the
    rendered code plus the (possibly updated) assembly context handed to the
    next module in the composition."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable Rails rendering fragment. Every module
    in this Phase A registry is ``"per_cell"`` cardinality; the one
    ``"accumulator"``-cardinality module of this stack (``config/routes.rb``)
    lives in :mod:`fuzzlab.labgen.emitters.ruby_rails.route_accumulator`,
    mirroring ``php_laravel``'s ``CR-LAB-0001`` Addendum D split."""

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
        self.template_name = template_name

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self.template_name)
        code = template.render(**ctx)
        return RenderResult(code=code, context=dict(ctx))


# --- sources ----------------------------------------------------------------


class GetParamSource(TemplateModule):
    """One query-string parameter read through Rails' ``params`` accessor
    (``params[:id]``), publishing ``value_expr``/``bound=False`` -- the Rails
    analogue of ``fuzzlab.labgen.modules.GetParamSource``'s ``$_GET`` read /
    ``php_laravel``'s ``$request->query(...)``."""

    def __init__(self) -> None:
        super().__init__("get_param", "source", _SOURCE_ENV, "get_param.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


# --- transforms ---------------------------------------------------------------


class IdentityTransform(TemplateModule):
    """No-op transform: the tainted value reaches the sink unmodified."""

    def __init__(self) -> None:
        super().__init__("identity", "transform", _TRANSFORM_ENV, "identity.rb.j2")


class HtmlEntityEscapeTransform(TemplateModule):
    """HTML-entity-escapes the value (``ERB::Util.html_escape``) before the
    sink -- the Rails analogue of Laravel's ``e()``/PHP's
    ``htmlspecialchars()`` transform. Registered for parity with the shared
    module vocabulary; Phase A's own illustrative test does not render the
    secure twin, but a future secure-twin cell of the same shape can use it
    without adding a module this stack does not yet know."""

    def __init__(self) -> None:
        super().__init__("html_entity_escape", "transform", _TRANSFORM_ENV, "html_entity_escape.rb.j2")


# --- sinks --------------------------------------------------------------------


class HtmlBodyEchoSink(TemplateModule):
    """The view-body fragment for an HTML-body sink. Renders with ERB's
    ``raw`` on purpose: a sink never escapes anything itself (the same
    invariant ``php_laravel``'s ``html_body_echo.blade.php.j2`` documents),
    so both twins of a future minimal pair can share this exact view
    fragment and the cell's transform region alone decides whether the value
    was escaped before it got here."""

    def __init__(self) -> None:
        super().__init__("html_body_echo", "sink", _SINK_ENV, "html_body_echo.erb.j2")


# --- complexities ---------------------------------------------------------------


class RenderOnlyComplexity(TemplateModule):
    """Wraps a source + transform(s) into one controller action body that
    assigns ``@value`` and renders the paired view -- the Rails analogue of
    ``php_laravel``'s ``render_only.php.j2`` (a ``return view(...)`` action).
    """

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.rb.j2")


SOURCES: dict[str, Module] = {"get_param": GetParamSource()}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "html_entity_escape": HtmlEntityEscapeTransform(),
}
SINKS: dict[str, Module] = {"html_body_echo": HtmlBodyEchoSink()}
COMPLEXITIES: dict[str, Module] = {"render_only": RenderOnlyComplexity()}
