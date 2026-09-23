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

CC-LAB-0070 adds one genuinely new, JS/Node-runtime-specific shape on top of
that Tier-A baseline: ``prototype_pollution``/``object_property_bulk_set``
(CWE-1321) -- an unguarded recursive merge of a JSON request body onto a
live object, letting a ``__proto__``/``constructor``/``prototype`` key
escape the target object and land on the shared ``Object.prototype`` chain.
Node/Express's own npm-ecosystem CVE history (lodash ``merge`` et al.) is
this stack's own well-documented shape for this class, per the Walmart
functionality/CWE research this addition is grounded in (see
``docs/research/site-architecture-survey-functionality-walmart.md``).

CC-LAB-0076 adds a second, unrelated, genuinely new JS/Node-runtime-specific
shape: ``redos``/``regex_highlight_match`` (CWE-1333) -- a search/highlight
endpoint that builds a ``RegExp`` straight from a user-supplied search term.
The vulnerable transform (``unescaped_regex_construct``) interpolates the
raw term with no escaping, so an attacker-supplied pathological pattern
(e.g. ``(a+)+$``) causes catastrophic backtracking against the endpoint's
content; the secure transform (``regex_escape_construct``) escapes regex
metacharacters first, so the term can only ever match itself literally.
Distinct from ``object_property_bulk_set`` in the mechanism (regex-engine
backtracking, not the prototype chain) but the same "genuinely new,
JS-runtime-specific shape on top of the Tier-A baseline" category. See
``docs/research/site-architecture-survey-functionality-walmart.md`` for the
grounding research (CVE-2024-45296, ``path-to-regexp``) and
``docs/architecture/oracle-confirmation.md`` for the timing-differential
(M1) oracle mechanism this shape needed and that this addition builds.
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


class PostBodyJsonSource(TemplateModule):
    """Extracts the WHOLE JSON request body (not one named field) -- the
    Express analogue of ``fuzzlab.labgen.modules.AllPostParamsSource``,
    needed for the ``object_property_bulk_set`` (prototype-pollution) sink
    family (CC-LAB-0070), which needs the whole tainted key/value map to
    decide what a recursive merge writes."""

    def __init__(self) -> None:
        super().__init__("post_body_json", "source", _SOURCE_ENV, "post_body_json.js.j2")

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


class UnguardedDeepMergeTransform(TemplateModule):
    """The ``unguarded_deep_merge`` op (CC-LAB-0070, ``proto_pollution``
    concern): recursively merges ``value_expr``'s own keys onto a live
    target object (``target_var``/``target_literal``, supplied by the
    emitter's own route profile -- render-only metadata, same convention as
    ``RuntimeFieldAllowlistTransform``'s ``allowed_fields``) with no check
    that a key is ``__proto__``/``constructor``/``prototype``. Safety
    matrix: ``effect=no_effect`` (the vulnerable twin). Publishes
    ``value_expr = 'mergedPreferences'`` for the sink."""

    def __init__(self) -> None:
        super().__init__("unguarded_deep_merge", "transform", _TRANSFORM_ENV, "unguarded_deep_merge.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        for key in ("target_var", "target_literal"):
            if key not in ctx:
                raise ValueError(
                    f"unguarded_deep_merge transform needs a {key!r} context value "
                    "(the live object this endpoint merges onto) -- the emitter's "
                    "route profile must supply it; there is no safe default"
                )
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = "mergedPreferences"
        return RenderResult(code=result.code, context=new_ctx)


class ProtoKeyFilteredMergeTransform(TemplateModule):
    """The ``proto_key_filtered_merge`` op (CC-LAB-0070): the same recursive
    merge as :class:`UnguardedDeepMergeTransform`, except every
    ``__proto__``/``constructor``/``prototype`` key is skipped before it is
    ever written onto the target object. Safety matrix:
    ``effect=neutralises``, ``neutralizes: [proto_pollution]``."""

    def __init__(self) -> None:
        super().__init__(
            "proto_key_filtered_merge", "transform", _TRANSFORM_ENV, "proto_key_filtered_merge.js.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        for key in ("target_var", "target_literal"):
            if key not in ctx:
                raise ValueError(
                    f"proto_key_filtered_merge transform needs a {key!r} context value "
                    "(the live object this endpoint merges onto) -- the emitter's "
                    "route profile must supply it; there is no safe default"
                )
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = "mergedPreferences"
        return RenderResult(code=result.code, context=new_ctx)


class UnescapedRegexConstructTransform(TemplateModule):
    """The ``unescaped_regex_construct`` op (CC-LAB-0076, ``redos`` concern,
    CWE-1333): builds a ``RegExp`` directly from ``value_expr`` (the raw
    user-supplied search term) with no escaping, so a pathological pattern
    causes catastrophic backtracking against the content it is later
    matched over. Safety matrix: ``effect=no_effect`` (the vulnerable
    twin). Publishes ``value_expr = 'highlightRegex'`` for the sink, the
    same "transform builds the dangerous expression under a fixed name"
    convention :class:`UnguardedDeepMergeTransform` established."""

    def __init__(self) -> None:
        super().__init__(
            "unescaped_regex_construct", "transform", _TRANSFORM_ENV, "unescaped_regex_construct.js.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = "highlightRegex"
        return RenderResult(code=result.code, context=new_ctx)


class RegexEscapeConstructTransform(TemplateModule):
    """The ``regex_escape_construct`` op (CC-LAB-0076): the secure twin of
    :class:`UnescapedRegexConstructTransform` -- escapes every regex
    metacharacter in ``value_expr`` via the ``escapeRegExp`` helper (see
    ``__init__.py``, included unconditionally in every generated
    controller, same convention as ``escapeHtml``) before building the
    ``RegExp``, so the term can only ever match itself literally. Safety
    matrix: ``effect=neutralises``, ``neutralizes: [redos]``."""

    def __init__(self) -> None:
        super().__init__(
            "regex_escape_construct", "transform", _TRANSFORM_ENV, "regex_escape_construct.js.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = "highlightRegex"
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


class ObjectPropertyBulkSetSink(TemplateModule):
    """The ``object_property_bulk_set`` sink family (CC-LAB-0070,
    ``proto_pollution`` concern): responds with the merged object built by
    whichever merge transform ran upstream. Never itself decides which keys
    are legitimate -- like every other sink here, that is the transform's
    job (``unguarded_deep_merge`` vs. ``proto_key_filtered_merge``); this
    sink just serializes whatever ``value_expr`` resolves to."""

    def __init__(self) -> None:
        super().__init__("object_property_bulk_set", "sink", _SINK_ENV, "object_property_bulk_set.js.j2")


class RegexHighlightMatchSink(TemplateModule):
    """The ``regex_highlight_match`` sink family (CC-LAB-0076, ``redos``
    concern): highlights matches of ``highlightRegex`` (built by whichever
    transform ran upstream) inside a fixed content string and responds with
    the result. Never itself decides which characters were escaped -- like
    every other sink here, that is the transform's job (
    ``unescaped_regex_construct`` vs. ``regex_escape_construct``); this
    sink just applies whatever ``value_expr`` resolves to. Requires
    ``content_literal`` in the assembly context (the emitter's route
    profile's render-only metadata, same convention as
    ``UnguardedDeepMergeTransform``'s ``target_literal``) -- there is no
    safe default for what content a search/highlight endpoint serves."""

    def __init__(self) -> None:
        super().__init__("regex_highlight_match", "sink", _SINK_ENV, "regex_highlight_match.js.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        if "content_literal" not in ctx:
            raise ValueError(
                "regex_highlight_match sink needs a 'content_literal' context value "
                "(the fixed content this endpoint searches/highlights) -- the emitter's "
                "route profile must supply it; there is no safe default"
            )
        return super().render(ctx)


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
    # CC-LAB-0070: prototype-pollution's whole-body source (vs. one named
    # field).
    "post_body_json": PostBodyJsonSource(),
}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "param_bind": ParamBindTransform(),
    "html_entity_escape": HtmlEntityEscapeTransform(),
    # CC-LAB-0070: prototype-pollution ops (lab/safety_matrix.yaml's
    # object_property_bulk_set rows).
    "unguarded_deep_merge": UnguardedDeepMergeTransform(),
    "proto_key_filtered_merge": ProtoKeyFilteredMergeTransform(),
    # CC-LAB-0076: ReDoS ops (lab/safety_matrix.yaml's regex_highlight_match
    # rows).
    "unescaped_regex_construct": UnescapedRegexConstructTransform(),
    "regex_escape_construct": RegexEscapeConstructTransform(),
}
SINKS: dict[str, Module] = {
    "sql_numeric_lookup": SqlNumericLookupSink(),
    "sql_string_literal_lookup": SqlStringLiteralLookupSink(),
    "html_body_echo": HtmlBodyEchoSink(),
    # CC-LAB-0070: prototype-pollution's sink family.
    "object_property_bulk_set": ObjectPropertyBulkSetSink(),
    # CC-LAB-0076: ReDoS's sink family.
    "regex_highlight_match": RegexHighlightMatchSink(),
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
