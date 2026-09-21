"""Composable rendering modules (T-LAB0.4 / ``CR-LAB-0001`` Addendum C).

Per Addendum C's architecture correction, an emitter is built as **module
composition, not one template per cell**: a small inventory of independently
authored, independently testable ``source``/``transform``/``sink``/
``complexity``/``depth`` fragments (following NIST VTSG's schema, not its PHP
code) that an emitter assembles per :class:`~fuzzlab.labgen.schema.Cell`. This
keeps the unit of authoring effort at "a handful of modules" rather than
"one template per ``(class, sink_context, stack)`` combination."

This Phase-0 inventory started deliberately small -- enough to prove the
composition model end to end for one illustrative vulnerable/secure SQLi
pair -- and was then extended to cover a small **real** sample of Ryder's
Puppy Fort Factory's actual pages (``product.php``, ``blog_post.php``,
``login.php``, ``profile.php`` -- see
``fuzzlab.labgen.emitters.php_current``) spanning two vulnerability classes
and three sink-context shapes (a GET numeric-literal SQL lookup, a POST
string-literal SQL lookup, and a stored-value HTML-body echo), to prove the
module set generalizes beyond one illustrative pair. It is still not
exhaustive coverage of every vulnerability class -- authoring the rest of
the inventory for the full ~30-page app is separate, later work.

A fifth category, ``depth`` (``depths/``, registry :data:`DEPTHS`), was added
for the ``context_depth`` axis (§3.5, L-P2.5): the helper definition and call
site a ``same_file_helper``/``cross_file`` cell's tainted value travels
through. Deliberately its own category rather than extra ``transform`` ops --
``transform`` op names are the verdict-relevant vocabulary
``fuzzlab.labgen.verdict`` walks, and a depth hop must never appear there.

Every module is a small Jinja2-rendered unit. Per the Phase-0 plan's own
determinism rule, every :class:`jinja2.Environment` here sets
``trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True``
explicitly -- never Jinja2's defaults -- and templates are always given
already-computed, already-ordered values (never asked to iterate a raw
``dict``/``set``), so two renders of the same inputs are byte-identical.
"""

from __future__ import annotations

import re
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
_DEPTH_ENV = _make_env("depths")


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


class PostParamSource(TemplateModule):
    """Extracts one POST parameter into a PHP variable (e.g. ``login.php``'s
    ``username``) -- the same ``value_expr``/``bound`` contract as
    :class:`GetParamSource`, just a different request-data origin."""

    def __init__(self) -> None:
        super().__init__("post_param", "source", _SOURCE_ENV, "post_param.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class ReadStoredFieldSource(TemplateModule):
    """A source that is **not** a request parameter: reads an already-stored
    value (e.g. ``profile.php`` rendering a ``bio`` field written earlier by
    ``edit_profile.php``). Proves the module system generalizes beyond
    request-derived taint, which stored-XSS cells need -- the injection
    point (where the value is written) and the sink (where it is rendered)
    are different pages, matching ``CR-LAB-0001`` Addendum B's multi-artifact
    ground-truth shape (out of scope to model as two artifacts in this
    Phase-0 sample; this module renders the sink side only)."""

    def __init__(self) -> None:
        super().__init__("read_stored_field", "source", _SOURCE_ENV, "read_stored_field.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        return RenderResult(code=result.code, context=new_ctx)


class IdentityTransform(TemplateModule):
    """The empty-pipeline transform: the tainted value is used as-is. Used
    whenever a cell's ``transform`` pipeline has no ops. Family-agnostic --
    reused unchanged by both SQL and HTML sink cells."""

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


class HtmlEntityEscapeTransform(TemplateModule):
    """The ``html_entity_escape`` op: unlike :class:`ParamBindTransform`
    (which flags a downstream sink to change its execution shape), this
    transform wraps ``value_expr`` itself in ``htmlspecialchars(...)``,
    since HTML escaping is applied inline at the point of use, not deferred
    to a prepare/execute step -- a second, equally valid module-composition
    shape, demonstrated deliberately rather than forcing every transform
    through the SQL family's ``bound``-flag pattern."""

    def __init__(self) -> None:
        super().__init__("html_entity_escape", "transform", _TRANSFORM_ENV, "html_entity_escape.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"htmlspecialchars({ctx['value_expr']})"
        return RenderResult(code=result.code, context=new_ctx)


def _php_string_list(values: tuple[str, ...]) -> str:
    """Render an already-ordered tuple of identifiers as a PHP single-quoted
    list literal body (``'id', 'name'``).

    Deliberately takes a *tuple* and never sorts or de-duplicates: the
    determinism rule in this module's docstring is that templates are given
    already-computed, already-ordered values, and the author's own allowlist
    order is meaningful (its first element is the fallback identifier).
    Rejects a value that is not a bare identifier rather than emitting PHP
    that would need escaping -- an authoring gap fails loud here, exactly as
    it does in ``fuzzlab.labgen.verdict.SafetyMatrix.lookup``.
    """
    if not values:
        raise ValueError(
            "identifier allowlist is empty -- an allowlist transform with nothing "
            "allowed has no safe fallback to fall back to; supply the real "
            "identifiers in the emitter's page profile"
        )
    for value in values:
        if not re.fullmatch(r"[A-Za-z0-9_]+", value):
            raise ValueError(
                f"identifier allowlist entry {value!r} is not a bare identifier "
                "([A-Za-z0-9_]+) -- allowlisted identifiers are emitted into PHP "
                "source verbatim and are never escaped or quoted for you"
            )
    return ", ".join(f"'{value}'" for value in values)


class IdentifierCharsetFilterTransform(TemplateModule):
    """The ``identifier_charset_filter`` op: emits a guard *statement* (a
    ``preg_match`` bare-identifier check that 400s on mismatch) and leaves
    ``value_expr`` untouched.

    A third module-composition shape, alongside
    :class:`ParamBindTransform` (flags the sink) and
    :class:`HtmlEntityEscapeTransform` (wraps the expression): a transform
    whose whole effect is a guard emitted *before* the sink. That shape is
    what makes this op's ``partial`` safety-matrix effect legible in the
    generated code -- the filter is plainly there, and plainly does not
    restrict *which* identifier is used.
    """

    def __init__(self) -> None:
        super().__init__(
            "identifier_charset_filter", "transform", _TRANSFORM_ENV, "identifier_charset_filter.php.j2"
        )


class IdentifierAllowlistTransform(TemplateModule):
    """The ``identifier_allowlist`` op: rewrites ``value_expr`` into an
    ``in_array``-guarded expression that can only ever evaluate to one of
    the page profile's real identifiers (falling back to the first).

    Requires ``allowed_identifiers`` in the assembly context (an ordered
    tuple supplied by the emitter's own page profile -- render-only metadata
    the :class:`~fuzzlab.labgen.schema.Cell` IR deliberately does not
    carry). Raises rather than inventing a default allowlist: guessing which
    columns an endpoint may expose is precisely the decision this transform
    exists to make explicit.
    """

    def __init__(self) -> None:
        super().__init__("identifier_allowlist", "transform", _TRANSFORM_ENV, "identifier_allowlist.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        try:
            allowed = tuple(ctx["allowed_identifiers"])
        except KeyError as exc:
            raise ValueError(
                "identifier_allowlist transform needs an 'allowed_identifiers' context "
                "value (an ordered tuple of the real identifiers this endpoint may use) "
                "-- the emitter's page profile must supply it; there is no safe default"
            ) from exc
        allowed_php = _php_string_list(allowed)
        fallback_php = f"'{allowed[0]}'"
        value_expr = ctx["value_expr"]
        new_ctx = dict(ctx)
        new_ctx["allowed_identifiers_php"] = allowed_php
        new_ctx["fallback_identifier_php"] = fallback_php
        result = TemplateModule.render(self, new_ctx)
        new_ctx["value_expr"] = (
            f"(in_array((string) {value_expr}, [{allowed_php}], true) ? {value_expr} : {fallback_php})"
        )
        return RenderResult(code=result.code, context=new_ctx)


class UrlSchemeAllowlistTransform(TemplateModule):
    """The ``url_scheme_allowlist`` op: rewrites ``value_expr`` so a value
    whose URL scheme is not ``http``/``https`` collapses to an inert ``'#'``
    -- the escaping-context-*correct* fix for a ``javascript:``-URL sink,
    where :class:`HtmlEntityEscapeTransform` is the mismatch."""

    def __init__(self) -> None:
        super().__init__("url_scheme_allowlist", "transform", _TRANSFORM_ENV, "url_scheme_allowlist.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        value_expr = ctx["value_expr"]
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = (
            "(in_array(strtolower((string) parse_url((string) "
            f"{value_expr}, PHP_URL_SCHEME)), ['http', 'https'], true) ? {value_expr} : '#')"
        )
        return RenderResult(code=result.code, context=new_ctx)


class AttrValueAllowlistTransform(TemplateModule):
    """The ``attr_value_allowlist`` op: rewrites ``value_expr`` so only a
    strict ``^[A-Za-z0-9_-]+$`` value survives (otherwise a safe default
    from the page profile's ``attr_default``) -- the transform-only fix for
    an *unquoted* HTML attribute, whose boundary htmlspecialchars() does not
    protect."""

    def __init__(self) -> None:
        super().__init__("attr_value_allowlist", "transform", _TRANSFORM_ENV, "attr_value_allowlist.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        default = ctx.get("attr_default", "default")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", str(default)):
            raise ValueError(
                f"attr_default {default!r} does not itself satisfy the allowlist this "
                "transform enforces (^[A-Za-z0-9_-]+$) -- a fallback that would be "
                "rejected by the very check it backstops is an authoring error"
            )
        value_expr = ctx["value_expr"]
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = (
            f"(preg_match('/^[A-Za-z0-9_-]+$/', (string) {value_expr}) ? {value_expr} : '{default}')"
        )
        return RenderResult(code=result.code, context=new_ctx)


class SqlNumericLookupSink(TemplateModule):
    """A single-row lookup by a numeric-literal-position column. Branches on
    ``bound`` (published by a transform) to render either a raw
    concatenated query (vulnerable) or a prepared statement (secure) --
    the same sink fragment serves both twins of a minimal pair, since the
    only permitted difference between them is the transform region."""

    def __init__(self) -> None:
        super().__init__("sql_numeric_lookup", "sink", _SINK_ENV, "sql_numeric_lookup.php.j2")


class SqlStringLiteralLookupSink(TemplateModule):
    """A single-row lookup by a quoted-string-literal-position column, with
    a second, non-tainted, already-hashed condition (``login.php``'s
    password check) folded in as sink boilerplate -- the manifest cell's
    injection point is the string-literal column only. Branches on
    ``bound`` exactly like :class:`SqlNumericLookupSink`."""

    def __init__(self) -> None:
        super().__init__("sql_string_literal_lookup", "sink", _SINK_ENV, "sql_string_literal_lookup.php.j2")


class HtmlBodyEchoSink(TemplateModule):
    """Echoes ``value_expr`` into an HTML body position. Does not itself
    know or care whether ``value_expr`` was escaped upstream -- that is
    exactly what :class:`HtmlEntityEscapeTransform` (or its absence)
    determines, keeping this sink reusable across both twins of a pair."""

    def __init__(self) -> None:
        super().__init__("html_body_echo", "sink", _SINK_ENV, "html_body_echo.php.j2")


class SqlIdentifierOrderBySink(TemplateModule):
    """An ``ORDER BY <identifier>`` lookup: the tainted value *is* a column
    identifier, not a literal value (L-P1.2b / plan §2.2).

    Branches on ``bound`` like the literal-position sinks, but for the
    opposite reason: its ``bound`` branch shows a prepared statement binding
    an unrelated WHERE *value* while the identifier is still concatenated --
    the generated-code evidence for the safety matrix's
    ``(param_bind, sql_identifier) -> no_effect`` row. No dialect can bind an
    identifier placeholder, so "use a prepared statement" is inapplicable
    here rather than merely omitted.
    """

    def __init__(self) -> None:
        super().__init__("sql_identifier_order_by", "sink", _SINK_ENV, "sql_identifier_order_by.php.j2")


class SqlJoinAliasLookupSink(TemplateModule):
    """A JOIN-alias (connector-position) lookup: the tainted value is a table
    alias, substituted **three** times in one statement (projection, alias
    declaration, ``ON`` clause).

    The multi-substitution shape is the point: it is what makes a
    comment-based escape degenerate into ordinary statement truncation (see
    ``fuzzlab.labgen.identifier_sqli_oracle``'s spot-check finding #2) and
    what keeps a character filter only ``partial`` at this family.
    """

    def __init__(self) -> None:
        super().__init__("sql_join_alias_lookup", "sink", _SINK_ENV, "sql_join_alias_lookup.php.j2")


class HtmlJsUrlEchoSink(TemplateModule):
    """Echoes ``value_expr`` into the body of a ``javascript:`` URL inside a
    quoted ``href`` attribute -- the escaping-context-mismatch XSS shape
    (plan §2.2): the value sits in an HTML attribute but is *JavaScript
    source*, so HTML-entity escaping is correct escaping for the wrong
    context. Like every sink here it escapes nothing itself; the cell's
    transform decides."""

    def __init__(self) -> None:
        super().__init__("html_js_url_echo", "sink", _SINK_ENV, "html_js_url_echo.php.j2")


class HtmlAttributeUnquotedEchoSink(TemplateModule):
    """Echoes ``value_expr`` into an **unquoted** HTML attribute value, whose
    boundary is whitespace -- the second escaping-context-mismatch shape
    (the safety matrix has had its ``(html_entity_escape,
    html_attribute_unquoted) -> partial`` row since Phase 0; this is the
    module that finally renders it)."""

    def __init__(self) -> None:
        super().__init__("html_attribute_unquoted_echo", "sink", _SINK_ENV, "html_attribute_unquoted_echo.php.j2")


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


class RenderOnlyComplexity(TemplateModule):
    """A complexity wrapper for cells with no DB row to return -- e.g. an
    HTML-rendering cell whose body is just an ``echo``. Distinct from
    :class:`SingleStatementComplexity`, which always closes with
    ``return $row;``; this is the module system's own evidence that
    different sink shapes need different complexity wrappers, not one
    universal function template."""

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


class PassthroughHelperDepth(TemplateModule):
    """The function definition a ``same_file_helper``/``cross_file`` cell's
    tainted value travels through (§3.5, L-P2.5).

    A deliberately *pure pass-through*: it adds a hop to the flow (the shape
    the ``context_depth`` axis exists to vary, and the shape a taint-tracking
    tool has to follow) without adding a neutralization, so a cell's derived
    verdict stays a function of ``(transform, sink_context, safety_matrix)``
    alone (D20) at every depth. Its own category rather than a ``transform``
    module precisely because ``transform`` op names are the verdict-relevant
    vocabulary ``fuzzlab.labgen.verdict`` walks -- a depth hop must never
    appear there.
    """

    def __init__(self) -> None:
        super().__init__("passthrough_helper", "depth", _DEPTH_ENV, "passthrough_helper.php.j2")


class HelperCallDepth(TemplateModule):
    """The call site that routes the tainted value through the helper
    :class:`PassthroughHelperDepth` defines -- rendered between the source and
    the cell's own transform pipeline, so the value reaching the sink has
    provably passed through the helper."""

    def __init__(self) -> None:
        super().__init__("helper_call", "depth", _DEPTH_ENV, "helper_call.php.j2")


class CrossFileRequireDepth(TemplateModule):
    """The ``require_once`` that pulls in a ``cross_file`` cell's helper file.
    The only difference between ``same_file_helper`` and ``cross_file`` is
    where the helper definition lands (one file or two) -- the flow itself is
    identical, which is exactly what makes them a clean pair of depth levels
    for measuring a tool's cross-file reach."""

    def __init__(self) -> None:
        super().__init__("cross_file_require", "depth", _DEPTH_ENV, "cross_file_require.php.j2")


SOURCES: dict[str, Module] = {
    "get_param": GetParamSource(),
    "post_param": PostParamSource(),
    "read_stored_field": ReadStoredFieldSource(),
}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "param_bind": ParamBindTransform(),
    "html_entity_escape": HtmlEntityEscapeTransform(),
    # L-P1.2b (plan §2.2): the harder shapes' transform ops. Each name here
    # must also have a row for every sink family it is authored against in
    # lab/safety_matrix.yaml -- an op the emitter can render but the matrix
    # cannot score would derive no verdict at all (verdict() raises), which
    # tests/test_labgen_harder_shapes.py asserts against for real.
    "identifier_charset_filter": IdentifierCharsetFilterTransform(),
    "identifier_allowlist": IdentifierAllowlistTransform(),
    "url_scheme_allowlist": UrlSchemeAllowlistTransform(),
    "attr_value_allowlist": AttrValueAllowlistTransform(),
}
SINKS: dict[str, Module] = {
    "sql_numeric_lookup": SqlNumericLookupSink(),
    "sql_string_literal_lookup": SqlStringLiteralLookupSink(),
    "html_body_echo": HtmlBodyEchoSink(),
    # L-P1.2b: identifier/alias/connector-position SQL and
    # escaping-context-mismatch XSS sinks.
    "sql_identifier_order_by": SqlIdentifierOrderBySink(),
    "sql_join_alias_lookup": SqlJoinAliasLookupSink(),
    "html_js_url_echo": HtmlJsUrlEchoSink(),
    "html_attribute_unquoted_echo": HtmlAttributeUnquotedEchoSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "single_statement": SingleStatementComplexity(),
    "render_only": RenderOnlyComplexity(),
}
#: Depth-hop fragments (§3.5, L-P2.5). Keyed by fragment, not by depth level:
#: `same_file_helper` and `cross_file` share the same helper definition and
#: call site and differ only in file placement, and `direct`/
#: `stored_second_order` need no fragment at all (the first is today's inline
#: body; the second is already expressed by `Cell.sink_endpoint` routing
#: php_current to the sink page). Which fragments each level composes lives in
#: the emitter, next to the file-assembly decision it drives.
DEPTHS: dict[str, Module] = {
    "passthrough_helper": PassthroughHelperDepth(),
    "helper_call": HelperCallDepth(),
    "cross_file_require": CrossFileRequireDepth(),
}
