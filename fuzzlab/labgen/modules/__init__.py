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


class AllPostParamsSource(TemplateModule):
    """Extracts the WHOLE ``$_POST`` array (not one named parameter) into a
    PHP variable and publishes it as ``value_expr`` -- the mass-assignment
    family's source shape (``orm_entity_bulk_assign``, CC-LAB-0064).
    ``GetParamSource``/``PostParamSource`` both extract exactly one named
    parameter, the wrong shape for a bulk-assignment sink, which needs the
    whole tainted key/value map to decide which fields get written."""

    def __init__(self) -> None:
        super().__init__("all_post_params", "source", _SOURCE_ENV, "all_post_params.php.j2")

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


class UnfilteredBodyUpdateTransform(TemplateModule):
    """The ``unfiltered_body_update`` op (CC-LAB-0064, `mass_assignment`
    concern): ``value_expr`` passes through unchanged -- every key in the
    whole tainted array reaches the sink, including any the endpoint never
    intended to accept. Safety matrix: ``effect=no_effect`` (the vulnerable
    twin)."""

    def __init__(self) -> None:
        super().__init__(
            "unfiltered_body_update", "transform", _TRANSFORM_ENV, "unfiltered_body_update.php.j2"
        )


class RuntimeFieldAllowlistTransform(TemplateModule):
    """The ``runtime_field_allowlist`` op (CC-LAB-0064, `mass_assignment`
    concern): rewrites ``value_expr`` to only the keys also present in
    ``allowed_fields`` (an ordered tuple the emitter's own page profile
    supplies -- mirrors :class:`IdentifierAllowlistTransform`'s
    ``allowed_identifiers`` context-key convention exactly, including its
    "raise rather than invent a default allowlist" design). Safety matrix:
    ``effect=neutralises``, ``neutralizes: [mass_assignment]``."""

    def __init__(self) -> None:
        super().__init__(
            "runtime_field_allowlist", "transform", _TRANSFORM_ENV, "runtime_field_allowlist.php.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        try:
            allowed = tuple(ctx["allowed_fields"])
        except KeyError as exc:
            raise ValueError(
                "runtime_field_allowlist transform needs an 'allowed_fields' context "
                "value (an ordered tuple of the real fields this endpoint may update) "
                "-- the emitter's page profile must supply it; there is no safe default"
            ) from exc
        allowed_php = _php_string_list(allowed)
        value_expr = ctx["value_expr"]
        new_ctx = dict(ctx)
        new_ctx["allowed_fields_php"] = allowed_php
        result = TemplateModule.render(self, new_ctx)
        new_ctx["value_expr"] = f"array_intersect_key({value_expr}, array_flip([{allowed_php}]))"
        return RenderResult(code=result.code, context=new_ctx)


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


class HtmlAttributeQuotedEchoSink(TemplateModule):
    """Echoes ``value_expr`` into a **quoted** HTML attribute value -- the
    reflected search-box shape (``puppy-fort-factory/search.php``'s
    ``value="<?= $q ?>"``), added by lane L-P3.3c-G6 alongside the
    ``(raw_concat, html_attribute_quoted)`` safety-matrix row that finally
    makes the unescaped end of this family scorable.

    The opposite of its unquoted sibling in one important way: here
    ``htmlspecialchars()`` is the *context-correct* escaping (the quote that
    would close the attribute is escaped), which is why the matrix scores
    ``(html_entity_escape, html_attribute_quoted)`` as ``neutralises`` and
    ``(html_entity_escape, html_attribute_unquoted)`` only as ``partial``.
    Like every sink here it escapes nothing itself.

    Registered in :data:`SINKS` so the shared composition vocabulary (which
    :mod:`fuzzlab.labgen.minimal_pair` classifies every emitter's composition
    positions against, and *raises* for a name it cannot find) knows it.
    ``php_current``'s own ``_MODULE_SET_BY_SHAPE`` is deliberately **not**
    widened to this shape -- that emitter's supported set is unchanged by
    L-P3.3c-G6; the Laravel emitter is the one that renders it.
    """

    def __init__(self) -> None:
        super().__init__("html_attribute_quoted_echo", "sink", _SINK_ENV, "html_attribute_quoted_echo.php.j2")


class SqlStringLiteralLikeSink(TemplateModule):
    """A ``LIKE '%<value>%'`` lookup: a quoted-string-literal SQL position
    reached through a search filter rather than an equality lookup
    (``puppy-fort-factory/search.php``'s ``WHERE name LIKE '%$q%'``).

    Same ``sql_string_literal`` *family* as
    :class:`SqlStringLiteralLookupSink` -- the ``LIKE`` wildcards are not
    verdict-relevant to ``sql_syntax_break``, per the plan's §4.3.6.2 shape-gap
    analysis, so this is a second rendering of one family, never a new family
    or a new matrix row. It exists because the equality sink folds in a
    login-style password condition as boilerplate, which a catalogue search
    page does not have; forcing search.php through it would have emitted a
    password check on a search form.

    Registered here for the same shared-vocabulary reason as
    :class:`HtmlAttributeQuotedEchoSink`; ``php_current``'s shape map is
    unchanged.
    """

    def __init__(self) -> None:
        super().__init__("sql_string_literal_like", "sink", _SINK_ENV, "sql_string_literal_like.php.j2")


class OrmEntityBulkAssignSink(TemplateModule):
    """The ``orm_entity_bulk_assign`` sink family (CC-LAB-0064,
    mass-assignment): builds and executes a parameterized ``UPDATE ... SET
    ...`` at runtime from whatever keys are present in ``value_expr``'s
    array. Column *names* come from the array's own keys -- tainted when
    unfiltered, allowlisted when the ``runtime_field_allowlist`` transform
    has run first; bound *values* are always parameters, never
    concatenated. Unlike every other sink here (each a single-line
    ``{{ value_expr }}`` interpolation, since each handles exactly one
    tainted scalar), this sink's template needs its own runtime PHP
    ``foreach`` over the array to build both the SET-clause text and a
    positionally-matching bound-values array -- real new surface, not a
    reuse of :class:`SqlIdentifierOrderBySink`'s single-value-substitution
    pattern. No Jinja-level loop is needed: the column set isn't known
    until PHP runtime, since the keys are attacker-controlled.

    One narrow exception to "a sink never filters anything itself": each
    key is checked against a bare-identifier charset (``^[A-Za-z0-9_]+$``)
    before it is spliced into ``$sql``, since PHP array keys survive far
    more punctuation than a SQL identifier position can safely admit and
    neither PDO nor any SQL dialect offers a binding mechanism for
    identifiers. Without this, the vulnerable twin would smuggle a second,
    unlabeled vulnerability class (raw SQL injection, CWE-89) into a cell
    this corpus classifies as mass-assignment only. This does not narrow
    *which* columns are legitimate (still the transform's job, per
    `runtime_field_allowlist`) -- only a value that could never be a real
    column name at all is rejected, so the mass-assignment vulnerability
    itself (writing `role`, `is_admin`, or any other validly-shaped,
    endpoint-unintended column) is untouched on the unfiltered twin."""

    def __init__(self) -> None:
        super().__init__("orm_entity_bulk_assign", "sink", _SINK_ENV, "orm_entity_bulk_assign.php.j2")


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


# --- L-P3.3c-DOM: DOM-based XSS (reviews.php/feedback.php) -----------------
#
# A genuinely different shape from every other one in this file: the tainted
# value is read AND written entirely client-side (a URL fragment or
# query-string parameter assigned to an element's `innerHTML` by embedded
# JavaScript) and never reaches the server -- there is no PHP variable to
# extract into, escape or bind. Registered here (unrendered by
# `php_current`'s own `_MODULE_SET_BY_SHAPE`, exactly like L-P3.3c-G6's
# `html_attribute_quoted_echo`/`sql_string_literal_like` before it) purely
# for the shared minimal-pair vocabulary
# (:mod:`fuzzlab.labgen.minimal_pair` classifies every emitter's composition
# positions against this package's registries and raises for a name it
# cannot find) -- `php_laravel` is the emitter that actually renders this
# shape (docs/LAB_IMPLEMENTATION_PLAN.md's `L-P3.3c-DOM`).


class DomUrlSource(TemplateModule):
    """The (non-)source for a client-only DOM-XSS cell: no PHP variable is
    extracted at all, because the tainted value never reaches the server.
    Publishes ``value_expr = 'null'`` (a PHP placeholder no template
    meaningfully reads) and ``bound=False`` only so this module still
    satisfies every other source's context contract."""

    def __init__(self) -> None:
        super().__init__("dom_url_source", "source", _SOURCE_ENV, "dom_url_source.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = "null"
        new_ctx.setdefault("bound", False)
        new_ctx.setdefault("dom_write_prop", "innerHTML")
        return RenderResult(code=result.code, context=new_ctx)


class DomTextContentTransform(TemplateModule):
    """The ``dom_text_content`` op: the client-side DOM write uses
    ``Node.textContent`` instead of ``Element.innerHTML``. The DOM analogue
    of ``html_entity_escape`` -- except there is no PHP-side call to make,
    since the value never reaches PHP, so this flips a client-side write
    mechanism (``dom_write_prop``) rather than wrapping ``value_expr``."""

    def __init__(self) -> None:
        super().__init__("dom_text_content", "transform", _TRANSFORM_ENV, "dom_text_content.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["dom_write_prop"] = "textContent"
        return RenderResult(code=result.code, context=new_ctx)


class DomInnerhtmlEchoSink(TemplateModule):
    """The DOM-XSS sink: a ``<script>`` block that reads a URL fragment or
    query-string parameter and assigns it to ``dom_write_prop`` of a target
    element -- ``innerHTML`` (vulnerable) or ``textContent`` (secure,
    ``dom_text_content``), decided entirely by the cell's transform, exactly
    like every other sink in this package never escaping anything itself.
    Requires ``dom_location`` (``"hash"`` or ``"query"``), ``dom_param_name``,
    ``dom_target_id``, ``dom_prefix`` and ``dom_suffix`` in the assembly
    context -- render-only metadata a page profile supplies; there is no
    safe default for which parameter/element a page reads and targets."""

    def __init__(self) -> None:
        super().__init__("dom_innerhtml_echo", "sink", _SINK_ENV, "dom_innerhtml_echo.php.j2")


class WebhookRequestSource(TemplateModule):
    """The ``webhook_request`` source (`CC-LAB-0133`, Huddle Hub's
    webhook-signature-verification cell): the raw request body plus the
    ``X-Signature`` header (via ``$_SERVER``/``php://input``, this stack's
    own idiom) and a fixed, lab-only shared secret. Registered for the
    shared minimal-pair vocabulary only -- ``php_current``'s own
    ``_MODULE_SET_BY_SHAPE`` is not widened to this shape (the cell is
    built on ``php_laravel`` only, per category 3's stack pick); this
    registration is what lets `php_laravel`'s own composition line
    classify by name (see this module's own docstring, decision 1)."""

    def __init__(self) -> None:
        super().__init__("webhook_request", "source", _SOURCE_ENV, "webhook_request.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(var_name=ctx["var_name"], secret=ctx["secret"])
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        return RenderResult(code=code, context=new_ctx)


class LooseEqualityCompareTransform(TemplateModule):
    """The ``loose_equality_compare`` op (`CC-LAB-0133`, `weak_signature_
    comparison` concern): PHP's ``==``/``!=`` operators both short-circuit
    and type-juggle hex-looking numeric strings as equal numbers (the
    documented "magic hash" bypass). Safety matrix: ``effect=partial``,
    ``neutralizes: [weak_signature_comparison]``. Registered for the shared
    minimal-pair vocabulary only, same reasoning as
    :class:`WebhookRequestSource`."""

    def __init__(self) -> None:
        super().__init__("loose_equality_compare", "transform", _TRANSFORM_ENV, "loose_equality_compare.php.j2")


class ConstantTimeCompareTransform(TemplateModule):
    """The ``constant_time_compare`` op (`CC-LAB-0133`, secure twin): PHP's
    ``hash_equals()``. Safety matrix: ``effect=neutralises``,
    ``neutralizes: [weak_signature_comparison]``. Registered for the shared
    minimal-pair vocabulary only, same reasoning as
    :class:`WebhookRequestSource`."""

    def __init__(self) -> None:
        super().__init__("constant_time_compare", "transform", _TRANSFORM_ENV, "constant_time_compare.php.j2")


class WebhookSignatureVerificationSink(TemplateModule):
    """The ``webhook_signature_verification`` sink family (`CC-LAB-0133`):
    accepts and "processes" the event -- illustrative, echoes ``value_expr``
    via its length only (never escapes/filters it itself, per this file's
    own convention). Registered for the shared minimal-pair vocabulary
    only, same reasoning as :class:`WebhookRequestSource`."""

    def __init__(self) -> None:
        super().__init__(
            "webhook_signature_verification", "sink", _SINK_ENV, "webhook_signature_verification.php.j2"
        )


SOURCES: dict[str, Module] = {
    "get_param": GetParamSource(),
    "post_param": PostParamSource(),
    "read_stored_field": ReadStoredFieldSource(),
    # CC-LAB-0064: mass-assignment's whole-array source (vs. one named param).
    "all_post_params": AllPostParamsSource(),
    # L-P3.3c-DOM: registered for the shared minimal-pair vocabulary only --
    # php_current's own _MODULE_SET_BY_SHAPE is not widened to this shape.
    "dom_url_source": DomUrlSource(),
    # CC-LAB-0133: registered for the shared minimal-pair vocabulary only --
    # this cell is built on php_laravel only (category 3's Huddle Hub).
    "webhook_request": WebhookRequestSource(),
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
    # CC-LAB-0064: mass-assignment ops (lab/safety_matrix.yaml's
    # orm_entity_bulk_assign rows).
    "unfiltered_body_update": UnfilteredBodyUpdateTransform(),
    "runtime_field_allowlist": RuntimeFieldAllowlistTransform(),
    # L-P3.3c-DOM: registered for the shared minimal-pair vocabulary only --
    # php_current's own _MODULE_SET_BY_SHAPE is not widened to this shape.
    "dom_text_content": DomTextContentTransform(),
    # CC-LAB-0133: registered for the shared minimal-pair vocabulary only --
    # this cell is built on php_laravel only (category 3's Huddle Hub).
    "loose_equality_compare": LooseEqualityCompareTransform(),
    "constant_time_compare": ConstantTimeCompareTransform(),
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
    # L-P3.3c-G6: search.php's two sink renderings -- a quoted attribute
    # (new safety-matrix pair) and a LIKE-pattern string literal (existing
    # family, second rendering). Registered in the shared vocabulary so
    # minimal_pair can classify them; php_current's _MODULE_SET_BY_SHAPE is
    # deliberately not widened to either.
    "html_attribute_quoted_echo": HtmlAttributeQuotedEchoSink(),
    "sql_string_literal_like": SqlStringLiteralLikeSink(),
    # CC-LAB-0064: mass-assignment's sink family.
    "orm_entity_bulk_assign": OrmEntityBulkAssignSink(),
    # L-P3.3c-DOM: registered for the shared minimal-pair vocabulary only --
    # php_current's own _MODULE_SET_BY_SHAPE is not widened to this shape.
    "dom_innerhtml_echo": DomInnerhtmlEchoSink(),
    # CC-LAB-0133: registered for the shared minimal-pair vocabulary only --
    # this cell is built on php_laravel only (category 3's Huddle Hub).
    "webhook_signature_verification": WebhookSignatureVerificationSink(),
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
