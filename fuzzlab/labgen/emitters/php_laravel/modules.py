"""Composable Laravel/Eloquent/Blade rendering modules for the
``php_laravel`` emitter (lane L-P3.3b, ``docs/LAB_IMPLEMENTATION_PLAN.md``
§4.3 step 2 -- the **full-depth** module inventory).

Mirrors :mod:`fuzzlab.labgen.modules`' composition shape (the
``source``/``transform``/``sink``/``complexity`` categories, a
``Module``/``TemplateModule`` base pair, one explicit-flags Jinja2
environment per category) exactly, per ``CR-LAB-0001`` Addendum C's
instruction to reuse ``php_current``'s module *categories* as the porting
template -- the same convention
:mod:`fuzzlab.labgen.emitters.node_express.modules` already follows. The
code is new and wholly owned by this directory: nothing is imported from,
or registered into, :mod:`fuzzlab.labgen.modules` (that package is
``php_current``'s plain-PHP/PDO idiom and another lane's files) and nothing
here touches :mod:`fuzzlab.labgen.emitters.php_current`.

**Full depth, per the plan's own reasoning.** Laravel is the one stack that
gets every shape ``php_current`` supports: the three value-context shapes
from Phase 0 (``sql_numeric_literal``/``sql_string_literal`` SQL and
``html_body`` HTML) *plus* all four of Phase 1's harder shapes (§2.2) --
identifier (``sql_identifier``) and connector-position (``sql_join_alias``)
SQL, and the two escaping-context-mismatch HTML shapes
(``url_javascript_scheme``, ``html_attribute_unquoted``).

Two deliberate, load-bearing naming/rendering decisions, stated here rather
than left for a reader to infer:

1. **Module names are the project's shared composition vocabulary, not
   Laravel-specific names.** The registry keys here (``get_param``,
   ``param_bind``, ``sql_identifier_order_by``, ...) are exactly
   :mod:`fuzzlab.labgen.modules`' names, even though every implementation
   differs. That is a hard requirement, not cosmetic: the shared
   minimal-pair checker (:mod:`fuzzlab.labgen.minimal_pair`, which
   ``fuzzlab.labgen.conformance.tier0.get_minimal_pair_checker`` and
   therefore ``lab-generate --check`` both prefer) classifies each position
   of a generated file's ``// Module composition: ...`` provenance line by
   looking the name up in ``fuzzlab.labgen.modules``' registries, and
   *raises* for a name it cannot classify. ``tier0``'s own docstring already
   states that checker is "correct for ``php_current``/``php_laravel``" --
   which holds only if this emitter speaks the same module-name vocabulary.
   A name here that the shared registry does not know would make every
   Laravel cell fail the minimal-pair gate with a setup error. (The
   alternative -- a pluggable category map on ``minimal_pair`` -- is a change
   to a sibling lane's shared module and is recorded as an open question in
   ``docs/components/01-target-lab/requirements.md`` §8 instead of smuggled
   in here.) L-P3.3a's foundation used two names of its own
   (``get_query_param``, ``db_select_raw``); they are renamed to the shared
   vocabulary by this lane for exactly that reason.
2. **A sink never escapes anything itself** -- the same invariant
   ``php_current``'s sinks hold, and the reason both twins of a minimal pair
   can share one sink fragment. In Blade terms this means the HTML sinks
   always echo with ``{!! ... !!}`` (raw) and the ``html_entity_escape``
   transform applies Laravel's ``e()`` helper in the controller. ``e()`` is
   the *same* ``htmlspecialchars()`` call Blade's own ``{{ }}`` echo
   applies, so the generated behavior is idiomatic Laravel either way; what
   the choice buys is that the escape lives in the transform region a
   minimal pair is allowed to differ in, rather than in the sink of a
   different file. Rendering the escape as a Blade ``{{ }}``/``{!! !!}``
   switch instead would move the security-relevant difference into the view
   file and out of the declared transform region -- see this module's
   registry comments and ``tests/test_labgen_php_laravel_harder_shapes.py``.

Determinism: every :class:`jinja2.Environment` sets ``trim_blocks``,
``lstrip_blocks`` and ``keep_trailing_newline`` explicitly (never Jinja2's
defaults) and templates are handed already-computed, already-ordered values,
so two renders of the same inputs are byte-identical
(NFR-LAB-reproducible).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_ROOT = Path(__file__).parent / "templates"


def _make_env(subdir: str) -> Environment:
    """One Jinja2 environment per module category, with the
    determinism-relevant flags always set explicitly (never left at Jinja2's
    defaults) -- the same ``_make_env`` contract
    :mod:`fuzzlab.labgen.modules` and
    :mod:`fuzzlab.labgen.emitters.node_express.modules` use."""
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
_VIEW_ENV = _make_env("views")
_WRITE_ENV = _make_env("writes")


@dataclass(frozen=True)
class RenderResult:
    """Same shape as :class:`fuzzlab.labgen.modules.RenderResult`: the
    rendered code plus the (possibly updated) assembly context handed to the
    next module in the composition."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable Laravel rendering fragment.

    ``cardinality`` is ``"per_cell"`` for every module in this registry; the
    one ``"accumulator"``-cardinality module of this stack (``routes/web.php``)
    lives in :mod:`fuzzlab.labgen.emitters.php_laravel.route_accumulator`,
    per ``CR-LAB-0001`` Addendum D, and is rendered per *manifest* rather
    than through this per-cell registry.
    """

    name: str
    category: str
    cardinality: str = "per_cell"

    def render(self, ctx: dict[str, Any]) -> RenderResult:  # pragma: no cover - abstract
        raise NotImplementedError


class TemplateModule(Module):
    """A module whose rendering is exactly one Jinja2 template call. A module
    that must publish new context keys for downstream modules subclasses this
    and overrides :meth:`render`."""

    def __init__(self, name: str, category: str, env: Environment, template_name: str):
        self.name = name
        self.category = category
        self._env = env
        self.template_name = template_name
        self._template_name = template_name

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(**ctx)
        return RenderResult(code=code, context=dict(ctx))


# --- sources --------------------------------------------------------------


class GetParamSource(TemplateModule):
    """One query-string parameter read through Laravel's ``Request`` accessor
    (``$request->query('id')``), publishing ``value_expr`` and
    ``bound=False`` -- the Laravel analogue of
    ``fuzzlab.labgen.modules.GetParamSource``'s ``$_GET`` read."""

    def __init__(self) -> None:
        super().__init__("get_param", "source", _SOURCE_ENV, "get_param.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class PostParamSource(TemplateModule):
    """One POST-body parameter read through ``$request->input(...)`` -- same
    ``value_expr``/``bound`` contract as :class:`GetParamSource`, a different
    request-data origin."""

    def __init__(self) -> None:
        super().__init__("post_param", "source", _SOURCE_ENV, "post_param.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class ReadStoredFieldSource(TemplateModule):
    """A source that is **not** a request parameter: an already-stored value
    read back through Eloquent (a model attribute written by an earlier
    request). The taint origin is storage, which is what a stored-XSS cell
    needs; like ``php_current``'s equivalent this renders the *sink side*
    only -- modelling the write endpoint as a second artifact is
    ``Cell.sink_endpoint``/``context_depth`` work this emitter does not yet
    carry (see :mod:`fuzzlab.labgen.emitters.php_laravel`)."""

    def __init__(self) -> None:
        super().__init__("read_stored_field", "source", _SOURCE_ENV, "read_stored_field.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class AllPostParamsSource(TemplateModule):
    """The WHOLE request body, read through ``$request->all()`` -- the
    Laravel analogue of ``fuzzlab.labgen.modules.AllPostParamsSource``'s
    ``$_POST`` read (CC-LAB-0064's follow-up, restoring the "Laravel carries
    every shape php_current supports" full-depth invariant
    ``tests/test_labgen_php_laravel_harder_shapes.py`` asserts).
    ``GetParamSource``/``PostParamSource`` both extract exactly one named
    parameter, the wrong shape for a bulk-assignment sink."""

    def __init__(self) -> None:
        super().__init__("all_post_params", "source", _SOURCE_ENV, "all_post_params.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"${ctx['var_name']}"
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


# --- transforms -----------------------------------------------------------


class IdentityTransform(TemplateModule):
    """The empty-pipeline transform: the value reaches the sink as it
    arrived. Rendered (as a comment) rather than omitted, so a cell with no
    ops still occupies a transform position in the composition line -- which
    is what lets :mod:`fuzzlab.labgen.minimal_pair` compare a cell against
    its transform-emptied twin position-for-position."""

    def __init__(self) -> None:
        super().__init__("identity", "transform", _TRANSFORM_ENV, "identity.php.j2")


class ParamBindTransform(TemplateModule):
    """The ``param_bind`` op: flags the value as bound so the sink renders a
    placeholder/query-builder binding instead of concatenating the value into
    the statement text."""

    def __init__(self) -> None:
        super().__init__("param_bind", "transform", _TRANSFORM_ENV, "param_bind.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["bound"] = True
        return RenderResult(code=result.code, context=new_ctx)


class HtmlEntityEscapeTransform(TemplateModule):
    """The ``html_entity_escape`` op: wraps ``value_expr`` in Laravel's
    ``e()`` helper -- the same ``htmlspecialchars()`` call Blade's escaped
    echo applies, made explicit in the controller so the escape sits in the
    transform region (see this module's docstring, decision 2)."""

    def __init__(self) -> None:
        super().__init__("html_entity_escape", "transform", _TRANSFORM_ENV, "html_entity_escape.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"e({ctx['value_expr']})"
        return RenderResult(code=result.code, context=new_ctx)


class IdentifierCharsetFilterTransform(TemplateModule):
    """The ``identifier_charset_filter`` op: emits a guard *statement* (a
    bare-identifier ``preg_match`` check that ``abort(400)``s on mismatch --
    Laravel's own abort idiom rather than a raw ``http_response_code()``) and
    leaves ``value_expr`` untouched.

    Leaving the expression alone is the point: the filter plainly blocks
    statement-breaking characters and plainly does not restrict *which*
    identifier is used, which is what makes the safety matrix's ``partial``
    effect legible in the generated code."""

    def __init__(self) -> None:
        super().__init__(
            "identifier_charset_filter", "transform", _TRANSFORM_ENV, "identifier_charset_filter.php.j2"
        )


def _php_string_list(values: tuple[str, ...]) -> str:
    """Render an already-ordered tuple of identifiers as a PHP single-quoted
    list body (``'id', 'name'``).

    Never sorts or de-duplicates (the author's order is meaningful: the first
    entry is the documented safe fallback) and rejects anything that is not a
    bare identifier rather than emitting PHP that would need escaping -- an
    authoring gap fails loud, the same contract
    ``fuzzlab.labgen.modules._php_string_list`` holds for ``php_current``.
    """
    if not values:
        raise ValueError(
            "identifier allowlist is empty -- an allowlist transform with nothing allowed has "
            "no safe fallback to fall back to; supply the real identifiers in the emitter's "
            "page profile"
        )
    for value in values:
        if not re.fullmatch(r"[A-Za-z0-9_]+", value):
            raise ValueError(
                f"identifier allowlist entry {value!r} is not a bare identifier ([A-Za-z0-9_]+) "
                "-- allowlisted identifiers are emitted into PHP source verbatim and are never "
                "escaped or quoted for you"
            )
    return ", ".join(f"'{value}'" for value in values)


class IdentifierAllowlistTransform(TemplateModule):
    """The ``identifier_allowlist`` op: rewrites ``value_expr`` into an
    ``in_array``-guarded expression that can only ever evaluate to one of the
    page profile's real identifiers (falling back to the first).

    Requires ``allowed_identifiers`` in the assembly context -- render-only
    metadata the :class:`~fuzzlab.labgen.schema.Cell` IR deliberately does
    not carry. Raises rather than inventing a default: guessing which columns
    an endpoint may expose is exactly the decision this transform exists to
    make explicit."""

    def __init__(self) -> None:
        super().__init__("identifier_allowlist", "transform", _TRANSFORM_ENV, "identifier_allowlist.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        try:
            allowed = tuple(ctx["allowed_identifiers"])
        except KeyError as exc:
            raise ValueError(
                "identifier_allowlist transform needs an 'allowed_identifiers' context value "
                "(an ordered tuple of the real identifiers this endpoint may use) -- the "
                "emitter's page profile must supply it; there is no safe default"
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
    strict ``^[A-Za-z0-9_-]+$`` value survives (otherwise the page profile's
    ``attr_default``) -- the transform-only fix for an *unquoted* HTML
    attribute, whose whitespace boundary ``htmlspecialchars()``/``e()`` does
    not protect."""

    def __init__(self) -> None:
        super().__init__("attr_value_allowlist", "transform", _TRANSFORM_ENV, "attr_value_allowlist.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        default = ctx.get("attr_default", "default")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", str(default)):
            raise ValueError(
                f"attr_default {default!r} does not itself satisfy the allowlist this transform "
                "enforces (^[A-Za-z0-9_-]+$) -- a fallback that would be rejected by the very "
                "check it backstops is an authoring error"
            )
        value_expr = ctx["value_expr"]
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = (
            f"(preg_match('/^[A-Za-z0-9_-]+$/', (string) {value_expr}) ? {value_expr} : '{default}')"
        )
        return RenderResult(code=result.code, context=new_ctx)


class UnfilteredBodyUpdateTransform(TemplateModule):
    """The ``unfiltered_body_update`` op (CC-LAB-0064, `mass_assignment`
    concern): ``value_expr`` passes through unchanged -- every key in the
    whole request body reaches the sink. Safety matrix: ``effect=no_effect``
    (the vulnerable twin)."""

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


# --- sinks ----------------------------------------------------------------
#
# Every sink branches on `bound` where a bound form exists at all, so one
# fragment serves both twins of a minimal pair, and none of them escapes
# anything itself (see this module's docstring, decision 2).


class SqlNumericLookupSink(TemplateModule):
    """A single-row lookup at a numeric-literal position, via the ``DB``
    facade (``DB::select``). Its ``bound`` branch renders a real ``?``
    placeholder with a binding array; its raw branch concatenates."""

    def __init__(self) -> None:
        super().__init__("sql_numeric_lookup", "sink", _SINK_ENV, "sql_numeric_lookup.php.j2")


class SqlStringLiteralLookupSink(TemplateModule):
    """A lookup at a quoted-string-literal position, with a second,
    non-tainted, already-hashed condition folded in as sink boilerplate (the
    login-style page's password check -- the cell's injection point is the
    string-literal column only). The ``bound`` branch uses Eloquent's query
    builder ``where()``, which binds values for you; the raw branch uses
    ``whereRaw()`` with the value spliced into the SQL -- the real Laravel
    footgun rather than a transliterated PDO call."""

    def __init__(self) -> None:
        super().__init__("sql_string_literal_lookup", "sink", _SINK_ENV, "sql_string_literal_lookup.php.j2")


class SqlIdentifierOrderBySink(TemplateModule):
    """An ``ORDER BY <identifier>`` lookup: the tainted value *is* a column
    identifier, not a literal value.

    The raw branch uses ``orderByRaw()`` -- the query-builder method that
    takes raw SQL precisely because no dialect can bind an identifier -- and
    the ``bound`` branch shows a real ``?`` binding for an unrelated WHERE
    *value* while the identifier is still concatenated: the generated-code
    evidence for the safety matrix's ``(param_bind, sql_identifier) ->
    no_effect`` row. "Use a prepared statement" is *inapplicable* here, not
    merely omitted."""

    def __init__(self) -> None:
        super().__init__("sql_identifier_order_by", "sink", _SINK_ENV, "sql_identifier_order_by.php.j2")


class SqlJoinAliasLookupSink(TemplateModule):
    """A JOIN-alias (connector-position) lookup: the tainted value is a table
    alias, substituted **three** times in one statement (projection, alias
    declaration, ``ON`` clause).

    The multi-substitution shape is the point -- it is what makes a
    comment-based escape degenerate into ordinary statement truncation and
    what keeps a character filter only ``partial`` at this family."""

    def __init__(self) -> None:
        super().__init__("sql_join_alias_lookup", "sink", _SINK_ENV, "sql_join_alias_lookup.php.j2")


class HtmlBodyEchoSink(TemplateModule):
    """Echoes the value into an HTML body position -- rendered as a **Blade
    view** body (``role="view"``), not a controller ``echo``: a Laravel
    controller returns a view, which is the whole point of porting these
    shapes to this stack's idiom. Uses Blade's raw echo, so whether the value
    was escaped is decided entirely by the cell's transform."""

    def __init__(self) -> None:
        super().__init__("html_body_echo", "sink", _SINK_ENV, "html_body_echo.blade.php.j2")


class HtmlJsUrlEchoSink(TemplateModule):
    """Echoes the value inside a ``javascript:`` URL in a quoted ``href`` --
    an HTML attribute whose content is JavaScript source, so HTML-entity
    escaping is correct escaping for the wrong context. Rendered as a Blade
    view body."""

    def __init__(self) -> None:
        super().__init__("html_js_url_echo", "sink", _SINK_ENV, "html_js_url_echo.blade.php.j2")


class HtmlAttributeUnquotedEchoSink(TemplateModule):
    """Echoes the value into an **unquoted** HTML attribute, whose boundary is
    whitespace -- which ``htmlspecialchars()``/``e()`` does not escape.
    Rendered as a Blade view body."""

    def __init__(self) -> None:
        super().__init__(
            "html_attribute_unquoted_echo", "sink", _SINK_ENV, "html_attribute_unquoted_echo.blade.php.j2"
        )


class HtmlAttributeQuotedEchoSink(TemplateModule):
    """Echoes the value into a **quoted** HTML attribute -- the reflected
    search box (``puppy-fort-factory/search.php``'s ``value="<?= $q ?>"``),
    rendered as a Blade view body. Added by lane L-P3.3c-G6 together with the
    ``(raw_concat, html_attribute_quoted)`` safety-matrix row.

    The mirror image of its unquoted sibling: here the quote that would close
    the attribute *is* one of the characters ``e()``/``htmlspecialchars()``
    escapes, so entity escaping is the context-correct fix and the matrix
    scores it ``neutralises`` rather than ``partial``."""

    def __init__(self) -> None:
        super().__init__(
            "html_attribute_quoted_echo", "sink", _SINK_ENV, "html_attribute_quoted_echo.blade.php.j2"
        )


class SqlStringLiteralLikeSink(TemplateModule):
    """A ``LIKE '%<value>%'`` catalogue search at a quoted-string-literal
    position (``puppy-fort-factory/search.php``'s ``WHERE name LIKE '%$q%'``).

    Same ``sql_string_literal`` family as :class:`SqlStringLiteralLookupSink`
    -- per the plan's §4.3.6.2 shape-gap analysis the ``LIKE`` wildcards are
    not verdict-relevant to ``sql_syntax_break``, so this is a second
    *rendering* of one family, never a new family, a new matrix row or a
    ``sql_like_pattern`` concept. It exists because the equality sink folds a
    login-style password condition in as boilerplate, which a search page does
    not have.

    Both branches use ``whereRaw()`` and differ only in whether the value is
    bound -- the minimal-pair shape §4.3.6.3a requires on this stack, where
    the idiomatic secure form (``->where('name', 'like', ...)``) would differ
    from its vulnerable twin by the whole statement construction."""

    def __init__(self) -> None:
        super().__init__("sql_string_literal_like", "sink", _SINK_ENV, "sql_string_literal_like.php.j2")


class OrmEntityBulkAssignSink(TemplateModule):
    """The ``orm_entity_bulk_assign`` sink family (CC-LAB-0064,
    mass-assignment). Unlike ``fuzzlab.labgen.modules``' php_current
    analogue -- plain PDO, which needs a runtime ``foreach`` to build a SET
    clause by hand -- Laravel's Query Builder ``update()`` accepts an
    associative array directly (``DB::table(...)->update($fields)``), a
    genuine, idiomatic one-line Laravel equivalent, not a manufactured
    workaround for a Laravel limitation. Deliberately ``DB::table()``, not
    an Eloquent model's own ``update()``: Eloquent's ``$fillable``/
    ``$guarded`` is a model-class property with no existing module category
    in either registry for emitting a separate model file (the reason an
    earlier draft of CC-LAB-0064 was re-scoped away from Eloquent
    entirely); the Query Builder bypasses Eloquent's mass-assignment guard
    the same way raw PDO does, which is exactly the vulnerability class
    this sink renders -- and it is real, commonly-used Laravel API, not a
    contrivance to dodge the model-file problem."""

    def __init__(self) -> None:
        super().__init__("orm_entity_bulk_assign", "sink", _SINK_ENV, "orm_entity_bulk_assign.php.j2")


# --- views (the `view` module category, L-P3.3c-G2) -----------------------
#
# CR-LAB-0001 Addendum D names `"view"` as a module *category* alongside
# `source`/`transform`/`sink`/`complexity`/`route`, and
# `fuzzlab.labgen.minimal_pair`'s own docstring already anticipates it. Until
# this lane nothing needed it: the three HTML sinks render a **Blade view
# body** and the emitter writes that body to a second file, so the "view" was
# a property of the sink, not a module of its own.
#
# `api/products.php` is the first page that breaks that: it is a JSON API
# endpoint, so there is no HTML body for a sink to render, yet the response
# still has a *presentation layer* -- the field set, the field order and the
# casts the endpoint's consumers (the fetch-based JS pages) depend on. In
# Laravel that layer is an **Eloquent API Resource**
# (`Illuminate\Http\Resources\Json\JsonResource`), which is precisely a view
# for a JSON response. So the category is real, and a JSON view is its first
# member.
#
# Shape convention (chosen to mirror the Blade sinks position-for-position,
# so a reader who knows one knows the other):
#
#   * `render(ctx).code` is the **view artifact's file content** -- exactly
#     what a Blade sink's `.code` is (the emitter writes it to a second,
#     `role="view"` file), rather than a statement inside the controller.
#   * `render(ctx).context["view_bridge_code"]` is the *one* controller-side
#     statement that hands the composed result to that view -- the analogue
#     of `render_only`'s `return view(...)` line, kept in the context so the
#     emitter appends it to the controller body without a second template
#     call.
#
# The bridge statement deliberately rebinds `$rows`, which lets the existing
# `single_statement` complexity close the method unchanged
# (`return response()->json($rows);`). That is why this category costs one
# new module and no new complexity: the JSON view changes *what* `$rows` is,
# not *how* the method returns it.
#
# Why a view module's name is NOT in the `// Module composition:` provenance
# line: `fuzzlab.labgen.minimal_pair` classifies every name on that line
# through `fuzzlab.labgen.modules`' registries and *raises* for one it cannot
# find (see this module's docstring, decision 1), and registering a
# Laravel-only module in that shared, cross-stack package is exactly the
# change L-P3.3b recorded as an open question rather than making. The
# established precedent is the `route` category, which is likewise a real
# module category whose name never appears in the composition line. The view
# category is recorded in its own `// View category: <name>` provenance line
# instead -- identical between a minimal pair's twins, so it lands in the
# checker's common prefix and confines the declared difference to the
# transform/sink region exactly as before.

#: Casts a JSON view may apply to a field, mapped to the PHP expression
#: wrapper each one renders. `None` means "pass the stored value through".
#: An explicit, closed set: a page profile naming a cast that is not here
#: fails loud rather than reaching PHP source unvalidated.
JSON_FIELD_CASTS: dict[str | None, str] = {
    None: "{expr}",
    "int": "(int) {expr}",
    "float": "(float) {expr}",
    "string": "(string) {expr}",
}


class ViewModule(Module):
    """Base class for a ``view``-category module: the presentation layer of a
    response whose sink produced data rather than markup.

    Two-part contract (see this section's comment for the reasoning):
    ``render(ctx).code`` is the view artifact's own file content, and
    ``render(ctx).context["view_bridge_code"]`` is the single controller
    statement that routes the composed result through it.
    """

    category = "view"


class JsonViewModule(ViewModule):
    """The ``json_view`` module: a Laravel **Eloquent API Resource** class as
    the view for a JSON endpoint.

    Renders the endpoint's declared response shape -- the ordered field set
    and each field's cast, from the page profile's ``json_fields`` -- rather
    than letting the raw database row shape become the API contract by
    default. ``$wrap`` is pinned to ``null`` in the generated class so the
    response is a bare JSON array, which is what a JSON feed's consumers
    actually parse.

    ``json_fields`` is required and validated, never defaulted: guessing
    which columns an endpoint publishes is the same class of decision
    :class:`IdentifierAllowlistTransform` refuses to guess, and a field name
    reaches PHP source verbatim and is never quoted or escaped for you.
    """

    def __init__(self) -> None:
        super().__init__()
        self.name = "json_view"
        self._env = _VIEW_ENV
        self.template_name = "json_view.php.j2"
        self._template_name = self.template_name

    @staticmethod
    def _fields(ctx: dict[str, Any]) -> list[dict[str, str]]:
        try:
            raw = tuple(ctx["json_fields"])
        except KeyError as exc:
            raise ValueError(
                "json_view module needs a 'json_fields' context value (an ordered tuple of "
                "(field_name, cast) pairs naming this endpoint's declared JSON response shape) "
                "-- the emitter's page profile must supply it; there is no safe default, and a "
                "raw database row shape is not an API contract"
            ) from exc
        if not raw:
            raise ValueError(
                "json_view 'json_fields' is empty -- a JSON view that publishes no field renders "
                "an endpoint with no response shape at all; supply the real fields in the "
                "emitter's page profile"
            )
        fields: list[dict[str, str]] = []
        for entry in raw:
            name, cast = entry
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(name)):
                raise ValueError(
                    f"json_view field name {name!r} is not a bare identifier "
                    "([A-Za-z_][A-Za-z0-9_]*) -- field names are emitted into PHP source "
                    "verbatim and are never escaped or quoted for you"
                )
            if cast not in JSON_FIELD_CASTS:
                raise ValueError(
                    f"json_view field {name!r} names cast {cast!r}, which is not one of "
                    f"{sorted(k for k in JSON_FIELD_CASTS if k is not None)} (or None for no "
                    "cast) -- an unknown cast would reach PHP source unvalidated"
                )
            # Author order is preserved, never sorted: field order is part of
            # the response shape this view declares (NFR-LAB-reproducible).
            fields.append({"key": str(name), "expr": JSON_FIELD_CASTS[cast].format(expr=f"$this->{name}")})
        return fields

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        fields = self._fields(ctx)
        resource_class = ctx["resource_class"]
        template = self._env.get_template(self._template_name)
        code = template.render(resource_class=resource_class, json_fields=fields)
        new_ctx = dict(ctx)
        new_ctx["json_fields_rendered"] = tuple(field["key"] for field in fields)
        # The one controller-side statement: the composed rows are handed to
        # this cell's JSON view, which is what makes the endpoint's response
        # shape the view's declaration rather than the row shape's accident.
        new_ctx["view_bridge_code"] = (
            "// json_view: the rows are handed to this endpoint's own JSON view (an Eloquent\n"
            "// API Resource collection), which declares the field set, the field order and\n"
            "// each field's cast -- the JSON analogue of a Blade view.\n"
            f"$rows = \\App\\Http\\Resources\\{resource_class}::collection($rows);"
        )
        return RenderResult(code=code, context=new_ctx)


# --- writes (stored-write endpoints, L-P3.3c-G4) ---------------------------
#
# A `stored_second_order` cell has two endpoints, not one: the *write* endpoint
# the payload is submitted to (`Cell.route`) and the *read*/sink endpoint it
# later executes on (`Cell.sink_endpoint`). Every module category above renders
# the read side; this category renders the write side, which no existing
# emitter emits at all -- `php_current` models a stored cell by rendering the
# sink page only and leaving the real app's write page unreproduced (see
# `fuzzlab.labgen.emitters.php_current.PhpCurrentEmitter._render_depth`, which
# returns no fragments for `stored_second_order`). Reproducing a real page pair
# needs both halves, which is what the plan's per-page inventory calls G4's
# "stored-write sink" module (§4.3.6.3).
#
# **Never named in a cell's `// Module composition:` line.** That line is read
# by the shared `fuzzlab.labgen.minimal_pair` checker, which classifies every
# position by looking the name up in `fuzzlab.labgen.modules`' registries and
# *raises* for a name it cannot find (see this module's docstring, decision 1).
# The write endpoint is also not a composition position in any meaningful
# sense: it carries no transform, so it is byte-identical between a minimal
# pair's twins by construction. It is emitted as its own method on its own
# controller instead.


class StoredFieldWriteModule(TemplateModule):
    """The write half of a ``stored_second_order`` cell: an Eloquent attribute
    assignment plus ``save()``, persisting the tainted request parameter into
    the owning identity's stored field **verbatim**.

    Storing raw is deliberate and is not the modelled defect: Eloquent binds
    the value, so the write is not an injection point (the real
    ``puppy-fort-factory/edit_profile.php`` likewise stores ``bio`` through a
    prepared statement). The cell's transform pipeline applies at the *read*
    endpoint, which is where its verdict is decided -- so this fragment is
    identical for a vulnerable cell and its secure twin, and the minimal-pair
    invariant is unaffected by its existence.

    Requires ``stored_model``, ``stored_field``, ``owner_param``,
    ``write_param_name``, ``write_method_name`` and ``sink_url_path`` in the
    assembly context. Raises (via :class:`jinja2.StrictUndefined`) rather than
    inventing a default for any of them -- which model and column a write
    endpoint persists into is exactly the decision a page profile exists to
    state.
    """

    def __init__(self) -> None:
        super().__init__("stored_field_write", "write", _WRITE_ENV, "stored_field_write.php.j2")


# --- complexities ---------------------------------------------------------


class SingleStatementComplexity(TemplateModule):
    """The controller method for a cell whose sink is a database statement:
    the composed source/transform/sink body, closing with a JSON response.
    The Laravel counterpart of ``php_current``'s ``single_statement``
    function wrapper (which closes with ``return $row;``)."""

    def __init__(self) -> None:
        super().__init__("single_statement", "complexity", _COMPLEXITY_ENV, "single_statement.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        # The whole context is passed, not two hand-picked keys: the page
        # profile's optional real-page tail flags (`session_login`,
        # `register_insert` -- see `php_laravel._SESSION_LOGIN_KEY`) are read
        # by the template, and re-listing them here would be a second place
        # that has to learn every new key (PA-0001/PA-0003's one-place rule).
        # Every pre-existing profile declares none of them, so their rendering
        # is byte-identical to before.
        code = template.render(**ctx)
        return RenderResult(code=code, context=dict(ctx))


class RenderOnlyComplexity(TemplateModule):
    """The controller method for a cell with no row to return: it hands the
    (possibly transformed) value to this cell's own Blade view.

    Distinct from :class:`SingleStatementComplexity` for the same reason
    ``php_current`` needs two complexity modules -- different sink shapes
    need different wrappers, not one universal template -- and additionally
    because this is the module that *names* the view file, which is what
    makes an HTML cell a two-file cell on this stack."""

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.php.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(
            body=ctx["body"],
            method_name=ctx["method_name"],
            view_name=ctx["view_name"],
            value_expr=ctx["value_expr"],
        )
        return RenderResult(code=code, context=dict(ctx))


#: Source modules. Keys are :mod:`fuzzlab.labgen.modules`' shared names on
#: purpose -- see this module's docstring, decision 1.
SOURCES: dict[str, Module] = {
    "get_param": GetParamSource(),
    "post_param": PostParamSource(),
    "read_stored_field": ReadStoredFieldSource(),
    "all_post_params": AllPostParamsSource(),
}
#: Transform ops. Every name here must also have a row for every sink family
#: it is authored against in ``lab/safety_matrix.yaml`` -- an op this emitter
#: can render but the matrix cannot score would derive no verdict at all
#: (``verdict()`` raises), the emitter/matrix lockstep gap PA-0024 is about.
#: ``tests/test_labgen_php_laravel_harder_shapes.py`` asserts that for real,
#: from these registries rather than a hand-kept list (PA-0001/PA-0027).
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "param_bind": ParamBindTransform(),
    "html_entity_escape": HtmlEntityEscapeTransform(),
    "identifier_charset_filter": IdentifierCharsetFilterTransform(),
    "identifier_allowlist": IdentifierAllowlistTransform(),
    "url_scheme_allowlist": UrlSchemeAllowlistTransform(),
    "attr_value_allowlist": AttrValueAllowlistTransform(),
    "unfiltered_body_update": UnfilteredBodyUpdateTransform(),
    "runtime_field_allowlist": RuntimeFieldAllowlistTransform(),
}
#: Sinks. The three HTML sinks render a **Blade view** body rather than a
#: controller statement; :data:`VIEW_SINKS` names them so the emitter knows
#: which cells are two-file cells without re-deriving it from the shape map.
SINKS: dict[str, Module] = {
    "sql_numeric_lookup": SqlNumericLookupSink(),
    "sql_string_literal_lookup": SqlStringLiteralLookupSink(),
    "sql_identifier_order_by": SqlIdentifierOrderBySink(),
    "sql_join_alias_lookup": SqlJoinAliasLookupSink(),
    "html_body_echo": HtmlBodyEchoSink(),
    "html_js_url_echo": HtmlJsUrlEchoSink(),
    "html_attribute_unquoted_echo": HtmlAttributeUnquotedEchoSink(),
    # L-P3.3c-G6 (search.php): a quoted-attribute Blade sink for the new
    # `raw_concat x html_attribute_quoted` matrix pair, and a LIKE-pattern
    # rendering of the existing `sql_string_literal` family.
    "html_attribute_quoted_echo": HtmlAttributeQuotedEchoSink(),
    "sql_string_literal_like": SqlStringLiteralLikeSink(),
    "orm_entity_bulk_assign": OrmEntityBulkAssignSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "single_statement": SingleStatementComplexity(),
    "render_only": RenderOnlyComplexity(),
}
#: ``view``-category modules (L-P3.3c-G2). Selected per page by the emitter's
#: own page profile (``view_category``), never by the verdict-relevant shape
#: vocabulary -- the same reasoning as ``_SOURCE_OVERRIDE_KEY``: which
#: presentation layer a page uses is render-only metadata and must never fork
#: ``class`` x ``sink_context.family``, which the safety matrix is keyed on.
VIEWS: dict[str, Module] = {
    "json_view": JsonViewModule(),
}
#: Write-endpoint modules (L-P3.3c-G4). Its own registry, deliberately *not*
#: folded into :data:`SOURCES`/:data:`SINKS`/:data:`COMPLEXITIES`: those four
#: registries are the composition vocabulary the shared
#: :mod:`fuzzlab.labgen.minimal_pair` checker classifies a cell's
#: ``// Module composition:`` line against, and a name it cannot find there
#: makes every cell of this stack fail the minimal-pair gate with a setup
#: error. A write endpoint is a second *endpoint*, not a position in the read
#: path's composition -- see this category's section comment above.
WRITES: dict[str, Module] = {
    "stored_field_write": StoredFieldWriteModule(),
}

#: The sink modules whose rendered code is a Blade **view** body (emitted as
#: a second, ``role="view"`` file) rather than a statement inside the
#: controller method. Derived from the registry itself by template suffix, so
#: a sink added later cannot be forgotten here (PA-0001/PA-0027: no
#: hand-kept parallel list).
VIEW_SINKS: frozenset[str] = frozenset(
    name
    for name, module in SINKS.items()
    if getattr(module, "template_name", "").endswith(".blade.php.j2")
)
