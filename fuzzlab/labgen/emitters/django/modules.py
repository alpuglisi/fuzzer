"""Composable Python/Django rendering modules for the ``django`` emitter
(category 2 pilot, `CC-LAB-0090`/`CC-LAB-0091`/`CC-LAB-0093`).

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

**Phase A** (`CC-LAB-0090`) built exactly one shape --
``sqli``/``sql_numeric_literal`` -- that ``php_laravel``'s own L-P3.3a
foundation lane and ``node_express``'s Phase A plan both picked as the first
shape to prove the scaffold end to end. **Phase B** (`CC-LAB-0091`) widens
this to the same three-shape Tier-A bar ``node_express`` already proves:
``sqli``/``sql_string_literal`` (a login-style lookup, POST body source, an
MD5'd-password-boilerplate sink) and ``xss``/``html_body`` (a stored value
echoed raw into an ``HttpResponse`` body vs. escaped with
``django.utils.html.escape()``). The full ``php_laravel``-depth nine-shape
inventory (identifier/alias SQLi, DOM XSS, mass-assignment) stays out of
scope, as does the researched, corpus-grounded Django-specific XSS footgun
(``mark_safe()``/``|safe``/``{% autoescape off %}`` disabling Django's own
template autoescaping -- see
``docs/research/category2-social-ugc-functionality-and-cwe-research.md``
§4) -- deliberately deferred to Phase C's own corpus-grounded page design,
where a real Instagram-shaped comment page exists to place it on, per
`CC-LAB-0091`'s own reasoning.
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


class PostParamSource(TemplateModule):
    """Extracts one Django ``request.POST`` parameter and publishes
    ``value_expr``/``bound=False`` -- the Django analogue of
    ``fuzzlab.labgen.modules.PostParamSource``/``node_express.modules.
    PostBodyParamSource`` (`CC-LAB-0091`)."""

    def __init__(self) -> None:
        super().__init__("post_param", "source", _SOURCE_ENV, "post_param.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class ReadStoredFieldSource(TemplateModule):
    """A source that is **not** a request parameter: reads an
    already-stored value -- the Django analogue of ``fuzzlab.labgen.
    modules.ReadStoredFieldSource``/``node_express.modules.
    ReadStoredFieldSource`` (`CC-LAB-0091`), used by the ``html_body``
    stored-XSS shape's sink side."""

    def __init__(self) -> None:
        super().__init__("read_stored_field", "source", _SOURCE_ENV, "read_stored_field.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        return RenderResult(code=result.code, context=new_ctx)


class PostBodyDictSource(TemplateModule):
    """Extracts the entire Django ``request.POST`` body as a plain
    ``dict`` and publishes ``value_expr``/``bound=False`` -- the
    "whole-body, multi-field" source shape mass-assignment (CWE-915)
    needs, distinct from every other source in this inventory (which
    each extract exactly one named parameter). `CC-LAB-0095`."""

    def __init__(self) -> None:
        super().__init__("post_body_dict", "source", _SOURCE_ENV, "post_body_dict.py.j2")

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


class HtmlEntityEscapeTransform(TemplateModule):
    """The ``html_entity_escape`` op: wraps ``value_expr`` in a call to
    Django's own ``django.utils.html.escape()`` -- the direct analogue of
    PHP's ``htmlspecialchars()``, applied inline at the point of use,
    exactly like ``fuzzlab.labgen.modules.HtmlEntityEscapeTransform`` /
    ``node_express.modules.HtmlEntityEscapeTransform`` (`CC-LAB-0091`).
    Unlike ``node_express`` (JS has no stdlib equivalent, hence its own
    hand-rolled ``escapeHtml`` helper), Django already ships one, so no
    hand-rolled helper is needed here -- ``escape`` is one of the fixed,
    unconditional header imports every generated view file carries."""

    def __init__(self) -> None:
        super().__init__("html_entity_escape", "transform", _TRANSFORM_ENV, "html_entity_escape.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"escape({ctx['value_expr']})"
        return RenderResult(code=result.code, context=new_ctx)


class MarkSafeWrapTransform(TemplateModule):
    """The ``mark_safe_wrap`` op (`CC-LAB-0093`): wraps ``value_expr`` in
    Django's own ``django.utils.safestring.mark_safe()``, marking
    untrusted content "already safe" so Django's own template
    auto-escaping skips it when the sink hands it to the template
    context -- the researched, Django-specific XSS footgun deferred from
    Phase B (`CC-LAB-0091`), per `docs/research/category2-social-ugc-
    functionality-and-cwe-research.md` §4 row 2 (a deliberately simpler,
    generic version of that row's own auto-linking-specific shape, see
    that entry's own "deliberate narrowing" note)."""

    def __init__(self) -> None:
        super().__init__("mark_safe_wrap", "transform", _TRANSFORM_ENV, "mark_safe_wrap.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = f"mark_safe({ctx['value_expr']})"
        return RenderResult(code=result.code, context=new_ctx)


class UncheckedUrlFetchTransform(TemplateModule):
    """The ``unchecked_url_fetch`` op (`CC-LAB-0094`): an explicit no-op,
    self-documenting rather than an empty pipeline relying on
    ``identity`` -- matches ``lab/safety_matrix.yaml``'s own
    ``unchecked_url_fetch``/``no_effect`` row for the
    ``server_side_http_fetch`` sink family. Publishes no new context;
    ``value_expr`` passes through unchanged."""

    def __init__(self) -> None:
        super().__init__("unchecked_url_fetch", "transform", _TRANSFORM_ENV, "unchecked_url_fetch.py.j2")


class SchemeAndResolvedIpAllowlistTransform(TemplateModule):
    """The ``scheme_and_resolved_ip_allowlist`` op (`CC-LAB-0094`): ports
    ``docs/research/corpus-examples/ssrf/python/idiomatic-oembed-
    unfurl-4.py``'s own defense almost line-for-line -- scheme check, then
    the *resolved* IP of the URL's hostname (``socket.gethostbyname()`` +
    ``ipaddress.ip_address(...).is_private/.is_loopback/.is_link_local``),
    raising ``ValueError`` on a disallowed scheme or resolved IP (fail-
    closed, propagated as Django's own real exception-handling path, same
    as the corpus example). Unlike every other transform in this
    inventory, this one emits real validation *statements*, not a
    ``value_expr``-wrapping expression -- ``value_expr`` itself passes
    through unchanged; the security effect is the ``raise`` happening
    before the sink ever runs, not a rewritten value."""

    def __init__(self) -> None:
        super().__init__(
            "scheme_and_resolved_ip_allowlist",
            "transform",
            _TRANSFORM_ENV,
            "scheme_and_resolved_ip_allowlist.py.j2",
        )


class UnfilteredBodyUpdateTransform(TemplateModule):
    """The ``unfiltered_body_update`` op (`CC-LAB-0095`): filters the
    whole-POST-body dict down to this table's own known real columns only
    -- SQL-column-name hygiene, not a security boundary. Every other
    submitted field, including privileged ones the real settings form
    never exposes, passes through unfiltered -- the mass-assignment
    (CWE-915) footgun. Reassigns ``value_expr`` in place (the same
    variable name, mutated to a filtered dict), unlike ``mark_safe_wrap``/
    ``html_entity_escape``, which rewrite ``value_expr`` to a new wrapping
    expression -- no context update is needed here since the variable
    name the sink reads never changes."""

    def __init__(self) -> None:
        super().__init__(
            "unfiltered_body_update", "transform", _TRANSFORM_ENV, "unfiltered_body_update.py.j2"
        )


class RuntimeFieldAllowlistTransform(TemplateModule):
    """The ``runtime_field_allowlist`` op (`CC-LAB-0095`): filters the
    whole-POST-body dict down to the real settings form's own
    publicly-settable fields only -- the actual security boundary for
    this shape, closing the mass-assignment gap
    `UnfilteredBodyUpdateTransform` leaves open."""

    def __init__(self) -> None:
        super().__init__(
            "runtime_field_allowlist", "transform", _TRANSFORM_ENV, "runtime_field_allowlist.py.j2"
        )


class OrmOrderByUnvalidatedTransform(TemplateModule):
    """The ``orm_order_by_unvalidated`` op (`CC-LAB-0096`): an explicit
    no-op -- the raw sort key passes straight through to the sink's
    ``ORDER BY`` clause, matching ``lab/safety_matrix.yaml``'s own
    ``orm_order_by_unvalidated``/``no_effect`` row for the
    ``sql_order_by_clause`` sink family."""

    def __init__(self) -> None:
        super().__init__(
            "orm_order_by_unvalidated", "transform", _TRANSFORM_ENV, "orm_order_by_unvalidated.py.j2"
        )


class IdentifierAllowlistTransform(TemplateModule):
    """The ``identifier_allowlist`` op (`CC-LAB-0096`): maps the raw sort
    key through a fixed, code-controlled dict of known-safe column names
    (``_ORDER_BY_ALLOWLIST``), defaulting to ``"id"`` for any
    unrecognized key -- closes both the ``sql_order_by_injection`` and
    ``sql_identifier_substitution`` concerns at once, matching
    ``lab/safety_matrix.yaml``'s own ``identifier_allowlist`` row.
    Reassigns ``value_expr`` in place (same convention as `CC-LAB-0095`'s
    own field-filtering transforms), not a wrapping expression."""

    def __init__(self) -> None:
        super().__init__(
            "identifier_allowlist", "transform", _TRANSFORM_ENV, "identifier_allowlist.py.j2"
        )


class UnrestrictedPickleLoadsTransform(TemplateModule):
    """The ``unrestricted_pickle_loads`` op (`CC-LAB-0097`,
    ``insecure_deserialization`` concern): flags the sink to parse the
    tainted value with Python's full ``pickle.loads()`` deserializer --
    any ``__reduce__`` hook in the byte stream is honored, executing
    arbitrary code during unpickling. A flag-only transform (mirroring
    ``ruby_rails``'s own ``YamlUnsafeLoadTransform``/``ParamBindTransform``
    convention exactly): the actual ``pickle.loads(...)`` call is emitted
    by the sink, not by this module, since the deserialize call and the
    ``try/except`` that observes its result belong together in one
    place. Safety matrix: ``effect=no_effect`` (the vulnerable twin)."""

    def __init__(self) -> None:
        super().__init__(
            "unrestricted_pickle_loads", "transform", _TRANSFORM_ENV, "unrestricted_pickle_loads.py.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = TemplateModule.render(self, ctx)
        new_ctx = dict(ctx)
        new_ctx["loader"] = "pickle"
        return RenderResult(code=result.code, context=new_ctx)


class JsonLoadsTypeCheckTransform(TemplateModule):
    """The ``json_loads_type_check`` op (`CC-LAB-0097`,
    ``insecure_deserialization`` concern): flags the sink to parse the
    tainted value with plain-data ``json.loads()`` instead of pickle --
    no ``__reduce__`` hook is ever honored -- and additionally requires
    the parsed result to be a ``dict``. Safety matrix:
    ``effect=neutralises``, ``neutralizes: [insecure_deserialization]``."""

    def __init__(self) -> None:
        super().__init__(
            "json_loads_type_check", "transform", _TRANSFORM_ENV, "json_loads_type_check.py.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = TemplateModule.render(self, ctx)
        new_ctx = dict(ctx)
        new_ctx["loader"] = "json"
        return RenderResult(code=result.code, context=new_ctx)


class SqlStringLiteralLookupSink(TemplateModule):
    """A single-row lookup by a quoted-string-literal-position column, with
    a second, non-tainted, already-hashed condition (a login-style password
    check) folded in as sink boilerplate -- the Django analogue of
    ``fuzzlab.labgen.modules.SqlStringLiteralLookupSink``/``node_express.
    modules.SqlStringLiteralLookupSink`` (`CC-LAB-0091`; the MD5 password
    hash is kept consistent with `node_express`'s own choice for this
    illustrative shape, not picked as a stronger hash here -- both stacks
    intentionally prove the same SQLi differential, not a hashing-strength
    lesson). Branches on ``bound`` (published by a transform), same
    contract as its siblings."""

    def __init__(self) -> None:
        super().__init__("sql_string_literal_lookup", "sink", _SINK_ENV, "sql_string_literal_lookup.py.j2")


class HtmlBodyEchoSink(TemplateModule):
    """Writes ``value_expr`` into an HTML response body via a raw
    ``HttpResponse`` string -- the Django analogue of ``fuzzlab.labgen.
    modules.HtmlBodyEchoSink``/``node_express.modules.HtmlBodyEchoSink``
    (`CC-LAB-0091`): a dev building a response by hand instead of through
    Django's own auto-escaping template layer, the realistic footgun this
    shape needs. Does not itself know or care whether ``value_expr`` was
    escaped upstream."""

    def __init__(self) -> None:
        super().__init__("html_body_echo", "sink", _SINK_ENV, "html_body_echo.py.j2")


class DjangoTemplateRenderSink(TemplateModule):
    """Renders through Django's real template engine
    (``django.shortcuts.render()``), the first sink in this emitter to
    do so rather than hand-building an ``HttpResponse``/``JsonResponse``
    string (`CC-LAB-0093`). Publishes no new context -- the companion
    ``.html`` template file this shape needs is **not** rendered through
    this module-composition system at all (a fixed Python string
    constant, `_COMMENT_TEMPLATE_HTML` in
    ``fuzzlab.labgen.emitters.django``, written directly by
    ``DjangoEmitter.render()`` -- seeCC-LAB-0093's own change-control
    entry for why: this project's own Jinja2 generation environments use
    the same ``{{ }}`` delimiter Django's own template engine uses, so a
    ``.html.j2`` generation template containing literal Django syntax
    would collide with generation-time rendering)."""

    def __init__(self) -> None:
        super().__init__("django_template_render", "sink", _SINK_ENV, "django_template_render.py.j2")


class HttpFetchJsonSink(TemplateModule):
    """Fetches an attacker-influenced URL server-side via ``requests.get()``
    and returns a JSON preview (`CC-LAB-0094`) -- the Django analogue of
    the researched corpus example's own vulnerable oEmbed/link-unfurl
    shape (``docs/research/corpus-examples/ssrf/python/vulnerable-oembed-
    unfurl-4.py``). Shared, byte-identical between the vulnerable and
    secure twin: the security boundary lives entirely in the
    **transform** (``scheme_and_resolved_ip_allowlist`` raises before this
    sink ever runs on the secure twin), never in the sink itself -- the
    same "sink is neutral" shape ``CC-LAB-0093``'s ``mark_safe_wrap``
    already established for this emitter. ``allow_redirects=False``
    closes the redirect-based bypass a pre-fetch-only allowlist would
    otherwise leave open (an allowlisted URL that 302s to a blocked
    target would reach ``requests.get()`` unresolved without it)."""

    def __init__(self) -> None:
        super().__init__("http_fetch_json_sink", "sink", _SINK_ENV, "http_fetch_json_sink.py.j2")


class ProfileBulkUpdateSink(TemplateModule):
    """Builds and executes a parameterized, multi-column ``UPDATE
    profiles SET ...`` from whatever fields survived the transform stage
    (`CC-LAB-0095`) -- the raw-``connection.cursor()`` analogue of a
    ``ModelForm``/serializer bulk-assignment sink, matching this
    emitter's own established "raw cursor, never the ORM" convention
    (`CC-LAB-0090`'s own reasoning). Shared, byte-identical between
    twins: the security boundary lives entirely in the **transform**
    (which fields survive to reach this sink), never in the sink itself
    -- the same "sink is neutral" shape `CC-LAB-0093`/`CC-LAB-0094`
    already established for this emitter. Column *values* are always
    parameterized (``%s`` placeholders); column *names* are always safe
    because every transform in this shape's inventory filters to a fixed,
    code-controlled set before the sink ever runs (never validated by
    the sink itself, which stays sink-family-generic)."""

    def __init__(self) -> None:
        super().__init__(
            "profile_bulk_update_sink", "sink", _SINK_ENV, "profile_bulk_update_sink.py.j2"
        )


class ExploreOrderBySink(TemplateModule):
    """Builds and executes a raw ``SELECT ... FROM posts ORDER BY
    <value_expr>`` (`CC-LAB-0096`) -- the Django-idiomatic realistic
    trigger for identifier/`ORDER BY`-position SQLi (a dev reaching for
    ``.extra()``/``RawSQL()`` instead of the ORM's parameterized
    ``.order_by()`` when a plain column name "isn't enough"), ported here
    as this emitter's own established raw-``connection.cursor()``
    convention. Shared, byte-identical between twins: the security
    boundary lives entirely in the **transform** (``identifier_allowlist``
    maps the sort key to a safe, hardcoded column name before this sink
    ever runs) -- the same "sink is neutral" shape every sink in this
    emitter since `CC-LAB-0093` has used."""

    def __init__(self) -> None:
        super().__init__("explore_order_by_sink", "sink", _SINK_ENV, "explore_order_by_sink.py.j2")


class InboxDeserializeSink(TemplateModule):
    """Deserializes a base64-encoded, attacker-supplied inbox/DM payload
    (`CC-LAB-0097`) -- the Django-idiomatic realistic trigger for
    `django.contrib.sessions.serializers.PickleSerializer`'s own real,
    documented opt-in footgun (§4 row 5), modeled here as an inbox
    message payload rather than a session cookie, since this emitter's
    per-cell views have no session-middleware round trip to exercise.
    Unlike every other sink in this emitter, this one is **not**
    byte-identical between twins: the deserialize *mechanism itself*
    (pickle vs. plain JSON) differs, so the transform stage flags which
    branch to render via Jinja2-time interpolation (`{% if loader ==
    "pickle" %}`) -- the same "flag-only transform, sink branches on it"
    convention `ruby_rails`'s own `YamlUnsafeLoadTransform`/
    `YamlSafeLoadTransform` pair already established for the identical
    architectural reason (Psych's `unsafe_load`/`safe_load`)."""

    def __init__(self) -> None:
        super().__init__("inbox_deserialize_sink", "sink", _SINK_ENV, "inbox_deserialize_sink.py.j2")


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
        # CC-LAB-0242: `html_row_template` (optional, per route profile)
        # swaps the JSON tail for a real Django-template page render --
        # passed through only when the route profile sets it.
        extra = {k: ctx[k] for k in ("html_row_template",) if k in ctx}
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"], **extra)
        return RenderResult(code=code, context=dict(ctx))


class RenderOnlyComplexity(TemplateModule):
    """A complexity wrapper for cells with no DB row to return -- the
    Django analogue of ``fuzzlab.labgen.modules.RenderOnlyComplexity``/
    ``node_express.modules.RenderOnlyComplexity`` (`CC-LAB-0091`), used by
    the ``html_body`` XSS shape (the sink's own ``return HttpResponse(...)``
    is the response mechanism; this wrapper adds no further boilerplate)."""

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.py.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        # CC-LAB-0242: `get_form_template`/`get_form_context` (optional, per
        # route profile) make a POST-processing page answer a non-POST
        # request with its form page before the source/transform/sink run.
        extra = {k: ctx[k] for k in ("get_form_template", "get_form_context") if k in ctx}
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"], **extra)
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "get_param": GetParamSource(),
    "post_param": PostParamSource(),
    "read_stored_field": ReadStoredFieldSource(),
    "post_body_dict": PostBodyDictSource(),
}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "param_bind": ParamBindTransform(),
    "html_entity_escape": HtmlEntityEscapeTransform(),
    "mark_safe_wrap": MarkSafeWrapTransform(),
    "unchecked_url_fetch": UncheckedUrlFetchTransform(),
    "scheme_and_resolved_ip_allowlist": SchemeAndResolvedIpAllowlistTransform(),
    "unfiltered_body_update": UnfilteredBodyUpdateTransform(),
    "runtime_field_allowlist": RuntimeFieldAllowlistTransform(),
    "orm_order_by_unvalidated": OrmOrderByUnvalidatedTransform(),
    "identifier_allowlist": IdentifierAllowlistTransform(),
    "unrestricted_pickle_loads": UnrestrictedPickleLoadsTransform(),
    "json_loads_type_check": JsonLoadsTypeCheckTransform(),
}
SINKS: dict[str, Module] = {
    "sql_numeric_lookup": SqlNumericLookupSink(),
    "sql_string_literal_lookup": SqlStringLiteralLookupSink(),
    "html_body_echo": HtmlBodyEchoSink(),
    "django_template_render": DjangoTemplateRenderSink(),
    "http_fetch_json_sink": HttpFetchJsonSink(),
    "profile_bulk_update_sink": ProfileBulkUpdateSink(),
    "explore_order_by_sink": ExploreOrderBySink(),
    "inbox_deserialize_sink": InboxDeserializeSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "single_statement": SingleStatementComplexity(),
    "render_only": RenderOnlyComplexity(),
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
