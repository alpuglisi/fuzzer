"""Composable Rails rendering modules for the ``ruby_rails`` emitter.

Phase A (the ``("xss", "html_body")`` illustrative shape) plus Phase B
(``CC-LAB-0072``..``CC-LAB-0075``/``FR-LAB-66``..``FR-LAB-68``): the three
real, Shopify-grounded Rails-idiom vulnerability modules
``docs/research/site-architecture-survey-functionality-shopify.md`` /
``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §9.4a's "Decided" block
name --

- webhook-signature verification (naive ``==`` vs
  ``ActiveSupport::SecurityUtils.secure_compare``), reusing this project's
  existing ``webhook_signature_verification`` sink family and
  ``naive_string_compare``/``constant_time_compare`` op vocabulary
  (``lab/safety_matrix.yaml``) verbatim -- no emitter had implemented that
  family in code before this lane.
- CWE-915 mass assignment (Rails' own ``permit!`` vs an explicit
  ``permit(:a, :b)`` allowlist) against the existing ``orm_entity_bulk_assign``
  sink family, minting the two ``permit!``-specific op names
  (``permit_bang_unrestricted``/``strong_params_explicit_allowlist``) that
  Rails' strong-parameters idiom needs and no other stack's op vocabulary
  already covers -- mirroring how ``orm_fields_option_allowlist``/
  ``typed_graphql_field_mapping``/etc. are each their own framework's own
  named mechanism in ``lab/safety_matrix.yaml``'s mass-assignment group.
- CWE-502 insecure deserialization (``YAML.unsafe_load`` vs
  ``YAML.safe_load``) against the existing ``object_deserialization`` sink
  family, minting the two Psych-specific op names
  (``yaml_unsafe_load``/``yaml_safe_load``) the same way
  ``unrestricted_pickle_loads``/``json_loads_type_check`` are Python's own
  named mechanism there.

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

Phase A registered only the one shape its illustrative cell needed
(``("xss", "html_body")``); Phase B (this delivery) adds the three shapes
above. Deepening this inventory further (e.g. the deferred ``order``/
``pluck`` identifier-position SQLi variant §9.4a names as a follow-up, not
this pass) remains later, separate scope.

Determinism: the one :class:`jinja2.Environment` this module builds sets
``trim_blocks``, ``lstrip_blocks`` and ``keep_trailing_newline`` explicitly
(never Jinja2's defaults) and templates are handed already-computed values,
so two renders of the same inputs are byte-identical (NFR-LAB-reproducible).
"""

from __future__ import annotations

import re
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

#: CC-LAB-0245 (PA-0053/PA-0054): the only absent-input behaviors a named
#: ``params`` read may render with. A source asked to render without one is an
#: emitter-authoring bug -- there is deliberately no bare ``params[:name]``
#: fallback for an undeclared input.
_ABSENT_KINDS = ("default", "required_4xx")


def _require_declared_absent_input(ctx: dict[str, Any], source: str) -> None:
    kind = ctx.get("absent_kind")
    if kind not in _ABSENT_KINDS:
        raise ValueError(
            f"{source} source for param {ctx.get('param_name')!r} has no declared absent-input "
            f"behavior (absent_kind={kind!r}, expected one of {_ABSENT_KINDS}) -- declare it in "
            "ruby_rails._ABSENT_INPUT_BY_SHAPE (PA-0053/PA-0054)"
        )
    if kind == "default" and not ctx.get("default_rb"):
        raise ValueError(f"{source} source: absent_kind 'default' needs a rendered default_rb")



class GetParamSource(TemplateModule):
    """One query-string parameter read through Rails' ``params`` accessor
    (``params[:id]``), publishing ``value_expr``/``bound=False`` -- the Rails
    analogue of ``fuzzlab.labgen.modules.GetParamSource``'s ``$_GET`` read /
    ``php_laravel``'s ``$request->query(...)``."""

    def __init__(self) -> None:
        super().__init__("get_param", "source", _SOURCE_ENV, "get_param.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        _require_declared_absent_input(ctx, "get_param")
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        new_ctx.setdefault("bound", False)
        return RenderResult(code=result.code, context=new_ctx)


class PostParamSource(TemplateModule):
    """One POST-body parameter read through Rails' unified ``params``
    accessor (``params[:yaml_payload]``) -- the ``post_param`` shared-
    vocabulary name (:mod:`fuzzlab.labgen.modules`' own
    ``PostParamSource``), reused here even though Rails' ``params`` does not
    itself distinguish GET/POST origin (unlike PHP's separate
    ``$_GET``/``$_POST`` superglobals) -- the name records *where this
    project's page profile puts the value*, not a Rails-specific mechanism
    difference from :class:`GetParamSource`."""

    def __init__(self) -> None:
        super().__init__("post_param", "source", _SOURCE_ENV, "post_param.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        _require_declared_absent_input(ctx, "post_param")
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        return RenderResult(code=result.code, context=new_ctx)


class AllParamsNestedSource(TemplateModule):
    """The ``all_params_nested`` source (CC-LAB-0073, ``mass_assignment``):
    reads the whole *nested* strong-parameters root for one resource
    (``params.require(:user)``) -- the real Rails idiom a
    ``permit!``/``permit(:a, :b)`` pair is applied to, distinct from
    :class:`GetParamSource`'s single scalar read. Genuinely new: no other
    stack's source vocabulary needs a nested-root read, since PHP's
    ``$request->all()`` (``all_post_params``, php_laravel) reads the flat
    top-level body instead -- Rails' own strong-parameters convention
    nests a resource's fields under one root key by default."""

    def __init__(self) -> None:
        super().__init__("all_params_nested", "source", _SOURCE_ENV, "all_params_nested.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        return RenderResult(code=result.code, context=new_ctx)


class RawRequestBodySource(TemplateModule):
    """The ``raw_request_body`` source (CC-LAB-0072, webhook-signature):
    reads the raw HTTP request body bytes (``request.body.read``) -- a
    webhook-signature check must recompute its HMAC over the exact raw
    bytes the provider signed, never a re-serialized/re-parsed form (per
    ``docs/research/site-architecture-survey-functionality-shopify.md``
    §1's own correctness note), so this is genuinely distinct from every
    ``params``-based source above."""

    def __init__(self) -> None:
        super().__init__("raw_request_body", "source", _SOURCE_ENV, "raw_request_body.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
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


def _ruby_symbol_list(values: tuple[str, ...]) -> str:
    """Render an already-ordered tuple of bare identifiers as a Ruby
    symbol-list literal body (``:username, :bio``) for a strong-parameters
    ``permit(...)`` call. Mirrors ``php_laravel.modules._php_string_list``'s
    exact discipline: an emitter-side authoring bug (an empty allowlist, or
    an allowlist entry that is not a bare identifier) fails loud here rather
    than being emitted as an escaping problem for later."""
    if not values:
        raise ValueError(
            "strong_params_explicit_allowlist transform's allowed_fields is empty -- an "
            "allowlist transform with nothing allowed has no safe fallback to fall back "
            "to; supply the real fields in the emitter's shape context"
        )
    for value in values:
        if not re.fullmatch(r"[A-Za-z0-9_]+", value):
            raise ValueError(
                f"strong_params_explicit_allowlist entry {value!r} is not a bare identifier "
                "([A-Za-z0-9_]+) -- allowlisted fields are emitted into Ruby source verbatim "
                "as symbols and are never escaped or quoted for you"
            )
    return ", ".join(f":{value}" for value in values)


class PermitBangUnrestrictedTransform(TemplateModule):
    """The ``permit_bang_unrestricted`` op (CC-LAB-0073, ``mass_assignment``
    concern): rewrites ``value_expr`` to ``value_expr.permit!`` -- Rails'
    own unrestricted strong-parameters escape hatch, which accepts every key
    the client sent, including any field the endpoint never intended to
    expose. Safety matrix: ``effect=no_effect`` (the vulnerable twin)."""

    def __init__(self) -> None:
        super().__init__(
            "permit_bang_unrestricted", "transform", _TRANSFORM_ENV, "permit_bang_unrestricted.rb.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = TemplateModule.render(self, ctx)
        new_ctx = dict(ctx)
        return RenderResult(code=result.code, context=new_ctx)


class StrongParamsExplicitAllowlistTransform(TemplateModule):
    """The ``strong_params_explicit_allowlist`` op (CC-LAB-0073,
    ``mass_assignment`` concern): rewrites ``value_expr`` to
    ``value_expr.permit(:a, :b)`` -- Rails' own explicit strong-parameters
    allowlist. Requires ``allowed_fields`` in the assembly context (an
    ordered tuple of the real fields this endpoint may update -- mirrors
    ``RuntimeFieldAllowlistTransform``'s/``IdentifierAllowlistTransform``'s
    "no safe default" design exactly). Safety matrix:
    ``effect=neutralises``, ``neutralizes: [mass_assignment]``."""

    def __init__(self) -> None:
        super().__init__(
            "strong_params_explicit_allowlist",
            "transform",
            _TRANSFORM_ENV,
            "strong_params_explicit_allowlist.rb.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        try:
            allowed = tuple(ctx["allowed_fields"])
        except KeyError as exc:
            raise ValueError(
                "strong_params_explicit_allowlist transform needs an 'allowed_fields' "
                "context value (an ordered tuple of the real fields this endpoint may "
                "update) -- the emitter's shape context must supply it; there is no "
                "safe default"
            ) from exc
        new_ctx = dict(ctx)
        new_ctx["allowed_fields_rb"] = _ruby_symbol_list(allowed)
        result = TemplateModule.render(self, new_ctx)
        return RenderResult(code=result.code, context=new_ctx)


class YamlUnsafeLoadTransform(TemplateModule):
    """The ``yaml_unsafe_load`` op (CC-LAB-0074, ``insecure_deserialization``
    concern): flags the sink to parse the tainted value with Psych's full
    object-graph loader (``YAML.unsafe_load``) -- any ``!ruby/object:...``
    tag in the input is honored, constructing an attacker-chosen Ruby
    object (CVE-2013-0156's own mechanism, applied here directly rather
    than through Rails' XML-parameter-parser entry point that CVE used).
    A flag-only transform (like ``ParamBindTransform``'s own docstring
    calls out): the actual ``YAML.unsafe_load(...)`` call is emitted by the
    sink, not by this module, since the deserialize call and the
    begin/rescue that observes its result belong together in one place.
    Safety matrix: ``effect=no_effect`` (the vulnerable twin)."""

    def __init__(self) -> None:
        super().__init__("yaml_unsafe_load", "transform", _TRANSFORM_ENV, "yaml_unsafe_load.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = TemplateModule.render(self, ctx)
        new_ctx = dict(ctx)
        new_ctx["deserialize_method"] = "unsafe_load"
        return RenderResult(code=result.code, context=new_ctx)


class YamlSafeLoadTransform(TemplateModule):
    """The ``yaml_safe_load`` op (CC-LAB-0074, ``insecure_deserialization``
    concern): flags the sink to parse the tainted value with Psych's
    restricted loader (``YAML.safe_load``) -- only YAML's built-in scalar/
    array/hash types are permitted; a ``!ruby/object:...`` tag raises
    ``Psych::DisallowedClass`` instead of building the object. Safety
    matrix: ``effect=neutralises``, ``neutralizes: [insecure_deserialization]``."""

    def __init__(self) -> None:
        super().__init__("yaml_safe_load", "transform", _TRANSFORM_ENV, "yaml_safe_load.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = TemplateModule.render(self, ctx)
        new_ctx = dict(ctx)
        new_ctx["deserialize_method"] = "safe_load"
        return RenderResult(code=result.code, context=new_ctx)


class NaiveStringCompareTransform(TemplateModule):
    """The ``naive_string_compare`` op (CC-LAB-0072, ``weak_signature_
    comparison`` concern -- reused verbatim from ``lab/safety_matrix.yaml``'s
    existing webhook-signature group, no new op minted): flags the sink to
    compare the computed and provided HMAC digests with plain ``==``, which
    short-circuits on the first mismatched byte -- a timing side channel,
    not a correctness bypass for a well-formed forged signature (both
    twins still correctly reject a wrong signature and accept a right one;
    see this module's own package docstring / the paired live-boot test's
    module docstring for how the actual timing-safety divergence is
    proven). Safety matrix: ``effect=partial``, ``neutralizes:
    [weak_signature_comparison]``."""

    def __init__(self) -> None:
        super().__init__("naive_string_compare", "transform", _TRANSFORM_ENV, "naive_string_compare.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = TemplateModule.render(self, ctx)
        new_ctx = dict(ctx)
        new_ctx["compare_expr"] = "computed == provided"
        return RenderResult(code=result.code, context=new_ctx)


class ConstantTimeCompareTransform(TemplateModule):
    """The ``constant_time_compare`` op (CC-LAB-0072, ``weak_signature_
    comparison`` concern -- reused verbatim, see :class:`NaiveStringCompareTransform`):
    flags the sink to compare the computed and provided HMAC digests with
    Rails' own ``ActiveSupport::SecurityUtils.secure_compare`` -- the real,
    sourced Shopify-adjacent idiom
    (``docs/research/site-architecture-survey-functionality-shopify.md``
    §1). Safety matrix: ``effect=neutralises``, ``neutralizes:
    [weak_signature_comparison]``."""

    def __init__(self) -> None:
        super().__init__("constant_time_compare", "transform", _TRANSFORM_ENV, "constant_time_compare.rb.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = TemplateModule.render(self, ctx)
        new_ctx = dict(ctx)
        new_ctx["compare_expr"] = "ActiveSupport::SecurityUtils.secure_compare(computed, provided)"
        return RenderResult(code=result.code, context=new_ctx)


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


class OrmEntityBulkAssignSink(TemplateModule):
    """The ``orm_entity_bulk_assign`` sink family (CC-LAB-0073,
    mass-assignment), reusing the existing family name
    (``lab/safety_matrix.yaml``, implemented so far only by
    ``php_laravel``'s own ``DB::table(...)->update($fields)`` twin) --
    Rails' idiomatic equivalent is a real ActiveRecord ``update!`` call
    against the checked-in ``users`` table (see this stack's own
    ``stack/README.md`` Phase B addendum for the paired migration that adds
    its one privilege-relevant ``role`` column). Every key present in the
    upstream strong-parameters hash at this point -- unrestricted when
    ``permit_bang_unrestricted`` ran, allowlisted when
    ``strong_params_explicit_allowlist`` ran -- becomes an attribute this
    write sets; the sink itself never filters anything, exactly like every
    other sink in this registry."""

    def __init__(self) -> None:
        super().__init__("orm_entity_bulk_assign", "sink", _SINK_ENV, "orm_entity_bulk_assign.rb.j2")


class ObjectDeserializationSink(TemplateModule):
    """The ``object_deserialization`` sink family (CC-LAB-0074,
    insecure-deserialization), reusing the existing family name
    (``lab/safety_matrix.yaml``, not previously implemented by any
    emitter). Requires ``deserialize_method`` in the assembly context
    (``"unsafe_load"``/``"safe_load"``, set by whichever transform op ran --
    see :class:`YamlUnsafeLoadTransform`/:class:`YamlSafeLoadTransform`).
    Reports which Ruby class the parsed value actually became (or which
    exception class Psych raised) as JSON -- the real, observable
    vulnerable/secure divergence this class's own live-boot test asserts
    against: an attacker-supplied ``!ruby/object:...`` tag builds a real
    Ruby object under ``unsafe_load`` and is rejected
    (``Psych::DisallowedClass``) under ``safe_load``."""

    def __init__(self) -> None:
        super().__init__("object_deserialization", "sink", _SINK_ENV, "object_deserialization.rb.j2")


class WebhookSignatureVerificationSink(TemplateModule):
    """The ``webhook_signature_verification`` sink family (CC-LAB-0072,
    webhook-signature), reusing the existing family name
    (``lab/safety_matrix.yaml``, not previously implemented by any
    emitter). Requires ``header_name``/``secret``/``compare_expr`` in the
    assembly context (``compare_expr`` set by whichever transform op ran --
    see :class:`NaiveStringCompareTransform`/:class:`ConstantTimeCompareTransform`).
    Recomputes the HMAC-SHA256 over the real raw request body
    (:class:`RawRequestBodySource`) exactly as Shopify's own mechanism does
    (``docs/research/site-architecture-survey-functionality-shopify.md``
    §1), then compares it to the header value using whichever comparison
    the cell's transform selected."""

    def __init__(self) -> None:
        super().__init__(
            "webhook_signature_verification", "sink", _SINK_ENV, "webhook_signature_verification.rb.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        for required in ("header_name", "secret", "compare_expr"):
            if required not in ctx:
                raise ValueError(
                    f"webhook_signature_verification sink needs {required!r} in the assembly "
                    "context -- the emitter's shape context and a naive_string_compare/"
                    "constant_time_compare transform must both have run first"
                )
        new_ctx = dict(ctx)
        new_ctx["secret_rb"] = f'"{ctx["secret"]}"'
        result = TemplateModule.render(self, new_ctx)
        return RenderResult(code=result.code, context=new_ctx)


# --- complexities ---------------------------------------------------------------


class RenderOnlyComplexity(TemplateModule):
    """Wraps a source + transform(s) into one controller action body that
    assigns ``@value`` and renders the paired view -- the Rails analogue of
    ``php_laravel``'s ``render_only.php.j2`` (a ``return view(...)`` action).
    """

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.rb.j2")


class SingleStatementComplexity(TemplateModule):
    """The ``single_statement`` complexity (CC-LAB-0072..0074), reusing the
    existing shared name (``php_laravel.modules.SingleStatementComplexity``):
    the controller method for a cell whose sink itself already renders a
    JSON response (:class:`OrmEntityBulkAssignSink`,
    :class:`ObjectDeserializationSink`,
    :class:`WebhookSignatureVerificationSink`) rather than handing a value
    to a separate view file, per :class:`RenderOnlyComplexity`'s own
    docstring on why this Rails stack needs a second complexity module for
    exactly the same reason ``php_laravel``/``php_current`` do."""

    def __init__(self) -> None:
        super().__init__("single_statement", "complexity", _COMPLEXITY_ENV, "single_statement.rb.j2")


SOURCES: dict[str, Module] = {
    "get_param": GetParamSource(),
    "post_param": PostParamSource(),
    "all_params_nested": AllParamsNestedSource(),
    "raw_request_body": RawRequestBodySource(),
}
TRANSFORMS: dict[str, Module] = {
    "identity": IdentityTransform(),
    "html_entity_escape": HtmlEntityEscapeTransform(),
    "permit_bang_unrestricted": PermitBangUnrestrictedTransform(),
    "strong_params_explicit_allowlist": StrongParamsExplicitAllowlistTransform(),
    "yaml_unsafe_load": YamlUnsafeLoadTransform(),
    "yaml_safe_load": YamlSafeLoadTransform(),
    "naive_string_compare": NaiveStringCompareTransform(),
    "constant_time_compare": ConstantTimeCompareTransform(),
}
SINKS: dict[str, Module] = {
    "html_body_echo": HtmlBodyEchoSink(),
    "orm_entity_bulk_assign": OrmEntityBulkAssignSink(),
    "object_deserialization": ObjectDeserializationSink(),
    "webhook_signature_verification": WebhookSignatureVerificationSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "render_only": RenderOnlyComplexity(),
    "single_statement": SingleStatementComplexity(),
}
