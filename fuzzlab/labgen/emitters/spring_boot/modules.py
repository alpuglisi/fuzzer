"""Composable rendering modules for the ``spring_boot`` emitter (`CC-LAB-0130`,
TrackerNest, category 3's Atlassian pick).

Mirrors ``fuzzlab.labgen.emitters.python_fastapi.modules``'s module-
composition architecture (small, independently authored ``source``/``sink``/
``complexity`` Jinja2 fragments an emitter composes per cell) but is a fully
independent implementation scoped to this package, per this project's "no
stack's emitter package imports another's" isolation rule
(``docs/LAB_IMPLEMENTATION_PLAN.md`` Phase 3).

**Why this stack's shape has no separate ``transform`` category.** The
``ssti``/``template_render`` concern (`lab/safety_matrix.yaml`) is not a
"tainted value passes through zero-or-more transforms before a fixed sink"
shape the way SQLi/XSS are -- the vulnerable and secure ops
(``user_supplied_template_compile`` vs. ``file_loaded_template_name``, per
`docs/research/corpus-examples/ssti/php/manifest.yaml`'s own
``suggested_op`` values) describe two different things the **sink itself**
does with the tainted value (compile it as an expression, vs. use it only to
select among a fixed, developer-defined set of template bodies) -- so here
the op selects which **sink** module renders, not a pipeline stage applied
before a fixed one. ``Cell.transform.ops`` is still the field that carries
this (per ``fuzzlab.labgen.schema.Cell``'s general "ops applied" contract),
interpreted this way by this emitter specifically.

Same determinism discipline as every other stack's module system: the one
:class:`jinja2.Environment` here sets ``trim_blocks=True, lstrip_blocks=True,
keep_trailing_newline=True`` explicitly, and templates are only ever given
already-computed, already-ordered values.
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


SOURCE_ENV = _make_env("sources")
SINK_ENV = _make_env("sinks")
COMPLEXITY_ENV = _make_env("complexities")


@dataclass(frozen=True)
class RenderResult:
    code: str
    context: dict[str, Any]


class Module:
    name: str
    category: str
    cardinality: str = "per_cell"

    def render(self, ctx: dict[str, Any]) -> RenderResult:  # pragma: no cover - abstract
        raise NotImplementedError


class TemplateModule(Module):
    def __init__(self, name: str, category: str, env: Environment, template_name: str):
        self.name = name
        self.category = category
        self._env = env
        self._template_name = template_name

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(**ctx)
        return RenderResult(code=code, context=dict(ctx))


class QueryParamSource(TemplateModule):
    """Extracts one query parameter via ``HttpServletRequest.getParameter``
    -- deliberately the raw Servlet API, not a typed ``@RequestParam``
    argument (a ``@RequestParam String`` still arrives untyped/uncoerced for
    a String parameter, but manual ``getParameter`` access matches how the
    real Confluence OGNL-injection CVEs' vulnerable code paths actually
    pulled the tainted value -- see
    docs/research/category3-saas-functionality-and-cwe-research.md sec 4).
    Publishes ``value_expr`` -- same contract as every other stack's source
    module."""

    def __init__(self) -> None:
        super().__init__("query_param", "source", SOURCE_ENV, "query_param.java.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        return RenderResult(code=result.code, context=new_ctx)


class UserSuppliedTemplateCompileSink(TemplateModule):
    """The vulnerable op: the tainted value is evaluated as an OGNL
    expression via ``Ognl.getValue()`` -- CWE-1336, the real shape behind
    CVE-2021-26084/CVE-2022-26134 (application-level: compiling tainted
    input as an expression at all, not a specific OGNL library CVE)."""

    def __init__(self) -> None:
        super().__init__(
            "user_supplied_template_compile", "sink", SINK_ENV, "user_supplied_template_compile.java.j2"
        )


class FileLoadedTemplateNameSink(TemplateModule):
    """The secure twin: the tainted value only ever selects among a fixed,
    developer-defined ``Map`` of macro bodies -- never compiled/evaluated as
    an expression, matching this concern's ``file_loaded_template_name``
    neutralizing op in `lab/safety_matrix.yaml`."""

    def __init__(self) -> None:
        super().__init__("file_loaded_template_name", "sink", SINK_ENV, "file_loaded_template_name.java.j2")


class RawBodySource(TemplateModule):
    """Reads the entire raw request body as a UTF-8 string
    (`CC-LAB-0131`) -- for a cell whose tainted value (e.g. an XML document
    with a DOCTYPE) cannot be a query parameter."""

    def __init__(self) -> None:
        super().__init__("raw_body", "source", SOURCE_ENV, "raw_body.java.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = ctx["var_name"]
        return RenderResult(code=result.code, context=new_ctx)


class XmlExternalEntitiesEnabledSink(TemplateModule):
    """The vulnerable op (`CC-LAB-0131`): parses the tainted XML body with a
    default-configured ``DocumentBuilderFactory`` -- external entities and
    DOCTYPE declarations are resolved, matching `lab/safety_matrix.yaml`'s
    `xml_external_entities_enabled` op (CWE-611)."""

    def __init__(self) -> None:
        super().__init__(
            "xml_external_entities_enabled", "sink", SINK_ENV, "xml_external_entities_enabled.java.j2"
        )


class XmlExternalEntitiesDisabledSink(TemplateModule):
    """The secure twin (`CC-LAB-0131`): the same parse, but with Xerces/
    JAXP's `disallow-doctype-decl` feature set first -- the real, standard
    Java XXE fix, matching `lab/safety_matrix.yaml`'s
    `xml_external_entities_disabled` neutralizing op."""

    def __init__(self) -> None:
        super().__init__(
            "xml_external_entities_disabled", "sink", SINK_ENV, "xml_external_entities_disabled.java.j2"
        )


class RequestStreamSource(TemplateModule):
    """A no-op source (`CC-LAB-0132`): the deserialization shape's sink
    reads `request.getInputStream()` directly (binary data -- converting to
    a `String` first, as `RawBodySource` does for the text-shaped XXE cell,
    would corrupt it). Exists to keep this emitter's source/sink/complexity
    composition contract uniform rather than special-casing this one shape
    to skip a source module entirely."""

    def __init__(self) -> None:
        super().__init__("request_stream", "source", SOURCE_ENV, "request_stream.java.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = "request"
        return RenderResult(code=result.code, context=new_ctx)


class JacksonBodySource(TemplateModule):
    """Reads the raw request body into a byte array (`CC-LAB-0173`, the
    §9.2a Java/Spring Boot consolidation port) -- the Jackson-based
    deserialization cells construct their own `JsonMapper` in the sink
    (with or without polymorphic default typing), so unlike
    `RequestStreamSource` this source does need to render real code, but
    still publishes only raw material for the sink to interpret, matching
    every other stack's "source publishes raw material, sink/transform
    decides the safe/unsafe shape" convention. Ported from
    `java_spring_boot`'s original `ReadPlaybackEventBodySource`, re-targeted
    at Jackson 3's real API (`tools.jackson.databind.*`, not the Jackson-2
    `com.fasterxml.jackson.databind.*` the original used against Spring
    Boot 3.4.1 -- see this entry's own change-control record for the real
    API-migration finding)."""

    def __init__(self) -> None:
        super().__init__("jackson_body", "source", SOURCE_ENV, "jackson_body.java.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        result = super().render(ctx)
        new_ctx = dict(ctx)
        new_ctx["value_expr"] = "requestBody"
        return RenderResult(code=result.code, context=new_ctx)


class JacksonDefaultTypingDeserializeSink(TemplateModule):
    """The vulnerable op (`CC-LAB-0173`, ported from `java_spring_boot`):
    deserializes into a polymorphic `Object` via Jackson 3's
    `JsonMapper.builder().activateDefaultTyping(...)` -- CWE-502, the
    concrete runtime type is resolved from an attacker-controlled type
    hint embedded in the JSON body itself. Matches
    `lab/safety_matrix.yaml`'s `jackson_default_typing_deserialize` op."""

    def __init__(self) -> None:
        super().__init__(
            "jackson_default_typing_deserialize", "sink", SINK_ENV, "jackson_default_typing_deserialize.java.j2"
        )


class JacksonTypedAllowlistDeserializeSink(TemplateModule):
    """The secure twin (`CC-LAB-0173`, ported from `java_spring_boot`):
    deserializes into a single, fixed, concrete DTO class
    (`PlaybackResumeRequest`) -- no polymorphism, so the attacker cannot
    redirect the runtime type. Matches `lab/safety_matrix.yaml`'s
    `jackson_typed_allowlist_deserialize` neutralizing op."""

    def __init__(self) -> None:
        super().__init__(
            "jackson_typed_allowlist_deserialize", "sink", SINK_ENV, "jackson_typed_allowlist_deserialize.java.j2"
        )


class FunctionExecutingDeserializeSink(TemplateModule):
    """The vulnerable op (`CC-LAB-0132`): an unrestricted
    `ObjectInputStream.readObject()` -- will construct any `Serializable`
    class present on the classpath the stream names, matching
    `lab/safety_matrix.yaml`'s `function_executing_deserialize` op
    (CWE-502)."""

    def __init__(self) -> None:
        super().__init__(
            "function_executing_deserialize", "sink", SINK_ENV, "function_executing_deserialize.java.j2"
        )


class HandlerRegistryLookupSink(TemplateModule):
    """The secure twin (`CC-LAB-0132`): a `resolveClass()`-override
    allowlist permitting exactly one expected class name, matching
    `lab/safety_matrix.yaml`'s `handler_registry_lookup` neutralizing op."""

    def __init__(self) -> None:
        super().__init__("handler_registry_lookup", "sink", SINK_ENV, "handler_registry_lookup.java.j2")


class StandardEvaluationContextUnrestrictedSink(TemplateModule):
    """The vulnerable op (`CC-LAB-0214`): parses the tainted value as a
    Spring Expression Language (SpEL) expression and evaluates it against
    an unrestricted `StandardEvaluationContext` -- CWE-917, the real
    mechanism behind CVE-2018-1273 (Spring Data Commons). Permits
    arbitrary type references (`T(...)`), method invocation, and bean
    resolution. Matches `lab/safety_matrix.yaml`'s
    `standard_evaluation_context_unrestricted` op."""

    def __init__(self) -> None:
        super().__init__(
            "standard_evaluation_context_unrestricted",
            "sink",
            SINK_ENV,
            "standard_evaluation_context_unrestricted.java.j2",
        )


class SimpleEvaluationContextRestrictedSink(TemplateModule):
    """The secure twin (`CC-LAB-0214`): the identical parse/evaluate call,
    but against a restricted `SimpleEvaluationContext` -- Spring's own
    documented fix for CVE-2018-1273. Rejects type references, method
    invocation, and bean resolution while still permitting ordinary
    property/index access. Matches `lab/safety_matrix.yaml`'s
    `simple_evaluation_context_restricted` neutralizing op."""

    def __init__(self) -> None:
        super().__init__(
            "simple_evaluation_context_restricted",
            "sink",
            SINK_ENV,
            "simple_evaluation_context_restricted.java.j2",
        )


class ReadAccountIdAndCallerHeaderSource(TemplateModule):
    """Reads the attacker-visible ``account_id`` query param and the fixed
    demo ``X-Account-Id`` header standing in for the caller's own
    authenticated identity (`CC-LAB-0187`) -- this stack has no session/
    auth system yet, the same declared simplification
    ``go_net_http``'s own ``ReadChannelIdAndBroadcasterHeaderSource``
    (`CC-LAB-0178`) already uses for its ``X-Broadcaster-Id`` header, ported
    here for Netflix's first ``access_control``/IDOR page. Publishes
    ``account_id_var``/``caller_id_var`` (two Java identifiers) for the sink
    module (selected by the op, per this package's own op-selects-sink
    convention -- see this module's own docstring) to compose its own
    ownership decision. Unlike ``go_net_http``'s shape, this stack has no
    separate transform stage, so there is no ``value_expr`` published here:
    each sink implements its own ownership check (or deliberate lack of
    one) directly, rather than branching on a value a transform computed."""

    def __init__(self) -> None:
        super().__init__(
            "read_account_id_and_caller_header", "source", SOURCE_ENV,
            "read_account_id_and_caller_header.java.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("account_id_var", "accountId")
        render_ctx.setdefault("caller_id_var", "callerAccountId")
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class NoOwnershipCheckObjectLookupSink(TemplateModule):
    """The vulnerable op (`lab/safety_matrix.yaml`'s ``no_ownership_check``,
    ``db_row_by_id_lookup`` family, ``no_effect`` -- added by `CC-LAB-0063`,
    already instantiated on ``go_net_http`` by `CC-LAB-0178`; `CC-LAB-0187`
    is its first instantiation for ``spring_boot``): returns canned
    account-billing data (payment method, last invoice amount, billing
    cycle) for whatever ``account_id`` is given, ignoring the caller's own
    ``X-Account-Id`` entirely (CWE-639/862, broken object-level
    authorization / IDOR)."""

    def __init__(self) -> None:
        super().__init__("no_ownership_check", "sink", SINK_ENV, "no_ownership_check.java.j2")


class IdentityMatchBeforeFetchObjectLookupSink(TemplateModule):
    """The secure twin (``identity_match_before_fetch``, ``neutralises`` --
    `CC-LAB-0187`): requires the requested ``account_id`` to equal the
    caller's own ``X-Account-Id`` before returning any billing data; a
    mismatch is a real HTTP 403 with no data, matching ``go_net_http``'s own
    ``ObjectLookupAuthorizationCheckSink`` shape."""

    def __init__(self) -> None:
        super().__init__(
            "identity_match_before_fetch", "sink", SINK_ENV, "identity_match_before_fetch.java.j2"
        )


class SingleHandlerComplexity(TemplateModule):
    def __init__(self) -> None:
        super().__init__("single_handler", "complexity", COMPLEXITY_ENV, "single_handler.java.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(
            class_name=ctx["class_name"],
            route_path=ctx["route_path"],
            handler_name=ctx["handler_name"],
            mapping_annotation=ctx["mapping_annotation"],
            body=ctx["body"],
        )
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "query_param": QueryParamSource(),
    "raw_body": RawBodySource(),
    "request_stream": RequestStreamSource(),
    "jackson_body": JacksonBodySource(),
    "read_account_id_and_caller_header": ReadAccountIdAndCallerHeaderSource(),
}
#: Keyed by the op name that selects this sink (see this module's own
#: docstring for why the op selects the sink here, not a pre-sink
#: transform).
SINKS: dict[str, Module] = {
    "user_supplied_template_compile": UserSuppliedTemplateCompileSink(),
    "file_loaded_template_name": FileLoadedTemplateNameSink(),
    "xml_external_entities_enabled": XmlExternalEntitiesEnabledSink(),
    "xml_external_entities_disabled": XmlExternalEntitiesDisabledSink(),
    "function_executing_deserialize": FunctionExecutingDeserializeSink(),
    "handler_registry_lookup": HandlerRegistryLookupSink(),
    "jackson_default_typing_deserialize": JacksonDefaultTypingDeserializeSink(),
    "jackson_typed_allowlist_deserialize": JacksonTypedAllowlistDeserializeSink(),
    "standard_evaluation_context_unrestricted": StandardEvaluationContextUnrestrictedSink(),
    "simple_evaluation_context_restricted": SimpleEvaluationContextRestrictedSink(),
    "no_ownership_check": NoOwnershipCheckObjectLookupSink(),
    "identity_match_before_fetch": IdentityMatchBeforeFetchObjectLookupSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "single_handler": SingleHandlerComplexity(),
}
