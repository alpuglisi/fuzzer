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


class ReadPlanChangeRequestSource(TemplateModule):
    """Reads a subscription plan-change request body (`CC-LAB-0188`,
    `price_integrity_bypass` concern) -- parses the JSON body with a plain
    Jackson 3 `JsonMapper.readTree()` (this stack's existing Jackson-3
    convention, `CC-LAB-0173`) and publishes two Java `String` locals:
    ``plan_tier_var`` (the requested tier, e.g. ``"standard"``) and
    ``client_price_var`` (whatever price/monthly-charge value the client
    submitted -- untrusted, and read by both twins' sinks only so they
    share one minimal-pair source; only the vulnerable twin actually uses
    it). Unlike `ReadAccountIdAndCallerHeaderSource`, this source's tainted
    material lives in the JSON body, not a query param/header -- the same
    real-world shape `JacksonBodySource` already established for this
    stack's whole-body-JSON cells, but this shape needs two named fields
    parsed out, not the whole body handed to a sink-owned deserializer."""

    def __init__(self) -> None:
        super().__init__(
            "read_plan_change_request", "source", SOURCE_ENV, "read_plan_change_request.java.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("plan_tier_var", "planTier")
        render_ctx.setdefault("client_price_var", "clientMonthlyCharge")
        render_ctx.setdefault("plan_tier_field", "plan_tier")
        render_ctx.setdefault("client_price_field", "monthly_charge")
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class ClientTrustedAmountSink(TemplateModule):
    """The vulnerable op (`lab/safety_matrix.yaml`'s existing
    ``client_trusted_amount`` op, ``payment_charge_amount`` sink family,
    ``no_effect`` -- added by `CC-LAB-0063`, already instantiated on
    ``php_laravel`` by `CC-LAB-0212`; `CC-LAB-0188` is its first
    instantiation for ``spring_boot``): reflects the client-supplied
    monthly-charge value verbatim as the new plan's charge -- CWE-807,
    price_integrity_bypass -- never recomputed server-side."""

    def __init__(self) -> None:
        super().__init__("client_trusted_amount", "sink", SINK_ENV, "client_trusted_amount.java.j2")


class ServerRecomputedAmountSink(TemplateModule):
    """The secure twin (``server_recomputed_amount``, ``neutralises`` --
    already instantiated on ``php_laravel`` by `CC-LAB-0212` as a
    *transform*; `CC-LAB-0188` reuses the identical op name for this
    stack's own op-selects-sink convention, since this stack's shapes have
    no separate transform stage): discards the client-supplied price
    entirely and looks the real charge up in a fixed, page-profile-supplied
    plan-tier-to-price map keyed only by the requested (non-numeric)
    plan_tier, matching ``ServerRecomputedAmountTransform``'s own real
    look-up shape (`fuzzlab.labgen.modules`, php_current's shared
    vocabulary) rather than a disguised constant."""

    def __init__(self) -> None:
        super().__init__(
            "server_recomputed_amount", "sink", SINK_ENV, "server_recomputed_amount.java.j2"
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


class SingleHandlerBinaryComplexity(TemplateModule):
    """A binary-body variant of `SingleHandlerComplexity` (`CC-LAB-0191`,
    Netflix's sixth real page, this stack's first `unrestricted_file_upload`
    instance): the generated handler returns `ResponseEntity<byte[]>`
    instead of `ResponseEntity<String>`, and additionally declares `throws
    jakarta.servlet.ServletException` alongside the existing `throws
    java.io.IOException` (Servlet `Part` API access can throw it). Needed
    because this shape's own sink must serve the uploaded file's real bytes
    back byte-for-byte -- a `String`-typed body would silently corrupt any
    byte >= 0x80 when Spring's `StringHttpMessageConverter` re-encodes it
    for the wire (UTF-8 is not a 1:1 byte<->char mapping the way latin-1
    is), which would make a real image control probe's own response bytes
    wrong even though this strategy's `confirm()` doesn't happen to check
    them. A new, additive complexity module registered under its own
    `"single_handler_binary"` key -- `single_handler.java.j2` and every
    existing cell that uses it are untouched."""

    def __init__(self) -> None:
        super().__init__(
            "single_handler_binary", "complexity", COMPLEXITY_ENV, "single_handler_binary.java.j2"
        )

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


class ReadUploadedAvatarFileSource(TemplateModule):
    """Reads a real `multipart/form-data` profile-avatar upload
    (`CC-LAB-0191`) -- this stack's first, the `unrestricted_file_upload`
    shape's source. Reaches the uploaded part off the raw Servlet 3.1+
    `Part` API (`request.getPart("file")`), matching this package's
    existing raw-Servlet-API convention (`QueryParamSource`'s own
    `request.getParameter`, not a typed `@RequestParam`/`MultipartFile`
    argument) -- necessary here specifically because every complexity
    template's handler signature takes only `HttpServletRequest`, so
    there is no Spring-bound `MultipartFile` parameter to read instead.
    Publishes three Java identifiers a sink reads directly:
    `filename_var` (the caller-supplied filename, entirely
    attacker-controlled), `content_var` (the raw `byte[]` payload), and
    `client_content_type_var` (the caller-supplied multipart part
    `Content-Type`, also attacker-controlled) -- the same three-identifier
    contract `go_net_http`'s own `ReadUploadedFileSource` (`CC-LAB-0186`)
    established for this exact shape, ported to Java's own `Part` API
    rather than Go's `r.FormFile`. Convention 2 (like SSRF/mass-
    assignment/access-control/price): no `value_expr` is published, since
    the manifest's one op names a sink module directly."""

    def __init__(self) -> None:
        super().__init__(
            "read_uploaded_avatar_file", "source", SOURCE_ENV, "read_uploaded_avatar_file.java.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("part_var", "filePart")
        render_ctx.setdefault("filename_var", "uploadFilename")
        render_ctx.setdefault("content_var", "uploadContent")
        render_ctx.setdefault("client_content_type_var", "clientContentType")
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class NoExtensionCheckContentTypeTrustSink(TemplateModule):
    """The vulnerable op (`lab/safety_matrix.yaml`'s existing
    `no_extension_check`, `fs_web_root_write` family, `no_effect` -- added
    by `CC-LAB-0063`, already instantiated on `go_net_http` by
    `CC-LAB-0186`; `CC-LAB-0191` is its first instantiation for
    `spring_boot`): writes the uploaded bytes under the caller's own
    filename verbatim into a web-served directory, and derives the served
    Content-Type from that same filename's extension via Spring's own
    `MediaTypeFactory` (the idiomatic Java/Spring analog of Go's
    `mime.TypeByExtension` -- a static, bundled extension-to-MediaType
    lookup table, never the file's real bytes), falling back to the
    caller-supplied multipart Content-Type header when the extension is
    unrecognized -- CWE-434, the same CWE-434-to-XSS chain
    `NoExtensionCheckSink`'s own (`go_net_http`) docstring documents."""

    def __init__(self) -> None:
        super().__init__("no_extension_check", "sink", SINK_ENV, "no_extension_check.java.j2")


class ExtensionAllowlistMagicByteCheckSink(TemplateModule):
    """The secure twin (`extension_allowlist_mime_check`, `neutralises` --
    `CC-LAB-0191`): allowlists exactly `.png`/`.jpg`/`.jpeg` (narrower than
    `go_net_http`'s own allowlist, which also accepts `.gif`/`.webp` -- a
    deliberate, stated scoping to the two formats this sink can actually
    sniff, not silently smaller) AND requires the uploaded bytes' own
    magic-byte signature to match a real PNG or JPEG. **Design choice,
    documented (task's own explicit ask):** Java's standard library has no
    ready-made `http.DetectContentType` equivalent; `Files.probeContentType`
    is platform/OS-dependent (many JDKs fall back to extension-based or a
    `file`-command-backed detector, neither of which is a deterministic,
    environment-independent "sniff the real bytes" check this lab's
    live-boot proof can rely on), so this implements a minimal, explicit
    magic-byte check instead (PNG's fixed 8-byte signature, JPEG's 3-byte
    `0xFFD8FF` prefix) -- chosen over `Files.probeContentType` specifically
    for that determinism. Writes under a fully server-chosen filename
    (`"avatar"+ext`) and always serves the SNIFFED content type, never one
    derived from the extension or the caller's own header."""

    def __init__(self) -> None:
        super().__init__(
            "extension_allowlist_mime_check", "sink", SINK_ENV, "extension_allowlist_mime_check.java.j2"
        )


class UnfilteredObjectAssignSink(TemplateModule):
    """The vulnerable op (`lab/safety_matrix.yaml`'s existing
    `unfiltered_object_assign` op, `orm_entity_bulk_assign` sink family,
    `CC-LAB-0063` -- already instantiated on `php_current`/`ruby_rails`/
    `php_laravel`/`go_net_http`; `CC-LAB-0192` is its first instantiation
    for `spring_boot`): parses the raw request body with a plain Jackson 3
    `JsonMapper.readTree()` (this stack's existing Jackson-3 convention,
    `CC-LAB-0173`) and assigns EVERY field present onto the account
    record's in-memory representation, including `is_partner` -- a field
    this endpoint's own intended form (display name/bio) never exposes --
    CWE-915, mass assignment. Mirrors `go_net_http`'s own
    `UnfilteredObjectAssignSink` (`CC-LAB-0182`) design, ported
    idiomatically: Java has no ORM/ActiveRecord bulk-assign call to
    misuse either, so this reads the whole body tree itself rather than
    unmarshalling onto a struct with every field declared."""

    def __init__(self) -> None:
        super().__init__(
            "unfiltered_object_assign", "sink", SINK_ENV, "unfiltered_object_assign.java.j2"
        )


class TypedSchemaAllowlistSink(TemplateModule):
    """The secure twin (`typed_schema_allowlist`, `neutralises` --
    `CC-LAB-0192`): parses the identical raw body, but only ever reads
    `display_name`/`bio` out of it -- `is_partner` is never read from
    client input at all, the same "narrow, typed allowlist has no field
    for the privileged key" shape `go_net_http`'s own `TypedSchema
    AllowlistSink` (`CC-LAB-0182`) established, ported to Jackson's
    `JsonNode` API rather than a Go typed unmarshal target."""

    def __init__(self) -> None:
        super().__init__(
            "typed_schema_allowlist", "sink", SINK_ENV, "typed_schema_allowlist.java.j2"
        )


class ReadAuthorizationBearerTokenSource(TemplateModule):
    """Reads and hand-parses a Bearer JWT off the `Authorization` header
    (`CC-LAB-0193`) -- a hand-rolled parser/verifier using only JDK
    standard-library primitives (`java.util.Base64`, `javax.crypto.Mac`,
    `java.security.MessageDigest`) plus this stack's existing Jackson-3
    JSON convention for the header/payload JSON, deliberately NOT a real
    JWT library dependency, matching `go_net_http`'s own
    `ReadAuthorizationBearerTokenSource` (`CC-LAB-0180`) "hand-rolled
    parser is the vulnerability" framing rather than modeling a real
    library's own CVE. Publishes five Java identifiers a sink reads
    directly: `token_var` (the raw token string), `alg_none_var`/
    `alg_hs256_var` (booleans, whether the token's own header claims
    `alg: none`/`alg: HS256`), `hmac_valid_var` (boolean, whether the
    token's HMAC-SHA256 signature verifies against this stack's own fixed
    demo secret, `TrackerNestApplication.JWT_SECRET`, compared in constant
    time via `MessageDigest.isEqual`), and `claims_var` (the decoded
    payload segment as a raw JSON string, unparsed -- each sink decides
    which claims to trust and echo). Unlike this stack's other shapes,
    this source computes the accept/reject condition's own boolean
    ingredients itself (mirroring `go_net_http`'s own source/transform
    split, since the two twins' condition genuinely differs in which
    booleans it combines and how) -- but per this package's own
    op-selects-sink convention (no separate transform stage on this
    stack), each sink module reads these booleans directly and decides
    its own condition, rather than a transform module computing a single
    shared `value_expr`."""

    def __init__(self) -> None:
        super().__init__(
            "read_authorization_bearer_token", "source", SOURCE_ENV,
            "read_authorization_bearer_token.java.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("token_var", "jwtToken")
        render_ctx.setdefault("alg_none_var", "jwtAlgIsNone")
        render_ctx.setdefault("alg_hs256_var", "jwtAlgIsHs256")
        render_ctx.setdefault("hmac_valid_var", "jwtHmacValid")
        render_ctx.setdefault("claims_var", "jwtClaimsJson")
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class JwtAlgNoneDefaultSink(TemplateModule):
    """The vulnerable op (`lab/safety_matrix.yaml`'s existing
    `jwt_alg_none_default` op, `jwt_signature_verification` sink family,
    `no_effect` -- added by `CC-LAB-0063`, already instantiated on
    `go_net_http` by `CC-LAB-0180`; `CC-LAB-0193` is its first
    instantiation for `spring_boot`): honors an attacker-chosen `alg:
    none` header, skipping signature verification entirely
    (`{jwtAlgIsNone} || {jwtHmacValid}`) -- CWE-347, the real
    `auth0/node-jsonwebtoken` GHSA-8cf7-32gw-wr33 bug."""

    def __init__(self) -> None:
        super().__init__("jwt_alg_none_default", "sink", SINK_ENV, "jwt_alg_none_default.java.j2")


class JwtNoneAlgOptInSink(TemplateModule):
    """The secure twin (`jwt_none_alg_opt_in`, `neutralises` --
    `CC-LAB-0193`): requires the token's own header to explicitly claim
    the one pinned algorithm (HS256) *and* a valid HMAC before any claims
    are trusted (`{jwtAlgIsHs256} && {jwtHmacValid}`) -- an `alg:none`
    token never reaches the HMAC check's own accepted-condition at all."""

    def __init__(self) -> None:
        super().__init__("jwt_none_alg_opt_in", "sink", SINK_ENV, "jwt_none_alg_opt_in.java.j2")


class UncheckedUrlFetchSink(TemplateModule):
    """The vulnerable op (`lab/safety_matrix.yaml`'s existing
    `unchecked_url_fetch` op, `server_side_http_fetch` sink family,
    `no_effect` -- added by `CC-LAB-0063`, already instantiated on
    `go_net_http` by `CC-LAB-0172`/`CC-LAB-0185`; `CC-LAB-0194` is its
    first instantiation for `spring_boot`): fetches whatever URL the
    caller-supplied `thumbnail_url` query parameter names, with no
    validation at all -- CWE-918, SSRF. Reuses this stack's existing
    `QueryParamSource` verbatim (the same `request.getParameter` source
    already used by the ssti/spel_injection shapes), matching
    `go_net_http`'s own `read_url_query_param` source contract exactly (a
    query-param-carried URL, not a JSON body field -- chosen so a generic
    `Candidate(location="query")` probe drives this shape identically to
    `go_net_http`'s SSRF cells, letting `SsrfInBandMarkerStrategy`/
    `SsrfOobStrategy` generalize with zero new detection code AND zero
    new sender/candidate plumbing). Ported idiomatically from
    `go_net_http`'s own `UncheckedUrlFetchSink` (`CC-LAB-0172`) to
    `java.net.http.HttpClient`, with a bounded connect/request timeout
    (never a default-timeout client)."""

    def __init__(self) -> None:
        super().__init__("unchecked_url_fetch", "sink", SINK_ENV, "unchecked_url_fetch.java.j2")


class SchemeAndResolvedIpAllowlistSink(TemplateModule):
    """The secure twin (`scheme_and_resolved_ip_allowlist`, `neutralises`
    -- `CC-LAB-0194`): the identical query-param read, but rejects any
    scheme but `https` and rejects a fetch whose hostname RESOLVES to a
    loopback/private/link-local address, checked against the actually-
    resolved address (`java.net.InetAddress.getAllByName`, the JDK's own
    real-DNS-resolution analog of Go's `net.LookupIP`) -- closing the
    DNS-rebinding gap `lab/safety_matrix.yaml`'s own comment on this sink
    family names, matching `go_net_http`'s own
    `SchemeAndResolvedIpAllowlistSink` (`CC-LAB-0172`) design exactly."""

    def __init__(self) -> None:
        super().__init__(
            "scheme_and_resolved_ip_allowlist", "sink", SINK_ENV, "scheme_and_resolved_ip_allowlist.java.j2"
        )


SOURCES: dict[str, Module] = {
    "query_param": QueryParamSource(),
    "raw_body": RawBodySource(),
    "request_stream": RequestStreamSource(),
    "jackson_body": JacksonBodySource(),
    "read_account_id_and_caller_header": ReadAccountIdAndCallerHeaderSource(),
    "read_plan_change_request": ReadPlanChangeRequestSource(),
    "read_uploaded_avatar_file": ReadUploadedAvatarFileSource(),
    "read_authorization_bearer_token": ReadAuthorizationBearerTokenSource(),
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
    "client_trusted_amount": ClientTrustedAmountSink(),
    "server_recomputed_amount": ServerRecomputedAmountSink(),
    "no_extension_check": NoExtensionCheckContentTypeTrustSink(),
    "extension_allowlist_mime_check": ExtensionAllowlistMagicByteCheckSink(),
    "unfiltered_object_assign": UnfilteredObjectAssignSink(),
    "typed_schema_allowlist": TypedSchemaAllowlistSink(),
    "jwt_alg_none_default": JwtAlgNoneDefaultSink(),
    "jwt_none_alg_opt_in": JwtNoneAlgOptInSink(),
    "unchecked_url_fetch": UncheckedUrlFetchSink(),
    "scheme_and_resolved_ip_allowlist": SchemeAndResolvedIpAllowlistSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "single_handler": SingleHandlerComplexity(),
    "single_handler_binary": SingleHandlerBinaryComplexity(),
}
