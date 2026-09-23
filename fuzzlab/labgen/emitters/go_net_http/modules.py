"""Composable Go rendering modules for the ``go_net_http`` emitter (category
4 pilot, ``CC-LAB-0170``/``FR-LAB-76``).

Mirrors ``fuzzlab.labgen.emitters.node_express.modules``' module-composition
shape (source/transform/sink/complexity categories, a ``Module``/
``TemplateModule`` base pair, an explicit-flags Jinja2 environment per
category) exactly, per this project's standing convention of reusing the
existing module *categories* as the porting template for a new stack. The
actual Go code is new: this module owns its own template directory and its
own registries, entirely inside
``fuzzlab/labgen/emitters/go_net_http/`` — it does not import from or
register into ``fuzzlab.labgen.modules`` or any other stack's registry.

Phase A scope only (one shape): ``webhook_signature`` /
``webhook_signature_verification`` — the one illustrative cell
``docs/research/site-architecture-survey-functionality-twitch.md`` §2
picked for this stack's first live-boot proof. The vulnerable/secure split
reuses ``lab/safety_matrix.yaml``'s existing ``webhook_signature_verification``
sink family and its existing ``naive_string_compare``/``constant_time_compare``
ops verbatim — no new safety-matrix entry was needed (a scope reduction
found during implementation of ``CC-LAB-0170``, which had drafted a new
``hmac_signature_check`` family before this family's prior existence, added
by ``CC-LAB-0063``, was found).

Phase B, eleventh increment (``CC-LAB-0190``/``FR-LAB-130``): this project's
first ``path_traversal``/``fs_path_read`` instance on any stack -- a
previously-exported-clip download endpoint (``GET /clips/export?filename=``)
that either joins the caller-supplied filename onto a fixed export
directory with no confinement check at all (vulnerable, CWE-22,
``unconfined_path``) or resolves the joined path to its real, symlink-
resolved absolute form and rejects anything that escapes the export
directory's own real form (secure, ``realpath_confine``). Convention 2
again: the manifest's one op names a sink module directly.

Phase B, thirteenth increment (``CC-LAB-0198``/``FR-LAB-138``): this
project's first ``http_header_injection``/``http_response_header_value``
instance on any stack -- a post-subscribe/-follow redirect convenience
endpoint (``GET /channels/redirect?destination=``) that either hijacks the
raw connection and hand-writes a ``302`` response line with the
caller-supplied ``destination`` concatenated straight into the
``Location:`` header, no CR/LF stripping (vulnerable, CWE-113,
``raw_socket_response_write``), or validates ``destination`` against a
strict site-relative-path allowlist before using Go's ordinary
``w.Header().Set()``/``w.WriteHeader()`` path (secure, ``allowlist_and_
runtime_crlf_rejection``). Go's own ordinary header-writing path was
verified, empirically, to already replace a stray CR/LF byte with a space
before writing to the wire -- see this increment's own change-control
entry -- so the vulnerable twin deliberately bypasses that path via
``http.Hijacker`` (a real, standard mechanism, not a contrivance) rather
than forcing an honest-but-impossible vulnerable instance through the
ordinary API. Convention 2 again: the manifest's one op names a sink
module directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_ROOT = Path(__file__).parent / "templates"


def _make_env(subdir: str) -> Environment:
    """Same determinism-relevant flags as every other stack's own
    ``_make_env`` (``node_express``, PHP's ``fuzzlab.labgen.modules``), set
    explicitly rather than left at Jinja2's defaults, so two renders of the
    same inputs are byte-identical (NFR-LAB-reproducible)."""
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
_ROUTE_ENV = _make_env(".")  # route.go.j2 lives directly under templates/


@dataclass(frozen=True)
class RenderResult:
    """Same shape as every other stack's own ``RenderResult``: the rendered
    code plus the (possibly updated) assembly context passed to the next
    module."""

    code: str
    context: dict[str, Any]


class Module:
    """Base class for one composable Go rendering fragment. ``cardinality``
    is ``"per_cell"`` for every module in this inventory except the route
    accumulator, which is rendered separately by
    :func:`render_route_line`/``GoEmitter.render_route_accumulator``
    (cardinality ``"accumulator"``) rather than through this per-cell
    registry."""

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


class ReadWebhookSignatureSource(TemplateModule):
    """Reads the raw request body, computes the expected HMAC-SHA256 digest
    over it with a fixed per-run shared secret, and reads the header
    carrying the caller-supplied digest. Publishes ``computed_var``/
    ``header_var`` (the two Go identifiers a comparison transform composes
    into ``value_expr``) rather than a single ``value_expr`` up front,
    since — unlike every SQLi/XSS source in this project's other stacks —
    this shape's "tainted value" is a boolean comparison outcome, not a
    single scalar the sink echoes/queries with."""

    def __init__(self) -> None:
        super().__init__(
            "read_webhook_signature", "source", _SOURCE_ENV, "read_webhook_signature.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("computed_var", "computed")
        render_ctx.setdefault("header_var", "headerSig")
        result = super().render(render_ctx)
        new_ctx = dict(render_ctx)
        # Vulnerable-by-default (no transform applied): a naive `==` --
        # matches every other stack's "identity transform" default of
        # publishing the least-safe rendering until a security op
        # overrides it (e.g. node_express's `bound=False` default).
        new_ctx["value_expr"] = f"{new_ctx['header_var']} == {new_ctx['computed_var']}"
        return RenderResult(code=result.code, context=new_ctx)


class NaiveStringCompareTransform(TemplateModule):
    """The ``naive_string_compare`` op (``lab/safety_matrix.yaml``,
    ``webhook_signature_verification`` family, ``partial`` effect --
    neutralizes nothing): renders a comment only, since the source already
    publishes the ``==`` comparison as ``value_expr`` by default -- this
    transform exists so a manifest can name the vulnerable path explicitly
    (never relying on "no transform" being silently equivalent to a named
    vulnerable op, per this project's own minimal-pair discipline)."""

    def __init__(self) -> None:
        super().__init__(
            "naive_string_compare", "transform", _TRANSFORM_ENV, "naive_string_compare.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = f"{ctx['header_var']} == {ctx['computed_var']}"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class ConstantTimeCompareTransform(TemplateModule):
    """The ``constant_time_compare`` op (``lab/safety_matrix.yaml``,
    ``webhook_signature_verification`` family, ``neutralises`` effect --
    the secure twin): rewrites ``value_expr`` to a ``crypto/hmac.Equal``
    call, constant-time regardless of where the two digests first differ."""

    def __init__(self) -> None:
        super().__init__(
            "constant_time_compare", "transform", _TRANSFORM_ENV, "constant_time_compare.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = f"hmac.Equal([]byte({ctx['header_var']}), []byte({ctx['computed_var']}))"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class WebhookSignatureVerificationSink(TemplateModule):
    """Branches on ``value_expr`` (the comparison a transform above
    published) and writes ``200``/``401`` -- does not itself know or care
    whether the comparison it received is constant-time, matching every
    other stack's sink-is-transform-agnostic convention (e.g.
    ``node_express``'s ``HtmlBodyEchoSink``)."""

    def __init__(self) -> None:
        super().__init__(
            "webhook_signature_verification",
            "sink",
            _SINK_ENV,
            "webhook_signature_verification.go.j2",
        )


class ReadUrlQueryParamSource(TemplateModule):
    """Reads one query-string parameter carrying the caller-supplied fetch
    target -- the SSRF shape's source (``CC-LAB-0172``). Publishes
    ``var_name`` unchanged from ``ctx`` (the route-profile table already
    names it), matching every other source's "publish the Go identifier
    the sink reads" convention."""

    def __init__(self) -> None:
        super().__init__("read_url_query_param", "source", _SOURCE_ENV, "read_url_query_param.go.j2")


class UncheckedUrlFetchSink(TemplateModule):
    """The ``unchecked_url_fetch`` op (``lab/safety_matrix.yaml``,
    ``server_side_http_fetch`` family, ``no_effect``): fetches the
    caller-supplied URL with a bounded-timeout ``http.Client`` and no
    other validation at all -- CWE-918, the vulnerable twin. A **sink**
    module, not a transform: see this package's own ``__init__.py``
    module docstring for why this shape's manifest op names a sink
    directly."""

    def __init__(self) -> None:
        super().__init__("unchecked_url_fetch", "sink", _SINK_ENV, "unchecked_url_fetch.go.j2")


class SchemeAndResolvedIpAllowlistSink(TemplateModule):
    """The ``scheme_and_resolved_ip_allowlist`` op (``lab/safety_matrix.yaml``,
    ``server_side_http_fetch`` family, ``neutralises`` -- the secure twin):
    rejects any scheme but ``https`` and rejects a resolved IP that is
    loopback/private/link-local/unspecified, checked against the
    *resolved* address (not just the hostname string), before fetching
    with the same bounded-timeout ``http.Client``."""

    def __init__(self) -> None:
        super().__init__(
            "scheme_and_resolved_ip_allowlist",
            "sink",
            _SINK_ENV,
            "scheme_and_resolved_ip_allowlist.go.j2",
        )


class ReadChannelIdAndBroadcasterHeaderSource(TemplateModule):
    """Reads the attacker-visible ``channel_id`` query param and the fixed
    demo ``X-Broadcaster-Id`` header standing in for the caller's own
    authenticated identity -- this stack has no session/auth system yet, so
    this header models only the ownership-check-bypass mechanism in
    isolation, the same kind of declared simplification
    ``ReadWebhookSignatureSource``'s fixed demo secret already is, never a
    real session/auth system. Publishes ``channel_id_var``/``broadcaster_var``
    (two Go identifiers, like ``ReadWebhookSignatureSource``'s ``computed_var``/
    ``header_var``) plus a default ``value_expr="true"`` -- vulnerable by
    default (no ownership check at all) until a transform overrides it,
    matching this stack's own "vulnerable by default" convention."""

    def __init__(self) -> None:
        super().__init__(
            "read_channel_id_and_broadcaster_header", "source", _SOURCE_ENV,
            "read_channel_id_and_broadcaster_header.go.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("channel_id_var", "channelID")
        render_ctx.setdefault("broadcaster_var", "broadcasterID")
        result = super().render(render_ctx)
        new_ctx = dict(render_ctx)
        new_ctx["value_expr"] = "true"
        return RenderResult(code=result.code, context=new_ctx)


class NoOwnershipCheckTransform(TemplateModule):
    """The ``no_ownership_check`` op (``lab/safety_matrix.yaml``,
    ``db_row_by_id_lookup`` family, ``no_effect`` -- added by ``CC-LAB-0063``,
    never before instantiated by any stack's generator): renders a comment
    only, since the source already publishes ``value_expr="true"`` (always
    "authorized") by default -- this transform names the vulnerable path
    explicitly, matching ``NaiveStringCompareTransform``'s own
    never-rely-on-the-default convention."""

    def __init__(self) -> None:
        super().__init__(
            "no_ownership_check", "transform", _TRANSFORM_ENV, "no_ownership_check.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = "true"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class IdentityMatchBeforeFetchTransform(TemplateModule):
    """The ``identity_match_before_fetch`` op (``lab/safety_matrix.yaml``,
    ``db_row_by_id_lookup`` family, ``neutralises`` -- the secure twin):
    rewrites ``value_expr`` to require ``channel_id_var == broadcaster_var``
    before the sink treats the caller as authorized."""

    def __init__(self) -> None:
        super().__init__(
            "identity_match_before_fetch", "transform", _TRANSFORM_ENV,
            "identity_match_before_fetch.go.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = f"{ctx['channel_id_var']} == {ctx['broadcaster_var']}"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class ObjectLookupAuthorizationCheckSink(TemplateModule):
    """Branches on ``value_expr`` (the ownership decision a transform above
    published) and either returns canned per-channel analytics or a real
    HTTP 403 with no data -- does not itself know or care whether an
    ownership check was actually performed, matching
    ``WebhookSignatureVerificationSink``'s own sink-is-transform-agnostic
    convention."""

    def __init__(self) -> None:
        super().__init__(
            "object_lookup_authorization_check", "sink", _SINK_ENV,
            "object_lookup_authorization_check.go.j2",
        )


class ReadAuthorizationBearerTokenSource(TemplateModule):
    """Reads the ``Authorization: Bearer <jwt>`` header and hand-parses the
    three-segment JWT (base64url header/payload/signature -- Go stdlib
    only, no third-party JWT library, matching this stack's own
    zero-dependency ``go.mod``), publishing four Go identifiers a
    transform composes into ``value_expr``: ``alg_none_var``/
    ``alg_hs256_var`` (what the token's own header claims) and
    ``hmac_valid_var`` (a real, constant-time HMAC-SHA256 check via
    ``crypto/hmac.Equal`` -- computed unconditionally, fails closed on any
    decode failure or length mismatch, per this template's own inline
    comment). ``claims_var`` carries the decoded payload JSON string for
    the sink to read. Publishes a vulnerable-by-default ``value_expr``
    (``alg_none_var || hmac_valid_var``, honoring an unsigned ``alg:none``
    token), matching every other source in this stack's own convention."""

    def __init__(self) -> None:
        super().__init__(
            "read_authorization_bearer_token", "source", _SOURCE_ENV,
            "read_authorization_bearer_token.go.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("token_var", "bearerToken")
        render_ctx.setdefault("alg_none_var", "algIsNone")
        render_ctx.setdefault("alg_hs256_var", "algIsHS256")
        render_ctx.setdefault("hmac_valid_var", "hmacValid")
        render_ctx.setdefault("claims_var", "claimsJSON")
        result = super().render(render_ctx)
        new_ctx = dict(render_ctx)
        new_ctx["value_expr"] = f"{new_ctx['alg_none_var']} || {new_ctx['hmac_valid_var']}"
        return RenderResult(code=result.code, context=new_ctx)


class JwtAlgNoneDefaultTransform(TemplateModule):
    """The ``jwt_alg_none_default`` op (``lab/safety_matrix.yaml``,
    ``jwt_signature_verification`` family, ``no_effect`` -- added by
    ``CC-LAB-0063``, never before instantiated by any stack's generator):
    renders a comment only, since the source already publishes this
    vulnerable ``value_expr`` by default -- names the vulnerable path
    explicitly, matching ``NoOwnershipCheckTransform``'s own convention."""

    def __init__(self) -> None:
        super().__init__(
            "jwt_alg_none_default", "transform", _TRANSFORM_ENV, "jwt_alg_none_default.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = f"{ctx['alg_none_var']} || {ctx['hmac_valid_var']}"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class JwtNoneAlgOptInTransform(TemplateModule):
    """The ``jwt_none_alg_opt_in`` op (``lab/safety_matrix.yaml``,
    ``jwt_signature_verification`` family, ``neutralises`` -- the secure
    twin): rewrites ``value_expr`` to require the token's own header to
    explicitly claim the one pinned, allowed algorithm (``HS256``) *and*
    a valid HMAC -- an ``alg:none`` token is rejected before
    ``hmac_valid_var`` even matters."""

    def __init__(self) -> None:
        super().__init__(
            "jwt_none_alg_opt_in", "transform", _TRANSFORM_ENV, "jwt_none_alg_opt_in.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx["value_expr"] = f"{ctx['alg_hs256_var']} && {ctx['hmac_valid_var']}"
        result = super().render(render_ctx)
        return RenderResult(code=result.code, context=render_ctx)


class JwtClaimsResponseSink(TemplateModule):
    """Branches on ``value_expr`` (the algorithm/signature decision a
    transform above published) and either returns the decoded claims as
    channel settings or a real HTTP 401 with no data -- does not itself
    know or care which algorithm policy produced that decision, matching
    ``WebhookSignatureVerificationSink``'s own sink-is-transform-agnostic
    convention."""

    def __init__(self) -> None:
        super().__init__(
            "jwt_claims_response", "sink", _SINK_ENV, "jwt_claims_response.go.j2"
        )


class NoOpTokenRequestSource(TemplateModule):
    """A genuinely new module-composition shape for this stack (neither
    Convention 1 -- a transform modifies a value a shared sink renders --
    nor Convention 2 -- the manifest's op names a sink directly, but with
    a *real* source still reading real request input, `CC-LAB-0172`'s own
    SSRF shape): ``session_token_generation``'s vulnerability is entirely
    in how the sink *generates* its own output, not in any attacker-
    controlled value reaching it, so there is no tainted input to read at
    all. Renders a comment-only file stating that explicitly (never a
    silently-omitted source stage) and publishes nothing."""

    def __init__(self) -> None:
        super().__init__(
            "no_op_token_request", "source", _SOURCE_ENV, "no_op_token_request.go.j2"
        )


class PredictableTokenSourceSink(TemplateModule):
    """The ``predictable_token_source`` op (``lab/safety_matrix.yaml``,
    ``session_token_generation`` family, ``no_effect`` -- added by
    ``CC-LAB-0063``, never before instantiated by any stack's generator):
    the session token *is* the current nanosecond timestamp as a decimal
    string (CWE-330) -- trivially predictable, since an attacker who
    observes or roughly times one token knows every other token issued in
    a narrow, guessable window."""

    def __init__(self) -> None:
        super().__init__(
            "predictable_token_source", "sink", _SINK_ENV, "predictable_token_source.go.j2"
        )


class CsprngTokenSink(TemplateModule):
    """The ``csprng_token`` op (``lab/safety_matrix.yaml``,
    ``session_token_generation`` family, ``neutralises`` -- the secure
    twin): 32 bytes from ``crypto/rand``, hex-encoded -- genuinely
    unpredictable, matching this stack's own error-handling convention
    (never silently ignore a `crypto/rand.Read` error)."""

    def __init__(self) -> None:
        super().__init__(
            "csprng_token", "sink", _SINK_ENV, "csprng_token.go.j2"
        )


class ReadChannelProfileBodySource(TemplateModule):
    """Reads the whole raw request body -- the mass-assignment shape's
    source (``CC-LAB-0182``). Publishes ``body_var`` (a Go ``[]byte``
    identifier), matching ``ReadUrlQueryParamSource``'s own
    "publish the Go identifier the sink reads" convention. Unlike every
    other source in this stack, there is no single named field to read:
    the shape's whole point is that the *entire* body reaches the sink
    unfiltered, so the source stage does no field-level parsing at all --
    that split (parse into a typed struct, or not) is exactly what the
    two sink modules below differ on."""

    def __init__(self) -> None:
        super().__init__(
            "read_channel_profile_body", "source", _SOURCE_ENV, "read_channel_profile_body.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("body_var", "reqBody")
        return super().render(render_ctx)


class UnfilteredObjectAssignSink(TemplateModule):
    """The ``unfiltered_object_assign`` op (``lab/safety_matrix.yaml``,
    ``orm_entity_bulk_assign`` family, ``no_effect`` -- added by
    ``CC-LAB-0063`` for the corpus-examples/mass-assignment research,
    never before instantiated by any stack's generator): unmarshals the
    raw request body directly onto a channel record struct that is
    pre-seeded with the record's *entire* persisted shape, including
    ``is_partner`` -- a field this endpoint's own intended form never
    exposes. Go's standard-library ``encoding/json`` only ever sets the
    fields actually present in the input and leaves the rest at their
    seeded value, so any JSON key the struct declares, privileged or not,
    takes effect the moment the client sends it (CWE-915). Echoes the
    resulting record straight back in the response -- this stack's own
    "no database in Phase A" scope call (see
    ``fuzzlab.labgen.conformance.go_live_boot``'s module docstring)
    applies here too: proving the mutation happened needs no persisted
    read-back, only the same request's own response."""

    def __init__(self) -> None:
        super().__init__(
            "unfiltered_object_assign", "sink", _SINK_ENV, "unfiltered_object_assign.go.j2"
        )


class TypedSchemaAllowlistSink(TemplateModule):
    """The ``typed_schema_allowlist`` op (``lab/safety_matrix.yaml``,
    ``orm_entity_bulk_assign`` family, ``neutralises`` -- the secure
    twin): unmarshals the request body into a narrow, separately typed
    DTO struct that only declares the fields this endpoint intends to
    accept (``display_name``/``bio``), then copies exactly those two
    fields onto the channel record -- ``is_partner`` has no field in the
    DTO at all, so no JSON key the client sends can ever reach it,
    regardless of what the raw body contains."""

    def __init__(self) -> None:
        super().__init__(
            "typed_schema_allowlist", "sink", _SINK_ENV, "typed_schema_allowlist.go.j2"
        )


class ReadUploadedFileSource(TemplateModule):
    """Reads a real ``multipart/form-data`` upload -- this stack's first
    (``CC-LAB-0186``), the ``unrestricted_file_upload`` shape's source.
    Bounds the read at ``maxUploadBytes`` (5 MiB, a fixed lab-only cap --
    same "fixed demo value" convention as ``webhookSecret``/
    ``jwtSecret``) via ``io.LimitReader`` so an oversized upload fails
    closed rather than exhausting memory. Publishes three Go identifiers
    a sink reads directly: ``filename_var`` (the caller-supplied
    filename, entirely attacker-controlled), ``content_var`` (the raw
    ``[]byte`` payload), and ``client_content_type_var`` (the caller-
    supplied multipart part ``Content-Type``, also attacker-controlled --
    the second half of what this shape's vulnerable sink wrongly
    trusts). Convention 2 (like SSRF/mass-assignment): no ``value_expr``
    is published, since the manifest's one op names a **sink** directly
    (see this package's own ``__init__.py`` module docstring)."""

    def __init__(self) -> None:
        super().__init__(
            "read_uploaded_file", "source", _SOURCE_ENV, "read_uploaded_file.go.j2"
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("filename_var", "uploadFilename")
        render_ctx.setdefault("content_var", "uploadContent")
        render_ctx.setdefault("client_content_type_var", "clientContentType")
        return super().render(render_ctx)


class NoExtensionCheckSink(TemplateModule):
    """The ``no_extension_check`` op (``lab/safety_matrix.yaml``,
    ``fs_web_root_write`` family, ``no_effect`` -- added by
    ``CC-LAB-0063``, never before instantiated by any stack's generator):
    writes the uploaded bytes to a web-served directory under the
    caller-supplied filename **verbatim**, then serves them back with a
    ``Content-Type`` derived from that same caller-supplied filename's
    extension (``mime.TypeByExtension``), falling back to the caller-
    supplied multipart ``Content-Type`` header when the extension is
    unrecognized -- never from the file's real bytes (CWE-434). Go has
    no PHP-style "the web server executes an uploaded script" footgun
    (the task's own note), so this models the real, well-documented
    CWE-434-to-XSS chain instead: an uploaded ``.html``/``.svg`` file is
    served back same-origin with a ``Content-Type`` that lets an embedded
    ``<script>`` execute (stored XSS via unrestricted file upload)."""

    def __init__(self) -> None:
        super().__init__(
            "no_extension_check", "sink", _SINK_ENV, "no_extension_check.go.j2"
        )


class ExtensionAllowlistMimeCheckSink(TemplateModule):
    """The ``extension_allowlist_mime_check`` op (``lab/safety_matrix.yaml``,
    ``fs_web_root_write`` family, ``neutralises`` -- the secure twin):
    rejects any extension outside a fixed image allowlist (``.png``/
    ``.jpg``/``.jpeg``/``.gif``/``.webp``), then sniffs the REAL bytes
    with ``http.DetectContentType`` and rejects anything whose sniffed
    type is not ``image/*`` -- closing the gap `lab/safety_matrix.yaml`'s
    own comment block documents for the `partial`-effect ops in this
    family (``mime_type_check``/``filename_charset_sanitize``: narrowing
    without inspecting real content leaves a spoofable gap). Writes under
    a fully server-chosen filename (``"emote"+ext``, never the caller's
    own filename) and always serves the response with the SNIFFED
    content type, never one derived from the extension or the caller's
    ``Content-Type`` header -- so neither a spoofed extension nor a
    spoofed header can change what the response is served as."""

    def __init__(self) -> None:
        super().__init__(
            "extension_allowlist_mime_check", "sink", _SINK_ENV,
            "extension_allowlist_mime_check.go.j2",
        )


class ReadSubscriptionPurchaseRequestSource(TemplateModule):
    """Reads the whole raw request body -- the price-integrity-bypass
    shape's source (``CC-LAB-0189``, this stack's first
    ``price_integrity_bypass`` instance, mirroring ``spring_boot``'s own
    first instantiation, ``CC-LAB-0188``). Publishes ``body_var`` (a Go
    ``[]byte`` identifier), the same "publish the raw body, let the sink
    do its own JSON parsing" convention ``ReadChannelProfileBodySource``
    already established for this stack's other whole-body-JSON shape
    (mass-assignment) -- reused here as its own distinct source class
    (not the same instance) since the two shapes are conceptually
    unrelated even though the body-read line is byte-identical, matching
    every other shape in this stack having its own dedicated source
    class."""

    def __init__(self) -> None:
        super().__init__(
            "read_subscription_purchase_request", "source", _SOURCE_ENV,
            "read_subscription_purchase_request.go.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("body_var", "reqBody")
        return super().render(render_ctx)


class ClientTrustedAmountSink(TemplateModule):
    """The ``client_trusted_amount`` op (``lab/safety_matrix.yaml``,
    ``payment_charge_amount`` family, ``no_effect`` -- added by
    ``CC-LAB-0063``; this stack's first instantiation, mirroring
    ``spring_boot``'s own ``ClientTrustedAmountSink``, ``CC-LAB-0188``):
    unmarshals the request body's ``plan_tier``/``monthly_charge`` fields
    and echoes ``monthly_charge`` straight back as the charged amount,
    verbatim, with no server-side price lookup at all and no validation
    of ``plan_tier`` either (CWE-807). Convention 2 (like SSRF/mass-
    assignment/file-upload): the manifest's one op names a **sink**
    module directly -- the vulnerable/secure difference here is one
    inseparable trust-the-client-vs-recompute-server-side operation, not
    a value rewrite feeding a shared sink."""

    def __init__(self) -> None:
        super().__init__(
            "client_trusted_amount", "sink", _SINK_ENV, "client_trusted_amount.go.j2"
        )


class ServerRecomputedAmountSink(TemplateModule):
    """The ``server_recomputed_amount`` op (``lab/safety_matrix.yaml``,
    ``payment_charge_amount`` family, ``neutralises`` -- the secure
    twin): discards the client-supplied ``monthly_charge`` entirely and
    looks the real charge up in a fixed, server-owned
    ``plan_tier -> price`` map (``tier1``/``tier2``/``tier3``, three
    genuinely distinct prices -- a real, data-driven lookup, never a
    disguised single constant, the same adequacy-review lesson
    ``CC-LAB-0188`` applied for ``spring_boot``'s own twin). An
    unrecognized ``plan_tier`` fails closed (HTTP 400) rather than
    silently defaulting, the same fail-closed design call ``CC-LAB-0188``
    made for Netflix's own closed tier enumeration."""

    def __init__(self) -> None:
        super().__init__(
            "server_recomputed_amount", "sink", _SINK_ENV, "server_recomputed_amount.go.j2"
        )


class UnconfinedPathSink(TemplateModule):
    """The ``unconfined_path`` op (``lab/safety_matrix.yaml``,
    ``fs_path_read`` family, ``no_effect`` -- added by ``CC-LAB-0063``;
    this project's first instantiation of this family/concern on any
    stack, ``CC-LAB-0190``): joins the caller-supplied filename onto the
    fixed export directory with ``filepath.Join`` -- which only lexically
    *cleans* the resulting string, it never *confines* it -- then reads
    and serves whatever file results, with no check at all that the
    resolved path stays inside that directory (CWE-22). A
    ``filename=../../whatever``-style value walks straight back out.
    Convention 2 (like SSRF/mass-assignment/file-upload/price-integrity):
    the manifest's one op names a **sink** module directly -- the
    vulnerable/secure difference here is one inseparable
    join-and-read-unconfined-vs-resolve-and-confine operation, not a value
    rewrite feeding a shared sink."""

    def __init__(self) -> None:
        super().__init__("unconfined_path", "sink", _SINK_ENV, "unconfined_path.go.j2")


class RealpathConfineSink(TemplateModule):
    """The ``realpath_confine`` op (``lab/safety_matrix.yaml``,
    ``fs_path_read`` family, ``neutralises`` -- the secure twin): resolves
    the joined path to its real, canonical, symlink-resolved absolute form
    (``filepath.Abs`` + ``filepath.EvalSymlinks``, not just
    ``filepath.Clean``/a string-prefix check on the *unresolved* path,
    which a planted symlink could still defeat -- the same lexical-vs-real
    distinction ``lab/safety_matrix.yaml``'s own comment block documents
    for this family's ``path_prefix_check`` `partial`-effect op) and
    rejects (HTTP 403) anything whose resolved form does not stay inside
    the export directory's own real, resolved absolute form. Any
    resolution failure fails closed (404/500), never falls through to a
    confinement check on an unresolved path."""

    def __init__(self) -> None:
        super().__init__("realpath_confine", "sink", _SINK_ENV, "realpath_confine.go.j2")


class ReadChannelCommandRequestSource(TemplateModule):
    """Reads the whole raw request body -- the SSTI shape's source
    (``CC-LAB-0196``, this stack's first ``ssti``/``template_render``
    instance, reusing ``lab/safety_matrix.yaml``'s existing
    ``server_template_injection`` concern and mirroring ``spring_boot``'s
    own TrackerNest ``ssti``/``template_render`` shape, ``CC-LAB-0130``).
    Publishes ``body_var`` (a Go ``[]byte`` identifier), the same
    "publish the raw body, let the sink do its own JSON parsing"
    convention ``ReadChannelProfileBodySource``/
    ``ReadSubscriptionPurchaseRequestSource`` already established for this
    stack's other whole-body-JSON shapes -- reused here as its own
    distinct source class since a custom-chat-command definition
    (``POST /channels/commands``) is conceptually unrelated to either."""

    def __init__(self) -> None:
        super().__init__(
            "read_channel_command_request", "source", _SOURCE_ENV,
            "read_channel_command_request.go.j2",
        )

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        render_ctx = dict(ctx)
        render_ctx.setdefault("body_var", "reqBody")
        return super().render(render_ctx)


class UserSuppliedTemplateCompileSink(TemplateModule):
    """The ``user_supplied_template_compile`` op (``lab/safety_matrix.yaml``,
    ``template_render`` family, ``no_effect`` -- this stack's first
    instantiation, mirroring ``spring_boot``'s own
    ``UserSuppliedTemplateCompileSink``, ``CC-LAB-0130``): the caller-
    supplied ``template`` field of a custom chat-command definition (a
    real, well-documented streaming-bot feature -- Nightbot/StreamElements-
    style custom commands with template variables, e.g. ``!uptime`` showing
    ``{{.Uptime}} since going live``) is compiled and executed directly via
    Go's ``text/template`` package (CWE-1336). Unlike ``html/template``,
    ``text/template`` performs no output escaping, and -- the real,
    observable differential this sink deliberately exposes -- its template
    *language* can invoke exported fields/methods and its own conditional/
    range constructs on the data passed to ``Execute``, not just substitute
    inert placeholders: a caller-supplied template string can branch on
    ``{{if eq .Uptime "..."}}...{{end}}`` or call a builtin like
    ``{{len .Uptime}}``, proving real server-side evaluation rather than
    dumb string interpolation. A parse or execution error is surfaced to
    the caller (HTTP 400), never silently swallowed, so a malformed probe
    is distinguishable from a successful evaluation."""

    def __init__(self) -> None:
        super().__init__(
            "user_supplied_template_compile", "sink", _SINK_ENV,
            "user_supplied_template_compile.go.j2",
        )


class FileLoadedTemplateNameSink(TemplateModule):
    """The ``file_loaded_template_name`` op (``lab/safety_matrix.yaml``,
    ``template_render`` family, ``neutralises`` -- the secure twin,
    mirroring ``spring_boot``'s own ``FileLoadedTemplateNameSink``): the
    caller-supplied ``template`` field only ever selects a KEY into a
    small, fixed, developer-defined ``map[string]string`` of pre-approved
    variable names (``uptime``/``viewers``/``game``) -- it is never
    compiled or executed as template source at all, so no template
    language construct the caller sends (arithmetic, conditionals,
    field/method access) can ever be evaluated, regardless of its
    syntax."""

    def __init__(self) -> None:
        super().__init__(
            "file_loaded_template_name", "sink", _SINK_ENV,
            "file_loaded_template_name.go.j2",
        )


class RawSocketResponseWriteSink(TemplateModule):
    """The ``raw_socket_response_write`` op (``lab/safety_matrix.yaml``,
    ``http_response_header_value`` family, ``no_effect`` -- added by
    ``CC-LAB-0063``; this project's FIRST instantiation of this family/
    concern on any stack, ``CC-LAB-0198``): a "redirect me here after
    subscribing/following" convenience endpoint (``GET /channels/
    redirect?destination=`` -- a real pattern streaming platforms use for
    post-action redirects) hijacks the connection
    (``http.ResponseWriter.(http.Hijacker).Hijack()``, a real, standard
    net/http mechanism) and writes a raw ``HTTP/1.1 302`` response
    line-by-line, concatenating the caller-supplied ``destination`` value
    straight into the ``Location:`` line with no CR/LF stripping at all
    (CWE-113). This bypasses Go's own net/http response-header-writing
    path, which -- verified empirically before this shape was designed,
    see this op's own change-control entry -- already silently replaces a
    bare CR/LF byte reaching ``w.Header().Set()`` with a space before
    writing to the wire, making an honest vulnerable instance impossible
    to construct through that ordinary path in Go. A **sink** module, not
    a transform (Convention 2, like SSRF/mass-assignment/file-upload/
    price-integrity/path-traversal/ssti): the vulnerable/secure difference
    here is one inseparable hijack-and-hand-roll-vs-validate-and-use-the-
    ordinary-header-API operation, not a value rewrite feeding a shared
    sink."""

    def __init__(self) -> None:
        super().__init__(
            "raw_socket_response_write", "sink", _SINK_ENV, "raw_socket_response_write.go.j2"
        )


class AllowlistAndRuntimeCrlfRejectionSink(TemplateModule):
    """The ``allowlist_and_runtime_crlf_rejection`` op (``lab/safety_
    matrix.yaml``, ``http_response_header_value`` family, ``neutralises``
    -- the secure twin): rejects (HTTP 400) any ``destination`` value that
    does not match a strict site-relative-path allowlist regex
    (``^/[A-Za-z0-9/_-]*$``, no ``\\r``/``\\n``/any other header-breaking
    character) before ever reaching Go's ordinary
    ``w.Header().Set()``/``w.WriteHeader()`` path -- which, as this op's
    own change-control entry documents empirically, independently
    replaces any stray CR/LF byte with a space before writing the response
    to the wire, a second, redundant layer of protection this twin never
    relies on alone."""

    def __init__(self) -> None:
        super().__init__(
            "allowlist_and_runtime_crlf_rejection", "sink", _SINK_ENV,
            "allowlist_and_runtime_crlf_rejection.go.j2",
        )


class RenderOnlyComplexity(TemplateModule):
    """Wraps the composed source/transform/sink body as the entire body of
    one ``net/http.HandlerFunc`` -- the Go analogue of every other stack's
    own ``RenderOnlyComplexity`` (used for a cell with no DB row to
    return)."""

    def __init__(self) -> None:
        super().__init__("render_only", "complexity", _COMPLEXITY_ENV, "render_only.go.j2")

    def render(self, ctx: dict[str, Any]) -> RenderResult:
        template = self._env.get_template(self._template_name)
        code = template.render(body=ctx["body"], handler_name=ctx["handler_name"])
        return RenderResult(code=code, context=dict(ctx))


SOURCES: dict[str, Module] = {
    "read_webhook_signature": ReadWebhookSignatureSource(),
    "read_url_query_param": ReadUrlQueryParamSource(),
    "read_channel_id_and_broadcaster_header": ReadChannelIdAndBroadcasterHeaderSource(),
    "read_authorization_bearer_token": ReadAuthorizationBearerTokenSource(),
    "no_op_token_request": NoOpTokenRequestSource(),
    "read_channel_profile_body": ReadChannelProfileBodySource(),
    "read_uploaded_file": ReadUploadedFileSource(),
    "read_subscription_purchase_request": ReadSubscriptionPurchaseRequestSource(),
    "read_channel_command_request": ReadChannelCommandRequestSource(),
}
TRANSFORMS: dict[str, Module] = {
    "naive_string_compare": NaiveStringCompareTransform(),
    "constant_time_compare": ConstantTimeCompareTransform(),
    "no_ownership_check": NoOwnershipCheckTransform(),
    "identity_match_before_fetch": IdentityMatchBeforeFetchTransform(),
    "jwt_alg_none_default": JwtAlgNoneDefaultTransform(),
    "jwt_none_alg_opt_in": JwtNoneAlgOptInTransform(),
}
SINKS: dict[str, Module] = {
    "webhook_signature_verification": WebhookSignatureVerificationSink(),
    "unchecked_url_fetch": UncheckedUrlFetchSink(),
    "scheme_and_resolved_ip_allowlist": SchemeAndResolvedIpAllowlistSink(),
    "object_lookup_authorization_check": ObjectLookupAuthorizationCheckSink(),
    "jwt_claims_response": JwtClaimsResponseSink(),
    "predictable_token_source": PredictableTokenSourceSink(),
    "csprng_token": CsprngTokenSink(),
    "unfiltered_object_assign": UnfilteredObjectAssignSink(),
    "typed_schema_allowlist": TypedSchemaAllowlistSink(),
    "no_extension_check": NoExtensionCheckSink(),
    "extension_allowlist_mime_check": ExtensionAllowlistMimeCheckSink(),
    "client_trusted_amount": ClientTrustedAmountSink(),
    "server_recomputed_amount": ServerRecomputedAmountSink(),
    "unconfined_path": UnconfinedPathSink(),
    "realpath_confine": RealpathConfineSink(),
    "user_supplied_template_compile": UserSuppliedTemplateCompileSink(),
    "file_loaded_template_name": FileLoadedTemplateNameSink(),
    "raw_socket_response_write": RawSocketResponseWriteSink(),
    "allowlist_and_runtime_crlf_rejection": AllowlistAndRuntimeCrlfRejectionSink(),
}
COMPLEXITIES: dict[str, Module] = {
    "render_only": RenderOnlyComplexity(),
}


def render_route_line(*, method: str, path: str, handler_name: str) -> str:
    """Render one ``net/http.ServeMux`` route-registration line (the
    ``route``-category accumulator fragment). Kept as a pure,
    single-purpose function -- not a class -- matching
    ``node_express.modules.render_route_line``'s own shape."""
    template = _ROUTE_ENV.get_template("route.go.j2")
    return template.render(method=method.upper(), path=path, handler_name=handler_name)
