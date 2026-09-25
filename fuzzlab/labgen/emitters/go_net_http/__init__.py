"""``go_net_http``: this project's first Go stack (category 4 pilot,
``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §9.4/§9.5, Twitch pick;
``CC-LAB-0170``/``FR-LAB-76``).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for Go's standard-library
``net/http`` (no third-party router/framework — matching Twitch's own
documented "Go-centric microservices, new API edge" architecture, per
``docs/research/site-architecture-survey.md`` Category 4 and
``docs/research/site-architecture-survey-functionality-twitch.md``) by
assembling :mod:`fuzzlab.labgen.emitters.go_net_http.modules` fragments per
cell, following ``node_express``'s module-composition shape.

**Phase A scope, stated plainly.** Exactly one shape:
``("webhook_signature", "webhook_signature_verification")`` — an
EventSub-webhook-receiver-shaped handler that reads a request body plus a
digest header and either compares the two HMAC-SHA256 digests with Go's
``==`` (vulnerable, CWE-347, data-dependent-time comparison) or
``crypto/hmac.Equal`` (secure, constant-time) — the simplest illustrative
cell for this stack's first live-boot proof, matching every other stack's
own Phase-A "exactly one shape" scope. CWE-918 (SSRF) and CWE-862 (GraphQL
field authorization, on the sibling Netflix/Java pick) stay deferred to
Phase B, per this pilot's own research note.

**Phase B, first increment (``CC-LAB-0172``/``FR-LAB-78``): a second
shape**, ``("ssrf", "server_side_http_fetch")`` — a clip-thumbnail-fetch
proxy handler that server-side-fetches a caller-supplied URL either with
no validation at all (vulnerable, CWE-918, ``unchecked_url_fetch``) or
after rejecting any scheme but ``https`` and rejecting a resolved IP that
is loopback/private/link-local (secure, ``scheme_and_resolved_ip_
allowlist`` -- closes the DNS-rebinding gap a hostname-string-only
allowlist would leave open). **A deliberate module-composition divergence
from the webhook-signature shape, decided during implementation:** the
vulnerable/secure difference here lives entirely in *which sink module
renders* (the validation-then-fetch logic is one inseparable operation,
not a value transform composed before a shared downstream sink), so this
shape's single manifest op names a **sink** directly rather than a
transform -- ``_ModuleSet.sink is None`` is this module's signal for that
convention; see :meth:`GoEmitter.render`'s own comment at the branch point.
Each shape also declares its own Go ``import`` list now (the fixed,
webhook-only import block became per-shape once a second shape needed a
different set).

**Phase B, tenth increment (``CC-LAB-0189``/``FR-LAB-144``): this stack's
first `price_integrity_bypass` instance**, ``("price_integrity_bypass",
"payment_charge_amount")`` -- a channel-subscription purchase handler
(``POST /subscriptions/purchase``, a real, plausible, core Twitch feature:
subscribing to a broadcaster's channel at a chosen tier) that either
trusts the caller-supplied ``monthly_charge`` field verbatim (vulnerable,
CWE-807, ``client_trusted_amount``) or discards it entirely and looks the
real price up server-side from a fixed ``plan_tier -> price`` map
(secure, ``server_recomputed_amount``), mirroring ``spring_boot``'s own
first instantiation of this concern (``CC-LAB-0188``). Convention 2, like
SSRF/mass-assignment/file-upload: the manifest's one op names a sink
module directly.

**Phase B, eleventh increment (``CC-LAB-0190``/``FR-LAB-145``): this
project's first `path_traversal`/`fs_path_read` instance on any stack**,
``("path_traversal", "fs_path_read")`` -- a previously-exported-clip
download handler (``GET /clips/export?filename=`` -- a real, plausible
Twitch feature: downloading a clip export a broadcaster previously
requested) that either joins the caller-supplied ``filename`` onto a fixed
export directory with no confinement check at all (vulnerable, CWE-22,
``unconfined_path``) or resolves the joined path to its real, symlink-
resolved absolute form and rejects (403) anything that escapes the export
directory's own real form (secure, ``realpath_confine``). Reuses
``read_url_query_param`` verbatim as its source (like the SSRF shape) --
no new source module needed. Convention 2 again: the manifest's one op
names a sink module directly.

**Phase B, twelfth increment (``CC-LAB-0196``/``FR-LAB-151``): this stack's
first `ssti`/`template_render` instance**, ``("ssti", "template_render")``
-- a custom chat-command handler (``POST /channels/commands``, a real,
well-documented streaming-bot feature: Nightbot/StreamElements-style custom
commands with template variables, e.g. an ``!uptime`` command whose response
is ``{{.Uptime}} since going live``) that either compiles and executes the
caller-supplied ``template`` field directly via Go's ``text/template``
package (vulnerable, CWE-1336, ``user_supplied_template_compile`` -- the
same op `spring_boot`'s own TrackerNest wiki-macro shape already uses,
``CC-LAB-0130``) or only ever looks the caller-supplied string up as a KEY
in a small, fixed map of pre-approved variable names, never compiling it as
template source at all (secure, ``file_loaded_template_name``). Reuses
`lab/safety_matrix.yaml`'s existing `server_template_injection` concern and
`template_render` sink family verbatim -- no safety-matrix change needed.
Convention 2 again: the manifest's one op names a sink module directly.
**Detection generalization, checked empirically, not assumed:** the
existing generic `SstiStrategy` (`fuzzlab/oracle/strategies.py`) confirms
SSTI by sending an arithmetic-expression payload (`${a*b}`, `{{a*b}}`,
`<%= a*b %>`, `#{a*b}`, `${{a*b}}`) and checking that the numeric PRODUCT
appears while the literal expression does not. A direct `go run` check
against Go's real `text/template` package (not assumed from the payload
list's syntax alone) shows this does **not** generalize to this stack:
`{{a*b}}`/`${{a*b}}` fail to PARSE at all (`text/template`'s action
grammar has no infix arithmetic operators, unlike Jinja2/FreeMarker/OGNL/
EL -- a hard syntax-level restriction, not a missing wiring gap analogous
to `CC-FUZZ-0032`'s header-point fix), and `${a*b}`/`<%= a*b %>`/`#{a*b}`
contain no `{{`/`}}` at all, so `text/template` treats them as plain
literal text and echoes them back completely unevaluated regardless of
what the vulnerable sink's own `FuncMap` might define. This is a genuine,
verified architecture mismatch between the generic strategy's arithmetic-
marker technique and Go's template-action syntax, not a fixable gap in
this shape's own reachability wiring -- so this instance lands with real,
live-boot-proven field-access/conditional/builtin-call evaluation as its
differential (a genuine SSTI, per the task's own honest-judgment standard),
but automatic confirmation via `SstiStrategy` is an explicitly open
question, not silently claimed working. See `CC-LAB-0196`'s own
change-control entry for the full analysis.

**Phase B, thirteenth increment (``CC-LAB-0198``/``FR-LAB-153``): this
project's first `http_header_injection`/`http_response_header_value`
instance on any stack**, ``("http_header_injection",
"http_response_header_value")`` -- a post-subscribe/-follow redirect
convenience handler (``GET /channels/redirect?destination=``, a real
pattern streaming platforms use for post-action redirects, e.g. a
`?next=`-style param) that either hijacks the raw connection
(``http.Hijacker``) and hand-writes a ``302`` response with the
caller-supplied ``destination`` concatenated straight into the
``Location:`` line, no CR/LF stripping at all (vulnerable, CWE-113,
``raw_socket_response_write``), or validates ``destination`` against a
strict site-relative-path allowlist regex before using Go's ordinary
``w.Header().Set()``/``w.WriteHeader()`` path (secure, ``allowlist_and_
runtime_crlf_rejection``). Reuses ``lab/safety_matrix.yaml``'s existing
`http_response_header_value` sink family / `http_header_injection`
concern and its existing `raw_socket_response_write`/`allowlist_and_
runtime_crlf_rejection` op rows verbatim (added by `CC-LAB-0063` for the
`docs/research/corpus-examples/header-injection/` research, never before
instantiated in a generated lab app on any stack) -- no safety-matrix
change needed. **Honest-vulnerable-instance judgment, checked empirically
before finalizing the design (not assumed):** a real `go run` check
(recorded in `CC-LAB-0198`'s own change-control entry) against a real
booted `net/http.Server` shows Go's own ordinary
`w.Header().Set()`+`w.WriteHeader()` path already replaces a bare CR/LF
byte in a header value with a space before writing the response to the
wire, so an honest vulnerable instance of this concern cannot be built
through that ordinary API -- the vulnerable twin instead uses
`http.Hijacker.Hijack()`, a real, standard net/http mechanism (used for
WebSocket upgrades and other raw-protocol handling in real Go servers,
not a contrivance invented for this lab), to obtain the raw connection
and write the response itself, exactly mirroring this same op's own
`vulnerable-raw-socket-write-5.js`/`vulnerable-raw-socket-response-4.php`
corpus precedent (Node/PHP both bypass their own frameworks' built-in
header-writing CRLF protection the same way). Convention 2 again: the
manifest's one op names a sink module directly. Reuses
`read_url_query_param` verbatim as its source (like the SSRF/path-
traversal shapes) -- no new source module needed.

**Phase B, fourteenth increment (`CC-LAB-0199`/`FR-LAB-154`): this
stack's first `open_redirect`/`http_redirect_location` instance**,
`("open_redirect", "http_redirect_location")` -- a "return here after
login" convenience endpoint (`GET /auth/login-redirect?next=` -- a real,
plausible Twitch feature, and a genuinely common real-world open-redirect
vector on many real sites) that either sets the caller-supplied `next`
value as the `Location` header verbatim, through Go's ORDINARY
`w.Header().Set()`/`w.WriteHeader()` path with no check at all that it
stays on this site (vulnerable, CWE-601, `raw_concat`), or rejects
(HTTP 400) any `next` value that is not a genuine site-relative path
before ever setting the header (secure, `redirect_target_allowlist`).
Reuses `lab/safety_matrix.yaml`'s existing `open_redirect` concern /
`http_redirect_location` sink family and its existing
`raw_concat`/`redirect_target_allowlist` op rows verbatim (added by
`CC-LAB-0210` for `php_laravel`'s Booking.com pilot, never before
instantiated on this stack -- grepped `fuzzlab/labgen/emitters/
go_net_http/` for "open_redirect"/"redirect_target_allowlist" before
starting and found no prior instance) -- no safety-matrix change needed.
Unlike `http_header_injection`'s own vulnerable twin (`CC-LAB-0198`),
this shape's vulnerable twin needs NO `http.Hijacker` bypass: open
redirect requires no CR/LF byte to reach the wire at all (a bare absolute
external URL, e.g. `https://evil.example/phish`, is already a perfectly
well-formed `Location` header value), so Go's ordinary header-writing
path is already sufficient to build an honest vulnerable instance --
verified by this increment's own live-boot test alongside a genuine
regression check that the `BUG-0044` redirect-following fix holds (a
live confirmation via `fuzzlab.oracle.strategies.OpenRedirectStrategy`
would immediately re-expose `TooManyRedirects` if that fix somehow
regressed, since the strategy's own canary is a `Location:`-header value
the probe sender must NOT follow). Convention 2 again: the manifest's
one op names a sink module directly. Reuses `read_url_query_param`
verbatim as its source, exactly like the SSRF/path-traversal/http-
header-injection shapes.

**Multi-file output, like every other routed emitter.** Per this project's
routed-emitter convention (``node_express``, ``ruby_rails``), a ``route``-
category *accumulator* module (``net/http.ServeMux`` registration lines)
is fed by one fragment per cell, sorted by cell ID at render time — never
by append/iteration order, so the whole-lab regeneration determinism gate
stays meaningful. :meth:`render` therefore returns only the per-cell
handler file for a cell; :meth:`render_route_accumulator` builds the
accumulator separately, over the whole supported cell set at once.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS, render_route_line

__all__ = ["ABSENT_INPUT_KINDS", "GoEmitter", "served_url_for"]


class _ModuleSet(NamedTuple):
    source: str
    #: The fixed sink module name for shapes where the manifest's
    #: transform ops modify a *value* the sink then renders unconditionally
    #: (the webhook-signature shape). ``None`` signals the other
    #: convention this stack now has two of: the manifest's one op names a
    #: **sink** module directly (the SSRF shape) -- see
    #: :meth:`GoEmitter.render`.
    sink: str | None
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("webhook_signature", "webhook_signature_verification"): _ModuleSet(
        "read_webhook_signature", "webhook_signature_verification", "render_only"
    ),
    ("ssrf", "server_side_http_fetch"): _ModuleSet("read_url_query_param", None, "render_only"),
    ("access_control", "db_row_by_id_lookup"): _ModuleSet(
        "read_channel_id_and_broadcaster_header", "object_lookup_authorization_check", "render_only"
    ),
    ("jwt_algorithm_confusion", "jwt_signature_verification"): _ModuleSet(
        "read_authorization_bearer_token", "jwt_claims_response", "render_only"
    ),
    # A third convention (neither 1 nor 2 above): the manifest's one op
    # names a sink directly (like convention 2), but the source itself has
    # no tainted input to read at all -- see `NoOpTokenRequestSource`'s own
    # docstring in modules.py for why this genuinely differs from the SSRF
    # shape's own convention 2 (which still has a real source).
    ("weak_token_entropy", "session_token_generation"): _ModuleSet(
        "no_op_token_request", None, "render_only"
    ),
    # Convention 2 again (like SSRF): the manifest's one op names a sink
    # directly (`unfiltered_object_assign`/`typed_schema_allowlist`) --
    # the vulnerable/secure difference is one inseparable
    # unmarshal-onto-the-live-record-vs-unmarshal-into-a-narrow-DTO
    # operation, not a value rewrite feeding a shared sink, same reasoning
    # as `UncheckedUrlFetchSink`/`SchemeAndResolvedIpAllowlistSink`'s own
    # docstrings (CC-LAB-0182).
    ("mass_assignment", "orm_entity_bulk_assign"): _ModuleSet(
        "read_channel_profile_body", None, "render_only"
    ),
    # Convention 2 again (like SSRF/mass-assignment): the manifest's one op
    # names a sink directly -- the vulnerable/secure difference is one
    # inseparable write-and-serve operation (which filename/content-type to
    # trust when writing to and serving from a web-served directory), not a
    # value rewrite feeding a shared sink. This stack's first
    # `unrestricted_file_upload`/`fs_web_root_write` instance on any stack
    # in this project (`CC-LAB-0186`).
    ("unrestricted_file_upload", "fs_web_root_write"): _ModuleSet(
        "read_uploaded_file", None, "render_only"
    ),
    # Convention 2 again (like SSRF/mass-assignment/file-upload): the
    # manifest's one op names a sink module directly -- the vulnerable/
    # secure difference is one inseparable trust-the-client-vs-recompute-
    # server-side operation, not a value rewrite feeding a shared sink.
    # This stack's first `price_integrity_bypass`/`payment_charge_amount`
    # instance on any Go page (`CC-LAB-0189`), mirroring `spring_boot`'s
    # own first instantiation of the same concern (`CC-LAB-0188`).
    ("price_integrity_bypass", "payment_charge_amount"): _ModuleSet(
        "read_subscription_purchase_request", None, "render_only"
    ),
    # Convention 2 again (like SSRF): the manifest's one op names a sink
    # module directly -- the vulnerable/secure difference is one
    # inseparable join-and-read-unconfined-vs-resolve-and-confine
    # operation, not a value rewrite feeding a shared sink. This project's
    # first `path_traversal`/`fs_path_read` instance on any stack
    # (`CC-LAB-0190`). Reuses `read_url_query_param` verbatim as its
    # source, exactly like the SSRF shape.
    ("path_traversal", "fs_path_read"): _ModuleSet("read_url_query_param", None, "render_only"),
    # Convention 2 again (like SSRF/mass-assignment/price-integrity/path-
    # traversal): the manifest's one op names a sink module directly --
    # the vulnerable/secure difference here is one inseparable compile-
    # and-execute-caller-template-vs-lookup-fixed-variable-name operation,
    # not a value rewrite feeding a shared sink. This stack's first
    # `ssti`/`template_render` instance (`CC-LAB-0196`), reusing
    # `lab/safety_matrix.yaml`'s existing `server_template_injection`
    # concern and mirroring `spring_boot`'s own TrackerNest
    # `ssti`/`template_render` shape (`CC-LAB-0130`).
    ("ssti", "template_render"): _ModuleSet("read_channel_command_request", None, "render_only"),
    # Convention 2 again (like SSRF/mass-assignment/price-integrity/path-
    # traversal/ssti): the manifest's one op names a sink module directly
    # -- the vulnerable/secure difference here is one inseparable
    # hijack-and-hand-roll-vs-validate-and-use-the-ordinary-header-API
    # operation, not a value rewrite feeding a shared sink. This project's
    # first `http_header_injection`/`http_response_header_value` instance
    # on any stack (`CC-LAB-0198`). Reuses `read_url_query_param` verbatim
    # as its source, exactly like the SSRF/path-traversal shapes.
    ("http_header_injection", "http_response_header_value"): _ModuleSet(
        "read_url_query_param", None, "render_only"
    ),
    # Convention 2 again (like SSRF/mass-assignment/price-integrity/path-
    # traversal/ssti/http-header-injection): the manifest's one op names a
    # sink module directly. This stack's first `open_redirect`/`http_
    # redirect_location` instance (`CC-LAB-0199`), reusing
    # `lab/safety_matrix.yaml`'s existing concern/family and its existing
    # `raw_concat`/`redirect_target_allowlist` op rows verbatim (added by
    # `CC-LAB-0210` for `php_laravel`'s Booking.com pilot) -- no
    # safety-matrix change needed. Reuses `read_url_query_param` verbatim
    # as its source, exactly like the SSRF/path-traversal/http-header-
    # injection shapes.
    ("open_redirect", "http_redirect_location"): _ModuleSet(
        "read_url_query_param", None, "render_only"
    ),
}

#: Per-module (source/transform-op/sink name) -> the extra Go standard-
#: library packages that module's own rendered code references, beyond
#: ``net/http`` (always included -- every handler signature needs it).
#: Keyed per-module rather than per-shape (``CC-LAB-0172``'s own fix,
#: found while assembling the SSRF shape's vulnerable twin: that twin's
#: sink, ``unchecked_url_fetch``, does not use ``net``/``net/url`` at all,
#: so a shape-level fixed import list -- covering the union every sink a
#: shape *could* pick needs -- fails `go build`/`gofmt` with an "imported
#: and not used" error the moment a shape has two sinks with different
#: import needs). :meth:`GoEmitter.render` unions exactly the modules a
#: given cell actually renders with, never a shape-wide superset.
_MODULE_IMPORTS: dict[str, tuple[str, ...]] = {
    "read_webhook_signature": ("crypto/hmac", "crypto/sha256", "encoding/hex", "io"),
    "webhook_signature_verification": (),
    "read_url_query_param": (),
    "unchecked_url_fetch": ("io", "time"),
    "scheme_and_resolved_ip_allowlist": ("io", "net", "net/url", "time"),
    "read_channel_id_and_broadcaster_header": (),
    "no_ownership_check": (),
    "identity_match_before_fetch": (),
    "object_lookup_authorization_check": ("html",),
    "read_authorization_bearer_token": (
        "crypto/hmac", "crypto/sha256", "encoding/base64", "encoding/json", "strings",
    ),
    "jwt_alg_none_default": (),
    "jwt_none_alg_opt_in": (),
    "jwt_claims_response": ("encoding/json", "io"),
    "no_op_token_request": (),
    "predictable_token_source": ("fmt", "io", "time"),
    "csprng_token": ("crypto/rand", "encoding/hex", "io"),
    "read_channel_profile_body": ("io",),
    "unfiltered_object_assign": ("encoding/json",),
    "typed_schema_allowlist": ("encoding/json",),
    "read_uploaded_file": ("io",),
    "no_extension_check": ("mime", "os", "path/filepath"),
    "extension_allowlist_mime_check": ("os", "path/filepath", "strings"),
    "read_subscription_purchase_request": ("io",),
    "client_trusted_amount": ("encoding/json",),
    "server_recomputed_amount": ("encoding/json",),
    "unconfined_path": ("os", "path/filepath"),
    "realpath_confine": ("os", "path/filepath", "strings"),
    "read_channel_command_request": ("io",),
    "user_supplied_template_compile": ("bytes", "encoding/json", "text/template"),
    "file_loaded_template_name": ("encoding/json",),
    "raw_socket_response_write": (),
    "allowlist_and_runtime_crlf_rejection": ("regexp",),
    "raw_concat": (),
    "redirect_target_allowlist": ("regexp",),
}

#: Per-route static context this Phase A emitter needs beyond the
#: verdict-relevant Cell IR -- same render-only-information separation
#: rationale as every other stack's own per-route params table.
#:
#: CC-LAB-0243 (FR-LAB-162, Browsable Labs Lane 3) makes one key
#: **required on every route** and adds optional render-only keys, each
#: consumed by exactly one source/sink template and identical on both twins
#: of a route (so every minimal pair still differs only in its
#: transform/sink region, BUG-0027):
#:
#: * ``absent_input`` (required, PA-0053/PA-0054/PA-0055): the route's
#:   *declared* behavior for a bare request carrying none of its inputs --
#:   one of :data:`ABSENT_INPUT_KINDS`. Checked offline over every route
#:   the go manifests produce (``tests/test_labgen_go_net_http_browsable.py``)
#:   and live by the every-route, two-method bare sweep
#:   (``tests/test_labgen_go_net_http_navigability_live_boot.py``).
#: * ``default_value`` (``read_url_query_param``): an absent/empty value
#:   becomes this default before the sink runs.
#: * ``required_param`` (``read_url_query_param``): an absent/empty value is
#:   a handled 400 before the sink runs (no safe default exists).
#: * ``default_to_caller`` (``read_channel_id_and_broadcaster_header``): an
#:   absent ``channel_id`` defaults to the caller's own ``X-Broadcaster-Id``;
#:   with neither present, a handled 401 page before the sink (R6).
#: * ``page_title`` (``object_lookup_authorization_check``): the dashboard
#:   page's title -- that sink renders inside the site layout (CC-LAB-0243).
_ROUTE_PARAMS: dict[str, dict[str, Any]] = {
    # Genuine api (EventSub webhook receiver); GET serves its client page.
    "/webhooks/eventsub": {"absent_input": "form_on_get"},
    # CC-LAB-0243: `required_param` -- no safe default URL exists (any
    # default would make the vulnerable twin fetch it); before this change
    # a bare GET answered 502 on the vulnerable twin (BUG-0053).
    "/api/clips/thumbnail": {
        "var_name": "targetUrl", "param_name": "url",
        "absent_input": "required_400", "required_param": True,
    },
    "/channels/analytics": {
        "param_name": "channel_id",
        "absent_input": "default_caller_else_401", "default_to_caller": True,
        "page_title": "Channel analytics",
    },
    # Bearer-token JSON api: its existing fail-closed token check already
    # answers a bare request with 401 on both twins (asserted, unchanged).
    "/channels/settings": {"absent_input": "auth_reject_401"},
    # The source reads no request input at all (`no_op_token_request`).
    "/sessions/refresh": {"absent_input": "no_input"},
    "/channels/profile": {"absent_input": "form_on_get"},
    # CC-LAB-0183: second instance of the access_control/db_row_by_id_lookup
    # shape (CC-LAB-0178's own /channels/analytics), zero new generator
    # code -- just this route-profile entry.
    "/channels/subscribers": {
        "param_name": "channel_id",
        "absent_input": "default_caller_else_401", "default_to_caller": True,
        "page_title": "Subscribers",
    },
    # CC-LAB-0185: second instance of the ssrf/server_side_http_fetch shape
    # (CC-LAB-0172's own /api/clips/thumbnail), zero new generator code --
    # just this route-profile entry. CC-LAB-0243: `required_param`, for the
    # same reason as /api/clips/thumbnail (BUG-0053).
    "/clips/download": {
        "var_name": "sourceUrl", "param_name": "source_url",
        "absent_input": "required_400", "required_param": True,
    },
    # CC-LAB-0186: this stack's first unrestricted_file_upload/
    # fs_web_root_write instance -- no per-route var_name/param_name needed
    # (ReadUploadedFileSource publishes its own default identifiers).
    # CC-LAB-0243: a `page` -- GET renders the real upload form.
    "/channels/emotes/upload": {"absent_input": "form_on_get"},
    # CC-LAB-0189: this stack's first price_integrity_bypass/
    # payment_charge_amount instance -- no per-route var_name/param_name
    # needed (ReadSubscriptionPurchaseRequestSource publishes its own
    # default identifiers).
    "/subscriptions/purchase": {"absent_input": "form_on_get"},
    # CC-LAB-0190: this project's first path_traversal/fs_path_read
    # instance on any stack. Reuses ReadUrlQueryParamSource's own
    # var_name/param_name convention -- filename is read from the
    # `filename` query param. CC-LAB-0243: `required_param` -- a download
    # naming no export has no meaningful default.
    "/clips/export": {
        "var_name": "requestedFilename", "param_name": "filename",
        "absent_input": "required_400", "required_param": True,
    },
    # CC-LAB-0196: this stack's first ssti/template_render instance -- no
    # per-route var_name/param_name needed (ReadChannelCommandRequestSource
    # publishes its own default identifier).
    "/channels/commands": {"absent_input": "form_on_get"},
    # CC-LAB-0198: this project's first http_header_injection/
    # http_response_header_value instance on any stack. CC-LAB-0243:
    # defaults to `/`, which the secure twin's own allowlist accepts --
    # before this change the vulnerable twin sent an empty `Location`.
    "/channels/redirect": {
        "var_name": "destination", "param_name": "destination",
        "absent_input": "default", "default_value": "/",
    },
    # CC-LAB-0199: this stack's first open_redirect/http_redirect_location
    # instance. CC-LAB-0243 (R7): defaults to `/dashboard`, a real site page
    # the secure twin's allowlist accepts (`/` alone does not: the regex
    # needs `/` followed by an alphanumeric character).
    "/auth/login-redirect": {
        "var_name": "nextTarget", "param_name": "next",
        "absent_input": "default", "default_value": "/dashboard",
    },
}

#: CC-LAB-0243: the closed vocabulary of ``absent_input`` declarations.
ABSENT_INPUT_KINDS: frozenset[str] = frozenset(
    {
        "default",                  # a real default value (``default_value``)
        "required_400",             # handled 400 before the sink (``required_param``)
        "default_caller_else_401",  # caller's own id, else handled 401 (``default_to_caller``)
        "auth_reject_401",          # existing fail-closed credential check answers 401
        "form_on_get",              # POST route: GET serves its page, never the sink
        "no_input",                 # the source reads no request input at all
    }
)

#: CC-LAB-0243 (FR-LAB-162, R1 -- see ``requirements.md``'s FR-LAB-162
#: "R1 sign-off"): every Twitch-clone route's **vulnerable** cell, served at
#: its own manifest ``route.path`` (the URL ground truth names), replacing
#: the generic ``/generated/{cell_id}`` every cell used before. Declared
#: explicitly, never inferred from odd/even cell IDs.
_REAL_PAGE_CELL_IDS: frozenset[str] = frozenset(
    {
        "LABGEN-GO-0001", "LABGEN-GO-0003", "LABGEN-GO-0005", "LABGEN-GO-0007",
        "LABGEN-GO-0009", "LABGEN-GO-0011", "LABGEN-GO-0013", "LABGEN-GO-0015",
        "LABGEN-GO-0017", "LABGEN-GO-0019", "LABGEN-GO-0021", "LABGEN-GO-0023",
        "LABGEN-GO-0025", "LABGEN-GO-0027",
    }
)

#: CC-LAB-0243 (R1, branch (a)): each route's **secure twin**, served at the
#: twin-suffixed variant of that route (:func:`_twin_url_for`), mirroring the
#: `django` (CC-LAB-0242) and `php_laravel` conventions. Ground truth still
#: describes only the vulnerable cell. Every entry shares its ``route.path``
#: with exactly one :data:`_REAL_PAGE_CELL_IDS` cell (asserted offline).
_REAL_PAGE_TWIN_CELL_IDS: frozenset[str] = frozenset(
    {
        "LABGEN-GO-0002", "LABGEN-GO-0004", "LABGEN-GO-0006", "LABGEN-GO-0008",
        "LABGEN-GO-0010", "LABGEN-GO-0012", "LABGEN-GO-0014", "LABGEN-GO-0016",
        "LABGEN-GO-0018", "LABGEN-GO-0020", "LABGEN-GO-0022", "LABGEN-GO-0024",
        "LABGEN-GO-0026", "LABGEN-GO-0028",
    }
)


def _twin_url_for(real_url: str, cell_id: str) -> str:
    """``/webhooks/eventsub`` + ``LABGEN-GO-0002`` ->
    ``/webhooks/eventsub.labgen-go-0002`` -- the same suffix shape the
    `django` emitter's own ``_twin_url_for`` produces."""
    return f"{real_url}.{cell_id.lower()}"


def served_url_for(cell: Cell) -> str:
    """The URL path ``cell`` is actually served at -- **the one shared
    derivation** of that fact (PA-0003/PA-0021), used by
    :meth:`GoEmitter.render_route_accumulator` and by tests alike:

    * a vulnerable cell (:data:`_REAL_PAGE_CELL_IDS`): its ``route.path``;
    * its secure twin (:data:`_REAL_PAGE_TWIN_CELL_IDS`): :func:`_twin_url_for`;
    * any other (not yet pinned) cell: ``/generated/{cell_id}``.
    """
    if cell.cell_id in _REAL_PAGE_CELL_IDS:
        return cell.route.path
    if cell.cell_id in _REAL_PAGE_TWIN_CELL_IDS:
        return _twin_url_for(cell.route.path, cell.cell_id)
    return f"/generated/{cell.cell_id.lower()}"


class GoEmitter(Emitter):
    """Renders a :class:`Cell` to a single Go handler file (plus a shared
    route accumulator) via module composition, Phase A shape only.

    ``render()`` never falls back to a default sink/transform/route-profile
    silently, matching every other stack's "fail loud on an authoring gap"
    discipline.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for go_net_http "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _ROUTE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: go_net_http has no route profile for route {cell.route.path!r} "
                f"-- known routes: {sorted(_ROUTE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_ROUTE_PARAMS[cell.route.path])
        ctx["handler_name"] = f"handle{_pascal_case(cell.cell_id)}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["naive_string_compare"]

        if modules.sink is not None:
            # Convention 1 (webhook-signature): every op is a transform
            # that modifies a value the fixed sink then renders.
            transform_code_blocks: list[str] = []
            for op in applied_ops:
                if op not in TRANSFORMS:
                    raise ValueError(
                        f"{cell.cell_id}: go_net_http has no transform module for op {op!r} "
                        f"-- known ops: {sorted(TRANSFORMS)}"
                    )
                transform_result = TRANSFORMS[op].render(ctx)
                ctx = transform_result.context
                transform_code_blocks.append(transform_result.code)
            sink_result = SINKS[modules.sink].render(ctx)
            body_parts = (source_result.code, *transform_code_blocks, sink_result.code)
            sink_name_for_composition = modules.sink
        else:
            # Convention 2 (SSRF, CC-LAB-0172): the manifest's one op names
            # a SINK module directly -- there is no separate transform
            # stage, since the vulnerable/secure difference here is one
            # inseparable validate-then-fetch operation, not a value
            # rewrite feeding a shared sink. See the module docstring.
            if len(applied_ops) != 1:
                raise ValueError(
                    f"{cell.cell_id}: go_net_http's sink-selecting shapes take exactly one op "
                    f"(the sink module name), got {applied_ops!r}"
                )
            (sink_op,) = applied_ops
            if sink_op not in SINKS:
                raise ValueError(
                    f"{cell.cell_id}: go_net_http has no sink module for op {sink_op!r} "
                    f"-- known sinks: {sorted(SINKS)}"
                )
            sink_result = SINKS[sink_op].render(ctx)
            body_parts = (source_result.code, sink_result.code)
            sink_name_for_composition = sink_op

        body = _indent_block("\n".join(body_parts), "\t")
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        # For convention 2 (sink is None), `applied_ops` already names the
        # sink module -- adding it again here would render a redundant
        # "... -> unchecked_url_fetch -> unchecked_url_fetch -> ...".
        composition_sink_part = (sink_name_for_composition,) if modules.sink is not None else ()
        composition = " -> ".join((modules.source, *applied_ops, *composition_sink_part, modules.complexity))

        used_module_names = {modules.source, sink_name_for_composition, *applied_ops}
        extra_imports: set[str] = set()
        for name in used_module_names:
            extra_imports.update(_MODULE_IMPORTS.get(name, ()))
        all_imports = sorted({"net/http", *extra_imports})
        import_lines = "".join(f'\t"{pkg}"\n' for pkg in all_imports)
        go_source = (
            "package main\n"
            "\n"
            f"// Generated by fuzzlab.labgen.emitters.go_net_http for cell {cell.cell_id}\n"
            f"// Route: {cell.route.method} {cell.route.path}\n"
            f"// Module composition: {composition}\n"
            "\n"
            "import (\n"
            f"{import_lines}"
            ")\n"
            "\n"
            f"{complexity_result.code}"
        )
        path = f"{cell.cell_id.lower().replace('-', '_')}.go"
        return (EmittedFile(path=path, content=go_source.encode("utf-8"), role="controller"),)

    def render_route_accumulator(self, cells: list[Cell]) -> EmittedFile:
        """Build ``routes_generated.go`` -- the ``route``-category
        accumulator (cardinality ``accumulator``) -- fed by one fragment
        per **supported** cell, sorted by ``cell_id`` at render time.

        Deliberately not part of :meth:`render` (see the module docstring):
        the accumulator's real cardinality is "one file, fed by every cell,"
        which a single ``render(cell)`` call cannot express without either
        re-emitting a growing file on every single-cell call (breaking the
        generic Tier-3 harness's "no two cells emit the same path"
        invariant) or silently overwriting it. Two calls with an equal
        ``cells`` sequence (as a set -- order of the input iterable does not
        matter, only sorted ``cell_id`` does) produce byte-identical output.
        """
        supported = [c for c in cells if self.supports(c.vuln_class, c.sink_context)]
        by_id = sorted(supported, key=lambda c: c.cell_id)
        route_lines: list[str] = []
        # `route.go.j2` renders one registration line; the GET page lines
        # below use the same shape so gofmt sees one uniform block.
        for c in by_id:
            # CC-LAB-0243: the one shared `served_url_for` derivation
            # (PA-0003/PA-0021) -- the vulnerable twin at its real
            # `route.path`, the secure twin at the twin-suffixed variant, so
            # the two never double-register one `net/http.ServeMux` pattern
            # (the reason the old `/generated/{cell_id}` scheme existed).
            served = served_url_for(c)
            route_lines.append(
                render_route_line(
                    method=c.route.method,
                    path=served,
                    handler_name=f"handle{_pascal_case(c.cell_id)}",
                )
            )
            # CC-LAB-0243 (`absent_input: form_on_get`): a POST route also
            # answers GET at the same URL with its page -- the site layer's
            # form/client page for that route (`site.go`'s `sitePage`), never
            # the cell's own handler, so every per-cell handler file (and so
            # every minimal pair) is unchanged.
            if c.route.method.upper() == "POST":
                route_lines.append(
                    f'\tmux.HandleFunc("GET {served}", sitePage("{c.route.path}"))\n'
                )
        go_source = (
            "package main\n"
            "\n"
            "// Generated by fuzzlab.labgen.emitters.go_net_http -- route accumulator.\n"
            "// Route lines below are sorted by cell ID at render time, never by\n"
            "// append/iteration order, so adding one cell can never reshuffle this\n"
            "// file (the whole-lab regeneration determinism gate).\n"
            "\n"
            'import "net/http"\n'
            "\n"
            "func registerRoutes(mux *http.ServeMux) {\n"
            f"{''.join(route_lines)}"
            "}\n"
        )
        return EmittedFile(path="routes_generated.go", content=go_source.encode("utf-8"), role="route")


def _pascal_case(cell_id: str) -> str:
    """``LABGEN-GO-0001`` -> ``LabgenGo0001`` -- a valid Go identifier
    fragment derived deterministically from the cell ID."""
    return "".join(part.capitalize() for part in cell_id.replace("_", "-").split("-"))


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free, same convention as every other stack's own
    ``_indent_block``."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)
