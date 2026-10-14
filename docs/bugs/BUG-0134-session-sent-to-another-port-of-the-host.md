# BUG-0134 — A session was sent to every port of its host (another app's origin)

- Date: 2026-10-14
- Status: fixed (CC-SESS-0023, CC-CRAWL-0026, CC-FUZZ-0080, CC-PROXY-0023)
- Severity: high (security). A lab app's session cookie and bearer token were handed to
  any other service on another port of the same host (another lab app, the OOB
  listener, the fuzzlab web UI), and a request there could log in there with this
  host's credential.

## Description
`SessionManager` keyed a session by `(host, identity)` and `prepare()` applied it to
every in-scope request whose **hostname** matched. On a loopback lab every app shares
`127.0.0.1`, so Juice Shop's `token` cookie and bearer (`:3000`) were attached to
requests to bWAPP (`:8090`) or any other loopback port the crawl or a probe reached.
The same host-level rule was repeated wherever the session was carried:
- `ensure()` / `prepare()`: a request to another port that arrived before (or after a
  logout of) the session logged in **there**, from that request's directory, with the
  host's keyring credential — another app's login form received it;
- `authorize()` refused a plugin retarget to another host but not another port;
- `observe()` looked the state up by host, so another app's login page on another port
  logged this session out;
- `verify_live` and the browser login's probe differential (`_navigate(session_host=)`,
  `_spa_probe`) carried the session to any hop on the host;
- greybox's `RequestsCorrelatingSender` put the cookie on every probe, whatever the URL;
- the browser path: `header_scope_for` admitted any URL whose canonical host matched,
  and Chromium's cookie jar is port-agnostic (RFC 6265 §8.5), so in a host-scoped
  (external, any-port) crawl the jar went to every port;
- lane A's header breaker (`_on_logout`) and lane B's single-session breaker
  (`_on_main_logout`) attributed a logout by host, and `is_auth_endpoint` matched a
  path on any port;
- `session_header(s)` (`fuzzlab session print`, greybox) handed the session out for any
  base URL on the host;
- a proxy-captured session (`SessionCapture`) carried no notion of where it was seen.

## Where encountered
Review of BUG-0132 (reviewer A, S2): after the browser login started carrying Juice
Shop's JS-set `token` cookie into the requests senders, the cookie and the bearer were
shown to reach any port of `127.0.0.1`. PA-0123 had stated this as a "host-level
exception" (FR-SESS-12/13, FR-SESS-19's residual "origin-scoped sessions are a separate
follow-up"). The design draft `origin-scope-draft.md` (Revision 2, reviewers A and B
reconciled) is the spec of the fix.

## What it caused to fail
- **NFR-SESS-redaction's intent** and the lab's isolation: a secret of one app was
  disclosed to another app (or to whatever listens on another loopback port).
- **FR-SESS-8** (credentials per host, sent to the host being authenticated): a
  request to another app on the host could trigger a login there with this host's
  credential.
- **Measurement:** a probe of bWAPP during a Juice Shop run went out with Juice Shop's
  session, so its verdict was attributed to a session that does not exist there.
- **FR-SESS-16 / FR-FUZZ-43 / FR-FUZZ-44:** another app's logout tripped the run's
  breakers.

## What the bug was identified to be
A session's **send scope** was its host, decided by hostname comparisons in each place
the session is carried. The session had no record of the origins it belonged to, so no
send path could ask the right question ("is this URL one of the session's origins?").

## Root cause analysis
Five Whys:
1. *Why did bWAPP receive Juice Shop's cookie?* `prepare()` applied the
   `("127.0.0.1", "user")` session to every request on host `127.0.0.1`.
2. *Why by host?* The session is keyed by `(host, identity)` because credentials are
   stored per host (D12), and the key was also used as the send scope: nothing else
   described where the session belonged.
3. *Why was that accepted?* FR-SESS-13 and BUG-0098 recorded "other ports of the same
   host are allowed (D12)" as *by design*, and PA-0123 (which made the **browser
   scope** an origin) restated it as a "stated exception" for the session manager.
4. *Why did the exception survive PA-0123?* PA-0123 governs outbound **scope** (where a
   request may go at all), and was applied to the browser's scope predicate. A
   session's **destination set** (where a secret may go among in-scope requests) was not
   read as a scope, so the PA-0002 sweep for BUG-0123 did not visit `prepare`,
   `header_scope_for`, `_navigate(session_host=)` or greybox; BUG-0132's review deferred
   it again in prose ("a separate follow-up"), with nothing pinning the exception.
5. *Why was each carrier able to repeat it?* There was no single "where may this
   session go" predicate on the state; each carrier compared hostnames itself (eight
   copies of one decision).

**Root cause:** the session's send scope was an implicit property of its storage key
(the host), carried by per-site hostname comparisons, and a stated "by design"
exception kept it alive after the project had decided (PA-0123) that a target is an
origin, not a host.

## Corrective action
Built to Revision 2 of the design (O1–O13); CC-SESS-0023, CC-CRAWL-0026, CC-FUZZ-0080,
CC-PROXY-0023:
- **O1** `SessionState.origins` (canonical origins): the base URL's, the login page's,
  the credential destination's and the operator's `auth_origins`, from one function
  (`manager.session_origins`, PA-0003). **In memory only** (A4): a resumed record
  never applies a session by itself. Not secret (in `redacted()`).
- **O2** `prepare()` applies the session only when `canonical_origin(url)` is one of
  them; otherwise the request goes out anonymously, never triggers a login there, is
  logged once per (origin, identity), counted (`out_of_origin_sends`), and the decision
  is reported (`session_note`) so the seam sender stamps `Probe.session = "anonymous
  (out of origin)"`; the oracle carries it into `Verdict.evidence["session"]` and
  greybox into the attempt's features. Crawl, auto and greybox summaries report the
  count (`session_out_of_origin`).
- **O3** `ensure()` logs in only from an operator base or a base on the existing
  session's origins; an operator base on another origin is refused loudly naming the
  remedy (a distinct identity name per app).
- **O4** `authorize()` refuses a retarget that carries the session to an origin
  outside the session's (another port included; an anonymous out-of-origin request may
  still be edited on its own origin); `observe()` finds the session by origin
  membership.
- **O5** `_navigate(session_origins=)`: `verify_live`, the protected probe and the
  probe differential refuse a hop outside the origins before it is fetched; a
  candidate on another origin is never fetched.
- **O6** greybox: `_cookie_for` returns the session's origins and
  `RequestsCorrelatingSender(cookie_origins=)` attaches the cookie only there (a cookie
  without origins is refused at construction).
- **O7** `SessionCapture` records the canonical origins of observed URLs on its host;
  `adopt()` refuses a session with none.
- **O8** `header_scope_for` admits the session's origins only (in scope and the https
  floor still apply); in an authenticated context the guarded route withholds the
  context's jar from an in-scope request on another origin (`cookie_scope`: an empty
  `Cookie` header through `route.fetch(headers=)`, so Playwright's API client adds no
  jar), on the request and on each redirect hop; the spider's `_isolated_submit` drops
  the jar's cookies for such an action.
- **O9** lane A `_on_logout` and lane B `_on_main_logout` get the logout's canonical
  origin (FR-SESS-16's listener now receives `(origin, identity)`) and compare it with
  the run's session's origins; `is_auth_endpoint` compares origin and path (`url_key`).
- **O10** `session_header(s)` refuse a base URL whose origin is not one of the
  session's (`_check_origin`, at the action).
- **O11** isolated copies compute the same origins (same function, same inputs) and
  enforce them.
- **O12** the destination refusal names the origin and how to authorise it; a login
  handshake that fetched another origin warns with the same advice.
- **O13** residual (stated): the key stays `(host, identity)`; two apps on one host need
  distinct identity names (CLI help).

Tests: `tests/test_session_origin_scope.py` (two real loopback servers; real Chromium for
the crawl) and the updated `test_session_transport_binding.py`,
`test_logout_listener.py`, `test_login_form_isolation.py`, `test_forms_phase2.py`,
`test_proxy_session_capture.py`, `test_destructive_urls.py`.

## Recurrence review
Checked `docs/bugs/` (session, scope, browser, transport and cookie bugs) and
`docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0123 / PA-0123** (the browser left the target origin): **same root cause.**
  "The target was a host where it needed to be an origin", decided per layer. PA-0123(2)
  made scope an origin and named a host-only scope a stated exception; this bug is that
  exception, one layer over (the session's destination set rather than the browser's
  request scope).
- **BUG-0050** (crawler scope by host): the origin of the host-level decision; its
  any-port external crawl is exactly where the browser jar still reached every port.
- **BUG-0098 / PA-0099** (an https session reused over http): same *class* (a secret's
  send scope not bound at every send point); PA-0099 bound the **transport** floor to
  every send path and explicitly kept "other ports of the same host" as by design. This
  bug binds the **origin** at the same points.
- **BUG-0132 / PA-0132** (the browser login dropped the JS-set cookie): its fix made the
  cookie reach the requests senders, which widened the exposure; its review deferred
  origin scoping in prose.
- BUG-0081 / BUG-0092 / BUG-0097 (credential destinations): FR-SESS-12's destination
  rule for the *password*; unchanged here except its message (O12).
Result: a recurrence of BUG-0123's root cause (PA-0123), through a "stated exception"
that PA-0099 and PA-0132 each re-accepted.

## Prior-preventive-action failure analysis
**BUG-0123 / PA-0123.** PA-0123(2): "Scope is an origin … A host-only scope is a
stated exception (BUG-0050's external crawl), never a default; another loopback port is
another service." It did not prevent this because:
1. **Too narrow.** It was written about outbound *scope* (where any request may go) and
   enforced on the browser's scope predicate. A session's destination set is a
   different decision taken among already-in-scope requests, and PA-0123's wording did
   not name it, so its PA-0002 sweep did not visit the session carriers.
2. **The exception had no owner and no pin.** "Stated exception" made the host-level
   session rule legitimate in FR-SESS-13, BUG-0098 and FR-SESS-19 without a test that
   pinned its extent or a trigger to re-review it once PA-0123 narrowed the same class.
   BUG-0132's review re-deferred it in prose ("a separate follow-up") — the pattern
   PA-0054(3)/PA-0056(3) forbid for un-fixed instances.
3. **No single predicate.** PA-0003/PA-0087 ("one policy decision, one place") were not
   applied to "where may this session go": eight carriers compared hosts themselves, so
   narrowing one (the browser scope) left the others.
**PA-0099** (BUG-0098) bound the transport floor at every send point but carried the
host-level rule forward as by design; **PA-0132** (BUG-0132) widened what the session
carries without re-asking where it goes.

## Preventive action
**PA-0134** (strengthens PA-0123, PA-0099 and PA-0132; see `docs/PREVENTIVE_ACTIONS.md`):
1. Every secret-bearing artefact (cookie, token, Basic header, a browser's jar or
   storage state, a captured session) carries the set of **origins** it belongs to from
   its creation, and every send path checks membership through one predicate. A storage
   key (host, identity) indexes; it never authorises a send.
2. A "stated exception" to where a secret may go is pinned by a test asserting its exact
   extent, and a PA that narrows the same class (as PA-0123 did) re-reviews every
   exception of that class in the same change. A deferral of a security exception is
   never prose only.
3. Enforced by an AST guard over the session-carrying modules: no `==`/`!=` with a
   hostname (`.hostname`, `canonical_host(...)`) decides a send, except listed,
   reasoned allowances; proven on BUG-0134's own shapes (PA-0034(2))
   (`tests/test_session_origin_scope.py::test_no_session_send_decision_compares_hosts`).

### PA-0002 sweep (every site that applied session secrets by host)
Grepped `fuzzlab/` for `hostname`, `canonical_host`, `session_host`, `.apply(`,
`session_header`, `add_cookies`, `storage_state`, `extra_http_headers` and `"Cookie"`;
each site that carries a session, with its disposition (PA-0067(1): what the reader is
for):

| Site | What it decided by host | Disposition |
| --- | --- | --- |
| `session/manager.py` `prepare` | applied the session to any request on the host; a missing/invalid one logged in from the request's directory | **fixed** (O2/O3): origin membership; no login from another origin |
| `manager.ensure` | any base on the host could start a login | **fixed** (O3): `_check_base`, loud refusal with the remedy |
| `manager.authorize` | refused another host only | **fixed** (O4) |
| `manager.observe` | state by host: another app's login page was a logout | **fixed** (O4): by origin membership; listener gets the origin |
| `manager._navigate(session_host=)` / `verify_live` | any hop on the host was fetched with the session | **fixed** (O5): `session_origins` |
| `manager._spa_probe` / `_probe_fetch` | candidates and hops by host | **fixed** (O5) |
| `manager.is_auth_endpoint` / `_auth_endpoints` | path on any port | **fixed** (O9): origin + path; keyed by origin |
| `manager.session_header(s)` (`session print`, greybox) | any base on the host | **fixed** (O10): `_check_origin` |
| `manager.isolated_copy` | copies had the same host rule | **fixed** (O11): same origins, same checks |
| `manager.adopt` | adopted a session with no origin | **fixed** (O7): refused without origins |
| `manager._jar_cookies` | jar cookies matched by domain (port-agnostic) | **kept**: it selects which jar cookies the session carries; where they go is now `prepare`'s origin rule |
| `manager._login` handshake (`_discover_login_form`, `_post_credentials`, `_verify_authenticated`) | FR-SESS-12's destination rule admits an in-scope host on any port for the login itself; the login fetcher's jar (requests: port-agnostic) and a Basic/bearer header go along on such a hop | **residual, flagged**: the agreed spec keeps FR-SESS-12's login-time scope and adds the O12 warning; such a hop now warns with the `auth_origins` advice. Tightening the handshake is a reviewed follow-up (PA-0093(2)), not done silently here |
| `tools/browserauth.header_scope_for` | `canonical_host(url) == host` | **fixed** (O8): `state.origins` |
| `tools/navguard.make_route_handler` (authenticated context) | the context jar went with every in-scope request | **fixed** (O8): `cookie_scope` withholds it (request and hops) |
| `tools/navguard` WebSockets (`route_web_socket` → `connect_to_server`) | an in-scope socket is connected by the browser, which may attach its jar | **residual, stated**: in a loopback crawl scope is the exact origin, so no other port is in scope; only an external any-port crawl could open a socket to another port. Not in the agreed spec; flagged |
| `tools/spider._start_browser` / `_guard` | header scope by host | **fixed** (O8) |
| `tools/spider._isolated_submit` | the jar's cookies via `storage_state` to any in-scope action | **fixed** (O8 sweep): cookies dropped for another origin |
| `tools/spider._readopt_session` | re-adds the session's cookies to the jar | **covered**: the jar never leaves the origins (route) |
| `tools/fetcher.ContentFetcher` (auditor browser) | `browser_session` header scope | **covered**: `header_scope_for` now by origin; its scope is the base origin only, a subset of the session's origins, so no out-of-origin request is routed (no AUD change) |
| `tools/fetcher` / `blind_sqli_fuzzer` / static auditor requests paths | the seam | **covered** by `prepare` |
| `tools/probesender.SeamProbeSender._on_logout` (lane A) | `host != target host` | **fixed** (O9) |
| `probesender.SeamProbeSender._on_main_logout` (lane B) | `host != self._run_host` | **fixed** (O9) |
| `probesender` `_identity_for` / `_prg_session_gate` | `is_auth_endpoint` | **fixed** via O9 |
| `probesender.RequestsProbeSender` | no session | not affected |
| `greybox/greybox_cli._cookie_for` + `greybox/run.RequestsCorrelatingSender` | the cookie on every probe URL | **fixed** (O6) |
| `mutation/run.make_coverage_fn` | builds a `RequestsCorrelatingSender(cookie=…)` | **covered**: its only caller passes no cookie; a cookie without origins is now refused at construction (fail closed) |
| `proxy/session_capture.SessionCapture` | no origins | **fixed** (O7) |
| `tools/browserexec` (M6) | operator storage headers, no session | not affected |
| `labgen/*_oracle.py`, `labgen/identity_session.py` | a third-party tool's cookie for the one URL it is run against | not this class (no session manager state) |
| `session/browserlogin.filter_storage_state` | jar cookies by host | **kept**: scope filter of what is adopted; where it is sent is O8 |
