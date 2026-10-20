# Session Manager — Requirement Specification

Component code: **SESS** · Status: `[built; live validation + resume pending]` (Phase 1)
· Last updated: 2026-10-20

Related: `ARCHITECTURE.md` #3; `DECISIONS_AND_ROADMAP.md` (D3, D10, D12, D13);
`./change-control.md`.

## 1. Purpose
Keep every tool authenticated consistently **across many target labs**, so that
session expiry does not silently poison crawls, audits, fuzzing, and training
data. Shared by all tools; a hard dependency for external validation (D10).

## 2. Scope
- **In:** dynamic login/session **detection** per host; identities; per-host
  credentials; session state (cookies + tokens); validity checking;
  re-authentication; auth-endpoint exclusion.
- **Out:** attacking authentication (that is a testing target, handled by the
  tools, not by this component); hand-written per-host auth profiles/overrides
  (detection-only, D13).

## 3. Functional requirements
- **FR-SESS-1** Model multiple identities (at least `anonymous`, `user`,
  `admin`) **per host**, each with its own session state (cookie jar +
  headers/tokens) and connection pool.
- **FR-SESS-2** Expose `prepare(request, identity)`, `observe(request, response,
  identity)`, and `ensure(identity)`, resolved against the request's host.
  *(FR-SESS-20, CC-SESS-0023:)* the session is keyed by host but **sent by origin**:
  `prepare` and `observe` resolve it by the request's canonical origin.
- **FR-SESS-3 (login detection)** Detect a host's login dynamically: find the
  login form (a form containing an enabled password field), carry its other fields
  (e.g. a CSRF `user_token`, the submit button's `name=value`, a select's default)
  through by re-fetching the form immediately before submit (fresh, never cached),
  map the username/password fields, and submit the host's credentials. The body is
  serialised per FR-SESS-14. (D13)
- **FR-SESS-4 (session-credential detection)** Detect what the login response
  establishes and reuse it: `Set-Cookie` → session cookie; a token/JWT in a JSON
  body → `Authorization: Bearer` (read `exp` locally to refresh proactively); a
  `WWW-Authenticate` challenge → Basic/Bearer. (D13)
- **FR-SESS-5 (success/expiry detection)** Confirm login by differential behavior
  (a protected probe stops redirecting to login); detect logout/expiry from
  multiple signals ~~(401/403, redirect to the detected login, the login form
  reappearing, JWT `exp`)~~ *(amended CC-SESS-0029, FR-SESS-23, BUG-0533:)* -- a
  credentialed 401, a redirect to the detected login, the login form reappearing, JWT
  `exp` -- confirmed on the session's stable protected resource (FR-SESS-23); and
  re-authenticate under a single-flight lock, with loss-driven re-logins limited by a
  refilling budget: past it an identity with a resource is unknown and the run fails
  loudly, and an identity with none carries on until the budget refills. A 403 is a
  policy answer, never by itself a loss. Cap failed attempts then hard-fail.
- **FR-SESS-6 (fail loud)** When detection cannot parse a login (multi-step,
  CAPTCHA, an SPA login the browser fallback cannot find or confirm, FR-SESS-19), fail
  loudly with diagnostics (what was found, where it stopped) rather than silently
  proceeding unauthenticated; there is no hand-written override (D13).
- **FR-SESS-7** Auto-exclude auth endpoints (the detected login/logout,
  session-destroy) from fuzzing scope.
- **FR-SESS-8** Obtain credentials from the `core/` credential store **keyed by
  host** (OS keyring with an encrypted-file headless fallback and a gated lab-only
  env fallback, D12); never from the project store or the repo. The manager passes
  the credentials associated with the host it is authenticating to.
- **FR-SESS-9** Persist non-secret session state (host, identity, auth status,
  timestamps) to the store so a crashed run resumes; never persist live
  cookies/tokens/credentials in cleartext.
- **FR-SESS-10** Be usable standalone (print a ready-to-use cookie/header/token
  for a given identity on a given host). *(CC-SESS-0022, BUG-0132:)* `fuzzlab session
  print` prints **every** header the session sends (`SessionManager.session_headers`:
  `Cookie` and `Authorization` together for a browser login); `session_header` keeps
  returning one (the Cookie first).
- **FR-SESS-11** `[planned, post-Phase 6]` **Adopt a captured manual session.**
  For hosts whose login detection can't parse (the FR-SESS-6 fail-loud cases),
  accept an authenticated session captured by the proxy from a manual browser login
  (FR-PROXY-9) and use it as the live session state for `(host, identity)` — no
  per-host config. On expiry of an interactive login, prompt for re-capture rather
  than attempting an automated re-login. Depends on the proxy (component #11).

- **FR-SESS-12 (credential destinations, CC-SESS-0011, BUG-0081; amended CC-SESS-0012,
  BUG-0092)**
  - **Transport deny, before every allow (CC-SESS-0012).** The destination's scheme must
    be `http` or `https`. It must be `https` whenever the floor is https, that is when
    any of these was https:
    - the operator's `base_url`;
    - any hop of the discovery redirect chain;
    - the login page;
    - the URL a POST redirect comes from.

    No allow rule overrides it, `auth_origins` included. A login page reached by a
    downgrade is refused before any POST. `FetchResponse.url` / `.history_schemes`
    report the final URL and every hop; a fetcher that does not report them falls back
    to `base_url`'s scheme. ~~Host scope stays host-level *for the login handshake*: an
    in-scope other port over the same or an upgraded scheme is allowed as a login
    destination, and `auth_origins` is the origin-precise alternative.~~ *(Superseded by
    FR-SESS-20, CC-SESS-0023, BUG-0134: the session itself is sent only to its origins;
    and since review round 1 (R3) the login handshake too is origin-anchored: an
    in-scope other port is no longer a login destination, only the base origin, its
    same-host https upgrade at the default or same port, and `auth_origins` /
    `--auth-origin`.)*
  - **Where credentials may go.** They are POSTed only to the login page's own
    canonical origin, that host upgraded to https, ~~an in-scope host,~~ or an origin in
    `SessionManager(auth_origins=[...])` *(FR-SESS-20 R3: the in-scope-host clause is
    superseded; the upgrade only at the default or the same port)*. Anything else fails loudly, naming the
    option. *(FR-SESS-20, O12/R5:)* the refusal names the refused origin and the flag
    that authorises it (`--auth-origin <origin>`).
  - **No automatic redirects.** The credential POST never follows them. 301/302/303
    are followed by hand as a GET, only to an allowed origin; 307/308 never. *(CC-SESS-0020,
    BUG-0123:)* every later hop of that chain is walked the same way, each checked by
    the navigation predicate (destination and destructive URLs) before it is fetched;
    a refused hop leaves the POST's own response to be judged.
  - **HTTP Basic.** A base URL answering `401` + `WWW-Authenticate: Basic` (no form)
    authenticates with the Basic header, sent only to that in-scope base URL.
- **FR-SESS-13 (session transport binding, CC-SESS-0013, BUG-0097/0098)**
  - **Navigation.** Login discovery and the post-login probe never let the fetcher
    follow redirects. Each hop (at most 5) is authorised **before** it is fetched, by
    the same predicate as credential destinations. A fetcher that cannot refuse
    redirects must report the URL it was asked for, or discovery refuses.
  - **The anchor is operator input only:** the base URL's origin, its https upgrade,
    ~~in-scope hosts (any port: host-level scope, D12),~~ and `auth_origins`, which is
    the origin-precise alternative *(FR-SESS-20 R3: in-scope hosts superseded; the
    upgrade at the default or the same port only)*. A response-derived page is never an
    anchor.
  - **`SessionState.secure_only`.** Set when the login, a captured session or the stored
    `login_url` was https. An unknown legacy `login_url` fails closed.
  - **Where it is enforced.** An https session's cookies, tokens and Basic header are
    never sent over plain http:
    - `prepare`;
    - `authorize`, after a plugin retarget, which also refuses another host (and, since
      FR-SESS-20, an origin outside the session's);
    - `session_header`;
    - greybox's sender.
  - ~~**Per host, by design (D12).** A session is keyed per host, so other ports of the
    same host are allowed.~~ **Superseded by FR-SESS-20 (CC-SESS-0023, BUG-0134):** the
    session is still *keyed* per host (D12), but *sent* only to its own origins; another
    port of the same host is another app. Cookie Path is not enforced: a stated
    residual, since the same origin learns nothing new.
  - **No destructive hop** *(CC-SESS-0015, BUG-0111).* Discovery and the post-login
    probe never fetch a URL `core.urls.destructive_reason` flags (a redirect to
    `logout`, `reset`, ...), other than the operator's own base URL.
- **FR-SESS-21 (JSON login from the page's own script, CC-SESS-0026)**
  - **When.** Detection only (D13): the login form `detect.find_login_form` found has no
    `action` attribute, and one inline `<script>` of the page that builds a JSON body
    (`JSON.stringify` or `application/json` in that script) makes exactly one POST to a
    URL literal whose last path segment is a login word (`_LOGIN_SEGMENTS`): an
    `XMLHttpRequest.open('POST', …)`, a `fetch(…, {method: 'POST'})`, or a client
    library's `.post(…)` (`detect.json_login_target`, SP-44). A URL built at run time,
    a linked script, or two candidate URLs: no JSON login; the form is submitted as
    before. A protocol-relative URL resolves against the page.
  - **How.** The form's entries (`LoginForm.fill`: credentials in place) as one JSON
    object, POSTed with `Content-Type: application/json` and redirects walked by hand
    (`_post_credentials`). The URL must pass `_credential_destination_ok` like a form
    action: a login API on another origin needs `--auth-origin` (the refusal names it,
    and nothing is sent).
  - **Success (FR-SESS-5's differential, BUG-0008).** The same body with a wrong
    password (`WRONG_SUFFIX` appended) goes first, on a fetcher of its own. The login
    holds only when the real one answers 2xx **and** carries a credential the wrong one
    did not: a cookie its answer set that the wrong attempt's did not set (the session
    then sends the jar's cookies), or a token in its JSON answer (`find_token_in_json`)
    that the wrong answer lacks (a bearer). A non-2xx answer is a rejected login; a 2xx
    with no such credential fails loudly ("no credential that a wrong password does not
    also get"). Then the common follow-up probe (`_verify_authenticated`), auth-endpoint
    recording and persistence (`_established`, shared with the form login). The login
    URL is an auth endpoint (FR-SESS-7).
  - **Residuals (stated).** Each login costs one failed attempt (an app that locks an
    account after a few failures sees one per login and re-login). A script that builds
    the body from anything but the form's controls (renamed keys, nesting, an extra
    field) is not reproduced; neither is a linked script's login.
- **FR-SESS-22 (SP-16 login facts for one exchange, CC-SESS-0028, BUG-0529)**
  `session.detect.login_facts(url, headers=None, *, response_url=None, login_url=None,
  entry_names=())` -> `LoginFacts`, the facts SP-56 (FR-CORE-507) needs:
  - **`credential_submission`:** the request goes to the session's own `login_url` (when
    known) or an SP-16 login URL (`looks_like_login_url`); or its path names account
    creation or a password reset or change (`CREDENTIAL_PATH_TOKENS`: register,
    registration, signup, "sign up", password, passwd, reset -- deliberately narrower
    than the login window's `browserlogin.account_endpoint_reason`, which also names a
    user or account collection and a bare `change`); or one of `entry_names` is a
    credential name (`core.redaction.is_credential_name`; strings only -- a JSON leaf by
    its `jsonbody.display_name`). Its refusal is that endpoint's answer, never a lost
    session.
  - **`redirect_to_login`:** `Location` in any case, resolved against the answer's own
    URL (`response_url`, a PRG follow-up's) or else `url`, judged by `redirect_is_logout`
    with the known `login_url`.
  - **`account_submission`:** the path names account creation or a reset and is not a
    login URL; its redirect to the login page is its success (the contract runner's
    setup steps, FR-FUZZ-52).
  - Total: odd input reads as "no". The contract runner, the oracle, the blind-SQLi
    builder take these facts from it alone (PA-0003).
  - Residuals: a credential check none of the rules names (`/rest/2fa/verify` with a
    `code` field) reads its 401 as a refused credential (fail closed); a field whose
    name carries the `pass` token (`pass_count`) makes its request a credential
    submission (a narrow fail-open).
  - Enforced by: `tests/test_session_detect.py::test_login_facts_names_every_credential_submission`,
    `tests/test_session_detect.py::test_login_facts_reads_location_in_any_case_against_the_follow_ups_url`,
    `tests/test_session_detect.py::test_login_facts_uses_the_sessions_known_login_url`,
    `tests/test_session_detect.py::test_login_facts_names_an_account_submission_apart_from_a_login`,
    `tests/test_session_detect.py::test_login_facts_is_total`.
- **FR-SESS-23 (a forbidden answer is never, by itself, a lost session, CC-SESS-0029,
  BUG-0533; DRAFT-AU-SESS403 revision 3, decisions D and D′, review round 4)**
  - **One loss predicate.** `detect.detect_logout(status, headers, body, login_url=None,
    page_url=None, content_check=True, login_fields=None, *, credentialed=True,
    credential_submission=False)` names a **loss shape** in two cases only:
    - an auth failure SP-56 (FR-CORE-507) gives only because the request carried the
      session (a credentialed 401; a redirect to this session's login page or an
      anchored login URL, FR-SESS-18) -- never a 407, an auth failure to anyone;
    - this session's login form at 200, to a credentialed request that is not a
      submission (FR-SESS-15's form rules; never for Basic).

    No classified status is written as a literal. `health_verdict` decides through the
    same predicate, and only `observe` and `health_verdict` call it (T19's guard).
    `detect.request_entry_names(url, body, content_type)` gives a request's entry
    names (its query's, a urlencoded body's, a JSON body's leaves by
    `jsonbody.display_name`; at most 64 KiB; multipart not read; total).
  - **Classification first** (`observe`). A throttle, gateway, 407, incomplete or other
    application answer never changes the session (counted by class).
    - With a stable protected resource, three answers trigger the health check: a loss
      shape; a credentialed policy block (403, 451); a credential submission's loss
      shape (`login_facts` with `request_entry_names`).
    - Without one, only a loss shape that is not a submission counts, as an
      **unconfirmed loss**. Nothing else does.
  - **Generations.** Each login and `adopt` gives the state the next
    `SessionState.generation`, numbered before it is installed. `prepare` records it on
    the request (`core.http.Request.session_generation`, FR-CORE-6) from the state it
    applied, never re-read. A signal from another generation is ignored; an unstated one
    is read as the current generation. A signal on an invalid or paused generation is
    ignored.
  - **The health check** (`check_health`) is one GET of the resource, carrying the
    session's own material and sent with the seam's headers (`requests` per hop, no
    browser header set), with a 15 s timeout per hop (a timeout or other transport error
    is no response: inconclusive).
    - **The walk.** Redirects are walked by hand inside the session's origins and the
      transport floor (`_navigate(stop_at=)`), stopping at a login redirect (a login on
      another origin is judged at its hop, never fetched). An unapproved hop that is not
      one raises at once (fail fast, never a pause).
    - **The verdict** (`health_verdict`, public and total over any state), first match:
      **lost** for a stop at a login redirect; **inconclusive** for an answer SP-56
      classes incomplete, throttle-or-unavailable or gateway, or a 407 -- before any
      refusal is matched; **lost** for a loss shape or the resource's recorded refusal
      (status or body); **live** for any other 2xx; **inconclusive** otherwise.
    - **Cookies.** A live answer's rotated value of one of the session's own cookies is
      adopted.
    - **Single flight, the cover, compare-and-set.** Single flight per (host,
      identity), the verdict recorded before the lock is released. A live verdict
      covers a signal only when the signal was **seen before its GET was sent** (a
      sequence counter, never a clock). After the GET, the verdict counts only for the
      state object it judged, if that object is still the current one and of the
      generation judged; otherwise it is stale and records nothing (no live mark, no
      pause, no `_mark_lost`, no row, no listener).
  - **The cache.** For `health_ttl_s` (30 s), a live verdict also covers later loss
    shapes of the same generation and URL key, except from a request carrying a header
    the session does not own (`Content-Type` and `Content-Length` excepted); and it
    covers a **policy block** (a 403 or 451 that is no loss shape) of the same
    generation **whatever its URL or headers** (review round 5: a WAF that blocks every
    path or header payload costs one check per window, not one per path). Only the
    latest live generation's entries are kept (dict lookups). Neither a pause re-check
    nor `verify_live` reads it.
  - **The stable protected resource** is recorded at login by one owner (`_spa_probe`):
    a candidate whose credentialed answer is live on the stopping walk and whose
    anonymous and corrupted answers agree as a refusal -- both lost; or the same status
    `admitted_refusal` admits (a non-2xx below 500 that SP-56 classes as the
    application's answer or a policy block, never a throttle, gateway or 407), recorded
    as `probe_refusal_status`; or the same stable body apart from the credentialed one,
    recorded as its sha256.
    - Candidates: a browser login's post-click GETs (FR-SESS-19); the operator's base
      URL (every HTTP session kind, Basic included); the post-login landing.
    - `adopt(state, *, protected_probe=None, refusal_status=None)` may give one, with a
      refusal status held to the same admission (refused loudly otherwise).
  - **Lost.** `_mark_lost(state, generation)` is the only writer of `valid = False`.
    Under the manager's observe lock it compare-and-sets on the current state and
    generation, marks the next login loss-driven, and persists the row **inside the
    same critical section**. Every install -- a login's (`ensure`), `adopt`'s -- numbers
    the state, installs it and persists its row under that same lock (`_install`), so a
    replaced state's row never lands after its replacement's.
  - **Listeners** are told only when the loss was seen on a send (FR-SESS-16).
  - **Pause.** An inconclusive check changes nothing else.
    - **The wait.** The identity is paused for that generation (5 s doubling to 60 s;
      `Retry-After` up to 60 s; one log line, and a `pauses` count). `prepare` waits it
      out on the injectable `sleep`, holding no lock, then checks again: live, send;
      lost, `_mark_lost` (no listener) and a re-login under the bucket; inconclusive,
      pause again. A pause of another generation never pauses the current one.
    - **The bounds.** Past `max_pause_s` (300 s) or the run's `pause_budget_s` (600 s),
      `prepare` raises `SessionHealthUnknown` (a copy: `IsolatedHealthUnknown`), sticky:
      every later `prepare` raises at once, with no clock and no network, until a check
      gives a definite answer.
    - **Whose budget.** One budget per run, shared by the run's manager and its isolated
      copies (with the run's credential-POST count). A peer identity has its own manager
      and its own budget.
  - **Re-login budget.** Loss-driven re-logins draw on a token bucket per (host,
    identity) per manager: a burst of 5, refilled at 1 per 120 s, drawn under the login
    lock in the critical section that logs in. The first login and a JWT refresh do not
    draw.
    - With the bucket empty, an identity **with** a stable protected resource waits for
      a token within the pause bound and the budget, holding no lock; otherwise it goes
      sticky unknown.
    - With the bucket empty, an identity **without** one (decision D) skips the
      re-login and sends at once on the session it has, still marked lost: no wait, no
      `SessionHealthUnknown`, no abort. It logs in again when a token has refilled.
      One warning names the identity (never a credential) when it enters that window,
      once per window.
      **Every request so sent is marked** (`Request.session_lost`, FR-CORE-6;
      decision D′), and the oracle reads any answer to it as not comparable
      (FR-FUZZ-65): such a probe never confirms, never negates and never passes.
    - Credential POSTs are counted per account (`submitted`, a JSON login's `control`;
      a browser login's submission counts as `submitted`), the run's isolated copies
      included.
  - **`verify_live`** is a fresh check (never the cache): live True; lost False and
    invalid (no listener); an unapproved hop raises; inconclusive, it waits on its own,
    bounded by `max_pause_s` per call and its own run budget (never `prepare`'s, never
    the identity's pause), checks again, and still inconclusive returns True, logged
    once; a session replaced while it checked returns True, logged. It never records a
    pause, and never sets or clears a sticky unknown on an inconclusive check (a live or
    lost answer clears one).
  - **`_verify_authenticated`** (a login's follow-up) decides through `health_verdict`:
    lost or a policy block fails the login; anything else accepts it (R8).
  - **Reported.** `health_report()` gives counts per class and outcome (signals,
    checks, covered, cached, stale, pauses, unconfirmed, re-logins drawn and skipped),
    `prepare`'s and `verify_live`'s waited seconds, and credential POSTs per account. It
    holds no URL, header value or body.
  - **Residuals** (DRAFT-AU-SESS403 §8): R1 (a 403 on expiry with no resource), R2 (no
    resource; a re-login during a throttle records none), R3 (the TTL; a policy block is
    covered whatever its URL), R4 (a moved, broken or throttled resource, or one that
    turns 403 for a policy reason), R5 (the health GET is untraced), R6 (a comparison
    that straddles a re-login, pinned by a strict xfail), R7 (a 200 login page is
    `application` to the oracle outside D's window), R8, R9 (the contract runner,
    disco, greybox's static header), R10-R15, R16 (D's window: answers are not
    comparable, D′, at every consumer), R17 (Laravel's 419 after an expiry is an
    application answer), R18 (RFC 6750's `401 insufficient_scope` is still an
    unconfirmed loss without a resource), R19 (concurrent pause waiters each send a
    re-check and each charge the budget).
  - Enforced by: `tests/test_session_forbidden_answers.py` (91 tests: 90 that pass --
    the classification, the cover, the cache (policy blocks per window), both
    compare-and-sets, the install atomicity, the resource rules, the pause, sticky
    unknown, both budgets, D and its log line, D′ at the oracle (the peer included), the
    live filter and the blind-SQLi builder, T19's whole-package guard -- and R6's
    strict-xfail pin), `tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner`.
    Every test but the pin fails against a named revert of the implementation
    (DRAFT-AU-SESS403 §13).
- **FR-SESS-20 (origin-scoped sessions, CC-SESS-0023, BUG-0134; design Revision 2,
  O1-O13; review rounds 1-2, R1-R9, T1-T6)**
  - **Origins (O1).** `SessionState.origins` is a set of canonical origins
    (`core.urls.canonical_origin`: scheme, host, port; loopback aliases one origin):
    the base URL the login ran from, the login page, the credential destination and the
    operator's `auth_origins`, from one function (`manager.session_origins`). A Basic
    session's is the base URL's. **In memory only:** never persisted, so a resumed
    record never applies a session by itself. Not secret (shown in `redacted()`).
  - **prepare (O2).** The session is applied only when the request's canonical origin
    is one of them. A request to an in-scope host but another origin goes out
    **anonymously** (that app's anonymous visitor), never triggers a login there, is
    logged once per (origin, identity) and counted (`out_of_origin_sends`, reported as
    `session_out_of_origin` by the crawl, auto and greybox summaries). *(R6, T4:)*
    `prepare` records its decision on the request it was given, in the declared field
    `core.http.Request.session_decision` (CC-CORE-0054; `"anonymous (out of origin)"`);
    the seam sender copies it into `Probe.session` after the send, never recomputing it; the oracle copies that into
    `Verdict.evidence["session"]`, greybox into the attempt's features.
    *(R9:)* an https-only session's **plain-http** request to another port of its host
    is refused loudly (`SessionAuthError`, BUG-0098's floor runs before the origin
    rule), never sent anonymously: it fails closed.
  - **ensure (O3).** A login runs only from an operator base or a base whose origin is
    one of the existing `(host, identity)` session's origins (or, before any session,
    the operator base's origin); never from a request's directory on another origin.
    Otherwise `SessionAuthError` names the remedy: a distinct identity name per app
    (D38: refuse rather than warn). An isolated copy raises it as `IsolatedLoginFailed`.
  - **authorize / observe (O4).** A plugin retarget that carries the session to an
    origin outside the session's (another port included) is refused, as another host
    is. *Carries* (`_carries`; R7, narrowed by T2): a secret-looking value -- any
    Authorization value or its token, a cookie value `looks_like_identifier` holds for
    or of at least 8 characters -- contained anywhere in the request's headers (an
    edited `sid=<v>'OR1` still counts); any other cookie only as its exact `name=value`
    pair in `Cookie` (a short plain value like `en` or `0` is ordinary header text); an anonymous out-of-origin request may
    still be edited on its own origin. `observe` finds the session by origin
    membership, so another app's login page never logs it out.
  - **verify_live and the probe differential (O5).** `_navigate(session_origins=)`
    refuses a hop outside the origins before it is fetched; a probe candidate on another
    origin is never fetched; both fail closed.
  - **greybox (O6).** `_cookie_for` returns the session's origins and
    `RequestsCorrelatingSender(cookie_origins=)` attaches the cookie only to a probe on
    one of them (a cookie without origins is refused at construction).
  - **Proxy adoption (O7).** `SessionCapture` records the canonical origins of the
    observed URLs on its host; `adopt` refuses a session with none.
  - **Browser (O8; R1/R2).** `browserauth.header_scope_for` admits an in-scope URL on
    one of the session's origins (and the https floor). Browser cookies are
    port-agnostic (RFC 6265 §8.5), so in an authenticated context (`cookie_scope`) the
    guarded route, for an in-scope origin outside the session's:
    - **aborts every document** (a navigation, top-level or frame, and a redirect landing
      there) with ERR_ABORTED (`"aborted"`, T1: the page stays where it is, no error page)
      and **every WebSocket**: a document loaded there would run that app's script with
      the context's cookies and `localStorage` (R1, review A-M1, seen live);
    - fetches every other request there (and every hop) through **one cookie-less
      request context per guard** (`isolated_request`, a `playwright.request.new_context()`
      with no storage, made once when the guard is built and kept for its life; every
      fetch carries an explicit empty `Cookie`, so that context's own jar is never sent:
      review round 3, V1), never `route.fetch` or the
      context's client, and fulfils it with `Set-Cookie` removed, so that origin can
      neither read nor write the jar (R2, review A-M2, seen live);
    - the crawl records such a page as skipped, with its kind ("crawl that origin
      separately, or --auth-origin"); a page navigation whose own target or redirect
      landing was withheld, or whose main frame committed on an in-scope origin outside
      the session's, extracts nothing, while a script-initiated navigation away leaves
      the page extracted (T1); an out-of-scope commit is BUG-0123's scope abort, counted
      under its own reason, never this one (V2); the spider's `_isolated_submit` drops the jar's
      cookies for such an action (FR-CRAWL-14).
  - **Listeners and auth endpoints (O9).** FR-SESS-16's listener gets the logout's
    origin; lane A's header breaker and lane B's single-session breaker compare it with
    the run's session's origins. `is_auth_endpoint` compares origin and path.
  - **session_header(s) / `session print` (O10)** refuse a base URL whose origin is not
    one of the session's.
  - **Isolated copies (O11)** compute the same origins from the same inputs and
    enforce them.
  - **The login handshake (R3).** A login may go only to its anchors
    (`_login_anchors`): the base URL's origin, its https upgrade on the same host at the
    default or the same port, and `auth_origins`. An in-scope host on another port is no
    longer one (it widened O1's origins too). `_verify_authenticated` carries the
    session's header only to the session's origins; a post-login redirect elsewhere is
    not followed and warns.
  - **Advice (O12; R5).** Every refusal and warning names the origin and the flag:
    `--auth-origin ORIGIN` (repeatable) on `crawl`, `auto`, `session print` and
    `greybox-run` authorises an origin as both a credential destination and a session
    origin. Each value must be a bare http(s) origin (no user, path, query or fragment)
    whose host is in the CLI's scope, compared canonically (T5: `localhost` ≡
    `127.0.0.1`), else a usage error before any side effect
    (`manager.parse_auth_origins`). `adopt` unions the manager's `auth_origins` into a
    captured session's origins.
  - **Residuals (O13, stated; each pinned by a test, BUG-0134).** The key stays
    `(host, identity)` (credentials and the store's session rows are host-keyed;
    re-keying would orphan stored credentials): two apps on one host need distinct
    identity names (CLI help; refused, never shared). The login's https upgrade on the
    same host (default or same port) is a login anchor. Anonymous static jars
    (`requests.Session`) are port-agnostic but never hold session material. *(The login
    handshake's any-port scope, the WebSocket residual and the missing CLI flag of the
    first fix are superseded by R1, R3 and R5.)*
- **FR-SESS-19 (browser login for single-page apps, CC-SESS-0021)**
  - **When.** Only as a fallback (detection only, D13): `_login` found no
    server-rendered login form and no Basic challenge, and the manager may use a
    browser (`SessionManager(browser_login=...)`; default on when the manager's fetches
    go to the network, i.e. the default fetcher; off when a fetcher double stands in;
    copied to isolated copies). Without Playwright or a launchable Chromium the login
    fails loudly naming the missing browser.
  - **Where it runs (`session/browserlogin.py`).** On a dedicated worker thread (no
    event loop: a sync Playwright never nests inside a crawl's), under the
    per-(host, identity) login lock, joined with a deadline (120 s). *(Review round 1,
    B-M1/B-M2:)* at the deadline the login is **cancelled**: a shared event makes the
    gate refuse every request and the worker stop at its next checkpoint (before each
    navigation, each fill and the click); its `finally` still closes the context,
    browser and driver, waited for up to 30 s more, else the error says "browser login
    abandoned; cleanup pending". While a worker for the same (base URL, identity) is
    alive, a new browser login refuses ("still finishing"). Its own browser
    (the one launch helper, `navguard.chromium_launch_kwargs` over
    `browser_launch_args(login scope)`) and its own context (service workers blocked);
    no passive capture, no spider-DB writer, no HAR, no trace. The context is closed
    (`navguard.release` first) right after its `storage_state()` is captured, before
    the manager's differential and before any crawl context opens. Playwright's API log
    is off: the driver starts without `DEBUG` / `PWDEBUG`; `DEBUGP` set refuses the
    login.
  - **The login scope and window.** The route's and WebSockets' scope is the base
    URL's origin plus the operator's `auth_origins`. From the first fill until the
    context closes (the window) every request, of any method or content, must also pass
    `_credential_destination_ok` (transport deny first); WebSockets connect only if they
    pass it. The password detector (raw, percent, form `+`, JSON-escaped, base64; in the
    URL, headers and body) only identifies the login request (the first in-scope
    POST/PUT carrying it after the click). Every write (POST, PUT, PATCH, DELETE) in the
    window to an account endpoint (path tokens register, sign-up, password, reset,
    change; users / accounts without a login token) is aborted before it is sent,
    whatever its body (review round 1, A-S1: a client-side hashed password included),
    and again on a 307/308 hop that keeps the body. Aborted-request logs name the host
    only. *(CC-SESS-0023 amendment, BUG-0136 review X3:)* a refused submission leaves
    the login page alive (an aborted navigation keeps the document, BUG-0136; a refused
    fetch never replaced it), so when the click produced no login request and something
    was refused in the window, the password field is cleared before the context is torn
    down. The clear is in place and never waits (`page.evaluate`, clear if present;
    BUG-0137 review Z5): an app that removed the field costs nothing.
    *(CC-SESS-0024, BUG-0138:)* the base page and each login route are loaded through
    `navguard.navigate` (the commit, then a bounded load). A page whose script
    navigates to a refused URL while it is parsed is never waited out: with no form on
    it, the login fails loudly, and fast.
  - **The form.** On the base page, then on SPA routes (from the app's own scripts and
    links, hash or history mode) and same-origin links whose last segment is a login
    word (`detect._LOGIN_SEGMENTS`, whole segment), at most 5: the first rendered form
    (`spa.FORMS_JS`) with exactly one enabled password control that is login-shaped
    (`store_adapter.login_shaped`), has no account word (register, sign up, create,
    join, enroll, new, forgot, recover, reset, change, repeat, confirm, retype, security
    question/answer, OTP) on its route, button text or aria-label, action or control
    names, is not a credential-change form (`store_adapter.credential_change_reason`)
    and passes `spa.form_refusal`. The username goes into the one user field
    (`_USERNAME_HINT` or `type=email`, else the only one: BUG-0121 owns the hint); the
    password only into the password control, from the credential store, never logged.
    One click (`spa.click_vetted`: covered -> Escape -> dispatch, labels re-read),
    never retried within an attempt. After a 2xx login answer the page is settled until
    it is quiet **and** a probe candidate has been seen, within the settle budget (5 s),
    so an app slow to start its follow-up requests is not cut off by a quiet gap.
    Quiet never waits for a long-lived request (a long-poll, an event stream;
    `netquiet.Inflight`, SP-40, CC-SESS-0025).
  - **The credential and success.** `detect.detect_session_credential` on the login
    request's own response (a cookie that response set, else a token in its JSON body,
    `exp` read for refresh); a non-2xx answer is a rejected login. Success is FR-SESS-5's
    positive differential on a **protected probe**: an in-scope GET XHR the app made
    after the click (scope- and destructive-checked, 2xx in the browser, no password in
    its URL) that answers 2xx when replayed with the credential, and whose answers with
    **no** credential and with a **corrupted** one (review round 1, A-M1: a bearer with
    its last character flipped in its high bits, a cookie with a random value under the
    same name) agree with each other and not with the credentialed one: the same
    non-2xx, non-5xx status, or the same body, stable over two fetches each, that
    differs from the (stable) credentialed body. So an endpoint that reacts to the mere
    presence of a header or cookie (an echo, a header-keyed cache) never confirms. The
    probe (and the corrupted credential's body sha256 when that was 2xx) is kept in
    memory on the `SessionState`; `verify_live` re-fetches it (2xx, and not the
    corrupted-credential body), so a revoked token reads as lost even when the app
    answers it with a 2xx error body. *(CC-SESS-0029, FR-SESS-23:)* the probe is chosen
    by the one owner of "a stable protected resource" (`_spa_probe`, which every HTTP
    login's rules 2 and 3 share): the credentialed answer must be live by
    `health_verdict` on the walk that stops at a login redirect, and an agreeing
    non-2xx status counts only when `admitted_refusal` admits it (it is recorded as
    `probe_refusal_status`); the health check reads it through `health_verdict`. The login request URL and `logout` are auth
    endpoints (FR-SESS-7); the SPA shell is not.
  - **The browser's cookies go with the session (CC-SESS-0022, BUG-0132).** The
    session's cookies are the detected credential's **plus** the browser jar's cookies
    from the captured `storage_state` (after `drop_secret_values` and
    `filter_storage_state`) whose domain matches the session's host (loopback aliases
    one host), unexpired, and not `secure` unless the session is https-only
    (`manager._jar_cookies`); the detected credential wins a name clash. So a cookie the
    app's own JS sets after the login (Juice Shop's `token`, read by its server-rendered
    `/profile`) reaches the requests-based senders through the one cookie path
    (`apply` / `prepare`: the session's host only, its transport floor). Their names are
    kept in memory (`SessionState.browser_cookies`). The differential and `verify_live`
    replay the cookies with the bearer; the corrupted arm gives a cookie equal to the
    bearer token the same corrupted token, every other credential cookie (one the login
    response set, or an identifier-like jar cookie) a random value, and keeps an ambient
    jar cookie (a short non-identifier value such as a language choice) as it is.
    Re-login and isolated copies go through the same path. *(Review of CC-SESS-0022:)*
    which cookies are credentials is one predicate, `manager.credential_cookie`, used
    by the corrupted arm and the crawler's check (FR-CRAWL-14). These are credentials:
    every login-response cookie; a jar cookie equal to a detected token; a jar cookie
    that `_identifier_like` holds for. Only a short, plain jar cookie is ambient. The
    anonymous arm carries the ambient jar cookies too, so it differs from the corrupted
    arm only by the credential (reviewer A-S1). An IP host takes only cookies for its
    own address, never a parent domain's (A-N2).
  - **What is kept.** `SessionState.browser_state` = the login context's
    `storage_state()` (cookies and per-origin localStorage) without any entry whose
    name or value carries the password (review round 1, A-M2), then filtered to the
    login scope, in memory only (never persisted, never in repr, not compared).
    `SessionState`'s cookies, headers, browser state and probe are `repr=False`. The
    login URL is kept without its query or fragment (and the login refuses if its path
    carries the password); `non_secret_state` persists `login_url` / `logout_url`
    without query or fragment for every login.
  - **Attempts.** Each browser login is one attempt toward `max_reauth` / `_failures`
    and an isolated copy's `max_logins`; a wrong password stops at the cap.
  - **Residuals (stated).** JWT sessions are stateless: an isolated copy's distinct
    token is the same account server-side (FR-FUZZ-44's isolation is weaker there);
    each isolated copy performs its own browser login. A login whose API lives on
    another origin needs that origin in `auth_origins`. An app that makes no
    credential-dependent GET after its login cannot be confirmed (fails loudly).
    Username detection depends on `_USERNAME_HINT` (BUG-0121). Juice Shop itself has
    not been exercised here (offline fixture only). ~~*(CC-SESS-0022 review:)* the jar
    cookies and the bearer reach any port on the session's host, per PA-0123's stated
    host-level exception (FR-SESS-12/13); origin-scoped sessions are a separate
    follow-up (reviewer A).~~ **Superseded by FR-SESS-20 (CC-SESS-0023, BUG-0134):** the
    jar cookies and the bearer go only to the session's origins (the base URL's and the
    login request's, plus `auth_origins`). A jar cookie's `path` is not kept: a
    `path=/admin` cookie is sent origin-wide (A-N2).
- **FR-SESS-18 (logout by redirect, CC-SESS-0019, BUG-0122)**
  - A redirect is a logout only when its target, resolved against the page, is either:
    - the session's own login URL: same host and path, an http→https upgrade on
      default ports allowed, and `login_url`'s query parameters present with their
      values;
    - an anchored login URL (http/https only): the last non-empty path segment
      (lower-cased, extension stripped) is a login word, or `session(s)/new`, or a
      front controller's routing parameter names one; *only when no `login_url` is
      known*, also a segment whose final name token is a login word (`wp-login`).
  - Never a substring test (PA-0122).
  - Only one hop is judged.
  - **Residuals:**
    - privilege-gated redirects to the real login page still read as a logout
      ~~;~~ *(amended CC-SESS-0029, FR-SESS-23:)* only as a suspected loss: confirmed
      live on the stable protected resource when there is one, an unconfirmed loss
      (bounded by the re-login budget, then D) when there is none;
    - without a known `login_url`, an app page whose name ends in a login token
      (`xss_login.php`) still reads as a login URL (fails safe);
    - the fallback misses `/auth`, `/sso`, IdP redirects and unlisted routing
      parameters.
- **FR-SESS-17 (isolated session copies, CC-SESS-0018)**
  - **`isolated_copy(identity, *, ordinal, max_logins=3)`** returns a throwaway manager
    for probing an in-app login form (FR-FUZZ-44): its own login, so its own
    server-side session. It is built through `__init__` and shares no mutable state;
    it shares the credential store and fetch factory, and copies scope, auth origins
    and the operator's bases. It has no store (never persisted). It answers only to
    its label `<identity>#isolated:<n>` (also its `flow.identity`) and refuses every
    other identity; it never adopts a captured session.
  - **Login cap.** `max_logins` login attempts per host/identity, then
    `LoginCapReached`. A run's manager has no cap (default None).
  - **Distinctness (distinctness-specific policy).** Every copy login is checked
    against the run's session and every other live copy (`distinctness_problem`).
    Basic is distinct. Otherwise the new state must carry a credential and differ in
    at least one value, and no credential with the same name may have an equal value
    that is identifier-like: a sensitive name, `core.redaction.looks_like_identifier`
    (FR-CORE-30), **or at least 16 characters** (`DISTINCT_MIN_LEN`, local to this
    check: a false "not distinct" only costs an anonymous fallback). Failure raises
    `SessionIsolationError`, naming credentials, never values.
  - **Errors.** A copy reports any failure to obtain a usable session as
    `IsolatedLoginFailed` (a `SessionAuthError`); a transport refusal stays a plain
    `SessionAuthError`.
  - **`verify_live(host, identity, base_url)`** re-checks the run's session with one
    fresh-fetcher walk of the operator's base carrying its cookies; on failure it marks
    the state invalid and persists that, without telling listeners. *(Amended
    CC-SESS-0029:)* it is FR-SESS-23's fresh health check of the stable protected
    resource (else the base): live True, lost False, an unapproved hop raises, an
    inconclusive answer waits on its own bounded budget and then reads live, and a
    session replaced while it checked reads live. The session goes
    only to its own origins *(FR-SESS-20; before: its own host)*: a hop to any other
    origin, another port of the same host included, is never fetched and raises
    `SessionAuthError` ("cannot verify"), as an unapproved hop does. A copy's session
    gets the same origins as the run's (O11).
  - **Reasons.** `IsolatedLoginFailed.reason` is a fixed text, never a URL or value; it
    is what reports and logs show.
  - **Accepted:** an equal session id shorter than 16 characters, low-entropy, under a
    name `is_sensitive_name` misses (`ASPSESSIONID…`, Drupal `SESS…`,
    `wordpress_logged_in_*`, `express:sess`, `remember_web_*`) would be accepted as
    distinct. No realistic framework issues such ids.
- **FR-SESS-16 (logout listeners, CC-SESS-0017)**
  - `add_logout_listener(fn)` registers `fn(origin, identity)` *(FR-SESS-20; before:
    `fn(host, identity)`)*: `origin` is the canonical origin of the response that showed
    the logout, one of the session's origins; a listener compares it with
    `session_origins_for(target, identity)`, never a host. `observe` calls it once
    each time it marks a valid session of this manager logged out; the check-and-set
    is atomic, so concurrent sends seeing one logout tell it once. *(Amended
    CC-SESS-0029, FR-SESS-23:)* it is told once per valid -> invalid transition **seen
    on a send** (an unconfirmed loss, or a check that confirmed the send's suspicion),
    after the health lock is released; never for a loss a pause re-check or
    `verify_live` found (no culprit send), never for a session that was replaced while
    its check was in flight, and never again in D's window (the state is already
    lost).
  - It runs inside the observing send, after the state is invalid, and its errors
    propagate. Adding the same listener twice is a no-op.
- **FR-SESS-15 (the discovery base is the operator's URL, CC-SESS-0016, BUG-0113)**
  - **Operator bases.** `ensure(..., operator=True)` is called by every operator entry
    point with the operator's own URL, path kept. It is remembered per
    `(host, identity)` for re-login, and it is the only kind of base exempt from the
    destructive-URL check during discovery. The default is `operator=False`
    (fail-closed).
  - **Derived bases.** With no remembered base, `prepare` uses the request URL's
    directory, with no query or fragment: a probe URL or its payload is never a
    discovery base.
  - **Basic auth.** A Basic session has `login_url=None`, so its logout signal is
    ~~401/403~~ *(amended CC-SESS-0029, FR-SESS-23:)* a credentialed 401, confirmed on
    its base URL (rule 2: the base URL that challenged is its stable protected
    resource); its page content is never read.
  - **"The login page" is this session's login form.** A rejected login, a failed
    verification and a logout are recognised by a password form posting to the
    session's login action or carrying exactly its entry names
    (`detect.shows_login_form`), never by any password field:
    app pages such as change-password or LDAP-settings have one. Without a known login
    URL (an adopted session), any password input still counts.
  - **Known limitation (D12).** Sessions and remembered bases are keyed per
    `(host, identity)`, so two sub-path apps on one host:port share them. Use distinct
    identities per app. *(FR-SESS-20:)* two apps on **different ports** of one host no
    longer share a session's sends (each origin is its own), but still share the
    host-keyed credential entry and session slot under one identity name: an operator
    base on another origin is refused, naming the remedy (distinct identity names).
- **FR-SESS-14 (login form serialised as a browser would, CC-SESS-0014, BUG-0110)**
  - **The credential POST body** is the login form's entry list from
    `core.forms.form_entries` (FR-CORE-27), with the username and password entries
    replaced in place. It includes the submitter's `name=value` and a select's
    default option, and leaves out unchecked and disabled controls.
  - **Submitter overrides are refused.** A submit button carrying `formaction`,
    `formmethod` or `formenctype` makes the login fail loudly **before any credential
    request**. A browser would follow those, and they are not emulated.
  - **Known divergence:** the credentials are always sent as a urlencoded POST to
    `form.action`, also for a `method=GET` or `multipart/form-data` form.
  - **Known limitation:** the first form with a password field is taken (a signup
    form before the login form would be chosen).

## 4. Non-functional requirements
- **NFR-SESS-single-flight** Concurrent expiry triggers exactly one re-auth. *(Amended
  CC-SESS-0029, FR-SESS-23:)* and at most two health checks per (host, identity) for
  concurrent signals; a late answer from an earlier generation triggers neither.
- **NFR-SESS-zero-request** Prefer validity signals that cost no request (e.g.
  JWT `exp`); validate on a schedule or reactively, not before every request.
- **NFR-SESS-redaction** Credentials, cookies, and tokens redacted on write.
  - Enforced by (a browser login's JS-set cookie, BUG-0132: only to the session's host, never in repr, logs or the store): `manager._jar_cookies`, `SessionState.apply` / `prepare` — `tests/test_session_browser_login.py::test_the_js_set_cookie_value_is_in_no_repr_log_or_store`, `tests/test_session_browser_login.py::test_the_js_set_cookie_never_goes_to_another_host`, `tests/test_session_browser_login.py::test_jar_cookies_are_host_scoped_unexpired_and_secure_only_over_https`
  - Enforced by: `SessionState.non_secret_state` / `redacted` — `tests/test_session_persistence.py::test_login_persists_non_secret_state_only`, `tests/test_proxy_session_capture.py::test_adopt_persists_only_non_secret_metadata`, `tests/test_session_detect.py::test_session_state_apply_and_redacted`
  - Enforced by (isolated copies, FR-SESS-17): never persisted, and no credential value in an isolation error or report — `tests/test_login_form_isolation.py::test_the_isolated_session_is_never_persisted`, `tests/test_login_form_isolation.py::test_isolation_errors_and_report_carry_no_secret_values`
  - Enforced by (browser login, FR-SESS-19): a unique password never reaches the spider DB, the store, the logs (with `DEBUG=pw:api`), an exception or a repr; `SessionState`'s secrets are `repr=False` — `tests/test_session_browser_login.py::test_the_password_appears_nowhere`, `tests/test_session_browser_login.py::test_session_state_repr_and_str_hold_no_secret`, `tests/test_session_browser_login.py::test_the_driver_starts_without_debug_logging`, `tests/test_session_browser_login.py::test_a_failure_text_never_holds_the_password`
  - Enforced by (browser login: where the password may go): `browserlogin.LoginGate`, `navguard.make_route_handler(request_refusal=)` — `tests/test_session_browser_login.py::test_the_password_never_leaves_to_another_port`, `tests/test_session_browser_login.py::test_the_window_gate_refuses_a_non_destination_only_in_the_window`, `tests/test_session_browser_login.py::test_a_login_route_posting_to_api_users_creates_nothing`, `tests/test_session_browser_login.py::test_a_sign_up_button_on_the_login_route_is_never_clicked`, `tests/test_session_browser_login.py::test_register_and_change_password_forms_on_the_login_route_are_never_used`, `tests/test_session_browser_login.py::test_a_hashed_password_posted_to_api_users_sends_nothing`, `tests/test_session_browser_login.py::test_every_write_to_an_account_endpoint_is_refused_in_the_window`, `tests/test_session_browser_login.py::test_a_body_keeping_redirect_to_an_account_endpoint_is_refused_at_the_hop`
  - Enforced by (a refused submission leaves no password in the page; BUG-0136 review X3): `browserlogin._drive` — `tests/test_session_browser_login.py::test_a_refused_submission_leaves_no_password_in_the_page`, `tests/test_session_browser_login.py::test_clearing_a_password_field_the_app_removed_costs_nothing`
  - Enforced by (a login page that navigates away while parsed fails loudly and fast; CC-SESS-0024, BUG-0138): `browserlogin._drive` → `navguard.navigate` — `tests/test_guarded_navigation.py::test_a_login_page_that_navigates_away_fails_loudly_and_fast`
  - Enforced by (an abandoned browser login sends nothing; no second login beside it; review round 1): `browserlogin.run` cancellation, `LoginGate.cancelled`, `_LIVE` — `tests/test_session_browser_login.py::test_an_abandoned_login_never_sends_the_password`, `tests/test_session_browser_login.py::test_a_cancelled_gate_refuses_every_request`, `tests/test_session_browser_login.py::test_a_cancelled_login_stops_at_a_checkpoint`, `tests/test_session_browser_login.py::test_no_second_login_starts_beside_an_abandoned_one`
  - Enforced by (the password never kept through URLs or storage; review round 1, A-M2): `browserlogin.strip_url`, `drop_secret_values`, `SessionState.non_secret_state` — `tests/test_session_browser_login.py::test_the_password_is_kept_out_of_urls_and_storage`, `tests/test_session_browser_login.py::test_persisted_login_urls_carry_no_query_or_fragment`, `tests/test_session_browser_login.py::test_storage_values_carrying_the_password_are_dropped`
  - Enforced by (origin-scoped sessions, FR-SESS-20, BUG-0134: a session never reaches another app on another port): `SessionManager.prepare` / `_check_base` / `authorize` / `_navigate(session_origins=)` / `_check_origin`, `browserauth.header_scope_for`, `navguard.make_route_handler(cookie_scope=)`, `greybox.run.RequestsCorrelatingSender(cookie_origins=)` — `tests/test_session_origin_scope.py::test_a_send_to_another_port_carries_no_session_and_never_logs_in_there`, `tests/test_session_origin_scope.py::test_an_operator_base_on_another_port_is_refused_with_the_remedy`, `tests/test_session_origin_scope.py::test_a_plugin_retarget_to_another_port_is_refused`, `tests/test_session_origin_scope.py::test_verify_live_never_follows_a_redirect_to_another_port`, `tests/test_session_origin_scope.py::test_greybox_attaches_the_cookie_only_in_origin`, `tests/test_session_origin_scope.py::test_an_authenticated_crawl_never_hands_the_session_to_another_port`, `tests/test_session_origin_scope.py::test_session_headers_refuse_a_base_on_another_origin`, `tests/test_session_origin_scope.py::test_no_session_send_decision_compares_hosts`, `tests/test_session_origin_scope.py::test_the_route_aborts_other_origin_documents_and_fetches_the_rest_cookie_less`, `tests/test_session_origin_scope.py::test_a_websocket_to_another_origin_is_never_connected_in_an_authenticated_context`, `tests/test_session_origin_scope.py::test_a_form_action_on_another_port_is_refused_with_the_advice`, `tests/test_session_origin_scope.py::test_the_post_login_check_keeps_the_header_inside_the_sessions_origins`
  - Not yet enforced: no test runs the server-form login (`_login`) with a logger and checks the log; `login_url` is persisted without `redact_url`. (BUG-0111 sweep.) (The BUG-0134 sweep's login-handshake residual is closed: since review round 1, R3, those hops are refused.)
- **NFR-SESS-portable** Works on interactive desktops, headless hosts, containers,
  and CI via the credential-store backend resolution (D12).
- **NFR-SESS-zero-config** No per-host auth configuration: the only per-host input
  is the credentials in the vault; everything else is detected.

## 5. Interfaces and data contracts
`prepare`/`observe`/`ensure` API resolved by host, the session sent by origin
(`SessionState.origins`, FR-SESS-20); attaches as a proxy addon so
hand-driven traffic is also handled. Obtains credentials from the credential store
keyed by host (D12); writes only non-secret, redacted session state to the store.
Internally, the detected mechanism maps to an auth handler (cookie/form,
JSON+token, Basic, header-key) — an implementation detail selected by detection,
not a user-authored profile.

## 6. Dependencies (components)
`core/` (config, store, HTTP seam, credential store); crawler (discovered forms
help locate the login, though the manager can also probe on its own).

## 7. Acceptance criteria
- Crawler and fuzzer stay authenticated through a full run, with results per
  identity, on the Puppy Fort Factory (cookie) **and** an external lab with a
  different scheme (a JWT-based app) — with **no per-host auth config**, only
  saved credentials.
- Login, session credential, success, and expiry are all detected dynamically;
  concurrent expiry produces one re-auth, not many.
- A login detection cannot parse fails loudly with diagnostics (no silent
  unauthenticated run).
- Fuzzing never logs itself out via an auth endpoint.
- Runs headless/CI via the encrypted-file credential backend (D12).

## 8. Open questions
- Detection heuristics for multi-form pages (which form is the login). SPA logins
  where the login is an XHR are detected in a browser since FR-SESS-19; cases
  detection still can't crack are covered post-Phase 6 by proxy session capture,
  FR-SESS-11.
- MFA/TOTP: out of scope for automated detection; handled post-Phase 6 by adopting
  a manual browser login captured through the proxy (FR-SESS-11).
- How aggressively to probe for a login when the crawler has not yet found a form.
- Re-capture UX when an adopted interactive session expires (FR-SESS-11).
