# Session Manager — Requirement Specification

Component code: **SESS** · Status: `[built; live validation + resume pending]` (Phase 1)
· Last updated: 2026-10-14

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
  multiple signals (401/403, redirect to the detected login, the login form
  reappearing, JWT `exp`) and re-authenticate under a single-flight lock; cap
  attempts then hard-fail.
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
  for a given identity on a given host).
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
    to `base_url`'s scheme. Host scope stays host-level: an in-scope other port over
    the same or an upgraded scheme is allowed, and `auth_origins` is the origin-precise
    alternative.
  - **Where credentials may go.** They are POSTed only to the login page's own
    canonical origin, that host upgraded to https, an in-scope host, or an origin in
    `SessionManager(auth_origins=[...])`. Anything else fails loudly, naming the
    option.
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
    in-scope hosts (any port: host-level scope, D12), and `auth_origins`, which is the
    origin-precise alternative. A response-derived page is never an anchor.
  - **`SessionState.secure_only`.** Set when the login, a captured session or the stored
    `login_url` was https. An unknown legacy `login_url` fails closed.
  - **Where it is enforced.** An https session's cookies, tokens and Basic header are
    never sent over plain http:
    - `prepare`;
    - `authorize`, after a plugin retarget, which also refuses another host;
    - `session_header`;
    - greybox's sender.
  - **Per host, by design (D12).** A session is keyed per host, so other ports of the
    same host are allowed. Cookie Path is not enforced: a stated residual, since the
    same origin learns nothing new.
  - **No destructive hop** *(CC-SESS-0015, BUG-0111).* Discovery and the post-login
    probe never fetch a URL `core.urls.destructive_reason` flags (a redirect to
    `logout`, `reset`, ...), other than the operator's own base URL.
- **FR-SESS-19 (browser login for single-page apps, CC-SESS-0021)**
  - **When.** Only as a fallback (detection only, D13): `_login` found no
    server-rendered login form and no Basic challenge, and the manager may use a
    browser (`SessionManager(browser_login=...)`; default on when the manager's fetches
    go to the network, i.e. the default fetcher; off when a fetcher double stands in;
    copied to isolated copies). Without Playwright or a launchable Chromium the login
    fails loudly naming the missing browser.
  - **Where it runs (`session/browserlogin.py`).** On a dedicated worker thread (no
    event loop: a sync Playwright never nests inside a crawl's), under the
    per-(host, identity) login lock, joined with a deadline (120 s). Its own browser
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
    POST/PUT carrying it after the click). A password-carrying request to an account
    endpoint (path tokens register, sign-up, password, reset, change; users / accounts
    without a login token) is aborted before it is sent. Aborted-request logs name the
    host only.
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
    never retried within an attempt.
  - **The credential and success.** `detect.detect_session_credential` on the login
    request's own response (a cookie that response set, else a token in its JSON body,
    `exp` read for refresh); a non-2xx answer is a rejected login. Success is FR-SESS-5's
    positive differential on a **protected probe**: an in-scope GET XHR the app made
    after the click (scope- and destructive-checked, 2xx in the browser) that answers
    2xx when replayed with the credential and, without it, 401/403, another non-5xx
    status, or a body that differs while both are stable over two fetches. The probe
    (and the anonymous body's sha256 when that was 2xx) is kept in memory on the
    `SessionState`; `verify_live` re-fetches it (2xx, and not the anonymous body), so a
    revoked token reads as lost. The login request URL and `logout` are auth endpoints
    (FR-SESS-7); the SPA shell is not.
  - **What is kept.** `SessionState.browser_state` = the login context's
    `storage_state()` (cookies and per-origin localStorage) filtered to the login scope,
    in memory only (never persisted, never in repr, not compared). `SessionState`'s
    cookies, headers, browser state and probe are `repr=False`.
  - **Attempts.** Each browser login is one attempt toward `max_reauth` / `_failures`
    and an isolated copy's `max_logins`; a wrong password stops at the cap.
  - **Residuals (stated).** JWT sessions are stateless: an isolated copy's distinct
    token is the same account server-side (FR-FUZZ-44's isolation is weaker there);
    each isolated copy performs its own browser login. A login whose API lives on
    another origin needs that origin in `auth_origins`. An app that makes no
    credential-dependent GET after its login cannot be confirmed (fails loudly).
    Username detection depends on `_USERNAME_HINT` (BUG-0121). Juice Shop itself has
    not been exercised here (offline fixture only).
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
    - privilege-gated redirects to the real login page still read as a logout;
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
    the state invalid and persists that, without telling listeners. The session goes
    only to its own host: a hop to any other host is never fetched and raises
    `SessionAuthError` ("cannot verify"), as an unapproved hop does.
  - **Reasons.** `IsolatedLoginFailed.reason` is a fixed text, never a URL or value; it
    is what reports and logs show.
  - **Accepted:** an equal session id shorter than 16 characters, low-entropy, under a
    name `is_sensitive_name` misses (`ASPSESSIONID…`, Drupal `SESS…`,
    `wordpress_logged_in_*`, `express:sess`, `remember_web_*`) would be accepted as
    distinct. No realistic framework issues such ids.
- **FR-SESS-16 (logout listeners, CC-SESS-0017)**
  - `add_logout_listener(fn)` registers `fn(host, identity)`. `observe` calls it once
    each time it marks a valid session of this manager logged out; the check-and-set
    is atomic, so concurrent sends seeing one logout tell it once.
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
    401/403.
  - **"The login page" is this session's login form.** A rejected login, a failed
    verification and a logout are recognised by a password form posting to the
    session's login action or carrying exactly its entry names
    (`detect.shows_login_form`), never by any password field:
    app pages such as change-password or LDAP-settings have one. Without a known login
    URL (an adopted session), any password input still counts.
  - **Known limitation (D12).** Sessions and remembered bases are keyed per
    `(host, identity)`, so two sub-path apps on one host:port share them. Use distinct
    identities per app.
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
- **NFR-SESS-single-flight** Concurrent expiry triggers exactly one re-auth.
- **NFR-SESS-zero-request** Prefer validity signals that cost no request (e.g.
  JWT `exp`); validate on a schedule or reactively, not before every request.
- **NFR-SESS-redaction** Credentials, cookies, and tokens redacted on write.
  - Enforced by: `SessionState.non_secret_state` / `redacted` — `tests/test_session_persistence.py::test_login_persists_non_secret_state_only`, `tests/test_proxy_session_capture.py::test_adopt_persists_only_non_secret_metadata`, `tests/test_session_detect.py::test_session_state_apply_and_redacted`
  - Enforced by (isolated copies, FR-SESS-17): never persisted, and no credential value in an isolation error or report — `tests/test_login_form_isolation.py::test_the_isolated_session_is_never_persisted`, `tests/test_login_form_isolation.py::test_isolation_errors_and_report_carry_no_secret_values`
  - Enforced by (browser login, FR-SESS-19): a unique password never reaches the spider DB, the store, the logs (with `DEBUG=pw:api`), an exception or a repr; `SessionState`'s secrets are `repr=False` — `tests/test_session_browser_login.py::test_the_password_appears_nowhere`, `tests/test_session_browser_login.py::test_session_state_repr_and_str_hold_no_secret`, `tests/test_session_browser_login.py::test_the_driver_starts_without_debug_logging`, `tests/test_session_browser_login.py::test_a_failure_text_never_holds_the_password`
  - Enforced by (browser login: where the password may go): `browserlogin.LoginGate`, `navguard.make_route_handler(request_refusal=)` — `tests/test_session_browser_login.py::test_the_password_never_leaves_to_another_port`, `tests/test_session_browser_login.py::test_the_window_gate_refuses_a_non_destination_only_in_the_window`, `tests/test_session_browser_login.py::test_a_login_route_posting_to_api_users_creates_nothing`, `tests/test_session_browser_login.py::test_a_sign_up_button_on_the_login_route_is_never_clicked`, `tests/test_session_browser_login.py::test_register_and_change_password_forms_on_the_login_route_are_never_used`
  - Not yet enforced: no test runs the server-form login (`_login`) with a logger and checks the log; `login_url` is persisted without `redact_url`. (BUG-0111 sweep.)
- **NFR-SESS-portable** Works on interactive desktops, headless hosts, containers,
  and CI via the credential-store backend resolution (D12).
- **NFR-SESS-zero-config** No per-host auth configuration: the only per-host input
  is the credentials in the vault; everything else is detected.

## 5. Interfaces and data contracts
`prepare`/`observe`/`ensure` API resolved by host; attaches as a proxy addon so
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
