# Session Manager — Requirement Specification

Component code: **SESS** · Status: `[built; live validation + resume pending]` (Phase 1)
· Last updated: 2026-09-21

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
  CAPTCHA, exotic SPA), fail loudly with diagnostics (what was found, where it
  stopped) rather than silently proceeding unauthenticated; there is no
  hand-written override (D13).
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
    are followed by hand as a GET, only to an allowed origin; 307/308 never.
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
  - Not yet enforced: no test runs `SessionManager` with a logger and checks the log; `login_url` is persisted without `redact_url`. (BUG-0111 sweep.)
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
- Detection heuristics for multi-form pages (which form is the login) and for
  SPA logins where the login is an XHR, not an HTML form. (Cases detection still
  can't crack are covered post-Phase 6 by proxy session capture, FR-SESS-11.)
- MFA/TOTP: out of scope for automated detection; handled post-Phase 6 by adopting
  a manual browser login captured through the proxy (FR-SESS-11).
- How aggressively to probe for a login when the crawler has not yet found a form.
- Re-capture UX when an adopted interactive session expires (FR-SESS-11).
