# Session Manager — Requirement Specification

Component code: **SESS** · Status: `[planned]` (Phase 1) · Last updated: 2026-09-21

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
  login form (a form containing a password field), carry its hidden fields
  (e.g. a CSRF `user_token`) through by re-fetching the form immediately before
  submit (fresh, never cached), map the username/password fields, and submit the
  host's credentials. (D13)
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

## 4. Non-functional requirements
- **NFR-SESS-single-flight** Concurrent expiry triggers exactly one re-auth.
- **NFR-SESS-zero-request** Prefer validity signals that cost no request (e.g.
  JWT `exp`); validate on a schedule or reactively, not before every request.
- **NFR-SESS-redaction** Credentials, cookies, and tokens redacted on write.
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
