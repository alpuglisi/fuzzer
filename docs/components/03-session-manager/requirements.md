# Session Manager — Requirement Specification

Component code: **SESS** · Status: `[planned]` (Phase 1) · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #3; `DECISIONS_AND_ROADMAP.md` (D3, D10, D12, D13);
`./change-control.md`.

## 1. Purpose
Keep every tool authenticated consistently **across many target labs**, so that
session expiry does not silently poison crawls, audits, fuzzing, and training
data. Shared by all tools; a hard dependency for external validation (D10).

## 2. Scope
- **In:** target profiles; identities; pluggable auth strategies (cookie/form,
  JSON+JWT, Basic, header API key, scripted); session state (cookies + tokens);
  validity checking; re-authentication; credential access; auth-endpoint exclusion.
- **Out:** attacking authentication (that is a testing target, handled by the
  tools, not by this component).

## 3. Functional requirements
- **FR-SESS-1** Model multiple identities (at least `anonymous`, `user`,
  `admin`) **per target profile**, each with its own session state (cookie jar +
  headers/tokens) and connection pool.
- **FR-SESS-2** Expose `prepare(request, identity)`, `observe(request, response,
  identity)`, and `ensure(identity)`, resolved against the active target profile.
- **FR-SESS-3** Extract CSRF/anti-forgery tokens fresh from the immediately
  preceding response (no caching); handle bearer/JWT tokens, reading `exp`
  locally to refresh proactively. Token **location** (cookie name / header /
  JSON path) comes from the target profile.
- **FR-SESS-4** Detect logout/expiry from multiple per-profile signals (status,
  redirect, body/JSON marker, 401/403) and re-authenticate via the profile's auth
  strategy, guarded by a single-flight lock; cap re-auth attempts then hard-fail.
- **FR-SESS-5** Auto-exclude auth endpoints (login/logout/session-destroy) from
  fuzzing scope.
- **FR-SESS-6** Obtain credentials through the `core/` credential store (OS keyring
  with an encrypted-file headless fallback and a gated lab-only env fallback, D12);
  never from the project store or the repo. Config holds only references.
- **FR-SESS-7** Persist non-secret session state (identity, auth status,
  timestamps) to the store so a crashed run resumes; never persist live
  cookies/tokens/credentials in cleartext.
- **FR-SESS-8** Be usable standalone (print a ready-to-use cookie/header/token for
  a given identity on a given target).
- **FR-SESS-9** Be **target-profile-driven** (D13): a data profile per lab
  declares base URL, scope, the auth strategy + its parameters, identities, and
  their credential references. Adding a same-scheme lab is a new profile, not code.
- **FR-SESS-10** Support **pluggable auth strategies** (D13) behind one
  `AuthStrategy` interface — `authenticate`, `attach`, `is_expired`, optional
  `refresh`. Ship: form+cookie (with optional login-form CSRF pre-fetch),
  JSON+bearer/JWT, HTTP Basic, header API key, and scripted/multi-step. New
  schemes register via the plugin system (component #13); built-in for now.

## 4. Non-functional requirements
- **NFR-SESS-single-flight** Concurrent expiry triggers exactly one re-auth.
- **NFR-SESS-zero-request** Prefer validity signals that cost no request (e.g.
  JWT `exp`); validate on a schedule or reactively, not before every request.
- **NFR-SESS-redaction** Credentials, cookies, and tokens redacted on write.
- **NFR-SESS-portable** Works on interactive desktops, headless hosts, containers,
  and CI via the credential-store backend resolution (D12).
- **NFR-SESS-extensible** A new auth scheme is one new `AuthStrategy`; a new
  same-scheme lab is one new profile — no changes elsewhere.

## 5. Interfaces and data contracts
`prepare`/`observe`/`ensure` API over a selected target profile; attaches as a
proxy addon so hand-driven traffic is also handled. Obtains credentials from the
credential store (D12); writes only non-secret, redacted session state to the
store. Auth strategies and target profiles are the two extension points.

## 6. Dependencies (components)
`core/` (config, store, HTTP seam, credential store); plugin system (component
#13) for third-party auth strategies (built-in registry until then).

## 7. Acceptance criteria
- Crawler and fuzzer stay authenticated through a full run, with results per
  identity, on the Puppy Fort Factory **and** on at least one external lab with a
  different auth scheme (e.g. a JWT-based app).
- CSRF and JWT handled; token location driven by the profile; concurrent expiry
  produces one re-auth, not many.
- Fuzzing never logs itself out via an auth endpoint.
- Runs headless/CI via the encrypted-file credential backend (D12).
- Adding a same-scheme lab requires only a new target profile.

## 8. Open questions
- MFA/TOTP support (a scripted-strategy step, later).
- The exact set of validation labs to ship profiles for (drives which strategies
  are exercised first).
- Scripted-strategy configuration format for the most complex multi-step logins.
