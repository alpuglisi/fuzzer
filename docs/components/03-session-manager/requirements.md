# Session Manager — Requirement Specification

Component code: **SESS** · Status: `[planned]` (Phase 1) · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #3; `DECISIONS_AND_ROADMAP.md` (D3); `./change-control.md`.

## 1. Purpose
Keep every tool authenticated consistently, so that session expiry does not
silently poison crawls, audits, fuzzing, and training data. Shared by all tools.

## 2. Scope
- **In:** identities, cookie jar, token extraction/injection, validity checking,
  re-authentication, credential access, auth-endpoint exclusion.
- **Out:** attacking authentication (that is a testing target, handled by the
  tools, not by this component).

## 3. Functional requirements
- **FR-SESS-1** Model multiple identities (at least `anonymous`, `user`,
  `admin`) with separate cookie jars and connection pools.
- **FR-SESS-2** Expose `prepare(request, identity)`, `observe(request, response,
  identity)`, and `ensure(identity)`.
- **FR-SESS-3** Extract CSRF/anti-forgery tokens fresh from the immediately
  preceding response (no caching); handle bearer/JWT tokens, reading `exp`
  locally to refresh proactively.
- **FR-SESS-4** Detect logout/expiry from multiple signals and re-authenticate via
  a macro guarded by a single-flight lock; cap re-auth attempts then hard-fail.
- **FR-SESS-5** Auto-exclude auth endpoints (login/logout/session-destroy) from
  fuzzing scope.
- **FR-SESS-6** Load credentials from the OS keyring; never from the store.
- **FR-SESS-7** Persist session state (not credentials) to the store so a crashed
  run resumes.
- **FR-SESS-8** Be usable standalone (print a ready-to-use cookie/header for a
  given identity).

## 4. Non-functional requirements
- **NFR-SESS-single-flight** Concurrent expiry triggers exactly one re-auth.
- **NFR-SESS-zero-request** Prefer validity signals that cost no request (e.g.
  JWT `exp`); validate on a schedule or reactively, not before every request.
- **NFR-SESS-redaction** Credentials, cookies, and tokens redacted on write.

## 5. Interfaces and data contracts
`prepare`/`observe`/`ensure` API; attaches as a proxy addon so hand-driven
traffic is also handled. Reads credentials from the keyring; writes session state
(redacted) to the store.

## 6. Dependencies (components)
`core/`.

## 7. Acceptance criteria
- Crawler and fuzzer stay authenticated through a full run, with results per
  identity.
- CSRF and JWT handled; concurrent expiry produces one re-auth, not many.
- Fuzzing never logs itself out via an auth endpoint.

## 8. Open questions
- MFA/TOTP support (pluggable step).
- Which keyring backend on Fedora.
