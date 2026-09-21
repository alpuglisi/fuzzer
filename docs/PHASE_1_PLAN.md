# Phase 1 — Session manager (plan)

The session manager keeps every tool authenticated consistently, so session
expiry never silently poisons crawls, audits, fuzzing, or training data. It is the
most load-bearing dependency after `core/` — everything authenticated flows
through it.

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (D3, Phase 1),
`docs/components/03-session-manager/` (spec + change-control), and
`docs/PREVENTIVE_ACTIONS.md` (rules to follow).*

## Goal

The crawler and fuzzer stay authenticated through a whole run against the
containerized lab, with results recorded per identity; concurrent expiry produces
exactly one re-authentication; and fuzzing can never log itself out.

## The lab's auth (what Phase 1 validates against)

The Puppy Fort Factory authenticates with **PHP session cookies only**
(`session_start()` / `$_SESSION`); login is a POST to `login.php`
(username + password), success redirects to `profile.php`, and `logout.php` ends
the session. There are **no CSRF tokens and no JWT** anywhere in the app.

## Scope decision — CSRF/JWT (FR-SESS-3)

**Build to spec, fixture-tested.** CSRF extraction and JWT `exp` handling are
implemented now to the component spec and unit-tested against mock endpoints and
fixtures, since the current lab exercises neither. The cookie-session path is
validated live against the lab; CSRF/JWT are validated live later, when a target
(a second lab target, or a CSRF/JWT-enabled lab profile) uses them.

## Tasks

Ordered; each lists a deliverable and an acceptance check. Follow
`PREVENTIVE_ACTIONS.md` throughout (e.g. PA-0001: don't hardcode source-of-truth
values in tests).

### T1.1 — Identity model and cookie jars
An identity model with at least `anonymous`, `user`, and `admin`, each with its own
cookie jar and connection pool. Credentials for `user`/`admin` are referenced by
keyring key (not stored by value); `anonymous` has none. (FR-SESS-1)
- **Accept:** three identities load; each keeps a separate cookie jar; no
  credential value appears in config, the store, or logs.

### T1.2 — Session API wired into the HTTP seam
Implement `prepare(request, identity)`, `observe(request, response, identity)`,
and `ensure(identity)`, and wire the real session manager into the `core/` HTTP
seam, replacing the Phase 0 addon stub. `prepare` attaches the identity's
cookies/headers; `observe` updates them and watches for logout. (FR-SESS-2)
- **Accept:** a request sent through the seam for an identity carries that
  identity's session; `observe` records returned cookies.

### T1.3 — Token handling (CSRF + JWT), fixture-tested
Extract CSRF/anti-forgery tokens fresh from the immediately preceding response (no
caching) and inject them into the next mutating request; handle bearer/JWT tokens,
reading `exp` locally to refresh proactively. (FR-SESS-3)
- **Accept:** against mock endpoints, a fresh CSRF token is taken from each prior
  response (never cached) and a JWT nearing `exp` is refreshed before use.

### T1.4 — Validity detection + single-flight re-auth
Detect logout/expiry from multiple signals (redirect to `login.php`, missing
session, an unauthenticated marker) and re-authenticate via a login macro guarded
by a single-flight lock; cap attempts, then hard-fail loudly. (FR-SESS-4,
NFR-single-flight)
- **Accept:** concurrent expiry triggers exactly one login (verified by a
  call-counting mock); after the cap, `ensure` raises rather than looping.

### T1.5 — Credentials, redaction, session-state persistence
Load credentials from the OS keyring; redact credentials/cookies/tokens on every
write to the store and logs; persist non-secret session state (identity, auth
status, timestamps) so a crashed run resumes, keeping live secrets out of the
store in cleartext. (FR-SESS-6, FR-SESS-7, NFR-redaction)
- **Accept:** credentials come only from the keyring; a store/log scan finds no
  cleartext cookie/credential/token; a resumed run reuses persisted session state.

### T1.6 — Auth-endpoint exclusion from fuzzing
Auto-exclude auth endpoints (`login.php`, `logout.php`, session-destroy) from
fuzzing scope so the fuzzer cannot log itself out. (FR-SESS-5)
- **Accept:** the fuzzing scope for a run excludes the auth endpoints; a test
  asserts they are never selected as targets.

### T1.7 — Standalone use
Usable standalone: print a ready-to-use cookie/header for a given identity (e.g.
`fuzzlab session --identity user --print-cookie`) for manual testing. (FR-SESS-8)
- **Accept:** the command prints a valid cookie/header for the identity and sends
  nothing else.

### T1.8 — Per-identity crawl and fuzz against the live lab
Run the crawler and fuzzer per identity through the session manager and record
results tagged by identity (add an `identity` column where needed via a new,
append-only migration, or derive via `flow.identity`). (Exit criterion)
- **Accept:** a full crawl + fuzz as `admin` (and as `user`) stays authenticated
  end-to-end, and results are attributable to the identity that produced them.

## Exit criterion

The crawler and fuzzer stay authenticated through a full run against the lab, with
results per identity; concurrent expiry produces one re-auth (not many); fuzzing
never logs itself out; and no secret is written in cleartext.

## Out of scope for Phase 1 (deferred)

Attacking authentication (that is a testing target the tools handle, not the
session manager); MFA/TOTP (a pluggable step, later); live CSRF/JWT validation
(until a target uses them); proxy-addon integration (the API is designed
addon-friendly, but the proxy itself is Phase 6).

## To confirm during the build

- Keyring backend on Fedora (which `keyring` backend; headless fallback).
- Exact logout-detection signals for this lab (redirect target, marker).
- Whether to add an `identity` column to `attempt`/`finding` (a migration) or
  attribute via `flow.identity`.
- Session-state persistence format — what is safe to store (non-secret) vs kept in
  memory/keyring.

## Known risks

- **Silent session failure poisons data.** Mitigated by multi-signal validity
  checks, the single-flight lock, a capped-then-hard-fail re-auth, and building
  this early (before most tools depend on auth).
- **Storing secrets.** Mitigated by keyring-only credentials, redaction on write,
  and not persisting live cookies/tokens in cleartext.
- **Fuzzing an auth endpoint and logging out.** Mitigated by auto-exclusion (T1.6).
- **Re-auth during timing-sensitive fuzzing.** A mid-measurement login distorts
  timing; ensure re-auth happens outside timing windows (coordinate with the
  budget manager's per-host timing mutex).
