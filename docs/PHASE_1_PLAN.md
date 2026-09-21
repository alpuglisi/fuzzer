# Phase 1 — Session manager (plan)

The session manager keeps every tool authenticated consistently **across many
target labs**, so session expiry never silently poisons crawls, audits, fuzzing,
or training data. It is the most load-bearing dependency after `core/` —
everything authenticated flows through it — and a hard dependency for the external
validation in D10.

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (D3, D10, D12, D13),
`docs/components/03-session-manager/` (spec + change-control), and
`docs/PREVENTIVE_ACTIONS.md` (rules to follow).*

## Goal

The crawler and fuzzer stay authenticated through a whole run — on the Puppy Fort
Factory **and** on at least one external lab with a different auth scheme — with
results recorded per identity; concurrent expiry produces exactly one
re-authentication; fuzzing can never log itself out; and it works headless/CI.

## Auth landscape (what Phase 1 must handle)

Different labs authenticate differently, so the manager is target-profile-driven
and scheme-pluggable (D13):

| Scheme | Example targets | Session credential |
| --- | --- | --- |
| Form POST + session cookie | Puppy Fort Factory, DVWA*, Mutillidae, bWAPP | cookie (`PHPSESSID`) |
| JSON login + bearer/JWT | Juice Shop | `Authorization: Bearer <jwt>` |
| HTTP Basic | misc | `Authorization: Basic …` |
| Header API key | misc/REST | custom header |
| Scripted / multi-step | bespoke | varies |

\*DVWA adds a login-form CSRF `user_token` and a security-level cookie — handled by
the form+cookie strategy's optional CSRF pre-fetch.

The Puppy Fort Factory itself uses **PHP session cookies only** — no CSRF, no JWT.

## Settled scope decisions

- **Credential store (D12).** OS keyring with an encrypted-file headless fallback
  (passphrase from `FUZZLAB_KEYRING_PASSPHRASE`) and a gated, lab-only env fallback
  (default off). Config holds only references; secrets never touch the store.
- **Multi-target auth (D13).** One `AuthStrategy` interface with built-in
  strategies; per-target profiles as data. Adding a same-scheme lab is a profile,
  not code.
- **CSRF/JWT (FR-SESS-3).** Built to spec and fixture-tested now (the JWT path is
  also exercised live against the external JWT lab in T1.10); the Puppy Fort
  Factory validates the cookie path.

## Tasks

Ordered; each lists a deliverable and an acceptance check. Follow
`PREVENTIVE_ACTIONS.md` throughout (e.g. PA-0001: don't hardcode source-of-truth
values in tests).

### T1.1 — Credential store in `core/` (D12)
A `CredentialStore` abstraction over `keyring` with backend resolution: OS Secret
Service → encrypted-file (`keyrings.alt`, passphrase from env/prompt) → gated
lab-only env fallback. A `fuzzlab session set-credential` helper writes through the
active backend. Config references only (service/user); redaction on write.
- **Accept:** a credential set on the encrypted-file backend (headless) is read
  back; no secret appears in the store, logs, or repo; env fallback is refused
  outside lab scope.

### T1.2 — Target profiles + identity model (D13)
A data-driven target profile (base URL, scope, auth strategy + params, identities
with credential references) and an identity model (`anonymous`/`user`/`admin`)
scoped per profile, each with its own session state (cookies + headers/tokens) and
connection pool. Ship a Puppy Fort Factory profile.
- **Accept:** the PFF profile loads three identities with separate session state;
  a second profile can be added without code changes.

### T1.3 — `AuthStrategy` interface + registry
One interface — `authenticate(identity, http) -> SessionState`, `attach(request,
session_state)`, `is_expired(...) -> bool`, optional `refresh(...)` — plus a
built-in strategy registry (plugin-extensible later via component #13).
- **Accept:** a strategy can be selected by name from a profile and drives login.

### T1.4 — Built-in strategies (incl. CSRF/JWT, fixture-tested)
Ship: **form+cookie** (with optional login-form CSRF pre-fetch), **JSON+bearer/JWT**
(read `exp`, refresh proactively), **HTTP Basic**, **header API key**, and a
**scripted/multi-step** strategy. Token location comes from the profile.
- **Accept:** against mocks/fixtures, form+cookie logs in and holds a cookie; the
  JWT strategy attaches a bearer and refreshes near `exp`; CSRF is taken fresh from
  the preceding response (never cached).

### T1.5 — Session API wired into the HTTP seam
Implement `prepare`/`observe`/`ensure` over the active profile and wire the real
manager into the `core/` HTTP seam, replacing the Phase 0 addon stub. `prepare`
applies the strategy's session state; `observe` updates it and watches for logout.
- **Accept:** a request sent through the seam for an identity carries that
  identity's session (cookie or token, per scheme); `observe` records updates.

### T1.6 — Validity detection + single-flight re-auth
Detect logout/expiry from per-profile signals (status, redirect, body/JSON marker,
401/403) and re-authenticate via the profile's strategy under a single-flight
lock; cap attempts then hard-fail loudly.
- **Accept:** concurrent expiry triggers exactly one login (call-counting mock);
  after the cap, `ensure` raises rather than looping.

### T1.7 — Redaction + non-secret session-state persistence
Redact credentials/cookies/tokens on every write to the store and logs; persist
only non-secret session state (identity, target, auth status, timestamps) so a
crashed run resumes, keeping live secrets out of the store in cleartext.
- **Accept:** a store/log scan finds no cleartext secret; a resumed run reuses the
  persisted non-secret state.

### T1.8 — Auth-endpoint exclusion from fuzzing
Auto-exclude each profile's auth endpoints (login/logout/session-destroy) from
fuzzing scope so the fuzzer cannot log itself out.
- **Accept:** the fuzzing scope excludes the profile's auth endpoints; a test
  asserts they are never selected as targets.

### T1.9 — Standalone use
Print a ready-to-use cookie/header/token for a given identity on a given target
(e.g. `fuzzlab session --profile pff --identity user --print`) for manual testing.
- **Accept:** the command prints a valid credential for the identity and sends
  nothing else.

### T1.10 — Per-identity runs on PFF + an external lab
Run the crawler and fuzzer per identity through the session manager against the
Puppy Fort Factory (cookie) and one external lab with a different scheme (a
JWT-based app), recording results tagged by identity (add an `identity` column
where needed via a new, append-only migration, or derive via `flow.identity`).
- **Accept:** full crawl + fuzz stays authenticated end-to-end on both targets,
  and results are attributable to the identity that produced them.

## Exit criterion

The crawler and fuzzer stay authenticated through a full run on the Puppy Fort
Factory **and** an external lab with a different auth scheme, with results per
identity; concurrent expiry produces one re-auth (not many); fuzzing never logs
itself out; no secret is written in cleartext; and the whole thing runs headless
via the encrypted-file credential backend.

## Out of scope for Phase 1 (deferred)

Attacking authentication (a testing target the tools handle); MFA/TOTP (a
scripted-strategy step, later); OAuth interactive redirect flows; proxy-addon
integration (the API is addon-friendly, but the proxy itself is Phase 6).

## To confirm during the build

- **Which validation labs to ship profiles for** (drives which strategies are
  exercised first — Juice Shop pins the JWT path).
- Keyring passphrase handling in CI (env vs. prompt) and the encrypted-store path.
- Exact logout-detection signals per profile.
- Whether to add an `identity` column to `attempt`/`finding` (a migration) or
  attribute via `flow.identity`.
- Scripted-strategy configuration format for the most complex logins.

## Known risks

- **Silent session failure poisons data.** Mitigated by multi-signal validity
  checks, the single-flight lock, capped-then-hard-fail re-auth, and building this
  early.
- **Broader auth surface (multiple schemes/profiles).** Mitigated by keeping
  per-target quirks in data (profiles) not code, one narrow `AuthStrategy`
  interface, and validating on the known cookie lab before trusting new schemes.
- **Storing secrets.** Mitigated by the credential store (keyring/encrypted file),
  redaction on write, and not persisting live cookies/tokens in cleartext.
- **Fuzzing an auth endpoint and logging out.** Mitigated by auto-exclusion (T1.8).
- **Re-auth during timing-sensitive fuzzing.** A mid-measurement login distorts
  timing; ensure re-auth happens outside timing windows (coordinate with the
  budget manager's per-host timing mutex).
