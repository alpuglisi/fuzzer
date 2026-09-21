# Phase 1 — Session manager (plan)

The session manager keeps every tool authenticated consistently **across many
hosts**, so session expiry never silently poisons crawls, audits, fuzzing, or
training data. It is the most load-bearing dependency after `core/` — everything
authenticated flows through it — and a hard dependency for the external validation
in D10.

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (D3, D10, D12, D13),
`docs/components/03-session-manager/` (spec + change-control), and
`docs/PREVENTIVE_ACTIONS.md` (rules to follow).*

## Status (2026-09-21)

Phase 1 is **built and unit-tested** (session package 17 tests; suite 60 green).

- **T1.1** per-host credential store (`core/credentials.py`) — done.
- **T1.2** login detection (form + fresh CSRF carry-through) — done.
- **T1.3** session-credential detection (cookie / JSON-token+JWT / Basic) — done.
- **T1.4** success/expiry detection + single-flight re-auth + fail-loud — done.
- **T1.5** wired into the `core/` HTTP seam (drop-in addon) — done.
- **T1.6** identities per host — done.
- **T1.7** secret redaction — done; persist non-secret state to a store table — todo.
- **T1.8** auth-endpoint exclusion — done.
- **T1.9** standalone `fuzzlab session` (set-credential / print) — done.
- **T1.10** migrate tool HTTP onto the seam + **live two-lab validation** (cookie
  lab + JWT lab) — todo (needs a runnable container daemon / network to an external
  lab; the cookie and JWT paths are covered by unit tests with scripted fetchers).

Remaining to close Phase 1 end-to-end: route the crawler/fuzzer HTTP through the
seam with the session addon and run per-identity against the containerized lab and
an external JWT lab; wire non-secret session-state persistence for crash-resume.

## Goal

Point the toolkit at a host; it **detects that host's login dynamically**, logs in
with the credentials saved for that host, holds the session, and re-authenticates
on expiry — with **no per-host auth configuration**. The crawler and fuzzer stay
authenticated through a whole run on the Puppy Fort Factory (cookie) and on an
external lab with a different scheme (JWT), results per identity, headless-capable.

## Approach: detection-only (D13)

No hand-written per-host profiles. The manager detects and handles the common
login shapes; the only per-host input is the credentials in the vault.

| Detected shape | Example | Session credential |
| --- | --- | --- |
| Login form → session cookie | Puppy Fort Factory, DVWA, Mutillidae, bWAPP | cookie (`PHPSESSID`) |
| JSON login → token/JWT | Juice Shop | `Authorization: Bearer <jwt>` |
| HTTP Basic / Bearer challenge | misc/REST | `Authorization: …` |

Hidden login-form fields (e.g. a DVWA `user_token`) are carried through by
re-fetching the form immediately before submit. A login detection **cannot** parse
(multi-step, CAPTCHA, exotic SPA) **fails loudly with diagnostics** — the remedy is
to improve detection, not to add config (accepted trade-off).

## Settled scope decisions

- **Credentials (D12).** Saved **per host** (vault keyed by `(host, identity)`) in
  the `core/` credential store: OS keyring → encrypted-file headless fallback
  (passphrase from `FUZZLAB_KEYRING_PASSPHRASE`) → gated lab-only env fallback
  (default off). Config holds no secrets.
- **Auth (D13).** Detection-only; no per-host profiles/overrides; fail loud on
  unparseable logins.
- **CSRF/JWT.** Handled by detection (hidden-field carry-through for CSRF; `exp`
  read locally for JWT); fixture-tested, and the JWT path exercised live on the
  external lab in T1.10.

## Tasks

Ordered; each lists a deliverable and an acceptance check. Follow
`PREVENTIVE_ACTIONS.md` throughout (e.g. PA-0001: don't hardcode source-of-truth
values in tests).

### T1.1 — Per-host credential store in `core/` (D12)
A `CredentialStore` keyed by `(host, identity)` over `keyring`, with backend
resolution (OS Secret Service → encrypted-file → gated lab-only env). A
`fuzzlab session set-credential --host <host> --identity <id>` helper writes
through the active backend; lookups are by host. Redaction on write.
- **Accept:** a credential set for a host (encrypted-file backend, headless) is
  read back by host lookup; no secret appears in the store, logs, or repo; env
  fallback refused outside lab scope.

### T1.2 — Login detection
Locate a host's login (from crawler-discovered forms, or probe): pick the form
containing a password field, map the username/password fields, and re-fetch the
form immediately before submit so hidden/CSRF fields are carried fresh. Submit the
host's credentials.
- **Accept:** against the lab, the login form is found, the fresh hidden fields are
  carried, and credentials are submitted; on a mock CSRF form, the token is taken
  fresh each time (never cached).

### T1.3 — Session-credential detection
Detect what the login response establishes and reuse it on subsequent requests to
that host: `Set-Cookie` → cookie jar; a token/JWT in a JSON body →
`Authorization: Bearer` (decode `exp`); a `WWW-Authenticate` challenge →
Basic/Bearer. Session state holds cookies **and** headers/tokens per `(host,
identity)`.
- **Accept:** against fixtures, a cookie login yields a reused cookie; a JSON+JWT
  login yields a reused bearer with `exp` parsed; a Basic challenge is satisfied.

### T1.4 — Success/expiry detection + single-flight re-auth + fail-loud
Confirm login by differential behavior (a protected probe stops redirecting to
login). Detect expiry (401/403, redirect to the detected login, login form
reappears, JWT `exp`) and re-authenticate under a single-flight lock; cap attempts
then hard-fail. When detection can't parse a login, **fail loudly** with
diagnostics (what was found, where it stopped).
- **Accept:** concurrent expiry triggers exactly one login (call-counting mock);
  after the cap, `ensure` raises; a deliberately unparseable login produces a clear
  diagnostic failure, never a silent unauthenticated run.

### T1.5 — Session API wired into the HTTP seam
Implement `prepare`/`observe`/`ensure` resolved by the request's host, and wire the
real manager into the `core/` HTTP seam (replacing the Phase 0 addon stub).
`prepare` applies the detected session; `observe` updates it and watches for logout.
- **Accept:** a request through the seam carries the right session for its host and
  identity (cookie or bearer, per detection); `observe` records updates.

### T1.6 — Identities per host
Model `anonymous`/`user`/`admin` per host, each with its own session state and
connection pool, drawing the right credentials from the vault.
- **Accept:** two identities on the same host hold independent sessions.

### T1.7 — Redaction + non-secret session-state persistence
Redact credentials/cookies/tokens on every write to the store and logs; persist
only non-secret session state (host, identity, auth status, timestamps) so a
crashed run resumes.
- **Accept:** a store/log scan finds no cleartext secret; a resumed run reuses the
  persisted non-secret state.

### T1.8 — Auth-endpoint exclusion from fuzzing
Auto-exclude the detected auth endpoints (login/logout/session-destroy) from
fuzzing scope so the fuzzer cannot log itself out.
- **Accept:** the fuzzing scope excludes the detected auth endpoints; a test
  asserts they are never selected as targets.

### T1.9 — Standalone use
Print a ready-to-use cookie/header/token for a given identity on a given host
(e.g. `fuzzlab session --host <host> --identity user --print`).
- **Accept:** the command prints a valid credential for the identity and sends
  nothing else.

### T1.10 — Per-identity runs on PFF + an external lab
Run the crawler and fuzzer per identity through the session manager against the
Puppy Fort Factory (cookie) and one external lab with a different scheme (JWT),
recording results tagged by identity (add an `identity` column where needed via a
new, append-only migration, or derive via `flow.identity`).
- **Accept:** full crawl + fuzz stays authenticated end-to-end on both hosts with
  only saved credentials (no per-host config), and results are attributable to the
  identity that produced them.

## Exit criterion

With only saved credentials and no per-host auth config, the crawler and fuzzer
stay authenticated through a full run on a cookie lab **and** a JWT lab, results
per identity; login/session/success/expiry are all detected dynamically;
concurrent expiry produces one re-auth; an unparseable login fails loudly; fuzzing
never logs itself out; no secret is written in cleartext; and it runs headless via
the encrypted-file credential backend.

## Out of scope for Phase 1 (deferred)

Attacking authentication (a testing target the tools handle); MFA/TOTP (out of
scope for detection-only; revisit if a target needs it); OAuth interactive
redirect flows; proxy-addon integration (the API is addon-friendly, but the proxy
itself is Phase 6).

## To confirm during the build

- Detection heuristics for multi-form pages (which form is the login) and SPA
  logins where login is an XHR, not an HTML form.
- Keyring passphrase handling in CI (env vs. prompt) and the encrypted-store path.
- Whether to add an `identity` column to `attempt`/`finding` (a migration) or
  attribute via `flow.identity`.
- How aggressively to probe for a login when the crawler hasn't found a form.

## Known risks

- **Detection can't parse a login.** Accepted trade-off (zero per-host config);
  mitigated by failing loudly with diagnostics, never running silently
  unauthenticated, and improving detection over time.
- **Silent session failure poisons data.** Mitigated by differential success
  checks, multi-signal expiry detection, the single-flight lock, and
  capped-then-hard-fail re-auth.
- **Storing secrets.** Mitigated by the per-host credential store
  (keyring/encrypted file), redaction on write, and not persisting live
  cookies/tokens in cleartext.
- **Fuzzing an auth endpoint and logging out.** Mitigated by auto-exclusion (T1.8).
- **Re-auth during timing-sensitive fuzzing.** A mid-measurement login distorts
  timing; ensure re-auth happens outside timing windows (coordinate with the
  budget manager's per-host timing mutex).
