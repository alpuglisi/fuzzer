# Session Manager — Change Control Log

Component code: **SESS**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-SESS-0005 — Session manager implemented (Phase 1) (2026-09-21)
- Change: built `fuzzlab/session/` — `state.py` (SessionState: cookies + tokens per
  host/identity; redaction; JWT-time expiry), `detect.py` (dynamic login-form
  detection with fresh hidden/CSRF carry-through; session-credential detection for
  cookie / JSON-token+JWT / Basic challenge; success + logout detection; base64url
  JWT `exp`), and `manager.py` (`prepare`/`observe`/`ensure`, identities per host,
  single-flight re-auth, fail-loud on unparseable logins, auth-endpoint exclusion,
  standalone `session_header`). Added a `fuzzlab session` CLI (set-credential /
  print). Drop-in addon for the `core/` HTTP seam. Realizes T1.2–T1.9.
- Impact (other components / project): the crawler/auditor/fuzzer can authenticate
  by routing HTTP through the seam with this addon; depends on the credential store
  (CC-CORE-0004). Detection-only per D13; no per-host profiles. No store-schema
  change (non-secret session-state persistence method exists but is not yet wired
  to a table — deferred, see below).
- Risk (level; mitigation): medium–high (auth correctness). Mitigated by: fail-loud
  with diagnostics (never a silent unauthenticated run), differential success
  verification, multi-signal logout detection, single-flight re-auth with a cap,
  auth-endpoint exclusion, secret redaction, and 17 unit tests (cookie + JWT login,
  wrong-creds/no-form/missing-creds/out-of-scope failures, single-flight one-login,
  auth-endpoint exclusion, observe→re-auth, standalone header, seam integration).
- Deliverables:
  - [x] SessionState + detection + manager (T1.2–T1.6, T1.8) — done.
  - [x] Fail-loud on unparseable logins (FR-SESS-6) — done.
  - [x] Standalone `session_header` + `fuzzlab session` CLI (T1.9) — done.
  - [x] Redaction of secrets in logs/repr (T1.7 redaction) — done.
  - [ ] Persist non-secret session state to a store table (T1.7 resume) — todo.
  - [ ] Migrate tool HTTP onto the seam + live two-lab validation (T1.10) — todo (needs a runnable lab; cookie path validated on PFF, JWT path on an external lab).
- Effectiveness (assessed 2026-09-21): effective in unit tests (17/17 for the
  session package; 60/60 suite) — cookie and JWT logins detected and handled,
  single-flight confirmed, unparseable logins fail loud. Live end-to-end on the
  containerized lab and an external JWT lab is pending an environment with a
  container daemon / network to those labs.

### CC-SESS-0004 — Planned: adopt proxy-captured manual sessions (spec) (2026-09-21)
- Change: added FR-SESS-11 `[planned, post-Phase 6]` — for logins detection can't
  parse (the FR-SESS-6 fail-loud cases: MFA, CAPTCHA, multi-step, exotic SPA), the
  session manager adopts a session captured by the proxy from a manual browser
  login (FR-PROXY-9) as the live session state for `(host, identity)`, still with
  no per-host config; interactive-login expiry prompts for re-capture. Resolves the
  MFA/SPA open questions as "handled post-Phase 6." Spec only — no code.
- Impact (other components / project): closes the accepted detection-only gap
  without reintroducing per-host profiles. Adds a post-Phase 6 dependency on the
  proxy (component #11, FR-PROXY-9). Recorded in D13 and the Phase 6 roadmap;
  `ARCHITECTURE.md` #3 updated.
- Risk (level; mitigation): low (planning). When built, captured cookies/tokens are
  secrets — mitigated by the existing redaction and no-cleartext-persistence rules
  (NFR-SESS-redaction, FR-SESS-9). Interactive re-auth can't be automated; mitigated
  by prompting for re-capture rather than silently failing.
- Deliverables:
  - [x] FR-SESS-11 recorded; open questions resolved to post-Phase 6 — done.
  - [ ] Implement session adoption from a proxy capture — todo (post-Phase 6).
- Effectiveness (assessed or pending): pending — depends on the proxy (Phase 6).

### CC-SESS-0003 — Detection-only auth + per-host credentials (spec) (2026-09-21)
- Change: per user direction, superseded the profile-first framing of CC-SESS-0002.
  Auth is now **detection-only** (D13, revised): the session manager detects each
  host's login, session credential, success, and expiry dynamically and handles
  them, with **no hand-written per-host profiles or overrides**; a login detection
  cannot parse **fails loudly**. Credentials are **saved per host** (D12, revised:
  vault keyed by `(host, identity)`) and passed to the host they belong to. The
  auth handlers (cookie/form, JSON+token, Basic, header-key) remain internally but
  are selected by detection, not authored by the user. Rewrote FR-SESS-1…10 around
  detection + per-host credentials; NFR-SESS-extensible → NFR-SESS-zero-config.
  Spec/plan only — no code.
- Impact (other components / project): removes the per-lab profile authoring the
  previous entry introduced; the only per-host input is credentials in the vault.
  The crawler is now a (soft) dependency — discovered forms help locate the login.
  Updated D12/D13 in `DECISIONS_AND_ROADMAP.md`, `ARCHITECTURE.md` #3, and
  `PHASE_1_PLAN.md`. Supersedes CC-SESS-0002's profile/strategy-authoring parts;
  the credential-store backend resolution from CC-SESS-0002 stands (now per-host).
- Risk (level; mitigation): medium–high. Detection-only is less predictable than
  declared profiles — a login it cannot parse fails (accepted trade-off, chosen for
  zero per-host config). Mitigated by fail-loud with diagnostics (never a silent
  unauthenticated run), differential success/expiry checks, single-flight re-auth,
  auth-endpoint exclusion, credential-store redaction, and validating first on the
  known cookie lab then a JWT lab. The accepted limitation (complex logins fail
  until detection improves) is documented in D13 and the spec.
- Deliverables:
  - [x] Spec rewritten for detection-only + per-host credentials — done.
  - [x] D12/D13 revised; `ARCHITECTURE.md` #3 + `PHASE_1_PLAN.md` updated — done.
  - [ ] Implement the login/session detector (FR-SESS-3…6) — todo (Phase 1).
  - [ ] Per-host credential vault + lookup by host (D12) — todo (Phase 1).
  - [ ] Fail-loud diagnostics for unparseable logins — todo (Phase 1).
- Effectiveness (assessed or pending): pending — spec-level. Judged in Phase 1 by
  authenticated runs on a cookie lab and a JWT lab with only saved credentials
  (no per-host config), and a clear failure on a deliberately unparseable login.

### CC-SESS-0002 — Multi-target auth + settled credential store (spec) (2026-09-21)
- Change: expanded the requirement spec before building, in response to the need to
  validate on several other lab environments (D10). Made the component
  **target-profile-driven** and **auth-scheme-pluggable** (new FR-SESS-9/10;
  generalized FR-SESS-1/3/4/7/8; new NFR-SESS-portable/extensible) and settled the
  **credential store** as an OS-keyring abstraction with an encrypted-file headless
  fallback and a gated lab-only env fallback (FR-SESS-6). Recorded as decisions D12
  (credential store) and D13 (multi-target auth). No code yet — spec/plan only.
- Impact (other components / project): the session manager can now log in and hold
  sessions across many labs (cookie/form, JSON+JWT, Basic, header key, scripted),
  which unblocks D10 external validation (WAVSEP, Juice Shop, …). Adds two
  extension points (auth strategies, target profiles) that the plugin system
  (component #13) will later expose; `core/` gains a credential-store abstraction
  (D12). `ARCHITECTURE.md` component #3 and `PHASE_1_PLAN.md` updated to match.
- Risk (level; mitigation): medium — a broader surface (multiple schemes, profiles,
  a pluggable interface) is more to get right, and mis-scoped auth silently
  corrupts data across tools. Mitigated by keeping per-target quirks in data
  (profiles) not code, one narrow `AuthStrategy` interface, the single-flight lock,
  auth-endpoint exclusion, credential-store redaction, and validating first on the
  known lab (cookie) then one external JWT lab before trusting broadly.
- Deliverables:
  - [x] Spec: target profiles, pluggable strategies, credential store (FR-SESS-6/9/10) — done.
  - [x] Decisions D12/D13 recorded; `ARCHITECTURE.md` #3 + `PHASE_1_PLAN.md` updated — done.
  - [ ] Implement the credential store (D12) — todo (Phase 1 T1.x).
  - [ ] Implement `AuthStrategy` + built-in strategies + profiles — todo (Phase 1).
  - [ ] Ship profiles for the chosen validation labs — todo (pending the lab list).
- Effectiveness (assessed or pending): pending — spec-level change. Judged in
  Phase 1 by authenticated runs across ≥2 auth schemes/labs and a headless/CI run.

### CC-SESS-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented; tools
  currently run unauthenticated or with ad-hoc handling.
- Impact (other components / project): once built, the crawler, auditor, fuzzer,
  and proxy all route auth through it; it is a hard dependency for any
  authenticated testing and for authorization (IDOR/BOLA) work later.
- Risk (level; mitigation): medium — silent session failure corrupts data across
  every tool. Mitigated by building it early (Phase 1, before most tools rely on
  auth), the single-flight lock, capped re-auth, and auto-excluding auth
  endpoints from fuzzing.
- Deliverables:
  - [ ] Identity model + cookie jar — todo (Phase 1).
  - [ ] `prepare`/`observe`/`ensure` + single-flight re-auth — todo (Phase 1).
  - [ ] CSRF extraction + JWT `exp` handling — todo (Phase 1).
  - [ ] Keyring credentials + redaction — todo (Phase 1).
- Effectiveness (assessed or pending): pending — not yet built.
