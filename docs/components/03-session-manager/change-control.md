# Session Manager — Change Control Log

Component code: **SESS**. Entry format and required fields: see `../README.md`.
Newest first.

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
