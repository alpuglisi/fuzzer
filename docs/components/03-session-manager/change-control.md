# Session Manager — Change Control Log

Component code: **SESS**. Entry format and required fields: see `../README.md`.
Newest first.

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
