# Plugin System — Change Control Log

Component code: **PLUG**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-PLUG-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented. The
  hook set is defined so later components (ML, extra rules, custom oracles) can be
  built as plugins from the start.
- Impact (other components / project): once built, the ML components attach here,
  and extra rules/payload sources/oracles register through it — it is how the
  toolkit extends without core edits (D6). Depends only on `core/`. It enforces
  part of the store contract at the boundary (only an oracle plugin may write
  `finding`).
- Risk (level; mitigation): low–medium — in-process plugins could destabilize a
  run or (via `register_oracle`) write labels wrongly. Mitigated by per-plugin
  isolation with contained failures, recorded plugin versions for reproducibility,
  and enforcing the oracle/advisory split at the hook boundary. Sequenced last
  (Phase 10), after the components that will consume it are understood.
- Deliverables:
  - [ ] Entry-point discovery (`importlib.metadata`) — todo (Phase 10).
  - [ ] Hook registry (request/response/candidate/finding/rules/payload/oracle) — todo (Phase 10).
  - [ ] Per-plugin isolation + priority ordering — todo (Phase 10).
  - [ ] Oracle/advisory split enforced at the boundary — todo (Phase 10).
  - [ ] Active-plugin set/versions recorded on the run — todo (Phase 10).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by a
  sample plugin registering on each hook, a failing plugin being contained without
  aborting the run, and the toolkit running unchanged with zero plugins.
