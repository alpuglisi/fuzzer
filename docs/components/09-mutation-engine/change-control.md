# Mutation Engine — Change Control Log

Component code: **MUT**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-MUT-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented;
  payloads today come only from the static catalog.
- Impact (other components / project): once built, it feeds new candidates back
  into the catalog/attempts, so its variants flow through the scheduler, fuzzer,
  and oracle like any payload. Its search depends on grey-box coverage (LAB) and
  the scheduler for operator selection; it benefits from the auditor's sink-context
  typing for XSS generation.
- Risk (level; mitigation): medium — meaning-changing mutations produce false
  candidates and waste budget; generated payloads could be destructive. Mitigated
  by a semantics-preservation validator, the default-off destructive gate applying
  to generated payloads, budget-bounded reproducible search, and keeping any LLM
  expansion offline and human-gated. Scheduled late (Phase 8), after the oracle,
  scheduler, and grey-box exist.
- Deliverables:
  - [ ] AST parsing + typed semantics-preserving SQL operators — todo (Phase 8).
  - [ ] Context-typed XSS generation — todo (Phase 8).
  - [ ] Filter-transformation learning from canaries — todo (Phase 8).
  - [ ] Bandit-scheduled operators + coverage-guided hill climbing — todo (Phase 8).
  - [ ] Gated offline LLM catalog expansion (default off) — todo (Phase 8).
  - [ ] Write new candidates back to catalog/attempts — todo (Phase 8).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  coverage reached beyond the static catalog and by the semantics validator's
  rejection of meaning-changing transformations.
