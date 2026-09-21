# Payload Scheduler (Bandit) — Change Control Log

Component code: **SCHED**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-SCHED-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented;
  payload selection today is fixed/enumerated by the fuzzer.
- Impact (other components / project): once built, it sits between the auditor's
  candidates and the fuzzing harness, consuming oracle/grey-box reward. Its value
  depends on the oracle being trustworthy (FUZZ) and, for dense reward, on grey-box
  instrumentation (LAB). Adds the `bandit_posteriors` table to the store contract.
- Risk (level; mitigation): medium — a bandit optimizing on a noisy or wrong
  reward wastes budget or chases false signal. Mitigated by taking reward only from
  the deterministic oracle, keeping a uniform-random control to measure real lift,
  hierarchical backoff for data-poor contexts, and cost-normalized selection.
  Building it after the oracle (Phase 4, post Phase 2/3) ensures the reward exists
  first.
- Deliverables:
  - [ ] Family-arm model + context buckets — todo (Phase 4).
  - [ ] Hierarchical Thompson sampling with backoff — todo (Phase 4).
  - [ ] Catalog-derived priors — todo (Phase 4).
  - [ ] Cost-normalized selection — todo (Phase 4).
  - [ ] Persisted posteriors (`bandit_posteriors`) — todo (Phase 4).
  - [ ] Uniform-selection control + lift measurement — todo (Phase 4).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  confirmed-findings-per-request lift over the uniform control on the lab.
