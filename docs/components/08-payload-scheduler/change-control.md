# Payload Scheduler (Bandit) — Change Control Log

Component code: **SCHED**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-SCHED-0002 — Bandit learning core (Phase 4 groundwork, offline) (2026-09-21)
- Change: added `fuzzlab/scheduler/` — `ThompsonBandit` (Beta-Bernoulli Thompson
  sampling per (context, arm), catalog priors, `select`/`update`/`mean`/`best_arm`,
  and `load`/`save` to the reserved `bandit_posteriors` table) and `UniformScheduler`
  (the control that ignores feedback). The RNG is injected so the method is stochastic
  but the tests are deterministic. Consumes a reward in [0, 1] (the Phase 3 shaped
  reward). Wrote `docs/PHASE_4_PLAN.md` and pointed the roadmap at it.
- Impact (other components / project): gives Phase 4 its learning core and control,
  ready to wire into the fuzz/auto loop (T4.3) to spend fewer requests. Fills the
  reserved `bandit_posteriors` (no migration). No live traffic; the scheduler only
  orders payloads the run plan already permits.
- Risk (level; mitigation): low — pure, dependency-light logic, no I/O beyond the
  posterior table. Mitigated by 7 tests (Beta update math incl. fractional/clamped
  reward; learning + best_arm; catalog priors; deterministic seeded select; a
  beat-uniform simulation where the bandit finds the good arm and beats the control on
  hits; posterior persistence round-trip with UNIQUE upsert). Suite 169 passed / 2 skipped.
- Deliverables:
  - [x] `ThompsonBandit` + `UniformScheduler` + `bandit_posteriors` persistence — done.
  - [x] Beat-uniform simulation (exit-in-miniature) + tests — done.
  - [x] `docs/PHASE_4_PLAN.md`; roadmap pointer — done.
  - [ ] Context buckets + catalog-derived priors (T4.2) — next.
  - [ ] Wire into the fuzz/auto loop + cost-normalization + backoff (T4.3–T4.5) — later.
  - [ ] On-lab exit: beat uniform on hits-per-1000-requests (T4.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the bandit learns the
  paying arm and beats uniform on hits in simulation, and posteriors persist; live
  request-reduction pending the loop wiring + lab.

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
