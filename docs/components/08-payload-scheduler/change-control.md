# Payload Scheduler (Bandit) — Change Control Log

Component code: **SCHED**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-SCHED-0005 — Per-pull metric emission: regret/cumulative + posterior/arm_<N>/mean (R-05) (2026-09-22)
- Change: `ThompsonBandit` (`fuzzlab/scheduler/bandit.py`) gained optional per-pull
  metric emission into the shared `metric_series` sink added by B0/CC-CORE-0018.
  `attach_metrics(metrics: MetricLogger | None)` attaches (or clears) a
  `fuzzlab.core.store.MetricLogger`; every subsequent `update(context, arm, reward,
  cost=…)` call (one bandit pull) then, under `source="bandit"`: (1) logs
  `regret/cumulative` — a running sum of pseudo-regret, computed each pull as
  `max(0, best_known_posterior_mean_in_context_before_this_pull - reward)`, using the
  bandit's own belief state (no extra caller-supplied "optimal arm" needed); and (2)
  logs `posterior/arm_<N>/mean` for the arm just played, where `<N>` is a stable,
  first-seen-order index per distinct arm name (assigned once, reused every pull of
  that arm). `flush_metrics()` flushes any buffered rows (no-op if nothing attached).
  With no `attach_metrics` call (the default), `update()`'s selection/posterior math
  and its return value are byte-for-byte unchanged — purely additive/observational.
  Wired into the existing `fuzzlab auto --bandit` path in
  `fuzzlab/harness/auto_cli.py`: right after `scheduler.load(store)`, a
  `MetricLogger(store, run_id, "bandit")` is attached; right before
  `scheduler.save(store)`, `scheduler.flush_metrics()` commits the buffer. No change
  to `fuzzlab/oracle/oracle.py` (the actual per-candidate confirmation loop that
  calls `scheduler.update()`) was needed — it already just calls `update()`, which now
  emits when a logger is attached upstream.
- Impact (other components / project): unblocks R-05's diagnostics UX (U5 "bandit
  cumulative-regret + per-arm posterior-mean" panel) — `metric_series` now actually
  receives `bandit` rows during a `--bandit` run, not just the `gbt`/`logreg` writers
  from other Wave-1b lanes. CORE (`metric_series`/`log_scalar`/`MetricLogger`, read
  only) and the oracle (`fuzzlab/oracle/oracle.py`, unchanged — still just calls
  `scheduler.update()`) are the only other components touched/consulted; both are
  additive/read-only from the oracle's side. `fuzzlab/mutation/search.py`'s
  `MutationSearch` also holds a `ThompsonBandit` but has no `store`/`run_id` to attach
  a logger to yet — left un-wired (out of scope; no behavior change there).
- Risk (level; mitigation): low — new methods (`attach_metrics`, `flush_metrics`) plus
  a guarded `if self._metrics is not None:` block inside `update()`; the default
  (unattached) path is untouched code executing the same statements as before this
  change. Non-finite values can't reach `metric_series` (rejected by
  `log_scalar`/`MetricLogger.log` itself, per CC-CORE-0018). Mitigated by tests:
  `tests/test_scheduler.py` (rows land with `source="bandit"`, expected keys/steps,
  cumulative regret non-decreasing, posterior mean rises with reward, attaching a
  logger does not change selection/posterior outputs vs. an unattached bandit with the
  same seed) and `tests/test_auto.py::test_run_auto_with_bandit_emits_metric_series`
  (end-to-end through a real `run_auto()` pass — the same call path
  `auto_cli.py`/`harness/pipeline.py`/`oracle.py` use in production). Full suite green
  (see CHANGELOG entry for the pass/skip count run for this change).
- Deliverables:
  - [x] `ThompsonBandit.attach_metrics`/`flush_metrics` + per-pull emission in
    `update()` — done.
  - [x] Wired into `fuzzlab auto --bandit` (`auto_cli.py`) — done.
  - [x] Tests: unit (`test_scheduler.py`) + end-to-end via `run_auto`
    (`test_auto.py`) — done.
  - [x] `requirements.md` updated (new `FR-SCHED-9`) — done.
  - [ ] Wire the same attach into `MutationSearch` (`fuzzlab/mutation/search.py`) once
    it gains a `store`/`run_id` — later, tracked as a MUT-side follow-up (out of this
    lane's scope: MUT owns that file, and it currently has no store handle to attach
    to at all).
- Effectiveness (assessed 2026-09-22): effective — `metric_series` rows with
  `source="bandit"`, `regret/cumulative`, and `posterior/arm_<N>/mean` are written on
  every pull of a real `--bandit` run (verified via `run_auto` in the test above);
  live-lab UI rendering of the R-05 diagnostics panel is a later U5 lane's job.

### CC-SCHED-0004 — Cost-normalized selection (T4.4) + hierarchical backoff (T4.5) (2026-09-21)
- Change: `ThompsonBandit` gained two opt-in refinements. **Cost-normalized** (T4.4):
  `update(context, arm, reward, cost=…)` records a running mean cost; with
  `cost_normalized`, `order`/`select` divide the sampled reward by the arm's mean cost
  (reward-per-cost), so a cheap informative arm beats an expensive one of equal reward.
  Costs persist in `bandit_posteriors` (`cost_sum`/`cost_n`, migration 5). **Backoff**
  (T4.5): with `backoff`, a fresh (context, arm) is seeded from the first coarser
  context that has data (`context_parents`), borrowing strength. The oracle passes each
  mechanism's probe count as its cost; `fuzzlab auto --bandit` enables both.
- Impact (other components / project): the bandit now prefers cheap, productive
  mechanisms (fewer/faster probes) and warms up cold contexts from related ones — both
  improve the Phase 4 request-reduction. Defaults off (existing callers unchanged).
- Risk (level; mitigation): low — opt-in, pure logic. Mitigated by tests
  (`test_scheduler.py`: cost-normalized prefers the cheaper arm; cost persists; backoff
  inherits parent strength; `test_scheduler_context.py`: `context_parents`). Suite 183
  passed / 2 skipped.
- Deliverables:
  - [x] Cost tracking + cost-normalized ordering; migration-5 persistence — done.
  - [x] `context_parents` + backoff prior seeding — done.
  - [x] Oracle passes mechanism cost; `auto --bandit` enables both — done.
  - [ ] On-lab: confirm cost-normalization/backoff help the live numbers (T4.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — cheaper arms win under equal
  reward and cold contexts inherit parent tendency; live tuning pending the lab.

### CC-SCHED-0003 — Context buckets, priors, catalog reader, arm ordering (T4.2) (2026-09-21)
- Change: added `fuzzlab/scheduler/context.py` — `context_for` (bucket =
  `category:sink|location`), `arm_priors` (cost/reliability warm starts for the oracle
  mechanisms — cheap/strong mechanisms like error-signature start ahead of expensive
  ones like differential-timing), and `catalog_families`/`catalog_priors` that read the
  `references/<category>/payloads/*.txt` catalogs (payload-family arms + weak
  size-scaled priors) for the future payload-level bandit. Added `ThompsonBandit.order`
  and `UniformScheduler.order` (a full arm ordering) to drive the oracle's mechanism
  ordering (T4.3).
- Impact (other components / project): gives the bandit its context keys and warm
  starts, and honestly incorporates the `references/` catalogs (T4.2's literal ask).
  No traffic; pure/offline.
- Risk (level; mitigation): low — pure functions + a filesystem read of the repo's
  `references/`. Mitigated by tests (`tests/test_scheduler_context.py`: buckets, priors
  favor cheap mechanisms, catalog families read, size-scaled priors; order tests in
  `test_scheduler.py`). Suite 179 passed / 2 skipped.
- Deliverables:
  - [x] `context_for`, `arm_priors`, `catalog_families`/`catalog_priors` — done.
  - [x] `order()` on both schedulers — done.
  - [ ] Payload-family bandit wired into the fuzzer loop using `catalog_priors` — later.
- Effectiveness (assessed 2026-09-21): effective — contexts/priors feed the oracle
  bandit (CC-FUZZ-0015) and the catalog reader returns real families from `references/`.

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
