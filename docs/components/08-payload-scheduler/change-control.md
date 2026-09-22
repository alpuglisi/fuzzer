# Payload Scheduler (Bandit) — Change Control Log

Component code: **SCHED**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-SCHED-0005 — Mutation-variant candidate source, wired into the live attempt path (2026-09-22)
- Change: closes a confirmed wiring gap (verified by grep, not inference): the mutation
  engine's `payload_variant` table (MUT, migration 8) was write-only — nothing in the
  scheduler/candidate/fuzzer pipeline read it back in as candidates. New
  `fuzzlab/scheduler/variants.py` adds `VariantCandidate`, `load_variant_candidates`
  (reads `payload_variant`, optionally scoped by `vuln_class`/`vuln_classes`/
  `sink_context`/`run_id`, bounded by `limit`, `semantics_ok`-filtered by default) and
  `variant_probe_specs` (maps rows to `greybox.run.ProbeSpec`s, `family="mut:<vuln_class>:
  <row id>"` for traceability back to the exact row). This is the same candidate-source
  shape as the existing static-catalog reader (`catalog_families`/`catalog_priors` over
  `references/<category>/payloads/*.txt`), extended to a second, DB-backed catalog
  rather than replacing the first. Exported from `fuzzlab.scheduler`. Wired into
  `fuzzlab greybox-run` via two new opt-in flags, `--mutation-variants` (default off)
  and `--mutation-limit` (default 25): when set, the resulting probes are appended to
  (never substituted for) `run_greybox`'s `DEFAULT_PROBES`, scoped to the run's known
  vuln classes when the points carry one (ground-truth runs), else pooled across all
  recorded variants. `greybox-run` already refuses to run at all without `--authorized`
  (D11) regardless of this flag, so the new source inherits that same gate rather than
  needing (or getting) a separate one.
- Impact (other components / project): mirrored in
  `docs/components/09-mutation-engine/change-control.md` (CC-MUT-0009) since it reads
  MUT's table and closes MUT's own stated "still sent through the attempt path" gap
  (see the `payload_variant` migration comment in `fuzzlab/core/migrations.py`).
  Requirements: FR-SCHED-9 (this doc) and FR-MUT-8 (mirrored). No schema change; default
  behavior unchanged (opt-in, off by default).
- Risk (level; mitigation): low-medium — a new path that, once opted into, sends real
  mutation-engine payloads at the (lab) target. Mitigated by: default-off, additive
  (never replaces the default probes), `--mutation-limit`-bounded, and gated by the
  existing unconditional `--authorized` check on `greybox-run`. Tests:
  `tests/test_scheduler_variants.py` (10 — round-trip of a real `payload_variant` row;
  scoping by vuln_class/sink_context/run_id; `semantics_ok` filtering; `limit`;
  `ProbeSpec` shape + family-to-row traceability; vuln_class->kind mapping; and an
  end-to-end real-`Store`-plus-fake-sender `run_greybox` call proving the actual variant
  string is sent and produces a real, correctly-attributed `attempt` row — not a mock of
  this module's own internals) and `tests/test_greybox_cli_mutation_variants.py` (4 —
  flag parsing/defaults; `--authorized` still required with the new flag set; `main()`
  merges variants additively when set; `main()` ignores a real, present
  `payload_variant` row when the flag is not set). Full suite: 1591 passed, 8 skipped,
  12 deselected — no regressions.
- Deliverables:
  - [x] `fuzzlab/scheduler/variants.py` + `fuzzlab.scheduler` export — done.
  - [x] `fuzzlab greybox-run --mutation-variants`/`--mutation-limit`, additive,
    `--authorized`-gated wiring — done.
  - [x] Round-trip + CLI tests, no regressions — done.
  - [x] FR-SCHED-9, FR-MUT-8, `docs/ARCHITECTURE.md` Phase 8 status — done.
  - [ ] On-lab: measure whether mutation-variant probes actually raise attempt yield
    vs the default set alone — on-host, future work.
- Effectiveness (assessed 2026-09-22): effective for the wiring gap itself — a real
  `payload_variant` row now demonstrably reaches a real `attempt` row through the live
  grey-box path, additively and behind the standard authorization gate; whether it
  improves live-lab yield is unmeasured pending on-host use.

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
