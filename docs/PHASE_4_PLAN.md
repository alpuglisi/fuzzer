# Phase 4 — Bandit scheduler (plan)

Spend requests where they pay off. Phases 0–3 confirm findings and produce a reward
signal; Phase 4 uses that reward to **choose which payload family to try next**, so a
run finds the known vulnerabilities in fewer requests than uniform selection.

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (Phase 4), the reserved
`bandit_posteriors` table in `fuzzlab/core/migrations.py`, the reward in
`fuzzlab/greybox/reward.py` (Phase 3), and `docs/PREVENTIVE_ACTIONS.md`.*

## Goal

A scheduler that, per **context** (a discrete bucket — vuln class + sink, or endpoint
template), picks a payload-family **arm**, observes the shaped reward, and learns which
families pay off where — beating a uniform control on hits-per-N requests, with
posteriors that persist across runs.

## Status (2026-09-21)

`[in progress — learning core + oracle wiring built offline]`. The schema reserves
`bandit_posteriors` (context, arm, alpha, beta). Built and unit-tested
(`fuzzlab/scheduler/` + oracle wiring, ~20 tests):
- **T4.1** `ThompsonBandit` (per-(context, arm) Beta, `select`/`order`/`update`/
  `best_arm`, `load`/`save`), `UniformScheduler` control, beat-uniform simulation.
- **T4.2** context buckets (`context_for` = `category:sink|location`), mechanism warm
  starts (`arm_priors`, cheap/strong mechanisms ahead), and a `references/`-derived
  payload-family reader (`catalog_families`/`catalog_priors`) for the future
  payload-level bandit.
- **T4.3** the bandit **orders the oracle's applicable mechanisms** per context in
  `Oracle.confirm` (productive mechanism first → the confirmation short-circuits the
  expensive ones), updating on outcome; threaded through `run_pipeline`/`run_auto` and
  `fuzzlab auto --bandit`, with posteriors loaded/saved around the run. A test shows a
  trained bandit reaches the confirming mechanism with **fewer probes** than a fresh one.

## Principles (this phase)

- **Deterministic tests, stochastic method.** The RNG is injected so Thompson sampling
  is reproducible in tests; production seeds from entropy.
- **Reward composes (Phase 3).** The bandit consumes the shaped reward in [0, 1]
  (`greybox.shaped_reward`: screening / coverage-novelty / db_fault), so exploration is
  driven by the same causal signal, not a flattened bit.
- **A control condition, always.** Every bandit claim is measured against
  `UniformScheduler` on held-out pages — no baseline, no result.
- **Persist and resume.** Posteriors live in `bandit_posteriors`, so learning carries
  across runs and is inspectable in the panel.
- **Safety unchanged.** The scheduler only *orders* payloads already permitted by the
  run plan/scope; destructive classes stay off; it sends no traffic itself.

## Tasks

- **T4.1 — Learning core (done, offline).** `ThompsonBandit` + `UniformScheduler` +
  posterior persistence + the beat-uniform simulation. `fuzzlab/scheduler/`.
- **T4.2 — Context buckets & catalog priors (done, offline).** `context_for` buckets by
  `category:sink|location`; `arm_priors` warm-starts the oracle mechanisms from a
  cost/reliability model (cheap+strong ahead); `catalog_families`/`catalog_priors` read
  the `references/` payload catalogs for the future payload-level bandit.
- **T4.3 — Wire into the confirm loop (done, offline).** `Oracle.confirm` orders its
  applicable mechanisms via `scheduler.order(context, arms)` and `update`s on outcome,
  so the productive mechanism is front-loaded and a confirmation skips the expensive
  ones. Threaded through `run_pipeline`/`run_auto` and `fuzzlab auto --bandit`;
  posteriors load/save around the run. The live request reduction is measured on the lab
  (T4.6). (The payload-family selection *within* a mechanism, using `catalog_priors`, is
  the later fuzzer-loop application.)
- **T4.4 — Cost-normalized selection (done, offline).** Each observation records a cost
  (the oracle passes the mechanism's probe count); with `cost_normalized`, ordering
  divides the sampled reward by the arm's mean cost, so a cheap informative arm beats an
  expensive one of equal reward. Costs persist in `bandit_posteriors` (migration 5).
- **T4.5 — Hierarchical backoff (done, offline).** With `backoff`, a fresh (context,
  arm) is seeded from the first coarser context that has data (`context_parents`:
  `cat:facet` → `cat` → root), so a cold bucket borrows strength, then specializes.
  Both are enabled on the live `fuzzlab auto --bandit`.
- **T4.6 — Exit measurement (on-lab).** Plot the bandit vs `UniformScheduler` on
  hits-per-1000-requests over held-out pages; the bandit must win.

## Exit criterion

On held-out pages, the bandit finds the known vulnerabilities in **measurably fewer
requests** than uniform selection (hits-per-1000-requests), with posteriors persisted
and a uniform control run for comparison.

## Component mapping

- **SCHED (08)** — the scheduler package (`fuzzlab/scheduler/`), priors, cost model,
  backoff.
- **FUZZ (07)** — wiring `select`/`update` into the fuzz/auto loop.
- **CORE (02)** — `bandit_posteriors` persistence (reserved schema; no migration).

## Out of scope for Phase 4 (deferred)

- The detection **classifier** and conformal abstention — Phase 5.
- New reward *sources* — the grey-box signals come from Phase 3; Phase 4 only consumes
  the reward.
