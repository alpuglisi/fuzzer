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

`[in progress — learning core built offline]`. The schema already reserves
`bandit_posteriors` (context, arm, alpha, beta). Built and unit-tested
(`fuzzlab/scheduler/`, 7 tests):
- `ThompsonBandit` — Beta-Bernoulli Thompson sampling per (context, arm), catalog
  priors, `select`/`update`/`mean`/`best_arm`, and `load`/`save` to `bandit_posteriors`;
- `UniformScheduler` — the control (ignores feedback);
- a deterministic beat-uniform simulation (the bandit finds the good arm and beats
  uniform on hits) — the Phase 4 exit in miniature, offline.

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
- **T4.2 — Context buckets & catalog priors.** Define the context key (vuln class +
  sink, coarse enough to share evidence, fine enough to matter) and derive per-family
  priors from the `references/` payload catalogs (families that historically pay off
  start ahead). Offline-testable from the catalogs.
- **T4.3 — Wire into the fuzz/auto loop.** Replace the fuzzer's fixed payload order with
  `scheduler.select(context, families)` → send → `update(context, family, reward)`,
  loading/saving posteriors around the run. Behind the existing seams; the live request
  reduction is measured on the lab.
- **T4.4 — Cost-normalized selection.** Weight by reward-per-second (a `sleep`-heavy
  timing family costs more wall-clock than an error probe), so the bandit prefers cheap
  informative arms. Offline-testable with synthetic costs.
- **T4.5 — Hierarchical backoff.** Fall back from a specific context to a coarser one
  when a bucket has little data, so cold contexts borrow strength. Offline-testable.
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
