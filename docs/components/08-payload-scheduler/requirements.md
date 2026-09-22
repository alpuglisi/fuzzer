# Payload Scheduler (Bandit) — Requirement Specification

Component code: **SCHED** · Status: `[planned]` (Phase 4) · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #8; `DECISIONS_AND_ROADMAP.md` (D1, D5, Phase 4);
`./change-control.md`.

## 1. Purpose
Spend the fuzzing budget efficiently: for each candidate, choose the payload
family most likely to yield a confirmed finding (and coverage), learning online
from oracle and grey-box reward.

## 2. Scope
- **In:** payload-family arm selection, context conditioning, online posterior
  updates, cost-normalized selection, a control arm.
- **Out:** generating the concrete payload bytes (catalog / mutation engine) and
  confirming a hit (oracle).

## 3. Functional requirements
- **FR-SCHED-1** Model payload **families** as arms and select one per candidate.
- **FR-SCHED-2** Condition on discrete context buckets (DBMS/framework/sink
  context/parameter type) — a contextual bandit, not a global one.
- **FR-SCHED-3** Use hierarchical Thompson sampling with backoff to a coarser
  context when a fine bucket is data-poor.
- **FR-SCHED-4** Seed arm priors from the catalog metadata (family × DBMS).
- **FR-SCHED-5** Normalize selection by cost (request count / latency) so cheap,
  informative families are preferred.
- **FR-SCHED-6** Persist posteriors across runs and reload them.
- **FR-SCHED-7** Provide a uniform-random selection control for measuring lift
  over no learning.
- **FR-SCHED-8** Take reward from the oracle (confirmed finding) and, when
  available, grey-box coverage (dense reward).
- **FR-SCHED-9** *(added 2026-09-22, CC-SCHED-0005)* Optionally emit per-pull
  diagnostics into the shared `metric_series` sink: `ThompsonBandit.attach_metrics`
  takes a `fuzzlab.core.store.MetricLogger`, after which every `update()` call
  (one bandit pull) logs `regret/cumulative` (running pseudo-regret vs. the best
  posterior mean known in that context before the pull) and
  `posterior/arm_<N>/mean` (the just-played arm's updated posterior mean, `<N>` a
  stable first-seen-order per-arm index) under `source="bandit"`. With no logger
  attached, behavior (selection, posteriors, return values) is unchanged — this is
  observational-only. `fuzzlab auto --bandit` attaches a logger and flushes it
  around the run (`auto_cli.py`).

## 4. Non-functional requirements
- **NFR-SCHED-reproducible** Given a fixed seed and posteriors, selection is
  reproducible.
- **NFR-SCHED-observable** Every selection records the arm, context, and sampled
  value for later analysis (research-platform posture, D2). *(2026-09-22,
  CC-SCHED-0005)* Extended: when attached, per-pull `regret/cumulative` and
  `posterior/arm_<N>/mean` time series are additionally recorded in
  `metric_series` (see FR-SCHED-9) for cross-run diagnostics (R-05).
- **NFR-SCHED-degrade** With no learned signal, behaves no worse than the uniform
  control.

## 5. Interfaces and data contracts
Reads `candidate` rows and `target` fingerprint; reads/writes `bandit_posteriors`;
reads reward from `finding`/`attempt` and grey-box signals. Emits a per-candidate
family choice consumed by the fuzzing harness. *(2026-09-22, CC-SCHED-0005)* Also
optionally writes `metric_series` rows (`source="bandit"`,
`regret/cumulative` and `posterior/arm_<N>/mean` keys, one step per pull) via
`fuzzlab.core.store.MetricLogger`, when a logger is attached with
`attach_metrics` — read by the diagnostics UI (R-05, component U5).

## 6. Dependencies (components)
`core/`, auditor (candidates), fuzzing harness and oracle (rewards), grey-box
instrumentation (coverage reward).

## 7. Acceptance criteria
- On the lab, beats the uniform control on confirmed-findings-per-request.
- Posteriors persist and reload; selection is reproducible under a fixed seed.
- Backoff engages for data-poor contexts without stalling.

## 8. Open questions
- Context-bucket granularity vs. data sparsity.
- Reward weighting between confirmed findings and coverage gain.
- Cold-start behavior before any reward is observed.
