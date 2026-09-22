# Payload Scheduler (Bandit) — Requirement Specification

Component code: **SCHED** · Status: `[partial — bandit core/priors/backoff built;
mutation-variant candidate source built (FR-SCHED-9); wired into the live grey-box
attempt path via fuzzlab greybox-run --mutation-variants]` (Phase 4/8) ·
Last updated: 2026-09-22 · see CC-SCHED-0005

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
- **FR-SCHED-9** Provide a candidate source over the mutation engine's
  `payload_variant` table (`fuzzlab.scheduler.variants`), mirroring the existing
  static-catalog candidate source (`catalog_families`/`catalog_priors` over
  `references/<category>/payloads/*.txt`): read variants back in, optionally scoped
  by vuln_class/sink_context/run, and hand them to the live attempt path
  (`greybox.run.run_greybox`) as additional `ProbeSpec`s **alongside** — never
  instead of — the existing default/catalog probes. Any caller that can increase
  real attempt traffic (e.g. `fuzzlab greybox-run --mutation-variants`) is gated by
  the same `--authorized` requirement as every other request-sending path (D11).
  See FR-MUT-8 (the mutation-engine-side half of the same requirement).

## 4. Non-functional requirements
- **NFR-SCHED-reproducible** Given a fixed seed and posteriors, selection is
  reproducible.
- **NFR-SCHED-observable** Every selection records the arm, context, and sampled
  value for later analysis (research-platform posture, D2).
- **NFR-SCHED-degrade** With no learned signal, behaves no worse than the uniform
  control.

## 5. Interfaces and data contracts
Reads `candidate` rows and `target` fingerprint; reads/writes `bandit_posteriors`;
reads reward from `finding`/`attempt` and grey-box signals. Emits a per-candidate
family choice consumed by the fuzzing harness. Also reads the mutation engine's
`payload_variant` table (FR-SCHED-9, `fuzzlab.scheduler.variants`) as an additional,
optionally-scoped candidate source, emitting `greybox.run.ProbeSpec`s consumed by
`run_greybox` alongside its default probes.

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
