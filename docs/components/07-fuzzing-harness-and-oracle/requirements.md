# Fuzzing Harness and Oracle — Requirement Specification

Component code: **FUZZ** · Status: `[built fuzzer; oracle built (black-box M1/M2/M3/M5); harness generalization ongoing; greybox-run consumes mutation-engine variants (opt-in); coverage-frontier growth emitted to metric_series]`
· Last updated: 2026-09-22 · see CC-FUZZ-0021

Related: `ARCHITECTURE.md` #7; `DECISIONS_AND_ROADMAP.md` (D1, D5, D7, Phase 2/3,
Phase 8); `./change-control.md`.

## 1. Purpose
Send payloads at candidates, extract per-attempt features and reward, and — via a
deterministic **oracle** — confirm vulnerabilities. The oracle is the single
source of truth for labels; everything downstream (findings, training rows,
rewards) derives from it.

## 2. Scope
- **In:** the generalized harness (`template + injection_point + payload_source +
  oracle`); attempt feature/reward extraction; the **class-pluggable** deterministic
  oracle covering the web-app attack vectors in `references/` (mechanisms +
  injection-class mapping in `../../architecture/oracle-confirmation.md`).
- **Out:** choosing the next payload family (scheduler) and scoring/screening
  attempts (ML classifier). The oracle does not guess; ML never writes labels.

## 3. Functional requirements
- **FR-FUZZ-1** Generalize `blind_sqli_fuzzer.py` into a harness parameterized by
  `template`, `injection_point`, `payload_source`, and `oracle`, so one harness
  serves multiple vulnerability classes.
- **FR-FUZZ-2** For each send, record an `attempt` row with a versioned feature
  vector and a reward signal.
- **FR-FUZZ-3** The oracle is **class-pluggable** across web-app attack vectors,
  not time-based only: a `ConfirmationStrategy` per vulnerability class selects from
  a shared set of deterministic **mechanisms** — differential timing, error
  signature, boolean/response differential, evaluation marker, reflected-canary-in-
  context, browser execution, file-content marker, out-of-band callback,
  redirect-target control, and grey-box (when on). Strategy is chosen by
  `(vuln_class, sink_context)`. The mechanism set and the injection-class →
  mechanism mapping (from `references/`) are specified in
  `../../architecture/oracle-confirmation.md`.
- **FR-FUZZ-3a** Timing confirmation is **differential** (rising-delay across
  several requested delays; median/MAD baseline), never a single absolute
  measurement.
- **FR-FUZZ-4** Confirm via the mechanism(s) each class registers (e.g. error
  signature for error-based SQLi, evaluation marker for SSTI, browser execution for
  stored/DOM XSS), and via grey-box coverage / DB-fault signals when instrumentation
  is on (D7). Ambiguity is "not confirmed," never a guess (fail-closed).
- **FR-FUZZ-5** The oracle is the **only** writer of `finding` labels; keep
  detection (the measurement) decoupled from the payload's label to avoid circular
  labeling. New classes register via a built-in strategy registry now, and the
  plugin system's `register_oracle` hook (component #13) later.
- **FR-FUZZ-6** Require an explicit `--authorized` flag and lab-only scope before
  sending anything.
- **FR-FUZZ-7** Serialize timing-sensitive sends at concurrency 1 per host via the
  shared budget mutex.
- **FR-FUZZ-8** The live grey-box run (`greybox/run.py::run_greybox`) can, opt-in
  (`--mutation-variants` / `mutation_variants=True`, off by default), also probe
  each point's sqli/xss attacks with a bounded set of the mutation engine's
  semantics-preserving variants (component #9, MUT), through the same
  attempt/reward/coverage path as the built-in probes; a variant that hits or
  reaches new code is written back to `payload_variant` via MUT's existing
  destructive-gated `catalog.record_variant` — the harness's own consumer of
  Phase 8 T8.5's write-back path, alongside the standalone `mutate-run` CLI.
  Added by `CC-FUZZ-0019` (Lane C1/M8-wiring).
- **FR-FUZZ-9** `run_greybox()` emits the run-wide `CoverageFrontier`'s growth
  to `core/store.py`'s `metric_series` table (component #2, CORE) once per
  attempt, via a buffered `MetricLogger(store, run_id, source="coverage")`
  and the private `_record_coverage_metric()` helper: `key="coverage/lines"`,
  `step=` the running attempt count, `value=` the frontier's current `.size`.
  Always on (no flag — read-side-only addition, no new traffic or behavior
  change to the attempt path itself); additive alongside the pre-existing
  `greybox_frontier_size` end-of-run `run_metrics` total, which is unchanged.
  Added by `CC-FUZZ-0021` (lane B0's coverage-frontier emitter, Wave 1b,
  sequenced after `CC-FUZZ-0019`/`CC-FUZZ-0020` per the file-overlap note in
  `docs/PARALLEL_LANE_BUILD_PLAN.md`).

## 4. Non-functional requirements
- **NFR-FUZZ-precision** Oracle precision is measured and prioritized; a confirmed
  finding must reproduce.
- **NFR-FUZZ-deterministic** Given the same target state and inputs, oracle
  verdicts are reproducible (state reset via snapshot/restore between iterations).
- **NFR-FUZZ-safe** Destructive payload classes off by default; auth endpoints
  excluded from scope; no traffic off localhost.
- **NFR-FUZZ-labeled-output** Emits labeled results (e.g. CSV) with opaque case IDs
  for benchmarking and ML training (D9, D10).
- **NFR-FUZZ-dry-run** `fuzzlab fuzz`, `fuzzlab auto`, and `fuzzlab greybox-run`
  accept `--dry-run`: plans and prints the exact argv/command that would run and
  sends nothing (no probe, no oracle confirmation, no coverage/DB-fault side-channel
  read, no `Store`/CA/sender construction), for headless use outside the web UI.
  Bypasses the `--authorized` gate for the preview itself (nothing is sent either
  way), and reuses the web launcher's dry-run plan/report logic
  (`fuzzlab/web/commandspec.py` + `fuzzlab/web/runner.py`) via the shared
  `fuzzlab/cli_dryrun.py` helper. `fuzz`/`auto` were added by `CC-FUZZ-0020` (lane
  D0a); `greybox-run` — including the `--mutation-variants`/
  `--max-mutation-variants`/`--allow-destructive` flags `CC-FUZZ-0019` (Lane
  C1/M8-wiring) added — was added by `CC-FUZZ-0022` (lane D0b), sequenced after
  C1 since both touch `fuzzlab/greybox/greybox_cli.py`.

## 5. Interfaces and data contracts
Reads `candidate` rows (and scheduler choices); writes `attempt` rows (features,
reward) and, via the oracle, `finding` rows (labels, evidence). Reads grey-box
coverage/fault signals when available. Authenticates via the session manager;
sends via the `core/` HTTP client. Optionally (FR-FUZZ-8) reads mutation-engine
operators/validator (component #9, MUT) and writes accepted variants to
`payload_variant` via MUT's `catalog.record_variant`. Writes `metric_series`
rows (`source="coverage"`, `key="coverage/lines"`) via `core/store.py`'s
`log_scalar`/`MetricLogger` (FR-FUZZ-9).

## 6. Dependencies (components)
`core/`, session manager, payload scheduler, indicator DB & catalogs; grey-box
instrumentation for reward and coverage/fault labels; mutation engine (MUT,
optional — FR-FUZZ-8). (The oracle itself depends on `core/` and the target lab,
plus grey-box signals when available.) `core/store.py`'s `metric_series` table
and `log_scalar`/`MetricLogger` writer API (FR-FUZZ-9).

## 7. Acceptance criteria
- Confirms the lab's known blind-SQLi injection points with the differential
  oracle and no false positives on the secure controls.
- Emits `attempt` rows with versioned features and a reward usable by the bandit
  and classifier.
- `finding` rows are written only by the oracle and reproduce on re-run.

## 8. Open questions
- Oracle interface for pluggable vulnerability classes (register-oracle hook
  shape).
- Timing-threshold calibration per target/network profile.
- Reward shaping when grey-box signals are unavailable (black-box fallback).
