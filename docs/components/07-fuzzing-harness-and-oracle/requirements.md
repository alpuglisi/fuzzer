# Fuzzing Harness and Oracle — Requirement Specification

Component code: **FUZZ** · Status: `[built fuzzer; oracle built (black-box M1/M2/M3/M5/M8); harness generalization ongoing]`
· Last updated: 2026-09-22

Related: `ARCHITECTURE.md` #7; `DECISIONS_AND_ROADMAP.md` (D1, D5, D7, Phase 2/3);
`./change-control.md`.

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
- **FR-FUZZ-8** The oracle supports **M8 out-of-band (OOB) callback** confirmation
  for blind injection classes with no observable direct-response difference. Scope
  and contract:
  - `fuzzlab.oracle.oob.OobListener` is a loopback-only (`127.0.0.1`/`localhost`
    only; any other host raises) local HTTP callback tracker. It binds no socket
    until `start()` is called (default-off — never binds implicitly), mints
    unguessable per-probe tokens (`register()`), gives the URL to embed in a payload
    (`callback_url(token)`), and reports whether that exact token was later
    requested (`wait_for(token, timeout)`, `hits(token)`). It is a process-local test
    fixture for this lab — no DNS component, no external reachability, no
    persistence — never a general-purpose, publicly reachable interaction/
    collaborator service (Safety, `CLAUDE.md`).
  - `CommandInjectionOobStrategy` (`fuzzlab.oracle.strategies`) is a
    `ConfirmationStrategy` for `vuln_class="command-injection"`,
    `category="command-injection"`, `mechanism="oob-callback"`. It takes an
    `OobListener` by injection (constructor arg, default `None`) exactly like the M6
    `BrowserExecutor` seam: with a listener, it embeds a fresh canary URL in a
    shell-fetch payload (`curl`/`wget`) per attempt and confirms iff that token is
    requested before `timeout`; without one, it no-ops (`confirm()` returns `None`
    immediately, no probe sent) — fail-closed, and it never constructs a listener of
    its own.
  - Wiring: `default_strategies(oob=None)`, `Oracle(oob=None)`,
    `run_pipeline(oob=None)`, `run_auto(oob=None)` all take the listener as an
    optional keyword that defaults to `None` (no behavior change for existing
    callers). `fuzzlab auto --oob` is the only place that constructs and `start()`s a
    real `OobListener`; it is default-off and torn down (`stop()`) at the end of the
    run regardless of outcome.
  - Applies alongside the existing M1 timing strategy for the same category (both
    `applies()` on `category="command-injection"`); the oracle tries the cheaper M1
    timing check first, then M8, so a target that suppresses timing signal but still
    executes the shell fragment is still confirmable.
  - Other blind classes named in `docs/architecture/oracle-confirmation.md` Tier 3
    (blind SSRF, blind XXE, blind insecure-deserialization) can register their own
    `ConfirmationStrategy` against the same `OobListener` seam later — M8 the
    *mechanism* is now built and pluggable; wiring every blind class onto it is
    tracked as future work, not blocked on anything.

## 4. Non-functional requirements
- **NFR-FUZZ-precision** Oracle precision is measured and prioritized; a confirmed
  finding must reproduce.
- **NFR-FUZZ-deterministic** Given the same target state and inputs, oracle
  verdicts are reproducible (state reset via snapshot/restore between iterations).
- **NFR-FUZZ-safe** Destructive payload classes off by default; auth endpoints
  excluded from scope; no traffic off localhost.
- **NFR-FUZZ-labeled-output** Emits labeled results (e.g. CSV) with opaque case IDs
  for benchmarking and ML training (D9, D10).

## 5. Interfaces and data contracts
Reads `candidate` rows (and scheduler choices); writes `attempt` rows (features,
reward) and, via the oracle, `finding` rows (labels, evidence). Reads grey-box
coverage/fault signals when available. Authenticates via the session manager;
sends via the `core/` HTTP client.

## 6. Dependencies (components)
`core/`, session manager, payload scheduler, indicator DB & catalogs; grey-box
instrumentation for reward and coverage/fault labels. (The oracle itself depends
on `core/` and the target lab, plus grey-box signals when available.)

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
