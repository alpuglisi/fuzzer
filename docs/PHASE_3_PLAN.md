# Phase 3 — Grey-box instrumentation (plan)

Give the toolkit a **dense, causal reward signal**. Phases 0–2 judged a payload's
effect only from the outside (status, size, latency, error strings, reflection).
Phase 3 reads what the payload actually did *inside* the app — which application
lines it executed and whether it provoked a database fault — and folds that into
`attempt.reward`, so later phases (the Phase 4 bandit, the Phase 5 classifier) learn
from evidence, not guesses. Still **no ML** in this phase.

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (Phase 3, D7),
`docs/architecture/oracle-confirmation.md` (M10 grey-box), the reserved columns in
`fuzzlab/core/migrations.py` (`attempt.coverage`, `attempt.db_fault`),
`docs/components/01-target-lab/` (the instrumented image + `labctl.sh reset`), and
`docs/PREVENTIVE_ACTIONS.md` (rules to follow).*

## Goal

Per request, capture the set of **application** source lines executed and a
**database fault** signal, reset lab state deterministically between iterations, and
shape these into `attempt.reward` so that **a request reaching new application code
produces a distinguishable reward**. Feed the same signals to the oracle as the
corroborating grey-box mechanism (M10), without changing the oracle's fail-closed,
sole-finding-writer posture.

## Status (2026-09-21)

`[planned]`. Phases 0–2 are built and unit-tested offline; the schema already
**reserves** `attempt.coverage` and `attempt.db_fault` (migration 1) and the lab's
`labctl.sh` already exposes `reset`, so Phase 3 fills reserved columns and extends
the image — it should not need a core-schema migration for the coarse signals (a new
migration is added only if we choose to store normalized per-line coverage).

**On-host by nature.** Unlike Phases 0–2, most of Phase 3 must run against the
*live instrumented lab* — reading real coverage from PHP and manipulating the lab's
DB — which this sandbox cannot do (no container daemon, no live target). The plan is
therefore explicit per task about what is **offline-testable here** (readers,
reward math, hooks — built against recorded/synthetic fixtures with injected fakes)
vs the **on-host** capture and validation (tracked in `docs/ON_HOST_TASKS.md`).

## Principles (this phase)

- **Grey-box corroborates; it does not shortcut the oracle.** The oracle stays the
  sole finding-writer and fail-closed. Coverage/fault are a **reward** signal and an
  M10 confirmation input that raises confidence or confirms where a black-box
  mechanism alone abstains — never an auto-label.
- **App-scoped.** Filter coverage and faults to application files; exclude
  framework/vendor and the instrumentation shim itself. A signal that includes
  boilerplate every request runs is not causal.
- **Deterministic iterations.** Reset lab state between iterations so coverage
  novelty and stateful cases (stored XSS, state-changing payloads) are reproducible;
  a fast per-iteration restore, not a container rebuild.
- **Reserved columns first.** Fill `attempt.coverage` / `attempt.db_fault`; add a
  new migration only if normalized per-line storage is needed (PA: derive test
  expectations from the migration registry, not literals — PA-0001).
- **Reward composes.** Coverage novelty is a **tier** in a shaped, multi-tier reward
  that still carries the Phase 2 screening signals — so the Phase 4 bandit can use
  all tiers, not a single flattened number.
- **Safety unchanged.** Lab-only; `--authorized`; scope/budget enforced; destructive
  classes off by default. Instrumentation and any coverage/fault read channel bind
  to **loopback only** and are never exposed; the instrumented image is a lab build,
  never a target we point at third parties.

## Tasks

Ordered; each lists a deliverable and an acceptance check, and marks the
offline-testable vs on-host split. Follow `PREVENTIVE_ACTIONS.md` throughout.

### T3.1 — Instrument the lab image (pcov, app-filtered)
Add coverage instrumentation to `web.Dockerfile` (`php:8.3-apache`). Prefer **pcov**
(low overhead, line coverage) over Xdebug for throughput. Add a request-scoped
coverage collector — an `auto_prepend_file`/`auto_append_file` shim that starts
coverage, and on shutdown writes the executed **application** lines for that request
to a loopback-only side channel keyed by a per-request correlation id (a request
header the tools set), filtered to app source (exclude vendor/framework/shim).
- **Deliverable:** the image builds with pcov enabled and a per-request coverage
  side channel; `labctl.sh` brings it up.
- **Accept (on-host):** a single authenticated request records the set of app source
  lines it executed, correlatable to that request; vendor/framework lines are
  excluded. (Offline: the shim/config is reviewed and templated; capture is on-host.)

### T3.2 — Per-request coverage reader (consumer seam)
Add `fuzzlab/greybox/coverage.py` — a reader that, given a request's correlation id,
returns the covered app-line set for that request from the T3.1 side channel,
normalized (file→line-set) and app-filtered. Injected/faked in tests via a small
`CoverageSource` protocol, exactly as the oracle uses an injected `Sender`.
- **Deliverable:** `CoverageSource` protocol + a live reader + an in-memory fake.
- **Accept (offline):** given a recorded/synthetic coverage fixture, the reader
  returns the expected covered-line set and drops non-app files (unit-tested).

### T3.3 — Coverage novelty → `attempt.reward`
Maintain a per-run **coverage frontier** (the union of app lines seen so far) and
compute a per-attempt novelty (new lines this request added). Store the request's
coverage in `attempt.coverage` (reserved column, as a compact encoding) and fold
novelty into `attempt.reward` as a **tier** in a shaped reward that still carries the
Phase 2 timing/error screening signal.
- **Deliverable:** frontier + shaped-reward function; writes `attempt.coverage`,
  updates `attempt.reward`.
- **Accept (offline):** with synthetic coverage sets, a request covering **new** app
  lines yields a strictly higher reward than one covering only already-seen lines,
  and the coverage is recorded in `attempt.coverage` (unit-tested; frontier logic
  and reward ordering derived from code, not magic literals).

### T3.4 — Database fault signal
Add a DB error/fault hook: tail MariaDB's general/error log (or a thin DB-proxy/error
hook) and flag when a request produced a SQL **error/warning** (syntax error,
truncation, etc.), correlated to the request id. Add `fuzzlab/greybox/dbfault.py`
with an injected `DbFaultSource` fake. Write `attempt.db_fault`.
- **Deliverable:** fault reader + fake; writes `attempt.db_fault`; adds a reward tier.
- **Accept:** offline — given a fault-log fixture, a request that caused a SQL error
  sets `db_fault=1` and a benign one `0`; on-host — a real error-based SQLi payload
  is distinguishable from a benign request on the live lab.

### T3.5 — Deterministic lab reset between iterations
Extend `labctl.sh` (and a harness-callable `reset()` hook) with a **fast DB
snapshot/restore** so stateful cases run independently: pin a clean baseline, restore
it between iterations rather than rebuilding the container. The harness calls the hook
between iterations for state-changing payload families.
- **Deliverable:** snapshot/restore in `labctl.sh` + a `LabControl.reset()` seam
  (with an injected fake for tests).
- **Accept:** offline — the harness calls `reset()` at the right points (unit-tested
  with a fake); on-host — after a state-changing payload, a restore returns the DB to
  the pinned baseline and two consecutive runs see identical initial state.

### T3.6 — Grey-box confirmation mechanism (M10) into the oracle
Add the grey-box `ConfirmationStrategy` input (M10 in
`architecture/oracle-confirmation.md`): coverage-of-the-vulnerable-sink and
`db_fault` as corroborating evidence. Where a black-box mechanism alone **abstains**
(ambiguous), M10 can confirm with grey-box evidence; the oracle stays fail-closed and
records the mechanism in the finding's confidence.
- **Deliverable:** an M10-aware strategy path that reads the T3.2/T3.4 signals via
  injected sources; still the sole finding-writer.
- **Accept:** offline — a fixture case the black-box oracle abstains on is confirmed
  via M10 with grey-box evidence, and controls stay unconfirmed (no false positive);
  on-host — reproduced against the live lab.

### T3.7 — Wire into the run + exit measurement (on-host)
Feed the coverage/fault readers and the `reset()` hook into `run_pipeline` and the
fuzzer loop (behind the same injected-source seams), and record coverage-reward
metrics in `run_metrics`.
- **Accept (on-host, Phase 3 exit):** on the running instrumented lab, a request
  reaching **new application code** produces a distinguishable (higher) reward than
  one that does not, visible in `attempt.reward`/`attempt.coverage`; the DB-fault
  signal separates error-based SQLi from benign traffic. Tracked in
  `docs/ON_HOST_TASKS.md`.

## Exit criterion

A request reaching new application code produces a **distinguishable reward**
(coverage novelty folded into `attempt.reward`, coverage in `attempt.coverage`); a
database fault is captured per request (`attempt.db_fault`) and corroborates SQLi in
the oracle via M10; lab state resets deterministically between iterations; and all
consumer-side code (readers, reward math, reset hook, M10 path) is built behind
injected-source seams and unit-tested offline, with the live capture and the
distinguishable-reward measurement validated on the host. No ML.

## Component mapping

- **LAB (01)** — instrumented image (pcov + shim), coverage/fault side channels,
  `labctl.sh` snapshot/restore. (Closes the open `[ ] Grey-box …` deliverables in
  `docs/components/01-target-lab/change-control.md`.)
- **CORE (02)** — `fuzzlab/greybox/` consumer readers (`coverage.py`, `dbfault.py`)
  and the shaped-reward/frontier logic; a migration only if per-line storage is added.
- **FUZZ (07)** — reward wiring into the fuzzer/`run_pipeline` and the M10 oracle
  path.

## Out of scope for Phase 3 (deferred)

- **Any ML.** The bandit scheduler that *uses* this reward is Phase 4; the detection
  classifier is Phase 5.
- **Manifest-driven lab generation** and new vulnerability **pages/classes** — Lab
  track (its own phases), not here.
- **Xdebug-based step debugging / profiling** beyond line coverage — pcov line
  coverage is sufficient for the reward; richer traces are a later option if needed.
