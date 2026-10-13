# BUG-0078 — The D15 fail-safe exit left an orphan run row behind

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0056, CC-CORE-0033)
- Severity: low. A usage error left an empty run, which became "the latest run" that
  `fuzzlab report` and the web UI default to.

## Description
`fuzzlab auto` with no ground truth and no `--categories` (decision D15: never guess
what to test) exited 2 correctly, but only after `auto_cli.main` had opened the store,
written a run row with `start_run`, and imported the spider db. `run_auto` resolved the
plan and raised `RunModeError` afterwards. The same applied to `--points ground-truth`
without a contract. Environment failures (`--browser` without Playwright, a missing
greybox side-channel path, an OOB listener bind failure) likewise left an unmarked run
that read as an empty finished run.

## Where encountered
The error-review phase. Repro: exit 2, but `runs left behind: [{'id': 1, 'tool':
'auto'}]`, and `latest_run_id → 1`.

## What it caused to fail
`fuzzlab report` (it defaulted to the empty run), the runs list, and anything picking
"the latest run".

## What the bug was identified to be
Usage-level validation ran after side effects. CC-FUZZ-0050 had moved plugin settlement
before the store for exactly this reason ("leaves no run row behind"), but only for
plugin errors.

## Root cause analysis
Five Whys:
1. *Why a run row?* `start_run` ran before `run_auto` resolved the plan.
2. *Why was the plan resolved so late?* Resolution lived inside `run_auto`, which needs
   the store for crawl points.
3. *Why was the pure part not factored out?* CC-FUZZ-0050 fixed the same symptom only
   for its own error class (plugins). No PA was written and no sweep was run.
4. *Why were the environment failures unmarked?* Nothing recorded on the run that it
   aborted.
5. *Why did no test catch it?* No test asserted "no run row" for the usage-error paths.

**Root cause:** usage-level validation ordered after side effects, and an earlier fix of
the same symptom left no rule or sweep behind.

## Corrective action
In CC-FUZZ-0056:
- **One shared resolver.** `harness.auto.plan_run(mode, ground_truth,
  selected_categories, points_source)` is pure: no store, no traffic. It returns
  `(source, plan)`, raising `RunModeError`. `run_auto` calls it, and so does the CLI,
  **before** opening the store (PA-0003: one resolution).
- **Environment prechecks before the store** (`_precheck_environment`): `--browser`
  needs Playwright importable (`importlib.util.find_spec`), and greybox side-channel
  paths must exist. Each is a clean `p.error` (exit 2).
- **Failures after `start_run`** (an OOB bind, a crash, a late usage error) are caught
  as `BaseException`. Through `Store.mark_aborted`, the run row's `notes` records `aborted: <Type>: <message>` (or
  `aborted: exit N`) and is committed, then the error re-raises: a usage error still
  exits 2, and a real bug keeps its traceback.
- **Tests** (`tests/test_auto_cli_side_effects.py`):
  - parametrised: D15 with nothing to run, `--points ground-truth` without a contract,
    `--browser` without Playwright, a missing coverage path and a missing dbfault path
    each exit 2 with **no store file**;
  - an OOB bind failure (stubbed) marks the run `aborted: OSError: …` and propagates;
  - a late `RunModeError` exits 2 and marks `aborted: exit 2`;
  - a good run has no note.

## Recurrence review
Checked `docs/bugs/`, `docs/PREVENTIVE_ACTIONS.md` and the change-control logs:
- **CC-FUZZ-0050** (plugin settlement before the store, "leaves no run row behind").
  **Same symptom, same root cause** (validation after a side effect), for a different
  error class. It was fixed under the batch review gate, with no bug report, no PA and
  no sweep.

**Result:** a recurrence. A prior-fix failure analysis follows.

## Prior-preventive-action failure analysis
There was **no prior PA**: CC-FUZZ-0050's fix was scoped to its own error class, and the
general rule was never written down, so nothing prompted a sweep of the other
usage-level errors. That is the "not written, therefore not followed" failure mode.

## Preventive action
**PA-0079** (in `docs/PREVENTIVE_ACTIONS.md`):
1. **Every usage-level validation runs before any side effect** (store open, run row,
   import, network). The pure part of a resolution is factored into one function that
   both the CLI and the library call.
2. **A failure only the run can hit marks the run** (`notes = "aborted: …"`), and is
   never left looking like a finished empty run.
3. **Tested per path:** each known usage-error path asserts that no run row (no store)
   is left behind.

**Sweep (PA-0002):** every `store.start_run` caller (grep), judged on whether a usage
error or a failure can follow the run row:
- **`fuzzlab auto`** (`harness/auto_cli.py`): fixed.
- **`fuzzlab greybox-run`** (`greybox/greybox_cli.py`) — **a second instance, fixed.**
  Its "no injection points" usage error fired after `start_run`.
  - Ground-truth points are pure, so that check now runs before the store.
  - Crawl points need the imported store, so everything after `start_run` is guarded:
    the run is marked `aborted: …`, then the error re-raises.
  - Test: a crawl run with no points exits 2 and its run reads `aborted: exit 2`.
- **`run_targets`** (`harness/multitarget.py`) — **a third instance, fixed.** A
  `RunModeError` for target N fired after the runs for targets 1..N had started.
  - Every spec's plan is now resolved by `plan_run` before the first run row.
  - Each run is guarded, so it is marked aborted on failure.
  - Tests: a bad spec leaves no run, and a dead target marks its run aborted.
- **`fuzzlab mutate-run`** (`mutation/cli.py`): validates before `start_run`; nothing
  usage-level follows. Its destructive-payload defect is in the next review batch.
- **`fuzzlab proxy`** (`proxy/cli.py`) and the web proxy control: they build scope
  before `start_run`. Their crash on bad rules is in the next review batch.
- **`spider` / `fetcher` / `blind_sqli_fuzzer`:** they start a run only to import
  finished work at the end, so no usage error follows.

The abort marking lives in one place, `Store.mark_aborted` (CC-CORE-0033, PA-0003),
used by all three guarded paths.
