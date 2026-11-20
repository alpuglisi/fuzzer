# BUG-0740 — One wave's concurrent launch failures switched M6 off for the run

- Date: 2026-11-20
- Status: fixed (CC-FUZZ-0721)
- Severity: medium (detection). With `workers` > 1, one candidate meeting a transient
  browser-launch failure (memory pressure) disabled the M6 browser for every later
  candidate of the run: browser-only XSS candidates became inconclusive. Never a false
  positive; no traffic or safety rule affected. Found before the lane merged.
- Records: ERROR_LOG 2026-11-20, PA-0740, CC-FUZZ-0721, F-740.

## Description
`PlaywrightBrowserExecutor` counts launch failures "in a row" (`_failures`,
`MAX_LAUNCH_FAILURES = 2`) so that one transient failure does not silence M6 (reviewer
A, BUG-0126), and driver-stop failures the same way (`_stop_failures`, BUG-0137 review
Z2). Lane M6CONC's `run_many` (CC-FUZZ-0720) runs a candidate's next payloads in up to 3
worker threads at once. Each concurrent visit of a wave that hit the same transient
failure counted once, so one wave reached 3 and set `_unavailable` for the run.

## Where encountered
The lane's adversarial-test subagent, offline, with a fake `playwright.sync_api` whose
`launch` fails during one candidate only:
`tests/test_m6_concurrency.py::test_one_candidates_transient_launch_failure_does_not_switch_m6_off[3]`
failed (`[1]` passed) on dc4692d. The same review of the stop counter found it there too
(swept: `test_one_waves_driver_stop_failures_do_not_switch_m6_off`).

## What it caused to fail
On dc4692d (pushed to the lane branch, never merged): the second candidate raised
`UnplaceableLocation("browser unavailable: 'out of memory'")` without launching; one
at a time it launched and was observed.

## What the bug was identified to be
Run-wide counters whose unit ("one failure in a row") was defined for visits made one
after another, incremented once per visit by concurrent visits.

## Root cause analysis (Five Whys)
1. Why was M6 switched off? `_failures` reached `MAX_LAUNCH_FAILURES` within one wave.
2. Why? Each of the wave's three concurrent visits called `_launch_failed`.
3. Why was that wrong? Three visits started together that meet one condition are one
   event; "in a row" means consecutive attempts, which concurrent visits are not.
4. Why was it missed? Making the executor concurrent, the agent made the counters
   thread-safe (a lock) but did not restate what each run-wide field means when visits
   overlap: it checked for lost updates, not for changed meaning.
5. Why was there no rule? PA-0023 (BUG-0021) asks to re-check a single-thread
   assumption when state is reused by new callers, but is written for sqlite handles and
   enforced by nothing.
- **Root cause:** run-wide state designed under a one-at-a-time assumption was given
  concurrent callers with its safety (locking) checked but its meaning not re-derived.

## Corrective action (CC-FUZZ-0721)
- `run_many`'s workers run through `_in_wave`, which marks the thread with the wave
  (`threading.local`); `_launch_failed` and `_stop_driver` count a wave's failures once
  (`_failed_wave`, `_stop_failed_wave`); a successful launch or stop resets both, as it
  resets the counters.
- Tests: the launch test above and the stop test, each at workers 1 and 3.

## Recurrence review
Searched `docs/bugs/` for concurrency and shared-state defects (BUG-0021, BUG-0087,
BUG-0108) and `docs/PREVENTIVE_ACTIONS.md` for their rules. BUG-0021 (a sqlite handle
cached on `self`, reused from another thread) has the same root cause: state shaped for
one thread reused by concurrent callers without re-checking the assumption. BUG-0108 /
PA-0109 (lost update) is about safety, which the lock here already gave.

## Prior-preventive-action failure analysis
PA-0023 (from BUG-0021) did not prevent this: **too narrow and not enforced.** It
speaks of a sqlite connection or a thread-affine OS handle, so a counter did not read as
in scope; its enforcement line is "none". It also asks only whether the state is
thread-safe, not whether what it counts still means the same thing when calls overlap.

## Preventive action
PA-0740 (strengthens PA-0023): when a component's calls become concurrent, every
instance and module field its one-at-a-time path reads or writes is listed in the change
record with its concurrent meaning (locked, per-thread, or counted per wave), and each
counter or flag whose meaning depends on order gets an N-worker test. The sweep (PA-0002)
covered every run-wide field of `PlaywrightBrowserExecutor`: `_unavailable` (read before
each wave and each visit; set under the lock), `_failures` and `_stop_failures` (counted
once per wave, the defect), `_failed_wave`/`_stop_failed_wave` (new, under the lock),
`_headless`/`_timeout`/`_headers`/`_session_route`/`workers` (read-only), and the
module state navguard keeps for every browser (measured in CC-FUZZ-0720).
