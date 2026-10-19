# BUG-0526 — Browser-step timing tests bounded the Playwright driver's start, not the step

- Date: 2026-10-19
- Status: fixed (test-only)
- Severity: low. A test defect with no product impact. It failed one harness run of a
  docs-only commit under parallel load.

## Description
Four tests bounded a whole browser-driven run with a small wall-clock limit, to show
that a step was not waited out:
- `test_guarded_navigation::test_a_login_page_that_navigates_away_fails_loudly_and_fast`
  (`took < 8.0`);
- `test_guarded_navigation::test_the_auditor_reads_the_page_without_waiting_it_out`
  (`took < FAST + 1.5`, "the launch included");
- `test_m6_navigation_failures::test_a_before_load_navigation_is_no_verdict_well_under_the_timeout`
  (`took < 6.5`);
- `test_session_browser_login::test_clearing_a_password_field_the_app_removed_costs_nothing`
  (`took < 8.0`).

## Where encountered
`scripts/verify_change.py --base 685259e` on 85c9bcb (docs only), with three lanes'
harness runs on the host (load average 23 on 4 cores): the login test took 9.7 s.

## What it caused to fail
That test, under load; the other three share the shape.

## What the bug was identified to be
Measured with each step timed separately (loopback, the same fixture):

| | driver start | launch | login steps | total |
| --- | --- | --- | --- | --- |
| idle | 0.45-0.58 s | 0.1 s | about 1 s | 1.4-2.2 s |
| 24 CPU-bound processes | 4.6-7.1 s | 0.1-0.6 s | about 3 s | 9.1-11.4 s |

No navigation came near its timeout under load (each at most 0.94 s); the time was the
Playwright driver's start (a node process). The tests timed a span that held it.

## Root cause analysis
**Method: change analysis.** Only load differs between passing and failing runs, and
under load only the driver start grows beyond the bound. **Root cause:** the oracle for
"this step is not waited out" was the run's wall time, which also measures process
start-up; it measured the step only on an idle machine.

## Corrective action
Each test times the step it guards, at the step's own call: each `navguard.navigate`
(login, auditor fetch, M6 visit), or the password clear (`Page.evaluate` of
`browserlogin._CLEAR_IF_PRESENT`), each under 3.5 s; a whole-run bound stays only as a
60 s smoke alarm. Proven both ways:
- under 24 CPU-bound processes all four pass, 2 runs (they failed before: 8.4 s and
  16.7 s);
- against the exact original defects: the pre-BUG-0137 `goto(wait_until="load")` (8.04 s),
  the pre-Z5 `page.fill` clear (10.0 s), and a navigation that waits out its load
  (10.1 s, 8.1 s): each fails.

`tests/test_no_startup_timing.py` forbids the shape: a duration around a run-level entry
point asserted below 30 s. It flags all four old sites and passes today.

## Recurrence review
- **BUG-0135 / PA-0135:** wall-clock ratios under load. PA-0135(1) says a wall-clock
  bound is only a generous absolute smoke alarm.
- **BUG-0511 / PA-0511** (the same day): a scheduling-dependent oracle.
- **BUG-0143 / PA-0149(2):** reproduce a failure seen under load before setting it aside.
  That is how this one was found.

## Prior-preventive-action failure analysis
PA-0135(1) states the rule ("a wall-clock bound is only a generous absolute smoke
alarm"), but its guard catches ratios only, and these four bounds (6.5-9.5 s) were
written as timing claims, not smoke alarms. The rule was not enforced for absolute
bounds.

## Preventive action
PA-0526 (strengthens PA-0135(1)): a test that bounds how long a step takes times that
step at its own call. A span that includes a process, driver or browser start is only a
smoke alarm (30 s or more). An AST guard enforces it.
