# BUG-0150 — "Nothing was sent" asserted over a module-shared lab's cumulative log

- Date: 2026-10-15
- Status: fixed
- Severity: medium (order-dependent failures; a safety assertion that could be blind or
  wrong depending on test order)

## Description
`tests/test_spa_query.py` shares one crawled lab across the module (the `query_crawl`
fixture). Several tests asserted that something never reached the lab
(`lab.seen("POST", "/api/autopost") == []`, `lab.ws_messages == []`, ...) over the lab's
**cumulative** request log, which every later test of the module also writes to.

## Where encountered
`scripts/verify_change.py --base 06041df` on the DISC-CAPTURE lane's commit a9a94c7:
`test_a_seed_that_blocked_a_write_is_never_a_point_and_m6_never_sends_it` and
`test_a_shell_that_writes_on_every_load_still_gives_hash_points` failed in the
harness's parallel pass and passed alone.

## What it caused to fail
- The M6 test found `POST /api/autopost v=zqxm…` (the reflected-XSS confirmer's marker)
  in the log: sent by `test_two_findings_for_two_routes_sharing_a_name`'s `auto` run,
  which under D67 (captured writes probed by default, CC-FUZZ-0089) probes the write the
  crawl recorded. It ran earlier in that worker.
- The shell test found 527 forwarded socket messages: the M6 test's real browser (no
  WebSocket hold) loading the shared lab's pages.

## What the bug was identified to be
An absence assertion judged a log that other legitimate actors (other tests' crawls,
`auto` runs and browsers on the same module fixture) also write, so its verdict
depended on test order: blind when they ran after, wrong when they ran before.

## Root cause analysis
Five Whys:
1. Why did the tests fail? Their absence assertions saw requests made by other tests.
2. Why did other tests' requests land there? The lab is a module-scoped fixture; every
   test of the module reaches it.
3. Why did this start now? D67 made `auto` probe captured writes by default, so a test
   that never sent POSTs to `/api/autopost` now does; the order-dependence was latent.
4. Why was it latent? The assertions were written when no other test happened to send
   those requests; nothing tied an assertion to the window of the log its own actor
   produced (the fixture's `first_requests` snapshot existed, but only some tests used
   it).
5. Why was it not caught by a rule? PA-0150 says to assert exact counts only for actions
   the test alone performs, but it was written for counts and orders under a supervisor
   or reaper, and it is enforced by one test of `procutil`; an absence (`== []`) over a
   shared fixture's log was not read as its case.

**Root cause:** an assertion about what one actor sent was made over a log shared with
other actors, with no snapshot or window marking that actor's part.

## Corrective action
In this change (DISC-CAPTURE lane, the commit after a9a94c7):
- the fixture snapshots the crawl's own WebSocket messages (`first_ws`) beside
  `first_requests`;
- `_crawl_seen(query_crawl, method, prefix)` reads the crawl's own snapshot;
- the M6 test judges its own run on `lab.requests[start:]` / `lab.ws_messages[ws_start:]`
  (taken just before its `run_auto`) and the crawl on its snapshot.

## Recurrence review
- **BUG-0144 / PA-0150** ("assert exact counts or orders only for actions the test
  alone performs"): the same root cause, another actor acting on the observed objects.
- BUG-0135 / PA-0135 (wall-clock ratios): a different scheduling-dependent oracle; not
  the same cause.
- None other.

## Prior-preventive-action failure analysis
PA-0150 (from BUG-0144) did not prevent this because it was **too narrow** and **not
enforced at this layer**: its wording names counts and orders and its examples are
processes (a supervisor, a reaper, the kernel); its only enforcement is
`tests/test_procutil.py::test_kill_process_group_kills_exactly_the_recorded_group`. An
absence assertion over a module-shared fixture's log is the same failure (another actor
acts on the same objects) at the test-fixture layer, which neither its text nor its
test reaches.

## Preventive action
**PA-0156** (strengthens PA-0150): a test that asserts what one actor sent (or did not
send) over a log a module- or session-scoped fixture shares judges only that actor's
window: the fixture's snapshot taken before any other test reaches it, or a slice taken
just before the actor runs. The PA-0002 sweep for this class covers every such assertion
over the shared fixture's log when a change makes another test send more (here: every
`lab.seen` / `lab.requests` / `lab.ws_messages` assertion on `query_crawl`'s lab: four
moved to the snapshot, one to a slice; the others are on each test's own lab).
- Enforced by: tests/test_spa_query.py::test_a_seed_that_blocked_a_write_is_never_a_point_and_m6_never_sends_it, tests/test_spa_query.py::test_a_shell_that_writes_on_every_load_still_gives_hash_points
