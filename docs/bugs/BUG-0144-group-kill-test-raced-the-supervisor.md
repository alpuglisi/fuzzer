# BUG-0144 — the group-kill test raced the supervisor it ran under

- Date: 2026-10-15
- Status: fixed
- Severity: low. A test defect, with no product impact: the group always died, and only
  the count raced. It failed one verification run, and would have been set aside as
  "flaky" under the old habit.

## Description
`tests/test_procutil.py::test_kill_process_group_kills_exactly_the_recorded_group`
asserted that `procutil.kill_process_group` signals exactly 3 members of
`sh -c "sleep 300 & sleep 300 & wait"`. It ran that group under
`procutil.start_server`.

## Where encountered
A parallel verification of BUG-0143 (3 pytest workers with live boots): `assert 1 == 3`.

## What it caused to fail
That test, intermittently, under CPU load: 11 of 30 runs with six CPU-bound processes,
against 0 of 25 runs unloaded.

## What the bug was identified to be
Instrumented under load:
- the group listing always held the 3 members;
- after the leader (`sh`) was signalled, both `sleep`s were already gone before
  `kill_process_group` reached them. The supervisor, which stops the child's whole
  group when the child dies, had killed them.

So the function signalled 1 member and returned 1, which is correct. The test's exact
count raced the supervisor's own cleanup. The function is specified for a group "a
caller owns itself … started with `start_new_session=True`": an unsupervised group, as
in the corpus sandbox.

## Root cause analysis
**Method: change analysis.** The difference between the passing and failing
conditions is CPU load. Load changes the order of two actors:
- the test's signalling loop;
- the supervisor's reaction to the leader's death.

Both act on the same group. Unloaded, the loop wins. Under load, the supervisor often
does.

**Root cause:** the test's setup did not model the function's documented use. It added
a second actor (the supervisor) that legitimately kills the same processes, then
asserted an exact count that only holds when that actor loses the race.

## Corrective action
In commit `6e44a3f`:
- the test owns the group itself (`_caller_owned_group`, `start_new_session=True`);
- it asserts the exact count, the leader's `-SIGKILL` status, and that every member is
  gone;
- it also asserts that a bystander process outside the group survives;
- the launch guard's allowlist for `tests/test_procutil.py` is 4, with the reason.

Result: 30 of 30 runs pass under the same load.

## Recurrence review
- **BUG-0135** (timing tests under load): the same class, an oracle that depends on
  scheduling.
- **BUG-0143:** a failure seen only under concurrency, and the same lesson.
- **PA-0135** covers wall-clock ratios only.

## Prior-preventive-action failure analysis
PA-0135 was too narrow: it named wall-clock ratios. This oracle depended on the order
of two concurrent actors, not on elapsed time. PA-0149(2) (from BUG-0143, same day)
requires a failure seen under load to be reproduced before it is set aside. That is how
this one was found and fixed instead of re-run.

## Preventive action
PA-0150: a test asserts exact counts or orders only for actions it alone performs. When
another legitimate actor can act on the same objects (a supervisor, a reaper, a
server), the test either removes that actor (the documented use), or asserts the
outcome (all gone, nothing else touched) instead of the count.
