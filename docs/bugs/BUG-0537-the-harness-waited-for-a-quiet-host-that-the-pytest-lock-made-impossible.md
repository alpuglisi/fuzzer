# BUG-0537 — The harness waited for a quiet host that the pytest lock made impossible

- Status: fixed (scripts/verify_change.py, `pytest_lock_enforced`; process tooling, no component change control)
- Found: 2026-10-20, by the coordinator, when a docs-only verification of 7855b8c waited 30 minutes without starting.

## Description
`scripts/verify_change.py` waits, before it starts its child pytest, until no other pytest process exists on the
host (`wait_for_quiet_host`, up to `--wait-other`). Since BUG-0532 every pytest session of the test tree takes the
host pytest lock and waits for it. With three agent lanes working, there is always some pytest process, running or
queued on that lock, so the quiet-host condition is never met: the harness starves until `--wait-other` expires and
then refuses (rc 3), and no change can be verified or pushed.

## Where encountered / what failed
The coordinator's verification of the F-108 commit (`verify_change --base 4ee8007 --wait-other 7200`): 30 min
waiting, listing a sequence of lane sessions (`test_web_sitetree_browser.py`, `test_session_forbidden_answers.py`,
`test_bounded_reads.py`), each queued or running under the lock.

## The defect
Two serialisation mechanisms were combined: the harness's one-sided "zero other pytest" wait (from before BUG-0532)
and the per-session lock. The first requires an idle host; the second keeps the host busy by design whenever anyone
queues. Each alone serialises; together they starve the harness.

## Root cause (Five Whys)
1. Why did the verification not start? `wait_for_quiet_host` never saw zero pytest processes.
2. Why were there always some? Lanes queue pytest sessions on the host lock (BUG-0532), and a queued session is a
   pytest process.
3. Why does the harness still wait for zero? AU-TESTLOCK kept the quiet-host wait unchanged.
4. Why was it kept? My dispatch told the lane to keep `verify_change.py`'s own lock and quiet-host wait.
5. Why was that not caught? The lock was measured with one or two sessions, never with several agents queueing
   continuously; the harness's own run on the merge went first because the host happened to be idle.
Root cause: the harness kept a "host must be idle" precondition after the lock made "queue for the host" the rule.

## Corrective action
`pytest_lock_enforced(tree)`: when the tree's root conftest takes the host pytest lock, the harness skips the
quiet-host wait and relies on its child's lock wait (whose timeout already follows `--wait-other`); a tree without
the lock keeps the old wait. Test: `tests/test_verify_change.py::test_a_tree_whose_conftest_takes_the_pytest_lock_never_waits_for_a_quiet_host`
(fails if the helper always says yes — the empty tree — or always no — this repository).

## Recurrence review
BUG-0532 / PA-0532 (the lock) is the immediate predecessor: PA-0532(2) says a process rule is enforced where every
such process passes, as a lock the process itself takes — the harness's extra precondition contradicted that and
was not removed. Prior-preventive-action failure analysis: PA-0532 was not followed through to the one tool that
already had its own mechanism (not swept by mechanism, PA-0002). PA-0537 strengthens PA-0532.

## Preventive action
PA-0537.
