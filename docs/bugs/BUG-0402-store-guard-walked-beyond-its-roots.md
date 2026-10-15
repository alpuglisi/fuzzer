# BUG-0402 — The test-suite store guard walked directories it does not own

- Date: 2026-10-15
- Status: fixed
- Severity: low (test infrastructure; false failures and slowness, no product effect)

## Description

`tests/_store_guard.py` snapshots every `fuzzlab.db` so the session fails if a test
creates or writes a default store outside `tmp_path`. It walked the repository
**and**, when pytest was started from outside the repository, the whole invocation cwd,
recursively.

## Where encountered

Code reviews A and B of the CLI-simplification Phase 1, before merge. Both reproduced it
with `_roots()` / `store_files()` from a cwd outside the repository.

## What it caused to fail

- **From `$HOME` or `/`:** the guard walked the whole home directory or filesystem
  (`/proc` included). That is slow, and any unrelated `~/otherproj/fuzzlab.db` written
  during the run (for example a running `fuzzlab web`) failed the session.
- **From a cwd containing pytest's temp base** (`cd /tmp && pytest …`, or `--basetemp`
  inside the tree): every test that creates `tmp_path/fuzzlab.db`, which is exactly what
  tests of the default store do, was reported as "created a default store". The session
  then failed.

## What the bug was identified to be

The guard's scope was "every root, recursively", and the cwd was added as a root. The
agreed design (§8) says "snapshot the cwd's own store", not "walk the cwd". pytest's
temp base was not excluded either.

## Root cause analysis

Five Whys:

1. *Why the false failures?* The walk reached pytest's temp base and other people's
   directories.
2. *Why did it reach them?* The cwd was treated like the repository: a tree we own and
   scan.
3. *Why?* The implementation generalised "repository root plus cwd" into one list of
   walk roots, so both got the same recursive treatment.
4. *Why didn't a test catch it?* The guard's own tests ran with temporary directories as
   the tree, never from a cwd outside the repository, and never with pytest's temp base
   inside the walked tree.
5. *Why did the design statement not prevent it?* The design named the cwd check as a
   *snapshot of its own store*. The implementation used a walk, the more general
   mechanism, without re-checking the bound.

**Root cause:** a filesystem-observing guard was given a recursive scope over a
directory it does not own (an arbitrary cwd), and did not exclude the test framework's
own scratch area. Its tests never ran it from the positions where those differ.

## Corrective action

- `store_files(tree, *, exclude, cwd)` now walks **only** the repository tree, minus
  pytest's temp base (`tmp_path_factory.getbasetemp()`).
- For a cwd outside the repository, it stats **only** `cwd/fuzzlab.db{,-wal,-shm,-journal}`.
  It never walks the cwd.
- The store environment variables are also cleared in `pytest_configure`, before any
  fixture, so module- and session-scoped fixtures and their child processes never see a
  host value (review A9).

Test: `tests/test_storepath.py::test_the_store_guard_never_walks_pytests_temp_base_nor_an_outside_cwd`.
Delivered by CC-CORE-0401.

## Recurrence review

- **`docs/bugs/`.** BUG-0125 is the session-end server-leak guard
  (`tests/_leak_guard.py`). It is a different mechanism (process registry, not
  filesystem); its scope is the processes the suite registered. No prior bug is about a
  guard's filesystem scope.
- **`docs/PREVENTIVE_ACTIONS.md`.**
  - **PA-0125:** owns *its* process tree.
  - **PA-0035:** probe the real operation.
  - **PA-0052:** a scope filter derives from the configured target, never a hardcoded
    lab literal. That is the closest rule, but it is about target-scoping filters in the
    product, not test guards.
- **Result:** no recurrence of this root cause.

## Preventive action

**PA-0402.** A test-suite guard that observes the filesystem is bounded to what the
suite owns. It may walk the repository tree, but never a directory it does not own (the
invocation cwd, home, the temp area). It excludes the test framework's own scratch area
(pytest's basetemp). Its tests run it from a cwd outside the repository, and with the
basetemp inside the walked tree.

PA-0002 sweep: the suite's other session-wide guards. `tests/_leak_guard.py` tracks
registered processes, with no filesystem walk. The AST guards (`tests/test_*_guard*.py`,
`tests/test_loopback_listeners.py`, `tests/test_procutil_guard.py`) read `fuzzlab/` and
`tests/` only. No other guard walks an unowned directory.
