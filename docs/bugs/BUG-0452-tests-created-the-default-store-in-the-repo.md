# BUG-0452 — tests created the default store `./fuzzlab.db` in the working directory

- Date: 2026-10-15
- Status: fixed
- Severity: medium

## Description
With project files, every store-writing launch is pinned to the open project, and the UI
bound the built-in default `store_path` (`./fuzzlab.db`) as the project whenever no other
was configured. Web tests that build the app with the default config and launch a job
(`tests/test_web_runner.py::test_launch_readonly_tool_returns_token`) therefore created
`./fuzzlab.db` and `./fuzzlab.db.d/` in the repository root (gitignored, so unnoticed).

## Where encountered
Layout design review C (round 2) found `/home/user/fuzzer/fuzzlab.db` (v22, six `report`
launches, 0 runs) left by this branch's test runs. Never merged.

## What it caused to fail
Test runs wrote a project file into the checkout; once present it changed the behaviour of
every later default-config test (the default "exists" → bound, so the start screen never
appeared), so results depended on the working directory's history.

## What the bug was identified to be
The UI treated an unconfigured default as an operator choice and created it on the first
write; the tests relied on the default config; nothing checked that a test run left the
working directory clean.

## Root cause analysis
1. Why the file? A pinned launch called `require_writable`, which creates the open project.
2. Why was the default the open project? Startup bound `cfg.store_path`, and the default
   config always has one.
3. Why did tests hit it? Several web tests use the default config, which before pinning was
   harmless (a launched `report` without `--store` just exited).
4. Why unnoticed? `.gitignore` hides `/fuzzlab.db`, and no guard looks.
**Root cause:** a fixed default output path shared by every run in a directory — PA-0450's
hazard — applied by the UI to its *own* project, with no check that a test leaves the
working directory as it found it.

## Corrective action
FR-UI-458: the built-in default counts as configured only if that file already exists;
otherwise the UI starts on the start screen, which offers it explicitly ("Use
./fuzzlab.db"), and pinned launches with nothing open are refused (409). The default-config
tests now use a private store (`test_web_runner.py`, `test_web_frontend.py`,
`test_web_launcher.py`), the start-screen tests run from an empty directory, and a
session-wide guard (`tests/conftest.py::_no_default_store_in_the_working_directory`) fails
the run if any test creates `./fuzzlab.db`. The stray file was removed. CC-UI-0450.

## Recurrence review
- **BUG-0450 / PA-0450** (same change): a fixed default output path shared by everything run
  in a directory is a provenance hazard. **Same root cause**, one layer up.

## Prior-preventive-action failure analysis
PA-0450 was **too narrow**: its enforcement (`OPTION_CLASS`, the classification test) covers
the *tools'* path options the UI pins, but not the UI's *own* project default, and it had
no check on what a test run leaves behind.

## Preventive action
**PA-0452** (strengthens PA-0450): a built-in default path is never written implicitly — it
counts as chosen only if it already exists, and otherwise it is offered, not used; and a
session-wide guard fails a test run that leaves a default output in the working directory
(`tests/conftest.py`). A new default output path gets the same guard.

## Addendum — code review round 3 (2026-10-15)
- **Recurrence review, completed:** **BUG-0125 / its session guard** (`tests/_leak_guard.py`:
  a session-end safety net failing the run on a leaked lab server) is the precedent for the
  guard this report adds — same mechanism, a different leaked resource. Not the same root
  cause (BUG-0125 leaked processes, not default outputs).
- **The guard was weaker than PA-0452(2) says** (both reviewers): it was disarmed whenever
  `./fuzzlab.db` existed before the run, and ignored the side files and `fuzzlab.db.d/`.
  It now records `(inode, size, mtime_ns)` of the store, `-wal`, `-shm`, `-journal` and
  `.d` before the session and fails on any difference
  (`tests/test_web_projects.py::test_the_default_store_guard_sees_changes_to_an_existing_store`).
- **The `--with-proxy` exception** (the lifespan creates the default store at start-up for
  the in-process proxy) is now written into PA-0452(3) and FR-UI-458.
- **PA-0002 sweep (recorded):** default output paths a test run could leave in the working
  directory — the UI's store (`./fuzzlab.db`, guarded here) and the tools' intermediates
  (`spider.db`, `audit.db`, `fuzz.csv`), which the UI pins into the project directory
  (`OPTION_CLASS`, PA-0450(2)); a full-suite run of the round-3 tree is checked for any of
  them left in the working tree (CC-UI-0450, Effectiveness). No other default output.

