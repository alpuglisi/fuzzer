# BUG-0532 — "One pytest at a time" was prose plus a harness-only lock; ad-hoc runs overlapped six times

- Date: 2026-10-20
- Status: fixed (AU-TESTLOCK; see Corrective action)
- Severity: medium. Test tooling and process only; no product code was wrong. Overlapping
  runs killed one verification run, and their load produced false failures in others.

## Description
`CLAUDE.md` (definition of done, step 2) and `docs/MULTI_AGENT_ORCHESTRATION.md` §2 say
the verification harness "runs one pytest at a time". Only `scripts/verify_change.py`
enforced that, with two mechanisms:
- `acquire_host_lock`, a `flock` on `<tempdir>/fuzzlab-verify-change.lock`, which
  serialises harness runs with each other;
- `wait_for_quiet_host`, which makes the harness wait while `/proc` shows another
  pytest.

Neither applies to a pytest started any other way. An agent lane's ad-hoc `pytest` took
no lock and checked nothing, so it started whenever the lane ran it. A harness run
waited for an ad-hoc run that was already running. Nothing made an ad-hoc run wait for
anything.

## Where encountered
Agent lanes under orchestration on this host, recorded in
`docs/claude_juicelab_failures.md`:

| Entry | Date | Lane | What overlapped | Effect |
|---|---|---|---|---|
| F-092 | 2026-10-19 | DG-UNPLACEABLE | an ad-hoc `pytest -n 3` over the orchestrator's `verify_change` run and DG-NAVBLANK's pytest | timing and ML failures that passed serially; load on a harness run (it stayed green) |
| F-093 | 2026-10-19 | DG-NAVBLANK | overlapping harness runs of its own, stopped with `kill` on a `pgrep -fa` pattern | the orchestrator's run on 806791a matched the pattern and was killed 1 s after it started |
| F-095 | 2026-10-19 | DG-NAVBLANK | three ad-hoc pytest runs during other harness runs | load (both runs stayed green) |
| F-097 | 2026-10-19 | AU-OUTCOME | its first run printed another lane's pytest (pids 2179/2181) and started anyway, after a dispatch that stated the rule and the `ps` check | about 0.9 s overlap |
| F-098 | 2026-10-20 | AU-REQID14 | pytest in the same shell command as its `ps` check | about 8 s overlap |
| F-102 | 2026-10-20 | AU-OUTCOME | a 600 s wait loop ran out and started the run instead of refusing | overlapped the last 1-4 s of `verify_change --base 8117855` |

Earlier, before the harness existed: F-029 (the orchestrator itself ran pytest
concurrently with full-suite runs).

## What it caused to fail
- **A lost verification (F-093).** The orchestrator's harness run on 806791a ended
  "interrupted (signal 15)". The DG-UNPLACEABLE merge was verified again.
- **Spurious red results (F-092).** Timing and ML tests failed under the combined load
  and passed serially. Earlier bugs show these timing tests fail under load:
  BUG-0135, and BUG-0526 (load average 23 on 4 cores).
- **Load on runs used as merge evidence (F-092, F-095, F-097, F-098, F-102).** No
  recorded result was wrong. Each overlap could have produced a false failure in a
  harness run, and each one cost the orchestrator time to find and record.

## What the bug was identified to be
The rule had one mechanical enforcement point, at the wrong layer:
1. `acquire_host_lock` serialises `verify_change.py` runs with each other only. A bare
   `pytest` never opens `fuzzlab-verify-change.lock`.
2. `wait_for_quiet_host` is one-sided: the harness waits for others, but nothing makes
   others wait for the harness, or for each other. It is also a check followed by a
   start, which leaves a window between them.
3. For every other pytest the rule was prose:
   - `CLAUDE.md` and `MULTI_AGENT_ORCHESTRATION.md` §2;
   - `docs/HANDOFF-2026-10-15.md` §7 ("one pytest at a time across all lanes");
   - `docs/ON_HOST_RUNBOOK.md`;
   - after F-092, a sentence in every dispatch.

## Root cause analysis
**Method: Five Whys**, checked against the six entries above.

1. *Why did lanes' pytest runs overlap other runs?* Nothing stopped them from starting:
   a bare pytest takes no lock and checks nothing.
2. *Why did the lanes not apply the rule themselves?* Each lane re-implemented it, run by
   run, from prose (a `ps` check, then a wait loop, then the run). The
   re-implementations failed in different ways:
   - no check at all (F-092, F-095);
   - a check whose output was read and then ignored (F-097);
   - a check in the same command as the run (F-098);
   - a loop that fell through on its timeout (F-102).

   Compliance needed several fallible steps from every agent on every run.
3. *Why was the rule left to each agent?* When the harness was built (2026-10-15,
   CHANGELOG "process: a verification harness…"), the rule was made mechanical only
   where the harness runs. "Runs one pytest at a time" describes the harness. Ad-hoc
   runs were outside its scope.
4. *Why was no enforcement added where every run passes through?* Every pytest session
   of this test tree passes through the root conftest's `pytest_configure`. That point
   was never used. Each response added prose or a one-sided check:
   - F-029: the harness;
   - F-092 and F-093: dispatch text;
   - F-097: a proposal, queued for the owner.
5. *Why did prose survive six recurrences?* The project already holds the principle:
   PA-0020 and PA-0033 say a written rule alone is not prevention, and each instance of
   the class needs its own mechanical check. No PA named the one-pytest rule as such an
   instance. So each recurrence was recorded as a conduct lapse ("open as a practice"),
   not as a defect in the enforcement.

**Root cause:** the one-pytest-at-a-time rule was enforced only inside one entry point,
`verify_change.py`'s own lock and its one-sided quiet-host check. Every other pytest
relied on each agent remembering a prose rule and re-implementing it correctly. There
was no mechanism at the layer that every pytest session passes through.

## Corrective action
AU-TESTLOCK (commit: see the CHANGELOG line for 2026-10-20). This is project-level test
tooling, so there is no component change-control entry (`CLAUDE.md`).

- **`tests/_pytest_lock.py`** (new). The root `tests/conftest.py` calls its
  `pytest_configure` first, before the store guard, and uses its `pytest_unconfigure`.
  - **The lock.** The session's controller takes an exclusive `fcntl.flock` on
    `/tmp/fuzzlab-pytest.lock` and holds it until unconfigure or process exit (the
    kernel drops it if the process dies). The path is fixed under `/tmp`, not taken from
    `tempfile.gettempdir()`: a process with its own `TMPDIR` would otherwise take a lock
    nobody else sees. `TMPDIR` is unset on this host today (measured).
  - **xdist workers** skip it. They are identified by `config.workerinput`, which xdist
    3.8.0 sets in every worker before its configure (`xdist/remote.py`).
    `PYTEST_XDIST_WORKER` alone is not trusted: xdist exports it to every process a
    worker's test starts, and anyone can set it.
  - **Nested sessions** skip it. The holder sets `FUZZLAB_PYTEST_LOCK_HELD=<its pid>`,
    and its workers and children inherit it. A session that finds the lock busy skips
    it when three things hold:
    - the token names the holder;
    - the holder is in its `/proc` ancestor chain;
    - the holder is the lock's real holder, by the kernel's `/proc/locks` (otherwise by
      the side file's pid and `/proc` start time).

    A token copied into another shell, a true ancestor's pid and `$$` all fail this
    check (measured). A second session inside the same process reuses the hold.
  - **A descendant of the holder without the token** fails at once with a usage error.
    Waiting would deadlock, because its own ancestor is waiting for it.
  - **Everyone else waits.** The message names the holder: its pid, argv, cwd and start
    time, from the side file `/tmp/fuzzlab-pytest.lock.holder`. The wait lasts up to
    `FUZZLAB_PYTEST_LOCK_WAIT` seconds (default 1800, the same as `verify_change.py
    --wait-other`; 0 means refuse at once). Then the session exits with a usage error
    (exit code 4) and runs nothing. It never falls through.
  - **No off switch.** `FUZZLAB_PYTEST_LOCK_PATH` is honoured only inside a session that
    holds the host lock (the plugin's own tests) and is refused elsewhere.
    `FUZZLAB_PYTEST_LOCK_TRACE` only records decisions.
  - **Without `fcntl`** (not POSIX), the session warns and runs unlocked.
  - **`--help` and `--markers`** take no lock: they collect and run nothing.
- **`scripts/verify_change.py`** keeps its own lock and quiet-host wait.
  - Each pass's pytest controller takes the new lock. Its xdist workers do not.
  - `pytest_env` gives the child `FUZZLAB_PYTEST_LOCK_WAIT` equal to `--wait-other`,
    unless the caller set it. This covers a session that takes the lock between the
    quiet-host check and the child's start.
  - The script never holds the pytest lock itself, so it cannot deadlock against its
    child.
- **Nested pytest call sites.** Found by grep over `tests/`, `fuzzlab/`, `scripts/` and
  `lab/`, and by an AST scan of every spawn call (`subprocess.*`, `os.exec*`, asyncio,
  procutil) for a `pytest` string in the call or its function:

  | Site | Handling |
  |---|---|
  | `tests/test_procutil.py::test_the_conftest_safety_net_fails_the_session_and_kills_the_leak` | runs pytest with `--rootdir tmp_path` and its own conftest (leak guard only), so it never loads the lock. Its `{**os.environ}` passes the token anyway |
  | `tests/test_procutil.py::test_a_clean_session_passes_the_safety_net` | the same |
  | `scripts/verify_change.py` (`pytest_cmd` / `Runner.run`), driven in-process by `tests/test_verify_change.py::test_end_to_end_on_a_synthetic_repo` | the synthetic repo's conftest is empty, so its child never loads the lock. On the real tree the child is the session's controller and takes the lock (measured below) |
  | `tests/_no_ml_child.py` | not a pytest session: a plain `python` child that imports `tests.test_auto` and never runs pytest's configure |
  | `scripts/on_host_full_run.sh` (two top-level `pytest` commands, run one after the other) | top-level sessions: each takes the lock in turn |

  No test calls `pytest.main`, `pytester` or `runpytest`.

- **Tests:**
  - `tests/test_pytest_lock.py` (12 functions, 14 cases) covers:
    - the two-session wait;
    - the timeout refusal, with waits of 0 and 1;
    - one acquisition for an xdist session, with its workers skipping;
    - a nested session with the token (plain and xdist);
    - a tokenless descendant;
    - forged tokens (a sibling's pid, an ancestor that is not the holder, `$$`);
    - a private path refused outside a locked session;
    - the in-process re-entry;
    - the `/tmp` path and the wait parsing;
    - the no-`fcntl` warning;
    - a real-tree child session taking the lock.
  - `tests/test_pytest_lock_wiring.py` (3 tests) is a light whole-tree guard, so
    `verify_change.py` runs it with every change. It checks that the root conftest calls
    the lock first and releases it, proven on synthetic offenders. It also checks that
    the running session ran the hook and holds the host lock, directly, through its
    xdist controller, or as a nested session. The heavier behaviour tests run when the
    lock, the conftest or procutil changes.
  - `tests/test_verify_change.py::test_the_child_pytest_waits_for_the_pytest_lock_as_long_as_the_run`.

  Every child session takes a private lock under `tmp_path`, so the tests never take the
  real host lock and cannot deadlock the harness running them. On an idle host, the
  plain run of both files passed 17 of 17 (14.4 s). With `-n 3`, the two files plus
  `test_verify_change.py`, `test_storepath.py` and `test_procutil.py` passed 112 of 112.

**Measured** (tiny trees, the real default lock path, on an idle host, 2026-10-20
05:18 UTC; `scratchpad/lock/measure.log`):
- **Two sessions.** The second printed the holder (pid, argv, start time, cwd), ran
  nothing while it waited, and ran after the first ended.
- **Timeout refusal.** With `FUZZLAB_PYTEST_LOCK_WAIT=2`, the session exited 4 and its
  test never ran. It printed `ERROR: the pytest lock … is still held by pid … after 2 s
  … nothing was run`.
- **Forged tokens.** A sibling's pid, a true ancestor's pid and `$$` each exited 4
  without running.
- **xdist `-n 3`.** One `acquired`, by the controller. Three `worker` events, each with
  the controller as its ppid. From a worker, a nested child with the token ran
  (`nested`), and a child with the token stripped failed at once
  (`refused-tokenless`). Then one `released`.
- **Real conftest.** A `--co` session of the real `tests/` took the lock and released
  it; `--help` took none.
- **`/proc/locks`** names the holder's pid on `/tmp`, on pytest's basetemp and on
  `/home/user`.
- **`verify_change.py` parent and child:** see the harness run recorded in the lane's
  report.

## Recurrence review
- **`docs/claude_juicelab_failures.md`.** F-029 (before the harness), then F-092, F-093,
  F-095, F-097, F-098 and F-102: the same bug six times in two days, after the harness
  existed.
- **The prior rule.** None of these is a numbered PA:
  - `CLAUDE.md` step 2 and `MULTI_AGENT_ORCHESTRATION.md` §2;
  - `docs/HANDOFF-2026-10-15.md` §7 ("one pytest at a time across all lanes (F-025,
    F-029)");
  - `docs/ON_HOST_RUNBOOK.md`;
  - the harness's lock and quiet-host wait (CHANGELOG 2026-10-15);
  - the dispatch practice adopted after F-092 and F-093 (`--wait-other`, the `ps` check,
    signal only recorded PIDs).
- **`docs/PREVENTIVE_ACTIONS.md`.** No PA states the one-pytest rule. PAs with the same
  root cause:
  - **PA-0020** (BUG-0019): when the root cause is an agent's missed self-check, a
    written rule alone is not prevention;
  - **PA-0033** (BUG-0030): each instance of that class needs its own mechanical check,
    not the assumption that the general principle covers it;
  - **PA-0141..PA-0147** (BUG-0141): conduct rules made hook-enforced.

  Related to the effect, not the cause:
  - BUG-0135 / PA-0135 and BUG-0526 / PA-0526 (timing tests under load);
  - PA-0149(2) (reproduce a concurrency-only failure before setting it aside).
- **Result:** a recurrence of the same bug (F-029, then six times), and of the
  root-cause class of PA-0020 and PA-0033.

## Prior-preventive-action failure analysis
Why the prior rule (the 2026-10-15 harness plus the prose) and PA-0020/PA-0033 did not
prevent this:
1. **Wrong layer.** The only enforcement lived in `verify_change.py`. It keeps harness
   runs from overlapping each other and makes the harness wait for others. None of the
   six offending runs was a harness run. The enforcement sat at an entry point the
   failure did not pass through.
2. **Not enforced.** For ad-hoc runs the rule was text. F-097 shows the limit: the
   dispatch stated the rule and the `ps` check explicitly, and the lane started anyway.
   PA-0020 already says a written rule alone is not prevention for agent conduct, but
   it was never applied to this rule. PA-0033 says each instance needs its own
   mechanical check. The harness was taken as "enforcement exists" for the whole rule,
   though it covered one entry point.
3. **Too fragile even when followed.** The compliant procedure (check, wait, then start)
   is a race with several steps, and every agent re-implemented it on every run. F-098
   (check and run in one command) and F-102 (a loop that fell through on its timeout)
   both followed the procedure and still overlapped.
4. **Recorded as practice, not defect.** F-092 and F-095 were left "open as a practice".
   F-097 named the host-level lock as the fix this class needs, and it was queued for
   the owner. F-098 and F-102 happened while it waited, until the owner approved this
   item on 2026-10-20.

## Preventive action
**PA-0532.** It strengthens PA-0020 and PA-0033 for this rule, and supersedes the
prose-only "one pytest at a time":
1. **The session enforces it.** Every pytest session of `tests/` takes the host pytest
   lock in the root conftest's `pytest_configure`, before anything else, and refuses
   rather than runs beside another session. A guard keeps the hook first.
2. **A rule about how processes may run is enforced where every such process passes**,
   as a lock the process itself takes. It is not enforced by one tool that starts some
   of them, nor by a check-then-start procedure in prose or a dispatch.
3. **A nested pytest inherits its parent's environment** (the holder's token). A
   descendant without the token fails at once, rather than deadlocking.
4. **No routine bypass.** There is no off switch, and a private lock path is honoured
   only inside a locked session.

**Sweep (PA-0002):**
- Every nested pytest call site is listed above.
- The other one-at-a-time statements (`CLAUDE.md`, `MULTI_AGENT_ORCHESTRATION.md` §2,
  `ON_HOST_RUNBOOK.md`, `HANDOFF-2026-10-15.md` §7) all concern pytest sessions of this
  tree, which the lock now enforces. Their wording is still true, so they are
  unchanged.

**Limits, stated rather than hidden:**
- `pytest --noconftest` turns off every conftest guard, this one included.
- The lock does not stop F-093's failure mode, a kill chosen by pattern. Signalling
  only recorded PIDs stays a dispatch rule. In code, PA-0125 forbids killing by name or
  pattern.
- `verify_change.py`'s own lock still lives under `tempfile.gettempdir()`, as the item
  asked ("keep its own host lock").
