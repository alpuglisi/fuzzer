# BUG-0125 — Test-launched lab servers leaked and OOM-killed the suite

- Date: 2026-10-14
- Status: fixed (CC-LAB-0254, CC-CORE-0048, CC-UI-0053)
- Severity: high (availability of the build host; the operator's own labs share it).
  Full-suite runs were OOM-killed, taking Chrome and pytest with them.

## Description
Every server a live-boot harness or a test started was a plain `subprocess.Popen`
child, stopped with `terminate()`/`kill()` on that one pid:

- `LiveBootHarness` (Laravel) started `php artisan serve`, which itself spawns
  `php -S 127.0.0.1:<port> …/server.php` as **its** child. `close()` terminated only
  the `artisan` parent; `php -S` was re-parented to init and kept its port and its
  memory. Every Laravel live-boot test leaked one server per boot, pass or fail.
- `go run` (a test's header-injection proof) builds `/tmp/go-build…/exe/main` and runs
  it as a child: terminating `go run` leaves `exe/main` running. `bundle exec`/puma and
  `mvn` have the same shape.
- Nothing tied any of these processes to its owner's life: a pytest that was itself
  killed (OOM, a timeout, Ctrl-C) left everything it had started running.
- `subprocess.run(..., timeout=)` on a tool that forks (composer, npm, go, mvn,
  bundle) kills only the direct child on timeout.
- A harness whose `build()` raised **after** the server had started leaked it too:
  `__exit__` never runs when `__enter__` raises (found by the sweep, in all five
  harnesses).

## Where encountered
The orchestrator's full-suite runs on the build host. The memory cgroup OOM killer
fired; the process table then showed **429 orphaned**
`/usr/bin/php8.3 -S 127.0.0.1:<port> /tmp/fuzzlab-php-laravel-live-boot-*/…/server.php`
processes (ages 1–10 h), about 15 orphaned `/tmp/go-build…/exe/main` and one `puma`,
all with parent PID 1, holding about 14 GB RSS. Stopping them (by PID, after reading
each one's command line; the operator's bWAPP and Juice Shop labs were left untouched)
freed 12.7 GB (15.0 → 2.1 GB used). Reproduced: one normal, passing run of
`tests/test_labgen_php_laravel_access_control_live_boot.py` left 3 new orphaned
`php -S`.

## What it caused to fail
- Full-suite runs (OOM-killed); every later run on the host had less memory.
- Ports and temp trees of dead runs stayed held.
- The safety of the shared host: an unbounded pile of loopback servers running
  deliberately vulnerable code next to the operator's labs.

## What the bug was identified to be
Process lifetime was managed per pid, not per process tree, and only on the happy
path: `close()` signalled the direct child; nothing covered grandchildren, the owner's
death, a timed-out forking tool, or a build that failed after the server started.

## Root cause analysis
Five Whys:
1. *Why were 429 `php -S` servers running?* Each Laravel boot's `close()` terminated
   `artisan serve`, and its child `php -S` survived, re-parented to init.
2. *Why did `close()` stop only `artisan`?* The harness held one `Popen` and called
   `terminate()` on it, assuming the process it started **is** the server. For
   `artisan serve`, `go run`, `bundle exec` and `mvn` it is a launcher.
3. *Why did nothing else stop them?* Nothing tied a server to its owner: no process
   group or session to signal, no parent-death signal, no record of what a test
   started, no check at the end of a run.
4. *Why did no test catch it?* Every harness test asserted the server answered; none
   asserted that nothing was left after `close()` or after the owner's death. The
   teardown rule the harnesses cite (PA-0012) asks for a **bounded** teardown, and
   `terminate()` + `wait(5)` is bounded; nobody checked it was **complete**.
5. *Why did it surface only as an OOM?* A leaked server is silent: it holds memory and
   a port and logs nothing, so the cost accumulated across runs until the cgroup limit.

**Root cause:** the toolkit treated "the process I started" as "the server", so a
stop signalled one pid and the rest of the process tree (grandchildren, a dead owner's
children, a failed build's server) was nobody's; and no test asserted that a stop or an
owner's death left nothing behind.

## Corrective action
- **CC-CORE-0048 / FR-CORE-38 — `fuzzlab/procutil.py`** (stdlib-only leaf; imports
  nothing from fuzzlab). `start_server(argv, …)` starts a **supervisor**
  (`sys.executable -I -S fuzzlab/procutil.py …`) in a new session as the direct child.
  The supervisor sets `PR_SET_PDEATHSIG(SIGTERM)` and `PR_SET_CHILD_SUBREAPER` on itself
  (ctypes `prctl`), re-checks `getppid()` against the owner pid, starts the real program
  in a new process group (with `PDEATHSIG(SIGKILL)` on it and a raised `oom_score_adj`),
  and on a stop request, an unrequested SIGTERM (idempotent handler), owner death
  (PDEATHSIG, a changed parent, or EOF on the owner's control pipe) or the server's own
  exit: SIGTERMs the server's group and every re-parented descendant once, waits the
  grace period, SIGKILLs what is left, reaps, and exits with the server's exit code.
  `stop_server` writes a stop token, signals the supervisor through a pidfd, waits for
  it to exit **without reaping it**, falls back (D15) if it is wedged, sweeps the
  supervisor's session while its pid is still held, and only then reaps it. Every
  signal is identity-checked: a pidfd is opened, `/proc/<pid>/stat` field 22 is compared
  with the recorded start time, and only then is the signal sent through that pidfd. A
  group or session id is trusted only while its leader pid is held (alive or an
  unreaped zombie with the recorded start time); a start time of 0 matches nothing.
  Nothing is ever killed by name or pattern. *(Tightened in review round 1, below.)*
  `run_bounded` is `subprocess.run(capture_output=True, timeout=)` through the
  supervisor: a timeout or the tool's own exit takes the tool's whole tree.
  `astart_server` / `astop_server` / `arun_bounded` are the asyncio forms. A registry
  records what this process started; `reap_registered()` stops and reports live ones.
- **CC-LAB-0254 — the five harnesses** (`live_boot.py`, `rails_live_boot.py`,
  `live_boot_spring_boot.py`, `go_live_boot.py`, `django_live_boot.py`): the server is
  started with `procutil.start_server`, `close()` calls `procutil.stop_server` (and
  removes the temp tree even if the stop raises), `__enter__` closes on a failed
  build, and every forking install/build step (`_run`) and network probe goes through
  `procutil.run_bounded`. Laravel now starts `php -S 127.0.0.1:<port> -t public
  <router>` directly in `public/` — the exact command `artisan serve` runs (Laravel's
  `ServeCommand`: the app's `server.php` if present, else the framework's bundled
  router) — so the server is the supervisor's direct child.
- **Tests:** every test that started a server with `subprocess.Popen` uses
  `procutil.start_server`/`stop_server` (`tests/_meadowmart_app.py`,
  `test_labgen_go_live_boot.py`, `test_multitarget_category1_combined.py`,
  `test_multitarget_category3_combined.py`, `test_multitarget_category4.py`,
  `test_labgen_node_bff_app.py`, `test_labgen_node_bff_multitarget.py`,
  `test_labgen_spring_boot_absent_input_live_boot.py`,
  `test_labgen_spring_boot_trackernest_multitarget.py`,
  `test_labgen_header_injection_circlefeed_live_boot.py`, `test_no_ml.py`), and every
  test `subprocess.run` of a forking tool with a timeout uses `run_bounded`
  (npm install, `go run`, `go vet`, `mvn package`/`compile`).
- **Safety net:** `tests/conftest.py` loads `tests/_leak_guard.py`: at session finish
  it stops every still-live registered server (identity-checked) and **fails the
  session**, printing `LEAKED SERVER pid …, age …: [argv]`.
- **Guard:** `tests/test_procutil_guard.py` (AST) fails on any spawn primitive in
  `fuzzlab/` or `tests/` outside `procutil` and a three-entry reasoned allowlist
  (exact counts), and on `subprocess.run`-family calls of a forking tool with a
  timeout; proven on 12 synthetic offenders. It also enforces the leaf rule and
  labgen's import guard (labgen may import itself, the label contract — pre-existing —
  and `fuzzlab.procutil`, nothing else).
- **CC-UI-0053:** the web launcher's jobs and the Lab page's `labctl.sh ps` go through
  procutil (D18 below).

### Design decisions (local to this bug's review; not the project's D-numbers)
- **D12 — thread rule.** `PR_SET_PDEATHSIG` fires when the *forking thread* exits.
  `start_server` raises off the main thread unless `allow_thread=True`.
- **D13 — SIGTERM, not SIGKILL, as the supervisor's death signal**: a SIGKILLed
  supervisor could not stop its group. (The server's own PDEATHSIG is SIGKILL: it fires
  only if the supervisor itself was killed.)
- **D14 — the corpus sandbox keeps runsc's lifecycle** (its pid is attached to cgroups
  at once); only its timeout kill becomes an identity-checked group kill
  (`procutil.kill_process_group`).
- **D15 — fallback for a wedged supervisor (reviewer B).** If the supervisor has not
  exited within its grace after `stop_server` signals it, `stop_server` signals the
  server's own process group directly (SIGTERM, then SIGKILL), identity-checked by
  PGID and start time, then SIGKILLs the supervisor and sweeps its session. Tested with
  a supervisor that cannot act on SIGTERM (SIGSTOPped); the server is shown to receive
  the group SIGTERM.
- **D16 — keep the OOM killer off the supervisor (reviewer B).** The server's
  `oom_score_adj` is raised to the supervisor's value + 500 (capped at 1000) before
  exec — an unprivileged increase, inherited by its descendants — so a cgroup OOM picks
  servers before their supervisors. Residual: a supervisor already at 1000 cannot have
  a likelier child (the test skips then, saying so); lowering the supervisor instead
  would need `CAP_SYS_RESOURCE`. Verified here: supervisor 0, server 500.
- **D17 — `allow_thread=True` is documented and loud (reviewer B).** With it the server
  dies when the forking thread ends. The supervisor then writes
  `fuzzlab.procutil: supervisor <pid>: SIGTERM without a stop request …` to its stderr
  and records `reason=signal`; `stop_server`/`finish` raise `ServerLost`. Tested.
- **D18 — web-runner lifetime (the coordinator's decision rule: keep the most operator
  flexibility).** Jobs launched by the web UI are **tied to the UI's life**: started
  under the supervisor on the event-loop thread (`allow_thread=True`; that thread lives
  as long as the UI), stopped as a whole tree by *Stop*, stopped on the UI's lifespan
  shutdown (`Runner.shutdown`), and stopped by the supervisor if the UI process dies.
  Why not "outlive the UI with a stop path": a job's output is streamed to the UI over a
  pipe, so a job that outlived its UI would run blind and die on its next write
  (SIGPIPE) — an undefined stop, not a flexible one. Tying it keeps both options: a
  deterministic UI-owned job, or the same command run from the CLI (the dry-run preview
  shows it) to outlive any UI. An unrequested stop is reported on the job's stream.

### Deviations from the agreed draft (for review, PA-0093(2))
1. The supervisor runs by file path, `sys.executable -I -S fuzzlab/procutil.py`, not
   `-m fuzzlab.procutil`: it then needs no importable `fuzzlab` in the server's cwd and
   ignores `PYTHON*` variables. Same module, same code.
2. Laravel's argv is `php -S 127.0.0.1:<port> -t <app>/public <router>` with cwd
   `public/`, where `<router>` is the app's `server.php` if present, else
   `vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php`. The
   draft's `-t public server.php` assumed a root `server.php`, which Laravel 13 does not
   ship; this is exactly what `ServeCommand` runs.
3. There was no labgen import guard to update; one was added
   (`tests/test_procutil_guard.py::test_labgen_imports_only_itself_the_label_contract_and_procutil`).
   It allows `fuzzlab.labgen`, `fuzzlab.labels` (four pre-existing imports) and
   `fuzzlab.procutil` -- not procutil alone.
4. The supervisor also gives the server `PDEATHSIG(SIGKILL)` through `preexec_fn`, so
   a SIGKILLed supervisor takes its direct child with it. The "no `preexec_fn`" rule is
   about the owner (threads); the supervisor is single-threaded.
5. Two pipes per server: a control pipe (owner → supervisor: the stop token; EOF is a
   third owner-death signal) and a status pipe (supervisor → owner: `ready`, `error`,
   `exit reason=…`). They make a requested stop distinguishable from an unrequested
   one, which D17's loud failure needs.
6. D15 is tested with a SIGSTOPped supervisor (it cannot act on SIGTERM) rather than a
   test-only "ignore TERM" switch in production code.
7. `greybox/reset.py` is unchanged (cleared in the sweep), so CC-FUZZ-0069 is unused.
8. Beyond the listed test files, every test `subprocess.run` of a forking tool with a
   timeout was converted (8 files), because the AST guard now forbids it.

### Found and fixed while verifying
A clean `stop_server` occasionally raised `ServerLost` under CPU load (1 in 250
start/stop cycles with three busy loops; seen once in a targeted test run): the owner
writes its stop token and then signals, but the SIGTERM handler could run between the
supervisor's control-pipe drain and its signal check, so a requested stop read as
unrequested. The supervisor now drains the pipe again before calling a stop
unrequested (`_Supervisor._stop_reason`): 0 in 500 under the same load, and a
deterministic test injects the interleaving
(`test_a_stop_token_that_lands_before_its_signal_is_never_misread_as_unrequested`).

### Review round 1 (CC-CORE-0050, 2026-10-14)
Reviewer B agreed; reviewer A found two kill paths that could signal processes this
run did not start (pid_max is 32768 here, so pids wrap within minutes). The rule both
fixes follow: **a group or session id may be signalled only while its leader pid is
still held -- alive, or an unreaped zombie with the recorded start time.**
- **A-M1 (supersedes B's should-fix 1).** The supervisor's grace loop reaped
  (`waitpid(-1)`) its server, then the SIGKILL loop kept calling `killpg` on the freed
  group id while a setsid-escaped descendant lived. *Mechanism:* `_reap` now reaps every
  exited child **except the server** (each zombie child found in `/proc`, by pid); the
  server is reaped by `_reap_server` only after the last `killpg` (bounded, loud if it
  cannot be reaped). *Test:* the supervisor runs under a spy that records, at every
  `os.killpg`, whether `read_stat(group)` exists; a server that exits on SIGTERM with a
  setsid child that ignores SIGTERM forces the SIGKILL phase; every call must find the
  leader held. Reverting the fix fails it.
- **A-M2.** (a) The owner reaped the supervisor (`Popen.wait`) and only then swept its
  session. *Mechanism:* `stop_server`, `reap_registered` and the asyncio path wait with
  `waitid(P_PID, pid, WEXITED|WNOHANG|WNOWAIT)` in a timeout loop, then sweep, then
  reap. asyncio's own `create_subprocess_exec` would reap the supervisor as soon as it
  exits, so `astart_server` now spawns it with `subprocess.Popen` and offers an asyncio
  view (`_AsyncSupervisorProc`: stream readers, a non-reaping `wait()`,
  `communicate()`); `astop_server` runs the same stop steps off the loop. (b) The
  fallback's pgid kill now also requires `st.sid == supervisor pid` (the supervisor is
  alive at fallback time, so that id is anchored), and the fallback also kills the
  supervisor's other descendants and session members before the supervisor itself.
  (c) `_members` accepts an absent leader only with such an anchor (a held
  `(sid, start)`); otherwise it returns nothing. *Tests:* a reaped supervisor's session
  faked onto a bystander (`_iter_stats`/`read_stat` monkeypatched) is never swept; a
  bystander faked into the server's freed pgid but outside the session is never
  signalled by the fallback; an externally SIGKILLed supervisor's leftover child is
  swept (sync and asyncio) because the supervisor is still held.
- **B-2.** A start time of 0 meant "match anything". *Mechanism:* 0 is "identity
  unknown": `_members` returns nothing, `_signal_checked` refuses, `start_server`
  refuses loudly (`ProcUtilError`, after the supervisor has stopped what it started),
  and the safety net reports such a record (`note="identity unknown: not signalled"`)
  without signalling it. *Tests:* a group whose leader is gone with a live member and a
  start-0 record naming it: nothing is signalled, the leak is reported; `start_server`
  with an unknown supervisor start time raises and leaves nothing.
- **A-S1.** The server's `child_setup` re-checks `getppid()` against the supervisor's
  pid after its `prctl` (the fork-to-prctl race) and exits if the supervisor is gone.
  Not testable deterministically (a race of a few instructions); recorded as such.
- **A-S2 (measured, once).** A throwaway script ran a pytest in its own session, opened
  a real Chromium page (about:blank), SIGKILLed the pytest, and counted by session id
  and by the recorded process tree (pid + start time, never by name): before, 9
  descendants -- the Playwright node driver in pytest's session and 8 chrome processes
  in their own (detached) session; 5 s after the SIGKILL, **0 of 9** alive and 0 left in
  pytest's session. Playwright's own cleanup held. Not a standing test: follow-up owner
  the crawler component (04), recorded on NFR-LAB-cleanup's `Not yet enforced:` line.
- **B-3 / B-4 (nits).** The dead `if not _send(...): pass` is gone (the safety net was
  rewritten). `web/runner.py` documents that `allow_thread=True` is right because
  `serve()` runs uvicorn's loop on the main thread, and that a shorter-lived loop thread
  (TestClient's portal) stops its jobs loudly; a test checks `serve` calls
  `uvicorn.run` on the main thread.
- **A-N1.** `_members`' docstring states that pids wrap quickly (pid_max 32768 here) and
  an id is only trusted while its leader pid is held.
- **Mutation check (round 1), one mutant at a time over `tests/test_procutil.py`, the
  failed-build cleanup test and `tests/test_web_runner.py`: 22/26 killed**, each
  must-fix's revert among them: A-M1 revert (supervisor reaps the server mid-
  termination) killed; A-M2(a) "owner reaps before the sweep" and "asyncio-style reap
  on exit" killed; A-M2(c) "absent leader trusted without an anchor" and "anchor's
  session not required" killed; B-2 "unknown identity accepted at start" killed. (A
  separate held re-check inside the sweep was removed: it duplicated
  `session_members`' rule, and its revert could not fail any test.) The four
  survivors: the fallback's group TERM without its anchor (with the
  leader gone and no anchor, `_members` returns nothing, and the session/descendant
  kill that follows reaches the same processes -- no unsafe signal results), B-2's
  explicit `leader_start <= 0` guard (subsumed by A-M2(c): an absent leader without an
  anchor already yields nothing), the "members no older than the leader" filter
  (unreachable while the leader is held), and A-S1's race re-check (not deterministic).
  None of the survivors lets a signal reach a process this run did not start.

## What was verified here (and what was not)
- Real processes, offline: `tests/test_procutil.py` (22), `tests/test_live_boot_cleanup.py`
  (8: a real Laravel boot — composer offline from the local cache, `php -S` — and a
  real Go boot; `close()` leaves the port refusing and no process in the server's group
  or the supervisor's session; a build that fails after the server started leaves
  nothing), the web-runner and Lab-page additions, the AST guard (24).
- Mutation check of the supervisor and identity gates (one mutant at a time, targeted
  tests): **17/18 killed**. The survivor drops the "member started no earlier than the
  leader" filter; with the leader start-time check intact, a group or session id can
  only name our leftovers, so it is a defense-in-depth filter with no reachable
  distinguishing case (equivalent here).
- Owner death: an owner process SIGKILLed with a server whose grandchild escaped its
  group **and** session (setsid + double fork) — nothing survives within 10 s; the same
  with `go run` and its built binary.
- **Not run here:** the Rails, Spring Boot and Django harnesses and the npm/mvn test
  servers need network installs this session did not make (no traffic to external
  hosts); their conversion is the same code path, checked by source for all five
  harnesses, and runs in the orchestrator's full suite.

## Sweep (PA-0002, by mechanism; PA-0067(1): each site with its lifetime and verdict)

| Site | Mechanism | Lifetime / owner | Disposition |
| --- | --- | --- | --- |
| `labgen/conformance/live_boot.py` `LiveBootHarness.build` | `Popen(php artisan serve)` | server, harness | **Fixed**: `start_server(php -S …)` direct; `close()` → `stop_server`; `__enter__` closes on failure |
| `live_boot.py` `_run` (composer install, artisan key:generate), `_composer_network_probe` | `run(timeout=)`, forking | build step | **Fixed**: `run_bounded` |
| `live_boot.py` `MariaDbServer` (`service mariadb start/stop`, `mariadb` client) | `run(timeout=)` | system service owned by init by design; stopped by `teardown()` only if it started it | Cleared: not a test-owned tree; clients are short, non-forking |
| `rails_live_boot.py` server, `_run` (bundle install, db:prepare, `bundle exec ruby`), probe (`bundle lock`) | `Popen`, `run(timeout=)` | server (puma), build steps | **Fixed**: `start_server` / `run_bounded`; `__enter__` closes on failure |
| `live_boot_spring_boot.py` server (`java -jar`), `_run` (mvn package), probe (mvn dependency:get) | `Popen`, `run(timeout=)` | server, build steps | **Fixed** (same) |
| `go_live_boot.py` server (built binary), `_run` (go build), probe (go list) | `Popen`, `run(timeout=)` | server, build steps | **Fixed** (same) |
| `django_live_boot.py` server (`runserver --noreload`), `_run` (venv, pip, migrate), probe (pip download) | `Popen`, `run(timeout=)` | server, build steps | **Fixed** (same). `InternalServiceFixture` is an in-process thread: cleared |
| `labgen/conformance/tier0.py` (`php -l`, `py_compile`) | `run(timeout=)` | one non-forking compile check | Cleared |
| `web/runner.py` `Runner.launch` | `asyncio.create_subprocess_exec` | operator job, UI | **Fixed** (D18): `astart_server`, whole-tree stop, `shutdown()` on lifespan |
| `web/labcontrol.py` `fetch_states` (`labctl.sh ps`) | `create_subprocess_exec`, `proc.kill()` on timeout | short query that forks the engine | **Fixed**: `arun_bounded` (timeout stops the tree) |
| `greybox/reset.py` `ScriptLabControl._default_runner` (`labctl snapshot/restore`) | `run(check=True)`, no timeout | foreground; the caller waits for the script and its children | Cleared, unchanged: no timeout means no partial kill; an owner killed mid-restore lets a finite restore finish (better than a half-restored DB). CC-FUZZ-0069 not used |
| `tools/corpus_validation_sandbox.py` runsc | `Popen(start_new_session=True)` + cgroups, `proc.kill()` on timeout | sandbox run, bounded by `timeout --kill-after=2` | **Fixed** (D14): timeout → `kill_process_group` (identity-checked) |
| `tools/pattern_corpus_sourcing.py` `default_git_runner` | `run(timeout=600)` of git (forks `git-remote-https`) | sync step | **Fixed**: `run_bounded` |
| `labgen/oracle_wrapper.py` `default_runner` (sqlmap, commix, SSTImap, ZAP) | `run(timeout=)` | oracle run | **Fixed**: `run_bounded` |
| `labgen/nuclei_oracle.py` `default_nuclei_runner` | `run(timeout=)` | oracle run | **Fixed**: `run_bounded` |
| `labgen/secret_scanner.py` `default_runner` (gitleaks) | `run()`, no timeout | single non-forking scan, runs to completion | Cleared |
| `tools/spider.py`, `tools/fetcher.py`, `tools/browserexec.py` | Playwright `chromium.launch` (library-managed driver + browser) | crawl / fetch | Not changed. **Residual (flagged):** on the owner's SIGKILL, cleanup relies on Playwright's driver noticing its pipe close and closing its browsers; not verified here |
| 11 test files with `Popen` servers (list above) | `Popen` + `terminate()` | test server | **Fixed**: `start_server` / `stop_server` |
| Test `run(timeout=)` of npm / go / mvn (8 files) | forking tool | install / build / `go run` proof | **Fixed**: `run_bounded` |
| Test `run(timeout=)` of `php -l/-r`, `node --check`, `node <runner>` | non-forking | one check | Cleared |
| Every harness `__enter__` | `build()` raising after the server started | harness | **Fixed** (all five): close, then re-raise |

The guard (`tests/test_procutil_guard.py`) keeps this table true: a new spawn outside
procutil fails the suite.

## Recurrence review
Checked `docs/bugs/` (grep for orphan, zombie, terminate, leak, teardown, subprocess)
and `docs/PREVENTIVE_ACTIONS.md`.
- **BUG-0011 → PA-0012** (an asyncio server's shutdown hung): the teardown rule every
  live-boot harness cites for its `close()` ("bounded, deterministic teardown"). Same
  family — a stop that did not do what its caller assumed — different defect (an
  unbounded wait there; an incomplete stop here).
- **BUG-0033 → PA-0035** (a capability probe that did not exercise the real
  operation): PA-0035 also requires every later subprocess step to enforce its own
  timeout, and `_run` did — with `subprocess.run(timeout=)`, which kills only the
  direct child. A sibling: the prescribed mechanism bounded the *wait*, not the *tree*.
- **BUG-0078 → PA-0079** (the D15 exit left an orphan run row): a lifecycle cousin —
  an aborted path left state behind that later readers treated as live. Different
  resource (a store row), same shape (cleanup only on the happy path).
- **BUG-0123** `navguard.release()`: teardown that silences in-flight browser handlers
  — the closest prior work on "nothing keeps running after teardown", scoped to one
  browser context.
No prior bug is the same defect (a leaked process tree), but PA-0012 and PA-0035 were
the rules in force on exactly the code that leaked, so their failure is analysed.

## Prior-preventive-action failure analysis
- **PA-0012 (BUG-0011) — too narrow, and satisfied by the leaking code.** It asks for a
  bounded teardown of an asyncio server. The harnesses applied it to a subprocess
  (their docstrings say so) and met its letter: `terminate()` then `wait(5)` then
  `kill()` is bounded. It never asked whether the stop was **complete** — whether the
  process signalled was the whole server — so it could not catch a launcher whose child
  survives.
- **PA-0035 (BUG-0033) — right instinct, wrong layer.** It made every later subprocess
  step enforce its own timeout "at the shared helper that runs it". `_run` did exactly
  that with `subprocess.run(timeout=)`, whose timeout kills the direct child only; for
  composer, npm, go, mvn and bundle the tree survives. A bounded wait was mistaken for a
  bounded tree.
- **Not enforced.** Neither rule had a test that looked for residue: no test asserted
  that nothing was left after `close()`, after a timeout, or after the owner's death,
  and nothing checked at the end of a session. PA-0020/PA-0033's lesson (a rule needs a
  mechanical check) was not applied to process lifetime.

## Preventive action
**PA-0125** (strengthens PA-0012 and PA-0035 from bounded to complete, and adds the
enforcement neither had): a process the toolkit or its tests start owns its whole
process tree, grandchildren included: started in its own session under a supervisor
tied to its owner's life, stopped as a group, identity-checked, never killed by
pattern; a real-process test proves nothing survives `close()` or the owner's death.
Enforced by `tests/test_procutil_guard.py` (AST, synthetic offenders), the session-end
safety net (`tests/_leak_guard.py`, which fails the run), and the real-process tests
named under NFR-LAB-cleanup.

## Clean-up of the host
The orchestrator stopped the 429 + ~16 orphans by PID before this fix (the operator's
bWAPP and Juice Shop were not touched). While this fix was being verified, eight more
`php -S … /tmp/fuzzlab-php-laravel-live-boot-*/…/Console/../resources/server.php`
orphans (the `artisan serve` form, so from a run of the pre-fix code in another
session) were present; this session did not start them and did not stop them.
