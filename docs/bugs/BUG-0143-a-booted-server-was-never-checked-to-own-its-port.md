# BUG-0143 — a live boot accepted any process listening on its port as its own server

- Date: 2026-10-15
- Status: fixed
- Severity: high (test validity). A live-boot test could run against another test's
  application and report what that application did: a wrong pass, a wrong fail, or a
  connection reset. Twice before, the failure was set aside as "only under concurrent
  load" without being root-caused.

## Description
Every live-boot harness (Laravel, Go, Django, Rails, Spring Boot) and eleven test-side
server starts followed the same steps:
1. pick a free port by binding port 0 and closing the socket;
2. start the server on that port;
3. wait until a TCP connect to the port succeeded.

Between steps 1 and 2 the port is free for any process to take. When another process
held it:
- the new server failed to bind;
- the connect succeeded against the other process;
- the boot was reported as complete;
- the test's requests went to the wrong application.

## Where encountered
The serial list run with 3 workers (`ser10`, BUG-0142 work):
`tests/test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real`
failed with `ConnectionResetError` inside the oracle's probe to the Twitch clone's
`/channels/redirect`. The same test had failed twice before under concurrent pytest
load, on 2026-10-14. The decision log recorded it then as a "WATCH" item: "pass
isolated … if it fails in the serial full suite → investigate".

## What it caused to fail
- Parallel test runs could not be trusted for any of the 16 boot sites.
- The suite's slowest pass had to stay serial, about 39 minutes instead of about 15.
- Worse, a wrong-application result is silent whenever the other application happens
  to answer plausibly.

## What the bug was identified to be
Reproduced deterministically, with no concurrency needed:
1. start an HTTP server answering `I AM A DIFFERENT SERVER` on port P;
2. force the Go harness's port pick to P;
3. boot it.

The harness reported a successful boot, and its base URL answered
`I AM A DIFFERENT SERVER`. The loopback-only check (BUG-0130) also passed, because the
Go process, which could not bind, held no listening socket of its own.

## Root cause analysis
**Method: barrier analysis.** It fits better than Five Whys because the defect passed
through several controls, and each of them has to be explained.

| Barrier | Why it did not stop this |
|---|---|
| The boot wait (`_wait_for_boot` and the test-local `_wait_until_listening`) | It checked *that* a listener existed, never *whose* it was. A connect cannot tell the two apart. |
| The early-exit check (`proc.poll()`) | It ran before the connect in each loop. A server that fails to bind exits a few milliseconds after start, and the first connect had already succeeded. |
| `assert_loopback_only` (BUG-0130) | It checks that the server's sockets are not exposed beyond loopback. "No sockets at all" passes, vacuously. |
| Running tests serially | It made the race rare; it did not remove it. Ports came from the ephemeral range, which other host processes also use. |
| The investigation of the 10-14 failures | A failure only under load was classed as load sensitivity and parked, not reproduced. That repeats the "flake" anti-pattern the project's rules forbid. |
| Shared-primitive control (`docs/SHARED_PRIMITIVES.md`, PA-0003) | "Start a server and wait for it" had 16 copies across 5 harnesses and 11 test sites, none listed as a shared mechanism. No owner existed to fix once. |

**Root cause:** server readiness was defined as "the port accepts a connection" rather
than "this server's own process listens on the port". The definition was copied into
every boot site instead of owned in one place, and a failure that pointed at it was
classified as load sensitivity instead of being reproduced.

## Corrective action
Commit (with CC-CORE-0057, FR-CORE-41, CC-LAB-0257, FR-LAB-174):
- **`procutil.port_owner(h, port)`** reports `ours`, `taken` or `none`, from the server
  tree's own listening sockets (the BUG-0130 `/proc` inspection).
- **`procutil.wait_until_listening`** raises `PortTaken` or `ServerDidNotListen`.
- **`procutil.start_server_on_free_port`** owns the whole sequence: pick a port, start,
  wait for its own listener, and retry a taken port up to 3 times.
- **The five harnesses** accept a boot only at `ours`. They raise `PortTaken` when the
  port is answered by another process (and on an early exit if so), and retry on a
  fresh port.
- **The eleven test-side starts** now use `start_server_on_free_port`, and their
  bare-connect wait helpers are deleted.
- **`tests/test_server_port_ownership.py`:**
  - a port held by another process is never taken;
  - a taken port is retried, and the server really answers;
  - an exiting server is reported, not waited out;
  - the real-Go reproduction;
  - an AST guard: every function that picks a port and starts a server must prove
    ownership, or be allow-listed with a reason. It flags all 16 pre-fix sites and
    passes all 16 now.

## Recurrence review
- **BUG-0130 / PA-0130** (lab servers pinned to loopback, checked on real sockets): the
  same mechanism (`procutil.listeners`) and the same boot sites. Its check asked
  "exposed beyond loopback?", never "is it the server's?". **Related, and a prior PA
  failure** (below).
- **BUG-0125** (process-tree lifecycle): the same sites; its lifecycle is unchanged
  here.
- **BUG-0135** ("timing tests failing under load"): the same classification error, a
  failure under concurrency treated as an environmental artefact. **Same root pattern**
  in how failures are triaged.

## Prior-preventive-action failure analysis
- **PA-0130** pinned what a booted server may listen on. It never required that the
  server *is* the listener. That was too narrow: it validated the server's sockets when
  present, and accepted their absence.
- **PA-0135** and the orchestration rule "never call a failure flaky" (MULTI_AGENT §2):
  the rule existed when this test failed on 10-14, yet the failure was parked as a
  WATCH item. The rule had no enforcement: nothing required a reproduction before a
  failure under load could be set aside.
- **PA-0003** (a shared convention gets one owner): not applied. "Start a server and
  wait for readiness" was never recognised as a shared mechanism, so 16 copies grew.

## Preventive action
PA-0149:
1. Readiness means the server's own process listens on its port. Use
   `procutil.start_server_on_free_port` or `wait_until_listening` (guarded by
   `tests/test_server_port_ownership.py`).
2. A failure seen only under concurrency is reproduced deterministically, or tied to a
   specific shared resource, before it is set aside. A WATCH entry is not an outcome.
3. "Start and wait for a server" is listed in `docs/SHARED_PRIMITIVES.md` with its
   owner and guard.

**PA-0002 sweep:**
- all 23 modules calling `start_server(` were classified: 16 fixed, 2 allow-listed with
  reasons, and 5 out of scope (no port pick, or a different `start_server`);
- two in-process `uvicorn` servers (`test_web_launcher_browser`,
  `test_web_repeater_browser`) fail loudly on a taken port rather than reach another
  process: residual;
- `test_live_boot_cleanup`'s "port released" assertion can fail loudly if another
  process takes the freed port: residual, never a false pass.
