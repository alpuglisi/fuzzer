# BUG-0130 — Lab servers launched by the harnesses and tests were not pinned to loopback

- Date: 2026-10-14
- Status: fixed (CC-LAB-0255, CC-CORE-0051; launcher note on CC-UI-0053)
- Severity: high (safety). CLAUDE.md: the lab is loopback-only and must never be
  exposed. Deliberately vulnerable apps could listen on every interface of the build
  host while a test ran.

## Description
The live-boot harnesses and the test files start real, deliberately vulnerable lab
servers. Where the server binds was left to each stack's default or to the inherited
environment:
- **Spring Boot** (`live_boot_spring_boot.py` and four tests) started the jar with
  `--server.port=` only. Spring Boot binds **0.0.0.0** by default.
- **Go** (`go_live_boot.py`): the generated `main.go` binds `$HOST` (default
  127.0.0.1), and the harness passes the **whole inherited environment**
  (`_go_env()`), so an inherited `HOST=0.0.0.0` exposes the lab.
- **Node** (`tests/_meadowmart_app.py`, `test_labgen_node_bff_app.py`,
  `test_labgen_node_bff_multitarget.py`, `test_multitarget_category1_combined.py`):
  the emitted `app.js` calls `app.listen(port, process.env.HOST || '127.0.0.1')`, and
  every test passed `{**os.environ, "PORT": ...}` -- the same inherited-`HOST` hole.
- PHP (`php -S 127.0.0.1:`), Rails (`-b 127.0.0.1`) and Django
  (`runserver 127.0.0.1:port`) were already pinned.

## Where encountered
The orchestrator's integration full suite (p3-int + bug-0125 at `83650d6`) failed
`tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`. That
guard treats any call named `start_server` as `asyncio.start_server`, so it flagged the
five harnesses' `procutil.start_server` calls and `run_bounded`'s. The flag was a false
positive for those calls (they launch processes), but right in spirit: reading what
each launched server binds found the Spring default and the inherited-`HOST` hole.

## What it caused to fail
- The loopback-only rule (CLAUDE.md Safety, D11, NFR-LAB-safety): while a Spring Boot
  live-boot test ran, its vulnerable app answered on every interface; a Go or Node
  test run under an environment carrying `HOST=0.0.0.0` (e.g. a shell used for the
  container lab, whose entrypoints set it) would have done the same.
- The listener guard (after BUG-0125 made these launches visible to it).

## What the bug was identified to be
The loopback rule was enforced for **listeners fuzzlab opens itself** (PA-0081: one
gate, an AST guard over `fuzzlab/`), not for **servers it launches as other
programs** -- another language's process, whose bind address is an argument, an
environment variable or a framework default.

## Root cause analysis
Five Whys:
1. *Why did the Spring Boot app listen on 0.0.0.0?* Its argv set the port only, and
   Spring's default `server.address` is all interfaces.
2. *Why did nobody pin it?* The harnesses each followed their stack's own launch
   recipe; only some recipes happen to carry a host (`php -S host:port`,
   `rails server -b`, `runserver host:port`).
3. *Why did the loopback guard not catch it?* PA-0081's guard inspects listener call
   shapes in Python (`asyncio.start_server`, `HTTPServer`, `bind`, `uvicorn.run`) in
   `fuzzlab/` only. A server in another language, started through `subprocess`, has no
   such call; the test files were not scanned at all.
4. *Why did the env-driven stacks (Go, Node) look safe?* Their default is 127.0.0.1,
   but the launch passed the inherited environment, so the default could be silently
   overridden -- by the very variable the container lab sets (CC-LAB-0247).
5. *Why was there no runtime check?* Nothing ever looked at the sockets a launched
   tree actually holds; the guard proves intent in source, not the bound address
   (PA-0035: probe the real operation).

**Root cause:** loopback-only was enforced at the in-process listener call, not at the
real sockets of every server the toolkit or its tests launch; launch sites left the
bind address to framework defaults and the inherited environment.

## Corrective action
- **Pin every server site (CC-LAB-0255).** Spring: `--server.address=127.0.0.1` (the
  harness and four tests). Go harness: `HOST=127.0.0.1` set explicitly in the server's
  environment, never inherited. Node: `HOST=127.0.0.1` in each test's env. The
  CircleFeed raw-socket PHP responder, the `go run` header-sanitisation program and the
  no-ML child server now take their bind host from argv (`127.0.0.1`), so the pin is
  visible at the launch site; the no-ML child also passes it through
  `core.net.require_loopback`.
- **Runtime check on the real sockets (CC-CORE-0051).** `procutil.listeners(h)` lists
  every TCP LISTEN socket held by the server's identity-checked tree (the supervisor
  and its descendants, while its pid is held): `/proc/<pid>/fd` socket inodes mapped to
  `/proc/<pid>/net/tcp` and `tcp6` LISTEN rows (decoded from host-order words; a
  missing `tcp6` -- no IPv6, as here -- is an empty table). `exposed_listeners` /
  `assert_loopback_only` (raises `NonLoopbackListener`) use `ipaddress` (127/8, `::1`,
  IPv4-mapped loopback). **Mechanism chosen:** the check runs in `stop_server` /
  `astop_server` / the safety net (`_stop_core`) while the server is still up -- the
  one choke point every launch site goes through, so it covers every site without
  per-site code: the tree is stopped first, then `NonLoopbackListener` is raised (the
  safety net records it on the leak). In addition, all five harnesses call
  `assert_loopback_only` right after boot (an early failure; `__enter__` then closes),
  and the web launcher reports an exposed job on its stream when it is stopped.
- **The guard's false positive (tests/test_loopback_listeners.py).** A call to
  `procutil.start_server` / `astart_server` / `run_bounded` (or the bare name inside the
  module defining it) is a launch, not a listener; `asyncio.start_server` stays
  covered (`test_the_guard_flags_an_ungated_listener` unchanged, plus a test of the
  exemption). The listener guard now also scans `tests/`.
- **A static pin rule** (`server_launch_problems`): every `procutil.start_server` /
  `astart_server` call in `fuzzlab/` and `tests/` must carry a loopback literal
  (`127.0.0.1`, `localhost`, `::1`) in its argv or `env=` -- directly, in a same-module
  helper they call (`_php_server_argv`), or in the enclosing function's assignment to a
  name they use (`proc_env["HOST"] = ...`) -- and never a wildcard literal (`0.0.0.0`).
  Three launch sites that start no lab server are allowlisted with reasons and exact
  counts (`run_bounded`/`arun_bounded`; the launcher's CLI jobs, whose own listeners
  pass the existing gate; `tests/test_procutil.py`, whose listener tests bind 0.0.0.0
  on purpose). Proven on five synthetic offenders and four pinned forms.

## Sweep (PA-0002: every place fuzzlab or the tests start something that listens)

| Site | How it binds | Before | Disposition |
| --- | --- | --- | --- |
| `labgen/conformance/live_boot.py` (`php -S`) | argv helper `_php_server_argv`: `127.0.0.1:<port>` | pinned | boot check added; verified live (offline) |
| `rails_live_boot.py` (`rails server`) | `-b 127.0.0.1` | pinned | boot check added; not booted here (network install) |
| `django_live_boot.py` (`runserver`) | `127.0.0.1:<port>` | pinned | boot check added; not booted here (network install) |
| `live_boot_spring_boot.py` (`java -jar`) | `--server.port` only -> **0.0.0.0** | **exposed** | **fixed**: `--server.address=127.0.0.1` + boot check; static only (no Maven build here) |
| `go_live_boot.py` (built binary) | `$HOST`, env inherited | **inheritable** | **fixed**: `HOST=127.0.0.1` set + boot check; verified live, incl. an inherited `HOST=0.0.0.0` |
| `django_live_boot.InternalServiceFixture` | in-process `HTTPServer(("127.0.0.1", 0))` | pinned | covered by the listener guard |
| `tests/_meadowmart_app.py`, `test_labgen_node_bff_app.py`, `test_labgen_node_bff_multitarget.py`, `test_multitarget_category1_combined.py` (`node app.js`) | `$HOST`, env inherited | **inheritable** | **fixed**: `HOST=127.0.0.1` in env; static only (npm install) |
| `test_labgen_spring_boot_absent_input_live_boot.py`, `..._trackernest_multitarget.py`, `test_multitarget_category3_combined.py`, `test_multitarget_category4.py` (`java -jar`) | **0.0.0.0** | **exposed** | **fixed**: `--server.address=127.0.0.1`; static only |
| `test_labgen_header_injection_circlefeed_live_boot.py` responder | literal inside the PHP script | pinned (hidden) | host now from argv; verified live |
| same file, `php -S` | `127.0.0.1:<port>` | pinned | verified live |
| `test_labgen_go_live_boot.py` `go run` program | literal inside the Go source | pinned (hidden) | host now from argv; verified live |
| `tests/_no_ml_child.py` (uvicorn) | literal | pinned | host from argv + `require_loopback`; verified live (browser) |
| fuzzlab in-process listeners (proxy, OOB, web panel, repeater) | `core.net.require_loopback` | pinned | unchanged (PA-0081 guard) |
| tests' in-process listeners (marker servers, fixtures) | literal loopback | pinned | now under the listener guard too (`test_every_listener_in_the_tests_is_gated_too`) |
| web launcher jobs (`fuzzlab <tool>`) | the tools' own gated listeners | pinned | checked at Stop (reported on the stream) |
| `run_bounded` tools (composer, npm, go, mvn, bundle, VCS sync, `labctl.sh ps`) | do not listen | n/a | covered by the stop-time check if one ever did |
| container lab (`lab/compose.yaml`) | host-side port binds `127.0.0.1:` (in-container `HOST=0.0.0.0` by design, CC-LAB-0247) | pinned | unchanged; `tests/test_lab_compose_network_isolation.py` |

## What was verified here (and what was not)
- Real processes, offline: a server tree listening on 0.0.0.0 (itself, or a process it
  forked) is caught by `listeners` / `assert_loopback_only` and by `stop_server` (tree
  stopped, then `NonLoopbackListener`); a 127.0.0.1 server passes; the safety net
  records the exposure; the launcher reports it on Stop. The Laravel and Go harnesses
  boot with their boot check and show exactly one listener, `127.0.0.1:<port>`; the Go
  harness stays on loopback with `HOST=0.0.0.0` inherited.
- IPv6: this sandbox has no `/proc/net/tcp6`; IPv6 decoding (`::1`, `::`,
  `::ffff:127.0.0.1`) is tested on synthetic rows only.
- **Not run here:** the Spring Boot (Maven), Node (npm) and Rails/Django (network
  installs) servers. Their pins are checked statically by the pin rule; the stop-time
  runtime check covers them whenever they run (the orchestrator's full suite).

## Mutation check
One mutant at a time over its covering tests (`test_procutil.py`,
`test_live_boot_cleanup.py`, `test_web_runner.py`, `test_loopback_listeners.py`):
**15/16 killed**.
- Runtime check (8/9): only the supervisor's own sockets; every address loopback; wrong
  byte order; LISTEN state not required (killed after adding synthetic established
  rows); the stop does not check; the launcher Stop does not check; a harness skips
  its boot check; the Go harness inherits `HOST` (the real inherited-`HOST=0.0.0.0`
  boot fails). Survivor: dropping the explicit IPv4-mapped loopback branch -- Python
  3.13's `ipaddress` already reports `::ffff:127.0.0.1` as loopback, so it is
  equivalent here; kept for Python 3.11/3.12, which the project supports.
- Static rule and guard (7/7): same-module helpers not followed; enclosing-function
  assignments not followed; a wildcard accepted (killed after adding an offender that
  pins loopback elsewhere but binds `0.0.0.0`); any string counts as a pin; procutil
  launches read as listeners again; the Spring harness without `--server.address`; the
  MeadowMart Node env without `HOST`.

Final targeted offline run: 341 passed, 13 skipped (one pytest process, with
`test_loopback_listeners.py`, `test_lint.py` and `test_requirements_traceability.py`).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for "loopback", "0.0.0.0",
"bind", "listen", "expose".
- **BUG-0080 -> PA-0081** (`fuzzlab proxy --host 0.0.0.0`): the same safety property
  (loopback only) at a different layer. PA-0081 made one gate
  (`core.net.require_loopback`) and an AST guard over `fuzzlab/` listener call shapes.
- **The compose isolation tests** (`tests/test_lab_compose_network_isolation.py`,
  NFR-LAB-safety): enforce loopback for the container lab's published ports -- not for
  servers run directly on the host by the harnesses and tests.
- **CC-LAB-0247** chose `HOST=0.0.0.0` inside containers with the host-side bind as
  the guarantee; the direct-host launches relied on the default and inherited the
  environment.
- **BUG-0125** (this branch) made every launch go through `procutil`, which is what
  made these sites visible to the listener guard.
This is a recurrence of BUG-0080's class (a loopback rule not enforced at every place
something listens), so the prior PA's failure is analysed below.

## Prior-preventive-action failure analysis
- **PA-0081 -- wrong layer, too narrow.** It enforced loopback at the Python listener
  call (`require_loopback` before `asyncio.start_server` / `HTTPServer` / `uvicorn.run`)
  and proved it by call shape. A server launched as another program has no such call:
  its bind address is an argv flag, an environment variable or a framework default,
  invisible to the guard. "Every listener" was read as "every listener call in our
  Python", not "every socket our processes listen on".
- **Scope.** The guard scanned `fuzzlab/` only; the test files, which launch most of
  the lab servers, were never checked.
- **No runtime evidence.** Both PA-0081 and the compose tests check declarations (source
  call shapes, compose port strings). Nothing looked at the real sockets -- the
  PA-0035 lesson (probe the real operation) was not applied to binding.
- **Inherited configuration.** Defaults that are safe (Go/Node `HOST=127.0.0.1`) were
  trusted while the launch passed the whole environment, so the safe default was
  never actually in force.

## Preventive action
**PA-0130** (strengthens PA-0081; related: PA-0035, PA-0125): every server the toolkit
or its tests launch binds loopback **explicitly at the launch site** (argv or an env
value set there, never a framework default or an inherited variable), and the real
listening sockets of its process tree are checked at runtime -- at the stop choke point
for every site, and right after boot in the harnesses -- so an exposed server fails the
run. Enforced by the static pin rule over `fuzzlab/` and `tests/` and the runtime check,
each proven on offenders.
