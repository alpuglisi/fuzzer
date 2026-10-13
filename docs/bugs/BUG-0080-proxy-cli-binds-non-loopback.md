# BUG-0080 — `fuzzlab proxy` bound any host, e.g. `--host 0.0.0.0`

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0019, CC-CORE-0034, CC-UI-0049)
- Severity: high. Decision D11 and NFR-PROXY-safe say loopback only. The CLI (and the
  web launcher, which passes `--host` through) exposed an intercepting proxy to the
  network.

## Description
The loopback check existed in three copies with different host sets:
- `web/app.serve` (`ipaddress.is_loopback`) for the panel and the in-process proxy;
- `OobListener` (a literal set);
- `labgen/oracle_wrapper` (a target check).

The standalone proxy CLI and `AsyncProxyServer` had **none**, so `fuzzlab proxy
--authorized --host 0.0.0.0` bound every interface.

## Where encountered
The error-review phase (`scratchpad/review7/r4_proxy_bind.py`: the CLI would bind
0.0.0.0; the web launcher builds the same argv).

## What it caused to fail
The loopback-only guarantee for the most dual-use component.

## What the bug was identified to be
A safety gate kept as copies at some call sites, with one listener left uncovered.

## Root cause analysis
1. *Why did the CLI bind 0.0.0.0?* No check was there.
2. *Why not?* Each listener author wrote, or forgot, their own check.
3. *Why copies?* No shared helper existed.
4. *Why undetected?* No test asserted that every listener is gated.

**Root cause:** a convention kept as copies (PA-0003), not enforced at every listener.

## Corrective action
- **One gate (CC-CORE-0034).** `core.net.is_loopback_host` accepts `localhost`, all of
  127/8, `::1` (bracketed or not) and IPv4-mapped loopback. `require_loopback` raises.
- **Every listener uses it** (CC-PROXY-0019, CC-UI-0049):
  - the proxy CLI, which exits 2 before binding;
  - `AsyncProxyServer.start` (defence in depth);
  - `ProxyController.build`;
  - `app.serve`;
  - `OobListener`. Its accepted set widens from three literals to all of loopback; it
    never narrows.
- **Tests** (`tests/test_loopback_listeners.py`):
  - host truth tables;
  - the CLI refuses four non-loopback hosts and never reaches `start`;
  - the server, the controller and OOB refuse;
  - **an AST guard**: every `start_server` / `HTTPServer` / `bind` / `uvicorn.run` in
    `fuzzlab/` binds a literal loopback, or sits in a function or class that calls
    the gate. It is proven on a synthetic offender.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **PA-0003** (one convention, one helper): **not followed** for the loopback gate.
- **BUG-0050 / PA-0052:** a lab-only filter built from a hardcoded literal. Related,
  but about the crawler's target scope, not listeners.

**Result:** a recurrence of the PA-0003 class at a new site.

## Prior-preventive-action failure analysis
PA-0003 was **not followed and not enforced**. It asks for one helper when a
convention spans sites, but nothing checked that new listeners used it, and the proxy
CLI predates any shared helper.

## Preventive action
**PA-0081** (strengthens PA-0003 for safety gates):
1. Every listener the toolkit opens goes through `core.net.require_loopback`.
2. **Enforced by a guard test** that finds listeners by call shape, so a new one is
   covered without being listed.

**Sweep (PA-0002):**
- **Listeners:** proxy CLI, proxy server, in-process proxy, web serve and OOB, all
  gated. The labgen live-boot servers bind literal `127.0.0.1` (the guard accepts
  that).
- **`labgen/oracle_wrapper`:** gates a *target* URL, not a listener. Its strict set is
  left as is.
