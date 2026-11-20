# BUG-0672 — Releasing a guarded context hung forever on a page whose main thread was blocked

- Date: 2026-11-20
- Status: fixed (CC-CRAWL-0641; CC-FUZZ-0671)
- Severity: medium (availability). A target page that blocks its main thread
  (`while(true){}`, a runaway script) hung `navguard.release` -- and with it the M6
  executor's probe, and any teardown through `close_pages` -- with no bound: the run
  never finished. No traffic or safety rule affected.
- Records: ERROR_LOG 2026-11-20, PA-0672, CC-CRAWL-0641, CC-FUZZ-0671, F-672; BUG-0673
  (the open sibling: callers' own reads of such a page).

## Description
`close_pages` (SP-38, BUG-0504) freezes every page before draining and closing it
(`Emulation.setScriptExecutionDisabled`), and `release` adds a refusing route on the
context before the close. Both are answered by the page's renderer; a renderer whose
main thread is blocked never answers, and Playwright's sync calls take no deadline, so
the teardown waited forever.

## Where encountered
An independent verifier on real Chromium 1243 (pre-existing at d492b9d), through the
full `PlaywrightBrowserExecutor` on a page whose script blocks after load; relayed to
lane NAV by the orchestrator (2026-11-20).

## What it caused to fail
- `PlaywrightBrowserExecutor.run` never returned (reproduced: killed after 90 s at
  d492b9d; 7.3 s after the fix with `timeout_ms=5000`).
- Every teardown through `release`/`close_pages` (spider windows and stop, disco, the
  fetcher, ede, the browser login) with such a page open hung the same way.

## What the bug was identified to be
Two renderer-bound calls in a teardown with no bound.

## Root cause analysis (measured, then Five Whys)
Measured per call on a page in `while(true){}` 50 ms after load, one process per call,
25 s cap, headless shell 157.0.8103.78 and full 153.0.8010.12 alike:
`Emulation.setScriptExecutionDisabled`, `BrowserContext.route`,
`Runtime.terminateExecution` never return; `new_cdp_session` 4 ms, `Page.stopLoading`
6-9 ms, `wait_for_timeout(100)` 102-105 ms, `page.close()` 505-509 ms,
`context.close()` 11-17 ms, `Target.closeTarget` 8-9 ms. Pinned:
`tests/test_chromium_navigation_outcomes.py::test_a_blocked_main_thread_answers_only_the_browsers_own_calls`.
1. Why did `release` hang? Its freeze call never returned.
2. Why not? The renderer handles it on its main thread, which a page script held.
3. Why was it waited on unbounded? Playwright's sync API has no deadline for a CDP call
   or a route, and nothing bounded it.
4. Why was that thought safe? PA-0128(1) made quiescing first mandatory *because* a sync
   Playwright call cannot be bounded -- it took the quiescing call itself to be one
   that always returns.
5. Why untested? BUG-0504's and BUG-0128's tests start a teardown with work in flight
   (a navigation, a request), never with a renderer that cannot answer.
- **Root cause:** teardown calls that wait on the page's own renderer, unbounded, under
  the assumption that the quiescing step itself cannot block.

## Corrective action (CC-CRAWL-0641)
- `navguard._bounded(owner, sync_call, impl_call, pump, budget_ms)`: runs one Playwright
  sync object's call as a task on Playwright's loop, driven by `pump.wait_for_timeout`
  in short steps (a driver timer, answered while a renderer is blocked), for at most
  `budget_ms`; True if it finished, else left pending with its late outcome consumed.
  A double without Playwright's loop is called plainly.
- `close_pages`: the freeze and `add_route` (the refusing route `release` passes) each
  bounded by `RELEASE_CALL_MS` (2 s), every expiry counted (`release_expiries()`) and
  logged; a page that did not answer its freeze is closed after the drain and before the
  route is added (it starts nothing: its main thread is blocked), the others after it,
  in BUG-0504's order.

## Sweep (PA-0002, by primitive: every caller of `close_pages` / `release`)
`release`: browserexec, fetcher, spider (`_stop_browser`, windows), disco explore, ede,
browserlogin; `close_pages`: spider `_close_window_pages`, disco explore 1903 -- all
bounded now by construction. The sweep found the same class outside teardown, not
fixed here: the callers' own reads of a rendered page (`page.content()` in
`fetcher.py:507`, `page.title()` in `spider.py:2319`, and every other unbounded
renderer call) hang on such a page **before** teardown is reached (measured: both
killed after 60 s). Filed as BUG-0673 (open), with `_bounded` as the means.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for teardown liveness and
renderer waits: **BUG-0128 / PA-0128** (teardown unrouted while a page navigated; the
driver sometimes never answered), **BUG-0504 / PA-0504** (teardown let a paused request
out; freeze-drain-close introduced), PA-0012 (a server wait with no bound). Same class
as BUG-0128: a teardown call that waits on work it does not control.

## Prior-preventive-action failure analysis
- **PA-0128(1)** ("stop sources of in-flight work first, and only then make a call that
  may wait on that work; where the wait cannot be bounded, quiescing first is
  mandatory") was **wrong at one layer**: the quiescing call (freeze) is itself a call
  that waits on the page, and the rule assumed it returns. Its test checks call order
  on fakes.
- **PA-0504(2)** ("a page is frozen and drained before it is closed") made the freeze
  mandatory without a bound, so it turned a page that cannot answer into a teardown
  that cannot end.
- **PA-0504(3)** tested a refused request at teardown; neither PA tested a renderer that
  cannot answer: **too narrow**.

## Preventive action
PA-0672 (strengthens PA-0128(1) and PA-0504(2)): every call a teardown makes that the
page's renderer must answer is bounded (`navguard._bounded`), counted and logged on
expiry, and the teardown then goes on with the calls the browser itself answers (stop,
timer, close); a teardown is tested against a page whose main thread is blocked, on
every binary.
