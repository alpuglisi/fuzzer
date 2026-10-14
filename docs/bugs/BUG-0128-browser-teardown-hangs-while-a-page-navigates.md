# BUG-0128 — Browser teardown can hang while a page is still navigating

- Date: 2026-10-14
- Status: fixed (CC-CRAWL-0020)
- Severity: medium. A run that hangs never finishes and never reports: the crawler,
  the auditor and the M6 executor all tear their browser down the same way.

## Description
`tools/navguard.release(context)` (BUG-0123) calls `context.unroute_all(behavior=
"ignoreErrors")` before the context is closed. When a page of that context was still
navigating, with requests paused in interception, the driver sometimes never answered
the `setNetworkInterceptionPatterns` call behind `unroute_all`. The sync API then
waited forever.

## Where encountered
While adding reviewer A's and B's navigation test for the M6 executor (forms phase 3
review round). The test page fires the payload and navigates away at once. The test
hung (pytest killed after 45 s by `faulthandler_timeout`) in about 1 run in 9.
Tracing every Playwright call over 25 runs pinned it: the last call was
`BrowserContext.unroute_all`, entered just after a `/next` navigation's route was
fulfilled, and it never returned.

## What it caused to fail
Any browser teardown that races a navigation or an in-flight request:
- `fuzzlab auto --browser`: an app that navigates during the settle wait (redirects
  after a timer, SPA route changes);
- the crawler and the auditor at the end of a crawl, on an app with polling or
  timed navigation.

The process hangs with no error and no report.

## What the bug was identified to be
Teardown changed interception (unroute) while traffic was still in flight, and nothing
bounded the wait.

## Root cause analysis
1. *Why did the run hang?* `unroute_all` never returned.
2. *Why?* The driver did not answer the interception change while the page had a
   navigation (and its paused, routed requests) in flight.
3. *Why was traffic in flight at teardown?* `release` unrouted first and closed the
   pages last (with the context), so pages kept navigating and requesting during the
   unroute.
4. *Why was it not caught?* No test tore a browser down while its page was navigating.
   The real-browser tests' pages are idle at teardown, and the race is intermittent.

**Root cause:** the teardown did not stop its sources of in-flight work (the pages)
before an operation that waits on that work.

## Corrective action
- `navguard.release` closes every page of the context first, each failure ignored,
  then calls `unroute_all(behavior="ignoreErrors")`. Closing the pages ends their
  navigations and requests, so the unroute has nothing in flight. All four teardown
  sites already go through `release`: `spider.py` (crawl and the anonymous submission
  context), `fetcher.py` and `browserexec.py`.
- **Measured:** before the fix, 1 hang in 9 runs of the navigation test (and 1 in 6
  under pytest). After it, 80 runs in a row with no hang. At the old rate, the chance
  of 80 clean runs by luck is under 1 in 10,000.
- Tests:
  - `tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting`
    (deterministic order; the reverted order fails);
  - `tests/test_browser_scope.py::test_a_hit_before_the_page_navigates_is_kept`
    (the real-browser reproduction).

## Recurrence review
- **BUG-0011 / PA-0012 — the same root cause in another layer.** The async proxy's
  shutdown awaited `wait_closed()`, which waits on active connections that never end.
  PA-0012 said to track and cancel in-flight work and bound the final wait, but only
  for "an `asyncio` server".
- BUG-0123 introduced `release()` for teardown noise (`TargetClosedError`), not for
  ordering. BUG-0125 (process trees) is teardown of processes, a different mechanism.

## Prior-preventive-action failure analysis
PA-0012 was **too narrow**: it named one API (`asyncio.Server.wait_closed`), not the
principle. `release()` was written later for a different API (Playwright's interception)
and nothing pointed its author to PA-0012. The rule also asked for a timeout, which a
sync Playwright call cannot take. The layer-independent lesson is to stop the sources
of in-flight work first, and only then wait.

## Preventive action
**PA-0128** (strengthens and generalises PA-0012): every teardown first stops its
sources of in-flight work (connections, pages, child tasks) and only then makes a call
that may wait on that work. Where the wait cannot be bounded (a sync Playwright call),
quiescing first is mandatory. A teardown has a test that starts it with work still in
flight.

## PA-0002 sweep
| Site | Teardown | Disposition |
|---|---|---|
| `navguard.release` | unroute before pages closed | fixed |
| `spider.py` crawl end, `_submit_anonymously` | through `release` | fixed (by `release`) |
| `fetcher.py` | through `release` | fixed (by `release`) |
| `browserexec.py` | through `release` | fixed (by `release`) |
| `proxy/AsyncProxyServer.stop` | cancels connections, bounded `wait_closed` (BUG-0011) | cleared |
| `procutil` / BUG-0125 supervisors | stop, then wait, bounded (BUG-0125) | cleared |

## Residuals
- `release` cannot bound a driver that stalls for another reason (a sync Playwright
  call takes no timeout). The known trigger is removed. Bounding it would need the run
  to supervise the driver process, which is out of scope here.
