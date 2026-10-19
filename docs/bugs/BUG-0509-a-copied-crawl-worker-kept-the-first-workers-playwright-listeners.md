# BUG-0509 — A copied crawl worker kept the first worker's Playwright listeners

- Date: 2026-10-19
- Status: fixed (CC-CRAWL-0047)
- Severity: medium. Every `--workers N` (N > 1) Playwright crawl since CC-CRAWL-0037: the
  fetch/XHR endpoints the other workers' pages requested were lost or filed under the
  wrong page, and their failures and finishes were counted on the first worker's page.

## Description
`LocalSpider._clone` made each extra crawl worker by copying the first worker's
`__dict__`. The copy is taken after the first worker's browser has started, and
Playwright's sync API caches the wrapper of a bound-method listener on the method's own
object: `page.on("request", self._on_request)` stores it as
`self._pw_impl_instance__on_request` (`ImplToApiMapping.wrap_handler`). The clone got
those attributes, so its own `page.on("request", self._on_request)` found the cached
wrapper and registered the **first worker's** `_on_request` (likewise
`_on_request_failed`, `_on_request_finished` and `_dry_request`). Every request event of
another worker's page reached the first worker's per-page state.

## Where encountered
The verification harness on CC-CRAWL-0047 (FR-CRAWL-29):
`tests/test_spider_trace.py::test_every_page_row_names_the_page_that_queued_it[playwright-2]`
found `/api/items` with `found_from` `/a`, though only `/b`'s script fetches it.
Reproduced in 1 of 8 two-worker crawls; instrumented (each listener call logged with
its object, its thread and the request's frame), worker 2's navigation to `/b` and both
of `/b`'s fetches were delivered, on worker 2's thread, to worker 1's `_on_request`
while worker 1 was loading `/a`. `/a`'s visit returned them as its own XHR endpoints and
queued them with `found_from` `/a`; `/b`'s visit returned none. In other runs worker 1
had already moved on and the endpoints were lost (no row at all).

## What it caused to fail
- XHR/fetch endpoints of pages loaded by any worker but the first: lost, or queued
  from whatever page the first worker was loading (wrong `found_from` and depth since
  FR-CRAWL-29).
- The M8 in-flight and the failed-request bookkeeping (`_on_request_failed`,
  `_on_request_finished`) of another worker's page applied to the first worker's.
- `_dry_request` registered on a clone's anonymous dry-submit page: its blocked write
  recorded against the first worker's state.
Two crawls of the same site with `--workers 2` could disagree on which API endpoints
exist; nothing failed visibly.

## What the bug was identified to be
A shallow copy of an object that a third-party library had already annotated: the
library's per-object cache (keyed by attribute name on the object) was copied with the
crawl state, and it decides which handler a later `page.on(...)` registers.

## Root cause analysis
Five whys:
1. Why was `/api/items` filed under `/a`? Worker 1's `_xhr_urls` held it when `/a`'s
   load returned.
2. Why did worker 1's list hold a URL worker 2's page requested? Worker 2's page
   called worker 1's `_on_request` (instrumented: object id of the callee is worker 1's,
   the thread is worker 2's, the frame URL is `/b`).
3. Why was worker 1's handler registered on worker 2's page? `page.on` registers
   `wrap_handler(handler)`, which for a bound method returns the wrapper cached on the
   method's object when there is one; worker 2 had one.
4. Why did worker 2 have one? `_clone` copied every attribute of worker 1, after
   worker 1's `_start_browser` had registered its listeners (and so cached them).
5. Why did the copy include it? `_clone` copied `__dict__` wholesale and then reset the
   attributes it knew to be per-worker; an attribute added by a library is unknown to
   that list.

**Root cause:** cloning by wholesale `__dict__` copy assumes every attribute on the
object is the crawl's own; Playwright attaches per-object state (its listener wrapper
cache) that must never be shared between workers.

Measured (not inferred): a minimal two-thread Playwright script, each thread its own
`sync_playwright` and listener with no copying, never crossed (3 runs × 24 navigations);
the crossing appears only through the copied cache.

## Corrective action
`LocalSpider._clone` copies every attribute except Playwright's cached listener
wrappers (`_PW_HANDLER_CACHE`, Playwright's own `IMPL_ATTR` imported, its value as a
fallback). Tests: `tests/test_spider_trace.py::test_a_cloned_worker_never_inherits_playwrights_cached_listeners`
(the mechanism still holds -- `wrap_handler` caches on the object -- and the clone
carries none) and `::test_each_workers_page_events_reach_that_worker` (two real
browsers: the second worker loads `/b`, the first `/c`; judged by what each worker
recorded itself). Both fail with the old copy. After the fix every listener call ran
on its own worker's object (30 instrumented two-worker crawls). The remaining
differences: 2 of 30 instrumented crawls lost `/b`'s endpoints, each after `/b`'s
load was interrupted (logged) -- the separate defect below; 3 of 12 uninstrumented
crawls lost them (two) or filed them under `/d`, the page that worker loaded next
(one) -- not instrumented, consistent with the same interruption (a document whose
load was abandoned still running), not shown to be it.
With the test site's 404s given a body (no failed load): 60 of 60 two-worker crawls
put both endpoints under `/b`, and the module passed 16 of 16 runs, 8 of them four at
a time. CC-CRAWL-0047.

## Recurrence review
Checked `docs/bugs/` for `_clone`, shallow copies, worker state, `wrap_handler` and
Playwright listeners, and `docs/PREVENTIVE_ACTIONS.md` for copying and per-thread state.
Related, not the same root cause: PA-0023 (BUG-0021), shared thread-affine handles on
one object; here the state was not shared deliberately but copied unknowingly. No prior
occurrence of copying a library-annotated object found.

A second, separate pre-existing defect was found while reproducing this one and is
**not** fixed here (outside this change's files; it needs its own number and a sweep):
after a load fails with an error status and an empty body
(`net::ERR_HTTP_RESPONSE_CODE_FAILURE`), Chromium commits its own
`chrome-error://chromewebdata/` page; the spider's teardown of a failed load
(`navguard.navigate(page, "about:blank")`, BUG-0136 review X1) is "interrupted by
another navigation to chrome-error://" and its error suppressed, but the `about:blank`
navigation still lands later and interrupts the **next** load ("Navigation to … is
interrupted by another navigation to about:blank"), which then falls back to a static
request: its JavaScript-built links and its fetch/XHR endpoints are lost (a seed load,
with no fallback, fails). Measured in a single Playwright page: 29 of 40 loads after a
failed one interrupted; retrying `about:blank` until shown: 10 of 40; waiting for the
load state first: 18 of 40; skipping `about:blank` once the error page has committed:
0 of 40. The same teardown is in `tools/fetcher.py` (the auditor). Reported to the
orchestrator; `tests/test_spider_trace.py`'s site answers its 404s with a body so this
module's expectations do not depend on it.

## Preventive action
PA-0509 (text handed to the orchestrator for `docs/PREVENTIVE_ACTIONS.md`): an object
copied to make another worker copies only state the code owns. A clone made by copying
`__dict__` after the original was handed to a library (registered as a listener, route
or callback) excludes the library's per-object attributes, and a two-worker test judges
each worker's events by what that worker recorded itself. Sweep: `LocalSpider._clone`
(fixed); `disco.explore.Explorer._clone` copies `__dict__` too, but before any worker's
browser starts (`run` clones first), so no listener is cached at copy time; safe today,
and recommended to filter the same way.
