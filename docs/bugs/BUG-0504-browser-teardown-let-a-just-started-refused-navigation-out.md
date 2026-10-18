# BUG-0504 — Browser teardown let a refused navigation the page had just started reach the server

- Date: 2026-10-18
- Status: fixed (CC-CRAWL-0040)
- Severity: high (safety). Every guarded browser in the project (crawler, disco, M6
  executor, fetcher, browser login) tears down through `navguard.release`. A page that
  starts a navigation to a refused URL (destructive, out of scope) just as teardown
  runs had that request sent: `/logout.php` reached the server in 8 of 24 and 18 of 80
  M6 runs under 8-way parallel load; 15 of 15 in a direct test.

## Description
`release(context)` closed the context's pages and then called
`unroute_all(behavior="ignoreErrors")` (BUG-0128's order). A navigation the page had
started (an app timer firing) is paused at interception; its route event is
dispatched to the guard only when Python next pumps Playwright events. Closing the page
first let the request out un-intercepted, and unrouting continued any request still
paused with no route left. The guard's route handler was never called for the
leaked request (instrumented).

## Where encountered
`verify_change` on 6a30ec9: `test_m6_a_sink_that_fires_before_a_refused_navigation_is_executed`
failed once in the parallel pass, passed alone. Root-caused, not dismissed: a stress
harness (the test 24-80 times at `-n 8`) reproduced it at 33% / 22%, and instrumented
runs placed the server hit inside or just after `release`, with no route call.

## What it caused to fail
NFR-CRAWL-safe / NFR-FUZZ-safe: a destructive URL is never requested by the browser.

## What the bug was identified to be
Teardown assumed that closing a page cancels what it started. It does not for a
request already handed to interception; and removing the routes releases such a
request rather than refusing it.

## Root cause analysis (Five Whys)
1. Why was `/logout.php` sent? It was neither routed nor refused.
2. Why not routed? The page closed (and the routes were removed) before Playwright
   dispatched its paused route event.
3. Why that order? BUG-0128 put page closes before `unroute_all` to stop a driver hang;
   its rule (PA-0128) is about liveness: "stop sources of in-flight work first".
4. Why did that not cover safety? Closing a page was taken as stopping its in-flight
   work; it stops the page, not a request already at interception, and `unroute_all`
   then continues it.
5. Why not seen for months? It needs a navigation started within milliseconds of
   teardown; serial tests never hit it, a loaded parallel pass does.
   **Root cause:** a teardown that removes a safety guard while work it guards may still
   be in flight, judged by liveness alone.

## Prior-preventive-action failure analysis (BUG-0128 / PA-0128)
PA-0128 (1) "a teardown stops its sources of in-flight work first" was followed: pages
were closed first. It failed because (a) it treated *close* as *stop* -- the page is a
source of new work, but a request already paused is not stopped by closing it; (b) it
was written for liveness (no hang), and its enforcing test checked call order on fakes,
never that a refused request stays refused across teardown; (c) its "measure a race
over enough runs" clause was applied to the hang, not to safety. Wrong layer and too
narrow.

## Corrective action (CC-CRAWL-0040)
- `navguard.close_pages(context, pages)`: the one way a guarded page closes. It
  freezes each page (scripts disabled, loading stopped), drains `RELEASE_DRAIN_MS`
  of event dispatch so a paused request gets the guard's own answer, then closes.
- `release`: `close_pages` with a refuse-everything route added before the close;
  never unroutes.
- Disco's `_close_popups` and the spider's `_close_window_pages` use `close_pages`.
- Measured: 0 of 160 loaded M6 runs leak (was 18 of 80); the direct test 0 of 15
  (was 15 of 15).
- Tests: `tests/test_navigation_aborts.py::test_a_navigation_started_at_teardown_is_refused_never_sent`
  (fails on the old `release` every time), `tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting`
  (rewritten: freeze, drain, refuse, close, never unroute),
  `tests/test_shared_primitives.py::test_a_guarded_page_is_closed_only_through_close_pages`.

## Recurrence review
Same mechanism as BUG-0128 (navguard teardown), different failure: see the analysis
above. PA-0504 strengthens PA-0128.

## Preventive action
PA-0504. Sweep (PA-0002), by primitive: every `release` caller (disco ×2, spider ×2,
fetcher, browser login, M6) goes through the owner; every other page close in
`fuzzlab/` (disco popups, spider window popups) now goes through `close_pages`; the
SP-38 guard keeps it so.
