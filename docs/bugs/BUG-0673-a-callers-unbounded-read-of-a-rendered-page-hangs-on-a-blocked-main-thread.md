# BUG-0673 — A caller's unbounded read of a rendered page hangs forever on a page whose main thread is blocked

- Date: 2026-11-20
- Status: **open** (found by lane NAV's sweep of BUG-0672; not fixed in that lane --
  flagged to the orchestrator for its own item)
- Severity: medium (availability). A target page in `while(true){}` hangs the auditor's
  fetcher and the spider with no bound; nothing outside the guards is sent.
- Records: ERROR_LOG 2026-11-20 (open); BUG-0672 (the teardown half, fixed).

## Description
After a guarded navigation, the callers read the rendered page through Playwright sync
calls answered by its renderer, with no deadline: `page.content()`, `page.title()`,
`page.evaluate(...)`, locator reads. A page whose script blocks its main thread after
load never answers them, and the caller waits forever, before its teardown (now
bounded by BUG-0672) is ever reached.

## Where encountered / measured
Lane NAV, 2026-11-20, sweeping BUG-0672's primitive. A loopback page that blocks its
main thread 50 ms after load, headless shell 157.0.8103.78, each run killed after 60 s:
- `ContentFetcher.fetch` (AUD): last Playwright call `Page.content` at
  `fuzzlab/tools/fetcher.py:507` (after `wait_for_state` at :493 returned).
- `LocalSpider._fetch_rendered` (CRAWL): last call `Page.title` at
  `fuzzlab/tools/spider.py:2319` (after `wait_for_state` at :2415).
- `PlaywrightBrowserExecutor.run` (FUZZ) does **not** hang before teardown (7.3 s with
  the BUG-0672 fix).
Measured by wrapping `SyncBase._sync` to log each call
(`scratchpad/probe/trace_sync.py`, `sweep_hang.py`).

## What it causes to fail
A crawl or audit of a target with such a page never finishes.

## Root cause (so far)
Renderer-bound reads with no bound, the same class as BUG-0672, outside teardown. The
means to bound them exists (`navguard._bounded`, SP-115); the fix is to route every
renderer read of a guarded page through one bounded owner and to treat an expiry as a
failed load (the page then replaced, since every later renderer call on it hangs too).

## Why not fixed in lane NAV
It spans dozens of read sites across `spider.py` (a hot file owned by other lanes),
`fetcher.py`, disco and ede, and needs a decision on how a hung page is replaced
mid-crawl. Recorded and flagged rather than built partially. The recurrence review and
preventive action follow BUG-0672/PA-0672 and are to be completed with the fix.
