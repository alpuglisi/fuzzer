# BUG-0126 — The M6 browser executor had never worked against a real browser

- Date: 2026-10-14
- Status: fixed (CC-FUZZ-0071, CC-CRAWL-0018, CC-AUD-0037)
- Severity: medium. `fuzzlab auto --browser` was unusable here, and on a host where it
  launched it missed every DOM XSS that renders asynchronously (any single-page app).

## Description
The first live run of `fuzzlab auto --browser` (Juice Shop, forms phase 3 integration)
exposed two defects in `tools/browserexec.PlaywrightBrowserExecutor.run`:
1. **It ignored the configured Chromium.** The crawler and the auditor launch the binary
   named by `PLAYWRIGHT_CHROMIUM_EXECUTABLE`; the executor called
   `pw.chromium.launch(headless=…)` without it and failed (`Executable doesn't exist at
   …/chrome-headless-shell`). The exception was not contained, so **the whole run
   aborted** at the first browser check (`rc=1`).
2. **It looked too early.** After `page.goto(..., wait_until="load")` it slept a fixed
   300 ms and read the sentinel once. Juice Shop renders its search results after its own
   API call; the payload in `#/search?q=` fired at about one second, so the DOM XSS was
   reported as not executing (verified: with a 3 s wait it fires).

## Where encountered
The forms phase 3 live run on the operator's loopback Juice Shop lab (127.0.0.1:3000).

## What it caused to fail
`--browser` (M6: DOM and stored XSS confirmation) on this host; DOM XSS detection on
asynchronously rendered sinks everywhere.

## What the bug was identified to be
A component tested only against a fake Playwright: its launch configuration drifted from
the other launch sites, and its timing was never measured on a real page.

## Root cause analysis
1. *Why did the run abort?* The executor's launch failed and nothing contained it.
2. *Why did the launch fail?* It did not pass the configured binary; the crawler and
   auditor did, each with its own copy of the launch configuration.
3. *Why could the copies drift?* Three launch sites built their keyword arguments
   separately; nothing made them one (PA-0003), and BUG-0123's AST guard checked only
   that each used `browser_launch_args`.
4. *Why was the 300 ms wait never caught?* Every executor test used a fake Playwright
   (`tests/test_destructive_urls.py`, `tests/test_browser_scope.py`): no test loaded a
   real page whose sink fires after `load`.

**Root cause:** the M6 executor was never exercised against a real browser and a real,
asynchronously rendering page; its launch configuration was a copy, not the shared one.

## Corrective action
- `navguard.chromium_launch_kwargs(args, headless=)`: the one launch configuration
  (args, headless, the operator's binary). The crawler, the auditor and the executor
  all use it; the BUG-0123 AST guard now also requires it at every
  `chromium.launch` (proven on its synthetic offender).
- The executor contains a launch failure: it records why, logs once, and raises
  `UnplaceableLocation` for this and every later probe in the run: no verdict from the
  browser mechanisms (never a negative, never a crash); other mechanisms still decide.
- `PlaywrightBrowserExecutor.SETTLE_MS` (4000): the sentinel is polled every 100 ms
  after `load`, ending at the first hit. Verified live: Juice Shop's `#/search?q=` DOM
  XSS now confirms (2.1 s); a negative costs the full window.
- Tests: `tests/test_browser_scope.py::test_the_m6_executor_uses_the_configured_chromium`;
  `::test_a_browser_that_cannot_start_is_no_verdict_never_a_crash_or_negative` (a failed
  launch is `UnplaceableLocation`, remembered: one launch attempt; the DOM strategy
  propagates it); `::test_the_m6_executor_sees_a_sink_that_fires_after_load` (a real
  Chromium and a page whose sink runs 1.2 s after `load`: confirmed; its escaping twin
  is not; the old 300 ms read misses it, proving the fixture is asynchronous). The
  fake-Playwright pages in `test_browser_scope.py`, `test_destructive_urls.py` and
  `test_json_points.py` gained the settle poll's `wait_for_timeout`. The live Juice
  Shop re-run is the end-to-end check (`xss-dom` on `/#/search?q` confirmed).

## Recurrence review
- **BUG-0123** (this session): fixed the browser's network scope at the three launch
  sites but left their launch configurations as three copies; its guard checked one
  argument, not the whole configuration.
- **PA-0035** ("probe the real operation"): the executor's tests never probed a real
  browser.

## Prior-preventive-action failure analysis
PA-0035 was not applied to M6: its tests were all fakes, because the executor "runs
on-host only". PA-0123 required each launch to be scoped, not to share one configuration.

## Preventive action
**PA-0126** (strengthens PA-0035 and PA-0123): every Chromium launch takes its whole
configuration from one helper (`chromium_launch_kwargs`), guarded at every
`chromium.launch`; a browser mechanism has at least one real-browser test against a page
whose sink fires after `load`, and a browser that cannot start is "no verdict", never a
crash or a negative.

## PA-0002 sweep
| Site | Result | Disposition |
|---|---|---|
| `tools/spider.py _start_browser` | own copy of launch kwargs | fixed (helper) |
| `tools/fetcher.py _start_browser` | own copy | fixed (helper) |
| `tools/browserexec.py run` | no binary; uncontained launch; 300 ms wait | fixed |
| `tests/_browser.py launch_browser_or_skip` | test harness, own candidates list | cleared (tests choose their binary; not product code) |

## Residuals
- A negative DOM-XSS check costs up to 4 s per payload (4 payloads).
