# BUG-0670 — An empty HTTP error answer was a page on the headless shell and a failure on the full browser: SP-01's error-page path depended on the binary

- Date: 2026-11-20
- Status: fixed (CC-CRAWL-0640; callers CC-SESS-0640)
- Severity: medium. No safety rule broken (nothing outside the guards was sent). The
  outcome of a guarded navigation to an empty 4xx/5xx depended on which Chromium binary
  ran: on the product's default binary (the headless shell) a crawl, audit, login or
  M6 check took it for a rendered empty page; SP-01's error-page path (BUG-0522,
  BUG-0561) was never exercised there.
- Records: ERROR_LOG 2026-11-20, PA-0670, CC-CRAWL-0640, CC-SESS-0640; BUG-0671 (the
  harness binary choice that hid it); F-670, F-671.

## Description
For a navigation whose answer is HTTP 400-599 with an empty body, the full Chromium
fails the navigation (`net::ERR_HTTP_RESPONSE_CODE_FAILURE`) and commits its own error
page after `goto` raised -- the behaviour BUG-0522 and BUG-0561 measured (on 141) and
SP-01 settles on. The headless shell 157.0.8103.78 (Playwright 1.63, build 1243), which
Playwright launches by default and so the product does unless the operator names a
binary, loads the same answer as an empty page with its status. navguard's route
handler fulfils every document it fetched as fetched, so the guarded page inherited
the binary's choice.

## Where encountered
Five `tests/test_navigation_aborts.py` cases failed "DID NOT RAISE" in this container
since the move to build 1243 (`test_a_failed_navigation_returns_after_its_own_error_page[1-3]`,
`test_a_navigation_overtaken_by_an_error_page_waits_for_it`,
`test_an_error_page_ends_the_previous_document`), carried by every lane as "known".

## What it caused to fail
- On the headless shell, for an empty 4xx/5xx top-level answer: the spider stored an
  empty rendered page (no static fallback), the auditor's fetcher returned an empty
  document, disco seeded an empty state, the browser login read an empty page, M6
  reported a negative where the full browser gives no verdict (the caller sweep in
  CC-CRAWL-0640 lists each).
- The same target crawled with two binaries gave two results.
- SP-01's error-page settle (BUG-0522/BUG-0561's fix) had no path to run on the default
  binary through an HTTP answer; its tests failed instead of measuring.

## What the bug was identified to be
navguard relied on a browser behaviour (an empty HTTP error answer fails the
navigation) that one binary has and the other does not, without fixing the outcome
itself.

## Root cause analysis (differential, then Five Whys)
Differential measurement (`tests/test_chromium_navigation_outcomes.py`, 52 cells, three
runs, identical): every cell SP-01 relies on is the same on both binaries -- an abort
(`aborted`) keeps the document; `failed`/`blockedbyclient`, a refused or unsafe port,
a redirect to one, a dropped connection commit the error page after the raise, then
load it (raise-to-commit p50 24-35 ms, p95 56-123 ms; commit-to-load p50 3-36 ms, p95
18-90 ms); a navigation right after the raise is overtaken (shell 30/30, full 18-30/30)
and still lands afterwards -- **except** the empty 400-599 answer (shell: page; full:
error page, 7-80 ms after the raise). A frame's empty 404, a 399, a one-byte 404 are a
page on both. Base on the full binary: the five tests pass (89 passed); on the shell:
they fail.
1. Why did the guarded `goto` of an empty 404 not raise? The headless shell 157 loads
   it as a page.
2. Why did that reach the page? The guard fulfils the fetched answer as it is.
3. Why was that safe before? The full Chromium (and 141) fails such an answer itself;
   every measurement of the path was on the full browser.
4. Why only the full browser? The suite ran the full browser by a path glob while the
   product runs the headless shell (BUG-0671); the records named a version, not a binary.
5. Why did the guard depend on it at all? SP-01 made "what a failure starts has landed"
   its guarantee, but left *whether an answer is a failure* to the binary.
- **Root cause:** an SP-01 premise (an empty HTTP error answer is a navigation failure)
  owned by the browser binary instead of by the guard, and measured on one binary.

## Corrective action (CC-CRAWL-0640)
`navguard.make_route_handler`: when a guarded **main-frame** navigation's final answer
(after its checked redirect chain, the landing included) is HTTP 400-599 with an empty
body (`_empty_error_answer`), the route aborts it with `ERROR_ANSWER_ABORT` (`"failed"`,
`net::ERR_FAILED`) after the observer saw the answer: the browser commits its error page
on every binary, and SP-01's settle waits for it, committed and loaded, as before.
Frames, other statuses, non-empty bodies and subresources are given as fetched.

## Sweep (PA-0002, by primitive: every SP-01 caller and guard user)
A read-only sweep of every caller (fetcher, spider incl. windows/restore/re-adoption/
submissions, disco explore seed/restore/harvest, ede, browserlogin, browserexec):
behaviour on the full Chromium/141 unchanged for the main frame by construction (it
already failed there); on the shell, each now takes its failure path, as on 141. Fixed:
- `session/browserlogin.py::_drive` -- the login-route search let one route's failed
  load end the whole search (on 141 too); now that route is ended
  (`end_failed_load`), noted, and the next tried (CC-SESS-0640,
  `tests/test_browser_login_route_fails.py`, fails on the base).
- Frames excluded after measurement (F-671): aborting them would have changed the full
  browser too and misled the spider's window evidence and disco's answer sign.
Flagged, not changed (outside SP-01; recorded as open in CC-CRAWL-0640): the enforcer's
own refusal (`_REFUSAL`, an empty 403) and `_forward`'s empty 502 reach a top-level
navigation unrouted (an expired or reused landing ticket); on the shell that is a page
at the refused URL, on the full browser an error page.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for SP-01 / navigation-outcome
defects: **BUG-0522 / PA-0522** (a late error page overtook the next navigation),
**BUG-0561 / PA-0561** (a navigation before the error page loaded was dropped),
**BUG-0136 / PA-0136** (the abort code decides whether the document survives),
**BUG-0126 / PA-0126** (a launch copy ignored the operator's binary). Same primitive
and the same class (SP-01's guarantee rested on a browser behaviour measured too
narrowly) as BUG-0522 and BUG-0561.

## Prior-preventive-action failure analysis
- **PA-0522(3)** ("a cleanup that navigates is measured against every way the step
  before it can fail") and **PA-0561(3)** ("measured under each kind of host
  contention") varied the failures and the contention, never the **binary**: too
  narrow. Both measurements ran on the full Chromium only (the harness's glob,
  BUG-0671), so the product's default binary was outside every measurement.
- PA-0522's and PA-0561's enforcing tests drive the premise *through* navguard; none
  pins the raw browser fact (an empty error answer fails the navigation) on its own,
  so when the fact changed the tests failed as "DID NOT RAISE" with no measurement to
  say why: not enforced at the layer that changed.
- PA-0126 kept product launch sites on one helper but not the suite (BUG-0671).

## Preventive action
PA-0670 (strengthens PA-0522(3) and PA-0561(3)): every browser behaviour a shared
primitive relies on is pinned by a raw-browser probe on each binary the product can
run (the default and the full Chromium), per binary; and where binaries differ the
primitive itself fixes the outcome rather than inheriting the binary's.
