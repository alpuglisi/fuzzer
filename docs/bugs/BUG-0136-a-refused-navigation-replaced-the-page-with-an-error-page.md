# BUG-0136 — A refused navigation replaced the crawled page with Chromium's error page

- Date: 2026-10-14
- Status: fixed (CC-CRAWL-0028)
- Severity: medium (coverage, not safety). Nothing left the scope and nothing
  destructive was sent: the refusal itself was right. But a page whose script
  navigated somewhere the guard refuses lost its rendered content and links to the
  crawl, silently.

## Description
`tools/navguard.make_route_handler` aborts a request it refuses. For most reasons it
called `route.abort()` with Playwright's default error code (`"failed"`). For a
**navigation** (top-level or frame), Chromium answers a failed navigation by committing
its own error page (`chrome-error://chromewebdata/`) in the frame. So when a page's
script navigated (`location.href = …`) after load to a URL the guard refuses, the page
the crawl was reading was replaced: its content, title and links were Chromium's
error page. Only two branches used `"aborted"` (ERR_ABORTED, which leaves the current
document in place): the reveal window (FR-CRAWL-15/16) and, since BUG-0134's T1, the
session-withheld branch.

The reasons that still used the default code were:
- out of scope (BUG-0123);
- a destructive URL (BUG-0111);
- a refused method (the crawl's DELETE rule);
- a refused body (FR-SESS-19's login window);
- the same checks on a redirect hop;
- a chain over `MAX_REDIRECTS`;
- an unfetchable request.

## Where encountered
BUG-0134's review round 3 (V2 test): an authenticated crawl whose page navigated by
script to an out-of-scope host stored the error page for A; A's `/next` link was never
crawled. The lane flagged it; the coordinator confirmed it as a defect.

## What it caused to fail
- **FR-CRAWL coverage:** the page's content and links were lost whenever its script
  navigated to a refused URL. Common causes are a "logout" redirect after idle time, a
  link to another service on the host, and an analytics or SSO redirect off scope.
- **Silent:** the page was stored with status 200 and the error page's text, so
  nothing showed the loss.

## What the bug was identified to be
The abort code was chosen per branch, not per kind of request. The two branches that
already handled navigations correctly were never generalised.

## Root cause analysis
Five Whys:
1. *Why did A's content disappear?* The main frame committed Chromium's error page.
2. *Why did it commit an error page?* The guard aborted the script's navigation with
   the default error code, and Chromium treats a failed navigation by showing its error
   page.
3. *Why the default code?* Each abort site in `make_route_handler` wrote its own
   `route.abort()`. Only the reveal window (written with this exact concern, W2) and
   BUG-0134's T1 chose `"aborted"`, each for its own branch.
4. *Why was it not generalised when it was first understood?* The reveal window's
   "`ERR_ABORTED`, so the page stays" was recorded as a property of the window
   (FR-CRAWL-16), not as a rule about aborting navigations. T1 fixed the same symptom
   for the withheld branch only; its review scoped the fix to FR-SESS-20.
5. *Why did no test catch it?* The guard's tests used fake routes that recorded "abort"
   without a code, and the real-browser scope tests checked that nothing left scope,
   not what the page showed afterwards.

**Root cause:** the abort code of a navigation was decided separately at each abort
site, with no single rule. The correct choice, known in two places, was treated as
local to those features.

## Corrective action
CC-CRAWL-0028:
- **`tools/navguard.py`:** one rule in the handler. `document = _is_document(req)` (a
  navigation, top-level or frame, or a `document` resource) is decided once. Every
  abort goes through `abort()`, which uses `_abort_code(document)`: `DOCUMENT_ABORT =
  "aborted"` for a document request, the default for a subresource. This covers every
  reason and every redirect hop.
- **Callers' signals are unchanged:**
  - `page.goto` of a refused target still raises (`net::ERR_ABORTED`), and the page
    already shown stays;
  - the spider's bookkeeping (`skipped_out_of_scope`, `skipped_destructive`,
    `skipped_other_origin`, `SessionWithheld`) comes from the callbacks, which are
    unchanged;
  - a refused navigation of the crawl's own target still raises, so its static
    fallback or SessionWithheld path runs as before.
- **Tests** (`tests/test_navigation_aborts.py`):
  - the abort code pinned for 11 reasons × {navigation, subresource};
  - real Chromium: a script navigation out of scope and one to `/logout.php` each keep
    A's content and get `/next` crawled, with the reason still recorded;
  - real Chromium: `goto` of a refused target raises `ERR_ABORTED` and leaves the page.
- **Fake routes** in `tests/test_browser_scope.py` and
  `tests/test_session_browser_login.py` now accept and record the code.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0134 / PA-0134 (round 2, T1):** **the same defect**, fixed for one branch only
  (the session-withheld abort used `"blockedbyclient"`, which also commits an error
  page). This is a recurrence: the same root cause in the sibling branches.
- **The reveal window (FR-CRAWL-15/16, CC-CRAWL-0024):** chose `"aborted"` for exactly
  this reason ("a navigation aborted as ERR_ABORTED leaves the page where it is"), but
  as a window-local choice.
- **BUG-0123 / PA-0123** (scope checked where each request is made): introduced the
  scope aborts this bug concerns. PA-0123 was about *whether* to abort, not *how*.
  Same layer, different defect.
- **BUG-0128 / PA-0128** (teardown while a page navigates): another navigation-lifecycle
  bug in the same handler; different cause (ordering of unroute and close), not a
  recurrence.

Result: a recurrence of BUG-0134 T1's defect (a navigation aborted with an
error-page code), in the branches T1 did not touch.

## Prior-preventive-action failure analysis
**BUG-0134 (T1) / PA-0134.** T1 replaced `"blockedbyclient"` with `"aborted"` in the
withheld branch. It did not prevent this because:
1. **Too narrow.** PA-0134 is about where session secrets go. T1 was recorded as a
   FR-SESS-20 fix, so the abort-code lesson had no rule of its own, and the PA-0002
   sweep for BUG-0134 enumerated sites that apply session secrets, not abort sites.
2. **Not enforced.** No test pinned the abort code per reason. The fake routes dropped
   the code entirely, so a default-code abort and an `"aborted"` one looked the same.

The reveal window's choice (CC-CRAWL-0024) likewise lived only in that feature's text.
PA-0136 makes it one rule, in one helper, pinned per reason.

## Preventive action
**PA-0136** (strengthens PA-0003/PA-0087 "one policy decision, one place" for the
browser guard, and generalises BUG-0134 T1 and the reveal window's choice), in
`docs/PREVENTIVE_ACTIONS.md`.

### PA-0002 sweep (every abort of a navigation)
| Site | Reason | Before | Disposition |
| --- | --- | --- | --- |
| `navguard.make_route_handler`, first request | out of scope (BUG-0123) | default | **fixed**: `abort()` |
| same | destructive (BUG-0111) | default | **fixed** |
| same | reveal window (FR-CRAWL-16) | `"aborted"` for a navigation | unchanged rule, now via `abort()` |
| same | refused method (DELETE, FR-CRAWL-12) | default | **fixed** |
| same | refused body (FR-SESS-19 login window) | default | **fixed** |
| same | session withheld (FR-SESS-20) | `"aborted"` for a document (T1) | unchanged rule, now via `abort()` |
| redirect hop | no request client / out of scope / destructive | default | **fixed** |
| redirect hop | reveal window | default | **fixed** (a navigation's hop is a navigation) |
| redirect hop | refused body (307/308) | default | **fixed** |
| redirect hop | session withheld (landing) | `"aborted"` for a document | unchanged rule, now via `abort()` |
| chain over `MAX_REDIRECTS` | — | default | **fixed** |
| unfetchable request (exception) | — | default | **fixed** |
| `navguard.make_ws_handler` | WebSockets | never connected (no abort code applies) | not this class |
| `spider` (`_guard`), `fetcher` (auditor), `browserexec` (M6), `browserlogin` | — | all install `navguard.guard_page`; none aborts a route itself (`grep route.abort`/`.route(` over `fuzzlab/`) | covered by the one rule |
| `spider._isolated_submit` (`checked_api_request`) | API request, not a navigation | raises before sending | not this class |

## Review of the fix (added in review)
Reviewer A agreed; reviewer B agreed with changes (D50, X1–X5). What the review found
is a consequence of the fix itself: ERR_ABORTED keeps the current document, which is
the point, but that document **keeps running**, and some callers relied on the error
page to stop it.

- **X1 (B-M1), the crawl's own failed `goto`:** after a refused target (or any failed
  load), the page shown before stayed alive, so its timers and fetches went on, and
  they were sent and captured (`discovered_requests.page_url`) under the URLs crawled
  next. Fixed: `_fetch_rendered`'s `except` sends the page to `about:blank` first, as
  the reveal window already does when it cannot close cleanly (CC-CRAWL-0024). Pinned
  by `test_a_failed_load_ends_the_previous_document`: a 50 ms POST ticker on A, A's
  link /go redirecting to /logout.php. The server gets no tick after the fallback's
  own request, and nothing is captured but what A sent before it ended. A fetch A sent
  just before it ended can still finish after the mark, so the test bounds those at 2;
  that is in-flight work, not the leak. Without the line, a burst of ticks reaches the
  server after the fallback and is captured under /next.
- **X2 (B-S1), the M6 semantic shift (CC-FUZZ-0082, FR-FUZZ-48).** Measured on a real
  browser, for a page that navigates by script to /logout.php:

  | When the page navigates | Before (default code) | After (`"aborted"`) |
  | --- | --- | --- |
  | after its sink fired | executed=True | executed=True |
  | after `load`, no sink | executed=False | executed=False |
  | after `load`, sink fires later | executed=False (false negative) | **executed=True** |
  | during parsing / at `DOMContentLoaded` | executed=False | **`goto` times out, the run raises** |
  | the target's own redirect is refused | raises `ERR_FAILED` | raises `ERR_ABORTED` |

  The fourth row is open and flagged, not built. A raise from the executor is
  contained by neither the oracle nor the pipeline (it ends the confirmation loop),
  which is already true for the last row and for any `goto` timeout. Rows 1, 2, 3 and 5
  are pinned (`test_m6_*`).
- **X3 (B-S2), the browser login:** a refused submission now leaves the login page,
  and its filled password field, alive until teardown. The field is cleared first
  (CC-SESS-0023 amendment, FR-SESS-19).
- **X4 (A-S1, A-S2):** real-Chromium pins added: the crawl's own target redirected to
  a refused URL (raises, the page stays, recorded through the static fallback), a
  script-submitted POST form to a refused URL (page kept, nothing posted), and a
  refused iframe (parent kept).
- **X5:** unit pins for an iframe navigation and for a `document` request whose
  `is_navigation_request` raises (B-N1); NFR-CRAWL-safe states that a refused
  navigation looks like nothing happened and shows only in `skipped_*` and the summary
  (A-N1). B-N3 is accepted as is.

Sweep additions (the PA-0002 table above, for what keeps running after an abort):
| Site | After a refused navigation | Disposition |
| --- | --- | --- |
| `spider._fetch_rendered` (`except`) | the previous page ran on into the next URLs | **fixed** (X1): `about:blank` first |
| reveal window close failure (`spider._window`) | pages closed, route page sent to `about:blank` | already handled (CC-CRAWL-0024) |
| `browserlogin._drive` after a refused submission | login page alive with the password filled | **fixed** (X3): field cleared |
| `browserexec.run` | the page stays; the context is closed right after the wait | no leak (one probe per context); verdict shift recorded (X2) |
| `fetcher.ContentFetcher.fetch` (auditor, `tools/fetcher.py`) | the same leak: one page for the whole audit, `_xhr_urls` reset per URL, `except` goes straight to the static fallback, so a previous page's XHRs are listed under the next URL's `xhr_urls` | **open, flagged**: the same one-line fix belongs to the auditor component (a CC-AUD entry), which this lane has no number for |
