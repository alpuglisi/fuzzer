# BUG-0522 — A failed load's late error page overtook the next navigation

- Date: 2026-10-19
- Status: fixed (CC-CRAWL-0049, CC-AUD-0053, CC-SESS-0027, CC-FUZZ-0104)
- Severity: medium. Every guarded browser (crawler, auditor, disco, browser login, M6)
  lost the navigation after a failed load of an empty error answer. A rendered page fell
  back to a plain request, so its links and fetch endpoints were lost. Disco lost harvest
  loads and states. Seeds failed. No safety rule was broken: nothing outside the guards
  was sent.

## Description
A load can fail with an error status and an empty body
(`net::ERR_HTTP_RESPONSE_CODE_FAILURE`). Chromium then commits its own error page,
`chrome-error://chromewebdata/`, tens of milliseconds after `goto` has raised. Any
navigation made in that gap is overtaken. Playwright reports it as "interrupted by
another navigation to chrome-error://", yet the browser keeps it and commits it later
(measured: 30 of 30, 6–69 ms later). That late commit overtakes the navigation after
it in turn.

The X1 cleanup (BUG-0136 review) navigated to `about:blank`, with the error suppressed,
straight after the failure. That blank was overtaken, landed late, and interrupted the
next load. Callers that navigated straight on were overtaken by the error page itself:
disco's harvest and `restore`, and the spider's pre-seed blank.

## Where encountered
BUG-0509's lane (DG-SPIDER): a two-worker spider crawl lost a page's fetch endpoints.
The cause was traced to a load that followed a failed one. It was reported as a
separate open defect, and the DG-NAVBLANK lane measured it through each tool's real path.

## What it caused to fail
Before the fix, on a8b81df and bf1356a: the `C0` rows of DG-NAVBLANK, as ranges over
three runs at different machine loads, and the reviewer's run.

| Path | Lost |
|---|---|
| Spider's next load after an empty 404 | 14–19/20 |
| Same, after two or three in a row | 14–20/20 |
| Auditor's next fetch after an empty 404 | 10–16/20 |
| Same, after two or three in a row | 13–20/20 |
| Any next navigation through `navguard.navigate` | 24–40 of 40 |
| Disco harvest load | 11–20/20 |
| Disco restore | 15–20/20 |
| A seed after a failed load | 8–15/20 |
| `_leave` after a failed seed (it raised) | 8–20/20 |

## What the bug was identified to be
A failed navigation raised before the browser had finished what the failure starts, and
callers navigated straight on. Specifically:

1. `navguard.navigate` and `reload` (SP-01) re-raised a failed `goto` at once.
2. X1's cleanup, in two copies (the spider and the auditor) and one ad-hoc site (the
   spider's window close), navigated over the coming error page.

## Root cause analysis
Five whys:

1. Why did the next load fall back to a request? Its `goto` raised "interrupted by
   another navigation to about:blank" (or to chrome-error://).
2. Why was another navigation in flight? X1's `about:blank`, made right after the
   failure, was itself interrupted by Chromium's error page. Its error was suppressed,
   and the browser still committed it later.
3. Why was the error page still to come? Chromium commits it asynchronously after the
   failed navigation's `goto` has raised: p50 about 25 ms, worst measured 304 ms.
4. Why did nothing wait for it? SP-01's `navigate` treated "`goto` raised" as "the
   navigation is over". X1 was proven only against a refused load (ERR_ABORTED), which
   commits no error page.
5. Why was that never caught? No test made a failed load with an error page followed by
   another navigation. The round-1 draft of this fix then judged "the error page has
   come" by the page's current URL. After one failure that URL already is an error page,
   so a second failure in a row was unprotected (lost 7–18/20 over the runs).

**Root cause:** a failed navigation was treated as finished when Playwright raised,
not when the browser had committed what the failure starts. The cleanup that followed
was written and tested against one kind of failure only.

## Corrective action
CC-CRAWL-0049 (SP-01), CC-AUD-0053, CC-SESS-0027, CC-FUZZ-0104:

- `navguard.navigate` / `reload` settle a failure before re-raising (`_settle_failure`).
  - Which failures wait is read only from the first line of the message:
    - a network error other than an abort waits for one fresh `chrome-error:` commit;
    - "interrupted by … chrome-error://" waits for that commit and then one more, the
      overtaken navigation landing.
  - A commit counts only when a listener registered before the navigation saw it.
  - The wait is at most `ERROR_PAGE_WAIT_MS` (3 s). Every expiry is counted
    (`error_page_waits()`) and logged.
- `navguard.end_failed_load` decides the cleanup: nothing when the failure settled on the
  browser's error page (it replaced the previous document), else `about:blank` as X1.
- The spider's `_fetch_rendered` and `_window` and the auditor's `fetch` call
  `end_failed_load`.
- An AST guard holds every other `about:blank` navigation to a reasoned allow-list.

## Recurrence review
- **BUG-0136 / PA-0136** (an abort replaced the page with an error page; the X1 cleanup
  came from its review). Same area, different failure: PA-0136(3) asked that a fix of
  one branch sweep its siblings. X1's cleanup was written for the refused-load branch
  and never measured on the error-page branch.
- **BUG-0138 / PA-0138** (a load a refused navigation cancelled was waited out).
  PA-0138(1) made SP-01 the one navigation helper, and PA-0138(3) asked a fix of a
  shared primitive to follow every consumer. SP-01 was the right owner; its failure path
  was never examined.
- **BUG-0504 / PA-0504** (teardown let a just-started navigation out). The same class:
  a browser action assumed finished when the API returned. PA-0504 covered closing a
  page, not a failed navigation.

## Prior-preventive-action failure analysis
PA-0136(3) and PA-0138(3) both ask for a sweep of sibling branches and consumers. Neither
prevented this, for two reasons:

- **Too narrow.** They are phrased per primitive and per branch ("every abort site",
  "every caller of the helper"). The missed case is a *sequence*: a failure, then
  whatever navigates next. No per-site sweep reaches it.
- **Not enforced for sequences.** The guards check where navigation happens (an AST
  guard), not what a failure leaves behind.

The round-1 draft repeated the class: its "wait" read a stale state (the current URL)
instead of an event that happened after the action. PA-0522 strengthens both rules. A
failed navigation is over only when what it starts has landed, judged by events seen
since it started. A cleanup that navigates is measured against every kind of failure
before it, including several in a row.

## Preventive action
PA-0522. Its text is in `docs/PREVENTIVE_ACTIONS.md`; the orchestrator writes it at
merge.
