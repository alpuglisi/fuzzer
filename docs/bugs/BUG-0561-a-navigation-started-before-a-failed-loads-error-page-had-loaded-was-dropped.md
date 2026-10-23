# BUG-0561 — A navigation started before a failed load's error page had loaded was dropped

- Date: 2026-10-23
- Status: fixed (CC-CRAWL-0065)
- Severity: low to medium. About 1% of disco restores under heavy disk I/O lost the
  state they restored and stalled 15 s; the spider's window exits and pre-seed blank
  share the path. No safety rule was broken: nothing outside the guards was sent. A
  residual of BUG-0522, present on every tree since its fix (7393c90 included).
- Records: ERROR_LOG 2026-10-23, PA-0561, CC-CRAWL-0065; agent failure records F-281
  (where it surfaced) and F-282 (the BUG-0522 fix's commit-only settle).

## Description
A failed load of an empty error answer makes Chromium commit its own error page
(`chrome-error://chromewebdata/`) after `goto` has raised. Since BUG-0522,
`navguard._settle_failure` (SP-01) waits for that commit before the failure is
re-raised, so the next navigation is not overtaken by it. But the error page is only
committed at that point, not loaded: its `load` comes 15-25 ms later (p95 about
130 ms under I/O load). An `about:blank` navigation started in that window is
sometimes dropped by Chromium: the CDP timeline shows `frameStartedNavigating`, two
`frameStartedLoading`, one `frameStoppedLoading`, then nothing -- no commit, no
`requestfailed`, no "interrupted by another navigation". Playwright has nothing to
settle on and waits out the whole `goto` timeout (15 s), then raises `TimeoutError`.

## Where encountered
The harness run of e69bd1e (`scratchpad/vverify14/parallel.log`: 5180 passed, 1
failed), recorded as F-281: `tests/test_disco_harvest.py::test_disco_harvest_and_restore_after_failed_loads[2]`
failed in 19.1 s (about 4 s plus one 15 s `goto` timeout; 3.8-10.4 s in the 17 earlier
harness runs that passed). A checker agent was driving large corpora on the same host
(disk 95% full, PSI io some about 19%). The root-cause investigation is
`subagents/workflows/wf_133dd7c1-a2f/journal.jsonl` with its scripts and per-run CDP
timelines in `scratchpad/rca-restore/`.

## What it caused to fail
- **Disco `restore`** (`disco/explore.py`, the `about:blank` before the entry URL, after
  a failed harvest load): `restore` returned False (`_restore_failure =
  "navigation"`), the page stayed on the error page, the state was not restored, and
  the worker stalled 15 s.
- **The same exposure, not separately measured:** the spider's `_window` reload
  fallback and `_leave` (`about:blank` after a failed seed or probe load) and its
  pre-seed blank (errors suppressed: a silent 15 s stall).
- Rates measured by the RCA, `scratchpad/rca-restore/` (one lane per tree in parallel,
  4 CPU hogs, 4 fsync loops and one bulk writer; PSI io some avg10 41-54%):

  | Tree | Restores failed |
  |---|---|
  | 7393c90 (before the batch) | 4/600 |
  | 1ad0fd0 | 2/360 |
  | e69bd1e | 9/840 |
  | every tree, CPU load only (load average up to 15) | 0/1,320 |

  Every failure had the same signature (`about:blank` `goto` raised `TimeoutError`
  after 15,001-15,118 ms). Classed browser-side: an `about:blank` Chromium started
  before the error page's `load` timed out 15 times in 268; started after it, 0 in
  2,012 (Fisher p = 7.9e-15). An http navigation started from a still-loading error
  page: 0 dropped in 2,306.

## What the bug was identified to be
`_settle_failure` (SP-01, BUG-0522's fix) treated a failed navigation as over when
Chromium's error page **committed**, not when it had **loaded**. Every caller that
navigates after a failure could start its next navigation inside the error page's
commit-to-load window.

## Root cause analysis
Five whys:

1. Why did `restore` fail? Its `about:blank` `goto` raised `TimeoutError` after
   15 s: Chromium never committed it and never reported it failed.
2. Why did Chromium drop it? It was started while the previous failure's error page was
   still loading. Every drop in the RCA started before that page's `load` lifecycle
   event (15/268), none after it (0/2,012). That the drop comes from the error page
   stopping its load while the navigation is pending is inferred from the CDP sequence,
   not read in Chromium's source.
3. Why was the error page still loading? `navguard._settle_failure` returned as soon as
   it saw the error page's commit (`framenavigated` to `chrome-error:`), and the load
   follows 15-25 ms later (p95 about 130 ms under I/O load; the error page runs in its
   own process and its load is slowed by disk contention: Chromium runs with
   `--disable-dev-shm-usage`, so its shared memory is on the root disk).
4. Why did the settle stop at the commit? BUG-0522's defect was being overtaken: a
   navigation interrupted by a later commit. A commit wait fixes that, and BUG-0522's
   measurements (20-40 per path, CPU load) showed 0 losses after it. "Landed" was read
   as "committed" in the fix, in SP-01's row and in PA-0522's own text.
5. Why was that never caught? The drop happens in about 1% of restores and only under
   disk I/O pressure (0 in 1,320 under CPU load alone). BUG-0522's real-browser tests
   repeat each path 5 times, and no deterministic test fixed the order of events a
   failure must wait for (commit, then load, then the raise).

**Root cause:** a failed navigation was taken as over when the browser's error page
committed, not when it had finished loading; the wait was sized to the defect that was
seen (being overtaken), and its proof could not see a race of about 1% that disk
contention opens.

## Corrective action
CC-CRAWL-0065 (SP-01's owner, `fuzzlab/tools/navguard.py`):

- `_settle_failure`: once a fresh `chrome-error:` commit settles a failure of the
  "error-page" kind, it also waits for that error page's own `load`
  (`_error_page_loaded`: `page.wait_for_load_state("load")` with what is left of the
  same `ERROR_PAGE_WAIT_MS` budget). Playwright clears a frame's load states at each
  commit before it reports the commit, so the load awaited is the error page's own,
  never the previous document's. An expiry is counted in `error_page_waits()["expired"]`
  and logged (naming BUG-0561); it never raises, and the failure's own error is
  raised. `NAVIGATION_SETTLED_ATTR` still records the commit, so `end_failed_load`
  keeps the error page as before.
- The "overtaken" kind (the error page, then the overtaken navigation's own late
  commit) does not wait for a load: measured, see below.
- Tests: `tests/test_navigation_settle_load.py` (a page double on a fake clock; no
  browser). `tests/test_disco_harvest.py` is unchanged.

Proof (plain Python, pytest only as a library; `scratchpad/navsettle/scripts/prove.py`,
logs `scratchpad/navsettle/logs/proof_5502228.log` and `proof_fixed.log`): on 5502228
`test_a_failure_raises_only_after_its_error_page_has_loaded[1-navigate, 1-reload,
2-navigate, 2-reload]` fail at their own assertion (`page.steps == expected`: the steps
were goto, commit, raise, with no load wait) and
`test_an_error_page_that_never_loads_expires_within_the_budget_and_is_counted` fails at
its own assertion (no `wait-load` step); after the fix all six pass.

Measured after the fix (real Chromium, the RCA's driver `inject.py` and its load:
4 CPU hogs, 4 fsync loops and one bulk writer; `scratchpad/navsettle/scripts/lanes.sh`,
rounds `logs/r1`, `logs/r2`; PSI io some avg10 median 41%, load average median 25;
5502228 and the fixed tree in the same rounds, two lanes each, 960 restores each):

| Tree | Restores failed | `about:blank` started before the error page's load | of those, timed out | Error-page settle p50 / p95 |
|---|---|---|---|---|
| 5502228 | 6/960 | 116 | 6 | 37 / 120 ms |
| fixed | 0/960 | 0 | 0 | 67 / 165 ms |

Fisher p = 0.031 on the failures (the RCA's wrapper: 0/720 against 8/720). 0 expiries
in 3,840 waits on the fixed tree. The spider's `_leave` path is not driven by these
scripts and was not measured separately; it gets the same wait through `navigate`.

The overtaken kind, measured before deciding it (`scripts/overtaken.py`, rounds
`logs/o1`, `logs/o2`, the same load): without a load wait, 996 overtaken settles each
followed at once by `navigate(page, "about:blank")`; all landed, and 283 of them were
started before the overtaken document's own `load` -- 0 dropped, against 15 of 268
started before an error page's load in the RCA (Fisher p = 1.6e-5). So it does not
wait: its last document is the overtaken navigation's own http page, not an error
page.

## Sweep (PA-0002, by primitive)
Every caller of `navguard.navigate` / `reload` gets the wait by construction: a failure
of the "error-page" kind raises only after its error page has loaded. The callers that
navigate again after a failure, and what they now get:

| Caller | Next navigation after a failure | Effect |
|---|---|---|
| disco `Explorer.restore` (`explore.py`) | `about:blank`, then the entry URL | the measured path: covered |
| disco harvest `_load` (`explore.py`) | the next harvest URL (http) | covered; http from a loading error page was not dropped (0/2,306) |
| disco `ede._load` | none: a failure ends `_page` | no change |
| spider `_fetch_rendered` / `_window` (`end_failed_load`) | none after an error-page settle; `about:blank` otherwise | no change (nothing navigated after an error page) |
| spider `_restore` (a reveal window's reload) | a failed reload raises (after its error page loaded) and the window's `except` keeps that page (`end_failed_load`); the `about:blank` fallback follows a reload that committed but did not complete, which is not a failure of the reload | covered; the fallback's case is the residual below |
| spider `_leave` (window exit) | `about:blank` after a failed seed or probe | covered |
| spider pre-seed blank (`_visit`) | `about:blank` (suppressed) after a failed load | covered |
| spider `_goto_and_parse`, session re-adoption, submissions, reveals | the next crawl load | covered |
| auditor `ContentFetcher.fetch` | the next fetch (`end_failed_load` first) | covered |
| `session.browserlogin` | the next login route | covered |
| `tools.browserexec` (M6) | the next observe navigation | covered |

`end_failed_load` itself navigates only when the failure did not settle on an error
page (an abort, a timeout, an expiry, an overtaken navigation), so it never starts
from a loading error page. **Not covered (residual, unmeasured):** an error page
committed by a navigation navguard did not start (a click, a form submission or a
script navigation answered by an empty error) has no failure to settle; a navigation
started from it before its load would be exposed the same way. The callers that act
on a page wait for a quiet period after the action before they navigate (disco's
`wait_quiet` / `settled_fingerprint`, the spider's `_settle`), which is expected to
outlast that load; this was not measured, so it is stated as a residual and no change
is made there. Likewise a load-wait expiry (counted, logged) leaves the next
navigation exposed for that one failure.

## Recurrence review
- **BUG-0522 / PA-0522** (a failed load's late error page overtook the next
  navigation): the same defect class and the same owner. A failed navigation was
  treated as over before what it starts had finished. BUG-0522 fixed the commit; this
  is its load. A recurrence.
- **BUG-0136 / PA-0136, BUG-0138 / PA-0138** (an abort replaced the page; a load a
  refused navigation cancelled was waited out): the same primitive, different
  failures; PA-0522 already strengthened both for this class.
- **BUG-0504 / PA-0504, BUG-0128 / PA-0128** (teardown let a just-started navigation
  out; teardown waited on in-flight work): the same family (a browser action assumed
  finished when the API returned), on teardown, not on a failed navigation.
- **BUG-0526 / PA-0526, BUG-0511 / PA-0511** (timing and arrival-order oracles under
  load): not the same defect; they bear on the proof, which here is a deterministic
  ordering test plus a measurement, not a timing assertion.

## Prior-preventive-action failure analysis
PA-0522 (from BUG-0522) said "a failed navigation is over only when the browser has
finished what the failure starts" -- the right principle -- and did not prevent this,
for three reasons:

- **Too narrow in its concrete clause.** Its item (1) went on to name what to wait for:
  "the error page a network error starts and ... the overtaken navigation's late
  commit", and SP-01's row says "raises only once the commits its failure starts have
  landed". The fix, the row and the rule all equated "finished" with "committed",
  because the defect that was seen (being overtaken) is cured by a commit. A document
  that has committed has not finished: it still loads.
- **Not enforced at the volume or the load where the residual lives.** PA-0522(3) asks
  that a cleanup be "measured against every way the step before it can fail"; the
  measurement varied the failures, not the host's contention. The drop is about 1% of
  restores and only under disk I/O (0 in 1,320 under CPU load alone), so 20-40
  repetitions per path under CPU load, and 5 per test, could not see it.
- **No ordering oracle.** Its enforcement tests are real-browser outcome tests; none
  states the order of events a failure must wait for, so a settle that stopped at the
  commit passed them all.

## Preventive action
PA-0561 strengthens PA-0522: "landed" is the last lifecycle event of what the action
starts (a document's load, not its commit), the order of those events is fixed by a
deterministic test, and a browser race is measured under each kind of host contention
the harness sees (CPU and disk I/O), at a volume that can see its rate, both arms in the
same rounds. Its text is in `docs/PREVENTIVE_ACTIONS.md`.
