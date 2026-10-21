# BUG-0545 — The legacy spider took every load for a finished, trusted page: its static engine dropped the identity, a failed load was filed as visited, every URL was admitted, and each page row waited on a commit

- Date: 2026-10-21
- Status: fixed (CC-CRAWL-0056), with stated residuals
- Severity: high. The audit rated defects 5 and 12 CRITICAL and 11 and 25
  PERF_DEGRADATION. An identity-scoped crawl could silently become an anonymous one; a
  transient outage at a navigation page hid its whole subtree, on the run and on every
  resume; one page of calendar cells or facets could exhaust memory before depth 3.

## Description
`fuzzlab/tools/spider.py` (deprecated by D70, still read by `fuzzlab auto`; the owner
asked for these to be fixed) had four defects of one shape: the crawl loop recorded a load
as a finished, trusted observation without modelling whose it was, whether it was
complete, whether its extraction finished, or what admitting it would cost.

1. **Audit defect 5 (identity).** Authentication was wired into the browser's start only
   (`_start_browser` → `browserauth.browser_session`). `_fetch_static` -- the `requests`
   engine, the engine chosen when Playwright is absent, and the browser's fallback for a
   page it cannot render -- sent through the bare `requests` session: no session-manager
   `prepare`, no `observe`, no Cookie or Authorization. The static selector-form
   submission (`_isolated_submit`) copied the same anonymous jar. Nothing said so.
2. **Audit defect 11 (frontier).** The queue was a `list` (`_CrawlQueue`) of every
   `(url, depth, source, found_from)` a producer appended. Producers checked
   `is_visited` but reserved nothing, so many parents queued one destination many times;
   `pop(0)` and `_take`'s `list.__delitem__` shifted the rest; nothing bounded fan-out,
   pending items, URL length, an origin or a route's query variants. The depth limit
   bounds chain length only. `NFR-CRAWL-bounded` ("cap per-template instance counts")
   was specified and never built.
3. **Audit defect 12 (transient failures).** `_visit`'s `except Exception` stored a
   timeout, a reset, SP-60's `BodyIncomplete` or a processing error as a `discovered_pages`
   row with status 0; a 429/502/503/504 answer took the normal path. Both made the page's
   visit key "visited": the run never loaded it again and `--resume` skipped it. A
   processing error after `mark_visited` left a terminal-looking row whose extraction had
   not finished.
4. **Audit defect 25, the spider's part (writer).** `StorageManager.mark_visited` held the
   store's one lock and committed each page row on its own: every crawl worker's page
   record waited on a commit (an fsync) and on any other worker's.

## Where encountered
The external adversarial audit at 6552276 (defects 5, 11, 12 and 25's spider part,
`tools/spider.py` lines 554-560, 582-589, 1429-1445, 502-516, 3014-3036, 3191-3264,
3296-3303, 335-378; `tools/spa.py` 219-231), re-located on c483dc1; reproduced there by
`tests/test_spider_static_identity.py` and `tests/test_spider_frontier.py` (14 tests
written first; a fifteenth after the fix, for a gap the host-compare guard's review
exposed: an answer the manager sent without the session; all 15 fail on c483dc1).

## What it caused to fail
Measured on c483dc1 against the fix, loopback sites only
(`scratchpad/lanes/SPIDER/measure/measure.py`, `old.out`, `new.out`):

| Case | c483dc1 | fixed |
|---|---|---|
| `/` links 40 hubs, each links the same 40 leaves (depth 2): queue peak | 1599 entries | 78 |
| a calendar trap, each `/cal?d=N` links 30 new days (depth 3): `/cal` loads | 931 (28.8 s) | 100 (1.1 s), 831 refused and reported |
| `/hubpage` answers 503 once, then links `/child` | `/hubpage` filed visited 503; `/child` never found | retried: `/hubpage` 200, `/child` 200 |
| 1000 page rows recorded | 1000 commits, 11.0 s on the recording thread | 3 commits, 0.07 s on the recording thread |

And each of the 15 tests written for these behaviours fails on c483dc1, 14 of them on the
behaviour itself (`scratchpad/lanes/SPIDER/measure/direct_old2.out`, `direct_old3.out`):
a loopback alias outside the manager's host scope was crawled anonymously and filed as a
page; the identity crawl
stored `/` as `home` and reached no protected page; a session lost on a send never
reached `/expiring`; a browser-storage identity and a wrong password each crawled
instead of failing ("DID NOT RAISE"); B's landing was followed and not recorded as
withheld; `/pick` was submitted with no cookie; the hub site's queue peaked at 1599; the
trap loaded the over-long URL; a 503, a dropped connection and a dripped body were each
stored as the page with no outcome; a page that kept failing was stored as visited; 200
page rows made 200 commits; `mark_visited` was still waiting on the store's lock after
2 s. The fourteenth, the frontier's own unit test, needs the new class.

## What the bug was identified to be
- A crawl's identity was a property of one engine's start-up, not of the send path, so
  every path that does not start a browser was anonymous by construction.
- "Visited" (a final record, skipped on resume) was written for every load, whatever its
  outcome: fetch completion, extraction completion and retry eligibility were one flag.
- Admission to the queue was "not yet visited", with no reservation and no budget.
- The page record was the store's write: a synchronous commit under the store's lock on
  the crawl's hot path.

## Root cause analysis
Five Whys:
1. *Why did a static crawl run anonymously, a failed load count as crawled, and the queue
   grow without bound?* The loop wrote one kind of record -- a visited page -- and
   admitted one kind of thing -- an unvisited URL. Who sent it, whether it answered,
   whether its extraction finished and what it cost were never states.
2. *Why were those never states?* The spider grew around the browser engine (forms phases
   1-5, CC-CRAWL-0013..0047). Each phase added a safety or evidence state to the browser
   path (scope, the write windows, session adoption, FR-SESS-20's withholding) and left
   the static path and the queue as they were. The static engine was reviewed only as a
   *leak* question -- BUG-0134's residual R8 pinned that "the static engine's anonymous
   jar never holds the session" -- never as a *coverage* question: does the static path
   carry the identity it was given?
3. *Why did a timeout become "visited"?* The except handler's job was "do not crash the
   crawl", and the record it wrote was the only record type. SP-60 (BUG-0536) made an
   incomplete body a typed `BodyIncomplete`, but CC-CRAWL-0054's sweep bounded the
   spider's sessions and did not follow the marker into the spider's handler, which
   turned it into a status-0 visited row.
4. *Why was the frontier unbounded?* `NFR-CRAWL-bounded` was a NOT_SAFETY NFR with no
   enforcement line, and the queue was built for one worker and kept as a list when
   workers came (CC-CRAWL-0037), with a claimed-URL set at `_take` instead of a reserved
   key at admission.
5. *Why did each page wait on a commit?* `StorageManager` was made thread-safe by one
   lock (PA-0023), and every write kept its own commit under it: correct, and on the hot
   path, with nothing measuring what a page record cost.

**Root cause:** the legacy spider's crawl loop had no model of a load's outcome: one
"visited" record and one "unvisited" admission stood for who sent it, whether it answered
completely, whether its extraction finished, whether it may be retried, and what
admitting it costs. Every state that was added later was added to the browser path only,
and no rule or test asked each send path, each failure and each admission what record it
leaves.

## Corrective action
CC-CRAWL-0056 (FR-CRAWL-34..36, `fuzzlab/tools/spider.py`, `fuzzlab/tools/spa.py`):
- **Identity (FR-CRAWL-34).** In an authenticated crawl every static hop goes through the
  core seam (`core.http.HttpClient`) with the session manager as its addon, over a
  persistent bounded (SP-60) session whose jar keeps nothing. The crawl's per-hop scope
  and destructive rules still decide each redirect, and a hop to another origin than the
  session's is never followed (`SessionWithheld`, FR-SESS-20). Before any page:
  `ensure` from the operator's start URL, `session_headers` (origin and transport), a
  check that the session holds a cookie or header a request can send
  (`StaticIdentityUnsupported` otherwise), and `verify_live` (SP-61). A loss the manager
  sees on any send while a static load is in flight, or a send on a session it knows
  lost, makes that answer no evidence: the page is retried after the re-login. An answer
  the manager sent without the session -- withheld (another origin), or with none applied
  (`session_generation` unset: a host outside the manager's own scope, such as a loopback
  alias it was not given) -- is never extracted (`withheld`). A `SessionAuthError` on a
  send stops the crawl (`IdentityUnavailable`). The static selector-form submission sends
  through the same seam (`core.urls.with_query`, SP-42). The seam's host gate mirrors the
  crawl's request scope: one reasoned allowance in PA-0134(3)'s host-compare guard.
- **Frontier (FR-CRAWL-35).** `_Frontier` replaces `_CrawlQueue`: a key reserved at
  admission (`spa.visit_key`; the exact URL is kept), two deques (ordinary; seeds and
  probes) and a retry heap, all O(1) at the head; budgets (`FrontierLimits`: total,
  pending, per origin, per route shape -- `spa.route_shape`, through
  `core.pathtemplate.id_shaped` -- and URL length), each refusal counted by reason in
  `crawl_stats` and logged as partial coverage.
- **Transient failures (FR-CRAWL-36).** A page row is `pending` once the page answered
  and `visited` only when its extraction finished. A throttle, gateway, incomplete
  (SP-56) or other 5xx answer, a transport failure, `BodyIncomplete`, or a session lost
  on the send is retried after a backoff (`Retry-After` honoured, bounded) up to
  `FETCH_ATTEMPTS` loads; each failed load is stored `failed` (status, load count, error
  class), never visited; the last is reported (`failed_pages`, `pages_failed`) and a
  `--resume` crawl loads every unresolved row again.
- **Writer (FR-CRAWL-36).** Page rows are queued in memory and committed by one writer
  thread by count, bytes and age, in order, and at close; recording a page never waits
  on the store (only on a backlog past 16 MiB, counted); a failed write is raised, never
  dropped.

**PA-0002 sweep.**
- *Send paths that could drop an identity:* the auditor's static fetch
  (`tools/fetcher.py::_static_fetch`) already sends through the seam when it has an
  identity (CLI `make_auth`); its browser fallback reaches the same method -- carries it.
  `disco` sends from the browser only (its session is adopted by the context). The probe
  senders are chosen by identity (`SeamProbeSender` with one). The spider's three static
  paths (the `requests` engine, the browser's fallback, the selector-form submission)
  are fixed here. None left.
- *A failed observation filed as final:* the spider's `_visit` handler (fixed); the
  contract runner (BUG-0528, already fixed); greybox (BUG-0536, fixed). The auditor's
  `ContentFetcher` audits what it fetched and records findings, not a "visited" set, so it
  has no final record to fix; it is not changed.
- *Unbounded frontiers:* disco's explorer is bounded by its own state and action budgets
  (FR-CRAWL-19); the spider's was the one without. `spa.py`'s route queue
  (`_pending_routes`) feeds the frontier, which now bounds it.
- *Per-row commits on a hot path:* the spider's other tables (forms, verdicts, captured
  requests, revealed forms, script segments) still commit per write; they return
  decisions read from the store (a duplicate) and are far fewer than page rows. Residual
  R3 of CC-CRAWL-0056; `record_request` is lane SPIDER9's region.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug or the same root
cause, by each defect:
- **Identity dropped on a path:** BUG-0132 / PA-0132 (a browser login's session handed to
  the requests senders without the JS-set cookie; (3) the sweep lists every handoff point
  of a session between clients) and BUG-0134 / PA-0134 (every send path checks session
  membership through one predicate). **Match.**
- **An incomplete observation recorded as a finished one:** BUG-0528 / PA-0528 (an
  outcome that claims something held rests only on complete, evaluated observations) and
  BUG-0536 / PA-0536(1) (every consumer keeps SP-60's marker typed; no consumer records or
  accepts what it names). **Match.**
- **A specified bound never built:** BUG-0111/0112 / PA-0112 (NFR-CRAWL-safe and
  NFR-FUZZ-safe specified and never built). **Match** (NFR-CRAWL-bounded).
- **A shared SQLite handle on the hot path:** BUG-0021 / PA-0023 (thread-affine handles)
  and BUG-0101 / PA-0102 (blocking I/O on an event loop). Related, not the same:
  PA-0023's lock is kept; nothing there governs commit cost.

## Prior-preventive-action failure analysis
- **PA-0132 (BUG-0132) and PA-0134 (BUG-0134): too narrow, and the exception was pinned
  the wrong way.** PA-0132(3) asked the sweep to list every handoff point of a session
  between clients; its sweep and BUG-0134's listed the requests *senders*, the browser
  routes and greybox, and treated the spider's static engine as a place the session must
  *not* reach (R8: "the static engine's anonymous jar never holds the session"). Neither
  asked the opposite question -- does every send path of an authenticated tool carry the
  identity, or refuse? -- so a send path that silently drops the identity satisfied both
  rules. Neither was enforced on the spider: their tests cover the browser crawl.
- **PA-0536(1) (BUG-0536): not followed to the consumer, enforced on one consumer.** It
  says every consumer keeps the incomplete marker typed and none records what it names,
  but its enforcement line names greybox's test only, and CC-CRAWL-0054's sweep bounded
  the spider's sessions without following `BodyIncomplete` into `_visit`'s handler, which
  recorded the page as visited. PA-0528 was scoped to judges and oracles (a pass, a
  baseline); a crawler's "visited" is the same kind of claim and was not seen as one.
- **PA-0112 (BUG-0111/0112): scoped to SAFETY NFRs.** It made safety NFRs traceable to
  tests; NFR-CRAWL-bounded is classified NOT_SAFETY ("crawl termination"), so its absence
  failed nothing, exactly as NFR-CRAWL-safe's had.

## Preventive action
PA-0545 (strengthens PA-0132(3), PA-0134(1), PA-0536(1) and PA-0528, and carries PA-0112
to a crawl's bounds):
1. **An authenticated tool's every send path carries the identity or refuses, loudly.**
   The PA-0002 sweep for an identity feature lists every send path of the tool (each
   engine, each fallback, each submission) with "carries it through the session manager"
   or "refuses with an error"; "sends anonymously" is never a disposition. A send path's
   test asserts what the target received (the session on each crawled request), and a
   test with an identity the path cannot carry asserts the refusal and that nothing was
   sent. An answer the session layer sent without the identity (withheld, or none
   applied) is never taken as the identity's.
2. **A record that later work trusts as final is written only for a final outcome.** A
   load that did not answer, answered with a throttle, gateway, incomplete or server
   error, or whose extraction did not finish is recorded as unresolved, retried within a
   bound when it may pass, reported, and resumed; it never takes the final record's
   place. SP-60's and SP-56's markers are followed into every handler that writes a
   record.
3. **A queue that grows from what the target returns has an admission budget**: a key
   reserved at admission, and bounds on total, pending, per origin and per route shape
   (values never counted), each refusal counted and reported as partial coverage; a
   specified bound (an NFR) is built and tested, or marked not yet enforced, whatever its
   safety class.
4. **A record on a crawl's hot path never waits on a commit**: rows are batched by count,
   bytes and age by one writer, flushed at close, with a bounded backlog and a failed
   write raised. (from BUG-0545)

Enforced by: the tests named on PA-0545's line in `docs/PREVENTIVE_ACTIONS.md`.
