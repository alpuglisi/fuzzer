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
- *Readers of page rows while a crawl runs* (the batched writer's consumers, PA-0152):
  in `fuzzlab/`, `count`, `set_source` and `unresolved` flush first, and `is_visited`
  reads memory; in `tests/`, the U2 seed test of `test_spa_query.py` read the newest
  row from the store mid-crawl and now flushes first (found by the selection run, not
  the sweep: F-record). The CLI's one builder (`spider_kwargs`) passes the new `limits`
  keyword.
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

## Review round 1 (added in review round 1, 2026-10-21)
Two reviewers of 9071440; each finding below was confirmed by a skeptic with a run on
both commits. Fixed on `lane/SPIDER-r1` (CC-CRAWL-0056, review round 1). This section
supersedes the paragraphs above where they disagree.

### What the fix still let through, or claimed without measuring
- **B1 (both reviewers; a regression this fix introduced): a resumed crawl loaded stored
  rows around the scope and destructive rules.** `crawl()` put every unresolved row
  (`StorageManager.unresolved`) into the frontier. Every other producer asks `_in_scope`
  and `_destructive` before it queues; the frontier and `_visit` asked neither, and
  `navguard.get_checked` sends the first hop without asking anyone (`may_follow` decides
  redirect hops only). Measured on 9071440 (`scratchpad/lanes/SPIDER/rev1-scripts/
  resume_scope.py`, the skeptics' `refute_b1`): a `--resume` crawl of B
  (`127.0.0.1:Y`) sent three GETs to A's `/down` (`127.0.0.1:X`, another service,
  BUG-0123); a row that only an earlier crawl's start-URL exemption let through
  (`A/logout`) was loaded by a crawl started at `A/`. c483dc1 never loaded a stored URL.
  The CLI reaches it: `--db` defaults to one file for every run. An older database's
  status-0 rows (unresolved by `_final`) took the same path.
- **R6 (reviewer A; the fix's own residual R6, flagged to SESS): a host the session
  manager does not serve was sent to without the session.** The seam's host gate admits
  every loopback alias; `SessionManager.prepare` returns early, applying nothing and
  recording nothing, for a host outside its scope; `_seam_page` noticed only after the
  send, stored the page `withheld` (final, never resumed) and reported "another origin
  than the session's ... pass --auth-origin", which is false (its canonical origin is
  the session's) and names a remedy that cannot help. That broke this bug's own
  PA-0545(1) ("sends anonymously is never a disposition"), and the test written for it
  asserted the withheld row, not what the site received, so it pinned the defect.
  Measured on 9071440: the site recorded `GET /deeper?via=alias` with no Cookie.
- **B2 (reviewer B): three tests failed on c483dc1 only for the first test's reason.**
  `_IdSite` served an anonymous `/` with no link and no form, so c483dc1's anonymous
  crawl loaded only `/`, `robots.txt` and `sitemap.xml` and never reached `/go`,
  `/pick` or the alias (`measure/direct_old2.out`, `direct_old3.out`). The redirect,
  selector-form and alias tests therefore failed on c483dc1 because the crawl was
  anonymous, not on their own behaviour.

### Correction of "What it caused to fail" (added in review round 1)
The paragraph above says that on c483dc1 "a loopback alias outside the manager's host
scope was crawled anonymously and filed as a page", that "B's landing was followed and
not recorded as withheld" and that "`/pick` was submitted with no cookie". The outputs
it cites show none of the three: those claims were inferred, not measured. With the
test site fixed, they are measured now on c483dc1 (one pytest invocation, below):
B received `GET /land` with no cookie (the redirect test fails at `other.requests == []`); `/pick?bug=1` and `/pick?bug=2` were sent with no cookie (the selector-form test fails at its `sid=` assertion); the alias received `GET /deeper?via=alias` with no cookie (the alias test fails at `sent == []`). c483dc1's `spider.py` was loaded in place of the module the tests call; the rest of the tree differs from c483dc1 only by additions (`scratchpad/lanes/SPIDER/r1/proof.log`).

### Root cause of the review findings (added in review round 1)
Five Whys, B1:
1. *Why did a resumed crawl send to another service?* A new producer -- the stored
   unresolved rows -- fed the frontier without the gates every other producer applies.
2. *Why could a producer skip them?* Scope and the destructive rule were checked by each
   producer before it queued, not where a load is made; the static engine's first hop
   is sent unasked.
3. *Why was the new producer not gated?* This fix's sweep listed the queue's producers
   by what feeds it from a page; the store, which this fix itself made a source, was not
   seen as one.
4. *Why did nothing fail?* The resume test resumed the same target, where every stored
   row is in scope.
5. *Why was the check not at the load already?* PA-0123(1) ("every outbound path is
   scope-checked where the request is made") was enforced for the browser and redirect
   hops, never for the static engine's first hop.

R6: the fix detected a send without the session after the send, and its author left the
send itself as a residual for another component though the spider can refuse it before
the transport (the seam calls the addon's `prepare` first). B2: the pre-fix proof asked
"does each test fail on c483dc1", not "on its own assertion".

**Root cause:** the crawl's load-time rules (scope, destructive, "never without the
session") were enforced where URLs and sends were chosen -- at each producer, and after
the send -- instead of at the one point every load and every send passes, so a new
producer and an unserved host each went around them; and the tests proved what was
recorded, not what each target received.

### Corrective action (added in review round 1)
CC-CRAWL-0056, review round 1 (`fuzzlab/tools/spider.py`):
- **B1.** `_visit` asks `_load_refusal` before anything else for every load, whatever
  queued it: `out_of_scope` (`_in_scope`) or `destructive` (`_destructive`) is never
  requested and nothing is stored; each refusal is counted (`loads_refused[<reason>]`,
  `LOAD_REFUSALS`) and reported. The stored rows stay unresolved for a crawl whose scope
  covers them.
- **R6.** The seam's session addon is `_SessionAddon`: the manager's `prepare`,
  `authorize` and `observe`, and, after `prepare`, a request with no
  `session_generation` and no `session_decision` (the manager left it alone) raises
  `HostNotServed` before the transport. Nothing is sent; the page is `failed`
  (unresolved) with the cause, counted `session_host_unserved`; a selector form whose
  action is on such a host is not submitted. The remedy it names (add the host to
  `scope_hosts`) was measured: with `localhost` in the manager's scope the alias goes
  with the session (`scratchpad/lanes/SPIDER/r1/alias_scope.py`). No SESS change.
- **B2.** `_IdSite` serves `home_extra` to an anonymous visitor too.
- Tests: `test_spider_frontier.py::test_a_resumed_crawl_never_loads_a_stored_row_out_of_its_scope_or_destructive`
  (new); `test_spider_static_identity.py::test_a_host_the_session_manager_does_not_serve_is_never_sent_without_the_session`
  replaces `test_an_answer_the_manager_sent_without_the_session_is_never_extracted` and
  asserts that nothing reached the alias. Pre-fix proof: one pytest invocation with 9071440's `spider.py` in place (`scratchpad/lanes/SPIDER/r1/proof.log`, 5 failed in 4.87 s with the three c483dc1 runs above): the resume test fails at "B's crawl loaded A's row" (`A/logout` received 6 GETs, 3 expected); the unserved-host test fails at `sent == []` (`GET /deeper?via=alias` with no cookie). Both pass on the fix.

**PA-0002 sweep (added in review round 1).**
- *Producers that queue a load without the crawl's gates:* the start URL and the
  well-known files (in scope by construction), links and XHR URLs, redirect landings,
  selector-form targets, SPA routes, seeds and probes (`_query_gate`), reveal links,
  query-window navigations (all gated), probe routes (`_plan_probes`: visited routes)
  and the resumed rows (not gated). All now pass `_visit`'s gate as well.
- *Send paths that could go without the session:* the static page hop and the selector
  form submission (both through `_seam_send`, refused before the transport now). The
  browser path withholds by route (FR-SESS-20). The auditor's static fetch and the probe
  senders use the CLI's `make_auth` client, whose scope is the manager's own
  (`authhttp._build_parts`), so `prepare` serves every host its seam admits: no gap.

### Recurrence review (added in review round 1)
- **B1** is BUG-0123's root cause (scope enforced where a URL is chosen, not where the
  request is made) and PA-0503(1)'s class (a queue source that does not state its GET
  safety). **Match.**
- **R6** is this bug's own PA-0545(1). **Match** (same bug, same fix).
- **B2** is F-record class "a pre-fix proof that cannot tell a test's own failure"
  (this lane's earlier F-record) and PA-0034(2). **Match.**

### Prior-preventive-action failure analysis (added in review round 1)
- **PA-0123(1): enforced on the wrong layer for the static engine.** Its tests cover the
  browser's every request and the redirect hops; the static engine's first hop relied on
  the producers, so the rule held only while every producer remembered it.
- **PA-0503(1): too narrow.** It asks a source that feeds the queue to state that its
  URLs are safe to GET; it did not say that a store is such a source, so the resumed
  rows stated nothing.
- **PA-0545(1): not followed by its author.** Written with this fix, it forbids "sends
  anonymously" as a disposition; R6 was given exactly that disposition (a residual), and
  the rule's own test clause (assert what the target received) was not applied.
- **PA-0034(2) and this lane's earlier F-record: not applied to the proof.** A test was
  counted as proven when it failed on the old code, whatever the assertion.

### Preventive action (added in review round 1)
PA-0545 is strengthened (no new number; text in the lane's doc_texts): (1) now says a
send the session layer would make without the identity is refused before the transport,
never sent and then withheld; new (5): every load passes the crawl's scope and
destructive rules at the one point every load passes, whatever queued it -- a store
read back by a resumed run is a producer -- and its test asserts what an out-of-scope
and a destructive target received; new (6): a regression test's pre-fix proof records
the failing assertion of each test, and a fixture serves the pre-fix path what the
test needs to reach its own behaviour.

## Review round 2 (added in review round 2, 2026-10-21)
An adversarial check of 8c2fa86; each finding below was confirmed by a skeptic
(`scratchpad/lanes/SPIDER/review_round2.md`). Fixed on `lane/SPIDER-r2` (CC-CRAWL-0056,
review round 2). This section supersedes the paragraphs above where they disagree.

### What the fix still let through, or claimed without measuring
- **S2-1: R6 on the other engine -- the Playwright engine loaded a loopback alias of the
  session's origin without the session and filed its anonymous landing as the
  identity's page.** Same setup as R6 (an identity crawl of `_IdSite` on `127.0.0.1`,
  its home linking `http://localhost:PORT/deeper?via=alias`) with `engine="playwright"`.
  The reviewer measured on 8c2fa86 (and 9071440: the same), with the manager's scope
  `['127.0.0.1']` and with the CLI's default `['localhost', '127.0.0.1']`: the site
  recorded `GET /deeper?via=alias` with Cookie `''` and an anonymous `GET /login`; the
  alias was stored `(200, visited)` (final, never resumed); nothing in
  `skipped_other_origin` or `failed_pages`. The cause: `browserauth._cookies_of` adds the
  session cookie by the start URL, host-only for `127.0.0.1`, which Chromium sends to
  that host only (measured here too: `scratchpad/lanes/SPIDER/r2/cookie_domains.out`);
  `browser_launch_args` resolves every loopback spelling on the port; and the route's
  `cookie_scope` (`header_scope_for` -> `in_origin_scope`, aliases folded) counts the
  alias as the session's own origin, so it neither withheld nor isolated it. The round-1
  fix had put R6's refusal in the static seam only, and its sweep gave the browser path
  "withholds by route (FR-SESS-20)" without measuring what an alias received.
- **S2-2: a fourth test failed on c483dc1 only because the crawl was anonymous.**
  `test_a_session_lost_on_a_send_is_never_extracted_and_the_page_is_retried` failed on
  c483dc1 with `KeyError: '/expiring'`: the site got `/`, `/robots.txt` and
  `/sitemap.xml` only, since `_IdSite` linked `/secret` and `/expiring` from the live
  session's home alone (round 1 moved `home_extra`, not those links). FR-CRAWL-34's
  enforcement line ("each test fails on c483dc1 on its own assertion") was false for it,
  and this doc's list kept "a session lost on a send never reached `/expiring`". Round
  1's proof ran only the three tests the review named, so PA-0545(6) was not applied to
  this one.
- *Minor, recorded, not changed (outside this round's scope):* the cannot-carry and
  failed-login tests fail on c483dc1 on their own behaviour ("DID NOT RAISE": the old
  code crawled instead of refusing); the resume test fails on 9071440 at its scope
  assertion first, so its destructive half is never shown failing on the pre-fix code.

### Correction of "What it caused to fail" (added in review round 2)
"A session lost on a send never reached `/expiring`" above was the anonymous crawl's
doing, not the session-loss behaviour. With the anonymous home linking `/secret` and
`/expiring` too, every test of `tests/test_spider_static_identity.py` was run on
c483dc1 (a driver with the real fixtures, pytest imported as a library only,
`fuzzlab.__file__` checked to be c483dc1's export; `scratchpad/lanes/SPIDER/r2/
direct_c483dc1.out`). Each failing assertion, measured:

| Test | Fails on c483dc1 at | What the old code did |
|---|---|---|
| static crawl carries the identity | `"welcome alice" in rows["/"]` | stored `/` as `home`; `/secret`, `/expiring` and `/login` as `(200, '')` |
| session lost on a send | `"EXPIRING-PAGE" in rows["/expiring"]` | loaded `/expiring` anonymously, followed its 302 and filed `/login`'s answer as the page `(200, '')`; `/login` stored too |
| identity the static engine cannot carry | `pytest.raises(..., match="cannot carry")`: DID NOT RAISE | crawled instead of refusing |
| failed login stops the crawl | `pytest.raises(SessionAuthError)`: DID NOT RAISE | crawled instead of failing |
| redirect to another origin | `other.requests == []` | followed A's `/go` to B |
| host the manager does not serve | `sent == []` | `GET /deeper?via=alias` with no cookie |
| selector form with the session | its `sid=` check | `/pick?bug=1`, `/pick?bug=2` with no cookie |
| browser load the cookie does not reach (new) | `to_alias == []` | `GET /deeper?via=alias`, `GET /login` twice, all to `localhost` |

The new browser test also fails on 8c2fa86, at the same assertion with the same three
requests (pytest, below); the other seven pass there.

### Root cause of the review findings (added in review round 2)
Five Whys, S2-1:
1. *Why did the browser send to the alias without the session?* The alias is in the
   crawl's scope and on the session's canonical origin, so no rule refused it, and the
   context's session cookie is host-only for the start's host.
2. *Why did no rule see that?* The browser's session rule (`cookie_scope`) compares
   canonical origins, which fold loopback aliases; the browser's carrier of the session
   (its cookie jar) works by exact host. One engine held two notions of where the
   session goes.
3. *Why did round 1's fix not cover it?* R6's refusal was put where R6 was found -- the
   static seam's addon -- not at the one point every load passes.
4. *Why was the browser's disposition wrong in the sweep?* It was read from the route's
   origin rule, not measured against what an alias received.
5. *Why did the rule allow that?* PA-0545(1) asks for a disposition per send path, not
   for each disposition to be measured; and PA-0545(5) put scope and the destructive rule
   at the one gate, leaving "never without the session" to each engine's send path.

S2-2: round 1 fixed the fixture for the links the review named and proved the tests the
review named; PA-0545(6)'s "each test" was read as "each named test".

**Root cause:** "a load never goes where the session does not reach" was enforced in one
engine's send path, where it was found, instead of at the one gate every load passes; the
decision of where the session reaches was taken from an origin rule, which is not how
the browser's carrier (a host-scoped cookie jar) works; and the proofs measured the paths
and tests a review named, not every path and test of their own lists.

### Corrective action (added in review round 2)
CC-CRAWL-0056, review round 2 (`fuzzlab/tools/spider.py`):
- **S2-1.** `_visit` asks `_session_host_refusal` for every load of an identity crawl,
  after the scope, destructive and other-origin checks, before any navigation or send. It
  compares the host the load goes to with the hosts the engine's carrier of the session
  reaches: the static engine asks the manager's own `prepare` through `_SessionAddon` on a
  request that is never sent; the browser requires each of the session's credential
  cookies, as its context holds them, to reach the host (`_cookie_reaches`, RFC 6265
  domain match: host-only reaches that exact host). A refused load raises `HostNotServed`
  with the cause: stored `failed` (unresolved, resumed), counted `session_host_unserved`,
  never visited, never reported as another origin. No alias list: a loopback alias is
  refused because the cookie does not reach it, and would be loaded if it did.
- **S2-2.** `_IdSite` links its `protected` pages (`/secret`, `/expiring`) from the
  anonymous home too; FR-CRAWL-34's enforcement text and the table above record each
  test's measured failing assertion.
- Tests: `tests/test_spider_static_identity.py::test_a_browser_load_the_session_cookie_does_not_reach_is_refused_never_sent`
  (new, real Chromium; the CLI-default manager scope, so the cookie alone decides).
  Pre-fix proof: one pytest invocation with 8c2fa86's `spider.py` in place, then
  restored (`scratchpad/lanes/SPIDER/r2/proof.log`): 1 failed, 7 passed in 14.13 s; the
  new test failed at `to_alias == []`. All 8 pass on the fix.

**PA-0002 sweep (added in review round 2), by the carrier -- every send path of an
identity crawl to a host the session might not reach:**
- *Static page load:* the gate (the manager's `prepare`), then the seam: refused before
  the send.
- *Static redirect hop, static selector form:* the seam's `_SessionAddon`: refused before
  the transport (measured by the reviewer on 8c2fa86: `/go` -> `localhost/land` never
  requested; a form on `localhost` not submitted).
- *Browser page load (a link, a seed, a probe, a resumed row) and its static fallback:*
  the gate (cookie reach), then the seam for the fallback: refused before the navigation
  (the new test).
- *Browser redirect hop inside a load, and a browser selector form's submission:* **not
  covered** -- residual R8 (CC-CRAWL-0056), measured on this fix
  (`scratchpad/lanes/SPIDER/r2/browser_hops.out`): `localhost` received
  `GET /pick?bug=1`, `?bug=2` and `GET /land` twice with no Cookie, and `/go` was stored
  visited with the landing's answer. Flagged for the orchestrator (the hop walk is
  `navguard`'s, a shared primitive's owner; this round's scope is the load gate).
- *A page's own subresource and fetch requests to such a host:* sent by the route
  without the cookie, as in a user's browser; their answers are never filed as pages
  (their URLs are queued and refused at the gate). Code read, not measured.
- *Other tools with the same carrier:* the auditor's browser fetcher
  (`tools/fetcher.py::_start_browser`: the cookie by URL, scope by `in_origin_scope`, so
  a loopback alias of its base would go without the cookie) and disco's adopted
  `storage_state` (`disco/cli.py`, `disco/explore.py`). Code read, not measured, not
  changed (other components); flagged.

### Recurrence review (added in review round 2)
- **S2-1** is R6 again (this bug's own PA-0545(1)), on the other engine, and BUG-0134's
  class (where a session goes, decided by one predicate at every send path). **Match:
  a recurrence after round 1's fix.**
- **S2-2** is round 1's B2 again (a test failing on the old code for another test's
  reason) and PA-0545(6). **Match: a recurrence after round 1's fix.**

### Prior-preventive-action failure analysis (added in review round 2)
- **PA-0545(1) (round 1): followed for the path the finding named, not enforced for the
  others.** It asks the sweep for a disposition per send path, and round 1 gave the
  browser "withholds by route" from the route's rule; nothing required the disposition
  to be measured, and its tests covered the static engine only.
- **PA-0545(5) (round 1): too narrow.** It put scope and the destructive rule at the one
  gate every load passes, and left "never without the session" to each engine's send
  path, where R6 was patched one engine at a time.
- **PA-0134(1): one predicate, the wrong unit for one carrier.** "Every send path checks
  membership through one predicate (`SessionState.origins`)" holds for headers and the
  manager; a browser's cookie jar carries by host, so an origin that folds loopback
  aliases admitted a host the cookie never reaches.
- **PA-0545(6) (round 1): not applied to every test.** The proof recorded the failing
  assertion of each test the review named, not of each test in the file.

### Preventive action (added in review round 2)
PA-0545 is strengthened again (no new number; text in the lane's doc_texts): (1) now
also says a sweep's disposition for each send path is measured (what the target received
for each host the crawl's scope admits), never read from the path's rule; new (7): a
load goes only where the session's carrier in that engine reaches -- the manager for a
static send, the cookie jar for a browser -- decided at the one gate every load passes
by comparing the host the load goes to with the hosts that carrier reaches, never by an
origin rule alone and never by an alias list; (6) now says *every* test of a regression
test file, not only those a review names. Enforced by the new browser test as well.
