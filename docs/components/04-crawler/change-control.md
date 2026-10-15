# Crawler / Spider — Change Control Log

Component code: **CRAWL**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CRAWL-0030 — A guarded navigation never waits for a load a refused navigation cancelled: one helper (BUG-0138) (2026-10-15)
- Change:
  - **`tools/navguard.py`:** the one way a guarded page is navigated (PA-0138):
    - `navigate(page, url, *, timeout_ms, wait_until="domcontentloaded", wait_ms=None)`
      and `reload(...)`: `goto` / `reload` with `wait_until="commit"`, so a refused or
      failed own target still raises (BUG-0136);
    - then the load state in 100 ms steps, at most `wait_ms` (default `timeout_ms`),
      suppressed, and no longer than `SUPERSEDED_GRACE_MS` (300 ms) after a main-frame
      navigation of the page fails (`requestfailed`). It returns
      `Navigation(response, reached, superseded, committed_at)`;
    - `wait_for_state` (the same rule, for `networkidle`), `load_state_reached` (a check)
      and `response_html` (the HTML the browser already received).
  - **`tools/spider.py`:** every `goto` and `reload` goes through it: `_goto_and_parse`,
    the `about:blank` leaves, `_restore`, the re-adoption page, `_submit_anonymously`,
    and the two reloads.
    - `_goto_and_parse` waits for `networkidle` only after a completed load. It reads
      the body text with `evaluate`, never `inner_text('body')`: a document stopped in
      its head has no body, and that wait cost 30 s.
    - When the load did not complete, the title, text and links come from
      `response_html`, parsed as `_fetch_static` parses a page (now the shared
      `_parse_html`) and merged with the DOM's links. `_last_html` is that HTML, so its
      forms are read. There is no second request.
    - `_rendered_ok` is set for a completed load only.
- Impact (other components / project):
  - A page whose script navigates to a refused URL while it is parsed is read in about
    2 s from its one request. Before, it waited out `timeout_ms` and was sent again by
    the static fallback.
  - Query probes and seeds (FR-CRAWL-17) load once and finish: a seed keeps its
    content, and a probe is counted.
  - A page whose `domcontentloaded` takes longer than `timeout_ms` is read from its
    response, no longer re-sent statically.
  - The auditor (CC-AUD-0043), the browser login (CC-SESS-0024) and M6 (CC-FUZZ-0083
    amendment) use the same helper. No contract change.
- Risk: low to medium (it touches every navigation). Mitigated:
  - the helper's bound is the caller's own timeout, cut short only after a refused
    navigation, so slow pages are waited for as before (pinned);
  - the BUG-0136/0137 suites pass;
  - the AST guard holds the rule.
- Deliverables:
  - [x] code (`tools/navguard.py`, `tools/spider.py`) — done
  - [x] tests (`tests/test_guarded_navigation.py`: crawl, slow page, query probe and
    seed, auditor, browser login, AST guard with synthetic offenders) — done
  - [x] BUG-0138 (RCA, recurrence review, prior-PA analysis, PA-0002 sweep), PA-0138,
    ERROR_LOG, CHANGELOG, NFR-CRAWL-safe edited in place — done
  - [x] mutation checks — done
- Effectiveness (assessed 2026-10-15): `tests/test_guarded_navigation.py` 13 passed.
  Mutation (the spider's `_goto_and_parse` back on `goto(wait_until="domcontentloaded")`):
  the crawl test, the query probe/seed test and the AST guard fail. The BUG-0136/0137 and
  Playwright-fake suites (`test_browser_scope`, `test_destructive_urls`,
  `test_json_points`, `test_m6_navigation_failures`, `test_navigation_aborts`): 316
  passed. The full related run on the committed tree is recorded below.
- Effectiveness, the related run (2026-10-15): every test file importing
  `tools/navguard.py`, `tools/spider.py`, `tools/fetcher.py`, `session/browserlogin.py`
  or `tools/browserexec.py`, the SPA, query and login fixtures' users, and the
  traceability guard. 30 files, run on the committed tree (00b9545) with
  FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_NETNS=1: 1486 passed, 11 skipped, 6 xfailed,
  7 failed.
  - The 7 failures were all in `test_spa_query.py`: its `_FakePage` lacked the `on`
    and `wait_for_load_state` that `navigate` uses. f0b1109 gives the double that
    surface (test-only).
  - `test_spa_query.py` rerun on that committed tree: 103 passed.
  - In all: 1493 passed, 0 failed, 6 xfailed, 11 skipped. The skips are 7 for the
    optional fastapi extra (PA-0005) and 4 labgen live-boot reproductions.
  - Mutation checks, the old `goto(wait_until="domcontentloaded")` restored per
    caller:
    - the spider: the crawl and query tests and the AST guard fail;
    - the fetcher: the auditor test and the guard fail;
    - the browser login: the login test and the guard fail.
- Amendment, review of 98325e5 (2026-10-15; reviewer A AGREE, reviewer B
  AGREE-with-changes; D58 Q1, Q2, Q4; Q3 waits for the SPA lane's merge):
  - **Q1 (A-S1 = B-S1):** `_NavigationFailures` counts a main-frame failure only once
    armed, at this navigation's commit (when `goto(commit)` returns). A previous page's
    pending navigation that this one cancels, reported before the commit, no longer
    cuts the wait. On real Chromium a head script's refusal was reported after the
    return in 40 of 40 runs.
  - **Q2 (B-S2 + A-S2):** the not-reached branch of `_goto_and_parse` tells the cases
    apart with `navguard.shows_own_document` (the page's URL against the requested and
    final URL):
    - **superseded**, same document: the received HTML, with the DOM's links merged
      (as before);
    - **merely slow**, same document: the live DOM (JS-rendered text kept), with the
      received HTML filling an empty text only;
    - **another document** (an allowed script navigation committed): this URL's
      received HTML alone, and `_last_final_url` stays this URL.

    A replaced document's body is dropped by the browser before `goto(commit)` even
    returns, so the received HTML comes from the guard. `make_route_handler` keeps the
    body of the main-frame document it fulfils, per page (`_note_received`, a weak map).
    `navigate` / `reload` clear it before their own navigation and return it as
    `Navigation.html`.
  - **Q4:**
    - `_restore` leaves for `about:blank` when its reload did not complete (B-N1);
    - the AST guard also forbids `set_content`, `wait_for_event` and `expect_event`
      outside navguard, with three more synthetic offenders (A-N1, B-N2);
    - the download-navigation residual is in BUG-0138 (A-N2).
  - Tests (`tests/test_guarded_navigation.py`, now 20):
    - a page double whose failure is reported before the commit, with `load` at
      500 ms: reached;
    - real Chromium, a previous page's slow navigation pending when the next URL
      loads: its `domcontentloaded` (about 1 s, a slow script) is reached;
    - a merely slow page keeps its JS-rendered text;
    - A's head script to an allowed, slow B: A's row holds A's title, text and links
      only, and B's link is never crawled.
  - Mutation checks:
    - **Q1**, failures counted before the commit: both Q1 tests fail;
    - **Q2**, the old branch (`own = True`, always the response): both Q2 tests fail.
  - Effectiveness: the 20 tests of `tests/test_guarded_navigation.py` pass; the related
    run on the committed tree is recorded below.
  - Effectiveness, the related run (the same 30 files, FUZZLAB_REQUIRE_BROWSER=1
    FUZZLAB_REQUIRE_NETNS=1):
    - On 1a1da68: 1484 passed, 2 failed. Two route-handler tests' request doubles have
      no `frame`, and `_note_received` raised `AttributeError`; 0d2371b names it.
    - On 0d2371b: 1485 passed, 1 failed, 4 skipped, 6 xfailed. The failure is
      `test_labgen_go_net_http_navigability_live_boot.py::test_pa_0053_bare_request_sweep_no_route_answers_5xx`
      (status 0 for `/channels/redirect`). That test crawls with the `requests` engine,
      which does not use `navguard.navigate`. It passed on 1a1da68 and in 7 of 7 reruns
      on 0d2371b: a live-boot flake, not this change.
- Amendment, review of 8350ab1 (2026-10-15; reviewers A and B AGREE; A-S1, B-N1, B-N2):
  - **A-S1:** `url_key` drops the query, so `/p?a=1` and `/p?a=2` looked like one
    document to `shows_own_document`, `_received_html` and the `_RECEIVED` entry. A new
    `core.urls.document_key` (canonical origin, path and query, no fragment) is the one
    key (PA-0003). The spider's `_nav_key` now returns it, and navguard's three uses go
    through one `_navigation_keys`.
    - Test (real Chromium): `/p?a=1`'s head script navigates, allowed, to a slow
      `/p?a=2`. The row for `/p?a=1` holds `P-A1`, its text and link only;
      `_last_final_url` stays `/p?a=1`; `/a2link` is never crawled.
    - Mutation: with `url_key` back at those sites, the test fails (the row takes
      `P-A2`).
  - **B-N1:** `_NavigationFailures` arms on the main frame's own commit
    (`framenavigated`) as well as when `goto` returns (kept as a fallback for a page
    that reports no `framenavigated`). In 20 of 20 real-Chromium head-script loads it
    was armed by `framenavigated` before the refusal was reported, and the refusal
    counted. The arming therefore no longer depends on when `goto` returns.
  - **B-N2:** in the fetcher, see CC-AUD-0043.
  - Tests: `tests/test_guarded_navigation.py` 21 passed. `tests/test_navigation_aborts.py`'s
    `_Site` looks a page up by path and query first.
  - Effectiveness: the related run on the committed tree is recorded below.
  - Effectiveness, the related run on e7afbb8 (FUZZLAB_REQUIRE_BROWSER=1
    FUZZLAB_REQUIRE_NETNS=1): the 30 files above plus every test file importing
    `core.urls` (33 files): 1679 passed, 4 skipped (labgen live-boot reproductions),
    6 xfailed, 0 failed.

- Amendment (2026-10-15, final merge review, reviewer A M1): `core.urls.document_key`
  (added in e7afbb8) is filed in the core library's log as CC-CORE-0055 / FR-CORE-40.

### CC-CRAWL-0029 — One rule for both windows: a refused non-GET navigation is a write, never a page (forms phase 4, FR-CRAWL-16) (2026-10-14)
- Change: `tools/spider.py` `LocalSpider._window_refusal` keeps a refused navigation's
  target for the queue only when it is a GET/HEAD navigation. A refused non-GET
  navigation -- an auto-submitted form's POST -- is counted as the window's blocked
  write (`reveal_writes_blocked`; in a query window `spa_query_writes_blocked`) and its
  target is never queued, so the crawl never requests the action later as a GET.
  Before, the reveal window queued that target, and the crawl then fetched the write
  endpoint with a GET outside the window (review A3-N1 of FR-CRAWL-17; the query window
  already had this rule since its U1 amendment).
- Impact: CRAWL only (reveal navigation, FR-CRAWL-16 W2). A GET/HEAD navigation (a menu
  item's `location.assign`) is queued as before. Fewer pages: a form action reached only
  through a reveal's POST navigation is no longer crawled as a GET page.
- Risk: low; it only removes requests. Coverage cost: such an action URL is no longer
  discovered by that path (its form, when rendered, is still recorded as a form).
- Deliverables:
  - [x] code: `_window_refusal`, docstring — done
  - [x] test: `tests/test_forms_phase4.py::test_a_refused_post_navigation_in_a_reveal_is_a_write_never_a_page`
    (real Chromium; fixture `PostRevealSpa`) — done
  - [x] FR-CRAWL-16 W2 text in place, NFR-CRAWL-safe trace, CHANGELOG — done
- Effectiveness (assessed 2026-10-14): the new test passes with a real browser, and the
  mutation that restores the old rule for reveal windows fails it (the server got
  `GET /api/revealpost`); `tests/test_forms_phase4.py` is otherwise unchanged and green
  (its GET-navigation queueing test still passes). Every test file that imports a module
  changed since `cdde39f` (`core/urls.py`, `tools/fetcher.py`, `spa.py`, `spider.py`,
  `store_adapter.py`; 31 files, found by AST), plus `test_no_wall_clock_ratio`,
  `test_requirements_traceability` and `test_lint` (`FUZZLAB_REQUIRE_LINT=1`), with
  `FUZZLAB_REQUIRE_BROWSER=1`, one process at a time: 1638 passed, 0 failed, 4 skipped
  (the spring-boot navigability file's own reproduction skips), 4 xfailed (strict pins).
  This tree also carries the CC-CRAWL-0027 round-3 (Y1-Y4) amendment.

### CC-CRAWL-0028 — A refused navigation keeps the current document: one abort rule (BUG-0136) (2026-10-14)
- Change: `tools/navguard.py` `make_route_handler` decides a request's kind once
  (`document = _is_document(req)`) and refuses it through one `abort()`:
  `_abort_code(document)` gives `DOCUMENT_ABORT = "aborted"` for a document request (a
  navigation, top-level or frame, and its redirect hops) and the default code for a
  subresource. This holds for every reason: scope, destructive, refused method or body,
  the reveal window, a withheld session, too many hops, an unfetchable request. Before,
  only the reveal window and the withheld branch (BUG-0134 T1) used `"aborted"`; the
  rest used the default, which makes Chromium commit its error page in the page's
  place.
- Impact (other components / project): the crawler, the auditor's browser (CC-AUD), the
  M6 executor (FUZZ) and the browser login (SESS) all install this guard; none aborts a
  route itself, and none reads the abort code. `goto` of a refused target still raises
  (`net::ERR_ABORTED` instead of `ERR_FAILED`), so the crawl's own-target fallbacks and
  `SessionWithheld` behave as before. All bookkeeping callbacks are unchanged. No
  contract change.
- Risk: low (a refusal stays a refusal; only the browser's response to it changes).
  Mitigated by real-Chromium tests of both common reasons, a per-reason pin, and the
  existing scope, browser-login, SPA and reveal suites passing.
- Deliverables:
  - [x] code (`tools/navguard.py`) — done
  - [x] tests (`tests/test_navigation_aborts.py`; fake routes in
    `test_browser_scope.py` and `test_session_browser_login.py` record the code) — done
  - [x] BUG-0136 (RCA, recurrence review, prior-PA analysis, PA-0002 sweep), PA-0136,
    ERROR_LOG, CHANGELOG, NFR-CRAWL-safe edited in place and traced — done
  - [x] mutation checks — done
- Effectiveness (assessed 2026-10-14): `tests/test_navigation_aborts.py` 26 passed (22 per-reason pins, the code pin, 3 real-Chromium tests); the related suites (22 files, FUZZLAB_REQUIRE_BROWSER=1) 1272 passed, 2 xfailed, 0 failed; the traceability guard 3 passed. Mutation checks: the first request's scope/destructive abort reverted to `route.abort()` fails 5 (both real crawl tests, the `goto` test, and the out-of-scope and destructive navigation pins), 20 pass; `_abort_code` returning the default for a document fails 14 (the 3 real tests and all 11 navigation pins), 12 pass. Effective.
- Amendment, review of c69e6fb (2026-10-14; reviewer A AGREE, reviewer B
  AGREE-with-changes; D50 X1, X4, X5; X2 in CC-FUZZ-0082, X3 in CC-SESS-0023):
  - **X1 (B-M1):** an ERR_ABORTED abort keeps the previous document alive, timers and
    all, so after a failed `goto` its fetches ran on and were sent and captured under
    the URLs crawled next. `LocalSpider._fetch_rendered`'s `except` now first sends the
    page to `about:blank` (Playwright errors suppressed), then runs the withheld check,
    `SessionWithheld` or the static fallback as before. As a result
    `_navigation_withheld` decides there by the withheld targets alone (its committed-URL
    half sees `about:blank`); its docstring is updated (A-N2, B-N2).
  - **X4 (A-S1, A-S2):** real-Chromium pins: the crawl's own target whose 302 lands out
    of scope or on /logout.php raises ERR_ABORTED with the page kept, and /go is
    recorded through the static fallback (status 302). A script-submitted POST form to
    a refused URL keeps the page and posts nothing. A refused iframe keeps its parent.
  - **X5:** the unit table adds an iframe navigation and a `document` request whose
    `is_navigation_request` raises (B-N1). NFR-CRAWL-safe notes that a refused
    navigation looks as if nothing happened and is visible only through `skipped_*`
    and the summary (A-N1). B-N3 is accepted as is.
  - Effectiveness: `tests/test_navigation_aborts.py` has 59 tests (44 per-reason pins over 4 request
    kinds, the code pin, 14 real-Chromium tests), all passing. The X1 test passed 25 of
    25 repeated runs. The files that import `tools/spider.py`, `session/browserlogin.py`
    or `tools/navguard.py`, plus the traceability guard (23 files,
    FUZZLAB_REQUIRE_BROWSER=1): 1295 passed, 4 skipped (labgen live-boot reproductions),
    4 xfailed, 0 failed. Mutation checks:
    - dropping the `about:blank` line fails the X1 test 3 of 3 times. With its
      `about:blank` assertion moved last, the server-side assertion fails on its own:
      a burst of ticks after the fallback;
    - `_abort_code` returning the default fails 43 and passes 16. The iframe pins and
      M6 (a)/(b) pass either way, because they pin behavior that did not change.
  - Sweep note (2026-10-14): the X1 twin in the auditor's `ContentFetcher.fetch` is
    fixed under CC-AUD-0042. The M6 executor's failed or superseded loads are no
    verdict under BUG-0137 / CC-FUZZ-0083.

### CC-CRAWL-0027 — SPA route query-parameter discovery: scan, seeds, the observation probe (FR-CRAWL-17, forms phase 5) (2026-10-14)
- Change (the agreed design `spa-query-draft.md`, **Revision 2**: reviewer B's
  Revision 1 and reviewer A's points reconciled into Q1-Q7; that review was this
  change's pre-change gate). Juice Shop's `#/track-result?id=` renders the order id the
  server echoes as trusted HTML, but the crawler visited only bare routes, so no
  fragment point existed and M6 never ran there.
  - **Q1/Q2, the scan (`tools/spa.py`):** `spa.scan_script(text)` is the crawler's one
    call per already-loaded same-origin script (`LocalSpider._note_script`): one size cap
    (`MAX_SCRIPT_BYTES`), `scan_routes` and the new `scan_query_params`. Anchors only
    `navigate(` (followed by `[`, or a quote for a React literal), `queryParams:`,
    `queryParams.`, `queryParams[`, `queryParamMap.get(`, `searchParams.get(`,
    `URLSearchParams(`, `route.query.` (so `$route.query.` too), `query:` (only as a
    depth-1 key of a `push(` / `replace(` object found at most 200 characters back),
    `<Link` and `Link,{`. Each anchor kind is found with `str.find` from where the
    previous window ended (windows never overlap); a window ends at `min(anchor +
    QUERY_WINDOW (512), the next anchor of the same kind, the end of its call)`, and the
    call's arguments are read by a bounded walk inside it (strings, brackets, object
    keys at depth 1); at most `MAX_QUERY_ANCHORS` (2000) anchors per script
    (`QueryScan.anchor_cap`). Pairs: an all-literal route array (elements joined with
    `/`) with a literal `queryParams` object; Vue `push({path, query})` (a `name:` route
    or a non-literal path leaves the names unpaired); React `navigate("/r?a=")`,
    `<Link to="/r?a=">`, `(Link,{to:"/r?a="})`. A multi-element array with any
    non-literal element is a dynamic segment: refused (`spa_query_refused[dynamic
    segment]`), names dropped, no element seeded alone (B7). An empty array or a lone
    non-literal element names no known route: its names are unpaired. A non-literal
    `queryParams` value is counted (`non-literal query`); `{}` is nothing. Unpaired
    names: the member/quoted reads above and a `queryParams:{..}` object outside a
    `navigate` call. Names (`spa.query_name_ok`): ASCII identifier characters, at most 64,
    never an Observable/ParamMap member (`QUERY_MEMBERS`) nor a name followed by `(`; a
    sensitive name (`core.redaction.is_sensitive_name`) is dropped and counted by class
    only; at most 50 per script (`name cap`).
  - **Q3, seeds:** `LocalSpider._queue_routes` turns each pair into one crawl URL, queued
    after the bare routes (B8) with `source = 'spa-query'` (`spa.SEED_SOURCE`):
    `spa.seed_url` sets every name to the text filler (`spa.query_filler` =
    `store_adapter`'s, PA-0003), or to `/` for a redirect-ish name (`spa.redirect_name`:
    a whole token, or the whole name, in `tools.fetcher.REDIRECT_PARAMS`, the one shared
    open-redirect name set). Gates: `classify_route` (parameterised, destructive, not a
    route), then `LocalSpider._query_gate`: `spa.query_url_refusal` (`route_destructive_reason`,
    then `window_request_refusal("GET", url, False)` on the URL **and** on the route
    fragment's path and query re-rooted on the origin, which a hash URL hides from that
    rule; A-M1), scope, the visit key. One seed per (route URL, names not yet seeded).
  - **Q4, the window:** `_window(..., query=)` is the reveal window's variant: it opens
    with `own_nav = {_nav_key(load URL)}`, `_goto_and_parse` clears it once the load has
    settled, `_window_refusal` / `_ws_hold` gate the load exactly as for a reveal
    (non-GET and W2 words aborted, navigations aborted and kept, WebSocket messages
    held), counting `spa_query_writes_blocked` instead of `reveal_writes_blocked`. The
    exit decision: **not** `_restore` (its reload would replay the load's own on-load
    code) but `_leave`: a seed's same-document route change (`location.hash` on load) is
    kept as a navigation, popups are closed, the page goes to `about:blank` inside the
    window, then `_quiesce` and the lift; requests aborted while leaving are counted with
    the rest. A seed's kept navigations are queued through the normal gates (`source =
    'redirect'`, one level deeper). A seed neither reveals nor submits, and its landing
    is not marked as a redirect page (`_after_fetch`).
  - **Q5, the observation probe:** when the queue drains, `_plan_probes` queues one probe
    load (`spa.PROBE_SOURCE`) per scanned, rendered route not yet probed (at most
    `MAX_QUERY_PROBE_ROUTES` = 40, `probe route cap`); `_mint_probe` mints **fresh**
    markers at load time for the unpaired names not yet seeded there (at most
    `MAX_UNPAIRED_NAMES` = 12, all in one load; `probe name cap` once per name;
    redirect-ish names carry `/`, no marker, B6) and gates the URL as a seed. Markers
    (`spa.mint_markers`): `fzq` + two index letters + 8 random letters, all lower case,
    fixed length (13), so word-shaped and never `looks_like_identifier` (pinned).
    The load runs in the crawl loop inside its window; right after it the loop's
    **store suppression** branch reads the page (`_finish_probe`) and `continue`s: no
    page, link, XHR URL or form is recorded (and a failed probe is not marked visited);
    `_observe` returns at once and `_on_request` sends the load's requests -- the page's
    `request` event, which fires before the route decides, so aborted requests and
    their bodies are included -- to the probe only. `spa.observed_names` attributes only
    this load's markers, matched with non-alphanumeric boundaries, in the DOM's text
    nodes, attribute values and control values (`spa.OBSERVE_JS`) and the requests'
    decoded URLs and bodies; a string carrying another of the load's markers or
    `<probed name>=` syntax counts for nothing (B5); strings over 8 KiB are not judged.
    Kept names are seeded as in Q3.
  - **Q6:** a seed becomes a `fragment` point through the existing
    `_import_route_query`, and a GET XHR carrying the filler in its query a `query` point
    through the XHR link set; a marker or filler in a GET path segment gives no point
    (counted `spa_query_marker_in_path`). No server-side point is claimed from a capture.
  - **Q7, counts** (`spa_counts`, `crawl_stats`, the summary): `spa_query_pairs`,
    `spa_query_unpaired`, `spa_query_probe_loads`, `spa_query_kept`,
    `spa_query_refused` (total; by reason as `spa_query_refused[<reason>]` keys),
    `spa_query_writes_blocked`, `spa_query_marker_in_path`, `spa_query_anchor_cap`, and
    `spa_query_seeded` / `spa_query_seeded_fragment`, so the summary shows seeds that are
    fragment points (confirmable only with `--browser`) apart from history-mode query
    points (A-S5). `LocalSpider(spa_query=False)` turns the feature off; it is on with
    SPA routes in the Playwright engine (`--no-spa-routes` turns both off).
- Impact: crawler only (`tools/spa.py`, `tools/spider.py`); no store schema, importer,
  navguard or core change. New spider-DB values: `discovered_pages.source =
  'spa-query'` and the `crawl_stats` names above. `spa.py` now reads the auditor's
  `tools.fetcher.REDIRECT_PARAMS` (read only). Downstream: more `fragment` points (M6,
  `--browser`) and, from seeds' GET XHRs and history-mode seeds, more `query` points.
  More page loads per crawl: one probe per rendered route (40 at most) and one per seed.
- Risk: medium (the crawl now loads routes with query values and observation markers).
  Mitigated: every such load is inside the window (no write, navigation or WebSocket
  message reaches the app's server), gated like a seed, same-origin, with inert
  letters-only markers or the filler (`/` for a redirect-ish name); probe loads record
  nothing; residuals below are stated in FR-CRAWL-17.
- Deliverables:
  - [x] `spa.scan_script` / `scan_query_params` / `seed_url` / `query_url_refusal` /
    `redirect_name` / `mint_markers` / `observed_names` / `filler_in_path` /
    `OBSERVE_JS` — done
  - [x] spider: `_note_query_scan`, `_queue_seed`, `_query_gate`, `_plan_probes`,
    `_mint_probe`, `_finish_probe`, `_take_query_navs`, `_leave`, `_window(query=)`, the
    crawl loop's window and store-suppression branch, summary and `crawl_stats` — done
  - [x] tests `tests/test_spa_query.py` (49), fixture `tests/_spa_query_fixture.py` — done
  - [x] FR-CRAWL-17 and NFR-CRAWL-safe tracing in `requirements.md`; ARCHITECTURE.md;
    CHANGELOG — done
- Effectiveness (assessed 2026-10-14): `tests/test_spa_query.py` 49 passed, 0 skipped
  (real Chromium, `FUZZLAB_REQUIRE_BROWSER=1`), including the end-to-end
  `test_track_result_id_reaches_m6_and_confirms_dom_xss` (crawl -> `/#/track-result`
  `id` fragment point -> M6 `xss-dom` finding; none with the feature off). Mutation
  checks, each reverted afterwards: the scan's wiring removed -> 10 tests fail (the
  end-to-end one included); the window not entered for seeds and probes -> 3 fail
  (`test_a_seed_load_cannot_write`: the server got 1 POST; the navigation and beacon
  tests); the store-suppression branch removed -> 3 fail
  (`test_no_stored_row_carries_a_marker` among them); the marker filter reduced to
  prefix + index -> 4 fail (the stale-marker unit and browser tests among them). The
  4 MB adversarial bodies scan in 0.02-0.26 s each (bound 10 s). On Juice Shop's real
  `main.js` the scan gives pairs `403: error`, `login: redirectUrl`, `track-result:
  id`, unpaired `q, id, challenge, redirectUrl, error, testDecal, initialMessage`,
  refused `non-literal query` x2 and `dynamic segment` x1 (`chatbot/conversation`).
  Related suites, real Chromium, `FUZZLAB_REQUIRE_BROWSER=1`: (a) `test_spa_query`,
  `test_spa_routes`, `test_spa_capture`, `test_spider_scope`, `test_store_adapter`,
  `test_json_points`, `test_storage_redaction`, `test_proxy_redaction`,
  `test_logout_redirect`, `test_requirements_traceability`, `test_lint`
  (`FUZZLAB_REQUIRE_LINT=1`): 576 passed, 1 failed, 0 skipped -- the failure was the
  unchanged `scan_routes` timing-ratio test
  `test_spa_routes.py::test_the_scan_is_linear_on_adversarial_5mb_bodies`, which then
  passed 5/5 alone, 2/2 after `test_spa_capture` + `test_spa_query` (suite order), and
  in a full `test_spa_routes.py` re-run (70 passed): flagged as a timing flake;
  (b) `test_browser_scope`, `test_forms_phase4`, `test_destructive_urls`,
  `test_forms_phase1`, `test_forms_phase2`, `test_session_browser_login`,
  `test_browserauth`: 658 passed, 0 skipped. Not verified here: the live Juice Shop crawl
  and M6 run (the coordinator's live check).

- **Review amendment, round 1 (2026-10-14; reviewers A and B, both AGREE-with-changes;
  the coordinator's reconciled fix list S1-S11, D41).** Appended; the entry above stays
  as landed. Supersedes, from this amendment on: the anchor cap (`MAX_QUERY_ANCHORS`,
  `QueryScan.anchor_cap`, `spa_query_anchor_cap`), "windows never overlap" as the stated
  bound, the "same-name API forwarding discounted" and "persisted markers can reappear"
  residuals, the "no CLI flag" and "no session check" residuals, and the read of
  `tools.fetcher.REDIRECT_PARAMS`.
  - **S1 (A-M1):** each seed/probe window records what it blocked
    (`LocalSpider._window_refusal`: `win["writes"]` for non-GETs; the probe's
    `blocked` set, also fed by `_note_guard_abort` / `_note_out_of_scope`). A name
    whose only evidence is a blocked request is not kept (`spa.observed_names` takes
    `(url, body, blocked)`). A seed whose window blocked a write is re-filed
    `source = 'spa-query-writes'` (`spa.WRITE_SEED_SOURCE`,
    `StorageManager.set_source`, `_after_query_window`; counted
    `spa_query_write_seeds`), which `store_adapter.import_spider` imports as a page only
    (CC-CORE-0053). Follow-up, its own design gate (CC-FUZZ): M6 loads of such a route
    inside a write-blocking window.
  - **S2 (A-M2):** docstrings and FR-CRAWL-17 state the real bound: monotone `str.find`
    per anchor kind plus a step budget.
  - **S3 (A-M3, B-S3), BUG-0135 / PA-0135:** `spa.StepCounter` (`steps`, `scanned`);
    `scan_routes(counter=)` and `QueryScan.steps/.scanned`; the linearity tests of both
    scanners assert `ops(2n) <= 2 * ops(n) + slack` (wall clock: absolute smoke only);
    the AST guard `tests/test_no_wall_clock_ratio.py`, which this crawler lane adds for
    the whole `tests/` tree (no other component's test changed).
  - **S4 (A-S1):** the walker's budget is `MAX_QUERY_STEPS` (2,000,000) steps, not an
    anchor count (`QueryScan.budget_hit`, counted `spa_query_step_cap`).
  - **S5 (A-S2):** options with `relativeTo` leave the names unpaired;
    `classify_route` refuses a `.` / `..` segment.
  - **S6 (A-S3):** the `<name>=` discount applies to a request URL only when it is a
    copy of the page's own (its path is the document's, or it carries the fragment
    route).
  - **S7 (A-S4):** `spa.scrub_markers` replaces any whole-token marker with
    `spa.MARKER_PLACEHOLDER` at the spider's storage boundary (`mark_visited` URL, title
    and text; `record_request`; `record_form`; `record_revealed_form`).
  - **S8 (A-S5, B-S2, A-N5):** `REDIRECT_PARAMS` moved unchanged to `core.urls`
    (CC-CORE-0053); `tools.fetcher` re-exports it; `spa.redirect_name` reads it. Wording:
    the window is the guard, `/` is hygiene; the `R-OPEN-REDIRECT` `name_regex` tension
    is stated in FR-CRAWL-17 / FR-CORE-39.
  - **S9 (B-S1):** `_note_guard_abort` never records a probe URL in
    `skipped_destructive`.
  - **S10 (B-S4):** in an authenticated crawl `_leave` runs `_client_session_intact` on
    the load's own page before it leaves; on a loss query loads stop
    (`spa_query_stopped`, `spa_query_session_losses`, later ones refused
    `session lost`) and the session is re-adopted once on the start page; a
    re-adoption that does not hold stops reveals and submissions (as W4).
  - **S11:** the `navigateByUrl(` anchor (A-N1); a quoted name that is not
    identifier-shaped is counted `not identifier-shaped` (A-N2); `--no-spa-query`
    (A-N3); a `queryParams` anchor continuing a longer identifier is ignored (A-N4).
  - Not done here: the merge with origin-scope (B-M1), pending the coordinator.
  - Effectiveness (review amendment, assessed 2026-10-14): `tests/test_spa_query.py` 71
    passed, 0 skipped (real Chromium, `FUZZLAB_REQUIRE_BROWSER=1`), including the S1
    crawl + import + real-M6 test (no POST to `/api/send` or `/api/beacon`) and the S10
    authenticated test. Mutation checks, each reverted afterwards: S1 blocked evidence
    counted -> the probe test fails (`beacon` kept); S1 seed re-filing dropped -> the S1
    M6 test fails; S3 a quadratic walker (`hi = len(text)`) -> 4 fail (3 doubling shapes
    and the budget test, deterministically), and an unbounded `<Route` look-back in
    `scan_routes` -> its linearity test fails; S4 an anchor cap of 2000 in place of the
    step budget -> 2 fail (the 3000-noise-anchor test, the budget test); S6 the
    `<name>=` discount on every request URL -> 2 fail (the unit test and the browser
    probe test, `forward`); S7 no scrub in `mark_visited` -> the no-marker test fails.
    The 4 MB adversarial bodies scan in 0.02-1.4 s (budget-bound; smoke bound 10 s). The
    Juice Shop `main.js` scan is unchanged (pairs `403: error`, `login: redirectUrl`,
    `track-result: id`; 7 unpaired; refused `non-literal query` x2, `dynamic segment`
    x1; 45 anchors, 664 steps). Related suites with `FUZZLAB_REQUIRE_BROWSER=1`: 1312
    passed, 0 failed, 0 skipped (`test_spa_query`, `test_no_wall_clock_ratio`,
    `test_spa_routes`, `test_store_adapter`, `test_json_points`,
    `test_requirements_traceability`, `test_lint` with `FUZZLAB_REQUIRE_LINT=1`,
    `test_logout_redirect`: 286; `test_spa_capture`, `test_spider_scope`,
    `test_storage_redaction`, `test_proxy_redaction`, `test_destructive_urls`,
    `test_browserauth`: 377; `test_browser_scope`, `test_forms_phase4`,
    `test_forms_phase1`, `test_forms_phase2`, `test_session_browser_login`,
    `test_form_entries`, `test_cli_dry_run`, `test_auditor_seam`: 649).

- **Review amendment, round 2 (2026-10-14; reviewers A and B, both AGREE-with-changes;
  the coordinator's reconciled fix list U1-U10, D46).** Appended.
  - **U1 (A2-M1, B2-M1):** in a query window `_window_refusal` counts as a write every
    refused non-GET/HEAD (a navigation included) and every refused non-navigation GET
    (the word rules); `_note_ws_drop` counts a held WebSocket message. A refused non-GET
    navigation's target is not queued (it was queued as a GET: reviewer A's note; an
    addition to U1's text, flagged to the coordinator). **Found by U1's test and fixed
    here:** a URL the window blocked was still queued from the load's request list
    (`_xhr_urls`) and fetched later outside the window (`GET /api/order/confirm`, `GET
    /api/send`); every URL a query window or the guard blocks now goes in
    `win["blocked"]`, and the loop never queues one. This defect was in this lane's own
    unmerged code, not on trunk.
  - **U2 (A2-S1):** a seed is stored `spa-query-writes` and promoted to `spa-query` in
    `_after_query_window` only when `win["closed"]` (the exit, quiet period and re-check
    all completed) and it wrote nothing; a failed visit is never promoted.
  - **U3 (B2-M2):** `win["session"]` is preset to `(False, "the session check did not
    complete")`; the check in `_leave` is wrapped and any exception is kept as a loss;
    the reader's default is `(not self._authenticated, "no session check")`; the page
    still leaves for `about:blank`. A re-adoption that raises anything is a failed one.
  - **U4 (B2-S1/S2):** `_recheck_query_session` runs after `_quiesce`: the cookie half
    (`_cookies_intact`, split out of `_client_session_intact`) again, then
    `_live_session_intact` when the window blocked a write.
  - **U5 / U6:** BUG-0135's oracle and guard tightened (see that bug's "Added in
    review").
  - **U7 (A2-S3):** `spa._known_route`: a route with a `.` / `..` segment names no route
    at the scan (its names unpaired, no pair counted).
  - **U8 (B2-S4):** `TRANSACTION_TOKENS`' comment is back above it in `core/urls.py`.
  - **U9:** `spider_kwargs(args)` builds `LocalSpider`'s keywords for `__main__`
    (B-N1); `record_revealed_form` scrubs its route and signature before the dedup read
    (B-N3); `observed_names` states that URL-keyed blocking is conservative (B-N4);
    `_plan_probes` plans nothing once query loads stopped (B-N5); FR-CRAWL-17's
    residuals gained B-N6, A-N1 and A-N2.
  - **U10:** CC-AUD-0041 (the importer), CC-CORE-0053 amended to point to it.
  - Effectiveness (U1-U10 amendment, assessed 2026-10-14): `tests/test_spa_query.py` 92
    passed, 0 skipped (real Chromium, `FUZZLAB_REQUIRE_BROWSER=1`); the crawl + import +
    real M6 test sees no POST to `/api/send`, `/api/beacon` or `/api/autopost`, no
    `ping-` WebSocket message, and no GET of a blocked URL. Mutation checks, each reverted
    afterwards: U1 (the old write rule and no WebSocket count) -> 4 fail; U2 (seeds filed
    importable from the start) -> the fail-closed test fails; U3 (no preset, no
    try/except, an open default) -> both U3 tests fail; U5 a prefix re-walking walker ->
    all 8 non-constant shapes fail, an unbounded window -> the same 8 plus 2 constant
    shapes; U6 each guard feature reverted -> exactly its synthetic offender escapes (14
    features, 17 offenders). Related suites, `FUZZLAB_REQUIRE_BROWSER=1`: 1333 passed, 0
    failed, 0 skipped (`test_spa_query`, `test_no_wall_clock_ratio`, `test_spa_routes`,
    `test_store_adapter`, `test_requirements_traceability`, `test_lint` with
    `FUZZLAB_REQUIRE_LINT=1`, `test_logout_redirect`: 194; `test_json_points`,
    `test_spa_capture`, `test_spider_scope`, `test_storage_redaction`,
    `test_proxy_redaction`, `test_destructive_urls`, `test_browserauth`: 490;
    `test_browser_scope`, `test_forms_phase4`, `test_forms_phase1`, `test_forms_phase2`,
    `test_session_browser_login`, `test_form_entries`, `test_cli_dry_run`,
    `test_auditor_seam`: 649).

- **Review amendment, round 3 (2026-10-14; reviewer A AGREE, reviewer B AGREE-with-changes,
  no must-fix; the reconciled fix list Y1-Y4, D52).** Appended.
  - **Y1 (A3-S1 = B3-S1):** `LocalSpider._on_request_failed` (the crawl page's
    `requestfailed` event): while a query window is open every failed request's URL goes
    into `win["blocked"]` (and the probe's): a GET whose redirect hop the window refused
    fails, so it is never queued from the load's request list and fetched later outside
    the window (where the hop would run). `observed_names` documents exact-URL matching
    (A3-N2).
  - **Y2 (B3-S2, B3-N2):** `spa_query_unclean_windows` counts a query window that did not
    close cleanly (summary, `crawl_stats`); every seed not promoted -- a write, an unclean
    close or a failed visit -- is counted in `spa_query_write_seeds`.
  - **Y3 (B3-S3):** `_recheck_query_session` also runs on the window's failure path,
    after its `about:blank` attempt.
  - **Y4 (B3-N1):** the slow-expiry test's docstring says it passes through either check.
  - Effectiveness (Y1-Y4, assessed 2026-10-14): `tests/test_spa_query.py` 94 passed, 0
    skipped (real Chromium). Mutations, each reverted: Y1 (no `requestfailed` hook) ->
    the hop test and the M6 test fail (the server got `GET /api/order/confirm?via=go`
    twice); Y3 (no re-check on the failure path) -> its unit test fails. The every-file
    run is recorded with CC-CRAWL-0029.
- **Merge amendment (2026-10-15; p3-int @ 89268f7 -- origin-scoped sessions, FR-SESS-20 /
  BUG-0134, BUG-0136, BUG-0137 -- merged into spa-query as f68a077; the consolidated list
  M0-M10, D55).** Appended. The merge commit carries the conflict resolutions only (the
  spider CLI tail; the newest-on-top logs, both sides kept). Then:
  - **M0:** `spider.session_manager_for(args)` is the one builder of the CLI's session
    manager (`make_session_manager(args.start, store_path=args.store,
    auth_origins=args.auth_origin)`, None without `--identity`); `__main__` calls
    `LocalSpider(args.start, **spider_kwargs(args, session_manager_for(args)))` after
    origin-scope's `parse_args(argv)` validates `--auth-origin`.
  - **M1:** `_note_session_withheld` diverts to `probe["blocked"]` while a probe is open:
    a marker URL never reaches `skipped_other_origin`, the withheld targets or the log.
  - **M2:** a probe route on another origin is recorded under its own URL before
    `_mint_probe`: never minted, never loaded.
  - **M3:** the loop's `except SessionWithheld` records nothing for a probe and files a
    seed as `spa-query-writes`.
  - **M4:** `_fetch_rendered(url, fallback=True)`: a seed's failed load re-raises
    instead of falling back to a static request (which would re-send it outside the
    window); the seed takes the failure path and stays a write seed.
  - **M5:** a failed probe's log line (and the window's could-not-close line) is passed
    through `spa.scrub_markers`: the Playwright error quotes the probe URL. (Found by
    M5's merged test; in this lane's own unmerged code.)
  - **M6:** `_leave` reads `page.url` as a seed's same-document navigation only when
    the load committed (`self._doc_url == page_url` and the page is an `http(s)`
    document, not `about:blank` / an error page).
  - **M7:** for a load that did not commit, `_leave`'s session check is
    `_cookies_intact` then `_live_session_intact` (the page is `about:blank` after X1:
    no localStorage of the app). Mechanism choice, flagged: every seed and probe load
    first goes to `about:blank` **outside** its window, so the previous page's interval
    POSTs and requests are never the load's write or XHR (the failed seed's own goto
    left that page running for the whole window otherwise).
  - **M8:** a query window tracks its non-probe XHR/fetch URLs in flight
    (`request` -> `requestfinished` / `requestfailed`); the seed's XHR loop skips them
    as it skips blocked ones.
  - **M9:** FR-CRAWL-17's residuals say ordinary failures also block; the summary reads
    "seed(s) kept as pages, never points (a write, an unclean close or a failed visit)".
  - **M10:** the `query_crawl` fixture snapshots `lab.requests` after its crawl; the hop
    test reads the snapshot.
  - Residuals, stated: a seed's refused GET redirect hop is a navigation target, queued
    through the normal gates (W2), so it may be crawled later as a page.
    No session code changed (no CC-SESS cross-reference).
  - Tests: `tests/test_spa_query.py` (+9: the `--auth-origin` builder test, M1, M2,
    M3, M5 (with M3's real-browser path, A and B on 127.0.0.2), M6, M7 unit, M8 unit, and
    the real-browser M4/M7/M8 crawl of `RedirectSeedSpa`); `tests/_spa_query_fixture.py`
    (`RedirectSeedSpa`).
  - Effectiveness (M0-M10, assessed 2026-10-15): `tests/test_spa_query.py` 103 passed, 0
    skipped (real Chromium). Mutations, each reverted: M1 (no divert) -> the M1 test
    fails; M2 (no origin check) -> the M2 test fails (the route was minted); M6 (no
    `_doc_url` check) -> the M6 test fails; M7 (localStorage check always) -> the M7
    unit test and the real crawl fail (`spa_query_session_losses` 1); M7 (no
    `about:blank` before the window) -> the real crawl fails (`/api/tick` in the seed's
    window); also M3 (seed filed as `spa-query`), M4 (static fallback: the seed sent
    twice), M8 (no in-flight skip: `/rest/late` fetched 3 times) and the M5 log scrub
    each make their test fail.
- **Post-merge amendment (2026-10-15; review of b5bf8c5: reviewer A AGREE, reviewer B
  AGREE-with-changes; the fix list P1-P4, D57; P1 decided as both (a) and (b)).**
  Appended. B's must-fix: since M7's `about:blank` pre-step every seed was a full app
  load, so an app shell that writes on every load (Juice Shop's socket.io client: an
  engine.io polling POST, WebSocket pings) would demote every seed to
  `spa-query-writes`, and `#/track-result?id=` would never become a point.
  - **P1(a):** a hash-route seed or probe loads its bare route (`_route_key`) fresh
    and settled **outside** the window (after the `about:blank` pre-step, so the
    previous page's timers still die; its captures are filed under the bare route),
    then makes the same-document hash change into the seed or probe inside the window.
    The shell's start-up writes are sent before the window opens.
  - **P1(b):** a per-route write baseline. While a page loads outside any window
    (`_goto_recording`, around `_goto_and_parse`), every request a query window would
    count as a write, and every forwarded page-to-server WebSocket message (navguard's
    new `on_ws_send`, CC-CRAWL-0026 amendment), is recorded by (method, path), `WS` for
    a socket (`_write_key`), under the load's bare route. In a query window a write whose
    key is in the route's baseline is blocked all the same but not counted
    (`_count_query_write`; counted `spa_query_baseline_writes`, a new `crawl_stats` key).
    This covers history-mode seeds (a full load in the window) and periodic shell writes.
  - **Found while building P1, fixed here (flagged to the coordinator):** with P1(a) a
    hash seed's load is a same-document change, which completes where the full load
    used to fail ("navigation interrupted"). `#/autopost?go2=`'s form, rendered by the
    query and auto-submitted (the write its window blocked), was then still in the DOM
    and stored as a crawled form, and the S1 test caught M6 POSTing it. Now a seed's
    forms are kept in its window and stored only when the seed is promoted, and they are
    never enumerated (`_after_fetch`, `_after_query_window`). A bare route that fails
    before its seed's window opens is counted as a failed visit
    (`spa_query_write_seeds`).
  - **P2 (B-S2):** in a query window, a refused GET navigation's target (a redirect hop
    included) that the window's GET word rules refuse (a transaction or account GET) is
    a blocked write and is never queued. This supersedes the merge amendment's stated
    residual for such hops.
  - **P3 (B-S1):** the M5 test's probe also opens a WebSocket to B carrying the marker:
    it is never connected, and it is that probe's blocked evidence. The `/goaway`
    docstring now says the landing was window-refused, not withheld.
  - **P4:**
    - (B-N1) `_load_committed` is set when `_goto_and_parse` completes (`response is
      not None or same_document`), never before the goto, and `_leave` requires it.
    - (B-N2) navguard's URL-bearing log lines are scrubbed of markers (CC-CRAWL-0026
      amendment).
    - (B-N3) FR-CRAWL-17 states the cost.
  - Fixtures: `QuerySpa` and `RedirectSeedSpa` shells POST
    `/socket.io/?EIO=4&transport=polling` on every load and ping a `/socket.io/`
    WebSocket every 100 ms. RedirectSeedSpa's hop is now `/api/order/confirm?via=hop`:
    `via=seed` tripped the destructive rule (`seed`), so the guard, not the window,
    refused it.
  - Tests (`tests/test_spa_query.py`, +6 and 4 extended): the shell-writes test on the
    shared crawl, covering (a), (b), `#/track` promoted and imported as a fragment
    point, `#/poster` still a write seed, and no `/api/autopost` form stored. Also:
    - the baseline unit test;
    - navguard's `on_send` unit test;
    - the guard log-scrub test;
    - the seed-forms test;
    - the RedirectSeedSpa crawl, extended for P1(b) in history mode (`/next1?y=`
      promoted with the shell's writes blocked and baselined) and for P2 (the hop never
      requested);
    - the write-classification parametrisation (P2);
    - the M5 test (P3);
    - the M6 test (P4 B-N1).
  - Effectiveness (P1-P4, assessed 2026-10-15): `tests/test_spa_query.py` 109 passed, 0
    skipped (real Chromium). Mutations, each reverted:
    - P1(a) off: the shell-writes test fails (the start-up POST blocked in `#/track`'s
      window).
    - P1(b) off: the shell-writes test, the RedirectSeedSpa crawl and the unit test fail
      (`#/track` and `/next1` demoted).
    - P2 off: the parametrised unit test and the RedirectSeedSpa crawl fail (the goaway
      seed's write is not counted).
    - Seed-forms deferral off: the S1 M6 test and the shell-writes test fail.
- **Baseline amendment (2026-10-15; review of 5e0dc5a: reviewers A and B both
  AGREE-with-changes, the same two holes found independently; the fix list B1-B3, D60).**
  Appended. Both holes let a seed whose query causes a write be promoted, so M6 would
  replay that write.
  - **B1 (A-M1 = B-S2):** only a load of a **bare** route (`_is_bare_route`: a hash
    route whose fragment has no query, or a URL with no query) records into
    `_write_baseline`. Before this, a crawled link such as `#/poster?msg=hi` put its
    query-caused POST into `#/poster`'s baseline, and the seed was then promoted.
  - **B2 (A-S1 = B-S1):** a write in a query window that carries the load's own query
    values always counts, a baseline endpoint's included. The values are the seed's text
    filler or the probe's markers (`win["taint"]`), checked in:
    - the URL, also percent-decoded;
    - the HTTP body, read by the page's `request` event while the window is open;
      `_note_tainted` handles either event order, moving a write already set aside as a
      baseline one into `writes`;
    - the WebSocket message text. navguard's `on_drop` is now `on_drop(url, message)`
      (CC-CRAWL-0026 amendment).
  - **B3:** navguard's `on_send` call is wrapped in `contextlib.suppress(Exception)`.
    FR-CRAWL-17 now states three residuals and costs:
    - a bare-route load's late requests may be captured under the seed's URL (harmless);
    - each seed and probe makes the shell's start-up writes once more (A-N2);
    - an app that reads a query only at bootstrap shows a hash seed nothing.
    It also restates the (method, path) residual: a query-caused write on a baseline
    endpoint that does not carry the value literally is still not counted.
  - Not done here, as instructed: the MERGE step with BUG-0138.
  - Fixture: `BaselineSpa`.
    - The crawl starts at `/start`, so the query links `#/poster?msg=hi` and
      `#/search?q=foo` are crawled before any seed.
    - The shell POSTs `/api/events` and pings a socket.io socket on every load.
    - `#/find?q=` POSTs `{"q": q}` to `/api/events`; `#/talk?q=` emits `q` on the shell's
      socket; `#/calm?q=` only renders.
    - `tests/test_forms_phase4.py`'s forwarder test now takes `on_drop(url, message)`.
  - Tests (`tests/test_spa_query.py`, +3, 1 extended):
    - `test_the_baseline_never_takes_a_query_caused_write_and_a_query_value_always_counts`
      (real Chromium): the poster, search, find and talk seeds are all write seeds, none
      imported (`write_seed_skipped` >= 4); calm is promoted and imported as a fragment
      point.
    - the B2 unit test: both event orders, a percent-encoded URL, str and bytes WS text;
    - the B1 predicate test;
    - the forwarder test, extended for the message text and a failing `on_send`.
  - Effectiveness (B1-B3, assessed 2026-10-15): `tests/test_spa_query.py` 112 passed, 0
    skipped (real Chromium). Mutations, each reverted:
    - B1 (record every load outside a window): the real-browser test fails, with
      `("POST", "/api/send")` in `#/poster`'s baseline.
    - B2 (`_carries` always false): the real-browser test fails (`#/find?q=fuzzlab`
      promoted to `spa-query`), and so does the unit test.
- **Merge amendment, BUG-0138 (2026-10-15; bug-0138 @ e51a3d4 -- guarded navigation,
  CC-CRAWL-0030 -- merged into spa-query as 0d03e12).** Appended. The merge commit holds
  the conflict resolutions only:
  - navguard: the P4 `_scrubbed` observer log line, then BUG-0138's `_note_received`
    block. `make_ws_handler` keeps `on_drop(url, message)` and the suppressed `on_send`.
  - `_goto_and_parse`: BUG-0138's Q2 body, then `_load_committed = (response is not None
    or same_document) and own`. `own` starts as True for a non-HTML response, which
    has no Q2 reading.
  - The query pre-step: `navguard.navigate(about:blank, wait_until="load")`, then the
    P1(a) bare-route block, with no raw `page.goto`. `core.urls.document_key` and
    `_nav_key` returning it are kept.
  - CHANGELOG: both sides' entries, newest on top by commit time.
  Follow-up:
  - **S3:** a hash seed or probe whose bare route did not load is refused with "bare
    route did not load" (`spa_query_refused`), and its window is never entered. Not
    loaded means `_rendered_ok` is false after `_goto_recording`: the load stopped,
    because a refused script navigation superseded it, or never completed. A refused
    seed is neither stored nor counted as a write seed.
  - **Reviewer A N1:** `_load_committed` comes from the Navigation result. A navigation
    that committed but whose load did not complete is committed while the page still
    shows its own document (`own`), and is not once another document replaced it.
    `_goto_recording`'s `finally` still wraps the `navigate` path.
  - Tests (`tests/test_spa_query.py`, +2; fixture `HeadNavSpa`):
    - `test_a_query_load_whose_bare_route_did_not_load_is_refused` (real Chromium):
      the shell's head script navigates to `/logout.php`; the refusal is counted (also
      in `crawl_stats`); no seed is stored or promoted; no window is entered.
    - `test_a_load_that_committed_but_did_not_complete_is_committed`: N1, both cases.
  - Effectiveness (2026-10-15): `tests/test_guarded_navigation.py` and
    `tests/test_spa_query.py` run together: 136 passed (real Chromium). Mutations, each
    reverted: S3 off fails the S3 test (no refusal counted); dropping `and own` fails
    N1's replaced-document case.

### CC-CRAWL-0026 — The browser session is origin-scoped; the jar never reaches another origin (FR-SESS-20, BUG-0134) (2026-10-14)
- Change:
  - **`tools/browserauth.py`:** `header_scope_for(state, base_url, in_scope)` admits an
    in-scope URL whose canonical origin is one of `state.origins` (a state without
    origins: the base URL's origin only), with the https floor; it was
    `canonical_host(url) == host`. `BrowserSession.cookie_scope` (default: the same
    predicate, PA-0003).
  - **`tools/navguard.py`:** `make_route_handler` / `guard_page` take `cookie_scope` and
    `on_session_withheld`. In an authenticated context an in-scope request or redirect
    hop on another origin is fetched with an explicit empty `Cookie` header (Playwright's
    API client adds the context's port-agnostic jar only when no `Cookie` header is
    given; checked in its source and live) and without the session's headers; a
    redirected navigation landing there is answered with the landing response, not a
    redirect: Chromium's own re-request of the landing URL is never routed and carried
    the jar (found by the real-browser test, fixed, then mutation-checked).
  - **`tools/spider.py`:** the crawl's authenticated context passes `cookie_scope` and
    counts withheld requests (`session_out_of_origin`, summarised at the end of the
    crawl); `_isolated_submit` drops the jar's cookies for an action on another origin.
- Impact: an external (any-port) crawl visits another port of its host anonymously; a
  loopback crawl is unchanged (its scope is already the exact origin). The auditor's
  browser (CC-AUD-0038) gets the origin-based header scope through `browserauth` with no
  code change. On such a landing, `page.url` stays the first URL (relative links on that
  page resolve against it; in scope either way).
- Risk: low-medium (browser path). Mitigated: unit tests of the route (request, hop,
  landing) and a real-Chromium crawl whose second server records every request.
  Residual: an in-scope WebSocket on another origin is connected by the browser itself.
- Deliverables:
  - [x] code (`tools/browserauth.py`, `tools/navguard.py`, `tools/spider.py`) — done
  - [x] tests (`tests/test_session_origin_scope.py`: header scope, the route's
    withholding, `_isolated_submit`, the real-Chromium external crawl) — done
  - [x] FR-CRAWL-14 amended in place — done
- Effectiveness (assessed 2026-10-14): see CC-SESS-0023 (mutation checks of
  `header_scope_for`, the cookie strip and its landing rule each fail their tests);
  the browser scope / browser login / SPA / forms phase 4 suites pass.
- Review round 1 of 0046b77 (2026-10-14; R1, R2, R5 of the reconciled fix list):
  - **R1 (A-M1, seen live: the landing ran B's script under A's URL and read A's
    cookie and localStorage):** the landing-response branch is removed. In an
    authenticated context every document (navigation, top-level or frame; a redirect
    landing) and every WebSocket on an in-scope origin outside `cookie_scope` is aborted
    and reported (`on_session_withheld(url, kind)`, kind `document` / `frame` /
    `websocket` / `request`). The spider records it in `skipped_other_origin`, skips such
    a queued URL without navigating, and raises `SessionWithheld` (no static fallback,
    nothing extracted) when a page navigation landed there.
  - **R2 (A-M2, seen live: `route.fetch` wrote B's `Set-Cookie` into the shared jar):**
    the empty-`Cookie` trick is replaced: withheld requests and hops go through one
    cookie-less `playwright.request.new_context()` per guard
    (`guard_page(isolated_request=)`; retired once it holds a cookie and disposed at the
    next fetch, since its answer is still being fulfilled; the spider disposes all at the
    end), fulfilled with `Set-Cookie` removed.
  - **R5:** `fuzzlab crawl --auth-origin ORIGIN` (validated in `parse_args`).
  - Mutation checks: R1a (documents loaded through the isolated context), R1b (a
    redirect landing loaded), R1c (a WebSocket connected) and R2 (back to `route.fetch`
    with an empty Cookie) each fail the route unit test and/or the real-Chromium crawl
    (`test_an_authenticated_crawl_never_hands_the_session_to_another_port`, now with a
    frame, a WebSocket, a beaconing landing and a cookie-setting image of B).
- Review round 2 of 97101a9 (2026-10-14; T1, T6 of the reconciled list):
  - **T1 (A2-M1, B2-S2; seen live):** a withheld document, frame or redirect landing is
    aborted with `"aborted"` (ERR_ABORTED, as the reveal window), not `"blockedbyclient"`,
    which committed Chromium's error page in the page's place. `on_session_withheld` now
    gets `(url, kind, source)`: `document` (the navigation's own target), `landing` (its
    redirect landing), `frame`, `websocket`, `request`, and the chain's first URL. The
    spider raises `SessionWithheld` only when the navigation's own target or its
    landing was withheld, or the main frame committed off the session's origins
    (`_navigation_withheld`); a script-initiated navigation away leaves the page
    extracted normally, its target recorded as skipped.
  - **T6:** `skipped_other_origin` reasons name the kind; `isolated_contexts_created`
    counts the cookie-less request contexts (logged at the end); `isolated_fetch`'s
    docstring names both disposals kept (at the next fetch, and the creator's at
    teardown).
  - Mutation checks: `"blockedbyclient"` restored fails
    `test_a_script_navigation_to_another_origin_leaves_the_page_crawled` and the route
    unit test; attributing every withheld document to the current navigation fails the
    former.
- Review round 3 of 9f417ae (2026-10-14; reviewer A, D47; V1, V2):
  - **V1 (A3-M1, seen live in 3 of 4 runs):** concurrent withheld fetches went out with a
    cookie another B answer had stored in the isolated context (a retired context was
    still in use by fetches in flight). Every isolated fetch, request and hop, now
    carries an explicit empty `Cookie` header; retirement and the deferred disposal are
    dropped. The context is made once, when the guard is built: a lazy creation in the
    handler made up to 12 contexts for 12 concurrent images (route handlers run
    concurrently; seen live while testing). The creator still disposes it at teardown.
  - **V2 (A3-N1):** `_navigation_withheld` counts a committed URL only when it is
    in scope and off the session's origins (`_other_origin`); an out-of-scope commit,
    or the error page the scope guard's abort leaves, is BUG-0123's scope abort (already
    counted in `skipped_out_of_scope`), never `SessionWithheld`.
  - Tests: `test_concurrent_withheld_fetches_never_carry_a_cookie` (real Chromium,
    reviewer A's 12-image probe, 5 repetitions), the route unit test (an empty Cookie on
    request and hop, one context, never disposed by the guard),
    `test_an_out_of_scope_script_navigation_is_a_scope_abort_not_fr_sess_20`.
  - Mutation checks: without the empty header the 12-image test failed in **15 of 15**
    repetitions (3 runs of 5; 6–11 of the 12 B requests carried a cookie each time), and
    the unit test failed; restoring the old committed-URL rule fails the V2 test (A's
    row stored as `SessionWithheld`, status 0).
  - Observation (not changed here, flagged): the scope guard aborts an out-of-scope
    navigation with the default error code, so a script navigation off scope still
    commits Chromium's error page and the page's links are lost to the crawl (a
    BUG-0123 coverage effect, not a leak).
  - Effectiveness (review round 3): the related suites (as in round 2) with `FUZZLAB_REQUIRE_BROWSER=1`: **1492 passed, 2 xfailed, 0 skipped**; `tests/test_session_origin_scope.py` has 76 tests; the traceability guard passes. The full suite is the coordinator's run.
- Amendment (2026-10-15; FR-CRAWL-17 post-merge fix list D57, recorded in full under
  CC-CRAWL-0027's post-merge amendment): `tools/navguard.py` only.
  - `make_ws_handler(on_send=)` / `guard_page(on_ws_send=)`: an additive callback,
    `on_send(url)`, told of each page-to-server WebSocket message the forwarder sends.
    The spider records it into a route's write baseline (P1(b)).
  - Every log line that names a URL path or quotes an error is passed through
    `spa.scrub_markers` (`_scrubbed`): a blocked destructive or refused request, an
    over-long redirect chain, a failed fetch, a failed observer (P4, B-N2: an
    FR-CRAWL-17 probe marker never reaches the log).
  - The session and origin rules are unchanged.
  - Tests: `tests/test_spa_query.py::test_the_websocket_forwarder_reports_each_forwarded_message`,
    `::test_the_guards_url_log_lines_never_carry_a_probe_marker`.
- Amendment (2026-10-15; FR-CRAWL-17 baseline fix list D60, recorded in full under
  CC-CRAWL-0027's baseline amendment): `tools/navguard.py` only.
  - The WebSocket forwarder tells `on_drop(url, message)` the held message's text, so
    the crawler can read it for a query load's values (B2).
  - `on_send` runs inside `contextlib.suppress(Exception)`, so a failing hook never
    breaks forwarding (B3).
  - Callers updated: the spider's `_note_ws_drop(url, message=None)` and
    `tests/test_forms_phase4.py::test_the_websocket_forwarder_drops_page_messages_only_inside_the_window`.
  - Tests: `tests/test_spa_query.py::test_the_websocket_forwarder_reports_each_forwarded_message`.

### CC-CRAWL-0300 — NFR-CRAWL-safe records BUG-0301's import risk (doc-only) (2026-10-15)
- Change: `requirements.md` NFR-CRAWL-safe gains two lines:
  - an `Enforced by:` line for the PA-0114/PA-0301 tables and the spelling scan
    (`tests/test_destructive_routes_external_labs.py`);
  - a `Not yet enforced:` line (BUG-0301). A crawl that reaches Juice Shop's
    `/dataerasure` would visit it and import its server-rendered erasure form, and the
    deny rule does not refuse the GET password change. It names the strict xfails that
    pin both.
  No crawler code changes.
- Impact: documentation only; the spec now states the gap (PA-0112(2)).
  `tests/test_requirements_traceability.py` checks the cited tests exist.
- Risk: none (doc-only).
- Deliverables:
  - [x] NFR-CRAWL-safe lines — done
  - [x] traceability test run — done
- Review: the pre-change gate was cleared by design rev 2 (3/3 AGREE, §12); the drafts are in its §10 (CC-FUZZ-0300, CC-CORE-0301) and §12 (CC-CRAWL-0300).
- Effectiveness (assessed 2026-10-15): the traceability guard passes with the new lines
  (counts in CC-FUZZ-0300's report). The line is removed when CC-CORE-0301's corrective
  action lands.

### CC-CRAWL-0025 — The crawl's cookie check covers credential cookies only (BUG-0132) (2026-10-14)
- Change: `tools/browserauth.py` `BrowserSession.checked_cookies`, which is the
  session's cookies minus those a browser login took from the app's own jar
  (`SessionState.browser_cookies`, CC-SESS-0022). `tools/spider.py` `_start_browser`
  sets `_injected_cookies` from it. Since BUG-0132 the session's cookies include the
  jar's (e.g. Juice Shop's `token`, which the app rewrites). Checking those would read a
  legitimate rewrite as a lost session. They reach the crawl context through
  `storage_state` already, as the localStorage entries do.
- Impact: none for server-rendered logins (they have no jar cookies). For a browser
  login, the check is what it was before BUG-0132: credential cookies, localStorage and
  `verify_live`.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] test:
    `tests/test_session_browser_login.py::test_a_rotated_token_keeps_the_crawl_submitting`
    (the fixture now rewrites the cookie with the localStorage token); the mutation that
    checks every cookie fails it — done
  - [x] FR-CRAWL-14 in place — done
- Review of 26507a1 (reviewer B; a follow-up commit):
  - `BrowserSession.checked_cookies` now uses `session.manager.credential_cookie`:
    every login-response cookie, and a jar cookie that copies the token or looks like
    an identifier. Only an ambient jar cookie is skipped. Before, a submission deleting
    only the JS-set `token` cookie went unseen (must-fix 1; test: the fixture's notes
    form deletes only that cookie and the crawl stops).
  - `BrowserSession.rotating_cookies` names the jar ones. `_client_session_intact`
    applies `_storage_rotated` to them: a new identifier-like value is re-adopted;
    cleared, empty, `"null"` or `"undefined"` is a loss. A login-response cookie keeps
    strict equality (should-fix 2; a parametrised unit, and the rotation crawl test,
    whose fixture rotates the cookie with localStorage).
  - `_readopt_session` resets the checked cookies to their adopted values.
- Follow-up (same branch, with CC-AUD-0040): `_start_browser` creates its context through
  `browserauth.context_options(session)`, the one adoption helper the auditor now shares.
  The crawl's behaviour is unchanged.
- Review: with CC-SESS-0022 (BUG-0132 brief).
- Effectiveness (assessed 2026-10-14): verified offline against loopback fixtures, real Chromium (`FUZZLAB_REQUIRE_BROWSER=1`, `FUZZLAB_REQUIRE_LINT=1`, `FUZZLAB_REQUIRE_NETNS=1`): the targeted run (`test_session*.py`, `test_login_form_isolation`, `test_browser_scope`, `test_forms_phase4`, `test_lint`, `test_requirements_traceability`, `test_browserauth`, `test_spa_capture`, `test_subpath_apps`, `test_logout_listener`, `test_proxy_session_capture`, `test_logout_redirect`, `test_loopback_listeners`) gave 751 passed, 1 xfailed (the strict pin of the auditor's localStorage gap), 0 skipped, 0 failed. Not verified here: the live Juice Shop re-run (no lab traffic in this change).

### CC-CRAWL-0024 — Reveal navigation inside a reveal window (FR-CRAWL-16, forms phase 4, G2 and W1-W4) (2026-10-14)
- Change (the agreed design `forms-p4-draft.md`, Revision 2, reviewers A and B):
  - **The reveal window (W1), `tools/spider.py`:** `LocalSpider._window` (a context
    manager, re-entrant) opens before a reveal click or the first G1 interaction; on
    exit `_restore` presses `Escape`, closes popups opened in the window, re-navigates to
    the route if needed and reloads it (the window lets this one GET navigation through
    for its own context and URL), then `_quiesce` settles (nothing in flight, three
    quiet polls) and flushes the driver's events with a round trip before the window is
    lifted; if the close fails the page goes to `about:blank`. `spa.click_vetted` gained
    `before_click`, which lifts the window for the vetted final click of a named-route
    form only (W1).
  - **W2:** `navguard.make_route_handler(window=)` / `guard_page(window=)` asks the
    window after the scope and destructive checks, for the request and each redirect
    hop; a refused navigation is aborted with `"aborted"` (no error page is committed)
    and its target kept. `spa.window_request_refusal`: only GET/HEAD; every navigation;
    destructive (with the SPA fragment), transaction, account-endpoint, account-word or
    credential-token GETs. `LocalSpider._window_refusal` keeps the state (any context
    of the crawl; the lifted context; the own reload), counts `reveal_writes_blocked`
    and queues the navigations' targets through the normal gates.
  - **W3:** `navguard.make_ws_handler(hold=, on_drop=)`: an in-scope socket is
    connected through a forwarding handler (`connect_to_server()`, `ws.on_message`
    forwarding with the server route's no-reply `send` only while the window is
    closed; dropped and counted `reveal_ws_dropped` while open). Mechanism checked in
    Playwright 1.63's source: `send` is `send_may_fail` (no reply), so it does not
    deadlock a sync handler as `close()` does.
  - **W4:** `_session_intact` is split into `_client_session_intact` (cookies, adopted
    localStorage, rotation) and `_live_session_intact` (`verify_live`).
    `_reveal_session_check` runs after every reveal in an authenticated crawl (client
    side; `verify_live` too when the window aborted anything); on a loss reveals stop on
    the route and `_readopt_session` re-adopts the session's cookies, its browser
    login's cookies and the localStorage entries **as adopted** (kept in
    `_adopted_original`), then reloads; a second loss, or a re-adoption that does not
    hold (which also sets `spa_submit_stopped`), sets `reveals_stopped`.
  - **G2a-G2e:** `spa.REVEAL_JS` (announcers, sidenav toggles, interactive cards with no
    interactive descendant; never links, select-likes, disabled elements or elements in
    a form unless `type=button`), `CARD_LABELS_JS`, `MENU_ITEMS_JS`;
    `LocalSpider._reveal_page` / `_reveal_one` / `_reveal_click` (announcers through
    `click_vetted`, cards by `el.click()` after their labels are re-read) /
    `_revealed` / `_queue_revealed` (source `reveal`) / `_record_revealed_forms` (spider
    table `revealed_forms`; real `<form>`s through `form_record`) /
    `_submit_revealed` (named routes only, never a password form). Revealed menu items
    passing the gate are clicked inside the window, each after a reload and a re-click
    (G2b); the close is Escape then the reload, never a dialog's own button (G2c). The
    label gate (G2d): `spa.label_refusal` (destructive with inflections folded,
    settings, transaction, account words), `spa.reveal_refusal` (plus any destructive
    glyph, no label); `exit_to_app` added to `DESTRUCTIVE_GLYPHS`, judged text-first on
    a form's submitter (`spa.submitter_glyph`, `TEXT_FIRST_GLYPHS`) so Juice Shop's
    login stays submittable. Caps as constants: `MAX_REVEAL_CANDIDATES` 40,
    `MAX_REVEALS_PER_PAGE` 6, `MAX_REVEALS` 60, `MAX_CARDS_PER_SIGNATURE` 3,
    `MAX_MENU_ITEMS` 4, `MAX_CARD_TEXT` 1000. On by default in the Playwright engine
    (`--no-reveal`, `LocalSpider(reveal=)`); only on a page the browser rendered
    (`_rendered_ok`). Scripts a reveal loads are scanned for routes.
  - **Counts** (`spa_counts`, `crawl_stats`): `reveals_clicked`, `reveals_refused`,
    `reveals_over_cap`, `reveal_writes_blocked`, `reveal_ws_dropped`,
    `reveal_navigations_captured`, `revealed_links`, `revealed_forms`,
    `session_losses_after_reveal`, `reveals_stopped`; summary lines.
  - **BUG-0131 (found here):** `formnav.option_refusal` judges option texts with
    `core.urls.text_destructive_reason`; `spa.form_refusal`'s labels and control names
    and `spa.route_destructive_reason`'s fragment likewise.
  - **Fixture/test changes:** `tests/_spa_fixture.py` (a minimal WebSocket endpoint and
    extra server-rendered pages on the loopback lab; `RevealSpa`, `G1Spa`,
    `SessionRevealSpa`); `tests/test_spa_routes.py` (the stored-stats contract has
    `reveals_stopped`); `tests/test_session_browser_login.py` (the synthetic glyph-only
    `exit_to_app` login case is now refused, per G2d -- `FORMS_JS` never yields that
    shape: an icon-only button with no aria-label keeps its raw text, already refused on
    `exit`).
- Impact (other components / project): SESS -- `login_form_refusal` calls
  `spa.form_refusal`, so a glyph-only `exit_to_app` submitter is refused (unreachable
  from a real page, see above); the browser login is otherwise unchanged (its window,
  guard and `click_vetted` call without `before_click`). AUD/FUZZ -- `navguard`'s new
  parameters are optional; the auditor's and M6's guards are unchanged. The importer
  reads `discovered_pages.source = 'reveal'` as any source; `revealed_forms` is not
  imported. CORE -- uses `text_destructive_reason` (CC-CORE-0052). Default-on behaviour
  change: every Playwright crawl now opens menus, dialogs and cards (read-only through
  the window; `--no-reveal` restores the old crawl).
- Risk (level; mitigation): medium -- a new automatic click path on every rendered page.
  Mitigated by the window (all writes, navigations and side-effect GETs aborted,
  WebSocket messages dropped, the close inside it, the lift after a quiet period),
  the label gate, the card rules, caps, W4's session check, and real-browser tests for
  each; each mechanism mutation-checked. Accepted residuals (FR-CRAWL-16): an opaque
  side-effect GET; a request whose route callback the driver dispatches in the instant
  after the lift (narrowed by the flush); cards clickable only through an
  `addEventListener` handler without a pointer cursor are not seen.
- Deliverables:
  - [x] code: `tools/spider.py`, `tools/spa.py`, `tools/navguard.py`,
    `tools/formnav.py` — done
  - [x] tests: `tests/test_forms_phase4.py` (window unit tests: GET rules, route hook,
    redirect hop, WS forwarder; the reveal gate; Juice Shop login with `exit_to_app`;
    BUG-0131 and its AST guard with synthetic offenders; real browser: W2 POST and
    side-effect GETs, W2 navigation captured and `/profile` requested once, W3 WS
    message dropped, W1 debounced POST after close, G2b menu items, G2a cards (cap,
    descendants, gate, dialog Close never clicked), G2e dialog form and menu link,
    counts persisted, named-route revealed submission, crawl cap, `--no-reveal`, W4
    re-adopt then stop) — done
  - [x] mutation checks (each reverted, its test failed for the expected assertion):
    W1 (close and quiet period removed: `/api/after-close` arrived), W2 writes (POST
    arrived), W2 navigations (`/profile` requested twice), W3 (`reveal-msg` arrived),
    W4 (`opened-late` requested), G2a(c) (`card-bad` requested), G2b (the gated items
    clicked) — done
  - [x] FR-CRAWL-16, FR-CRAWL-13 (CAPTCHA, texts), NFR-CRAWL-safe traced, §5 contract,
    ARCHITECTURE #2/#4 — done
- Code review round 1 (reviewer A AGREE; reviewer B AGREE-with-changes; a follow-up
  commit):
  - **B-M1 (must):** the lift outlived its one click. `before_click` set
    `win["lifted_for"]` and only the window's exit cleared it, so after a click that
    raised, the next revealed form's fills and G1 interactions and the menu-item clicks
    ran unblocked. Now `_fill_and_click_now`'s `finally` clears the lift (it covers one
    click and its settle), and `_submit_revealed` stops after the first click
    **attempt** (`_click_attempted`, set by the lift), a raising one included.
  - **A-S1:** a failed close also closes every page the window opened
    (`_close_window_pages`) before `about:blank` and the lift.
  - **A-S2:** the own-reload exemption compares the exact navigation URL (`_nav_key`:
    canonical origin, path, query) instead of `url_key`; `navguard` asks the window
    about a navigation's redirect hop as a navigation.
  - **A-S3:** in the window a GET is refused for explicit account-action tokens
    (`ACCOUNT_PATH_TOKENS`, `sign up`) and credential tokens only, no longer for the
    users / accounts collection rule or the broader account words, so the app's
    identity check (`/rest/user/whoami`) passes. The clean reload stays.
  - **A-N1:** `_readopt_session` also requires `verify_live`.
  - **A-N2 / B nit:** FR-CRAWL-16 states that reveals run in authenticated crawls (the
    window plus W4 as the safety basis) and records the split-WebSocket-frame residual.
  - Tests (`tests/test_forms_phase4.py`): `test_the_lift_covers_exactly_one_click_and_its_settle`
    (raise and success), `test_a_click_that_raises_never_leaves_the_window_open`
    (a two-form dialog; the first button is detached right after the lift through
    `before_click`, because a page event fires already in the trial click),
    `test_a_failed_close_still_closes_the_windows_popups`,
    `test_the_own_reload_exemption_matches_the_exact_url`,
    `test_a_redirect_after_the_own_reload_is_still_a_navigation`, whoami / users
    collection pass in `test_the_window_lets_only_safe_gets_through`, and
    `verify_live` after the re-adoption in the W4 test.
  - Mutation checks (each killed for the expected assertion): the lift not cleared
    (the fake page's lift outlived the click), no stop after a click attempt
    (`/api/second` arrived), popups not closed on a failed close (`/api/popup-post`
    arrived), own reload by `url_key` (`?action=x` let through), hops not navigations
    (the hop was fetched), the collection rule back (whoami refused).
  - Item 7: `tests/test_forms_phase4.py` had 116 tests at 61ddb4d (none skipped or
    deselected); the "119" reported was a combined run with
    `tests/test_requirements_traceability.py` (3 tests).
- Effectiveness (assessed 2026-10-14): offline only. Real-browser fixtures reproduce
  Juice Shop's patterns (a script-navigating account-menu item, product cards with a
  review dialog, an icon-only client-side logout); every safety clause has a failing
  mutation. Not verified against the live Juice Shop (no traffic to a running lab in
  this lane): `/profile` discovery and the product-review dialog on the real app remain
  to be confirmed on-host. pending (live).

### CC-CRAWL-0023 — Constraint-aware SPA form filling on named routes (FR-CRAWL-15, forms phase 4, G1) (2026-10-14)
- Change:
  - **`LocalSpider._fill_and_click`** splits into the window wrapper and
    `_fill_and_click_now`: on a named route (`explicit`) the fill, G1 and the checks
    run inside the reveal window (CC-CRAWL-0024) and the vetted click lifts it
    (`before_click=_lift_for(context)`); an unnamed route fills as before.
  - **`LocalSpider._g1`** (with `_g1_ladder`, `_g1_native_select`,
    `_g1_custom_select`, `_g1_radio`, `_g1_invalid_names`): reads `spa.G1_READ_JS`,
    and for each invalid control tries `spa.g1_candidates` (a pattern's candidates
    first filtered by `spa.PATTERN_TEST_JS`: the page's own RegExp in a worker
    terminated after `G1_PATTERN_TIMEOUT_MS` 500), at most `G1_MAX_ATTEMPTS` 6; selects
    by `select_option`, mat-selects by opening click and option click
    (`G1_OPTIONS_JS`), radios and checkboxes by their own `click()`, ranges by
    `G1_SET_JS`; refusals `g1_sensitive` (G1b), `select_refusal` (G1c),
    `checkbox_refusal` (G1d); still disabled → "invalid after N attempts: <names>".
    A per-control log line says which control was made valid.
  - **`spa.captcha_reason`** (G1e) runs beside `form_refusal` for every SPA submission;
    `FORMS_JS` now reports `hints` (container attribute values and label texts),
    `challenge` (a canvas), `tags`, and custom selects (mat-select, `role=combobox`)
    as kind `select`.
  - **The ladder is ours** (B7): `store_adapter.is_ladder_value` / `ladder_digits`
    (CC-AUD-0039); `is_filler` recognises every ladder value; none is identifier-like.
  - **The submission loop** finds each later form again by its signature after an
    earlier one (or G1's reload) re-rendered the page (`_refind_form`).
- Impact: AUD (`is_filler` widened, CC-AUD-0039; the fuzzer's `_send_value` and the
  shape fallback treat ladder values as fillers), CORE (`is_sensitive_name` names card
  security codes, CC-CORE-0052). Named-route submissions now reload the route after the
  click (inside the window), so a debounced write the app schedules after a submission
  is not sent.
- Risk: medium -- G1 interacts with more controls (selects, checkboxes, radios) on
  routes the operator named. Mitigated: inside the window (nothing is written before
  the vetted click), object selectors / identifier options / gated labels / sensitive
  controls / CAPTCHAs refused, only filler values. Stated gaps: async validators;
  grids and patterns without a ladder value; a select named with a settings word
  (`country`) is still refused by FR-CRAWL-13's control-name rule before G1.
- Deliverables:
  - [x] code: `tools/spider.py`, `tools/spa.py` — done
  - [x] tests (`tests/test_forms_phase4.py`): the ladder's constraints, quantifier
    lengths, a grid without a ladder value, every ladder value a filler and not
    identifier-like, `select_refusal`, `checkbox_refusal`, `g1_sensitive`, CAPTCHA
    rule, caps; real browser: the Angular-like form (number range, pattern, select,
    slider, checkbox, mat-select) submitted once with ladder values, no autosave before
    the submission, an unsatisfiable pattern reported with the reason, a CAPTCHA form
    refused, a saved-card mat-select never chosen in, a delete-account checkbox never
    checked — done
  - [x] mutation checks: G1c (identifier options: the card form was submitted), G1d
    (checkbox gate: the delete-account form was submitted) — done
  - [x] FR-CRAWL-15 — done
- Code review round 1 (reviewer B-M1, in CC-CRAWL-0024's follow-up commit): the G1
  window's lift now covers the vetted click and its settle only and is cleared in
  `_fill_and_click_now`'s `finally`, a click that raised included
  (`tests/test_forms_phase4.py::test_the_lift_covers_exactly_one_click_and_its_settle`,
  mutation-checked).
- Effectiveness (assessed 2026-10-14): offline fixture forms with Juice Shop's patterns
  are submitted or refused as specified; the live address/contact/recycle forms are not
  verified here (no lab traffic in this lane; contact is a CAPTCHA form and is now
  refused by design). pending (live).

### CC-CRAWL-0022 — The crawl adopts a browser session; session headers through the route only (FR-CRAWL-14) (2026-10-14)
- Change:
  - **`tools/spider.py` `_start_browser`:** the session is ensured **before** the crawl
    context opens (`browserauth.browser_session`), so a browser login (CC-SESS-0021) has
    already closed its own context; the context is created with its `storage_state`
    filtered to in-scope origins (`browserlogin.filter_storage_state`, reviewer A7) and
    gets the session's cookies (`add_cookies`).
  - **Headers (reviewers A6/B7).** `_guard(context, session=True)` hands the session's
    headers to `navguard.guard_page(headers=, header_scope=)`: the route adds them with
    `route.fetch(headers=)` (the request's own headers merged, case-insensitively) only
    after `in_scope` passes and `header_scope` (`browserauth.header_scope_for`: the
    session's host, its transport floor) admits the URL, and to each fetched redirect
    hop only when that hop does. Verified live first that `route.fetch(headers=)`
    replaces the whole header set, hence the merge. An unauthenticated submission
    context gets none. `_isolated_submit`'s API client sends them only when the action
    passes `header_scope`.
  - **`browserauth`:** `apply_to_context` adds cookies only and refuses headers
    (`ValueError`); new `browser_session`, `BrowserSession`, `header_scope_for`.
    `set_extra_http_headers` is gone from `fuzzlab/` (PA-0002 sweep, below).
  - **Session check (reviewer B4).** `_session_intact` also compares each adopted
    localStorage entry with `page.evaluate` on an open page of its origin (fail closed);
    `verify_live` now checks a browser login's protected probe.
  - **`navguard.make_route_handler` / `guard_page`:** new `headers`, `header_scope`,
    `request_refusal` (the login window's pre-send hook, CC-SESS-0021); a
    request-refusal log names the host only.
  - **`spa.click_vetted` / `spa.covered`:** `LocalSpider._click_vetted` now delegates to
    the one implementation it shares with the browser login (PA-0003).
  - **Sweep (PA-0002), every session-header path into a browser:**
    `browserauth.apply_to_context` (crawler, auditor: moved onto the route);
    `browserexec` storage headers (moved, CC-FUZZ-0076); `fetcher._start_browser`
    (moved, CC-AUD-0038); `spider._isolated_submit`'s `pw.request.new_context(
    extra_http_headers=)` (kept: one `checked_api_request`-checked request with
    `max_redirects=0`; now also gated by `header_scope`). Enforced by
    `tests/test_browser_scope.py::test_no_browser_context_gets_session_headers_outside_the_route`
    (AST, proven on synthetic offenders).
- Impact: SESS (adopts `browser_state`, `verify_live`), AUD and FUZZ (same header
  mechanism). Cookie sessions from server-rendered logins behave as before. A bearer is
  no longer sent to an out-of-scope or other-host request even if a guard let one
  through.
- Risk: low-medium. The header path moved from Chromium to the route; covered by the
  route unit tests, the existing real-browser SPA tests (bearer seen on the crawl's
  submissions, never on the unauthenticated context's) and the new authenticated-crawl
  test.
- Deliverables:
  - [x] code (`tools/spider.py`, `tools/navguard.py`, `tools/browserauth.py`,
    `tools/spa.py`) — done
  - [x] tests: `tests/test_browser_scope.py` (route headers, hop headers, request
    refusal, header AST guard + offenders), `tests/test_browserauth.py` (headers refused
    on the context; header scope; https-only), `tests/test_session_browser_login.py`
    (authenticated crawl sees the protected route; localStorage loss stops submitting;
    revoked token stops submitting; re-login during a crawl; storage filtering) — done
  - [x] mutation checks: localStorage check, header scope, `set_extra_http_headers`
    reintroduced — each failed its tests — done
  - [x] FR-CRAWL-14, NFR-CRAWL-safe traced, ARCHITECTURE #4 — done
- Code review round 1 (reviewer B-S3; a follow-up commit): `_session_intact` tells a
  token rotation from a loss (`_storage_rotated`): an adopted localStorage entry changed
  to another non-empty, identifier-like value (`core.redaction.looks_like_identifier`) is
  re-adopted and `verify_live` still decides; cleared, empty, `"null"`, `"undefined"` or
  a non-identifier value is a loss. Tests: an app that rotates its token every 300 ms
  keeps submitting (and the new value is re-adopted); a clear still stops it with
  rotation on; a predicate table. Mutation checks: no rotation ever
  (`test_a_rotated_token_keeps_the_crawl_submitting` failed); any change a rotation
  (`test_a_cleared_token_still_stops_the_crawl_with_rotation_on` failed).
- Review: with CC-SESS-0021 (reviewers A and B, Revision 2 items 6, 7 and 4).
- Effectiveness (assessed 2026-10-14): verified offline against loopback fixtures, real Chromium (`FUZZLAB_REQUIRE_BROWSER=1`, `FUZZLAB_REQUIRE_LINT=1`): the targeted run (every touched test file, the session-manager tests, the browser-scope, SPA, sub-path, destructive-URL, lint, traceability and loopback-listener guards) gave 739 passed, 2 xfailed, 0 skipped, 1 failed -- `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`, which fails identically on the unmodified base 2150bf8 (`labgen/conformance/*_live_boot.py` `start_server` sites, outside this change; flagged, not fixed here). The authenticated-crawl, localStorage, revocation and re-login tests passed; the header-scope and `set_extra_http_headers` mutations failed their tests. Live Juice Shop crawl not run here.

### CC-CRAWL-0021 — `release` closes pages until none remain (reviewer B, BUG-0128 follow-up) (2026-10-14)
- Change: `navguard.release` repeats its page-closing pass, at most 3 passes, while the
  context still has pages, and only then unroutes. A popup opened by one page while
  another was closing was missed by the single snapshot and would have been unrouted
  for the moment before its context closed: still held in scope by Chromium's resolver
  rules, but not by the destructive and DELETE checks.
- Impact: FR-CRAWL-11 text unchanged in substance ("closes the context's pages").
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting`
    (a popup on the second pass; a context that never empties stops after 3 passes) —
    done
- Review: reviewer B, round 2 nit.
- Effectiveness (assessed 2026-10-14): verified offline.

### CC-CRAWL-0020 — Browser teardown closes pages before unrouting (BUG-0128) (2026-10-14)
- Change: `tools/navguard.release(context)` closes every page of the context first
  (each failure ignored), then calls `unroute_all(behavior="ignoreErrors")`. Before,
  it unrouted while pages could still be navigating, and the driver sometimes never
  answered (the sync call hung). All browser teardowns use `release`: the spider (crawl
  and anonymous submission contexts), the fetcher and the M6 executor.
- Impact: FR-CRAWL-11 amended in place. No behaviour change besides teardown order.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting`
    (the reverted order fails); `::test_a_hit_before_the_page_navigates_is_kept` (the
    real-browser reproduction) — done
  - [x] BUG-0128, PA-0128, ERROR_LOG — done
- Review: with the forms phase 3 review-round commit, reviewers A and B.
- Effectiveness (assessed 2026-10-14): 80 runs with no hang (was 1 in 9).

### CC-CRAWL-0019 — Forms phase 3 review: button labels and the vetted click (reviewer B) (2026-10-14)
- Change:
  - `tools/spa.py`: the button labels the gate judges come from one JS function
    (`_LABELS_FN`) used by `FORMS_JS` and by the new `LABELS_JS`. It removes only
    icon-**ligature** elements (`mat-icon`, `.material-icons`, `material-symbols`):
    `aria-hidden`, `[class*="fa-"]` and `svg` are no longer stripped. **Must-fix:**
    `<button aria-label="Item 3"><span aria-hidden="true">Delete</span></button>`
    passed the gate as `""` / `"Item 3"`. Ligature names are returned as
    `button_icons`, and `form_refusal` refuses a button whose icon is in
    `DESTRUCTIVE_GLYPHS` (`delete`, `logout`, …) whatever its text says.
  - `tools/spider.py` `_click_vetted(page, selector, vetted)`: dispatch only when the
    trial click failed because the button is **covered** ("intercepts pointer
    events"); a hidden, detached or never-actionable button raises (not submittable).
    Right before the real or dispatched click the labels are read again
    (`spa.LABELS_JS`) and must equal the vetted ones, else nothing is clicked
    (`forms_label_changed`, a new crawl count).
- Impact: FR-CRAWL-13 amended in place. Lane S's live-run fixes (70c2aca, cb59111)
  were unpushed, so no shipped crawl is affected. Juice Shop's login
  (`<mat-icon>exit_to_app</mat-icon> Log in`) is still submitted.
- Risk: low (refuses more, never less).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_spa_capture.py::test_icon_text_never_decides_a_button_label`
    (adds aria-hidden "Delete" twice, a `delete` glyph with neutral text, and an
    invisible button), `::test_a_covered_button_is_still_clicked_exactly_once` (adds a
    node re-rendered on Escape), `::test_a_destructive_glyph_refuses_the_button_whatever_its_text`
    — done
  - [x] mutation check: 4 of 4 killed (aria-hidden stripped again, glyph check off,
    label re-check off, dispatch when not covered) — done
- Review: reviewer B's must-fix 1 and should-fix 2; to be confirmed by A and B.
- Effectiveness (assessed 2026-10-14): verified offline on real Chromium.

### CC-CRAWL-0018 — One Chromium launch configuration (BUG-0126) (2026-10-14)
- Change:
  - `tools/navguard.py`: `chromium_launch_kwargs(args, *, headless=True)`, the one
    launch configuration (headless, the scoped `browser_launch_args`, and
    `executable_path` from `PLAYWRIGHT_CHROMIUM_EXECUTABLE` when set).
  - `tools/spider.py` `_start_browser` uses it (its own copy removed, and the now
    unused `os` import).
  - `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped` also
    requires `chromium_launch_kwargs` at every `chromium.launch`, proven on its
    synthetic offender.
- Impact: FR-CRAWL-11 amended in place (the launch configuration is shared). The
  auditor (CC-AUD-0037) and the M6 executor (CC-FUZZ-0071) use the same helper.
  Behaviour of the crawl unchanged.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (AST guard, real-browser crawl tests unchanged and passing) — done
- Review: with the forms phase 3 integration, reviewers A and B.
- Effectiveness (assessed 2026-10-14): the guard fails on a launch without the helper;
  the live crawl and fuzz runs launch the operator's binary.

### CC-CRAWL-0017 — Request capture and SPA form submission (forms phase 3, lane S: I) (2026-10-14)
- Change:
  - `tools/spider.py`:
    - `StorageManager`: the spider table `discovered_requests (id, page_url, method, url,
      content_type, body_json TEXT, source TEXT, signature TEXT UNIQUE)`, cleared on
      reset; `record_request(...)` is its one write site and redacts there through
      `core.redaction` only (`redact_captured_body`, `redact_url_identifiers`,
      CC-CORE-0047). Only the media type of the request's own Content-Type is read; no
      header and no cookie is stored. `signature` = `[method, url_key(url), sorted keys]`.
    - Passive capture (default on, Playwright engine): the guard's `observe` hook hands
      each sent fetch/XHR request with a body (not GET/HEAD/OPTIONS) to `_observe`;
      socket.io / engine.io requests are excluded (counted).
    - `--submit-spa-forms [ROUTE …]` (default off; values also split on commas and
      spaces, for the web form): `_submit_spa_forms` reads the rendered page's forms
      and form-like containers (`spa.FORMS_JS`), gates each with `spa.form_refusal`,
      fills (`store_adapter` fillers; `spa.PASSWORD_FILLER`) and clicks once per
      `spa.form_signature`, at most `spa.MAX_SUBMISSIONS` (50) per crawl.
      `_submit_anonymously` submits password forms (and, in an authenticated crawl,
      every form whose route was not named) in a fresh context of the same browser,
      guarded the same way, closed afterwards. `_session_intact` re-checks the crawl's
      session after each authenticated submission (injected cookies unchanged, then
      `verify_live`; unverifiable = lost); on loss submitting stops and
      `spa_submit_stopped` is reported. A settle loop (`_track` / `_settle`) waits for
      the page's own requests after a click or a hash change.
  - `tools/spa.py` (new): `form_refusal` (the one gate: unnamed route, destructive /
    settings / transaction route, label, action or control, file input,
    credential-change via `store_adapter.credential_change_reason`, 2FA-only),
    `fillable` / `filler`, `form_signature`, `FORMS_JS`.
  - `tools/navguard.py`: `observe(request, response)` on `make_route_handler` /
    `guard_page`, called after a request was sent and before it is answered,
    contained (a failing observer is logged, never changes the answer).
- Impact (other components / project): FR-CRAWL-13 (new); NFR-CRAWL-safe gains the
  submission clauses, traced. The spider DB gains a table (the spider's own schema; no
  store migration); lane J's importer reads it (an absent table = none). `navguard`'s
  new hooks are optional; the auditor's fetcher and the M6 executor are unchanged.
  The PA-0100 producer guard (`tests/test_storage_redaction.py`) now covers
  `discovered_requests` and requires both capture redactors; `tools/spa.py` joins the
  PA-0122 guard's module scope.
- Risk (level; mitigation or accepted-risk justification): medium. Submissions change
  lab state (a feedback row, a failed login, a registration attempt with filler data):
  default off, lab only, refusals and caps as above, mutation-checked. A password
  filler is a constant that is never a real credential. Accepted gaps: file-upload
  forms are never submitted; a form whose button stays disabled after filling (e.g. a
  required slider or CAPTCHA) is counted "not submittable"; Angular forms without
  `name` attributes are described by `id` / `formcontrolname` / label.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_spa_capture.py` (redaction boundary, table contract, write
    site, passive filters, every refusal and every transaction word, fillers, session
    check, CLI; real browser: capture on by default and redacted, submission off by
    default, bare submission in an anonymous crawl incl. both contexts' scope, the fake
    SPA whose failed login clears the token, a named login route still anonymous, an
    authenticated bare flag never using the crawl's context, session loss stopping
    submission, the cap); `tests/test_storage_redaction.py` (capture producers and
    their synthetic offenders); `tests/test_logout_redirect.py` (scope) — done
  - [x] FR-CRAWL-13; NFR-CRAWL-safe `Enforced by`; requirements §5 contract — done
- Review: design agreed by reviewers A and B (p3 draft revisions 1–4); code review
  pending.
- Effectiveness (assessed 2026-10-14): verified offline with a real Chromium against a
  loopback fake SPA; mutation check of lane S's safety gates: 36 of 36 mutants killed
  (one survivor on the first pass, a password form routed into the crawl's context on
  a named route, now killed by
  `test_a_named_login_route_is_still_submitted_only_unauthenticated`). The live Juice
  Shop re-crawl (`--submit-spa-forms login search contact`) is pending (D11: not run
  here).
- Code-review fixes (2026-10-14; reviewers A and B AGREE subject to these; a new
  commit on top of the first):
  - *Must-fix 1:* the capture boundary no longer depends on the body's encoding
    (identifier-like numbers and keys; CC-CORE-0047).
  - *Should-fix 2 (decided under the operator's standing instruction):* security
    answers are secrets (CC-CORE-0047); the registration body's `securityAnswer` is now
    blanked when captured.
  - *Should-fix 4 (decided under the standing instruction): the DELETE window is the
    clicking context's.* `_delete_ok` (crawl-wide) became `_delete_ok_for`, the one
    context whose named-route click is in progress; each context's guard passes its
    own context to `_method_refusal`, so the crawl context's background DELETEs during
    an unauthenticated context's click are refused. Found while testing it: within the
    clicking context the window (click plus settle, up to 5 s while the page keeps
    polling) let a background poller through as often as it polled, so the allowance
    is now **single use** -- one DELETE per named-route click. Stated residual: that
    one DELETE may be the clicking context's background request rather than the
    click's own. Tests: `_method_refusal` with two contexts and the single use; a real
    browser crawl where the crawl context polls with DELETE every 50 ms while the
    unauthenticated context clicks the named login route: the server receives none.
  - *Should-fix 5 (decided under the standing instruction): the counts are stored.*
    `StorageManager` gains `crawl_stats (name TEXT PRIMARY KEY, value INTEGER)`,
    cleared on reset; `record_stats` upserts `spa_counts` plus `submit_stopped` (0/1)
    at the end of every crawl. The log line stays. Tests: upsert and reset; the stored
    counts equal `spa_counts` after a real crawl.
  - FR-CRAWL-13 and NFR-CRAWL-safe updated in place.
  - Effectiveness of the fixes (assessed 2026-10-14): the mutation check re-run over
    every lane S gate, including the ten new ones (identifier-like numbers, JSON keys,
    form names, security-answer pairs, transport and `//` routes, non-routes not
    counted, the DELETE window's context and single use, stored counts): 46 of 46
    mutants killed. Click and fill timeouts now follow the crawl's per-page timeout
    (the fixed 2–3 s timed out on a loaded host).
- Live-run fix (2026-10-14; from the orchestrator's interim live Juice Shop crawl with
  4476e93: 72 pages, 40 SPA routes, 8 forms, the github open redirect blocked,
  `crawl_stats` stored, but **0 forms submitted**):
  - Defect (a false refusal): `#/login` was refused as `destructive button ('exit')`.
    Juice Shop's login button is `<button aria-label="Login"><mat-icon>exit_to_app
    </mat-icon> Log in</button>`; `FORMS_JS` read the icon's ligature text as part of
    the label, and `exit` is a destructive token.
  - Fix (`tools/spa.py`): the label judged is the button's text with icon elements'
    text removed (`mat-icon`, `.material-icons`, `material-symbols`,
    `[aria-hidden="true"]`, `i.fa`, `[class*="fa-"]`, `svg`), and its `aria-label` /
    `title` is judged too (`button_aria`); the button is refused when **either** is
    destructive, settings-like or a transaction, so a real "Log out" is refused
    whatever its icon. The submission signature uses the cleaned label. Addition
    (fail closed, not in the request): an icon-only button with no aria-label or title
    keeps its raw text, so `<button><mat-icon>delete</mat-icon></button>` is still
    refused. The aria-label also joins the credential-change submitter check.
  - Tests: `test_the_button_is_refused_on_its_text_or_its_aria_label`; a real-browser
    crawl of a new icon fixture (`IconSpa`): Juice Shop's login button and a Font
    Awesome "Search" button are submitted; `aria-label="Log out"` with an
    `exit_to_app` icon, `aria-label="Sign out"` with a neutral icon, a
    `material-icons` "delete" + "Remove" button and an icon-only "delete" button are
    refused; no signature carries `exit_to_app`. Mutation check on the label cleaning:
    4 of 4 killed (icon text kept, aria-label not judged, aria-label never read, no
    raw-text fallback).
  - Not a defect (stated gap, unchanged): `#/contact` stays "not submittable" -- its
    button is disabled until the math CAPTCHA and the rating are valid.
- Live-run fix 2 (2026-10-14; from the orchestrator's live re-crawl with 70c2aca: the
  login button now passed the gate, but `SPA form on …/#/login could not be clicked
  (Page.click: Timeout 15000ms exceeded.)`; 0 submitted, 12 refused, 2 not submittable):
  - Cause, confirmed on a loopback fixture (no lab traffic): a password form is
    submitted in a fresh unauthenticated context, where the app shows its first-visit
    overlays (Juice Shop's welcome `mat-dialog`, the cookie bar); Playwright's
    actionability wait times out because the overlay "intercepts pointer events". A
    plain click on the fixture fails the same way and sends nothing, so a timed-out
    click never clicked (no double submission).
  - Fix (`LocalSpider._click_vetted`, used for every SPA submission): a trial click
    (actionability only, nothing clicked; at most 5 s) first; if the button is covered,
    `Escape` is pressed once and the trial repeated; if it is still covered, the vetted
    button's own `click()` is run on the element. Exactly one real or dispatched click,
    always after the gate (`spa.form_refusal`) passed. An overlay's own buttons are
    never clicked (their labels are unvetted). `clicks_dispatched` is counted, stored
    in `crawl_stats` and in the summary line.
  - Tests: `test_a_covered_button_is_still_clicked_exactly_once` (fixture `OverlaySpa`:
    a login view under a modal that closes on Escape, one whose modal ignores Escape
    (the dispatch path), and a "Delete account" button under a modal): the server sees
    exactly one POST for each of the two logins, none for the destructive form and none
    from the overlay's "Dismiss" button; `clicks_dispatched` is 1, in memory and in
    `crawl_stats`. Mutation check on the fallback: 4 of 4 killed (no Escape, no
    dispatch, no actionability trial, a double dispatch).

### CC-CRAWL-0016 — SPA routes, canonical page keys, transport noise, the DELETE rule (forms phase 3, lane S: R) (2026-10-14)
- Change:
  - `tools/spa.py` (new): `scan_routes` (linear `str.find` scan with bounded
    look-around; Angular, Vue and React declarations; `MAX_SCRIPT_BYTES` 4 MiB,
    `MAX_ROUTES_PER_SCRIPT`), `classify_route` (parameterised / wildcard / destructive /
    root / invalid), `route_url` (hash, hashbang, history under a base), `spa_fragment`,
    `crawl_url`, `visit_key` (canonical origin + path + query + SPA fragment),
    `route_destructive_reason` (the URL and its SPA fragment), `route_of`,
    `is_transport_url`, `MAX_SCRIPTS_PER_PAGE` (32).
  - `tools/spider.py`:
    - `StorageManager.is_visited` / `mark_visited` key on `spa.visit_key` (an in-memory
      key set, rebuilt from the table on open for `--resume`), so loopback aliases are
      one site and hash routes distinct pages. Stored URLs keep the spelling first seen.
    - Routes (default on in the Playwright engine; `--no-spa-routes`): `_note_script`
      scans same-origin scripts the guard already fetched (`observe`), cross-origin ones
      never read, size and per-page caps, each script once; `_queue_routes` builds hash
      or history URLs and queues them as `spa-route` pages; counts in `spa_counts`,
      reported by `spa_summary()` at the end of the crawl (PA-0110: "visited" counts a
      route page actually rendered).
    - Links keep a SPA fragment (its query through `core.redaction.redact_spa_fragment`);
      `_destructive` also checks the fragment. A same-document hash navigation keeps the
      document's status and waits for the app's own requests.
    - XHR URLs (`_queue_xhr`): socket.io / engine.io transport URLs dropped (counted);
      sensitive and identifier-like query values redacted (`redact_url_identifiers`).
    - `_method_refusal`: every browser-initiated DELETE is aborted (counted) unless a
      submission on an operator-named route sends it (`_delete_ok`).
    - `_guard(context)`: the one guard call for every context the crawl opens (scope,
      destructive rule, DELETE rule, observer).
  - `tools/navguard.py`: `method_refusal(method, url)` on `make_route_handler` /
    `guard_page`: a reason aborts the first request before any fetch, whatever `allow`
    says; `on_abort` is told.
- Impact (other components / project): FR-CRAWL-12 (new); NFR-CRAWL-safe gains the
  DELETE and SPA-route clauses, traced. `discovered_pages.source` gains `spa-route`; a
  route page's URL keeps `#/…` (the importer's `to_path` maps it to its path, as
  before; lane J reads the fragment). The static engine is unchanged except for alias
  dedupe. Juice Shop's hash routes become pages, so its forms are rendered and recorded.
- Risk (level; mitigation or accepted-risk justification): medium. More pages per
  crawl (one per route) and one settle wait (≤ 5 s, usually 300 ms) per hash change.
  Stated residuals: a route load can trigger the app's own non-DELETE writes (the guard
  aborts only DELETE and destructive-token URLs); nested routes are not joined to their
  parent's path; a history-mode false positive (an object with a `path` key that is
  not a route) costs one in-scope, destructive-checked GET.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_spa_routes.py` (declarations, near-misses, linear time on
    5 MB adversarial bodies incl. an unterminated `{path:'` repeated plus a growth-ratio
    check, the size cap, the route cap, classification, route URLs never leaving the
    origin, fragment destructiveness, visit keys and alias dedupe incl. resume,
    transports, XHR identifiers, the guard's method rule before any fetch, observer
    containment, the spider's DELETE rule, cross-origin / oversized / per-page script
    caps; real browser: hash routes crawled with destructive and parameterised ones
    never rendered, summary counts, `--no-spa-routes`, loopback alias start, socket.io
    pages and identifiers, a route-load DELETE aborted, a DELETE sent only from a named
    route's submission, history mode) — done
  - [x] FR-CRAWL-12; NFR-CRAWL-safe `Enforced by` — done
- Review: design agreed by reviewers A and B (p3 draft revisions 1–4); code review
  pending.
- Effectiveness (assessed 2026-10-14): verified offline with a real Chromium against
  loopback hash- and history-mode fake SPAs; mutation check: every route, DELETE,
  script-cap and XHR mutant killed (see CC-CRAWL-0017 for the total). The live Juice
  Shop re-crawl is pending (D11: not run here).
- Code-review fixes (2026-10-14; reviewers A and B AGREE subject to these; a new
  commit on top of the first):
  - *Should-fix 3 (decided under the operator's standing instruction): transport paths
    are not routes.* `spa.classify_route` returns `ROUTE_TRANSPORT` for a route whose
    path `is_transport_url` recognises (socket.io's own `{path:'/socket.io'}` client
    option, `/engine.io`) and `ROUTE_INVALID` for a value starting with `//` (before
    normalising, which used to strip it to a same-origin path); `spa.NOT_ROUTES`
    (root, invalid, transport) are skipped **before** counting, so `routes_found`
    counts routes only. Tests: classification cases; the fake SPA's bundle now carries
    both values and the real crawl still finds exactly its 14 routes and visits
    neither.
  - *Should-fix 5:* the route counts are stored in `crawl_stats` (see CC-CRAWL-0017).
  - FR-CRAWL-12 updated in place.

### CC-CRAWL-0015 — The crawler's browser is confined to the crawl scope; a loopback crawl to its origin (BUG-0123) (2026-10-14)
- Change:
  - `tools/navguard.py` (shared with the auditor and M6, owned here):
    - `guard_page(target, allow, on_abort, *, in_scope, on_out_of_scope)`: `in_scope` is
      required. It routes the context (popups included) and WebSockets
      (`make_ws_handler`: an out-of-scope socket is never connected; `ws.close()` in a
      sync handler deadlocks, seen live).
    - `make_route_handler(..., in_scope, on_out_of_scope, api)`: scope first, then the
      destructive rule (`allow` lifts only the latter). An allowed request is fetched
      with `route.fetch(max_redirects=0)`; a redirect chain is walked through `api`
      (the context's request client), each hop checked, at most `MAX_REDIRECTS`, with
      301/302/303 turning a POST into a GET and 307/308 keeping it. A redirected
      GET/HEAD navigation is fulfilled with one redirect to the checked landing URL
      (`page.url` and relative links stay right; the landing page is requested twice);
      a body-keeping chain and any other request with the landing response itself, so
      no body is sent twice. No `api`, a failed fetch or too many hops: abort. The
      fetches are the Playwright driver's, so this predicate, run before each, is their
      only guard (the resolver rules confine Chromium's own traffic only).
    - `browser_launch_args(scope_urls, *, any_port_hosts=())`: `--no-proxy-server`,
      `--host-resolver-rules` (`MAP host:port host:port` per scope origin, the three
      loopback spellings for a loopback one, `EXCLUDE host` for `any_port_hosts`, then
      `MAP * ~NOTFOUND`), and background networking, sync, component update, domain
      reliability, pings, DNS prefetch and network prediction off.
    - `checked_api_request(in_scope, url)` raises `PermissionError`; `release(context)`
      unroutes with `ignoreErrors` before close.
  - `tools/spider.py`:
    - `_in_scope`: a loopback start is scoped to its exact origin (`in_origin_scope`);
      an external start keeps BUG-0050's host rule. It is the one predicate for the
      queue, static redirect hops, the browser route and `_isolated_submit`.
    - `_start_browser`: scoped launch args (origin for loopback, host for external),
      `new_context(service_workers="block")`, a context guard, then `new_page`.
      Out-of-scope requests are counted by host in `skipped_out_of_scope` and
      summarised at the end of the crawl.
    - `_isolated_submit` calls `checked_api_request` first.
  - PA-0002 sweep: see BUG-0123.
- Impact: FR-CRAWL-11 (new); NFR-CRAWL-safe gains its scope clause, traced per layer.
  BUG-0050's loopback rule narrows: `127.0.0.1:9999` is no longer in scope of a crawl
  started on `127.0.0.1:8080` (`tests/test_spider_scope.py` updated). Every allowed
  browser request now goes through Playwright's fetch (slower; bodies buffered in the
  driver).
- Risk: medium. A site that depends on cross-origin resources renders differently (by
  design). A redirected navigation costs one extra request for its landing page.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py` (handlers, redirect chains, launch args,
    the spider's API client, real-browser crawl/auditor/launch-arg tests against a
    second loopback port and an off-host address, the AST guard and its offenders);
    `tests/test_spider_scope.py`, `tests/test_destructive_urls.py` updated — done
  - [x] FR-CRAWL-11; NFR-CRAWL-safe — done
- Review: design agreed by reviewers A and B (consolidated requirements). Code review of
  the deviations (redirect walking, port-aware resolver rules, sockets never connected,
  the fetcher's lazy launch): all four agreed, with must-fixes adopted: the auditor's
  scope fixed once (A, who showed the driver's fetches bypass the resolver rules), a
  body-keeping navigation answered with its landing response (A, B: it was POSTed
  twice), the docs' two-layer claim corrected and the check-before-fetch order pinned
  (A); residuals stated (A, B).
- Effectiveness: verified offline with a real Chromium (zero connections to the second
  port); the Juice Shop re-crawl is the live check.

### CC-CRAWL-0014 — Shared, extended settings words; the spider records what a picker did (forms phase 2, lane A) (2026-10-14)
- Change:
  - `formnav.settings_word` (public, replaces `_settings_word`) is shared by navigation
    and the importer. `SETTINGS_WORDS` gains `sort`, `tz`, `currency`, `country`,
    `region`, `layout`, `skin`, `view`, `display`, `default`, `notify`, `privacy`,
    `visibility`; `SETTINGS_PAIRS` adds `per page`. `t` is deliberately absent ("Don't").
  - `enumerate_form(on_verdict=)` reports `settings` (stopped on a cookie or the
    self-redirect run) or `navigation`; what is submitted is unchanged.
    `formnav.signature_key` is the one key. The spider stores it in a new spider-DB
    table, `selector_verdicts` (settings wins), cleared on reset.
- Impact: FR-CRAWL-8 amended: navigation refuses pickers and options so named.
  Measured offline over all 159 option values and labels of the local bWAPP build
  (outside the repo; no bWAPP file is committed): the final set refuses exactly the six
  labels Phase 1 refused (rows 58, 73, 103, 127, 150, 155) and adds none; the `bug` /
  `form_bug` / `form` controls are not hit; `security_level` and `form_security_level`
  are, as before.
- Risk: low (refuses more, never less).
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_forms_phase2.py`: the inlined six-label pin, `page` /
    "Don't" not settings words, a cookie-setting picker recorded and never fuzzed) — done
  - [x] FR-CRAWL-10; FR-CRAWL-8 amended — done
- Review: as CC-FUZZ-0063 (reviewers' should-fix 1).
- Effectiveness: verified offline.

### CC-CRAWL-0013 — Selector-form navigation; landing URLs and forms recorded (forms phase 1) (2026-10-13)
- Change: `tools/spider.py` and new `tools/formnav.py`.
  - **Navigation.** `--follow-selector-forms [names]`, off by default.
    - GET selector forms are enumerated. POST ones are enumerated only for
      operator-named selects.
    - Never submitted: a form with a settings-named control, or a destructive or
      out-of-scope action. Skipped: an option with a settings word or destructive
      value/label.
    - Enumeration stops on a non-3xx response, a cookie, or a destructive or
      out-of-scope `Location`. Self-redirects are skipped, and five in a row stop the
      form.
    - Submissions go through an isolated client (a throwaway session, or a Playwright
      `APIRequestContext` seeded from cookies). A response cookie never reaches the
      crawler.
  - **Recording.** The landing URL of a redirect is recorded with its query
    (`redact_url`). Every form is recorded in `discovered_forms` (redacted).
- Impact:
  - **Behaviour:** the crawler POSTs for the first time, only under the flag.
    NFR-CRAWL-safe's text and `Enforced by:` lines are updated.
  - **Spider DB:** a new table.
- Risk: medium (state change by submission), mitigated by the gate before any
  submission, which reviewers A and B required, and the fail-safes.
- Residuals:
  - a named settings picker could change state, so the operator names deliberately;
  - a visit to bWAPP's `restrict_folder_access.php` deletes its `.htaccess`.
- Deliverables:
  - [x] code — done
  - [x] tests — done
  - [x] FR-CRAWL-8 and FR-CRAWL-9; NFR-CRAWL-safe — done
- Review: as CC-CORE-0039. Reviewer A's optional nit was declined: A suggested that a
  destructive or out-of-scope `Location` *skip* that option rather than stop the form.
  Stopping is the v2 rule reviewer B required (a menu leading somewhere destructive is
  not trusted further). It costs coverage only.
- Effectiveness: live. From `portal.php` alone, 159 pages and 304 forms; the
  security-level picker was never submitted.

### CC-CRAWL-0012 — The crawler logs in from its start URL (BUG-0113) (2026-10-13)
- Change: `LocalSpider._auth_base_url = start_url`, not its origin. `playwright_auth`
  marks it as operator input and scopes the injected cookies to the origin root.
- Impact: authenticated crawls of sub-path apps work, and pages outside the start
  page's directory receive the cookie.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (unit, plus a real-browser sibling-cookie test) — done
- Review: as CC-SESS-0016.
- Effectiveness: verified live (bWAPP).

### CC-CRAWL-0011 — NFR-CRAWL-safe built: no destructive link queued, redirected to, or requested by the browser (BUG-0111) (2026-10-13)
- Change: `tools/spider.py`:
  - destructive links and XHR URLs are not queued (`_destructive`, logged and counted
    in `skipped_destructive`);
  - the static engine follows redirects by hand (`navguard.get_checked`), each hop in
    scope and not destructive;
  - the rendered engine installs `navguard.guard_page`, which aborts destructive
    navigations, fetch/XHR and subresources;
  - the start URL is exempt in both modes;
  - pages open with `service_workers="block"`, because a worker's fetches bypass
    `page.route` (reviewer B). WebSockets are not routed, a stated gap.

  New `tools/navguard.py`.
- Impact:
  - **Behaviour change:** fewer pages crawled where links are destructive, and the
    static engine no longer auto-follows redirects;
  - **AUD:** the auditor shares `navguard`.
- Risk: low. It adds refusals only, and a real-browser test covers the route.
- Deliverables:
  - [x] spider and navguard — done
  - [x] tests: static (link, 302) and a real-browser crawl — done
  - [x] NFR-CRAWL-safe amended, with traceability — done
- Review: as CC-CORE-0038 (A1 and B1/B2 adopted).
- Effectiveness: verified, including under `FUZZLAB_REQUIRE_BROWSER=1`.

### CC-CRAWL-0010 — Full browser header set (not UA alone), so a real external WAF stops 403ing a UA/Accept mismatch (2026-09-25, BUG-0060/PA-0062, recurrence of CC-CRAWL-0009)
- **Change:** `LocalSpider.__init__`'s `requests.Session()` now applies
  `fuzzlab.core.http.DEFAULT_BROWSER_HEADERS` (UA + `Accept`/`Accept-Language`/
  `Sec-Fetch-*`/`Upgrade-Insecure-Requests`) instead of `DEFAULT_USER_AGENT` alone.
- **Why:** live-reported by the operator running the crawler against a real external,
  authorized test target — `403 Forbidden`, one layer past `CC-CRAWL-0009`'s own fix. A
  Chrome `User-Agent` paired with `requests`' own `Accept: */*` and no
  `Accept-Language` is an internally inconsistent request several WAFs specifically
  detect and reject; `CC-CRAWL-0009` fixed the UA alone, which surfaced this deeper
  layer of the same gap instead of closing it. Full RCA:
  `docs/bugs/BUG-0060-ua-header-mismatch-403-external-waf.md`. Preventive action:
  `PA-0062` (supersedes `PA-0061`). Confirmed with the operator that the affected
  targets are theirs/authorized before implementing, since this class of fix is
  dual-use (it makes traffic harder for a WAF to distinguish from a real browser).
- **Verification:** offline — inspected the prepared request headers from a
  `DEFAULT_BROWSER_HEADERS`-configured session directly; `tests/test_spider_scope.py`'s
  12 tests pass unchanged. Live re-verification against the operator's own target that
  returned the `403` is the operator's own follow-up.
- **Scope:** no interface/contract change (`requirements.md` unaffected).

### CC-CRAWL-0009 — Default browser User-Agent, so real external targets don't silently serve 0-link content (2026-09-25, BUG-0059/PA-0061)
- **Change:** `LocalSpider.__init__`'s `requests.Session()` now sets a realistic
  Chrome-on-Linux `User-Agent` (`fuzzlab.core.http.DEFAULT_USER_AGENT`, a new shared
  constant) instead of leaving `requests`' own default (`python-requests/x.y`). The
  Playwright/rendered engine is unaffected (a real headless Chromium already sends an
  authentic browser UA).
- **Why:** live-reported running a crawl from the web UI against a real external,
  authorized test target — `200 OK` on the start URL, 0 links discovered. Root cause: the
  default UA is trivially fingerprintable, and several real external sites serve
  reduced/interstitial content to it instead of real markup; the local lab never
  surfaces this since it doesn't discriminate by UA. Full RCA:
  `docs/bugs/BUG-0059-spider-default-ua-zero-links-external-targets.md`. Preventive
  action: `PA-0061`. The same sweep found and fixed 5 other bare, UA-unset
  `requests.Session()` instances across the codebase (`fetcher.py`,
  `blind_sqli_fuzzer.py`, `probesender.py`, `greybox/run.py`, `session/manager.py`) —
  see the CORE component's own log for the shared constant this entry and those all
  route through.
- **Verification:** offline — `tests/test_spider_scope.py`'s 12 tests pass unchanged.
  Live re-verification against the operator's own external target that originally
  showed 0 links is the operator's own follow-up (this sandbox's outbound network is
  proxied/restricted and cannot reach arbitrary external hosts).
- **Scope:** no interface/contract change (`requirements.md` unaffected) — an HTTP
  client fidelity fix, not a behavior/scope change to what the crawler follows.

### CC-CRAWL-0008 — Scope link-following to the start URL's host, not a hardcoded loopback allowlist (2026-09-24, BUG-0050/PA-0052)
- Change: `fuzzlab/tools/spider.py` — replaced `LocalSpider._is_local(url)` (which
  followed a link only if its hostname was `localhost`/`127.0.0.1`) with
  `_in_scope(url)`, scoped to the start URL's own host (`self._scope_host`,
  computed in `__init__` via the new `_norm_host` helper). Loopback aliases
  (`localhost`/`127.0.0.1`/`::1`) are treated as one host and `www.` is
  normalised, so apex/`www` and cross-alias lab links still match; third-party
  and other-subdomain links are still not followed (the "don't escape to the open
  web" intent is preserved). Both enqueue call sites (link + XHR) updated. Applies
  to both engines and, via the CLI, to the web-UI crawl.
- Why: pointed at any authorized non-loopback host, the old guard dropped **every**
  discovered link, so the crawler fetched only the start page and found nothing —
  reported by the operator crawling authorized live hosts via the web UI. See
  BUG-0050.
- Verification: new `tests/test_spider_scope.py` (12 cases: external same-host /
  subdomain / third-party / `www` / no-host / loopback aliases) — all pass.
  End-to-end: a 3-page same-host site is fully discovered on both the `requests`
  and `playwright` engines, while an embedded third-party link is correctly not
  followed. Full non-slow suite unaffected.
- Scope: `fuzzlab/tools/spider.py`, `tests/test_spider_scope.py` (new); requirement
  FR-CRAWL-7 added. See BUG-0050, PA-0052.

### CC-CRAWL-0007 — `--dry-run` CLI flag (lane D0a) (2026-09-22)
- Change: `fuzzlab/tools/spider.py::build_parser()` gained `--dry-run` (via the new
  shared `fuzzlab/cli_dryrun.add_dry_run_flag()`). The module's `__main__` block now
  checks `args.dry_run` first: if set, it calls `fuzzlab/cli_dryrun.report("crawl",
  args)` — which plans and prints the exact argv/display command via the web
  launcher's existing pure functions (`fuzzlab/web/commandspec.spec()` +
  `fuzzlab/web/runner.build_argv()`/`display_command()`, CC-UI-0013/0015) — and exits
  0 before `LocalSpider` is ever constructed. No crawl request is made. When
  `--dry-run` is absent, behavior is unchanged.
- Impact (other components / project): CRAWL only, plus an incidental UI effect — see
  CC-UI-0027 (the web launcher's per-tool option list is introspected straight from
  `build_parser()`, so the new `--dry-run` checkbox shows up there automatically, with
  no code change to `fuzzlab/web/app.py`). No schema/store change; the dry-run path
  never touches the spider DB or the store.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect. Mitigated by `tests/test_cli_dry_run.py` (crawl cases: flag present, report
  printed, `LocalSpider.__init__`/`.crawl` patched to raise if called — confirming
  nothing executes) and the unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `crawl`'s parser — done.
  - [x] Short-circuit in `__main__` calling the shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab crawl --dry-run` prints
  the planned argv/command and exits 0 without constructing `LocalSpider` or making
  any request; verified directly and via the new tests.

### CC-CRAWL-0006 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/tools/spider.py` now factors its argparse setup into `build_parser()`
  (returns the `ArgumentParser`); `parse_args()` delegates to it. Added `prog="fuzzlab
  crawl"` for accurate usage. Behavior-preserving — same flags, defaults, and parsing.
- Impact: lets the web launcher introspect the crawler's flags (CC-UI-0011). No CLI
  behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `parse_args()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds the crawler's spec
  from this parser.

### CC-CRAWL-0005 — Template dedup + hybrid-crawl decision (algorithms) (2026-09-21)
- Change: built two Phase 2 crawler algorithms as pure, tested `core/` modules.
  `core/dedup.py` (T2.6): DOM-skeleton MinHash + `TemplateClusterer` — near-duplicate
  pages (same structure, different data) get the same `template_cluster_id` so they
  are audited once. `core/hybrid.py` (T2.7): `needs_browser(html)` — decides whether
  a statically fetched page is client-rendered and must escalate to Playwright
  (conservative: escalate on doubt).
- Impact (other components / project): these reduce requests when wired into the
  crawl loop (audit-once-per-cluster; static-first, browser-on-demand). The
  algorithms are in `core/` (shared, dependency-light). Wiring into `spider.py`'s
  fetch loop — computing `template_cluster_id` from the fetched HTML and switching
  engines per page — is the next step (needs the live browser/lab to validate, and
  is measured by T2.8).
- Risk (level; mitigation): low (pure functions, tested). Dedup hiding a distinct
  page mitigated by clustering on skeleton (not content) with a tunable threshold;
  hybrid mis-classifying a JS page mitigated by conservative escalation. 6 unit
  tests (same-template clusters together; different templates separate; SPA/noscript
  escalate; static page does not).
- Deliverables:
  - [x] `dedup.py` (MinHash + clusterer) + tests (T2.6) — done.
  - [x] `hybrid.py` (`needs_browser`) + tests (T2.7) — done.
  - [ ] Wire into `spider.py` fetch loop (cluster id from HTML; engine switch) — todo (with T2.8).
- Effectiveness (assessed 2026-09-21): effective in unit tests — 5 same-template
  pages collapse to one cluster; SPA/noscript shells escalate while a text-rich page
  does not. Live request reduction measured in T2.8.

### CC-CRAWL-0004 — Authenticated Playwright crawl (cookie injection) (2026-09-21)
- Change: the crawler's Playwright engine now authenticates by injecting the
  session into the browser context. `LocalSpider` gained `session_manager`/
  `identity`; `_start_browser` ensures the session and injects cookies
  (`add_cookies`) or a bearer header (`set_extra_http_headers`) via a shared
  `fuzzlab/tools/browserauth.py`. Added a `--identity` flag (base URL derived from
  `--start`). Anonymous crawl unchanged. Completes the crawler side of Phase 0/1
  Option A (both static and browser paths now authenticate).
- Impact (other components / project): JS-rendered pages and the Discover-nav
  links are now crawled as an identity, so authenticated-only surface is
  discovered; depends on the session manager (#3) and credential store.
- Risk (level; mitigation): low–medium — injection runs once at browser start; a
  failed login fails loud through `ensure`. `browserauth` is Playwright-free and
  unit-tested (cookie → add_cookies, bearer → extra header); the live browser wiring
  is thin glue validated on a host with a browser + lab.
- Deliverables:
  - [x] `browserauth` helper; `_start_browser` injection; `--identity` — done.
  - [x] Unit tests for cookie/bearer injection — done.
  - [ ] Live authenticated crawl against the lab (T1.10) — todo (needs a browser + lab).
- Effectiveness (assessed 2026-09-21): effective in unit tests — the session is
  shaped and applied to a (fake) context for both schemes. Live crawl pending.

### CC-CRAWL-0003 — Consolidates into the unified store (2026-09-21)
- Change: added `--store PATH` to the crawler; after a crawl it consolidates its
  native `discovered_pages` output into the unified store via
  `fuzzlab/tools/store_adapter.import_spider`, writing `page`, `endpoint`, and
  `parameter` rows (URLs normalized to path form; query params captured). Native
  standalone output is unchanged when `--store` is omitted. Phase 0 T0.8.
- Impact (other components / project): the crawler now feeds the integration bus
  (D5); its pages/params are readable by the auditor, harness, and (later) ranker.
  Adapter-based for now; a future phase can make the crawl write directly.
- Risk (level; mitigation): low — opt-in and additive; covered by the
  consolidation end-to-end test (synthetic spider DB → page/endpoint/parameter).
- Deliverables:
  - [x] `--store` + `import_spider` (page/endpoint/parameter) (T0.8) — done.
  - [ ] Direct-to-store writes (drop the native DB) — todo (later).
- Effectiveness (assessed 2026-09-21): effective — a synthetic crawl of 5 pages
  populates 5 pages and 4 parameters in the unified store (test green).

### CC-CRAWL-0002 — Moved into the `fuzzlab` package (2026-09-21)
- Change: `spider.py` moved to `fuzzlab/tools/spider.py` and now imports `core/`
  (`get_logger`), emitting a structured startup line. Still writes its own SQLite
  file for now (T0.8 migrates it to the shared store). Part of Phase 0 T0.1.
- Impact (other components / project): the crawler is now a package module
  (`python -m fuzzlab.tools.spider`) importing the shared library; no behavior or
  output-format change yet.
- Risk (level; mitigation): low — a move plus one import; verified the module
  imports and `--help` runs.
- Deliverables:
  - [x] Move into package; import `core/` (T0.1) — done.
  - [ ] Write to the shared store (T0.8) — todo.
- Effectiveness (assessed 2026-09-21): effective — imports cleanly and runs as a
  package module.

### CC-CRAWL-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `spider.py` renders
  JavaScript via Playwright, captures fetch/XHR endpoints, resets/reuses its own
  SQLite results, and fixes the earlier port-scope bug. Standalone; not yet on the
  shared store or session manager.
- Impact (other components / project): feeds the auditor and fuzzer; currently
  writes its own database rather than the shared store, and crawls unauthenticated.
- Risk (level; mitigation): low. Present gaps (no shared store, no auth, no
  template dedup) are addressed in Phase 0 (store migration) and Phase 2
  (hardening); no current risk to other components beyond its own DB format.
- Deliverables:
  - [x] JavaScript rendering + XHR capture — done.
  - [x] Reset-by-default and `--resume`; port-scope fix — done.
  - [ ] Migrate to the shared store — todo (Phase 0 T0.8).
  - [ ] Session-manager integration + per-identity crawl — todo (Phase 1).
  - [ ] Template dedup, hybrid crawl, state-machine — todo (Phase 2).
- Effectiveness (assessed or pending): effective for JS discovery — verified that
  the Playwright engine finds all 10 JS pages the static engine missed. Remaining
  items pending.
