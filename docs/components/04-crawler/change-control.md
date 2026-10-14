# Crawler / Spider — Change Control Log

Component code: **CRAWL**. Entry format and required fields: see `../README.md`.
Newest first.

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
