# Crawler / Spider — Requirement Specification

Component code: **CRAWL** · Status: `[built; to harden]` · Last updated: 2026-10-14

Related: `ARCHITECTURE.md` #4; `DECISIONS_AND_ROADMAP.md` (D5, D6, Phase 2);
`./change-control.md`.

## 1. Purpose
Discover the target's reachable surface — pages, endpoints, parameters, and
JavaScript-driven endpoints — and record it in the store for the auditor and
fuzzer.

## 2. Scope
- **In:** fetching and rendering, link and endpoint discovery, deduplication,
  scope and budget, per-identity crawling.
- **Out:** deciding whether a parameter is vulnerable (auditor/fuzzer).

## 3. Functional requirements
- **FR-CRAWL-1** Hybrid fetch: cheap HTTP first, escalate to a headless browser
  only when a page is client-rendered.
- **FR-CRAWL-2** Capture fetch/XHR endpoints and JS-extracted endpoints, not just
  static anchors.
- **FR-CRAWL-3** Deduplicate by DOM-skeleton template cluster (MinHash), recording
  a `template_cluster_id`, and normalize URLs.
- **FR-CRAWL-4** Crawl as a state machine (state = DOM-skeleton hash + identity),
  reaching pages behind multi-step flows.
- **FR-CRAWL-5** Crawl per identity, using the session manager; detect logout and
  re-authenticate. The login is discovered from the start URL itself, path and all,
  never its bare origin; injected cookies are scoped to the origin root (CC-CRAWL-0012,
  BUG-0113).
- **FR-CRAWL-6** Respect a crawl budget and deadline via the shared budget
  manager; never overlap headless work with timing-sensitive fuzzing.
- **FR-CRAWL-7** Link-following scope is the **start URL's own host** (loopback
  aliases `localhost`/`127.0.0.1`/`::1` treated as one host; `www.` normalised):
  follow same-host links, never third-party/other-subdomain links. Scope is
  derived from the operator-configured target, never a hardcoded loopback
  literal — so the crawler works on any authorized target, not only the
  loopback lab (BUG-0050/PA-0052).

- **FR-CRAWL-8 (selector-form navigation, CC-CRAWL-0013)** With
  `--follow-selector-forms [names]` (off by default), the crawler enumerates menu-like
  forms (one `<select>`, nothing typed):
  - GET forms always; POST forms only for operator-named selects;
  - the gate, per-option checks, fail-safes and cookie isolation are as in
    `tools/formnav.py`;
  - redirects found this way are crawled as ordinary links.
  - *(Amended in place, CC-CRAWL-0014, 2026-10-14.)* The settings words are the one
    shared `formnav.settings_word`, extended with `sort`, `tz`, `currency`, `country`,
    `region`, `layout`, `skin`, `view`, `display`, `default`, `notify`, `privacy`,
    `visibility` and the token pair `per page` (`t` deliberately not: "Don't"). It
    governs navigation too, so a picker or option so named is no longer submitted.
    On bWAPP this refuses exactly the six option labels Phase 1 refused (measured over
    all 159 options of the local build).
- **FR-CRAWL-9 (landings and forms recorded, CC-CRAWL-0013)** A redirect's landing URL
  is recorded with its query (redacted). Every form seen is recorded in
  `discovered_forms` (redacted).
- **FR-CRAWL-10 (what a picker did, CC-CRAWL-0014)** When selector navigation submits a
  picker, the spider records its verdict in `selector_verdicts`, keyed by
  `formnav.signature_key`: `settings` (it set a cookie, or kept redirecting to itself)
  or `navigation`. What is submitted is unchanged. The importer never fuzzes a POST
  picker seen as `settings` (FR-FUZZ-43).

- **FR-CRAWL-11 (scope, CC-CRAWL-0015, BUG-0123)** A crawl started on a loopback URL is
  scoped to that URL's exact origin (scheme, host, port; `localhost`, `127.0.0.1` and
  `::1` on the same port are one origin): another loopback port is another service.
  A crawl started on any other host keeps BUG-0050's host rule (same host or `www.`,
  any scheme or port). The one predicate, `LocalSpider._in_scope`, gates the link
  queue, static redirect hops, the browser's every request and `_isolated_submit`.
  The crawl summary reports the out-of-scope browser requests it blocked, by host.
  The browser's routed requests (fetched by the Playwright driver) are guarded by that
  predicate alone, checked before every fetch; Chromium's own traffic is confined by
  the launch arguments. Stated residuals (BUG-0123): a redirected GET navigation's
  landing page is requested twice, the second time unrouted (scope still enforced by
  the resolver rules, destructive tokens not re-checked on any new hops); a 307/308
  navigation keeps its first URL as `page.url`; walked hops carry the context's headers,
  not the browser's; with `--no-proxy-server` a browser in a proxy-only container
  cannot reach an external target (fails safe).

- **FR-CRAWL-12 (single-page-app routes, CC-CRAWL-0016, forms phase 3)** In the
  Playwright engine, on by default (navigation, like link following; decision 1 of the
  phase 3 draft), off with `--no-spa-routes`:
  - **Discovery, read-only.** Route declarations are read from the page's **same-origin
    script bodies the browser already loaded**, through the guard's own fetched response
    (`navguard` `observe`): no extra request. Cross-origin scripts are never read. A
    script over `spa.MAX_SCRIPT_BYTES` (4 MiB) is not scanned; at most
    `spa.MAX_SCRIPTS_PER_PAGE` (32) scripts per page, each once per crawl. `spa.scan_routes`
    is a linear scan (`str.find` with bounded look-around, no regular expression over
    the body): Angular `{path:'x'`, Vue `path: '/x'`, React `{ path: "/x"` and
    `<Route path="/x"`.
  - **Routes.** Parameterised and wildcard routes (`:id`, `*`, `**`) are skipped (a
    stated gap); a route whose path `destructive_reason` flags (`logout`,
    `delete-account`, …) is never visited. Hash mode (`origin/#/x`, or `#!/x`) when the
    page or its links use it, else history mode under the page's `<base>` or the start
    URL's directory. The counts of routes visited (a route page actually rendered),
    skipped as destructive and skipped as parameterised are kept
    (`LocalSpider.spa_counts`) and reported in the crawl summary (PA-0110).
  - **Pages and keys.** Hash routes are distinct pages: a fragment starting with `/` or
    `!/` is kept (its own query redacted, `core.redaction.redact_spa_fragment`), any
    other fragment dropped. Pages dedupe on `spa.visit_key` (canonical origin, path,
    query, SPA fragment), so loopback aliases are one site. A SPA route's fragment is
    checked by the destructive rule too (`spa.route_destructive_reason`): a hash
    navigation sends no request the browser guard could see.
  - **XHR noise.** socket.io / engine.io transport URLs (a `socket.io` / `engine.io`
    path segment, or `EIO` and `transport` query names) are not stored as pages; an XHR
    URL is stored with sensitive and identifier-like query values redacted
    (`core.redaction.redact_url_identifiers`).
  - **DELETE.** The crawl guard aborts every browser-initiated `DELETE` unless it comes
    from a `--submit-spa-forms` submission on a route the operator named; each abort is
    counted and reported. Stated residual (reviewer A): loading a route can make the
    app send its own non-DELETE writes (a POST/PUT/PATCH on page load); the guard aborts
    only DELETE and destructive-token URLs. Route children are not joined to their
    parent's path (a nested route may be visited at the wrong URL: harmless, a stated
    gap).

- **FR-CRAWL-13 (request capture and SPA form submission, CC-CRAWL-0017, forms phase 3)**
  - **Passive capture (default on, Playwright engine).** Every fetch/XHR request the
    page itself makes through the guarded route with a body (not GET/HEAD/OPTIONS) that
    is JSON or form-encoded is recorded in the spider table `discovered_requests`
    (contract in §5). Redaction is only `core.redaction` (FR-CORE-37,
    `StorageManager.record_request`, the one write site, in the PA-0100 producer
    guard): sensitive names and identifier-like values blanked (a string to `""`, a
    number or boolean to `null`, a container empty), password values blanked, bodies
    over 64 KiB or nested deeper than 8 not recorded, fail closed. Request headers and
    cookies are never recorded; socket.io / engine.io requests are excluded.
    Non-sensitive captured values (e.g. a logged-in e-mail address) are kept and are
    replayed as siblings by the importer (reviewer A8).
  - **Active submission (opt-in, `--submit-spa-forms [ROUTE …]`, default off).** On a
    visited SPA route, each rendered `<form>` or form-like container (typed inputs and
    exactly one button) is filled with the importer's fillers (`store_adapter`; a
    password gets `spa.PASSWORD_FILLER`, never a real credential; hidden, select,
    checkbox and sensitive-named fields are left as they are) and its button clicked
    once, so the app sends its real request, which passive capture records with
    `source = 'submit'`. One submission per form signature (controls and button
    label); at most `spa.MAX_SUBMISSIONS` (50) per crawl, the rest counted and reported.
    The submission's requests pass the same scope, destructive and DELETE guard.
  - **Refused** (`spa.form_refusal`, the one gate): a route not named when routes are
    named (whole-route comparison); a destructive, settings-like (`formnav.settings_word`)
    or transaction (`core.urls.transaction_reason`) route, button label or action; a
    destructive or settings-like control name; a form with `<input type=file>` (a stated
    gap); a credential-change form (`store_adapter.credential_change_reason`); a form
    whose only typed input is a one-time code (2FA/TOTP).
  - **Sessions.** A form with a password input is submitted only in a fresh
    unauthenticated browser context (same browser, so the same launch arguments; the
    same guard and scope), closed afterwards. In an **authenticated** crawl a bare
    `--submit-spa-forms` submits only there; a form is submitted in the crawl's own
    authenticated context only when its route is named. After each such submission the
    crawl's session is re-checked (every injected cookie still holds its value, and the
    session manager's `verify_live`); on loss, or when it cannot be verified, submitting
    stops for the rest of the crawl and the reason is reported.
  - Stated risk: a submission changes lab state (a feedback row, a failed login, a
    registration attempt with filler data). Lab only, default off.

## 4. Non-functional requirements
- **NFR-CRAWL-safe** Deny-list destructive actions (delete/logout/reset); default
  to not clicking them. *(Built CC-CRAWL-0011, BUG-0111:)* the one rule is
  `core.urls.destructive_reason` (FR-CORE-28). A destructive URL is never queued,
  never reached through a redirect (the static engine follows redirects by hand, each
  hop checked), and never requested by the browser (`navguard.guard_page` aborts
  navigations, scripts' fetch/XHR and subresources). The start URL is the operator's
  own input and is exempt. The auditor never re-fetches one from a spider DB, old or
  new. There is no opt-in: stricter than "default". *(CC-CRAWL-0013:)* the crawler
  POSTs only to operator-named selector forms (FR-CRAWL-8), never to a settings or
  destructive one. *(CC-CRAWL-0015, BUG-0123:)* **no request leaves the crawl scope**
  (FR-CRAWL-11), and the destructive rule covers every redirect hop, at each layer:
  the queue; static redirects (by hand); the browser (a context-wide route that walks
  redirect chains hop by hop, WebSockets routed, plus launch arguments that resolve
  nothing outside scope); and the API-request client (scope-checked, no redirects).
  - Enforced by (scope, per layer): `LocalSpider._in_scope`, `navguard.guard_page` / `make_route_handler` / `make_ws_handler` / `browser_launch_args` / `checked_api_request` — `tests/test_spider_scope.py::test_loopback_start_treats_aliases_as_one_host`, `tests/test_browser_scope.py::test_a_rendered_crawl_never_leaves_the_target_origin`, `tests/test_browser_scope.py::test_the_launch_args_alone_confine_an_unrouted_page_to_the_origin`, `tests/test_browser_scope.py::test_a_redirect_hop_out_of_scope_is_never_requested`, `tests/test_browser_scope.py::test_out_of_scope_requests_are_aborted_and_reported`, `tests/test_browser_scope.py::test_allow_never_lifts_scope`, `tests/test_browser_scope.py::test_websockets_are_scope_checked`, `tests/test_browser_scope.py::test_the_spiders_isolated_submit_refuses_an_out_of_scope_action`, `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`, `tests/test_browser_scope.py::test_the_browser_guard_catches_synthetic_offenders`, `tests/test_browser_scope.py::test_scope_is_checked_before_any_fetch`
  *(CC-CRAWL-0016/0017, forms phase 3:)* **a crawl never deletes**: a browser-initiated
  DELETE is aborted unless it comes from a submission on an operator-named route
  (FR-CRAWL-12); a destructive SPA route (by its fragment) is never visited; a SPA form
  is submitted only with `--submit-spa-forms`, never a destructive, settings,
  transaction, credential-change, 2FA-only or file form, a password form only in a fresh
  unauthenticated context, and in an authenticated crawl the crawl's own context only on
  a named route, stopping when the session is lost (FR-CRAWL-13).
  - Enforced by (DELETE and destructive SPA routes): `navguard.make_route_handler(method_refusal=)`, `LocalSpider._method_refusal`, `spa.classify_route`, `spa.route_destructive_reason` — `tests/test_spa_routes.py::test_the_guard_aborts_a_refused_method_before_any_fetch`, `tests/test_spa_routes.py::test_the_spider_refuses_a_delete_unless_a_named_route_submission_sends_it`, `tests/test_spa_routes.py::test_a_browser_initiated_delete_is_aborted_and_counted`, `tests/test_spa_routes.py::test_a_delete_is_sent_only_from_a_named_routes_submission`, `tests/test_spa_routes.py::test_routes_are_classified`, `tests/test_spa_routes.py::test_a_hash_route_is_destructive_by_its_fragment`, `tests/test_spa_routes.py::test_hash_routes_are_read_from_the_bundle_and_crawled_as_pages`, `tests/test_spa_routes.py::test_history_mode_routes_are_paths_under_the_base`
  - Enforced by (SPA form submission): `spa.form_refusal`, `LocalSpider._submit_spa_forms` / `_submit_anonymously` / `_session_intact` — `tests/test_spa_capture.py::test_submission_is_off_by_default`, `tests/test_spa_capture.py::test_each_refusal`, `tests/test_spa_capture.py::test_each_transaction_word_is_refused_on_the_route_and_on_the_label`, `tests/test_spa_capture.py::test_a_route_not_named_is_refused_when_routes_are_named`, `tests/test_spa_capture.py::test_bare_submission_in_an_anonymous_crawl`, `tests/test_spa_capture.py::test_a_password_form_is_submitted_only_in_a_fresh_unauthenticated_context`, `tests/test_spa_capture.py::test_a_named_login_route_is_still_submitted_only_unauthenticated`, `tests/test_spa_capture.py::test_an_authenticated_bare_flag_never_submits_in_the_crawls_context`, `tests/test_spa_capture.py::test_a_named_route_is_submitted_authenticated_and_session_loss_stops_it`, `tests/test_spa_capture.py::test_the_session_check_fails_closed`, `tests/test_spa_capture.py::test_submissions_are_capped_and_the_cap_is_reported`
  - Enforced by (scope of SPA traffic, both contexts): `tests/test_spa_capture.py::test_bare_submission_in_an_anonymous_crawl`, `tests/test_spa_routes.py::test_cross_origin_and_oversized_scripts_are_never_read`
  - Enforced by (no request body sent twice by the guard): `tests/test_browser_scope.py::test_a_redirected_post_navigation_is_submitted_once`
  - Enforced by (destructive redirect hops in the browser): `tests/test_browser_scope.py::test_a_redirect_hop_to_a_destructive_url_is_never_requested`, `tests/test_browser_scope.py::test_an_endless_redirect_chain_is_aborted`
  - Enforced by: `core.urls.destructive_reason`; `tools/spider.py` (queue filter, hand-followed redirects, `navguard.guard_page`); `tools/fetcher.py:load_urls` — `tests/test_destructive_urls.py::test_static_crawl_never_fetches_a_destructive_link_or_redirect`, `tests/test_destructive_urls.py::test_rendered_crawl_sends_no_destructive_request_at_all`, `tests/test_destructive_urls.py::test_the_auditor_never_refetches_a_destructive_url_from_an_old_spider_db`, `tests/test_destructive_urls.py::test_login_discovery_never_follows_a_redirect_to_a_destructive_url`, `tests/test_forms_phase1.py::test_a_named_picker_is_navigated_and_the_settings_one_never_touched`, `tests/test_forms_phase1.py::test_a_settings_picker_is_never_submitted_even_when_named`, `tests/test_forms_phase1.py::test_selector_submissions_never_change_the_crawlers_cookies`, `tests/test_forms_phase1.py::test_bwapps_destructive_gets_are_refused`
- **NFR-CRAWL-bounded** Cap per-template instance counts to avoid infinite crawl
  spaces.
- **NFR-CRAWL-reproducible** Record a crawl manifest (URL → template →
  discovered-from) so runs can be diffed.
- **NFR-CRAWL-dry-run** `fuzzlab crawl` accepts `--dry-run`: plans and prints the
  exact argv/command it would run and sends nothing (no request is made), for
  headless use outside the web UI. Reuses the web launcher's dry-run plan/report
  logic (`fuzzlab/web/commandspec.py` + `fuzzlab/web/runner.py`) via the shared
  `fuzzlab/cli_dryrun.py` helper, rather than a separate implementation.
  - Enforced by: `cli_dryrun` — `tests/test_cli_dry_run.py::test_crawl_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_crawl_dry_run_reports_plan_and_sends_nothing`

## 5. Interfaces and data contracts
Writes `page`, `endpoint`, and `parameter` rows (with a `source` of link vs xhr).
Reads the session context and the request budget. Runs standalone or as part of a
pipeline.

Spider DB (the spider's own schema, `StorageManager`; no store migration):
`discovered_pages` (`source` is `link`, `xhr`, `redirect`, `form` or, since FR-CRAWL-12,
`spa-route`; a SPA route page's `url` keeps its `#/…` fragment), `discovered_forms`,
`selector_verdicts`, and, since FR-CRAWL-13, **`discovered_requests`** — the contract
the importer reads (lane J, forms phase 3):
`(id, page_url, method, url, content_type, body_json TEXT, source TEXT ('passive' |
'submit'), signature TEXT UNIQUE)`. `body_json` is the redacted body as JSON text (a
JSON body's parsed value; a form-encoded body as an object of name → value, last wins);
`url` and `page_url` are redacted (`core.redaction.redact_url_identifiers`);
`content_type` is the media type only; `signature` = JSON `[method,
url_key(url), sorted top-level keys]` (dedupe). No header and no cookie is stored.
An old spider DB has no such table (the importer treats it as none).

## 6. Dependencies (components)
`core/`, session manager, target lab.

## 7. Acceptance criteria
- Discovers JavaScript-rendered pages and XHR endpoints a static crawler misses.
- Deduplicates near-duplicate pages by template.
- Stays authenticated for a full crawl and records results per identity.

## 8. Open questions
- Form-fill value generation (type-aware) for reaching post-submission code.
- State-machine crawl depth and caps.
