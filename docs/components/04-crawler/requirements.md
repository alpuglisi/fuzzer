# Crawler / Spider — Requirement Specification

Component code: **CRAWL** · Status: `[built; to harden]` · Last updated: 2026-09-24

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

## 6. Dependencies (components)
`core/`, session manager, target lab.

## 7. Acceptance criteria
- Discovers JavaScript-rendered pages and XHR endpoints a static crawler misses.
- Deduplicates near-duplicate pages by template.
- Stays authenticated for a full crawl and records results per identity.

## 8. Open questions
- Form-fill value generation (type-aware) for reaching post-submission code.
- State-machine crawl depth and caps.
