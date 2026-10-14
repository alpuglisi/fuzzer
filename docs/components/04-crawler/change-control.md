# Crawler / Spider — Change Control Log

Component code: **CRAWL**. Entry format and required fields: see `../README.md`.
Newest first.

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
