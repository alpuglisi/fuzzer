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
  the launch arguments. Every Chromium launch (crawler, auditor, M6 executor) takes its
  whole configuration from `navguard.chromium_launch_kwargs` (CC-CRAWL-0018, BUG-0126),
  guarded at every `chromium.launch`. Every teardown goes through `navguard.release`,
  which closes the context's pages before unrouting, so nothing is in flight
  (CC-CRAWL-0020, BUG-0128). Stated residuals (BUG-0123): a redirected GET navigation's
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
    `delete-account`, …) is never visited. A socket.io / engine.io transport path
    (socket.io's own `{path:'/socket.io'}` option) and a value starting with `//` are
    not routes at all: neither visited nor counted. Hash mode (`origin/#/x`, or `#!/x`) when the
    page or its links use it, else history mode under the page's `<base>` or the start
    URL's directory. The counts of routes visited (a route page actually rendered),
    skipped as destructive and skipped as parameterised are kept
    (`LocalSpider.spa_counts`), stored in the spider table `crawl_stats` and reported
    in the crawl summary (PA-0110).
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
    from a `--submit-spa-forms` submission on a route the operator named, from the
    browser context doing that click, at most once per click; each abort is counted
    and reported. Stated residual: that one allowed DELETE may be the clicking
    context's own background request rather than the click's. Stated residual (reviewer A): loading a route can make the
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
    guard): sensitive names (security answers included) and identifier-like values --
    strings, and numbers judged as their text -- blanked (a string to `""`, a number or
    boolean to `null`, a container empty), identifier-like keys replaced by a
    placeholder, password values blanked, the same whether the body was JSON or
    form-encoded, bodies
    over 64 KiB or nested deeper than 8 not recorded, fail closed. A cookie's or a
    credential header's value is never recorded: only allowlisted non-secret headers are
    (`redact_captured_headers`, CC-CRAWL-0037, contract in §5); socket.io / engine.io
    requests are excluded.
    Non-sensitive captured values (e.g. a logged-in e-mail address) are kept and are
    replayed as siblings by the importer (reviewer A8).
  - **Blocked writes recorded, never sent (CC-CRAWL-0036, survey option 3).** A write
    the **reveal** window refuses before it is sent (`navguard`
    `on_window_refused`; any method but GET/HEAD/OPTIONS, a navigation POST of an
    auto-submitted form or picker included) with a JSON or form-encoded body is recorded
    through the same write site and boundary with `source = 'blocked'`
    (`spider.BLOCKED_SOURCE`, counted `requests_blocked_recorded`). Not recorded: a
    transport URL, a body-less write, and anything a seed or probe load's window refused
    (*CC-CRAWL-0039:* a query load's write is never replayed, FR-CRAWL-17; a probe
    records nothing). It is never sent by the crawl; the importer's FR-AUD-22 rules
    decide whether it becomes a point.
  - **Active submission (opt-in, `--submit-spa-forms [ROUTE …]`, default off).** On a
    visited SPA route, each rendered `<form>` or form-like container (typed inputs and
    exactly one button) is filled with the importer's fillers (`store_adapter`; a
    password gets `spa.PASSWORD_FILLER`, never a real credential; hidden, select,
    checkbox and sensitive-named fields are left as they are) and its button clicked
    once, so the app sends its real request, which passive capture records with
    `source = 'submit'`. A covered button (a first-visit dialog or cookie bar
    intercepting pointer events) gets `Escape` once, then its own `click()` on the
    element (`clicks_dispatched`); an overlay's own buttons are never clicked. Only a
    *covered* button is dispatched: a hidden, detached or never-actionable one is not
    submittable. Right before the click the button's labels are read again and must
    equal the vetted ones, else nothing is clicked (`forms_label_changed`;
    CC-CRAWL-0019, reviewer B). One
    submission per form signature (controls and button
    label); at most `spa.MAX_SUBMISSIONS` (50) per crawl, the rest counted and reported.
    The submission's requests pass the same scope, destructive and DELETE guard.
  - **The listener registry and Enter submission (CC-CRAWL-0038, survey option 6).**
    Every crawl context runs `spa.LISTEN_INIT_JS` before the page's scripts: it records,
    in a WeakMap (no DOM change, the listeners unchanged), which elements get a `click`,
    `submit` or key listener through `addEventListener` (a framework's own bindings) or
    an `on*` property (at most `spa.MAX_LISTENED`). `FORMS_JS` then also finds (only
    where no button is): a container whose one submitter is a click-listened element
    (`submitter = "listener"`, clicked through `click_vetted` like a button; refused
    without a text or aria-label to judge, or when its text is over 100 characters), and
    a text control (`spa.ENTER_KINDS`) with a key listener, outside any form, with no
    button (hidden or shown) and no click-listened element within three levels of it, or
    a `<form>` with exactly one text control whose elements hold no default button at all
    -- a hidden one, or one outside it through `form=`, included (`submit_by = "enter"`,
    `enter_id`; review M1/M3 of CC-CRAWL-0040: Enter must never click a button the gate
    did not judge). A container with a password control is never an Enter container
    found by its listener. An element that is itself an icon (`mat-icon`,
    `.material-icons`, `material-symbols`) is judged with its text as a glyph, so the
    glyph rules apply to it (review M2). An Enter form passes the same gate; it is
    submitted only on a named route, inside the reveal window (G1), by pressing Enter in
    `enter_id` after the page re-reads its name, finds it unchanged and finds no default
    button in its form (`_press_enter`, `spa.CONTROL_NAME_JS`; the window is lifted for
    that one press, W1), counted `forms_submitted_enter`; with no route named it is not
    submittable (it has no label to vet).
  - **Refused** (`spa.form_refusal`, the one gate): a route not named when routes are
    named (whole-route comparison); a destructive, settings-like (`formnav.settings_word`)
    or transaction (`core.urls.transaction_reason`) route, button label or action -- a
    button is judged on its text with only icon-**ligature** elements' text removed
    (`mat-icon`, `.material-icons`, `material-symbols`: a glyph name; never
    `aria-hidden` text, which is real text; an icon-only button with no aria-label
    keeps its raw text) **and** on its `aria-label` / `title`, refused when either is,
    and refused when a ligature names a destructive glyph (`spa.DESTRUCTIVE_GLYPHS`:
    `delete`, `logout`, …; CC-CRAWL-0019); a
    destructive or settings-like control name; a form with `<input type=file>` (a stated
    gap); a credential-change form (`store_adapter.credential_change_reason`); a form
    whose only typed input is a one-time code (2FA/TOTP). *(Superseded, CC-CRAWL-0033,
    D71: a CAPTCHA form is no longer refused; CC-CRAWL-0023 had added
    `spa.captcha_reason`.)* The destructive, transaction and credential-change parts
    follow `core.sendpolicy` (FR-CORE-45: each can be turned off for a lab run);
    `form_refusal(strict=True)` keeps them for the login flow. Labels, control names and options are
    judged as **texts** (`core.urls.text_destructive_reason`), never by embedding them
    in a URL, where a `#` hid the rest (BUG-0131).
  - **Sessions.** A form with a password input is submitted only in a fresh
    unauthenticated browser context (same browser, so the same launch arguments; the
    same guard and scope), closed afterwards. In an **authenticated** crawl a bare
    `--submit-spa-forms` submits only there; a form is submitted in the crawl's own
    authenticated context only when its route is named. After each such submission the
    crawl's session is re-checked (every injected cookie still holds its value, and the
    session manager's `verify_live`); on loss, or when it cannot be verified, submitting
    stops for the rest of the crawl and the reason is reported. The submission counts
    and whether submitting stopped (`submit_stopped`) are stored in `crawl_stats`.
  - Stated risk: a submission changes lab state (a feedback row, a failed login, a
    registration attempt with filler data). Lab only, default off.

- **FR-CRAWL-14 (the crawl adopts a browser session; session headers through the route,
  CC-CRAWL-0022)**
  - **Order.** An authenticated Playwright crawl ensures its session (FR-CRAWL-5)
    **before** its browser context opens, so a browser login (FR-SESS-19) has closed its
    own context first.
  - **Adoption.** The crawl context is created with the session's `browser_state`
    (`browser.new_context(storage_state=...)`) filtered to in-scope origins
    (`browserlogin.filter_storage_state`: a localStorage origin that passes the crawl's
    `_in_scope`; a cookie whose domain matches an in-scope start/base URL's host), plus
    the session's own cookies (`add_cookies`, origin root).
  - **Headers.** The session's headers (a bearer) are added by the crawl context's
    guarded route only: `route.fetch(headers=)` after `in_scope` passes, and on each
    fetched redirect hop only when that hop is in scope; only to the session's own
    origins *(CC-CRAWL-0026, FR-SESS-20, BUG-0134; before: its own host)* (loopback
    aliases one origin, another port another app), and over https when the session is
    https-only (`browserauth.header_scope_for`).
  - **Cookies withheld from another origin** *(CC-CRAWL-0026, FR-SESS-20).* Browser
    cookies are port-agnostic (RFC 6265 §8.5), and an external crawl's scope is its
    host on every port (BUG-0050). In the crawl's authenticated context
    (`BrowserSession.cookie_scope`, the header-scope predicate), for an in-scope origin
    outside the session's *(review round 1, R1/R2, CC-CRAWL-0026 amendment)*:
    - every **document** (a navigation, top-level or frame, and a redirect landing
      there) is aborted with ERR_ABORTED (`"aborted"`: the page stays, no error page;
      review round 2 T1) and every **WebSocket** is never connected: such a page is
      recorded as skipped (`skipped_other_origin`, its reason naming the kind: "crawl that
      origin separately, or --auth-origin"). A page navigation whose own target or
      redirect landing was withheld, or whose main frame committed on an **in-scope**
      origin outside the session's, extracts nothing and has no static fallback (an
      out-of-scope commit is BUG-0123's scope abort, counted in `skipped_out_of_scope`;
      review round 3, V2); a script-initiated
      navigation away leaves the page extracted normally;
    - every other request there, and every hop, is fetched through one cookie-less
      request context per guard (`navguard.guard_page(isolated_request=)`, the spider's
      `pw.request.new_context()`, made once when the guard is built and disposed at the
      end), each fetch with an explicit empty `Cookie` (that context's own jar is never
      sent; review round 3, V1), and fulfilled with `Set-Cookie` removed, so that origin
      neither receives nor writes a cookie;
    - the selector-form API client drops the jar's cookies for such an action.
    Each is counted (`session_out_of_origin`) and summarised at the end of the crawl.
    `fuzzlab crawl --auth-origin ORIGIN` (repeatable; a bare, in-scope origin, else a
    usage error) makes an origin one of the session's (FR-SESS-20). Never `set_extra_http_headers` or a browser
    context's `extra_http_headers` (an AST guard over `fuzzlab/`). An unauthenticated
    submission context gets none. The selector-form API client sends them only when the
    action passes the same header scope. The auditor's browser (CC-AUD-0038) and the M6
    executor's storage headers (CC-FUZZ-0076) use the same mechanism.
  - **Session check.** After each authenticated submission (FR-CRAWL-13), besides the
    injected credential cookies (since CC-CRAWL-0025, BUG-0132: `session.manager.
    credential_cookie` decides, the same predicate as the corrupted arm. Every
    login-response cookie counts, and so does a jar cookie the app's JS set when it
    copies the token or looks like an identifier, e.g. Juice Shop's `token`; an ambient
    jar cookie does not, `BrowserSession.checked_cookies`). A credential jar cookie may
    rotate the way a localStorage entry may: a new non-empty, identifier-like value is
    re-adopted, while cleared, empty, `"null"` or `"undefined"` is a loss. A
    login-response cookie must keep its value. Then `verify_live` (a browser login's
    protected probe) runs, and each
    adopted localStorage entry must still hold its value, read with `page.evaluate` on
    an open page of its origin; no such page, a read failure, or an entry cleared or set
    to an empty, `"null"`, `"undefined"` or non-identifier value is a loss (fail closed)
    and stops submitting with the reason. An entry changed to another non-empty,
    identifier-like value (`core.redaction.looks_like_identifier`) is a token rotation:
    re-adopted, and `verify_live` still has to pass (review round 1, B-S3).
  - Residual: the adopted localStorage is not refreshed after a re-login during the
    crawl (stateless JWTs stay valid; a revoked one is caught by the session check).
  - Residuals (review round 1, reviewer B):
    - a rotation lasts only as long as the manager's token: `verify_live` still probes
      with the manager's original token, so once that expires the crawl stops submitting
      (fails closed);
    - a logout that installs a fresh anonymous identifier-like token reads as a rotation;
      if `verify_live` with the manager's token still passes, the crawl believes the
      browser is authenticated (a coverage cost, never a safety one).

- **FR-CRAWL-15 (constraint-aware SPA form filling, CC-CRAWL-0023, forms phase 4, G1)**
  - **When.** Only for a form that passed `spa.form_refusal` on a
    route the operator **named** with `--submit-spa-forms ROUTE …`, in the crawl's own
    context or the fresh unauthenticated one. Entirely inside the reveal window
    (FR-CRAWL-16, W1): the existing fill, every G1 interaction and the checks run with
    its write block on; only `spa.click_vetted`'s final vetted click lifts it, for that
    click and its settle only (`before_click`; the lift is cleared when the submission
    ends, a click that raised included -- review B-M1), and the route is then closed and
    reloaded inside the window.
    A bare `--submit-spa-forms` (no route named) fills as before, without G1.
  - **Signals.** Per control (`spa.G1_READ_JS`): `type`, `required`, `min`, `max`,
    `step`, `minlength`, `maxlength`, `pattern`; invalid by `validity`,
    `aria-invalid`, Angular's `ng-invalid` (on the control or its mat-checkbox /
    mat-radio-group / mat-slider / mat-select host) or `mat-form-field-invalid`. Stated
    false negative: custom async validators (the form is then reported still invalid).
  - **The ladder (G1a).** At most `spa.G1_MAX_ATTEMPTS` (6) values per invalid control,
    keeping the first that makes it valid (`spa.g1_candidates`): a number / range in
    `[min, max]` on its step grid (default 1); a text fitted into `[minlength,
    maxlength]`; for a `pattern`, generated candidates (digits of the pattern's
    quantifier lengths, letters, e-mail, URL, phone) that the page's own
    `RegExp('^(?:' + pattern + ')$')` (flag `v`, else `u`) must accept, tested in a
    dedicated worker terminated after `spa.G1_PATTERN_TIMEOUT_MS` (no verdict, no
    candidate); with no explicit constraint, the typed ladder by name hint
    (phone/mobile → 10 digits, zip/postal → 5 digits, quantity/amount → 1, year →
    2000) or filler variants. Every value is a filler or a ladder value: repeated or
    ascending digits of at most 15 digits, the `fuzzlab` text padded with `x` or cut
    to a prefix, two case variants, the year 2000 — recognised by
    `store_adapter.is_filler` (the single source, `is_ladder_value`), never
    identifier-like. Stated gap: a grid or pattern with no ladder value (e.g. `[10, 20]`
    step 5, `[A-Z]{3}`) is unsatisfiable.
  - **Selects, radios, checkboxes, sliders.** A native `<select>` gets its first
    non-empty option (`select_option`); a mat-select (`role=combobox`, reported by
    `FORMS_JS` as kind `select` with tag `custom-select`) is opened by a click and its
    first non-empty option clicked (not a submission); a radio group its first option
    whose label passes the gate; a required checkbox is checked by its own `click()`; a
    range is set by the native value setter plus `input`/`change`.
  - **Refused (the form is not submittable, with the reason; G1b-G1e):** an invalid
    control whose name is sensitive (`is_sensitive_name`, which now names card security
    codes, CC-CORE-0052), credential-like (`is_credential_name`) or a one-time code
    (`spa._G1_OTP_TOKENS`; a bare `code` token only as the whole name, so `zipCode`
    stays fillable) is never filled (G1b); a select, mat-select or radio whose name is an
    object selector (`store_adapter._object_selector`, or `id`), whose option values or
    texts look like identifiers (`is_identifier_value`, `looks_like_identifier`), hold
    a run of 4 digits, or are numbers that are not their own text (a record key), or
    whose chosen option fails the label gate (G1c, `spa.select_refusal`); a required
    checkbox whose label (text, `aria-label`, associated `<label>`, mat-checkbox text)
    is empty, fails the label gate (inflections folded: `deleted` → `delete`) or names a
    subscription / default / remember-me (`spa.SUBSCRIPTION_WORDS`) (G1d,
    `spa.checkbox_refusal`). *(G1e superseded, CC-CRAWL-0033, D71: a CAPTCHA form is
    filled and submitted like any other form; no CAPTCHA is solved, and the app's
    answer to a wrong one is recorded like any other response. `FORMS_JS` still
    reports a container's hints and a canvas challenge; nothing refuses on them.)*
  - **Outcome.** The button enabled → `click_vetted` as before; still disabled →
    `forms_not_submittable` with "invalid after N attempts: <control names>" and
    `g1_forms_unsatisfiable`. Counts `g1_controls_filled`, `g1_forms_unsatisfiable`
    (persisted in `crawl_stats`). After a submission in the crawl's authenticated
    context the existing session check runs (client-side and `verify_live`).

- **FR-CRAWL-16 (reveal navigation and the reveal window, CC-CRAWL-0024, forms phase 4,
  G2)**
  - **The reveal window (W1).** From just before a reveal click (or the first G1
    interaction, FR-CRAWL-15) until after the close: `Escape`, popups opened in the
    window closed, the route reloaded (a GET navigation the window lets through for its
    own context and that URL only; a dialog's timers die with it) and a final quiet
    period (`_quiesce`: `_settle` — nothing in flight (realtime transports and event streams not counted, CC-CRAWL-0035: they stay open by design and are held or blocked by the window anyway), three quiet 100 ms polls — then
    a driver round trip that flushes pending events). Only `click_vetted`'s final vetted
    submission of a named-route form lifts it, for that click and its settle; the lift
    is cleared when that submission ends, even if its click raised (review B-M1). The
    own-reload exemption matches the exact URL (scheme, host, port, path and query,
    `spider._nav_key`), never the path alone, and a redirect hop of a navigation is a
    navigation too (review A-S2). If the close fails, every page the window opened is
    closed and the route's page goes to `about:blank` before the window is lifted
    (review A-S1).
  - **What it lets through (W2, `spa.window_request_refusal`, on every request of every
    context of the crawl, and on each redirect hop):** GET and HEAD only, any other
    method aborted whatever its destination; every navigation request aborted
    (`ERR_ABORTED`, so the page stays) and, for a GET/HEAD navigation, its target queued
    through the normal queue gates (scope, the destructive rule — a logout is refused —
    not visited, depth); a refused **non-GET** navigation (an auto-submitted form) is a
    blocked write (`reveal_writes_blocked`), never a page: its target is not queued, so
    it is never requested later as a GET (CC-CRAWL-0029, one rule with FR-CRAWL-17's
    query window). *(Superseded by D72, CC-CRAWL-0042: a non-navigation GET goes through
    whatever its words; the text that follows describes the D71 rule.)* A
    GET refused when destructive (also by its SPA fragment), a transaction
    (`transaction_reason`, CC-CORE-0045), or with a credential token
    (`CREDENTIAL_TOKENS`, path and query names) or an explicit account-**action** token
    (`browserlogin.ACCOUNT_PATH_TOKENS`: register, signup, password, reset, change …,
    or `sign up`; path and query) -- not the users / accounts collection rule, so the
    app's own identity check (Juice Shop's `/rest/user/whoami`) passes and the app
    does not log itself out (review A-S3). Residual: an opaque GET with a side effect
    and none of those words.
  - **WebSockets (W3).** An in-scope socket goes through a forwarding handler
    (`navguard.make_ws_handler(hold=, on_drop=)`: `connect_to_server()`, then each
    page-to-server message forwarded with `send` only while the window is closed,
    dropped and counted `reveal_ws_dropped` while it is open; server-to-page messages
    and closes as Playwright forwards them).
  - **Candidates (G2a, `spa.REVEAL_JS`).** Popup / toggle announcers
    (`[aria-haspopup]`, mat-menu triggers, `[aria-expanded=false]`, buttons with
    `aria-controls`, sidenav toggles by whole label token or a `menu` glyph), clicked
    through `click_vetted`; cards / list items (`mat-card`, `[role=listitem]`,
    `[role=button]`, `mat-grid-tile`, `mat-list-item`) only when the element itself is
    interactive (role=button, a tabindex, an `onclick`, a pointer cursor, or *(CC-CRAWL-0038)*
    a click listener the listener registry recorded), has no interactive descendant, and
    its whole text (at most `spa.MAX_CARD_TEXT` characters, longer is refused) passes
    the gate, dispatched by the element's own `el.click()` after its labels are read
    again, never a coordinate click. Never a link, a select-like control, a disabled
    element, or an element inside a form (unless a `type=button` button). Each once per
    (route, kind, label signature); cards at most `spa.MAX_CARDS_PER_SIGNATURE` (3) per
    (route, structural signature); at most `spa.MAX_REVEALS_PER_PAGE` (6) per page and
    `spa.MAX_REVEALS` (60) per crawl (`reveals_over_cap`). *(CC-CRAWL-0038:)* any other
    element the registry saw get a click listener (a framework binding with no role or
    class) is a card under the same rules (an element that is itself an icon is judged by
    its glyph, CC-CRAWL-0040), unless it is a button, link, label, option or
    summary, or sits within three levels of a typed control (a form-like container's
    submitter, which FR-CRAWL-13 submits, never a reveal).
  - *(G2d superseded for reveals by D72, CC-CRAWL-0042: `spa.reveal_refusal` refuses
    nothing -- a reveal click is a visit whose writes the window holds; `label_refusal`
    still gates G1's select options and checkboxes, on the write path. CC-CRAWL-0044: a
    destructive-looking candidate or menu item (`spa.reveal_looks_destructive`) is
    clicked at the end of the crawl, under the same caps, so a logout cannot stop the
    reveals and query loads after it (W4/S10).)*
  - **The label gate (G2d, `spa.reveal_refusal` / `spa.label_refusal`):** destructive
    (`core.urls.text_destructive_reason`, inflections folded), settings-like,
    transaction or account words in the text or aria-label; any
    `spa.DESTRUCTIVE_GLYPHS` glyph (now with `exit_to_app`); no label at all. A form's
    submitter is judged on its text and aria-label first for a `spa.TEXT_FIRST_GLYPHS`
    glyph (`exit_to_app`: Juice Shop's LOGIN button stays submittable, FR-SESS-19), and a
    glyph-only one is refused (`spa.submitter_glyph`).
  - **After a click.** Settle, then collect: new `a[href]` targets, a changed page URL
    (a same-document route change) and the navigations the window aborted, all queued
    with `source = 'reveal'` through the normal gates (`revealed_links`,
    `reveal_navigations_captured`); scripts a reveal loaded are scanned for routes;
    newly visible forms are filed (G2e). Revealed menu items (G2b, `role=menuitem` and
    mat-menu items without an `href`) that pass the gate are clicked inside the window,
    each after a reload and a re-click of the trigger (at most `spa.MAX_MENU_ITEMS`);
    one that fails it is never clicked; a link item is a link. Close (G2c): `Escape`,
    then the reload — never a dialog's own Cancel / Close button. When the window
    aborted anything during the close, the page is reloaded once more outside it (a
    page visit, as the crawl makes), so the next reveal sees the app's normal state.
  - **Revealed forms (G2e).** Filed in the spider table `revealed_forms` (route,
    `spa.form_signature`, redacted page URL, `submitted`) and in the crawl report; a
    real `<form>` also through the phase 1/2 record (`form_record`: its own action and
    method, never relocated, BUG-0115), so the importer applies its existing rules.
    Never imported as points otherwise. A revealed form is submitted only on a route
    named with `--submit-spa-forms`, under FR-CRAWL-13's gate and G1, in the crawl's own
    context, at most one click **attempt** per reveal (a click that raised included:
    nothing more is done in that reveal, review B-M1), never a password form (those are
    submitted only in a fresh context, which a reveal cannot reproduce: a stated gap).
  - **The session after a reveal (W4, authenticated crawls).** After every reveal the
    client-side check (each injected cookie and adopted localStorage entry, no network;
    `_client_session_intact`), plus `verify_live` when the window aborted anything. On a
    loss: reveals stop on that route, the adopted browser state is re-adopted once (the
    session's cookies, its browser login's cookies, the localStorage entries as
    adopted, then a reload; it holds only if the client-side check **and** `verify_live`,
    when the session manager has one, pass -- review A-N1) and the crawl goes on; a
    second loss, or a re-adoption that does not hold (which also stops submitting),
    stops reveals for the crawl (`reveals_stopped`, reported). Counted
    `session_losses_after_reveal`.
  - **Switch.** On by default in the Playwright engine (`--no-reveal` turns it off);
    never in the static engine. Reveals run in **authenticated** crawls too, in the
    crawl's own context: the safety basis there is the window (nothing is written,
    navigated or sent over a WebSocket while it is open) plus W4's session check after
    every reveal (review A-N2).
  - **Counts** (`crawl_stats`, PA-0110): `reveals_clicked`, `reveals_refused`,
    `reveals_over_cap`, `reveal_writes_blocked` (every write or side-effect GET the
    window aborted, G1's included), `reveal_ws_dropped`, `reveal_navigations_captured`,
    `revealed_links`, `revealed_forms`, `session_losses_after_reveal`, and
    `reveals_stopped` (0/1).
  - Residuals: an opaque side-effect GET; a request issued in the last instant before
    the window lifts whose route callback the driver dispatches after it (narrowed by
    the flush round trip); a card clickable only through an `addEventListener` handler
    with no pointer cursor is not seen; a card with an interactive descendant (Juice
    Shop's product card with "Add to basket" while logged in) is not one target;
    dropping page-to-server WebSocket frames inside the window can split a multi-frame
    message (a socket.io binary event, an engine.io pong), so the app's socket may
    desync or reconnect after a reveal -- a coverage effect, never a safety one (review
    A-N2, B).

- **FR-CRAWL-17 (SPA route query parameters, CC-CRAWL-0027, forms phase 5)** In the
  Playwright engine, on with SPA routes (`--no-spa-routes` turns both off;
  `--no-spa-query` / `LocalSpider(spa_query=False)` this alone). A route whose view reads a query
  parameter (Juice Shop's `#/track-result?id=`) is crawled **with** that parameter, so
  the importer makes it a point:
  - **The scan (Q1/Q2).** `spa.scan_script` is the one call per already-loaded
    same-origin script (FR-CRAWL-12's caps): routes and `spa.scan_query_params`.
    **Paired** (route, names): Angular `navigate([`/r`], {queryParams: {id: t}})` (an
    all-literal array, elements joined with `/`) and `navigateByUrl("/r?a=")`, Vue `push({path: '/r', query: {..}})` /
    `replace`, React literals `navigate("/r?a=")`, `<Link to="/r?a=">`,
    `(Link,{to:"/r?a="})`. **Unpaired** names: `queryParams.x`, `queryParams["x"]`,
    `queryParamMap.get("x")`, `searchParams.get("x")`, `URLSearchParams(..).get("x")`,
    `$route.query.x` / `route.query.x`, and a `queryParams: {..}` object outside a
    `navigate` call (never as part of a longer name, `myqueryParams:`); also an empty
    or lone non-literal route array, a navigation `relativeTo` another route, and a
    route with a `.` / `..` segment (relative: dropped at the scan, so no pair is
    counted that `classify_route` would refuse later). Never a bare `get(` or `query`. A multi-element route array with any non-literal element is a dynamic
    segment: refused, its names dropped, no element seeded alone. A non-literal
    `queryParams` value is skipped (counted), `{}` is nothing. Names: ASCII identifier
    characters, at most 64, never an Observable/ParamMap member (`spa.QUERY_MEMBERS`) or
    a name followed by `(`; at most 50 per script; a sensitive name
    (`core.redaction.is_sensitive_name`) is dropped and counted by class only; a quoted
    name that is not identifier-shaped (`'a-b'`) is dropped and counted (`not
    identifier-shaped`). **The bound** (PA-0095, PA-0135): each anchor kind is searched
    with `str.find` from a position that only moves forward (together at most one pass
    over the body per kind), each window ends at `min(anchor + 512, the next anchor of
    the same kind, the end of the call)` and is read only inside it, and every
    Python-level step of the walker counts against a per-script budget of 2,000,000
    steps (`spa.MAX_QUERY_STEPS`; when spent, the scan stops and `spa_query_step_cap`
    counts it). A cheap noise anchor costs O(1) steps, so it never hides a later real one.
    The scan's operation counts (`QueryScan.steps`, `.scanned`; `spa.StepCounter`) are
    what its complexity tests assert.
  - **Seeds (Q3).** Each paired route gets one crawl URL, queued after the bare routes
    with `source = 'spa-query'`: `route_url(...)?a=fuzzlab&…` (the text filler), a
    redirect-ish name (a whole token, or the whole name, in the one shared open-redirect
    name set, `core.urls.REDIRECT_PARAMS`, FR-CORE-39) set to `/` instead -- hygiene:
    the guard is the window, which aborts every navigation a seed or probe load makes.
    PA-0003 tension, stated: the auditor's rules-data `R-OPEN-REDIRECT` `name_regex` is
    a second, regex-shaped list (detection is out of this requirement's scope). A route
    with a `.` or `..` segment is not a route (`classify_route`). The seed passes
    `classify_route`, `route_destructive_reason`, `spa.window_request_refusal` as a GET
    on the URL and on the route fragment's own path and query, scope and the visit key.
  - **Every seed and probe load runs inside the reveal window (Q4)** (FR-CRAWL-16's
    W2/W3: non-GET and W2-word GETs aborted, navigations aborted and queued through the
    normal gates, WebSocket messages held), its own navigation exempt only until it has
    settled; it leaves for `about:blank` inside the window (never a reload, which would
    replay the load's on-load code). A seed neither reveals nor submits. Counted
    `spa_query_writes_blocked`. M6's own fuzz loads are unchanged (outside this window),
    so a seed is stored with `source = 'spa-query-writes'`, which the importer never
    makes a point (`write_seed_skipped`; CC-AUD-0041), and is promoted to `'spa-query'`
    only after its window **closed cleanly with no write** (fail closed: a crawl that
    stops in between leaves it a page). A **write** in a query window is every refused
    non-GET/HEAD request, a navigation included (an auto-submitted form: its target is
    never queued as a GET), every held page-to-server WebSocket message, every
    non-navigation GET the window's word rules refused (a transaction or account GET),
    and every GET navigation (a redirect hop included) to a target those word rules
    refuse, which is never queued (P2);
    a seed that wrote stays a write seed (`spa_query_write_seeds`): fuzzing it would send
    that write unguarded (review A-M1, round 2 U1). No URL a query window blocked is
    queued from the load's request list (it would be fetched outside the window);
    blocked includes every request of the page that **failed** while the window was
    open -- a GET whose redirect hop the window refused fails, so it is never fetched
    again outside the window where its hop would run (Y1). A window that did not close
    cleanly is counted (`spa_query_unclean_windows`); its seed stays a write seed, as
    does a seed whose visit failed (all counted in `spa_query_write_seeds`). A seed's
    load that fails is never re-sent as a static request (no fallback outside the
    window); a seed whose document landed on another origin than the session's
    (FR-SESS-20, `SessionWithheld`) is filed as a write seed, and such a probe records
    nothing (merge with origin-scoped sessions, M3/M4). Each seed and probe load starts
    from `about:blank`, outside its window, so the previous page's timers and requests
    are never counted as the load's writes or XHRs (M7). **A hash-route seed or probe**
    then loads its bare route (`#/r`) fresh and lets it settle, still outside the window,
    so the app shell's start-up writes are sent there, and makes the same-document hash
    change into `#/r?a=…` inside the window (P1(a)). A bare route whose load did not
    complete (a refused script navigation stopped it, BUG-0138) is refused, "bare route
    did not load" (`spa_query_refused`): the window is never entered and the seed is
    neither stored nor seeded (S3). `_leave`'s commit is the Navigation result's: a
    navigation that committed, while the page still shows its own document. **The write baseline (P1(b)):**
    every load of a **bare** route outside a window (a hash route whose fragment has no
    query, or a URL with no query; never a crawled link with a query of its own, B1)
    records, by (method, path) (`WS` for a WebSocket message), the writes a query window
    would have counted, under that route; in a seed's window a write that is in its
    route's baseline is blocked all the same but does not demote the seed
    (`spa_query_baseline_writes`) -- unless it carries the load's own query values (the
    seed's text filler, or the probe's markers) in its URL (also percent-decoded), its
    body (read by the page's `request` event while the window is open, whichever of the
    two events comes first) or its WebSocket message text: such a write always counts
    (B2). This covers the shell's
    periodic writes (Juice Shop's socket.io polling and WebSocket pings) and a
    history-mode seed, which is a full load inside its window. *(CC-CRAWL-0034, narrowed
    by CC-CRAWL-0039:)* an engine.io **control** packet on a transport WebSocket
    (`spa.is_transport_url`; `spa.engineio_control`: ping `2`, pong `3`, upgrade `5`,
    noop `6`, `2probe` / `3probe`, a bare socket.io connect or disconnect `40` / `41`
    with an optional namespace) is baseline whether or not the bare route's load
    happened to send one (a periodic ping is timing), still blocked. A socket.io event
    (`42[...]`), an auth connect, a polling POST and a write carrying the load's values
    are judged by the baseline and B2 as before. A seed's forms are stored
    only when it is promoted, and never enumerated: a form its query rendered and
    auto-submitted is the write its window blocked. A request still in flight when
    the load is read is not queued from its request list either (M8). `_leave` reads
    `page.url` as the seed's same-document navigation only when **this** load committed
    (its `goto` returned, with a response or as a same-document change, P4; its
    navigation was this load's and the page is a document of the app, not
    `about:blank` after a failed load nor an error page; M6). Follow-up, its own design gate (a CC-FUZZ
    change): run M6's loads of such a route inside a write-blocking window instead, so
    the route stays fuzzable. **In an authenticated crawl** each seed and probe window
    ends with the client-side session check (`_client_session_intact`, on the load's own
    page, before it leaves) -- for a load that did not commit (the page is
    `about:blank`, X1) the cookie half and `verify_live` instead, since that page has no
    localStorage of the app (M7) -- its cookie half again after the window's quiet period, and
    `verify_live` when the window blocked a write (W4 parity) -- also on the window's
    failure path, after its `about:blank` attempt; the verdict is preset to a
    loss and any failure of a check is a loss (fail closed); on a loss seed and probe
    loads stop for the crawl (no probe is planned after it)
    (`spa_query_stopped`, `spa_query_session_losses`; later ones refused `session lost`)
    and the session is re-adopted once on the start page, as W4 does -- a re-adoption
    that does not hold stops reveals and submissions too.
  - **The observation probe (Q5).** Unpaired names are attached to a route only by
    observation: once the bare routes are visited, at most 40 rendered routes are loaded
    once each with all (at most 12) unpaired names, each with a **fresh** marker minted
    for that load (`fzq` + 10 lower-case letters: word-shaped, never
    `looks_like_identifier`); a redirect-ish name carries `/`. A name is kept for the
    route only when **this** load's marker is seen, with non-alphanumeric boundaries,
    in the rendered DOM (text, attributes, control values) or in a request the load
    made (its URL or body, seen by the page's `request` event while the probe is open),
    never from the store. Never evidence: a request the window or the guard **blocked**
    (a name whose only evidence is a blocked request is not kept, review A-M1); a
    string that also carries another of the load's markers; `<name>=` syntax of a probed
    name in a DOM string or a body, or in a request URL that is a copy of the page's own
    (its path is the document's, or it carries the fragment route) -- an app's API
    forwarding `?q=<marker>` keeps `q` (review A-S3). Kept names are seeded as above.
    **A probe load records nothing**: no page, link, XHR URL, form or capture; a guard
    abort during a probe is never recorded as a skipped destructive URL, and a URL
    withheld from the session while a probe is open (another origin, FR-SESS-20) is that
    probe's blocked evidence only -- never in `skipped_other_origin` nor the log (M1); a
    probe route itself on another origin is never minted nor loaded (M2); a failed
    probe's log line, and the browser guard's URL-bearing log lines, are scrubbed of
    markers (M5, P4). **No row ever
    carries a marker**: the spider's storage boundary (`mark_visited`'s URL, title and
    text; captured requests; forms; revealed forms) replaces any whole-token marker with
    `spa.MARKER_PLACEHOLDER` (`spa.scrub_markers`), so one an app persisted and replays
    on a later page is never stored (review A-S4).
  - **Points (Q6).** A hash-mode seed becomes a `fragment` point (`_import_route_query`):
    a DOM point, confirmed only with `--browser` (M6). The open-redirect rules
    (`R-OPEN-REDIRECT`, `R-OPEN-REDIRECT-VALUE`) exclude `fragment`, so these are XSS/DOM
    points only. A GET XHR a seed's load sends with the filler in its query becomes a
    `query` point (the XHR link set); a history-mode seed is a `query` point itself.
  - **Counts (Q7; `crawl_stats`, PA-0110):** `spa_query_pairs`, `spa_query_unpaired`,
    `spa_query_probe_loads`, `spa_query_kept`, `spa_query_refused` (and by reason,
    `spa_query_refused[<reason>]`), `spa_query_writes_blocked`,
    `spa_query_marker_in_path`, `spa_query_step_cap`, `spa_query_seeded`,
    `spa_query_seeded_fragment`, `spa_query_write_seeds`, `spa_query_session_losses`,
    `spa_query_unclean_windows`, `spa_query_baseline_writes`, `spa_query_stopped` (0/1); the summary shows fragment seeds (`--browser` only)
    apart from history-mode ones.
  - Residuals: a hash route whose bare shell does not reach its load state within
    `timeout_ms` gets no seeds and no probes (refused, counted
    `spa_query_refused[bare route did not load]`; final merge review, reviewer A); a marker or filler in a request's **path** segment gives no point
    (counted `spa_query_marker_in_path`); fragment points need `--browser`; there is
    **no open-redirect coverage for fragment names**; a redirect-ish unpaired name is
    never kept (it carries `/`, no marker); a route whose load writes is a page, not a
    point, until the M6 follow-up above; a name seen only in a blocked request is not
    kept; requests from popups and WebSocket frames are not observed; a marker an app
    transforms (upper-cases, splits) is neither seen nor scrubbed; a destructive non-GET
    is aborted by the guard's destructive rule before the window is asked, so it is not
    counted as a write (the request is never sent either way); a crawled hash URL whose
    load writes (a link, not a seed) is still imported as a point until FR-FUZZ-50's
    M6 window; blocked requests are matched by URL (conservative: a completed GET to a
    URL also blocked as a POST is not evidence); for a hash route,
    `own_nav` admits the document path itself while the load settles (`_nav_key` drops
    the fragment), as the reveal window's own reload does; a route not in a route table
    is probed only if paired; names read through other APIs (a hand-rolled
    `location.search` parser, `useSearchParams()`) are not seen; **ordinary failures
    also block**: a seed whose visit failed for any reason (a timeout, a refused
    redirect hop, a network error) stays a page, never a point, like one that wrote
    (`spa_query_write_seeds`), and a failed probe keeps nothing; a seed's refused GET
    navigation or redirect hop that the word rules pass is queued through the normal
    gates (W2) and so possibly crawled later as a page; the write baseline is keyed by
    (method, path), so a write the query causes to the same path as one the shell makes
    on every load is not counted when it does not carry the query's value literally
    (the value transformed, hashed or split, or the write merely triggered by it), and
    a history-mode seed's write that the bare route's own loads never made (a start-up
    write that varies by path, or one the bare load did not reach before it settled)
    still demotes it; a bare-route load's late requests (after it settled, before the
    window opened) may be captured under the seed's URL (harmless: the window has not
    opened, so they are neither its writes nor its evidence); an app that reads a
    route's query only when it bootstraps (a full load), never on a hash change, shows
    a hash seed or probe nothing of it (P1(a)), so such a name is neither observed nor
    seeded. **Cost (P1, B-N3, A-N2):** a hash-route seed or probe costs an
    `about:blank`, a full load of its bare route and a same-document hash change (about
    two loads); a history-mode one, an `about:blank` and its own load. Each such load
    makes the app shell's start-up writes once more, for real (outside the window): on
    Juice Shop, one socket.io handshake per seed and per probe.

## 4. Non-functional requirements
- **NFR-CRAWL-safe** Deny-list destructive actions (delete/logout/reset); default
  to not clicking them. *(Superseded for visits by D72, CC-CRAWL-0042, owner
  2026-10-16:)* a **visit** -- a GET or HEAD link, route, redirect hop, subresource,
  script fetch, seed or probe load, or a reveal click (whose writes the window still
  holds) -- is never refused for its words (destructive, transaction, account,
  settings). A destructive-looking page is visited **last** (`LocalSpider._deferrable`,
  counted `pages_deferred`), never skipped. What follows still holds for **writes**
  (any method but GET/HEAD, form submissions) and for the login flow (``strict``);
  scope (FR-CRAWL-11) is unchanged. Stated consequences: bWAPP's `reset.php` (DROP
  DATABASE on GET) and `logout.php` are visited; a crawl that visits a logout page
  goes on without its session; a page whose script navigates to such a page is read as
  the page it landed on. *(Built CC-CRAWL-0011, BUG-0111:)* the one rule is
  `core.urls.destructive_reason` (FR-CORE-28). A destructive URL is never queued,
  never reached through a redirect (the static engine follows redirects by hand, each
  hop checked), and never requested by the browser (`navguard.guard_page` aborts
  navigations, scripts' fetch/XHR and subresources). The start URL is the operator's
  own input and is exempt. The auditor never re-fetches one from a spider DB, old or
  new. *(D71, CC-CRAWL-0033:)* `--allow-destructive-routes` turns this rule off for one
  lab run (FR-CORE-45); without it there is no opt-in. The login flow keeps it. *(CC-CRAWL-0013:)* the crawler
  POSTs only to operator-named selector forms (FR-CRAWL-8), never to a settings or
  destructive one. *(CC-CRAWL-0015, BUG-0123:)* **no request leaves the crawl scope**
  (FR-CRAWL-11), and the destructive rule covers every redirect hop, at each layer:
  the queue; static redirects (by hand); the browser (a context-wide route that walks
  redirect chains hop by hop, WebSockets routed, plus launch arguments that resolve
  nothing outside scope); and the API-request client (scope-checked, no redirects).
  *(CC-CRAWL-0028, BUG-0136:)* **how** a request is refused is one rule: every abort
  of a document request (a navigation, top-level or frame, and each of its redirect
  hops), whatever the reason -- scope, destructive, refused method or body, the reveal
  window, a withheld session, too many hops, an unfetchable request -- uses `"aborted"`
  (ERR_ABORTED: the current document survives, so a page whose script navigates to a
  refused URL keeps its content and links; `goto` of a refused target still raises);
  a subresource keeps the default code (`navguard._abort_code`). A refused navigation
  therefore looks to the page as if the click or script did nothing; it is visible
  only through the crawl's `skipped_*` records and its summary (review A-N1). *(BUG-0136
  review, X1:)* when the crawl's **own** `goto` fails (a refused target or redirect
  landing, a timeout, anything), `_fetch_rendered` first sends the page to
  `about:blank`, so the previous document, which ERR_ABORTED left alive, stops: its
  timers and fetches are never sent or captured under the URLs crawled next. Then the
  withheld check, `SessionWithheld` or the static fallback run as before.
  *(CC-CRAWL-0030, BUG-0138:)* **no guarded navigation waits for a load a refused
  navigation can cancel.** A script that navigates to a refused URL while the page is
  parsed stops the page's loading, so `domcontentloaded` never fires.
  - Every navigation of a guarded page goes through `navguard.navigate` / `reload`:
    wait for the commit (a refused own target still raises), then for the load state at
    most the caller's timeout, cut short 300 ms after a main-frame navigation fails.
    Only failures reported at or after this navigation's commit count, so a previous
    page's pending navigation, cancelled by this one, never cuts the wait (review Q1).
  - `networkidle` is waited for (`wait_for_state`) only after a completed load. The
    body text is read without waiting for a body.
  - A page whose load did not complete is read without a second request (review Q2).
    The source depends on which of three cases it is:
    - **superseded** (a refused script navigation stopped its parsing): from the HTML
      the browser received (`Navigation.html`, parsed as the static engine parses a
      page), with the DOM's links merged;
    - **merely slow** (it outlasted the wait): from its live DOM, JS-rendered text
      included, with the received HTML filling an empty text only;
    - **replaced** (a script navigation it allowed committed another document): from
      its own received HTML alone, never the other document's title, links or URL. A
      document is its origin, path and query (`core.urls.document_key`), so
      `/p?a=2` replaces `/p?a=1`.
    - The received HTML is the body the guard fulfilled for that main-frame document,
      kept per page, because the browser drops a replaced document's body.
    - Query probes and seeds (FR-CRAWL-17) take the same path.
  - A reveal's restore whose reload did not complete leaves for `about:blank` (review
    B-N1).
  - No other module of fuzzlab navigates a page or waits for a load state itself.
  - Enforced by (the abort code, per reason; BUG-0136): `navguard.make_route_handler` (`abort()`, `_abort_code`) — `tests/test_navigation_aborts.py::test_every_abort_reason_keeps_the_document_for_a_navigation`, `tests/test_navigation_aborts.py::test_a_script_navigation_out_of_scope_keeps_the_page_crawled`, `tests/test_navigation_aborts.py::test_a_script_navigation_to_a_destructive_url_is_a_visit`, `tests/test_navigation_aborts.py::test_goto_of_a_refused_target_still_raises_and_the_page_stays`, `tests/test_navigation_aborts.py::test_the_crawls_own_target_redirected_to_a_refused_url_raises_and_falls_back`, `tests/test_navigation_aborts.py::test_a_refused_post_form_submission_keeps_the_page_crawled`, `tests/test_navigation_aborts.py::test_a_refused_iframe_keeps_its_parent_crawled`
  - Enforced by (a failed load ends the previous document; BUG-0136 review X1): `LocalSpider._fetch_rendered` (`about:blank` before the fallback) — `tests/test_navigation_aborts.py::test_a_failed_load_ends_the_previous_document`
  - Enforced by (no navigation waits for a load a refused navigation cancelled; one helper; BUG-0138): `navguard.navigate` / `reload` / `wait_for_state` / `response_html`, `LocalSpider._goto_and_parse` — `tests/test_guarded_navigation.py::test_a_head_script_navigation_to_a_refused_url_is_not_waited_out`, `tests/test_guarded_navigation.py::test_a_slow_page_is_still_waited_for`, `tests/test_guarded_navigation.py::test_query_probe_and_seed_loads_are_not_waited_out`, `tests/test_guarded_navigation.py::test_every_guarded_navigation_goes_through_the_one_helper`, `tests/test_guarded_navigation.py::test_the_navigation_guard_catches_synthetic_offenders`, `tests/test_guarded_navigation.py::test_a_failure_reported_before_the_commit_never_cuts_the_wait`, `tests/test_guarded_navigation.py::test_a_previous_pages_pending_navigation_never_cuts_the_next_load`, `tests/test_guarded_navigation.py::test_a_merely_slow_page_keeps_its_rendered_text`, `tests/test_guarded_navigation.py::test_another_document_never_fills_this_urls_row`, `tests/test_guarded_navigation.py::test_a_same_path_document_with_another_query_never_fills_this_urls_row`
  - Enforced by (scope, per layer): `LocalSpider._in_scope`, `navguard.guard_page` / `make_route_handler` / `make_ws_handler` / `browser_launch_args` / `checked_api_request` — `tests/test_spider_scope.py::test_loopback_start_treats_aliases_as_one_host`, `tests/test_browser_scope.py::test_a_rendered_crawl_never_leaves_the_target_origin`, `tests/test_browser_scope.py::test_the_launch_args_alone_confine_an_unrouted_page_to_the_origin`, `tests/test_browser_scope.py::test_a_redirect_hop_out_of_scope_is_never_requested`, `tests/test_browser_scope.py::test_out_of_scope_requests_are_aborted_and_reported`, `tests/test_browser_scope.py::test_allow_never_lifts_scope`, `tests/test_browser_scope.py::test_websockets_are_scope_checked`, `tests/test_browser_scope.py::test_the_spiders_isolated_submit_refuses_an_out_of_scope_action`, `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`, `tests/test_browser_scope.py::test_the_browser_guard_catches_synthetic_offenders`, `tests/test_browser_scope.py::test_scope_is_checked_before_any_fetch`
  *(CC-CRAWL-0016/0017, forms phase 3:)* **a crawl never deletes**: a browser-initiated
  DELETE is aborted unless it comes from a submission on an operator-named route
  (FR-CRAWL-12); a destructive SPA route (by its fragment) is never visited; a SPA form
  is submitted only with `--submit-spa-forms`, never a destructive, settings,
  transaction, credential-change, 2FA-only or file form, a password form only in a fresh
  unauthenticated context, and in an authenticated crawl the crawl's own context only on
  a named route, stopping when the session is lost (FR-CRAWL-13).
  - Enforced by (DELETE and destructive SPA routes): `navguard.make_route_handler(method_refusal=)`, `LocalSpider._method_refusal`, `spa.classify_route`, `spa.route_destructive_reason` — `tests/test_spa_routes.py::test_the_guard_aborts_a_refused_method_before_any_fetch`, `tests/test_spa_routes.py::test_the_spider_refuses_a_delete_unless_a_named_route_submission_sends_it`, `tests/test_spa_capture.py::test_a_named_login_route_is_still_submitted_only_unauthenticated`, `tests/test_spa_routes.py::test_a_browser_initiated_delete_is_aborted_and_counted`, `tests/test_spa_routes.py::test_a_delete_is_sent_only_from_a_named_routes_submission`, `tests/test_spa_routes.py::test_routes_are_classified`, `tests/test_spa_routes.py::test_a_hash_route_is_destructive_by_its_fragment`, `tests/test_spa_routes.py::test_hash_routes_are_read_from_the_bundle_and_crawled_as_pages`, `tests/test_spa_routes.py::test_history_mode_routes_are_paths_under_the_base`
  - Enforced by (SPA form submission): `spa.form_refusal`, `LocalSpider._submit_spa_forms` / `_submit_anonymously` / `_session_intact` — `tests/test_spa_capture.py::test_submission_is_off_by_default`, `tests/test_spa_capture.py::test_each_refusal`, `tests/test_spa_capture.py::test_the_button_is_refused_on_its_text_or_its_aria_label`, `tests/test_spa_capture.py::test_icon_text_never_decides_a_button_label`, `tests/test_spa_capture.py::test_a_covered_button_is_still_clicked_exactly_once`, `tests/test_spa_capture.py::test_each_transaction_word_is_refused_on_the_route_and_on_the_label`, `tests/test_spa_capture.py::test_a_route_not_named_is_refused_when_routes_are_named`, `tests/test_spa_capture.py::test_bare_submission_in_an_anonymous_crawl`, `tests/test_spa_capture.py::test_a_password_form_is_submitted_only_in_a_fresh_unauthenticated_context`, `tests/test_spa_capture.py::test_a_named_login_route_is_still_submitted_only_unauthenticated`, `tests/test_spa_capture.py::test_an_authenticated_bare_flag_never_submits_in_the_crawls_context`, `tests/test_spa_capture.py::test_a_named_route_is_submitted_authenticated_and_session_loss_stops_it`, `tests/test_spa_capture.py::test_the_session_check_fails_closed`, `tests/test_spa_capture.py::test_submissions_are_capped_and_the_cap_is_reported`
  - Enforced by (scope of SPA traffic, both contexts): `tests/test_spa_capture.py::test_bare_submission_in_an_anonymous_crawl`, `tests/test_spa_routes.py::test_cross_origin_and_oversized_scripts_are_never_read`
  - Enforced by (no request body sent twice by the guard): `tests/test_browser_scope.py::test_a_redirected_post_navigation_is_submitted_once`
  - Enforced by (session headers only in scope, through the route; FR-CRAWL-14): `navguard.make_route_handler(headers=, header_scope=)`, `browserauth.header_scope_for` — `tests/test_browser_scope.py::test_session_headers_are_added_by_the_route_only_in_scope`, `tests/test_browser_scope.py::test_session_headers_ride_a_redirect_hop_only_when_it_is_in_scope`, `tests/test_browser_scope.py::test_no_browser_context_gets_session_headers_outside_the_route`, `tests/test_browser_scope.py::test_the_header_guard_catches_synthetic_offenders`, `tests/test_browserauth.py::test_bearer_session_headers_go_through_the_route_only`, `tests/test_browserauth.py::test_an_https_sessions_headers_never_go_over_http`
  - Enforced by (adopted browser session; FR-CRAWL-14): `browserlogin.filter_storage_state`, `LocalSpider._session_intact` — `tests/test_session_browser_login.py::test_storage_state_adoption_keeps_in_scope_origins_only`, `tests/test_session_browser_login.py::test_a_submission_that_clears_local_storage_stops_submitting`, `tests/test_session_browser_login.py::test_the_crawls_session_check_catches_a_revoked_token`, `tests/test_session_browser_login.py::test_a_cleared_token_still_stops_the_crawl_with_rotation_on`, `tests/test_session_browser_login.py::test_a_rotated_token_keeps_the_crawl_submitting`, `tests/test_session_browser_login.py::test_a_crawl_stops_when_only_the_token_cookie_is_deleted`, `tests/test_session_browser_login.py::test_a_rotated_credential_jar_cookie_is_readopted_and_a_cleared_one_is_a_loss`, `tests/test_session_browser_login.py::test_one_predicate_tells_credential_cookies_from_ambient_ones`
  *(CC-CRAWL-0023/0024, forms phase 4:)* **a reveal can only read**: from just before a
  reveal click or the first constraint-aware interaction until after the close, the
  reload and a quiet period, the route aborts every write and every navigation (its
  target queued through the normal gates) and side-effect GETs, and page-to-server
  WebSocket messages are dropped; only a named-route form's vetted final click lifts it;
  a revealed menu item, card or option whose label fails the gate is never clicked, a
  card with an interactive descendant is not one target, a dialog's own buttons are
  never clicked, and after a reveal in an authenticated crawl the session is checked
  (FR-CRAWL-15/16).
  - Enforced by (the reveal window, W1-W3): `navguard.make_route_handler(window=)` / `make_ws_handler(hold=)`, `spa.window_request_refusal`, `LocalSpider._window` / `_window_refusal` / `_restore` / `_quiesce` — `tests/test_forms_phase4.py::test_the_window_lets_only_safe_gets_through`, `tests/test_forms_phase4.py::test_a_refused_post_navigation_in_a_reveal_is_a_write_never_a_page`, `tests/test_forms_phase4.py::test_the_route_asks_the_window_before_any_fetch_and_keeps_the_page_on_navigation`, `tests/test_forms_phase4.py::test_the_window_is_asked_again_on_every_redirect_hop`, `tests/test_forms_phase4.py::test_the_websocket_forwarder_drops_page_messages_only_inside_the_window`, `tests/test_forms_phase4.py::test_w2_a_reveal_can_only_read`, `tests/test_forms_phase4.py::test_w2_a_menu_items_navigation_is_queued_never_sent_during_the_reveal`, `tests/test_forms_phase4.py::test_w3_a_websocket_message_in_the_window_is_dropped`, `tests/test_forms_phase4.py::test_w1_a_debounced_post_after_close_never_arrives`, `tests/test_forms_phase4.py::test_g1_a_selection_change_post_is_never_sent_before_the_submission`, `tests/test_forms_phase4.py::test_the_lift_covers_exactly_one_click_and_its_settle`, `tests/test_forms_phase4.py::test_a_click_that_raises_never_leaves_the_window_open`, `tests/test_forms_phase4.py::test_the_own_reload_exemption_matches_the_exact_url`, `tests/test_forms_phase4.py::test_a_redirect_after_the_own_reload_is_still_a_navigation`, `tests/test_forms_phase4.py::test_a_failed_close_still_closes_the_windows_popups`
  *(CC-CRAWL-0027, forms phase 5:)* **a query seed or probe load can only read**: each
  runs inside the reveal window (no write, navigation or WebSocket message reaches the
  app; it leaves for `about:blank` inside the window), a destructive, transaction,
  account-action or credential-bearing seed or probe URL is never loaded *(superseded by
  D72, CC-CRAWL-0042: `spa.query_url_refusal` refuses none for its words; a
  destructive-looking one is loaded last, and a GET such a load makes is a visit, not a
  write -- U1's "a word-refused GET is a write" and P2 are superseded)*, a
  redirect-ish name carries a same-origin `/`, a probe load records nothing, a seed
  whose load blocked a write is never a point (so M6 never replays that write outside a
  window), and in an authenticated crawl a session lost in a query load stops them
  (FR-CRAWL-17).
  - Enforced by (seed and probe loads, FR-CRAWL-17): `LocalSpider._window(query=)` / `_leave` / `_query_gate` and the crawl loop's store-suppression branch, `spa.query_url_refusal`, `spa.seed_url` — `tests/test_spa_query.py::test_a_seed_load_cannot_write`, `tests/test_spa_query.py::test_a_seeds_navigations_are_queued_never_followed_in_its_window`, `tests/test_spa_query.py::test_a_destructive_seed_is_never_visited_and_a_redirect_name_stays_on_origin`, `tests/test_spa_query.py::test_the_seed_gate_never_refuses_a_url_for_its_words`, `tests/test_spa_query.py::test_a_seed_gets_the_filler_and_a_redirect_name_gets_a_same_origin_path`, `tests/test_spa_query.py::test_no_stored_row_carries_a_marker`, `tests/test_spa_query.py::test_a_seed_that_blocked_a_write_is_never_a_point_and_m6_never_sends_it`, `tests/test_spa_query.py::test_a_session_lost_in_a_query_load_stops_query_loads`, `tests/test_spa_query.py::test_what_a_query_window_counts_as_a_write`, `tests/test_spa_query.py::test_a_held_websocket_message_is_a_write`, `tests/test_spa_query.py::test_a_seed_is_never_importable_until_its_window_closed_cleanly`, `tests/test_spa_query.py::test_a_session_check_that_raises_is_a_loss`, `tests/test_spa_query.py::test_a_slow_response_that_expires_the_session_cookie_is_a_loss`, `tests/test_spa_query.py::test_a_request_whose_redirect_hop_was_refused_is_never_fetched_again`, `tests/test_spa_query.py::test_the_session_is_rechecked_when_leaving_the_page_fails`, `tests/test_spa_query.py::test_a_withheld_url_while_a_probe_is_open_is_that_probes_blocked_evidence`, `tests/test_spa_query.py::test_a_probe_route_on_another_origin_is_never_minted_nor_loaded`, `tests/test_spa_query.py::test_an_authenticated_query_load_that_goes_to_another_origin_hands_it_nothing`, `tests/test_spa_query.py::test_a_seeds_leave_reads_the_page_only_when_its_load_committed`, `tests/test_spa_query.py::test_a_failed_seed_load_checks_the_cookies_and_the_server_not_local_storage`, `tests/test_spa_query.py::test_a_query_loads_request_in_flight_is_tracked_until_it_ends`, `tests/test_spa_query.py::test_a_seed_whose_own_redirect_is_refused_fails_and_the_crawl_goes_on`, `tests/test_spa_query.py::test_a_withheld_seed_is_a_write_seed_and_a_withheld_probe_records_nothing`, `tests/test_spa_query.py::test_a_shell_that_writes_on_every_load_still_gives_hash_points`, `tests/test_spa_query.py::test_the_baseline_is_what_a_load_outside_a_window_would_have_written`, `tests/test_spa_query.py::test_the_websocket_forwarder_reports_each_forwarded_message`, `tests/test_spa_query.py::test_the_guards_url_log_lines_never_carry_a_probe_marker`, `tests/test_spa_query.py::test_a_seeds_forms_are_stored_only_when_it_is_promoted`, `tests/test_spa_query.py::test_the_baseline_never_takes_a_query_caused_write_and_a_query_value_always_counts`, `tests/test_spa_query.py::test_a_write_carrying_the_loads_query_value_counts_on_a_baseline_endpoint`, `tests/test_spa_query.py::test_a_transport_control_packet_is_baseline_even_when_the_load_saw_none`, `tests/test_spa_query.py::test_what_an_engineio_control_packet_is`, `tests/test_spa_query.py::test_only_a_bare_routes_load_is_its_baseline`, `tests/test_spa_query.py::test_a_query_load_whose_bare_route_did_not_load_is_refused`, `tests/test_spa_query.py::test_a_load_that_committed_but_did_not_complete_is_committed`
  - Enforced by (the session after a reveal, W4): `LocalSpider._reveal_session_check` / `_client_session_intact` / `_readopt_session` — `tests/test_forms_phase4.py::test_w4_a_client_side_logout_is_readopted_then_a_second_loss_stops_reveals`
  - Enforced by (the reveal gate, G2a-G2d): `spa.reveal_refusal` / `label_refusal` / `submitter_glyph`, `spa.REVEAL_JS`, `LocalSpider._reveal_one` — `tests/test_forms_phase4.py::test_the_reveal_gate`, `tests/test_forms_phase4.py::test_g2b_menu_items_are_clicked_whatever_their_words`, `tests/test_forms_phase4.py::test_g2a_cards_are_clicked_on_the_element_capped_and_never_with_descendants`, `tests/test_forms_phase4.py::test_a_card_is_dispatched_on_the_element_never_by_a_coordinate_click`, `tests/test_forms_phase4.py::test_juice_shops_login_button_still_passes_with_exit_to_app_a_destructive_glyph`, `tests/test_forms_phase4.py::test_the_crawl_cap_on_reveals`, `tests/test_crawl_survey_options.py::test_listener_found_forms_are_submitted_on_named_routes_and_gated`, `tests/test_crawl_survey_options.py::test_an_enter_form_is_never_submitted_on_an_unnamed_route`, `tests/test_crawl_survey_options.py::test_the_listener_registry_records_without_changing_the_page`
  - Enforced by (constraint-aware filling, G1b-G1e): `spa.g1_sensitive` / `select_refusal` / `checkbox_refusal`, `LocalSpider._g1` — `tests/test_forms_phase4.py::test_g1_never_fills_a_sensitive_or_credential_control`, `tests/test_forms_phase4.py::test_select_refusal`, `tests/test_forms_phase4.py::test_checkbox_refusal`, `tests/test_forms_phase4.py::test_a_captcha_form_is_not_refused`, `tests/test_forms_phase4.py::test_g1_a_saved_card_picker_is_never_chosen_in`, `tests/test_forms_phase4.py::test_g1_a_delete_account_checkbox_is_never_checked_and_never_submitted`, `tests/test_forms_phase4.py::test_g1_a_captcha_form_is_submitted`, `tests/test_forms_phase4.py::test_a_revealed_form_is_submitted_only_on_a_named_route`
  - Enforced by (labels judged as texts, BUG-0131): `core.urls.text_destructive_reason` — `tests/test_forms_phase4.py::test_a_hash_in_a_label_name_value_or_option_hides_nothing`, `tests/test_forms_phase4.py::test_no_text_is_judged_through_a_url`, `tests/test_forms_phase4.py::test_the_text_guard_catches_synthetic_offenders`
  - Enforced by (destructive redirect hops in the browser): `tests/test_browser_scope.py::test_a_redirect_hop_to_a_destructive_url_is_never_requested_by_a_write`, `tests/test_browser_scope.py::test_an_endless_redirect_chain_is_aborted`
  - Enforced by: `core.urls.destructive_reason`; `tools/spider.py` (queue filter, hand-followed redirects, `navguard.guard_page`); `tools/fetcher.py:load_urls` — `tests/test_destructive_urls.py::test_static_crawl_fetches_a_destructive_link_or_redirect_last`, `tests/test_destructive_urls.py::test_rendered_crawl_visits_destructive_links_and_subresources`, `tests/test_destructive_urls.py::test_the_auditor_refetches_a_destructive_url_last`, `tests/test_destructive_urls.py::test_login_discovery_never_follows_a_redirect_to_a_destructive_url`, `tests/test_forms_phase1.py::test_a_named_picker_is_navigated_and_the_settings_one_never_touched`, `tests/test_forms_phase1.py::test_a_settings_picker_is_never_submitted_even_when_named`, `tests/test_forms_phase1.py::test_selector_submissions_never_change_the_crawlers_cookies`, `tests/test_forms_phase1.py::test_bwapps_destructive_gets_are_refused`
  - Enforced by (PA-0114 / PA-0301 tables: each lab's destructive routes judged by the real gates, and the compound-spelling scan over every lab's routes; BUG-0301): `core.urls.destructive_reason`, `store_adapter.form_skip_reason`, `spa.form_refusal` — `tests/test_destructive_routes_external_labs.py::test_each_destructive_route_gets_its_gates_actual_verdict`, `tests/test_destructive_routes_external_labs.py::test_no_lab_route_hides_a_destructive_word_in_a_compound`, `tests/test_destructive_routes_external_labs.py::test_the_spelling_scan_catches_synthetic_offenders`
  - Not yet enforced (BUG-0301, deferred to the owner of `core/urls.py`, CC-CORE-0301): the deny rule does not refuse Juice Shop's `/dataerasure` (one token, `dataerasure`) or `GET /rest/user/change-password?current=&new=&repeat=` (a `change`+`password` pair). A crawl that reaches `/dataerasure` would visit it and import its server-rendered erasure form, which passes `form_skip_reason`. Neither is captured today: the SPA's change-password form is never submitted, and a captured GET has no body to import. Pinned by strict xfails: `tests/test_destructive_routes_external_labs.py::test_juice_dataerasure_url_is_refused`, `tests/test_destructive_routes_external_labs.py::test_juice_dataerasure_form_is_never_imported`, `tests/test_destructive_routes_external_labs.py::test_juice_change_password_url_is_refused`.
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
  - Not yet enforced (exact argv display; BUG-0400, open, the UI lane's fix): the shared display `web/runner.build_flags` mis-serialises `nargs='*'` lists, a bare `const=""` flag and dash-leading values, so for those the printed plan is not the exact argv. Pinned by strict xfails in `tests/test_cli_argv_roundtrip.py`.

## 5. Interfaces and data contracts
Writes `page`, `endpoint`, and `parameter` rows (with a `source` of link vs xhr).
Reads the session context and the request budget. Runs standalone or as part of a
pipeline.

Spider DB (the spider's own schema, `StorageManager`; no store migration):
`discovered_pages` (`source` is `link`, `xhr`, `redirect`, `form`, since FR-CRAWL-12
`spa-route`, since FR-CRAWL-16 `reveal`, or since FR-CRAWL-17 `spa-query` (a query
seed); a SPA route page's `url` keeps its `#/…` fragment, a seed's with its query),
`discovered_forms`, `selector_verdicts`, `crawl_stats (name TEXT PRIMARY KEY,
value INTEGER)` (the last crawl's SPA, reveal and, since FR-CRAWL-17, `spa_query_*`
counts -- refusals by reason as `spa_query_refused[<reason>]` -- `submit_stopped` and
`reveals_stopped`), since FR-CRAWL-16 **`revealed_forms`** `(id, page_url, route,
signature, submitted INTEGER, UNIQUE (route, signature))` — the forms a reveal showed,
for a later opt-in (`page_url` redacted by `redact_url_identifiers`; never values) —
and, since FR-CRAWL-13,
**`discovered_requests`** — the contract
the importer reads (lane J, forms phase 3):
`(id, page_url, method, url, content_type, body_json TEXT, source TEXT ('passive' |
'submit' | 'blocked': a write the window refused, recorded unsent, CC-CRAWL-0036),
signature TEXT UNIQUE)`. `body_json` is the redacted body as JSON text (a
JSON body's parsed value; a form-encoded body as an object of name → value, last wins);
`url` and `page_url` are redacted (`core.redaction.redact_url_identifiers`);
`content_type` is the media type only; `signature` = JSON `[method,
url_key(url), sorted leaf paths of the redacted body]` (dedupe; CC-CRAWL-0037: each
path is the object keys down to a leaf, an array's items sharing one `"[]"` step, at
most 256 paths; it was the sorted top-level keys). `headers_json` (CC-CRAWL-0037) is
`core.redaction.redact_captured_headers`: `{"kept": {name: value}, "withheld":
[names]}` -- Content-Type as media type and charset, Accept, X-Requested-With and
non-sensitive `x-` headers whose value is short and not identifier-like are kept; a
cookie, an Authorization or a sensitively named header is withheld by name, never its
value; the browser's own headers are not recorded. A database from before it gains the
column (NULL in old rows).
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
