# Crawler / Spider — Requirement Specification

Component code: **CRAWL** · Status: `[built; to harden]` · Last updated: 2026-10-21

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
  BUG-0113). Every engine carries the identity or refuses: the static engine too
  (FR-CRAWL-34, CC-CRAWL-0056).
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
    whose only typed input is a one-time code (2FA/TOTP). *(Amended in place,
    CC-CRAWL-0033, D71: a CAPTCHA form is no longer refused -- see FR-CRAWL-15 G1e.)*
    Labels, control names and options are
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
    `spa.checkbox_refusal`). *(Amended in place, CC-CRAWL-0033, D71; G1e was a refusal
    since CC-CRAWL-0023.)* A CAPTCHA form (`spa.captcha_reason`: a control or a
    container hint — attribute values, `<label>` / `<mat-label>` / `<code>` text — with
    a `captcha` / `recaptcha` / `hcaptcha` / `turnstile` token, or a `<canvas>`) is
    gated and filled like any other: its CAPTCHA control gets a filler answer and the
    form is submitted, so its request is captured (G1e; counted in `captcha_forms`,
    logged; no CAPTCHA is solved).
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
    period (`_quiesce`: `_settle` — nothing in flight, three quiet 100 ms polls — then
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
    query window); a
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
    interactive (role=button, a tabindex, an `onclick`, or a pointer cursor — the page
    side cannot see an `addEventListener` handler), has no interactive descendant, and
    its whole text (at most `spa.MAX_CARD_TEXT` characters, longer is refused) passes
    the gate, dispatched by the element's own `el.click()` after its labels are read
    again, never a coordinate click. Never a link, a select-like control, a disabled
    element, or an element inside a form (unless a `type=button` button). Each once per
    (route, kind, label signature); cards at most `spa.MAX_CARDS_PER_SIGNATURE` (3) per
    (route, structural signature); at most `spa.MAX_REVEALS_PER_PAGE` (6) per page and
    `spa.MAX_REVEALS` (60) per crawl (`reveals_over_cap`).
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
    The pairs are placed in the route's query through the one owner
    (`core.urls.place_route_query_pairs`, SP-42; CC-CRAWL-0053): a name the route query
    already has is replaced in place, never sent twice, and names and values are
    percent-encoded by `spa.seed_value`, which keeps `/` as written (so a redirect-ish
    name's value is `/` in hash and history mode alike).
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
    history-mode seed, which is a full load inside its window. A seed's forms are stored
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

- **FR-CRAWL-18 (behavioural capture: the interception layer, CC-CRAWL-0031, D70)**
  `fuzzlab disco capture` records every exchange the application makes, whatever stack
  it runs on, by sending the browser through a loopback capture proxy:
  - **The proxy** is mitmdump running `fuzzlab.disco.recorder` in this interpreter
    (`python -m fuzzlab.disco.mitm`), started and stopped through `procutil` (SP-22,
    SP-31), listening on `127.0.0.1` only and checked loopback-only after boot
    (PA-0130). Its CA lives in the run's own directory.
  - **It is a scope firewall.** A request whose canonical origin is outside the run's
    scope (`core.urls.in_origin_scope`) is killed before it is forwarded and counted per
    host; an empty scope refuses everything. A CONNECT names a host and port, not a
    scheme (the Playwright driver tunnels plain `http` too, measured): it is opened
    when `host:port` is in scope under either scheme, and each request inside is checked
    on its real origin. mitmproxy connects upstream only after that check
    (`connection_strategy=lazy`).
  - **One record format, one producer, one reader** (`fuzzlab.disco.capture`,
    SP-35): `make_record` builds each `capture.jsonl` line -- method, URL, request and
    response headers and bodies, content types, status, latency, the UI action
    (`x-disco-action`) and the auth profile -- redacted at the write through
    `core.redaction` (`redact_url`, `redact_body` failing closed, every sensitively named
    header's value replaced); identifier values are kept; a body is cut at 200 000
    characters only after redaction, and marked truncated. The record is built off the
    proxy's event loop, by the recorder's writer (`build_record`), from what a hook
    took (`snapshot`); a body not captured whole is recorded as none, marked truncated
    (FR-CRAWL-38). `read_capture` types every
    line and quarantines (counts) a malformed one. The line cap (`MAX_LINE_BYTES`) holds
    while a line is read (`JsonlTail`, CC-CRAWL-0054, BUG-0536).
    - Once the held part of a line passes the cap, the line is quarantined once
      (`OVERLONG` in its place) and its bytes dropped. The rest of it is discarded,
      across reads, up to its newline.
    - At most the cap plus one file read is held, and the work is linear (`copied`).
    - The explorer's action log reads through the same tail and numbers such a line as
      one malformed line.
    - Enforced by `tests/test_bounded_reads.py`
      (`test_an_unterminated_line_over_the_cap_is_quarantined_once_and_never_held`,
      `test_reading_a_long_line_in_small_pieces_copies_each_byte_a_bounded_number_of_times`,
      `test_the_copy_oracle_flags_a_quadratic_tail`).
  - **The action tag** is added by the browser route's header hook and stripped by the
    proxy before forwarding (`--keep-tag` forwards it), so the target never sees it.
  - **One capture per run** (PA-0450): a run directory that already holds a capture is
    refused.
- **FR-CRAWL-19 (behavioural capture: the interaction engine, CC-CRAWL-0031, D70)**
  `fuzzlab.disco.explore.Explorer` drives a guarded Chromium through the proxy:
  - **The browser** is launched like every other (SP-03/SP-04) with
    `navguard.browser_launch_args(scope, proxy=)` and `chromium_launch_kwargs(proxy=)`;
    the context ignores HTTPS errors, blocks service workers, is guarded by
    `navguard.guard_page`, navigated through `navguard.navigate` and released through
    `navguard.release`.
  - *(Amended in place, CC-CRAWL-0055, BUG-0539: a state's identity is FR-CRAWL-31's
    execution key; this is the structural key.)* **Element signatures and the
    structural key** (`fingerprint.state_fingerprint`): the normalised route and the set
    of visible interactive elements' signatures (tag, role, type, name, class tokens, a
    three-ancestor chain, normalised id / href / action; digit runs folded; text never;
    *(CC-CRAWL-0032, BUG-0501)* classes that carry UI state -- a BEM `--modifier` or a
    class with a state-word part (`visible`, `active`, `pristine`, `touched`...) --
    dropped; *(CC-CRAWL-0034, BUG-0502)* nothing of where the element was seen: a
    form-less container has no action). The structural key schedules and folds only. At
    most `max_same_signature` (2) elements of one signature per state are acted on
    (`same_signature_capped` counts the rest).
    *(CC-CRAWL-0059, review round 1; at the merge with CC-CRAWL-0055.)* A delegated
    candidate (FR-CRAWL-40) is never part of a state's identity: neither key, a state's
    recorded contract nor any restore check reads it -- its membership or its flags
    (`fingerprint.counts_for_state`: `state_signatures`, and the execution key's
    `element_multiset` and `workflow_markers`).
  - *(Superseded by FR-CRAWL-32, CC-CRAWL-0055, BUG-0539; was, CC-CRAWL-0034: each
    (route, element signature, occurrence, action) tried once, and a step on chrome --
    a signature seen on more than one route -- once in the whole run.)*
  - *(Amended in place, CC-CRAWL-0032, BUG-0501; CC-CRAWL-0055.)* **The frontier**
    explores a state on a route no known state is on before another state of a known
    route -- a new layout before a variant of a known one (FR-CRAWL-31) -- and holds at
    most `max_states_per_route` (8) states per folded route (`route_capped` and
    `coverage_excluded` count the rest).
  - *(Superseded by FR-CRAWL-33, CC-CRAWL-0055, BUG-0539; was, CC-CRAWL-0032: a replay
    step whose element is gone was skipped, and a restore showing core elements only
    gone narrowed the core, `transient_dropped`.)* **Restore:** the page leaves for
    `about:blank`, then loads the state's entry URL (a fresh document, also on a
    hash-routed app), replays its path and checks the state's recorded contract
    (FR-CRAWL-33). A fallback path covers a page only a POST shows, when its steps are
    safe to repeat.
  - **Actionable elements:** native controls and ARIA roles; elements with a JS
    click / pointer / key listener from Chrome DevTools (*(amended in place,
    CC-CRAWL-0059)* the Command Line API's `getEventListeners`, run inside the read, at
    most 200 candidates per document; was: `DOMDebugger.getEventListeners` per
    candidate); `cursor: pointer` as a fallback; *(CC-CRAWL-0059)* delegated candidates
    (FR-CRAWL-40); re-enumerated after every action, *(CC-CRAWL-0059)* across the
    page's composed tree (FR-CRAWL-39; was: the top document's light tree only).
    Text-like controls are filled through their form, never clicked alone.
  - *(Amended in place, CC-CRAWL-0032.)* **A form** is a `<form>` or, without one, the
    nearest ancestor (six levels) holding typed inputs; a button there is its submitter,
    a disabled one included (filling enables it). *(CC-CRAWL-0059, review round 1.)*
    When those ancestors end at the top of a shadow tree, the shadow root is the
    container if it holds a typed control: a form-less widget whose input and button sit
    directly under its root (no action, as any form-less container).
  - *(CC-CRAWL-0034.)* **Enter:** a text input that is the last typed control of a
    container with no submit control, or the only one of a form-less container (a
    search box among a toolbar's buttons), gets an Enter step: its container filled,
    Enter pressed (`enter_submits`).
  - **Forms valid-first** (`formfill`): each control gets the first candidate (from its
    type, pattern, bounds, autocomplete, name, label, placeholder, options) it accepts,
    then the submitter is clicked; then up to six submissions with one control perturbed
    (empty, boundary length or value, another option), once per form (route and field
    set) and never through a search box's buttons. *(Amended in place, CC-CRAWL-0034,
    BUG-0502.)* A control accepts a value when, blurred, it passes `checkValidity()` and
    is not `aria-invalid="true"` (a script validator the browser cannot see); with no
    such candidate, the first the browser accepted is kept. A number with no stated
    maximum also gets wider magnitudes (10 .. 10^9); `\d` / `\w` / `\s` inside a
    pattern class are read as such and `*` repeats once. A page-set or optional sensitive control is left as it is; a required
    empty one is filled. A password gets a filler, never a credential. A CAPTCHA
    control gets a filler answer and its form is submitted (D71, CC-CRAWL-0033); the
    report counts them (`captcha_submissions`, of the sent submissions).
  - *(CC-CRAWL-0034, BUG-0502.)* **Counters count effects:** `submissions` counts the
    submit and Enter steps taken; `submissions_sent` counts the submit, Enter and
    perturbation steps whose filled values (five characters or more, not all digits)
    reached a request's URL or body -- the figure that says a form was sent.
  - **Network quiescence:** after each action, no request in flight for 500 ms
    (polled), at most 8 s.
  - **Budgets:** states (60), actions (400), a deadline (900 s); the one hit is reported.
  - *(CC-CRAWL-0036.)* **Workers:** `ExploreOptions.workers` / `disco capture
    --workers N` (1..8, default 1) explore with N browsers at once. Each worker has its
    own Playwright instance, browser, guarded context, page, network-quiet tracking and
    action tag; they share one frontier, the known states, the seen and done steps, the
    chrome map, the perturbed forms, the denied steps, the action-id counter and the
    report, behind one lock (every check-then-act holds it, PA-0088). A run ends when the
    frontier is empty and no worker holds a state, or on a budget, which stops every
    worker; a worker's exception stops the others and is raised to the caller. One
    worker runs the same loop without threads. With more than one, which worker takes
    which state is not deterministic, and one worker's submissions change the server
    state the others see.
  - **Authenticated runs** start from a Playwright storage state kept to in-scope
    origins (`browserlogin.filter_storage_state`), *(CC-CRAWL-0060)* or from a session
    provider (`ExploreSession`, FR-CRAWL-41); with more than one scope origin the
    guard's `cookie_scope` keeps the session to its origins (FR-SESS-20). *(Superseded
    in place by FR-CRAWL-41, CC-CRAWL-0060, BUG-0552; was: a landing on a login URL is a
    lost session, the action is denied and the context rebuilt from the storage
    state.)* A lost session is FR-CRAWL-41's.
    *(CC-CRAWL-0055; at the merge with CC-CRAWL-0060)* a replaced context's states are
    read in the next session generation (FR-CRAWL-31).
  - Each action is logged to `actions.jsonl` (state, route, signature, kind, a 60-char
    label, the new state, *(CC-CRAWL-0036)* the element's occurrence;
    *(CC-CRAWL-0035)* the page URL after it, redacted
    (`redact_url`), and for a form step its controls' names and types, never values;
    *(CC-CRAWL-0055)* `state` / `new_state` are execution keys and `replay_safe` is
    whether the step sent no non-idempotent request, FR-CRAWL-33).
    `seq` is the number of the action id its requests carry (`act-<seq>`).
- **FR-CRAWL-20 (the schema synthesizer, CC-CRAWL-0031, D70)** `fuzzlab disco synth`
  turns captures into an OpenAPI 3.1-shaped inventory (`fuzzlab.disco.synth`):
  - path segments classified across samples (`int`, `uuid`, `id` via
    `looks_like_identifier`, and `slug` when one position, never the first, varies over
    at least three siblings *and every value was seen as data in a captured response*,
    CC-CRAWL-0032 / BUG-0501) and templated `{p1}`, `{p2}`...; static assets excluded;
  - endpoint key (origin, method, template, request content-type family);
  - genson-style body, query and response schemas: type unions, `required` = present in
    every sample, `enum` only for 2..5 distinct string values over 4+ samples, formats,
    observed ranges under `x-observed` (never constraints), `x-redacted` for a field
    seen only redacted; form and multipart bodies flattened; truncated bodies skipped;
  - headers classed `session` / `static` (value kept) / `varies`; auth `none` /
    `optional` / `required` from session headers and anonymous answers;
  - response-only fields per resource (mass-assignment candidates);
  - producer -> consumer edges with the extracting JSONPath (identifier-like values
    only; a small integer only into an id slot);
  - `x-disco` provenance per operation (samples, actions, profiles, statuses, latency);
    path literals mined from captured JS bundles listed as `observed: false`
    candidates, never as operations.
- **FR-CRAWL-21 (the legacy spider is deprecated, CC-CRAWL-0031, D70)** `fuzzlab crawl`
  (`tools/spider.py`) still runs, unchanged, and says on stderr that it is deprecated:
  `fuzzlab auto` reads its spider DB. `fuzzlab/disco` imports nothing from
  `tools/spider.py`, `tools/spa.py` or `tools/formnav.py` (an AST guard).
  *(Amended in place, CC-CRAWL-0035.)* `auto` reads a disco run since CC-FUZZ-0090
  (`--disco-run`, FR-FUZZ-53); removing the module waits for the owner's decision on
  the held-out comparison of the two.
- **FR-CRAWL-22 (crawl workers, CC-CRAWL-0037)** `fuzzlab crawl --workers N` (1..8,
  default 1) loads and renders N queued pages at once, one browser (or HTTP session)
  per worker. The first worker runs on the calling thread and starts its browser first
  (the session is ensured once; the others adopt it); each other worker starts and
  stops its own browser on its own thread. *(Amended in place, CC-CRAWL-0056.)* A URL's
  key is reserved when the frontier admits it (FR-CRAWL-35), so no page is queued or
  loaded twice; one worker runs the same loop. Whatever can write -- reveals, SPA form
  submissions, selector-form enumeration (`_after_fetch`) and every seed or probe load
  (FR-CRAWL-17) -- runs under one crawl-wide lock (`_interact`), one worker at a time,
  so the submission, reveal and probe caps and the write windows keep their one-worker
  meaning. Seeds and probes run on the first worker only; probes are planned once every
  worker is idle. Stop flags and the crawl-wide counts are one value across workers;
  the SQLite store's connection is shared under its own lock (PA-0023). The first
  worker exception stops the crawl and is raised. One worker crawls exactly as before.
- **FR-CRAWL-23 (every linked resource, CC-CRAWL-0038/0039)** Both discovery tools take
  the URLs a fetched document links from `core.linkextract` (SP-39), by the rules of its
  format, not only `<a href>`: every URL-valued HTML attribute of the HTML standard and
  its obsolete-but-parsed features (`src`, `srcset`, `data`, `poster`, `cite`,
  `background`, `manifest`, SVG `href`/`xlink:href` ...), `<base>`, a refresh `<meta>`,
  the DOCTYPE system identifier, CSS in `style` attributes and `<style>` blocks and in
  stylesheets (`url()`, `@import`), IE conditional comments, the `Location`,
  `Content-Location`, `Refresh` and `Link` headers, `robots.txt` rules and sitemap
  entries. Each origin's `robots.txt` and `sitemap.xml` are seeded. The spider follows
  them whatever the response's media type (scope and destructive gates unchanged); its
  rendered engine never fetches as a page a subresource the browser already requested
  in the crawl. Disco gathers them per settled page and loads the never-requested ones
  once its frontier holds no new route or layout, *(CC-CRAWL-0055)* four loads per
  variant of a known layout (`max_harvest`, 500), an HTML document becoming a state. A
  response body is marked read only once it was read (a body the driver let go is read
  from its next response).
  **Never a link** (BUG-0503): a form's `action`, a `formaction`, a `ping`, or a string
  in a script -- their method is a write or unknown; forms reach the target only through
  the gated submission paths, and a script's requests are what the browser was seen to
  make when the page ran or was acted on.
- **FR-CRAWL-24 (network quiet, CC-CRAWL-0041)** Every wait for a page's requests to
  finish -- the crawler's `_settle` / `_quiesce`, disco's `wait_quiet`, browser login's
  `_settle` -- counts them through `netquiet.Inflight` (SP-40) and never waits for a
  long-lived one: an `eventsource` or `websocket` request, or any request still open
  after `LONG_LIVED_MS` (2 s; a long-poll such as socket.io's `polling` transport); the
  answer to a long-lived request is not activity. A request in flight has already passed
  the guard and any write window, so not waiting for it lets nothing through.
- **FR-CRAWL-25 (excessive data exposure, CC-CRAWL-0042)** `fuzzlab disco ede --run DIR
  --scope URL --authorized` tests each in-scope HTML page of a disco run (at most
  `--max-pages`, within `--deadline`). The page's JSON GET answers are served from the
  run's capture (matched by method and redacted URL; whole 2xx JSON bodies only) through
  a route added over the guard; nothing else changes. The page is loaded 3 times with
  the recorded answers: nodes that differ are ignored, a page whose structure differs is
  skipped. Then each scalar field of each answer the page requested, by shape
  (`$.items[*].id` across every element), is removed for one load; a field whose
  removal leaves every non-ignored node unchanged is reported *unused at load* in
  `ede.json`, with its JSON type and whether its name is sensitive, never its value. A
  finding is a candidate: a field used only after an interaction is reported too. The
  replayed answers never reach the target; the pages and their assets do (hence
  `--authorized`); an existing `ede.json` is never overwritten. *(CC-CRAWL-0060,
  FR-CRAWL-41, BUG-0552 review B2)* An answer recorded in the run's known-lost window
  (its action id marked, `disco.capture.lost_action_ids`) is neither replayed nor a page
  of the run.
- **FR-CRAWL-26 (dry submission and blocked writes recorded, CC-CRAWL-0045,
  BUG-0506)** In the Playwright engine with SPA routes on and `--submit-spa-forms` not
  given, each eligible form on an SPA route is dry-submitted unless `--no-dry-submit` is
  given. Eligible means it passes `spa.form_refusal`, is taken once per signature, and
  is within `spa.MAX_SUBMISSIONS`. A dry submission:
  - fills the form with the fillers (a password control gets the filler, never a
    credential);
  - clicks its vetted button inside the write-blocking window (W1-W3), never lifted;
  - records the write the click makes (an `xhr`/`fetch` that is not GET, HEAD or
    OPTIONS and that the window refuses) in `discovered_requests` with source
    `dry-submit`, through `record_request`'s redaction;
  - lets the window abort that write, so the server receives nothing.

  Session safety:
  - A form with a password input is dry-submitted only in a fresh unauthenticated
    context.
  - Any other form's click runs between a snapshot and a rollback of the client state
    (the context's cookies, the page origin's `localStorage` and `sessionStorage`)
    inside the window.
  - In an authenticated crawl, the client-side session check follows. A loss stops dry
    submission and is reported.

  A write any other non-query window aborts (a reveal or G1 click) is recorded the same
  way with source `reveal-blocked`. A seed or probe window (FR-CRAWL-17) records none,
  since its URLs carry markers. Nothing is recorded while a vetted submission has
  lifted the window. `forms_dry_submitted`, `requests_captured_dry` and
  `requests_captured_blocked` count stored effects and are reported. The importer takes
  every `discovered_requests` row as a captured request whatever its source (SP-37).
- **FR-CRAWL-27 (disco's harvest: script routes and document aliases, CC-CRAWL-0044,
  BUG-0505)** Disco reads every JavaScript response body with `spa.scan_script` (SP-47,
  the spider's scanner):
  - each route `spa.classify_route` calls OK, and each paired route-query seed
    `spa.query_url_refusal` admits, is queued in the page's routing mode. The mode is
    hash when the page URL or one of its links holds a `#/` route, as the spider
    decides it;
  - these URLs go in a harvest queue loaded before the linked URLs;
  - a harvest load of a hash-route URL writes an `actions.jsonl` line of kind `load`
    (every action key present), so the importer gives its query as `fragment`
    parameters.

  An HTML document whose body (sha256) was first loaded under another path is an alias
  (`harvest_aliases`), and no state is taken from it, when either:
  - the page is hash-routed (its URL or a link holds `#/`), or
  - its rendered state, read as if at the first path, is already a known state.

  Otherwise it is explored: a history-mode route renders its own view from the same
  shell. **Known gap:** the spider's FR-CRAWL-17 probe loads (marker reflection of
  unpaired query names) have no disco counterpart.
- **FR-CRAWL-28 (the path segments an app's scripts hold, CC-CRAWL-0046, BUG-0507)**
  Both crawlers keep `core.pathtemplate.code_segments` of each script body they read
  in full, at most 20,000 per crawl, names only (identifier-like segments are never
  kept):
  - the spider, in a `script_segments (segment TEXT PRIMARY KEY)` table filled when it
    scans a script (`StorageManager.record_script_segments`; counted
    `script_segments`);
  - disco, in `script_segments.json` beside `actions.jsonl` (sorted), from the bodies
    `_gather` reads. The capture truncates a body, and these reads do not.

  They are the importers' evidence that a varying URL segment is a route's name
  (FR-AUD-26). `disco.synth.template_paths` decides slugs through the same
  `varying_is_parameter` (with its data evidence).
- **FR-CRAWL-29 (which page queued a page, and when, CC-CRAWL-0047)**
  The spider records, at its execution points:
  - **`discovered_pages.found_from`**: the queued URL whose load queued this page --
    through a link or any URL its response named, a script's fetch/XHR, a selector
    form, a SPA route or seed, a reveal, a navigation a window aborted, or (for a
    `redirect` row) the load that redirected to it. It travels in the queue entry
    `(url, depth, source, found_from)`, so with several workers it is the entry the
    URL was claimed from (the first queued). NULL for what the crawl queues itself: the
    start URL and the origin's well-known files. Links found in a load that redirected
    are attributed to the queued URL (whose row holds it), not to the landing.
    Stored as that write site stores the page's URL: as queued (probe markers
    scrubbed), and `redact_url` at the redirect landing.
  - **`discovered_pages.seen_at`**: wall time (seconds since the epoch) when the page's
    own load began; a redirect landing has its load's time. Never earlier than its
    `found_from` page's.
  - **`discovered_requests.seen_at`**: when the request was captured.

  An older spider DB is upgraded in place; its rows keep NULL (unknown). Crawl order
  and the requests sent are unchanged. With `--workers N` each worker's page events
  reach that worker only (BUG-0509): a fetch is filed under the page that made it,
  whichever worker loaded it.
- **FR-CRAWL-30 (a disco capture's trace, live, CC-CRAWL-0050)**
  `fuzzlab disco capture --store PATH` (or `--record`: the store by `core.storepath`)
  records the capture into a new store run (`run.tool` `disco`) **while it runs**: each
  capture record and each explorer action carrying an `action_id`, as the events
  FR-AUD-28 defines, with the same keys and bodies (FR-AUD-29).
  - **Who writes:** one thread of the capture command (`disco-trace`,
    `disco/livetrace.py::LiveTrace`), on its own store connection, through the run's
    one `TraceRecorder` (SP-48). It reads the files the capture writes
    (`capture.jsonl` through SP-35's `CaptureTail`, `actions.jsonl` through
    `observe.DiscoActionLines`) every 0.25 s; a line is read only once its newline has
    arrived, and a line over `MAX_LINE_BYTES` is quarantined while it is read, never
    held (FR-CRAWL-18, BUG-0536). mitmdump and the explorer are not changed.
  - **At the end** (after the capture proxy stopped and `explore.json` was written) the
    same thread imports the directory into the run (`observe_disco`), adding what the
    live passes did not write: a batch the store refused, the last unterminated line,
    old-log actions, and the hosts the capture proxy and the browser guard refused,
    with final counts. Then `run.end`: `complete`, or `aborted: <class>` with the run
    row marked. Importing the directory into that run again adds nothing;
    `fuzzlab auto --disco-run` imports it into its own run.
  - **A failed trace never fails the capture.** An item that cannot be built is counted
    `dropped`; a failure that stops the trace is printed to stderr when it happens and
    again at the end, the run ends `aborted: trace <class>` and its row is marked, and
    the exit code is unchanged. The command waits for the trace at most `join_bound`
    (60 s, more when the final pass needs more than one flush: each can take ~20 s
    under a write lock held elsewhere); past it the timeout is reported and the command
    exits 1. A batch once dropped stays counted (`trace_dropped`), so a healed run
    still reads partial.
  - **Measured (CC-CRAWL-0050):** a record is visible in the store p95 0.28 s after its
    response; the capture's counters are unchanged.
  - **Off by default.** Without `--store` / `--record` nothing is written outside the
    run directory. The Diagrams page shows the capture when the store is the one it has
    open. `--record` adds the newest run that `report`/`diagram --run latest` pick.
  - **Not recorded:** after SIGTERM or SIGKILL (no handler: no end import and no
    `run.end`; the run reads partial); action lines worker threads append after an
    interrupt; a crashed capture's browser-guard refusals (no `explore.json`).
  - **Stale directories (BUG-0525):** `capture` refuses an `--out` that holds any file a
    consumer reads as the run's (`disco.cli.RUN_FILES`: `capture.jsonl`,
    `actions.jsonl`, `capture.jsonl.stats.json`, `explore.json`,
    `script_segments.json`), before any side effect and with `--dry-run` too. Order:
    scope URLs, run files, storage state, store, `--dry-run` (which names the trace),
    `--authorized`, workers.
- **FR-CRAWL-31 (disco: a state's identity is its execution key, CC-CRAWL-0055,
  BUG-0539)** The explorer keeps two keys per page (`disco/fingerprint.py`):
  - **The execution key** (`execution_key`, SP-62) is a state's identity. It hashes:
    - the exact route (`execution_route`): origin, the path as served (numeric segments
      kept), every query pair with its value (sorted, each occurrence kept), and a SPA
      route fragment with its own query pairs; a sensitive name's value is replaced
      (`redact_query`);
    - the element multiset (`element_multiset`): each signature with its count;
    - the workflow markers (`workflow_markers`): an element's selection state (a
      select's value, a checkbox's or radio's checked state, `aria-selected`,
      `aria-current`, `aria-checked`; none for a sensitively named control), a named
      hidden input's value (not for a sensitive name, a value over 64 characters or a
      token-like one), and a non-interactive `aria-current` element's position; typed
      text never; *(at the merge with CC-CRAWL-0059)* read in the same composed read
      as the elements (FR-CRAWL-39: across open shadow roots and the frames read);
    - the session generation of the worker's context: the run-wide generation of the
      session it carries (FR-CRAWL-41: one for every worker on that session, unchanged
      by a reinstall of it), or, for a context that carries none, 0 plus one per
      rebuild *(amended at the crawl batch's merge integration)*.
  - *(At the merge with CC-CRAWL-0059.)* A delegated candidate (FR-CRAWL-40) is in
    neither the multiset nor the markers (`fingerprint.counts_for_state`); its
    `aria-current`, if any, is read as a page-level marker, as it was before it was a
    candidate.
  - Every visited-state check reads it: the known set, a child state's novelty, a
    harvest document's novelty.
  - **The structural key** (`state_fingerprint`: folded route, set of signatures)
    schedules and folds only: the frontier's order (a new route, then a new layout,
    then a variant of a known layout; once only variants are queued, up to
    `HARVEST_PER_VARIANT` (4) harvest loads and one variant take turns, so neither
    starves the other) and per-route bound, and a harvest alias
    (FR-CRAWL-27). It is called only from `Explorer.reading` and
    `Explorer._alias_state` (an AST guard).
  - A step's effect and whether it changed the page are judged against the page just
    before it. A page that passed the state's contract (FR-CRAWL-33) is that state:
    its key is added to the known set; no other reading is.
  - **The per-route bound is reported, never claimed equivalence**: each state refused
    because its folded route holds `max_states_per_route` states is counted in
    `explore.json`'s `coverage_excluded` (per folded route) and `route_capped`; a state
    found past `max_states`, or left in the frontier when `max_actions` ends
    exploration, in `states_over_budget`.
  - Enforced by `tests/test_disco_state_identity.py`
    (`test_a_query_value_a_numeric_segment_or_a_second_identical_button_is_another_state`,
    `test_the_structural_key_never_decides_a_visited_state`) and, in a real browser,
    `tests/test_disco_state_identity_browser.py::test_a_wizard_step_with_the_same_layout_is_explored_to_its_end`.
- **FR-CRAWL-32 (disco: action work per execution state, CC-CRAWL-0055, BUG-0539)**
  - **The work key** of an action is (execution key, element signature, occurrence,
    action kind) (`explore.work_key`). `WorkLedger` tracks each item as `pending`,
    `running`, `succeeded`, `refused`, `retryable` or `failed` (`equivalent` when
    skipped as below); `explore.json`'s `work` counts them at the end.
  - **A failure never consumes the work.** A Playwright error, a step that could not
    act, an element gone from the restored page, or *(CC-CRAWL-0055 review B3)* a safe
    step whose result page could not be read makes the item `retryable` (an item is
    `succeeded` only once its result was read); it is
    queued again after a restore, up to `max_action_attempts` (3) attempts, then
    `failed` (`actions_retried`, `actions_failed`). A refusal (the denylist, a
    credential-change form) is `refused`.
  - *(At the merge with CC-CRAWL-0059.)* **A delegated candidate's work** (FR-CRAWL-40)
    is `inert` once its trial found it inert (an observed verdict, never a failure). A
    trial whose click reached nothing, and one another worker is running, is a failed
    attempt (`retryable`). An item the run's spent trials leave untried stays
    `pending`, counted `delegated_unexplored`.
  - **Presumed chrome is a scheduling hint.** A step taken in another state is
    scheduled after the state's own steps (`deprioritised`). It is skipped
    (`chrome_skipped`, status `equivalent`) only when its recorded effect -- the
    requests it made (method and folded route) and its transition (none, or the state
    it led to) -- was the same in states on two folded routes, and never once two of
    its effects differed. With one worker, a header button whose effect is the same
    everywhere is taken at most twice in a run.
  - **Perturbation passes** stay one per form (folded route and the *set* of its
    fields: a second identical dialog adds no variation): a bound on value variations,
    counted in `perturbations_folded`; the form's submission is work of every state.
  - Enforced by `tests/test_disco_state_identity.py`
    (`test_the_same_step_in_another_execution_state_of_one_route_is_new_work`,
    `test_a_failed_attempt_never_consumes_the_work_and_is_retried_then_failed`,
    `test_presumed_chrome_is_deprioritised_and_skipped_only_on_equal_effects_on_two_routes`,
    `test_an_action_whose_result_could_not_be_read_is_retried_and_its_successor_recorded`)
    and, in a real browser, `tests/test_disco_state_identity_browser.py`
    (`test_a_dialogs_second_stage_takes_the_same_next_again`,
    `test_a_transient_playwright_error_never_consumes_an_action`).
- **FR-CRAWL-33 (disco: a restore never accepts or weakens a wrong state, CC-CRAWL-0055,
  BUG-0539)**
  - **A recorded contract** is the state's element multiset and workflow markers when
    first read. It is never rewritten or narrowed. A restore reproduces the state when
    its execution key comes back, or when the exact route matches and every element
    is present exactly as many times as recorded, every recorded marker is shown and
    no other (`explore.contract_mismatch`). *(Amended in place, CC-CRAWL-0055 review
    B2; was: a page with more was accepted.)* Neither a proper subset (`core`,
    `markers`) nor a superset (`extra`: a control more often than recorded, or a marker
    the contract lacks) is accepted: a server that moved on shows a later stage with
    the earlier stage's controls and more.
  - **A step is taken only on a page that holds its state's contract.** Before each
    step the page is read and, when the last step changed it or it no longer holds
    the contract (a late render, a server that moved on), the state is restored and
    checked again; only a page that passed is taken as the state (its key added to
    the known set).
  - **Optional features are declared, with evidence, never inferred by shrinking;** a
    declared feature is excused whether missing or shown again:
    - `first-visit`: what the start document's first load held and a fresh second load
      of it (made when the start state is recorded) does not (a welcome dialog); the
      start state's own optional counts and markers, and run-wide when gone altogether;
    - *(Amended in place, CC-CRAWL-0055 review B1; was: any click that removed its own
      element.)* `dismissed`: what a safe click (no non-idempotent request) on an
      entry document as loaded (a state with no path) removed altogether, with no
      navigation and nothing new, when the clicked element's own signature was among
      it and all of it was in that state's recorded contract, and a fresh load of the
      entry URL still shows none of it (a notice's "Got it"); run-wide. A control a
      step added (a modal its Open showed) is never declared.
    - A run-wide declaration never excuses a control the state's own last path step
      added (`State.added`).
    `explore.json`'s `optional_declared` counts them by evidence.
  - **Replay never skips a missing step silently.** A path step whose element is
    missing fails the restore (`missing-step`) unless its signature is declared
    optional; that skip is counted (`replay_skipped_optional`).
  - **A step that sent a non-idempotent request is never replayed.** Each step records
    `safe` when taken: no request outside GET, HEAD and OPTIONS was issued during it
    (sent or refused). A path holding an unsafe step is not restored (`unsafe-step`); a
    replay that issues one anyway fails (`replay-mutated`). A state reached by an unsafe
    step, or whose path holds one, is explored **in place** when it is reached
    (`live_states`), to `max_live_depth` (3) such states one inside another; it is never
    queued for a replay.
  - **A failed restore marks the state unresolved** with its reason (`route`, `core`,
    `extra`, `markers`, `missing-step`, `unsafe-step`, `replay-mutated`, `navigation`,
    `step-refused`, `step-failed`, `replay-error`, `unreadable`, `live-depth`),
    counted in `explore.json`'s `unresolved` and `unrestorable`; the steps it still had
    are counted in `steps_abandoned`. Its contract is kept as recorded. A step that sent
    a non-idempotent request and whose result page could not be read is counted
    `unreadable` too, logged with no new state, and never taken again.
  - **Not reset by a restore** (stated limit): `about:blank` resets the document only;
    server state, cookies and storage persist. A state that depends on them either
    holds its contract or is reported unresolved.
  - Enforced by `tests/test_disco_state_identity.py`
    (`test_a_recorded_core_is_never_accepted_by_a_proper_subset_nor_shrunk`,
    `test_a_superset_of_the_contract_is_never_the_recorded_state`,
    `test_a_declared_optional_feature_never_excuses_a_missing_mandatory_one`,
    `test_a_declaration_never_excuses_what_the_states_own_last_step_added`,
    `test_a_dismissal_is_declared_only_on_the_entry_document_and_confirmed_by_a_reload`,
    `test_a_replay_never_skips_a_missing_step_silently`,
    `test_a_path_that_sent_a_non_idempotent_request_is_never_replayed`) and, in a real
    browser, `tests/test_disco_state_identity_browser.py`
    (`test_a_restore_that_lost_a_core_control_is_unresolved_and_its_contract_kept`,
    `test_a_state_reached_by_a_post_is_explored_in_place_and_never_replayed`,
    `test_a_modal_closed_by_its_own_control_that_does_not_reopen_is_unresolved`,
    `test_a_restore_that_lands_on_a_later_stage_is_unresolved_never_that_stage`).

- **FR-CRAWL-34 (the legacy spider's static engine carries its identity, and no load of
  either engine goes where the session does not reach, CC-CRAWL-0056, BUG-0545)** In a
  crawl with `--identity`, every request the `requests` engine sends --
  the engine chosen, the engine Playwright's absence selects, the browser's fallback for
  a page it cannot render, and a selector form's submission (FR-CRAWL-8) -- goes through
  the core seam (`core.http.HttpClient`) with the session manager as its addon, on a
  persistent bounded session (SP-60) whose cookie jar keeps nothing: the manager is the
  one source of the session.
  - **Before any page** (`_static_identity`): the manager logs in from the start URL
    (operator base); the session must cover the start URL's origin over its transport
    (`session_headers`); it must hold a cookie or a header a request can send, else the
    crawl fails with `StaticIdentityUnsupported` ("cannot carry": a session in browser
    storage needs `--engine playwright`); and it must be live (`verify_live`, SP-61). A
    failed login fails the crawl. Nothing is crawled anonymously in its place.
  - **Each hop:** the crawl's scope and destructive rules decide a redirect hop as before;
    a hop to another origin than the session's is not followed and the load extracts
    nothing (`withheld`, FR-SESS-20). An answer the manager withheld the session from
    (another origin) is never extracted (`withheld`).
  - **A host the session does not reach is never loaded or sent to, in either engine**
    *(BUG-0545 review, R6; review round 2 for the browser)*. Every load of an identity
    crawl -- whatever queued it -- passes one gate in `_visit`
    (`_session_host_refusal`), after the scope, destructive and other-origin checks and
    before any navigation or send. It compares the host the load goes to with the hosts
    the engine's carrier of the session reaches: the **static** engine asks the session
    manager's own `prepare` (through `_SessionAddon`, on a request that is never sent),
    and a host it leaves alone -- no session applied (`session_generation` unset) and no
    decision recorded: outside the manager's own scope, such as a loopback alias of the
    start the config does not list -- is refused; the **browser** refuses a host that
    one of the session's credential cookies, as its context holds them (by URL, or a
    browser login's cookies by domain), does not reach (`navguard.session_host_refusal`,
    SP-74, whose `cookie_reaches` moved there from the spider in CC-CRAWL-0063: a
    host-only cookie reaches its own host only, so a loopback alias of the start is
    refused even when the manager serves it; a dotted domain also reaches its
    subdomains, never an IP address). A session without cookies goes by its headers, by
    origin (FR-SESS-20). Never a list of aliases. A refused load raises `HostNotServed`
    with the cause: nothing is sent; the page is stored `failed` (unresolved, resumed)
    with that cause, counted `session_host_unserved` in `crawl_stats` and reported,
    never `withheld`. Inside a static load the seam keeps the same refusal before the
    transport for a redirect hop and a selector form's submission (logged; the page
    holding the form is kept). **Inside a browser load** *(BUG-0559, CC-CRAWL-0063,
    closing residual R8)* the same predicate refuses every request the load makes, at
    the guard's route (FR-CRAWL-43), and the browser makes none the route does not see
    -- no speculation-rules preload is ever registered *(review round 1, BA-3)*: a
    redirect hop to such a host is never fetched and
    the load is stored `failed` with the cause (never the landing's page, no static
    fallback); a selector form's submission there (`_isolated_submit`'s browser branch)
    is refused before it is sent (`navguard.checked_api_request`, counted, the page
    holding the form kept); a navigation the page makes itself (a script's `location`, a
    meta refresh) is refused, the page keeps its own document, and the target is queued
    and refused at the gate; a load whose main frame is found committed on such a host
    before extraction (a navigation the route never saw) is stored `failed` with the
    cause too. Adding the host to `scope_hosts` makes the manager serve it
    (measured for a loopback alias); `--auth-origin` does not; a browser crawl of such a
    host starts there.
  - **Losses:** an answer on a session the manager knows lost, or sent while the manager
    saw a loss on any send (its logout listener), is no evidence: the page is retried
    (FR-CRAWL-36) after the manager's re-login. A `SessionAuthError` on a send (a re-auth
    cap, an unknown health) stops the crawl (`IdentityUnavailable`).
  - Enforced by: `tests/test_spider_static_identity.py` (8 tests). The test site serves
    an anonymous visitor the same links and forms as the identity (`/secret`,
    `/expiring` and each test's extra ones; BUG-0545 review B2 and round 2 S2-2), so
    c483dc1's anonymous crawl reaches every page a test is about. Measured on c483dc1,
    each test's failing assertion (BUG-0545, review round 2): the identity test, `/`
    stored as `home`; the session-loss test, `/expiring` filed as the login redirect's
    answer `(200, '')`; the cannot-carry and failed-login tests, "DID NOT RAISE" (the
    old code crawled instead of refusing); the redirect test, B received a request; the
    unserved-host test, `GET /deeper?via=alias` with no cookie; the selector-form test,
    `/pick?bug=1` and `?bug=2` with no cookie; the browser test, the alias received
    `GET /deeper?via=alias` and two `GET /login`. The unserved-host test also fails on
    9071440 (the alias was sent with no cookie), and
    `test_a_browser_load_the_session_cookie_does_not_reach_is_refused_never_sent` on
    8c2fa86 (the same three requests to the alias). The browser load's own requests
    (BUG-0559): FR-CRAWL-43's tests in `tests/test_browser_session_reach.py`.
- **FR-CRAWL-35 (the legacy spider's frontier: one admission per key, budgets,
  CC-CRAWL-0056, BUG-0545)** Every URL the crawl would load enters through one frontier
  (`_Frontier`), shared by every worker:
  - **One admission per key.** A URL is admitted once per scheduling key
    (`spa.visit_key`: canonical origin, path, exact query, SPA route); a key already
    admitted or stored final is a duplicate (counted, dropped). The entry keeps its exact
    URL. A probe (FR-CRAWL-17) is never deduplicated.
  - **Budgets** (`FrontierLimits`; defaults are bounds, not tuning): `max_url_length`
    4096 characters, `max_pages` 20000 admissions, `max_per_origin` 10000,
    `max_route_variants` 100 per route shape (`spa.route_shape`: origin, path with
    id-shaped segments as `{}` through `core.pathtemplate.id_shaped`, sorted query names,
    the SPA route's own shape -- values never count), `max_pending` 10000 queued, checked
    in that order. A refusal is counted by reason in `crawl_stats`
    (`frontier_rejected[<reason>]`) and logged as partial coverage; it is never queued or
    stored.
  - **Order.** Two queues (ordinary; seeds and probes, the first worker's) and a retry
    heap; a worker takes a due retry first, then the older head: one worker crawls in
    admission order, as before. A pending retry keeps the crawl going; probes are planned
    once every worker is idle and no retry waits.
  - **Every load passes the crawl's scope and destructive rules first** *(BUG-0545
    review, B1)*. Whatever queued it -- a link, a redirect, a route, a seed, a probe's
    route, a retry, or a row a resumed crawl read from the store (FR-CRAWL-36) --
    `_visit` asks `_load_refusal` before anything else: outside the crawl's scope
    (`_in_scope`, FR-CRAWL-7/11; another loopback port is another service) or
    destructive (`_destructive`; the start URL is the operator's own) is never requested
    and nothing is stored for it. Each refusal is counted by reason in `crawl_stats`
    (`loads_refused[out_of_scope]`, `loads_refused[destructive]`, `LOAD_REFUSALS`) and
    reported in the crawl summary. The check sits where every load is made, not at the
    producers (PA-0123(1)); a stored row refused there was admitted by the frontier
    first, so it counts in `frontier_admitted` and the frontier's budgets.
  - Enforced by: `tests/test_spider_frontier.py::test_a_destination_many_parents_link_is_queued_once`,
    `tests/test_spider_frontier.py::test_a_fan_out_trap_is_bounded_by_the_route_budget_and_reported`,
    `tests/test_spider_frontier.py::test_the_frontier_admits_each_key_once_and_counts_every_budget`,
    `tests/test_spider_frontier.py::test_a_resumed_crawl_never_loads_a_stored_row_out_of_its_scope_or_destructive`.
- **FR-CRAWL-36 (the legacy spider's page record: a load's outcome, retries, the
  batched writer, CC-CRAWL-0056, BUG-0545)**
  - **Outcomes.** `discovered_pages.outcome` is `pending` once the page answered,
    `visited` only when its extraction finished (links queued), `withheld` for another
    origin than the session's (FR-SESS-20), `failed` for a load that did not give the
    page. Only `visited` and `withheld` (and a row from before this requirement with a
    status) are visited: skipped by the run and by a resumed crawl.
  - **Transient failures.** A load whose answer SP-56 classes incomplete,
    throttle-or-unavailable or gateway, another 5xx, a transport failure (connection,
    timeout, a broken or undecodable body), SP-60's `BodyIncomplete`, or a session lost on
    the send (FR-CRAWL-34) is stored `failed` (its status, `attempts`, `error`: an answer
    or exception class, never a URL or a body) and loaded again after a backoff (1 s
    doubling, a `Retry-After` honoured, at most 30 s), up to 3 loads; seeds and probes are
    never retried (their windows, FR-CRAWL-17). A page still failing is unresolved:
    `failed_pages`, `pages_failed`, a warning. A `--resume` crawl admits every stored
    unresolved row again (not a seed or a probe); each is loaded only through the crawl's
    scope and destructive rules (FR-CRAWL-35's load gate), so a row another target's or
    another start URL's crawl left is never requested and stays unresolved for a crawl
    whose scope it is in. `pages_retried` counts retries. A host the session does not
    reach (FR-CRAWL-34: the manager does not serve it, or the browser's session cookies
    do not reach it -- where the load starts or at a redirect hop inside it,
    FR-CRAWL-43) is unresolved too, with that cause, never `withheld`.
  - **The writer.** Recording a page never touches the store: rows are queued in memory
    and one writer thread commits them in order when they hold 64 rows or 1 MiB, or the
    oldest waited 1 s, and at close; reads of page rows flush first. A crawl thread waits
    only when the unwritten rows pass 16 MiB (`store_writer_waits`). A failed write is
    raised at the next record, flush or close, never dropped. `is_visited` reads memory.
  - Enforced by: `tests/test_spider_frontier.py::test_a_transient_failure_is_retried_and_never_recorded_visited`,
    `tests/test_spider_frontier.py::test_an_incomplete_body_is_retried_never_taken_for_a_page`,
    `tests/test_spider_frontier.py::test_a_page_that_keeps_failing_is_unresolved_reported_and_resumed`,
    `tests/test_spider_frontier.py::test_a_resumed_crawl_never_loads_a_stored_row_out_of_its_scope_or_destructive`,
    `tests/test_spider_frontier.py::test_recording_a_page_never_waits_for_the_stores_lock`,
    `tests/test_spider_frontier.py::test_page_rows_are_committed_by_count_bytes_and_age_and_flushed_at_close`.
- **FR-CRAWL-37 (captured requests kept per API operation, CC-CRAWL-0057, BUG-0546,
  audit defect 9)** The spider's capture writer (`StorageManager.record_request`, the
  one writer of `discovered_requests`) keys every row through `tools/apiop.py`:
  - **The operation** (`apiop.operation_key`): two captured requests are one API
    operation only when their method, canonical origin and path (`core.urls.url_key`;
    an exact path, never coarser than its template), media type and every **operation
    selector** match. The selectors (`apiop.operation_selectors`), in the body at any
    depth and in the query:
    - a GraphQL document's operation (type, name and root fields, for the operation
      `operationName` selects; aliases resolved, fragments expanded; read by a linear
      scanner, at most 20000 tokens and 16 operations; a longer document is told by the
      digest of its whitespace-folded text; a `query` string that is no executable
      document, such as search text, selects nothing);
    - the value of a dispatcher field: `action`, `act`, `op`, `operation`,
      `operationName`, `cmd`, `command`, `do`, `task`, `func`, `function`, `method`
      (JSON-RPC), `_method` (a method override), compared lower-cased, whatever its
      value when that value is a non-empty string or an integer (a boolean, an empty
      string, `null`, a float or a container selects nothing). A string is keyed with
      every run of whitespace folded to one space: a folded value of at most 64
      characters (`apiop.MAX_SELECTOR_CHARS`) by its text, a longer one by
      `sha256:` and the digest of its folded text. So multi-word values (a submit
      button's `value="Add to cart"`) and long ones keep their operations apart. A data
      field so named is a selector too: misjudging it costs a row, never an input.
      *(CC-CRAWL-0057 review round 1, B1: a value with whitespace, or over 64
      characters, was data, so two operations told apart only by it were merged.)*
  - **What a request adds** (`apiop.request_shape`, `apiop.operation_schema`): a
    request's shape is its typed key paths, every position of its body at every depth
    with the JSON type found there (array elements as one position), and each query
    parameter name. An operation's merged schema is the union of its stored rows'
    shapes. Every stored row is one real redacted body the application sent:
    - a request whose exact shape a row of its operation already has is a `duplicate`;
    - one whose shape adds a key path or a type, at any depth, to the merged schema is
      always stored: no input a captured request carried is dropped;
    - one that only combines known inputs differently (another context) is stored
      while the operation has fewer than 32 rows (`apiop.MAX_CONTEXT_ROWS`), then not
      recorded: counted in `requests_not_recorded` and logged as "operation over its
      context cap".

    Bodies are never merged into one row: the importer judges a body as a whole
    (FR-AUD-22's refusals, `jsonbody.MAX_LEAVES`), so a merged body would be refused
    for a field another request carried (measured 2026-10-21: `{"q"}` imports,
    `{"q", "sort"}` is refused as a settings field, and the 80-leaf union of two
    40-leaf bodies is over the leaf limit).
  - **Bounds:** the context cap above; at most 64 selectors per operation; a selector
    value in the key is at most 71 characters (64, or `sha256:` and a digest). A
    request that adds an input is never capped, and each distinct selector value is its
    own operation (both bounded by the crawl's captures, as before).
  - **Known gaps (PA-0505(2), BUG-0546 sweep), pinned by strict xfails in
    `tests/test_captured_operations.py` (PA-0531(4)):**
    - disco's synthesizer (FR-CRAWL-20) keys an endpoint by origin, method, template
      and content family, so a GraphQL or JSON-RPC endpoint's operations are one
      inventory operation (their schemas are merged, not lost; the disco import itself
      imports every exchange);
    - `StorageManager.record_form` keys a crawled form by action, method and control
      names, so a form told apart only by a hidden dispatcher value is dropped;
    - the importer (`tools/store_adapter.py::_store_request`, FR-AUD-22) keeps a
      captured request's parameter only when no earlier captured request on its
      endpoint has that name, so the inputs a second operation shares by name with the
      first (every GraphQL operation's `query`, `operationName` and a shared variable
      name) are bound to the first operation's form and never sent with the second's
      document: the rows FR-CRAWL-37 keeps reach the store as forms, not all as points
      (audit defect 8);
    - the pipeline's DOM-template stage (`core/dedup.py`, `harness/pipeline.py::_dedup`)
      keeps only the points on the first page of each tag-skeleton template (audit
      defect 10, BUG-0547).

    A spider DB written before FR-CRAWL-37 keeps its rows; a resumed crawl stores new
    rows beside them (an old signature never matches a new one).
- **FR-CRAWL-38 (the capture proxy's work is off its event loop: bounded, paced,
  counted; CC-CRAWL-0058, BUG-0548)**
  mitmproxy runs the recorder's hooks on the one loop that carries every browser
  request.
  - **A hook only takes the exchange** (`capture.snapshot`): the scope check, then the
    header pairs and each body as sent (`raw_content`, content-coded), by reference, in
    time that does not depend on the bodies. The recorder's one writer thread builds
    the record (`capture.build_record`): each body decoded through SP-60
    (`bodyread.read_body`) under `MAX_CAPTURE_BODY_BYTES` (8 MiB), then `make_record`,
    the JSON, the append and flush. Records keep their order (one writer, one FIFO
    line). A failure there is logged and counted, and the writer goes on.
    - Enforced by an AST guard (`tests/test_capture_hook_guard.py`): no per-flow hook
      of a `fuzzlab` mitmproxy addon reaches body or record work (decoding, redaction,
      building, serialising, writing, or a message's decoded `.content`/`.text`).
  - **A body is captured whole or not at all.** A body over the ceiling as sent is
    never held (`omitted.too_large`). One over it once decoded, in a coding with no
    bounded decoder, or corrupt is `omitted.undecodable`. Either way the record has no
    body and says `*_truncated` (PA-0455). Each request's `Accept-Encoding` is narrowed
    to what SP-60 can bound (`bodyread.advertise`; Chromium asks for `zstd` too,
    measured).
  - **The queue is bounded by records (`QUEUE_MAX`, 10 000) and bytes held
    (`QUEUE_MAX_BYTES`, 32 MiB), with backpressure.**
    - An exchange that does not fit waits. Its hook returns an awaitable that
      mitmproxy awaits, so that flow -- and every exchange after it, to keep the
      order -- is held back while the loop runs on (`waited`).
    - After `BACKPRESSURE_WAIT_S` (30 s) it is queued without its bodies
      (`omitted.backlog`), or dropped when even that does not fit (`dropped`).
    - A waiting exchange whose flow is cancelled is `dropped`. At shutdown the line
      is handed to the writer: its exchanges are complete.
  - **Shutdown drains.** The recorder waits `DRAIN_TIMEOUT_S` (30 s) in all for its
    writer. The capture proxy's stop grants mitmdump `proxyproc.STOP_GRACE_S` (45 s)
    before a kill. What is still unwritten is `queued` in the final stats.
  - **The GIL.** The writer's work holds the GIL, so mitmdump's process switches
    threads every `SWITCH_INTERVAL_S` (1 ms), not CPython's 5 ms.
  - **Measured (BUG-0548)** on a loopback page firing fetches through a real mitmdump
    and Chromium, before and after back to back under the same host load:
    - 1500 x 64 KiB gzip JSON: response hook median 7.44 -> 0.17 ms, and its total
      time on the loop 13.1 -> 0.44 s. Loop lag p99 67.8 -> 38.9 ms. Page 71.7 -> 85.9
      requests/s. Nothing lost.
    - 200 x 1 MiB: hook median 104 -> 0.19 ms. Loop lag p99 467 -> 18.3 ms. Page
      8.4 -> 10.7 requests/s, paced to the writer (7.4 records/s). All 201 records
      written whole.
    - A repeat pair under heavier load agrees (BUG-0548's table).
- **FR-CRAWL-39 (the composed UI tree, CC-CRAWL-0059, BUG-0551)** Discovery reads what a
  page offers across its composed tree, not only its top document's light tree.
  - **One walk** (SP-70, `tools/composed.py::COMPOSED_JS`): a document and every open
    shadow root under it, each shadow tree right after its host. On a page without a
    shadow root, its order and result are `querySelectorAll`'s. Every crawler page
    script that discovers or locates UI builds on it. A light-tree-only query is a
    reviewed allowance with its count and its reason
    (`tests/test_composed_tree_guard.py`).
  - **disco** (`disco/compose.py::read_page`, from `Explorer.enumerate`):
    - It reads the page's document and each **visible, same-origin, in-scope frame**,
      each in its own main-world context, breadth first, at most 8 frames, 3 deep.
    - It runs through DevTools' `Runtime.evaluate` with the Command Line API when the
      browser has it, else through Playwright (no listeners then).
    - An element's ancestry goes on past each shadow root (`^shadow<host`) and each frame
      (`^frame<iframe#id<@/path`). Its signature, the identity of its steps and of the
      states it is in, says which component and frame it is in; on a page without
      shadow roots or frames, signatures are unchanged.
    - A step is located through the frame markers (`compose.frame_scope`) and a
      selector that pierces open shadow roots, so a state reached through a shadow root
      or a frame is restored by replaying there.
    - A form's controls are read, and earlier `data-disco-field` markers cleared, across
      the document's composed tree. A control's container may be the shadow root its
      ancestors end at (FR-CRAWL-19's form rule; review round 1).
    - The described elements are bounded at 400 per read across the page and its
      frames, as before.
  - **What is not read is counted in `explore.json`, never claimed.** Per route; a page
    read again adds nothing; written while the run is live.
    - **Read:** `shadow_roots` (open shadow roots) and `frames` (same-origin frames).
    - **Not read:**
      - *(Amended in place, review round 1; was: custom elements whose light tree
        renders nothing, at most 16 per document.)* `closed_shadow_roots`: every element
        of a document read that hosts a closed shadow root, on any host and whatever its
        light children render, found by one `DOM.getDocument` of the page with every
        shadow root and in-process frame pierced (`compose._census`). A page is checked
        once per route and shape (each read document's tag and child-count digest);
      - `frames_cross_origin`;
      - `frames_out_of_scope` (by its `src` or its document; the guard never loads it).
    - **`budget_limited`:** per bound (`elements`, `candidates`, `delegated`, `nodes` (a
      walk past 30 000 elements), `frames` (past the frame bounds, or navigating under
      the read), `census` (the elements whose shadow roots were not checked: a page
      whose documents read hold more than 30 000 elements, read without DevTools, or
      navigating under the check)), what it left out.
  - **The spider's form read** (`spa.FORMS_JS`, also the session manager's browser login)
    finds forms, buttons and controls across open shadow roots. *(Review round 1.)* A
    button's container may be the shadow root its ancestors end at (a form-less widget,
    described by its host).
  - **Not covered:**
    - A closed shadow root attached where the page's composed shape did not change
      (the same tags and child counts) is counted only once the shape next changes.
    - A cross-origin frame is not read in the page; its URL is explored as a top-level
      page when the harvest reaches it.
    - The harvest's link extraction reads the top document's serialised light tree;
      links inside shadow roots and frames are reached by acting on them.
- **FR-CRAWL-40 (delegated actions, and the composed tree's known gaps, CC-CRAWL-0059,
  BUG-0551)**
  - **A delegated candidate** is a labelled, non-semantic element with no action
    listener of its own and no pointer cursor, whose composed event path (an ancestor
    element, a shadow root, its document or its window) listens for `click`,
    `dblclick`, `mouseup` or `pointerup`. It must hold no other candidate and no
    described element, and must cover less than a quarter of the viewport. Only the
    first of each shape is kept, at most 16 per read (`budget_limited.delegated` counts
    the rest). It is described `how: "delegated"`.
  - **Each is tried once per run**, at most 48 trials (`compose.Trials`). A trial clicks
    it and waits for quiet. It is **live** when its click caused a request, the URL
    changed, a page opened or *(amended in place at the merge with CC-CRAWL-0055; was:
    the explorer's own state fingerprint)* the page's execution key (FR-CRAWL-31)
    changed: a performed, logged action, clicked like any other from then on. Otherwise
    it is **inert**: never logged, never counted an action, and described `disabled`
    from then on. A candidate still untried once the trials are spent is described
    `disabled` and counted `delegated_unexplored`. *(At the merge with CC-CRAWL-0055.)*
    A trial whose click reached nothing (the candidate gone, or not actionable) is no
    verdict: it is released and counts as a failed attempt (FR-CRAWL-32). Whether a
    live step is safe to replay (FR-CRAWL-33) is decided from the requests after its
    click: the control window's are the page's own.
  - *(Review round 1.)* **A request the click caused** is one whose method and
    normalised route (`explore.request_key`) are not explained on that route: just
    before the click, a **control window** leaves the page alone for the same quiet
    wait (from an action mark); what it, or an earlier control window on the route,
    saw is the page's own traffic (a poll, a beacon, a keep-alive), and a key an
    earlier trial there already counted is not counted again.
  - *(Review round 1.)* **A delegated candidate is no part of a state's identity**
    (FR-CRAWL-19's states): which labelled leaves are candidates depends on their text
    and order, so a click that only swaps static text under a document listener stays
    in its state.
  - **Counters** (`explore.json`): `delegated_trials` = `delegated_live` +
    `delegated_inert`, and `delegated_unexplored`.
  - **Known gaps (pinned or allowed):**
    - The spider's G1 read (`spa.G1_READ_JS`) and the browser login's X3 password clear
      (`session/browserlogin.py::_CLEAR_IF_PRESENT`) resolve a FORMS_JS id with
      `document.querySelector`. Until both go through SP-70, FORMS_JS never describes
      a password control inside a shadow root: its container is read by its light tree
      only, and left out when it is in a shadow root itself. Both are pinned by strict
      xfails.
    - The legacy spider's reveal, option and menu scripts read the light tree only, and
      the spider reads no frame and no delegated action (deprecated, FR-CRAWL-21).
    - *(Review round 1.)* Background traffic slower than a control window can make one
      inert candidate per route and request key live (measured: a 2.5 s poll with
      `idle_ms` 500, at most one per run, 4 of 12 inert candidates over 4 runs; 0 of
      21 at 400 ms and 1 s).
    - *(Review round 1.)* A delegated candidate that appears only after an action that
      changes nothing else in the state is not tried there: the state is unchanged, and
      its steps were planned before the action.
- **FR-CRAWL-41 (disco: a lost session, CC-CRAWL-0060, BUG-0552)** An authenticated
  exploration (FR-CRAWL-19) decides that the session its contexts carry was lost only
  through the session layer's owners, replaces it only with a fresh, revalidated one,
  and never takes an answer on a session known lost as the identity's coverage (D′).
  - **The session.** `Explorer(storage_state=)` or `Explorer(session=ExploreSession(
    manager, identity, base_url))` -- one, not both. With a provider the context adopts
    the manager's session (`ensure(..., operator=True)`) through
    `browserauth.browser_session`: its cookies and a browser login's storage state; a
    session carried only in headers is refused (`SessionUnavailable`, raised at the
    start). The run holds one session **generation** at a time (the manager's; 0 for a
    storage state) and every worker's context carries the current one.
  - **One generation for every worker** *(review B1)*. A lost, stale or unresolved
    verdict is recorded for the whole run (`_Shared.lost_generations`) at the verdict,
    under the recovery lock, before any recovery starts. A worker whose context carries
    a generation that is gone (recorded lost, or a newer one installed) never acts,
    restores or loads on it: it checks before every action, restore and harvest load
    (*(amended in place at the merge with CC-CRAWL-0055; was `_ready`)* `_bring_to`,
    `_restore_checked`, `_load`), not only at a state boundary; its
    checkpoint marks its window (stale) even when its answers show no sign; it then
    waits for the recovery decision and adopts the newer session or stops. The action
    ids a context sent after its window was marked, up to its release (a replacement or
    the worker's end), are marked too.
  - **Suspicion.** After every action, restore, harvest load and the seed, each request
    the context sent on the session's origins whose answer arrived whole
    (`requestfinished`) is classed by SP-56 (`core.comparability.response_class`,
    credentialed, with SP-16's `login_facts` and `request_entry_names`): an auth failure
    (a 401 or a login redirect that is not a credential submission; never a 407, which
    is an auth failure to anyone) is a suspected loss, a policy block (403, 451) a
    suspected denial; a throttle, a gateway, an incomplete answer or another origin's
    answer is no sign. The page is read whatever the answers were *(review R2)*. The
    page at a login URL (`looks_like_login_url`), or showing this session's login form
    (`shows_login_form` with the session's login page and fields), is a suspected loss
    -- unless the step asked for a login URL (a link, a harvest URL, the state's own
    URL), or, for a form, the page already showed one. With no known login form, any
    password form is one *(review R1)*: **in place** (strong) where the page was known
    without one -- the URL before an action, the restored state's URL or entry URL (a
    state records whether it showed a password form when found, `State.login_shown`),
    the start page at the seed; elsewhere (a harvest load, a navigation) it is a weak
    sign, raised only when a protected check will decide it.
  - **Decision.** With a provider: SP-61, `SessionManager.check_health` for the
    context's generation (``signal_url`` the answer's or page's URL, ``policy`` for a
    policy block, ``pause=False``). Live: an answer or a policy block was an
    authorization denial (`authorization_denials`) and nothing changes; after an action,
    a strong page sign on a live session means the context no longer carries it --
    whichever answer (a 401 its script read) came with it *(review R2)* -- and the
    context is given the live session again (`session_reinstalled`); a login page a
    restore or load shows, or a weak sign, is that page's own. Lost: confirmed. Stale
    (another generation): the context is replaced with the current one. Inconclusive,
    or a check that cannot run: unresolved. **Without a provider** *(review R3)*: at the
    seed, the start page's URL becomes the run's protected resource when SP-61's
    `health_verdict` reads a GET of it with the context's cookies as live and one with
    no credential as refused (a login redirect, a 401, a login form); both GETs, and
    each check, go straight to the target from a request context of their own (never
    through the capture proxy: not the identity's exploration), are scope- and
    destructive-gated at the send (`checked_api_request`, `check_send_url`), follow no
    redirect and verify TLS; this is disco's second send path of its own, beside the
    contract runner's (`tests/test_disco_isolation.py`). A suspicion (a loss shape or a policy block) is then decided by a GET of
    it with the suspected context's cookies (`health_verdict`): live, an authorization
    denial; lost, confirmed; anything else, unresolved. With no such resource, a loss
    shape is an unconfirmed loss and a policy block never is one (PA-0533(1)).
  - **Recovery** (single flight across workers): a newer generation another worker
    installed is adopted; else the provider's session is taken (`ensure`, which logs in
    again on a lost one), must be another generation, and must pass its own protected
    check (`check_health`, ``use_cache=False``) before use. The old context is released
    (SP-38) and **closed** before the new one is made. At most
    `ExploreOptions.max_session_recoveries` (3) fresh sessions or re-gives a run. A loss
    nothing resolves -- no provider, an unresolved check, no fresh session, the cap --
    **ends the run's exploration** (the identity is the run's only one: an anonymous
    continuation would be recorded under its profile), the reason in
    `ExploreReport.auth_ended` and a warning; it never re-installs the storage state
    the run started from.
  - **The known-lost window (D′).** The action ids requests went out under since the
    last checkpoint without a sign are marked on a loss: appended to
    `ExploreReport.session_lost_actions` and written as one `actions.jsonl` line
    `{"kind": "session", "session": <lost|stale|reinstall|unknown>, "reason",
    "generation", "action_ids"}` (no `seq`: `observe.DiscoActionLines` and the importer
    pass over it). The action whose answers fell in it is logged with no new state and
    no URL and denied for the rest of the run (it may have ended the session), unless
    the window was stale; nothing a lost window showed becomes a state, a harvest URL's
    document or a gathered link. Reasons name a class and a status, never a URL.
  - **Reading the mark** *(review B2)*. `disco.capture.lost_action_ids(run_dir)` is
    the one reader of the mark (SP-71): the action ids of every `session` line, read
    bounded (`JsonlTail`). Every function of `fuzzlab/` that reads a capture's records
    reads the mark too, or is listed with its pin or reason
    (`tests/test_lost_window_mark.py`). `fuzzlab disco ede` reads it (FR-CRAWL-25).
  - **Counters** (`explore.json`): `session_lost` (confirmed, or unconfirmed without a
    provider), `session_suspected`, `authorization_denials`, `session_recovered`,
    `session_reinstalled`, `session_lost_actions`, `auth_ended`.
  - **Not covered (residuals, BUG-0552):** `fuzzlab disco capture` offers a storage
    state only (no provider flag yet). Two consumers do not read the window's mark yet,
    each pinned by a strict xfail naming its owner: `disco synth` (CRAWL) and
    `store_adapter.import_disco` (AUD: a lost window's status and media type are its
    page and path-template evidence). The live trace shows a lost window's exchanges
    as exchanged (not evidence). Answers a context got after the server invalidated its
    session but before any worker's checkpoint found a sign are not marked (D′ covers a
    session *known* lost). Without a provider and without a protected resource, a
    password form at the same place reads as an unconfirmed loss, and one shown by a
    harvest load or a navigation is no sign. With a resource, a context that lost only
    its own copy of the session (its script cleared a cookie) reads as lost, never
    re-given the storage state.
  - *(At the merge with CC-CRAWL-0055 and CC-CRAWL-0059.)* An action whose answers
    fell in a known-lost window finishes its work item (FR-CRAWL-32: its effect a lost
    session); a delegated trial decided in such a window decides nothing (its verdict
    reopened, FR-CRAWL-40). A replaced context reads its states in the next session
    generation of the execution key (FR-CRAWL-31). The first-visit and dismissal reloads
    (FR-CRAWL-33) are session-checked before anything is declared from them. A step is
    taken only on a page that holds its state's contract and a current session
    (`_bring_to`); a restore lost twice is unresolved `session-lost`.
- **FR-CRAWL-42 (the capture writer is total: a lone surrogate is stored, a failed write
  is counted; CC-CRAWL-0061, BUG-0554)** A captured JSON body may hold a `\udXXX`
  escape with no partner (valid JSON; measured 2026-10-21, Chromium's `JSON.stringify`
  writes half an emoji pair that way), which `json.loads` decodes to a lone surrogate
  code point that SQLite's bind and a strict UTF-8 encode refuse.
  - **Stored losslessly.** `StorageManager.record_request` writes `body_json` with
    `tools.apiop.storable_json`: each surrogate as its JSON escape, so the row reads
    back as the body the app sent. The operation key (`apiop.operation_key`, hence every
    signature and the lookup prefix) is written the same way, and every digest
    (`row_signature`, a GraphQL document over the token cap, a long selector value)
    encodes with `surrogatepass`. For text without a surrogate both are byte-identical
    to the FR-CRAWL-37 forms, so no stored row or signature changes.
  - **The probe-marker scrub** (FR-CRAWL-17) still reads the raw text, before the
    escape: an escape's hex digits would end the token before a marker.
  - **Never raises.** A write the store still refuses (a lock, a full disk, anything
    raised on the way) is rolled back and returned as `write failed (<error class>)`;
    the passive capture and the dry-submit path (`_record_dry`) count it in
    `requests_not_recorded` and log it, as every other reason. Nothing reaches the browser guard's observer catch, which only logs.
  - **Its reader.** The importer refuses such a body, counted (FR-AUD-22); a field
    holding a lone surrogate cannot be a store row.
  - **Known gap, pinned** (strict xfail in `tests/test_capture_surrogates.py`): a body
    with a sensitive field and a lone surrogate is refused as "redaction failed"
    (counted, not stored), because the storage boundary (`core.redaction.
    redact_json_body`, CORE) re-encodes a rewritten body strictly.
- **FR-CRAWL-43 (a browser context carrying a session sends nothing to a host its
  cookies do not reach; CC-CRAWL-0063, CC-CRAWL-0064, BUG-0559, SP-74)** A browser
  carries a cookie session by host (RFC 6265: a host-only cookie goes to its own host
  only; a dotted domain to the names under it, never an IP), while the crawl scope and
  the session's origins fold the loopback aliases (`localhost`, `127.0.0.1`, `[::1]`)
  into one origin. A request there goes without the session to what the tool takes for
  the session's own origin, and its anonymous answer would be the identity's.
  - **One owner, every request.** `tools/navguard.py` decides it: `cookie_reaches` (the
    domain match; an IPv6 literal compared without its brackets on both sides, since
    Chromium holds a cookie for `[::1]` with the domain `[::1]` -- measured, review round
    1, BA-2), `session_host_refusal` (a host where one of the session's cookies has
    no held copy that reaches it; `None` for a context with no session cookie and for an
    origin FR-SESS-20's `cookie_scope` puts outside the session's, which keeps its own
    disposition: documents aborted, the rest fetched cookie-less) and
    `held_session_cookies` (the session's cookies as a context that adopted them holds
    them: by URL, and an adopted `storage_state`'s by domain, kept to the credential
    names when known). Every guarded context that adopts a session passes them to
    `guard_page(session_cookies=, on_session_unreached=)`; its route refuses a
    navigation (top-level or frame), each redirect hop, a subresource (an image, a
    script, a `fetch`/XHR) and its WebSocket handler a socket, to such a host, right
    after the scope and destructive checks and before anything is sent (a document with
    `ERR_ABORTED`, SP-02), and tells `on_session_unreached(url, kind, source, reason)`.
    `checked_api_request(..., session_cookies=)` refuses an API request the same way
    (`SessionHostUnreached`). No alias list: the host is compared with where the cookies
    go.
  - **No request the route does not see** *(review round 1, BA-3; measured on Chromium
    141, the full browser and the headless shell)*. A speculation-rules prefetch is sent
    by the browser process, past the route -- a prefetch of the alias went with no
    cookie, a same-origin `/logout` named by document rules went with the session past
    the destructive rule -- and a navigation it served committed the alias's anonymous
    page past the route too. No launch switch or CDP call stops it. So every guarded
    context, with or without a session, never registers a rule set: `guard_page`
    installs `navguard.PRELOAD_OFF_JS` before any page script runs (every
    `<script type=speculationrules>` taken out as it is inserted -- by the parser, a
    script, a fragment, `document.write`, into an open shadow root, re-inserted --
    with what it calls captured before the page runs); the route drops the
    `Speculation-Rules` header from every answer and gives a main-frame document's
    parser-inserted rule sets an inert type (a closed declarative shadow root, which no
    script sees); and a popup's first document -- which Chromium loads into the Window of
    its initial `about:blank`, where no init script runs again -- is answered with a
    same-URL trampoline and then given the answer the route already fetched (sent once).
    A `<link rel=prefetch>` is the page's own request and passes the route as any other.
  - **The document a load committed** is checked before anything of it is read
    (`navguard.committed_session_refusal`, defence in depth behind the route): a main
    frame on a host the session's cookies do not reach is never read as the session's.
  - **The legacy spider** (`--engine playwright`, an identity crawl): every refusal is
    counted (`session_host_unserved`). A load whose own redirect hop was refused, or
    whose main frame is found committed on such a host before extraction, is stored
    `failed` with the cause (`HostNotServed`, unresolved, resumed; no static
    fallback); a navigation the page made itself leaves the page with its own content,
    and its target is queued and refused at the load gate (FR-CRAWL-34: stored
    `failed`); a selector form's submission there is never sent. No anonymous landing
    is ever stored.
  - **Disco** (`disco capture`, a storage state or a session provider): the explorer's
    context passes the session material's cookies -- a provider's credential cookies; a
    storage state's cookies that reach the start URL's host (`navguard.names_reaching`,
    review round 1, BA-1: disco cannot tell a state's credentials from its ambient
    cookies, and an ambient cookie held for an alias or another scope origin never
    makes the start host unreached; a state none of whose cookies reaches the start
    host keeps them all, so the start host is refused, never explored as the session's)
    -- and counts each refusal by host in `explore.json`
    (`explore.session_host_unreached`), printed in the capture summary. A state read
    (`settled_fingerprint`) of a document committed on such a host is none (counted),
    and the protected-resource probe never takes such a page.
  - **The auditor's browser fetcher** (FR-AUD, CC-AUD-0060) does the same for its pages.
  - Enforced by: `tests/test_browser_session_reach.py` -- the predicate (the IPv6 held
    form included) and the route on doubles; real Chromium on loopback for a redirect
    hop, a selector form, a script's `location` and a meta refresh (each with an image
    and a `fetch` to the alias), the auditor's fetcher and disco's explorer, each
    asserting the alias received no request and no anonymous landing is stored; and an
    AST guard that every module adopting a session into a browser context passes
    `session_cookies=` to every `guard_page` and to `checked_api_request` beside an API
    request context with a storage state, proven on synthetic offenders. Each
    real-browser test fails on 7393c90 on its own assertion (the alias received the
    requests with no cookie). *(Review round 1:)* Chromium's held form of an IPv6 cookie
    (`test_an_ipv6_cookie_as_chromium_holds_it_reaches_its_own_host_and_no_other`); a
    storage state with an ambient alias cookie, explored with the session in disco
    (`test_disco_explores_its_start_host_with_a_storage_state_that_holds_an_alias_cookie`,
    `test_a_storage_states_ambient_cookie_on_another_host_never_refuses_its_start_host`);
    no preload of any measured shape leaves a guarded context
    (`test_no_speculation_rules_preload_leaves_a_guarded_context`,
    `test_the_auditors_fetcher_and_the_spider_never_preload_the_alias`,
    `test_the_route_gives_no_speculation_rule_set`,
    `test_every_guarded_context_neutralises_preloads_before_its_pages_run`); a preload
    past the guard is never read as the identity's page
    (`test_a_preload_past_the_guard_is_never_read_as_the_identitys_page`,
    `test_disco_never_reads_a_state_or_a_protected_resource_on_an_unreached_host`,
    `test_a_document_committed_on_an_unreached_host_is_never_the_sessions`). Each fails
    on 72297c9 on its own assertion (`scratchpad/lanes/BROWSERALIAS/r1proof/proof.log`).

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
  *(BUG-0545 review, B1:)* and every load, where it is made (`_visit`): scope and the
  destructive rule are asked again whatever queued it, a resumed crawl's stored rows
  included (FR-CRAWL-35). *(BUG-0559 review round 1, BA-3:)* and no browser preload
  makes a request the route never sees: Chromium's speculation-rules prefetch of a
  same-origin `/logout` a page's document rules named went with the session past the
  destructive rule (measured on Chromium 141), so no guarded context ever registers a
  rule set (`navguard.PRELOAD_OFF_JS`, FR-CRAWL-43) --
  `tests/test_browser_session_reach.py::test_no_speculation_rules_preload_leaves_a_guarded_context`.
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
  landing, a timeout, anything), `_fetch_rendered` first ends the previous document
  through `navguard.end_failed_load` (SP-01; *CC-CRAWL-0049, BUG-0522*): when the
  failure settled on the browser's own error page, that page has already replaced it
  and nothing more is navigated; otherwise the page goes to `about:blank`, so a
  document ERR_ABORTED left alive stops. Either way its timers and fetches are never
  sent or captured under the URLs crawled next. Then the withheld check,
  `SessionWithheld` or the static fallback run as before. A seed, probe or reveal
  window that cannot close cleanly leaves its page the same way.
  *(CC-CRAWL-0030, BUG-0138:)* **no guarded navigation waits for a load a refused
  navigation can cancel.** A script that navigates to a refused URL while the page is
  parsed stops the page's loading, so `domcontentloaded` never fires.
  - Every navigation of a guarded page goes through `navguard.navigate` / `reload`:
    wait for the commit (a refused own target still raises), then for the load state at
    most the caller's timeout, cut short 300 ms after a main-frame navigation fails.
    Only failures reported at or after this navigation's commit count, so a previous
    page's pending navigation, cancelled by this one, never cuts the wait (review Q1).
  - *(CC-CRAWL-0049, BUG-0522:)* **a failed navigation raises only once the commits its
    failure starts have landed.** Only the first line of the error decides:
    - a network error other than an abort (an empty error answer) waits for the
      browser's own error page;
    - "interrupted by another navigation to chrome-error://" waits for that page and
      then for the overtaken navigation's own late commit.

    A commit counts only if a listener registered before the navigation saw it. The
    page's current URL never counts: after one failure it already shows an error page.
    The wait is bounded by `ERROR_PAGE_WAIT_MS` (3 s); every expiry is counted
    (`navguard.error_page_waits()`) and logged. An abort, a download or a timeout
    raises at once, as before. Without this, the late error page overtook the next
    navigation of every caller: the next crawl load, a seed, disco's harvest and
    restore.
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
  - No other module of fuzzlab navigates a page or waits for a load state itself. A
    failed load's cleanup is `navguard.end_failed_load`. Every other `about:blank`
    navigation outside navguard is allow-listed by function, with its reason: a fresh
    document before a query load or a disco restore, a window's exit, an unfinished
    reload's stop. None of them sits in an `except` or `finally` (BUG-0522).
  - Enforced by (the abort code, per reason; BUG-0136): `navguard.make_route_handler` (`abort()`, `_abort_code`) — `tests/test_navigation_aborts.py::test_every_abort_reason_keeps_the_document_for_a_navigation`, `tests/test_navigation_aborts.py::test_a_script_navigation_out_of_scope_keeps_the_page_crawled`, `tests/test_navigation_aborts.py::test_a_script_navigation_to_a_destructive_url_keeps_the_page_crawled`, `tests/test_navigation_aborts.py::test_goto_of_a_refused_target_still_raises_and_the_page_stays`, `tests/test_navigation_aborts.py::test_the_crawls_own_target_redirected_to_a_refused_url_raises_and_falls_back`, `tests/test_navigation_aborts.py::test_a_refused_post_form_submission_keeps_the_page_crawled`, `tests/test_navigation_aborts.py::test_a_refused_iframe_keeps_its_parent_crawled`
  - Enforced by (a failed load ends the previous document; BUG-0136 review X1, BUG-0522): `navguard.end_failed_load`, called by `LocalSpider._fetch_rendered` — `tests/test_navigation_aborts.py::test_a_failed_load_ends_the_previous_document`, `tests/test_navigation_aborts.py::test_an_error_page_ends_the_previous_document`
  - Enforced by (a failed navigation settles before it raises; the cleanup has one owner; BUG-0522): `navguard.navigate` / `reload` (`_settle_failure`), `navguard.end_failed_load` — `tests/test_navigation_aborts.py::test_a_failed_navigation_returns_after_its_own_error_page`, `tests/test_navigation_aborts.py::test_a_navigation_overtaken_by_an_error_page_waits_for_it`, `tests/test_navigation_aborts.py::test_only_the_leading_code_decides_a_wait_for_an_error_page`, `tests/test_navigation_aborts.py::test_a_refused_load_naming_a_network_error_in_its_url_is_not_waited_for`, `tests/test_navigation_aborts.py::test_the_spiders_load_after_failed_loads_is_rendered`, `tests/test_navigation_aborts.py::test_a_query_load_after_a_failed_load_is_rendered`, `tests/test_disco_harvest.py::test_disco_harvest_and_restore_after_failed_loads`, `tests/test_shared_primitives.py::test_every_about_blank_navigation_is_a_reasoned_exception`, `tests/test_shared_primitives.py::test_the_about_blank_guard_catches_synthetic_offenders`
  - Enforced by (no navigation waits for a load a refused navigation cancelled; one helper; BUG-0138): `navguard.navigate` / `reload` / `wait_for_state` / `response_html`, `LocalSpider._goto_and_parse` — `tests/test_guarded_navigation.py::test_a_head_script_navigation_to_a_refused_url_is_not_waited_out`, `tests/test_guarded_navigation.py::test_a_slow_page_is_still_waited_for`, `tests/test_guarded_navigation.py::test_query_probe_and_seed_loads_are_not_waited_out`, `tests/test_guarded_navigation.py::test_every_guarded_navigation_goes_through_the_one_helper`, `tests/test_guarded_navigation.py::test_the_navigation_guard_catches_synthetic_offenders`, `tests/test_guarded_navigation.py::test_a_failure_reported_before_the_commit_never_cuts_the_wait`, `tests/test_guarded_navigation.py::test_a_previous_pages_pending_navigation_never_cuts_the_next_load`, `tests/test_guarded_navigation.py::test_a_merely_slow_page_keeps_its_rendered_text`, `tests/test_guarded_navigation.py::test_another_document_never_fills_this_urls_row`, `tests/test_guarded_navigation.py::test_a_same_path_document_with_another_query_never_fills_this_urls_row`
  - Enforced by (scope, per layer): `LocalSpider._in_scope`, `navguard.guard_page` / `make_route_handler` / `make_ws_handler` / `browser_launch_args` / `checked_api_request` — `tests/test_spider_scope.py::test_loopback_start_treats_aliases_as_one_host`, `tests/test_browser_scope.py::test_a_rendered_crawl_never_leaves_the_target_origin`, `tests/test_browser_scope.py::test_the_launch_args_alone_confine_an_unrouted_page_to_the_origin`, `tests/test_browser_scope.py::test_a_redirect_hop_out_of_scope_is_never_requested`, `tests/test_browser_scope.py::test_out_of_scope_requests_are_aborted_and_reported`, `tests/test_browser_scope.py::test_allow_never_lifts_scope`, `tests/test_browser_scope.py::test_websockets_are_scope_checked`, `tests/test_browser_scope.py::test_the_spiders_isolated_submit_refuses_an_out_of_scope_action`, `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`, `tests/test_browser_scope.py::test_the_browser_guard_catches_synthetic_offenders`, `tests/test_browser_scope.py::test_scope_is_checked_before_any_fetch`
  - Enforced by (every load, whatever queued it -- a resumed crawl's stored rows included -- passes scope and destructive first; BUG-0545 review, B1): `LocalSpider._load_refusal`, asked first by `LocalSpider._visit` — `tests/test_spider_frontier.py::test_a_resumed_crawl_never_loads_a_stored_row_out_of_its_scope_or_destructive`
  *(CC-CRAWL-0039, BUG-0503:)* **a URL source feeding the queue returns only GET-safe
  URLs**: `core.linkextract` never returns a form `action`, a `formaction`, a `ping` or
  a script string; forms are submitted only through the gated paths, and a script's
  requests are what the browser was seen to make.
  - Enforced by (no write target is a link; BUG-0503): `core.linkextract` — `tests/test_linkextract.py::test_a_submission_target_or_a_script_string_is_never_a_link`, `tests/test_spider_links.py::test_every_linked_resource_is_followed_and_the_gates_still_refuse`
  *(CC-CRAWL-0040, BUG-0504:)* **teardown keeps a refused request refused**: a guarded
  page is closed only through `navguard.close_pages` (frozen, drained through the guard,
  then closed); `release` adds a refuse-all route and never unroutes.
  - Enforced by (teardown; BUG-0504): `navguard.close_pages`, `navguard.release` — `tests/test_navigation_aborts.py::test_a_navigation_started_at_teardown_is_refused_never_sent`, `tests/test_shared_primitives.py::test_a_guarded_page_is_closed_only_through_close_pages`, `tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting`
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
  account-action or credential-bearing seed or probe URL is never loaded, a
  redirect-ish name carries a same-origin `/`, a probe load records nothing, a seed
  whose load blocked a write is never a point (so M6 never replays that write outside a
  window), and in an authenticated crawl a session lost in a query load stops them
  (FR-CRAWL-17).
  - Enforced by (seed and probe loads, FR-CRAWL-17): `LocalSpider._window(query=)` / `_leave` / `_query_gate` and the crawl loop's store-suppression branch, `spa.query_url_refusal`, `spa.seed_url` — `tests/test_spa_query.py::test_a_seed_load_cannot_write`, `tests/test_spa_query.py::test_a_seeds_navigations_are_queued_never_followed_in_its_window`, `tests/test_spa_query.py::test_a_destructive_seed_is_never_visited_and_a_redirect_name_stays_on_origin`, `tests/test_spa_query.py::test_the_seed_gate_refuses`, `tests/test_spa_query.py::test_a_seed_gets_the_filler_and_a_redirect_name_gets_a_same_origin_path`, `tests/test_spa_query.py::test_no_stored_row_carries_a_marker`, `tests/test_spa_query.py::test_a_seed_that_blocked_a_write_is_never_a_point_and_m6_never_sends_it`, `tests/test_spa_query.py::test_a_session_lost_in_a_query_load_stops_query_loads`, `tests/test_spa_query.py::test_what_a_query_window_counts_as_a_write`, `tests/test_spa_query.py::test_a_held_websocket_message_is_a_write`, `tests/test_spa_query.py::test_a_seed_is_never_importable_until_its_window_closed_cleanly`, `tests/test_spa_query.py::test_a_session_check_that_raises_is_a_loss`, `tests/test_spa_query.py::test_a_slow_response_that_expires_the_session_cookie_is_a_loss`, `tests/test_spa_query.py::test_a_request_whose_redirect_hop_was_refused_is_never_fetched_again`, `tests/test_spa_query.py::test_the_session_is_rechecked_when_leaving_the_page_fails`, `tests/test_spa_query.py::test_a_withheld_url_while_a_probe_is_open_is_that_probes_blocked_evidence`, `tests/test_spa_query.py::test_a_probe_route_on_another_origin_is_never_minted_nor_loaded`, `tests/test_spa_query.py::test_an_authenticated_query_load_that_goes_to_another_origin_hands_it_nothing`, `tests/test_spa_query.py::test_a_seeds_leave_reads_the_page_only_when_its_load_committed`, `tests/test_spa_query.py::test_a_failed_seed_load_checks_the_cookies_and_the_server_not_local_storage`, `tests/test_spa_query.py::test_a_query_loads_request_in_flight_is_tracked_until_it_ends`, `tests/test_spa_query.py::test_a_seed_whose_own_redirect_is_refused_fails_and_the_crawl_goes_on`, `tests/test_spa_query.py::test_a_withheld_seed_is_a_write_seed_and_a_withheld_probe_records_nothing`, `tests/test_spa_query.py::test_a_shell_that_writes_on_every_load_still_gives_hash_points`, `tests/test_spa_query.py::test_the_baseline_is_what_a_load_outside_a_window_would_have_written`, `tests/test_spa_query.py::test_the_websocket_forwarder_reports_each_forwarded_message`, `tests/test_spa_query.py::test_the_guards_url_log_lines_never_carry_a_probe_marker`, `tests/test_spa_query.py::test_a_seeds_forms_are_stored_only_when_it_is_promoted`, `tests/test_spa_query.py::test_the_baseline_never_takes_a_query_caused_write_and_a_query_value_always_counts`, `tests/test_spa_query.py::test_a_write_carrying_the_loads_query_value_counts_on_a_baseline_endpoint`, `tests/test_spa_query.py::test_only_a_bare_routes_load_is_its_baseline`, `tests/test_spa_query.py::test_a_query_load_whose_bare_route_did_not_load_is_refused`, `tests/test_spa_query.py::test_a_load_that_committed_but_did_not_complete_is_committed`
  - Enforced by (the session after a reveal, W4): `LocalSpider._reveal_session_check` / `_client_session_intact` / `_readopt_session` — `tests/test_forms_phase4.py::test_w4_a_client_side_logout_is_readopted_then_a_second_loss_stops_reveals`
  - Enforced by (the reveal gate, G2a-G2d): `spa.reveal_refusal` / `label_refusal` / `submitter_glyph`, `spa.REVEAL_JS`, `LocalSpider._reveal_one` — `tests/test_forms_phase4.py::test_the_reveal_gate`, `tests/test_forms_phase4.py::test_g2b_a_menu_item_failing_the_gate_is_never_clicked`, `tests/test_forms_phase4.py::test_g2a_cards_are_clicked_on_the_element_capped_and_never_with_descendants`, `tests/test_forms_phase4.py::test_a_card_is_dispatched_on_the_element_never_by_a_coordinate_click`, `tests/test_forms_phase4.py::test_juice_shops_login_button_still_passes_with_exit_to_app_a_destructive_glyph`, `tests/test_forms_phase4.py::test_the_crawl_cap_on_reveals`
  - Enforced by (constraint-aware filling, G1b-G1e): `spa.g1_sensitive` / `select_refusal` / `checkbox_refusal` / `captcha_reason`, `LocalSpider._g1` — `tests/test_forms_phase4.py::test_g1_never_fills_a_sensitive_or_credential_control`, `tests/test_forms_phase4.py::test_select_refusal`, `tests/test_forms_phase4.py::test_checkbox_refusal`, `tests/test_forms_phase4.py::test_captcha_forms_are_recognised`, `tests/test_forms_phase4.py::test_g1_a_saved_card_picker_is_never_chosen_in`, `tests/test_forms_phase4.py::test_g1_a_delete_account_checkbox_is_never_checked_and_never_submitted`, `tests/test_forms_phase4.py::test_g1_a_captcha_form_is_submitted_with_a_filler_answer`, `tests/test_forms_phase4.py::test_a_revealed_form_is_submitted_only_on_a_named_route`
  - Enforced by (labels judged as texts, BUG-0131): `core.urls.text_destructive_reason` — `tests/test_forms_phase4.py::test_a_hash_in_a_label_name_value_or_option_hides_nothing`, `tests/test_forms_phase4.py::test_no_text_is_judged_through_a_url`, `tests/test_forms_phase4.py::test_the_text_guard_catches_synthetic_offenders`
  - Enforced by (destructive redirect hops in the browser): `tests/test_browser_scope.py::test_a_redirect_hop_to_a_destructive_url_is_never_requested`, `tests/test_browser_scope.py::test_an_endless_redirect_chain_is_aborted`
  - Enforced by: `core.urls.destructive_reason`; `tools/spider.py` (queue filter, hand-followed redirects, `navguard.guard_page`); `tools/fetcher.py:load_urls` — `tests/test_destructive_urls.py::test_static_crawl_never_fetches_a_destructive_link_or_redirect`, `tests/test_destructive_urls.py::test_rendered_crawl_sends_no_destructive_request_at_all`, `tests/test_destructive_urls.py::test_the_auditor_never_refetches_a_destructive_url_from_an_old_spider_db`, `tests/test_destructive_urls.py::test_login_discovery_never_follows_a_redirect_to_a_destructive_url`, `tests/test_forms_phase1.py::test_a_named_picker_is_navigated_and_the_settings_one_never_touched`, `tests/test_forms_phase1.py::test_a_settings_picker_is_never_submitted_even_when_named`, `tests/test_forms_phase1.py::test_selector_submissions_never_change_the_crawlers_cookies`, `tests/test_forms_phase1.py::test_bwapps_destructive_gets_are_refused`
  - Enforced by (PA-0114 / PA-0301 tables: each lab's destructive routes judged by the real gates, and the compound-spelling scan over every lab's routes; BUG-0301): `core.urls.destructive_reason`, `store_adapter.form_skip_reason`, `spa.form_refusal` — `tests/test_destructive_routes_external_labs.py::test_each_destructive_route_gets_its_gates_actual_verdict`, `tests/test_destructive_routes_external_labs.py::test_no_lab_route_hides_a_destructive_word_in_a_compound`, `tests/test_destructive_routes_external_labs.py::test_the_spelling_scan_catches_synthetic_offenders`
  - Not yet enforced (BUG-0301, deferred to the owner of `core/urls.py`, CC-CORE-0301): the deny rule does not refuse Juice Shop's `/dataerasure` (one token, `dataerasure`) or `GET /rest/user/change-password?current=&new=&repeat=` (a `change`+`password` pair). A crawl that reaches `/dataerasure` would visit it and import its server-rendered erasure form, which passes `form_skip_reason`. Neither is captured today: the SPA's change-password form is never submitted, and a captured GET has no body to import. Pinned by strict xfails: `tests/test_destructive_routes_external_labs.py::test_juice_dataerasure_url_is_refused`, `tests/test_destructive_routes_external_labs.py::test_juice_dataerasure_form_is_never_imported`, `tests/test_destructive_routes_external_labs.py::test_juice_change_password_url_is_refused`.
  *(CC-CRAWL-0031, D70:)* **behavioural capture keeps every layer's scope and never acts
  on a destructive control.** The capture proxy refuses anything outside the run's
  origins on its own (it is the third layer beside the browser route and the launch
  arguments, and trusts neither); the explorer's browser keeps both navguard layers,
  with the proxy's own `host:port` added to the resolver rules only; an element whose
  label, name or id is destructive (`text_destructive_reason`) or operator-denied, or
  whose link or form action is destructive, is never acted on; a credential-change
  form is never submitted (a CAPTCHA form is, with a filler answer: D71, CC-CRAWL-0033);
  the route still aborts destructive requests whatever the page sends.
  - Enforced by (the proxy, per request and per tunnel): `disco.recorder.Recorder.request` / `http_connect` — `tests/test_disco_capture.py::test_an_out_of_scope_request_is_killed_counted_and_never_recorded`, `tests/test_disco_capture.py::test_an_empty_scope_refuses_everything`, `tests/test_disco_capture.py::test_a_tunnel_is_opened_for_an_in_scope_host_port_under_either_scheme`, `tests/test_disco_e2e.py::test_the_proxy_refuses_an_out_of_scope_request_on_its_own`
  - Enforced by (the browser through the proxy): `navguard.browser_launch_args(proxy=)` / `chromium_launch_kwargs(proxy=)` — `tests/test_browser_scope.py::test_a_capture_proxy_replaces_no_proxy_and_is_itself_resolvable`, `tests/test_browser_scope.py::test_a_capture_proxy_is_a_loopback_ip_literal_and_port_only`, `tests/test_browser_scope.py::test_launch_kwargs_refuse_args_built_for_another_proxy_or_none`, `tests/test_browser_scope.py::test_the_launch_sites_are_the_four_known_ones`
  - Enforced by (the explorer, end to end in a real browser): `disco.explore.refusal` / `form_refusal` — `tests/test_disco_e2e.py::test_destructive_controls_and_other_origins_are_never_reached`, `tests/test_disco_e2e.py::test_every_exchange_is_recorded_with_its_cause_and_the_tag_never_reaches_the_app`, `tests/test_disco_synth.py::test_a_captcha_form_is_submitted_and_a_credential_change_is_not`
  - Enforced by (the capture is redacted at the write): `disco.capture.make_record` — `tests/test_disco_capture.py::test_no_secret_reaches_the_capture_file_and_benign_content_stays`, `tests/test_disco_capture.py::test_a_secret_straddling_the_body_cut_is_still_removed`, `tests/test_disco_capture.py::test_an_unparseable_json_body_with_a_secret_is_omitted`
- **NFR-CRAWL-bounded** Cap per-template instance counts to avoid infinite crawl
  spaces. *(Built for the legacy spider, CC-CRAWL-0056: FR-CRAWL-35's per-route-shape,
  per-origin, total, pending and URL-length budgets, each refusal counted and reported;
  disco's explorer bounds itself by states and actions, FR-CRAWL-19.)*
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
seed); a SPA route page's `url` keeps its `#/…` fragment, a seed's with its query;
since FR-CRAWL-29 `found_from TEXT` and `seen_at REAL`, NULL when unknown; since
FR-CRAWL-36 `outcome TEXT` (`pending` | `visited` | `withheld` | `failed`), `attempts
INTEGER` and `error TEXT` (an answer or exception class), NULL in an older row, whose
status 0 reads unresolved; a failed load is still a row with its status, 0 when there was
no answer),
`discovered_forms`, `selector_verdicts`, `crawl_stats (name TEXT PRIMARY KEY,
value INTEGER)` (the last crawl's SPA, reveal and, since FR-CRAWL-17, `spa_query_*`
counts -- refusals by reason as `spa_query_refused[<reason>]` -- `submit_stopped` and
`reveals_stopped`; since FR-CRAWL-35/36 `frontier_admitted`, `frontier_duplicates`,
`frontier_rejected[<reason>]`, `pages_retried`, `pages_failed`, `store_writer_waits`;
since BUG-0545's review `loads_refused[<reason>]` (only a reason that refused) and
`session_host_unserved`),
since FR-CRAWL-16 **`revealed_forms`** `(id, page_url, route,
signature, submitted INTEGER, UNIQUE (route, signature))` — the forms a reveal showed,
for a later opt-in (`page_url` redacted by `redact_url_identifiers`; never values) —
and, since FR-CRAWL-13,
**`discovered_requests`** — the contract
the importer reads (lane J, forms phase 3):
`(id, page_url, method, url, content_type, body_json TEXT, source TEXT ('passive' |
'submit'), signature TEXT UNIQUE, seen_at REAL)` (`seen_at` since FR-CRAWL-29: when it
was captured; NULL in an older DB). `body_json` is the redacted body as JSON text (a
JSON body's parsed value; a form-encoded body as an object of name → value, last wins);
`url` and `page_url` are redacted (`core.redaction.redact_url_identifiers`);
`content_type` is the media type only. Since FR-CRAWL-37 a row is one
**representative of an API operation** (one real captured body per distinct typed
shape of the operation, FR-CRAWL-37's rules), and `signature` = JSON
`[method, url_key(url), media type, operation selectors, sha256 of the row's typed key
paths]` (`tools.apiop.row_signature`; its first four items are the operation,
`apiop.operation_key`). Before FR-CRAWL-37 it was `[method, url_key(url), sorted
top-level keys]`, and an older DB keeps that form. Since FR-CRAWL-42 `body_json` and
`signature` write a lone surrogate as its JSON escape (`apiop.storable_json`; valid
JSON and valid UTF-8, read back by `json.loads` as the body sent); any other text is
unchanged. No header and no cookie is stored.
An old spider DB has no such table (the importer treats it as none).

**Behavioural capture (FR-CRAWL-18..20, D70) -- file contracts, not store tables:**
- `<run>/capture.jsonl`: one JSON object per exchange, `v: 1`: `kind` (`http`/`ws`), `t`,
  `action_id`, `profile`, `method`, `url`, `req_headers`, `req_ctype`, `req_body`,
  `req_truncated`, `status` (null with `error` when there was no response),
  `res_headers`, `res_ctype`, `res_body`, `res_truncated`, `latency_ms`,
  `ws_direction`. Redacted at the write; written only by `disco.capture.make_record`,
  read only by `disco.capture.read_capture`.
- `<run>/capture.jsonl.stats.json` (refusals per host `blocked`, `recorded`, `dropped`,
  `omitted` {`too_large`, `backlog`, `undecodable`}, `waited`, `queued`; FR-CRAWL-38),
  `<run>/actions.jsonl` (one line per UI action; *(CC-CRAWL-0060, FR-CRAWL-41)* plus one
  `{"kind": "session", ...}` line, with no `seq`, per known-lost window, naming its
  action ids), `<run>/explore.json` (the report; FR-CRAWL-41's session counters).
  *(CC-CRAWL-0055, additive.)* An action line's `state` / `new_state` are execution keys
  (FR-CRAWL-31) and it carries `replay_safe` (a load line: null). `explore.json`'s
  `explore` gains `unresolved`, `optional_declared`, `replay_skipped_optional`,
  `coverage_excluded`, `states_over_budget`, `live_states`, `deprioritised`,
  `actions_retried`, `actions_failed`, `steps_abandoned`, `same_signature_capped`,
  `perturbations_folded` and `work`, and loses `transient_dropped`. Readers of the run
  directory (`store_adapter.import_disco`, `tools.observe`) read none of the changed
  keys; an older run directory reads as before.
  *(CC-CRAWL-0059, additive)* `explore.json`'s `explore` carries FR-CRAWL-39's and
  FR-CRAWL-40's counters; *(at the merge with CC-CRAWL-0055)* its `work` may hold
  `inert` (a delegated candidate's trial verdict). An action's `signature` is opaque to
  every reader; *(CC-CRAWL-0059)* inside a shadow root or a frame its ancestry part names
  the hosts and frames (`^shadow<...`, `^frame<...`).
- The inventory: an OpenAPI 3.1 document whose operations carry `x-disco`
  (`origin`, `method`, `content_type_family`, `observed`, `samples`, `actions`,
  `profiles`, `statuses`, `headers` {name: {class, value?}}, `auth`, `dependencies`
  [{producer, extract, target, count}], `response_only_fields`, `latency_ms`); path
  parameters carry `x-kind`; the document's `x-disco` holds the record counts and the
  JS candidates. Phase 2 (FR-MUT-10) reads it.

## 6. Dependencies (components)
`core/`, session manager, target lab.

## 7. Acceptance criteria
- Discovers JavaScript-rendered pages and XHR endpoints a static crawler misses.
- Deduplicates near-duplicate pages by template.
- Stays authenticated for a full crawl and records results per identity.

## 8. Open questions
- Form-fill value generation (type-aware) for reaching post-submission code.
- State-machine crawl depth and caps.
