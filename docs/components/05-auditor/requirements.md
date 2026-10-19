# Auditor / Fetcher — Requirement Specification

Component code: **AUD** · Status: `[built; to harden]` · Last updated: 2026-09-23

Related: `ARCHITECTURE.md` #5; `DECISIONS_AND_ROADMAP.md` (D5, D6, D9, Phase 2);
`./change-control.md`.

## 1. Purpose
Turn discovered surface (pages, endpoints, parameters) into ranked **injection
candidates** with recorded rule evidence, so the fuzzer and oracle spend their
budget where a vulnerability is plausible.

## 2. Scope
- **In:** per-parameter rule evaluation, canary reflection probing with context
  typing, target fingerprinting, candidate emission with evidence and features.
- **Out:** confirming a vulnerability (fuzzer + oracle) and ordering candidates by
  a learned model (the ranker reads what the auditor writes).

## 3. Functional requirements
- **FR-AUD-1** Evaluate each injection point against the rule set and record a
  full per-rule evaluation log (which rules fired, which did not, and why), not
  only the rules that matched.
- **FR-AUD-2** Move rules from code toward data (rules-as-data) so the rule set is
  editable and versioned without code changes.
- **FR-AUD-3** Probe reflection with a unique canary and classify the **sink
  context** of each reflection (HTML body, attribute, JS string, URL, etc.).
- **FR-AUD-4** Fingerprint the target (DBMS, framework, WAF) and record it for
  the scheduler and fuzzer to condition on.
- **FR-AUD-5** Emit `candidate` rows carrying rule evidence and an extracted,
  versioned feature vector; never emit a vulnerability label.
- **FR-AUD-6** Read discovered surface from the shared store and write candidates
  back to it (no direct tool-to-tool calls). (D5)
- **FR-AUD-7** *(`CC-AUD-0016`, 2026-09-23).* A candidate is generated for the
  `ssrf` category: `R-SSRF` (`fuzzlab/audit/rules_data/default_rules.json`)
  matches a parameter name against a common SSRF-fetch vocabulary (`url`,
  `src`, `target`, `webhook`, `thumbnail`, etc.), the same bare
  `name_regex`-only shape `R-OPEN-REDIRECT`/`R-FILE-INCLUSION`/
  `R-COMMAND-INJECTION` already use. Rule-generation only — confirmation is
  `fuzzlab.oracle`'s job (`FR-FUZZ-18`).
- **FR-AUD-8** *(`CC-AUD-0017`, 2026-09-23; regex widened by
  `CC-AUD-0024`, 2026-09-23).* A candidate is generated for the
  `access-control` category: `R-ACCESS-CONTROL`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `GET`/`query`
  parameter whose name looks like an object identifier (`channel_id`,
  `resource_id`, `object_id`, `item_id`, `record_id`, `owner_id`,
  `account_id` — the last added by `CC-AUD-0024` for Netflix's first
  `access_control` page, `CC-LAB-0187`) —
  narrower than `R-SSRF`'s bare-`name_regex` shape (adds `method_in`/
  `location_in`) to bound the false-positive risk a broader match would
  carry for this category (see `CC-AUD-0017`). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-20`).
- **FR-AUD-9** *(`CC-AUD-0018`, 2026-09-23).* A candidate is generated for
  the `insecure-deserialization` category: `R-INSECURE-DESERIALIZATION`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `body`-location
  point whose `sink_context` is `"deserialization"` — this project's first
  use of the `sink_context_in` predicate, since this class has no
  informative parameter name to key off (every whole-body point shares the
  literal `param="body"`). **Scope limit, stated explicitly**:
  `sink_context` is currently populated only from ground truth
  (`fuzzlab.harness.auto.points_from_ground_truth` looks it up from the
  matching scoring `Case`); the auditor does not yet infer `sink_context`
  generically for an arbitrary crawled target, so this rule is reachable
  only in the project's own ground-truth-scored detection-benchmark mode
  today, not yet a general crawl-driven capability. Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-21`).
- **FR-AUD-10** *(`CC-AUD-0019`, 2026-09-23).* A candidate is generated for
  the `xxe` category: `R-XXE` (`fuzzlab/audit/rules_data/
  default_rules.json`) matches a `body`-location point whose `sink_context`
  is `"xml"` — the second use of `sink_context_in` (after `R-INSECURE-
  DESERIALIZATION`), same necessary shape and same scope limit (reachable
  only from ground-truth-sourced points today). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-22`).
- **FR-AUD-11** *(`CC-AUD-0020`, 2026-09-23).* A candidate is generated for
  the `jwt-algorithm-confusion` category: `R-JWT-ALG-NONE`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `header`-
  location point whose name looks like a JWT-carrying header
  (`authorization|jwt`) — scoped to header points only, mirroring
  `R-ACCESS-CONTROL`'s own location-narrowed shape. Rule-generation only
  — confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-23`).
- **FR-AUD-12** *(`CC-AUD-0021`, 2026-09-23).* A candidate is generated for
  the `weak-token-entropy` category: `R-WEAK-TOKEN-ENTROPY`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `POST` point
  whose `sink_context` is `"session_token"` — genuinely a new,
  less-constrained rule shape (no `location_in`, since this class has no
  real tainted location to key off at all; `method_in` substitutes as
  the available constraint). Rule-generation only — confirmation is
  `fuzzlab.oracle`'s job (`FR-FUZZ-24`).
- **FR-AUD-13** *(`CC-AUD-0022`, 2026-09-23).* A candidate is generated for
  the `mass-assignment` category: `R-MASS-ASSIGNMENT`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a body point
  whose `sink_context` is `"mass_assignment"` — the same
  `location_in`+`sink_context_in` shape as `R-INSECURE-DESERIALIZATION`/
  `R-XXE`. The project's first-ever candidate-generation rule for this
  vuln class (already built on three other stacks' lab pages, but with
  no rule anywhere before this entry). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-25`).
- **FR-AUD-14** *(`CC-AUD-0023`, 2026-09-23).* A candidate is generated for
  the `unrestricted-file-upload` category: `R-UNRESTRICTED-FILE-UPLOAD`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a body point
  whose `sink_context` is `"fs_web_root_write"` — the same
  `location_in`+`sink_context_in` shape as `R-MASS-ASSIGNMENT`/
  `R-INSECURE-DESERIALIZATION`/`R-XXE`. This project's first-ever
  candidate-generation rule for this vuln class, closing `CC-LAB-0186`'s
  own deliberately-deferred detection follow-on for Twitch's
  unrestricted-file-upload cell (`TWCH-0009`). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-26`).
- **FR-AUD-15** *(`CC-AUD-0025`, 2026-09-23).* A candidate is generated for
  the `price-integrity-bypass` category: `R-PRICE-TRUST-DIFFERENTIAL`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a body point
  whose `sink_context` is `"payment_charge"` — the same
  `location_in`+`sink_context_in` shape as `R-MASS-ASSIGNMENT`/
  `R-UNRESTRICTED-FILE-UPLOAD`. Deliberately scoped to `"payment_charge"`
  only, not also `"sql"` (Booking.com's own `BKNG-0003` ground truth uses
  `sink_context="sql"`, since its sink is a real DB insert): `"sql"` is
  already used as the `sink_context` for a large number of unrelated
  SQL-injection candidates project-wide, and widening this rule's own
  `sink_context_in` to include it would have generated a
  `price-integrity-bypass` candidate for essentially every SQL-sink point
  in the project, a real false-candidate-explosion risk caught during
  this rule's own pre-change review, not discovered after the fact. This
  project's first-ever candidate-generation rule for this vuln class,
  closing `CC-LAB-0188`'s own deliberately-deferred detection follow-on
  for Netflix's price-integrity-bypass cell (`NFLX-0005`). Rule-generation
  only — confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-27`).
  **Cross-stack generalization, verified live (`CC-LAB-0189`,
  2026-09-23, updated in place)**: this rule's own `location_in`/
  `sink_context_in` gate was never stack-specific, so it needed **zero**
  changes to also generate a candidate for `go_net_http`'s new
  `price_integrity_bypass` cell (`TWCH-0010`, Twitch's channel-
  subscription-purchase endpoint) — verified directly, not merely
  assumed from the rule's shape.
- **FR-AUD-16** *(`CC-AUD-0026`, 2026-09-23).* A candidate is generated
  for the `http-header-injection` category: `R-HEADER-INJECTION`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `query`/`body`
  point whose `sink_context` is `"header"` — the same `location_in`+
  `sink_context_in` shape as `R-INSECURE-DESERIALIZATION`/
  `R-UNRESTRICTED-FILE-UPLOAD`/`R-PRICE-TRUST-DIFFERENTIAL`. Closes `CC-LAB-0198`'s
  own deliberately-deferred detection follow-on for Twitch's
  `http_header_injection` cell (`TWCH-0013`). Checked directly (not
  assumed) that the one other real user of `sink_context="header"`
  (php_laravel's HuddleHub `outbound_header_injection` case, a genuinely
  distinct concern) cannot false-positive through this rule: the
  companion oracle strategy fails closed on that page, and that app's own
  `vuln_class` has no category mapping that would ever include this
  category in a real automatic run's `plan.categories`. Rule-generation
  only — confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-29`).
- **FR-AUD-17** *(`CC-AUD-0027`, 2026-09-23).* A candidate is generated
  for the `path-traversal` category: `R-PATH-TRAVERSAL`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `query`/`body`
  point whose `sink_context` is `"fs_path_read"` — the same
  `location_in`+`sink_context_in` shape as `R-HEADER-INJECTION`/
  `R-INSECURE-DESERIALIZATION`/`R-UNRESTRICTED-FILE-UPLOAD`/
  `R-PRICE-TRUST-DIFFERENTIAL`. Closes `CC-LAB-0190`'s own deliberately-deferred
  detection follow-on for Twitch's `path_traversal` cell (`TWCH-0011`) —
  this project's own last known real, TRACKED category-4 detection gap.
  Checked directly (not assumed) that `sink_context="fs_path_read"` has
  no other current user in any ground truth, so there is no cross-target
  overlap to reason about. The pre-existing `R-FILE-INCLUSION` rule's
  broader `name_regex` also matches `filename`, generating a second,
  independent candidate under a genuinely distinct category
  (`file-inclusion`, matching no current ground truth) — by design, not
  a duplicate: that category has no confirming path in a scored
  automatic run today. Rule-generation only — confirmation is
  `fuzzlab.oracle`'s job (`FR-FUZZ-30`).

- **FR-AUD-18** *(`CC-AUD-0028`, 2026-10-13, BUG-0110).* The passive auditor
  (`tools/fetcher.py`) reports each field's default value as a browser holds it
  (`core.forms.default_value`): a select's selected or first option, a textarea's
  text, a checkbox's value or `on`. These values feed the value-based indicator
  rules.
  *(CC-AUD-0042, BUG-0136 review:)* each URL's rendered result (its DOM and its XHR
  list) comes from that URL's page only. When the browser cannot load a URL (a refused
  navigation, a timeout), `ContentFetcher.fetch` sends its one page to `about:blank`
  before the static fallback. The page shown before, which ERR_ABORTED leaves alive,
  stops, and its requests are never listed under a later URL. *(CC-AUD-0043,
  BUG-0138:)* the rendered fetch navigates through `navguard.navigate` and waits for
  `networkidle` only after a completed load. A page whose load did not complete is
  returned without waiting out the timeout and without a second request (review Q2):
  - superseded, or replaced by another document, the HTML the browser received for it;
  - merely slow, its live DOM.
  - Enforced by (a failed load ends the previous document; CC-AUD-0042): `ContentFetcher.fetch` — `tests/test_navigation_aborts.py::test_the_auditors_failed_load_ends_the_previous_document`
  - Enforced by (no wait for a load a refused navigation cancelled; CC-AUD-0043, BUG-0138): `ContentFetcher.fetch` → `navguard.navigate` — `tests/test_guarded_navigation.py::test_the_auditor_reads_the_page_without_waiting_it_out`

- **FR-AUD-19** *(`CC-AUD-0031`, 2026-10-13).* A form point's candidate evidence
  carries its entry list (`"entries"`, secrets blank), so the oracle probes it with its
  sibling fields.
- **FR-AUD-20** *(forms phase 2; `CC-AUD-0032`, 2026-10-14).*
  - **Value shapes.** `audit/value_shape.value_shape` is the one classifier of an
    example value: `url`, `ip`, `filename` (a closed extension set), `path`, `hostname`
    (RFC 1123 labels; the last a two-letter or listed generic TLD), or none. It is
    total, bounded (2048 characters) and linear, with no regular expression.
    Accepted false positive: a dotted name ending in two letters (`user.id`,
    `order.by`) is a host name.
  - **Predicates.** `value_shape_in` (the point's `value_shapes`) and `origin_in`
    (`crawl` / `ground-truth`). `load_rules` validates every rule: unknown keys, values
    outside a closed set, or a regex that does not compile raise `RuleError`. An invalid
    plugin rule is left out and counted (`invalid_plugin_rules`).
  - **Rules.** `R-COMMAND-INJECTION-VALUE` (ip, hostname) and `R-FILE-INCLUSION-VALUE`
    (filename, path) fire whatever the parameter is called; `R-SQLI-HEADER` and
    `R-XSS-HEADER` fire on crawl-sourced header points only. None fires on a
    ground-truth point.
  - **Examples.** Crawl points carry their example's shapes; a field whose own example
    is empty or our filler takes the shapes its name has elsewhere in the run (one
    pass).
  - **Neutral base values.** A point whose example is ip- or hostname-shaped is probed
    from `127.0.0.1` (the command-injection base value and payload prefix, built under
    CC-FUZZ-0063). `value_shape.neutral_value` errs toward loopback for siblings and
    header-point queries: any value with `://` (any scheme, any length) or starting
    with `//` → `http://127.0.0.1/`; an ip or host name, also with a port →
    `127.0.0.1`, and with a path after it → `http://127.0.0.1/`. Our own fillers (exact
    match, `store_adapter.is_filler`; since CC-AUD-0039 also the crawler's
    constraint-aware ladder values, `store_adapter.is_ladder_value`: repeated or
    ascending digits of at most 15 digits, `fuzzlab` padded with `x` or cut to a
    prefix of 3 or more, `Fuzzlab`, `FUZZLAB`, `2000`, FR-CRAWL-15) are sent as they
    are. The fuzzer never sends a host name taken from the app's
    own defaults. Stated residual: an e-mail default (`user@mail.example.com`) is sent
    as is and may trigger mail. **Stated exception (FR-AUD-21, BUG-0124,
    operator-approved 2026-10-14):** the open-redirect retry probe.
- **FR-AUD-21** *(open redirect and SSRF by value; `CC-AUD-0034`, 2026-10-14,
  BUG-0124).*
  - **Shape → categories.** `audit/value_shape.SHAPE_CATEGORIES` is the one table of
    the categories each shape implies (ip, hostname → command-injection; filename,
    path → file-inclusion; url → open-redirect, ssrf). The default rules carry exactly
    one `R-*-VALUE` rule per pair (`R-OPEN-REDIRECT-VALUE`, `R-SSRF-VALUE` new), and
    `SHAPE_EXCLUSIONS` records the pairs left out with a reason (url → file-inclusion).
  - **The redirect seed.** `value_shape.redirect_seed(example)` is an `http`/`https`
    crawled example sliced from its original text up to its query or fragment, userinfo
    cut out; `None` for any other scheme and for a host or path with an identifier-like piece.
    `harness/auto` sets it on crawl points; `audit/engine.evaluate` writes it to an
    **open-redirect** candidate's evidence only. An AST guard limits where
    `redirect_seed` is set, carried and read.
  - **The FR-AUD-20 exception and its reach.** The open-redirect confirmer may send the
    seed, after its plain canary failed, as text in the query of a reserved `.example`
    canary (FR-FUZZ-46). fuzzlab never sends a request to the seed's host (it is never
    a request host) and never follows the redirect. **A target that extracts and
    fetches URLs embedded in a parameter could contact the seed's host** (a third
    party): the operator accepted this residual explicitly. Every other category keeps
    FR-AUD-20 as written.
  - **Stated gaps:** a protocol-relative example (`//host/x`, shape `path`) gets no
    rule and no seed; an allowlist keyed on a query string is not matched (the seed
    drops the query).
- **FR-AUD-22** *(captured requests and JSON leaves; `CC-AUD-0035`, 2026-10-14, forms
  phase 3, lane J).*
  - **Source.** `store_adapter.import_spider` reads the spider table
    `discovered_requests` (`id, page_url, method, url, content_type, body_json, source,
    signature`; FR-CRAWL-13). A spider DB without it imports exactly as before.
  - **Never imported** (counted `request_refused`, nothing stored): a method outside
    GET/POST/PUT/PATCH (DELETE included); PUT/PATCH unless `fuzzlab auto
    --fuzz-json-writes` is given (and the URL passes the next rules); a URL
    `destructive_reason` or `transaction_reason` flags; a URL on another origin than
    the page that sent it; a content type other than JSON (`application/json`,
    `application/*+json`) or form-encoded; a body that is malformed, not an object,
    empty, over 64 leaves or 16 levels; a **credential-change body**
    (`store_adapter.credential_change_rule`, the one rule crawled forms use: two or
    more password fields, a password field named with a change word — new, confirm,
    repeat, current, old …, or an account-management token in the URL path); a body
    with a settings word (`formnav.settings_word`) on any key; a destructive name or
    value (`entries_refusal`, run with `credential_names=True` over the non-password
    leaves — every credential-named leaf is a password field, so that half is a second
    check; each name and value is judged as a text, `core.urls.text_destructive_reason`,
    so a `#` in it hides nothing — CC-AUD-0039, BUG-0131).
  - **Stored.** A JSON body is a `form` row (`enctype` `application/json`, entries as
    FR-CORE-36). A form-encoded body is a `form` row (`enctype`
    `application/x-www-form-urlencoded`) and imports as today's form points (`body`).
    The endpoint is the request's path plus its (redacted) query, at its method. Every
    stored value passes `redact_leaf` (a sensitive key on the path or an
    identifier-like value: `""` for a string, `null` otherwise; PA-0100).
  - **Points.** Each string, number or bool leaf is a `json` parameter named by its
    display name, with its value as the example (non-strings as JSON text), except:
    - a **password field** — a credential name (`is_credential_name`) on any key of
      its path: never a point, stored and sent `""`, listed in `form.password_fields`,
      so `isolated_paths_from_store` isolates the path (FR-FUZZ-44);
    - a sensitive or identifier-like leaf (pinned, sent blank);
    - an **object selector** (`_object_selector` on the last key: `UserId`,
      `BasketId`, `username`, `owner` …; pinned, sent as captured).

    When two captured requests share an endpoint, the first one's leaf wins a name.
  - **Rules on JSON leaves.** `name_regex` matches the path's last object key
    (`rules.rule_name`); credential and sensitive checks run on every key; value shapes
    apply to the leaf's example, and a url leaf's `redirect_seed` keeps FR-AUD-21's host
    and path identifier checks. `R-SQLI-PARAM` and `R-SSTI` include `json`.
    `R-XSS-REFLECT` does not: a JSON response is not rendered as HTML, and the
    reflected-XSS check does not read the response's content type, so a JSON echo would
    read as a break-out (stated gap: reflected and stored XSS through JSON bodies).
  - **SPA route queries.** A crawled URL whose fragment is a hash route with a query
    (`/#/search?q=x`) gives `fragment` parameters on the endpoint `/#/search`
    (`core.urls.to_route_path`), never `query` ones; lane A's link sets and header
    queries read only `urlsplit(url).query`. A `fragment` crawl point is built only with
    a browser (`--browser`, M6), else reported as ground truth's DOM points are; a
    destructive route (`/#/logout`) is never a point. A crawled SPA query seed whose
    load blocked a write (`discovered_pages.source = 'spa-query-writes'`, FR-CRAWL-17) is
    imported as a page only: no endpoint, parameter or link set comes from it (counted
    `write_seed_skipped`; `CC-AUD-0041`), so M6 never replays that write outside a
    window.
  - **Client-side categories only on fragment points.** A `fragment` payload never
    reaches the server, so every server-side rule carries `location_not_in:
    ["fragment"]` (a closed predicate beside `location_in`) or a `location_in` without
    it: a fragment point draws only xss candidates (reviewer B). *(Integration,
    CC-AUD-0036:)* both open-redirect rules carry `location_not_in: ["fragment"]` too:
    the only confirmer is the HTTP `OpenRedirectStrategy`, so a fragment candidate could
    never be decided. `location_in` / `location_not_in` values are a closed set
    (`audit.rules.LOCATIONS`); an unknown location is a `RuleError`.
  - **Stated gaps:** points are only as good as lane I's capture (no captured request,
    no points; API calls only seen in a bundle are not imported); an object-selector
    user field (`username`, `login`) of a JSON login is pinned, so it is not fuzzed;
    an identifier-like value blanked by the crawler before import reads as an empty
    example; other query parameters of an SPA route are not sent with a fragment probe.
- **FR-AUD-24** *(the store request on a stored-XSS candidate; `CC-AUD-0045`,
  2026-10-19, FR-FUZZ-56).* An `InjectionPoint` with a `store_url` also carries
  `store_method` (default `POST`), `store_location` (`body`, `query` or `json`) and,
  for a JSON store, `store_entries` (the body's other leaves); a fired rule's candidate
  evidence records all three (`store_entries` as lists) so the oracle plants through
  the request the ground truth enumerates.
- **FR-AUD-23** *(a disco run as crawl points; `CC-AUD-0044`, 2026-10-18, D70).*
  `store_adapter.import_disco(run_dir, store, run_id, fuzz_json_writes=)` imports a
  `fuzzlab disco capture` run directory as `import_spider` imports a crawl, through
  the same code (`fuzzlab auto --disco-run DIR`, FR-FUZZ-53):
  - **Pages and queries.** Each captured GET with a query string or an HTML answer goes
    through `_import_page_url` (the per-URL step of `import_spider`): a `page` row, its
    query as `query` parameters and a link set (source `disco`). An asset GET (script,
    style, image, JSON without a query) is not a page.
  - **Captured requests.** Every other HTTP exchange with a response is judged by
    `captured_request` and stored by `_store_request`, so every FR-AUD-22 refusal,
    redaction and pinning applies unchanged. A form-encoded body is read from the wire
    into the object form the spider stores. A truncated body (`req_truncated`) is
    refused. The `Referer` header stands for the sending page in the other-origin rule.
    WebSocket messages and exchanges without a response are skipped.
  - **Fragments.** Each page URL of `actions.jsonl` (`url`, redacted by the explorer)
    goes through `_import_page_url`, so an SPA hash route's query is a `fragment` point:
    the browser never sends a fragment, so only the explorer's log holds it.
  - **Fields a user saw.** A form step in `actions.jsonl` lists its controls' names and
    types (`fields`); joined to the capture by action id (`act-<seq>`), the names of
    its non-hidden controls are `visible` to `_store_request`. An object selector
    among them (a visible `username` input) is a point, as a crawled form's visible
    field is (`_import_forms`); a hidden or unseen one stays pinned (FR-AUD-22).
  - Malformed `actions.jsonl` lines are counted `quarantined`, with the capture's own.

## 4. Non-functional requirements
- **NFR-AUD-explainable** Every candidate is traceable to the rule evidence that
  produced it; a candidate with no evidence is a bug.
- **NFR-AUD-idempotent** Re-auditing the same surface produces stable candidate
  identities (no duplicate churn).
- **NFR-AUD-safe** Probing uses non-destructive canaries only; destructive checks
  are gated off by default.
  - Clause (scope; CC-AUD-0033, BUG-0123): the auditor's scope is one origin, fixed
    once (the auth base's, else the first fetched URL's); a URL outside it is never
    fetched, and the rendered fetcher's browser reaches nothing else (a context-wide
    route, redirect chains walked, plus launch arguments for Chromium's own traffic).
    Stated consequence: with `--base-url` on a separate auth origin (a login hosted
    elsewhere), every page fetch is refused and logged ("outside the audit scope"),
    so the audit finds nothing; audit with a base URL on the pages' own origin.
  - Enforced by (scope): `ContentFetcher.fetch` / `_start_browser`, `navguard` — `tests/test_browser_scope.py::test_the_auditors_browser_never_leaves_the_target_origin`, `tests/test_browser_scope.py::test_the_auditors_scope_is_fixed_and_never_moves`, `tests/test_browser_scope.py::test_the_static_auditor_refuses_another_origin_too`, `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`
  - Enforced by: the auditor sends only GETs of crawled URLs, now deny-listed and redirect-checked — `tests/test_destructive_urls.py::test_the_auditor_never_refetches_a_destructive_url_from_an_old_spider_db`, `tests/test_destructive_urls.py::test_the_auditors_static_fetch_does_not_follow_a_redirect_to_one`
  - Enforced by (session headers; CC-AUD-0038, FR-CRAWL-14's mechanism): the rendered fetcher ensures the session before its context opens and hands its headers to the guarded route only (in scope, the session's host, its transport), never `set_extra_http_headers` — `tests/test_browser_scope.py::test_no_browser_context_gets_session_headers_outside_the_route`, `tests/test_browser_scope.py::test_session_headers_are_added_by_the_route_only_in_scope`, `tests/test_browserauth.py::test_an_https_sessions_headers_never_go_over_http`
  - Enforced by (a browser login's state adopted in scope only, through the one helper; CC-AUD-0040): `ContentFetcher._start_browser` → `browserauth.context_options` — `tests/test_session_browser_login.py::test_the_auditors_browser_adopts_a_browser_logins_local_storage`, `tests/test_session_browser_login.py::test_the_auditors_browser_renders_the_app_logged_in`, `tests/test_session_browser_login.py::test_storage_state_adoption_keeps_in_scope_origins_only`
  - Not yet enforced: there is no destructive-check gate in `fuzzlab/audit` (it has no destructive checks today), and the FR-AUD-3 reflection canary is not wired into production code. (BUG-0111 sweep.)
- **NFR-AUD-no-leak** Candidate identifiers carry no vulnerability class name (D9).
- **NFR-AUD-dry-run** `fuzzlab audit` accepts `--dry-run`: plans and prints the
  exact argv/command it would run and sends nothing (no probe is made), for
  headless use outside the web UI. Reuses the web launcher's dry-run plan/report
  logic (`fuzzlab/web/commandspec.py` + `fuzzlab/web/runner.py`) via the shared
  `fuzzlab/cli_dryrun.py` helper.
  - Enforced by: `cli_dryrun` — `tests/test_cli_dry_run.py::test_audit_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_audit_dry_run_reports_plan_and_sends_nothing`
  - Not yet enforced (exact argv display; BUG-0400, open, the UI lane's fix): the shared display `web/runner.build_flags` mis-serialises `nargs='*'` lists, a bare `const=""` flag and dash-leading values, so for those the printed plan is not the exact argv. Pinned by strict xfails in `tests/test_cli_argv_roundtrip.py`.

## 5. Interfaces and data contracts
Reads `page`, `endpoint`, `parameter` (and, for crawl points, `form` sibling entries;
the importer writes them from the spider's `discovered_forms` and, since forms phase 3,
`discovered_requests`, FR-AUD-22) from the store; writes `candidate` rows
(rule evidence, `features_json` + `feature_version`) and `target` fingerprint
data. Reads indicators/rules from the indicator DB & catalogs. Authenticates via
the session manager: the static path through the `core/` seam; the rendered path's
browser context adopts the session the crawl's way (`browserauth.browser_session`,
then `browserauth.context_options`: a browser login's `storage_state`, cookies and
localStorage, filtered to in-scope origins; its cookies; its headers through the guarded
route only; CC-AUD-0038, CC-AUD-0040). Runs standalone or in the discovery pipeline.

## 6. Dependencies (components)
`core/`, session manager, crawler, indicator DB & catalogs.

## 7. Acceptance criteria
- Produces candidates with complete per-rule evidence on the lab's known
  injection points.
- Correctly types reflection contexts on the lab's reflected-input pages.
- Fingerprints the lab's DBMS/framework; candidates carry a versioned feature
  vector consumable by the ranker.

## 8. Open questions
- Rules-as-data schema and how rule versions bind to a run.
- Confidence weighting of overlapping rules for the same parameter.
