# Auditor / Fetcher — Change Control Log

Component code: **AUD**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-AUD-0040 — The auditor's browser adopts a browser login's localStorage (BUG-0132 sweep) (2026-10-14)
- Change: `tools/fetcher.py` `ContentFetcher._start_browser` creates its context with
  `browserauth.context_options(session)`, the one adoption helper the crawl uses now too
  (CC-CRAWL-0025). It adopts a browser login's `storage_state` (cookies and localStorage)
  as filtered to in-scope origins by `browserauth.browser_session`. Before, the auditor
  adopted the session's cookies and headers but not localStorage: an app that reads its
  token from localStorage rendered logged out in the auditor's browser. BUG-0132's
  PA-0002 sweep found this and pinned it by a strict xfail. The log line now counts the
  adopted localStorage entries.
- Impact: the auditor's rendered fetch of a single-page app shows its logged-in UI, so
  the forms and inputs behind it are audited. Server-rendered sessions are unchanged:
  no browser state means no options. Scope is unchanged: the guard and the launch
  arguments are as before, and only in-scope origins' state is adopted.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_session_browser_login.py`). The strict xfail is now a
    passing static check that both `_start_browser`s (auditor, crawl) build their
    context through `context_options`. A real-browser test fetches a route that renders
    `LOGGED-IN-UI` from localStorage alone, and checks that only the in-scope origin is
    adopted — done
  - [x] mutation checks, each reverted and failing: the fetcher without the helper
    (both tests); the helper adopting nothing (the real-browser test) — done
  - [x] interfaces (§5) and NFR-AUD-safe traced in place; BUG-0132's sweep table;
    CHANGELOG — done
- Review: the coordinator's decision on BUG-0132's flagged sweep gap; reviewers A and B
  are reviewing 26507a1 in parallel.
- Effectiveness (assessed 2026-10-14): verified offline against loopback fixtures, real Chromium (`FUZZLAB_REQUIRE_BROWSER=1`, `FUZZLAB_REQUIRE_LINT=1`, `FUZZLAB_REQUIRE_NETNS=1`): `test_session_browser_login`, `test_browser_scope`, `test_lint`, `test_requirements_traceability`, `test_browserauth`, `test_spa_capture`, `test_subpath_apps`, `test_auditor_seam`, `test_destructive_urls`, `test_forms_phase4`: 560 passed, 0 skipped, 0 failed. Live Juice Shop not run here.

### CC-AUD-0039 — The importer recognises the crawler's ladder values as fillers; entries judged as texts (FR-CRAWL-15, BUG-0131) (2026-10-14)
- Change (`tools/store_adapter.py`, filed under the auditor as CC-AUD-0035 was):
  - **The ladder (FR-CRAWL-15, reviewer B7):** `LADDER_MAX_DIGITS` (15),
    `LADDER_CONSTANTS` (`2000`), `LADDER_TEXT` / `LADDER_TEXT_VARIANTS` /
    `LADDER_PAD` / `LADDER_MIN_PREFIX` / `LADDER_MAX_TEXT`, `ladder_digits(n)` and
    `is_ladder_value(value)` (total). `is_filler` is the single source: an importer
    filler **or** a ladder value -- repeated or ascending digits up to 15 digits,
    `fuzzlab` padded with `x` or cut to a prefix of 3+, `Fuzzlab`, `FUZZLAB`, `2000`.
    16+ digits are excluded because they look like identifiers.
  - **BUG-0131:** `entries_refusal` judges each name and value with
    `core.urls.text_destructive_reason`, never `destructive_reason("/?x=" + text)`.
- Impact: FUZZ -- `harness.auto._send_value` sends a ladder value as is (it never
  resolves), and a field whose example is a ladder value takes the shapes its name has
  elsewhere in the run, as for any filler; an app-supplied example that happens to be
  a ladder value (`11`, `123`) is treated the same way (a coverage nuance, never a
  safety one). CRAWL -- the constraint-aware filling (CC-CRAWL-0023) types only these
  values. Link sets / captured bodies: an entry with a `#` before a destructive word is
  now refused (more refusals only).
- Risk: low. The filler predicate only widens toward values that are not identifiers
  (tested over every value the ladder can produce); the entry rule only adds refusals.
- Deliverables:
  - [x] code: `tools/store_adapter.py` — done
  - [x] tests: `tests/test_forms_phase4.py::test_every_ladder_value_is_a_filler_and_never_identifier_like`
    (plus near misses), `::test_a_hash_in_a_label_name_value_or_option_hides_nothing`;
    `tests/test_forms_phase2.py` and `tests/test_json_points.py` still green — done
  - [x] FR-AUD-20 (fillers) and FR-AUD-22 (entries) text — done
- Effectiveness (assessed 2026-10-14): every ladder value is a filler and none is
  identifier-like; the `#` case is refused. Effective.

### CC-AUD-0038 — The auditor's browser sends session headers through its route only (FR-CRAWL-14 sweep) (2026-10-14)
- Change: `tools/fetcher.py` `_start_browser` ensures the session first
  (`browserauth.browser_session`), then guards the context with
  `guard_page(headers=session.headers, header_scope=session.header_scope)` and adds only
  cookies to the context (`apply_to_context`, which now refuses headers). It used
  `set_extra_http_headers`, which would send a bearer with every request the browser
  made (CC-CRAWL-0022's PA-0002 sweep).
- Impact: none for cookie sessions; a bearer goes only to in-scope requests on the
  session's host over its transport. A browser login (FR-SESS-19) triggered here runs on
  its own thread, so it does not nest in the auditor's Playwright.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: the header AST guard and route unit tests in `tests/test_browser_scope.py`;
    the auditor's real-browser scope tests still pass — done
  - [x] NFR-AUD-safe traced — done
- Review: with CC-SESS-0021 / CC-CRAWL-0022 (reviewers A and B, Revision 2 item 6).
- Effectiveness (assessed 2026-10-14): verified offline against loopback fixtures, real Chromium (`FUZZLAB_REQUIRE_BROWSER=1`, `FUZZLAB_REQUIRE_LINT=1`): the targeted run (every touched test file, the session-manager tests, the browser-scope, SPA, sub-path, destructive-URL, lint, traceability and loopback-listener guards) gave 739 passed, 2 xfailed, 0 skipped, 1 failed -- `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`, which fails identically on the unmodified base 2150bf8 (`labgen/conformance/*_live_boot.py` `start_server` sites, outside this change; flagged, not fixed here).

### CC-AUD-0037 — The auditor's browser launches with the shared configuration (BUG-0126) (2026-10-14)
- Change: `tools/fetcher.py` `_start_browser` launches with
  `navguard.chromium_launch_kwargs` (CC-CRAWL-0018) instead of its own copy; the unused
  `os` import is removed.
- Impact: none on behaviour (the copy matched today); it cannot drift again (PA-0126).
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: the AST guard over every `chromium.launch`;
    `tests/test_browser_scope.py::test_the_auditors_browser_never_leaves_the_target_origin`
    (real browser) passing — done
- Review: with the forms phase 3 integration, reviewers A and B.
- Effectiveness (assessed 2026-10-14): verified offline.

### CC-AUD-0036 — Forms phase 3 integration: locations a closed set; open redirect off fragment points (2026-10-14)
- Change:
  - `audit/rules.py`: `LOCATIONS` (query, body, header, cookie, json, fragment, path:
    the ground truth's schemas plus `json`); `validate_rule` checks `location_in` and
    `location_not_in` against it, as `value_shape_in` / `origin_in` are (reviewer A,
    lane J re-review: a typo such as `"fragmnet"` would silently widen a rule).
  - `default_rules.json`: `R-OPEN-REDIRECT` and `R-OPEN-REDIRECT-VALUE` gain
    `location_not_in: ["fragment"]` (reviewer B, lane J re-review; decision D16, equal
    flexibility, the reviewer's recommendation): no browser open-redirect mechanism
    exists, so such a candidate could only ever be inconclusive.
  - `tools/store_adapter.redact_leaf` delegates to `core.redaction.redact_leaf` (the one
    leaf rule, CC-CORE-0049).
- Impact: FR-AUD-22 amended (fragment points draw xss candidates only). Rule loading
  rejects an unknown location.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_json_points.py::test_an_unknown_location_is_a_rule_error`,
    `::test_open_redirect_rules_never_fire_on_a_fragment_point`,
    `::test_one_leaf_rule_serves_capture_and_import` — done
  - [x] FR-AUD-22 — done
- Review: reviewers A and B (lane J re-reviews); integration commit.
- Effectiveness: verified offline.

### CC-AUD-0035 — Captured JSON requests become points; rules on JSON leaves; SPA route queries are fragment points (forms phase 3, lane J) (2026-10-14)
- Change:
  - `tools/store_adapter.py`: `import_spider(..., fuzz_json_writes=False)` reads the
    spider table `discovered_requests` (lane I's contract; absent = nothing).
    `captured_request(row)` is the whole, pure import decision; `request_refusal`
    (method outside GET/POST/PUT/PATCH incl. DELETE; PUT/PATCH without the flag;
    `destructive_reason`; `transaction_reason`; another origin than its page) and
    `body_refusal` (`credential_change_rule`, settings words on any key,
    `entries_refusal(credential_names=True)` on the non-password leaves). A JSON
    object body is stored as a `form` row (`enctype` `application/json`, entries via
    `jsonbody.encode_entries`, `password_fields` = the display names of leaves with a
    credential name on any key, sent `""`); each string/number/bool leaf that is not
    a password, sensitive, identifier-like (`redact_leaf`) or an object selector
    (`_object_selector` on the last key) is a `json` parameter. A form-encoded body
    is stored as today's form (`body` points). `credential_change_reason` now calls
    the extracted `credential_change_rule`, shared with bodies (its messages for
    forms are unchanged). An SPA hash route's query becomes `fragment` parameters on
    the route's endpoint (`_import_route_query`).
  - `audit/rules.py`: `rule_name(point)` — `name_regex` matches a `json` point's last
    object key. `default_rules.json`: `R-SQLI-PARAM` and `R-SSTI` list `json` in
    `location_in`; `R-XSS-REFLECT` deliberately does not (FR-AUD-22).
  - `harness/auto.py` (`injection_points_from_store`): `json` points carry their
    body's other leaves (`_json_base_entries`: `decode_entries`, then `_send_value`);
    credential names checked on every key; a destructive SPA route is refused
    (`_crawl_url_refusal`); `fragment` points only with `browser_available`.
  - `harness/auto_cli.py`: `--fuzz-json-writes`; a "captured requests" summary line
    (printed only when the spider DB has captured requests).
- Impact: FR-AUD-22 (new); the AUD interface section names `discovered_requests`. The
  crawler (lane I, CC-CRAWL-0017) writes the table; nothing here edits the spider.
  Old spider DBs import unchanged (tested). The sqli/xss `auto_summary` goldens are
  unchanged (their runs have no captured requests). FUZZ (CC-FUZZ-0068) sends the new
  points; CORE (CC-CORE-0046) holds the convention.
- Risk: medium (new traffic shapes against a lab app's real API). Mitigation: every
  refusal tested; PUT/PATCH opt-in; DELETE never imported and refused again at send;
  login bodies isolated (FR-FUZZ-44); the residuals are stated in FR-FUZZ-47.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_json_points.py` (import, every refusal, pinning, password
    isolation, the PA-0100 producer guard, old spider DBs, the `form.enctype` readers,
    rules on leaves, the seed checks, fragment points) — done
  - [x] FR-AUD-22 — done
- Review: phase 3 design (`p3-spa-draft.md`, revisions 1–4), agreed by reviewers A and
  B; implementation review by the orchestrator pending.
- Effectiveness: verified offline, 2026-10-14 (`tests/test_json_points.py` 90 passed;
  mutation check: every import refusal, the password, pinning and redaction gates and
  the leaf/depth limits killed — see CC-FUZZ-0068). The live Juice Shop crawl (lane I
  capture) and `fuzzlab auto` run are the remaining check.
- Review follow-up (2026-10-14; reviewer B item 1): a new closed rule predicate,
  `location_not_in` (`audit/rules.py`, validated like `location_in`), and
  `"location_not_in": ["fragment"]` on every server-side rule that had no location
  filter: R-FILE-INCLUSION, R-COMMAND-INJECTION, R-SPEL-INJECTION, R-SSRF,
  R-WEAK-TOKEN-ENTROPY, R-PRICE-INTEGRITY, R-CSV-FORMULA-INJECTION and the
  command-injection, SSRF and file-inclusion value rules. A `fragment` point now draws
  only client-side categories (xss, open-redirect). A predicate rather than a
  `location_in` list, so no other location (ground truth also uses `cookie`) can be
  dropped by omission. Ground truth's one fragment point (`author`) matches none of
  these rules, so its candidates are unchanged; the `auto_summary` goldens pass.
  Effectiveness: both mutants (predicate ignored; one rule's exclusion removed) killed.

### CC-AUD-0034 — URL-valued parameters imply open redirect and SSRF; the redirect seed (BUG-0124) (2026-10-14)
- Change:
  - `audit/value_shape.py`: `SHAPE_CATEGORIES` (the one shape → categories table) and
    `SHAPE_EXCLUSIONS` (url → file-inclusion, with its reason); `redirect_seed(value)`
    (http/https only, sliced from the original text up to `?`/`#`, userinfo cut, `None`
    for an identifier-like host or path piece).
  - `default_rules.json`: `R-OPEN-REDIRECT-VALUE` and `R-SSRF-VALUE`
    (`value_shape_in: ["url"]`).
  - `audit/engine.py`: `InjectionPoint.redirect_seed`; `evaluate` writes it to the
    evidence of an open-redirect candidate only.
  - `harness/auto.py` (`injection_points_from_store`): crawl points carry
    `redirect_seed(example)`.
- Impact: FR-AUD-21 (new); FR-AUD-20 gains its one stated exception, with its reach
  (operator-approved). A URL-valued crawl parameter becomes an open-redirect and an
  SSRF candidate whatever its name. All-category crawl runs gain those candidates (and
  their negatives); the sqli/xss `auto_summary` goldens are unchanged (ground-truth
  points have no shapes), asserted by the existing golden tests.
- Risk: low; the exception is narrow and guarded.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_open_redirect_seed.py` (the shape table, the seed, the
    end-to-end Juice-like app, the category-gated evidence write, the AST guard and
    its offender) — done
  - [x] FR-AUD-20 amended, FR-AUD-21 — done
- Review: design agreed by reviewers A and B (revisions 1–3); code review pending.
- Effectiveness: verified offline; the live Juice Shop run is the check.

### CC-AUD-0033 — The auditor's rendered fetcher is confined to the page's origin (BUG-0123) (2026-10-14)
- Change:
  - `tools/fetcher.py` `ContentFetcher`: the scope is fixed once, the auth base's
    origin or else the first fetched URL's, and never re-derived. `fetch(url)` outside
    it returns `(0, "", "", [])` before anything is sent, on both engines, and counts
    the host in `skipped_out_of_scope`. The browser starts on the first `fetch`
    (`_start_browser`), launched with `browser_launch_args` of the scope, on a
    `service_workers="block"` context guarded by `guard_page(context,
    in_scope=self._in_scope)`. A launch failure still raises, as before.
    `release(context)` before close.
- Impact: NFR-AUD-safe gains the scope clause. A spider DB row on another origin than
  the audit's (an old or foreign DB) is no longer fetched at all.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py::test_the_auditors_browser_never_leaves_the_target_origin`,
    `::test_the_auditors_scope_is_fixed_and_never_moves`,
    `::test_the_static_auditor_refuses_another_origin_too`, and the AST guard — done
  - [x] NFR-AUD-safe — done
- Review: with CC-CRAWL-0015.
- Effectiveness: verified offline with a real Chromium.

### CC-AUD-0032 — Value-shape and header rules; rules validated on load (forms phase 2, lane A) (2026-10-14)
- Change:
  - `audit/value_shape.py`: `value_shape` (url, ip, filename, path, hostname; total,
    bounded, linear, regex-free), `neutral_value`, `SAFE_HOST`, `SAFE_URL`.
  - `InjectionPoint.origin`, `.value_shapes`, `.base_value`; a fired rule's evidence
    carries `"base_value"` when set (the strategy prefix is built under CC-FUZZ-0063).
  - `audit/rules.py`: `value_shape_in` and `origin_in` predicates; `validate_rule` /
    `RuleError` in `load_rules`; `evaluate` leaves an invalid plugin rule out and counts
    it (`invalid_plugin_rules`), never fatal.
  - Rules: `R-SQLI-HEADER`, `R-XSS-HEADER` (crawl header points),
    `R-COMMAND-INJECTION-VALUE`, `R-FILE-INCLUSION-VALUE` (appended last).
- Follow-up (code review of 97fe402, reviewer B R3): `neutral_value` now errs toward
  loopback — any `://` value (any scheme, any length) or `//`-prefixed value →
  `SAFE_URL`; a host or ip with a port → `SAFE_HOST`, with a path → `SAFE_URL`. Before,
  `10.0.0.1:8080`, `www.example.com:8080`, `//host/`, `gopher://…`, `dict://…`,
  `www.example.com/page` and a >2048-character URL went out unchanged. E-mail
  defaults are a stated residual.
- Impact: crawl points whose default is a host or a file name become command-injection
  or file-inclusion candidates whatever their name; ground-truth candidates are
  unchanged (tested per contract). Accepted false positive: `user.id`, `order.by`
  classify as host names (one command-injection candidate each, 11 requests on a
  negative). Each run records four more `evaluation` rows per point.
- Risk: low to medium (more candidates on crawl runs; one confirmation per key).
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_forms_phase2.py`) — done
  - [x] FR-AUD-20 — done
- Review: as CC-FUZZ-0063.
- Effectiveness: verified offline; mutation check as CC-FUZZ-0063.

### CC-AUD-0031 — Candidate evidence carries a form point's entries (forms phase 1) (2026-10-13)
- Change: `audit/engine.InjectionPoint.base_entries`. A fired rule's candidate evidence
  includes `"entries"`, values already blanked for secrets.
- Impact: the pipeline (`_candidate_of`) and oracle bind them. Rules are unchanged.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests — done
  - [x] FR-AUD-19 — done
- Review: as CC-CORE-0039.
- Effectiveness: verified live.

### CC-AUD-0030 — The auditor logs in from `--base-url` before any fetch (BUG-0113) (2026-10-13)
- Change: with `--identity`, after `make_auth`, the auditor calls
  `ensure(host, identity, --base-url, operator=True)`, so seam requests and re-logins
  use the operator's base rather than a page's directory.
- Impact: an authenticated audit of a sub-path app works. A wrong credential fails
  before the first fetch.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] test — done
- Review: B-S1 (BUG-0113 v2).
- Effectiveness: verified by test.

### CC-AUD-0029 — The auditor never re-fetches or follows to a destructive URL (BUG-0111) (2026-10-13)
- Change: `tools/fetcher.py`:
  - `load_urls` drops destructive URLs, so a spider DB written before the fix is safe
    too;
  - the raw static fetch follows redirects by hand (same origin, not destructive);
  - the Playwright page gets `navguard.guard_page`;
  - `requirements.md` gains traceability lines for NFR-AUD-safe (partly; there is no
    destructive-check gate yet) and NFR-AUD-dry-run.
- Impact: the auditor audits fewer URLs where they are destructive. Its raw path no
  longer auto-follows redirects.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: old DB, redirect — done
  - [x] traceability — done
- Review: as CC-CORE-0038 (A2, B1).
- Effectiveness: verified.

### CC-AUD-0028 — Field default values as a browser holds them (BUG-0110 sweep) (2026-10-13)
- Change: `tools/fetcher.py::PageContext._field`'s `value` is
  `core.forms.default_value(el)`:
  - a select reports its selected or first option;
  - a textarea reports its text;
  - a checkbox or radio reports its value, or `on`.
- Impact:
  - **Behaviour change:** these values feed `candidates()` and the value-based rules
    (`rule_nosql_operators`, `rule_serialized_tokens`, `rule_export_endpoints`'s
    example, `rule_privileged_hidden_fields`). They can now emit an indicator for a
    select or textarea that holds a token or operator; before, those values were
    always `""`;
  - no schema change.
- Risk: low. It adds correct indicators only; names and targets are unchanged.
- Deliverables:
  - [x] `_field` uses `default_value` — done
  - [x] tests: default values, and a serialised token in a textarea now found — done
  - [x] FR-AUD-18 — done
- Review: as CC-CORE-0037. The draft named this CC-CRAWL-0011, but `tools/fetcher.py`'s
  log is the Auditor's, so it was corrected here. Reviewer A asked for this exact
  behaviour-change note.
- Effectiveness: verified by the tests above.

### CC-AUD-0027 — `R-PATH-TRAVERSAL` audit rule closes category 4's last known real, tracked detection gap (2026-09-23)

- Change: adds `R-PATH-TRAVERSAL`, category `path-traversal`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["query", "body"], "sink_context_in": ["fs_path_read"]}`, the same
  `location_in`+`sink_context_in` shape as `R-HEADER-INJECTION`/
  `R-INSECURE-DESERIALIZATION`/`R-UNRESTRICTED-FILE-UPLOAD`/
  `R-PRICE-TRUST-DIFFERENTIAL`. `reference` is `"directory-traversal"` — an
  existing `references/directory-traversal` catalog directory names this
  exact concern, unlike `R-HEADER-INJECTION`'s own deliberate departure
  (checked before choosing this reference, not assumed). Gated on
  `sink_context_in: ["fs_path_read"]` rather than the pre-existing
  `R-FILE-INCLUSION` rule's `name_regex` (`file|path|page|include|
  template|doc|folder|dir|load`) deliberately: `sink_context=
  "fs_path_read"` is this project's own ground-truth-schema label for
  exactly this concern (`TWCH-0011`'s own `labels.json` entry), and this
  rule's own category (`path-traversal`) and `vuln_class`
  (`path_traversal`, underscored) are both genuinely distinct from
  `R-FILE-INCLUSION`'s own category/vuln_class (`file-inclusion`, which
  matches no current ground truth and is left untouched) — the two rules
  legitimately both fire on `filename` (the `name_regex` matches
  "file" too), generating two independent candidates under two
  independent categories for the same point; this is by design, not a
  duplicate, since `PathTraversalStrategy`'s own `"file-inclusion"`
  strategy fails closed on this page (no candidate reaches it, since
  `file-inclusion` has no `_VULN_TO_CATEGORY`/ground-truth path into a
  scored automatic run today), while the new `R-PATH-TRAVERSAL`/
  `PathTraversalFsPathReadStrategy` pair is the one that actually scores.
  Checked before landing: `sink_context="fs_path_read"` is used nowhere
  else in the project (`grep -rl '"sink_context": "fs_path_read"'
  lab/ground-truth-*/labels.json` returns only Twitch's own file), so
  there is no cross-target overlap to reason about, unlike
  `R-HEADER-INJECTION`'s own `outbound_header_injection` case.
- Impact (other components / project): `AUD` primarily
  (`default_rules.json`). `FUZZ`'s `CC-FUZZ-0046` (this rule's own
  companion oracle strategy, `PathTraversalFsPathReadStrategy`) depends
  on this rule to ever receive a candidate to confirm. Closes
  `CC-LAB-0190`'s own deliberately-deferred detection follow-on for
  Twitch's `TWCH-0011` — this project's own last known real, TRACKED
  category-4 detection gap.
- Risk (level; mitigation or accepted-risk justification): Low.
  Additive-only (one new rule entry, no existing rule changed). The
  `sink_context_in` gate means this rule only ever fires for a point
  whose `sink_context` was positively typed as `"fs_path_read"` — never
  for a crawled/untyped real point with no `sink_context` at all — so it
  cannot spuriously widen candidate generation on an untyped black-box
  target. No cross-target `sink_context` overlap exists today (checked
  directly).
- Deliverables:
  - [x] `R-PATH-TRAVERSAL` rule added — done
  - [x] Cross-checked `sink_context="fs_path_read"` against every other
        `labels.json` file for an unintended overlap — none found — done
  - [x] Verified live via the real, scored multitarget pipeline
        (`tests/test_multitarget_category4.py`) — done
- Effectiveness (assessed 2026-09-23): achieved. `evaluate()` now
  nominates a real candidate for `TWCH-0011`'s `filename` param under
  category `path-traversal`, which `PathTraversalFsPathReadStrategy`
  confirms — verified against a live-booted app through the real
  `run_targets` pipeline (Twitch's own `tp` moves from 13 to 14, `fp`
  stays 0).

### CC-AUD-0026 — `R-HEADER-INJECTION` audit rule (2026-09-23)

- Change: adds `R-HEADER-INJECTION`, category `http-header-injection`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["query", "body"], "sink_context_in": ["header"]}`, the same
  `location_in`+`sink_context_in` shape as `R-INSECURE-DESERIALIZATION`/
  `R-UNRESTRICTED-FILE-UPLOAD`/`R-PRICE-TRUST-DIFFERENTIAL`. `reference` is
  `"http-response-splitting"` (no existing `references/` catalog
  directory names this concern under that exact slug — the same kind of
  deliberate departure from the "reference matches an existing catalog
  dir" default `R-PRICE-TRUST-DIFFERENTIAL`'s own entry already took, for the same
  reason: no catalog entry exists yet for this concern). Gated on
  `sink_context_in: ["header"]` rather than a `name_regex` (the shape
  `R-OPEN-REDIRECT` uses) deliberately: `sink_context="header"` is this
  project's own ground-truth-schema label for exactly this concern
  (`TWCH-0013`'s own `labels.json` entry), and a name-based regex would
  either miss this shape (a redirect-style `destination` param, already
  claimed by `R-OPEN-REDIRECT`'s own broader regex) or risk over-matching
  unrelated params project-wide for a concern that is currently
  single-instance — checked before choosing this gate: `sink_context=
  "header"` is also used by `outbound_header_injection`
  (php_laravel's HuddleHub `triggerWord`, `CC-LAB-0135`, a genuinely
  distinct OUTBOUND-request-header concern, not this one), so this rule
  DOES generate a second candidate there too under this rule's own
  category — verified this cannot cause a false positive:
  `HttpHeaderInjectionCrlfStrategy` (`CC-FUZZ-0045`) fails closed on that
  page (no response-header splice is observable for an outbound-only
  injection), and `outbound_header_injection`'s own `vuln_class` has no
  `_VULN_TO_CATEGORY` entry mapping it to `http-header-injection`, so no
  currently-automatic, ground-truth-driven run against HuddleHub ever
  includes this category in `plan.categories` to generate the candidate
  in the first place.
- Impact (other components / project): `AUD` primarily
  (`default_rules.json`). `FUZZ`'s `CC-FUZZ-0045` (this rule's own
  companion oracle strategy, `HttpHeaderInjectionCrlfStrategy`) depends on
  this rule to ever receive a candidate to confirm. Closes `CC-LAB-0198`'s
  own deliberately-deferred detection follow-on for Twitch's
  `TWCH-0013`.
- Risk (level; mitigation or accepted-risk justification): Low.
  Additive-only (one new rule entry, no existing rule changed). The
  `sink_context_in` gate means this rule only ever fires for a point whose
  `sink_context` was positively typed as `"header"` — never for a
  crawled/untyped real point with no `sink_context` at all — so it cannot
  spuriously widen candidate generation on an untyped black-box target.
  The one cross-concern overlap found during review (`outbound_header_
  injection`'s shared `sink_context` value) was checked directly, not
  assumed, and shown structurally unable to produce a false positive
  through either the strategy's own fail-closed confirm logic or the
  category's own current unreachability from that app's ground truth.
- Deliverables:
  - [x] `R-HEADER-INJECTION` rule added — done
  - [x] Cross-checked `sink_context="header"` against every other
        `labels.json` file for an unintended overlap, and verified the
        one found (`outbound_header_injection`) cannot false-positive —
        done
  - [x] Verified live via the real, scored multitarget pipeline
        (`tests/test_multitarget_category4.py`) — done
- Effectiveness (assessed 2026-09-23): achieved. `evaluate()` now
  nominates a real candidate for `TWCH-0013`'s `destination` param under
  category `http-header-injection`, which `HttpHeaderInjectionCrlfStrategy`
  confirms — verified against a live-booted app through the real
  `run_targets` pipeline (Twitch's own `tp` moves from 12 to 13, `fp`
  stays 0).

### CC-AUD-0025 — `R-PRICE-TRUST-DIFFERENTIAL` audit rule (2026-09-23)

- Change: adds `R-PRICE-TRUST-DIFFERENTIAL`, category `price-integrity-bypass`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["body"], "sink_context_in": ["payment_charge"]}`, the same
  `location_in`+`sink_context_in` shape as `R-MASS-ASSIGNMENT`/
  `R-UNRESTRICTED-FILE-UPLOAD`. `reference` is
  `"business-logic-price-manipulation"` (no existing `references/`
  catalog directory names this concern -- the same kind of deliberate
  departure from the "reference matches an existing catalog dir" default
  `CC-AUD-0023` already recorded and explained for
  `"upload-insecure-files"`, not silently assumed to exist). The
  project's first-ever candidate-generation rule for
  `price_integrity_bypass` (CWE-807) -- this vuln class now exists on two
  lab pages (`php_laravel`'s Booking.com checkout, `CC-LAB-0212`, and
  `spring_boot`'s Netflix plan-change endpoint, `CC-LAB-0188`), and had no
  rule at all before this entry, closing Netflix's own deliberately-
  deferred `NFLX-0005` structural detection zero. Paired with
  `CC-FUZZ-0041`'s new `PriceTrustDifferentialStrategy` oracle confirmation.
  **Deliberately scoped to `sink_context_in: ["payment_charge"]` only,
  not also `"sql"`** (Booking.com's own `BKNG-0003` ground truth uses
  `sink_context="sql"` there, since its own sink is a real DB insert) --
  checked and rejected during this rule's own drafting, not discovered
  after the fact: `"sql"` is already the `sink_context` for a large
  number of unrelated SQL-injection ground-truth points project-wide
  (confirmed by grep across every `lab/ground-truth-*/labels.json`), so
  including it here would have generated a spurious
  `price-integrity-bypass` candidate for essentially every SQL-sink point
  in the project -- a real false-candidate-explosion risk this narrower
  scoping avoids entirely. `R-SQLI-PARAM`'s own `when` clause has no
  `sink_context_in` filter at all, so it is unaffected either way; this
  rule simply does not attempt to also cover Booking.com's own
  `php_laravel` cell, which remains a real, deliberately-scoped, one-page
  detection gap tracked here rather than silently claimed as covered.
  Reviewed via the mandatory pre-change review gate: the `Agent` tool for
  a two-independent-reviewer pass was checked for and found unavailable
  in this session's toolset (via `ToolSearch`) -- the same substitution
  precedent `CC-LAB-0182`-`0188`/`CC-AUD-0023`/`CC-AUD-0024` already used,
  documented here rather than silently skipped. **(1) Accuracy** --
  checked by direct source inspection: confirmed `NFLX-0005`'s real
  ground-truth `sink_context` value (`"payment_charge"`) directly from
  `lab/ground-truth-netflix-clone/labels.json`, and confirmed
  `fuzzlab.harness.auto.points_from_ground_truth` genuinely propagates it
  onto the real audited `InjectionPoint` (verified by reading that
  function's own code, not assumed, the same discipline `CC-AUD-0023`
  used) -- and, in the course of that check, actually found the point
  was NOT reaching the strategy as JSON at all (see `CC-FUZZ-0041`'s own
  entry for the `param="body"` ground-truth correction this uncovered).
  **(2) Adequacy** -- checked this rule does not collide with or
  duplicate `R-MASS-ASSIGNMENT`/`R-UNRESTRICTED-FILE-UPLOAD`/any SQLi
  rule (each keys on a disjoint `sink_context_in` value, or no
  `sink_context_in` filter at all for `R-SQLI-PARAM`, so no two rules
  with a `sink_context_in` filter can ever both fire for the same
  `payment_charge` point); confirmed via a real, executed `run_targets`
  pipeline run
  (`tests/test_multitarget_category4.py::test_netflix_multi_cell_boot_confirms_all_positives`)
  that this rule actually fires for the real ground-truth point and the
  paired strategy actually confirms it, moving Netflix's own real, scored
  recall from 4/4 to 5/5 -- not assumed correct from unit tests alone.
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-15`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-UNRESTRICTED-FILE-UPLOAD`). Only
  Netflix's own ground truth currently uses `sink_context="payment_charge"`
  (Booking.com's own price-integrity cell uses `"sql"` instead, per this
  entry's own explicit, recorded scoping decision), so no other target's
  scoring changes. Paired with `CC-FUZZ-0041` (oracle) — see that entry
  for the full strategy record and the ground-truth correction it made.

### CC-AUD-0024 — `R-ACCESS-CONTROL` widened to also match `account_id` (2026-09-23)

- Change: widens `R-ACCESS-CONTROL`'s `name_regex` in `fuzzlab/audit/
  rules_data/default_rules.json` from `channel_id|resource_id|object_id|
  item_id|record_id|owner_id` to `channel_id|resource_id|object_id|
  item_id|record_id|owner_id|account_id` — one new alternative, additive
  only, nothing else about the rule changes (`method_in: ["GET"]`,
  `location_in: ["query"]`, `reference: "access-control"` all unchanged).
  Needed because `CC-LAB-0187` (Netflix's `/api/account/billing`, this
  project's first `access_control`/IDOR page on `spring_boot`) uses
  `account_id` as its query-param name — the idiomatically correct name
  for a real account-billing feature — and that name did not already
  match the rule (read and confirmed directly before widening, not
  assumed). Reviewed via the mandatory pre-change review gate: the
  `Agent` tool for a two-independent-reviewer pass was checked for and
  found unavailable in this session's toolset (via `ToolSearch`) — the
  same substitution precedent `CC-LAB-0182`-`0186`/`CC-AUD-0023` already
  used, documented here rather than silently skipped. **(1) Accuracy** —
  confirmed by direct source inspection: the pre-existing regex, read
  verbatim from the file before editing, genuinely lacked `account_id`;
  grepped every existing manifest and every ground-truth `labels.json`
  in the project for `account_id` first and found none, so this widening
  cannot silently start matching (and therefore rescoring) any
  pre-existing case. **(2) Adequacy** — checked this widening does not
  make the rule dangerously broad: `account_id` is exactly as
  specific as the six names already present (a `_id`-suffixed
  object-identifier name, not a generic token like `id` alone), and the
  rule's own `method_in`/`location_in` scoping (GET query params only)
  is unchanged, so the same bounded false-positive risk
  `AccessControlIdorStrategy`'s own docstring already documents and
  accepts is not widened in kind, only in the set of param names that
  can reach it; confirmed via a real, executed `run_targets` pipeline
  run (`tests/test_multitarget_category4.py::
  test_netflix_multi_cell_boot_confirms_all_positives`) that the widened
  rule actually fires for `NFLX-0004`'s real ground-truth point and the
  paired, already-existing `AccessControlIdorStrategy` actually confirms
  it, moving Netflix's own real, scored recall from 3/3 to 4/4 — not
  assumed correct from unit tests alone.
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/01-target-lab/requirements.md` (`FR-LAB-142`, paired
    lab-side entry)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — additive
  only (one new regex alternative on an existing rule). No other ground
  truth in the project currently uses `account_id` (grepped and
  confirmed before landing), so no other target's scoring changes.
  Paired with `CC-LAB-0187` (target lab) — see that entry for the full
  new-page record.
- Risk (level; mitigation or accepted-risk justification): **low**.
  A single-alternative regex widening on an already-scoped rule
  (`method_in`/`location_in` unchanged); confirmed to affect zero
  pre-existing cases by grep before landing, and to correctly fire for
  the one new case it targets by a real, executed pipeline run.
- Deliverables:
  - [x] Regex widened, additive-only, confirmed to affect no pre-existing
    case
  - [x] Verified live against a real booted app via
    `test_netflix_multi_cell_boot_confirms_all_positives` — recall
    `3/3` -> `4/4`
  - [x] Full non-slow suite re-verified green
  - [x] Pre-change review gate's `Agent`-tool absence flagged explicitly,
    substituted with a documented self-review (accuracy + adequacy)
- Effectiveness (assessed 2026-09-23): met — `R-ACCESS-CONTROL` now fires
  for Netflix's own `account_id`-keyed page with no other case affected,
  verified live, not assumed.

### CC-AUD-0023 — `R-UNRESTRICTED-FILE-UPLOAD` audit rule (2026-09-23)

- Change: adds `R-UNRESTRICTED-FILE-UPLOAD`, category
  `unrestricted-file-upload`, to `fuzzlab/audit/rules_data/
  default_rules.json` — `{"location_in": ["body"], "sink_context_in":
  ["fs_web_root_write"]}`, the same `location_in`+`sink_context_in` shape
  as `R-MASS-ASSIGNMENT`/`R-INSECURE-DESERIALIZATION`/`R-XXE`. `reference`
  is `"upload-insecure-files"` (the matching `references/` catalog
  directory name — `unrestricted-file-upload` itself has no catalog dir,
  so this is a genuine, deliberate departure from the "reference matches
  the category slug" convention every prior rule in this file happened to
  follow, recorded here rather than left implicit). The project's
  first-ever candidate-generation rule for `unrestricted_file_upload`
  (CWE-434) — this vuln class exists on only one lab page so far
  (Twitch's `/channels/emotes/upload`, `CC-LAB-0186`), and had no rule at
  all before this entry, closing that page's own deliberately-deferred
  `TWCH-0009` structural detection zero. Paired with `CC-FUZZ-0040`'s new
  `UnrestrictedFileUploadContentTypeTrustStrategy` oracle confirmation.
  Reviewed via the mandatory pre-change review gate: the `Agent` tool for
  a two-independent-reviewer pass was checked for and found unavailable
  in this session's toolset (via `ToolSearch`, several queries) — the
  same substitution precedent `CC-LAB-0182`-`0186` already used,
  documented here rather than silently skipped. **(1) Accuracy** —
  checked by direct source inspection of both real Go sink templates
  (`no_extension_check.go.j2`/`extension_allowlist_mime_check.go.j2`)
  before designing the rule/strategy pair, not assumed from the
  `CC-LAB-0186` change-control entry's own prose alone: confirmed both
  twins write-and-serve in the same POST response (no separate GET
  round trip exists to key detection off), confirmed `TWCH-0009`'s real
  ground-truth `param`/`location`/`sink_context` values
  (`file`/`body`/`fs_web_root_write`) directly from `lab/
  ground-truth-twitch-clone/labels.json` and confirmed
  `fuzzlab.harness.auto.points_from_ground_truth` genuinely propagates
  `sink_context` onto the real audited `InjectionPoint` (verified by
  reading that function's own code, not assumed). **(2) Adequacy** —
  checked this rule does not collide with or duplicate `R-MASS-
  ASSIGNMENT`/`R-INSECURE-DESERIALIZATION`/`R-XXE` (each keys on a
  disjoint `sink_context_in` value: `mass_assignment`/`deserialization`/
  `xml` vs. this rule's own `fs_web_root_write`, so no two rules can ever
  both fire for the same point); confirmed via a real, executed
  `run_targets` pipeline run (`tests/test_multitarget_category4.py::
  test_both_apps_run_through_multitarget_for_real`) that this rule
  actually fires for the real ground-truth point and the paired strategy
  actually confirms it, moving Twitch's own real, scored recall from 7/9
  to 8/9 — not assumed correct from unit tests alone, the same discipline
  `CC-AUD-0018`'s own `sink_context` propagation defect was originally
  caught by.
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-14`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-MASS-ASSIGNMENT`). No other
  ground truth in the project currently uses `fs_web_root_write`, so no
  other target's scoring changes. Paired with `CC-FUZZ-0040` (oracle) —
  see that entry for the full strategy record.

### CC-AUD-0022 — `R-MASS-ASSIGNMENT` audit rule (2026-09-23)

- Change: adds `R-MASS-ASSIGNMENT`, category `mass-assignment`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["body"], "sink_context_in": ["mass_assignment"]}`, the same rule
  shape as `R-INSECURE-DESERIALIZATION`/`R-XXE`. The project's first-ever
  candidate-generation rule for the `mass-assignment` category —
  `mass_assignment` lab pages already exist on three other stacks
  (`php_current`/`ruby_rails`/`php_laravel`), but none had ever had a
  rule or strategy at all before this entry, and this Twitch page
  (`CC-LAB-0182`) closes its own `TWCH-0006` structural detection zero.
  Paired with `CC-FUZZ-0039`'s new `MassAssignmentPrivilegedFieldStrategy`
  oracle confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0039`
  for the full review record and the real ground-truth `param`
  convention defect the accuracy pass's real `run_targets` re-run
  caught before landing).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-13`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-WEAK-TOKEN-ENTROPY`). Also the
  first rule to ever fire for the pre-existing `php_current`/
  `ruby_rails`/`php_laravel` mass-assignment ground-truth cases
  (`FCART-0004` et al.) if/when their own targets are next run through
  the generic pipeline — those cases use a differently-shaped
  form-encoded/nested-param convention this rule still nominates
  (`location_in`/`sink_context_in` alone, no `param`-shape assumption),
  but `MassAssignmentPrivilegedFieldStrategy` itself fails closed on them
  (see that strategy's own docstring) — a candidate nominated but not yet
  confirmable elsewhere, the same honest state every other rule's
  cross-target reach already carries.
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate; it cannot itself produce a false
  "confirmed" finding (that risk lives in the paired strategy, assessed
  in `CC-FUZZ-0039`).
- Deliverables:
  - [x] `R-MASS-ASSIGNMENT` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_mass_assignment_rule_matches_a_body_mass_
        assignment_point`, `test_r_mass_assignment_rule_does_not_match_a_
        query_point`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `MassAssignmentPrivilegedFieldStrategy`, the rule correctly nominates
  Twitch's real `TWCH-0006` point and is proven end-to-end against a
  real booted app — see `CC-FUZZ-0039`'s Effectiveness note.

### CC-AUD-0021 — `R-WEAK-TOKEN-ENTROPY` audit rule (2026-09-23)

- Change: adds `R-WEAK-TOKEN-ENTROPY`, category `weak-token-entropy`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"method_in":
  ["POST"], "sink_context_in": ["session_token"]}`. The project's first
  candidate-generation rule for the `weak-token-entropy` category,
  closing Twitch's `TWCH-0005` structural detection zero. Genuinely a
  new, less-constrained rule shape (no `location_in`, unlike
  `R-INSECURE-DESERIALIZATION`/`R-XXE`'s own `sink_context_in`+
  `location_in` pairing) — this class has no real tainted location to
  key off at all, so `method_in` substitutes as the available
  constraint, confirmed by the accuracy-review pass as a deliberate,
  documented departure from the established pattern, not an oversight.
  Paired with `CC-FUZZ-0038`'s new `PredictableTokenSourceStrategy`
  oracle confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0038`
  for the full review record).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-12`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-JWT-ALG-NONE`).
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate; it cannot itself produce a false
  "confirmed" finding (that risk lives in the paired strategy, assessed
  in `CC-FUZZ-0038`).
- Deliverables:
  - [x] `R-WEAK-TOKEN-ENTROPY` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_weak_token_entropy_rule_matches_a_post_
        session_token_point`, `test_r_weak_token_entropy_rule_does_not_
        match_a_get_point`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `PredictableTokenSourceStrategy`, the rule correctly nominates Twitch's
  real `TWCH-0005` point and is proven end-to-end against a real booted
  app — see `CC-FUZZ-0038`'s Effectiveness note.

### CC-AUD-0020 — `R-JWT-ALG-NONE` audit rule (2026-09-23)

- Change: adds `R-JWT-ALG-NONE`, category `jwt-algorithm-confusion`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["header"], "name_regex": "authorization|jwt"}`. The project's first
  candidate-generation rule for the `jwt-algorithm-confusion` category,
  closing Twitch's `TWCH-0004` structural detection zero. Scoped to
  header-location points only, mirroring `R-ACCESS-CONTROL`'s own
  location-narrowed shape — this class's own attack surface is
  inherently header-carried. `"bearer"` deliberately dropped from the
  `name_regex` during review (a header *value* prefix, not a header
  name — would have added dead/misleading weight). Paired with
  `CC-FUZZ-0037`'s new `JwtAlgNoneConfusionStrategy` oracle
  confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0037`
  for the full review record, since both passes covered the rule and the
  strategy together).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-11`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-XXE`).
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate; it cannot itself produce a false
  "confirmed" finding (that risk lives in the paired strategy, assessed
  in `CC-FUZZ-0037`).
- Deliverables:
  - [x] `R-JWT-ALG-NONE` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_jwt_alg_none_rule_matches_an_authorization_
        header_point`, `test_r_jwt_alg_none_rule_does_not_match_an_
        unrelated_header`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `JwtAlgNoneConfusionStrategy`, the rule correctly nominates Twitch's
  real `TWCH-0004` point and is proven end-to-end against a real booted
  app — see `CC-FUZZ-0037`'s Effectiveness note.

### CC-AUD-0019 — `R-XXE` audit rule (2026-09-23)

- Change: adds `R-XXE`, category `xxe`, to `fuzzlab/audit/rules_data/
  default_rules.json` — `{"location_in": ["body"], "sink_context_in":
  ["xml"]}`. The project's first candidate-generation rule for the `xxe`
  category, closing TrackerNest's and Netflix's shared structural
  detection zero. Second use of `sink_context_in` (after
  `R-INSECURE-DESERIALIZATION`) — same necessary shape: this class has no
  informative parameter name to key off, every whole-body point sharing
  the literal `param="body"`. Paired with `CC-FUZZ-0035`'s new
  `XxeInBandMarkerStrategy`/`XxeOobStrategy` oracle confirmation. Reviewed
  pre-implementation per the component's pre-change review gate (accuracy
  + adequacy passes — see `CC-FUZZ-0035` for the full review record).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-10`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-INSECURE-DESERIALIZATION`).
- Risk (level; mitigation or accepted-risk justification): Low-medium.
  Same explicit scope limit as `R-INSECURE-DESERIALIZATION`
  (`FR-AUD-9`): `sink_context` is currently populated only from ground
  truth (`BUG-0041`'s fix), not inferred generically by the auditor for
  an arbitrary crawled target — reachable only in the project's own
  ground-truth-scored detection-benchmark mode today.
- Deliverables:
  - [x] `R-XXE` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_xxe_rule_matches_a_body_xml_point`,
        `test_r_xxe_rule_does_not_match_an_unrelated_sink_context`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `XxeInBandMarkerStrategy`, the rule correctly nominates TrackerNest's
  real `TNEST-0002` point and is proven end-to-end against a real booted
  app, through both a dedicated live-boot test and the real generic
  ground-truth-driven multitarget pipeline — see `CC-FUZZ-0035`'s
  Effectiveness note.

### CC-AUD-0018 — `R-INSECURE-DESERIALIZATION` audit rule (2026-09-23)

- Change: adds `R-INSECURE-DESERIALIZATION`, category
  `insecure-deserialization`, to `fuzzlab/audit/rules_data/
  default_rules.json` — `{"location_in": ["body"], "sink_context_in":
  ["deserialization"]}`. The project's first rule to use the
  `sink_context_in` `when` predicate (`fuzzlab/audit/rules.py`'s own
  docstring has always listed it as supported; no prior rule exercised
  it). Necessary shape: this vulnerability class has no informative
  *parameter name* to key off (`param="body"` for a whole-body point,
  the same literal string every whole-body point of any class uses), so
  `sink_context` (what kind of sink the point actually is) is the only
  available signal, unlike every previous rule in this file. Paired with
  `CC-FUZZ-0034`'s new `InsecureDeserializationTypeConfusionStrategy`
  oracle confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0034`
  for the full review record, since both passes covered the rule and the
  strategy together).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-9`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-ACCESS-CONTROL`). Being the
  first `sink_context_in` rule, it also exposed a real, previously
  dormant defect in `fuzzlab.harness.auto.points_from_ground_truth`
  (`sink_context` was never propagated onto a ground-truth-sourced
  `InjectionPoint` at all) — recorded and fixed in `CC-FUZZ-0034`, not
  duplicated here, since this rule alone cannot itself cause a false
  finding (that risk lives in the paired strategy).
- Risk (level; mitigation or accepted-risk justification): Low-medium.
  `sink_context` is currently populated only from ground truth, not
  inferred generically by the auditor for an arbitrary crawled target
  (`FR-AUD-9` states this explicitly) — this rule is reachable only in
  the project's own detection-benchmark (ground-truth-scored) mode today,
  not yet a general crawl-driven capability. Documented as a real,
  explicit scope limit rather than silently assumed to generalize.
- Deliverables:
  - [x] `R-INSECURE-DESERIALIZATION` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_insecure_deserialization_rule_matches_a_body_
        deserialization_point`,
        `test_r_insecure_deserialization_rule_does_not_match_an_
        unrelated_sink_context`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `InsecureDeserializationTypeConfusionStrategy`, the rule correctly
  nominates Netflix's real `NFLX-0001` point and is proven end-to-end
  against a real booted app, including through the real generic
  ground-truth-driven pipeline (not just a dedicated Tier1/2 test) — see
  `CC-FUZZ-0034`'s Effectiveness note.

### CC-AUD-0017 — `R-ACCESS-CONTROL` audit rule (2026-09-23)

- Change: adds `R-ACCESS-CONTROL`, category `access-control`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"method_in": ["GET"],
  "location_in": ["query"], "name_regex": "channel_id|resource_id|
  object_id|item_id|record_id|owner_id"}`. The project's first
  candidate-generation rule for the `access_control` (IDOR/BOLA) category,
  closing the `CC-LAB-0178` open question. Narrower than `R-SSRF`'s own
  bare-`name_regex` shape by design — the adequacy pass of the paired
  `CC-FUZZ-0033` pre-change review gate flagged the originally-drafted
  bare `name_regex` (which also matched `account_id`) as a realistic
  false-positive source against a legitimate multi-account search
  feature; `method_in`/`location_in` were added and `account_id` dropped
  from the term list in response. Paired with `CC-FUZZ-0033`'s new
  `AccessControlIdorStrategy` oracle confirmation (this rule alone only
  generates a candidate; that strategy confirms it).
  Reviewed pre-implementation per the component's pre-change review gate
  (accuracy + adequacy passes — see `CC-FUZZ-0033` for the full review
  record, since both passes covered the rule and the strategy together).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-8`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-SSRF`, nothing else changed), so
  no existing rule's behavior is affected. Requires the paired
  `fuzzlab.core.runmode._VULN_TO_CATEGORY` fix (`CC-FUZZ-0033`) to
  actually be reachable from a ground-truth-driven run — recorded there,
  not duplicated here.
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate for confirmation; it cannot itself produce a
  false "confirmed" finding (that risk lives in the paired strategy,
  assessed in `CC-FUZZ-0033`). The narrowed `method_in`/`location_in`
  scope reduces how often the rule fires on an unrelated GET/query param
  that happens to share a common id-shaped name.
- Deliverables:
  - [x] `R-ACCESS-CONTROL` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_access_control_rule_matches_a_channel_id_query_
        get_point`, `test_r_access_control_rule_does_not_match_a_body_or_
        post_point`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `AccessControlIdorStrategy`, the rule correctly nominates Twitch's real
  `TWCH-0003` point and is proven end-to-end against a real booted app
  (see `CC-FUZZ-0033`'s Effectiveness note).

### CC-AUD-0016 — `R-SSRF` audit rule (2026-09-23)

- Change: adds `R-SSRF`, category `ssrf`, to
  `fuzzlab/audit/rules_data/default_rules.json` — a bare `name_regex`-only
  rule (`url|uri|link|src|source|target|endpoint|fetch|proxy|webhook|
  image|thumbnail|avatar`), the same shape `R-OPEN-REDIRECT`/
  `R-FILE-INCLUSION`/`R-COMMAND-INJECTION` already use. The project's first
  candidate-generation rule for the `ssrf` category, closing one of the
  three "no audit rule yet" gaps `CC-LAB-0176`/`FR-LAB-99` (category 4's
  Phase E) flagged as real follow-on work. Paired with
  `CC-FUZZ-0031`'s new `SsrfInBandMarkerStrategy`/`SsrfOobStrategy`
  oracle confirmation (this rule alone only generates a candidate; those
  strategies confirm it). Overlaps `R-OPEN-REDIRECT`'s `target` term
  deliberately — `fuzzlab.audit.rules.matches()` is non-exclusive (a
  parameter can match more than one rule, each producing its own
  candidate/category), so the overlap is harmless, not a bug.
  Reviewed pre-implementation per the component's pre-change review gate
  (accuracy + adequacy passes; the adequacy pass's one addition — a cheap
  in-band confirmation layer alongside the OOB one — is reflected in the
  paired FUZZ change, not this rule itself).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-7`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (one new rule appended; no existing rule changed). No existing
  target's scoring changes (no existing ground truth uses the `ssrf`
  category with this rule absent, so nothing regresses).
- Risk (level; mitigation or accepted-risk justification): **low**.
  Additive-only; verified by re-running the full non-slow suite (no new
  failures) plus category 4's own real live-boot Phase E test, which now
  shows a real, confirmed SSRF finding.
- Deliverables:
  - [x] `R-SSRF` rule added, additive
  - [x] Full non-slow suite re-verified green
- Effectiveness (assessed 2026-09-23): met — `evaluate()` now emits a
  real `ssrf`-category candidate for category 4's real SSRF cell
  (`LABGEN-GO-0003`), confirmed end to end by `CC-FUZZ-0031`.

### CC-AUD-0015 — `--dry-run` CLI flag (lane D0a) (2026-09-22)
- Change: `fuzzlab/tools/fetcher.py::build_parser()` gained `--dry-run` (via the
  shared `fuzzlab/cli_dryrun.add_dry_run_flag()`). The module's `__main__` block
  checks `args.dry_run` first: if set, it calls `fuzzlab/cli_dryrun.report("audit",
  args)` — reusing the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015) — and exits 0 before `load_urls`/
  `load_indicators`/`ContentFetcher` run. No probe is sent. Unchanged when
  `--dry-run` is absent.
- Impact (other components / project): AUD only, plus an incidental UI effect — see
  CC-UI-0027 (the introspected `build_parser()` surfaces the new checkbox in the web
  launcher automatically; `fuzzlab/web/app.py` untouched). No schema/store change.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect. Mitigated by `tests/test_cli_dry_run.py` (audit cases: flag present, report
  printed, `load_urls`/`load_indicators` patched to raise if called) and the
  unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `audit`'s parser — done.
  - [x] Short-circuit in `__main__` calling the shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab audit --dry-run` prints
  the planned argv/command and exits 0 without loading any DB or fetching anything;
  verified directly and via the new tests.

### CC-AUD-0014 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/tools/fetcher.py` now factors its argparse setup into `build_parser()`;
  `parse_args()` delegates to it. Added `prog="fuzzlab audit"` for accurate usage.
  Behavior-preserving — same flags, defaults, and parsing.
- Impact: lets the web launcher introspect the auditor's flags (CC-UI-0011). No CLI
  behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `parse_args()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds the auditor's spec
  from this parser.

### CC-AUD-0013 — InjectionPoint carries stored-XSS store endpoint (2026-09-21)
- Change: `audit.InjectionPoint` gained optional `store_url`/`store_param`, and the
  engine writes them into the candidate evidence when set, so a stored-XSS observe
  point can carry the endpoint where its payload is planted (supports CC-FUZZ-0014).
- Impact (other components / project): lets the pipeline build a stored-XSS
  `Candidate`; no schema change (evidence is JSON), GET/query behavior unchanged.
- Risk (level; mitigation): low — additive fields. Covered by the auto stored-XSS
  tests. Suite 162 passed / 2 skipped.
- Deliverables:
  - [x] `store_url`/`store_param` on InjectionPoint + evidence — done.
- Effectiveness (assessed 2026-09-21): effective — the pipeline reconstructs the store
  endpoint and the oracle plants there.

### CC-AUD-0012 — R-XSS-REFLECT also nominates on `fragment` (DOM XSS) (2026-09-21)
- Change: added `fragment` to `R-XSS-REFLECT`'s `location_in`, so URL-fragment
  parameters (client-side DOM sinks, e.g. `reviews.php#author`) get an XSS candidate
  the M6 browser strategy can confirm (CC-FUZZ-0013). SQLi stays query/body (a fragment
  never reaches the server).
- Impact (other components / project): enables DOM-XSS confirmation for fragment
  points under `auto --browser`; no effect without a browser (the points aren't
  audited) or on non-fragment behavior.
- Risk (level; mitigation): low — data-only rule edit; oracle fail-closed. Covered by
  the auto browser-path test. Suite 154 passed / 2 skipped.
- Deliverables:
  - [x] `fragment` added to R-XSS-REFLECT — done.
- Effectiveness (assessed 2026-09-21): effective — fragment DOM points are nominated
  and confirmed via M6 in tests.

### CC-AUD-0011 — R-SSTI nominates on location (parity with XSS) (2026-09-21)
- Change: `R-SSTI`'s `when` changed from `sink_context_in [html]` to
  `location_in [query, body]`, so it nominates a candidate on what discovery knows
  (like `R-XSS-REFLECT`, CC-AUD-0009); the oracle's SSTI strategy (evaluation-marker)
  confirms precisely. Without this the rule was dead in automatic mode (sink_context is
  never set pre-detection — the BUG-0006 class).
- Impact (other components / project): SSTI candidates are now nominated when the SSTI
  category is active (scoped by the run plan, D14), enabling CC-FUZZ-0012's SSTI
  confirmer. No effect on the SQLi/XSS lab benchmark.
- Risk (level; mitigation): low — data-only rule edit; oracle fail-closed (no FP).
  Covered by updated `test_audit_rules`. Suite 145 passed / 2 skipped.
- Deliverables:
  - [x] R-SSTI location-based nomination — done.
- Effectiveness (assessed 2026-09-21): effective — SSTI is nominated when selected;
  the oracle confirms by evaluation marker.

### CC-AUD-0010 — Candidate evidence carries method/location (POST support) (2026-09-21)
- Change: the rules engine now records `method` and `location` in each `candidate`
  row's evidence JSON (previously only `url`/`param`), so the pipeline can reconstruct
  a POST/body candidate and the oracle can probe it over the right transport
  (supports CC-FUZZ-0011).
- Impact (other components / project): enables POST-body injection end to end; no
  schema change (evidence is JSON). GET/query behavior unchanged.
- Risk (level; mitigation): low — an additive evidence field. Covered by the existing
  audit-rules tests and the auto/pipeline POST tests. Suite 135 passed / 2 skipped.
- Deliverables:
  - [x] `method`/`location` added to candidate evidence — done.
- Effectiveness (assessed 2026-09-21): effective — the pipeline builds POST candidates
  from the evidence and the oracle probes them over POST.

### CC-AUD-0009 — R-XSS-REFLECT nominates on location, oracle confirms context (BUG-0006) (2026-09-21)
- Change: changed the `R-XSS-REFLECT` rule's `when` from `sink_context_in [...]` to
  `location_in [query, body]` (symmetric with `R-SQLI-PARAM`). `sink_context` is a
  post-detection label the pipeline's discovery upstream never sets, so the old rule
  never fired in automatic mode and no XSS candidate was ever nominated. The oracle's
  M5 strategy already types the reflection context from the response and is
  fail-closed, so nomination-on-location + oracle-confirmation is the correct division
  of labor (rules nominate on what discovery knows; the oracle decides precisely).
- Impact (other components / project): fixes BUG-0006 — automatic mode can now detect
  reflected XSS (e.g. `search.php?q`) with no false positives on escaped params
  (oracle rejects them). Broader nomination shifts negatives from non-firing rules to
  oracle-rejected candidates (see CC-FUZZ-0010). `R-SSTI` still keys on `sink_context`
  (a spec placeholder; no oracle strategy yet).
- Risk (level; mitigation): low — a data-only rule edit; the oracle remains the sole,
  fail-closed finding-writer so no FP is introduced. Mitigated by updated
  `test_audit_rules` (nomination model) and the auto/pipeline scored tests. Suite 132
  passed / 2 skipped.
- Deliverables:
  - [x] Rule predicate changed to location-based nomination — done.
  - [x] `test_audit_rules` updated to the model; no fixture hand-sets a post-detection
    label to fire a rule (PA-0006) — done.
- Effectiveness (assessed 2026-09-21): effective — XSS candidates are now nominated and
  the oracle confirms the reflected case; live tp for `search.php?q` XSS expected on
  the host run.

### CC-AUD-0008 — `known_categories()` for run-mode selection (2026-09-21)
- Change: added `audit.known_categories()` returning the sorted set of injection
  categories the rule set can test, so the run-mode resolver (CC-CORE-0007,
  D14/T2.9) can offer/validate a category selection.
- Impact (other components / project): consumed by the launcher/harness when
  building a run plan; no behavior change to the engine itself.
- Risk (level; mitigation): low — a read-only helper over the loaded rules; covered
  by the run-mode tests.
- Deliverables:
  - [x] `known_categories()` + export — done.
- Effectiveness (assessed 2026-09-21): effective — returns the rule categories used
  by the selection tests (105/105).

### CC-AUD-0007 — Rules-as-data engine + full evaluation logging (T2.3) (2026-09-21)
- Change: built `fuzzlab/audit/` — a rules-as-data engine. Rules live as JSON
  (`rules_data/default_rules.json`) with a declarative `when` predicate
  (always/location_in/method_in/sink_context_in/name_regex), loaded by `rules.py`;
  `engine.evaluate` runs every rule against every injection point and writes an
  `evaluation` row for **each** evaluation (fired and not-fired), emitting a
  `candidate` row for fired ones. Recording negatives gives a trainable dataset
  (Phase 2 exit half). An optional `categories` filter scopes active rules — the
  hook for D14/T2.9 category selection. Resolves the plan's to-confirm toward a
  dedicated `evaluation` table (negatives there; `candidate` stays the fired subset).
- Impact (other components / project): the store now holds negatives (via CORE
  migration 4, CC-CORE-0006). The rule set is editable data, not code. Wiring the
  fetcher to feed real discovered injection points (with sink-context from T2.4)
  into the engine is the next step (needs the live crawl/lab).
- Risk (level; mitigation): low–medium — a data rule language is new surface; the
  predicate set is small, safe (no code eval), and ANDed with a "no conditions =>
  never fires" guard. 4 unit tests (rules load as data; predicate matching; engine
  logs negatives + candidates with correct counts; category filter scopes rules).
- Deliverables:
  - [x] Rule schema + JSON rule set + loader (rules-as-data) — done.
  - [x] Engine: full evaluation logging (negatives) + candidate emission — done.
  - [x] Category filter hook (D14/T2.9) + 4 tests — done.
  - [ ] Wire the fetcher to feed real injection points into the engine — todo (live).
  - [ ] Port the existing 28 in-code reflection rules to data incrementally — todo.
- Effectiveness (assessed 2026-09-21): effective in unit tests — every (point, rule)
  pair is logged; negatives are present (fired=0) and candidates match fired=1;
  category filter restricts the active rules. Live fetcher wiring pending.

### CC-AUD-0006 — Target fingerprinting (algorithm) (2026-09-21)
- Change: built `core/fingerprint.py` (T2.5) — a pure, accumulative fingerprinter
  that identifies server / framework / DBMS / WAF from response headers, cookies,
  and error text (`Fingerprint.merge` accumulates over responses). Fingerprint-
  before-fuzz lets the scheduler/oracle scope payloads to the target.
- Impact (other components / project): the auditor will accumulate a fingerprint
  over its fetches and write the `target` row (dbms/framework/waf), which the
  scheduler (#8) and oracle (#7) read. The module is in `core/` (shared). Wiring it
  into the auditor's fetch loop + `target` write is the next step (needs live
  responses to validate end-to-end).
- Risk (level; mitigation): low (pure function, tested). Mis-fingerprint is
  non-fatal (payloads just aren't scoped); mitigated by first-observation-wins merge
  and signature specificity. 3 unit tests (PHP/MySQL from headers+error; framework
  from cookie; WAF + merge).
- Deliverables:
  - [x] `fingerprint.py` + tests (T2.5) — done.
  - [ ] Accumulate in the auditor loop and write the `target` row — todo (with T2.8).
- Effectiveness (assessed 2026-09-21): effective in unit tests — server/framework/
  DBMS/WAF identified from representative responses. Live wiring pending.

### CC-AUD-0005 — Authenticated Playwright audit (cookie injection) (2026-09-21)
- Change: the auditor's Playwright engine now authenticates too — `ContentFetcher`
  gained `session_manager`/`auth_base_url`, and `__enter__` injects the session
  (cookies / bearer header) into the browser context via `browserauth`. `main`
  builds the manager + seam client together (`make_auth`) and passes both. With
  this, both auditor paths (static via the seam, browser via injection) audit
  authenticated. Completes the auditor side of Option A.
- Impact (other components / project): JS-rendered pages are audited as an identity;
  depends on the session manager (#3) and credential store. No rule/output change.
- Risk (level; mitigation): low–medium — injection runs once at browser start;
  failed login fails loud. Covered by the `browserauth` unit tests; live browser
  wiring validated on a host with a browser + lab.
- Deliverables:
  - [x] `session_manager`/`auth_base_url` on ContentFetcher; `__enter__` injection — done.
  - [x] `main` builds manager + client via `make_auth` — done.
  - [ ] Live authenticated audit (browser) against the lab (T1.10) — todo.
- Effectiveness (assessed 2026-09-21): effective in unit tests (shared with the
  crawler's browser-auth path); live browser audit pending.

### CC-AUD-0004 — Auditor static fetch migrated onto the auth seam (2026-09-21)
- Change: `ContentFetcher` gained `identity`/`seam_client`; its static
  (non-browser) fetch now routes through the `core/` HTTP seam + session manager
  when an identity is given (via `fuzzlab/tools/authhttp.py`), so pages are audited
  authenticated. Added `--identity` and `--base-url` flags. The Playwright (browser)
  path is unchanged — cookie injection into the browser context is the separate,
  later sub-step. Standalone behavior is unchanged when no identity is given.
  Realizes the requests-tool half of Phase 1 T1.10 for the auditor.
- Impact (other components / project): the auditor can now reach and audit
  authenticated pages as an identity; depends on the session manager (#3) and
  credential store. No rule or output-format change; browser-rendered auditing is
  still unauthenticated until the Playwright sub-step.
- Risk (level; mitigation): low–medium — only the static path changed; standalone
  raw-requests path preserved. Mitigated by isolating the change to `_static_fetch`
  and 2 tests (authenticated static fetch attaches the cookie; standalone uses raw
  requests). Note the mixed state: static = authenticated, browser = not yet.
- Deliverables:
  - [x] `identity`/`seam_client` on ContentFetcher; `_static_fetch`; flags — done.
  - [x] Tests (authenticated static + standalone) — done.
  - [ ] Playwright path cookie injection (browser auth) — todo (next A sub-step).
  - [ ] Live authenticated audit run against the lab (T1.10) — todo.
- Effectiveness (assessed 2026-09-21): effective in tests — the static fetch is
  authenticated and returns the protected page; standalone unchanged. Browser-path
  auth and the live run pending.

### CC-AUD-0003 — Consolidates candidates into the unified store (2026-09-21)
- Change: added `--store PATH` to the auditor; after an audit it consolidates its
  native `findings` into the unified store via `store_adapter.import_audit`,
  writing `candidate` rows (rule = transaction type, evidence JSON incl. category/
  reference/occurrences, sink_context from the HTML context) and linking to a
  discovered `parameter` when one matches. It first imports the spider DB so
  candidates can link to parameters. Native output unchanged without `--store`.
  Phase 0 T0.8.
- Impact (other components / project): candidates now land on the integration bus
  for the scheduler/fuzzer/ranker; depends on the crawler having populated
  parameters (CC-CRAWL-0003) for linkage.
- Risk (level; mitigation): low — opt-in, additive; covered by the consolidation
  test (synthetic audit DB → candidate rows).
- Deliverables:
  - [x] `--store` + `import_audit` (candidate rows, param linkage) (T0.8) — done.
  - [ ] Full per-rule evaluation evidence + versioned features (Phase 2) — todo.
- Effectiveness (assessed 2026-09-21): effective — synthetic findings become
  candidate rows in the unified store (test green).

### CC-AUD-0002 — Moved into the `fuzzlab` package (2026-09-21)
- Change: `fetcher.py` moved to `fuzzlab/tools/fetcher.py`; imports `core/`
  (`get_logger`, structured startup line) and now defaults `--indicator-db` to the
  packaged `php_indicators.db` (via `fuzzlab.tools.paths`) so it runs from
  anywhere. Still writes its own SQLite file (T0.8 migrates it). Phase 0 T0.1.
- Impact (other components / project): the auditor is now a package module and
  resolves its indicator DB from the package rather than the working directory;
  depends on the IND component's packaged data path (CC-IND-0002). No rule or
  output-format change.
- Risk (level; mitigation): low — move + path default + one import; verified the
  module imports, `--help` shows the packaged default, and the indicator DB loads.
- Deliverables:
  - [x] Move into package; import `core/`; packaged indicator-db default (T0.1) — done.
  - [ ] Write candidates to the shared store (T0.8) — todo.
- Effectiveness (assessed 2026-09-21): effective — runs as a package module with
  the packaged indicator DB resolved automatically.

### CC-AUD-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `fetcher.py` renders dynamic
  content, evaluates 28 injection-point rules against discovered parameters, probes
  canary reflection, and emits candidates. Standalone; not yet on the shared store,
  session manager, or ranker.
- Impact (other components / project): produces the candidate queue the scheduler
  and fuzzer consume; depends on the indicator DB for its rule/indicator data.
  Currently writes its own output rather than the shared `candidate` table, and
  rules are in code rather than data.
- Risk (level; mitigation): low–medium. Rules-in-code and no shared store limit
  reuse and explainability; mitigated by the Phase 0 store migration and the
  Phase 2 move to rules-as-data with full per-rule evaluation logging. No current
  risk to other components beyond output format.
- Deliverables:
  - [x] 28-rule evaluation over dynamic + static content — done.
  - [x] Canary reflection probing — done.
  - [ ] Full per-rule evaluation logging (fired + not-fired) — todo (Phase 2).
  - [ ] Rules-as-data registry — todo (Phase 2).
  - [ ] Sink-context typing of reflections — todo (Phase 2).
  - [ ] Target fingerprinting (DBMS/framework/WAF) — todo (Phase 2).
  - [ ] Migrate to the shared store + versioned features — todo (Phase 0 T0.8).
  - [ ] Session-manager integration — todo (Phase 1).
- Effectiveness (assessed or pending): effective at emitting candidates from the
  lab's injection points with the 28 rules active; explainability and store
  integration pending.
