# Fuzzing Harness and Oracle — Change Control Log

Component code: **FUZZ**. Entry format and required fields: see `../README.md`.
Newest first.

### Bookkeeping-ID note: category 4's `CC-FUZZ`/`FR-FUZZ` entries renumbered `0027`-`0042`/`14`-`26` -> `0031`-`0046`/`18`-`30` at merge time (2026-09-23)

Category 4 (`claude/category-4-build-t9uz3y`) independently assigned
`CC-FUZZ-0027`-`0042` and `FR-FUZZ-14`-`26` to its own 16 detection-strategy
entries, colliding with already-landed `CC-FUZZ-0027`-`0030`/`FR-FUZZ-14`-
`17` (category 5's `open_redirect`/`spel_injection`/`price_integrity_
bypass`/`csv_formula_injection` work, below). Renumbered onto the next free
block on each namespace (`CC-FUZZ` `0031`-`0046`, `FR-FUZZ` `18`-`30`),
shift `+4` uniformly, preserving relative (oldest-first) order; every
internal cross-reference within category 4's own entries was updated to
match. Category 4 also independently built a same-named
`PriceIntegrityBypassStrategy`/`R-PRICE-INTEGRITY` pair for the same
`price_integrity_bypass` class with a genuinely different mechanism —
renamed throughout to `PriceTrustDifferentialStrategy`/`R-PRICE-TRUST-
DIFFERENTIAL`. Full old-ID -> new-ID mapping table (also covering `FR-LAB`,
`BUG`, and `PA`, which this merge also renumbered) recorded in
`docs/components/01-target-lab/change-control.md`'s own Bookkeeping-ID
note of the same date.

### CC-FUZZ-0080 — Senders and the oracle respect origin-scoped sessions (FR-SESS-20, BUG-0134) (2026-10-14)
- Change:
  - **`greybox/run.py`:** `RequestsCorrelatingSender(cookie_origins=)`: the cookie is
    attached only to a probe on one of the session's canonical origins; otherwise the
    probe goes without it, `Probe.session = "anonymous (out of origin)"`, counted
    (`session_out_of_origin`). A cookie without origins is refused at construction.
    `run_greybox` records `features["session"]`, `summary["session_out_of_origin"]` and
    the `greybox_session_out_of_origin` metric (when non-zero).
  - **`greybox/greybox_cli.py`:** `_cookie_for` also returns the session's origins and
    hands them to the sender; the summary prints the count.
  - **`oracle/probe.py`:** `Probe.session`.
  - **`oracle/oracle.py`:** `_SessionNotes`, around every strategy run (forwarding only
    non-default arguments; transparent `__getattr__`, `send_correlated` watched too),
    stamps a probe's note on the verdict's `evidence["session"]`.
  - **`tools/probesender.py`:** `SeamProbeSender` stamps `Probe.session` from the
    manager's `session_note` (the copy's for an isolated send) and reports
    `session_out_of_origin`; lane A `_on_logout` and lane B `_on_main_logout` take the
    logout's origin and compare it with the run's session's origins
    (`session_origins_for`), never a host.
  - **`harness/auto.py` / `auto_cli.py`:** `metrics["session_out_of_origin"]`, printed.
- Impact: greybox and auto runs report probes sent without the session; a finding made
  without it says so in its evidence. `tests/test_sender_conformance.py` lists the new
  wrapper.
- Risk: low. Mitigated: the conformance guard (signature, forwarding, PRG capability)
  covers `_SessionNotes`; greybox's gate is mutation-checked.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_session_origin_scope.py`; updated
    `test_forms_phase2.py`, `test_login_form_isolation.py`, `test_destructive_urls.py`,
    `test_session_transport_binding.py`, `test_sender_conformance.py`) — done
  - [x] FR-FUZZ-8 and FR-FUZZ-44 amended in place — done
- Effectiveness (assessed 2026-10-14): see CC-SESS-0023 (the greybox gate mutation
  fails its test); the oracle, greybox, sender-conformance, PRG and lane A/B suites pass.
- Review round 1 of 0046b77 (2026-10-14; R5, R6):
  - **R6:** `SeamProbeSender` copies `Probe.session` from the decision `prepare`
    recorded on the request (`SESSION_DECISION`), never recomputed after the send.
  - **R5:** `fuzzlab auto --auth-origin` and `greybox-run --auth-origin` (repeatable;
    bare, in-scope origins; a usage error before any side effect); `make_probe_sender`
    and greybox's `_cookie_for` take `auth_origins` (auto passes it only when given).

### CC-FUZZ-0079 — Evaluation markers judge their literal's echo by where it is (BUG-0133) (2026-10-14)
- Change: `SstiStrategy` refused Juice Shop's evaluated `/profile` SSTI because the probe's
  literal sat in the edit field (`<input value="#{728*889}">`) and its rule was
  `expr in text`. `oracle/context.split_form_control_values` splits the parsed page into
  form-control values (input `value`, textarea content, a selected option's text and
  value) and the rest; `strategies._echo` / `_echoed_outside_form_controls` /
  `_evaluated` refuse when the literal is echoed outside form controls (parsed, so
  entity-encoded too, or a raw occurrence no control accounts for) and, when it is only in
  form controls, require the number outside every form control. No literal in the page:
  the old rule exactly. Applied to `SstiStrategy`, `SpelInjectionStrategy`,
  `SqliEvaluationMarkerStrategy` (both samples) and `GoTemplateSstiStrategy`. The
  BUG-0117 second sample and FR-FUZZ-49's P5 attribution are unchanged. The rationale
  kept: "evaluated, not just reflected" (M4 since 12ce859; SpEL's literal holds its own
  canary).
- Impact (other components / project): none outside FUZZ; no interface or store change.
  More M4/SpEL/SQL-evaluation confirmations on edit-form pages (the intended effect);
  the Go marker now also refuses an HTML-escaped text echo it used to accept.
- Risk (level; mitigation or accepted-risk justification): medium (a confirmer relaxed).
  Mitigated: the relaxation is limited to form-control values by parsed role; the number
  must be outside them; the second-sample causality check still decides; every
  reflection shape the rule exists for is a fixture that must refuse, for all four
  strategies; mutation-checked both ways; the scored live-boot multitarget tests that
  carry SSTI/SpEL ground truth are re-run (Effectiveness).
- Deliverables:
  - [x] code: `fuzzlab/oracle/context.py`, `fuzzlab/oracle/strategies.py` — done
  - [x] tests: `tests/test_evaluation_marker_echo.py` (4 strategies × 10 page shapes, the
    PRG edit form, the second sample, the split, the old answer, the PA-0133 guard and its
    synthetic offenders); `tests/test_prg_observation.py`'s `editform` fixture — done
  - [x] mutation checks — done (see Effectiveness)
  - [x] BUG-0133, PA-0133, ERROR_LOG, FR-FUZZ-4 (in place), CHANGELOG — done
  - [ ] on-host: Juice Shop `/profile` username SSTI confirms — todo (coordinator)
- Effectiveness (assessed 2026-10-14, offline; on-host pending): the targeted run (34 files: the BUG-0133 and PRG
  tests, the oracle/sender/session/forms/JSON/destructive suites, the request-count and
  golden tests, `test_oracle_vectors`, lint, traceability, loopback) is 1169 passed, 2
  xfailed (the existing BUG-0115 strict xfails), 0 skipped, with
  `FUZZLAB_REQUIRE_BROWSER/LINT/NETNS=1`. Live-boot tests carrying SSTI/SpEL/Go-template
  ground truth are unchanged: category 4 multitarget + `test_labgen_go_live_boot` +
  trackernest + category 5, 32 passed; SpEL live boot + SpEL + Netflix template preview +
  category 1 and 3 combined, 17 passed. Mutations: the old rule (`expr in text`) fails
  the 9 edit-form cases and the PRG edit form (BUG-0133 reproduced) and accepts Go's
  number-only-in-control page; any echo allowed fails 17 reflection cases; the number
  anywhere fails 5; a raw-only literal check fails Go's 3 escaped-echo cases; any option
  as a control fails the split test.
- Review (reviewers A and B agree; their nits, a further commit): A-N1 pins a number
  shown anyway beside the edit-form echo (a fixed number equal to probe 1's value under a
  seeded draw, and a dense-number page) for all four strategies: none confirms, the second
  sample decides; a variant of each strategy that skips its second sample fails them (16
  cases, all 4 mutations caught). B's nit: the split-number residual (`593<b>541</b>`)
  added to BUG-0133 and FR-FUZZ-4. A's PA-0106(1)/PA-0086 note for the restore is already
  in CC-FUZZ-0078's follow-up.

### CC-FUZZ-0078 — Post/redirect/get observation for the server-side confirmers (FR-FUZZ-49) (2026-10-14)
- Change: builds the reviewed design's Revision 2 (P1-P9; reviewers A and B agreed,
  coordinator-assigned number). Live evidence: Juice Shop answers `POST /profile
  username=#{11*13}` with `302 /profile` and no `143`; `GET /profile` shows `143`, and the
  confirmers read only the probe's own response.
  - `oracle/probe.py`: `Probe.followed` (a separate whole `Probe`), `Probe.prg`
    (`observed` / `unobserved` / `skipped: <reason>`), `Probe.url`,
    `Probe.follow_up_sends`; the trigger sets (`PRG_ANY_METHOD` 301/302/303,
    `PRG_GET_ONLY` 307/308); the `Sender.send` protocol gains `prg: bool = False` and
    `prg_capable`, with `accepts_prg`.
  - `tools/probesender.py`: `prg_target` (the one rule: trigger, `Location` resolved,
    same origin, `check_send_url`, `transaction_reason`, `account_endpoint_reason`,
    `redirect_is_logout`) and `PRG_RULES` (each emulated redirect rule with its Fetch /
    RFC 9110 step, PA-0111). `SeamProbeSender` follows on the probe's own route (the
    run's session, the path's isolated copy through the shared `_on_copy`, or
    anonymous) with its own gates (`_prg_session_gate`: auth endpoint, header breaker,
    isolated path from the main session) and dispatches through `_dispatch`, so the
    header breaker attributes what the follow-up observes to its probe.
    `RequestsProbeSender` follows anonymously (jar cleared). Neither follows on a timing
    send.
  - `oracle/oracle.py`: `_PrgRun` sets `prg=True` on every send of an opt-in strategy's
    run (P1); `Oracle.prg_counts`; P9's restore (`_restore`, `_restore_value`);
    `_CostCounter` and `_FormBoundSender` forward `prg` (no sibling binding into the
    follow-up) and delegate `prg_capable`; `_CostCounter` counts follow-ups.
  - `harness/auto.py`: `_CountingSender` (counts follow-ups in `requests`) and
    `_FragmentGuard` forward `prg` and delegate `prg_capable`. `harness/pipeline.py`
    reports the non-zero `prg_*` counters; `harness/auto_cli.py` prints them on one line
    when non-zero.
  - `oracle/strategies.py`: `ConfirmationStrategy.prg` (default False) and
    `_observed`; opted in: `SqliErrorStrategy` (controls observed alike, a rejected
    control refuses, `second_order`), `ReflectedXssStrategy` (P6: `xss-stored`,
    `observation: "prg"`), `SstiStrategy` and `SpelInjectionStrategy` (product / canary 1
    absent from follow-up 2), `GoTemplateSstiStrategy` (the M4b marker; read as
    observed), `PathTraversalStrategy` and `PathTraversalFsPathReadStrategy` (control
    observed alike).
- Impact (other components / project): the `Sender` seam's contract widens (a new
  optional argument, a capability declaration, new optional `Probe` fields); every
  implementation and wrapper in `fuzzlab/` is updated and the conformance guard checks
  the argument, its forwarding and the capability delegation. No other component's code
  changes: SESS's `is_auth_endpoint`, `observe` and `detect.redirect_is_logout`, AUD's
  nothing, CORE's `check_send_url` / `transaction_reason` / `canonical_origin` and
  `store_adapter.LADDER_TEXT` are used as they are. Runs against a PRG app send one more
  GET per PRG probe plus one restore per candidate (counted in `requests`, budgeted).
  Findings: a reflection seen only after a redirect is now recorded `xss-stored` (a new
  finding where none was before). No store, migration or ground-truth change.
- Risk (level; mitigation or accepted-risk justification): medium. New traffic: a GET
  to an app-supplied URL. Mitigated by gating it like a probe (same origin, every send
  gate, the probe's own route, never an isolated path from the run's session, one hop,
  never a timing send), each gate pinned by a test that counts what reached the app.
  New evidence channel: false positives from a page that always shows a signal or keeps
  an earlier value; mitigated by like-with-like controls (P1/P5), attribution, a noise
  guard over every opt-in strategy with a synthetic offender (PA-0117(3), PA-0129), and
  BUG-0127's HTML check on the same response (P4). Scoring: a run with no PRG redirect
  is unchanged (golden summary asserted with a PRG-capable sender); live scored
  multitarget runs (PA-0042/0047) are in the Effectiveness section. Accepted residuals
  are listed in FR-FUZZ-49.
- Deliverables:
  - [x] code as above — done
  - [x] tests: `tests/test_prg_observation.py` (Revision 2's list but the live Juice Shop
    check, which the coordinator runs on-host; the PA-0111 rule fixtures, the noise
    guard and its synthetic offenders); `tests/test_sender_conformance.py` (the `prg`
    argument, its forwarding, capability delegation, PRG placement, and each concrete
    sender's real follow-up path, PA-0035) — done
  - [x] mutation checks (P1, P3 route and isolated skip, P4 splice, P5 M2 control and
    M4 product 1, P6, P7 sender and opt-in) — done, each caught
  - [x] FR-FUZZ-49, NFR-FUZZ-safe clause and trace, NFR-FUZZ-response-fidelity note,
    ARCHITECTURE, CHANGELOG — done
  - [ ] on-host: `fuzzlab auto --identity juice-user` confirms the `/profile` username
    SSTI — todo (coordinator)
- Effectiveness (assessed 2026-10-14, offline; on-host pending): the targeted run (33
  files: the touched tests, the oracle/sender/session/forms/JSON/destructive suites, the
  request-count and golden tests, lint, traceability, loopback) is 1090 passed, 2 xfailed
  (the existing BUG-0115 strict xfails), 0 skipped, with `FUZZLAB_REQUIRE_BROWSER/LINT/
  NETNS=1`; `tests/test_prg_observation.py` alone 53 passed. The scored multitarget
  live-boot tests (PA-0042/0047; `RequestsProbeSender`, now PRG-capable) are unchanged:
  php_laravel booking + huddlehub 4 passed, node_bff + ruby_rails forgecart + category 1
  and 5 combined 6 passed, category 3 combined + spring_boot expedia + trackernest +
  category 4 7 passed. Each mutation in the deliverables is caught by at least one test.
  The live Juice Shop `/profile` SSTI check is the coordinator's.
- Follow-up (review of 991f0af; coordinator, reviewers A and B), a second commit:
  - P6 refined (coordinator): `xss-stored` only when the follow-up's URL carries neither
    the payload nor its token in any reflected form (`strategies._rode_the_redirect`);
    otherwise `xss-reflected`, `observation: "prg-redirect"`.
  - The P9 restore is total (B must-fix 1, A S1): a restore send that raises is
    contained, counted `prg_restore_failed`, logged with the host and error class only;
    the outcome is returned unchanged; an interrupt propagates. A containment boundary
    under PA-0086, reported, not a silent PA-0106 swallow.
  - B's nit: a direct `accepts_prg` assertion on the chains `run_auto` builds; A's N1:
    two restore residuals in FR-FUZZ-49.
  - Mutation checks: never / always "rode the redirect", raw-only and no-JSON encodings,
    restore not contained / interrupts contained / failure not counted: each caught.

### CC-FUZZ-0077 — Point selection judges a SPA route's fragment as a text (BUG-0131 sweep) (2026-10-14)
- Change: `harness/auto._crawl_url_refusal` (point selection, FR-FUZZ-40) judged a SPA
  hash route by re-joining its path and query into a URL:
  `destructive_reason(route[0] + "?" + route[1])`. A second `#` inside the fragment
  therefore hid what followed it (`/#/a#/logout`). It now runs `destructive_reason(url)`
  and, for a SPA-route fragment (`core.urls.is_spa_route_fragment`),
  `core.urls.text_destructive_reason(fragment)` over the whole fragment. A fragment's
  path and query give the same tokens as before, so only the hidden-text case changes.
  PA-0131's AST guard (`tests/test_forms_phase4.py`) loses its last listed exception
  (`_ALLOWED_EMBEDDINGS` is now empty). This was the one residual recorded in BUG-0131's
  sweep; the orchestrator assigned this number for it.
- Impact (other components / project): CORE (uses `text_destructive_reason`,
  CC-CORE-0052). Crawl-sourced `fuzzlab auto` and `greybox-run` leave out more points
  (those whose route hides a destructive word behind a second `#`) and report them as
  destructive. No interface or store change.
- Risk (level; mitigation or accepted-risk justification): low. The change only adds
  refusals, and for fragments without a second `#` it is equivalent to the old rule
  (`test_a_destructive_spa_route_is_never_a_point` and the rest of
  `tests/test_json_points.py` are unchanged and pass).
- Deliverables:
  - [x] code: `fuzzlab/harness/auto.py` — done
  - [x] tests: `tests/test_json_points.py::test_a_second_hash_in_a_spa_route_hides_nothing_from_point_selection`
    (three `#`-hidden routes refused, an ordinary route and a non-route `#top` not),
    `::test_a_destructive_route_behind_a_second_hash_is_never_a_point` (through
    `injection_points_from_store`); `tests/test_forms_phase4.py::test_no_text_is_judged_through_a_url`
    with no exception — done
  - [x] mutation check: restoring the re-join fails the four new test cases and the
    guard — done
  - [x] FR-FUZZ-40 text and NFR-FUZZ-safe trace; BUG-0131 follow-up; ERROR_LOG
    follow-up — done
- Effectiveness (assessed 2026-10-14): the `#`-hidden routes are refused, the guard
  passes with no exception, and the suite is green. Effective.

### CC-FUZZ-0076 — The M6 executor's storage headers go through its route only (FR-CRAWL-14 sweep) (2026-10-14)
- Change: `tools/browserexec.py` `PlaywrightBrowserExecutor.run` passes
  `storage_headers` to `guard_page(headers=...)` (added by the route to in-scope
  requests only) instead of `context.set_extra_http_headers` (CC-CRAWL-0022's PA-0002
  sweep). No caller sets `storage_headers` today.
- Impact: none on current runs; the headers can no longer reach an out-of-scope request.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: the header AST guard (`tests/test_browser_scope.py`); the M6 executor's
    fake-Playwright wiring test still passes — done
  - [x] NFR-FUZZ-safe traced — done
- Review: with CC-SESS-0021 / CC-CRAWL-0022 (reviewers A and B, Revision 2 item 6).
- Effectiveness (assessed 2026-10-14): verified offline against loopback fixtures, real Chromium (`FUZZLAB_REQUIRE_BROWSER=1`, `FUZZLAB_REQUIRE_LINT=1`): the targeted run (every touched test file, the session-manager tests, the browser-scope, SPA, sub-path, destructive-URL, lint, traceability and loopback-listener guards) gave 739 passed, 2 xfailed, 0 skipped, 1 failed -- `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`, which fails identically on the unmodified base 2150bf8 (`labgen/conformance/*_live_boot.py` `start_server` sites, outside this change; flagged, not fixed here).

### CC-FUZZ-0075 — The OOB listener serves each connection on its own thread (reviewer A, round 2 nit) (2026-10-14)
- Change: `oracle/oob.OobListener` uses `ThreadingHTTPServer` (daemon threads, never
  joined at close) instead of a one-connection-at-a-time `HTTPServer`. An idle or slow
  connection (a port probe, a keep-alive, a partial request) delayed every other
  callback by up to the handler's 5 s timeout (CC-FUZZ-0074), long enough to outlast a
  strategy's `wait_for` and miss a real callback (a false negative). `stop()` stays
  bounded; the handler timeout still ends idle threads; `record` was already locked.
- Impact: none on confirmation semantics (hits are still keyed by minted token).
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_oracle_oob.py::test_a_callback_is_recorded_while_another_connection_sits_idle`
    (fails on the single-threaded listener), `::test_stop_returns_while_a_connection_sits_idle`
    — done
- Review: reviewer A's round-2 nit; implemented rather than stated as a residual.
- Effectiveness (assessed 2026-10-14): verified offline.

### CC-FUZZ-0074 — Dialogs are never a browser-XSS hit (BUG-0129); OOB listener stop is bounded (BUG-0128 sweep) (2026-10-14)
- Change:
  - `tools/browserexec.py`: the dialog handler only dismisses. It recorded the probe's
    token for any dialog, so an app's own `alert` confirmed DOM / stored XSS (BUG-0129,
    reviewers A and B, round 2).
  - `oracle/oob.py`: the listener's request handler has a 5 s socket timeout. The
    listener serves one connection at a time, so an idle connection blocked the serve
    loop and `OobListener.stop()` forever (BUG-0128 sweep, reviewer A's S1).
- Impact: FR-FUZZ-48 amended (evidence is the tokened sentinel only). OOB callbacks
  are unchanged; only a connection idle for 5 s is dropped.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py::test_an_apps_own_dialog_is_never_a_hit`
    (real Chromium; fails on the old code) and
    `tests/test_oracle_oob.py::test_stop_returns_while_a_connection_sits_idle` (fails
    on the old code) — done
  - [x] BUG-0129, PA-0129, ERROR_LOG; BUG-0128 sweep widened — done
- Review: reviewers A and B, round 2 of the forms phase 3 review.
- Effectiveness (assessed 2026-10-14): verified offline on real Chromium.

### CC-FUZZ-0073 — Forms phase 3 review: browser mechanisms give no verdict when they observe nothing; executor robustness (reviewers A, B) (2026-10-14)
- Change:
  - `oracle/strategies.py`:
    - `_BrowserXssStrategy.confirm` raises `UnplaceableLocation` with no executor at
      **any** location (it returned None, a negative, except on fragment points);
    - `DomXssStrategy._observe` raises for a location it does not place, and
      `StoredXssStrategy._observe` for a candidate with no store URL (both returned
      `ExecObservation(False)`, a negative) (reviewer A, S1);
    - `_renders_as_html` also refuses `Content-Disposition: attachment` (reviewer B,
      nit 5; BUG-0127).
  - `tools/browserexec.py`:
    - the Playwright driver's start is inside the same containment as the launch
      (reviewer A, S2);
    - a launch failure is remembered only after `MAX_LAUNCH_FAILURES` (2) in a row
      (reviewer A, N2);
    - the sentinel is a context binding (`expose_binding`) recording into a
      per-probe set, so a hit before a navigation is kept (reviewer B, 3);
    - the wait pumps events and treats a page that went away as "not yet", never an
      error (reviewer A, S3);
    - the init script and `page.evaluate` polling are gone.
- Impact:
  - FR-FUZZ-48 and FR-FUZZ-39 amended in place.
  - `oracle_unplaceable` (inconclusive, `unplaceable`) **rises** in runs without a
    browser or without greybox sources, for xss and greybox-only categories. This is
    accounting, not a sender regression: such points were wrongly recorded as checked
    negatives before (reviewer B, 4; CC-FUZZ-0070).
  - Query points are still placed by M5, so their verdicts are unchanged.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests:
    - `tests/test_browser_scope.py::test_a_driver_that_cannot_start_is_no_verdict_too`,
      `::test_browser_xss_without_a_browser_is_no_verdict_at_any_location`,
      `::test_browser_xss_that_cannot_place_its_probe_is_no_verdict`,
      `::test_a_hit_before_the_page_navigates_is_kept` (real Chromium);
    - `::test_a_browser_that_cannot_start_is_no_verdict_never_a_crash_or_negative`
      (now two launches);
    - `tests/test_oracle_browser.py::test_dom_xss_noop_without_a_browser`,
      `::test_stored_xss_needs_store_endpoint` and
      `tests/test_forms_phase2.py::test_dom_xss_never_relocates_a_body_or_header_payload`
      now expect `UnplaceableLocation`;
    - an attachment case in `tests/test_oracle_xss_structural.py`;
    - fake contexts gain `expose_binding`
    — done
  - [x] mutation check: 4 of 5 killed (no-executor None, store-URL negative, driver
    unwrapped, no retry). **Survivor, stated:** a per-document hit record (hits cleared
    on `framenavigated`) still passes the navigation test, 10 of 10 runs, even with
    the page navigating the instant the payload runs. The navigation is routed through
    the Python guard, and that round trip lets the wait see the hit before the new
    document commits. The binding keeps hits across documents by construction; the test
    proves the reviewer A property (a navigation under the wait never raises and the
    verdict stands), not that a per-document record would lose a hit — done
- Review: reviewers A and B, review round of the forms phase 3 integration.
- Effectiveness (assessed 2026-10-14): verified offline on real Chromium.

### CC-FUZZ-0072 — Markup signals confirm only in a response rendered as HTML (BUG-0127) (2026-10-14)
- Change:
  - `oracle/strategies.py`: `_renders_as_html(probe)` (`text/html`,
    `application/xhtml+xml`, or no Content-Type). `ReflectedXssStrategy` (M5) confirms
    only when a break-out's structural check passes in such a response;
    `OpenRedirectStrategy` (M9) reads a meta refresh only in one (a `Location` header is
    unchanged).
  - Found live: Juice Shop's `/api/Challenges/?sort=` echoes the value in an
    `application/json` error; M5 confirmed `xss-reflected` there.
- Impact: FR-FUZZ-39 and FR-FUZZ-46 amended in place (the document-type precondition).
  Fewer confirmed findings on REST APIs (false positives removed); no lab sink changes
  (they are HTML). ML labels from such responses become negatives.
- Risk: low. Stated false negatives: script-capable `text/xml` and `image/svg+xml`
  responses (M6 decides them when a browser is attached).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_oracle_xss_structural.py::test_a_reflection_confirms_only_in_a_response_rendered_as_html`,
    `tests/test_open_redirect_seed.py::test_a_meta_refresh_in_a_non_html_response_never_confirms`
    (mutation check: 4 failures with the gates removed) — done
  - [x] BUG-0127, PA-0127, ERROR_LOG — done
- Review: with the forms phase 3 integration, reviewers A and B.
- Effectiveness (assessed 2026-10-14): the live re-run no longer reports the
  `/api/Challenges` finding; its other three findings and the DOM XSS stand.

### CC-FUZZ-0071 — The M6 browser executor runs on a real browser (BUG-0126) (2026-10-14)
- Change:
  - `tools/browserexec.py` `PlaywrightBrowserExecutor.run`: launches with
    `navguard.chromium_launch_kwargs` (the operator's `PLAYWRIGHT_CHROMIUM_EXECUTABLE`,
    scoped args); a launch failure is logged once, remembered for the run
    (`_unavailable`) and raised as `UnplaceableLocation`: no verdict from M6, never a
    crash or a negative. After `load` the sentinel is polled every 100 ms for up to
    `SETTLE_MS` (4000), ending on the hit, replacing a fixed 300 ms sleep.
  - Found live: `auto --browser` on Juice Shop aborted (`rc=1`) at the first browser
    check; with the binary given, the `#/search?q=` DOM XSS (rendered after an API
    call, about 1 s after `load`) was missed.
- Impact: FR-FUZZ-48 (new). `auto --browser` works on this host; DOM/stored XSS on
  asynchronously rendering pages is confirmed. A negative browser check costs up to 4 s
  per payload.
- Risk: low; the browser stays scoped (BUG-0123 unchanged).
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py::test_the_m6_executor_uses_the_configured_chromium`,
    `::test_a_browser_that_cannot_start_is_no_verdict_never_a_crash_or_negative`,
    `::test_the_m6_executor_sees_a_sink_that_fires_after_load` (real Chromium); fake
    pages in `test_browser_scope.py`, `test_destructive_urls.py`, `test_json_points.py`
    gained `wait_for_timeout` — done
  - [x] BUG-0126, PA-0126, ERROR_LOG — done
- Review: with the forms phase 3 integration, reviewers A and B.
- Effectiveness (assessed 2026-10-14): live Juice Shop re-run confirms `xss-dom` on
  `/#/search?q` (2.1 s).

### CC-FUZZ-0070 — Forms phase 3 integration: a mechanism that observes nothing never makes a point read as tested (2026-10-14)
- Change:
  - `oracle/strategies.py`: `GreyboxConfirmationStrategy.confirm` raises
    `UnplaceableLocation` (no verdict from this mechanism) when no coverage or DB-fault
    source is attached, or the sender cannot mint a correlation id; it returned None,
    which the oracle (lane J's placement accounting) counted as a placed, negative check.
    `_BrowserXssStrategy.confirm` (DOM and stored XSS) raises it for a `fragment` point
    when no browser is attached (only a browser can place one).
  - Found while merging: a browserless xss fragment point was recorded `checked` and
    rejected (a negative training label) instead of `inconclusive` (`unplaceable`).
    Before lane J the oracle had no placement accounting, so no shipped run is affected.
- Impact: FR-FUZZ-47 (a point no mechanism could observe stays unlabelled). Query and
  body points are unchanged: other mechanisms still place them.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_json_points.py::test_a_fragment_point_no_mechanism_can_place_is_inconclusive_never_a_negative`
    (now xss without a browser), `tests/test_oracle_greybox.py::test_noops_without_any_source`,
    `::test_noops_without_a_correlating_sender` (now expect `UnplaceableLocation`) — done
- Review: integration commit; to be confirmed by reviewers A and B with the merge.
- Effectiveness: verified offline.

### CC-FUZZ-0068 — JSON body points: senders, oracle binding, executor placement (forms phase 3, lane J) (2026-10-14)
- Change:
  - `tools/probesender.py`: `SeamProbeSender` and `RequestsProbeSender` get a `json`
    branch — the body rebuilt from the entries (`core.jsonbody.body_for`, types kept)
    with the leaf set to the payload as a string, `Content-Type: application/json`; a
    leaf that cannot be placed raises `UnplaceableLocation` before any session routing
    or send. Both pass `method` to `check_send_url` (a crawl-sourced DELETE is refused
    at send).
  - `oracle/oracle.py`: `_FormBoundSender` binds a `json` candidate's siblings
    (`jsonbody.normalize_entries` / `replace_leaf`; malformed → `UnplaceableLocation`).
    `Oracle.confirm_outcome` treats `UnplaceableLocation` from a strategy as no verdict
    from that mechanism (no reward or cost for its arm; the others still run); when
    every applicable mechanism refused, the candidate is `inconclusive` (mechanism
    `unplaceable`), never a negative.
  - `harness/auto.py`: `_FragmentGuard` wraps a crawl-sourced run's sender: an HTTP
    send at location `fragment` raises `UnplaceableLocation` (only M6 places a fragment
    point; the senders' unknown-location fallback stays pinned, BUG-0115 instance 4).
    Ground-truth runs are not wrapped. `run_auto` builds `fragment` crawl points only
    with a browser.
  - `greybox/run.py`: `RequestsCorrelatingSender` passes `method` to the send gate and
    raises `UnplaceableLocation` for `json` (it does not rebuild JSON bodies);
    `points_from_store` leaves JSON points out and reports them.
  - `tools/browserexec.py`: `_with_fragment` places a fragment payload inside an SPA
    hash route's query (`/#/search?q=<payload>`, `%20`-encoded), never after a second
    `#`; the M6 executor already refuses `json` (no verdict, before any browser).
  - `harness/auto_cli.py`: a "not placeable" summary block when a candidate had no
    mechanism that could place it.
- Impact: FR-FUZZ-47 (new); NFR-FUZZ-safe gains the JSON / DELETE clauses with their
  tests. Every sender's existing locations are unchanged (conformance re-run). The
  pinned unknown-location fallback is not changed for ground truth. AUD
  (CC-AUD-0035) imports the points; CORE (CC-CORE-0046) holds the convention.
- Risk: medium: probes now reach JSON APIs and complete real writes (stated in
  FR-FUZZ-47). Mitigation: PUT/PATCH opt-in, DELETE refused at import and at send,
  login bodies only on an isolated or anonymous session, siblings redacted and
  neutral.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_sender_conformance.py` (`json` registered for every concrete
    sender and `_FormBoundSender`, a nested leaf with typed siblings, synthetic
    offenders, greybox refusal, the executor's fragment placement) and
    `tests/test_json_points.py` (end-to-end JSON login SQLi on an isolated session and
    anonymously, sibling redaction, DELETE per sender, fragment never sent over HTTP,
    the oracle's refusal handling) — done
  - [x] FR-FUZZ-47, NFR-FUZZ-safe trace lines — done
- Review: phase 3 design (`p3-spa-draft.md`, revisions 1–4), agreed by reviewers A and
  B; implementation review by the orchestrator pending.
- Effectiveness: verified offline, 2026-10-14. `tests/test_json_points.py` 90 passed;
  `tests/test_sender_conformance.py` 16 passed, 2 xfailed (the pinned BUG-0115
  instance 4); the lane's focused set (19 files, `FUZZLAB_REQUIRE_LINT=1`) 707 passed,
  2 xfailed. Mutation check of the safety gates (import refusals, password isolation,
  pinning, redaction, the DELETE send gate per sender, `json` placement, sibling
  binding and neutrality, the fragment guard, greybox, the oracle's refusal handling,
  the parser, the name rule): 34 of 35 mutants killed; the survivor (the point
  builder's per-key credential check reduced to the display name) is equivalent —
  `name_tokens` already splits the display name at every key boundary, and production
  never writes a `json` parameter with a credential key. The live Juice Shop `fuzzlab
  auto` run (expected: `/rest/user/login` `email` SQLi) is the remaining check.
- Review follow-up (2026-10-14; reviewer A's J2–J4 and reviewer B's items 1–4, both
  AGREE with should-fixes; second commit on `p3-lane-j`):
  - **J2 — two meanings of `inconclusive`:** "could not be decided: a cost cap stopped
    a started check, or no mechanism could place the point". The pipeline records the
    undecided mechanism per key, writes `oracle_inconclusive_<mechanism>` row counts
    and carries an unplaceable item's `reason`. `fuzzlab auto` prints the reworded
    header, then each item with its mechanism: `unplaceable (no mechanism could place
    the point: <reason>)`, or the capped mechanism with its families not started. The
    web run page (`web/results.inconclusive_by`, `templates/run.html`) names each
    mechanism with its count.
  - **B2:** `metrics["oracle_unplaceable"]`, the unplaceable subset of
    `oracle_inconclusive`; `fuzzlab auto` prints it only when non-zero (goldens
    unchanged).
  - **J3:** `_FragmentGuard` is in the breaker-passthrough test and the conformance
    wrapper scan; the pipeline's `_header_stop_reason` is pinned to read through it.
  - **J4:** `oracle.finding_url` writes a `fragment` finding at `core.urls.
    to_route_path` (its endpoint's function, PA-0003), so one parameter on two routes
    gives two findings; every other finding is still at `to_path` (identical for a URL
    without a hash route, so ground truth is unchanged).
  - **B3:** an AST guard: no handler catching `ValueError` or broader (or
    `UnplaceableLocation`) encloses a send in `oracle/strategies.py`; proven on synthetic
    offenders (PA-0034(2)).
  - **B4:** a JSON leaf absent from a captured body is refused (`replace_leaf` raises,
    `UnplaceableLocation` at the sender), never appended; with no entries the leaf is
    the whole body.
  - **UI:** `fuzzlab/web/results.py` and `templates/run.html` belong to component 12;
    no CC-UI number was pre-assigned for this round, so the change is recorded here and
    FR-UI-19 is updated in place. **Flagged:** assign a CC-UI entry at merge (PA-0031:
    not improvised).
  - **Effectiveness (2026-10-14):** `tests/test_json_points.py` 99 passed; the
    targeted set (24 files incl. it, `FUZZLAB_REQUIRE_LINT=1`) 827 passed, 2 xfailed;
    `FUZZLAB_REQUIRE_BROWSER=1` `tests/test_web_ml_context.py` 15 passed and
    `tests/test_web_pages_browser.py` 8 passed. Mutation check: all 12 mutants of this
    round's gates killed; 46 of 47 over both rounds (the same equivalent survivor).

### CC-FUZZ-0067 — Open-redirect confirmation passes containment allowlists; host-based (BUG-0124) (2026-10-14)
- Change:
  - `oracle/strategies.py` `OpenRedirectStrategy`: `_lands_on` (urljoin + urlsplit:
    http/https, our token host, path `/cb`) replaces the prefix test on both probes;
    `confirm` sends the plain canary, then, only if it did not land and
    `candidate.redirect_seed` is set, `https://oracle<tok2>.example/cb?fzlb=<seed>`;
    the verdict records `variant: allowlist-containment` and the probe.
  - `oracle/probe.py` `Candidate.redirect_seed`; `harness/pipeline._candidate_of`
    carries it from evidence.
- Impact: FR-FUZZ-46 (new). Juice Shop's `/redirect?to=` becomes confirmable. +1
  request per seeded open-redirect candidate whose plain probe failed.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_open_redirect_seed.py` (unconditional, containment and
    exact-match apps; host-not-prefix cases including scheme-relative, downgraded,
    `javascript:`/`data:`; meta refresh) — done
  - [x] FR-FUZZ-46 — done
- Review: with CC-AUD-0034.
- Effectiveness: verified offline; the live Juice Shop run is the check.

### CC-FUZZ-0066 — The M6 browser executor is confined to its observe and store origins (BUG-0123) (2026-10-14)
- Change:
  - `tools/browserexec.py` `PlaywrightBrowserExecutor.run`: the scope is
    `origin_scope(request.url, store.url)`. Chromium is launched with
    `browser_launch_args` of those URLs, the context is guarded with `in_scope`
    (redirect chains walked, WebSockets routed), and a body-located stored plant calls
    `checked_api_request` and posts with `max_redirects=0` (it followed redirects).
    `release(context)` before close.
- Impact: NFR-FUZZ-safe: the browser part of "no traffic off localhost" is enforced
  (the senders' part stays as recorded). A DOM-XSS sink that loads a cross-origin
  script cannot fire.
- Risk: low; the executor runs on-host only.
- Deliverables:
  - [x] code — done
  - [x] tests: `tests/test_browser_scope.py::test_the_m6_browser_is_launched_scoped_and_plants_without_redirects`,
    the AST guard — done
  - [x] NFR-FUZZ-safe — done
- Review: with CC-CRAWL-0015.
- Effectiveness: verified offline with a fake Playwright; the on-host `--browser` run is
  the live check.

### CC-FUZZ-0063 — Link siblings, header points with a session breaker, POST selectors, neutral host values; BUG-0115 (forms phase 2, lane A) (2026-10-14)
- Change:
  - **Link siblings (`store_adapter`):** every query-bearing crawled URL's query becomes
    a `form` row with `enctype` NULL (`_import_link_sets`, after forms, so forms win;
    the first crawled link wins, `ORDER BY rowid`). Values pass `redact_sibling`
    (sensitive name or identifier-like raw value → `""`; raw value from
    `query_pairs`, percent-decoded only). `entries_refusal` (one check for forms and
    link sets) refuses a set with a destructive or credential entry. Sets with two or
    more names are bound; one-name sets only give header points their query.
  - **POST selectors (`form_skip_reason`):** fuzzed unless a control name is a
    `formnav.settings_word`, the select name is shorter than 3, or the crawler's
    verdict is `settings`; GET selectors unaffected. `_import_forms` fuzzes a POST
    picker repeated at several actions once. `enctype` read NULL-safe.
  - **Points (`harness/auto`):** crawl points carry `origin="crawl"`, their example's
    `value_shapes` (inherited by name when the example is empty or a filler, one pass)
    and `base_value=127.0.0.1` for ip/host shapes; siblings are sent through
    `_send_value` (loopback for ip/host/url defaults, fillers as they are).
    Ground-truth points carry `origin="ground-truth"`.
  - **Header points:** `header_points_from_store` (2xx GET pages, representative query
    from `core.forms.first_link_set` only, destructive pages skipped and reported,
    appended last); `run_auto(header_names=)`; `plan_run(header_points=)` refuses them
    with ground-truth points; `fuzzlab auto --header-points [NAMES]` (off by default),
    names checked before the store opens, and with an identity the lower-bound cost
    (`header_point_cost`, derived from the strategies) is refused over `budget_total`.
  - **Header breaker (`SeamProbeSender`):** registers `add_logout_listener` on its main
    manager; a logout seen on a header probe's response, or on the first main send
    after one, sets `header_stop_reason` unless `isolated_copy_logins()` (lane B; read
    with `getattr(self, "isolated_copy_logins", lambda: 0)()` until lane B merges)
    rose since; later header sends raise `HeaderPointsStopped` before the gate. The
    pipeline leaves the remaining header keys `pending`, subtracts them from checked
    keys, and reports `metrics["header_breaker"]` and `skipped_points`.
  - **Senders:** `check_send_header` in the Seam, Requests and greybox header branches.
  - **Strategies:** the command-injection timing and OOB strategies start from
    `Candidate.base_value` (baselines and a payload prefix) when set (CC-AUD-0032 refers
    here); `SqliBooleanStrategy.probes` named for the cost estimate.
  - **BUG-0115:** greybox `send_correlated` places header probes in headers and refuses
    any other unplaceable location (`UnplaceableLocation`); `DomXssStrategy` applies only
    to query/fragment points and never relocates; the browser executor refuses an
    unplaceable observe or store location before starting a browser. The probe senders'
    unknown-location fallback is pinned by a strict xfail (not fixed).
  - **Follow-up (code review of 97fe402, reviewers A and B):**
    - header-point URLs are tested to carry loopback for host/url link values (their
      neutralisation was untested); identifier-like values there are **blanked**, as
      agreed in deviation 1 (v2 had said "dropped");
    - a breaker trip with no later header probe is still reported
      (`pipeline._header_stop_reason` reads it through the wrappers);
    - `invalid_plugin_rules` reaches `metrics`, `run_metrics` and the summary;
    - the fingerprint probe goes through the first query (else form-body) point with
      its method and siblings, never a header point (BUG-0115 instance 6; clears
      deviation 3);
    - `_on_logout` trips only for the run's target host (the operator's base URL's).
  - **Supersedes** CC-FUZZ-0062's binding where FR-FUZZ-42's "Siblings" clause was
    amended (link queries; neutral host values; blank identifiers) and its "never a POST
    selector" rule.
- Impact:
  - **Behaviour:** crawl-sourced runs bind link siblings, fuzz POST pickers, and (opt-in)
    probe request headers; hostname-shaped form defaults are now sent as `127.0.0.1`.
    Ground-truth runs gain no candidate (tested per real contract); their evaluation
    rows grow by the four new rules (`R-SQLI-HEADER`/`R-XSS-HEADER` within sqli/xss
    plans): the four `tests/data/auto_summary/*` goldens' "negatives" were re-derived,
    not regenerated (PA-0073(3)): 41→87 and 2→48, i.e. +2 rules × 23 points. These
    are origin-gated rules that cannot apply to ground-truth points; they are rule
    negatives in `evaluation`, not training rows.
  - **Changed existing tests** (requirement changes, not silent edits): the POST-picker
    case of `test_unsafe_forms_are_never_imported` now expects a settings-named picker
    (FR-FUZZ-42 superseded); `test_evaluate_category_filter_scopes_rules` derives its
    sqli rule count from the rule set (PA-0001); the two ground-truth header-location
    sender tests now mark their URL explicit, as `run_auto` does.
  - **ML:** `rules_fired` drifts on crawl runs (CC-ML-0027).
  - **Residuals:** header-logging pages grow the lab DB per probe; state-changing
    plain visits repeat per header probe; a site-wide picker is probed at one action;
    an identifier-like sibling is sent blank (a gate needing it does not confirm); an
    e-mail default is sent as is (may trigger mail); the web page shows breaker stops as
    "pending" without the reason (lane C rewords that text).
- Risk: medium (more traffic and real submissions), within the gates above; header
  points are opt-in and budget-checked.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_forms_phase2.py`, 260 passed + 1 skipped joint test until
    lane B merges; `tests/test_sender_conformance.py`, 9 passed + 2 strict xfail) — done
  - [x] FR-FUZZ-43; FR-FUZZ-42 amended in place; NFR-FUZZ-safe `Enforced by:` — done
  - [x] BUG-0115 / PA-0115 / ERROR_LOG — done
- Review: reviewers A and B, draft v1–v3 (scratchpad `p2-a-draft.md`), with two agreed
  deviations (`.invalid` filler exempt from neutral values; header representative
  queries from link-set rows only).
- Merge with lanes B and C (orchestrator; reviewers A and B, code review):
  - **Target row:** a run with points but no query/body point still writes its one
    `target` row (origin only, NULL fingerprint, no probe). ML's same-target key and
    holdout sealing need it: otherwise a sealed target's header-only run leaked into
    training (reviewer B, PA-0092; reviewer A, L2).
  - **`SeamProbeSender`:**
    - lane A's `_target_host` became `_header_target_host`, because lane B has its
      own;
    - the copy-login count is a direct `isolated_copy_logins()` call;
    - the `HeaderPointsStopped` gate and `check_send_header` run before lane B's
      isolated routing;
    - the main-send bookkeeping uses the identity actually sent.
  - **Joint tests:** `tests/test_forms_phase2_joint.py` (5) runs on lane B's real copy
    logins:
    - a copy login logs main out → lane B's breaker, not the header breaker;
    - a UA-bound session with a live copy → both breakers trip, once;
    - a header probe to an isolated path rides its copy;
    - a stopped or refused header never causes a copy login.

    A mutation check over the joints killed 5/5.
- Effectiveness: verified offline (the tests above; mutation check 40/40 killed over
  the new logic at 97fe402, 52/52 after the review follow-up, whose dead `url` branch
  in `neutral_value` was removed when its mutant proved equivalent). Live bWAPP verification (`[design]`, PA-0015): crawl from
  `portal.php` with `--follow-selector-forms bug`, then `auto --points crawl --identity
  … --header-points User-Agent,Referer,bWAPP` with `budget_total` raised; expected new
  confirmations: gap-map rows #5, #12, #13, #18, #19, #23, #28, #37, #43, #44, #48.
- Live bWAPP (orchestrator, 2026-10-14; integrated phase 2 tree):
  - **Setup:** crawl from `portal.php` with `--follow-selector-forms bug` (159 pages,
    3 destructive URLs skipped), then `auto --points crawl --identity user
    --header-points` with `budget_total=30000`. The default 5000 is refused up front:
    "143 page(s) x 2 header(s) need at least 6292 requests".
  - **First run, before BUG-0122:** 47 findings. Header coverage was cut short by
    BUG-0122, a false breaker trip on `ba_insecure_login.php`'s redirect.
  - **After BUG-0122:** 50 findings, none lost, 8236 requests, and no header-breaker
    trip. These are new against phase 1:
    - SQLi through User-Agent on `sqli_17`;
    - XSS through User-Agent on `xss_user_agent` and `xss_stored_4`, and through
      Referer on `xss_referer`;
    - `commandi` and `commandi_blind` (loopback base);
    - the `sqli_13` POST picker (SQLi and XSS);
    - `rlfi`;
    - three `iframei` parameters.

### CC-FUZZ-0065 — String-context SQLi confirmation; probes must cause their evidence (BUG-0117) (2026-10-14)
- Change:
  - **One engine** (`ConfirmationStrategy._differential`, FR-FUZZ-45 (a)):
    - B0, then a screen (V and D in a drawn order), then 6 rounds of (V, D, B) in a
      drawn permutation, with fresh tokens each round;
    - one draw per round from fixed tables; each round is judged once all of it is
      sent;
    - confirms only if every V and B equals B0, every D differs, and every D equals
      the first D;
    - P[confirm] ≤ 1/1458 per family for any probe-independent response sequence and
      any predicate.
  - **`SqliBooleanStrategy` runs three families on that engine** (numeric, unchanged
    probes; string-grammar `v' AND 't' LIKE 't` / `… LIKE t'`; string-evaluation
    `1' AND 't' LIKE 't` / `1' AND 'u' LIKE 't`):
    - the exact families compare status plus the body with every sent value's
      reflections stripped;
    - `HARD_CAP` is 30 and a family starts only with 21 left;
    - an exhausted cap returns an **inconclusive** verdict;
    - string families are skipped on raw whole-body points;
    - `HY000`/`SQLSTATE[…]` appear only as corroboration.
  - **New `SqliEvaluationMarkerStrategy`** (`0'+(SELECT a*b)+'0`, FR-FUZZ-45 (c)): two
    products, each digit-bounded in the response to the probe that computed it, with
    the literal absent. Arm `sqli:evaluation-marker`, registered between Boolean and
    Timing.
  - **BUG-0117 fixes:**
    - `SqliErrorStrategy` confirms a signature only when it is absent from the controls
      `fz…` (and `1fz…` for a digit-led probe);
    - `PathTraversalStrategy` sends a `passwd` control;
    - `SstiStrategy` and `SpelInjectionStrategy` need a second, cross-checked sample.
  - **`Verdict.inconclusive` and `Oracle.confirm_outcome`:**
    - `confirm()` is a thin wrapper, so greybox and other callers are unchanged;
    - the pipeline writes `inconclusive` (CC-CORE-0043) for every row of such a key,
      excludes it from `oracle_rejected`, counts `oracle_inconclusive`, and lists the
      key (no values) in `PipelineResult.inconclusive`;
    - `fuzzlab auto` prints that list only when it is non-empty.
- Impact:
  - **Behaviour:**
    - more requests per sqli candidate: 9 + 1 when the screens fail (was 3);
    - at most SqliError 6, Boolean 30, C 2;
    - under the scheduler, an inconclusive arm gets reward 0 and its real cost.
  - **Goldens** (`tests/data/auto_summary`), re-derived per strategy (PA-0073(3)).
    tp/fp/fn/tn and findings are unchanged:
    - `score_only` / `budget_fallback_nolabels`: requests 306 → 448
      (requests/finding 102.0 → 149.333). Boolean 60 → 180 (20 candidates, 3 → 9),
      C +20, SqliError +2 (the controls of the 2 confirmations).
    - `run` / `earlier`: 29 → 43 (2 budget-checked sqli keys × 7).
  - **Residuals:**
    - value contexts write coerced values to the baseline's own row: about 11 rows on
      sqli_12, at most 38 from these strategies. Reset the lab between benchmark runs;
    - pages that change on every request give false negatives;
    - inconclusive keys are no longer training negatives (CC-ML-0028);
    - the string families' MySQL semantics are unproven on host.
- Risk: medium (more traffic; live MySQL unproven). Mitigations: the AND-only closed
  templates test, the noise guard, the cost tests, and the secure twins.
- Deliverables:
  - [x] code — done
  - [x] tests:
    - `tests/test_oracle_sqli_string.py` (58): TP and secure twin per shape on
      in-memory sqlite3 (bWAPP sqli_11/14/12, sqli_4 text, lab LIKE/login, a
      code lookup);
    - FP classes: escaping, a quote validator, reflection, shell, XPath, hash, a growing
      guestbook, 429;
    - the exact bound by DFS over the engine's draws;
    - noise discovery with offender proofs;
    - closed templates and the sqlite compile check;
    - cost and cap, `inconclusive` end to end, the sqli_12 form, and `%2B` on the
      wire;
    - `tests/test_auto_plugins.py`: the drawn-order determinism guard;
    - existing fakes and patches, adjusted:
      - `tests/test_scheduler_backoff.py`'s fake showed the SQL signature on every
        request, the very false-positive class BUG-0117 refuses. It now errors on a
        quote only;
      - `tests/test_auto_budget.py` and `tests/test_pipeline_invariants.py` patch
        `Oracle.confirm_outcome`, which the pipeline now calls;
      - `tests/test_web_ml_context.py` seeds and expects `inconclusive` rows
        (CC-UI-0052);
      - `tests/test_oracle_scheduler.py` derives its SQLi arms from the registry
        (PA-0001).
  - [x] mutation check: 22/22 killed (engine checks, draws, cap, inconclusive path,
        controls, stripping, status, C's literal/second-sample checks, the sweep
        fixes, the pipeline status and rejected count, the web count). The first run
        left 7 survivors, which gained the tests "reflecting page confirms",
        "status-only differential", "drifting baseline", "D responses agree",
        "corroboration filter" and "cache / literal-once" — done
  - [x] FR-FUZZ-45; NFR-FUZZ-safe `Enforced by` line — done
  - [x] BUG-0117 / PA-0117 / ERROR_LOG — done
- Review:
  - **Design gate:** reviewers A and B, lane C draft v1 → v2 → v3 (AGREED).
  - **Cap exhaustion:** a new `inconclusive` status (B required it; A agreed).
  - **Implementation:** by the orchestrator. The lane agent stopped before writing code.
  - **Deviations:** C is skipped on raw whole-body points, like the string families.
    The redraw of C's second product is bounded (32 tries).
- Merge with lanes A and B (orchestrator; reviewers A and B, code review):
  - **SSTI and SpEL:** the second value must be absent from response 1 (with a redraw,
    like C). Response 2 may still show product 1, so a stored listing of results
    confirms; a cached page does not. The old "neither shows the other" clause
    rejected a genuine stored SSTI (reviewer B).
  - **CLI:** the `fuzzlab auto` inconclusive line is now asserted (reviewer A, C1).
  - **Lane A's `header_point_cost`:** reads the families' screens
    (`3 × len(_FAMILIES)`) and C's probe, instead of the removed
    `SqliBooleanStrategy.probes`.
- Effectiveness: effective in tests (counts above). Live pending: the bWAPP sandbox
  check of sqli_4/11/12/14, and the PFF scored run (a possible +1 tp on
  `/login.php [username]`, fp=0 expected).
- Live bWAPP (orchestrator, 2026-10-14):
  - **SQLite, new findings:**
    - `sqli_11 [title]` and `sqli_14 [title]`, by string-grammar boolean;
    - `sqli_12 [entry]` by the evaluation marker, with no `entry_delete` sent.
  - **`oracle_inconclusive`:** 0 in both runs.
  - **`sqli_4` (MySQL, masked blind):** not confirmed. Still pending the on-host
    MySQL proof, as recorded.

### CC-FUZZ-0064 — In-app login forms probed on an isolated session (forms phase 2, lane B) (2026-10-14)
- Merge note: CC numbers land out of numeric order here (0064 above 0062; lane A's 0063
  lands above 0064). That is intended: "newest first" means landing order.
- Change:
  - **Import (`store_adapter.form_skip_reason`):** the blanket "has a password control"
    skip is replaced.
    - **Credential-change forms stay excluded** (`credential_change_reason`): two or
      more password controls; a password control's name containing `new`, `conf`,
      `change`, `reset`, `old`, `curr`, `repeat`, `retype`, `verify` or `again`; the
      action path, the sent submitter or a hidden name tokenising to `change`, `new`,
      `set`, `reset`, `update`, `edit`, `modify`, `register`, `signup`, `create`,
      `forgot`, `recover`, `activate`, `password`, `passwd`, `pwd`, `pass`, `save`,
      `admin`, `manage`, `account`, `profile` or `users`; or a hidden object selector.
    - **Password forms that are not login forms stay excluded** (`login_shaped`: one
      password control, one text/email/tel field, nothing else typed).
    - **A login-shaped form is imported.** `password_fields` is written; a password
      control is never a parameter, whatever its name; its sibling is sent `""`.
  - **Marking (`harness.auto`):** `isolated_paths_from_store` (the one derivation): the
    `url_key` of every path with such a form, for any method and point source.
    `injection_points_from_store(..., isolated=None)` drops such points and reports
    them unless the caller passes a set; a parameter named like a password control on
    that path is never a point.
  - **Run wiring (`run_auto`, `fuzzlab auto`):** registers the paths with
    `sender.isolate`, or drops the points when the sender cannot isolate;
    `metrics["isolated_sessions"]` and one summary line.
  - **Sender (`SeamProbeSender`):** after the destructive gate and the auth-endpoint rule
    (which wins), a send to an isolated path goes on that path's own copy
    (`SessionManager.isolated_copy`, CC-SESS-0018), created lazily and kept for the run,
    labelled `<identity>#isolated:<n>` in `flow`; or anonymously.
    - **Fallbacks, reported:** no factory, a failed or non-distinct login, a copy
      re-login failure, the cap (`MAX_ISOLATED_SESSIONS` = 32), or a tripped breaker.
      Caught: `IsolatedLoginFailed` only; a transport refusal propagates.
    - **Breakers:** *single-session*, when `verify_live` fails after the run's first
      copy login or any copy re-login, or when the main manager's logout listener fires
      while a copy is live (registered before the first copy login, once, host- and
      identity-checked); copies are dropped and every isolated path goes anonymous.
      *Failed-logins*, after 2 failed copy logins: no new copies.
    - **Locking:** a plain `Lock`, never held across a send, login or verification; the
      listener takes it only briefly.
    - **Reasons** in `isolation_report()` and the CLI are fixed texts
      (`IsolatedLoginFailed.reason`, the breaker and cap reasons), never a failure
      message: a token-bearing URL in a login error never reaches the report or log.
    - **Public:** `isolate`, `isolated_copy_logins()` (lane A reads it),
      `isolation_report()`.
  - **`make_probe_sender`** wires an isolated-client factory sharing only the run's
    `RequestBudget` and scope (`authhttp.make_auth_with_isolation`).
  - **`RequestsProbeSender`:** isolated by construction; `isolate` only counts.
- Impact:
  - **Behaviour:** crawl-sourced `auto` runs now probe in-app login forms. Each costs one
    extra login per path plus one main verification after the first copy login.
  - **greybox-run** never receives these points (dropped and reported by default).
  - **`fuzz --identity` / `mutate-run --identity`:** a stated residual (operator's own
    `--url`); see NFR-FUZZ-safe.
  - **Accepted false positives** (excluded login forms, missed findings only): Rails
    `/sessions/new`, Devise `/users/sign_in`, `/admin/login`, `/account/login`, a "Save"
    login button, and bWAPP's `ba_weak_pwd.php` and `ba_pwd_attacks_2.php` (`pwd` in
    the action path; no current oracle confirms their bugs).
- Risk: medium (login-form submissions; more logins), within the caps, breakers and
  fallbacks above.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_login_form_isolation.py`, 71; `tests/test_forms_phase1.py`'s
        "password" skip case replaced by a credential-change case) — done
  - [x] code-review follow-up (reviewers A/B): a failed copy re-login falls back with
        no session at all (test); `verify_live` carries the session to the session's
        host only (CC-SESS-0018; test); a login cap never counts toward the
        failed-logins breaker, at creation or re-login (tests); an unapproved hop while
        verifying trips the breaker (test); fixed reason texts (test) — done
  - [x] FR-FUZZ-44; FR-FUZZ-42 edited in place; NFR-FUZZ-safe clause — done
- Review: reviewers A and B, lane B draft v1 → v2 → v2.1 → v2.2 → v2.3 (AGREED, both).
- Effectiveness: verified offline; live bWAPP pending (orchestrator).
  - **New tests vs the pre-change code (65d3cba):** measured by checking out 65d3cba's
    `fuzzlab/` (`git checkout 65d3cba -- fuzzlab`, restored afterwards) and running a
    copy of the test module whose imports of the new names are shimmed
    (`scratchpad/p2b-tools/base_shim_test.py`), so each test runs and fails on its own
    rather than at collection. Of the 71 tests, 70 fail there; the one that passes is
    `test_control_the_fake_app_rebinds_a_session_that_sends_the_injection`, the fake
    app's non-vacuity control, which passes by design. Against the first lane B commit
    (4c4f18c), the code-review tests that pin new behaviour fail (5).
  - **Mutation check** over the new logic: 40/40 killed (32 at the first commit, plus
    8 from the code review, including reviewer B's fallback-identity mutant).
- Live bWAPP (orchestrator, 2026-10-14):
  - **Isolation:** 6 login-form paths were probed on 6 isolated logins (381 isolated
    sends, 0 anonymous), and the run's session survived.
  - **New findings:** SQLi on `sqli_3 [login]`, `sqli_16 [login]` and
    `xss_login [login]`.
  - **Not imported:** `ba_weak_pwd` and `ba_pwd_attacks_2`, as accepted.

### CC-FUZZ-0062 — Forms as injection points, probed with their sibling fields (forms phase 1) (2026-10-13)
- Change:
  - **`store_adapter.import_spider`:**
    - imports forms: endpoint (a POST keeps its action query, a GET drops it), a `form`
      row and fuzzable parameters;
    - never fuzzed: the submitter, sensitive names, and hidden object selectors
      (`login`, `user`, `*_id`), which stay pinned to their defaults;
    - whole forms skipped: multipart, POST selector, any password control,
      destructive action/entries/submitter/checked box;
    - empty free-text siblings are filled as a user would type them. Never-resolving
      `.invalid` URL and e-mail fillers;
    - blank query values are kept.
  - **`injection_points_from_store`:**
    - loads `base_entries`;
    - drops credential-named parameters (`password`, `passwd`, `pwd`, `pass`,
      `secret`) from crawl and form sources. Ground truth is unaffected.
  - **`Candidate.base_entries`; `Oracle.confirm`'s `_FormBoundSender`:** the one
    binding. It matches url_key, method and location.
  - **Senders:** every probe sender and wrapper accepts `entries=`, guarded by an AST
    test.
- Impact:
  - **Behaviour:** crawl-sourced runs now probe forms. Form probes complete real
    submissions.
  - **Residuals:** rows or mail created by probes; one confirmation per
    (url, param, method, location); CSRF-token forms do not confirm; fillers ignore
    `maxlength` / `pattern`.
- Risk: medium (more traffic, completed submissions), within the gates above and the
  budget.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_forms_phase1.py`, 40) — done
  - [x] FR-FUZZ-42 — done
- Review: as CC-CORE-0039.
- Effectiveness: live. bWAPP from `portal.php` with no seeds: 32 confirmed findings on
  25 pages (9 before).

### CC-FUZZ-0061 — Crawl points join to the origin; `fuzz` logs in from `--url` (BUG-0113) (2026-10-13)
- Change:
  - `injection_points_from_store` joins stored absolute paths to `base_url`'s
    **origin**, so `--base-url .../bWAPP/` no longer gives `/bWAPP/bWAPP/`;
  - `fuzz --identity` calls `make_auth` and
    `ensure(host, identity, --url, operator=True)` before the baseline;
  - `SeamProbeSender`'s pre-login passes `operator=True`.
- Impact:
  - **Behaviour:** `auto` / `greybox-run` crawl points are correct for any base path
    (an origin base behaves as before);
  - ground-truth points are unchanged (app-relative by contract).
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests — done
  - [x] FR-FUZZ-41 — done
- Review: as CC-SESS-0016.
- Effectiveness: verified by test, and live in the operator's bWAPP run.

### CC-FUZZ-0060 — NFR-FUZZ-safe: send-time destructive gate, auth endpoints probed anonymously, no cookie carry-over (BUG-0112) (2026-10-13)
- Change:
  - **Send gate:** `check_send_url` is called first in `SeamProbeSender`,
    `RequestsProbeSender`, greybox's `RequestsCorrelatingSender`, and the blind-SQLi
    `RequestsSender` / `SeamSender`. Each has `allow_explicit(urls)`:
    - `run_auto` and `greybox-run` pass ground-truth point and store URLs;
    - `fuzz` passes its `--url`.
  - **Point selection:** `injection_points_from_store(..., skipped=)` leaves out
    destructive crawl points and reports them; `auto` prints them.
  - **Auth endpoints:** `SeamProbeSender` logs in once, then probes auth endpoints
    anonymously (counted in `auth_endpoint_anonymous_sends`). `make_probe_sender`
    builds it with `make_auth`. Greybox drops its cookie for auth endpoints
    (`_cookie_for` returns `is_auth_endpoint`).
  - **Cookie jars:** the requests senders clear theirs per probe.
  - **M6:** `browserexec` guards its context, with the observe and store URLs
    allowed.
  - **Tests:** a new AST guard.
- Impact:
  - **Behaviour change:** crawl runs skip destructive points; authenticated probes of
    login endpoints carry no session; ground truth is unchanged;
  - **SESS:** `is_auth_endpoint` now has callers;
  - **Test doubles:** `test_auditor_seam`'s fake `get` accepts `allow_redirects`.
  - **Behaviour change: cookie jars.** Unauthenticated probes no longer carry cookies
    set by earlier responses. A target that needs a first-visit cookie (a
    session-bound page, an anti-bot or consent cookie) now sees a fresh visitor on
    every probe. That is the intent: a payload that logs in can no longer make later
    "anonymous" probes authenticated. An on-host change in results may trace to this.
  - **Late login failure:** a `SessionAuthError` from the first-probe login surfaces
    inside the run and takes the existing aborted-run path (`mark_aborted`, BUG-0078;
    `tests/test_auto_cli_side_effects.py::test_a_failure_after_the_run_starts_marks_it_aborted`).
- Risk: medium. The send path of every sender changed. All of it is covered: the
  sender, run_auto, greybox and blind-SQLi suites pass, and the mutation check killed
  31/31. The destructive-payload gate on auto/fuzz was deliberately **not** added: it
  could refuse oracle payloads in on-host benchmarks that cannot be verified here. It
  is recorded as "Not yet enforced".
- Deliverables:
  - [x] senders, run_auto, greybox, blind-SQLi, M6 — done
  - [x] tests (`tests/test_destructive_urls.py`) — done
  - [x] FR-FUZZ-40 and traceability — done
- Review: reviewers A and B, draft v1 (changes required) → v2 (AGREED, both) →
  implementation AGREED by both. Their implementation nits were adopted:
  service-worker blocking, a WebSocket gap note, the jar-clearing impact line, and the
  late-login-failure path.
  - **Adopted:** B3 (send-time gate), B4 and A4 (anonymous auth sends), B S1
    (greybox cookie and jar), A nit 1 (the guard counts http/httpx/urllib3/socket
    imports too).
  - **[DEV] no crawl-point filter for auth endpoints:** accepted.
- Effectiveness: verified offline. A live check follows in the operator's bWAPP run.

### CC-FUZZ-0059 — Token-aware regex/division lexing (BUG-0102); CLI quarantine line (BUG-0107); greybox cookie floor (BUG-0098) (2026-10-13)
- Change:
  - **`oracle/context.js_states` (BUG-0102)** decides regex versus division from the
    previous **token**:
    - `REGEX_KEYWORDS` (`default` included);
    - a paren stack for `if` / `while` / `for` / `with` heads;
    - identifiers (`this` / `null` / `true` …), numbers, strings, `]`, other `)` and
      postfix `++` / `--` → division;
    - `}` followed by `/` → UNSURE.
  - **`harness/auto_cli._print_ml_extras`** prints "N candidate(s) with unreadable
    evidence skipped".
  - **Greybox:** `greybox_cli._cookie_for` returns `(cookie, secure_only)`, and
    `RequestsCorrelatingSender(cookie_secure_only=)` refuses http.
- Impact (other components / project):
  - **ML:** fewer false confirmations, so fewer false positive labels.
  - **SESS** (CC-SESS-0013).
  - The lab sink verdicts are unchanged (existing tests).
- Risk: low. 18 grammar cases plus every existing XSS fixture.
- Deliverables:
  - [x] lexer — done
  - [x] CLI line — done
  - [x] greybox floor — done
  - [x] tests — done
  - [x] FR-FUZZ-39 amended — done
- Implementation divergence: none.
- Review: the review-9 draft (all 13 findings reproduced first on `1619932`) went v1 → v4 through both reviewers. A: 2 must-fix, 6 should-fix and 4 nits on v1, then 1 must-fix and 1 nit on v2. B: 2 must-fix, 7 should-fix and 5 nits on v1, then 1 must-fix on v2, and S9 on v3. AGREED 3/3 on v3. S9, a narrowing, was adopted as v4 with A's confirmation.
- Effectiveness (assessed 2026-10-13): effective offline. All 13 findings were reproduced on `1619932` (`scratchpad/ext2/f01..f13`). Each now has a test that fails there (or cannot import there, its repro script showing the old behaviour), and the repros show the fixed behaviour on the new tree. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 47 mutants across the 13 fixes. 45 were killed on the first pass. The 2 survivors each showed a test gap, and both gaps were closed: the in-scope path of the event-loop test, and the thread lock without `fcntl`. Result: 47/47. Full non-labgen suite (150 files, `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 2003 passed, 13 skipped, 2 xfailed. The 1 error was `test_no_ml`'s real build, which builds from git-tracked files; it passes once the new files are staged (the no-ML and packaging files: 17 passed, 1 known environmental skip). The two gap-closing test files, re-run after the suite: 55 passed. The labgen half was not re-run, since no labgen code changed.

### CC-FUZZ-0058 — Reflected-XSS confirmation models script executability (BUG-0093); CLI says when a holdout is implied (BUG-0091) (2026-10-13)
- Change:
  - **`oracle/context.script_executes(tag)`** applies the HTML standard's script type
    rules exactly:
    - the type string, then an exact, case-insensitive JavaScript MIME essence match,
      or `module`;
    - `language` when there is no `type`;
    - `nomodule` on a classic script;
    - any `src`;
    - inert ancestors.
  - **`locate_reflection`** types a marker only in an executing script as `script`. A
    marker in an inert script falls through to text with `inert_parent="script"`, whose
    only try is the `</script>` element break-out.
  - **`js_executes`** reads only executing scripts, and `javascript:` URLs with no
    inert ancestor.
  - **`type_reflection`** uses the same predicate.
  - **`harness/auto_cli._print_ml_extras`** appends "(implied: target sealed)" to the
    holdout line. `ml/plugins._with_held_endpoints` counts held endpoints for an
    implied holdout too.
- Impact (other components / project):
  - **ML** (CC-ML-0024): the implied-holdout line.
  - The oracle produces fewer false confirmations, which become fewer positive labels
    for the ML.
  - The lab sink templates' verdicts are unchanged (existing tests).
- Risk: low. The predicate is tested on 13 inert and 10 executing shapes, plus
  break-out, escaped and inert-ancestor cases.
- Deliverables:
  - [x] `script_executes` and its use in the three readers — done
  - [x] CLI implied-holdout line — done
  - [x] tests: `test_oracle_xss_structural` (17 failing before), `test_ml_holdout_seal`
        (CLI line) — done
  - [x] FR-FUZZ-39 amended — done
- Implementation divergence: none. The test file's docstring still cited FR-FUZZ-15 and
  is corrected to FR-FUZZ-39.
- Review: the review-8 draft (all seven findings reproduced first) went v1 → v4 through both reviewers. v1→v2: B, 4 should-fix + 4 nits. v2→v3: A, 1 must-fix + 4 should-fix + 3 nits. v3→v4: A and B, the same must-fix (an implied holdout for every trainer). v4 was AGREED 3/3, and the final optional nits (A: store-wide trains skip, not refuse, an unknown target; B: the prioritizer raises, never returns None) were adopted.
- Effectiveness (assessed 2026-10-13): effective offline. Every finding's reproduction is now a test that fails on `5eb4be9` (counts in each bug doc). Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 38 mutants across the seven fixes, 35 killed on the first pass. The 3 survivors each showed a test gap (the plural fold of `pass`, the loader boundary's `OverflowError` catch, the discovery-hop https floor), and each gap was closed with a new test, after which 3/3 were killed (38/38). Full non-labgen suite (145 files, `FUZZLAB_REQUIRE_BROWSER=1`): 1869 passed, 13 skipped, 2 xfailed, 0 failed. The review-8 test files, re-run after the gap tests: 327 passed, and `test_secretfile` 13/13 with the reviewers' self-healing test. The labgen half was not re-run, since no labgen code changed.

### CC-FUZZ-0057 — Structural reflected-XSS confirmation (BUG-0083); in-band OOB proof (BUG-0089); greybox destructive send gate (BUG-0082) (2026-10-13)
- Change:
  - **XSS (BUG-0083), in `oracle/context.py`.**
    - `locate_reflection` types where a marker lands (script, attribute or text), and
      `xss_breakouts` offers at most 3 structural tries:
      - script: a JS breakout closing the lexer state;
      - attribute: js-url, scheme position, then attribute injection with the raw-text
        quote;
      - text: an element, or `</inert>` plus an element.
    - Each try is judged by `js_executes`, `attribute_injected` or `element_injected`.
    - The JS lexer fails closed (`UNSURE`).
    - `ReflectedXssStrategy` uses these and never reads `candidate.sink_context` (an
      AST guard).
    - `pipeline._candidate_of` documents the deliberate omission (item 11).
    - The substring helpers `is_unescaped` / `breakout_for` are removed.
  - **OOB proof (BUG-0089, found by the PA-0084 sweep).** `OobListener.proof(token)` is
    an HMAC under a per-listener secret; the callback serves it, and the in-band
    SSRF / XXE strategies require it.
  - **Greybox (BUG-0082).** `run_greybox` refuses destructive probes (base and
    mutation variants) before sending, counts `destructive_refused`, and the CLI prints
    it.
- Impact (other components / project):
  - XSS confirmation may take up to 4 requests per candidate (it was 2). The auto
    goldens are unchanged, because the lab's reflected-XSS cases are html-body shapes.
  - Labs that echo the fetched body still confirm SSRF / XXE in-band (the live
    category-3 / category-4 multitarget runs pass).
- Risk: medium. These are oracle verdicts. The four lab sink templates are tested
  vulnerable and secure, and the existing oracle, greybox and pipeline suites pass
  (351).
- Deliverables:
  - [x] structural XSS; the item-11 guard — done
  - [x] OOB HMAC proof — done
  - [x] greybox send gate — done
  - [x] tests: `test_oracle_xss_structural`, `test_oracle_oob` additions,
        `test_destructive_send_gate` — done
  - [x] FR-FUZZ-39 added; FR-FUZZ-8 / FR-FUZZ-10 amended — done
- Implementation divergence:
  - The draft named "FR-FUZZ-15 amended", but FR-FUZZ-15 is SpEL. The XSS rule is a new
    **FR-FUZZ-39**.
  - BUG-0089 was not in the draft: it was found by this batch's PA-0084 sweep and
    fixed here, being the same root-cause class.
  - Its review is this entry's mutation proof plus the agreed PA-0084.
- **Effectiveness addendum for CC-FUZZ-0056 / CC-ML-0023 / CC-UI-0048 / CC-PLUG-0008 /
  CC-CORE-0033 (review 6, committed 93270ae):**
  - **Non-labgen suite** (134 files, real browser and lint required): **1547 passed, 13
    skipped, 2 xfailed, 1 failed**. The failure was `test_multitarget_category4`'s live
    boot, a connection reset under concurrent CPU load; it passes alone (2 passed).
  - **Full suite** (all 289 files, labgen included, real browser and lint required):
    **3365 passed, 66 skipped, 9 xfailed, 33 failed**. All 33 failures are the known
    environmental labgen tests (`test_labgen_cli`, `test_labgen_fingerprint_gate`, the
    `*_cli_check_passes_end_to_end` family): scipy, scikit-learn and gitleaks are absent
    here. None involves a file this batch touched.
- Review: the review-7 draft v1 got AGREE-with-changes from both reviewers (A: 2 must-fix, 7 should-fix, 3 nits; B: 6 should-fix, 4 nits), all adopted; v2 was agreed 3/3, with the final nits adopted.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Mutation check** (a copy of the worktree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **40 of 40** review-7 mutants killed. Six first survivors were killed after adding tests for: the leaf cache refusing directly; 0600 with `chmod` disabled; the path backstop alone; a same-origin 307; a line-comment-split `INSERT … INTO`; a JS string open at a newline.
  - **Suites:** **non-labgen suite** (143 files, real browser and lint required; ): **1730 passed, 13 skipped, 2 xfailed, 0 failed**. The live multitarget category-3 / category-4 runs pass with no concurrent load. Packaging / no-ML / contract writers / lint: 22 passed, 1 skipped (the wheel, the known Debian setuptools issue). The labgen suites are untouched by this batch; the last full run (review 6) failed only the 33 known environmental tests (no scipy, scikit-learn or gitleaks).

### CC-FUZZ-0056 — Bandit cost wrapper takes `content_type` (BUG-0071); crash-safe oracle statuses; one confirmation per key (BUG-0072); usage checks before any run row (BUG-0078) (2026-10-13)
- Change:
  - **BUG-0071.**
    - `oracle._CostCounter.send` accepts and forwards `content_type`, in the same shape
      as `_CountingSender`.
    - `run_pipeline` writes one committed pre-loop status for every candidate:
      `no_confirmer` (final) or `pending` (unlabelled, CC-CORE-0033). The oracle loop
      runs in `try/finally`, and the `finally` writes the statuses gathered so far
      before the error re-raises. A crash never leaves a NULL, which the ML dataset
      reads as labelled.
  - **BUG-0072.** The unbudgeted loop confirms **each key once, on its first row in row
    order, whatever the verdict**. Later rows of a key are marked `checked` with no
    probe. Row order (the bandit's) is kept. There is no writer-level dedupe (`finding`
    has no `location`). **FR-FUZZ-32 is amended in place.**
  - **BUG-0078.**
    - New pure `harness.auto.plan_run(mode, ground_truth, selected_categories,
      points_source)` → `(source, plan)`. `run_auto` calls it, and so does `fuzzlab auto`
      **before opening the store**.
    - `_precheck_environment`, also before the store: `--browser` needs Playwright
      importable, and greybox side-channel paths must exist.
    - Everything after `start_run` is guarded: `Store.mark_aborted` (CC-CORE-0033)
      records `notes = "aborted: …"`, then the error re-raises.
    - Sweep fixes:
      - `greybox-run`: ground-truth "no points" is checked before the store, and the
        crawl path is guarded;
      - `run_targets`: every spec's plan is resolved before the first run, and each run
        is guarded.
- Impact (other components / project):
  - **CORE** (CC-CORE-0033): `PENDING`, `Store.mark_aborted`.
  - **UI** (CC-UI-0048): the run page counts pending rows.
  - **CLI output, a deliberate change.** Summary goldens `score_only.txt` and
    `budget_fallback_nolabels.txt` show `findings 4 → 3` and `requests 322 → 306`
    (`requests/finding 80.5 → 102.0`): the duplicate `/search.php q` confirmation is
    gone. `run.txt` and `earlier.txt` are unchanged.
  - `test_unbudgeted_run_confirms_rows_in_their_original_order` now expects one confirm
    per key.
  - The CLI prints `plugin refused (<reason>): <name>` (CC-PLUG-0008).
- Risk: low-medium. The confirmation change alters run numbers on labs with
  duplicate-key points. That is the intended correction; it is listed above with
  before/after. Pending rows appear only after a crash.
- Deliverables:
  - [x] `_CostCounter` signature and forwarding — done
  - [x] pending pre-write and `finally` flush — done
  - [x] one confirmation per key; FR-FUZZ-32 amended — done
  - [x] `plan_run`, environment prechecks, abort marking; greybox / multitarget sweep — done
  - [x] tests: `test_sender_conformance.py`, `test_pipeline_invariants.py`,
        `test_auto_cli_side_effects.py` — done
- Implementation divergence:
  - The draft's "no writer-level dedupe" holds.
  - **Sweep additions:** the BUG-0078 sweep found two more instances (`greybox-run`,
    `run_targets`). They were fixed in this entry rather than deferred, being the same
    root cause with the same mechanism.
  - The abort marker lives in `Store.mark_aborted`, not in the CLI, so all three guarded
    paths share it (PA-0003).
- Review: the review-phase draft v2, plus final amendments, agreed 3/3 (reviewers A and
  B). The BUG-0073 tie divergence was re-reviewed and agreed.
- Effectiveness (assessed 2026-10-13): effective offline. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **26 of 26** review-batch mutants killed (one survivor, the ranker reader passing the classifier's score column, was killed after adding `test_each_family_reader_backs_a_legacy_row_with_its_own_score_column`). Every new regression test fails on the pre-fix code. Suite results: see the related suites (83 files: auto, pipeline, plugins, ML, web incl. real-browser, report, oracle, scheduler, CLI, contract writers, lint, no-ML, packaging, harness, store, migrations, diagnostics; `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1054 passed, 1 skipped, before the last three tests were added, which pass with their files; greybox / multitarget / auto / store / CLI: 143 passed. The non-labgen and full-suite runs were still in progress at commit time and are recorded in a follow-up entry.

### CC-FUZZ-0055 — On-host run through the CLI; budget feature version; attempt feature schemas; FR-FUZZ-31 backfill; oracle lint (2026-10-13)
- Change:
  - **`scripts/on_host_full_run.sh`.** No ML step calls `fuzzlab.ml` any more:
    - **Part H.** The inline `propose_queries` is replaced by budgeted `fuzzlab auto`
      runs (uncertainty, committee), each followed by an **asserting** `_check_sql`
      (new helper): no fallback, and `min(5, confirmable)` keys checked. New steps:
      `--rank-objective auto`, and `--score --calibrate platt --holdout`. The holdout
      reveal runs only with `REVEAL_HOLDOUT` set.
    - **Part L.** It is one `--plugins --anomaly` run, so the report shows both, then an
      `--anomaly-method iforest` run (its own store) and `fuzzlab flow-anomaly` over
      Part I's proxy flows.
    - New steps are marked "[not yet executed on host]".
  - **`docs/ON_HOST_RUNBOOK.md`** matches, plus a "Release builds" section (BUG-0068).
  - **`harness/pipeline.py`** records `pipeline_budget_feature_version` from the
    prioritizer's order (BUG-0069).
  - **Attempt feature schemas.**
    - `greybox/run.py`: `ATTEMPT_FEATURE_SCHEMA = "greybox/1"`, written as `"_schema"`
      inside each attempt's `features_json`.
    - `tools/store_adapter.py`: `"_schema": "fuzz-csv/1"`.

    `attempt.feature_version` stays NULL (BUG-0069 sweep; allowlisted).
  - **FR-FUZZ-31 backfilled** from CC-FUZZ-0047. It landed 2026-09-25 with its
    effectiveness recorded, but the requirement was never written.
  - **`oracle/strategies.py`** imports `Probe`, which was used only in a postponed
    annotation (pyflakes "undefined name").
- Impact:
  - The on-host run now exercises the shipped CLI paths and fails visibly when a budget
    silently falls back.
  - `propose_queries` becomes library-only. It has no CLI caller; the budgeted run is
    its wired path.
  - Attempt rows gain a `_schema` key in their JSON; existing keys are unchanged.
- Risk: low. The script changes are offline-verified only: `bash -n`, the guard tests,
  and `_check_sql` against a stand-in `sqlite3`. They are marked as such.
- Deliverables:
  - [x] script + runbook — done
  - [x] pipeline metric — done
  - [x] attempt schemas — done
  - [x] FR-FUZZ-31 backfill, FR-FUZZ-38 — done
  - [x] tests:
    - `tests/test_on_host_script.py` (4): no `fuzzlab.ml`, syntax, opt-in reveal and the
      asserting check, `_check_sql` failing on a mismatch;
    - `test_auto_budget` (the pipeline metric per method);
    - `test_contract_writers` (the attempt schemas).

    — done
- Implementation divergence:
  - **FR-FUZZ-38** is a new requirement ID for the script and pipeline record; it was
    not pre-assigned. This is the only lane, so there is no collision.
  - **The iforest step uses its own store** (`anomaly_iforest.db`), so the reports that
    follow still describe the `--plugins --anomaly` run.
  - **CC-MUT-0012 was not needed.** `mutation/xss.py`'s flagged import is a deliberate
    `# noqa` re-export, which the lint test honours, so the file is unchanged.
- Review: covered by the batch-5 3/3 pre-change review (B3, A7, A9, A1, A5).
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Related suites** (95 files: ML, auto, web incl. real-browser, plugins, report,
    no-ML incl. the real no-ML build, harness, multitarget, pipeline, diagnostics, core,
    CLI, store, migrations, packaging, lint, contract writers, on-host script, greybox,
    store adapter, session, labgen CLI, mutation, oracle;
    `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1249 passed, 3 skipped,
    11 failed.
    - 10 failures are `test_labgen_cli.py` tests, among the 33 known environmental
      failures (no scipy, sklearn or gitleaks).
    - The 11th, the multitarget live-boot test, failed with a connection reset from its
      locally booted server while two other suites held the CPU. It passes alone
      (2 passed).
  - **Mutation check** (a staged git copy, bytecode caches cleared): all 21 batch-5
    mutants are killed. Three were first mis-anchored by shell expansion in the
    mutation script and were re-run correctly. Killed:
    - old per-directory globs; no dotfiles;
    - deny-list missing pem / env; an over-broad deny pattern; a one-line no-ML switch;
    - report union missing models / stage metrics / flow;
    - the anomaly version on the read-only path, or missing;
    - flow-version duplicates; prioritizer / pipeline version missing;
    - CSV / greybox schema missing;
    - `_check_sql` never failing; the reveal not opt-in; a literal 5 in the budget check;
    - a lint regression; the dropped `Probe` import.

### CC-FUZZ-0054 — `--rank-objective`, `--anomaly-method`; `fuzzlab flow-anomaly` (2026-10-13)
- Change:
  - **`--rank-objective {pointwise,pairwise,auto}`** needs `--rank`, and is a usage
    error with `--train-on saved`.
  - **`--anomaly-method {ecod,iforest}`** needs `--anomaly`.
  - Both reach the stages through `stage_plugins`.
  - **Summary.** It gains an `objective:` line under the ranker (with the run-wide
    per-fold NDCG / P@k, or the fallback). The anomaly line reads `anomaly (iforest):`
    for iforest; the ECOD line is unchanged.
  - **New `harness/flow_anomaly_cli.py`** and `fuzzlab flow-anomaly`:
    - reached through `import_ml`, exiting 2 when ML is missing;
    - a missing store or bad contamination is a usage error;
    - it prints per-host counts and the top flows, with the "forced per-host fraction"
      wording;
    - it is registered in `fuzzlab/cli.py`.
- Impact: new flags and a new command. The defaults and golden summaries are unchanged.
- Risk: low.
- Deliverables:
  - [x] flags, validation and summary — done
  - [x] flow-anomaly command — done
  - [x] FR-FUZZ-37 — done
  - [x] tests:
    - three usage errors;
    - the iforest summary label;
    - the flow CLI end to end with a bad contamination;
    - the no-ML child exiting 2 with the message (`tests/test_no_ml.py`).

    — done
- Review: covered by CC-ML-0021's 3/3 pre-change review (A7, B4-4). Renumbered from
  CC-FUZZ-0053 (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (61 files incl. real-browser, no-ML, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 953 passed. Batch-4 files (`test_ml_batch4.py`, `test_candidate_features_core.py`, `test_no_ml.py`, `test_web_ml_context.py`): 57 passed after the mutation-driven additions. Its mutants are among CC-ML-0021's 28, all killed.

### CC-FUZZ-0053 — `fuzzlab auto --holdout` / `--calibrate`; `fuzzlab reveal-holdout` (2026-10-13)
- Change:
  - **`--holdout`** passes `holdout=True` to the classifier, ranker and budget stages.
    It needs `--score`, `--rank` or `--confirm-budget`.
  - **`--calibrate {none,platt}`** needs `--score`. It is a usage error with
    `--train-on saved`.
  - Both reach the stages through `stage_plugins`, and appear in a stage's config only
    when set.
  - **Summary lines** (`_print_ml_extras`):
    - the out-of-fold ECE / Brier raw → cross-fitted, or why nothing was calibrated;
    - `holdout: N endpoint(s) of this run held out; metrics sealed — read with
      fuzzlab reveal-holdout --run R`, or `no sealed metrics (<reason>)`.

    Never a holdout number.
  - **New `harness/reveal_cli.py`** and `fuzzlab reveal-holdout --store --run`
    (registered in `fuzzlab/cli.py`, kept out of the web launcher). It prints the
    sealed metrics per model and the reveal count, or "nothing to reveal". A missing
    store is a usage error.
- Impact: new flags and a new command. The defaults are unchanged, and the golden
  summaries are byte-identical. The launcher shows `--holdout` / `--calibrate` through
  `commandspec` automatically.
- Risk: low.
- Deliverables:
  - [x] flags, validation and summary lines — done
  - [x] reveal command — done
  - [x] FR-FUZZ-36 — done
  - [x] tests: four usage errors with no run row, label-free summary lines (regex
    shape), plugin configs, the reveal CLI (counted / nothing to reveal / missing
    store), default configs unchanged — done
- Implementation divergence: the reveal is its own command, not `fuzzlab auto
  --reveal-holdout` (see CC-ML-0020).
- Review: covered by CC-ML-0020's 3/3 pre-change review. Renumbered from CC-FUZZ-0052
  after BUG-0070 took that number (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (58 files: ML, auto, web incl. real-browser, plugins, report, no-ML, harness, multitarget, pipeline, diagnostics, core, CLI, store, migrations; `FUZZLAB_REQUIRE_BROWSER=1`): 901 passed. `tests/test_ml_holdout_calibration.py`: 42 passed. Its mutants are among CC-ML-0020's 27, all killed.

### CC-FUZZ-0052 — `fuzzlab auto --anomaly` prints why fewer were flagged; contamination help says "at most" (BUG-0070) (2026-10-13)
- Change (`harness/auto_cli.py`):
  - The anomaly summary prints `    note: <flag_reason>` when ties left fewer than k
    flagged (CC-ML-0019).
  - The `--anomaly-contamination` help text changes from "Fraction of candidates
    --anomaly flags" to "At most this fraction of candidates is flagged by --anomaly,
    whole tie groups only".
  - The validation (0, 0.5] is unchanged.
- Impact: the CLI summary output changes where the tripwire's ties bind. The golden
  summaries `tests/data/auto_summary/run.txt` and `earlier.txt` were regenerated
  deliberately ("flagged 8 of 46" becomes "flagged 4 of 46" plus the note line, and one
  listed row fewer; every other line is byte-identical). No flag or exit code changes.
- Risk: low.
- Deliverables:
  - [x] reason line + help text — done
  - [x] goldens regenerated with the reason recorded; `test_auto_budget` asserts
    `0 < flagged ≤ anomaly_flag_budget` — done
- Review: covered by CC-ML-0019's 3/3 pre-change review (B1, B v2-1, A v2-2).
- Effectiveness (assessed 2026-10-13): effective offline.
  - `test_auto_plugins.py` passes with the regenerated goldens, and so does
    `test_auto_budget.py`.
  - The "no CLI reason" mutant is killed (CC-ML-0019's mutation check).

### CC-FUZZ-0051 — `--train-on saved`, `--model-id`, `--ranker-model-id`, `--hybrid` (2026-10-13)
- Change:
  - **`auto_cli`:**
    - `--train-on` gains `saved`.
    - New `--model-id ID` (needs `--score` and `--train-on saved`), `--ranker-model-id ID`
      (needs `--rank` and `--train-on saved`), and `--hybrid` (needs `--score`; a usage
      error with `--train-on saved`).
    - **Summary:** "ml (logistic): scored N candidate(s); with saved model #ID (trained
      on runs …), not trained on this run; X% … seen in training; forward …". A refusal
      reads "ml: NOT scored — <reason> …".
  - **`harness/pipeline.py`** imports the status vocabulary from `core.oracle_status`.
- Impact:
  - CLI only. FR-FUZZ-35 is added.
  - **Tests updated deliberately:**
    - `test_auto_train_on.py`: the launcher choices gain `saved`;
    - `test_auto_plugins.py`, `test_ml_plugins.py`, `test_no_ml.py`: config strings gain
      `hybrid`.
- Risk: low.
- Deliverables:
  - [x] Flags, validation, summary — done
  - [x] `tests/test_auto_train_on.py` (+8) — done:
    - saved end to end, with the source id and the summary wording;
    - the saved refusal;
    - five validation errors;
    - `--hybrid` reaches the classifier and is recorded.
- Review: pre-change review gate cleared 3/3 over drafts v1 to v4 (the proposing agent plus 2 independent reviewer agents; every raised issue adopted).
  - **Process note:** `core/oracle_status.py`, `core/urls.canonical_origin`, the dataset changes and `--hybrid` were drafted in the working tree **before** agreement. They were kept uncommitted and reconciled with the agreed v4.
  - **Reverted:** my early in-column version of D-c was reverted; reviewer B's separate-column design replaced it.
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (ML, auto, web incl. browser smoke, plugins, report, no-ML, harness, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 705 passed, including `test_ml_saved_and_decisions.py` 39 and `test_auto_train_on.py` 13. Mutation-checked on a copy with bytecode caches cleared: all 20 mutants are killed. The first run left two survivors, and each got a new test (noisy data where in-sample and out-of-fold PR-AUC differ; an earlier-trained saved source). Killed:
  - **gates:** the legacy gate on in-sample scores, `score_oof` ignored, the run page or conformal panel judging `score`;
  - **out-of-fold columns:** not written, not cleared by earlier mode, ranker out-of-fold dropped;
  - **saved selector:** any scope run, a bool scope, copies chosen, the wrong `train_run_ids`;
  - **targets and labels:** the localhost alias dropped, an empty host matching, no_confirmer labelled, exact-text target matching;
  - **UI and report:** the tab's metrics on deploy scores, the out-of-fold label missing, the report's saved block missing;
  - **CLI:** `--hybrid` allowed with saved.
  Full-suite result (on commit c16477e, `FUZZLAB_REQUIRE_BROWSER=1`): 3113 passed, 65
  skipped, 9 xfailed, 33 failed. The 33 failures are exactly the known environmental
  labgen failures (no scipy, sklearn or gitleaks), identical to the step-3 baseline.

### CC-FUZZ-0050 — `fuzzlab auto` attaches ML through plugins; `run_auto` dispatches the post-run hooks (2026-10-13)
- Change:
  - **`run_auto`**:
    - after `record()`, it takes the budget prioritizer from the plugins when none is
      passed (two raise `RunModeError`);
    - after the pipeline, it runs `plugins.after_run`, then `plugins.finalize`, into
      `result.plugin_outcomes`.
    - So every caller gets the hooks. `run_targets` is one, and `TargetOutcome` gains
      `plugin_outcomes`.
  - **`run_pipeline`**:
    - A `FailedBudgetOrder` records `confirm_budget_error=1`, so
      `pipeline_confirm_budget_error` lands in `run_metrics`, and `budget_error`
      (result only).
    - `budget_plugin` names the source.
    - The cap holds, in row order.
  - **`auto_cli`**:
    - It builds the plugin set **before the store is opened** (`_build_plugins`): the ML
      stages through `import_ml("fuzzlab.ml.plugins")` → `stage_plugins`, plus
      `--plugins` entry points, with built-ins registered first.
    - **Usage errors, exit 2, before any run row:**
      - ML flags with ML absent;
      - `--confirm-budget` with neither ML nor a plugin prioritizer;
      - two prioritizers.
    - It no longer imports `fuzzlab.ml`.
    - **Summary.** It reads the outcomes by plugin name:
      - `<stage>: FAILED — <error>` for a failed or missing requested stage;
      - `oracle budget: <plugin> FAILED — <error>; confirmed the first N of M
        confirmable candidate(s) in row order` (the "trained on" line is suppressed);
      - `plugin <name>: after_run done` / `FAILED` for third-party post-run plugins;
      - `plugins disabled after an error:` lists every other disabled plugin;
      - `plugin refused (duplicate name)`.
    - **Exit 1** when a post-run plugin or the prioritizer failed, or a requested stage
      did not run. A third-party scan-hook failure is printed and keeps exit 0.
  - **Behaviour preserved:**
    - The flags, defaults, validation messages and the existing summary lines are
      byte-identical to the pre-change capture (`tests/data/auto_summary/`).
    - With no ML flags and no `--plugins`, `plugins` stays `None`: no `run_plugin` rows
      and no hooks.
  - **Behaviour changes:**
    1. Runs with ML flags record `run_plugin` rows, so `fuzzlab report` gains a
       `plugins:` line.
    2. A failing ML stage no longer aborts with a traceback. Its uncommitted writes are
       rolled back, later stages run, and the CLI exits 1.
    3. A raising budget prioritizer no longer aborts the run. The cap holds in row order,
       and the CLI exits 1.
    4. ML usage errors are raised before the store is opened.
    5. The ML stages now run inside `run_auto`, before `auto_cli`'s
       `scheduler.flush_metrics()` / `save()` and `oob.stop()`. Nothing is pending there,
       so this is harmless, and an ML failure can no longer skip the scheduler save.
    6. With ML installed, `--confirm-budget` always attaches `ml-budget`, so a
       `--plugins` prioritizer cannot also be used (exit 2).
- Impact: CLI and harness. FR-FUZZ-34 is added.
  `scripts/on_host_full_run.sh:255,299` still imports `fuzzlab.ml` directly. It is an
  on-host script that needs ML anyway, so it is flagged and not changed.
- Risk: medium-low. Guarded by the golden summaries and the unchanged `test_auto*.py`.
- Deliverables:
  - [x] `run_auto` / `run_pipeline` / `run_targets` / `auto_cli` — done
  - [x] `tests/test_auto_plugins.py` (14) — done:
    - four golden summaries;
    - the stages recorded with their config and `ok`;
    - no ML flags → `plugins is None` and no rows;
    - the injected `dumps_model` failure: classifier scores NULL and no classifier model
      row, ranker and anomaly still written, FAILED line, exit 1, `failed` status with
      the error;
    - the raising prioritizer: exactly 2 keys confirmed, `pipeline_confirm_budget_error=1`,
      no "trained on" line, exit 1;
    - two prioritizers → exit 2 with no run row;
    - a third-party prioritizer works without ML;
    - ML flags without ML → exit 2 with no run row;
    - a failing third-party post-run plugin → exit 1;
    - `run_targets`: dispatched once per target run; a failure on target 1 is recorded
      `failed`, and the plugin is retried and `ok` on target 2.
  - [x] `tests/test_ml_import_guard.py` (3) — done. An AST scan of `fuzzlab/` outside
    `fuzzlab/ml/` rejects every import form and every module-path string except
    `import_ml("…")` arguments. Proven on 11 synthetic offenders and 6 allowed forms.
- Review: pre-change review gate cleared 3/3. The proposing agent and 2 independent reviewer agents went through DRAFT v1 to v4.
  - Reviewer A focused on architecture and spec fit; reviewer B on adversarial correctness, safety and tests, with SQLite experiments.
  - Every raised issue was adopted.
  - v1's guard was bypassable (a rename round-trip, a later-firing trigger, a temp shadow table, label state outside `finding`, an unguarded prioritizer). v1's failed-stage writes could also be committed by the next stage. Both were redesigned before any code.
- Effectiveness (assessed 2026-10-13): effective offline. `tests/test_auto_plugins.py` 14 passed, including four summaries byte-identical to the pre-change capture, and `tests/test_ml_import_guard.py` 3 passed. `test_auto.py`, `test_auto_budget.py`, `test_auto_train_on.py` and `test_multitarget*.py` pass unchanged. The CLI, `run_auto` and pipeline mutants are killed (CC-PLUG-0005). Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 3062 passed, 33 failed, 68 skipped, 9 xfailed. The 33 failures are the identical environmental labgen set as at `a3b782d` and `882cda8` (diffed: no scipy, scikit-learn or `gitleaks` binary here). Every skip is in lab/labgen/corpus tests guarded on toolchains or services, none in a file this change touches; the +3 against `882cda8`'s run is in that environment-dependent set.

### CC-FUZZ-0049 — `fuzzlab auto --train-on {run,earlier}` (2026-10-13)
- Change:
  - **Flag.** `auto_cli` gains `--train-on {run,earlier}` (default `run`), passed to
    `train_and_score` / `train_and_rank` (CC-ML-0016). It needs `--score` and/or
    `--rank`, otherwise `p.error` (a clean exit, no traceback).
  - **Summary line when trained** (`_print_earlier`), e.g.:

    > ml (logistic): scored N candidate(s); trained on M earlier labelled candidate(s)
    > from this target (runs 1, 2), not on this run's labels; X% of this run's
    > candidates were seen in training; forward PR-AUC=… (prevalence …)

    - The ranker line is the same, with `forward NDCG@k=… (random …)`.
    - Without forward metrics it reads `no forward PR-AUC (<reason>)`.
  - **Summary line when refused:** "ml: NOT scored — <reason> (use --train-on run to
    train on this run's labels)", and "ranker: NOT ranked — …".
  - **Launcher.** It shows the flag as a choice field, automatically via `commandspec`.
- Impact: CLI only. FR-FUZZ-33 is added.
- Risk: low.
- Deliverables:
  - [x] Flag, validation and summary — done
  - [x] Tests (`tests/test_auto_train_on.py`) — done:
    - **End to end:** two earlier `_seed_rich` runs with target rows, then a
      ground-truth run with `--score --rank --train-on earlier`. Both saved models are
      scoped to this run and earlier-trained from runs [1, 2]. Every candidate is
      scored and ranked. Forward and seen-fraction metrics are recorded, with no
      `run`-mode keys. The summary wording and seen percentage are exact.
    - **Refusal** with no earlier runs and with only another target's runs: both lines
      printed; no model row, metric or score written.
    - `--train-on earlier` without `--score`/`--rank` is rejected.
    - The launcher renders the flag as a `run`/`earlier` choice defaulting to `run`.
  - [x] FR-FUZZ-33 — done
- Implementation divergence (written back per the review gate):
  1. The trained line also prints the forward baseline (prevalence / random) next to
     the forward number.
  2. The refusal line prints the actual reason, so a run with no target row reads
     "no target recorded for this run".
- Review: pre-change review gate cleared 3/3 (with CC-ML-0016).
- Effectiveness (assessed 2026-10-13): effective offline. `tests/test_auto_train_on.py` 5 passed: end to end with exact summary wording, refusal writing nothing, validation, and the launcher choice field. The CLI-validation-removed and flag-ignored mutants are killed (CC-ML-0016). `test_auto.py` and `test_auto_budget.py` pass unchanged. Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 2973 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are exactly the same labgen `--check`/fingerprint-gate tests as at `a3b782d` and `369e887`, which fail identically in this environment because it has no scipy, scikit-learn or `gitleaks` binary. None is caused by this change.

### CC-FUZZ-0048 — `fuzzlab auto --confirm-budget N` and `--anomaly` (2026-10-13)
- Change:
  - **`harness/pipeline.py::run_pipeline(..., confirm_budget: int | None = None,
    prioritizer=None)`:**
    - After the audit, rows are grouped by their **confirmation key** `(url, param,
      method, location, category)`, so duplicate rows from several rules firing share
      one status.
    - Keys whose category has no oracle class get `no_confirmer`.
    - **No budget:** every row is confirmed exactly as today (same loop, same calls,
      duplicates included), and confirmable rows get `checked`.
    - **Budget N with a prioritizer:**
      - `order = prioritizer(store, run_id, <one representative candidate id per
        confirmable key>)`.
      - If it returns `None`, the run falls back to confirming everything as above, with
        `confirm_budget_fallback=1`.
      - Otherwise the first N keys of `order` are confirmed once each (`checked`), and
        every row of the remaining keys gets `skipped_budget`.
    - `confirm_budget < 1` raises `ValueError`.
    - Metrics:
      - `oracle_rejected = checked keys - confirmed keys`. A key is confirmed when any
        `Oracle.confirm` call for it returned a verdict, which happens exactly when it
        wrote a finding (`oracle.py:54-82`). Counting by key means a duplicate row
        confirmed once (budget) and a duplicate row confirmed twice (no budget) both
        count once. Rows that were never checked are not rejections;
      - new: `oracle_checked`, `oracle_skipped`, `oracle_no_confirmer`,
        `confirm_budget` (budget only), `confirm_budget_fallback` (budget only);
      - `negatives = rule_negatives + oracle_rejected`;
      - the result's metrics dict also carries the method name and the prioritizer's
        training size.
    - **Exact no-budget differences from today:**
      - `oracle_status` is written;
      - three new `pipeline_oracle_*` rows appear in `run_metrics` (visible in
        Diagnostics);
      - `oracle_rejected` and `negatives` are now counted per key, so they drop by the
        number of `no_confirmer` keys and duplicate rows.
        - Every built-in rule category has a confirmer, so `no_confirmer` keys only
          appear with plugin rules.
        - Duplicates come from multi-rule categories such as `price-integrity-bypass`.
        - `pipeline_findings` is unchanged (it counts `finding` rows).
  - **`harness/auto.py::run_auto`:** passes `confirm_budget` and `prioritizer` through.
  - **`harness/auto_cli.py`:**
    - Flags:
      - `--confirm-budget N` (`type=int`; `p.error` unless N >= 1);
      - `--budget-method {score,uncertainty,committee,random}` (default `score`);
      - `--budget-seed` (`type=int`, default 0);
      - `--anomaly`;
      - `--anomaly-contamination F` (`type=float`, default 0.1; `p.error` unless
        0 < F <= 0.5).
    - The prioritizer is `functools.partial(prioritize, method=..., seed=...)`.
    - Post-run order: score, then rank, then anomaly.
    - Summary lines:
      - With the budget applied: "oracle budget: checked X of Y confirmable
        candidate(s); Z skipped (ordered by <method>, trained on R earlier labelled
        candidate(s) from this target)". For `random` the parenthesis reads "(random
        order, seed S — the control for T7.4)".
      - On fallback: "oracle budget NOT applied: no usable earlier labels for this
        target — confirmed all Y".
      - When a scored run skipped candidates: "skipped candidates count as misses in
        the score".
      - `--anomaly`: "anomaly: flagged K of M candidate(s)", plus up to 5 flagged rows
        (path, param, category, score).
- Impact:
  - ML and CORE as above.
  - UI: the launcher form gains the five flags through `commandspec`. Int and float
    flags render as number inputs (`commandspec.py:76-87`), with no UI code change. A
    test asserts this.
  - Budgeted scored runs report skipped real vulnerabilities as false negatives. That is
    intended: it is the trade the budget makes.
  - FR-FUZZ-32.
- Risk: medium. The confirm loop changes shape. Mitigations:
  - the no-budget loop is kept identical, so every existing pipeline and auto test
    passes unchanged;
  - the prioritizer is injected, with a confirm-all fallback;
  - the T7.4 measurement stays on-host.
- Deliverables:
  - [ ] Pipeline (keys, statuses, budget, fallback, metrics) — done
  - [ ] `run_auto` passthrough; CLI flags, validation and summary — done
  - [ ] Tests:
    - no budget: existing tests pass, and rows are marked `checked` / `no_confirmer`;
    - a stub prioritizer confirms exactly the first N keys once each (counting fake
      sender/oracle), and duplicates share a status;
    - fallback, metrics, and `ValueError`;
    - CLI end-to-end per B5: two earlier `_seed_rich` runs on the same target, then a
      budgeted ground-truth run with `--budget-method random` and `score`, plus
      `--anomaly`; also a no-earlier-runs fallback and an other-target-only fallback.
      Both fallback tests use `--budget-method score`, since `random` never falls back.
      The seeded earlier runs get `target` rows for `http://127.0.0.1:8080`, matching
      `--base-url`. A duplicate-key metrics test is included;
    - argparse validation, dry-run, and the launcher rendering the new number inputs — done
  - [ ] FR-FUZZ-32 — done
- Implementation divergence (reflected back per the review gate): the pipeline also records `oracle_checked_keys` and `confirmable_keys` (the per-key counts behind `oracle_rejected` and the budget summary line) as `pipeline_*` metrics.
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; the budget-ordering objective was put to the user, who chose `score` as the default; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — `tests/test_auto_budget.py` 17 passed: unbudgeted runs confirm every row, in its original row order (duplicates not regrouped — order matters to the bandit), and mark it `checked`; a stub prioritizer's first N keys are confirmed exactly once each and the rest are `skipped_budget`; fallback confirms all and records it; duplicate rows share one key/confirmation/status; `no_confirmer` rows are recorded and are not rejections; `oracle_rejected` equals checked keys minus confirmed keys; the CLI end to end (two earlier `_seed_rich` runs on `http://127.0.0.1:8080`, then a ground-truth run with `--confirm-budget 2` under each of the four methods plus `--anomaly`) checks exactly 2 keys, skips the rest, prints the budget/anomaly lines, and persists anomaly values; both fallbacks (no earlier runs; other target only) confirm all and say so; bad values are rejected; the launcher renders int/float/choice/bool inputs. Mutation-checked: ignoring the budget, per-row rejection counting, and regrouping the unbudgeted loop by key each make a test fail. Related suites (ML, auto, web incl. browser smoke under `FUZZLAB_REQUIRE_BROWSER=1`, report, dry-run, plugins, core, multitarget, oracle): 492 passed, 0 failed (re-run after the final row-order fix). Full suite (2026-10-13, whole `tests/` at `369e887`, `FUZZLAB_REQUIRE_BROWSER=1`): 2868 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same labgen `--check`/fingerprint-gate tests that fail identically on `origin/main` in this environment (no scipy, scikit-learn or `gitleaks` binary); none is caused by this change.

### CC-FUZZ-0047 — `PriceIntegrityBypassStrategy` anchor moves from a JSON fragment to an HTML attribute (2026-09-25, FR-FUZZ-31, `docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md`)

**Status: pre-change review gate cleared, 3/3 agreement reached 2026-09-25
(2 independent reviewer agents plus the proposing agent — this entry was
approved unchanged from its first draft) — implementation authorized, not
yet landed.** Tracked jointly with LAB's `CC-LAB-0239` — the sink-template
change (LAB) and this strategy change (FUZZ) must land in the same commit,
never split across two.

- **Change:** `LABGEN-BC-0005`/`0006`'s (Booking clone checkout,
  `price_integrity_bypass`) response body is converting from
  `response()->json($rows)` to a real HTML confirmation page as part of
  `CC-LAB-0239`. `fuzzlab/oracle/strategies.py::PriceIntegrityBypassStrategy.confirm`
  currently does an exact substring match on the literal JSON fragment
  `f'"charged_amount":"{canary}"'` (after `.replace(" ", "")` whitespace
  normalization) — this will not match an HTML body and would silently stop
  detecting the vulnerability (false negative) if left unchanged. Fix:
  change the anchor to match a `data-charged-amount="<canary>"` HTML
  attribute instead (still an exact match, not a loose substring, to
  preserve the canary's own collision-avoidance property — 3 decimal
  places, explicit exclusion of the real rate-table values `89.00`/
  `149.00`/`249.00`), with the same `.replace(" ", "")` normalization
  discipline the live-boot test already uses. Update the strategy's own
  unit tests (`tests/test_oracle_vectors.py`,
  e.g. `test_price_integrity_bypass_confirmed_when_client_amount_echoed_back`)
  and its live-boot proof
  (`tests/test_labgen_price_integrity.py::test_live_boot_price_integrity_manifest_ignores_the_client_amount_on_the_secure_twin`)
  to the new HTML shape. Also re-run
  `tests/test_labgen_phase_d_tier12_category5.py`, an independent Tier1/
  Tier2 conformance proof against the same cells via a different
  `evaluate_tier1_response`/`build_tier1_case` marker mechanism (bare
  `"0.01"` `evidence_marker`, not a JSON-fragment anchor) — expected to
  still pass against the new attribute but must be confirmed, not assumed.
- **Impact (other components / project):** LAB (01) — the paired sink-
  template change (`CC-LAB-0239`). No other oracle strategy is affected;
  `AccessControlIdorStrategy` (the other strategy touched by `CC-LAB-0239`'s
  scope) is a generic body-diff strategy with no JSON dependency and needs
  no change (verified directly against its own test suite, which already
  includes a raw-HTML fixture). No change to `Probe`/`Candidate`/
  `ConfirmationStrategy`'s own interfaces — this is a change to one
  strategy's internal matching logic only.
- **Risk (level; mitigation or accepted-risk justification):** **Medium —
  this is the single highest-risk change in the paired `CC-LAB-0239`/
  `CC-FUZZ-0047` work,** since an anchor mismatch here is a silent false
  negative (the strategy would simply stop confirming a real vulnerability,
  with no error or test failure to flag it, if the sink-template and
  strategy changes ever land out of step). Mitigated by: (a) requiring both
  changes in the same commit, never split; (b) an exact, not
  loose-substring, match on the new attribute value, preserving the
  canary's existing collision-avoidance design; (c) re-running the
  independent Tier1/Tier2 conformance test
  (`test_labgen_phase_d_tier12_category5.py`) as a second, differently-
  mechanised proof the new shape is still detected.
- **Deliverables:**
  - [x] `PriceIntegrityBypassStrategy.confirm`'s anchor changed from the
        JSON fragment to `data-charged-amount="<canary>"` — done, landed in
        the same commit as `CC-LAB-0239`'s `LABGEN-BC-0005`/`0006` HTML
        conversion.
  - [x] `tests/test_oracle_vectors.py`'s `PriceIntegrityBypassStrategy`
        tests updated to the new shape (all 3: confirmed-vulnerable,
        fails-closed-on-secure, canary-collision-avoidance) — done.
  - [x] `tests/test_labgen_price_integrity.py`'s live-boot proof updated —
        done, re-run for real (live-boot available in this environment) and
        green.
  - [x] `tests/test_labgen_phase_d_tier12_category5.py` re-run and
        confirmed green against the new HTML shape — done; its own
        `evidence_marker` (a bare `"0.01"`, not a JSON-fragment anchor)
        matched the new `data-charged-amount="0.01"` attribute without
        needing its own change.
- **Effectiveness (assessed 2026-09-25):** effective — the anchor change
  landed in the same commit as the paired `CC-LAB-0239` sink-template
  change (never split, per this entry's own risk mitigation), all 4
  dependent tests re-run for real against a live-booted server and green,
  and the independent Tier1/Tier2 conformance test confirms detection holds
  via a second, differently-mechanised proof. No detection regression.

### CC-FUZZ-0046 — `PathTraversalFsPathReadStrategy` closes category 4's last known real, TRACKED detection gap (`path_traversal`/`fs_path_read`) (2026-09-23)

- Change: new `fuzzlab/oracle/strategies.py::PathTraversalFsPathReadStrategy`
  (`vuln_class="path_traversal"`, `category="path-traversal"`) confirms
  `CC-LAB-0190`'s own deliberately-deferred `TWCH-0011` cell
  (`GET /clips/export?filename=`, CWE-22) with a real, standard, purely-
  READ black-box `/etc/passwd`-content differential: a `../`-traversal
  payload (reused from the existing `_TRAVERSAL_PAYLOADS` list) must make
  the response body contain the target's own real, PRE-EXISTING
  `/etc/passwd` content (`_PASSWD_MARKER`, `root:.*:0:0:`); a control
  probe with no traversal separators at all (`"passwd"`) must NOT show
  that marker — ruling out a target that always echoes such content
  regardless of input. Nothing is planted on the target's filesystem;
  this only reads a file that already exists there — the same technique
  this project's own `fuzzlab/labgen/nuclei_oracle.py` already bundles
  for a different sub-purpose (`lab/nuclei-templates/
  path-traversal-etc-passwd.yaml`, same match pattern), reimplemented
  here as a pure-Python `ConfirmationStrategy` for the runtime oracle
  rather than invoked via Nuclei. Registered in `default_strategies()`.
  `fuzzlab/core/runmode.py::_VULN_TO_CATEGORY` gains `"path_traversal":
  "path-traversal"`; `fuzzlab/oracle/strategies.py::_CATEGORY_TO_CLASS`
  gains `"path-traversal": "path_traversal"` — both checked directly
  before assuming either already existed (per `BUG-0045`'s own lesson).
  **Corrects a mischaracterization made when `CC-LAB-0190` deliberately
  deferred this concern's detection**: that entry (and `docs/
  LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`'s category-4 row) reasoned
  detection was deferred because "a path-traversal strategy cannot plant
  its own canary on the target's filesystem... probing well-known OS
  paths is not a safe/realistic black-box signal," which conflated this
  concern with a canary-PLANTING design (the SSRF/XXE-style pattern via
  an `OobListener`). That reasoning never applied to the read-a-pre-
  existing-file technique this strategy actually uses — nothing is
  planted, only a real, pre-existing OS file already on the target is
  read. This was tracked as "genuinely unbuilt, an open follow-on" (per
  `TWCH-0011`'s own `labels.json` `notes` field) — NOT confirmed
  infeasible the way `webhook_signature`'s own CWE-347 timing side
  channel is, for an unrelated reason (this project's single-request
  oracle model cannot observe a timing side channel at all; that
  limitation is real and distinct, and is NOT being revisited here).
  Empirically verified against the real, live-booted vulnerable/secure
  twins before writing this class (per this change's own task
  instructions, not guessed): booted `GoLiveBootHarness` against
  `lab/manifests/path_traversal_go_sample.yaml` and sent
  `filename=../../../../../../../../etc/passwd` directly — the
  vulnerable twin (`LABGEN-GO-0021`) returned real `/etc/passwd` content
  (HTTP 200, `root:x:0:0:root:/root:/bin/bash...`); the secure twin
  (`LABGEN-GO-0022`, `realpath_confine`) rejected the identical payload
  outright (HTTP 403, no such content anywhere in the body); a legitimate
  in-directory filename and a nonexistent filename behaved identically on
  both twins. This confirms the existing, already-escalating
  `_TRAVERSAL_PAYLOADS` list (shared with the pre-existing, differently-
  named `PathTraversalStrategy`/`"file-inclusion"` class, left untouched
  — it matches no current ground truth and was not the class this task
  targeted) already reaches real OS-file content at this lab's
  confinement depth, with no new traversal-depth tuning needed. New
  live-boot test: `tests/test_labgen_go_live_boot.py::
  test_path_traversal_strategy_closes_the_fs_path_read_detection_gap`
  (driven through a real `GoLiveBootHarness` boot and a real
  `RequestsProbeSender`, never a fake sender — confirms the real
  vulnerable twin and correctly fails closed on the real secure twin).
  `tests/test_multitarget_category4.py`'s two independent hardcoded
  recall assertions (grep-counted per PA-0045: exactly 2 occurrences of
  the stale fraction, both updated) move from `13/15` to `14/15`
  (`tp` 13 -> 14, `fp` stays 0).
- Impact (other components / project): `FUZZ` (`strategies.py`,
  `runmode.py`) and `AUD` (`CC-AUD-0027`'s own `R-PATH-TRAVERSAL` rule,
  this entry's companion). `LAB`'s `CC-LAB-0190`/`FR-LAB-145` entry's own
  detection follow-on is now closed (no `LAB` change needed — the lab
  page and its ground-truth label already existed; `FR-LAB-145` and
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`'s category-4 row are
  updated in place to record the closure and correct the earlier
  mischaracterization).
- Risk (level; mitigation or accepted-risk justification): Low. The new
  strategy/rule are purely additive (new class registered, new dict
  entries added, no existing entry changed) and fail closed by
  construction (a target that rejects the traversal probe, or whose
  control probe also shows the marker, never confirms). The technique
  only ever reads a pre-existing file on the target over an ordinary
  HTTP request already being sent for this candidate — no write, no
  filesystem access outside the HTTP protocol, no new capability granted
  to the fuzzer. Full non-slow suite plus the category-4 multitarget
  slow test file re-run, no new failures beyond the pre-existing,
  unrelated PHP Laravel/labgen-CLI ones.
- Deliverables:
  - [x] `PathTraversalFsPathReadStrategy` added and registered — done
  - [x] `_VULN_TO_CATEGORY`/`_CATEGORY_TO_CLASS` entries added, verified
        neither already existed — done
  - [x] Empirically verified (before design) against a real live boot
        that the vulnerable twin returns real `/etc/passwd` content and
        the secure twin rejects the identical payload — done
  - [x] Live-boot test added and passing against a real booted app — done
  - [x] `tests/test_multitarget_category4.py`'s both independent
        hardcoded recall assertions grep-counted and updated (PA-0045) —
        done
  - [x] `FR-LAB-145` and the category-4 plan-doc row updated in place to
        record the closure and correct the earlier "no way to plant a
        canary" mischaracterization — done
  - [x] Full non-slow suite + the category-4 multitarget slow test file
        re-run, no new failures — done
- Effectiveness (assessed 2026-09-23): achieved. Twitch's own real, scored
  recall in `test_both_apps_run_through_multitarget_for_real` moves from
  `13/15` to `14/15` (`tp` 13 -> 14, `fp` 0), verified against a real
  booted app over the real `run_targets`/`RequestsProbeSender` pipeline,
  not merely a hand-built `Candidate` call. This closes this project's
  own last known real, TRACKED category-4 detection gap (only
  `webhook_signature`'s own confirmed-infeasible CWE-347 timing side
  channel remains undetected, for its own distinct, unrelated reason).

### CC-FUZZ-0045 — `HttpHeaderInjectionCrlfStrategy` closes category 4's last known real detection gap (`http_header_injection`); fix: a second, independent `points_from_ground_truth` bug found wiring it in (BUG-0046/PA-0048) (2026-09-23)

- Change: new `fuzzlab/oracle/strategies.py::HttpHeaderInjectionCrlfStrategy`
  (`vuln_class="http_header_injection"`, `category="http-header-injection"`)
  confirms `CC-LAB-0198`'s own deliberately-deferred `TWCH-0013` cell
  (`/channels/redirect?destination=`, CWE-113) with a real two-probe
  CRLF-response-header-injection differential: probe A sends
  `f"fuzzlab-ok\r\n{header_name}: {token}"` (a per-call random,
  never-legitimately-emitted header name/token) and requires the response
  to carry that exact header; probe B (the control) sends the identical
  text with the `\r\n` replaced by a single space and requires the header
  to be ABSENT — ruling out a target that turns an arbitrary input
  substring into a response header for some unrelated reason. Registered
  in `default_strategies()`. `fuzzlab/core/runmode.py::_VULN_TO_CATEGORY`
  gains `"http_header_injection": "http-header-injection"`;
  `fuzzlab/oracle/strategies.py::_CATEGORY_TO_CLASS` gains
  `"http-header-injection": "http_header_injection"` — both checked
  directly before assuming either already existed (per `BUG-0045`'s own
  lesson, not repeated here). Read `fuzzlab/labgen/emitters/go_net_http/
  templates/sinks/raw_socket_response_write.go.j2` (the vulnerable twin's
  own `http.Hijacker` mechanism) before designing this, and empirically
  verified against a live boot, before writing the strategy, that a plain
  `requests`-based sender genuinely observes the spliced-in header (via
  `urllib3`/`http.client`'s own header parser) with no
  normalization/merging defeating observation — a raw-socket-level probe
  turned out to be unnecessary in practice, confirmed rather than assumed.
  New live-boot test: `tests/test_labgen_go_live_boot.py::
  test_http_header_injection_strategy_closes_the_crlf_detection_gap`.
  `tests/test_multitarget_category4.py`'s two independent hardcoded
  recall assertions (grep-counted per PA-0045: exactly 2 occurrences of
  the stale fraction, both updated) move from `12/15` to `13/15`
  (`tp` 12 -> 13, `fp` stays 0).
  Second, independent defect found and fixed in the same change
  (`BUG-0046`/`PA-0048`): `fuzzlab/harness/auto.py::
  points_from_ground_truth`'s `sink_context_by_point` lookup silently
  collapsed `TWCH-0013` (`sink_context="header"`) and `TWCH-0015`
  (`sink_context="redirect"`, `BUG-0045`'s own addition, sharing the same
  `destination` sink) down to whichever case sorted last in
  `ground_truth.cases`, discarding the other's `sink_context` — the new
  `R-HEADER-INJECTION` rule's own `sink_context_in: ["header"]` gate never
  matched that point until this was fixed. Fixed by keeping every DISTINCT
  `sink_context` value per `(url, method, param)` key (a `set`, not a
  scalar) and emitting one audited `InjectionPoint` per distinct value —
  verified harmless against `fuzzlab.harness.scoring.score`'s own
  set-based, vuln_class-keyed dedup (a duplicate point differing only in
  `sink_context` cannot double-count a TP/FP) before relying on it, and
  verified to change nothing for every OTHER point in every existing
  corpus (one case per point, one value in the set, same single point as
  before).
- Impact (other components / project): `FUZZ` (`strategies.py`,
  `runmode.py`, `auto.py`) and `AUD` (`CC-AUD-0026`'s own
  `R-HEADER-INJECTION` rule, this entry's companion). `LAB`'s `CC-LAB-0198`
  entry's own detection follow-on is now closed (no `LAB` change needed —
  the lab page and its ground-truth label already existed). The
  `points_from_ground_truth` fix affects every corpus with a
  multi-vuln_class-per-endpoint case pair going forward, not just Twitch's
  own `TWCH-0013`/`TWCH-0015` — verified to change nothing for every
  other existing point across every corpus (full non-slow suite plus
  every multitarget/live-boot test file re-run, no new failures beyond
  the 18 pre-existing, unrelated PHP Laravel/labgen-CLI ones).
- Risk (level; mitigation or accepted-risk justification): Low. The new
  strategy/rule are purely additive (new class registered, new dict
  entries added, no existing entry changed) and fail closed by
  construction (a target that rejects the CRLF probe, or whose control
  probe also shows the marker, never confirms). The `points_from_ground_
  truth` fix changes point CARDINALITY only for the one point that
  actually has more than one distinct `sink_context` today — mitigated by
  `scoring.py`'s own set-based dedup (read directly, not assumed) and by
  re-running the full non-slow suite plus every multitarget/live-boot
  test file, which found no new failures.
- Deliverables:
  - [x] `HttpHeaderInjectionCrlfStrategy` added and registered — done
  - [x] `_VULN_TO_CATEGORY`/`_CATEGORY_TO_CLASS` entries added, verified
        neither already existed — done
  - [x] Empirically verified (before design) that `requests` observes the
        spliced-in header without normalization defeating it — done
  - [x] Live-boot test added and passing against a real booted app — done
  - [x] `points_from_ground_truth` `sink_context` collapse bug found,
        fixed, and documented (`BUG-0046`/`PA-0048`) — done
  - [x] `tests/test_multitarget_category4.py`'s both independent
        hardcoded recall assertions grep-counted and updated (PA-0045) —
        done
  - [x] Full non-slow suite + all multitarget/live-boot test files
        re-run, no new failures — done
- Effectiveness (assessed 2026-09-23): achieved. Twitch's own real, scored
  recall in `test_both_apps_run_through_multitarget_for_real` moves from
  `12/15` to `13/15` (`tp` 12 -> 13, `fp` 0), verified against a real
  booted app over the real `run_targets`/`RequestsProbeSender` pipeline,
  not merely a hand-built `Candidate` call. This closes this project's own
  last known real category-4 detection gap for the classes it has ground
  truth for (`webhook_signature`'s CWE-347 timing side channel and
  `path_traversal` remain open, each for its own distinct, already-tracked
  reason — not silently claimed closed).

### CC-FUZZ-0044 — fix: `open_redirect` silently unreachable in a scored pipeline -- missing category mapping, then a wrongly-hyphenated strategy `vuln_class` (BUG-0045/PA-0047) (2026-09-23)

- Change: `fuzzlab/core/runmode.py::_VULN_TO_CATEGORY` gains
  `"open_redirect": "open-redirect"`. `fuzzlab/oracle/strategies.py::
  OpenRedirectStrategy.vuln_class` corrected from `"open-redirect"`
  (hyphenated, wrongly copied from its own `category` field) to
  `"open_redirect"` (underscored, matching ground truth's own
  `labels.json` spelling and every other strategy's own convention in the
  file); `_CATEGORY_TO_CLASS["open-redirect"]` updated to `"open_redirect"`
  to match. `tests/test_oracle_vectors.py`'s one affected assertion
  updated. New, stronger generic guard test added: `tests/test_oracle.py::
  test_ground_truth_vuln_classes_with_a_ruled_hyphenated_twin_are_mapped`
  -- scans every real `lab/ground-truth*/labels.json` file's own
  `vuln_class` strings directly (not the oracle's own internal
  `_CATEGORY_TO_CLASS` dict, which `test_every_ruled_strategy_category_
  is_reachable_from_its_vuln_class`, `CC-FUZZ-0034`, checks and which
  stayed silently blind to this exact instance since
  `_CATEGORY_TO_CLASS["open-redirect"]` was itself trivially
  self-consistent, just wrong).
  Found while wiring `LAB`'s `CC-LAB-0199` cell (Twitch's first
  `open_redirect` page) into the real, full `run_targets`/multitarget
  pipeline for the first time: a hand-built `Candidate` confirmed
  `OpenRedirectStrategy` worked directly against the real booted page,
  but the same page showed up as a missed (false negative) finding in the
  real pipeline -- `plan.categories` never included `"open-redirect"`
  because `to_category("open_redirect")` returned the string unchanged
  (defect 1). Adding the missing mapping entry alone then produced a
  false-positive/false-negative pair instead of a true positive, because
  the `finding` row's `vuln_class` (from `Verdict.vuln_class`, i.e.
  `OpenRedirectStrategy.vuln_class`) was `"open-redirect"` while ground
  truth's own `Case.vuln_class` was `"open_redirect"` -- `fuzzlab.harness.
  scoring.score`'s exact `(url, method, param, vuln_class)` key match
  never matched (defect 2, independent of defect 1). Fixing defect 2 also
  surfaced a third, genuine (not a bug) finding, closed in `LAB`'s own
  `CC-LAB-0199` entry, not here: `CC-LAB-0198`'s existing page is
  independently, honestly open-redirect-vulnerable too, at the same
  url/param `R-OPEN-REDIRECT`'s own `name_regex` (`...|dest|...`) already
  matches via `destination`.
- Impact (other components / project): `FUZZ` primarily (`runmode.py`,
  `strategies.py`, their own tests). `LAB`'s `CC-LAB-0199`/`CC-LAB-0198`
  entries depend on this fix to score correctly in the shared multitarget
  pipeline (see `CC-LAB-0199`). Category 5's own Booking.com pilot
  (`BKNG-0001`) shares the identical `open_redirect` root cause for both
  defects and benefits from this fix too, though its own scored-pipeline
  wiring is out of scope for this branch to verify directly.
- Risk (level; mitigation or accepted-risk justification): Low-medium.
  Purely additive/corrective: `_VULN_TO_CATEGORY` gains one entry (no
  existing entry changed), and `OpenRedirectStrategy.vuln_class`'s
  correction only affects what string a `Verdict`/`finding` row for THIS
  vuln class carries -- no other strategy, rule, or dispatch path reads
  that field's literal value except the scorer's own exact-tuple match
  (checked: `category_to_oracle_class`'s only real consumer,
  `GreyboxSignal`'s vuln_class-family split, is scoped to
  `sql-injection`/`xss` only and never reaches `open-redirect`) and the
  web UI's severity mapper (`fuzzlab/web/results.py`), which already
  defensively maps BOTH spellings to the same severity and needed no
  change. Mitigated by a real, live, scored multitarget pipeline
  re-verification (not just the unit-test fake senders) before and after
  each of the two fixes, isolating which defect produced which wrong
  outcome (missed -> false-positive/false-negative pair -> correct true
  positive), per PA-0047's own explicit instruction.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py` -- `_VULN_TO_CATEGORY` entry added
  - [x] `fuzzlab/oracle/strategies.py` -- `OpenRedirectStrategy.vuln_class`
    corrected; `_CATEGORY_TO_CLASS` updated to match
  - [x] `tests/test_oracle_vectors.py` -- one assertion updated
  - [x] `tests/test_oracle.py` -- new guard test,
    `test_ground_truth_vuln_classes_with_a_ruled_hyphenated_twin_are_mapped`,
    verified to fail on the pre-fix code and pass after
  - [x] `tests/test_labgen_go_live_boot.py` -- asserts
    `verdict.vuln_class == "open_redirect"` directly (regression test for
    defect 2)
  - [x] `docs/bugs/BUG-0045-*.md` -- full RCA, prior-PA-failure analysis
  - [x] `docs/PREVENTIVE_ACTIONS.md` -- `PA-0047`
  - [x] `ERROR_LOG.md` -- dated entry
- Effectiveness (assessed 2026-09-23): effective, verified live and end to
  end -- `tests/test_multitarget_category4.py::
  test_both_apps_run_through_multitarget_for_real` scores Twitch
  `tp=12, fp=0` after both fixes + the `TWCH-0015` ground-truth addition
  (was: `TWCH-0014` missed with neither fix; `tp=10, fp=2` with only
  defect 1 fixed, `TWCH-0013`'s own page false-alarming as open-redirect
  once reachable but not yet honestly labeled).

### CC-FUZZ-0043 — fix: oracle-facing `requests`-based senders silently followed HTTP redirects (BUG-0044/PA-0046) (2026-09-23)

- Change: `fuzzlab/tools/probesender.py::RequestsProbeSender.send()`,
  `fuzzlab/greybox/run.py::RequestsCorrelatingSender.send_correlated()`,
  and `fuzzlab/tools/blind_sqli_fuzzer.py::RequestsSender.get()` now all
  pass `allow_redirects=False` explicitly on every `requests` call, matching
  `fuzzlab.core.http`'s own authenticated (`SeamProbeSender`) path, which
  already did. Found while wiring `lab/target-lab`'s `CC-LAB-0198` cell
  (Twitch's first `http_header_injection` page, a `Location:`-header
  redirect endpoint) into the real, full `run_targets`/`RequestsProbeSender`
  pipeline for the first time: the generic, vuln-class-agnostic
  `SstiStrategy` sent its own `#{a*b}` payload as that endpoint's
  `destination` query param; the vulnerable twin echoed it verbatim into
  a real `Location: #{a*b}` response header (its own honest vulnerability,
  CWE-113); `requests`' default redirect-following resolved that bare
  `#`-fragment value to the SAME url on every hop (fragments are never
  sent to the server), an infinite self-redirect loop that crashed
  `run_targets()` with `requests.exceptions.TooManyRedirects`.
  Independently of that crash, `OpenRedirectStrategy` (`fuzzlab/oracle/
  strategies.py`) reads `probe.headers.get("location")` off the FIRST,
  un-followed response -- with redirects silently followed by default, it
  could never have worked correctly against a real target through this
  sender at all (its own unit tests in `tests/test_oracle_vectors.py` use
  hand-rolled fake `Sender`s that hand back the un-followed response
  directly, so this gap was invisible to them).
- Impact (other components / project): `FUZZ` only. No interface/contract
  change -- `Probe`'s own shape is unchanged, only which response it now
  correctly reports. `LAB`'s `CC-LAB-0198` depends on this fix to run
  through the shared multitarget pipeline without crashing.
- Risk (level; mitigation or accepted-risk justification): Low. Purely a
  bug fix restoring the same "report the real response" contract
  `fuzzlab.core.http`'s sibling sender already honors; every existing
  caller of these three senders keeps working (none relied on
  redirect-following, since no prior cell ever exercised it through
  them). Mitigated by updating the fake-session test doubles in `tests/
  test_probesender.py`/`tests/test_fuzzer_seam.py` to accept and record
  `allow_redirects`, plus new regression assertions that it is actually
  `False`.
- Deliverables:
  - [x] `fuzzlab/tools/probesender.py` -- `allow_redirects=False`
  - [x] `fuzzlab/greybox/run.py` -- `allow_redirects=False`
  - [x] `fuzzlab/tools/blind_sqli_fuzzer.py` -- `allow_redirects=False`
  - [x] `tests/test_probesender.py`/`tests/test_fuzzer_seam.py` -- fake
    sessions updated + new regression assertions
  - [x] `docs/bugs/BUG-0044-*.md` -- full RCA, prior-PA-failure analysis
    (`PA-0030`/`BUG-0028`), recurrence review
  - [x] `docs/PREVENTIVE_ACTIONS.md` -- `PA-0046` (supersedes/strengthens
    `PA-0030`)
  - [x] `ERROR_LOG.md` -- dated entry
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    -- new `NFR-FUZZ-response-fidelity`
- Effectiveness (assessed 2026-09-23): Achieved. `tests/
  test_multitarget_category4.py::test_both_apps_run_through_multitarget_
  for_real` reproducibly crashed with `TooManyRedirects` before this fix
  and reproducibly passes after it (verified both ways); `tests/
  test_probesender.py::test_requests_probe_sender_never_follows_
  redirects` and the updated `test_requests_sender_unchanged_standalone_
  behavior` both pass; full non-slow suite green at the stable baseline.

### CC-FUZZ-0042 — `GoTemplateSstiStrategy`: closes `go_net_http`'s SSTI detection gap (2026-09-23)

- Change: builds a genuinely new, Go-`text/template`-syntax-aware
  confirmation strategy closing the real, honestly-documented detection
  gap `CC-LAB-0196` recorded: the existing generic `SstiStrategy`
  (`fuzzlab/oracle/strategies.py`, `mechanism="evaluation-marker"`) does
  NOT confirm Twitch's `TWCH-0012` SSTI cell (`/channels/commands`,
  `go_net_http`'s first `ssti`/`template_render` instance) because its
  arithmetic-product-marker payloads (`_ssti_payloads()`, wrapping
  `a*b` in five template-delimiter styles) are structurally incompatible
  with Go's `text/template`: its action grammar has NO infix arithmetic
  operators at all, so two of the five payloads fail to parse outright
  and the other three are echoed back as inert literal text (real,
  verified via `go run` and a real booted target).
  1. **`fuzzlab/oracle/strategies.py`**: `GoTemplateSstiStrategy`
     (`vuln_class="ssti"`, `mechanism="go-template-len-marker"`). Uses
     `text/template`'s own builtin functions (`len`, `index`, `printf`/
     `print`, the comparison functions), none of which need an infix
     arithmetic operator: `{{ len "AAA...A" }}` (a literal string of `N`
     `A` characters, `N` freshly randomized per probe — a 3-digit range,
     `secrets.randbelow(900) + 100`, matching `SstiStrategy`'s own `a`/
     `b` range) evaluates to the decimal integer `N` only if the engine
     genuinely parses the action and invokes the builtin.
     **False-positive defense, a differential over a single-probe
     heuristic** (this project's own established preference, per
     `InsecureDeserializationTypeConfusionStrategy`'s own docstring): a
     single probe's random `N` coincidentally already appearing
     somewhere in an unrelated normal response is a real, if small,
     risk. Sends TWO independent probes with two distinct random
     lengths `N1 != N2` and confirms only when: neither probe's own
     literal payload is echoed back verbatim (rules out reflection);
     probe 1's response contains `N1` as a whole decimal token
     (word-boundary matched, so `142` doesn't false-match inside
     `31420`); probe 2's response contains `N2` likewise; and NEITHER
     response also contains the OTHER probe's length as a whole token (a
     cross-contamination guard against a cached/stale/echo-everything
     response). For a JSON whole-body point (`content_type ==
     "application/json"`), the marker expression is wrapped as
     `{"template": "<expr>"}` — this lab's own `user_supplied_template_
     compile` sink shape, the same per-target field-name-hardcoding
     convention `PriceTrustDifferentialStrategy`'s/`MassAssignmentPrivileged
     FieldStrategy`'s own docstrings already use; a plain named param
     candidate sends the expression unwrapped.
     **Design decision, checked against this project's own established
     architecture before deciding, not assumed**: a NEW strategy under
     the same `server-side-template-injection` category, not a widened
     `SstiStrategy`. `default_strategies()`'s own registration pattern
     and `Oracle.confirm()`'s multi-strategy-per-category dispatch
     (tries every strategy whose `category` matches in order, stopping
     at the first confirming verdict, no code change needed to add a
     second strategy under one category) already establish exactly this
     "cheaper/broader mechanism first, specialized fallback for a syntax
     family the first one structurally cannot reach next" layering
     (`SsrfInBandMarkerStrategy`/`SsrfOobStrategy`, M1 timing/
     `CommandInjectionOobStrategy`). Folding this into `SstiStrategy.
     confirm()` would make every non-Go target pay for two wasted
     requests on top of its own five, and would conflate two
     structurally different marker techniques in one method, against
     this project's one-mechanism-per-strategy convention. Registered
     directly after `SstiStrategy` in `default_strategies()`.
  2. **No `fuzzlab/audit/` rule change** — verified, not assumed:
     `R-SSTI` already nominates on `sink_context`/location
     (`CC-AUD-0011`), not per-mechanism, so it already covers this
     candidate; grepped to confirm.
- Impact (other components / project): `fuzzlab/oracle/strategies.py`
  (new class + one line in `default_strategies()`); test-only changes to
  `tests/test_oracle_vectors.py` (5 new fake-sender unit tests),
  `tests/test_labgen_go_live_boot.py` (1 new live-boot test), and
  `tests/test_multitarget_category4.py` (Twitch's own scored-recall
  assertions re-derived from `9/12` to `10/12`, `tp` 9 -> 10,
  macro-recall re-derived, per `PA-0044`). No schema, rule, or
  cross-component interface change. `spring_boot`'s existing `SstiStrategy`
  coverage (TrackerNest's `TNEST-0001`) is additive-only and unaffected —
  re-verified live, not assumed (see Deliverables).
- Risk (level; mitigation or accepted-risk justification): low. The new
  strategy is purely additive (a new class + one registration-list
  entry); it does not modify `SstiStrategy` or any shared helper. Its own
  false-positive risk (a coincidental digit match) is mitigated by the
  two-probe, no-cross-contamination differential described above, the
  same evidentiary bar this project's other differential strategies
  (`InsecureDeserializationTypeConfusionStrategy`, `PriceIntegrityBypass
  Strategy`) already use. Its own known limitation (the JSON-field-name
  hardcode `"template"`) is stated explicitly in both the class docstring
  and this entry, matching the project's existing convention for
  per-target field-name-hardcoded strategies — a differently-shaped JSON
  whole-body SSTI sink fails closed rather than misfiring.
- Deliverables:
  - [x] `GoTemplateSstiStrategy` implemented and registered in
    `default_strategies()` — done.
  - [x] Unit tests (`tests/test_oracle_vectors.py`, fake-sender based):
    vulnerable-evaluation case confirms; reflection-only, static/fixed-
    response (including one with unrelated decimal digits — the named
    false-positive class), and stale/cross-contaminated-response cases
    each fail closed — done, 5/5 pass.
  - [x] Real live-boot proof against the real booted `LABGEN-GO-0023`/
    `0024` Twitch cell pair (`tests/test_labgen_go_live_boot.py::
    test_go_template_ssti_strategy_closes_the_generalization_gap`):
    confirms the vulnerable twin, correctly fails closed on the secure
    twin (fixed-map lookup, never evaluates `len` on caller input) —
    done, verified against a real `go build`/boot/HTTP round trip.
  - [x] Re-verified `spring_boot`'s existing TrackerNest SSTI coverage
    stays intact, unmodified: `tests/test_labgen_spring_boot_live_boot.py`'s
    two SSTI live-boot tests and `tests/test_labgen_spring_boot_
    trackernest_multitarget.py` (which drives `TNEST-0001` through
    `SstiStrategy` via the real `run_targets` pipeline) re-run directly
    against a real `mvn package`/boot — done, both green, no regression.
  - [x] Real `fuzzlab.harness.multitarget` pipeline re-run
    (`tests/test_multitarget_category4.py::
    test_both_apps_run_through_multitarget_for_real`): Twitch's own
    real, scored recall moves from `9/12` to `10/12` (`tp` 9 -> 10) —
    done, verified against a real pipeline run, not assumed.
  - [x] Per `PA-0044`/`BUG-0042`: grepped and re-ran `tests/
    test_multitarget_category4.py`, `tests/test_auto.py`, `tests/
    test_labels_contract_category4.py` regardless of `slow` marker —
    done. `test_labels_contract_category4.py`/`test_auto.py` have no
    Twitch-cardinality-dependent hardcoded count affected by this
    change (ground-truth cardinality is unchanged — a pure detection
    increment, not a lab-side change); both re-run and pass unmodified.
  - [x] Full non-slow suite re-run before commit — done (2082 passed, 18
    pre-existing unrelated failures — `gitleaks`/`scikit-learn` missing
    from this sandbox, matching the stable pre-existing baseline; count
    only grew, no new failures).
  - [x] `CHANGELOG.md`, `docs/components/07-fuzzing-harness-and-oracle/
    requirements.md` (`FR-FUZZ-28`), `docs/LAB_MULTI_CATEGORY_SECOND_
    TARGETS_PLAN.md`'s category-4 tracker row, `docs/ARCHITECTURE.md`'s
    current-status paragraph — done.
  **Pre-change review gate, mechanism fidelity noted explicitly (same
  substitution as `CC-LAB-0182`-`0196`'s own precedent wording):** the
  `Agent` tool for a two-independent-reviewer accuracy/adequacy pass was
  not present in this session's toolset (checked via `ToolSearch` before
  concluding this, not assumed absent) — substituted with a documented,
  rigorous self-review performed and recorded here rather than silently
  skipping the gate: (1) **accuracy** — confirmed by direct source
  inspection, not assumed: `SstiStrategy`'s own `_ssti_payloads()`,
  `default_strategies()`'s own registration order, `Oracle.confirm()`'s
  dispatch logic, `R-SSTI`'s own `when` clause, the real vulnerable/
  secure Go sink templates (`user_supplied_template_compile.go.j2`/
  `file_loaded_template_name.go.j2`), and `PriceTrustDifferentialStrategy`'s/
  `InsecureDeserializationTypeConfusionStrategy`'s own docstrings were
  all read directly before designing; the highest-used `CC-FUZZ`/
  `FR-FUZZ`/`CC-AUD` numbers were confirmed by grep (not merely
  mentioned-anywhere) before assigning `CC-FUZZ-0042`/`FR-FUZZ-28`; a
  first draft mistakenly sent the raw marker expression as the entire
  JSON whole-body candidate's value (not wrapped in the sink's own
  `{"template": ...}` field shape) — caught by actually running the real
  `test_multitarget_category4.py` pipeline test (which failed, `tp=9`
  not `10`) rather than assumed correct from the fake-sender unit tests
  alone, and fixed before landing; this correction is recorded here as a
  real caught-before-landing mistake, not silently omitted. (2)
  **adequacy** — checked that no rule/schema change was needed (grepped
  `R-SSTI`'s own `when` clause; confirmed it nominates on
  `sink_context`/location already); checked this does not silently
  duplicate existing detection (grepped for any prior `ssti`-category
  strategy besides `SstiStrategy`: absent); verified live against BOTH
  the real booted vulnerable AND secure Go twins (not just the
  vulnerable one) to rule out a false positive on the secure twin
  specifically; verified TrackerNest's own existing `SstiStrategy`
  coverage is genuinely unaffected by re-running its own live-boot AND
  real-pipeline tests directly, not assumed unaffected by code
  inspection alone; re-ran `tests/test_auto.py`/`tests/
  test_labels_contract_category4.py` directly per `PA-0044`/`BUG-0042`
  rather than assuming they were unaffected by analogy to prior entries;
  and ran the full non-slow suite before committing, confirming the
  pass count only grew against the stable 18-failure baseline.
- Effectiveness (assessed 2026-09-23): met its intent. `TWCH-0012` moved
  from a documented false negative to a real, confirmed finding through
  the actual `fuzzlab.harness.multitarget` pipeline (`tp` 9 -> 10,
  recall `9/12` -> `10/12`), verified against a real booted Go app, with
  zero regression to `spring_boot`'s existing SSTI coverage (re-verified
  live) and zero rule/schema change needed.

### CC-FUZZ-0041 — `PriceTrustDifferentialStrategy`: real detection for `price_integrity_bypass` (2026-09-23)

- Change: builds the deliberately-deferred detection follow-on
  `CC-LAB-0188` flagged: an oracle confirmation strategy for
  `price_integrity_bypass` (CWE-807), closing Netflix's `NFLX-0005`
  structural detection zero — this project's first-ever rule/strategy
  pair for this vuln class (a real implementation already exists on two
  stacks, `php_laravel`'s Booking.com checkout, `CC-LAB-0212`, and
  `spring_boot`'s Netflix plan-change endpoint, `CC-LAB-0188`, but
  neither had any detection capability before this entry).
  1. **`fuzzlab/oracle/strategies.py`**: `PriceTrustDifferentialStrategy`
     (`vuln_class="price_integrity_bypass"`, `mechanism=
     "client-price-trust-differential"`). Checked
     `MassAssignmentPrivilegedFieldStrategy`'s own docstring/pattern
     before designing from scratch, per this task's own explicit
     instruction: both hardcode the sink's own known field name(s)
     directly in the strategy (this project's existing per-target
     field-name-hardcoding convention), both gate on `content_type ==
     "application/json"` and fail closed otherwise, and both require a
     matching two-probe result rather than a bare single-probe 200 as
     evidence. Unlike a strategy that would need to know the target's
     own real price in advance (which a genuine black-box fuzzer never
     does), this strategy needs no such prior knowledge: it sends the
     same `plan_tier` twice with two deliberately different, implausible
     amounts (`0.01`, then `999999.99`) and confirms only if the
     server's own reported `monthly_charge` tracks *both* submitted
     amounts exactly (proof the charge moves with whatever the client
     sends); a target whose reported charge stays identical across both
     probes (the secure, server-recomputed shape -- the real charge for
     a fixed `plan_tier` never changes) fails closed, correctly, rather
     than being treated as ambiguous evidence -- the same "does the
     sink's own output move with this specific input" reasoning
     `MassAssignmentPrivilegedFieldStrategy`'s own two-probe differential
     already uses for a boolean field, generalized here to a numeric
     one. Registered in `default_strategies()` and `_CATEGORY_TO_CLASS`.
  2. **`fuzzlab/core/runmode.py`**: `_VULN_TO_CATEGORY` gained
     `"price_integrity_bypass": "price-integrity-bypass"` — checked and
     fixed proactively (`test_every_ruled_strategy_category_is_
     reachable_from_its_vuln_class` re-run and stays green), the same
     recurring underscore/hyphen gap `CC-FUZZ-0040` already documented
     for its own seventh instance; this is at least an eighth.
  3. **A real, pre-existing ground-truth defect found and fixed during
     this entry's own real end-to-end pipeline verification** (not
     silently left for a later discovery, and not routed around):
     `NFLX-0005`'s ground truth (landed by `CC-LAB-0188`) originally used
     `param="monthly_charge"` (a per-named-field convention modeled on
     `NFLX-0004`'s own query-param case), but
     `fuzzlab.harness.auto.points_from_ground_truth` only marks a
     `location="body"` point's Content-Type as `application/json` when
     `param == "body"` exactly (the same gate `CC-LAB-0182`'s own
     `mass_assignment` ground truth already had to satisfy) — a
     per-field `param` name for a body point silently starves this
     strategy of the JSON point it needs when driven through the real
     harness, even though the strategy's own dedicated unit/live-boot
     tests (which construct a `Candidate` directly and never touch
     `points_from_ground_truth`) never hit this gate and so never
     revealed it. Found by running `points_from_ground_truth` directly
     against the real ground truth and inspecting the resulting point's
     own `body_content_type` (`None`, not `"application/json"`), not
     assumed correct from the unit/live-boot tests' own green result
     alone. **Corrected in place** in `lab/ground-truth-netflix-clone/`
     (`labels.json`/`injection-points.json`/`expectedresults.csv`,
     living-doc discipline) to `param="body"`, the same whole-body
     convention `NFLX-0001`-`0003` use — re-verified directly afterward:
     `points_from_ground_truth` now reports
     `body_content_type="application/json"` for this point. The
     correction changes nothing about what either twin does or what the
     strategy sends; `docs/components/01-target-lab/requirements.md`'s
     own `FR-LAB-143` was also corrected in place to match (living-doc
     discipline), rather than left describing the wrong convention
     `CC-LAB-0188` originally shipped. This same correction also fixed a
     **real regression `CC-LAB-0188`'s own commit had silently
     introduced** into `tests/test_multitarget_category4.py`'s two
     `@pytest.mark.slow` tests (not caught by that commit's own
     non-slow-suite run before pushing, since both affected tests are
     slow-marked and therefore deselected by `-m "not slow"`): merely
     adding `NFLX-0005` to the ground truth changed Netflix's own total
     positive count from 4 to 5, which — independently of this entry's
     own new cell/strategy — dropped `test_both_apps_run_through_
     multitarget_for_real`'s `1/4` recall assertion and
     `test_netflix_multi_cell_boot_confirms_all_positives`'s `4/4`
     assertion to failing, since neither actually matched reality
     anymore. Found by actually re-running the full slow suite during
     this entry's own work (not assumed clean from the non-slow run
     alone, `PA-0040`'s own discipline extended to the slow suite too,
     not just the default one) and fixed here, in the same commit as the
     new detection capability that also closes the gap those two tests'
     own assertions needed updating for anyway.
  4. **Real, executed live-boot proof**
     (`tests/test_oracle_strategies_price_integrity_live_boot.py`, driven
     through the real `RequestsProbeSender` against a real booted
     `LABGEN-JV-0009`/`0010` cell pair, never a fake sender): the
     strategy confirms the vulnerable twin (`low=0.01`, `high=999999.99`,
     both tracked exactly) and correctly returns `None` (fails closed) on
     the secure twin, whose reported charge stays fixed at the real
     Standard price across both probes.
  5. **Unit tests** (`tests/test_oracle_strategies_price_integrity.py`,
     10 tests, fake-sender based, mirroring `test_oracle_strategies_mass_
     assignment.py`'s own vulnerable/secure-twin pattern): the vulnerable
     `client_trusted_amount` twin confirms; the secure `server_
     recomputed_amount` twin fails closed; a dedicated false-positive-
     avoidance case (a target that always returns the same fixed low
     amount regardless of input) fails closed; a non-JSON candidate, a
     missing-field response, and a rejected probe B each fail closed;
     the rule matches/doesn't-match-a-query-point/doesn't-match-an-
     unrelated-sink-context cases; and the registration check.
  6. **`tests/test_multitarget_category4.py`**: updated for the new real
     confirmation and the ground-truth correction above —
     `test_both_apps_run_through_multitarget_for_real`'s Netflix recall
     assertion moves from `1/4` to `1/5` (the single-cell-boot test still
     only boots `LABGEN-JV-0001`, so its own `tp` is unchanged at 1; only
     the denominator changed, correctly, now that Netflix has five real
     positives); `test_netflix_multi_cell_boot_confirms_all_positives` is
     extended to also assemble `LABGEN-JV-0009`
     (`price_integrity_netflix_subscription_sample.yaml`) into the same
     real multi-cell boot, and Netflix's own real, scored recall in that
     boot moves from 4/4 to 5/5 (`tp=5, fp=0`) — re-verified against a
     real booted app through the real `run_targets` pipeline, not
     assumed from the unit/live-boot tests alone.
  7. **A second, structurally identical regression found the same way**
     (a full, non-slow-suite re-run after the correction above, not
     assumed clean from the slow-test fix alone): `tests/test_auto.py::
     test_points_from_ground_truth_sets_body_content_type_only_for_json_cases`
     hardcoded Netflix's own whole-body-JSON point count at 3 (before
     this entry's `NFLX-0005` correction added a fourth); found by
     actually re-running the full non-slow suite after item 3's own fix
     landed, not assumed sufficient from the slow-test fix alone —
     updated to expect 4 and to assert the new `/api/subscription/
     change-plan` point's own `body_content_type ==
     "application/json"` explicitly, the same per-URL assertion style
     the existing three points already use.
  New/changed files:
  - `fuzzlab/oracle/strategies.py` (new `PriceTrustDifferentialStrategy` +
    `_json_number_field` helper; registered in `default_strategies()`
    and `_CATEGORY_TO_CLASS`)
  - `fuzzlab/core/runmode.py` (`_VULN_TO_CATEGORY` entry)
  - `fuzzlab/audit/rules_data/default_rules.json` (see `CC-AUD-0025`)
  - `lab/ground-truth-netflix-clone/{labels.json,injection-points.json,expectedresults.csv}`
    (`NFLX-0005`'s `param` corrected from `"monthly_charge"` to `"body"`)
  - `docs/components/01-target-lab/requirements.md` (`FR-LAB-143`
    corrected in place to match)
  - `tests/test_oracle_strategies_price_integrity.py` (new)
  - `tests/test_oracle_strategies_price_integrity_live_boot.py` (new)
  - `tests/test_auto.py` (whole-body-JSON point count updated, item 7)
  - `tests/test_multitarget_category4.py` (recall assertions updated;
    multi-cell boot extended)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-27`, new)
- Impact (other components / project): `default_strategies()` is shared
  across every target's own run — purely additive (a new strategy scoped
  by `category`, never fired for a candidate of a different category).
  The ground-truth `param` correction is scoped to `NFLX-0005` alone; no
  other case in any ground-truth directory used that field or that
  convention incorrectly (checked). No other target's ground truth
  currently uses `sink_context="payment_charge"` (Booking.com's own cell
  uses `"sql"` — see `CC-AUD-0025`'s own explicit, recorded scoping
  decision for why this entry's rule does not also reach it), so no
  other target's scoring changes. Paired with `CC-AUD-0025` (rule) — see
  that entry for the full rule record and pre-change review.

### CC-FUZZ-0040 — `UnrestrictedFileUploadContentTypeTrustStrategy`: real detection for `unrestricted_file_upload` (2026-09-23)

- Change: builds the deliberately-deferred detection follow-on
  `CC-LAB-0186` flagged: an oracle confirmation strategy for
  `unrestricted_file_upload` (CWE-434), closing Twitch's `TWCH-0009`
  structural detection zero — this project's first-ever rule/strategy
  pair for this vuln class, and its first-ever real `multipart/form-data`
  probe of any kind.
  1. **`fuzzlab/oracle/strategies.py`**: `UnrestrictedFileUploadContent
     TypeTrustStrategy` (`vuln_class="unrestricted_file_upload"`,
     `mechanism="extension-content-type-trust-differential"`). Read both
     real Go sink templates (`no_extension_check.go.j2`/
     `extension_allowlist_mime_check.go.j2`) before designing: both
     twins write-and-serve in the *same* POST response, so this strategy
     reads the upload response's own `Content-Type` header directly —
     no separate GET-the-served-file round trip exists on this stack.
     Two real, hand-encoded `multipart/form-data` probes (`_multipart_
     body`): probe A uploads `probe.svg` (a plausible image extension)
     whose bytes are an inert marker
     (`<!DOCTYPE html><p>FUZZLAB-MARKER-...</p>`, per `NFR-AUD-safe` —
     never an executing `<script>` tag, the same convention
     `CC-LAB-0186`'s own live-boot test already uses) that is NOT valid
     image content of any kind; confirms only a first condition from
     this leg — HTTP 2xx, the marker echoed back verbatim, and a
     response `Content-Type` in a named, bounded
     `_SCRIPT_EXECUTABLE_CONTENT_TYPES` set (`text/html`/`image/svg+xml`/
     etc. — deliberately never a bare "isn't a safe raster type"
     heuristic, which would over-claim on a harmless-but-unusual type
     like `application/octet-stream`). Probe B (the differentiator and
     the strategy's own false-positive defense, the same "two-probe, not
     a bare single-probe heuristic" reasoning
     `InsecureDeserializationTypeConfusionStrategy`'s own docstring
     argues for) uploads `control.png`, a real, minimal, valid 67-byte
     PNG (`_MINIMAL_PNG_BYTES`); confirms only if that upload is *also*
     accepted and its own response `Content-Type` is a genuine safe
     raster type (`_SAFE_RASTER_CONTENT_TYPES`). Requiring both legs
     rules out a legitimate SVG-accepting endpoint (which would also,
     correctly, serve `image/svg+xml` for a genuinely real SVG upload —
     not a vulnerability on its own) and a generically-permissive/broken
     target that serves every upload with the same dangerous type
     regardless of content — probe A alone is not sufficient evidence.
     Registered in `default_strategies()`.
  2. **`fuzzlab/core/runmode.py`**: `_VULN_TO_CATEGORY` gained
     `"unrestricted_file_upload": "unrestricted-file-upload"` — the
     seventh instance of this session's own recurring underscore/hyphen
     naming gap, checked and fixed proactively this time rather than
     found after the fact by the structural guard test (re-run and still
     green: `test_every_ruled_strategy_category_is_reachable_from_its_
     vuln_class`).
  3. **`fuzzlab/tools/probesender.py`**: a real, narrowly-scoped `Sender`
     extension, found necessary while implementing probe B. This
     project's `Sender` interface carries a whole-body value as a plain
     `str`, and both real senders (`RequestsProbeSender`/
     `SeamProbeSender`) previously always re-encoded it via `.encode
     ("utf-8")` — correct for the JSON/XML bodies every prior whole-body
     strategy sends, but probe B's own real PNG magic bytes (all
     `>= 0x80`) would be corrupted by a utf-8 re-encoding (each such byte
     turning into a multi-byte utf-8 sequence instead of round-tripping
     1:1). Fixed by encoding the multipart body into `value` as latin-1
     (a lossless 1:1 byte<->codepoint mapping, the same convention
     `fuzzlab.proxy`/`fuzzlab.web` already use for raw bytes) and, in
     both senders, re-encoding via latin-1 instead of utf-8 specifically
     when `content_type.startswith("multipart/")` — every other
     whole-body content type (`application/json`, XML) is untouched, so
     no existing sender behavior changed; re-ran `tests/
     test_probesender.py` and the mass-assignment/insecure-
     deserialization/XXE strategy suites unmodified-in-assertion to
     confirm.
  4. **Real, live-boot proof**
     (`tests/test_oracle_strategies_unrestricted_file_upload_live_boot.py::
     test_real_boot_confirms_the_vulnerable_twin_and_fails_closed_on_the_
     secure_twin`, driven through the real `RequestsProbeSender` against
     a real booted `LABGEN-GO-0017`/`0018` cell pair, never a fake
     sender): the strategy confirms the vulnerable twin (`served_content_
     type == "image/svg+xml"`, `control_content_type == "image/png"`)
     and correctly returns `None` (fails closed) on the secure twin,
     which rejects `probe.svg` outright (its extension is not
     allowlisted). Every write this test causes lands under
     `GoLiveBootHarness`'s own throwaway `tempfile.TemporaryDirectory`-
     backed process `cwd`, never a real/permanent/shared path.
  5. **Unit tests**
     (`tests/test_oracle_strategies_unrestricted_file_upload.py`, 10
     tests, fake-sender based, mirroring `test_oracle_strategies_mass_
     assignment.py`'s own vulnerable/secure-twin pattern): the vulnerable
     `no_extension_check` twin confirms; the secure `extension_allowlist_
     mime_check` twin fails closed; two dedicated false-positive-
     avoidance cases fail closed (a target that serves every upload as
     `text/html` regardless of content, and one that serves everything
     as the harmless `application/octet-stream`); a target that rejects
     both probes fails closed; the rule matches/doesn't-match cases; and
     the registration/`_VULN_TO_CATEGORY` reachability checks.
  6. **`tests/test_multitarget_category4.py`**: updated for the new real
     confirmation — Twitch's own real, scored recall moves from 7/9 to
     8/9 (`tp=8, fp=0`) in `test_both_apps_run_through_multitarget_for_
     real`, and the combined `macro_recall` assertion updated to match;
     re-verified against a real booted app through the real `run_targets`
     pipeline, not assumed from the unit/live-boot tests alone.
  New/changed files:
  - `fuzzlab/oracle/strategies.py` (new
    `UnrestrictedFileUploadContentTypeTrustStrategy` +
    `_multipart_body`/`_response_content_type` helpers +
    `_MINIMAL_PNG_BYTES`/`_SAFE_RASTER_CONTENT_TYPES`/
    `_SCRIPT_EXECUTABLE_CONTENT_TYPES` constants; registered in
    `default_strategies()` and `_CATEGORY_TO_CLASS`)
  - `fuzzlab/core/runmode.py` (`_VULN_TO_CATEGORY` entry)
  - `fuzzlab/tools/probesender.py` (latin-1 multipart-body encoding in
    both `RequestsProbeSender`/`SeamProbeSender`)
  - `fuzzlab/audit/rules_data/default_rules.json` (see `CC-AUD-0023`)
  - `tests/test_oracle_strategies_unrestricted_file_upload.py` (new)
  - `tests/test_oracle_strategies_unrestricted_file_upload_live_boot.py`
    (new)
  - `tests/test_multitarget_category4.py` (recall assertions updated)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-26`, new)
- Impact (other components / project): `default_strategies()` is shared
  across every target's own run — purely additive (a new strategy scoped
  by `category`, never fired for a candidate of a different category).
  The `probesender.py` change is scoped to the `content_type.startswith
  ("multipart/")` branch only; no other whole-body sender path (JSON/XML)
  is affected. No other ground truth in the project currently uses
  `fs_web_root_write`/`unrestricted_file_upload`, so no other target's
  scoring changes. Paired with `CC-AUD-0023` (rule) — see that entry for
  the full rule record and pre-change review.

### CC-FUZZ-0039 — `MassAssignmentPrivilegedFieldStrategy`: real detection for `mass_assignment` (2026-09-23)

- Change: adds the deliberately-separated detection follow-on `CC-LAB-0182`
  flagged: an oracle confirmation strategy for `mass_assignment`
  (CWE-915), closing Twitch's `TWCH-0006` structural detection zero —
  this project's first-ever rule/strategy pair for this vuln class at
  all (`mass_assignment` lab pages already exist on three other stacks,
  `php_current`/`ruby_rails`/`php_laravel`, but none had any detection
  capability before this entry).
  1. **`fuzzlab/oracle/strategies.py`**: `MassAssignmentPrivilegedFieldStrategy`
     (`vuln_class="mass_assignment"`, `mechanism=
     "privileged-field-injection"`). Two probes over a hardcoded, known
     JSON body field (`is_partner`, this stack's own privileged field —
     the same "hardcode the sink's own known field name" convention
     `PredictableTokenSourceStrategy`'s `session_token`/
     `JwtAlgNoneConfusionStrategy`'s `channel_id`/`role` claims already
     use): probe A sends only the intended fields (`display_name`/`bio`)
     plus a per-run marker, and requires the privileged field to read
     back `false`; probe B additionally sets the privileged field to
     `true` in the same JSON body, and requires it to read back `true`.
     Confirms only on that specific `false`-to-`true` transition — never
     a bare "does the endpoint ever return `true`" check, which would
     false-positive against a generically-permissive/broken target (the
     same reasoning `JwtAlgNoneConfusionStrategy`'s own two-probe
     differential already documents). Registered in `default_strategies()`
     and `_CATEGORY_TO_CLASS`.
  2. **A real ground-truth defect found and fixed before landing, not
     assumed correct from unit tests alone**: the lab-page commit's own
     first-draft ground truth (`CC-LAB-0182`) used `param="is_partner"`
     (the privileged field name, matching `ruby_rails`'s own
     `FCART-0004` convention), but `fuzzlab.harness.auto.
     points_from_ground_truth` only marks a body point's content type as
     `application/json` when `param == "body"` exactly — a real,
     deliberately narrow gate this strategy's own `content_type` check
     depends on. Running the real `run_targets()` pipeline end to end
     (not just this strategy's own fake-sender unit tests, which used a
     hand-built `Candidate` and so never exercised that gate) showed
     `tp=4` instead of the expected `5`; traced to the missing
     content-type detection and fixed by changing the ground truth to
     the `param="body"`/`location="body"` whole-body-point convention
     `weak_token_entropy`'s own `TWCH-0005` already uses, before either
     commit landed (`CC-LAB-0182`'s own change-control entry records the
     same correction on the lab-page side).
  3. **`fuzzlab/core/runmode.py`**: `_VULN_TO_CATEGORY` gained
     `"mass_assignment": "mass-assignment"` — the sixth instance of the
     recurring underscore/hyphen gap, caught automatically by the
     structural guard test (`tests/test_oracle.py`) before it could ever
     manifest as a silent non-firing rule.
  4. **`fuzzlab/audit/rules_data/default_rules.json`**: `R-MASS-
     ASSIGNMENT` (see the paired `CC-AUD-0022` entry for the rule
     itself).
  - Dispatched through this component's mandatory pre-change review
    gate. No `Agent`/`Task` tool was available in this session's toolset
    to run the gate's own two-independent-parallel-reviewer-session
    mechanism; per this project's multi-agent-orchestration fidelity
    rule, that substitution is flagged here rather than silently made:
    the design was instead verified by a rigorous self-review pass
    (accuracy: every claim checked against a real, executed
    `run_targets()` run against a real booted app — which is exactly
    what caught defect item 2 above before it could land; adequacy: the
    two-probe transition-based confirm logic, the field-name-hardcoding
    convention choice, and the content_type fail-closed gate were each
    explicitly re-derived from existing precedent). A real, documented
    gap in review independence versus every prior entry in this log, not
    claimed as equivalent to it.
  New/changed files:
  - `fuzzlab/oracle/strategies.py`
  - `fuzzlab/core/runmode.py`
  - `fuzzlab/audit/rules_data/default_rules.json` (shared with `CC-AUD-0022`)
  - `tests/test_oracle_strategies_mass_assignment.py` (new)
  - `tests/test_labgen_go_live_boot.py` (new
    `test_real_boot_proves_the_mass_assignment_strategy_end_to_end`)
  - `tests/test_multitarget_category4.py` (Twitch's real, scored recall
    moves from 4/6 to 5/6)
  - `lab/ground-truth-twitch-clone/{labels.json,injection-points.json,
    expectedresults.csv}` (the `param="body"` correction, item 2 above)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-25`, new)
- Impact (other components / project): `fuzzlab/oracle/strategies.py`,
  `fuzzlab/core/runmode.py`, and `fuzzlab/audit/rules_data/
  default_rules.json` are shared across every category/target.
  `fuzzlab.harness.multitarget`'s real, scored Twitch report for
  category 4's own Phase E test now shows `tp=5` instead of `tp=4`.
- Risk (level; mitigation or accepted-risk justification): Low. The
  transition-based confirm logic (both a `false` baseline and a
  `true` after-state required, not a bare truthy check) directly closes
  the "generically permissive target" false-positive class; the
  documented known limitation (fails closed, never misfires, against a
  differently-shaped mass-assignment endpoint such as `FCART-0004`) is
  an accepted, explicit scope boundary, not a silent gap.
- Deliverables:
  - [x] `MassAssignmentPrivilegedFieldStrategy` implemented, registered,
        unit-tested (vulnerable/secure/always-true-permissive/
        non-JSON/missing-field cases) — done
  - [x] The ground-truth `param` convention defect found and fixed
        before landing — done
  - [x] Real live-boot proof against Twitch's real booted twins — done
  - [x] `test_multitarget_category4.py` updated to the new real recall
        and re-run against a real double live boot — done
  - [x] Full non-slow suite re-run green at the stable baseline — done
- Effectiveness (assessed 2026-09-23): achieved. Twitch's real, scored
  `multitarget` recall moved from 4/6 to 5/6 (`tp=5, fp=0`), proven by a
  real, executed `run_targets()` call against a real booted app, and the
  strategy independently confirms/fails-closed correctly against real
  live-booted vulnerable/secure twins (`tests/test_labgen_go_live_boot.py`).

### CC-FUZZ-0038 — `PredictableTokenSourceStrategy`: real detection for `weak_token_entropy` (2026-09-23)

- Change: adds the deliberately-separated detection follow-on `CC-LAB-0181`
  flagged: an oracle confirmation strategy for `weak_token_entropy`
  (CWE-330), closing Twitch's `TWCH-0005` structural detection zero.
  1. **`fuzzlab/oracle/strategies.py`**: `PredictableTokenSourceStrategy`
     (`vuln_class="weak_token_entropy"`, `mechanism=
     "timestamp-derived-token"`). Two ordinary probes; parses each
     response's `session_token` field; confirms iff both parse as
     base-10 integers with a non-negative delta under a fixed
     `_DELTA_CEILING_NS` (10 seconds in nanoseconds) — a generous,
     jitter-immune backstop, not a precise measured-elapsed-time bound
     (a design correction from an earlier draft's `time.time()`-based
     window, per the adequacy pass). Registered in `default_strategies()`
     and `_CATEGORY_TO_CLASS`.
  2. **Primary false-positive defense named explicitly**: the hex-vs-
     decimal parse gate, not delta-window tightness — a real
     `crypto/rand`-sourced 64-character hex token essentially never
     parses as an all-decimal integer (`(10/16)^64 ≈ 8.6e-14`, corrected
     by the accuracy-review pass from an earlier draft's off-by-~5x
     estimate of `4e-13`).
  3. **`Verdict.evidence` deliberately never records a full raw token
     value** — only an 8-character prefix of each plus the computed
     delta (`token_a_prefix`/`token_b_prefix`/`delta_ns`). These are the
     target's own issued session-token-shaped values, unlike this file's
     existing strategies' own self-minted OOB canary tokens, an
     adequacy-pass requirement.
  4. **`fuzzlab/core/runmode.py`**: `_VULN_TO_CATEGORY` gained
     `"weak_token_entropy": "weak-token-entropy"` — the fifth instance
     of the recurring underscore/hyphen gap, caught automatically by the
     structural guard test.
  5. **`fuzzlab/audit/rules_data/default_rules.json`**: `R-WEAK-TOKEN-
     ENTROPY` (see the paired `CC-AUD-0021` entry for the rule itself).
  - Dispatched through this component's mandatory pre-change review gate
    (accuracy + adequacy passes). Accuracy pass found and corrected the
    false-positive probability math (item 2 above) before implementation.
    Adequacy pass required: (a) removing dead code left over from an
    abandoned measured-elapsed-time design (a `t_mid = time.time()`
    variable that was no longer used once the fixed-ceiling design
    replaced it); (b) sending `"{}"` rather than an empty string as the
    probe body (the point's own `content_type="application/json"` means
    an empty string is not valid JSON, risking a framework-level 400
    before the handler that ignores the body is even reached — a
    robustness fix, both real twins ignore the body either way); (c) the
    raw-token redaction (item 3 above).
  New/changed files:
  - `fuzzlab/oracle/strategies.py`
  - `fuzzlab/core/runmode.py`
  - `fuzzlab/audit/rules_data/default_rules.json` (shared with `CC-AUD-0021`)
  - `tests/test_oracle_strategies_weak_token_entropy.py` (new)
  - `tests/test_labgen_go_live_boot.py` (new
    `test_real_boot_proves_the_weak_token_entropy_strategy_end_to_end`)
  - `tests/test_multitarget_category4.py` (Twitch's real, scored recall
    moves from 3/5 to 4/5)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-24`, new)
- Impact (other components / project): `fuzzlab/oracle/strategies.py`,
  `fuzzlab/core/runmode.py`, and `fuzzlab/audit/rules_data/
  default_rules.json` are shared across every category/target (fresh
  `git show` collision check against category-2/3/5 and
  second-target-cat1-ecommerce before landing — all behind this branch's
  own prior commits, no independent edits). `fuzzlab.harness.multitarget`'s
  real, scored Twitch report for category 4's own Phase E test now shows
  `tp=4` instead of `tp=3`.
- Risk (level; mitigation or accepted-risk justification): Low. The
  parse-gate defense and fixed ceiling together directly close the
  false-positive classes the review passes named; one narrow, documented,
  accepted edge case remains (a target that always issues the literal
  same token value also confirms, since a delta of exactly 0 is not
  itself treated as suspicious — pinned by a dedicated test rather than
  left as a silent surprise).
- Deliverables:
  - [x] `PredictableTokenSourceStrategy` implemented, registered,
        unit-tested (vulnerable/secure/missing-field/zero-delta-edge-case
        cases) — done
  - [x] The false-positive-math correction and raw-token redaction
        applied before implementation — done
  - [x] Real live-boot proof against Twitch's real booted twins — done
  - [x] `test_multitarget_category4.py` updated to the new real recall
        — done
  - [x] Full non-slow suite re-run green at the stable baseline — done
- Effectiveness (assessed 2026-09-23): achieved. Twitch's real, scored
  `multitarget` recall moved from 3/5 to 4/5 (`tp=4, fp=0`), proven by a
  real, executed `run_targets()` call against a real booted app, and the
  strategy independently confirms/fails-closed correctly against real
  vulnerable/secure twins via a dedicated live-boot test, not only
  mocked senders.

### CC-FUZZ-0037 — `JwtAlgNoneConfusionStrategy`: real detection for `jwt_algorithm_confusion` (2026-09-23)

- Change: adds the deliberately-separated detection follow-on `CC-LAB-0180`
  flagged: an oracle confirmation strategy for `jwt_algorithm_confusion`
  (CWE-347), closing Twitch's `TWCH-0004` structural detection zero.
  1. **`fuzzlab/oracle/strategies.py`**: `JwtAlgNoneConfusionStrategy`
     (`vuln_class="jwt_algorithm_confusion"`, `mechanism=
     "alg-none-bypass"`). A two-probe differential over a header-carried
     Bearer token, mirroring `InsecureDeserializationTypeConfusionStrategy`'s
     own two-probe shape: probe A (an unsigned `alg:none` token, a
     freshly-minted marker carried in its `channel_id` claim — the
     literal field `CC-LAB-0180`'s own sink echoes, not an arbitrary
     field) must return HTTP 200 with the marker echoed back; probe B
     (the same marker, claiming `HS256` with a garbage signature) must
     return a real auth-rejection status (401/403 specifically) — ruling
     out both a generically-permissive endpoint and an unrelated
     parsing-crash false positive. Registered in `default_strategies()`
     and `_CATEGORY_TO_CLASS`.
  2. **`fuzzlab/core/runmode.py`**: `_VULN_TO_CATEGORY` gained
     `"jwt_algorithm_confusion": "jwt-algorithm-confusion"` — the fourth
     instance of the recurring underscore/hyphen gap this session's own
     structural guard test now catches automatically (no manual trace
     needed this time). Stale comment referencing the guard test's old
     pre-rename name also corrected.
  3. **`fuzzlab/audit/rules_data/default_rules.json`**: `R-JWT-ALG-NONE`
     (see the paired `CC-AUD-0020` entry for the rule itself).
  - Dispatched through this component's mandatory pre-change review gate
    (accuracy + adequacy passes). Accuracy pass found a real, blocking
    defect in the first draft before implementation: the marker was
    planned to travel in an arbitrary `{"marker": ...}` JSON field, which
    the real sink template (`jwt_claims_response.go.j2`) silently drops
    (it only unmarshals `channel_id`/`role`) — the strategy would have
    permanently returned `None` against a real boot despite passing
    every unit test with a hand-built fake sender. Corrected to carry
    the marker in `channel_id` before implementation, not discovered
    after. Adequacy pass required: (a) tightening probe B's pass
    condition from "any non-200" to specifically 401/403 (item in
    mechanism above); (b) an explicit docstring "known limitation"
    section (non-JWT `Authorization` schemes fail closed, don't
    misfire); (c) dropping "bearer" from the rule's `name_regex`
    (a header *value* prefix, not a header name — dead/misleading
    weight in a name-matching regex).
  New/changed files:
  - `fuzzlab/oracle/strategies.py`
  - `fuzzlab/core/runmode.py`
  - `fuzzlab/audit/rules_data/default_rules.json` (shared with `CC-AUD-0020`)
  - `tests/test_oracle_strategies_jwt_alg_none.py` (new)
  - `tests/test_labgen_go_live_boot.py` (new
    `test_real_boot_proves_the_jwt_alg_none_strategy_end_to_end`)
  - `tests/test_multitarget_category4.py` (Twitch's real, scored recall
    moves from 2/4 to 3/4)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-23`, new)
- Impact (other components / project): `fuzzlab/oracle/strategies.py`,
  `fuzzlab/core/runmode.py`, and `fuzzlab/audit/rules_data/
  default_rules.json` are shared across every category/target (fresh
  `git show` collision check against category-2/3/5 and
  second-target-cat1-ecommerce before landing — all behind this branch's
  own prior commits, no independent edits). `fuzzlab.harness.multitarget`'s
  real, scored Twitch report for category 4's own Phase E test now shows
  `tp=3` instead of `tp=2`.
- Risk (level; mitigation or accepted-risk justification): Low. The
  two-probe differential and its 401/403-specific control-probe check
  directly close the false-positive classes the review passes named;
  the strategy's own docstring states its one residual limitation
  (non-JWT `Authorization` header targets) explicitly rather than
  leaving it implicit.
- Deliverables:
  - [x] `JwtAlgNoneConfusionStrategy` implemented, registered,
        unit-tested (vulnerable/secure/false-positive/crash cases) — done
  - [x] The marker-field defect found by the accuracy pass fixed before
        implementation — done
  - [x] Real live-boot proof against Twitch's real booted twins — done
  - [x] `test_multitarget_category4.py` updated to the new real recall
        — done
  - [x] Full non-slow suite re-run green at the stable baseline — done
- Effectiveness (assessed 2026-09-23): achieved. Twitch's real, scored
  `multitarget` recall moved from 2/4 to 3/4 (`tp=3, fp=0`), proven by a
  real, executed `run_targets()` call against a real booted app, and the
  strategy independently confirms/fails-closed correctly against real
  vulnerable/secure twins via a dedicated live-boot test, not only
  mocked senders.

### CC-FUZZ-0036 — Netflix's own multi-cell boot confirms both real positives together (2026-09-23)

- Change: `tests/test_multitarget_category4.py` gained
  `test_netflix_multi_cell_boot_confirms_both_positives`, closing the
  follow-on `CC-FUZZ-0035`'s own module-docstring update flagged: proving
  `NFLX-0002` (XXE) through the real generic `run_targets` pipeline
  against a real boot, not only via `tests/test_labgen_spring_boot_xxe_
  live_boot.py`'s dedicated proof or TrackerNest's own multitarget test.
  A hand-rolled multi-cell Spring Boot boot (`shutil.copytree(SKELETON_DIR,
  ...)` + a real `mvn package` + `java -jar`), mirroring `tests/
  test_labgen_spring_boot_trackernest_multitarget.py`'s own established
  pattern exactly (no new mechanism invented): assembles `LABGEN-JV-0001`
  (insecure-deserialization, `/api/playback/resume`) and `LABGEN-JV-0003`
  (XXE, `/api/content/import`) into one running app — distinct routes,
  confirmed no collision — then runs `run_targets` (with a real, started
  `OobListener`) against it for real.
  New/changed files:
  - `tests/test_multitarget_category4.py` (new test + supporting fixture
    helpers, module docstring updated)
- Impact (other components / project): test-only change; no production
  code touched. Netflix's own real, scored recall in this dedicated
  multi-cell test is `1.0` (`tp=2, fp=0`) — both of its own ground-truth
  positives now confirm together in one real boot.
- Risk (level; mitigation or accepted-risk justification): Low. Reuses an
  already-established, already-reviewed pattern (TrackerNest's own
  hand-rolled multi-cell fixture) verbatim; no new mechanism or safety
  surface introduced.
- Deliverables:
  - [x] Multi-cell Netflix boot fixture implemented — done
  - [x] Real, executed `run_targets` proof against it — done
  - [x] `test_multitarget_category4.py`'s own module docstring updated to
        no longer describe this as an open follow-on — done
  - [x] Full non-slow suite + both `test_multitarget_category4.py` tests
        re-run green — done
- Effectiveness (assessed 2026-09-23): achieved. Netflix's own multi-cell
  boot shows `tp=2, fp=0, recall=1.0` for real, proven by a real, executed
  `run_targets()` call against a real booted app with both of its
  vulnerable cells present, not a mock.

### CC-FUZZ-0035 — `XxeInBandMarkerStrategy`/`XxeOobStrategy`: real detection for `xxe`; two stale multitarget tests fixed (2026-09-23)

- Change: adds the project's first oracle confirmation strategies for
  `xxe` (CWE-611), closing TrackerNest's and Netflix's shared structural
  detection zero (`TNEST-0002`/`NFLX-0002`).
  1. **`fuzzlab/oracle/strategies.py`**: `XxeInBandMarkerStrategy`
     (`vuln_class="xxe"`, `mechanism="in-band-external-entity-marker"`)
     and `XxeOobStrategy` (`mechanism="oob-external-entity-fetch"`),
     directly modeled on `SsrfInBandMarkerStrategy`/`SsrfOobStrategy`. A
     `SYSTEM` external entity is pointed at the injected `OobListener`'s
     own loopback callback URL; the in-band layer checks whether the
     immediate response echoes the minted token (real, empirically
     verified: `xml_external_entities_enabled.java.j2`'s parser genuinely
     fetches the URL and inlines its content into the extracted `<title>`
     field), the OOB layer falls back to `wait_for()` for a target that
     resolves the entity but never reflects its content (blind XXE). Two
     wrapper XML shapes tried in-band (`<title>`-child, matching this
     lab's own apps; root-element-direct-text, a plausible different
     real-world shape) before the OOB fallback, the same "≥2 documented
     variants, then fallback" pattern `RegexDosStrategy`/the SSRF pair
     already use.
  2. **Calls `sender.send()` directly, not the shared `_send()` helper**
     (a deliberate adequacy-pass correction from an earlier draft that
     would have added an unexercised `content_type` override parameter to
     `_send()` — YAGNI, reconsidered before implementation): XXE's own
     ground truth is `rendering="server"` (XML, not JSON), so
     `candidate.content_type` is `None` and `_send()` would form-encode
     the whole XML payload as one field value, defeating the entity-
     parsing proof; each strategy declares its own fixed
     `content_type="application/xml"` directly at the call site instead.
  3. **Explicit, docstring-stated safety scope**: the entity value sent is
     *always* `OobListener`'s own minted loopback callback URL — never a
     real filesystem URI or any other host. Required because XXE's
     `SYSTEM` mechanism is trivially adaptable to a genuine local-file-
     read primitive, unlike SSRF's URL-only shape this pattern is
     otherwise modeled on (the adequacy pass's top-ranked required
     addition) — pinned by
     `test_entity_value_is_always_the_injected_listeners_own_callback_url`.
  4. **`fuzzlab/audit/rules_data/default_rules.json`**: `R-XXE` (see the
     paired `CC-AUD-0019` entry).
  5. **Two pre-existing multitarget tests found never actually exercising
     SSRF detection**, discovered while wiring this (proving XXE detection
     meant starting a real `OobListener` and passing it through, which
     surfaced that two *other* tests never did, despite `R-SSRF`/
     `SsrfInBandMarkerStrategy` already existing): `tests/
     test_labgen_php_laravel_huddlehub_multitarget.py` and `tests/
     test_multitarget_category3_combined.py` both called `run_targets`
     without `oob=`, so every OOB-dependent strategy (SSRF included) had
     been failing closed there since `CC-AUD-0016`/`CC-FUZZ-0031` landed —
     not a production defect (`run_targets`'s own `oob` passthrough and
     the strategy both work correctly; the tests simply predated the
     capability and nobody revisited them), so no `docs/bugs/` entry, same
     reasoning as every other stale-test-assertion fix this session.
     Fixed by passing a real, started listener and updating each test's
     own assertions and docstrings to the now-real recall. `tests/
     test_labgen_spring_boot_trackernest_multitarget.py` (TrackerNest's
     own solo test) updated the same way for its new `xxe` confirmation.
  - Dispatched through this component's mandatory pre-change review gate
    (accuracy + adequacy passes). Accuracy pass independently re-ran the
    real live-boot probes (external-entity fetch, in-band echo, OOB hit,
    secure-twin rejection) and confirmed byte for byte. Adequacy pass
    required, and this entry incorporates: (a) the explicit safety-scope
    docstring (item 3 above); (b) bypassing `_send()` rather than
    generalizing it on spec (item 2 above); (c) scoping this increment to
    TrackerNest's own real multitarget test rather than also attempting
    Netflix's `SpringBootLiveBootHarness` one-cell-per-boot integration
    (left as its own explicitly-noted, separately-scoped follow-on in
    `tests/test_multitarget_category4.py`'s own docstring); (d) a
    documented rationale for the two wrapper shapes, matching
    `RegexDosStrategy`'s own docstring rigor.
  New/changed files:
  - `fuzzlab/oracle/strategies.py`
  - `fuzzlab/audit/rules_data/default_rules.json` (shared with `CC-AUD-0019`)
  - `tests/test_oracle_strategies_xxe.py` (new)
  - `tests/test_labgen_spring_boot_xxe_live_boot.py` (new
    `test_real_boot_proves_the_xxe_strategy_end_to_end`)
  - `tests/test_labgen_spring_boot_trackernest_multitarget.py`,
    `tests/test_labgen_php_laravel_huddlehub_multitarget.py`,
    `tests/test_multitarget_category3_combined.py`,
    `tests/test_multitarget_category4.py` (docstring/assertion updates)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-22`, new)
- Impact (other components / project): `fuzzlab/oracle/strategies.py` and
  `fuzzlab/audit/rules_data/default_rules.json` are shared across every
  category/target (fresh `git show` collision check against category-2/3/5
  and second-target-cat1-ecommerce before landing — all behind this
  branch's own prior commits, no independent edits). Real behavior change
  for four existing test files' own scored reports: TrackerNest's real
  recall 1/3→2/3 (both its solo test and the category-3 combined test),
  Huddle Hub's real recall 0→1/3 (both its solo test and the combined
  test), and the category-3 combined test's `generalizes` False→True.
- Risk (level; mitigation or accepted-risk justification): Low. The
  mechanism is identical in shape and risk to the already-approved SSRF
  strategies (a loopback-only fetch to the project's own `OobListener`);
  the one XXE-specific risk (adaptability to a real file-read payload) is
  explicitly scoped out and pinned by a dedicated test, not just stated in
  prose.
- Deliverables:
  - [x] `XxeInBandMarkerStrategy`/`XxeOobStrategy` implemented, registered,
        unit-tested (vulnerable/blind/secure/no-listener/safety-scope
        cases) — done
  - [x] Real live-boot proof against TrackerNest's real booted twins — done
  - [x] Two stale multitarget tests found, fixed, re-verified against real
        boots — done
  - [x] Full non-slow suite + every directly-affected slow test re-run
        green at the stable baseline — done
- Effectiveness (assessed 2026-09-23): achieved. TrackerNest's real,
  scored `multitarget` recall (both its own solo test and the category-3
  combined test) moved from 1/3 to 2/3; Huddle Hub's moved from 0 to 1/3
  in both tests it appears in; the category-3 combined test's
  `generalizes` moved from `False` to `True` — all proven by real,
  executed `run_targets()` calls against real booted apps, not mocks.

### CC-FUZZ-0034 — `InsecureDeserializationTypeConfusionStrategy`: real detection for `insecure_deserialization`; a `sink_context` propagation defect found and fixed (2026-09-23)

- Change: adds the project's first oracle confirmation strategy for
  `insecure_deserialization` (CWE-502), closing one of Netflix's two
  remaining structural detection zeros (`NFLX-0001`).
  1. **`fuzzlab/oracle/strategies.py`**: `InsecureDeserializationTypeConfusionStrategy`
     (`vuln_class="insecure_deserialization"`, `mechanism=
     "polymorphic-type-confusion"`, `category="insecure-deserialization"`).
     A two-probe differential over Jackson's `WRAPPER_ARRAY` polymorphic-type
     format (`["<class>",{}]`): probe A names a real, always-present JDK
     class (`java.util.HashMap`) and must succeed (200); probe B names a
     freshly-minted (`_token()`-suffixed), guaranteed-nonexistent class and
     must fail *specifically* by echoing that exact class name back in the
     rejection body — proof the target genuinely attempted
     attacker-controlled class resolution, not merely "any body succeeds."
     Deliberately never sends a real gadget-chain/RCE payload (no
     `ProcessBuilder`/JNDI/template trigger) — this project's own
     no-new-dual-use-infra posture, the same reasoning that shelved the
     URLDNS follow-on for this class (`docs/components/07-fuzzing-harness-
     and-oracle/requirements.md` §8). Registered in `default_strategies()`
     and `_CATEGORY_TO_CLASS`.
  2. **A real, previously dormant defect found and fixed**:
     `fuzzlab/harness/auto.py::points_from_ground_truth` never propagated
     `sink_context` from the ground truth's scoring `Case` onto the
     audited `fuzzlab.audit.InjectionPoint` at all — the enumerated
     *points* (`injection-points.json`, `fuzzlab.labels.contract.
     InjectionPoint`) carry no `sink_context` field by design (it lives
     only on `Case`/`labels.json`), and nothing ever bridged the two. This
     was harmless for every rule built before this entry (none used the
     `sink_context_in` predicate), so it caused no observed wrong
     behavior in the field — but it would have silently zeroed out
     `R-INSECURE-DESERIALIZATION` (the first rule ever keyed on
     `sink_context_in`) forever. Caught by the real, executed
     `test_multitarget_category4.py` run showing `netflix_report.tp == 0`
     despite a working rule+strategy pair, not assumed correct from unit
     tests alone. Fixed by looking up the matching `Case` by
     `(url, method, param)` identity and threading its `sink_context`
     through; pinned by a dedicated test
     (`test_points_from_ground_truth_carries_sink_context_from_the_
     matching_case`).
  3. **`fuzzlab/core/runmode.py`**: `_VULN_TO_CATEGORY` gained
     `"insecure_deserialization": "insecure-deserialization"` — the
     *second* instance of the exact gap `CC-FUZZ-0033` found and fixed for
     `access_control` minutes earlier in this same session. Added a
     structural guard this time instead of just noting the pattern:
     `tests/test_oracle.py::
     test_every_ruled_strategy_category_is_reachable_from_its_vuln_class`
     asserts the `_CATEGORY_TO_CLASS`/`_VULN_TO_CATEGORY` pairing for
     every category that already has a real audit `Rule` (so a third
     instance fails loudly at test time). Deliberately scoped to
     *ruled* categories only — an earlier, unscoped draft of this guard
     failed on the MeadowMart app's own already-documented, deliberately-
     deferred `redos`/`prototype_pollution` gap
     (`tests/test_labgen_node_bff_multitarget.py`'s own docstring), which
     must stay un-flagged, not accidentally forced closed by an
     over-broad guard.
  4. **`fuzzlab/audit/rules_data/default_rules.json`**: `R-INSECURE-
     DESERIALIZATION` (see the paired `CC-AUD-0018` entry for the rule
     itself, recorded in both logs per this README's "touches more than
     one component" rule).
  - Dispatched through this component's mandatory pre-change review gate
    (accuracy + adequacy passes). Accuracy pass independently re-booted
    both real twins and re-confirmed the claimed HTTP behavior byte for
    byte (status codes and error-message shapes). Adequacy pass required,
    and this entry incorporates: (a) the two-probe differential itself —
    the original draft's bare `probe.status == 200` check was judged
    insufficient evidence on its own (a false positive against an
    endpoint that validates nothing at all); (b) explicitly documenting
    that `R-INSECURE-DESERIALIZATION` is reachable only from
    ground-truth-sourced points today (`sink_context` is not yet inferred
    generically by the auditor for an arbitrary crawled target — see
    `FR-AUD-9`); (c) fixing the recurring `_VULN_TO_CATEGORY` gap with a
    real structural guard rather than only a comment, per item 3 above.
  New/changed files:
  - `fuzzlab/oracle/strategies.py`
  - `fuzzlab/core/runmode.py`
  - `fuzzlab/harness/auto.py` (the `sink_context` propagation fix)
  - `fuzzlab/audit/rules_data/default_rules.json` (shared with `CC-AUD-0018`)
  - `tests/test_oracle_strategies_insecure_deserialization.py` (new)
  - `tests/test_oracle.py` (the new reachability guard test)
  - `tests/test_auto.py` (the new `sink_context` propagation pinning test)
  - `tests/test_labgen_spring_boot_deserialization_jackson_live_boot.py`
    (new `test_real_boot_proves_the_insecure_deserialization_strategy_
    end_to_end`)
  - `tests/test_multitarget_category4.py` (Netflix's real, scored recall
    moves from 0 to 1/2; `generalizes` is `True` for the first time)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-21`, new)
- Impact (other components / project): `fuzzlab/oracle/strategies.py`,
  `fuzzlab/core/runmode.py`, and `fuzzlab/harness/auto.py` are all shared
  across every category/target (fresh `git show` collision check against
  category-2/3/5 and second-target-cat1-ecommerce before landing — all
  four are simply behind this branch's own prior `CC-FUZZ-0033` commit,
  no independent edits). The `sink_context` propagation fix changes real
  behavior for every ground-truth-sourced run project-wide (any future
  `sink_context_in`-keyed rule now actually works; no existing rule used
  that predicate before this entry, so no existing behavior changes).
  `fuzzlab.harness.multitarget`'s real, scored Netflix report for
  category 4's own Phase E test now shows `tp=1` instead of `tp=0`, and
  `generalizes=True` instead of `False` — a real behavior change
  reflected in `test_multitarget_category4.py`'s updated assertions.
- Risk (level; mitigation or accepted-risk justification): Low-medium.
  The strategy's own documented false-positive class (a legitimate
  two-element-array DTO whose validation error happens to echo a string
  back for an unrelated reason) is real and accepted, not eliminated —
  judged unlikely, the same evidentiary bar `SsrfInBandMarkerStrategy`
  already uses, and stated explicitly in the strategy's own docstring.
  The `sink_context` propagation fix touches a widely-shared function;
  mitigated by running the full non-slow suite plus every directly
  affected slow live-boot/multitarget test after the change, not just the
  tests written for this entry.
- Deliverables:
  - [x] `InsecureDeserializationTypeConfusionStrategy` implemented,
        registered, unit-tested (vulnerable/secure/false-positive/
        no-content-type/fresh-token cases) — done
  - [x] `sink_context` propagation defect found, fixed, pinned — done
  - [x] `_VULN_TO_CATEGORY` fix + a real structural guard (scoped to
        ruled categories only) — done
  - [x] Real live-boot proof against Netflix's real booted Spring Boot
        app — done
  - [x] `test_multitarget_category4.py` updated to the new real recall
        and `generalizes=True` — done
  - [x] Full non-slow suite + directly-affected slow tests re-run green
        at the stable baseline — done
- Effectiveness (assessed 2026-09-23): achieved. Netflix's real, scored
  `multitarget` recall for category 4 moved from 0 to 1/2 (`tp=1, fp=0`),
  and the project's own cross-target `generalizes` definition (recall > 0
  on ≥ 2 scored targets) is met for the first time (`True`), proven by a
  real, executed `run_targets()` call against two real booted apps
  (`tests/test_multitarget_category4.py`), and the strategy independently
  confirms/fails-closed correctly against real vulnerable/secure twins via
  a dedicated live-boot test, not only mocked senders.

### CC-FUZZ-0033 — `AccessControlIdorStrategy`: real detection for `access_control` (IDOR/BOLA) (2026-09-23)

- Change: adds the project's first oracle confirmation strategy for the
  `access_control` vulnerability class, closing the `CC-LAB-0178` open
  question (`docs/components/01-target-lab/requirements.md` §8).
  1. **`fuzzlab/oracle/strategies.py`**: `AccessControlIdorStrategy`
     (`vuln_class="access_control"`, `mechanism="identity-differential"`,
     `category="access-control"`). Sends two unrelated id values via
     `_send()`; confirms only when both legs return HTTP 200, a non-empty
     body that echoes the requested id back verbatim, no generic
     denial-phrase match (`\b`-anchored regex, per PA-0022), and the two
     bodies differ from each other — else fails closed (`None`), the same
     posture every other strategy in this file uses. Registered in
     `default_strategies()` (appended before the cross-cutting
     `GreyboxConfirmationStrategy`, after the category-specific SSRF
     strategies — matches existing ordering convention, not a literal
     reordering of any existing entry) and in `_CATEGORY_TO_CLASS`
     (`"access-control": "access_control"`).
  2. **`fuzzlab/core/runmode.py`**: `_VULN_TO_CATEGORY` gained
     `"access_control": "access-control"`. Without this, ground truth's
     `vuln_class="access_control"` (underscore) never maps to the rule's
     `category="access-control"` (hyphen) — the two genuinely differ,
     unlike `ssrf` (identical either way, needing no entry) — so the new
     rule/strategy would never actually be selected by a ground-truth-driven
     run despite existing. Found by re-tracing the real category-selection
     path (`categories_from_vuln_classes` → `resolve_run` → `plan.categories`)
     before considering this done, not assumed from the SSRF precedent.
  3. **`fuzzlab/audit/rules_data/default_rules.json`**: `R-ACCESS-CONTROL`
     (see the paired `CC-AUD-0017` entry for the rule itself — cross-cutting
     to both components' data contracts, so recorded in both logs per this
     README's "if a change touches more than one component" rule).
  - Dispatched through this component's mandatory pre-change review gate
    (accuracy + adequacy passes, both agents given the actual draft and the
    real repo to check against). Accuracy pass: no factual errors found.
    Adequacy pass required, and this entry incorporates: (a) narrowing
    `R-ACCESS-CONTROL`'s scope to `GET`/`query` only and dropping the
    overly broad `account_id` term (a legitimate multi-account search
    feature was flagged as a realistic false-positive source); (b) the
    id-echo check (item 1 above), added specifically to raise precision
    against the false-positive class the adequacy pass named; (c) moving
    the strategy's documented limitation into its own docstring (matching
    `SsrfOobStrategy`'s convention) rather than leaving it only in a
    scratch draft; (d) the `\b`-anchored denial-marker regex per PA-0022;
    (e) explicitly re-verifying the cross-branch collision check and the
    `docs/PREVENTIVE_ACTIONS.md`/`docs/ARCHITECTURE.md` bookkeeping
    questions the adequacy pass raised (confirmed: no other active branch
    touches `access_control`/`R-ACCESS-CONTROL`; `docs/ARCHITECTURE.md`
    does not track per-strategy detection coverage at this granularity
    anywhere else, so it needs no edit for this change).
  New/changed files:
  - `fuzzlab/oracle/strategies.py`
  - `fuzzlab/core/runmode.py`
  - `fuzzlab/audit/rules_data/default_rules.json` (shared with `CC-AUD-0017`)
  - `tests/test_oracle_strategies_access_control.py` (new)
  - `tests/test_labgen_go_live_boot.py` (new
    `test_real_boot_proves_the_access_control_idor_strategy_end_to_end`)
  - `tests/test_multitarget_category4.py` (Twitch's real, scored recall
    moves from 1/3 to 2/3 — updated assertions, not just a docstring)
  - `docs/components/01-target-lab/requirements.md` (§8 open question
    resolved)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-20`, new)
- Impact (other components / project): `fuzzlab/oracle/strategies.py` and
  `fuzzlab/core/runmode.py` are both shared across every category/target
  (confirmed no active branch collision via a fresh `git show` against
  category-2/3/5 and second-target-cat1-ecommerce before landing). Purely
  additive — no existing strategy, rule, or category mapping is changed,
  only a new entry appended to each. `fuzzlab.harness.multitarget`'s
  real, scored Twitch report for category 4's own Phase E test now shows
  `tp=2` instead of `tp=1` (a real behavior change, not just new code —
  any consumer asserting the old `tp=1`/`recall=1/3` figures needs the
  same update this entry makes to `test_multitarget_category4.py`).
- Risk (level; mitigation or accepted-risk justification): Low-medium. The
  strategy's own documented false-positive class (a legitimate
  arbitrary-id-echoing public lookup with nothing sensitive gated by
  ownership) is real and accepted, not eliminated — mitigated by scoping
  the triggering rule narrowly (GET/query, a short id-shaped name list)
  and by this project's own detection-benchmark framing (a confirmed
  finding here is scored against known ground truth, not shipped as an
  unreviewed live-scan verdict against a real target without human
  review — `docs/README.md`'s own lab-only/authorized-only scoping).
  Documented explicitly in the strategy's own docstring and pinned by
  `test_documented_false_positive_class_a_public_echo_endpoint_does_confirm`
  rather than discovered later as a surprise.
- Deliverables:
  - [x] `AccessControlIdorStrategy` implemented, registered, unit-tested
        (vulnerable/secure/false-positive/false-negative cases) — done
  - [x] `_VULN_TO_CATEGORY` fix so the strategy is actually reachable — done
  - [x] Real live-boot proof against Twitch's real booted Go app — done
  - [x] `test_multitarget_category4.py` updated to the new real recall — done
  - [x] Full non-slow suite re-run green at the stable baseline — done
    (18 failed pre-existing/environment, rest passed)
- Effectiveness (assessed 2026-09-23): achieved. Twitch's real, scored
  `multitarget` recall for category 4 moved from 1/3 to 2/3
  (`tp=2, fp=0`), proven by a real, executed `run_targets()` call against
  a real booted app (`tests/test_multitarget_category4.py`), and the
  strategy independently confirms/fails-closed correctly against real
  vulnerable/secure twins via a dedicated live-boot test, not only mocked
  senders.

### CC-FUZZ-0032 — Header-location points become real, audited points; a content-type-aware whole-body sender (2026-09-23)

- Change: closes the two structural gaps `CC-LAB-0176`/`FR-LAB-99`
  (category 4's Phase E) and `CC-FUZZ-0031` flagged as real follow-on work.
  Dispatched through this component's pre-change review gate (accuracy +
  adequacy passes) before implementation; the adequacy pass's finding — the
  original draft's whole-body convention would have force-sent
  `Content-Type: application/json` for *every* `param="body"` point,
  silently wrong for TrackerNest's own XXE (`TNEST-0002`, XML) and
  insecure-deserialization (`TNEST-0003`, binary Java-serialized) body
  points — is incorporated below, not shipped as originally drafted.
  1. **`fuzzlab/harness/auto.py::points_from_ground_truth`**: a
     `location="header"` point (e.g. `TWCH-0001`'s `X-Signature-256`) is
     now a real, audited `InjectionPoint`, not skipped — matches this
     function's own existing convention that "skipped" is reserved for a
     genuine structural gap (no point/sender support at all), never "no
     audit rule currently matches this category" (true of every
     `query`/`body` point with no matching rule already, silently
     zero-candidate, never listed as skipped). `FR-FUZZ-13`'s own scope
     statement is superseded by this entry.
  2. **Content-type-aware whole-body points, not a hardcoded JSON
     assumption.** A `param="body"`/`location="body"` point only gets
     `body_content_type="application/json"` when the ground truth's own
     `rendering` field says `"server-json"` (already the exact signal
     `NFLX-0001` carries and `TNEST-0002`/`TNEST-0003` do not — no new
     schema field needed, this reuses `rendering`, which
     `points_from_ground_truth` already reads for its DOM-detection
     logic). `fuzzlab.audit.engine.InjectionPoint` gained
     `body_content_type: str | None = None` (additive); `evaluate()`
     copies it into the candidate's evidence dict when set;
     `fuzzlab.oracle.probe.Candidate` gained the matching `content_type`
     field; `fuzzlab/harness/pipeline.py`'s Candidate-construction site
     reads it back from evidence; `ConfirmationStrategy._send()` passes it
     through when set.
  3. **`fuzzlab/tools/probesender.py`** (`RequestsProbeSender`,
     `SeamProbeSender`): `location="header"` sends `value` as a header
     named the literal `param` (the convention `CC-LAB-0174` already
     established: for a header case, `param` *is* the literal header
     name). `location="body"` **with** a `content_type` sends `value` as
     the raw body at that content type; **without** one, unchanged
     form-encoded `{param: value}` behavior — every existing body point
     (a real named field, or a whole-body point the ground truth doesn't
     mark JSON) is completely unaffected.
  4. **A real bug found and fixed before it could ever fire**:
     `fuzzlab/harness/auto.py::_CountingSender.send()` (the request-cost
     counter every sender is wrapped in inside `run_auto`'s real pipeline)
     did not accept or forward `content_type` at all — the moment a real
     run reached it, the new whole-body-JSON convention would have
     silently reverted to form-encoding, defeating this entire change
     without any test noticing (no existing test exercises
     `_CountingSender` directly). Found by re-reading the full call chain
     end to end, not by a failing test; fixed with a new, direct unit test
     pinning the fix (`tests/test_auto.py::test_counting_sender_forwards_content_type`).
  5. **Noted, not fixed**: `fuzzlab/greybox/run.py`'s
     `RequestsCorrelatingSender` has the identical `location="body"`
     form-encode-only branch and was not given the same content-type
     awareness — low risk today (`GreyboxConfirmationStrategy` only scopes
     to `sql-injection`/`xss`, which never reach a whole-body point), but a
     latent gap if a future grey-box-confirmable category ever does.
     Tracked as an open question (`requirements.md` §8), not silently
     left unrecorded.
  New/changed files:
  - `fuzzlab/harness/auto.py` (`points_from_ground_truth`, `_CountingSender`)
  - `fuzzlab/audit/engine.py` (`InjectionPoint.body_content_type`, `evaluate()`)
  - `fuzzlab/oracle/probe.py` (`Candidate.content_type`, `Sender.send()` signature)
  - `fuzzlab/harness/pipeline.py` (Candidate construction)
  - `fuzzlab/oracle/strategies.py` (`ConfirmationStrategy._send()`)
  - `fuzzlab/tools/probesender.py` (`RequestsProbeSender`, `SeamProbeSender`)
  - `tests/test_auto.py`, `tests/test_probesender.py` (updated/new tests)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-13` updated in place; new `FR-FUZZ-19`; new §8 open questions)
- Impact (other components / project): touches the shared
  `InjectionPoint`/`Candidate`/`Sender` shapes used by every category's own
  detection run. Additive/behavior-widening only for existing callers: a
  new optional field with a `None` default on each dataclass, a new
  optional keyword on `Sender.send()`; every existing `query`/ordinary-
  named-field-`body` point's audit is byte-for-byte unchanged (verified:
  `tests/test_probesender.py`'s pre-existing form-encoded-body tests still
  pass unmodified). A header point moves from always-skipped to
  always-included, a real behavior change, but the only ground truth
  affected today is category 4's own `TWCH-0001`.
- Risk (level; mitigation or accepted-risk justification): **low-medium**
  (a multi-file, shared-dataclass thread-through, but each hop additive
  and independently tested; the one real bug found — `_CountingSender`'s
  missing passthrough — was caught before landing, not after).
- Deliverables:
  - [x] Header points included, not skipped
  - [x] Content-type-aware whole-body sender support (both senders),
    correctly distinguishing `NFLX-0001` (JSON) from TrackerNest's XML/
    binary body points (unaffected)
  - [x] `_CountingSender` passthrough bug found and fixed, with a direct
    unit test
  - [x] Tests updated/added; `FR-FUZZ-13` updated in place; new `FR-FUZZ-19`
  - [x] Full non-slow suite + real live-boot slow tests re-verified green
- Effectiveness (assessed 2026-09-23): met — a real, end-to-end raw-JSON
  whole-body send now works through the full `run_auto` pipeline (not just
  a sender unit test), and the header point is real and audited.

### CC-FUZZ-0031 — Real SSRF detection: `SsrfInBandMarkerStrategy` + `SsrfOobStrategy`, plus `run_targets()` OOB passthrough (2026-09-23)

- Change: the project's first real, end-to-end detection path for the
  `ssrf` vuln_class, closing one of the three "no audit rule/strategy yet"
  gaps `CC-LAB-0176`/`FR-LAB-99` (category 4's Phase E) explicitly flagged
  as real follow-on work. Paired with `CC-AUD-0016`'s new `R-SSRF` rule
  (candidate generation); this entry is confirmation.
  Dispatched through this component's pre-change review gate (accuracy +
  adequacy passes) before implementation; the adequacy pass's finding —
  OOB-only would leave an unreasonably large gap for the common case where
  the target reflects the fetched resource back (this project's own SSRF
  lab cells do exactly that) — is incorporated as `SsrfInBandMarkerStrategy`
  below, not deferred.
  - **`SsrfInBandMarkerStrategy`** (cheap first layer, `fuzzlab/oracle/
    strategies.py`): points the candidate at the `OobListener`'s own
    callback URL and checks whether the *immediate* response to that one
    request echoes the minted token back — a single request, no polling
    wait. Needed `OobListener`'s HTTP handler to actually serve a body
    (previously always empty, `Content-Length: 0`) — an additive change
    (`fuzzlab/oracle/oob.py`): `do_GET`/`do_POST` now echo the token as
    the response body, `do_HEAD` correctly still sends none (a body on a
    HEAD response is invalid HTTP). `wait_for`/`hits()`/`record()` never
    read this body, so `CommandInjectionOobStrategy`'s own existing
    OOB-only usage is unaffected — re-verified via its full existing test
    suite.
  - **`SsrfOobStrategy`** (fallback layer, when the target doesn't echo
    the body back): modeled directly on `CommandInjectionOobStrategy`'s
    established M8 pattern, but simpler — the injected value *is* the
    callback URL sent directly, since an SSRF sink's own HTTP client
    fetches whatever URL it's given (unlike command injection, which
    needs a shell one-liner to turn a URL into an outbound fetch). A
    longer default timeout (3.0s vs. `CommandInjectionOobStrategy`'s
    1.5s) per the adequacy review's own finding: a local shell `curl` is
    near-instant, but a real DNS-resolve-connect-fetch round trip can
    plausibly take longer even when genuinely vulnerable.
  - Both registered in `default_strategies()`, cheapest-first (in-band
    before OOB), matching every other category's own stacking convention
    (SQLi: error/boolean/timing; command injection: timing then OOB).
    `_CATEGORY_TO_CLASS["ssrf"] = "ssrf"` added.
  - **`fuzzlab/harness/multitarget.py`'s `run_targets()`** previously
    forwarded `browser`/`scheduler`/`plugins` to `run_auto()` but silently
    dropped `oob`/`coverage`/`dbfault`, which `run_auto()` already
    accepted — found while wiring this change into category 4's own
    multitarget test (a `TargetSpec`-driven run had no way to actually use
    the new OOB strategies). Fixed by adding the same three
    keyword-passthrough params, default `None`, forwarded unchanged (no
    behavior change for any existing caller — verified against
    `tests/test_multitarget.py`'s own existing call sites, none of which
    pass these keywords). Safe to share one `OobListener` across every
    target in a batch: `run_targets()` loops sequentially, never
    concurrently, and `OobListener` correlates hits by a fresh per-probe
    token, never by target.
  - New offline unit tests (`tests/test_oracle_oob.py`): both strategies'
    hit/no-hit/no-op cases, plus a stacking-order check
    (`SsrfInBandMarkerStrategy` before `SsrfOobStrategy`).
  - **Real, live-boot proof, not just unit tests**: `tests/test_multitarget_category4.py`
    (updated) runs a real, started `OobListener` through `run_targets()`
    against the real live-booted Twitch app — `LABGEN-GO-0003` (vulnerable)
    is now a real, confirmed finding (`tp=1`, `recall=0.5` on that target's
    own 2 SSRF/webhook positives); `LABGEN-GO-0004` (secure) correctly
    stays unconfirmed (blocked by its scheme/IP allowlist before any
    fetch, so the in-band marker never appears and the OOB callback never
    fires).
  New/changed files:
  - `fuzzlab/oracle/strategies.py` (`SsrfInBandMarkerStrategy`, `SsrfOobStrategy`,
    `default_strategies()`, `_CATEGORY_TO_CLASS`)
  - `fuzzlab/oracle/oob.py` (`_make_handler`, additive body-echo)
  - `fuzzlab/harness/multitarget.py` (`run_targets()` passthrough)
  - `tests/test_oracle_oob.py` (new SSRF strategy tests)
  - `tests/test_multitarget_category4.py` (updated to the real, non-zero
    recall proof)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    (`FR-FUZZ-18`, new)
- Impact (other components / project): `default_strategies()`/
  `_CATEGORY_TO_CLASS`/`OobListener` are shared across every category and
  every existing target's own run — additive only (two new strategies
  appended, one new category-map entry, one existing handler's response
  body changed from always-empty to token-echoing when a token matches,
  which no existing caller reads). `run_targets()`'s three new keyword
  params default to `None`, matching every existing call site exactly.
- Risk (level; mitigation or accepted-risk justification): **low-medium**.
  Genuinely new production code in two shared, category-agnostic
  components (audit rule + oracle strategies), but additive by
  construction and directly modeled on an already-shipped, already-tested
  sibling mechanism (`CommandInjectionOobStrategy`) rather than a novel
  design; the `OobListener` body-echo change is the one shared-code touch,
  verified not to break its existing (hit-recording-only) consumer.
- Deliverables:
  - [x] `SsrfInBandMarkerStrategy` + `SsrfOobStrategy` added, registered
    cheapest-first, category-mapped
  - [x] `OobListener` serves the token in its response body (additive)
  - [x] `run_targets()` gains `oob`/`coverage`/`dbfault` passthrough
  - [x] New offline unit tests (hit / no-hit / no-op / stacking order)
  - [x] `tests/test_multitarget_category4.py` updated to a real, non-zero
    recall proof for the SSRF case
  - [x] Full non-slow suite + the real live-boot slow tests re-verified
    green
- Effectiveness (assessed 2026-09-23): met — a real, confirmed SSRF
  finding against a real live-booted target, both layers exercised for
  real (in-band on the echoing vulnerable twin; OOB unit-tested against a
  blind-fetch fake).
### CC-FUZZ-0030 — Build `CsvFormulaInjectionStrategy` + `R-CSV-FORMULA-INJECTION`: real confirmation for `csv_formula_injection`, category 5's fourth real detection, closing Booking.com's own ground truth (FR-FUZZ-17) (2026-09-23)
- Change: the one remaining unmapped class in Booking.com's own ground truth. New `Rule` `R-CSV-FORMULA-INJECTION` (`fuzzlab/audit/rules_data/default_rules.json`, `name_regex: "label|name|comment|note|description|title"`, `method_in: ["GET"]`, grounded in Booking.com's real `label` export parameter). New `ConfirmationStrategy` `CsvFormulaInjectionStrategy` (`fuzzlab/oracle/strategies.py`), registered in the strategy-instantiation list and in `_CATEGORY_TO_CLASS["csv-formula-injection"] = "csv_formula_injection"`. New `_VULN_TO_CATEGORY["csv_formula_injection"] = "csv-formula-injection"` (`fuzzlab/core/runmode.py`, see `CC-CORE-0023`'s own entry).

  Went through this component's pre-change review gate before implementation. The accuracy pass returned ACCURATE, confirming the vulnerable/secure twin response shapes (unescaped CSV-row echo vs. a leading-quote-prefixed row), the strategy's own API usage, and both required dict entries as self-consistent — but surfaced a real `name_regex` collision the draft's own open question hadn't concretely named: `username`/`comment`/`full_name` params belonging to unrelated `sqli`/`xss-stored`/benign ground-truth cases in other apps also match the proposed regex. Judged non-blocking (these would only ever produce extra, always-unconfirmed candidates — the strategy's own CSV-row-echo match can't confirm on a login or comment endpoint that doesn't return that shape), noted rather than fixed.

  The adequacy pass returned **INADEQUATE**, catching three blocking design flaws in the initial draft: (1) the match was anchored only to "right after a newline," with no check that the payload is actually followed by the row's own field separator — a debug/error page that merely echoes the raw payload on its own line would have false-positive-confirmed. Fixed: both the unmodified-echo check and the not-secure check now require an immediate trailing `,` after the payload (`f"{payload},"`), tying the match to an actual CSV cell boundary. (2) A single `=`-only trigger-character canary risked a false negative against a real neutralizer that only escapes a subset of OWASP's four trigger characters — this project already has precedent for exactly this robustness pattern (`SstiStrategy`'s own multi-payload loop). Fixed: the strategy now tries all four (`=`, `+`, `-`, `@`) in turn, confirming on the first that reproduces the unescaped-echo shape. (3) the rule lacked `method_in`, mirroring `R-PRICE-INTEGRITY`'s own recent precedent for cheap defense-in-depth against candidate-flood risk from a broad `name_regex`. Fixed: `method_in: ["GET"]` added (this shape is GET/query).

  Live-verified end to end through `fuzzlab.harness.multitarget.run_targets` against Booking.com's real, locally-booted deployment and real ground truth (`lab/ground-truth-booking-clone/`) before considering this complete, per `PA-0042`'s own rule (applied to itself for the fourth time this session). Real result: `tp=3, fn=0, fp=0` — all three of Booking.com's own ground-truth cases (`BKNG-0001`/`BKNG-0002`/`BKNG-0003`) now match. Recall moved `2/3 -> 1.0`.

  **This makes `csv_formula_injection` category 5's fourth genuinely-detecting vuln class, and closes Booking.com's own toolkit-side detection coverage entirely — no honestly-unmapped class remains for this app.** Updated `tests/test_labgen_php_laravel_booking_multitarget.py` and `tests/test_multitarget_category5_combined.py` to the new, real scored numbers.
  1. **Tests**: 4 new unit tests in `tests/test_oracle_vectors.py` (confirmed on a real-shaped unescaped-echo sender; not confirmed on a real-shaped quote-prefixing sender; an explicit regression test proving the match is anchored to the CSV cell boundary, not merely "after a newline" — the exact pitfall the adequacy review caught; and an explicit regression test proving the strategy tries every OWASP trigger character, not just `=`). 1 new test in `tests/test_runmode.py`. Whole-repo `pytest tests/` run before considering this increment complete (`PA-0036`) — see Effectiveness for the pass/skip/fail counts.
  2. `docs/components/02-core-library/requirements.md`/`docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-CORE-13`/`FR-FUZZ-17`.
  3. `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated.
- Impact (other components / project): `fuzzlab/core/runmode.py` (CORE component, one new dict entry — see `CC-CORE-0023`), `fuzzlab/audit/rules_data/default_rules.json` (new rule, checked for `name_regex` collisions against every existing ground-truth param name in the corpus before landing — real matches found on unrelated classes, judged non-blocking per the accuracy review's own reasoning above), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, real scored-number updates). No other of this component's own files touched.
- Risk (level; mitigation or accepted-risk justification): low. New code, narrowly scoped (one new `ConfirmationStrategy`, one new `Rule`, two dict entries) and thoroughly verified: all three of the adequacy review's own blocking findings were caught and fixed before any code was written, live end-to-end verification proves zero false positives on the real secure twin, and the whole-repo suite (see Effectiveness) confirms zero regressions across every other category's own tests. The accepted, non-blocking `name_regex` collision risk (extra unconfirmed candidates on unrelated params in other apps) has no false-positive consequence, per the accuracy review's own analysis.
- Deliverables:
  - [x] `fuzzlab/oracle/strategies.py`: `CsvFormulaInjectionStrategy` + registrations — done
  - [x] `fuzzlab/audit/rules_data/default_rules.json`: `R-CSV-FORMULA-INJECTION` — done
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["csv_formula_injection"]` — done
  - [x] `tests/test_oracle_vectors.py`: 4 new tests — done
  - [x] `tests/test_runmode.py`: 1 new test — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-FUZZ-17` — done
  - [x] `CHANGELOG.md` line — done
  - [x] `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated — done
- Effectiveness (assessed 2026-09-23): Met, with evidence beyond a returned `Verdict`. The adequacy review caught three real, blocking design flaws before any code was written — an unanchored match, a single-trigger-character false-negative risk, and a missing defense-in-depth rule constraint — exactly the review gate's purpose. Live end-to-end verification then proved the corrected design real: `tp=3, fn=0, fp=0` against Booking.com's real deployment, recall `2/3 -> 1.0`, closing this app's own ground truth entirely. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-FUZZ-0029 — Build `PriceIntegrityBypassStrategy` + `R-PRICE-INTEGRITY`: real confirmation for `price_integrity_bypass`, category 5's third real detection (FR-FUZZ-16) (2026-09-23)
- Change: unlike `ssti`/`open_redirect`/`spel_injection` (`CC-CORE-0020`/`CC-CORE-0021`/`CC-FUZZ-0028`), no existing rule+strategy pair applied to `price_integrity_bypass` (no CWE — a business-logic/trust-boundary defect, grounded in the real QloApps `Cart::getOrderTotal()` trust pattern this shape was modeled on, Booking.com's real cell `LABGEN-BC-0005`, `CC-LAB-0212`) — this entry builds one from scratch. New `Rule` `R-PRICE-INTEGRITY` (`fuzzlab/audit/rules_data/default_rules.json`, `name_regex: "amount|price|total|cost|charge"`, `method_in: ["POST"]`, grounded in Booking.com's own real `amount` parameter — checked for `name_regex` collisions against every existing manifest's real param names before landing, none found). New `ConfirmationStrategy` `PriceIntegrityBypassStrategy` (`fuzzlab/oracle/strategies.py`), registered in the strategy-instantiation list and in `_CATEGORY_TO_CLASS["price-integrity-bypass"] = "price_integrity_bypass"`. New `_VULN_TO_CATEGORY["price_integrity_bypass"] = "price-integrity-bypass"` (`fuzzlab/core/runmode.py`).

  Went through this component's pre-change review gate before implementation. The accuracy pass confirmed the core mechanism sound but caught two issues: (1) the draft's prose incorrectly implied a `ClientTrustedAmountTransform` class exists — in reality the vulnerable twin (`LABGEN-BC-0005`) simply has an empty transform pipeline (`transform: []`, no rewrite op at all), corrected before implementation; (2) the draft's plan again omitted the separate `_CATEGORY_TO_CLASS` entry `fuzzlab.harness.pipeline`'s own hard gate requires — the same completeness gap `CC-FUZZ-0028`'s own review already caught once this session, caught a second time here and fixed before implementation.

  The adequacy pass returned **INADEQUATE**, catching two blocking design flaws: (1) a randomly-drawn two-decimal-place canary has a real, non-negligible chance of coincidentally equaling one of the real rate-table values (`89.00`/`149.00`/`249.00`) — a collision risk, not just an improbability, that would make even the SECURE twin's own genuine rate-table echo look like a confirmation. Fixed: the canary always has three decimal places, structurally incompatible with the rate table's own two-decimal-place shape, with the three literals also excluded explicitly as defense in depth. (2) A bare substring match against the response body risks false-matching an unrelated field. Fixed: the match is anchored to `"charged_amount":"<canary>"`, checked after stripping whitespace from the response body (mirroring `tests/test_labgen_price_integrity.py`'s own live-boot test's `.replace(" ", "")` normalization). The adequacy review also confirmed as safe (not blocking) that omitting `room_type` from the confirmation POST is fine, since the real endpoint has a safe `'standard'`-default fallback with no error path.

  Live-verified end to end through `fuzzlab.harness.multitarget.run_targets` against Booking.com's real, locally-booted deployment and real ground truth (`lab/ground-truth-booking-clone/`) before considering this complete, per `PA-0042`'s own rule (applied to itself for the third time this session). Real result: `tp=2, fn=1, fp=0` — `BKNG-0001` (`open_redirect`) and `BKNG-0003` (`price_integrity_bypass`) both now match; `BKNG-0002` (`csv_formula_injection`) remains an honest false negative. Recall moved `1/3 -> 2/3`.

  **This makes `price_integrity_bypass` category 5's third genuinely-detecting vuln class.** Updated `tests/test_labgen_php_laravel_booking_multitarget.py` and `tests/test_multitarget_category5_combined.py` to the new, real scored numbers.
  1. **Tests**: 3 new unit tests in `tests/test_oracle_vectors.py` (confirmed on a real-shaped trusted-amount-echo sender; not confirmed on a real-shaped rate-table-recompute sender; and an explicit regression test — run 50 times to rule out flakiness from the strategy's own randomness — proving the canary's own three-decimal-place structure can never collide with the real two-decimal-place rate table, the exact pitfall the adequacy review caught). 1 new test in `tests/test_runmode.py`. Whole-repo `pytest tests/` run before considering this increment complete (`PA-0036`) — see Effectiveness for the pass/skip/fail counts.
  2. `docs/components/02-core-library/requirements.md`/`docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-CORE-12`/`FR-FUZZ-16`.
  3. `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated.
- Impact (other components / project): `fuzzlab/core/runmode.py` (CORE component, one new dict entry — see `CC-CORE-0022`), `fuzzlab/audit/rules_data/default_rules.json` (new rule), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, real scored-number updates). No other of this component's own files touched.
- Risk (level; mitigation or accepted-risk justification): low. New code, narrowly scoped (one new `ConfirmationStrategy`, one new `Rule`, two dict entries) and thoroughly verified: both of the adequacy review's own blocking findings (canary/rate-table collision risk, unanchored match) were caught and fixed before any code was written, live end-to-end verification proves zero false positives on the real secure twin, and the whole-repo suite (see Effectiveness) confirms zero regressions across every other category's own tests.
- Deliverables:
  - [x] `fuzzlab/oracle/strategies.py`: `PriceIntegrityBypassStrategy` + registrations — done
  - [x] `fuzzlab/audit/rules_data/default_rules.json`: `R-PRICE-INTEGRITY` — done
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["price_integrity_bypass"]` — done
  - [x] `tests/test_oracle_vectors.py`: 3 new tests — done
  - [x] `tests/test_runmode.py`: 1 new test — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-FUZZ-16` — done
  - [x] `CHANGELOG.md` line — done
  - [x] `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated — done
- Effectiveness (assessed 2026-09-23): Met, with evidence beyond a returned `Verdict`. The adequacy review caught two real, blocking design flaws before any code was written — a genuine collision risk with the real rate table, and an unanchored match that could false-positive on an unrelated field — exactly the review gate's purpose. Live end-to-end verification then proved the corrected design real: `tp=2, fn=1, fp=0` against Booking.com's real deployment, recall `1/3 -> 2/3`. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-FUZZ-0028 — Build `SpelInjectionStrategy` + `R-SPEL-INJECTION`: real confirmation for `spel_injection`, category 5's second real detection (FR-FUZZ-15) (2026-09-23)
- Change: unlike `ssti`/`open_redirect` (`CC-CORE-0020`/`CC-CORE-0021`), no existing rule+strategy pair applied to `spel_injection` (CWE-917, Expedia's real cell, `CC-LAB-0214`) — this entry builds one from scratch. New `Rule` `R-SPEL-INJECTION` (`fuzzlab/audit/rules_data/default_rules.json`, `name_regex: "sort|sortby|filter|order|expr|expression"`, grounded in Expedia's own real `sortBy` parameter). New `ConfirmationStrategy` `SpelInjectionStrategy` (`fuzzlab/oracle/strategies.py`), registered in the strategy-instantiation list and in `_CATEGORY_TO_CLASS["spel-injection"] = "spel_injection"`. New `_VULN_TO_CATEGORY["spel_injection"] = "spel-injection"` (`fuzzlab/core/runmode.py`).

  Went through this component's pre-change review gate before implementation. The accuracy pass returned mostly ACCURATE with one useful correction (a claim that `{{expr}}` isn't valid bare SpEL was wrong — it's a valid nested-list literal — worth noting in the code but not blocking, since this entry's own strategy never uses that payload shape) and one genuine completeness gap: the draft's plan only mentioned adding a `_VULN_TO_CATEGORY` entry and never mentioned the separate `_CATEGORY_TO_CLASS` entry `fuzzlab.harness.pipeline`'s own hard gate (`if category_to_oracle_class(category) is None: continue`, checked *before* `oracle.confirm()` is ever called) requires — without it, every candidate would be silently dropped regardless of how correct the strategy itself was. Fixed before implementation.

  The adequacy pass returned **INADEQUATE**, catching one blocking design flaw: the draft's first design mirrored `SstiStrategy`'s own bare-arithmetic-product canary (`<a>*<b>`, checking the product appears while the literal expression doesn't) — but `SimpleEvaluationContext` (the real, documented secure-twin fix for this class) restricts *type references* (`T(...)`), bean references, constructors, and arbitrary method/property access, but does **not** restrict bare literal arithmetic. A bare-arithmetic canary would therefore evaluate identically under both the vulnerable AND secure twin — a **guaranteed** false positive on every run, not a coincidental one, caught before any code was written. Fixed: `SpelInjectionStrategy` sends `T(java.lang.Math).abs(-<n>)` instead — the exact `T(...)`-type-reference differential this project already proved live in `CC-LAB-0214`'s own `tests/test_labgen_spel_injection_live_boot.py` (evaluates for real under an unrestricted context, rejected outright under a restricted one). The adequacy review also confirmed `"spel-injection"` as a genuinely new category (not a reuse of `"server-side-template-injection"`, which would risk exactly the `vuln_class`-spelling collision `BUG-0040` already showed causes real scoring bugs) and confirmed URL-encoding of the `T(...)` payload as a query param is not a real risk (matches this session's own earlier live-boot precedent).

  Live-verified end to end through `fuzzlab.harness.multitarget.run_targets` against Expedia's real, locally-booted deployment and real ground truth (`lab/ground-truth-expedia-clone/`) before considering this complete, per `PA-0042`'s own rule (this component's own precedent, applied to itself for the second time). Real result: `tp=1, fn=0, fp=0` — a real true positive with zero false positives, including an explicit secondary check confirming the secure twin (`LABGEN-EXP-0002`) returns `None`.

  **This makes `spel_injection` category 5's second genuinely-detecting vuln class, and — combined with `open_redirect`'s own real detection — the first time this category's Phase E combined test scores `generalizes=True` for real** (two independently-mapped classes, two different stacks, each with real recall > 0 — not one class counted twice). Updated `tests/test_labgen_spring_boot_expedia_multitarget.py` and `tests/test_multitarget_category5_combined.py` to the new, real scored numbers.
  1. **Tests**: 3 new unit tests in `tests/test_oracle_vectors.py` (confirmed on a real-shaped `StandardEvaluationContext` sender; not confirmed on a real-shaped `SimpleEvaluationContext` sender; and an explicit regression test proving the strategy's own `T(...)`-based canary does NOT fall into the bare-arithmetic false-positive trap the adequacy review caught — a sender that evaluates arithmetic but rejects type references must not be confirmed). 1 new test in `tests/test_runmode.py`. Whole-repo `pytest tests/` run before considering this increment complete (`PA-0036`) — see Effectiveness for the pass/skip/fail counts.
  2. `docs/components/02-core-library/requirements.md`/`docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-FUZZ-15`.
  3. `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated.
- Impact (other components / project): `fuzzlab/core/runmode.py` (CORE component, one new dict entry), `fuzzlab/audit/rules_data/default_rules.json` (new rule, checked for `name_regex` collisions against every existing manifest's real param names before landing — none found), `tests/test_labgen_spring_boot_expedia_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, real scored-number updates). No other of this component's own files touched.
- Risk (level; mitigation or accepted-risk justification): low. New code, but narrowly scoped (one new `ConfirmationStrategy`, one new `Rule`, two dict entries) and thoroughly verified: the adequacy review's own blocking finding (the guaranteed-false-positive arithmetic canary) was caught and fixed before any code was written, live end-to-end verification proves zero false positives on the real secure twin, and the whole-repo suite (see Effectiveness) confirms zero regressions across every other category's own tests.
- Deliverables:
  - [x] `fuzzlab/oracle/strategies.py`: `SpelInjectionStrategy` + registrations — done
  - [x] `fuzzlab/audit/rules_data/default_rules.json`: `R-SPEL-INJECTION` — done
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["spel_injection"]` — done
  - [x] `tests/test_oracle_vectors.py`: 3 new tests — done
  - [x] `tests/test_runmode.py`: 1 new test — done
  - [x] `tests/test_labgen_spring_boot_expedia_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates, `generalizes=True` — done
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-FUZZ-15` — done
  - [x] `CHANGELOG.md` line — done
  - [x] `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5 updated — done
- Effectiveness (assessed 2026-09-23): Met, with evidence beyond a returned `Verdict`. The adequacy review caught a real, blocking, 100%-reproducible false-positive design flaw before any code was written — exactly the review gate's purpose. Live end-to-end verification then proved the corrected design real: `tp=1, fn=0, fp=0` against Expedia's real deployment, and the combined Phase E test now scores `generalizes=True` for real, the first time this category has demonstrated genuine cross-target transfer. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-FUZZ-0027 — Fix two real defects found live-verifying `open_redirect`'s `_VULN_TO_CATEGORY` mapping (`BUG-0039`/`BUG-0040`) (FR-FUZZ-14) (2026-09-23)
- Change: Companion fix to `CC-CORE-0021` (category 5's `open_redirect` → `_VULN_TO_CATEGORY` mapping), owned here since both defects live in this component's own files:
  1. **`BUG-0039`** (`fuzzlab/tools/probesender.py`): `RequestsProbeSender.send()` never set `allow_redirects=False`, so any confirmation strategy reading a raw `Location` header (only `OpenRedirectStrategy` today) would crash or silently mis-follow a redirect against a real target — `fuzzlab.core.http`'s own authenticated client already set this; `RequestsProbeSender` alone did not. Fixed additively; `tests/test_probesender.py`'s fake session updated to accept and assert the new kwarg.
  2. **`BUG-0040`** (`fuzzlab/oracle/strategies.py`): `OpenRedirectStrategy.vuln_class` was `"open-redirect"` (hyphenated, matching this strategy's own `category` attribute) instead of `"open_redirect"` (underscored, this project's established ground-truth `vuln_class` convention every sibling strategy already follows) — a real confirmation would never score as a true positive no matter how correct the underlying detection was. Fixed; `category` left unchanged (a separate, correctly-hyphenated namespace).

  Both were caught by actually running `fuzzlab.harness.multitarget.run_targets` end to end against a real, locally-booted target and real ground truth (`PA-0042`, added by this same entry) — neither would have been caught by unit-testing `OpenRedirectStrategy.confirm()` alone against a hand-written fake, which is exactly what this component's own `tests/test_oracle_vectors.py` does and continues to pass unchanged throughout both fixes.
- Impact (other components / project): `RequestsProbeSender`'s fix affects every existing caller across every category's own Phase E `multitarget.py` tests (LAB component) — all re-verified green by the full whole-repo suite, see `CC-CORE-0021`. No other FUZZ-component file touched.
- Risk (level; mitigation or accepted-risk justification): low. Both fixes are strictly corrective (the prior behavior was either a crash or a silent scoring miss, never a working case these fixes could regress) and verified against this component's own full existing test suite (`test_oracle_vectors.py`, `test_probesender.py`, `test_ml_ranker.py`, `test_ml_ranking.py`, `test_web_findings.py`, `test_web_overview.py` — all still pass; the last four confirm `"open-redirect"`'s *category*-namespace spelling is genuinely untouched by the `vuln_class` fix).
- Deliverables:
  - [x] `fuzzlab/tools/probesender.py`: `allow_redirects=False` — done
  - [x] `fuzzlab/oracle/strategies.py`: `OpenRedirectStrategy.vuln_class` corrected — done
  - [x] `tests/test_probesender.py`: fake session + new assertion — done
  - [x] `docs/bugs/BUG-0039-*.md`/`BUG-0040-*.md`, `ERROR_LOG.md`, `docs/PREVENTIVE_ACTIONS.md` (`PA-0041`/`PA-0042`) — done
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-FUZZ-14` — done
  - [x] `CHANGELOG.md` line (shared with `CC-CORE-0021`) — done
- Effectiveness (assessed 2026-09-23): Met. Both fixes verified live against a real, locally-booted target (see `CC-CORE-0021`'s own Effectiveness section for the exact `tp`/`fp` numbers) and this component's full existing test suite re-run with no regressions.

### CC-FUZZ-0025 — Build the M1 timing-differential ReDoS oracle mechanism (`RegexDosStrategy`) (2026-09-22)
- Change: built `RegexDosStrategy` (`fuzzlab/oracle/strategies.py`), the
  `("regular-expression", "redos")` confirmation strategy
  `docs/architecture/oracle-confirmation.md` previously listed only as
  deferred ("could use M1 timing later"). Companion change to
  `CC-LAB-0076` (`docs/components/01-target-lab/change-control.md`), whose
  `node_express` ReDoS lab cells needed a real confirmation mechanism.
  - Registered `category = "regular-expression"` (the reference-folder name
    the oracle-confirmation doc's own "out of scope" list already used),
    `vuln_class = "redos"`, `mechanism = "differential-timing"` (M1); added
    to `default_strategies()` and `_CATEGORY_TO_CLASS`.
  - This is a genuinely new M1 *variant*, not a reuse of the existing
    `ConfirmationStrategy._confirm_timing` helper (already shared by
    `SqliTimingStrategy`/`CommandInjectionStrategy`) with a new template
    list: `_confirm_timing`'s templates each embed an explicit,
    attacker-*requested* delay (`SLEEP({d})`/`sleep {d}`) it checks the
    target both exceeds AND tracks; a ReDoS payload requests no duration at
    all (the blowup is an emergent property of the target's own content,
    which the strategy neither sees nor controls). `RegexDosStrategy`
    instead escalates across `_REDOS_TEMPLATES` -- several independent,
    single-nesting-level classic catastrophic-backtracking shapes -- and
    confirms when **at least two** independently clear a robust-baseline
    threshold (`Baseline.exceeds`, reused from `fuzzlab/oracle/baseline.py`,
    with `floor`/`k` overridden per-strategy to this mechanism's own
    bounded, tens-to-low-hundreds-of-milliseconds probe magnitude rather
    than `_confirm_timing`'s multi-second-tuned defaults). Full design
    rationale, including the nesting-depth-escalation alternative that was
    calibrated and explicitly rejected as unsafely explosive, is in
    `docs/architecture/oracle-confirmation.md`'s new "`regular-expression`
    (ReDoS, CWE-1333)" section and the class's own docstring.
  - `docs/architecture/oracle-confirmation.md` updated: new section
    describing the built mechanism (moved out of the "Out of scope" list at
    the bottom, which is updated to say so).
- Impact (other components / project): additive only -- one new strategy
  class, two registry entries (`default_strategies()`,
  `_CATEGORY_TO_CLASS`), no existing strategy's behavior changed. Consumed
  by `CC-LAB-0076`'s `node_express` ReDoS cells as the class this shape
  needs when scanned live; not yet wired into any live scanning run against
  an external target, and not wired into `fuzzlab/harness/multitarget.py`
  (both out of this change's scope).
- Risk (level; mitigation or accepted-risk justification): Medium,
  documented plainly rather than understated. Unlike every other M1 use in
  this file (SQLi/command-injection, each of which supplies its own exact
  requested delay), this mechanism's confirmation is inherently
  probabilistic against an arbitrary black-box target: it can only detect
  ReDoS when the target's own content happens to contain a run of the
  character class one of `_REDOS_TEMPLATES` targets, which the strategy has
  no way to know in advance. Mitigated by using several templates
  targeting different common run shapes (letters, digits, an alternation)
  to raise the odds, and by stating this limitation explicitly in the
  class's own docstring and in the architecture doc rather than presenting
  this mechanism as equivalent-confidence to the SQLi/cmdi M1 uses. The
  probe-magnitude side of the risk (an uncalibrated timing probe either
  never firing or blowing up unboundedly against a real target) is
  mitigated by the `floor`/`k` calibration recorded in `CC-LAB-0076` and by
  every template in `_REDOS_TEMPLATES` being single-nesting-level only
  (nesting-depth escalation was calibrated and rejected specifically
  because of its unbounded-blowup risk).
- Deliverables:
  - [x] `RegexDosStrategy` class + `_REDOS_TEMPLATES` — done
  - [x] Registered in `default_strategies()` / `_CATEGORY_TO_CLASS` — done
  - [x] Unit tests against a deterministic fake sender
    (`tests/test_oracle_redos.py`: confirms on a vulnerable fake, stays
    fail-closed on a secure/escaped fake, on a single-slow-reading fake,
    and on a within-jitter fake) — done
  - [x] `docs/architecture/oracle-confirmation.md` updated from "deferred"
    to describe the real, built mechanism — done
  - [x] `requirements.md` (`FR-FUZZ-12`) — done
- Effectiveness (assessed 2026-09-22): unit tests pass and correctly
  distinguish a simulated vulnerable target (confirms, needs >=2 templates
  above threshold) from a simulated secure one (does not confirm) and from
  ordinary jitter (does not confirm on a single slow reading or a
  within-tolerance gap). The underlying real-world mechanism (that a real
  regex engine really does blow up on these templates, and that escaping
  really does prevent it) is proven with real execution in `CC-LAB-0076`'s
  `tests/test_labgen_redos.py`, not re-proven here (this entry's own tests
  are decision-logic tests against a fake sender, consistent with how this
  file's other M1/M8/M10 strategies are tested). Not yet assessed against
  a live external target.
### CC-FUZZ-0026 — Give header-carried ground-truth points their own honest skip reason (2026-09-23)

- Change: `fuzzlab.harness.auto.points_from_ground_truth` treated a
  header-located ground-truth point (``location="header"``) as a
  client-only/DOM point, skipping it under the reason string
  ``"client-only/DOM (needs browser execution, M6)"`` — factually wrong: a
  header-carried value has nothing to do with DOM rendering or a browser,
  it is simply not yet expressible by this function's point model or by
  any of `fuzzlab.tools.probesender`'s senders. Found while wiring category
  4's Twitch app into Phase E (`CC-LAB-0176`): its webhook-signature case
  (`TWCH-0001`, `lab/ground-truth-twitch-clone/`) is the project's first
  header-located ground-truth point, and the misleading reason string
  surfaced immediately on inspection. Fixed with a distinct `is_header`
  branch and its own reason
  (``"header-carried injection point (no header-capable point/sender
  wiring yet, FR-FUZZ-13)"``), never folded into the DOM reason. Building
  actual header-injection support (a point type + a header-capable sender)
  is real, sized follow-on work, not attempted here — this change only
  makes the current, correct "cannot be audited yet" outcome honestly
  labeled.
  - **Not routed through the bug protocol**: the *behavior* was already
    correct (the point was, and still is, excluded from probing either
    way) — only the *diagnostic reason string* was inaccurate. No test
    asserted a wrong result, no crash, no regression; this is a clarity
    fix to a message, not a defect in what the function does. Recorded
    here in full regardless, per this component's own bookkeeping
    discipline.
  New/changed files:
  - `fuzzlab/harness/auto.py` (`points_from_ground_truth`)
  - `tests/test_auto.py` (`test_points_from_ground_truth_gives_header_points_their_own_skip_reason`)
  - `docs/components/07-fuzzing-harness-and-oracle/requirements.md` (`FR-FUZZ-13`, new)
- Impact (other components / project): none outside this function's own
  return value (`skipped`'s reason strings) — the set of points actually
  audited is unchanged (header points were already excluded before this
  change), so no scoring/detection behavior changes for any existing
  ground truth. `tests/test_auto.py`'s own pre-existing assertion (every
  default-lab skip reason ends in `"M6)"`) still holds unchanged, since the
  default `lab/ground-truth/` has no header-located points.
- Risk (level; mitigation or accepted-risk justification): **low**. A
  message-accuracy fix with no behavior change to what is audited;
  verified by re-running the full non-slow suite (1606 passed, same 15
  pre-existing unrelated failures) and category 4's own real live-boot
  Phase E test.
- Deliverables:
  - [x] `points_from_ground_truth` gives header-located points their own,
    accurate skip reason
  - [x] New test proving the reason string is accurate and distinct from
    the DOM/browser one
  - [x] Full non-slow suite re-verified green (no new failures, one new
    pass)
- Effectiveness (assessed 2026-09-23): met — `TWCH-0001`'s skip reason no
  longer claims a browser is the blocker.

### CC-FUZZ-0024 — Wire M10 grey-box confirmation into the oracle pipeline (2026-09-22)
- Change: built the seam layer for the M10 grey-box mechanism whose pure decision
  logic (`fuzzlab/greybox/confirm.py::greybox_confirms()`/`m10_evidence()`) and
  source protocols (`fuzzlab/greybox/coverage.py::CoverageSource`,
  `fuzzlab/greybox/dbfault.py::DbFaultSource`, plus their `InMemory*` fakes and live
  `File*` readers) were already built and unit-tested in an earlier Phase 3 lane.
  Added `GreyboxConfirmationStrategy` to `fuzzlab/oracle/strategies.py`: mechanism
  `grey-box-coverage`, `applies()` scoped to `category in ("sql-injection", "xss")`
  (a cross-cutting secondary layer, same pattern as M8 alongside M1 for
  command-injection — not one class). It takes an optional `CoverageSource` and an
  optional `DbFaultSource` by constructor injection (both default `None`) and
  no-ops (`confirm()` returns `None`, no probe sent) when neither is given — same
  seam shape as the M6 `BrowserExecutor`/M8 `OobListener`. When at least one source
  is given, it further requires the `sender` to expose `send_correlated(url, param,
  value, *, method, location) -> (Probe, request_id)` (the contract already
  established for the live grey-box run driver, `fuzzlab/greybox/run.py`'s
  `RequestsCorrelatingSender`) so its one probe can be matched back to the
  coverage/DB-fault side channel by a fresh `X-Fzl-Cov`-style id; without a
  `send_correlated`-capable sender it also no-ops (fail-closed, never a guess).
  Wired into `default_strategies(coverage=None, dbfault=None)`,
  `Oracle(coverage=None, dbfault=None)` (`fuzzlab/oracle/oracle.py`),
  `run_pipeline(coverage=None, dbfault=None)` (`fuzzlab/harness/pipeline.py`), and
  `run_auto(coverage=None, dbfault=None)` (`fuzzlab/harness/auto.py`); `fuzzlab
  auto` gained `--greybox-coverage-file DIR`/`--greybox-dbfault-file DIR` (default
  off, same shape as `--oob`), which construct `FileCoverageSource`/
  `FileDbFaultSource` against that directory only when passed.
- **Provenance note**: this lane was originally built on the diverged branch
  `claude/trusting-noether-heon0n` as `CC-FUZZ-0020`/`FR-FUZZ-9` (its own local
  numbering), independently of this branch's Wave 1a–3 dispatch. Cherry-picked and
  renumbered on merge into this branch — `CC-FUZZ-0020` and `FR-FUZZ-9` here
  already belonged to this branch's own D0a (`--dry-run` on `fuzz`/`auto`) and
  B0's coverage-frontier `metric_series` emitter, an unrelated same-numbered
  collision from independent, non-communicating concurrent work (see
  `docs/PREVENTIVE_ACTIONS.md` PA-0031 — pre-assigned numbers only prevent
  collisions *within* one dispatch; they cannot prevent collisions against a
  wholly separate branch neither dispatch knew existed). No functional content
  changed from the original commit; only IDs and cross-references were
  renumbered (`CC-FUZZ-0020`→`0024`, `FR-FUZZ-9`→`11`) and this note added.
- Impact (other components / project): FUZZ only — additive. `Oracle.__init__` and
  `default_strategies()`/`run_pipeline()`/`run_auto()` gained optional
  `coverage=None`/`dbfault=None` keywords; every existing caller that omits them is
  unaffected (no behavior change, same as `oob=None`/`browser=None`). Sql-injection
  and xss candidates that the black-box strategies leave unconfirmed can now be
  confirmed via covered-sink (+DB-fault for sqli) evidence, *once* both an
  instrumented lab's coverage/DB-fault side channel and a correlating oracle probe
  sender exist — neither exists yet in this repo, so in a live `fuzzlab auto` run
  today the new flags construct real `FileCoverageSource`/`FileDbFaultSource`
  readers but the strategy still no-ops (the shipped `RequestsProbeSender`/
  `SeamProbeSender` do not implement `send_correlated`). That live correlating
  sender and the on-host pcov/DB-fault shim remain out of scope here (on-host
  last-mile work, `docs/ON_HOST_TASKS.md`) — this change is deliberately scoped to
  the offline-buildable wiring layer only, not the live plumbing.
- Risk (level; mitigation): low — pure additive wiring with every new keyword
  defaulting to `None`/off, so no existing caller's behavior changes (verified by
  the full fast suite staying green). The one new behavior (sending a probe) is
  gated behind *both* an injected source and a `send_correlated`-capable sender, so
  it cannot fire against any sender or run configuration that exists in this repo
  today. Mitigated further by: (1) fail-closed by construction — `confirm()`
  returns `None` on either gate missing or when `greybox_confirms()` itself returns
  `False`, never a guess; (2) `applies()` scoped tightly to the two categories
  `greybox_confirms()` actually has a rule for, so it never masquerades as a
  confirmer for classes it cannot judge; (3) tests on the real strategy against
  real `InMemoryCoverageSource`/`InMemoryDbFaultSource` fakes (not mocks of this
  strategy's own code, per PA-0005), including the full `Oracle.confirm()` pipeline
  end to end.
- Deliverables:
  - [x] `GreyboxConfirmationStrategy` (M10, categories `sql-injection`/`xss`,
    constructor-injected `CoverageSource`/`DbFaultSource`, fail-closed no-op
    without a source or a correlating sender) — `fuzzlab/oracle/strategies.py` —
    done.
  - [x] Wired into `default_strategies()`, `Oracle`, `run_pipeline()`, `run_auto()`,
    and `fuzzlab auto --greybox-coverage-file`/`--greybox-dbfault-file` — done.
  - [x] Tests with real `InMemoryCoverageSource`/`InMemoryDbFaultSource` fakes (not
    mocks of our own code): `tests/test_oracle_greybox.py` (12 tests) — done,
    re-run clean against this branch's tree (22/22 with `test_oracle_oob.py`
    combined) at merge time.
  - [x] `requirements.md` `FR-FUZZ-11` added; `docs/ARCHITECTURE.md` Oracle status
    note updated — done.
  - [x] Full suite green on this branch's merged tree — done (see merge commit).
  - [ ] Live correlating oracle probe sender (a `send_correlated`-capable
    `RequestsProbeSender`/`SeamProbeSender` variant attaching a real `X-Fzl-Cov`
    header) and the on-host pcov/DB-fault shim behind `FileCoverageSource`/
    `FileDbFaultSource` — on-host last-mile, tracked in `docs/ON_HOST_TASKS.md`,
    not started here.
- Effectiveness (assessed 2026-09-22): effective for the wiring layer —
  `tests/test_oracle_greybox.py` proves the strategy confirms sqli only with both
  sink-covered and db-fault evidence, confirms xss with sink-covered evidence
  alone, no-ops without a source, no-ops without a `send_correlated`-capable
  sender, is registered in `default_strategies()`, and integrates through the full
  `Oracle.confirm()` pipeline. Live-target effectiveness is unverified and
  unverifiable in this sandbox — it depends on on-host infra this change does not
  build (tracked above, not a regression this lane introduced).

### CC-FUZZ-0023 — Build M8 out-of-band (OOB) callback mechanism (2026-09-22)
- Change: implemented the previously-unbuilt M8 mechanism from
  `docs/architecture/oracle-confirmation.md` — out-of-band callback confirmation for
  blind injection classes with no direct response difference. Added
  `fuzzlab/oracle/oob.py::OobListener`: a loopback-only (`127.0.0.1`/`localhost`
  only — raises `ValueError` on any other host), in-memory, per-run HTTP callback
  tracker (`register()` mints an unguessable token, `callback_url()` gives the URL to
  embed in a payload, `wait_for()` polls for a hit); it binds no socket until
  `start()` is called (default-off, mirroring the M6 `BrowserExecutor`/proxy/desync
  dual-use gating pattern in this project — not a general-purpose, publicly reachable
  collaborator-style service). Added `CommandInjectionOobStrategy` (mechanism
  `oob-callback`, category `command-injection`) to `fuzzlab/oracle/strategies.py`:
  embeds a fresh canary URL in `curl`/`wget` shell-fetch payloads and confirms only if
  that exact token is later requested; it takes the listener by injection and no-ops
  (returns `None`, no probe sent) when none is given, so it never reaches for a real
  listener on its own. Wired into `default_strategies(oob=...)`, `Oracle(oob=...)`
  (`fuzzlab/oracle/oracle.py`), `run_pipeline(oob=...)`
  (`fuzzlab/harness/pipeline.py`), and `run_auto(oob=...)`
  (`fuzzlab/harness/auto.py`); `fuzzlab auto` gained `--oob` (default off, same shape
  as `--browser`), which constructs and starts the listener only when passed and
  tears it down in a `finally` block after the run.
- **Provenance note**: this lane was originally built on the diverged branch
  `claude/trusting-noether-heon0n` as `CC-FUZZ-0019`/`FR-FUZZ-8` (its own local
  numbering), independently of this branch's Wave 1a–3 dispatch. Cherry-picked and
  renumbered on merge — `CC-FUZZ-0019` and `FR-FUZZ-8` here already belonged to
  this branch's own C1/M8-wiring lane (an unrelated, same-numbered lane about
  wiring mutation-engine *variants* into the attempt path — a task-numbering
  coincidence with oracle mechanism "M8", not the same M8). No functional content
  changed from the original commit; only IDs and cross-references were renumbered
  (`CC-FUZZ-0019`→`0023`, `FR-FUZZ-8`→`10`) and this note added.
- Impact (other components / project): FUZZ only — additive. `Oracle.__init__` and
  `default_strategies()`/`run_pipeline()`/`run_auto()` gained an optional `oob=None`
  keyword; every existing caller that omits it is unaffected (no behavior change,
  same as `browser=None`). Blind command injection (Tier 3,
  `docs/architecture/oracle-confirmation.md`) now has a working M8 confirmer
  alongside the existing M1 timing one — `applies()` scopes both to the
  `command-injection` category, so the oracle tries timing first, OOB second, and a
  target that suppresses timing signal but still executes the shell fragment (fetches
  the canary) is now confirmable. No schema change (findings already carry an
  arbitrary `mechanism` string). No traffic sent unless `--oob`/`--authorized` are
  both given, and the listener never leaves loopback.
- Risk (level; mitigation): low-medium — a new local network listener is more
  sensitive than a pure library change. Mitigated by: (1) the loopback-only guard in
  `OobListener.__init__` (raises before binding on any non-loopback host); (2)
  default-off at every layer (constructor argument defaults to `None`; CLI flag
  defaults to `False`); (3) no DNS component, no external reachability, no
  persistence beyond the process — it cannot function as a general-purpose OOB
  interaction/collaborator service; (4) real tests exercising the actual socket (not
  a mock) confirm it only ever records a hit for the exact token requested and never
  cross-wires tokens; (5) fail-closed by construction — `confirm()` returns `None` on
  timeout or when no listener is injected, never a guess.
- Deliverables:
  - [x] `OobListener` (loopback-only, default-off, real HTTP listener + token
    register/callback_url/wait_for) — `fuzzlab/oracle/oob.py` — done.
  - [x] `CommandInjectionOobStrategy` (M8, category `command-injection`) — done.
  - [x] Wired into `default_strategies()`, `Oracle`, `run_pipeline()`, `run_auto()`,
    and `fuzzlab auto --oob` — done.
  - [x] Tests on the real listener and the real strategy (not mocks of our own code):
    `tests/test_oracle_oob.py` (10 tests) — done.
  - [x] `requirements.md` `FR-FUZZ-10` added; `docs/ARCHITECTURE.md` Oracle status
    note updated — done.
  - [x] Full suite green on this branch's merged tree — done (see merge commit).
- Effectiveness (assessed 2026-09-22): effective — `tests/test_oracle_oob.py` proves
  the listener records a real hit end to end (real socket, real HTTP request via
  `urllib`), times out cleanly on a benign/secure target, does not cross-wire two
  concurrent tokens, and that `Oracle.confirm()` reaches a `mechanism="oob-callback"`
  verdict through the full pipeline wiring (not the strategy in isolation). Full
  fast suite on this branch's merged tree: see the merge commit for the exact count.

### CC-FUZZ-0022 — `--dry-run` CLI flag on `greybox-run` (lane D0b) (2026-09-22)
- Change: `fuzzlab/greybox/greybox_cli.py::build_parser()` gained `--dry-run` (via
  the shared `fuzzlab/cli_dryrun.add_dry_run_flag()`), and `main()` checks
  `args.dry_run` first — before the `--authorized` gate and before any
  `contract.load()`/points-sourcing/`Store()`/sender/coverage-source/dbfault-source/
  lab-control construction — and calls `fuzzlab/cli_dryrun.report("greybox-run",
  args)`, reusing the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015), then returns 0 before any probe/side-
  channel read happens. No traffic is sent. `greybox-run` was already registered
  in `fuzzlab/web/commandspec.py`'s `_REGISTRY` (introspecting
  `greybox_cli.build_parser()` directly), so the planned argv/display
  automatically reflects every flag on the parser — including the
  `--mutation-variants`/`--max-mutation-variants`/`--allow-destructive` flags Lane
  C1/M8-wiring (`CC-FUZZ-0019`) added to this same parser — with no separate
  wiring needed for those three flags specifically. Sequenced after Wave C1
  (genuine file overlap on `fuzzlab/greybox/greybox_cli.py`, per the build plan's
  D0b entry), on top of `CC-FUZZ-0019`. Deliberately bypasses the `--authorized`
  requirement for the dry-run preview itself (nothing is sent either way,
  mirroring D0a's `CC-FUZZ-0020` and the web launcher's own dry-run route).
  Unchanged when `--dry-run` is absent. Completes lane group B's D0
  (`--dry-run` on every CLI entry point); D0a (`CC-FUZZ-0020`, plus CC-CRAWL-0007/
  CC-AUD-0015/CC-MUT-0010/CC-PROXY-0017/conditional CC-UI-0027) covered the other
  six commands.
- Impact (other components / project): FUZZ only, plus an incidental UI effect —
  `greybox-run`'s introspected `build_parser()` now surfaces a `--dry-run` checkbox
  in the web launcher automatically alongside the pre-existing mutation-variant
  flags (no `fuzzlab/web/app.py` change; the web launcher already has its own
  dry-run route, unaffected by this CLI-level flag). No schema/store change.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect, placed ahead of the `--authorized` check by design (documented above so
  it isn't mistaken for a gate bypass on real execution). Mitigated by
  `tests/test_cli_dry_run.py` (new greybox-run cases: flag present; the plan
  reflects `--mutation-variants`/`--max-mutation-variants`/`--allow-destructive`
  when passed; `run_greybox`/`points_from_store`/`RequestsCorrelatingSender`/
  `Store.__init__`/`import_spider` patched to raise if called; a case also asserts
  `would_execute: False` is reported when `--authorized` is absent) and the
  unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `greybox-run`'s parser — done.
  - [x] Short-circuit ahead of the `--authorized` gate in `main()`, calling the
    shared `cli_dryrun.report()` — done.
  - [x] Dry-run preview correctly reflects the C1-added mutation-variant flags —
    done (verified via `introspect()`'s generic parser walk, no special-casing
    needed; covered by a dedicated test).
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab greybox-run --dry-run`
  prints the planned argv/command (including any mutation-variant flags passed)
  and returns 0 without constructing a `Store`, sender, coverage/dbfault source, or
  lab control, and without reading `--ground-truth`/`--spider-db`; verified
  directly and via the new tests.
### CC-FUZZ-0021 — coverage-frontier `metric_series` emitter (lane B0, Wave 1b) (2026-09-22)
- Change: `fuzzlab/greybox/run.py::run_greybox()` now emits a per-attempt
  `metric_series` row tracking the run-wide `CoverageFrontier`'s growth,
  additive alongside the pre-existing `greybox_frontier_size` `run_metrics`
  end-of-run total. New private helper `_record_coverage_metric(logger, step,
  frontier)` writes `source="coverage"`, `key="coverage/lines"`, `step=`
  the running attempt count, `value=` the frontier's current `.size` — per
  `docs/UI_IMPLEMENTATION_PLAN.md` §3 (B0)'s resolved schema notes (R-05),
  which name `coverage/lines` as the worked example key for this exact
  source. `run_greybox()` opens one `fuzzlab.core.store.MetricLogger(store,
  run_id, source="coverage")` at the top of the run (alongside the existing
  `frontier = CoverageFrontier()`), calls `_record_coverage_metric` once per
  attempt right after `summary["attempts"] += 1`, and flushes it once at the
  end of the run before the summary is returned. Follows the same
  small-function-slotted-into-the-loop pattern lane C1 established in this
  file (`mutation_variant_probes` / `_record_accepted_variant`) specifically
  so this sub-lane could land cleanly after it. No existing coverage-tracking
  or attempt-path behavior changed — this is additive metric emission only;
  `frontier`, `summary`, the `attempt`/`run_metrics` writes, and the
  mutation-variant wiring (`CC-FUZZ-0019`) are all untouched.
- Impact (other components / project): FUZZ only for the write path (new
  dependency on `fuzzlab.core.store.MetricLogger`/`metric_series`, landed by
  `CC-CORE-0018`). Enables — but does not itself build — a future UI reader
  (`docs/UI_IMPLEMENTATION_PLAN.md`'s U5 lane, "metric_series tab" /
  Datasette-style store exploration) to chart per-run coverage-frontier
  growth. This is the one B0 emitter sub-lane the build plan
  (`docs/PARALLEL_LANE_BUILD_PLAN.md`, "B0/C1 file-overlap risk" note) flagged
  as needing to land after C1's M8-wiring (`CC-FUZZ-0019`) rather than in
  parallel with it, since both touch `run.py`'s attempt/summary loop; it was
  dispatched only after confirming `CC-FUZZ-0019`/`CC-FUZZ-0020` were already
  merged into the base branch. No interface/contract change to
  `run_greybox()`'s signature or return value (`summary` dict unchanged).
- Risk (level; mitigation): low — purely additive write path (one buffered
  `MetricLogger` per run, flushed once at the end plus its own
  `flush_every=200` periodic flush; non-finite values are dropped with a
  warning by `log_scalar`/`MetricLogger.log` itself, never reaching this
  component). No change to reward shaping, screening, M10 confirmation, or
  the `attempt`/`run_metrics` tables. `MetricLogger` holds `store.conn` for
  the lifetime of one `run_greybox()` call on the same thread that already
  drives every other `store.conn` write in this function, so PA-0023
  (thread-affine `sqlite3` connection handles) does not apply — no new
  cross-thread caching is introduced.
- Deliverables:
  - [x] `_record_coverage_metric()` helper + wiring into `run_greybox()`'s
    attempt loop and end-of-run flush — done.
  - [x] Tests: `tests/test_greybox_live.py::test_run_greybox_emits_coverage_metric_series`
    and `::test_run_greybox_coverage_metric_series_isolated_per_run` — done.
  - [x] Confirmed lane C1's existing tests in `tests/test_greybox_live.py`
    pass unmodified (18/18, including the 16 pre-existing C1/base tests) —
    done.
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md`
    updated in place with the new emission behavior — done.
  - [x] `CHANGELOG.md` line — done.
- Effectiveness (assessed 2026-09-22): intent achieved — `run_greybox()` now
  writes `coverage/lines` rows to `metric_series` per attempt, verified by
  the new tests reading them back directly from the store (values match the
  frontier's growth exactly, isolated correctly per `run_id`), with no
  regression in any pre-existing `test_greybox_live.py`/`test_greybox.py`
  test.

### CC-FUZZ-0020 — `--dry-run` CLI flag on `fuzz` + `auto` (lane D0a) (2026-09-22)
- Change: `fuzzlab/tools/blind_sqli_fuzzer.py::build_parser()` and
  `fuzzlab/harness/auto_cli.py::build_parser()` both gained `--dry-run` (via the
  shared `fuzzlab/cli_dryrun.add_dry_run_flag()`). Both `main()`s check
  `args.dry_run` first — before the `--authorized` gate — and call
  `fuzzlab/cli_dryrun.report("fuzz", args)` / `report("auto", args)` respectively,
  reusing the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015), then return 0 before any sender/`Store`/
  oracle is constructed. No probe or confirmation traffic is sent. Deliberately
  bypasses the `--authorized` requirement for the dry-run preview itself (nothing is
  sent either way, mirroring the web launcher's own dry-run route, which also does
  not require `authorized`). Unchanged when `--dry-run` is absent. This is one
  reserved number covering both commands since they land in a single lane/commit
  (per the plan's numbering note); `fuzzlab greybox-run` is explicitly out of scope
  here — that is lane D0b's `CC-FUZZ-0022`, sequenced after Wave C1's `CC-FUZZ-0019`
  M8-wiring lane, which this lane does not touch.
- Impact (other components / project): FUZZ only, plus an incidental UI effect — see
  CC-UI-0027 (introspected `build_parser()` surfaces the new checkbox for both `fuzz`
  and `auto` in the web launcher automatically; `fuzzlab/web/app.py` untouched). No
  schema/store change; no interaction with Wave C1's M8-wiring (different files:
  that lane touches `fuzzlab/greybox/run.py`/`greybox_cli.py`, this lane does not).
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect, placed ahead of the `--authorized` check by design (documented above so it
  isn't mistaken for a gate bypass on real execution). Mitigated by
  `tests/test_cli_dry_run.py` (fuzz + auto cases: flag present, report printed,
  `establish_baseline`/`run_fuzzing_cycle` and `run_auto`/`Store.__init__` patched to
  raise if called; a fuzz case also asserts `would_execute: False` is reported when
  `--authorized` is absent, i.e. the preview correctly reflects that a real run would
  be refused) and the unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `fuzz`'s and `auto`'s parsers — done.
  - [x] Short-circuit ahead of the `--authorized` gate in both `main()`s, calling the
    shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs, for both commands —
    done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab fuzz --dry-run` and
  `fuzzlab auto --dry-run` both print the planned argv/command and return 0 without
  constructing a sender, `Store`, or oracle; verified directly and via the new tests.
### CC-FUZZ-0019 — Wire mutation-engine variants into `greybox-run`'s attempt path (Lane C1/M8-wiring) (2026-09-22)
- Change: `docs/PHASE_8_PLAN.md`'s T8.5 ("emit accepted variants into the attempt
  path") only reached the standalone `fuzzlab mutate-run` CLI
  (`fuzzlab/mutation/cli.py`/`fuzzlab/mutation/run.py`) — confirmed before this
  change: no `mutation`/`variant` references anywhere in `fuzzlab/greybox/run.py`
  or `fuzzlab/greybox/greybox_cli.py`. `fuzzlab/greybox/run.py` now wires the
  mutation engine into the **main harness's own** attempt loop:
  - New `mutation_variant_probes()` (function boundary kept separate from the main
    loop, per the build-plan's note that a later lane adds a `metric_series`
    emitter to this same file): given the point's existing sqli/xss `ProbeSpec`s,
    applies up to `max_variants` of the mutation engine's operators
    (`fuzzlab/mutation/operators.py`, T8.1) per base payload and keeps only the
    ones the semantics validator (`fuzzlab/mutation/semantics.py`, T8.1/
    NFR-MUT-semantics) judges meaning-preserving. Skips the `url-encode` operator
    here specifically, since the probe transport (`requests`' `params=`/`data=`)
    would percent-encode an already-percent-encoded value a second time.
  - `run_greybox(..., mutation_variants: bool = False, max_mutation_variants: int
    = 2, allow_destructive: bool = False)`: when `mutation_variants` is set, each
    point's ordered probe list is extended with that point's mutation variants,
    which then go through the **exact same** send/screening/reward/coverage/
    `record_attempt_signals` path as any other probe (one `attempt` row each,
    tagged `mutation_variant: true` in `features_json`, `payload_family =
    "mutation:<operator-id>"`).
  - New `_record_accepted_variant()`: a mutation-derived probe that actually hit
    (screening > 0) or reached new code (`new_lines > 0`) when probed live is
    written back to `payload_variant` via the existing, destructive-gated
    `fuzzlab.mutation.catalog.record_variant` (NFR-MUT-safe unchanged — same
    gate, same default-off `allow_destructive`) — exactly the write-back T8.5
    describes, now reachable from `greybox-run` too, not only `mutate-run`.
  - New summary/`run_metrics` counters: `mutation_variants_probed`,
    `mutation_variants_recorded` (`greybox_mutation_variants_probed`/
    `_recorded`, only recorded when the flag is on).
  - `greybox_cli.py`: new opt-in flags `--mutation-variants`, `--max-mutation-
    variants` (default 2), `--allow-destructive` (mirrors `mutate-run`'s own
    flag). The existing `--authorized` gate is unchanged and still required
    before anything is sent — this lane does not touch or weaken it; the new
    traffic is additional probes sent through the same already-gated sender, not
    a new unauthenticated path.
  - Default behavior is unchanged: `mutation_variants` defaults to `False`, so
    `greybox-run` without the new flag sends exactly the same probes as before
    (verified by a dedicated regression test).
- Impact (other components / project): FUZZ (`greybox/run.py`,
  `greybox_cli.py`) now has a direct, opt-in dependency on MUT
  (`fuzzlab.mutation.catalog`/`operators`/`semantics`) at import time — no
  circular import (MUT's own live-search path only imports `greybox.run` inside
  a function body, for its `make_coverage_fn`). `payload_variant` rows can now
  originate from a `greybox-run`, not only a `mutate-run`; existing readers of
  that table (`catalog.list_variants`) are unaffected — same schema
  (migration 8), no new columns. No change to the oracle's finding-writing path
  or to M10 (`greybox/confirm.py`) — mutation variants feed the attempt path
  exactly like any other probe, they are not a new confirmation mechanism.
- Risk (level; mitigation): low — additive and off by default. The new code path
  only runs when `--mutation-variants` (or `mutation_variants=True`) is passed;
  every existing call site and test keeps its old behavior (`ProbeSpec` gained
  two trailing-default fields, `base`/`operators`, so old positional/keyword
  construction is unaffected). Extra live traffic when opted in is bounded by
  `max_mutation_variants` per attack probe (NFR-MUT-bounded) and still requires
  `--authorized`. Mitigated by dedicated regression tests (below) plus the full
  suite green.
- Deliverables:
  - [x] `mutation_variant_probes()` in `fuzzlab/greybox/run.py` — done.
  - [x] `run_greybox(mutation_variants=..., max_mutation_variants=...,
    allow_destructive=...)` wiring + `_record_accepted_variant()` write-back —
    done.
  - [x] `greybox_cli.py` `--mutation-variants`/`--max-mutation-variants`/
    `--allow-destructive` flags, passed through; summary print updated — done.
  - [x] Tests in `tests/test_greybox_live.py`:
    `test_mutation_variant_probes_generates_preserving_variants`,
    `test_mutation_variant_probes_none_for_unclassed_kind`,
    `test_run_greybox_consumes_mutation_variants_into_attempt_path` (asserts
    extra `attempt` rows + `payload_variant` write-back with correct
    provenance), `test_run_greybox_mutation_variants_off_by_default`
    (backward-compat regression) — done.
  - [x] CHANGELOG.md line — done.
  - [x] `docs/components/07-fuzzing-harness-and-oracle/requirements.md` updated
    (new FR-FUZZ-8) — done.
  - [ ] T8.7's on-host exit criterion (WAF-enabled live verification) — out of
    scope for this lane per the build plan; left for a later on-host pass.
- Effectiveness (assessed 2026-09-22): effective offline — confirmed via grep
  that `fuzzlab/greybox/run.py`/`greybox_cli.py` had zero mutation/variant
  references before this change; after, `run_greybox` sends mutation-engine
  variants through the attempt path and records the accepted ones to
  `payload_variant` when opted in, proven by the new tests
  (`tests/test_greybox_live.py`), with the no-flag default path unchanged
  (regression test). On-host WAF-evasion verification (T8.7) is a separate,
  later exit check, not this lane's scope.

### CC-FUZZ-0018 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: the fuzz/oracle activities factor their argparse setup into `build_parser()`, with
  `main()` delegating — `fuzzlab/tools/blind_sqli_fuzzer.py` (`parse_args()` delegates;
  `prog="fuzzlab fuzz"`), `fuzzlab/harness/auto_cli.py`, and `fuzzlab/greybox/greybox_cli.py`
  (both keep the `p` reference so `p.error(...)` still works). Behavior-preserving — same
  flags, defaults, gates, and parsing.
- Impact: lets the web launcher introspect the fuzz/auto/greybox-run flags (CC-UI-0011).
  No CLI behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()` on fuzz/auto/greybox-run; `main()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds these specs from the
  real parsers (authorized gate derived from the `--authorized` flag).

### CC-FUZZ-0017 — Fix (BUG-0016): per-point differential coverage in `greybox-run` (2026-09-21)
- Change: `greybox/run.py::run_greybox` now credits an attack's coverage as a **per-point
  differential** — baselines are sent first to establish each point's benign coverage, and
  an attack's `new_lines_vs_baseline` drives the reward novelty and the summary
  `newcode_reward`. The global `CoverageFrontier` is retained only for the run-wide
  exploration total (`greybox_novel_lines`/`frontier_size`), not for per-attempt reward, so
  the benign baseline no longer consumes the novelty (it now scores ~0, a true control).
  Added a `coverage_lines_seen` total + metric; `greybox_cli` prints it and only warns
  ("no application coverage captured") when it is 0 (the real shim-not-wired case) instead
  of the old contradictory `newcode <= baseline` NOTE.
- Impact (other components / project): fixes the self-contradictory Part E output (step-5
  NOTE vs step-6 PASS) and makes the T3.7 "reaching new code → higher reward" property
  actually demonstrable (attack-vs-baseline), not incidentally passed via db_fault. No
  schema change; `attempt.features_json` now carries `new_lines_vs_baseline`/`cov_lines`.
  The Part F runbook exit was reframed (verify the bandit by posteriors; oracle-probes
  metric is a follow-up) — same BUG-0016 class.
- Risk (level; mitigation): low — reward is now a cleaner controlled comparison; the exit
  still passes and is more meaningful. Tests (`tests/test_greybox_live.py`): baseline earns
  0, attack new-code is per-point, and a regression proves a 2nd point's attack still
  scores new lines when those lines were globally seen by the 1st point. Suite 416 passed /
  6 skipped.
- Deliverables:
  - [x] Per-point differential coverage + `coverage_lines_seen`; corrected NOTE — done.
  - [x] Tests incl. the global-frontier-starvation regression — done.
  - [x] Part F runbook reframe; RCA `docs/bugs/BUG-0016-*`; PA-0017 — done.
  - [ ] Oracle-probes-per-finding metric so Part F can show the bandit's request savings — todo.
- Effectiveness (assessed 2026-09-21): effective in tests — benign baselines score 0, an
  attack reaching new branches scores strictly higher, and the shim-not-wired NOTE only
  fires on genuinely empty coverage. On-host re-run via `scripts/greybox_e2e.sh`.

### CC-FUZZ-0016 — Live grey-box last mile: file-backed sources + `greybox-run` (T3.2–T3.7) (2026-09-21)
- Change: built the on-host "run" side of Phase 3 so `docs/ON_HOST_RUNBOOK.md` Part E is a
  single command. New live implementations behind the existing seams:
  `greybox/coverage.py::FileCoverageSource` and `greybox/dbfault.py::FileDbFaultSource`
  read the lab shim's per-request side channel (one JSON file per `X-Fzl-Cov` id, holding
  both covered app lines and a `db_fault`/`db_error` marker); `greybox/reset.py::
  ScriptLabControl` drives `labctl.sh snapshot|restore` (fail-loud). New driver
  `greybox/run.py` (`run_greybox`, `RequestsCorrelatingSender`, `GreyboxPoint`,
  point builders) sends a benign baseline + SQLi/XSS probes per point, reads coverage
  novelty + db_fault, folds them via the already-built `shaped_reward`, writes an
  `attempt` row enriched through `record_attempt_signals`, resets between stateful points,
  and records grey-box `run_metrics`. Exposed as `fuzzlab greybox-run`
  (`greybox/greybox_cli.py`, `cli.py`), requires `--authorized`.
- Impact (other components / project): realizes the T3.2–T3.7 exit (a new-code request
  scores strictly higher; error-based SQLi sets `db_fault=1`) without touching the shared
  oracle. M10 is **advisory** in the driver (counts where grey-box would confirm via
  `greybox/confirm.py`); the oracle stays the sole, fail-closed finding-writer, and folding
  M10 into `Oracle.confirm` with a per-candidate sink line remains a follow-up (the
  contract has `vuln_class`/`sink_context` but no sink line). Depends on the target-lab
  instrumentation (CC-LAB-0009). Note (design correctness): the DB-fault signal is read
  from the same per-request side-channel file as coverage, not by tailing the MariaDB log,
  so it is attributed to exactly one request (no race).
- Risk (level; mitigation): low — all new code is additive and lab-only (gated on
  `--authorized`); the sources fail safe (missing/half-written files → no coverage / no
  fault, never a raise). Mitigated by 11 offline tests (`tests/test_greybox_live.py`):
  file sources incl. cid sanitization/missing-file, `ScriptLabControl` sequencing +
  fail-loud, `run_greybox` reward ordering + db_fault propagation + enriched rows +
  run_metrics + reset sequencing, and the correlating sender's header. Suite 405 passed /
  4 skipped.
- Deliverables:
  - [x] `FileCoverageSource` / `FileDbFaultSource` (live readers) — done.
  - [x] `ScriptLabControl` (live DB snapshot/restore) — done.
  - [x] `run_greybox` driver + `fuzzlab greybox-run` CLI — done.
  - [x] Offline tests; runbook Part E rewritten to the one-command flow — done.
  - [ ] Fold M10 into `Oracle.confirm` with a per-candidate sink line (T3.6 deepening) — todo.
- Effectiveness (assessed 2026-09-21): effective in tests — enriched attempts show the
  reward-ordering and db_fault exit properties end to end offline. The live on-lab exit is
  driven by `scripts/greybox_e2e.sh` (self-tests the side channel, then runs the pass).

### CC-FUZZ-0015 — Bandit orders oracle mechanisms in the confirm loop (T4.3) (2026-09-21)
- Change: `Oracle` takes an optional `scheduler`; `confirm` now orders its **applicable
  mechanisms** via `scheduler.order(context, arms)` (arm = `vuln_class:mechanism`,
  context = `category:sink|location`) and `update`s the scheduler per tried mechanism
  (1.0 on confirm, 0.0 on a tried-but-failed one), stopping at the first confirmation.
  So the productive mechanism is front-loaded and its confirmation short-circuits the
  expensive ones (e.g. skip the timing probes when error/boolean confirm). Threaded
  through `run_pipeline`/`run_auto`; `fuzzlab auto --bandit` constructs a
  `ThompsonBandit` (priors from `arm_priors`), loads posteriors from the store before
  the run and saves them after (persisted learning across runs). `ConfirmationStrategy`
  gained the `arm` id. Default (no scheduler) is unchanged (fixed cheapest-first order).
- Impact (other components / project): the Phase 4 request-reduction lever — fewer
  oracle probes once the bandit learns which mechanism confirms per context. No effect
  unless `--bandit`/a scheduler is passed. Posteriors live in `bandit_posteriors`.
- Risk (level; mitigation): low/medium — reordering changes which probes run, but the
  oracle stays fail-closed (ordering never changes *whether* something is confirmable,
  only the order tried) so no FP. Mitigated by tests: a trained bandit reaches the
  confirming mechanism with fewer probes than a fresh one; the oracle updates the
  scheduler; no-scheduler keeps the fixed order; `run_auto --scheduler` learns and
  persists. Suite 179 passed / 2 skipped.
- Deliverables:
  - [x] `Oracle` scheduler ordering + per-arm updates; `strategy.arm` — done.
  - [x] `run_pipeline`/`run_auto` scheduler passthrough; `auto --bandit` load/save — done.
  - [x] Tests (fewer probes when trained; updates; no-scheduler unchanged; persistence) — done.
  - [ ] On-lab exit (T4.6): bandit vs uniform on hits-per-1000-requests — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — a trained bandit cuts wasted
  probes and posteriors persist; the live request-reduction measurement is on-host.

### CC-FUZZ-0014 — Stored-XSS auto-wiring (source_url → store endpoint) (2026-09-21)
- Change: `auto`'s ground-truth sourcing now also emits **stored-XSS** observe points,
  taken from the ground-truth *cases* (`vuln_class=xss-stored` with a `source_url`),
  which the enumerated *points* file does not carry. Each becomes an `InjectionPoint`
  on the render URL with `store_url`/`store_param` set to the case's `source_url`
  (CC-AUD-0013 added those fields + their candidate-evidence); the pipeline threads
  them into the `Candidate`, and `StoredXssStrategy` plants the payload at the store
  endpoint and observes the render page (M6). Audited only with a browser; without one
  the stored point is reported as a skipped gap.
- Impact (other components / project): closes the last DOM/stored detection gap in
  `auto` — with `--browser`, `profile.php` stored XSS (planted via `edit_profile.php`)
  is confirmed as `xss-stored` and scores against PFF-0005. No effect without a browser.
- Risk (level; mitigation): low/medium — stored probing writes to the store endpoint
  (state-changing; reset the lab). Oracle stays fail-closed (no FP). Live stored XSS on
  an auth-gated store endpoint needs the browser executor to carry the session — an
  on-host wiring detail (pass `--identity`'s header to the executor). Mitigated by tests
  (`tests/test_auto.py`: stored confirmed with a store-scoped fake, fp=0; store point
  present only with a browser, carrying the store endpoint). Suite 162 passed / 2 skipped.
- Deliverables:
  - [x] Stored-XSS observe points from cases; `InjectionPoint` store fields + evidence — done.
  - [x] Tests (stored confirmed via browser; browser-gated point) — done.
  - [ ] Live: pass the authenticated session to the browser executor for the store step — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the stored point is wired
  from the contract and confirmed as `xss-stored`; live run needs the browser + session.

### CC-FUZZ-0013 — M6 browser execution: stored + DOM XSS (2026-09-21)
- Change: added the browser-execution mechanism (M6). New `fuzzlab/oracle/browser.py`
  seam — `BrowserExecutor` protocol, `ExecRequest`/`StoreStep`/`ExecObservation`, a
  shared `SENTINEL`, and a `FakeBrowserExecutor` for offline tests. New strategies
  `DomXssStrategy` (`xss-dom`) and `StoredXssStrategy` (`xss-stored`), category `xss`,
  that build a tokened payload calling the sentinel and confirm only when the token
  actually *fires* in the browser (execution, not reflection — fail-closed). The live
  `PlaywrightBrowserExecutor` is `fuzzlab/tools/browserexec.py` (on-host; lazy import).
  Strategies are now scoped by `Candidate.category` (a category can have several
  strategies; `applies()` falls back to `vuln_class` for direct use), so the `xss`
  category fans out to reflected + DOM + stored. `Oracle(browser=...)`,
  `run_pipeline(browser=...)`, `run_auto(browser=...)`, and `fuzzlab auto --browser`
  thread the executor through; `Candidate` gained `category` and stored-XSS
  `store_url`/`store_param`. `auto`'s ground-truth sourcing includes the DOM points
  when a browser is present (else they stay skipped), and `R-XSS-REFLECT` now nominates
  on `fragment` too (CC-AUD-0012) so DOM fragment points get candidates.
- Impact (other components / project): closes the DOM-XSS detection gap — `auto
  --browser --ground-truth` now confirms `reviews.php#author` and `feedback.php?ref`.
  Without `--browser` nothing changes (M6 no-ops → those stay fn), so the existing
  benchmark is unaffected. Stored XSS (`profile.php` via `edit_profile`) has a working
  strategy but needs the point→case source_url to populate `store_url`; auto-wiring
  that is a follow-up (the injection-points contract has no source_url), so stored XSS
  is still fn in auto for now.
- Risk (level; mitigation): medium — M6 drives a real browser and, when enabled, runs
  a DOM probe on every non-reflecting xss candidate (the oracle tries reflected first,
  so server-reflected params short-circuit). The oracle stays fail-closed (only a
  fired token confirms → no FP on escaped pages). Mitigated by the injected seam
  (offline-tested), lab-only/loopback usage, and tests: DOM confirm/fail-closed/no-
  browser/ fragment-placement, stored store-then-observe + needs-store-endpoint,
  oracle-with-browser writes an `xss-dom` finding, and `auto --browser` confirms the
  DOM points with fp=0. Suite 154 passed / 2 skipped.
- Deliverables:
  - [x] `oracle/browser.py` seam + fake; DomXss/StoredXss strategies — done.
  - [x] Category-scoped `applies`; `Candidate.category`/store fields — done.
  - [x] browser threaded through Oracle/pipeline/auto + `--browser`; live executor — done.
  - [x] Tests (`tests/test_oracle_browser.py`, auto browser path) — done.
  - [ ] Live run with `--browser` on the host (Playwright) — on-host.
  - [ ] Stored-XSS auto-wiring: map points→cases to fill `store_url` — follow-up.
- Effectiveness (assessed 2026-09-21): effective in tests — DOM XSS confirms via a
  fired sentinel and writes an `xss-dom` finding; escaped pages are not confirmed; the
  `auto --browser` benchmark picks up the DOM points with fp=0. Live Playwright run and
  stored-XSS wiring pending.

### CC-FUZZ-0012 — Four more deterministic oracle vectors (2026-09-21)
- Change: added `ConfirmationStrategy` classes for four more injection classes, each
  fail-closed and confirming on a positive marker: **open redirect** (M9 —
  redirect-target-control: the param controls a `Location` header or meta-refresh
  target), **SSTI** (M4 — evaluation-marker: `${a*b}` / `{{a*b}}` / `<%= a*b %>` etc.
  evaluate to the product, with the literal expression absent), **path traversal/LFI**
  (M7 — file-content-marker: an `/etc/passwd` `root:...:0:0:` signature), and **command
  injection** (M1 timing — shell `sleep` with rising delay). Factored the rising-delay
  timing logic into a shared `ConfirmationStrategy._confirm_timing` reused by SQLi and
  command injection. Registered all four in `default_strategies()` and mapped their
  categories in `category_to_oracle_class`. `R-SSTI` now nominates on location
  (CC-AUD-0011) so it fires when its category is active.
- Impact (other components / project): grows the oracle's coverage from 2 classes
  (SQLi, reflected XSS) to 6. Because categories are scoped by the run plan (D14), the
  new vectors add zero cost to the SQLi/XSS lab benchmark — they run only when their
  category is selected (manual `--categories`) or present in a target's ground truth.
  These classes are not in the puppy-fort lab, so no effect on its score; they extend
  the toolkit to other targets/labs. Payloads are detection markers (arithmetic,
  `sleep`, `/etc/passwd` read, a canary redirect), not destructive.
- Risk (level; mitigation): low — additive, class-scoped via `applies()`, oracle stays
  fail-closed. Mitigated by 10 tests in `tests/test_oracle_vectors.py` (each vector:
  confirm the true case + reject a benign/reflection-only case; category wiring) and
  the refactor keeping SQLi timing green. Suite 145 passed / 2 skipped.
- Deliverables:
  - [x] OpenRedirect / SSTI / PathTraversal / CommandInjection strategies — done.
  - [x] Shared `_confirm_timing`; `default_strategies` + category map updated — done.
  - [x] Tests (confirm + fail-closed per vector; category mapping) — done.
  - [ ] Live confirmation against a lab that has these classes (e.g. a validation lab
    or added puppy-fort cases) — on-host / Lab track.
- Effectiveness (assessed 2026-09-21): effective in tests — each vector confirms its
  positive and stays fail-closed on the benign case; live confirmation pending a target
  with these vulns.

### CC-FUZZ-0011 — POST-body injection through the oracle + senders (2026-09-21)
- Change: the oracle can now test **POST body** params, not just GET query. Threaded
  `method`/`location` (already on `Candidate`) into confirmation: a `_send` helper on
  `ConfirmationStrategy` routes every probe and passes `method`/`location` only for
  non-default (POST/body) candidates, so existing GET/query senders and test fakes are
  unaffected. `RequestsProbeSender` and `SeamProbeSender` now issue a POST with a
  form-encoded body when `location="body"` (via `session.request` / a seam `Request`
  with body + `Content-Type`). The pipeline builds candidates with `method`/`location`
  from the evaluation evidence, and `auto`'s ground-truth sourcing now includes POST
  points (only client-only/DOM points remain skipped, pending M6). `_CountingSender`
  forwards the new kwargs.
- Impact (other components / project): the ground-truth benchmark now audits the 16
  POST points too (mostly secure controls → richer negatives; the one POST positive is
  `login.php` auth-bypass SQLi, which may confirm via the quoted timing templates). The
  finding writer already records `method`, so POST findings score against the POST
  ground-truth cases. Only browser-execution (M6) points (stored/DOM XSS) remain out of
  reach. Note: POST probing is state-changing on some endpoints (register/checkout/
  add_to_cart) — reset the lab between runs; destructive payload classes stay off.
- Risk (level; mitigation): medium — POST requests mutate lab state and add traffic.
  Mitigated by lab-only scope + `--authorized`, the oracle staying fail-closed (secure
  POST controls are not confirmed → no FP), the backward-compatible `_send` (GET/query
  senders unchanged), and tests: RequestsProbeSender/SeamProbeSender POST-body
  (form-encoded body, no query string), oracle-threads-POST, and the GT filter now
  including POST. Suite 135 passed / 2 skipped.
- Deliverables:
  - [x] `_send` helper threads method/location; senders issue POST body — done.
  - [x] Pipeline candidate carries method/location; auto GT filter includes POST — done.
  - [x] Tests (probe senders POST; oracle POST threading; GT filter) — done.
  - [ ] Live run: confirm the 16 POST controls stay fp=0 and whether `login.php`
    auth-bypass SQLi confirms (timing) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — POST candidates are probed
  over POST with a form body and the secure POST controls are not confirmed; live
  numbers (and whether login confirms) pending on the host.

### CC-FUZZ-0010 — `auto`: ground-truth point sourcing + oracle-rejection negatives (2026-09-21)
- Change: `fuzzlab auto` can source injection points from the enumerated ground-truth
  contract (`points_from_ground_truth`), not only the crawl. A new `--points`
  flag (`auto`|`crawl`|`ground-truth`, default `auto` = ground-truth when a contract
  is given, else crawl) selects the source. Ground-truth sourcing filters to points
  the current pipeline can test (GET/query, server-rendered) and reports the rest
  (POST body, fragment, client-only/DOM) as explicit skipped gaps rather than silent
  misses. `run_pipeline` now also counts oracle-rejected candidates (nominated but not
  confirmed) as negatives (`oracle_rejected`), so the dataset's negatives stay
  meaningful after R-XSS-REFLECT was broadened (CC-AUD-0009).
- Impact (other components / project): the scored run is now a real **detection
  benchmark** decoupled from crawl coverage — it tests every enumerated point, so the
  oracle's true tp/fp is measured (the crawl-only run under-covered, inflating fn).
  The skipped gaps name the next capabilities precisely: POST-body injection and
  browser-execution (M6) for stored/DOM XSS. Discovery runs (`--points crawl`) still
  measure the end-to-end tool including crawl coverage.
- Risk (level; mitigation): low/medium — more points audited means more probes, but
  scoped to testable GET/query points; the oracle stays fail-closed (no FP). Mitigated
  by `tests/test_auto.py` (GT-point filtering; GT-source scored run beats crawl
  coverage with fp=0; crawl-source path; D15 paths). Suite 132 passed / 2 skipped.
- Deliverables:
  - [x] `points_from_ground_truth` + `--points` selector + skipped-gap reporting — done.
  - [x] `run_pipeline` negatives include oracle-rejected candidates — done.
  - [x] Tests for both point sources + the skipped gaps — done.
  - [ ] Live GT-benchmark run on the host (expect tp for the GET/query SQLi + reflected
    XSS; fn for POST SQLi + stored/DOM XSS until those capabilities land) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the GT-sourced run audits
  all enumerated GET/query points, scores fp=0, and lists the POST/DOM gaps; live
  numbers pending on the host.

### CC-FUZZ-0009 — `fuzzlab auto`: automatic-mode entry point wired live (T2.8) (2026-09-21)
- Change: added `fuzzlab/harness/auto.py` (`run_auto`, `injection_points_from_store`,
  `_CountingSender`) and `fuzzlab/harness/auto_cli.py`, wired as `fuzzlab auto`.
  `run_auto` builds injection points from a crawl consolidated into the store (one
  point per endpoint+param, full URL with no query so the sender adds `?param=value`),
  resolves the run plan (D14 categories from ground truth + scored, or D15 fail-safe),
  wraps the probe sender in a request counter, and runs `run_pipeline` (scoped rules
  eval with negatives → oracle confirm → target fingerprint → score → request
  metrics). The CLI consolidates an existing `spider_results.db`, requires
  `--authorized`, and prints the plan, counts, findings, score, and request cost.
- Impact (other components / project): gives the automatic-mode path a real runnable
  entry (the missing half of the manual tool chain) — it writes the `target`,
  `evaluation` (negatives), and oracle `finding` rows and scores against ground truth,
  which the standalone tools did not. Uses the real requests/seam probe sender
  (`make_probe_sender`), so it also runs authenticated (`--identity`). This is the
  "live wiring" T2.8 left open in CC-FUZZ-0008.
- Risk (level; mitigation): medium — it sends confirmation probes at a live target.
  Mitigated by the `--authorized` gate, the oracle's fail-closed confirmation, the
  D15 no-ground-truth fail-safe (loud, unscored), category scoping, and 4 offline
  tests (`tests/test_auto.py`: point building, scored end-to-end with request
  counting, D15 fail-loud, D15 unscored-with-categories). Suite 130 passed / 2 skipped.
- Deliverables:
  - [x] `run_auto` + `injection_points_from_store` + request-counting sender — done.
  - [x] `fuzzlab auto` CLI (import crawl, `--authorized`, D14/D15, summary) — done.
  - [x] Offline tests (scored, fail-safe, unscored) — done.
  - [ ] Run against the live lab; compare requests-per-finding to a Phase-1 baseline — on-host.
  - [ ] DOM-skeleton dedup for distinct-URL same-template pages (needs the crawler to
    store rendered HTML) — follow-up; endpoint-keying already collapses query-param
    variants (e.g. product.php?id=1..10 → one point), so it is not needed for this lab.
- Effectiveness (assessed 2026-09-21): effective in tests — automatic mode produces
  oracle findings, logs negatives, records the target fingerprint and request cost,
  and scores TP/FP against ground truth; live run + the fewer-requests comparison
  pending on the host.

### CC-FUZZ-0008 — Automatic-mode pipeline wired end-to-end (Phase 2 T2.8) (2026-09-21)
- Change: added `fuzzlab/harness/pipeline.py::run_pipeline`, the library-level
  composition of an automatic run: dedup injection points by DOM-skeleton template
  cluster (T2.6) → fingerprint the target from a baseline probe and record the
  `target` row (T2.5) → evaluate the rules-as-data engine scoped to the `RunPlan`
  categories, logging negatives (T2.3 / D14 / D15) → confirm each candidate with
  the deterministic oracle (sole finding-writer) via
  `oracle.category_to_oracle_class` → score against ground truth only when the plan
  is scored (D15 fail-safe) → record request-efficiency metrics. Exported
  `category_to_oracle_class` from `fuzzlab.oracle`. This completes the
  "same wiring in the generalized harness / automatic pipeline" deliverable left
  open in CC-FUZZ-0007. Fixed a path-form defect surfaced by the scored pipeline
  (see Risk; BUG-0003 / CC-CORE-0008).
- Impact (other components / project): gives the web UI / automatic-test path one
  entry point that runs the whole Phase 2 loop with an injected sender (fully
  testable offline). The live crawler/auditor browser-fetch edits that feed it real
  pages/HTML remain the on-host last mile. Store schema unchanged.
- Risk (level; mitigation): medium — composing five stages exposed a real
  integration bug: the oracle stored findings with full URLs while ground truth is
  keyed on path form, so a scored run reported `tp=0, fp=3`. Root-caused (BUG-0003),
  fixed by centralizing URL normalization in `fuzzlab/core/urls.py::to_path`
  (CC-CORE-0008) and calling it at every finding writer; preventive rule PA-0003.
  Mitigated further by three pipeline tests (scored end-to-end with TP/FP checks;
  unscored per D15; dedup collapses same-template pages).
- Deliverables:
  - [x] `run_pipeline` composing dedup→fingerprint→scoped-eval→confirm→score/metrics — done.
  - [x] `category_to_oracle_class` exported and used to select confirmers — done.
  - [x] Path-form fix + shared `to_path` (BUG-0003 / PA-0003) — done.
  - [x] Tests (`tests/test_pipeline.py`: scored, unscored, dedup) — done.
  - [ ] Wire `run_pipeline` into the live crawler/auditor browser-fetch loops and
    measure request reduction against the running lab — todo (on-host last mile).
- Effectiveness (assessed 2026-09-21): effective in tests — the pipeline produces
  three oracle findings on the lab fixture, the harness scores them TP with 0 FP
  (after the path-form fix), negatives are logged, and unscored runs report findings
  without TP/FP/FN. Live confirmation pending a lab. Suite 108/108.

### CC-FUZZ-0007 — Oracle wired in as the sole finding-writer (Phase 2) (2026-09-21)
- Change: routed confirmation through the oracle. Added `fuzzlab/tools/probesender.py`
  (`SeamProbeSender` authenticated / `RequestsProbeSender` standalone; `make_probe_sender`)
  adapting tool HTTP to the oracle's `Sender` (full `Probe`: text/headers/elapsed).
  The fuzzer's `--store` path now, after recording attempts, calls
  `Oracle.confirm` on its target candidate — the oracle writes the `finding`.
  `store_adapter.import_fuzz_csv` no longer writes findings (attempts only); the
  earlier provisional `timing-only` finding path is removed. The attempt `reward`
  still records the fuzzer's timing screening.
- Impact (other components / project): findings are now deterministic oracle
  verdicts, not timing-only; the integration harness scores oracle findings. Closes
  the screen→confirm loop for the fuzzer (before the scheduler/classifier exist).
  Store schema unchanged.
- Risk (level; mitigation): medium — the oracle sends its own confirmation probes
  (extra requests) and is now the label source. Mitigated by the oracle's
  fail-closed design (CC-FUZZ-0006), reusing the scope/budget/auth seam for the
  authenticated sender, and tests: probe-sender adaptation (auth + full response)
  and an oracle→store→harness end-to-end (findings scored, confidence is the
  mechanism, not `timing-only`). Updated the store-adapter tests to attempts-only.
- Deliverables:
  - [x] Probe senders + `make_probe_sender` — done.
  - [x] Fuzzer `--store` confirms via the oracle; adapter attempts-only — done.
  - [x] Tests (probe senders; oracle→harness; adapter attempts-only) — done.
  - [ ] Same wiring in the generalized harness / automatic pipeline — todo (as the
    harness is generalized).
- Effectiveness (assessed 2026-09-21): effective in tests — the oracle's findings
  are read back and scored by the harness (confidence = mechanism, not
  timing-only); the adapter writes attempts only. Live confirmation pending a lab.
  Suite 84/84.

### CC-FUZZ-0006 — Deterministic oracle implemented (Phase 2 T2.1/T2.2/T2.4) (2026-09-21)
- Change: built the `fuzzlab/oracle/` package — a class-pluggable deterministic
  confirmer and sole finding-writer. `baseline.py` (median/MAD robust baselines,
  T2.2); `context.py` (sink-context typing + break-out signatures, T2.4);
  `strategies.py` (`ConfirmationStrategy` base + `SqliErrorStrategy` [M2],
  `SqliBooleanStrategy` [M3], `SqliTimingStrategy` [M1 rising-delay], and
  `ReflectedXssStrategy` [M5]); `oracle.py` (`Oracle.confirm` runs applicable
  strategies cheapest/strongest first and writes a `finding` row on a positive,
  reproducible verdict — fail-closed otherwise). Senders are injected, so the whole
  thing is unit-tested without a network. Realizes T2.1 (framework + current-lab
  mechanisms), T2.2, and T2.4.
- Impact (other components / project): gives the project its deterministic
  confirmation layer; will supersede the fuzzer's provisional `timing-only`
  findings (CC-FUZZ-0003) once the harness/fuzzer route confirmation through the
  oracle (next chunk). Consumes the auditor's sink-context typing (candidate
  `sink_context`) when present, else types reflection itself. Writes `finding` rows
  (existing schema). Browser execution (M6, stored/DOM XSS), OOB (M8), and grey-box
  (M10) are later per `architecture/oracle-confirmation.md`.
- Risk (level; mitigation): high — the oracle is the label trust anchor. Mitigated
  by fail-closed labeling (confirm only on a positive reproducible signal),
  differential/rising-delay timing on median/MAD baselines (resists outliers),
  boolean confirmation requiring true≈benign and true≠false (avoids FP on secure
  int-cast params), error signatures cross-checked, escaped reflection rejected,
  and 10 unit tests incl. fail-closed cases for each mechanism.
- Deliverables:
  - [x] median/MAD baseline (T2.2) — done.
  - [x] sink-context typing + break-out (T2.4) — done.
  - [x] Strategy interface + M1/M2/M3/M5 + registry — done.
  - [x] Oracle orchestration + sole finding-writer + 10 tests — done.
  - [ ] Route the fuzzer/harness confirmation through the oracle (replace
    timing-only findings) — todo (next Phase 2 chunk).
  - [ ] M6 browser execution (stored/DOM XSS); new-class strategies as the lab grows — todo.
- Effectiveness (assessed 2026-09-21): effective in unit tests — each mechanism
  confirms its positive fixture and fails closed on the secure fixture; the oracle
  writes exactly one finding on confirmation and none when unconfirmed. Suite 81/81.

### CC-FUZZ-0005 — Oracle scoped as class-pluggable across attack vectors (spec) (2026-09-21)
- Change: per direction to expand the project to as many attack vectors as
  possible, re-scoped the oracle from "differential timing + error signatures"
  (SQLi-leaning) to a **class-pluggable deterministic confirmer**. Reviewed the
  `references/` catalogs (63 categories) and defined a small set of confirmation
  **mechanisms** (M1–M10: differential timing, error signature, boolean differential,
  evaluation marker, reflected-canary-in-context, browser execution, file-content
  marker, out-of-band callback, redirect-target control, grey-box) with a
  `ConfirmationStrategy` per class selecting mechanisms by `(vuln_class,
  sink_context)`. Added the secondary architecture doc
  `docs/architecture/oracle-confirmation.md` (mechanisms + full injection-class →
  mechanism mapping + sequencing tiers + out-of-scope non-injection categories).
  Updated FR-FUZZ-3/3a/4/5 and the scope; Phase 2 T2.1 + exit criterion reframed.
  Spec/plan only — no code.
- Impact (other components / project): broadens the oracle's remit to the whole
  injection surface, sequenced by tier (Tier 1 black-box in Phase 2; Tier 2 browser
  execution via Playwright; Tier 3 out-of-band with a lab loopback listener; Tier 4
  grey-box in Phase 3). Ties to the auditor's sink-context typing (AUD Phase 2), the
  Lab track's class-breadth order, and the plugin system's `register_oracle` hook
  (#13). First secondary architecture doc created under the splitting rule;
  `ARCHITECTURE.md` #7 + splitting-rule index updated.
- Risk (level; mitigation): medium — a much larger confirmation surface risks
  false labels across classes. Mitigated by fail-closed labeling (confirm only on a
  positive reproducible signal), preferring stronger mechanisms over timing,
  per-class strategies validated against lab ground truth, the default-off
  destructive gate, and OOB restricted to a loopback canary. Breadth is sequenced
  by tier so each confirmer is validated as its lab class is added.
- Deliverables:
  - [x] Review `references/`; define mechanisms + class mapping (secondary doc) — done.
  - [x] Re-scope FR-FUZZ-3/4/5, scope, Phase 2 T2.1 + exit — done.
  - [ ] Implement the pluggable oracle + current-lab confirmers (Phase 2 T2.1) — todo.
  - [ ] Add confirmers per new class as the Lab track generates them — todo (ongoing).
- Effectiveness (assessed or pending): pending — spec/design. Judged in Phase 2 by
  confirming the lab's 8 cases via their per-class mechanisms and by a new class
  being addable as one `ConfirmationStrategy`.

### CC-FUZZ-0004 — Fuzzer HTTP migrated onto the auth seam (2026-09-21)
- Change: the fuzzer's HTTP now goes through a sender abstraction — `RequestsSender`
  (standalone, unchanged raw-requests behavior) or `SeamSender` (routes through the
  `core/` HTTP seam with the session manager, timing-serialized per host). Added a
  `--identity` flag: with it, the fuzzer authenticates as that identity (per-host
  credentials, detection-only login) via a shared `fuzzlab/tools/authhttp.py`
  helper; without it, behavior is exactly as before. Realizes the requests-tool
  half of Phase 1 T1.10 for the fuzzer.
- Impact (other components / project): the fuzzer can now fuzz authenticated
  endpoints as a given identity; depends on the session manager (#3) and credential
  store. Timing goes through the seam's per-host mutex. No output-format change.
- Risk (level; mitigation): medium — must not perturb standalone timing. Mitigated
  by keeping `RequestsSender` byte-identical to the old `measure_once`, routing
  timing through the seam only on the authenticated path (`timing=True`), and
  fail-loud auth (a `SessionAuthError` aborts the run rather than fuzzing
  unauthenticated). Covered by 3 tests (URL building, standalone unchanged,
  authenticated send attaches the session cookie).
- Deliverables:
  - [x] Sender abstraction; `--identity`; `authhttp` helper — done.
  - [x] Tests (standalone + authenticated) — done.
  - [ ] Live authenticated fuzz run against the lab (T1.10) — todo (needs a lab).
- Effectiveness (assessed 2026-09-21): effective in tests — the authenticated
  sender attaches the session and reaches the fuzzed URL; standalone path
  unchanged. Live run pending.

### CC-FUZZ-0003 — Writes attempts/findings to the unified store (2026-09-21)
- Change: added `--store PATH` to the fuzzer; after a run it consolidates its CSV
  into the unified store via `store_adapter.import_fuzz_csv`, writing `attempt`
  rows (behavioral features JSON + reward) and, for confirmed timing hits, a
  `finding` row (vuln_class `sqli`, label 1, confidence `timing-only`, self-
  describing url/method/param). Native CSV unchanged without `--store`. Phase 0 T0.8.
- Impact (other components / project): closes the Phase 0 loop — the harness (T0.7)
  reads these findings to score against ground truth. Note the confidence is
  `timing-only`: the deterministic oracle that will own finding labels is Phase 2,
  so these are provisional confirmations flagged as such, not oracle verdicts.
- Risk (level; mitigation): medium — writing findings from a timing-only signal
  risks false positives before the real oracle exists. Mitigated by flagging them
  `timing-only`, keeping the differential/median timing logic from the baseline,
  and requiring `--authorized`; the Phase 2 oracle will supersede this path.
- Deliverables:
  - [x] `--store` + `import_fuzz_csv` (attempt + finding rows) (T0.8) — done.
  - [ ] Replace timing-only findings with the deterministic oracle (Phase 2) — todo.
- Effectiveness (assessed 2026-09-21): effective for Phase 0 — synthetic fuzz
  output yields 3 attempts and 2 timing findings that the harness scores as true
  positives on the lab's known GET SQLi cases (test green).

### CC-FUZZ-0002 — Moved into the `fuzzlab` package (2026-09-21)
- Change: `blind_sqli_fuzzer.py` moved to `fuzzlab/tools/blind_sqli_fuzzer.py`;
  imports `core/` (`get_logger`, structured startup line after the `--authorized`
  gate). Behavior unchanged; still writes a labeled CSV (T0.8 moves it onto the
  store). Phase 0 T0.1.
- Impact (other components / project): the fuzzer is now a package module; the
  `--authorized` safety gate and detection logic are unchanged.
- Risk (level; mitigation): low — move + one import placed after the authorization
  check so the gate still fires first; verified the module imports and `--help` runs.
- Deliverables:
  - [x] Move into package; import `core/` (T0.1) — done.
  - [ ] Read candidates / write attempts+findings to the shared store (T0.8) — todo.
- Effectiveness (assessed 2026-09-21): effective — runs as a package module with
  the authorization gate intact.

### CC-FUZZ-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `blind_sqli_fuzzer.py`
  performs time-based blind SQLi detection (median of repeats), requires `--url`
  and `--authorized`, and emits a labeled CSV. Detection is decoupled from the
  payload label. The generalized harness and the standalone deterministic oracle
  are specified but not yet built.
- Impact (other components / project): the oracle is the only writer of `finding`
  labels, so it is the trust anchor for the scheduler's reward, the classifier's
  training data, and all reports (D10). Generalizing the harness lets one engine
  serve multiple vulnerability classes; until then only blind SQLi is covered.
- Risk (level; mitigation): high — a wrong oracle silently corrupts every label
  and every learned model downstream. Mitigated by: differential (not absolute)
  timing, median-of-repeats, decoupling detection from the payload label (removes
  the earlier circular-labeling bug), grey-box confirmation when available,
  measured oracle precision, and state reset between iterations. Safety mitigated
  by the required `--authorized` flag, default-off destructive classes, and
  auth-endpoint exclusion.
- Deliverables:
  - [x] Time-based blind SQLi detection, median of repeats — done.
  - [x] `--authorized` gate; missing-`requests` import guard — done.
  - [x] Detection decoupled from payload label (circular-labeling fix) — done.
  - [x] Labeled CSV output — done.
  - [ ] Generalize to `template + injection_point + payload_source + oracle` — todo (Phase 2).
  - [ ] Standalone deterministic oracle (differential timing + error signatures) — todo (Phase 2).
  - [ ] Grey-box coverage / DB-fault confirmation — todo (Phase 3).
  - [ ] Write `attempt`/`finding` to the shared store — todo (Phase 0 T0.8).
- Effectiveness (assessed or pending): effective for time-based blind SQLi on the
  lab (confirms known points; circular-labeling defect removed). Multi-class
  harness, standalone oracle, and grey-box confirmation pending.
