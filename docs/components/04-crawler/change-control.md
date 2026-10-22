# Crawler / Spider — Change Control Log

Component code: **CRAWL**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CRAWL-0064 — disco's explorer hands its session's cookies to the guard: nothing an authenticated context sends goes to a host they do not reach (FR-CRAWL-43, BUG-0559, SP-74) (2026-10-22)
- Placement: pre-assigned to lane BROWSERALIAS (item GAP-BROWSER), base 7393c90; merged
  after CC-CRAWL-0063 (the owner). Touches `disco/explore.py` (the session context's
  guard wiring, its material and one report counter) and `disco/cli.py` (one summary
  line) only.
- Change:
  - `_SessionMaterial.credential_names` (a provider's `checked_cookies` names; `None`
    for a storage state: disco cannot tell its credentials from its ambient cookies, so
    every adopted cookie is the session's) and `session_cookies()`
    (`navguard.held_session_cookies` over its URL cookies and its storage state).
    `_provider_session` fills the names.
  - `Explorer._new_context` passes `session_cookies=auth.session_cookies()` and
    `on_session_unreached=self._count_session_unreached` to `guard_page`: the route of
    every context that carries the run's session refuses a navigation, redirect hop,
    subresource or socket to a host the session's cookies do not reach (a loopback alias
    of a host-only cookie's host, which the run's scope folds into its origin) before it
    is sent.
  - `ExploreReport.session_host_unreached` (`{host: count}`, written to `explore.json`
    with the rest of the report) and a `disco capture` summary line.
- Impact (other components / project):
  - `explore.json` gains the key `explore.session_host_unreached` (additive; readers
    that look up their own keys are unchanged: `tools/observe.py` reads `out_of_scope`
    only). Not yet traced as a diagram event (FR-AUD-29's guard-refusal events cover
    `out_of_scope`): a residual for AUD, stated in BUG-0559.
  - A run whose storage state holds cookies of two loopback spellings with different
    names fails closed: a host where one name has no copy is refused (counted, printed).
  - No change for an anonymous run, or for an origin `cookie_scope` puts outside the
    session's (FR-SESS-20 keeps its disposition).
- Risk (low): a deny-only refusal in the guard of authenticated contexts; it removes
  requests that went anonymous and, measured on 7393c90, ended the authenticated
  exploration (the alias's login redirect read as a lost session).
- Deliverables:
  - [x] the material's cookies and the guard wiring — done
  - [x] the report counter and the summary line — done
  - [x] test: `tests/test_browser_session_reach.py::test_disco_never_explores_an_unreached_host_as_the_storage_states_session`
    (real Chromium and the capture proxy; fails on 7393c90: the alias got 7 requests
    with no cookie and the run ended its authenticated exploration) — done
  - [x] FR-CRAWL-43 (disco's clause) — done
- Effectiveness (assessed <date> or pending): pending.

### CC-CRAWL-0063 — The browser guard owns where a session's cookies reach: every request, hop, socket and API request to a host they do not reach is refused, and the spider files such a load failed (FR-CRAWL-43, FR-CRAWL-34, BUG-0559, SP-74) (2026-10-22)
- Placement: pre-assigned to lane BROWSERALIAS (item GAP-BROWSER), base 7393c90.
  `tools/navguard.py` (the owner, SP-01/02/38's module) first, then `tools/spider.py`;
  CC-CRAWL-0064 (disco) and CC-AUD-0060 (the auditor's fetcher) follow. Closes BUG-0545's
  residual R8 (CC-CRAWL-0056) and the round-2 check's third path (client-side
  navigation).
- Change:
  - **`tools/navguard.py` (the owner, SP-74):** `cookie_reaches(cookie, host)` (moved
    from `spider._cookie_reaches`; RFC 6265: by URL or a bare domain, that exact host; a
    dotted domain, the names under it, never an IP), `held_session_cookies(cookies,
    storage_state, names)`, `unreached_session_cookies(cookies, host)`,
    `session_host_refusal(cookies, url, *, cookie_scope)` (why a request would go
    without the session -- a cookie name with no held copy reaching the host -- or None;
    None for no session cookie and for another origin than the session's, FR-SESS-20's)
    and `SessionHostUnreached(PermissionError)`. `make_route_handler` and `guard_page`
    take `session_cookies` and `on_session_unreached(url, kind, source, reason)`: a
    request to such a host is aborted right after the scope and destructive checks,
    before the window, method, body and FR-SESS-20 checks and before anything is fetched
    -- the request itself (kind `document`, `frame` or `request`) and every redirect hop
    (`landing`, `frame` or `request`, never asked of the context's client) -- with
    SP-02's code. `make_ws_handler` never connects such a socket (`websocket`).
    `checked_api_request(in_scope, url, *, session_cookies, cookie_scope)` raises
    `SessionHostUnreached`. A failing hook never lets the request out. `cookie_reaches`
    assigns one name per statement so PA-0134(3)'s host-compare guard sees its compare
    (its allowance moved from `spider.py:_cookie_reaches` to
    `navguard.py:cookie_reaches`).
  - **`tools/spider.py`:** `_session_host_refusal`'s browser branch asks the owner over
    `_session_cookies()` (the browser session's `checked_cookies` as the context holds
    them) and adds `UNREACHED_ADVICE`; `_guard` passes the cookies and
    `_note_session_unreached` for the authenticated context. The hook counts
    `session_host_unserved`, keeps a probe's URL as its blocked evidence, records a
    refused own target or redirect landing in `_unreached_targets` (keyed by
    `_target_key`: `url_key` and the host, since `url_key` folds the aliases) and queues
    a page's own refused jump (`_query_navs`, so `_visit`'s gate files it `failed`).
    `_fetch_rendered` raises `HostNotServed` for a load in `_unreached_targets` (after a
    failed `goto`, before the static fallback; or after a commit). `_isolated_submit`
    passes the cookies and `cookie_scope` to `checked_api_request` and turns a refusal
    into `HostNotServed` (counted; `_after_fetch` stops that form's enumeration). The
    private `_cookie_reaches` is removed. `_clone` resets `_unreached_targets`.
- Impact (other components / project):
  - Every guarded context that adopts a session: the spider (here), disco
    (CC-CRAWL-0064), the auditor's fetcher (CC-AUD-0060). Contexts with no session
    cookie (the spider's unauthenticated contexts, `disco/ede.py`, the M6 executor,
    the browser login's own context) pass nothing and are unchanged.
  - A crawl whose app sends its pages to another loopback spelling than the one its
    session cookie holds (a canonical-host redirect) now gets those loads `failed` with
    the cause, where it got the anonymous pages filed as the identity's: loud partial
    coverage instead of wrong coverage. The cause names the remedy (start on that host).
  - Spider DB: no schema change; rows that were `visited` with an anonymous landing are
    now `failed` with the cause (FR-CRAWL-36's unresolved state).
  - SHARED_PRIMITIVES gains SP-74 (text in the lane's doc_texts); PA-0134(3)'s
    allowance list moves one entry.
- Risk (low-medium): a deny-only check in a shared primitive's owner on every request
  of an authenticated context. Mitigated: it applies only when the caller passes
  session cookies and only to in-scope requests on the session's origins (FR-SESS-20's
  other-origin disposition is unchanged); measured on Chromium 141 before the design
  (`scratchpad/lanes/BROWSERALIAS/measure/reach.out`); the existing browser, scope and
  disco tests stay green (targeted run: 838 passed and one stale allowance found and
  fixed, then the harness).
- Deliverables:
  - [x] the owner: predicate, refusal, route, WebSocket handler, API check — done
  - [x] the spider: gate through the owner, guard wiring, hook, load refusal, form
    submission — done
  - [x] tests (`tests/test_browser_session_reach.py`, new): the predicate, the refusal,
    the route on doubles; real Chromium on loopback for a redirect hop, a selector form,
    a script's `location` and a meta refresh (each with an image and a `fetch` to the
    alias); the AST wiring guard and its synthetic offenders. Each real-browser test
    fails on 7393c90 on `_to_alias(site) == []` (the alias received the requests with no
    cookie); the guard on its own assertion (4 offenders); the unit tests on the
    missing API (`scratchpad/lanes/BROWSERALIAS/proof.log`: 10 failed, 1 passed) — done
  - [x] `tests/test_session_origin_scope.py`: the host-compare allowance moved — done
  - [x] FR-CRAWL-43 added; FR-CRAWL-34 and FR-CRAWL-36 edited in place (R8 closed) — done
  - [x] BUG-0559 (RCA, sweep, recurrence review, prior-PA analysis); CHANGELOG,
    ERROR_LOG, PA-0559, SP-74, ARCHITECTURE and failure-record texts in the lane's
    doc_texts — done
- Effectiveness (assessed <date> or pending): pending.

### CC-CRAWL-0061 — The capture writer is total: a body holding a lone surrogate is stored losslessly, and a write the store refuses is counted (FR-CRAWL-42, BUG-0554) (2026-10-21)
- Placement: pre-assigned to lane SURROGATE (item AU-REQID78), base 33b423e (after
  SPIDER9). Inside `StorageManager.record_request` and its new helper only; lane SPIDER
  owns the rest of `tools/spider.py` (disjoint regions). Also touches
  `tools/store_adapter.py::captured_request` (the importer's decision, component AUD:
  its own change-control entry needs a CC-AUD number, requested at merge).
- Change:
  - **`tools/apiop.py`.** `storable_json(value)`: `json.dumps(value,
    ensure_ascii=False)` with each surrogate code point written as its `\uXXXX` escape
    (`encode("utf-8", "backslashreplace")`); byte-identical for text without one, and
    `json.loads` returns the value. `_digest(text)`: SHA-256 with `surrogatepass`.
    `operation_key` returns `storable_json(...)`; `row_signature`, the over-cap GraphQL
    digest and `_selector_value` use `_digest`. The module docstring states the rule.
  - **`tools/spider.py::StorageManager.record_request`** runs its work inside one
    `try` (still one function, so the PA-0100 and PA-0546 writer guards see the
    redactors and the keying beside the `INSERT`): `IntegrityError` is still
    `duplicate`; any other exception is rolled back and returned
    as `write failed (<error class>)`, so `_observe` counts it in
    `requests_not_recorded` and logs it; `_record_dry` does not count it as captured.
    `body_json` is `apiop.storable_json(doc)`. The marker scrub keeps the raw
    `ensure_ascii=False` text (an escape's hex digits would hide a following marker
    from the scrub's word boundary).
  - **`tools/store_adapter.py::captured_request`** refuses a body whose field name or
    string value holds a lone surrogate ("a field holding a lone surrogate (not storable
    text)", counted `request_refused`), for `import_spider` and `import_disco`; new
    private `_storable_text`.
- Impact (other components / project):
  - Spider DB contract (§5): no change for any body that could be stored before (text
    and signature byte-identical, tested against BUG-0546's formula). A row may now hold
    a `\udXXX` escape in `body_json` and `signature`. Readers of the table, found by
    searching `discovered_requests` over `fuzzlab/` and `scripts/`:
    `tools/store_adapter.py` (refuses such a row, counted; it failed the import before),
    `tools/observe.py` (top-level field names into the trace, written by `json.dumps`'s
    ASCII default: tested with a recorder active), `apiop.operation_schema`
    (`json.loads`).
  - AUD (FR-AUD-22): one more refusal; `import_disco` no longer fails on a captured body
    holding a lone surrogate, which it did before this change.
  - CORE: none changed. `core.redaction.redact_json_body` still raises on a body with a
    sensitive field and a lone surrogate (pinned, BUG-0554 sweep; owner CORE).
  - No traffic change.
- Risk (low): a broad `except Exception` in the writer turns a programming error into a
  counted, logged reason instead of a crash. Accepted: before, the same exception was
  swallowed uncounted by navguard's observer catch; every writer test asserts the
  stored result, so such an error still fails a test. The escape is applied only to
  surrogates, so no existing row, signature or resume changes.
- Deliverables:
  - [x] `apiop.storable_json`, `_digest`, `operation_key`, `row_signature`, GraphQL and
    selector digests — done
  - [x] `record_request` total (one `try` around its work), `body_json` escaped, scrub
    on raw text — done
  - [x] `store_adapter.captured_request` refusal (AUD entry text in the lane's doc
    texts, number requested) — done
  - [x] tests: `tests/test_capture_surrogates.py` (new): 7 defect and regression tests,
    each defect test failing on 33b423e; the bind guard and the keying guard with
    synthetic offenders; the BUG-0554 sweep guard; the strict xfail pinning
    `redact_json_body` — done
  - [x] measured: Chromium's `JSON.stringify` writes a lone half as `\udXXX`; DOM
    strings reach Python with U+FFFD (BUG-0554) — done
  - [x] FR-CRAWL-42 added; §5 `discovered_requests` edited in place; FR-AUD-22 edited in
    place — done
- Effectiveness (assessed <date> or pending): pending.
- Review round 1 (2026-10-21, one reviewer and a skeptic on 43231dc; applied by the
  orchestrator at merge): `_record_dry` (the FR-CRAWL-26 dry-submit and blocked path)
  ignored the writer's returned reason, so a refused dry write was neither stored nor
  counted. It now counts it in `requests_not_recorded` and logs it, as `_observe` does.
  Test: `tests/test_capture_surrogates.py::test_a_dry_write_the_store_refuses_is_counted_never_lost`
  (count 0 on 43231dc, 1 after). The writer's helper named in the placement line was
  folded back into `record_request` (43231dc).
- *(Merge integration, 2026-10-21, found by the crawl batch's targeted run on
  a98c66d.)* The review fix's count reached a consumer test it was never run against:
  `tests/test_spa_capture.py::test_passive_capture_is_on_by_default_and_redacted`
  (CC-CRAWL-0057, BUG-0546) asserted `requests_not_recorded == 2`, written before the
  fix. On the HashSpa lab `/rest/big` and `/rest/deep` are refused twice each: by the
  passive capture, and again when the reveal window renders `/#/about` once more and
  blocks both writes (`_record_dry`, source `reveal-blocked`), which the fix counts.
  Measured by driving the test's crawl directly (no pytest) on a98c66d and on 07792e0's
  `spider.py` and `spa.py`: 4 each time, the second pair from `_record_dry`. The
  assertion now expects 4, with the two paths named. No product change.

### CC-CRAWL-0060 — Disco decides a lost session through the session layer's owners, installs only a fresh revalidated one, and closes the context it replaces (BUG-0552, FR-CRAWL-41) (2026-10-21)
- Placement: pre-assigned to lane DISCO4 (audit defect 4); merged after AU-DISCO
  (defects 1-3) and DISCO13. No session-layer file changed (the manager is used through
  its public API: `ensure`, `check_health`; SP-16's and SP-56's public functions).
- Change (`fuzzlab/disco/explore.py`; new functions, the loop calling them):
  - **A session provider.** `ExploreSession(manager, identity, base_url)` and
    `Explorer(session=)` (with `storage_state=`, one source; both is a `ValueError`).
    `_current_session` makes the run's first `_SessionMaterial` (the provider's through
    `_provider_session`: `ensure(..., operator=True)`, then
    `browserauth.browser_session`; a header-only session raises `SessionUnavailable`;
    or the storage state, filtered as before, generation 0). `_new_context` builds every
    context from the current material (storage state, cookies through
    `browserauth.apply_to_context`, the session's origins as the guard's
    `cookie_scope` with more than one scope origin) and records its generation.
  - **Suspicion** (`_note_window_tag`, `_note_answer`: two handlers on authenticated
    contexts only; `_loss_signal`, `_answer_class`, `_shows_login`): SP-56 classes each
    whole answer on the session's origins with SP-16's facts; the page at a login URL or
    showing this session's login form (SP-16) is a sign unless the step asked for a
    login URL or the state already showed the form; without a known login form, a
    password form counts only in place (same URL, after an action).
  - **Decision** (`_confirm_loss`): SP-61's `check_health` for the context's generation
    (``policy``, ``signal_url``, ``pause=False``): live (an authorization denial; after
    an action, a login page on a live session re-gives the context its session:
    `reinstall`), lost, stale, unknown. Without a provider: PA-0533(1)'s unconfirmed
    loss for a loss shape; a policy block never.
  - **Recovery** (`_recover_session` under `_Shared.auth_lock`; `_replace_context`;
    `_end_authenticated`): adopt a newer generation, or a fresh provider session that
    is another generation and passes its own protected check (``use_cache=False``),
    at most `ExploreOptions.max_session_recoveries` (new, 3); the old context released
    and closed first, its in-flight tracker, pending answers and responses dropped; an
    unresolved loss sets `ExploreReport.auth_ended` and stops the run.
  - **Checkpoints** (`_session_checkpoint`) after each action (replacing the
    `looks_like_login_url(page.url)` branch in `_process`), each restore
    (`_restore_checked`, used at both restore sites of `_process`: a restore on a lost
    session is retried once on the recovered one), each harvest load (`_load`) and the
    seed (`_seed_session`); `_session_current` gives a worker the current generation
    and a live page before each state and load.
  - **D′ for captures** (`_log_session_event`, `_lost_action`): the window's action ids
    to `session_lost_actions` and one `actions.jsonl` `session` line (no `seq`); the
    action logged with no new state and no URL and denied unless the window was stale.
  - **Report:** `session_suspected`, `authorization_denials`, `session_recovered`,
    `session_reinstalled`, `session_lost_actions`, `auth_ended` (new);
    `session_lost` now counts confirmed losses (or unconfirmed ones without a provider).
  - Tests: `tests/test_disco_session_loss.py` (new): real Chromium through the real
    capture proxy against a loopback board whose session dies after N API answers --
    a 401 with the route unchanged (provider: confirmed, a fresh login, revalidated,
    the dead sid never sent again, every 401 on a marked action id, one `session`
    line, `[1, 1]` contexts), a login form in place (provider), repeated losses (`[1,
    1, 1]` contexts, three logins, the cap's reason), no provider in three modes (an
    unconfirmed loss ends the run, one context); offline: a 403 on a live session is a
    denial (and never a loss without a provider), a credential submission's 401, a
    407, another origin's 401, a 429 and a 502 are no suspicion, a credentialed 401 is
    checked for the context's generation; and a strict xfail naming `disco synth`
    (the window's mark is not read yet).
- Impact (other components / project):
  - **SESS:** none changed. The explorer becomes a consumer of SP-56
    (`response_class`), SP-16 (`login_facts`, `request_entry_names`,
    `shows_login_form`, `looks_like_login_url`) and SP-61 (`check_health`, `ensure`);
    the SP rows' reader lists grow (`docs/SHARED_PRIMITIVES.md`, this lane's
    `doc_texts.md`). A loss the explorer confirms is the manager's (`check_health` marks
    it, its re-login bucket and caps apply).
  - **File contracts:** `actions.jsonl` gains `session` lines (no `seq`; the importer,
    `observe.DiscoActionLines` and the live trace pass over them); `explore.json` gains
    the counters above. No store table and no capture record changed.
  - **CLI:** `fuzzlab disco capture` is unchanged (a storage state only); with it a
    lost session now ends the run with its reason in `explore.json` instead of
    continuing on the dead session or re-installing the storage state.
  - **Concurrent lanes:** AU-DISCO adds an auth/session generation slot to the
    execution-state key; it reads `_Shared.auth.generation` (the generation the
    contexts carry; `Explorer._ctx_generation` per worker). Their work-state tracking
    must not count an action in a known-lost window as succeeded (`_lost_action`).
- Risk (level; mitigation or accepted-risk justification): **medium.** A loss decision
  ends or reshapes a run. Mitigations: the decision is the session layer's (no new
  detector); a policy block or an answer on a live session never changes anything;
  page signs are skipped where the step asked for a login page or the state shows its
  own login form; recoveries are capped; every end says why. Accepted: without a
  provider, a page that newly shows any password form at the same URL after an action
  ends the run (the session layer's coarse rule, stated in FR-CRAWL-41); an
  inconclusive check ends rather than pauses.
- Deliverables:
  - [x] Provider, generation, suspicion, decision, recovery, lifecycle, D′ marking in
    `explore.py` — done
  - [x] `tests/test_disco_session_loss.py` (real browser and offline; each new test
    shown failing on the base) — done
  - [x] FR-CRAWL-41 and FR-CRAWL-19's authenticated-runs bullet amended in place;
    the file contracts — done
  - [x] BUG-0552 (RCA, recurrence review, prior-PA failure analysis, sweep) — done
  - [x] Shared-doc texts (CHANGELOG, ERROR_LOG, PA-0552, SP rows, ARCHITECTURE,
    failure record) in the lane's `doc_texts.md` — done
  - [ ] `fuzzlab disco capture --identity` (a provider from the CLI) — todo (residual)
  - [ ] `disco synth` reads the window's mark (the strict xfail's owner) — todo
- Effectiveness (assessed 2026-10-21): on the base c483dc1 (the product file swapped in,
  one run) the no-provider tests fail on the defect itself -- `[stay]` and `[form]`:
  `session_lost == 0` (the loss unseen; `[form]` also two states unrestorable),
  `[redirect]`: two contexts open (the storage state re-installed, the old context left
  open); the provider and offline tests fail on the API the base lacks. After: the
  file's 13 tests pass and the synth pin xfails (28.6 s, real Chromium and mitmdump).
  The harness result is in the lane's report.
- Review round 1 of a1a93b1 (2026-10-21; DISCO4-B1, B2, R1, R2, R3; branch
  `lane/DISCO4-r1`):
  - Change:
    - **B1 (one generation for every worker).** `_Shared.lost_generations`: a lost,
      stale or unresolved verdict records the context's generation at the verdict,
      under `auth_lock`, before `_recover_session` (`_note_gone`); a worker that reads
      the record waits on that lock for the decision and adopts or stops.
      `_generation_gone` (a newer generation installed, or the context's recorded
      lost) is checked by `_session_checkpoint` (a clean window on a gone generation is
      marked stale), by `_session_current` (the pending window marked stale before the
      context is replaced; nothing more when the run stopped), before every action
      (`_ready`, new: once more right before the act), restore (`_restore_checked`
      begins with `_session_current`) and harvest load (`_load` returns when stopped).
      `_replace_context(page, verdict, reason)` releases and closes the old context and
      then marks what it sent after its window was marked; `_mark_leftover` does the
      same at a worker's end. `_mark_window` is the one marking path.
    - **B2 (consumers read the mark).** `disco.capture.lost_action_ids(run_dir)`: the
      one reader of the mark (bounded, `JsonlTail`). `ede.replayable` and
      `ede.page_urls` take ``lost`` and `EdeRunner(lost_actions=)`; `fuzzlab disco ede`
      passes the run's mark. `store_adapter.import_disco` (AUD) is pinned by a strict
      xfail naming its owner (a fix needs a CC-AUD entry this lane holds no number
      for). A whole-package guard (`tests/test_lost_window_mark.py`) requires every
      capture reader to read the mark or be listed with its pin or reason.
    - **R1 (in place without a known login form).** `State.login_shown` (new): whether
      a state showed a password form when found (seed, action, harvest). The
      checkpoint takes ``places``: a password form at the URL before an action, at the
      restored state's URL or entry URL (unless the state showed one), or at the seed's
      start page is a strong sign; at a harvest load or a navigation, a weak sign,
      raised only when a protected check decides it (`_checkable`). `login_shown` now
      suppresses only the form sign, not a login URL.
    - **R2 (a page sign whatever the answers).** `_loss_signs` returns the primary sign
      (answer, else page, else policy) and the page's own sign with its strength;
      `_confirm_loss` no longer returns ``reinstall``: the checkpoint makes a provider's
      live verdict after an action with a strong page sign a ``reinstall``.
    - **R3 (a protected check without a provider).** `_find_protected_resource` (at the
      seed of a storage-state run): the start page's URL is the run's protected
      resource (`_Shared.protected`) when `session.manager.health_verdict` reads a GET
      of it with the context's cookies (`ctx.storage_state()`) as live and one with no
      credential as refused. `_protected_get`: one GET from a request context of its
      own (`pw.request.new_context`, gated at the send by `checked_api_request` and
      `check_send_url`, ``max_redirects=0``, TLS verified, never through the capture
      proxy), judged by `health_verdict(refusal=False)`; disco's second send path of
      its own, which `tests/test_disco_isolation.py`'s send guard now sees (a
      ``.fetch(`` on a client the function made) and lists beside `Runner.send`. `_confirm_loss` without a provider checks every
      suspicion (a policy block too) against it with the suspected context's cookies
      (`_context_check`); with none, as before. `_recover_session` reports an
      unresolved verdict as such before the no-provider reason.
  - Impact (other components / project): **SESS:** none changed; the explorer becomes
    a consumer of SP-61's public `health_verdict` and `session.state.SessionState`
    (SP-61's reader list grows; this lane's `doc_texts.md`). **AUD:**
    `store_adapter.import_disco` is not changed; it is pinned (owner AUD). **File
    contracts:** none changed (`actions.jsonl`'s `session` lines as before; more of
    them in multi-worker runs). **New shared primitive SP-71** (the mark's one reader,
    `disco.capture.lost_action_ids`; row text in `doc_texts.md`). **Traffic:** a
    storage-state run sends two GETs of the start page at the seed and one per
    suspicion, straight to the target (lab-only, in scope; no new host).
  - Risk (level; mitigation or accepted-risk justification): **medium.** A gone
    generation now stops every worker's next step until the recovery decision
    (bounded by the recovery's own bounds; no new wait). A storage-state run whose
    start page is a protected resource now continues past a denial instead of ending;
    one whose start page is public keeps PA-0533(1)'s unconfirmed loss. Accepted: a
    seed that shows a password form ends a no-resource run (the identity's start page
    with a password form of its own is unusual; the reason says why).
  - Deliverables:
    - [x] B1, R1, R2, R3 in `explore.py`; B2 in `capture.py`, `ede.py`, `cli.py` — done
    - [x] tests: `tests/test_disco_session_loss.py` (four real-browser, five offline,
      the ede test, the import_disco pin), `tests/test_lost_window_mark.py` (the guard
      and its synthetic offenders), `tests/test_disco_isolation.py` (the send guard
      sees an API-request client's ``fetch``; `Explorer._protected_get` listed) — done
    - [x] FR-CRAWL-41 and FR-CRAWL-25 amended in place — done
    - [x] BUG-0552 "Review round 1"; shared-doc texts (PA-0552, SP-71, SP-61 readers,
      CHANGELOG, ERROR_LOG, F-1XX) in the lane's `doc_texts.md` — done
    - [ ] `store_adapter.import_disco` reads the mark (owner AUD; needs a CC-AUD number)
      — todo
    - [ ] a real two-worker run with an anonymous-200 API — todo (the race is covered
      offline, deterministically)
  - Effectiveness (assessed 2026-10-21): the targeted files passed (34 passed, the two
    pins xfailed). On a1a93b1 (its four product files swapped in, one run) nine of the
    ten new tests failed on their defect -- the no-provider restore and seed cases
    (`session_lost` 0; the seed's login form explored as the root state), the
    role-gated 401 (the run ended, `session_lost` 1), the offline R2 case (no
    reinstall), the three B1 cases (B's window unmarked; B acted on generation 7 three
    times; `act-5` dropped), the ede test (no `lost_action_ids`) and the guard (`_ede`
    unlisted). The tenth, the real-browser R2 test, passed there: its board left for
    `/login` before the 401 arrived whole, so the window held the page sign alone. Its
    board now reads each answer whole before reacting (as a client's interceptor does);
    run alone on a1a93b1 it fails (`session_reinstalled` 0, two states unrestorable).
    The harness result is in the lane's report.
- *(Merge integration, 2026-10-21, onto AU-DISCO (BUG-0539, CC-CRAWL-0055) and DISCO13
  (BUG-0551, CC-CRAWL-0059).)* `explore.py` (11 conflicting blocks) resolved so both
  hold:
  - **One page-before-the-step owner.** DISCO4's `_ready` (restore when dirty or the
    generation is gone, on a current session, re-checked after the read) is folded
    into AU-DISCO's `_bring_to` (the contract accepts the page, never a subset or a
    superset), which now returns ``(page, reading)``; its restores go through
    `_restore_checked`. `_process` restores through `_restore_checked` and hands the
    state to `_explore_here`. A restore lost twice is unresolved `session-lost`.
  - **The loss branch keeps both.** After an action, DISCO4's checkpoint decides
    (`_session_checkpoint`); a known-lost window's action is denied unless stale and
    logged with no new state (`_lost_action`), and its work item is finished, its
    effect a lost session (AU-DISCO's FR-CRAWL-32 rule; `_lost_window`). AU-DISCO's
    execution-key generation bump moved into `_replace_context`, the one place a
    context is rebuilt, so every worker that adopts a newer session reads its states
    in the next generation. AU-DISCO's own `session_lost` count in the branch is gone:
    DISCO4's checkpoint counts a confirmed loss once.
  - **Evidence only from a live window.** The first-visit reload (`_first_visit`)
    and a dismissal's reload (`_dismissal`) are session-checked before anything is
    declared from them; a delegated trial decided inert in a window later found lost
    is reopened (`compose.Trials.reopen`; `tests/test_disco_compose.py::test_an_inert_verdict_from_a_lost_session_window_is_reopened`)
    and its action treated as above.
  - `State` keeps AU-DISCO's contract and gains DISCO4's `login_shown`
    (`State.read(..., login_shown=)`, `_child(..., login_shown=)`); a child's is read
    before a dismissal's reload.
  - DISCO4's offline `_process` fakes (`tests/test_disco_session_loss.py::_stepper`)
    return a `Reading` and `ACTED`: the merged explorer's API, the tests' intent
    unchanged.

### CC-CRAWL-0059 — Discovery reads the composed UI tree: open shadow roots, same-origin frames, delegated actions; what it cannot read is counted (BUG-0551) (2026-10-21)
  - *(Coordinator, after the merge's semantic review.)* The generation bump moved
    into `_replace_context` counted this worker's rebuilds, not the session it
    carries: a reinstall split one session into two state spaces, and a worker that
    adopted a fresh session read it under a key another worker had recorded on the
    lost one, so the live session's states passed as known. `Explorer.reading` now
    keys by `_ctx_generation`, the run-wide generation the context carries (the
    worker's rebuild count only for a context with none). Test:
    `tests/test_disco_session_loss.py::test_the_execution_keys_generation_is_the_session_each_worker_carries`
    (fails on f025c2c at the reinstall step, passes after; plain Python call of the
    test function). FR-CRAWL-31's slot text amended in place. BUG-0552's merge
    section records it.
- Placement: pre-assigned to lane DISCO13 (audit defect 13), branch `lane/DISCO13` from
  c483dc1. Planned merge order: AU-DISCO, then DISCO13, then DISCO4. This lane's
  `explore.py` changes are in the enumeration, candidate and acting regions (the
  page-reading and acting sections, the report fields, `_Shared`); none is in
  AU-DISCO's fingerprint, dedup and replay code or in DISCO4's session-loss code.
- Change:
  - **SP-70, `tools/composed.py::COMPOSED_JS` (new).**
    - The composed-tree walk: a document and every open shadow root, each shadow tree
      right after its host; composed queries, `composedClosest`, `composedHosts`.
    - `deepAll`/`deepFind` use the native light-tree query when no shadow host is
      below, so a page without shadow roots reads as before.
  - **`disco/compose.py` (new): the explorer's read** (`read_page`, `READ_JS`,
    `FIELDS_JS`, `Reader`, `classify_frame`, `frame_scope`, `Coverage`, `Trials`).
    - `READ_JS` describes, per document, native, pointer, listener and delegated
      elements, bounded, and returns the document's frames, its open shadow-root count
      and its closed-root suspects. Unchanged for the light tree: the old ancestry,
      the old fields, the same order.
    - `Reader` runs it through DevTools' `Runtime.evaluate` with the Command Line API
      (`getEventListeners` inside the read). Frames run in their own main-world
      context, found through `Runtime.enable` and a marker the parent's read writes on
      the frame's window. Without DevTools it runs through Playwright.
    - An element's ancestry continues `^shadow<host` past each shadow root and
      `^frame<iframe<@/path` past each frame.
    - Frames are read when visible, same-origin and in scope; the rest are counted.
      Closed roots are confirmed through `DOM.describeNode` on suspects.
    - Delegated candidates are labelled non-semantic leaves under a
      `click`/`dblclick`/`mouseup`/`pointerup` listener in their composed path.
  - **`disco/explore.py`:**
    - `enumerate` calls `compose.read_page`, marks delegated candidates found inert or
      past the trial budget `disabled`, and adds the read's notes to the report
      (`_mark_delegated`, `_note_coverage`).
    - `_listener_elements`, `_ENUMERATE_JS`, `_CANDIDATES_JS` and `_MARK_JS` are gone.
      `_FIELDS_JS` is `compose.FIELDS_JS`: markers are cleared across the composed
      tree.
    - `_scope` and `_locate` follow the frame markers. `act` fills a form through its
      frame's scope, and a delegated element goes to `_act_delegated`/`_trial`. The
      click is factored into `_click`, with the same behaviour.
    - `ExploreReport` gains `shadow_roots`, `frames`, `closed_shadow_roots`,
      `frames_cross_origin`, `frames_out_of_scope`, `budget_limited`,
      `delegated_trials`, `delegated_live`, `delegated_inert` and
      `delegated_unexplored`. `_Shared` gains `trials` and `coverage`.
  - **`tools/spa.py::FORMS_JS`:**
    - It finds forms, buttons and controls across open shadow roots through SP-70.
    - A password control inside a shadow root is never described. A container holding
      one is read by its light tree (as before), and left out when it is itself in a
      shadow root, because the browser login's X3 clear and `G1_READ_JS` resolve ids
      with `document.querySelector` (pinned).
  - *(Review round 1, branch `lane/DISCO13-r1` from c219266; findings DISCO13-B1..B4,
    BUG-0551's review-round section.)*
    - **B1, a form-less widget at a shadow root's top.** `READ_JS`'s `formLike` returns
      the shadow root its ancestor walk ends at when the root holds a typed control: no
      `<form>`, so no action and `form_tag` false; `typed`, `last_typed` and
      `submitters` are the root's. `spa.FORMS_JS` considers that root once its 8-ancestor
      walk ends there, and describes such a container by its host (CAPTCHA hints, no
      action). SP-70: `deepAll`/`deepFind` walk a shadow root passed as the root.
    - **B2, state identity.** `fingerprint.counts_for_state` and `state_signatures`: a
      delegated candidate is never part of the state key, a state's core or
      `reproduces`. Every core in `explore.py` is built through `state_signatures`, and
      `_alias_state` through `state_fingerprint`. Delegated candidates are still read,
      stepped and tried.
    - **B3, causal trial evidence.** `Explorer._trial` runs a control window just
      before the click: `mark_activity` then `wait_quiet`, the same quiet wait the trial
      ends with. A request counts only when its `request_key` (method, normalised
      route) is not explained on that route (`_Shared.explained`): not seen by a control
      window there, not already counted by an earlier trial there.
    - **B4, the closed-root census.** The `suspects` heuristic, `Reader.census` and
      `MAX_CENSUS` are gone. `compose._census` makes one
      `DOM.getDocument({depth: -1, pierce: true})` per page. It counts every element
      hosting a closed root in each document read, attributed by the frame key on its
      frame element, once per route and page shape (`READ_JS` returns a digest of each
      element's tag and child count in walk order; `_Shared.censused`). A page whose
      documents read hold more than `MAX_NODES` elements, or that is read without
      DevTools, is not checked: its elements count `budget.census`.
- Impact (other components / project):
  - **SESS:** the session manager's browser login reads forms with `spa.FORMS_JS`.
    - A login form inside a shadow root is still never picked (left out, as before).
    - A light login form whose user field is a component's shadow input is now
      login-shaped and can be used. Its password stays in the light tree, where the X3
      clear reaches it.
    - No CC-SESS number was assigned to this lane; the coordinator decides whether
      SESS records an entry.
  - **The legacy spider** (deprecated) finds forms inside open shadow roots; G1 reads
    their controls as missing (pinned). A light container whose shadow components hold
    more buttons is no longer "one button" (composed semantics).
  - **AUD:** `store_adapter.import_disco` reads `actions.jsonl` as before; a signature is
    opaque. `explore.json` gains fields (additive). There is no store or wire
    contract change.
  - **The other lanes:**
    - AU-DISCO's new state identity must not read `disabled` or other flags of
      `how == "delegated"` elements (a trial verdict, not the DOM); BUG-0551 R7.
      *(Review round 1.)* Nor their membership: its `element_multiset` and
      `execution_key` (d9e269e) must filter `fingerprint.counts_for_state` at the merge,
      as `state_fingerprint` and `state_signatures` do here.
    - The SPIDER lane, or anyone adding a page script with a light-tree query, must add
      an allowance to `tests/test_composed_tree_guard.py::ALLOWED` or build on SP-70.
  - *(Review round 1.)* **SESS:** the browser login reads `spa.FORMS_JS`. A form-less
    shadow widget is now a container, but one holding a password control is still left
    out (it is in a shadow root), so the login's choice of form is unchanged.
- Risk (medium):
  - **The enumeration path changed for every disco run**, from Playwright's evaluate to
    CDP's evaluate. Mitigation: light-tree descriptions are byte-for-byte those of the
    old script (same fields, ancestry and order). `tests/test_disco_e2e.py`, with real
    mitmdump and Chromium, runs unchanged.
  - **Delegated trials add clicks** where a document-level click listener exists: at
    most 48 per run, each one click and one extra read. An inert trial is never an
    action. The destructive and deny gates run before `act` as for every element.
  - **The ancestry suffix** changes the signatures, and so the states, only of elements
    inside shadow roots and frames, which were not read before.
  - *(Review round 1; the round-0 statement above was wrong for light pages:
    delegated candidates changed state membership on any page with a document click
    listener, B2.)* With delegated candidates out of state identity, a light page's
    states are those of c483dc1 again.
  - *(Review round 1.)* **Costs added:**
    - each delegated trial waits one more quiet window (at least `idle_ms`): at most 48
      per run;
    - the closed-root census costs about 25 us per DOM node once per route and page
      shape (230 ms at 6 000 elements; 1.3-1.9 s at 24 000-30 000), and is skipped past
      `MAX_NODES` elements.
  - *(Review round 1.)* Accepted: background traffic slower than a control window can
    make one inert candidate per route and request key live (R8, measured). A delegated
    candidate that appears only after an action that changes nothing else is not tried
    there (R9; c483dc1's behaviour).
- Deliverables:
  - [x] SP-70 `tools/composed.py`; `disco/compose.py`; the `explore.py` enumeration,
    acting and report changes; `spa.FORMS_JS` — done
  - [x] `tests/test_disco_compose.py`, real browser:
    - an open-shadow-root form, filled and sent;
    - the shadow `Go`'s own identity, and a replay through the shadow root;
    - the settings frame's controls, and a replay through the frame;
    - a document-delegated tile kept and an inert candidate dropped;
    - the closed root, the cross-origin and out-of-scope frames and the delegated
      bounds counted;
    - the spider's form read across a shadow root.

    The offline tests cover frame classification, coverage aggregation and the trial
    budget, plus two strict xfail pins (G1, the browser login's X3 clear) — done
  - [x] `tests/test_composed_tree_guard.py`: the whole-package light-tree-query guard
    with its allowance list, the owner check, and synthetic offenders and near-misses —
    done
  - [x] FR-CRAWL-39 and FR-CRAWL-40 added; FR-CRAWL-19's actionable-elements bullet and
    section 5's `explore.json` line edited in place — done
  - [x] BUG-0551. PA-0551, SP-70, CHANGELOG, ERROR_LOG, ARCHITECTURE and F-1XX texts
    are in the lane's `doc_texts.md` for the coordinator — done
  - [x] *(Review round 1.)* B1-B4 fixed. Tests in `tests/test_disco_compose.py`:
    - a second real-browser app (`WIDGET`: a form-less shadow search widget, a Refresh
      that only swaps static text, delegated tiles, a 100 ms background poll) with
      three tests;
    - the spider's form read of the widget;
    - two more closed roots in the main fixture (a `<div>` host and an `<x-card>`
      slotting a visible child), counted exactly;
    - offline: state identity without delegated candidates, `request_key`, and the
      census's attribution, cache and bound.

    FR-CRAWL-19, FR-CRAWL-39 and FR-CRAWL-40 edited in place; BUG-0551's review-round
    section; PA-0551 (strengthened), SP-70, CHANGELOG, ERROR_LOG, ARCHITECTURE and
    F-1XX texts updated in `doc_texts.md` — done
- Effectiveness (assessed 2026-10-21, lane evidence; the harness on the committed tree
  is reported with the lane's result):
  - On c483dc1 the six defect tests in `tests/test_disco_compose.py` fail. The
    exploration never requests `/api/shadow/search`, `/api/shadow/go`,
    `/api/shadow/apply`, `/api/frame/save`, `/api/frame/apply` or `/api/tile/7`; the
    report has no composed-tree counters; `spa.FORMS_JS` misses the shadow form. The
    guard fails on the old `FORMS_JS`.
  - With the change all pass under `FUZZLAB_REQUIRE_BROWSER=1`.
  - Measured read cost: 20-28 ms for the fixture page (one document, one frame).
    getEventListeners inside the read costs 13 ms for 6 005 elements and 34 ms for
    24 005, one round trip, against about 1.35 ms per candidate per CDP call before.
  - *(Review round 1, assessed 2026-10-21.)* The new test file was run once against
    c219266's product code (a scratch copy of that tree, `FUZZLAB_REQUIRE_BROWSER=1`):
    8 failed, 8 passed, 2 xfailed. These are the eight review-round tests:
    - B1, explorer: the server got `/api/search?q=` (empty);
    - B1, spider: `spa.FORMS_JS` returned `[]`;
    - B2: Refresh's `new_state` differed from its state;
    - B3: `Just a note` was logged as an action;
    - B4: `closed_shadow_roots` was 1, not 3;
    - the three offline tests: the new names did not exist.

    On this branch the targeted files (`tests/test_disco_compose.py`,
    `test_composed_tree_guard.py`, `test_disco_e2e.py`, `test_disco_harvest.py`,
    `test_disco_workers.py`, `test_netquiet.py`, `test_session_browser_login.py`,
    `test_browser_scope.py`, `test_fewer_requests.py`,
    `test_base_url_subpath_registry.py`, `test_query_placement.py`,
    `test_shared_primitives.py`) gave 515 passed and 12 xfailed in one invocation. The
    reviewer's four probes on this branch:
    - B1: `q=test` was sent through an Enter step and a submit step;
    - B2: 1 state;
    - B3 (400 ms poll): 2 trials, 1 live;
    - B4: `div#host` and `x-card` counted.

    The harness result on the committed tree is reported with the lane's result.
- *(Merge integration, 2026-10-21, onto AU-DISCO's merge 07792e0: BUG-0539,
  CC-CRAWL-0055.)* `explore.py` (11 conflicting blocks) and `fingerprint.py` (1) were
  resolved so both lanes hold over every candidate:
  - AU-DISCO's identity inputs are read by the composed read. Each element's `sel` and
    each document's page markers (named hidden inputs, non-described `aria-current`;
    AU-DISCO's light-tree `_MARKS_JS`, which SP-70's guard refuses) moved into
    `compose.READ_JS`, in the same read as the elements (`PageRead.marks`).
  - BUG-0551 R7 closed: `fingerprint.element_multiset` and `workflow_markers` leave a
    delegated candidate out (`counts_for_state`), so neither the execution key nor a
    recorded contract reads it. Its `aria-current` is a page marker, as before it was a
    candidate.
  - `act` returns AU-DISCO's outcomes. A delegated candidate adds `ACT_INERT` (its work
    item finished `inert`; never logged, never counted an action) and `ACT_UNEXPLORED`
    (the run's trials spent: the item stays `pending`, counted). A trial whose click
    reached nothing, and one another worker holds, is a failed attempt (retried,
    FR-CRAWL-32): DISCO13 had decided a click that failed `inert`, which let one failure
    consume the candidate run-wide. A trial's "changed the state" is another execution
    key. `Step.safe` reads the requests after the click; the control window's are the
    page's own.
  - New tests: `tests/test_disco_compose.py::test_a_delegated_candidate_is_no_part_of_the_execution_key_or_a_contract`
    and `::test_the_composed_read_carries_the_execution_keys_markers`.
  - *(Found by the crawl batch's targeted run on a98c66d.)*
    `::test_an_element_in_a_shadow_root_has_its_own_identity_and_is_replayed_there`
    asserted each `Go` acted on once in the run: BUG-0539's removed route-scoped step
    key. The merged explorer takes each `Go` once in each of the fixture's 4 states
    (all on `/`, never equivalent; measured by driving the fixture directly: 8 actions,
    no (state, signature, occurrence, kind) twice). The test now asserts two
    signatures, one naming the shadow host, and never one step twice in a state, as
    AU-DISCO changed the e2e fixture's assertions (CC-CRAWL-0055).

### CC-CRAWL-0058 — The capture proxy builds records off its event loop, bounds its queue in bytes with backpressure, and counts every loss (BUG-0548, audit defect 22) (2026-10-21)
- Placement: pre-assigned to lane DISCO22 (audit defect 22); independent of AU-DISCO's
  defects 1-3 (`disco/fingerprint.py`, `disco/explore.py`, not touched here).
- Change:
  - **`disco/capture.py`.**
    - `snapshot(...)` -> `HeldExchange` (frozen, slotted): what a proxy hook takes. The
      header pairs (mitmproxy's `fields` tuple, by reference) and each body as sent
      (`raw_content`, content-coded, by reference), with its `size` in bytes. Nothing is
      decoded, redacted or serialised. A body over `MAX_CAPTURE_BODY_BYTES` (8 MiB, =
      `core.redaction.MAX_REDACT_BYTES`) is not held (`req_omitted`/`res_omitted`
      `"too_large"`); only its length is read.
    - `build_record(ex)` -> `(CaptureRecord, undecodable)`: run by the writer. Each
      body is decoded by `decode_body` through SP-60's `bodyread.read_body` (an
      in-memory `read1` stream) under `MAX_CAPTURE_BODY_BYTES`. A body over it once
      decoded, in a coding SP-60 cannot bound (`zstd`, a chain) or corrupt is `None`.
      Then `make_record`.
    - `make_record` gains `req_omitted` / `res_omitted`: a body not captured whole is
      recorded as none and marked `*_truncated` (fail closed, PA-0455: redaction
      needs the whole body). `OMIT_REASONS` = `too_large`, `backlog`, `undecodable`.
    - `_pairs` decodes latin-1 bytes pairs from any source (`fields`, a mapping, a
      tuple of pairs), so a held tuple is read like mitmproxy's `Headers`.
  - **`disco/recorder.py`.**
    - The hooks (`response`, `error`, `websocket_message`) only check scope and offer
      a `snapshot`. The writer thread (`_write`) runs `build_record`, `append_record`
      and the counters. Every failure there is contained, logged and counted
      `dropped` (PA-0086(2)).
    - The queue is bounded by `QUEUE_MAX` (10 000) records and `QUEUE_MAX_BYTES`
      (32 MiB) held.
      - An exchange that does not fit, or arrives while one waits, joins a line
        (`_Waiting` entries in a deque). Its hook returns an awaitable that mitmproxy
        awaits (`_wait_in_line`): the flow waits, never the loop, and records keep
        their order (`waited`).
      - The line is data: every offer and every waiter moves it (`_pump`), so a
        waiter that is never resumed holds no one back.
      - After `BACKPRESSURE_WAIT_S` (30 s) the exchange is queued without its bodies
        (`omitted.backlog`), or dropped when even that does not fit.
      - A waiting exchange whose flow is cancelled is `dropped`, and the line moves
        on. At shutdown the line is handed to the writer (`_flush_line`): its
        exchanges are complete, and only the browser was held back.
    - A refusal's stats refresh is a flag plus a wake-up item. It is never counted as
      a dropped record (it was, when the queue was full).
    - `request` narrows `Accept-Encoding` to what SP-60 can bound
      (`bodyread.advertise`). Measured: Chromium sends `gzip, deflate, br, zstd`
      through the proxy, even to a plain-http loopback origin.
    - `running` sets the process's GIL switch interval to `SWITCH_INTERVAL_S` (1 ms):
      measured, the loop waited up to CPython's 5 ms for the writer's GIL at each
      wake-up.
    - `stop` drains for `DRAIN_TIMEOUT_S` (30 s) in all. The stats file gains
      `omitted` {`too_large`, `backlog`, `undecodable`}, `waited` and `queued`.
  - **`disco/proxyproc.py`.** `STOP_GRACE_S` (45 s) is passed as procutil's `grace`:
    the stop lets mitmdump drain before the supervisor's kill. It was 5 s, so a
    backlog and the final stats would have been killed uncounted (PA-0138(3): the
    consumer that waits on the drain).
- Impact (other components / project):
  - The `capture.jsonl` record format is unchanged (`v` 1). A body not captured whole
    is `null` with `*_truncated: true`, which every reader already treats as "no
    schema from this body": `synth`, `ede`, `store_adapter`.
  - The stats file (`capture.jsonl.stats.json`) gains keys only. `cli` and
    `tools.observe` read `blocked`/`recorded`, unchanged.
  - The target sees a narrower `Accept-Encoding` from the capture proxy.
  - `proxyproc.stop` may take up to 45 s when the writer is behind (measured backlog
    drain: 8.5 s for 1 MiB JSON responses).
  - No SP-60 change: the recorder is a new consumer of `read_body` and `advertise`.
    The SP-35 owner gains `snapshot`, `build_record` and `decode_body`.
- Risk (medium): the hook now returns an awaitable when the queue is full, so the
  browser is paced to the writer (by design). The explorer's own deadlines therefore
  see the writer's speed on body-heavy bursts.
  - Mitigated: the wait is bounded (30 s, then the body is omitted and counted).
  - Measured: on 200 x 1 MiB JSON the page took 18.7 s, against 24.0 s when every
    hook blocked the loop (17.3 s against 30.6 s in a repeat pair).
  - The writer's CPU still shares the GIL with the loop (residual R1 in BUG-0548).
- Deliverables:
  - [x] `capture.snapshot`, `HeldExchange`, `decode_body`, `build_record`, `make_record`
    omission flags — done
  - [x] the recorder's hooks, writer, byte and count bounds, the backpressure line,
    contained failures, stats, `Accept-Encoding`, switch interval, drain — done
  - [x] `proxyproc.STOP_GRACE_S` — done
  - [x] tests: `tests/test_disco_capture.py`, 11 new and 1 changed; and the AST guard
    `tests/test_capture_hook_guard.py`, proven on synthetic offenders including the
    pre-fix shape — done
  - [x] measurement before and after: a loopback page firing 1500 x 64 KiB and
    200 x 1 MiB gzip JSON fetches through a real mitmdump, Chromium (BUG-0548) — done
  - [x] FR-CRAWL-18 and §5 edited in place; FR-CRAWL-38 added — done
- Effectiveness (assessed <date> or pending): pending.

### CC-CRAWL-0057 — Captured requests are kept per API operation: selectors in the key, nothing a request adds dropped (FR-CRAWL-37, BUG-0546, audit defect 9) (2026-10-21)
- Placement: pre-assigned to lane SPIDER9 (item AU-REQID78), base c483dc1; this lane's
  lines of `tools/spider.py` are `StorageManager.record_request` (plus the two-line
  schema comment in `_init_db` that described the old signature). Implemented first
  (PA-0541(1)); no design draft.
- Change:
  - **`fuzzlab/tools/apiop.py` (new, CRAWL).** The API operation of a captured request
    and what it adds:
    - `operation_key(method, url, media, doc)`: JSON `[method, url_key(url), media
      type, operation selectors]`;
    - `operation_selectors`: in the body at any depth and in the query, a GraphQL
      operation (`graphql_operations`: type, name and root fields of the operation
      `operationName` selects, aliases resolved, fragments expanded, a linear token
      scanner capped at 20000 tokens and 16 operations, an over-cap document told by
      the digest of its whitespace-folded text) and the value of a dispatcher field
      (`SELECTOR_NAMES`: action, act, op, operation, operationName, cmd, command, do,
      task, func, function, method, _method) when it is a token of at most 64
      characters or an integer; at most 64 selectors;
    - `request_shape`: typed key paths at every depth (array elements as one
      position) plus query parameter names; `operation_schema`: the union of an
      operation's stored rows' shapes; `row_signature`: the operation plus the sha256
      of the row's shape; `signature_prefix`: the operation's prefix of every row
      signature; `MAX_CONTEXT_ROWS` = 32.
  - **`StorageManager.record_request`.** After the unchanged redaction (both
    redactors at the write, probe markers scrubbed), it reads the operation's stored
    rows (`substr(signature, 1, len(prefix)) = prefix`, exact and case-sensitive). It
    returns `duplicate` when a row has the request's exact shape (its `row_signature`);
    "operation over its context cap" when the operation has 32 rows and the shape adds
    no key path or type to their merged schema (`operation_schema`); else it inserts the
    request's own body. A request that adds an input is never capped. Callers are
    unchanged (`None` = stored).
  - **Not done as asked, and why (flagged to the orchestrator).** The task said nested
    schemas are "MERGED". They are merged as the comparison basis (`operation_schema`);
    bodies are not merged into one stored row, because the importer judges a body as a
    whole (measured 2026-10-21 with `store_adapter.captured_request`: `{"q":"shoes"}`
    imports, `{"q":"shoes","sort":"price"}` is refused as a settings field; two
    40-leaf bodies merge to 80 leaves, over `jsonbody.MAX_LEAVES`). A merged row would
    have refused operations that import today.
  - **Sweep (PA-0002).** Two instances in other items' code are pinned by strict
    xfails (PA-0531(4)) in `tests/test_captured_operations.py`: `record_form` keys a
    form by action, method and control names (owner lane SPIDER); `disco.synth` keys an
    endpoint without selectors (owner disco synth). Recorded as known gaps in
    FR-CRAWL-37 (PA-0505(2)).
  - *(Review round 1, branch `lane/SPIDER9-r1` on 34d4fd1.)*
    - **B1, `apiop._selector_value` (was `_is_selector_value` and `_TOKEN`).** A
      `SELECTOR_NAMES` field was a selector only when its value was a whitespace-free
      token of at most 64 characters, so `action=Add+to+cart` and
      `action=Remove+from+cart` (form, JSON or query), or two values over 64
      characters, were one operation and the second was dropped as `duplicate`. Now
      every non-empty string value is a selector (a boolean is not, as before):
      whitespace runs are folded to one space, a folded value of at most
      `MAX_SELECTOR_CHARS` (64) is keyed by its text, a longer one by `sha256:` and the
      digest of its folded UTF-8 (surrogates passed through, so the digest is total).
      The free-text `command` case the first commit asserted as a merge is now two
      rows.
    - **B2, the sweep.** Two instances were left as prose: the importer's first-wins
      parameters (`tools/store_adapter.py::_store_request`, audit defect 8) and the
      pipeline's DOM-template stage (`core/dedup.py` via `harness/pipeline.py::_dedup`,
      audit defect 10, lane DEDUP10). Each is now pinned by an offline strict xfail
      naming its owner (PA-0531(4)), and BUG-0546's sweep names the pins. A guard
      (`sweep_rows_without_a_pin`) checks that every row of BUG-0546's sweep is fixed,
      not an instance, or names a strict xfail that exists, proven on synthetic
      offenders (34d4fd1's two rows among them).
- Impact (other components / project):
  - **Store contract (spider DB, `discovered_requests`; PA-0152 consumers from the
    code: `tools/store_adapter._import_requests`/`captured_request`,
    `tools/observe.observe_spider`, `scripts/crawl_maze_score.requested_spider`).**
    The columns are unchanged. `signature`'s form changes (no consumer reads it). A row
    is now one representative of an operation (one per distinct typed shape): each is
    still one real redacted body, so every consumer's reading of a row is unchanged.
    The new duplicate test is strictly finer than the old one (equal shapes imply equal
    top-level keys), so no request the old writer stored is dropped now, except one
    that adds no input past its operation's 32nd row; there are more rows for a
    dispatcher endpoint, a nested or type difference, a media type or a query name.
    AUD's importer gets every added operation as a form row, but not every added input
    as a point: its parameters are still first-wins per endpoint and name, so an input
    a second operation shares by name with the first (a GraphQL operation's `query`,
    `operationName`, a shared variable) is bound to the first operation's form and
    never sent with the second's document; only names new to the endpoint become
    points (audit defect 8, another lane; pinned by a strict xfail in review round 1,
    B2). *(As first committed this read "gets the added operations and inputs as form
    rows and points", which the review showed wrong for shared names.)*
  - An older spider DB keeps its rows; a resumed crawl's new rows never match an old
    signature, so they are stored beside the old ones (no loss).
  - `tools/spider.py`: only `record_request` and the `_init_db` comment changed; the
    callers `_observe` and `_record_dry` read the same return values.
- Risk (level; mitigation or accepted-risk justification): medium.
  - A data field named like a selector splits rows. Accepted: a split costs a row and
    is imported, never an input. Every non-empty string value of such a field is a
    selector, whitespace runs folded, a value over 64 characters keyed by its digest
    *(review round 1, B1; as first committed a value with whitespace or over 64
    characters was data, which merged two operations told apart only by it)*.
  - Row growth: one row per distinct typed shape of an operation, bounded by the
    crawl's captures as before; rows that add no input are capped at 32 per operation
    (counted and logged beyond). A request that adds an input is never refused.
  - GraphQL parsing of target text: a linear scanner with token, operation, root-field
    and fragment-depth caps; no backtracking regex.
- Deliverables:
  - [x] `tools/apiop.py` and the `record_request` change — done
  - [x] `tests/test_captured_operations.py` (each defect test fails on c483dc1's
    `spider.py`; the AST guard with synthetic offenders; two strict xfails) and
    `tests/test_spa_capture.py`'s signature expectation — done
  - [x] FR-CRAWL-37 and §5's `discovered_requests` contract edited in place — done
  - [x] BUG-0546; PA-0546, ERROR_LOG, CHANGELOG, ARCHITECTURE and failure-record texts
    for the orchestrator (lane doc texts) — done
  - [x] the harness run on the committed tree (`verify_change.py --base c483dc1`) —
    done; its counts are in the lane report to the orchestrator (this entry is
    committed with the tree it verified)
  - [x] *(review round 1)* B1: `apiop._selector_value`, the selector-value test and the
    `command` case as two rows — done
  - [x] *(review round 1)* B2: strict xfails for `store_adapter._store_request` and the
    DOM-template stage, the BUG-0546 sweep naming them, the sweep guard with synthetic
    offenders, the impact line corrected — done
  - [x] *(review round 1)* FR-CRAWL-37 (selector values, bounds, known gaps), BUG-0546
    (review round section, PA-0546(2) and (5)), and the lane doc texts — done
  - [x] *(review round 1)* the harness run on the committed tree
    (`verify_change.py --base 34d4fd1`) — done; its counts are in the lane report (this
    entry is committed with the tree it verified)
- Effectiveness (assessed 2026-10-21): achieved for the defect's scenarios.
  - *(Review round 1.)* One targeted pytest run on 34d4fd1's `apiop.py` (the round-1
    tests in place; `--runxfail`, so the pins report where they fail) failed exactly at
    the asserted requests:
    - `action=Remove+from+cart` after `action=Add+to+cart` returned `duplicate`;
    - `{"command": "cat a.txt"}` returned `duplicate`;
    - the importer pin failed at SearchPosts' own `variables.n` (all three parameters
      were on form 1);
    - the DOM-template pin audited 1 point of 2;
    - and the two earlier pins failed as before.
    The sweep guard was run on 34d4fd1's BUG-0546 text with a plain-Python driver. It
    flags exactly the two prose rows (`_store_request`, `core/dedup.py`). On this tree
    the round-1 tests pass and the four pins are xfailed.
  - Pre-fix proof: the new tests run once against c483dc1's `tools/spider.py` (a scratch
    copy of the tree, `apiop.py` present; a plain-Python driver calling the test
    functions, not pytest, while the host's pytest lock was queued by other lanes;
    the pytest verification is the harness run): 10 of the 11 non-xfail tests fail at the
    asserted request (`{"data":{"cmd":"x"}}`, the second GraphQL operation, the second
    JSON-RPC method, `?action=search`, the form body beside the JSON one, the over-cap
    GraphQL document, the context cap, the row signature, and the guard on the real
    writer); the guard's synthetic-offender test is test-only and passes on both; the
    two strict xfails stay xfailed.
  - On this tree every one of them passes, and `tests/test_spa_capture.py`'s
    write-site tests pass with the new signature.
  - Not measured on a live application: no lab run was in scope (the change is in the
    write site, exercised directly).

### CC-CRAWL-0056 — The legacy spider carries its identity on the static engine, admits URLs through a budgeted frontier, retries a transient failure and never files it visited, and batches its page rows (BUG-0545) (2026-10-21)
- Placement: pre-assigned to lane SPIDER (audit defects 5, 11, 12 and 25's spider part);
  FR-CRAWL-34..36; BUG-0545 / PA-0545. Implemented first (PA-0541): no design draft.
  Lane SPIDER9 owns `StorageManager.record_request` (the captured-API dedup); this entry
  does not touch it.
- Change:
  - **Identity on the static engine (FR-CRAWL-34, defect 5).** `tools/spider.py`:
    - `_fetch_static`, in an authenticated crawl (the `requests` engine, the engine chosen
      when Playwright is absent, and the browser's fallback), walks redirects with
      `navguard.get_checked` over `_SeamGet`: each hop is one send through
      `core.http.HttpClient` with the session manager as its addon (`prepare` applies,
      withholds or re-logs in; `observe` reads the answer), on the worker's own
      persistent `bodyread.bound(requests.Session())` whose jar keeps nothing
      (`_NoCookies`). The per-hop scope and destructive rules are unchanged; a hop to
      another origin than the session's is not followed and the load raises
      `SessionWithheld` (recorded `withheld`, FR-SESS-20), as the browser's route does.
    - `_static_identity` runs once per crawl before any page: `ensure` from the start URL
      (operator base), `session_headers` (origin and transport checks), a cookie or header
      a request can send (else `StaticIdentityUnsupported`), `verify_live` (SP-61; else
      `IdentityUnavailable`); then the session scope is `browserauth.header_scope_for`'s
      and a logout listener counts losses. A failure is cached and raised again.
    - `_seam_send`: an answer on a session the manager knows lost (`session_lost`) or
      sent while it saw a loss on any send is `_Transient` (retried after the re-login,
      never extracted); a `SessionAuthError` is `IdentityUnavailable`, which stops the
      crawl. `_sent_without_session`: an answer the manager withheld the session from
      (`OUT_OF_ORIGIN`) or applied none to (`session_generation` unset: a host outside
      its own scope) is never extracted (`SessionWithheld`). `_isolated_submit`
      (selector forms, FR-CRAWL-8) sends through the same seam in an authenticated
      static crawl (`_seam_submit`, `core.urls.with_query`).
    - The seam's host gate is the crawl's request scope (loopback aliases for a loopback
      start, else the host and its `www.`): one new host compare, a reasoned allowance in
      `tests/test_session_origin_scope.py::HOST_COMPARE_ALLOWED` (PA-0134(3)), deny only.
    - `--identity`'s help says the requests engine carries cookie and header sessions and
      refuses a browser-storage one.
  - **The frontier (FR-CRAWL-35, defect 11).** `_Frontier` replaces `_CrawlQueue`
    (`list`) and the one-worker `pop(0)` loop; every crawl, one worker included, runs
    `_crawl_parallel`. Admission reserves `spa.visit_key` (exact URL kept in the entry;
    a probe is never deduplicated); `FrontierLimits` (`max_pages` 20000, `max_pending`
    10000, `max_per_origin` 10000, `max_route_variants` 100, `max_url_length` 4096)
    refuse in `FRONTIER_REASONS` order, counted. Two deques (ordinary; seeds and probes,
    first worker only) and a retry heap; `take` is O(1). `_take` waits for a pending
    retry before planning probes or ending. `_claimed` is gone (the reservation replaces
    it). `tools/spa.py::route_shape` (new): canonical origin, path with
    `core.pathtemplate.id_shaped` segments as `{}`, sorted query names, the SPA
    fragment's shape -- a tuple, never a URL. `LocalSpider(..., limits=FrontierLimits)`.
  - **Transient failures (FR-CRAWL-36, defect 12).** `_visit` stores the row `pending`
    after the answer and `visited` (`set_outcome`) after extraction. `_check_answer`
    raises `_Transient` for SP-56 `incomplete`, `throttle-or-unavailable`, `gateway`, or
    another 5xx (no status literal outside SP-56's owner). `_page_failed` stores
    `failed` (status kept, `attempts`, `error`: an answer or exception class, never a URL
    or body) and retries `_is_transient` failures (`_Transient`, `BodyIncomplete`,
    connection, timeout, chunked and decoding errors) after `_backoff_s` (1 s doubling,
    `Retry-After` honoured, at most 30 s) up to `FETCH_ATTEMPTS` (3) loads; seeds and
    probes are never retried. The last failure is reported (`failed_pages`, a warning,
    `pages_failed`). `StorageManager`: `discovered_pages.outcome`, `attempts`, `error`
    (added in place); only `visited`/`withheld` (and an older row with a status) are
    "visited"; `unresolved()` feeds a `--resume` crawl every other row except seeds and
    probes.
  - **The page writer (FR-CRAWL-36, defect 25).** `mark_visited` / `set_outcome` decide
    from memory and queue the row; the `spider-store-writer` thread takes the queue and
    the store's lock together and commits by `WRITE_BATCH_ROWS` (64), `WRITE_BATCH_BYTES`
    (1 MiB) or `WRITE_BATCH_SECONDS` (1 s); `flush`, `count`, `set_source`,
    `unresolved` and `close` write what is queued first. A crawl thread waits only past
    `WRITE_BACKLOG_BYTES` (16 MiB, `writer_waits`); a failed write is raised at the next
    record, flush or close. `is_visited` reads memory only.
  - **Counts (PA-0110).** `crawl_stats` gains `frontier_admitted`, `frontier_duplicates`,
    `frontier_rejected[<reason>]`, `pages_retried`, `pages_failed`, `store_writer_waits`
    (`LocalSpider.CRAWL_COUNTS`, `crawl_counts`); `crawl_summary` logs refusals and
    unresolved pages as partial coverage.
  - Tests: `tests/test_spider_static_identity.py` (7), `tests/test_spider_frontier.py`
    (8), all failing on c483dc1; `tests/test_spa_routes.py`'s exact `crawl_stats` check
    takes the new counts out first; `tests/test_spa_query.py`'s U2 seed test, which
    times its injected stop by reading the newest page row from the store mid-crawl,
    flushes the queued rows first, under the store's lock (the guarantee it pins is
    unchanged: a stop before the promotion leaves the seed a write seed, written at
    close). `spider_kwargs` passes `limits=None` (the one CLI builder passes every
    keyword, U9). The writer executes on a cursor of its own (`conn.execute`), so the
    shared `cursor` is never used by two threads.
- Impact (other components / project):
  - **Spider DB contract (additive):** `discovered_pages.outcome TEXT`, `attempts INTEGER`,
    `error TEXT`; new `crawl_stats` names. Readers (`store_adapter.import_spider`,
    `observe.observe_spider`, `harness.auto`, `fetcher`) read named columns and are
    unchanged: a failed load is still a row with its status (0 when no answer), as
    before; a throttled one now keeps its 429/5xx status. An older DB is upgraded in
    place; its status-0 rows are loaded again by a resumed crawl.
  - **SESS:** the spider is a new caller of `ensure`, `session_headers`, `verify_live`,
    `add_logout_listener` and, through the seam, `prepare`/`observe`; nothing in the
    manager changes. **CORE:** a new caller of `HttpClient` (its own transport) and of
    SP-56's `response_class`; SP-60's `bound`; `core.pathtemplate.id_shaped`.
  - Crawl order is unchanged for one worker (FIFO by admission); the single-worker loop
    now runs through `_work`/`_take` (a `KeyboardInterrupt` still ends the crawl
    cleanly). A link to a URL already admitted is now dropped at admission instead of at
    `_take`/`_visit`.
  - `docs/SHARED_PRIMITIVES.md` SP-56's reader list gains the spider (text in the lane's
    doc_texts); no new primitive (SP-64 not used).
- Risk (level; mitigation or accepted-risk justification): medium.
  - Default budgets could cut a large real site, and the route budget cuts a page that
    lists more than 100 records of one route (`/item/1`..`/item/150`): they are bounds,
    not tuning; every refusal is counted and logged as partial coverage, and
    `LocalSpider(limits=...)` raises them. Not measured against the labgen labs (their
    live-boot crawls need the lab runtime, absent here).
  - A retry re-sends a GET (the crawl's only method for pages); a selector form's
    submission is never retried on its own (a page retry finds the form's signature
    enumerated already).
  - An authenticated static crawl now fails where it used to go on anonymously (a failed
    login, an unknown health, a browser-storage session): intended (FR-CRAWL-34).
  - The writer keeps up to one second (or 64 rows) of page rows in memory: a `SIGKILL`
    loses them; `KeyboardInterrupt` and normal ends flush (`crawl`'s `finally` closes the
    store).
- Deliverables:
  - [x] Identity on the static engine, fallback and selector forms — done
  - [x] Frontier with reserved keys and budgets, counted and reported — done
  - [x] Retry with backoff; failed rows never visited; resume loads unresolved rows — done
  - [x] Batched page writer, flush at close — done
  - [x] FR-CRAWL-34..36, NFR-CRAWL-bounded, FR-CRAWL-22 and §5 updated in place — done
  - [x] BUG-0545; PA-0545 and the shared-doc texts handed to the coordinator — done
  - [ ] Residuals R1-R6 below — todo (not this lane)
- Residuals:
  - R1: a status-0 load in the browser engine without an exception (no response object)
    is now retried as incomplete; not seen in any fixture -- a page Chromium can show
    without a response would be reported unresolved.
  - R2: a failed query seed is recorded `failed` but not resumed (it loads only inside
    its route's window, which a resumed crawl does not reopen for a visited route).
  - R3: the spider's other tables still commit per write under the store's lock
    (forms, verdicts, captured requests -- SPIDER9's region -- revealed forms, segments).
  - R4: the per-shape budget counts admissions, not loads: a refused variant is never
    re-admitted later in the run even if a sibling failed.
  - R5: a server that rotates its session cookie on every answer costs a re-login per
    rotation in the static engine (the seam does not adopt rotations; SESS's
    `observe`), bounded by the manager's re-login budget.
  - R6 (flag for SESS): `SessionManager.prepare` returns early, applying nothing and
    recording no decision, for a host outside its own scope; the crawl's scope can admit
    one (a loopback alias the config does not list). The spider never extracts that
    answer, but the request has already gone out without the session. A decision
    recorded on the request (as `OUT_OF_ORIGIN` is), or a refusal, belongs to SESS.
- Effectiveness (assessed pending): the 15 tests above fail on c483dc1 and pass here;
  measured on loopback (`scratchpad/lanes/SPIDER/measure/`): queue peak 1599 -> 78,
  trap loads 931 -> 100, a once-503 hub's child found, 1000 page rows 1000 commits /
  11.0 s -> 3 commits / 0.07 s on the recording thread. The harness result is in the
  lane report.
- Review round 1 of 9071440 (2026-10-21; two reviewers, each finding confirmed by a
  skeptic on both commits; branch `lane/SPIDER-r1`; BUG-0545's review section):
  - **B1 (both reviewers; a regression of this entry): a resumed crawl loaded stored
    rows around the scope and destructive rules.** `crawl()` fed every unresolved row
    to the frontier, and neither the frontier nor `_visit` asked `_in_scope` or
    `_destructive` (every other producer does, before it queues; `get_checked` sends
    the first hop unasked). Measured on 9071440: a `--resume` crawl of another loopback
    port sent 3 GETs to the first port's failed `/down` (BUG-0123), and a crawl started
    at `A/` loaded `A/logout`, which only an earlier crawl's start-URL exemption had let
    through. Now `_visit` asks `_load_refusal` (`LOAD_REFUSALS`: `out_of_scope`,
    `destructive`) first for every load, whatever queued it: never requested, nothing
    stored, counted `loads_refused[<reason>]` in `crawl_stats` and in the crawl
    summary; the rows stay unresolved. At the load, where the request is made
    (PA-0123(1)), not at the frontier: one place every load passes, retries and
    plain-list callers included.
  - **R6 (reviewer A; was residual R6, flagged to SESS): a host the session manager
    does not serve was sent to without the session**, then stored `withheld` with the
    false "another origin ... pass --auth-origin" reason. `_identity_client`'s seam now
    takes `_SessionAddon(manager)`: the manager's `prepare`, `authorize` and `observe`,
    and after `prepare` a request with no `session_generation` and no
    `session_decision` raises `HostNotServed` before the transport. Nothing is sent;
    `_seam_send` counts it (`session_host_unserved`, in `CRAWL_COUNTS`); the page is
    stored `failed` with the cause (`_page_failed` keeps `HostNotServed`'s text, which
    names the host, never a URL) and resumed; `_after_fetch` stops a selector form whose
    action is on such a host (logged; the page is kept). The manager's own decision is
    read, not its scope: no SESS change. The named remedy (add the host to
    `scope_hosts`) was measured: the alias then goes with the session
    (`scratchpad/lanes/SPIDER/r1/alias_scope.py`). Residual R6 is closed.
  - **B2 (reviewer B): three tests failed on c483dc1 only for the first test's
    reason** (the test site's anonymous `/` linked nothing). `_IdSite` serves
    `home_extra` to an anonymous visitor too; each now fails on c483dc1 on its own
    assertion. BUG-0545's "What it caused to fail" claims for these three are corrected
    in its review section (append-only).
  - Tests: `tests/test_spider_frontier.py::test_a_resumed_crawl_never_loads_a_stored_row_out_of_its_scope_or_destructive`
    (new: an out-of-scope and a destructive unresolved row; neither target receives a
    request); `tests/test_spider_static_identity.py::test_a_host_the_session_manager_does_not_serve_is_never_sent_without_the_session`
    replaces `test_an_answer_the_manager_sent_without_the_session_is_never_extracted`
    (it asserted the withheld row, not what the site received). Pre-fix proof, one
    pytest invocation (`scratchpad/lanes/SPIDER/r1/proof.log`): 5 failed in 4.87 s, each on its own assertion -- on 9071440's `spider.py`, the resume test ("B's crawl loaded A's row": `A/logout` 6 GETs, 3 expected) and the unserved-host test (`GET /deeper?via=alias` with no cookie); on c483dc1's `spider.py`, loaded in place of the tests' module, the redirect test (B got `GET /land`), the selector-form test (`/pick?bug=1`, `?bug=2` with no cookie) and the unserved-host test (the alias got a GET with no cookie). Targeted
    run on a83cb93, one pytest invocation of 13 files (`-n 3 --dist loadfile`, the
    harness's `FUZZLAB_REQUIRE_BROWSER/LINT/NETNS=1`; the two changed files, the
    spider suites whose loads pass `_visit` -- `test_spa_query`, `test_spa_routes`,
    `test_navigation_aborts`, `test_spider_links`, `test_spider_scope`,
    `test_forms_phase1/2` -- and the guards that read `spider.py` or the requirements:
    `test_session_origin_scope`, `test_logout_redirect`, `test_browser_scope`,
    `test_requirements_traceability`): 796 passed, 0 failed, 0 skipped, in 430.62 s
    (`scratchpad/lanes/SPIDER/r1/targeted.log`). `verify_change.py` was not run by the
    lane (the orchestrator verifies at merge).
  - Impact: `crawl_stats` gains `loads_refused[<reason>]` (when one refused) and
    `session_host_unserved`; its readers are the spider itself and two tests
    (`test_spa_routes.py` takes `CRAWL_COUNTS` out first; searched `crawl_stats` across
    `fuzzlab/`: no other reader). FR-CRAWL-34, FR-CRAWL-35, FR-CRAWL-36, the spider DB
    contract and NFR-CRAWL-safe edited in place.
  - Residual R7 (new): a stored row refused at its load was admitted by the frontier
    first, so it counts in `frontier_admitted` and against that crawl's total and
    pending budgets (one admission per stored unresolved row).
- Review round 2 of 8c2fa86 (2026-10-21; an adversarial fix check, each finding
  confirmed by a skeptic; branch `lane/SPIDER-r2`; BUG-0545's review round 2 section):
  - **S2-1 (R6 on the other engine): the Playwright engine loaded a loopback alias of the
    session's origin without the session and filed its anonymous landing as the
    identity's page.** The context holds the session cookie host-only for the start's
    host (`browserauth._cookies_of`, by URL); Chromium sends it to that host only
    (measured: `scratchpad/lanes/SPIDER/r2/cookie_domains.out`, a `127.0.0.1` cookie
    reached `127.0.0.1` and not `localhost` on the same port); the launch resolves every
    loopback spelling on the port; the route's `cookie_scope` compares canonical origins
    (aliases folded), so it neither withheld nor isolated the alias. The reviewer
    measured on 8c2fa86 and 9071440, with the manager's scope `['127.0.0.1']` and with
    the CLI's default `['localhost', '127.0.0.1']`: `GET /deeper?via=alias` with no
    cookie, an anonymous `/login`, the alias stored `(200, visited)`. Round 1's sweep had
    given the browser "withholds by route" without measuring it. Now `_visit` asks
    `_session_host_refusal` for every load of an identity crawl, after the scope,
    destructive and other-origin checks and before any navigation or send (the top of
    its `try`, ahead of a seed's or probe's window): the static engine asks the session
    manager's own `prepare` through `_SessionAddon` on a request that is never sent (a
    host it would leave alone: `HostNotServed`'s cause; a `SessionAuthError` is
    `IdentityUnavailable`, as on a send); the browser requires each of the session's
    credential cookies (`checked_cookies`), as its context holds them (`cookies` by
    URL, a browser login's `storage_state` cookies by domain), to reach the load's host
    (`_cookie_reaches`: host-only reaches that exact host; a dotted domain also its
    subdomains, never an IP address; RFC 6265 §5.1.3). A refused load raises
    `HostNotServed` with its cause: stored `failed` (unresolved, resumed) through
    `_page_failed`, counted `session_host_unserved`, logged, never visited, never
    `withheld`, never reported as another origin. A session without cookies goes by its
    headers, by origin, as before. The seam keeps its own refusal for a static redirect
    hop and a selector form. Generic: the host a load goes to is compared with the hosts
    the session's carrier reaches; there is no alias list. One new host compare
    (`_cookie_reaches`, deny only), a reasoned allowance in `HOST_COMPARE_ALLOWED`
    (PA-0134(3)). The crawl summary's line names both causes.
  - **S2-2: `test_a_session_lost_on_a_send_is_never_extracted_and_the_page_is_retried`
    failed on c483dc1 only because the crawl was anonymous** (`_IdSite` linked `/secret`
    and `/expiring` from the live session's home only; round 1 moved `home_extra` alone),
    and FR-CRAWL-34's enforcement line said every test failed on c483dc1 on its own
    assertion. `_IdSite` now links its `protected` pages (default `/secret`,
    `/expiring`) from the anonymous home too, and records the `Host` of each request.
    Each test of the file measured on c483dc1 (a driver with real fixtures, pytest
    imported as a library only, `fuzzlab.__file__` checked to be c483dc1's export:
    `scratchpad/lanes/SPIDER/r2/direct_c483dc1.out`), its failing assertion: identity
    test `"welcome alice" in rows["/"]` (`/` stored as `home`); session-loss test
    `"EXPIRING-PAGE" in rows["/expiring"]` (`/expiring` filed as its login redirect's
    answer `(200, '')`, `/login` stored); cannot-carry and failed-login tests
    `pytest.raises` "DID NOT RAISE"; redirect test `other.requests == []`; unserved-host
    test `sent == []` (`GET /deeper?via=alias` with no cookie); selector-form test its
    `sid=` check (`/pick?bug=1`, `?bug=2` with no cookie); browser test `to_alias == []`
    (`GET /deeper?via=alias`, `GET /login` twice). FR-CRAWL-34's enforcement text and
    BUG-0545's failure list now say this.
  - Tests: `tests/test_spider_static_identity.py::test_a_browser_load_the_session_cookie_does_not_reach_is_refused_never_sent`
    (new, real Chromium, `FUZZLAB_REQUIRE_BROWSER` applies: the CLI-default manager
    scope, so only the browser's cookie decides; the alias host receives no request,
    the alias is `(0, None, failed)` with the cause, counted, no `/login` row, not
    another origin, and `/`, `/secret`, `/deeper` crawled with the session); `_IdSite`
    as above; the static tests unchanged and green. Pre-fix proof, one pytest
    invocation with 8c2fa86's `spider.py` in place, then restored
    (`scratchpad/lanes/SPIDER/r2/proof.log`): 1 failed, 7 passed in 14.13 s -- the
    browser test at `to_alias == []` (`GET /deeper?via=alias`, `GET /login` twice, all
    to `localhost`); the 7 static tests pass on 8c2fa86, as they should (its static
    refusal sat at the seam). The 8 tests pass on the fix (driver run,
    `r2/direct_fix.out`). Targeted run on 6ccef90's tree, one pytest invocation of 17
    files (`-n 3 --dist loadfile`, `FUZZLAB_REQUIRE_BROWSER/LINT/NETNS=1`: round 1's 13
    files plus the authenticated browser crawls the new gate reads --
    `test_session_browser_login`, `test_spa_capture`, `test_forms_phase4`,
    `test_spider_workers`): 1236 passed, 0 failed, 0 skipped, in 498.43 s
    (`scratchpad/lanes/SPIDER/r2/targeted.log`). `verify_change.py` was not run by the
    lane (the orchestrator verifies at merge).
  - Impact: a browser crawl with a cookie session no longer loads a host its cookies do
    not reach (a loopback alias of its start among them): unresolved and reported,
    where it was crawled anonymously. A static crawl now asks the manager's `prepare`
    twice per load (the gate, then the send): no extra login or pause (the send's own
    `prepare` would make the same one first). `crawl_stats` names unchanged
    (`session_host_unserved` now counts browser refusals too; readers: the spider and
    `test_spa_routes.py`, which takes `CRAWL_COUNTS` out first). FR-CRAWL-34 and
    FR-CRAWL-36 edited in place. No SESS, navguard or browserauth change.
  - Residual R8 (new, measured, flagged; not fixed in this round, whose scope is the
    gate every load passes): inside a browser load, a same-origin redirect hop to a host
    the session's cookies do not reach (the route's walk, `navguard`'s `api.fetch`) and
    a selector form whose action is on such a host (`_isolated_submit`'s
    `storage_state` copy) are still sent without the cookie. Measured on this fix
    (`scratchpad/lanes/SPIDER/r2/browser_hops.out`): `localhost` received
    `GET /pick?bug=1`, `GET /pick?bug=2` and `GET /land` twice with no Cookie, and `/go`
    and `localhost/land` were stored visited (404). PA-0545(1) does not admit "sends
    anonymously" as a disposition: this needs the same predicate at the route's hop walk
    (a shared primitive's owner) and at the browser branch of `_isolated_submit` --
    flagged for the orchestrator.
    - *(Added at the merge, 2026-10-21.)* Residual R8 as measured by the round-2
      check: in the browser engine a redirect hop inside a load, a selector form's submission, and a client-side navigation (JS location / meta refresh) to a host the session's cookies do not reach are still sent without the cookie (pre-existing at c483dc1; the gate checks only where a load starts; the owner is navguard, a shared primitive; reported to the owner as a follow-up).

### CC-CRAWL-0055 — Disco: a state is its execution key, work is per state and survives a failure, and a restore never accepts or weakens a wrong state (BUG-0539) (2026-10-21)
- Placement: pre-assigned to AU-DISCO (audit defects 1, 2 and 3), with FR-CRAWL-31..33
  and SP-62; base 08e3eaa.
- Change:
  - **`disco/fingerprint.py` (defect 1, FR-CRAWL-31).**
    - New `execution_key` (SP-62): hash of `execution_route` (origin, the path as
      served, every query pair with its value, a SPA route's query pairs; a sensitive
      name's value replaced), `element_multiset` (signature counts),
      `workflow_markers` (an element's `sel`: a select's value, checked state,
      `aria-selected` / `aria-current` / `aria-checked`; a named hidden input's short,
      non-token value; a non-interactive `aria-current`'s position) and the session
      generation.
    - `state_fingerprint` is unchanged and documented as the structural key, for
      scheduling and folding only.
  - **`disco/explore.py`.**
    - The enumerator reads each element's `sel`; `_MARKS_JS` reads the page-level
      markers. `Explorer.reading` / `fingerprint` return a `Reading` (both keys, the
      elements, the multiset, the markers). `known` holds execution keys; `structures`
      holds structural keys for the harvest alias.
    - `Frontier`: a new route, then a new layout, then a variant of a known layout; the
      per-route bound counts refusals in `excluded`, reported as `coverage_excluded`
      (with `route_capped`); `admit` counts a state explored in place. States past
      `max_states`, or drained when `max_actions` is spent: `states_over_budget`.
    - **Work (defect 2, FR-CRAWL-32):** `work_key` = (execution key, signature,
      occurrence, kind); `WorkLedger` holds each item's status (pending, running,
      succeeded, refused, retryable, failed, equivalent) and each step's observed
      effects. `_pending` puts steps taken in another state last (`deprioritised`). A
      step is skipped (`chrome_skipped`, `equivalent`) only after equal effects
      (requests by method and folded route; transition) in states on two folded routes.
      A Playwright error, a step that could not act, or a missing element is a failed
      attempt: retried after a restore, up to `max_action_attempts` (3), then `failed`
      (`actions_retried`, `actions_failed`). `act` returns `ACTED` / `ACT_REFUSED` /
      `ACT_FAILED`. `seen`, `done` and `sig_routes` are gone.
    - **Restore (defect 3, FR-CRAWL-33):** `State` records its contract (`core` as a
      multiset, `markers`) and never changes it; `contract_mismatch` refuses a route,
      core (a proper subset, or fewer of a control) or marker mismatch. `restore`
      refuses a path holding an unsafe step before navigating, fails on a missing replay
      step unless its element is declared optional (`replay_skipped_optional`), and on
      a replay that issued a non-idempotent request (`replay-mutated`). Each step
      records `safe` from the requests issued while it ran (`_watch`, filled by
      `_on_request`); a state reached by an unsafe step, or with one in its path, is
      explored in place (`_admit` live, `max_live_depth` 3, `live_states`). A failed
      restore marks the state `unresolved` (`unresolved` by reason, `unrestorable`;
      `steps_abandoned`).
    - **Declared optional features:** `_seed` reads a fresh second load of the start
      URL (`_first_visit`: `restore` with an empty path) and declares what only the
      first load held (`first-visit`); `_dismissal` declares what a click removed
      altogether, with no navigation and nothing new, when the clicked element was
      among it (`dismissed`). `optional_declared` counts them.
    - The rebuilt context after a lost session bumps the worker's session generation.
    - A step's effect and its "changed the page" are judged against the page just
      before it (`_observe`, `now`), and a page a restore accepted is added to `known`
      (`_seen_as`): measured on the e2e fixture, the start state recorded with its
      first-visit dialog made every step on its restored page a "transition" to a new
      state, and the header buttons' effects never matched.
    - Scheduling: once no new route or layout is queued, up to `HARVEST_PER_VARIANT`
      (4) harvest loads and one variant of a known layout take turns (`_next_state`,
      `Frontier.priority`, `_Shared.harvest_credit`). Measured on the e2e fixture: with
      the multiset, a list growing a row per click (another tasks box, another dialog)
      filled the frontier with variants and the 240 s deadline came before the harvest
      started; with one load per variant it came after two script routes.
    - A perturbation pass is keyed on the form's field *set* (measured: a second
      identical dialog started a whole new pass of six submissions).
    - `_gather` marks a body read only after reading it, and `_seed` gathers the first
      load's bodies before its second load (measured: the second load let the first
      load's script go, its read failed and consumed it, and no script route or code
      segment was found).
    - `actions.jsonl` lines carry `replay_safe`; `explore.json` gains the counters
      above and `work`, and loses `transient_dropped`.
  - **Tests.** New `tests/test_disco_state_identity.py` (pure: both keys, markers, the
    frontier's bound and order, the ledger, the contract, the replay on fakes, the
    SP-62 AST guard and its synthetic offenders) and
    `tests/test_disco_state_identity_browser.py` (five real-browser flows on loopback
    pages). Changed: `tests/test_disco_e2e.py` (the old contract's assertions:
    `transient_dropped`, Theme once, no unrestorable state, per-route step uniqueness;
    the module run's safety deadline 240 -> 480 s, with an assertion that the deadline
    did not end it: the run is bounded by its 80 actions, which each state's own work
    now uses up, measured 229 s unloaded), `tests/test_disco_harvest.py` (the alias
    reads `structures` and a `Reading`) and `tests/test_base_url_subpath_registry.py`
    (`State.read`'s `entry_url` registered with its sub-path test).
  - *(Review round 1, on d9e269e: three blocking findings, each reproduced by a
    skeptic.)*
    - **B1 (a dismissal from one click).** Closing a modal with its own Close declared
      the modal's controls optional run-wide, so a restore that did not reopen the
      modal was accepted as the modal state. `_dismissal` now declares only for a safe
      click on an entry document as loaded (a state with no path), removing only what
      that state's recorded contract held, and only when a fresh load of the entry URL
      (`restore`, empty path) still shows none of it. `State.added` holds what a
      state's last path step added (`_child`, against the page just before the step);
      `contract_mismatch` never excuses it by a run-wide declaration.
    - **B2 (a superset accepted).** `contract_mismatch` refuses a control present more
      often than recorded or a marker the contract lacks (`extra`), unless declared.
      `_bring_to` reads the page before each step and restores when the last step
      changed it or the page no longer holds the contract; `_seen_as` is called only
      with a reading that passed the contract.
    - **B3 (work consumed by an unreadable result).** The work item is finished only
      once the result page was read. A safe step whose result could not be read is a
      failed attempt (`_attempt_failed`, retried after a restore); an unsafe one is
      `failed`, counted `unresolved: unreadable`, and logged with no new state. A lost
      session still finishes the item (its effect was read: the login page).
    - Tests: five pure tests (the superset, the PA-0029 pair, `added`, the dismissal's
      evidence on fakes, the unreadable result on fakes) and two real-browser tests
      (the modal, the later stage). The unit assertion that accepted a superset now
      expects `extra`.
- Impact (other components / project):
  - Store and file contracts: no store table changes. `actions.jsonl` gains a key and
    `explore.json` gains and loses report keys; their readers
    (`store_adapter.import_disco`, `tools.observe`, `disco.livetrace`) read none of the
    changed keys (searched: `new_state`, `"state"`, `transient_dropped`,
    `chrome_skipped`, `route_capped`, `unrestorable` over `fuzzlab/` and `tests/`). An
    older run directory imports as before.
  - AUD (FR-AUD-28's trace) reads `actions.jsonl` through `observe.DiscoActionLines`:
    unchanged.
  - A run takes more actions per state than before (each state's own work, then
    deprioritised repeats) and makes more states (multiset, markers); the per-route
    bound and the budgets cap both, and every cap is reported.
- Risk (medium): exploration order and counts change for every disco run.
  - Mitigation: the e2e fixture (third-party SPA shapes, BUG-0501/0502/0505) still
    reaches every endpoint it did; a state reached by a POST is explored in place
    rather than lost.
  - Residuals (BUG-0539): R1 data held in a closure; R2 background non-idempotent
    requests make steps unsafe (not measured on a third-party app: no lab in this
    lane, PA-0501(1)); R3 restores do not reset server state or storage; R4 first-visit
    UI off the start URL; R5 a list growing per submission fills its route's bound.
- Deliverables:
  - [x] `fingerprint.execution_key` and its parts; `state_fingerprint` documented as
    structural — done
  - [x] `WorkLedger`, `work_key`, retries, deprioritising, equivalence by effect — done
  - [x] the recorded contract, declared optional features, strict replay, unsafe steps
    never replayed, in-place exploration, unresolved reasons — done
  - [x] the two new test files; the e2e and harvest tests moved to the new contract —
    done
  - [x] FR-CRAWL-19 amended in place; FR-CRAWL-31..33 added; section 5's file
    contracts — done
- Effectiveness (assessed 2026-10-21, on e274706):
  - **On the pre-fix code** (08e3eaa's `explore.py` and `fingerprint.py` in a scratch
    copy, `FUZZLAB_REQUIRE_BROWSER=1`): all five real-browser tests fail on their
    behavioural assertion, and the pure module cannot import (`EQUIVALENT`, the new
    names). Measured:
    - wizard: `/api/wizard/finish` requested 0 times (three loads of `/wizard`);
    - dialog: the confirmation POST 0 times;
    - transient error: `/api/flaky/load` 0 times;
    - cart: the restore was accepted and the core shrank from
      `{start, pay, terms}` to `{start, pay}`;
    - order: `POST /api/order` 3 times (two replays).
  - **On the fix:** the 14 pure tests, the 5 real-browser tests and the 14 e2e tests
    pass (the e2e module run ends on its 80 actions, 229 s unloaded, every endpoint
    of the fixture reached, the hidden report's button acted on after its harvest
    load).
  - **verify_change** `--base 08e3eaa`: on e274706, 75 files, 3016 passed, 2 failed
    (the query-builder guard on `execution_route`'s `"?" + "&".join`, and the
    base-URL registry on `State.read`), 1 skipped, 20 xfailed; both fixed in the
    follow-up commit (the key is a JSON list; a sub-path test and a registry entry).
    On d9e269e (`--base 08e3eaa`): 75 files, 3019 passed, 0 failed, 0 errors, 1 skipped (`test_packaging`: bdist_wheel unavailable, environment), 20 xfailed.
    Review round 1, on c2057c6 (`--base d9e269e`): 75 files, 3026 passed, 0 failed, 0 errors, 1 skipped (the same environment skip), 20 xfailed.
  - *(Review round 1.)* The round's new tests on d9e269e's `explore.py` and
    `fingerprint.py` (one invocation, `FUZZLAB_REQUIRE_BROWSER=1`): 6 failed, 21 passed.
    - modal (B1): `unresolved == {}` where `{'core': 1}` is expected;
    - later stage (B2): Help logged under stage 1's key (`act-9`);
    - superset (B2): `contract_mismatch` gave None, not `extra`;
    - `added` (B1): `State.read()` takes no `added`; the dismissal's evidence (B1):
      `_dismissal` took the old arguments (no state, no reload);
    - unreadable result (B3): the step acted once, never retried.
    - The PA-0029 pair passes on d9e269e too: it pins the subset refusal d9e269e
      already had, against a future declaration that excuses too much.
  - On the revision, the targeted files (the two state-identity modules, the e2e,
    harvest, workers, the query-placement, base-URL registry and shared-primitive
    guards, lint): 320 passed, 10 xfailed.
  - Not measured on a third-party app (PA-0501(1)): this lane had no lab; residual R2.

### CC-CRAWL-0054 — The JSONL tail caps a line while reading it; the contract runner reads bounded and matches contract patterns in a killable worker (BUG-0536) (2026-10-20)
- Placement: pre-assigned to AU-BOUNDED (audit defects 23 and 27, with the disco and
  spider half of 21); the core reader is CC-CORE-0072, the senders CC-FUZZ-0109.
- Change:
  - **`disco/capture.py::JsonlTail` (defect 23).**
    - The cap is enforced while reading. When the held part of the current line
      would pass `MAX_LINE_BYTES` (newline included, as before), the module's
      `OVERLONG` marker (an empty `bytes` subclass instance, compared by identity) is
      yielded once in the line's place, the held bytes are dropped, and the rest of the
      line is discarded up to its newline, across `lines()` calls.
    - The held part is one `bytearray`, extended per read and copied out once; slices
      come from a `memoryview`. `copied` counts every byte copied (PA-0135(2)).
    - `CaptureTail.read` counts `OVERLONG` as quarantined. `read_capture` goes through
      it, as before.
    - `tools/observe.DiscoActionLines` (unchanged) numbers `OVERLONG` as one malformed
      line (`_action_doc` reads it as None), so the action log is capped by the same
      rule.
    - The boundary is unchanged: a final unterminated line of exactly the cap is read.
  - **`disco/runner.py` (defect 27, and BUG-0528 residual R6).**
    - `Runner.send` reads the streamed answer through `core.bodyread.read_body`:
      `max_body_bytes` is both the wire and the decoded ceiling, and `timeout_ms` is
      checked at every receive (the runner's own clock). `deadline` sets
      `timed_out`/`deadline`, a ceiling sets `truncated`, and an unbounded coding sets
      `cut`.
    - `search_bounded(patterns, texts)` runs a case's `body_matches` on its answer and
      its baseline in one worker, `python -I -S -c` through `procutil.run_bounded`,
      killed with its tree after `MATCH_SECONDS` (5 s). Its answer is shape-checked.
      `judge` uses it, and patterns that could not be evaluated make the case an
      `error` "body_matches not evaluated within 5 s (inconclusive)" unless other
      evidence matched.
    - `LEAK_PATTERNS` (reviewed constants) still match in-process.
  - **`tools/spider.py` (defect 21's sweep).** The crawl session, a worker clone's
    session and the isolated form-submission session (`iso`, which read whole a body
    it never used) are `bodyread.bound(requests.Session())`.
  - *(Review round 1.)*
    - The runner's session is `bodyread.watched`, and `Runner.send` runs inside a
      `bodyread.watch` of `timeout_ms`: the watchdog cuts a dripped status line or
      header too, and that is a `deadline` timeout.
    - Its requests advertise only codings the reader can bound (`bodyread.advertise`,
      applied to a copy of the case's headers).
    - The in-process matcher guard also flags `re.compile` of a non-literal (so
      `re.compile(rx).search(...)` and a kept compiled pattern) and `re` aliases. It is
      proven on synthetic offenders.
    - The optional persistent matcher worker was not built: the per-case worker start
      (about 140 ms) is residual R6.
- Impact (other components / project):
  - The live trace (FR-CRAWL-30) and the import read the same capped tail, so live and
    imported results stay equal (`tests/test_disco_livetrace.py`, with its over-cap
    record).
  - AUD's `DiscoActionLines` is capped without a change to its file.
  - FUZZ's FR-FUZZ-52 runner gains a liveness bound and a bounded matcher
    (requirements edited in place).
  - A case with `body_matches` costs one worker start per judged case (measured about
    140 ms on this host).
  - A cut exchange's evidence now records `body_bytes` 0: the bytes read before the cut
    are not kept (residual R5).
- Risk (low): the tail's output is unchanged except for an over-cap line, which was
  already quarantined once it ended.
  - The worker adds a process per judged case with patterns, and it is bounded.
  - A worker that cannot start makes the case an `error`, never a pass.
  - `disco/formfill.py::_fits` still runs a page's own `pattern` with `re.fullmatch`
    (residual R3, a strict xfail; flagged to the owner).
- Deliverables:
  - [x] `JsonlTail`, `CaptureTail`, `Runner.send`, `search_bounded`, `Runner.judge`, the
    spider's three sessions — done
  - [x] `tests/test_bounded_reads.py`:
    - the tail: an over-cap unterminated line, the boundary, the action log, memory
      (traced peak), the copy count, and the copy oracle proven on the pre-fix
      algorithm;
    - the runner: a dripped body, a catastrophic pattern under a 60 s smoke alarm,
      matching pins through the worker, the in-process matcher guard, the worker's
      shape check;
    - residual R3 as a strict xfail.

    — done
  - [x] FR-CRAWL-18's reader bullet and FR-CRAWL-30 edited in place; FR-FUZZ-52 (FUZZ's
    requirements) edited in place — done
- Effectiveness (assessed <date> or pending): pending.

### CC-CRAWL-0053 — The SPA seed builder places its route query through the one owner (BUG-0531 sweep, SP-42) (2026-10-20)
- Placement: assigned by the coordinator to AU-REQID14's part 2; CC-CRAWL-0051/0052 are
  other lanes'. The PA-0002 sweep of BUG-0531 found `spa.query_url` in its class.
- Change (`fuzzlab/tools/spa.py`):
  - `query_url(route_url, pairs)` now calls `core.urls.place_route_query_pairs`
    (CC-CORE-0068's part 2 addition): each pair by the standalone rule
    (`QueryEntries.replace_first`) in the route's query, a hash route's fragment query
    or, in history mode, the URL's own query. A name the route query already has is
    replaced in place; before, a second pair was appended (`#/s?q=1&p=2` + `q` gave
    `#/s?q=1&p=2&q=…`), and values were not encoded at all.
  - New `seed_value(text)`, the seed and probe encoder: `quote(text, safe="/")`. It keeps
    `/` as written. A redirect-type name's value is the same-origin path `/`
    (`query_value`, FR-CRAWL-17), and its safety test,
    `tests/test_spa_query.py::test_a_seed_gets_the_filler_and_a_redirect_name_gets_a_same_origin_path`,
    pins `redirectUrl=/`. Encoding it as `%2F` would rest on how each SPA router decodes
    it, which is not measured; the test stays unchanged. A space is `%20` in both modes,
    which every decoder reads as a space.
  - What reaches it is otherwise byte-identical: names are identifier-shaped
    (`query_name_ok`), probe markers are lower-case letters, the filler is `fuzzlab`, so
    the encoder changes no other byte today. The visible change is in-place
    replacement on a route that already carries the name, and no trailing `?` when
    `pairs` is empty.
- Reason: BUG-0531's sweep (PA-0002; PA-0531(4) had pinned it with a strict xfail for
  CRAWL). Not a separate item: same class, fixed under AU-REQID14 (coordinator).
- Impact (other components / project): CORE (the owner gains `place_route_query_pairs`
  and `encode_route_value`; `place_route_query_param`'s route branch now calls it, same
  bytes). Callers of `query_url` (by search): `spa.seed_url`, `spider.LocalSpider`'s
  probe builder (`spider.py:1851`); `disco/explore.py` uses `query_url_refusal` only. The
  query guard's allow-list loses the `spa.query_url` entry (43 findings under 41 keys).
- Risk: low. Mitigation: the seed tests of `tests/test_spa_query.py` (FR-CRAWL-17's
  safety enforcement) unchanged and passing; new rows in `tests/test_query_placement.py`:
  `test_the_spa_seed_builder_places_its_route_query_in_place` (8 rows, was the strict
  xfail), `test_a_seeds_redirect_type_value_stays_a_same_origin_path_in_both_modes`
  (2 rows), `test_the_route_query_owner_places_each_pair_by_the_standalone_rule` (3 rows).
- Deliverables:
  - [x] `query_url` through the owner; `seed_value` keeps `/` — done
  - [x] the strict xfail turned positive; the unit rows for `/` in both modes — done
  - [x] the allow-list entry removed; FR-CRAWL-17's seed text updated — done
- Effectiveness (assessed after landing): pending.

### CC-CRAWL-0049 — A failed navigation settles on its own error page before it raises; a failed load's cleanup has one owner (SP-01, BUG-0522) (2026-10-19)
- Placement: pre-assigned before CC-CRAWL-0050 was written (PA-0031), so it lands above that higher-numbered entry.
- Change (`fuzzlab/tools/navguard.py`, SP-01's owner; `fuzzlab/tools/spider.py`):
  - `_NavigationFailures.commits`: the main frame's commit URLs since this navigation
    started (its existing `framenavigated` listener, registered before `goto`).
  - `_settle_failure(page, failures, exc)`, called in `navigate`'s and `reload`'s
    failure path before re-raising. `_settles_on_error_page` reads only the first line
    of the error:
    - `^\S+: net::ERR_(?!ABORTED\b)[A-Z_]+ at ` waits for one fresh `chrome-error:`
      commit;
    - `^\S+: Navigation to ".*" is interrupted by another navigation to "chrome-error://[^"]*"$`
      waits for that commit and then one more (the overtaken navigation landing);
    - anything else does not wait.
    The wait polls with `page.wait_for_timeout(20)` for at most `ERROR_PAGE_WAIT_MS =
    3000`. The last commit is set on the exception (`NAVIGATION_SETTLED_ATTR`; None on
    expiry). Expiries are counted (`error_page_waits()`) and logged as a warning.
  - `end_failed_load(page, error, *, timeout_ms)`: "error-page" (nothing navigated) when
    `error` settled on the browser's error page, else `about:blank` (suppressed), "blank".
  - `LocalSpider._fetch_rendered`'s and `_window`'s `except` call `end_failed_load`
    instead of a hand-written `about:blank`. An error not raised by `navigate` (a key
    press, the session check) carries no record, so it gets `about:blank`. The
    `_navigation_withheld` docstring is updated.
  - Disco has no code change; its harvest `_load` and `restore` are covered through
    `navigate`.
- Reason: BUG-0522. Chromium commits its own error page for an empty error answer tens
  of milliseconds after `goto` raised, and any navigation made meanwhile is overtaken. An
  overtaken navigation still lands later (measured 30/30, 6–69 ms), overtaking the next
  one. Losses before the fix, as ranges over the a8b81df batch, two passes on bf1356a
  (`navblank/batch_r2.log`, `navblank/batch_sa.log`) and the reviewer's run
  (`gate6/r2_corroborate.log`):

  | Path | Lost |
  |---|---|
  | Spider's next load after one empty 404 | 14–19/20 |
  | Same, after two or three in a row | 14–20/20 |
  | Spider, a refused load then a 404 | 11–20/20 |
  | Auditor, after one empty 404 | 10–16/20 |
  | Auditor, after two or three in a row | 13–20/20 |
  | `navigate` straight after a failure | 24–40/40 |
  | Disco harvest load | 11–20/20 |
  | Disco restore | 15–20/20 |
  | A seed after a failed load | 8–15/20 |
  | `_leave` raised after a failed seed | 8–20/20 |
  | Next load after a failed seed | 3–18/20 |

  The r1 draft judged the error page by the page's current URL. It still lost 9–18/20
  (spider) and 7–15/20 (auditor) after two or three empty 404s in a row.
- Impact:
  - **Every SP-01 caller, by construction.** A failed navigation with a network error
    now raises after its error page commits. The sweep, with its call sites:

    | Caller | Effect |
    |---|---|
    | spider (`_goto_and_parse`, `_restore`, session re-adoption, anonymous submissions, reveals) | covered |
    | auditor `fetch` | covered (CC-AUD-0053) |
    | disco `explore` 811/812, 1005, 1083 | covered |
    | disco `ede._load` | a failure ends `_page`; the next page gets a new context |
    | `session.browserlogin` 530/537 | covered (CC-SESS-0027) |
    | `tools.browserexec` 539/563 (at 806791a) | covered (CC-FUZZ-0104) |

  - **Cost.** An abort (ERR_ABORTED), a download or a timeout raises at once, as before.
    In the overtaken case `navigate` still raises, so that one load is lost (a static
    fallback, or `restore` returning False); the one after it is not.
  - **Measured after the fix** (one process at a time; `navblank/batch_r2.log` and
    `navblank/verify_load.log`):
    - 0 lost in every order of Table 1;
    - 0/40 straight `navigate`;
    - 0/20 disco harvest and restore;
    - 0/20 seeds, `_leave` raised 0/20.

    Wait p50 24–44 ms, max 304 ms, 0 expired in 760 waits.
  - **Under the harness's parallel load.** The implemented code, unpatched (only its wait
    timed), was measured while another lane's `scripts/verify_change.py` parallel pass
    (`-n 3`) and this change's mutant runs were going: 280 waits, p50 25 ms, max 182 ms,
    0 expired; next load lost 0/20 in each order (`navblank/verify_load.log`). No timing
    assertion was added (PA-0526).
  - **Contracts.** SP-01's row is extended (owner `end_failed_load`, three guard tests).
    No contract, schema or traffic is added; fallback requests the interruptions caused
    go away.
- Risk: low to medium.
  - (a) Each failed navigation with a network error waits for its error page (p50
    under 50 ms).
  - (b) An expiry (3 s) reopens the race for that navigation. It is counted and
    warned, never silent.
  - (c) The overtaken case waits for one more commit. If one never came, the wait would
    expire.
  - (d) The classification depends on Playwright's message format (1.56). A change
    means no wait, today's race, and X1 still holds. Pinned by the classifier test.
  - (e) `chrome-error:` is Chromium's, and Chromium is pinned (1194).
  - (f) The record is an attribute on Playwright's exception. If it cannot be set, the
    cleanup goes to `about:blank`, as before.
- Deliverables:
  - [x] code — done
  - [x] Tests in `tests/test_navigation_aborts.py`, mutant results in the report — done:
    - `test_the_spiders_load_after_failed_loads_is_rendered[404,404x2,404x3,refused-404,404-refused]`
      (404-refused is not a pinning test: it passes on the old code);
    - `test_a_failed_navigation_returns_after_its_own_error_page[1,2,3]`;
    - `test_a_navigation_overtaken_by_an_error_page_waits_for_it`;
    - `test_only_the_leading_code_decides_a_wait_for_an_error_page`;
    - `test_a_refused_load_naming_a_network_error_in_its_url_is_not_waited_for`;
    - `test_an_error_page_ends_the_previous_document`;
    - `test_a_query_load_after_a_failed_load_is_rendered`.
  - [x] `tests/test_disco_harvest.py::test_disco_harvest_and_restore_after_failed_loads[1,2]`
    — done
  - [x] `tests/test_shared_primitives.py::test_every_about_blank_navigation_is_a_reasoned_exception`,
    `::test_the_about_blank_guard_catches_synthetic_offenders` — done
  - [x] The X1 tests and `test_the_send_time_oracle_sees_a_document_left_alive` kept
    green — done
  - [x] BUG-0522; FR-CRAWL X1 and SP-01 text in `requirements.md` — done
  - [ ] ERROR_LOG, PA-0522, the SP-01 row, CHANGELOG, ARCHITECTURE, failure record —
    orchestrator, at merge
- Effectiveness: pending (on a real crawl: static fallbacks after error answers, and
  `error_page_waits()`).

### CC-CRAWL-0050 — `fuzzlab disco capture --store` records the capture's trace live; a capture refuses a directory holding an earlier run's files (FR-CRAWL-30, BUG-0525) (2026-10-19)
- Change:
  - **`fuzzlab/disco/livetrace.py` (new): `LiveTrace(run_dir, store_path, run_id)`.**
    One thread, `disco-trace`, in the capture command's process, with its own `Store`
    connection and the run's one `TraceRecorder` (SP-48). Its steps are `open`, `poll`
    (every `POLL_S` = 0.25 s) and `finish`.
    - A live pass emits the complete records (`capture.CaptureTail`) and the action
      lines carrying an `action_id` (`observe.DiscoActionLines`) added since the last
      pass, through `observe.emit_capture_record` / `emit_disco_action`, then flushes
      once. Each item is guarded: one that cannot be built is counted `dropped` and
      logged.
    - The final pass (`stop(status)`, after the capture proxy stopped and `explore.json`
      was written) is `observe_disco(run_dir, read_capture(...).records)` on the same
      recorder, then `run.end` (scope `run`) and `close`. It writes whatever the live
      passes did not, so the run's events equal the import's.
    - `stop` never raises. A failure that stops the trace is printed to stderr at once;
      the thread writes `run.end` `aborted: trace <class>` and marks the run row
      (`LiveTraceFailed`). `stop` returns the reason, or a timeout after
      `join_bound(events)` = max(60 s, 20 s × (⌈(events+1)/512⌉ + 1) + 20 s).
  - **`fuzzlab/disco/capture.py` (SP-35):** `JsonlTail`, which returns complete lines
    split on `\n` bytes only, holds a partial line, and decodes nothing; `CaptureTail`
    on it (well-formed records numbered as `read_capture` numbers them); `_parse_line`.
    `read_capture` is now `CaptureTail(path).read(final=True)`: one loop, same result.
  - **`fuzzlab/disco/cli.py`:**
    - `capture --store PATH` / `--record` (opt-in, `core.storepath`, as `fuzzlab proxy`);
    - `RUN_FILES` and the BUG-0525 refusal;
    - usage order: scope → run files → storage state → store → `--dry-run` (which
      prints `trace: <path> (live, a new run)` / `trace: off`) → `--authorized` →
      workers;
    - with a store: `start_run("disco", <start netloc>)`, then `proxy.start()`, then
      `LiveTrace.start()`, then explore. `proxy.stop()` runs in the inner `finally`,
      then `explore.json`; `live.stop(status)` runs in the outer `finally`, so a
      `ServerLost` from the proxy still ends the trace. An exception marks the run
      aborted (`Store.mark_aborted`) and is re-raised;
    - the summary prints `trace: run <id> …`; a timeout exits 1. Without `--store`
      the capture runs as before.
  - **`fuzzlab/cli_taxonomy.py`:** `capture:store`, `capture:record`.
  - `recorder.py`, `mitm.py`, `proxyproc.py` and `explore.py` are not touched.
- Reason: gap 4 of the owner's diagrams goal. A capture reached the trace only when
  `fuzzlab auto --disco-run` imported it. BUG-0525 was found by this change's
  pre-change review.
- Impact (other components / project):
  - **AUD:** `tools/observe.py` builders, plus BUG-0524 (CC-AUD-0054).
  - **CORE:**
    - No code change. A new `run.tool` `disco`, holding trace events and
      `run_metrics` `trace_*` only.
    - `trace_duplicates` of such a run counts the final pass's re-emitted events
      (expected).
    - The one-recorder rule is now enforced:
      `tests/test_trace_writers.py::test_trace_recorders_are_made_only_at_the_listed_sites`.
  - **UI:** no code change. The Diagrams page lists the run while it writes, when the
    store is the one it has open. `--record` adds the newest run, so
    `report`/`diagram --run latest` pick it.
  - **Operators:**
    - A capture into a directory holding a stale `actions.jsonl`,
      `capture.jsonl.stats.json`, `explore.json` or `script_segments.json` now exits 2,
      `--dry-run` included.
    - `script_segments.json` is beyond the coordinator's list of three: the importer
      reads it (`store_adapter._disco_code_segments`), and a crashed single-worker
      explore leaves an old one in place.
- Risk (level; mitigation or accepted-risk justification): low–medium.
  1. *Capture timing:* measured below. Mitigation: opt-in; a reader only, outside the
     capture path.
  2. *A wrong live event under a right key* would survive `INSERT OR IGNORE`.
     Mitigation: one line reader per file shared with the import, and T1 checks the
     live rows alone, before the final pass, at 187 cuts.
  3. *A failed trace failing the capture:* per-item guard, thread catch, `stop()` never
     raises, `live.stop` in the outer `finally`.
  4. *Contention:* a write lock held elsewhere for more than 10 s drops a batch, which
     the final pass heals. Held throughout, a flush takes 20.1 s and `close` 10.0 s, so
     the join bound is 60 s or more; past it, exit 1.
  5. *Refused hosts at the end, not live:* their keys carry final counts.
  6. *Provenance:* `RUN_FILES` refused before anything runs (BUG-0525, PA-0525).
  7. *Ends that skip `finally`:* SIGTERM and SIGKILL leave the run without `run.end`
     (partial). Worker threads appending after an interrupt are not traced. Both are
     stated in FR-CRAWL-30.
- Review: pre-change gate on DRAFT-LIVEDISCO (rev 1, then rev 2). reviewer 2 confirmed
  both reviewers' findings in round 2; reviewer 1's re-check was stopped by the review
  cap. Rev 2's one blocking point is folded in: T1's second live pass, with the live
  rows checked before the final import.
- Deliverables:
  - [x] `fuzzlab/disco/livetrace.py`; `capture.py` `JsonlTail`/`CaptureTail`;
        `cli.py`; `cli_taxonomy.py` — done
  - [x] `tests/test_disco_livetrace.py`:
        `::test_the_live_trace_equals_the_import_wherever_the_files_are_cut` (T1),
        `::test_a_dropped_batch_is_healed_by_the_final_import`,
        `::test_a_capture_with_a_store_records_its_trace_and_its_end`,
        `::test_a_failed_live_trace_leaves_the_capture_and_marks_the_run`,
        `::test_a_proxy_that_cannot_stop_still_ends_the_trace`,
        `::test_a_failed_explorer_marks_the_run_aborted`,
        `::test_a_trace_that_does_not_finish_is_reported_and_exits_1`,
        `::test_the_join_bound_grows_with_the_flushes_the_final_pass_needs`,
        `::test_a_host_the_proxy_refuses_reaches_the_trace_with_its_final_count`
        (mitmdump), `::test_a_real_capture_is_in_the_store_while_it_runs_and_unchanged`
        (Chromium + mitmdump) — done
  - [x] `tests/test_disco_cli.py`:
        `::test_capture_refuses_a_directory_holding_any_file_the_trace_reads` (×8),
        `::test_every_file_the_import_and_the_trace_read_is_refused_when_stale`,
        `::test_capture_with_an_unusable_store_exits_2_naming_it_before_any_side_effect`,
        `::test_capture_dry_run_reports_the_live_trace_and_creates_no_store` — done
  - [x] `tests/test_trace_writers.py` (the one-recorder guard and its synthetic
        offender) — done
  - [x] FR-CRAWL-30; BUG-0525 — done
  - [ ] CHANGELOG, ERROR_LOG, PA-0525, SHARED_PRIMITIVES, DIAGRAMS.md, ARCHITECTURE.md:
        the text was given to the orchestrator, who owns those files — todo
        (orchestrator)
- Effectiveness (assessed 2026-10-19):
  - **Harness:** `scripts/verify_change.py --base 685259e` on a14334d (detached worktree, `FUZZLAB_REQUIRE_BROWSER/LINT/NETNS=1`): 73 files, one parallel pass, **2654 passed, 0 failed, 0 errors, 1 skipped** (`tests/test_packaging.py::test_the_wheel_ships_every_tracked_file`: bdist_wheel unavailable here, an environment skip), 10 xfailed (existing pins), rc 0, 708 s.
  - **Measured on the implementation** (the e2e fixture, 1 worker, 2 runs):
    - capture counters identical to the 5 earlier runs (104 records, 104 app hits, 11
      states, 26 actions, 5 submissions / 3 sent, 0 unrestorable);
    - explore 63.8 / 65.1 s, against baseline 63.3 / 64.4 s;
    - visible in the store to an independent reader (50 ms sampling) p50 0.15 s,
      p95 0.26–0.28 s, max 0.31 s after the response;
    - `stop` 50 ms; 0 dropped; a same-run re-import wrote 0.
  - **The prototype runs** (DRAFT §M3): tail thread CPU 0.19 s per 64 s capture, flush
    p50 1.2 ms.
  - **T1** runs 187 cuts in 5.5 s.
  - **On the old code** (`685259e`, the new tests copied in):
    - `test_disco_livetrace.py`: "ModuleNotFoundError: No module named
      'fuzzlab.disco.livetrace'";
    - the BUG-0525 test: "assert 0 == 2" (dry run, ×4), "Failed: a proxy was started"
      (×4);
    - the store tests: "SystemExit: 2" (argparse);
    - the guard: "Extra items in the right set: ('disco/livetrace.py', 'open')".
  - **Mutants of T1** (all fail):

    | Mutant | Failure |
    | --- | --- |
    | consume a partial line | `AssertionError: ('capture', 237)` at the live-only check |
    | decode each read chunk | `('actions', 349)` |
    | `str.splitlines` | `assert [] == ['…:rec:4']` |
    | text-mode / universal newlines for actions | the action scopes differ |
    | number records by physical line | `('capture', 237)` |
    | final pass without `observe_disco` | T1 and T8 fail |

  - **Mutants of the CLI tests:**

    | Mutant | Failure |
    | --- | --- |
    | the thread re-raising | T6: "assert 'the live trace stopped (RuntimeError: boom)' in ''" |
    | `live.stop` in the inner `finally` after `proxy.stop()` | T7: "assert {} == {'status': '…: ServerLost'}" |
    | `live.stop('complete')` before the outer handler | the explorer-failure test: "{'status': 'complete'} == {'status': 'a…RuntimeError'}" |

### CC-CRAWL-0048 — Disco logs each action's own id (BUG-0512) (2026-10-19)
- Change (`fuzzlab/disco/explore.py`): `_log_action` and `_log_load` write
  `action_id`, the id the action's requests carry (`act-`, `nav-`, `harvest-`).
- Reason: the importer had to guess the prefix (BUG-0512).
- Impact: one more key per `actions.jsonl` line. Readers that ignore it are unaffected.
- Risk: low.
- Review: this entry follows the two-reviewer gate run after the fact over the diagrams series (F-076); both reviewers disagreed, and every confirmed finding in this component is fixed here or answered below.
- Deliverables:
  - [x] code; covered by the capture test in `tests/test_diagram_e2e.py` (the log's own
    `action_id` and the fallback for an old log) — done
- Effectiveness: verified offline; a live disco run will carry it.

### CC-CRAWL-0047 — The spider records which page queued each page, and when it saw pages and captured requests (FR-CRAWL-29); a copied crawl worker no longer keeps the first worker's browser listeners (BUG-0509) (2026-10-19)
- Change (`fuzzlab/tools/spider.py`):
  - Spider DB: `discovered_pages` gains `found_from TEXT` and `seen_at REAL`,
    `discovered_requests` gains `seen_at REAL`, in `CREATE TABLE` and through the
    existing "columns older result databases won't have" `ALTER` loop (now
    `(table, column, declaration)`), so an older DB is upgraded in place and its rows
    keep NULL (unknown).
  - Crawl queue entries are `(url, depth, source, found_from)`. `_entries(items,
    found_from)` wraps the `(url, depth, source)` triples the producers still return
    (`_after_fetch`, `_finish_probe`, `_take_query_navs`, `_plan_probes`) at each
    queue insertion; `_visit`'s link and XHR appends carry it directly. Everything a
    visit queues carries that visit's **queued URL** (`queued`, taken before a probe's
    marker URL replaces it); what the crawl queues itself (the start URL, the
    well-known files, probes) carries None. `_take`, `_work` and the one-worker loop in
    `crawl` unpack the four fields and pass `found_from` to `_visit(..., found_from)`.
    Crawl order is unchanged: the same entries in the same positions; `_take` still
    claims the first entry for a URL.
  - `StorageManager.mark_visited(..., found_from=None, seen_at=None)` stores both
    (`found_from` through `spa.scrub_markers`, like the URL; `seen_at` now when not
    given); `_visit` passes the entry's `found_from` and `seen_at` (wall time taken
    just before the URL's own fetch -- after a seed's bare-route pre-load -- or at the
    start of the visit for a row stored after an earlier failure) at its three write
    sites; `_after_fetch(..., seen_at=None)` stores a redirect landing with
    `found_from = redact_url(url)` (the load that redirected, redacted as that site
    redacts the landing) and the load's `seen_at`.
  - `StorageManager.record_request(..., seen_at=None)` stores when the request was
    captured; `_observe` and `_record_dry` pass `time.time()` at capture.
  - BUG-0509: `_clone` copies every attribute but Playwright's cached listener
    wrappers (`_PW_HANDLER_CACHE`, Playwright's `IMPL_ATTR`): a worker copied after the
    first worker's browser started had registered the first worker's `_on_request`,
    `_on_request_failed`, `_on_request_finished` and `_dry_request` on its own page.
  - Deliberate contract change: `discovered_requests` is now `(id, page_url, method,
    url, content_type, body_json, source, signature, seen_at)`; the two tests pinning
    the exact columns (`tests/test_spa_capture.py::test_the_discovered_requests_table_is_exactly_the_contract`,
    `tests/test_json_points.py::test_the_crawlers_table_is_the_contract_the_importer_reads`)
    name it. The importer reads it in `tools/observe.py` (CC-AUD-0051: the event time);
    the point import (`store_adapter`, `captured_request`) reads named keys and does
    not need it.
- Reason: the diagrams (FR-CORE-505, FR-AUD-28) said "the spider records no
  timestamps, and a page's initiator is not recorded": the spider's events had no
  time and a page no initiator. Both are known at the execution point -- the queue
  entry is made while the parent's load is processed -- and were dropped.
- Impact: Spider DB contract (§5) gains three nullable columns. Consumers, found by
  searching `discovered_pages` / `discovered_requests` across `fuzzlab/` and
  `scripts/` (PA-0152): `tools/store_adapter.py` (`import_spider` reads named
  columns; the captured-request import reads `SELECT *` into `captured_request(dict(row))`,
  which reads named keys), `tools/observe.py` (`SELECT *`, now reads the new columns:
  CC-AUD-0051), `harness/auto.py` (named columns), `tools/fetcher.py` (named columns),
  `scripts/crawl_maze_score.py` (`url` only), `scripts/measure_diagrams.py` (builds its
  own old-schema DB). None breaks on an extra column; the two contract tests pinning
  the exact `discovered_requests` columns now include `seen_at`. No traffic change: the
  same requests in the same order. BUG-0509: a `--workers N` Playwright crawl now
  files each worker's fetch/XHR endpoints under that worker's own page (previously lost
  or filed under the first worker's page).
- Risk: low. A missed queue insertion would fail on unpacking (four fields) rather than
  silently store a wrong parent; every insertion is covered by the new tests on both
  engines. Thread safety unchanged: `found_from` travels in the entry,
  `_CrawlQueue` holds its lock, the storage methods hold theirs. A page whose URL
  carries a sensitive query keeps it in `found_from` exactly as its own row keeps it in
  `url` (the trace redacts it, `trace.safe_ref`); a landing's `found_from` is redacted.
- Deliverables:
  - [x] code; `tests/test_spider_trace.py` (new): a static (1 and 3 workers) and a real
    Chromium (1 and 2 workers) crawl of a loopback site -- every row's `found_from` is
    the page that linked, fetched or redirected to it, the start URL and well-known
    files NULL, a redirect landing's redacted; `seen_at` inside the crawl's wall
    window, never before the parent's, non-decreasing with one worker; a captured
    request timed after its page began; an old DB upgraded with its rows NULL. Proven
    to fail with the link parent dropped (5 tests fail) — done
  - [x] BUG-0509: `_clone` fix;
    `tests/test_spider_trace.py::test_a_cloned_worker_never_inherits_playwrights_cached_listeners`,
    `::test_each_workers_page_events_reach_that_worker` (two real browsers, judged by
    what each worker recorded, PA-0511); both fail with the old copy; the BUG-0509
    report — done
  - [x] FR-CRAWL-29, §5 contract; the two contract tests name `seen_at` — done
  - [ ] ERROR_LOG, PA-0509, CHANGELOG, ARCHITECTURE, DIAGRAMS.md, `report/diagram.py`
    spider note, the agent failure record — todo (orchestrator; files outside this lane)
  - [ ] The separate defect BUG-0509 records (the failed-load teardown to `about:blank`
    interrupting the next load, `tools/spider.py` and `tools/fetcher.py`) — todo (needs
    its own number and lane)
- Effectiveness (pending): to be assessed on a real crawl's diagram (initiators and
  first/last seen present on spider flows).

### CC-CRAWL-0046 — Both crawlers record the path segments the app's scripts hold; synth decides slugs through the one rule (FR-CRAWL-28, BUG-0507) (2026-10-19)
- Change: `fuzzlab/tools/spider.py` (`script_segments` table,
  `StorageManager.record_script_segments`, `MAX_SCRIPT_SEGMENTS`, the `script_segments`
  counter, filled at each script scan); `fuzzlab/disco/explore.py`
  (`_note_code_segments` from each JavaScript body `_gather` reads,
  `script_segments.json` written when the run ends); `fuzzlab/disco/synth.py`
  (`template_paths` decides through `core.pathtemplate.varying_is_parameter`, same data
  evidence and `SLUG_MIN_DISTINCT`).
- Reason: BUG-0507: the importers' variation rule needs the code's names as evidence,
  and only a crawl reads whole scripts (the capture truncates bodies); synth's own copy
  of the decision is the one BUG-0501 fixed.
- Impact: a new spider DB table and a new run file; synth's output unchanged.
- Risk: low. Names only; identifier-like segments never stored; capped.
- Deliverables:
  - [x] code; `tests/test_spa_capture.py` (the table filled, no identifier),
    `tests/test_disco_e2e.py` (the file written), `tests/test_disco_synth.py` unchanged
    and passing — done
  - [x] FR-CRAWL-28, ARCHITECTURE, CHANGELOG — done

### CC-CRAWL-0045 — The spider dry-submits SPA forms and records every write a window blocks (FR-CRAWL-26, BUG-0506) (2026-10-19)
- Change (`fuzzlab/tools/spider.py`, `fuzzlab/cli_taxonomy.py`):
  - `dry_submit=True` / `--no-dry-submit`: `_dry_submit_spa_forms`, `_dry_click`,
    `_dry_submit_anonymously` (a password form, fresh context), `_client_snapshot` /
    `_client_rollback` (cookies, `localStorage`, `sessionStorage`, inside the window),
    the client-side session check after each own-context click in an authenticated
    crawl (a loss stops and is reported); `_fill_controls` extracted from
    `_fill_and_click_now`.
  - `_dry_request` / `_record_dry`: a write a non-query window aborts while no vetted
    submission has lifted it is recorded through `record_request` (source `dry-submit`
    or `reveal-blocked`); the window's dict keeps its `page_url`.
  - Counters `forms_dry_submitted`, `requests_captured_dry`,
    `requests_captured_blocked` (stored rows, PA-0502), and their summary lines.
- Reason: the owner asked why the spider missed Juice Shop's login SQL injection and
  for the gap to be remediated (BUG-0506): with submission off, a form's request was
  never seen.
- Impact: a default Playwright crawl now records the request shapes of its SPA forms
  and of writes reveals make; nothing more reaches the target (each is aborted in the
  browser). The importer already takes every `discovered_requests` row (SP-37), so the
  points reach `auto`. More clicks per route; the crawl is slower by one window per
  eligible form.
- Risk: medium-low. An app's own code runs during a dry click: a handler that changes
  client state is rolled back, and an authenticated crawl fails closed on a loss. A
  form whose handler sends nothing (it navigates) records nothing.
- Deliverables:
  - [x] code; `tests/test_spa_capture.py` (the write recorded and never sent, redacted,
    the gate first; an authenticated crawl keeps its session, the login dry-submitted
    unauthenticated; `--no-dry-submit`), `tests/test_forms_phase4.py` (the reveal's
    blocked POST recorded); each proven to fail with the rollback or the fresh-context
    rule removed — done
  - [x] BUG-0506, PA-0506, ERROR_LOG, F-073, FR-CRAWL-26, ARCHITECTURE, CHANGELOG — done
- Effectiveness (Juice Shop v20.3.0, 2026-10-19; authenticated crawl, depth 3, 4
  workers, 38m42s): 6 forms dry-submitted, 2 writes recorded (`POST /rest/user/login`
  JSON `{"email", "password"}` -- the password blanked -- and `POST /rest/chat`), 9
  refused by the gate, 3 not submittable; no session loss. Counters reconciled with the
  DB (2 `dry-submit` rows = `requests_captured_dry`). The reveal window blocked 3,266
  writes and recorded none: none had a recordable body outside the transport rule (the
  log names no URL, so this is not verified per request; socket.io polling is the
  likely source). Spider-fed `auto`: **tp=6 fp=0 fn=9** (CC-LAB-0317: tp=5 fp=0); the
  new finding is `/rest/user/login` `email` (sqli). `/rest/chat` was refused at import
  (the captured-request gates).

### CC-CRAWL-0044 — Disco's harvest reads script routes and skips alias documents (FR-CRAWL-27, BUG-0505) (2026-10-19)
- Change (`fuzzlab/disco/explore.py`, `fuzzlab/disco/cli.py`):
  - `_script_routes`: each JavaScript body read in `_gather` is scanned with
    `spa.scan_script` (SP-47); OK routes and admitted route-query seeds are queued in
    `harvest_routes`, loaded before the linked URLs, in the page's routing mode
    (`_hash_routed`: a `#/` in the page URL or a link). `script_routes`,
    `script_route_seeds`, `scripts_too_large` counted and printed.
  - `_document_first` / `_alias_state`: a harvest load whose HTML body was first loaded
    under another path is not explored when the page is hash-routed or renders a known
    state (`harvest_aliases`); the start document is recorded at the seed.
  - `_log_load`: a harvest load of a hash route writes an `actions.jsonl` line (kind
    `load`, every action key) the importer reads.
  - `tests/test_disco_isolation.py`: the SP-47 names allowed by name (D70 amended).
- Reason: BUG-0505 -- on Juice Shop disco explored the shell served at `/sitemap.xml`
  as a second app (a duplicate finding) and never loaded `#/track-result`, which only
  the app's code names. The owner asked for the algorithmic gap to be remediated rather
  than worked around by a logged-in run.
- Impact: `fuzzlab/disco` only; the run directory's `actions.jsonl` gains `load` lines.
  A history-mode route served from the same shell is still explored.
- Risk: low. An alias is decided on the body hash plus the routing evidence or a known
  state; a dynamic page (a token in its body) is never an alias.
- Deliverables:
  - [x] code; `tests/test_disco_harvest.py` (alias rules incl. the history-mode
    negative, routing mode, oversized script, the SP-47 guard and its offender),
    `tests/test_disco_e2e.py` (a script-only route loaded with its query and imported
    as a `fragment` point; a catch-all `/sitemap.xml` not explored), the fixture's
    catch-all, route table and `#/` link — done
  - [x] BUG-0505, PA-0505, SP-47, D70 amendment, ERROR_LOG, F-072, F-073, FR-CRAWL-27,
    ARCHITECTURE, CHANGELOG — done
- Effectiveness (Juice Shop v20.3.0, 2026-10-19; anonymous, 4 workers, 600 s): 39
  script routes and 3 route-query seeds queued, 1 alias (`/sitemap.xml`) not explored;
  96 states, 216 actions. Disco-fed `auto`: **tp=5 fp=0 fn=10** (CC-LAB-0317: tp=4
  fp=1): `#/track-result` `id` (xss-dom) gained, the `/sitemap.xml#/search` duplicate
  gone; `/rest/user/login` `email` (sqli) found. `/profile` (ssti) is still missed: it
  answers only with a session, and an anonymous run has none (open; see the report to
  the owner). The first attempt stopped when the lab crashed under a probe of the
  crawled reviews template (ERROR_LOG); the repeat completed, and the lab exited again at
  its end.

### CC-CRAWL-0043 — The crawler's store import names the crawl's start as the main origin (2026-10-19)
- Change: `fuzzlab/tools/spider.py` (`--store`: `import_spider(..., base_url=args.start)`).
- Reason: FR-AUD-27 (CC-AUD-0048): rows on another origin than the run's main one keep
  it; the crawl's start URL is that origin.
- Impact: none for a single-origin crawl.
- Risk: low.
- Deliverables:
  - [x] call; covered by `tests/test_import_origin.py` (the importer) — done

### CC-CRAWL-0042 — `fuzzlab disco ede`: excessive data exposure by response mutation (FR-CRAWL-25) (2026-10-18)
- Change: `fuzzlab/disco/ede.py` (new), `fuzzlab/disco/cli.py` (`ede`),
  `fuzzlab/cli_taxonomy.py`. A route over the guard serves a disco run's recorded JSON
  GET answers, one field removed per load; the page's DOM (depth, tag, attributes, own
  text, value per element) is compared with 3 baseline loads (varying nodes ignored, a
  varying structure skipped). Unused fields go to `ede.json` with type and
  sensitive-name flag only.
- Reason: the owner's paper review (EDEFuzz, ICSE 2024: a metamorphic oracle for OWASP
  API3, 98.65% true positives on 8 sites, 33,365 exposed fields across 69 Alexa-200
  sites) and the owner's correction that the replay server's point is to *change* the
  response. No tool here detected this class.
- Impact: a new subcommand; nothing else changes. Pages and assets load from the target
  (`--authorized`); the replayed answers never do. One load per field shape, not one
  per element (EDEFuzz's cost was linear in leaves).
- Risk: low. Findings are candidates (a field used only after an interaction is
  reported; the paper's one false-positive class).
- Deliverables:
  - [x] code; `tests/test_disco_ede.py` (shapes, removal, types, noise mask, replay
    filter and redacted matching; a real browser on a local app: exactly the 4 fields
    the page never shows are reported, the noisy page skipped, a clock ignored, the API
    never called; the CLI's refusal, dry run and report) — done
  - [x] FR-CRAWL-25, ARCHITECTURE, CHANGELOG — done
- Effectiveness: not run on a lab yet (owner's direction: measure when asked).

### CC-CRAWL-0041 — Settles never wait for long-lived requests (FR-CRAWL-24, SP-40) (2026-10-18)
- Change: `fuzzlab/tools/netquiet.py` (new): `Inflight` counts a page's requests in
  flight minus event streams, WebSockets and any request open past `LONG_LIVED_MS`
  (2 s), whose answer is not activity either. The crawler's `_track` / `_settle` /
  `_quiesce` (`_busy`) and disco's `wait_quiet` (`_net`) count through it; browser
  login's own `_Inflight` class is gone (CC-SESS-0025).
- Reason: CC-CRAWL-0037's profile -- Juice Shop, one worker, 2072 s: `_settle` 64% of
  self time, 503 calls, often to its 5 s cap: a long-poll is in flight across every
  settle, so the count never reached zero.
- Impact: every browser settle ends once the app's own requests finish. Safety
  unchanged: a request in flight already passed the guard and the write window.
- Risk: low-medium. An ordinary request slower than 2 s is no longer waited for past
  2 s (its result may render after the page is read); the settle's other bounds stand.
- Deliverables:
  - [x] code; `tests/test_netquiet.py` (unit cases; the three settles against a real
    page holding a long-poll beside an 800 ms XHR: each waits for the XHR and ends in
    under 4 s -- the old code ran to the 8 s budget in both crawler and login cases;
    the SP-40 guard), `tests/test_disco_synth.py`, `tests/test_disco_workers.py`
    updated — done
  - [x] FR-CRAWL-24, SP-40, CHANGELOG — done
- Effectiveness: not re-measured on a lab (owner's direction); the fixture shows each
  settle bounded by the app's own requests instead of its budget.

### CC-CRAWL-0040 — Teardown never lets a just-started refused request out (BUG-0504) (2026-10-18)
- Change (`fuzzlab/tools/navguard.py`, `fuzzlab/disco/explore.py`, `fuzzlab/tools/spider.py`):
  `close_pages(context, pages)` freezes each page (CDP: scripts disabled, loading
  stopped), drains `RELEASE_DRAIN_MS` (100) of event dispatch through the guard, then
  closes; `release` uses it with a refuse-everything route added before the close and
  never calls `unroute_all`. Disco's `_close_popups` and the spider's
  `_close_window_pages` close through it. SP-38.
- Reason: BUG-0504 -- a refused navigation started at teardown reached the server
  (18/80 loaded M6 runs; 15/15 in the direct test).
- Impact: every guarded browser (crawler, disco, M6, fetcher, browser login): teardown
  takes about 100 ms more per page; nothing refused is ever sent.
- Risk: low. No call waits on in-flight work (PA-0128); each step is best effort.
- Deliverables:
  - [x] code; `tests/test_navigation_aborts.py::test_a_navigation_started_at_teardown_is_refused_never_sent`,
    `tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting` (rewritten),
    `tests/test_shared_primitives.py::test_a_guarded_page_is_closed_only_through_close_pages` — done
  - [x] BUG-0504, PA-0504, ERROR_LOG, SP-38, NFR-CRAWL-safe, CHANGELOG — done
- Effectiveness: stress (M6 `/fire`, `-n 8`): before 18/80 leaked; after 0/160.
- Verified: `verify_change --base 711bcdd` on 34ce24e: 79 files, 3104 passed, 0 failed,
  5 skipped, 18 xfailed (covers CC-CRAWL-0038/0039/0040).

### CC-CRAWL-0039 — Write targets are never links; no subresource fetched twice (BUG-0503) (2026-10-18)
- Change (`fuzzlab/core/linkextract.py`, `fuzzlab/tools/spider.py`): the extractor drops
  `action`, `formaction`, `ping` and script strings (`js_urls` and inline-script reading
  removed); its module doc states the contract (every URL returned is GET-safe). The
  rendered spider records what the browser requested as subresources (one set per
  crawl, shared by its workers) and never queues one as a page. Eight extractor
  functions registered with a sub-path test (PA-0300).
- Reason: BUG-0503 -- CC-CRAWL-0038 (unpushed 6a30ec9) made both tools GET POST-only
  endpoints.
- Impact: Security Crawl Maze cases reachable only by GETting a script string or a POST
  target (`js-post`, `js-put`, `js-delete`, the string-literal cases, form actions) are
  no longer reached by a GET; disco still reaches a script's requests by acting on the
  page. Not re-measured (owner's direction: measure when needed). FR-CRAWL-23 added: the
  extraction CC-CRAWL-0038 left "amended by reference" is now specified in place.
- Risk: low; fewer requests.
- Deliverables:
  - [x] code; `tests/test_linkextract.py` (negative cases, sub-path test),
    `tests/test_spider_links.py` (write targets never fetched; fails on 6a30ec9),
    `tests/test_spa_routes.py` (main.js once per document, never a page),
    `tests/test_navigation_aborts.py` (the previous page stays, whichever it was) — done
  - [x] BUG-0503, PA-0503, ERROR_LOG, CHANGELOG, F-066 — done

### CC-CRAWL-0038 — Both discovery tools follow every URL a response links; disco harvests them (2026-10-18)
- Change:
  - `fuzzlab/core/linkextract.py` (new, pure): URLs from every URL-valued HTML attribute
    of the HTML standard and its obsolete-but-parsed features, `<base>`, refresh
    `<meta>`, the DOCTYPE system id, CSS (`url()`, `@import`), headers (`Location`,
    `Content-Location`, `Refresh`, `Link`), path-like script strings, `robots.txt`
    rules and sitemap `<loc>`s; `KNOWN_FILES`.
  - Spider: both engines return every URL the response links (`_parse_html`,
    `response_urls`, header targets; a CSS/JS/robots/sitemap body read when that is what
    loaded), followed whatever the media type; `robots.txt` and `sitemap.xml` seeded.
  - Disco: each worker records the in-scope URLs requested and gathers what each settled
    page and its responses link (`_gather`); once the frontier is empty it loads the
    never-requested ones through its guarded page (`_load`, `max_harvest`, 500), an HTML
    document becoming a state outside `max_states`; known files seeded. `max_states` and
    `max_actions` now end exploration only; the deadline ends the run.
- Reason: the Security Crawl Maze (CC-LAB-0302) showed both tools reading `<a href>`
  (and clicks) only: spider 6/91, disco 3/91.
- Impact: both tools request more (every linked in-scope resource, known files); scope
  and destructive-URL gates unchanged. FR-CRAWL-19/22 amended by reference here.
- Risk: medium. More requests per run; a disco run no longer stops at 60 states while
  queued work and the harvest remain (the deadline bounds it).
- Deliverables:
  - [x] code; `tests/test_linkextract.py` (spec-derived), `tests/test_spider_links.py`,
    the disco e2e harvest test and fixture shapes, updated spider/disco tests — done
  - [x] CHANGELOG; F-064 — done
- Effectiveness (Security Crawl Maze, 84 built cases, one run each, 2 workers): spider
  6 -> 68 found (58 s); disco 3 -> 69 found (123 s). Not re-measured on Juice Shop.

### CC-CRAWL-0037 — Crawl workers in the legacy spider (FR-CRAWL-22) (2026-10-18)
- Change (`fuzzlab/tools/spider.py`, `fuzzlab/cli_taxonomy.py`):
  - `fuzzlab crawl --workers N` / `LocalSpider(workers=)` (1..8, default 1).
  - The crawl loop's body moved, unchanged, into `_visit`; one worker runs the same
    loop as before.
  - Several workers: `_crawl_parallel` runs the first worker on the calling thread
    (its browser started first, so the session is ensured once) and the others on
    threads, each with its own browser and HTTP session (`_clone`: shared containers,
    counts, store and locks; per-worker browser and per-page state).
  - `_take` claims each URL under the crawl lock (no page loaded twice), gives seeds and
    probes to the first worker only and plans probes once every worker is idle.
  - `_interact` serialises everything that can write: `_after_fetch` (reveals, SPA
    form submissions, selector forms) and seed/probe loads, so the caps and windows keep
    their one-worker meaning.
  - Stop flags and crawl-wide counts are shared fields (`_shared_field`). The SQLite
    store is opened `check_same_thread=False` and every method holds its lock
    (PA-0023).
  - The module docstring is brought current (auto reads a disco run since
    CC-FUZZ-0090).
- Reason: the owner asked for multithreading in the spider (2026-10-18).
- Impact: the spider only; one worker is unchanged. FR-CRAWL-22 added.
- Risk: medium. Page loads overlap while every write-capable step stays serial; the
  gain is bounded by how much of a crawl is page loading rather than reveals and
  submissions. Counters incremented outside `_interact` (request counts) are plain
  dict increments and may undercount by a few under contention; the caps that matter
  for safety are all checked inside `_interact`.
- Deliverables:
  - [x] code; `tests/test_spider_workers.py` (same pages, each once, overlapping loads;
    the write-capable phase never concurrent; a worker's failure ends the crawl; shared
    flags and counts; the bound; two real browsers) — done
  - [x] FR-CRAWL-22, CHANGELOG — done
  - [x] `verify_change --base 4bda67e` on a92d2c3 (the overlap test made deterministic
    after a loaded suite showed no overlap in the two-browser test): 77 files, 3057
    passed, 0 failed, 5 skipped, 18 xfailed — done
- Profile behind the design (Juice Shop, one worker, 2072 s, self time): `_settle` 64%
  (503 calls: waiting for in-flight requests, often to its 5 s budget), page loads 13%,
  reveals 11%, window restore/leave 8%.
- Effectiveness: not measured on a lab in this change (the owner asked to stop
  re-measuring after each change).

### CC-CRAWL-0036 — Parallel exploration workers in disco (2026-10-18)
- Change (`fuzzlab/disco/explore.py`, `cli.py`, `fuzzlab/cli_taxonomy.py`):
  `ExploreOptions.workers` / `disco capture --workers N` (1..8, default 1). The run's
  shared state (frontier, known states, seen/done steps, chrome map, perturbed forms,
  denied steps, action-id counter, report) moved into `_Shared` behind one lock;
  each worker is an `Explorer` clone with its own Playwright instance, browser, guarded
  context, page, quiet tracking and action tag. `run()` seeds the start state in one
  worker; each pops a state, restores and explores it, and pushes what it finds; the run
  ends on an empty frontier with no worker busy, or on a budget (every worker stops);
  a worker's exception stops the rest and is raised. One worker runs inline, as before.
  The action log gains `occurrence`.
- Reason: the owner asked for multithreading in the discovery tools (2026-10-18). A
  profile of a Juice Shop run (752 s) showed it waiting, not computing: 45% restoring
  states (mostly network-quiet waits), 33% acting (13% filling forms), 14% waiting
  after actions, 11% reading pages -- time several browsers can overlap.
- Impact: `fuzzlab/disco` only; the default (1 worker) explores as before. FR-CRAWL-19
  amended (workers, the log's occurrence).
- Risk: medium. With more than one worker, which worker takes which state is not
  deterministic, and one worker's submissions change the server state the others see;
  each extra worker is another Chromium against the target (lab only).
- Deliverables:
  - [x] code; `tests/test_disco_workers.py` (each state once, termination, budget stop,
    failure propagation, unique action ids, the bound, the CLI check; the termination
    test fails on a mutant that exits while a worker still holds a state);
    `tests/test_disco_e2e.py::test_two_workers_reach_the_same_surface_without_repeating_a_step`
    (real browsers) — done
  - [x] FR-CRAWL-19, CHANGELOG — done
- Effectiveness: not measured on a lab in this change (the owner asked to stop
  re-measuring after each change); the two-worker fixture run reaches the same surface
  as one worker.

### CC-CRAWL-0035 — The explorer's action log carries the page URL and a form step's fields, for `auto` (2026-10-18)
- Change (`fuzzlab/disco/explore.py::_log_action`): each line gains `url` (the page URL
  after the action, `redact_url`) and, for a form step, `fields` (its controls' names
  and types, never values); `seq` is documented as the action id's number.
- Reason: `store_adapter.import_disco` (CC-AUD-0044) needs a hash route's query (only
  the browser sees it) and which fields a user could see.
- Impact: `actions.jsonl` gains two keys; nothing else reads it. FR-CRAWL-19 and
  FR-CRAWL-21 amended in place; ARCHITECTURE updated (the legacy spider's removal no
  longer waits on `auto`).
- Risk: low; the URL is redacted like every other stored URL.
- Deliverables:
  - [x] code, `tests/test_disco_e2e.py::test_the_run_directory_feeds_auto` — done
- Effectiveness: see CC-FUZZ-0090.

### CC-CRAWL-0034 — The disco explorer stops re-acting chrome, fills the right fields, satisfies script validators, and counts sent submissions (BUG-0502) (2026-10-18)
- Change (`fuzzlab/disco/explore.py`, `formfill.py`, `cli.py`):
  - Steps are keyed `(route, signature, occurrence, kind)`, not per state; a step on a
    signature seen on more than one route (chrome) is taken once per run
    (`chrome_skipped`).
  - The enumerator gives a form-less container no `action` (it was `location.href`,
    which put the route into signatures); `form_refusal` takes the page URL instead.
  - `enter_submits` / the `enter` step: a search box or a container without a submit
    control is filled and Enter pressed.
  - Perturbations once per form (route and field set), none through a search box's
    buttons.
  - `_FIELDS_JS` clears earlier `data-disco-field` marks first.
  - `_VALID_JS`: a value is kept when the blurred control passes `checkValidity()` and
    is not `aria-invalid="true"`; else the first browser-valid value is kept.
  - `formfill._numeric`: wider magnitudes for a number with no stated maximum;
    `_from_pattern`: `\d` / `\w` / `\s` inside a class, `*` once.
  - `ExploreReport.submissions_sent` (submit / Enter / perturbation steps whose
    distinctive filled values reached a request); `captcha_submissions` counts only
    those; the CLI prints both counts.
  - Fixture (`tests/_disco_app.py`): a toolbar on every route with an Enter-only search
    box beside a button; a script-only range validator (`aria-invalid` after blur, the
    button disabled until it holds); a `-?[\d]*` control.
- Reason: the owner's "close the explorer's gaps" (2026-10-18). Reading the Juice Shop
  run's action log against its capture showed the budget spent on the header and the
  submissions counter counting clicks; a probe of the forms left unsubmitted showed the
  script validator and the pattern defects (BUG-0502).
- Impact: `fuzzlab/disco` only. Fewer, different actions per run; the report gains
  `submissions_sent` and `chrome_skipped`; `explore.json` carries them. No store or
  contract change.
- Risk: medium-low. Per-route keys skip an element's re-action in an overlay state of
  the same route (an overlay's own elements are still explored); a chrome signature is
  acted once even if it meant something else on another route. Both trade breadth on
  one route for routes reached. `aria-invalid` is WAI-ARIA, not a framework name.
- Corrects CC-CRAWL-0032's effectiveness figure (append-only, so here): its "75
  submissions" counted submit clicks, mostly on header buttons; the capture of that run
  holds 2 form POSTs (`/api/Complaints`). F-061.
- Deliverables:
  - [x] code, unit and e2e tests; the pushed explorer on the extended fixture: no
    POST, no PUT, no search (fixed: all reached) — done
  - [x] BUG-0502, PA-0502, ERROR_LOG, F-061, FR-CRAWL-19 amended, CHANGELOG — done
  - [x] `verify_change --base b2cfbd6` on fc91b02: 54 files, 2331 passed, 0 failed,
    1 skipped, 10 xfailed — done
- Effectiveness (assessed 2026-10-18, Juice Shop v20.3.0 reset via `lab/labctl.sh`, the
  lab identity, the same scorer as CC-CRAWL-0032):
  - Before (CC-CRAWL-0032): 60 states (budget hit), 206 actions, 2 form POSTs captured,
    24 endpoints, **reached 2/15**, 806 s.
  - After: 43 states (the frontier emptied, no budget hit), 167 actions (102 clicks,
    33 submits, 6 Enter, 26 perturbations), 127 chrome steps skipped, 0 unrestorable,
    14 routes, 43 endpoints; **reached 6/15** (+ `/profile/image/url` `imageUrl`,
    `/profile` `username` x2, `/api/Feedbacks` `comment`) in 766 s.
  - Counters reconciled with the capture (PA-0502(2)): `submissions` 39,
    `submissions_sent` 19; the capture holds 35 non-GET, non-socket requests, all from
    actions, over 11 endpoints (`/api/Feedbacks`, `/api/Cards`, `/rest/deluxe-membership`
    7 each, `/api/Complaints` 3, `/api/Addresss`, `/rest/chat`, `/profile`,
    `/profile/image/url` 2 each, `/profile/image/file`, two PUTs 1 each). The excess over
    19 is restore replays: a state behind a submit is reached by replaying it, which
    sends it again (a known cost, not changed here).
  - The legacy pipeline on Juice Shop (CC-CRAWL-0032): reached 7/15. Not reached by disco
    yet: the login form and registration (an authenticated run), `/file-upload`, the two
    DOM points (`#/search?q`, `#/track-result?id`: the capture holds no fragment), and
    routes the side-nav did not open within 43 states (46 route-capped).

### CC-CRAWL-0033 — CAPTCHA forms are submitted with a filler answer in both discovery tools (D71) (2026-10-18)
- Change:
  - `fuzzlab/disco/explore.py`: `form_refusal` no longer refuses a CAPTCHA form;
    `has_captcha(fields)` recognises one for the report only (`captcha_submissions`,
    printed by `disco capture`).
  - `fuzzlab/tools/spider.py`: both SPA submission paths (`_submit_spa_forms`,
    `_submit_revealed`) drop `spa.captcha_reason` from the gate; `_note_captcha` counts
    (`captcha_forms`, in the crawl summary) and logs it. `spa.captcha_reason` is now a
    recogniser, its name kept for its callers.
  - Tests: the G1 fixture's CAPTCHA view sends its answer; it is now asserted submitted
    once with a filler answer (`test_g1_a_captcha_form_is_submitted_with_a_filler_answer`);
    the Juice Shop feedback route (POST /api/Feedbacks) becomes a stated residual (row
    creation, low); a disco unit test pins the new rule beside the credential refusal.
- Reason: the owner's decision D71 ("Submit with a filler"), asked after the Juice Shop
  measurement (CC-CRAWL-0032), where the explorer refused 7 CAPTCHA submissions and the
  legacy crawler never captured the contact form's request.
- Impact: both discovery tools; more requests captured (a CAPTCHA-gated endpoint and its
  schema). The server still rejects the filler answer, so the request's effect is at
  most a failed validation. FR-CRAWL-13/15 (G1e), FR-CRAWL-19 and the NFR-CRAWL-safe
  clauses amended in place. No store, contract or interface change (one new counter
  each).
- Risk: low. Every other gate is unchanged (destructive labels, credential change,
  password forms, sensitive controls, the named-route rule, the write window); the
  filler is the same one every other control gets (`store_adapter.is_filler`).
- Deliverables:
  - [x] code, tests — done
  - [x] D71, FR-CRAWL-13/15/19 and NFR-CRAWL-safe amended, CHANGELOG — done
  - [x] `verify_change --base 349ce9e` on 3f795b3: 73 files, 3001 passed, 0 failed,
    5 skipped, 18 xfailed — done
- Effectiveness (assessed 2026-10-18 with CC-CRAWL-0034's explorer on Juice Shop): the
  contact form's `POST /api/Feedbacks` was captured with its CAPTCHA control's filler
  answer (`captcha_submissions` 1), and the `/api/Feedbacks` `comment` point is reached.
  The legacy crawler was not re-run for this change.

### CC-CRAWL-0032 — The disco explorer and synthesizer survive a real SPA (BUG-0501) (2026-10-18)
- Change (`fuzzlab/disco/explore.py`, `fingerprint.py`, `synth.py`):
  - `State.core` / `Explorer.reproduces`: a restore succeeds on the same fingerprint, or
    the same route with every stable element present; a restore with elements only gone
    narrows the core (one-time and dismissed UI; `transient_dropped`).
  - `Explorer.restore` leaves for `about:blank` first (a fresh document on a hash-routed
    app) and skips a replay step whose element is gone.
  - `fingerprint.stable_classes`: UI-state classes (BEM modifiers, state-word parts) out
    of signatures.
  - Form-like containers (the nearest ancestor holding typed inputs) define submitters
    and fields; a disabled button there is a submitter.
  - `Frontier`: new routes first, at most `max_states_per_route` (8) states per route
    (`route_capped`).
  - `synth.template_paths(paths, data_values)`: a slug needs every value seen as data,
    never the first segment.
  - `tests/_disco_app.py` gains a one-time overlay, a dismissible notice, a hash router
    and state classes; the e2e test asserts 0 unrestorable states.
- Impact: `fuzzlab/disco` only (no other caller of these functions); the inventory's
  templates change (fewer false merges). No contract or store change.
- Risk: low. The rules are framework-neutral (no app's names or routes); the state-word
  list deliberately excludes ambiguous words (`in`, `out`, `error`).
- Deliverables:
  - [x] code, tests (fixture shapes; signature, slug and frontier tests) — done
  - [x] BUG-0501, PA-0501, ERROR_LOG, F-060, FR-CRAWL-19/20 amended in place, CHANGELOG
    — done
  - [x] the pushed explorer shown to fail on the extended fixture (1 state, 0 actions,
    1 unrestorable, the POST never reached) — done
- Effectiveness (assessed 2026-10-18, Juice Shop v20.3.0 via `lab/labctl.sh`, the lab
  identity, scored by `funnel_report.py`'s "reached" rule; the explorer's inventory scored
  by the same rule in a scratch scorer):
  - Before (CC-CRAWL-0031): 1 state, 0 actions, 0 submissions.
  - After: 60 states (budget), 206 actions, 75 submissions, 80 perturbations, 9 routes,
    0 unrestorable, 24 endpoints; **reached 2/15** (`/redirect` `to`,
    `/rest/products/search` `q`) in 806 s.
  - The legacy pipeline on the same build, reset lab, the handoff's generic command line:
    crawl 1995 s + auto 315 s; **reached 7/15, confirmed 5/15** (333 requests).
  - Gaps left (general, not fixed here): framework-only validation keeps submit buttons
    disabled while `checkValidity()` passes; forms submitted by Enter (no button); the
    state budget runs out before most routes (29 states route-capped); CAPTCHA forms are
    refused (an open owner decision); `auto` cannot read a disco inventory, so the new
    tool has no candidate or confirmed stage yet.
  - `verify_change --base 8b1f361` on 0b0ba90: 54 files, 2326 passed, 0 failed,
    1 skipped, 10 xfailed.

### CC-CRAWL-0031 — Behavioural black-box discovery: capture proxy, state-graph explorer, schema synthesizer; the legacy spider deprecated (D70) (2026-10-17)
- Change:
  - **`fuzzlab/disco/` (new):** the owner's instruction (D70) to replace static crawling
    with protocol-level discovery, independent of the stack inside the container.
    - `capture.py` -- the `capture.jsonl` record: one producer (`make_record`, redacted
      at the write through `core.redaction`), one reader (`read_capture`, typed,
      quarantining). SP-35.
    - `recorder.py` -- the mitmproxy addon: the scope firewall (requests and CONNECT
      tunnels), the action tag read and stripped, records queued to one writer thread.
    - `mitm.py` / `proxyproc.py` -- mitmdump in this interpreter, on a free loopback
      port through `procutil`, checked loopback-only after boot; one capture per run.
    - `fingerprint.py` / `formfill.py` / `explore.py` -- the interaction engine:
      layout-fingerprint states, BFS with replayable paths, DevTools listener
      discovery, valid-first forms judged by the browser's `checkValidity()`, one
      perturbation per control, network quiescence, logout recovery, safety rails.
    - `synth.py` -- the OpenAPI 3.1 inventory: path templating, merged schemas,
      header classes, auth, response-only fields, dependency edges, JS candidates.
    - `cli.py` -- `fuzzlab disco capture|synth|generate|run` (generate is CC-MUT-0402,
      run CC-FUZZ-0089).
  - **`tools/navguard.py` (SP-03/SP-04 owners):** `browser_launch_args(..., proxy=)`
    and `chromium_launch_kwargs(..., proxy=)`: a loopback `host:port` recorder replaces
    `--no-proxy-server`, is added to the resolver rules, loopback is not bypassed; a
    non-loopback or malformed proxy, or args built for another proxy, are refused.
    Default (`proxy=None`) output is unchanged.
  - **`tools/spider.py`:** a deprecation docstring only; `fuzzlab crawl` prints a
    deprecation note (FR-CRAWL-21). Nothing else changes.
  - **`cli.py` / `cli_taxonomy.py`:** the `disco` command, its classified flags.
  - **Measured before design (CLAUDE.md rule 8), real mitmdump + Chromium:**
    - the Playwright driver's routed fetches (navguard's guard) honour the launch-level
      proxy and carry the route's headers;
    - without the proxy's own `host:port` in the resolver rules Chromium fails with
      `ERR_PROXY_CONNECTION_FAILED`;
    - the driver CONNECT-tunnels plain-`http` origins, so a tunnel is judged by
      `host:port` under either scheme (the first recorder killed every guarded request);
    - the explorer, on a client-rendered fixture, reaches listener-only navigation, a
      validated form's POST, a UUID-keyed PUT and a dialog-only webhook, and never the
      destructive controls or the out-of-scope image.
    - quiescence is measured from the action, not the last request: with a 120 ms
      click-to-fetch debounce, settling on "nothing in flight for 500 ms since the last
      request" read each state before its render and lost the dialog's subtree (3/3
      runs: 2 states, the POST never reached); counting the click and each navigation
      as activity (`Explorer.mark_activity`) reaches it 3/3. The fixture keeps the
      debounce; the e2e file then passed 5 consecutive runs. Listener hits are taken in
      document order (CDP lists properties in no stated order).
    - a page that navigates away while it is read ("execution context destroyed") is
      waited out once (`settled_fingerprint`), never the end of the exploration.
- Impact (other components / project):
  - Consumers of the SP-03/SP-04 owners, found from the code: `tools/spider.py`,
    `tools/fetcher.py` (AUD), `tools/browserexec.py` (FUZZ, M6),
    `session/browserlogin.py` (SESS) call them without `proxy`, so their launches are
    byte-for-byte unchanged (`test_launch_args_disable_the_proxy_and_resolve_only_scope_origins`
    still holds); `disco/explore.py` is the fifth launch site.
  - No store table, schema or existing CLI flag changes; `fuzzlab auto` still reads the
    spider DB. The inventory feeds Phase 2 (MUT) and the contract runner (FUZZ).
  - New optional dependency extra `disco` (mitmproxy, playwright, anthropic).
  - The web launcher does not list `disco` yet (a stated follow-up for UI).
- Risk: medium (a new traffic-sending path). Mitigated:
  - three scope layers, each tested on its own (proxy, route, launch arguments), the
    proxy one also with a plain HTTP client and no browser;
  - every launch and navigation through the navguard owners (AST guards);
  - redaction at the write with planted secrets; `--authorized` before any side effect;
  - the legacy pipeline left intact, so the measured `auto` path keeps working.
  - Not measured: the owner's metric (held-out lab recall). The held-out labs lived in
    the previous session's container; this change is measured on a fixture only.
- Deliverables:
  - [x] code (`fuzzlab/disco/*`, `tools/navguard.py`, `cli.py`, `cli_taxonomy.py`,
    `tools/spider.py` docstring, `pyproject.toml` extra) — done
  - [x] tests (`test_disco_capture.py`, `test_disco_synth.py`, `test_disco_e2e.py` real
    browser + proxy, `test_disco_isolation.py` AST guards with synthetic offenders,
    `test_disco_cli.py`, `test_browser_scope.py` proxy cases and the fifth launch
    site, `test_cli_taxonomy.py` subcommand parsers derived) — done
  - [x] FR-CRAWL-18..21, NFR-CRAWL-safe clause and data contracts edited in place;
    SHARED_PRIMITIVES (SP-03, SP-04 amended; SP-35, SP-36 new); ARCHITECTURE;
    DECISIONS (D70); CHANGELOG — done
  - [ ] the owner's held-out measurement with `disco` — todo (needs the labs)
  - [ ] the web launcher entry and `OPTION_CLASS` paths — todo (UI follow-up)
- Effectiveness (assessed 2026-10-17): Phase 1 does what it was built for on the
  fixture (the measurements above; `tests/test_disco_e2e.py` 6 passed, five
  consecutive runs). Verification record:
  - `scripts/verify_change.py --base e66685a` on e27fb40: 80 files, 3128 passed,
    1 failed, 9 skipped, 18 xfailed. The failure was the PA-0300 registry guard
    (`test_base_url_subpath_registry.py::test_every_base_url_function_is_registered`):
    `Explorer.__init__(start_url)` and `build_contract(base_url)` had no sub-path test.
    Both now have one (an app under `/shop/`), registered.
  - Re-run on 7c4931d (`--base e66685a`, the whole change): 80 files, 3131 passed,
    0 failed, 9 skipped, 18 xfailed.
  - Not assessed: the owner's held-out metric (the labs are not in this container).

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

### CC-CRAWL-0400 — Note: NFR-CRAWL-dry-run's exact-argv promise is not yet enforced (BUG-0400; documentation only) (2026-10-15)
- Change: NFR-CRAWL-dry-run gains a "Not yet enforced" line. The shared dry-run display
  (`web/runner.build_flags`) prints `--submit-spa-forms` lists as a Python repr and drops
  a bare `--follow-selector-forms` (BUG-0400, open, the UI lane's fix). Pinned by strict
  xfails in `tests/test_cli_argv_roundtrip.py`.
- Impact (other components / project): none; no code changed.
- Risk (level; mitigation or accepted-risk justification): none.
- Deliverables:
  - [x] NFR line — done
- Effectiveness (assessed 2026-10-15): n/a (documentation).

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
