# core/ Shared Library — Change Control Log

Component code: **CORE**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CORE-0021 — Map `open_redirect` to the existing `open-redirect` category in `_VULN_TO_CATEGORY` (FR-CORE-11) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"open_redirect": "open-redirect"`. Mirrors `CC-CORE-0020`'s own `ssti` precedent exactly: a real rule (`R-OPEN-REDIRECT`, `fuzzlab/audit/rules_data/default_rules.json`, `name_regex: "url|next|redirect|return|dest|goto|continue|target"` — matches Booking.com's real `return_to` param via its `return` alternative) and a real confirmation strategy (`OpenRedirectStrategy`, `fuzzlab/oracle/strategies.py`) already existed and were already correctly scoped for category 5's real cell (`LABGEN-BC-0001`, `CC-LAB-0210`) — purely a missing mapping, not a missing detector.

  **Two real, distinct code defects were found and fixed during this entry's own live-verification step** (per its own newly-added `PA-0042`, run before landing rather than trusting `confirm()`'s return value alone):
  1. **`BUG-0039`**: `RequestsProbeSender.send()` never set `allow_redirects=False` (unlike `fuzzlab.core.http`'s own authenticated client, which already does), so a real confirmation attempt against Booking.com's real vulnerable twin raised an uncaught `requests.exceptions.ProxyError` instead of returning a `Verdict` — `requests` tried to follow the strategy's own canary redirect target into an attacker-controlled/unreachable host. Fixed additively (`allow_redirects=False` added to that one sender, matching the other). No prior category's ground truth included a redirect-based sink, so no real confirmation run had ever reached this code path before.
  2. **`BUG-0040`**: after fixing `BUG-0039`, the confirmed finding still scored as a false positive (`tp=0, fp=1`), not a hit — `OpenRedirectStrategy.vuln_class` was `"open-redirect"` (hyphenated, matching this strategy's own `category` attribute) while every ground-truth case for this class (this project's `labels.schema.json` enum, every `open_redirect` manifest's `class:` field, `lab/safety_matrix.yaml`'s own `open_redirect` concern) uses `"open_redirect"` (underscored) — `fuzzlab.harness.scoring.score()`'s exact-key match never linked the two. Every sibling strategy (`SqliErrorStrategy`, `ReflectedXssStrategy`, `SstiStrategy`, etc.) already gets this right; `OpenRedirectStrategy` was an isolated inconsistency, latent since it was first authored (no `open_redirect` ground truth existed anywhere in this project to catch it until category 5's own work). Fixed: `vuln_class` corrected to `"open_redirect"`; `category` left unchanged (a separate, correctly-hyphenated namespace every strategy already uses consistently).

  Re-verified live, end to end, after both fixes: `fuzzlab.harness.multitarget.run_targets` against a real, locally-booted Booking.com deployment now scores `tp=1, fn=2, fp=0` for the real vulnerable twin (`LABGEN-BC-0001`) — a real, correctly-attributed true positive, not a relabeled false negative.

  Scoped to `open_redirect` only, not category 5's other three built classes (`csv_formula_injection`/`price_integrity_bypass`/`spel_injection`): none has a verified confirmer yet (no `ConfirmationStrategy`/`Rule` pair exists for CSV-formula-injection, business-logic price trust, or SpEL-evaluation-context detection) — mapping them now would only relabel an honest false negative as a mis-wired one, not a real improvement, matching `CC-CORE-0020`'s own established scoping discipline.

  Updates category 5's own Phase E tests (`CC-LAB-0217`/`0219`) to the new, real scored numbers (Booking.com recall `0 -> 1/3`; the combined test's per-target assertions, not a shared loop, per `CC-CORE-0020`'s own adequacy-review-caught precedent for that exact pitfall).
- Impact (other components / project): `fuzzlab/tools/probesender.py` (`BUG-0039`'s fix — affects every confirmation strategy and every Phase E `multitarget.py` test across every category, additively; no existing passing test's expectations changed except `test_probesender.py`'s own fake, updated to assert the new setting), `fuzzlab/oracle/strategies.py` (`BUG-0040`'s fix, `OpenRedirectStrategy.vuln_class` only — no other strategy touched), `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py` (LAB component, updated scored-number assertions). Both bug fixes are corrective, not new capability — component FUZZ (07) owns `fuzzlab/oracle/` and `fuzzlab/tools/probesender.py`; see that component's own change-control log for its own entry cross-referencing these same two bugs.
- Risk (level; mitigation or accepted-risk justification): low for the mapping itself (one dict entry, scoped and precedented). The `RequestsProbeSender` fix (`BUG-0039`) is the widest-blast-radius change in this entry — touches every existing caller of that sender — but is strictly *safer* than the prior behavior (was: crash or silently-wrong redirect-following; now: matches the already-correct authenticated client's own behavior) and the full whole-repo suite (see Effectiveness) confirms zero regressions across every other category's own Phase E tests.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py`: `_VULN_TO_CATEGORY["open_redirect"]` — done
  - [x] `fuzzlab/tools/probesender.py`: `BUG-0039` fix — done
  - [x] `fuzzlab/oracle/strategies.py`: `BUG-0040` fix — done
  - [x] `tests/test_probesender.py`: updated fake + new assertion — done
  - [x] `tests/test_labgen_php_laravel_booking_multitarget.py`/`test_multitarget_category5_combined.py`: real scored-number updates — done
  - [x] `docs/bugs/BUG-0039-*.md`/`BUG-0040-*.md`, `ERROR_LOG.md`, `docs/PREVENTIVE_ACTIONS.md` (`PA-0041`/`PA-0042`) — done
  - [x] `docs/components/01-target-lab/requirements.md`/`docs/components/02-core-library/requirements.md`/`docs/components/07-fuzzing-harness-and-oracle/requirements.md`: `FR-CORE-11`, cross-referenced from LAB's own Phase E entries — done
  - [x] `CHANGELOG.md` line — done
- Effectiveness (assessed 2026-09-23): Met, with evidence beyond a returned `Verdict`. Live-verified end to end through the real scoring pipeline before landing (`PA-0042`'s own new rule, applied to itself): real `tp=1, fn=2, fp=0` against Booking.com's real, locally-booted deployment. Full whole-repo `pytest tests/` run: see the commit message / `CHANGELOG.md` line for the exact pass/skip/fail counts.

### CC-CORE-0020 — Map `ssti` to the existing `server-side-template-injection` category in `_VULN_TO_CATEGORY` (FR-CORE-10) (2026-09-23)
- Change: Adds one entry to `fuzzlab/core/runmode.py`'s `_VULN_TO_CATEGORY` dict: `"ssti": "server-side-template-injection"`. This closes, for the `ssti` class specifically, a gap `CC-LAB-0138` (category 3, TrackerNest Phase E) flagged but did not fix: TrackerNest's real SSTI cell (`LABGEN-SSTI-0001`, OGNL evaluation of a raw query parameter) was scoring recall=0 purely because its ground-truth `vuln_class` (`"ssti"`) had no entry in this map, so `resolve_run`'s ground-truth-derived category set never included it and `evaluate()` never nominated a candidate for it — despite a real rule (`R-SSTI`, `fuzzlab/audit/rules_data/default_rules.json`, `category: server-side-template-injection`, `when: {location_in: [query, body]}`) and a real confirmation strategy (`SstiStrategy`, `fuzzlab/oracle/strategies.py`, already wired to that same category via `category_to_oracle_class`) already existing and already correctly scoped for this exact point shape (`macroExpr`, `location=query`).

  Scoped to `ssti` only, not all 6 of category 3's new classes: `xxe`/`insecure_deserialization`/`webhook_signature_bypass`/`ssrf`/`outbound_header_injection` have no confirmer built yet — mapping any of them now would only relabel an honest false negative as a mis-wired one (`evaluate()` would nominate a candidate `category_to_oracle_class()` returns `None` for, still never confirmed), not a real improvement, so they stay unmapped until each has its own verified confirmer (adequacy review's own finding, incorporated).

  `_VULN_TO_CATEGORY` is read only via `.get()` inside `to_category()`; nothing else iterates its keys or checks its size, so adding one key cannot affect any other, already-mapped class's behavior (checked directly, not assumed).

  Verified for real, not assumed: booted TrackerNest's real vulnerable SSTI cell live and sent `SstiStrategy`'s own existing payload set (`_ssti_payloads`, unmodified) directly against it — two of the five payloads (`{{a*b}}`, `#{a*b}`) genuinely evaluate under OGNL (`{{7*7}}` → `Rendered macro result: [[49]]`; OGNL's own list/map-literal syntax happens to nest the arithmetic result inside brackets/a map, but the product substring still appears and the un-evaluated expression string does not, which is exactly `SstiStrategy.confirm()`'s own pass condition: `product in text and expr not in text`) — so the existing strategy confirms this real vulnerability with zero changes to its own payload set or confirm logic. Also booted the real secure twin (`LABGEN-SSTI-0002`) with the same payloads and confirmed it never returns anything containing the product (`"Unknown macro"` for all payloads tested), so this mapping introduces no false-positive risk for that twin. Also checked no other ground truth anywhere in this now-consolidated branch uses `vuln_class: "ssti"` (only `lab/ground-truth-trackernest/labels.json` does, across all 10 `lab/ground-truth*/` directories currently on this branch), so this mapping's behavior change is scoped to exactly the one case it's meant to fix.

  Updates two of `CC-LAB-0138`'s/`CC-LAB-0140`'s own Phase E tests. `tests/test_labgen_spring_boot_trackernest_multitarget.py`: `tp==0`/`recall==0.0` → `tp==1`/`fp==0`/`fn==2`/`precision==1.0`/`recall≈1/3`, docstring corrected. `tests/test_multitarget_category3_combined.py`: the adequacy review caught a real gap in the first draft here — its single shared `for outcome in outcomes: assert tp==0` loop checked both targets identically, but only TrackerNest's outcome changes (Huddle Hub's own three classes remain entirely unmapped); restructured into per-target assertions (`trackernest_outcome.tp==1`/`recall≈1/3`, `huddlehub_outcome.tp==0`/`recall==0.0`), and the module's own docstring/inline comment corrected to state this precisely rather than the blanket "every class unmapped" framing the first draft would have left stale.
- Impact: Component 2 (CORE) primary; Component 1 (LAB)'s own two Phase E tests updated as a direct consequence (documented above, not a silent side effect). No change to `fuzzlab/oracle/strategies.py`/`fuzzlab/audit/rules_data/default_rules.json` (both already correctly built for this category; this entry only connects a third mapping this project's own docs already named as the missing piece).
- Risk: Low. One additive dict entry; verified against real running code (both twins) before landing, not just unit-level reasoning.
- Deliverables:
  - [x] `fuzzlab/core/runmode.py` `_VULN_TO_CATEGORY["ssti"]` entry — done
  - [x] `tests/test_runmode.py`: `test_categories_from_vuln_classes_maps_ssti` + `test_categories_from_vuln_classes_leaves_unmapped_classes_unchanged` — done, both passing
  - [x] `tests/test_labgen_spring_boot_trackernest_multitarget.py`/`tests/test_multitarget_category3_combined.py` assertions + docstrings updated — done, re-run and passing (real `mvn package`/`java -jar` + real `composer install`/`artisan serve` boots)
  - [x] `docs/components/02-core-library/requirements.md` FR-CORE-10 entry — done
  - [x] `CHANGELOG.md` line — done
- Effectiveness (assessed 2026-09-23): Met. `tests/test_runmode.py`'s 2 new unit tests pass. All 3 of `CC-LAB-0138`'s/`CC-LAB-0139`'s/`CC-LAB-0140`'s own Phase E tests re-run for real after this change: TrackerNest's own test now shows `tp=1`, `fn=2`, `precision=1.0`, `recall=1/3` (was `tp=0`/`recall=0.0`); the combined test correctly shows TrackerNest at `tp=1`/`recall≈1/3` and Huddle Hub still at `tp=0`/`recall=0.0`, with `generalizes` still correctly `False` (needs both scored targets above zero recall, not just one); Huddle Hub's own individual test unaffected (re-run, unchanged, still passing). Full non-slow suite re-run post-merge (this branch is now consolidated with categories 1/2/4/5's own work): 1838 passed, 52 skipped, 18 failed — every failure the same pre-existing `gitleaks`-binary/`scikit-learn`-dependency environment gap present before this change (more instances than category 3's own earlier baseline of 15, because the merged tree now has more manifests hitting the same missing-dependency gate — verified: identical failure shape, `2 gate(s) FAILED: secret scanner ... / metadata leakage gate ...`), zero regressions attributable to this entry.
- Pre-change review gate: drafted, reviewed by 2 independent agents (accuracy: all 6 specific factual claims checked — including an independent re-run of the exact live-boot reproduction against both real twins — found ACCURATE, no inaccuracies; adequacy: 6 findings — an undercounted test-update scope in `test_multitarget_category3_combined.py` (the real gap above, now fixed), a missing one-sentence statement of the dict-mutation-safety reasoning, a missing one-sentence statement of why only `ssti` and not the other 5 classes, a missing `Effectiveness: pending` placeholder line, an under-specified "unit coverage" deliverable (now named exactly), and a missing deliverables-checklist line for the docstring/comment corrections — all incorporated). 3/3 agreement reached by incorporating every concrete finding from both reviews without contesting any of them; implementation proceeds on this revised entry, matching this component's own gate discipline in full (unlike `CC-LAB-0138`-`0140`'s own acknowledged after-the-fact deviation).

### CC-CORE-0019 — Migration 12: `saved_views` table (U2-table, Findings workbench) (2026-09-22)
- Change: migration 12 (append-only registry; head → 12) adds
  `saved_views(id, table_key, name, spec_json, is_pinned, created_at,
  updated_at)` — a durable, server-side store for named filter/sort/column
  specs a person saves in a faceted workbench (the Findings workbench,
  `CC-UI-0029`, is the first caller; `table_key` names the logical dataset the
  view is over, e.g. `"finding"`, so other workbenches can reuse the same
  table later rather than inventing their own). `spec_json` is opaque to the
  store — it is only ever read/written as JSON by `fuzzlab.web.savedviews`,
  never queried by field. One index, `idx_saved_views_table(table_key)`, for
  the one read pattern (`GET /api/views?table=`). Additive; no existing
  table/column changed. **Note on bookkeeping numbering:** this CC-CORE number
  was not in lane U2's pre-assigned block (`docs/PARALLEL_LANE_BUILD_PLAN.md`
  reserved only `CC-UI-0029` for U2) — the lane's own scope statement
  (`fuzzlab/web/app.py` read route(s) plus the shared UI files) did not
  foresee needing a new store table. `CC-CORE-0019` was computed as "highest
  existing + 1" at the time this entry was written (mirroring how `B0`'s
  `metric_series` migration got both a `CC-CORE-0018` and a `CC-UI` entry);
  per PA-0031, an integrator merging this lane alongside others touching
  `02-core-library/change-control.md` should re-verify no other lane claimed
  `CC-CORE-0019` in the meantime before merging, rather than assuming this
  number is uncontested.
- Impact (other components / project): additive only. UI-owned data (view
  definitions a person authored in the panel), not a `finding`/`attempt`/
  `candidate`/flow result table, so it does not touch `NFR-UI-read-only`
  ("the UI writes no result tables") — see `CC-UI-0029`'s own impact note for
  why this is the one deliberate write path that requirement still allows.
  No other component reads or writes this table.
- Risk (level; mitigation): low — one additive table + one index, written only
  through `fuzzlab.web.savedviews`'s four functions (`list_views`/`get_view`/
  `create_view`/`update_view`/`delete_view`), each parameterized (no string-built
  SQL). Mitigated by `tests/test_web_findings.py`'s saved-view round-trip tests
  (direct store functions and the `/api/views` HTTP surface) and the existing
  `tests/test_core_foundations.py::test_migrations_are_idempotent` pattern
  (re-run here implicitly via every other store-backed web test creating a
  fresh store on migration 12).
- Deliverables:
  - [x] Migration 12 added to the append-only `MIGRATIONS` registry — done.
  - [x] `fuzzlab.web.savedviews` CRUD module — done.
  - [x] Round-trip tests (store-level + HTTP) — done.
- Effectiveness (assessed 2026-09-22): effective — saved views persist across
  store reopens and are visible to any reader of the same store file, unlike
  the `localStorage`-only alternative R-03 explicitly rejected for this data.

### CC-CORE-0018 — Migration 11: `metric_series` table + `open_store()`/`log_scalar`/`MetricLogger` (B0-table, Phase 4b) (2026-09-22)
- Change: migration 11 (append-only registry; head → 11) adds `metric_series(id, run_id,
  source, key, step, ts, value)`, the generic cross-run scalar-series sink for per-step
  emitters (GBT/logistic training curves, bandit posterior/regret, coverage-frontier
  growth, `MutationSearch` reward/novelty, stage wall-clock/throughput — those emitters
  themselves are separate lanes, not part of this change). `run_id INTEGER REFERENCES
  run(id)` (the store's actual runs table is `run`, singular — matches every other
  migration; R-05's "`runs(id)`" phrasing was generic, not a literal table name);
  `value REAL NOT NULL`; two indexes for the two read patterns: `idx_metric_series_run
  (run_id, source, key, step)` (one series within a run) and
  `idx_metric_series_overlay (source, key, run_id, step)` (cross-run overlay). Also:
  added `fuzzlab.core.store.open_store()`, the central WAL-configured connection
  constructor R-08 calls for (`journal_mode=WAL`, `busy_timeout=10000`,
  `synchronous=NORMAL`, `foreign_keys=ON`, connect-time `timeout=10.0`); `connect()` is
  now a thin backward-compatible alias for it (previously `connect()` set
  `busy_timeout=5000` with no connect-time `timeout=` — now centralized and raised to
  match R-08's resolved design). Added `log_scalar(store, run_id, source, key, step,
  value, ts=None)` (accepts a `Store` or a raw connection from `open_store()`) and
  `MetricLogger(store, run_id, source, flush_every=200)`, a buffered context-manager
  writer that batches an `executemany` every `flush_every` rows and flushes on
  `__exit__`/exception. Both reject non-finite (`NaN`/`inf`) values — dropped with a
  `UserWarning`, never written — per R-05 (no `is_nan` column, no NaN read-branch).
- Impact (other components / project): additive only; no existing table, column, or
  pragma value that any current caller depended on changed in a breaking way (raising
  `busy_timeout` 5000→10000 and adding connect `timeout=10.0` only widens the lock-wait
  window). This is the **table-only** slice of the B0 lane — the GBT/logistic,
  bandit-loop, coverage-frontier, and `MutationSearch` emitters that will write through
  `log_scalar`/`MetricLogger` are separate, later lanes (reserved `CC-ML-0009`,
  `CC-SCHED-0005`, `CC-FUZZ-0021`, `CC-MUT-0011` per
  `docs/PARALLEL_LANE_BUILD_PLAN.md`), not built here. The diagnostics UI (U5) reads this
  table once it lands.
- Risk (level; mitigation): low — one additive table + two indexes + a new always-central
  connection constructor that the existing `connect()` now simply delegates to. Mitigated
  by `tests/test_core_foundations.py::test_migrations_are_idempotent` (now also asserts
  `metric_series` exists), `test_open_store_is_wal_smoke` (R-08's required WAL smoke
  test), `test_metric_series_schema_and_indexes`, `test_log_scalar_roundtrip`,
  `test_log_scalar_accepts_raw_connection`, `test_log_scalar_rejects_non_finite`
  (parametrized NaN/+inf/-inf), `test_metric_logger_flushes_every_n`, and
  `test_metric_logger_drops_non_finite_and_flushes_on_exception`. Full suite (excluding
  pre-existing, unrelated collection failures in this environment from a missing
  `covertable` package and an unavailable `starlette.testclient` — both present before
  this change, confirmed via `git stash`): 486 passed / 2 skipped / 2 pre-existing
  failures unrelated to this change (`test_web_commandspec.py`, same `covertable`-driven
  registration gap, reproduced identically on the pre-change tree).
- Deliverables:
  - [x] Migration 11 (`metric_series` table + both indexes) — done.
  - [x] Central `open_store()` (WAL/busy_timeout/synchronous/foreign_keys/timeout),
    `connect()` kept as an alias — done.
  - [x] `log_scalar()` + `MetricLogger` (buffered, `flush_every=200` default,
    non-finite rejection) — done.
  - [x] R-08 WAL smoke test — done.
  - [ ] Per-component emitters (GBT/logistic, bandit-loop, coverage-frontier,
    `MutationSearch`) — explicitly out of scope for this lane; separate dispatches.
- Effectiveness (assessed 2026-09-22): effective — migration is additive/reversible-safe
  (no data touched, no column type changed), the full suite is unaffected, and the write
  path (`log_scalar`/`MetricLogger`) is ready for the emitter lanes to adopt.

### CC-CORE-0017 — Credentials keyed by bare hostname (BUG-0007) (2026-09-21)
- Change: `CredentialStore` now normalizes the host to its bare hostname
  (`_norm_host`: strips scheme/port) on `set`/`get`/`require`/`delete`, so credentials
  saved as `127.0.0.1`, `127.0.0.1:8080`, or `http://127.0.0.1:8080/` all resolve to the
  same key — matching how the session layer looks them up (`urlparse(url).hostname`). The
  `require` error message now prints the exact `set-credential` command with the
  normalized host.
- Impact (other components / project): fixes the on-host `CredentialError` where
  `set-credential --host 127.0.0.1:8080` stored a key the crawler's hostname lookup
  (`127.0.0.1`) missed (BUG-0007). No API change; existing hostname-only usage is
  unaffected (normalization is a no-op there).
- Risk (level; mitigation): low — normalization at the store boundary; the session layer
  and `HttpClient` scope already use `hostname`. Mitigated by
  `tests/test_credentials.py::test_host_is_keyed_by_hostname_regardless_of_port_or_scheme`.
  Suite 392 passed / 4 skipped.
- Deliverables:
  - [x] `_norm_host` normalization + actionable `require` message — done.
- Effectiveness (assessed 2026-09-21): effective — save-with-port / look-up-by-hostname
  now agree; the runbook was corrected to `--host 127.0.0.1`.

### CC-CORE-0016 — Migration 10: active-plugin recording (Phase 10 T10.1) (2026-09-21)
- Change: migration 10 adds the `run_plugin` table (append-only registry; head → 10):
  one row per active plugin per run (`run_id, name, version, priority`), so a run records
  exactly which plugins/versions produced its results (NFR-PLUG-reproducible).
- Impact (other components / project): the PLUG component's `PluginManager.record()`
  writes here; the reproducibility report (T10.4) reads it. Additive; a zero-plugin run
  writes no rows. Version-pinning tests derive the head from `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — one additive table + index. Mitigated by
  `tests/test_plugins.py::test_migration_10_adds_run_plugin` and `test_record_writes_active_plugins`.
  Suite 360 passed / 4 skipped.
- Deliverables:
  - [x] Migration 10 (`run_plugin`) — done.
- Effectiveness (assessed 2026-09-21): effective — active plugins persist per run.

### CC-CORE-0015 — Migration 9: flow protocol tag (Phase 9 T9.1) (2026-09-21)
- Change: migration 9 adds a `protocol` column to `flow` (append-only registry; head → 9)
  so history distinguishes `http/1.1` / `h2` / `ws` flows. Additive; existing rows read as
  NULL and the proxy's `HistoryWriter` defaults new rows to `http/1.1`.
- Impact (other components / project): lets the PROXY component record WebSocket and (later)
  HTTP/2 flows alongside HTTP/1.1 without touching existing rows. Version-pinning tests
  derive the head from `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — one nullable column. Mitigated by
  `tests/test_proxy_ws.py::test_migration_9_adds_flow_protocol`. Suite 328 passed / 4 skipped.
- Deliverables:
  - [x] Migration 9 (`flow.protocol`) — done.
- Effectiveness (assessed 2026-09-21): effective — WebSocket flows persist with their
  protocol tag.

### CC-CORE-0014 — Migration 8: mutation-engine payload variants (Phase 8 T8.1) (2026-09-21)
- Change: migration 8 adds the `payload_variant` table (append-only registry; head → 8):
  the provenance of each accepted mutation — `base_payload`, `variant`, the `operators`
  chain (JSON), `sink_context`, `bypassed_rule`, the `semantics_ok` verdict, and any
  `coverage_gain`. Variants are still sent through the `attempt` path; this is for reuse
  and analysis (decision 3 of the Phase 8 plan).
- Impact (other components / project): gives the MUT component its write-back target
  (FR-MUT-6) without touching existing rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001).
- Risk (level; mitigation): low — additive table + index. Mitigated by
  `tests/test_mutation_operators.py::test_migration_8_adds_payload_variant`. Suite 289
  passed / 4 skipped.
- Deliverables:
  - [x] Migration 8 (`payload_variant`) — done.
- Effectiveness (assessed 2026-09-21): effective — the table is present for T8.5's
  variant write-back.

### CC-CORE-0013 — Migration 7: candidate ranker scores (Phase 7 T7.2) (2026-09-21)
- Change: migration 7 adds advisory `rank_score` and `rank_uncertainty` columns to
  `candidate` (append-only registry; head → 7), kept separate from the Phase-5
  `candidate.score` so the ranker and the detection classifier coexist.
- Impact (other components / project): gives the ML ranker (A.2) its store columns
  without touching existing rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes a number.
- Risk (level; mitigation): low — additive nullable columns. Mitigated by
  `tests/test_ml_ranker.py::test_migration_7_adds_rank_columns`. Suite 266 passed / 3 skipped.
- Deliverables:
  - [x] Migration 7 (`candidate.rank_score`, `candidate.rank_uncertainty`) — done.
- Effectiveness (assessed 2026-09-21): effective — the ranker writes advisory ranks into
  the new columns.

### CC-CORE-0012 — Migration 6: proxy flow history (Phase 6 T6.3) (2026-09-21)
- Change: migration 6 extends `flow` with `host`, `in_scope`, and byte-exact
  `req_raw_sha`/`resp_raw_sha` (raw wire bytes content-addressed via `body`), adds the
  `flow_fts` FTS5 index and a `repeater_tab` table (append-only registry; head → 6).
- Impact (other components / project): gives the PROXY component the store contract for
  FR-PROXY-3/FR-PROXY-4 (searchable history with raw bytes; persisted repeater tabs)
  without changing any existing table's rows. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes a number.
- Risk (level; mitigation): low — additive columns/tables with NULL defaults (ADD
  COLUMN … REFERENCES is valid because the default is NULL). Mitigated by
  `tests/test_proxy_history.py::test_migration_6_schema`. Suite 224 passed / 2 skipped.
- Deliverables:
  - [x] Migration 6 (`flow` raw bytes + FTS5 + `repeater_tab`) — done.
- Effectiveness (assessed 2026-09-21): effective — the proxy history writer round-trips
  byte-exact raw bytes and FTS search works over the new index.

### CC-CORE-0011 — Migration 5: bandit cost columns (Phase 4 T4.4) (2026-09-21)
- Change: migration 5 adds `cost_sum`/`cost_n` to `bandit_posteriors` (append-only
  registry; head → 5), so the bandit's per-(context, arm) mean cost persists next to the
  reward posterior for cost-normalized selection.
- Impact (other components / project): the SCHED bandit's `load`/`save` now round-trip
  cost; no other reads change. Version-pinning tests derive the head from
  `migrations.MIGRATIONS` (PA-0001), so nothing hardcodes 5.
- Risk (level; mitigation): low — additive columns with defaults. Suite 183 passed / 2 skipped.
- Deliverables:
  - [x] Migration 5 (`cost_sum`, `cost_n`) — done.
- Effectiveness (assessed 2026-09-21): effective — cost persists across runs
  (`tests/test_scheduler.py::test_cost_persists_across_stores`).

### CC-CORE-0010 — Headless credential backend on `cryptography` (BUG-0005) (2026-09-21)
- Change: reimplemented the D12 encrypted-file credential backend in
  `fuzzlab/core/credentials.py`. It was `keyrings.alt.file.EncryptedKeyring` (needs
  PyCrypto/pycryptodome, undeclared and absent → crash on first use). It is now
  `_CryptographyFileBackend`: a single AES-Fernet-encrypted JSON file, key derived
  from `FUZZLAB_KEYRING_PASSPHRASE` via PBKDF2-HMAC-SHA256 over a random per-file
  salt, `0600` perms, atomic write, loud failure on a wrong passphrase — built on
  `cryptography` (the intended lib, already present). Declared `cryptography>=42,<51`
  in `pyproject.toml`.
- Impact (other components / project): fixes BUG-0005, which blocked every headless
  authenticated run (`fuzzlab session set-credential` / `--identity`). The session
  manager (component 03) consumes the store unchanged; the injectable-backend seam and
  the OS-keyring/env-fallback paths are unchanged. File format is new (`FZLB1` magic);
  no prior headless store existed to migrate.
- Risk (level; mitigation): medium — credentials are high-impact. Mitigated by
  encryption at rest (Fernet/AES128-CBC+HMAC), `0600` perms, ciphertext-verified in a
  test, password-masked `repr`, and new real-backend tests (round-trip, persistence,
  wrong-passphrase) that exercise the actual `cryptography` path and skip only when the
  native lib is unavailable. Suite 126 passed / 2 skipped.
- Deliverables:
  - [x] `_CryptographyFileBackend` (Fernet+PBKDF2, atomic, 0600) — done.
  - [x] `cryptography` declared; `keyrings.alt` EncryptedKeyring dependency dropped — done.
  - [x] Real round-trip/wrong-passphrase tests (skippable) — done.
  - [ ] Confirmed on the host: `set-credential` + `session print` + `--identity` run — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests where `cryptography` works;
  to be confirmed on the Fedora host (where the crash was seen) after `pip install -e .`.

### CC-CORE-0009 — Grey-box consumer layer (offline scaffolding, Phase 3) (2026-09-21)
- Change: added `fuzzlab/greybox/` — the consumer side of Phase 3 grey-box
  instrumentation, built behind injected-source protocols so it is fully testable
  without a lab: `coverage.py` (`CoverageSource` + `InMemoryCoverageSource` fake,
  `app_lines` filter, `CoverageFrontier` novelty tracking, coverage encode/decode),
  `dbfault.py` (`DbFaultSource` + fake), `reward.py` (`GreyboxSignal` + `shaped_reward`
  multi-tier: screening / coverage-novelty / db_fault), `reset.py` (`LabControl`
  protocol + `FakeLabControl`), `confirm.py` (the pure M10 decision), and
  `recorder.py` (`record_attempt_signals` filling the reserved `attempt.coverage`
  /`attempt.db_fault`/`reward` columns). No schema change (columns were reserved in
  migration 1).
- Impact (other components / project): gives Phase 3 turnkey seams — the on-host work
  is reduced to backing the protocols with live pcov/DB-fault/reset sources
  (`docs/ON_HOST_TASKS.md`) and wiring M10 into the oracle/pipeline (FUZZ). The
  shaped reward is the input the Phase 4 bandit will consume. Safety unchanged
  (live readers bind loopback-only; grey-box corroborates, oracle stays sole
  finding-writer).
- Risk (level; mitigation): low — pure, dependency-light logic with no live I/O in
  this layer. Mitigated by 17 offline tests (app-line filtering, frontier novelty +
  saturation, reward ordering incl. the new-code-scores-higher exit property, M10 per
  class, recorder writing the reserved columns end-to-end). Full suite 125/125.
- Deliverables:
  - [x] `fuzzlab/greybox/` package (coverage/dbfault/reward/reset/confirm/recorder) — done.
  - [x] `tests/test_greybox.py` (17 tests) — done.
  - [ ] Live sources + M10 oracle/pipeline wiring + exit measurement — on-host (T3.1/3.5/3.6/3.7).
- Effectiveness (assessed 2026-09-21): effective offline — the reward math, frontier,
  filtering, M10 decision, and column persistence are verified with fakes; live
  confirmation pending the instrumented lab.

### CC-CORE-0008 — Single home for URL path-normalization (`urls.to_path`) (2026-09-21)
- Change: added `fuzzlab/core/urls.py::to_path(url)` — the one shared function that
  normalizes a result URL to path form (`/product.php`), the convention every
  stored, ground-truth-cross-referenced URL must follow. The oracle's finding
  writer and `tools/store_adapter` (which had a private `_path` duplicate) both now
  call it; the duplicate is removed.
- Impact (other components / project): fixes BUG-0003 (the oracle stored full URLs,
  so scored pipeline runs reported every true finding as a false alarm). Any future
  writer of a cross-referenced URL imports `to_path` rather than re-implementing the
  rule (PA-0003). No schema change; behavior change is that oracle findings are now
  stored in path form like every other URL.
- Risk (level; mitigation): low — a pure, well-tested normalization helper.
  Mitigated by the pipeline tests (scored TP/FP now correct) and the existing
  store-adapter/harness tests (unchanged, still green). Suite 108/108.
- Deliverables:
  - [x] `core/urls.py::to_path` with the convention documented in-module — done.
  - [x] Oracle + store_adapter call it; local duplicate removed — done.
  - [x] BUG-0003 investigation + PA-0003 recorded — done.
- Effectiveness (assessed 2026-09-21): effective — the previously-failing scored
  pipeline test passes and no writer stores a verbatim URL for cross-referencing.

### CC-CORE-0007 — Run-mode category resolver (D14/D15) (2026-09-21)
- Change: added `core/runmode.py` — the pure decision logic for category selection
  and the no-ground-truth fail-safe. `resolve_run(mode, ...)` returns a `RunPlan`
  (categories, scored, source): automatic + ground truth → auto-derived + scored
  (D14); automatic + no ground truth → explicit selection required or **fail loud**,
  unscored (D15); manual → user selection, defaulting to all known categories,
  unscored (D14). `categories_from_vuln_classes` normalizes ground-truth classes
  (e.g. `sqli`→`sql-injection`, `xss-*`→`xss`) to reference-style categories; unknown
  categories/modes fail loud. Dependency-light (callers pass the ground-truth and
  known categories in), so no layering inversion.
- Impact (other components / project): the launcher/harness and tools call this to
  scope the auditor rules (T2.3 `categories` filter), payload sources, and oracle
  strategies (T2.9), and to enforce the D15 fail-safe. No schema change.
- Risk (level; mitigation): low — pure function; the safety-relevant path (D15) is
  fail-closed (raises rather than guessing/blasting). 7 unit tests cover D14 lab
  auto-derive (scored), manual selection/default, D15 fail-loud + unscored, and
  unknown-category/mode errors.
- Deliverables:
  - [x] `runmode.py` resolver + normalization + 7 tests — done.
  - [ ] Wire into the launcher/harness (scope tools; scored vs unscored) — todo (with T2.8/UI).
- Effectiveness (assessed 2026-09-21): effective in unit tests — each D14/D15 branch
  resolves correctly and fails loud on unsafe/unknown input. Suite 105/105.

### CC-CORE-0006 — Migration 4: rule-evaluation logging (negatives) (2026-09-21)
- Change: added migration 4 (an `evaluation` table + indexes) recording every
  per-(injection point, rule) evaluation with its outcome (`fired` 0/1), so the
  store holds negatives, not just hits. Supports the auditor's T2.3 rules-as-data
  engine.
- Impact (other components / project): the auditor writes here; the ranker/ML
  (later) train on the negatives. Schema head is now version 4; additive.
- Risk (level; mitigation): low — additive table + indexes; idempotent migration
  runner + tests. (The version-pinning tests already derive the head from the
  registry per PA-0001/PA-0002, so migration 4 needed no test edits.)
- Deliverables:
  - [x] Migration 4 (`evaluation` table + indexes) — done.
- Effectiveness (assessed 2026-09-21): effective — fresh store reports version 4;
  the auditor engine writes fired + not-fired evaluations (98/98 tests green).

### CC-CORE-0005 — Migration 3 + session-state store methods (2026-09-21)
- Change: added migration 3 (a `session_state` table for **non-secret** session
  metadata — host, identity, kind, valid, login/logout URLs, token_exp) and Store
  methods `upsert_session_state`/`get_session_state`/`all_session_states`. Supports
  T1.7 persistence. Secrets (cookies/tokens/creds) are never stored — the table has
  no column for them.
- Impact (other components / project): the session manager (#3) persists non-secret
  state here; the diagnostics UI can later read it. Schema head is now version 3;
  additive migration, existing data untouched.
- Risk (level; mitigation): low — additive table + upsert. Mitigated by the
  idempotent migration runner and tests. Discovered BUG-0002 (a test still
  hardcoding the schema head `== 2`); fixed to derive from the registry and added
  PA-0002 (sweep for a bug class when adding its preventive action).
- Deliverables:
  - [x] Migration 3 (`session_state`) + Store methods — done.
  - [x] Fix BUG-0002 + PA-0002 — done.
- Effectiveness (assessed 2026-09-21): effective — fresh store reports version 3,
  session state round-trips, suite 71/71 green.

### CC-CORE-0004 — Per-host credential store implemented (2026-09-21)
- Change: implemented `fuzzlab/core/credentials.py` (T1.1, D12) — a
  `CredentialStore` keyed by `(host, identity)` over `keyring`, with backend
  resolution (OS Secret Service → encrypted-file via `keyrings.alt` at
  `FUZZLAB_KEYRING_PATH`/`FUZZLAB_KEYRING_PASSPHRASE` → gated lab-only env fallback
  `FUZZLAB_CRED_<HOST>_<IDENTITY>`). Backend is injectable; `Credential` masks its
  password in `repr`. Exported from `core`. Added `keyring`/`keyrings.alt` deps;
  dropped the planned PyJWT dep (JWT `exp` is read by base64url-decoding the
  payload — no crypto dependency).
- Impact (other components / project): the session manager (component #3) draws
  per-host credentials from here; no other component affected. Secrets never enter
  the project store or repo (config holds references only).
- Risk (level; mitigation): medium — mishandled credentials are high-impact.
  Mitigated by keyring-only storage, password-masked repr, redaction discipline,
  and the env fallback being default-off and lab-scope-gated. The real
  encrypted-file backend is environment-dependent (needs a working `cryptography`);
  the store's own logic is covered by tests with an injected in-memory backend.
- Deliverables:
  - [x] `CredentialStore` (set/get/require/delete), per-host keying — done.
  - [x] Backend resolution incl. encrypted-file + gated env fallback — done.
  - [x] 6 unit tests (per-host, env-fallback gating, repr masking) — done.
  - [ ] Live check of the encrypted-file backend on a host with `cryptography` — todo.
- Effectiveness (assessed 2026-09-21): effective — 6/6 tests green; credentials
  round-trip per host, env fallback honored only when enabled + in scope, password
  never appears in `repr`.

### CC-CORE-0003 — Migration 2: self-describing findings (2026-09-21)
- Change: added migration 2, which ALTERs `finding` to add `url`, `method`, and
  `param` columns so a confirmed finding carries its own location and the
  integration harness can score by `(url, method, param, vuln_class)` without a
  candidate/parameter join. Registered as a new, higher-numbered migration (the
  registry is append-only; migration 1 is untouched).
- Impact (other components / project): the store schema head is now version 2; the
  harness (T0.7) reads these columns. Additive only — existing rows/columns
  unchanged; a fresh store applies 1 then 2.
- Risk (level; mitigation): low — additive `ALTER TABLE ADD COLUMN`. Mitigated by
  the idempotent migration runner and tests; the two foundation tests that pinned
  version 1 were updated to assert the current head rather than a literal.
- Deliverables:
  - [x] Migration 2 (finding url/method/param) + registry entry — done.
  - [x] Update version-pinning tests to the head version — done.
- Effectiveness (assessed 2026-09-21): effective — a fresh store reports version 2,
  re-migration is a no-op, and the harness scores from finding rows (22/22 tests).

### CC-CORE-0002 — Phase 0 core library implemented (2026-09-21)
- Change: created the `fuzzlab` package with a `core/` subpackage and built the
  Phase 0 foundations — the project store (`store.py`) with WAL/foreign-key
  pragmas and content-addressed bodies; a numbered, forward-only, idempotent
  migration runner (`migrations.py`) creating the core tables from the store
  contract (reserving grey-box coverage/fault columns); layered config
  (`config.py`, defaults → file → env → overrides) with a stable run hash and
  redaction; structured JSON logging (`obs.py`); the request budget + per-host
  timing mutex (`budget.py`); and a session-aware, scope-enforcing HTTP seam
  (`http.py`). Adds `pyproject.toml`. Realizes Phase 0 tasks T0.1, T0.3, T0.4.
- Impact (other components / project): every tool now has a real `core/` to
  import (D6) and the shared store exists as the integration bus (D5). Establishes
  the store schema other components will read/write (T0.8 migrates them onto it).
  No external interface beyond the store contract; the schema is versioned so
  later changes are additive migrations.
- Risk (level; mitigation): medium — the most depended-on component. Mitigated by
  numbered forward-only migrations (idempotent, transactional), a versioned
  feature store, config validation (e.g. timing_concurrency must be 1), and unit
  tests covering migrations idempotency, config precedence/hash/redaction, budget
  caps, the timing mutex, and HTTP scope enforcement + flow recording.
- Deliverables:
  - [x] Package layout with `core/` (T0.1) — done.
  - [x] Store + migrations (T0.3) — done.
  - [x] Config, logging, budget+mutex, HTTP seam (T0.4) — done.
  - [x] Versioned feature extractor `features.py` + golden tests (T0.5) — done.
  - [x] Foundation unit tests (12) passing — done.
  - [ ] Session manager replaces the HTTP-seam addon stub — todo (Phase 1).
- Effectiveness (assessed 2026-09-21): effective — `python -m pytest` is green
  (12/12); a fresh store migrates to version 1 and re-migration is a no-op; config
  hash is deterministic; the timing mutex serializes per host in a threaded test.

### CC-CORE-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented; the
  existing tools currently carry their own ad-hoc storage and helpers.
- Impact (other components / project): once built, every tool depends on it; it
  establishes the store as the integration bus (D5) and removes duplicated
  storage/logging/HTTP logic from the tools (D6). Until then, tools remain
  loosely coupled through separate SQLite files.
- Risk (level; mitigation): medium — this is the most depended-on component, so a
  bad schema or API is expensive to change later. Mitigated by numbered
  migrations, a versioned feature store, and building it first (Phase 0) before
  much depends on it.
- Deliverables:
  - [ ] Package layout with `core/` — todo (Phase 0 T0.1).
  - [ ] Store + migrations — todo (Phase 0 T0.3).
  - [ ] Config, logging, budget+mutex, HTTP seam — todo (Phase 0 T0.4).
  - [ ] Versioned features + golden tests — todo (Phase 0 T0.5).
- Effectiveness (assessed or pending): pending — not yet built.
