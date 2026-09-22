# Diagnostics and UI — Change Control Log

Component code: **UI**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-UI-0035 — Robustness: top-level `fuzzlab <command>` dispatcher backstop (2026-09-22)
- Change: `fuzzlab/cli.py::main()` had zero exception handling around any
  subcommand dispatch (every `if command == "...": return X.main(rest)` branch,
  and the `runpy.run_module(...)` delegation for `crawl`/`audit`/`fuzz`/
  `build-db`). Wrapped the whole dispatch in `try/except`: `KeyboardInterrupt` →
  clean message, exit 0 (matching every other command's established convention —
  `proxy/cli.py`, `mutate-run`, `auto`); any other exception → clean
  `"fuzzlab <command> failed: ..."` message to stderr, exit 1. This is explicitly
  a **defense-in-depth backstop**, not the primary fix for any one command — every
  affected tool is independently runnable as `python -m fuzzlab.<module>` too
  (D11), bypassing this dispatcher entirely, so the real fix for each command had
  to live in (and does live in, per the companion `session`/`mutate-run`/`auto`
  entries in this session) that command's own `main()`. The backstop's value is
  covering commands this pass didn't individually harden (`greybox-run`, `proxy`,
  `web`, `lab-generate`) and the still-unguarded tail sections this pass
  deliberately left in `crawl`/`audit`/`fuzz` (e.g. `spider.py`'s post-crawl store
  consolidation) without touching every one of them individually. Verified
  `SystemExit`/`KeyboardInterrupt` are `BaseException`, not caught by the new
  `except Exception`, so every existing `p.error()`/`sys.exit()` clean-exit
  convention already used throughout these commands is unaffected.
- Impact (other components / project): none behavioral for a successful run.
  Every subcommand's own return value/exit code passes through unchanged; only an
  otherwise-unhandled exception or interrupt now gets a clean message here instead
  of a raw traceback.
- Risk (level; mitigation): low — additive, outermost-layer-only exception
  handling. Mitigated by 7 new tests in `tests/test_cli.py` (this dispatcher had
  zero prior direct coverage — `tests/test_web_runner.py` only checks the `argv`
  the web launcher constructs to invoke it as a *subprocess*, never `main()`'s own
  dispatch/error-handling): help/no-args/version/unknown-command; dispatch to a
  subcommand's `main()` with the right `rest` args; a subcommand's
  `KeyboardInterrupt` and a subcommand's generic exception are both caught
  cleanly; and — the critical safety property — a subcommand's own `SystemExit`
  (the established clean-exit convention) still propagates through unmodified,
  proving the backstop cannot mask an intentional clean exit.
- Deliverables:
  - [x] Top-level `try/except` around the dispatch — done.
  - [x] `tests/test_cli.py` (7 tests) — done.
- Effectiveness (assessed 2026-09-22): effective — all 7 new tests pass,
  including the `SystemExit`-propagation guarantee; `tests/test_web_runner.py`
  passes unchanged.

### CC-UI-0034 — Technologies panel: surface web app/service fingerprinting in the UI (2026-09-22)
- Change: `fuzzlab.report.build_report` now additionally includes a `technologies`
  list (category/name/version/confidence/evidence/source_url, sorted by category,
  name, confidence desc) read from the new `fingerprint_signal` table (CC-CORE-0021,
  CC-AUD-0016, CC-FUZZ-0022); `format_text` gained a matching `technologies:` block.
  `run.html`'s run-detail page gained a new "Technologies" card (grouped by
  category via Jinja's `groupby`, one entry per detected technology with its
  version and confidence, only rendered when at least one signal was recorded) —
  purely additive; the existing one-line DBMS/framework/WAF summary (driven by the
  unrelated `target` table via `results.run_detail`) is untouched. Because
  `/runs/{id}/report.json` and `fuzzlab report --json` both go through the same
  `build_report`/`format_json`, they stay byte-identical (CC-UI-0032's guarantee)
  with the new field included on both.
- Impact (other components / project): none behavioral elsewhere — pure read-only
  rendering of already-stored data (NFR-UI-read-only), no new POST/PUT/DELETE
  route, so no new surface for the control-plane hardening middleware (CC-UI-0026)
  to reason about. `t.name`/`t.version`/`t.evidence`/`t.source_url` are untrusted
  (attacker-influenced response content) and render only via Jinja2's `{{ }}`
  autoescaping, never `|safe`, consistent with FR-UI-12's textContent-only
  invariant for untrusted fields.
- Risk (level; mitigation): low — additive template block + one new report field;
  no new endpoints. Mitigated by 2 new `tests/test_report.py` assertions (the
  `technologies` list appears in the JSON report and the text report; an empty-
  technologies run omits the text section) and 2 new `tests/test_web_results.py`
  tests (the panel renders with the right category/name/version/confidence when a
  signal exists; it is entirely absent from the page when none were recorded).
- Deliverables:
  - [x] `build_report`/`format_text` technologies field — done.
  - [x] `run.html` "Technologies" card — done.
  - [x] Tests (4 total across `test_report.py`/`test_web_results.py`) — done.
- Effectiveness (assessed 2026-09-22): effective — a run with a recorded PHP signal
  shows "Technologies (1)" with its category/name/version/confidence in the
  rendered page, and the report JSON/text both carry it; a run with none shows
  neither.

### CC-UI-0033 — Doc-currency fix: requirements.md said "planned" (2026-09-22)
- Change: `docs/components/12-diagnostics-and-ui/requirements.md`'s Status header
  read `[planned]`, stale against this log's 32 entries of built work — the FR list
  itself (FR-UI-1…18) already carried accurate "Realized: CC-UI-NNNN" annotations
  through CC-UI-0032, only the top-line header hadn't been updated to match.
  Corrected to `[built — ...]`, itemizing the shipped surface. Documentation only;
  no code or behavior change.
- Impact (other components / project): none functionally — corrects a
  living-spec/reality mismatch; `docs/ARCHITECTURE.md` #12 was checked and was
  already accurate, so it needed no change.
- Risk (level; mitigation): none — text-only, cross-checked against the FR list's
  own "Realized" notes and this log's entries before writing.
- Deliverables:
  - [x] `requirements.md` Status header corrected — done.
- Effectiveness (assessed 2026-09-22): effective — header now reads `[built]`
  consistent with the FR list's existing realization notes.

### CC-UI-0032 — Surface the reproducible evaluation report in the web panel (CC-UI-0009 follow-up) (2026-09-22)
- Change: a run's detail page (`/runs/{run_id}`) now renders a "Reproducibility
  report" card — schema version, config hash, feature version(s), deployed models,
  and the active plugin set — built from the same `fuzzlab.report.build_report`
  (T10.4) the `fuzzlab report` CLI already uses, plus a download link to a new
  `GET /runs/{run_id}/report.json` route. That route serves
  `fuzzlab.report.format_json`'s canonical, sorted-key output **byte-identical**
  to what the CLI's `--json` flag prints — the on-disk and web artifacts can
  never diverge, since both go through the same formatter. Pure read; no
  traffic; no schema change; `_read_report` follows the existing `_read_detail`
  guard pattern (a missing store or run id is `None`, never a store creation as
  a side effect of reading).
- Impact (other components / project): closes CC-UI-0009's explicitly-optional
  "surface the report in the web panel" follow-up. No change to the existing
  run-detail context (`detail`) — the report is a separate `report` template
  variable, avoiding any key collision with `results.run_detail`'s own
  differently-shaped `counts`/`findings`. `/runs/{run_id}/report.json` matches
  U6's `Cache-Control: no-store` prefix match on `/runs/*`, so no extra header
  wiring was needed there.
- Risk (level; mitigation): low — purely additive read surface, reusing an
  already-tested, deterministic builder. Mitigated by 4 new tests
  (`tests/test_web_results.py`): the run page shows the report card + download
  link; the JSON route's body is asserted **byte-identical** (not just equal)
  to `format_json(build_report(...))` called directly against the same store;
  404 for a run id that doesn't exist; 404 without creating a store when the
  store file doesn't exist yet.
- Deliverables:
  - [x] `_read_report` helper + wired into `run_html`'s context — done.
  - [x] `GET /runs/{run_id}/report.json` (canonical JSON, byte-identical to the
    CLI) — done.
  - [x] "Reproducibility report" card on the run detail page — done.
- Effectiveness (assessed 2026-09-22): effective — the web route's bytes are
  proven identical to the CLI's own formatter output in tests, and the run page
  now names exactly what produced a result (schema/config/feature/model/plugin
  versions) without leaving the panel.

### CC-UI-0031 — Lane U5: Diagnostics metric charts + read-only store explorer (2026-09-22)
- Change: rebuilt the `/diagnostics` tab (a U0 placeholder) into a TensorBoard-like
  metric-series viewer plus a Datasette-style store explorer. `fuzzlab/web/diagview.py`
  reads every populated `metric_series` `(source, key)`, server-downsamples it
  (`fuzzlab/web/downsample.py`: LTTB for line series, a min/max envelope bucketer for
  bandit posterior/regret CI-band series, R-05/R-08), and hands the result plus a
  capped offscreen-table row list to the template — so the page is informative even
  with JS disabled. `fuzzlab/web/storeview.py` provides read-only, paginated browsing
  of any store table via `GET /api/store/tables` / `GET /api/store/{table}`, redacting
  any column whose name matches a secret-like substring
  (password/secret/token/credential/cookie/authorization) and rendering every BLOB
  column as `<blob: N bytes>` rather than raw bytes — both at render time, before the
  data leaves the server. New shared front-end infra: `static/js/charts.js` (uPlot
  wrapper: theme/density retheme via destroy+rebuild, debounced `ResizeObserver`, the
  `window.__charts` registry, an offscreen `<table>` fallback kept in sync with the
  data — `mode: "line"` per-run trend lines, `mode: "envelope"` a min/max band via
  uPlot's native `bands` feature), `static/js/downsample.js` (client-side LTTB/envelope,
  pure and Node-testable), `static/js/smoothing.js` (client-side EMA for the
  Diagnostics smoothing slider), and uPlot 1.6.32 vendored to
  `static/vendor/uplot/`. `charts.js` was generalized after this lane landed
  (per-series `label`/`color`/`width` overrides + an opt-in `kind: "bars"` path, all
  additive/backward-compatible) so lane U4's ML tab could reuse this one wrapper
  instead of the near-duplicate implementation it had built independently and
  concurrently — see U4's own entry for that reconciliation.
- Impact (other components / project): `static/js/charts.js`/`downsample.js` +
  vendored uPlot are now the one shared chart implementation for both Diagnostics and
  the ML tab (U4). Purely read-only — no result table or `saved_views`/`metric_series`
  writes. The store explorer is a *generic* table browser (any table, not just result
  tables), so its redaction rule is deliberately over-inclusive (e.g. a plain
  `token_exp` timestamp column is masked purely because its name contains "token") —
  a conscious trade favoring never leaking a secret over precision.
- Risk (level; mitigation): medium (a generic store browser is a new read surface over
  every table, including ones that can hold credential-adjacent data) — mitigated by
  `tests/test_web_diagnostics.py` (redaction-by-column-name and never-render-raw-blob
  regressions, seeded with a real `Authorization: Bearer <token>` header and a
  `token_exp` field and asserting neither ever appears in a response), route/no-JS
  tests for both the empty-store and seeded-metrics cases, `node --test` coverage of
  the pure LTTB/envelope/EMA functions, a real-browser smoke asserting chart content
  via `window.__charts` + the offscreen table (never canvas pixels), and the unchanged
  full suite.
- Deliverables:
  - [x] Per-metric-series charts (line + envelope modes) over `metric_series` — done.
  - [x] Server-side LTTB/envelope downsampling — done.
  - [x] Read-only, redacting store explorer — done.
  - [x] Shared `charts.js`/`downsample.js`/`smoothing.js` + vendored uPlot — done.
  - [x] Generalized `charts.js` for U4 reuse (post-landing) — done.
- Effectiveness (assessed 2026-09-22): effective — every populated metric series
  renders as its own chart with a working offscreen-table fallback, the store explorer
  never leaks a secret-bearing column or raw blob in the tests exercising it, and U4's
  ML tab now renders through this same chart wrapper with no second implementation to
  maintain.

### CC-UI-0030 — Lane U4: read-only advisory ML tab (2026-09-22)
- Change: built out `/ml` (a U0 placeholder) into a read-only, advisory dashboard over
  classifier/ranker/conformal/anomaly/active-learning/bandit/mutation state already
  persisted in the store (`fuzzlab/web/mlview.py`: pure aggregation over `run_metrics`,
  `metric_series`, `model`, `candidate`, `bandit_posteriors`, `payload_variant` — never
  a training run, never a store write, never anything that touches the fuzzing loop). A
  family with no persisted data reports itself unavailable rather than fabricating a
  value (verified per family: anomaly has only a flagged-count, no per-point ECOD score
  to histogram; active learning persists nothing at all, so its queue reuses the
  ranker's own `rank_uncertainty`; mutation's `payload_variant` only ever records an
  *accepted* variant, so there is no killed/survived split to show; logistic's fitted
  coefficients are never persisted, so no diverging-bar weight chart). Charts render
  through the shared `static/js/charts.js` wrapper (U5, `CC-UI-0031`) — this lane
  originally vendored uPlot and built its own near-identical wrapper independently and
  concurrently with U5 (neither could see the other mid-build); reconciled at
  integration onto U5's version, generalized there (per-series `label`/`color`/`width`
  overrides + an opt-in `kind: "bars"` path for the histogram panels) rather than
  keeping two implementations. `ml.js`'s three chart-mount helpers now build data in
  the shared wrapper's `{mode, series}` shape; each sets `role="img"`/aria-label on its
  own chart element (some of this tab's labels are runtime-formatted, e.g. conformal's
  `t_lo`/`t_hi`, so they can't be set server-side the way Diagnostics' static labels
  are).
- Impact (other components / project): read-only consumer of CORE's `metric_series`
  (B0) and every ML/oracle/scheduler/mutation component's existing `run_metrics`/store
  writes — no new write path anywhere. Establishes `static/js/charts.js` as the one
  chart implementation for both Diagnostics and this tab (no second wrapper to
  maintain).
- Risk (level; mitigation): low (advisory, read-only; the one behavior risk was the
  charts.js reconciliation silently regressing a chart) — mitigated by
  `tests/test_web_ml.py` (empty-store "every family unavailable" case, a seeded-store
  case asserting every family's real read-only aggregation, and a route/no-JS render
  check), a `tests/test_web_ml_browser.py` real-browser smoke, and the unchanged full
  suite after the charts.js reconciliation.
- Deliverables:
  - [x] `mlview.py` read-only aggregation over every ML family — done.
  - [x] `/ml` route built out from the U0 placeholder — done.
  - [x] Charts reconciled onto U5's shared `charts.js` (no duplicate wrapper) — done.
- Effectiveness (assessed 2026-09-22): effective — every family with real persisted
  data renders a real chart/table, every family without one says so explicitly instead
  of fabricating a value, and the tab shares one chart implementation with Diagnostics.

### CC-UI-0029 — Lane U3: Proxy workbench rebuild on shared message-editor + splitter + sub-nav (2026-09-22)
- Change: replaced the Proxy section's single long page with an in-page sub-nav
  (History/Intercept/Repeater/Scope·Match-Replace, APG Tabs pattern) and a new shared ES
  module `static/js/msgeditor.js` exporting the `<message-editor>` custom element
  (`{editable, bytes, meta}` in, `getBytes()` out) — Raw|Pretty tabs (+read-only Hex on
  non-editable panes), a status/timing strip, Ctrl-F search painted via the CSS Custom
  Highlight API over a read-only `<pre>` mirror (never span-injected into the live
  `<textarea>`), and a CRLF/non-printing-char display toggle. Raw is the only editable
  view; Pretty/Hex are derived, view-only renderings recomputed from the current bytes and
  never written back. Also added `attachSplitter()` — a vanilla CSS-grid resizable
  splitter (pointer-capture drag, arrow-key `separator`-role a11y, localStorage-persisted
  px per orientation) — wired into History's flow detail and Repeater's request/response
  panes with a horizontal/vertical layout toggle. Intercept uses one editable instance;
  Repeater and History use an editable+read-only pair. `toWire` (`js/http.js`, unchanged)
  remains the single documented CRLF-restore point, applied only at the Forward/Send call
  sites. No library vendored; no build step.
- Impact (other components / project): front-end only — `RepeaterController`/
  `ProxyController` (PROXY component) and every `/api/proxy/*` route are unchanged. Kept
  the DOM ids other suites assert on (`flow-table`, `flow-search`, `flow-refresh`,
  `flow-empty`, `flow-detail*`, `flow-to-repeater`, `proxy-status`) and the
  `initIntercept`/`initProxy` function names. Establishes `msgeditor.js` as a reusable
  component other UI lanes could adopt for any future raw-message display. Did not touch
  `app.py` — every backend route this lane needed already existed.
- Risk (level; mitigation): medium (touches the Proxy page's entire DOM/JS surface,
  including the pre-existing Repeater Playwright smoke's selectors) — mitigated by
  updating that smoke test for the new markup, adding a byte-exact edit-and-forward
  Intercept regression and a redaction/`innerHTML`-safety History regression (both
  Playwright, skip cleanly without a browser), keeping the backend route tests untouched
  and green, and a full-suite run at the accepted baseline.
- Deliverables:
  - [x] Shared `<message-editor>` custom element + vanilla splitter (`msgeditor.js`) —
    done.
  - [x] Sub-nav (History/Intercept/Repeater/Scope·Match-Replace) — done.
  - [x] Intercept/Repeater/History rebuilt on the shared editor — done.
  - [x] Byte-exact edit-and-forward + redaction/XSS-safety regressions — done.
- Effectiveness (assessed 2026-09-22): effective — all four sub-views work through the
  shared editor, the CRLF round-trip through `getBytes()`/`toWire` is proven byte-exact
  against a real upstream, and redacted secrets never reach the DOM through the rebuilt
  panels.

### CC-UI-0026 — Lane U6: control-plane hardening middleware + Starlette pin (2026-09-22)
- Change: added `ControlPlaneHardening`, a global ASGI middleware in `fuzzlab/web/app.py`
  (pure ASGI, not `BaseHTTPMiddleware`, so it doesn't interfere with the launcher's SSE
  stream), registered on every request: (a) an exact host:port allow-list self-derived
  from the ASGI connection's own bound address (`scope["server"]`, never client-supplied)
  — rejects DNS-rebinding-style Host headers with **421**; (b) on POST/PUT/DELETE, an
  Origin-exact-match + `Sec-Fetch-Site: same-origin` gate (same-site is deliberately
  rejected too — the lab is same-site on a sibling port) with a Referer fallback for
  clients that send no Fetch Metadata, plus a custom `X-Fuzzlab-Client: 1` header
  requirement on `/api/*` to force a CORS preflight a cross-origin page can't satisfy —
  any failure is **403**, fail-closed. Every response (including rejections) also gets a
  fixed offline CSP + `X-Content-Type-Options: nosniff` / `X-Frame-Options: DENY` /
  `Referrer-Policy: same-origin` / COOP/CORP `same-origin`, plus `Cache-Control: no-store`
  on `/api/*`, `/results`, `/runs/*`. Bumped the `web` extra's Starlette pin to
  `>=1.0.1,<2` (CVE-2026-48710 "BadHost"); installed/tested against 1.6.0. Added
  `X-Fuzzlab-Client: 1` to the shared `postJSON`/`delJSON` fetch helpers
  (`fuzzlab/web/static/js/http.js`, used by every section's state-changing request) so
  existing UI actions keep passing the new `/api/*` gate.
- Impact (other components / project): a global gate in front of every route added by
  U0–U5; does not change any route's own logic. Verified (unchanged): the `authorized`
  no-auto-run gate is still read only from server-side `Config`, never the request body,
  on every gated route. **Open finding, not fixed here (out of this lane's file scope):**
  `RepeaterController.create_tab`/`send` (`fuzzlab/web/proxycontrol.py`) accepts an
  arbitrary client-supplied `host`/`port` for replay, restricted only by `authorized` —
  by design, a general-purpose repeater, but flagged for a deliberate scope-hosts
  decision (document as intentional, or add a scope check) rather than left silent.
- Risk (level; mitigation): medium (a global middleware guarding every current and
  future POST/PUT/DELETE route) — mitigated by `tests/test_web_hardening.py` (23 tests:
  the full acceptance matrix — wrong Host, cross-site/same-site-cross-origin POST,
  missing `/api/*` header, Referer fallback, DELETE/PUT, `authorized`-gate independence,
  headers present on success *and* on a rejected response, `Cache-Control: no-store`
  scoping) plus the unchanged full suite (1423 passed / 24 skipped, same 6 pre-existing
  unrelated failures — the +23 over the prior baseline is exactly this lane's new tests).
- Deliverables:
  - [x] Host allow-list (421 on mismatch) — done.
  - [x] Origin/Sec-Fetch-Site/Referer CSRF gate + `/api/*` custom-header requirement
    (403 fail-closed) — done.
  - [x] CSP + security headers on every response — done.
  - [x] Starlette `>=1.0.1,<2` pin (CVE-2026-48710) — done.
  - [x] `X-Fuzzlab-Client` added to shared fetch helpers — done.
- Effectiveness (assessed 2026-09-22): effective — the full acceptance matrix passes,
  no existing UI action (launcher run, proxy intercept/scope/match-replace/repeater)
  regressed, and the repeater's unrestricted-destination finding is now on record for a
  deliberate follow-up decision instead of silently unnoticed.

### CC-UI-0027 — Lane U1: Overview dashboard as the landing route (2026-09-22)
- Change: `GET /` now renders the Overview dashboard (new `_overview_context` builder in
  `app.py`, `templates/sections/overview.html`, `static/css/overview.css`,
  `static/js/overview.js`) — a 5-tile KPI row (Findings w/ severity split, Runs w/ 7-day
  count, Last run, Detection quality [F1/MCC, em-dash if unscored], Efficiency
  [requests-per-finding, em-dash if unscored]), each tile linking to an existing route;
  Panel A recent-runs table (≤10, newest first); Panel B a findings-by-severity bar (the
  uPlot sparkline is deferred — no chart infra existed yet when this lane branched);
  Panel C quick actions (Launch auto → `/launch`, Open proxy → `/proxy`, Model registry →
  `/ml`). Served from one aggregate read per request; writes no result tables. Zero runs
  → a single onboarding card, never a zero-grid. **Repointed the Launcher from `/` to
  `/launch`** (its own `NAV` entry) — U0 had wired `/` to the Launcher, but the plan's R-10
  spec and this lane's brief are explicit that `/` is the Overview landing route; this is
  a real, narrow behavior change (NAV + two route handlers only). Panel A hydrates via the
  shared `js/datatable.js` (U2, `CC-UI-0028`) once that lane landed — this lane originally
  built its own minimal DataTable ahead of U2 and adopted U2's fuller shared module at
  integration instead of keeping a duplicate implementation.
- Impact (other components / project): the one behavior change (Launcher's route) is
  covered by updated tests (`test_web_frontend.py`, `test_web_launcher.py`,
  `test_web_launcher_browser.py`, plus the `NAV`-parametrized nav/route tests that picked
  it up automatically). No `severity` column exists on `finding` — `finding.confidence` is
  actually the oracle's confirmation *mechanism*, not a risk level — so the KPI/Panel B
  severity split is a UI-only display heuristic keyed on `finding.vuln_class`
  (`_SEVERITY_BY_VULN_CLASS` in `app.py`), never persisted; superseding it with a real
  `severity` column is a candidate follow-up once U2's findings facets (which also assume
  a severity field) motivate one. No "run status" (running/passed/failed) is persisted
  either, so the "Last run" tile shows the finding count instead of a pass/fail badge.
- Risk (level; mitigation): low-medium (the `/` repoint is the one real behavior change) —
  mitigated by `tests/test_web_overview.py` (empty/unscored/scored/cap-at-10 cases) and
  the unchanged full suite.
- Deliverables:
  - [x] KPI row (5 tiles) + Panel A/B/C — done.
  - [x] Aggregate single-read context builder — done.
  - [x] Launcher repointed to `/launch` — done.
  - [x] uPlot sparkline — deferred (no chart infra at branch time; not blocking).
- Effectiveness (assessed 2026-09-22): effective — empty/scored/unscored states render
  correctly, the Launcher move didn't regress any existing launcher test, and Panel A now
  shares the same `DataTable` module U2/U5 use.

### CC-UI-0028 — Lane U2: Findings workbench (facets, saved views, shared DataTable) (2026-09-22)
- Change: new `/findings` + `/findings/{id}` routes (`fuzzlab/web/findingsview.py`) render
  a faceted workbench over `finding`/`attempt`: a collapsible left facet sidebar
  (multi-select, live counts; OR within a group, AND across groups — vuln class,
  severity, method, confidence/mechanism, endpoint), a debounced quick-filter, applied-
  filter chips + "Clear all", and a saved-view chip row. Saved views are server-side in a
  new `saved_views(id, table_key, name, spec_json, is_pinned, created_at, updated_at)`
  table (migration 12, `fuzzlab/core/migrations.py`) via `GET/POST/PUT/DELETE
  /api/views?table=` (`fuzzlab/web/savedviews.py`); `spec_json =
  {version, name, pinned, filter:{text, facets, predicates}, sort, columns}`.
  `localStorage` (try/catch) holds only throwaway per-viewer state (last view id, draft
  filter text, collapsed groups). Detail view (`/findings/{id}`) exposes the raw
  `case_id` and an explicit `ground_truth_fields_available: False` flag rather than
  fabricating `primary_endpoint`/`primary_role`/`related_endpoints`/`flow_variant` —
  those fields live only on the out-of-band ground-truth `Case` dataclass
  (`fuzzlab/labels/contract.py`), not on `finding`/`attempt`; not added here (out of
  scope). "Send to Repeater" is a Post/Redirect/Get: `POST` → 303 to
  `/proxy?repeater_tab=ID` (a narrow, additive query-hint on the existing `/proxy` route,
  never required). Added the shared, hand-rolled `js/datatable.js` (in-memory
  filter→sort→fragment-render, `textContent`-only cells, scheme-checked links via
  `isSafeHref`/`makeSafeLink`, capped at 2000 rows) that U1 and U5 also import —
  `createDataTable({container, columns, data, onRowClick, rowActions, textFilterKeys,
  cap, emptyMessage})`.
- Impact (other components / project): defines the shared `DataTable` API U1 (recent-
  runs) and U5 (store explorer) depend on — stable, exported per the above signature.
  Read-only over `finding`/`attempt`; writes only the new UI-owned `saved_views` table
  (not a result table — NFR-UI-read-only unaffected). Consumes CORE migration 12
  (CC-CORE-0019).
- Risk (level; mitigation): medium (new routes + a new store table + a shared module
  three lanes depend on) — mitigated by `tests/test_web_findings.py`,
  `tests/test_web_findings_browser.py`, `tests/test_datatable_js.py` (pure-logic
  `node --test` coverage of `compareValues`/DataTable filtering), a DOM-safety test
  confirming `textContent`-only rendering and `javascript:`-scheme link rejection, and
  the unchanged full suite.
- Deliverables:
  - [x] Facet sidebar + quick-filter + filter chips — done.
  - [x] `saved_views` table + `/api/views` CRUD — done.
  - [x] Shared `js/datatable.js` (stable API for U1/U5) — done.
  - [x] Detail view + send-to-Repeater PRG/303 pivot — done.
- Effectiveness (assessed 2026-09-22): effective — filter/saved-view round-trips verified,
  DOM-safety tests pass, and the DataTable module's API is documented and stable for the
  two sibling lanes that import it.

### CC-UI-0025 — Lane U0: MPA routes + asset split (retire hash-tab shell) (2026-09-22)
- Change: replaced the single-page hash-switched shell (`templates/index.html`,
  `static/app.js`, `static/app.css`, client-side `initTabs()`) with five real routes —
  `/` (Launcher), `/proxy`, `/results`, `/ml`, `/diagnostics` — each its own Jinja2
  template (`templates/sections/*.html`), ES module (`static/js/*.js`), and CSS partial
  (`static/css/*.css`). `app.py` gains a single `NAV` list as the sidebar's source of
  truth; each route handler passes an explicit `active` id (never derived from the
  request path) that `base.html`'s nav loop compares to render `aria-current="page"`.
  Shared browser chrome (theme/density/sidebar toggle, the proxy-status chip) and shared
  HTTP helpers moved to `static/js/shell.js` / `static/js/http.js`, loaded on every page;
  per-section behavior (`launcher.js`, `proxy.js`) loads only on its own route. The
  existing no-FOUC inline theme/density script in `base.html`'s `<head>` is unchanged and
  now runs on every full-page navigation, as required under an MPA. Added a skip-link +
  `<main id="main" tabindex="-1" data-section>` landmark (WCAG 2.2 AA).
- Impact (other components / project): this is the Wave-0 enabling refactor Wave-1 lanes
  (U1 Overview, U2 Findings, U3 Proxy rebuild, U4 ML, U5 Diagnostics) build on — each gets
  its own section/JS/CSS files to extend independently. Preserves the U0↔X0 activity-
  grouping contract (`commandspec.py`'s `group` field, `app.py`'s `_group_activities`,
  CC-UI-0024) unchanged — the Launcher's "Lab / authoring" group still renders. No-auto-
  run, loopback-only, the `authorized` gate, and read-only-over-the-store are all
  unchanged (no route added here writes result tables). U6 (control-plane hardening)
  touches the same `app.py` and lands with or right after this change per the plan's wave
  map — sequenced next.
- Risk (level; mitigation): medium (touches the app's entire routing/template/asset
  surface) — mitigated by a route/no-JS/active-nav test parametrized over every `NAV`
  entry, updated content-invariant tests for every panel, updated browser-navigation
  tests, and a new deep-link + active-nav Playwright smoke; full suite green at the
  accepted baseline with no new failures.
- Deliverables:
  - [x] Real per-section routes + `NAV` source of truth + server-rendered active-nav —
    done.
  - [x] `templates/index.html` → `templates/sections/*.html` — done.
  - [x] `static/app.js` → `static/js/{shell,http,launcher,proxy}.js`, `initTabs` retired
    — done.
  - [x] `static/app.css` → `static/css/*.css` per section — done.
  - [x] Skip-link + `<main>` landmark — done.
- Effectiveness (assessed 2026-09-22): effective — every section is reachable at its own
  URL, deep-links work, TestClient's no-JS body renders each section correctly, and the
  Playwright smoke confirms real-browser deep-link navigation + active-nav state; the
  U0↔X0 grouping contract still renders correctly.

### CC-UI-0024 — Lane X0: register `lab-generate` in the launcher (own group) (2026-09-22)
- Change: surfaced `fuzzlab lab-generate` as a launchable activity in the web launcher (Wave-0
  lane X0 of `docs/UI_IMPLEMENTATION_PLAN.md`). `fuzzlab/labgen/cli.py` already exposed
  `build_parser()`, so this added a `_load_labgen` loader + a `_REGISTRY` entry in
  `fuzzlab/web/commandspec.py` (`sends_traffic=False` — it renders files locally and `--check`
  runs offline build gates, so **no `authorized`/destructive gate**). Introduced an optional
  `group` field on `_Entry`/`CommandSpec` (+ `to_dict()`), set to `"Lab / authoring"` for
  lab-generate; made `app.py`'s `_group_activities` bucket leftover activities by that spec
  `group` (falling back to the existing name-map / "Other"), so the activity picker shows
  lab-generate under its own group while every other tool's grouping is unchanged.
- Impact (other components / project): UI only; no schema/contract change. The command-spec form
  contract is unchanged (fields still argparse-derived — PA-0001). The new `group` field is
  additive and defaults to `None`. Establishes the U0↔X0 grouping contract (X0 sets `group`; U0
  reads `a.get("group")`), so U0's app.py refactor composes without conflict. `lab-generate`'s
  parser pulls in `fuzzlab.labgen`, which needs the declared `covertable` dep; `all_specs()`
  already skips any activity whose parser import fails, so a missing optional dep degrades the
  launcher rather than breaking it.
- Risk (level; mitigation): low. Registering an activity runs nothing (introspection is pure).
  Mitigation: new `test_web_commandspec.py` cases assert lab-generate is registered, grouped
  ("Lab / authoring"), non-traffic/ungated, and argparse-derived, and that `group` defaults to
  `None` elsewhere; `python -m fuzzlab.cli lab-generate --help` verified; web + command-spec
  suites green (44 passed in the focused run). No `authorized` gate on a file-rendering tool
  keeps no-auto-run intact (it sends no traffic).
- Deliverables:
  - [x] `_load_labgen` + `_REGISTRY` entry + `group` field in `commandspec.py` — done.
  - [x] group-aware `_group_activities` in `app.py` — done.
  - [x] command-spec tests for lab-generate + the `group` default — done.
  - [x] full-suite check (X0 introduced no new failures; 1281 passed — the only failures are
    pre-existing LAB `--check` tests needing the `gitleaks` binary, absent in this sandbox) — done.
- Effectiveness (assessed 2026-09-22): effective — lab-generate now appears as a grouped,
  non-traffic launcher activity with argparse-derived fields, and the `group` contract is in place
  for U0. Re-assess once U0's MPA refactor renders the grouped picker end-to-end.

### CC-UI-0023 — UI implementation plan + build policy + round-1 research (2026-09-22)
- Change: added `docs/UI_IMPLEMENTATION_PLAN.md`, the single tracked plan for the remaining web UI
  work (companion to `UI_REVAMP_PLAN.md`, `UI_LAYOUT_REDESIGN.md`, and the LAB plan). It records
  the **settled build policy** ("no build step, ever; offline + loopback; hand-roll where vanilla
  is cheap; vendor exactly one zero-dependency static file only where hand-rolling is expensive")
  and the **five locked decisions** (D1 MPA routes; D2 vendor one zero-dep chart lib; D3 split
  assets, no bundler; D4 hand-roll tables; D5 include `lab-generate` in the launcher). It breaks
  the outstanding work into clear, executable, lane-organized deliverables — **U0** (MPA routes +
  asset split, the enabling refactor), **U1** Overview, **U2** Findings, **U3** Proxy rebuild,
  **U4** ML, **U5** Diagnostics + store explorer, **B0** `metric_series` + emitters, **X0**
  `lab-generate` in the launcher — with per-deliverable scope/files/deps/sub-lanes/acceptance and a
  wave/dependency map for concurrent-agent dispatch. It runs a research-refinement loop (mark gaps
  → dispatch one web agent per gap → fold findings back, ×3). **Round 1** (six agents, R-01…R-06)
  is folded in: full-page MPA, no HTMX; **uPlot 1.6.32** as the vendored chart lib (canvas;
  re-theme on `[data-theme]`; columnar data; offscreen-table a11y fallback); findings facet
  sidebar + **SQLite-backed saved views** + a hand-rolled DataTable (no virtualization,
  `textContent`-only, scheme-checked pivots); one shared `<message-editor>` (byte-exact textarea,
  vanilla grid splitter, hand-rolled highlighting); TensorBoard-style diagnostics controls +
  validated `metric_series(run_id, source, key, step, ts, value)` schema + a buffered
  `MetricLogger` emitter + **LTTB** server-side downsampling → client-side EMA; advisory-framed
  read-only ML panels (PR/reliability/weights/nDCG/conformal/anomaly/Beta-posteriors). Realizes
  more of FR-UI-8.
- Impact (other components / project): documentation/planning only — no code, schema, or contract
  change yet. Flags forthcoming work in CORE (the `metric_series` migration + WAL/concurrency in
  B0) and a `saved_views` table (U2); those land under their own change-control when built. Does
  not alter any invariant.
- Risk (level; mitigation): none (planning). The plan itself carries the invariants forward
  (no-auto-run / loopback / authorized / read-only / redaction / no-build-offline) into every lane
  and its acceptance criteria.
- Deliverables:
  - [x] `docs/UI_IMPLEMENTATION_PLAN.md` (policy + deliverables + lane map) — done.
  - [x] Round 1 research (R-01…R-06) dispatched + folded in — done.
  - [x] Round 2 (R-07 MPA pivot/state, R-08 SQLite WAL concurrency, R-09 test strategy, R-10
    Overview content) — folded in.
  - [x] Round 3 (R-11 accessibility, R-12 uPlot theming/responsive, R-13 loopback security) —
    folded in; added lane **U6 — control-plane hardening** and two §2 invariants (accessible;
    not-itself-an-attack-surface).
- Effectiveness (assessed 2026-09-22): effective — the 3-round research loop (13 markers) converted
  every open UI design fork into concrete, cited, executable spec and surfaced one net-new lane
  (U6) that a security tool needs to keep its own control plane off the attack surface. Deliverables
  are lane/wave-organized for distributed builds. Re-assess once the first lanes (U0/B0/X0/U6)
  build against it.

### CC-UI-0022 — Launch view rebuilt as the approved master-detail (2026-09-21)
- Change: rebuilt the Launcher section inside the R0 shell to match the **approved mockup**
  (`docs/UI_LAYOUT_REDESIGN.md`), replacing the old stacked cards (Target/Scope/Mode,
  Automatic, Manual, one card per activity). Brought forward from R1 at the user's request so
  the Launch view they reviewed is what ships now.
  - **Master-detail layout** (`.launch` grid): a left **activity picker** (`.actlist`) listing
    every activity grouped (Discovery / Attack / Analysis / Other), each row carrying compact
    **gate tags** (`traffic` / `auth` / `destr`) and an accent bar when selected; a right
    **detail** (`.lform`) that shows the selected activity's configurable form. All activity
    forms render server-side; `initLaunchNav()` shows one at a time (no-JS shows all — same
    progressive-enhancement rule as the tabs). Default selection is `auto`.
  - Detail form: a `.lform-head` (name + `sends traffic` / `--authorized` /
    `--allow-destructive` tags + Dry-run / Run / Stop), the tool's fields as `.frow` rows,
    bool flags folded into one inline `.optck` row, the D14 category picker as checkbox pills,
    and the plugins panel (`.plugpanel`) on `auto`. The dry-run **preview** and live SSE
    **console** are retokenized.
  - `auto` keeps a one-click **Run full pipeline** action (`POST /api/run/automatic`) above
    its flag form; the Manual/CLI prewired-command reference moved into a collapsed
    `<details>` below the grid.
  - Server: `_group_activities()` buckets activities into the ordered launcher groups
    (unknown tools fall into "Other"); `activity_groups` added to the index context.
- Impact (other components / project): UI only; no schema, contract, route, or CLI change.
  The command-spec-driven form contract is unchanged — every control still carries the same
  `data-dest` / `data-type` / `data-catgroup` hooks, so the runner, dry-run, gating, and SSE
  are untouched. Realizes the Launch portion of FR-UI-8 (the rest of R1 — per-section routes +
  Overview — still pending).
- Risk (level; mitigation): low. The forms and their JS are the same; only their container
  markup and CSS changed. Mitigation: full suite green (499 passed / 6 skipped), the
  whitespace-fragile gate assertion rewritten to match the stable gate title, the real-browser
  launcher test updated to select the activity first (dry-run + gated Run + SSE still verified
  end-to-end), and screenshots of the rebuilt view in light and dark.
- Deliverables:
  - [x] Master-detail Launch markup (activity picker + detail) — done.
  - [x] `initLaunchNav()` selection + retokenized launch CSS — done.
  - [x] `_group_activities()` + `activity_groups` context — done.
  - [x] Tests updated (gate title, browser select-first) + full suite green — done.
  - [x] Real-browser screenshot verification (light + dark) — done.
- Effectiveness (assessed 2026-09-21): effective. The Launch view now matches the reviewed
  mockup (verified by screenshots), the launcher behavior is unchanged, and the suite is green.

### CC-UI-0021 — App shell + design tokens (layout redesign R0) (2026-09-21)
- Change: implemented **R0** of the layout redesign (`docs/UI_LAYOUT_REDESIGN.md`,
  CC-UI-0020): replaced the top hash-tab masthead with a persistent **app shell** and a
  **design-token** system, with **no behavior change** to the launcher / proxy / results.
  Realizes new requirement **FR-UI-8**.
  - New `fuzzlab/web/static/tokens.css` — the single source of truth for color, elevation,
    and density: light default, dark under `@media (prefers-color-scheme: dark)` guarded by
    `:root:not([data-theme="light"])`, an explicit `:root[data-theme="dark"]` override, and
    `:root[data-density="compact"]`.
  - `base.html` rewritten into the shell: a left **sidebar** (`<nav class="tabs">`, grouped
    Workbench / Analysis) + a **top context bar** with target / scope / authorized / proxy
    chips and theme / density / collapse controls, over a scrolling `<main class="content">`
    (`{% block content %}`). A no-FOUC `<head>` script applies persisted theme / density /
    collapse to `<html>` before first paint (wrapped in try/catch — blocked storage never
    breaks rendering). `tokens.css` is linked before `app.css`.
  - `index.html` / `run.html` / `not_found.html` moved from `{% block body %}` to
    `{% block content %}` (the masthead + top-tabs were dropped from index; the five
    `.panel` sections and every launcher form are byte-for-byte unchanged). Each adds a
    `{% block crumb %}`.
  - `app.css` rewritten as a CSS-grid shell (`grid-template-areas: "side top" "side main"`)
    with **retokenized** components — every existing class preserved (`.card`, `nav.tabs`,
    `.panel`/`.hidden`, `.field`, `.launch-form`/`.catgroup`/`.cat`/`.actions`/
    `.launch-preview`/`.launch-output`, `#flow-table`/`.flow-raw`, `#pending-table`/
    `.pending-raw`, `.pill`/`.result`, tables) now consuming tokens instead of raw hex.
  - `app.js`: added `initShell()` (theme cycle system→light→dark, density toggle, sidebar
    collapse — all persisted in `localStorage` behind try/catch — plus the topbar proxy
    chip from `/api/proxy/status`); `initTabs()` now no-ops on pages without `.panel`
    sections (run detail / not-found) so no tab is falsely highlighted. Selectors,
    `subscribe`, and all proxy/launcher init unchanged.
  - `app.py`: added `_shell_context(cfg)` (target / scope / authorized) and merged it into
    the index, run-detail, and not-found `TemplateResponse`s so every page carries identical
    shell chrome; `_index_context` now spreads it.
- Impact (other components / project): UI only; no schema, contract, or CLI change. No route
  added or changed. Supersedes the Phase-0.2 top-tab shell (CC-UI-0012) as the layout, while
  keeping its hash-based section switching. New static asset `/static/tokens.css`. Adds
  decision **D-UI-shell** (left-nav app shell + design tokens) to the roadmap.
- Risk (level; mitigation): low. Chrome-only rewrite; the invariant-bearing markup (launcher
  forms, gate pills, proxy cards, result tables) is unchanged, so the no-auto-run / loopback /
  authorized / read-only / redaction invariants are untouched. Mitigation: full suite green
  (499 passed / 6 skipped) — existing shell tests pass unchanged because `nav.tabs` / `.card`
  / `initTabs` / `subscribe` were preserved — plus new asset/shell tests, and a real-browser
  (Playwright) screenshot check of launcher + proxy in light and dark.
- Deliverables:
  - [x] `tokens.css` (light / dark / system + density) — done.
  - [x] `base.html` app shell (sidebar + top context bar + no-FOUC) — done.
  - [x] `index.html` / `run.html` / `not_found.html` → `{% block content %}` + crumb — done.
  - [x] `app.css` grid shell + retokenized components (all classes preserved) — done.
  - [x] `app.js` `initShell()` + `initTabs()` guard — done.
  - [x] `app.py` `_shell_context()` merged into every page — done.
  - [x] Tests: tokens served, shell renders, shell context on run/not-found — done.
  - [x] Full suite + real-browser visual verification — done.
  - [ ] R1 (routes + Overview), R2 (Findings), R3 (Proxy rebuild) — pending.
- Effectiveness (assessed 2026-09-21): effective. The shell renders professionally in both
  themes (verified by screenshots), section switching and all launcher/proxy controls behave
  exactly as before, and the full suite is green with the design system now centralized in
  `tokens.css` for R1–R3 to build on.

### CC-UI-0020 — Web UI layout redesign (design record) (2026-09-21)
- Change: added `docs/UI_LAYOUT_REDESIGN.md` — a design record for reworking the panel's
  **layout / information architecture** (distinct from the feature revamp in
  `UI_REVAMP_PLAN.md`). Grounded in researched UI/UX patterns from Rapid7 InsightVM, Tenable
  (Nessus / VM / .sc), Qualys VMDR, Greenbone/OpenVAS (GSA), NodeWare, Burp Suite, and OWASP
  ZAP. Proposes replacing the single-page top hash-tab layout with an **app shell** (persistent
  left sidebar + top context bar) over a **deep-linkable multi-page app** (jinja `shell.html` +
  per-section routes, still dependency-light — no SPA/build), a shared design system (tokens
  with light/dark + density, one DataTable with faceted filters + saved views, one reusable
  proxy message editor, list→detail with breadcrumbs, command palette + "send to" chaining),
  an Overview dashboard, a Findings workbench, and a rebuilt Proxy workbench; plus an
  incremental migration path (R0 shell/tokens → R1 routes+Overview → R2 Findings → R3 Proxy
  rebuild) that preserves the no-auto-run / loopback / authorized / read-only / redaction
  invariants and folds Phases 3–4 in as sections.
- Impact (other components / project): design only — no code, no schema change. Supersedes the
  Phase-0.2 top-tab shell (CC-UI-0012) once adopted; will add a decision (UI shell = left-nav
  MPA) and FR-UI entries at that point.
- Risk (level; mitigation): none (documentation). The doc scopes each migration step as
  independently testable with invariants preserved.
- Deliverables:
  - [x] `docs/UI_LAYOUT_REDESIGN.md` (research synthesis + IA + design system + migration) — done.
  - [ ] Visual mockup of the shell for review — in progress.
  - [ ] R0–R3 implementation — pending user direction.
- Effectiveness (assessed 2026-09-21): effective as a design record — grounded in a
  cross-tool UX review; awaiting direction before implementation.

### CC-UI-0019 — Proxy tab: Scope + Match-Replace (Phase 2.4; completes the workbench) (2026-09-21)
- Change: `ProxyController` gained live `scope_view` / `scope_add(host, path_regex?, exclude)`
  / `scope_remove(index)` over the engine's default-deny `Scope`, and `matchreplace_view` /
  `matchreplace_add(target, match, replace, header_name?, is_regex)` / `matchreplace_remove` /
  `matchreplace_toggle` over the ordered `MatchReplaceEngine`. Routes: `GET|POST
  /api/proxy/scope`, `DELETE /api/proxy/scope/{index}`, `GET|POST /api/proxy/matchreplace`,
  `DELETE /api/proxy/matchreplace/{index}`, `POST /api/proxy/matchreplace/{index}/toggle`
  (all 409 without the in-process proxy; a bad match-replace target / missing header_name →
  400). The Proxy tab's **Scope · Match-Replace** card lists/add/removes scope rules
  (host + optional path-regex, include/exclude) and match-replace rules (target, header,
  match→replace, regex, enable toggle); rows are DOM-built. Changes apply to subsequent
  proxied requests on the same event loop.
- Impact (other components / project): **completes the Proxy workbench** (History,
  Intercept, Repeater, Scope/Match-Replace) — realizing ask #2 of the revamp. Consumes the
  proxy `Scope`/`MatchReplaceEngine` unchanged; no schema change. Available only under
  `fuzzlab web --with-proxy` (else the card shows a start hint).
- Risk (level; mitigation): low — edits an opt-in, loopback, authorized proxy's config.
  Mitigated by tests: `tests/test_web_scope.py` (controller scope add/remove + in_scope
  effect; match-replace add/view/toggle/remove + a real rewrite via `engine.matchreplace.apply`;
  add-validation raises; routes 409 without proxy, scope add/remove + host-required 400,
  match-replace add/toggle/remove + bad-target 400). Suite 496 passed / 6 skipped.
- Deliverables:
  - [x] Controller scope + match-replace methods; routes — done.
  - [x] Scope / Match-Replace UI (list/add/remove/toggle) — done.
  - [x] Tests (controller effects + routes) — done; verified in a real browser (screenshot).
- Effectiveness (assessed 2026-09-21): effective — scope include/exclude and ordered byte
  rewrites are manageable live and take effect on the engine; the Proxy workbench is complete.

### CC-UI-0018 — Proxy tab: Repeater (replay tabs) (Phase 2.3) (2026-09-21)
- Change: added a `RepeaterController` (web) over the existing `Repeater` backend — its own
  `SocketSender` + lazily-opened store (created only on first write), `list_tabs` (all tabs,
  newest first, read-only), `create_tab`, `create_from_flow`, and `send` (byte-exact replay,
  `authorized`-gated by the route). Routes: `GET /api/proxy/repeater/tabs`, `POST
  /api/proxy/repeater/tabs`, `POST /api/proxy/repeater/from-flow/{flow_id}` (seed a tab from
  a History flow), `POST /api/proxy/repeater/tabs/{id}/send` (403 unless authorized; 404 for
  an unknown tab). These handlers are async so the controller's persistent SQLite connection
  is only touched from the event-loop thread. The Proxy tab's **Repeater** card renders a
  tabs dropdown, a new-tab form, an editable raw request, Send, and a response viewer; a
  History flow gains a "→ Repeater" button. **Bug fixed:** a `<textarea>` normalizes
  newlines to LF, which breaks HTTP framing — the client now restores CRLF (`toWire`) before
  sending an edited request (repeater **and** intercept-forward); the API stays byte-exact.
- Impact (other components / project): replay is available whenever authorized, independent
  of the in-process proxy; tabs persist in `repeater_tab` across sessions. Consumes the proxy
  `Repeater`/`SocketSender` unchanged; no schema change. Sending is the only traffic path and
  is gated.
- Risk (level; mitigation): low–medium — replay sends traffic. Mitigated by the authorized
  gate, and tests: `tests/test_web_repeater.py` (controller create/list/send-with-injected-
  sender/from-flow; routes list/create, send 403 gate + a real over-socket send to a threaded
  upstream + 404, from-flow 404) and a real-browser regression `tests/test_web_repeater_browser.py`
  (create + edit in a textarea + Send → the upstream echoes the edited target, proving the
  CRLF fix). Suite 490 passed / 6 skipped.
- Deliverables:
  - [x] `RepeaterController` + routes (tabs/create/from-flow/send) — done.
  - [x] Repeater UI (tabs, new-tab, editor, Send, response) + History "→ Repeater" — done.
  - [x] CRLF (`toWire`) fix for textarea-edited raw (repeater + intercept) — done.
  - [x] Controller/route tests + real-browser regression — done.
  - [ ] Scope / match-replace (Phase 2.4) — next.
- Effectiveness (assessed 2026-09-21): effective — verified in a real browser: create a tab,
  edit the raw request, Send, and see the upstream's response; and a flow seeds a tab via
  "→ Repeater". Screenshot captured.

### CC-UI-0017 — Proxy tab: live Intercept (pause/edit/drop/forward) (Phase 2.2) (2026-09-21)
- Change: added the intercept control surface. `ProxyController` gained `pending_view()`
  (JSON-safe held flows: id/direction/host/method/target + raw text), `forward(id, raw?)`
  (edit via `RawMessage.from_bytes(raw.encode('latin-1'))`), `drop(id)`, and
  `set_intercept_responses(on)` (status now carries `intercept_responses`). Routes:
  `POST /api/proxy/intercept` extended to toggle `on`/`responses`, `GET
  /api/proxy/intercept/pending`, `POST /api/proxy/intercept/{id}/forward` (optional
  `{"raw"}`), `POST /api/proxy/intercept/{id}/drop` — all 409 without an in-process proxy.
  The Proxy tab's **Intercept** card renders the request/response toggles, a polled pending
  table, and an editable raw-bytes textarea with Forward / Drop. Pending rows come from
  traffic (untrusted) so they're DOM-built with `textContent`.
- Impact (other components / project): realizes live pause/edit/drop/forward in the browser,
  backed by the in-process proxy (Phase 0.4) and the CC-PROXY-0015 response hook. Available
  only under `fuzzlab web --with-proxy` (else the card shows a start hint). No schema change;
  the UI writes no results.
- Risk (level; mitigation): low–medium — the panel can now alter live traffic. Mitigated by
  the proxy being opt-in + `--authorized`-gated, DOM-safe rendering, and tests:
  `tests/test_web_intercept.py` (controller pending_view/forward round-trip against a real
  paused flow, unknown-id benign, responses toggle; routes 409 without proxy and
  pending/forward/drop with a pre-built proxy) plus the engine + over-socket integration
  tests under CC-PROXY-0015. Suite 484 passed / 6 skipped.
- Deliverables:
  - [x] Controller pending_view/forward/drop/set_intercept_responses — done.
  - [x] Intercept routes; Intercept UI (toggles, polled pending, edit + Forward/Drop) — done.
  - [x] Tests (controller + routes); live over-socket + engine tests — done.
  - [ ] Repeater (Phase 2.3); scope / match-replace (Phase 2.4) — next.
- Effectiveness (assessed 2026-09-21): effective — verified in a real browser holding a real
  in-flight request ("intercept ON · 1 pending"), with the raw bytes editable and
  Forward/Drop; and over real sockets an edited request reaches the upstream. Screenshot
  captured.

### CC-UI-0016 — Proxy tab: read-only flow History (Phase 2.1) (2026-09-21)
- Change: added `fuzzlab/web/proxyview.py` (pure, store-backed `list_flows` + `flow_detail`
  over `flow`/`body`/`flow_fts`; newest-first, FTS search, and raw request/response decoded
  for display) and read routes `GET /api/proxy/flows[?q=]` and `GET /api/proxy/flows/{id}`
  (404 for a missing flow). The Proxy tab now renders a **History** sub-panel — a search
  box, a flows table (method/url/host/status/ms/protocol), and a req/resp viewer — plus a
  live proxy-status line. Flow url/host/head come from recorded traffic (untrusted), so the
  rows are built with DOM APIs + `textContent`, never interpolated HTML.
- Impact (other components / project): surfaces the proxy component's flow history in the
  panel; works cross-process (reads the store a running `fuzzlab proxy` / `web --with-proxy`
  writes). Read-only — never creates the store, sends no traffic, writes no results. No
  schema change; the proxy component is consumed unchanged.
- Risk (level; mitigation): low — read-only store reads and DOM-safe rendering (redacted
  bytes on write; `textContent` blocks stored-XSS from flow fields). Mitigated by
  `tests/test_web_proxy_history.py` (7: list newest-first, FTS query hit/miss, detail decode
  + 404, API list/search, API detail/404, missing-store empty + no-create, tab renders) and
  the real-browser smoke extended to switch to the Proxy tab, see a seeded flow, and open
  its detail. Suite 474 passed / 6 skipped.
- Deliverables:
  - [x] `web/proxyview.py` (list_flows / flow_detail) — done.
  - [x] `/api/proxy/flows[/{id}]` routes; Proxy-tab History UI + status line — done.
  - [x] Tests (view + routes + read-only invariant) + browser smoke — done.
  - [ ] Live intercept (edit/drop/forward), repeater, scope/match-replace (Phase 2.2+) — next.
- Effectiveness (assessed 2026-09-21): effective — recorded flows list and are searchable,
  and a flow's redacted raw request/response render; verified in a real browser.

### CC-UI-0015 — Activity Launcher UI: forms + dry-run + live output (Phase 1) (2026-09-21)
- Change: turned the read-only activity preview into an interactive **launcher**. The
  Launcher tab now renders a form per non-subcommand activity, server-side from each
  command spec — a widget per flag by type (text / number / `<select>` for choices /
  checkbox for bools / textarea for repeatables), keyed by argparse `dest`. `app.js` gained
  `collectValues` + `initLaunchForms`: **Dry-run** (`POST /api/launch/dry-run`) shows the
  exact command and sends nothing; **Run** (`POST /api/launch`) streams the child's output
  live via a named-event `EventSource` (`output`/`done`), with **Stop**. Traffic tools' Run
  is disabled unless `authorized`, and `--authorized` is pre-checked when the panel is
  authorized. Added a **D14 category picker** — the `--categories` flag renders as
  checkboxes from `known_categories()`, joined to a comma value. Added a **Plugins** panel +
  `GET /api/plugins` (the active entry-point set that `--plugins` would attach). Session
  (subparsers) renders as a CLI note, not a form.
- Impact (other components / project): realizes FR-UI-6 (launcher) and FR-UI-5 (dry-run) in
  the browser, and the D14 manual category selection. Consumes the Phase-0 endpoints and the
  command spec; no backend behavior/schema change beyond the read-only `/api/plugins`. The
  no-auto-run / loopback / authorized / read-only invariants hold (launch is explicit and
  gated; the UI writes no results).
- Risk (level; mitigation): low–medium — new client JS driving real launches. Mitigated by
  the gate (traffic Run disabled/refused without `authorized`), the declared-flags-only +
  no-shell runner (CC-UI-0013), and tests: `tests/test_web_frontend.py` extended (form per
  activity, dest-keyed fields, Run-button gating by authorization, category picker, plugins
  panel/endpoint, session-as-note) and a real-browser end-to-end smoke
  `tests/test_web_launcher_browser.py` (Chromium + uvicorn: fills the report form, asserts
  the dry-run preview `fuzzlab report --store x.db`, then Runs and sees output stream to
  `[exit …]` over SSE — skip-guarded when no browser). Suite 467 passed / 6 skipped.
- Deliverables:
  - [x] Per-activity forms (server-rendered from specs) + dry-run/run/stop wiring — done.
  - [x] Live SSE output in the browser; Run gated by authorization — done.
  - [x] D14 category picker; Plugins panel + `/api/plugins` — done.
  - [x] Frontend tests + real-browser end-to-end smoke — done.
  - [ ] Phase 2 proxy workbench; Phase 3 ML tab; Phase 4 diagnostics — next.
- Effectiveness (assessed 2026-09-21): effective — verified in real Chromium: the launcher
  builds each command from its parser, previews it on dry-run without traffic, and streams a
  gated run's output to completion. Screenshot captured for review.

### CC-UI-0014 — Unified serve mode: in-process proxy controller (Phase 0.4; D19) (2026-09-21)
- Change: added `fuzzlab/web/proxycontrol.py` (`ProxyConfig` + `ProxyController`) — it
  builds the proxy engine (Scope + `MatchReplaceEngine` + `Interceptor` + `SocketSender` +
  optional `HistoryWriter` + `LocalCA`) and owns its lifecycle. `create_app(..., proxy=)`
  gained a FastAPI **lifespan** that starts the controller on startup and stops it on
  shutdown, so the live interceptor shares the panel's event loop (its `asyncio.Future`s
  are not cross-process). New endpoints `GET /api/proxy/status` (dormant `{configured:
  false}` when no proxy) and `POST /api/proxy/intercept` (toggle; 409 when none). `serve()`
  takes an optional `proxy` and refuses a non-loopback proxy host; a new `web_main()` parses
  `fuzzlab web [--with-proxy …]` and, because the proxy forwards to upstreams, requires
  `--authorized` before wiring one (mirrors `fuzzlab proxy`). `fuzzlab web` now routes
  through `web_main` (`cli.py`).
- Impact (other components / project): the seam the **Phase-2 Proxy workbench** will use —
  its routes reach the live `Interceptor` via the controller (pause/edit/drop/forward),
  while flow history stays store-readable cross-process. Consumes the existing proxy
  component unchanged (no proxy code edited; the response-intercept hook is Phase 2). No
  schema change. The proxy is opt-in, `--authorized`-gated, loopback-only, on a separate
  port; without `--with-proxy` the panel is unchanged. Records D18 (subprocess launch, from
  0.3) and D19 (in-process proxy).
- Risk (level; mitigation): medium — the panel can now host a listener that forwards
  traffic. Mitigated by the authorization gate on `--with-proxy`, loopback-only binding for
  both the panel and the proxy (asserted; `serve` refuses non-loopback), the opt-in default
  (dormant unless asked), and tests: `tests/test_web_proxy_serve.py` (7) — controller
  start/status/stop on an ephemeral port, intercept toggle, dormant status + 409 without a
  proxy, lifespan start/stop via the TestClient context manager, `serve` refusing a
  non-loopback proxy host, and `web_main` refusing `--with-proxy` without `--authorized`.
  Suite 462 passed / 6 skipped.
- Deliverables:
  - [x] `web/proxycontrol.py` (build/start/stop/status/set_intercept) — done.
  - [x] Lifespan wiring + `/api/proxy/status` + `/api/proxy/intercept` — done.
  - [x] `serve(proxy=)` loopback guard + `web_main` (`--with-proxy`, authorized-gated) — done.
  - [x] D18/D19 recorded; tests — done.
  - [ ] Proxy workbench UI: history, intercept edit/drop/forward, repeater (Phase 2) — next.
- Effectiveness (assessed 2026-09-21): effective — the controller binds/stops cleanly in the
  app's loop, status/intercept reflect the live engine, and the gates hold. This completes
  the Phase-0 foundations; Phases 1–4 build the tabs on them.

### CC-UI-0013 — Launcher runner: dry-run + gated execution + SSE output (Phase 0.3) (2026-09-21)
- Change: added `fuzzlab/web/runner.py` and four launcher endpoints. `build_flags`/
  `build_argv`/`display_command` turn a `CommandSpec` + submitted flag values into an argv
  (`python -m fuzzlab.cli <name> <flags>`, mirroring the real CLI); `Runner` launches it
  with `asyncio.create_subprocess_exec` and streams stdout/stderr as SSE (`output` events
  then a `done` event with the return code), with `stop()` to terminate. Endpoints:
  `POST /api/launch/dry-run` (plans + returns the exact argv/display, sends nothing —
  FR-UI-5), `POST /api/launch` (no-auto-run gate: a `sends_traffic` activity is refused
  with 403 unless `authorized:true`), `GET /api/launch/{token}/stream` (SSE), and
  `POST /api/launch/{token}/stop`. Two safety properties by construction: **only flags the
  spec declares reach argv** (unknown `values` keys are ignored — no arbitrary-arg
  injection), and **no shell** is used (`create_subprocess_exec` with an argv list, so
  values can't be shell-interpreted).
- Impact (other components / project): the execution backbone for the Phase-1 launcher UI
  (forms → dry-run → gated run → live output). Runs each tool as its own subprocess, so the
  tools keep writing their own results (the UI writes none). No schema change. The UI does
  not send traffic on its own — only an explicit, authorized `POST /api/launch` of a
  traffic tool does.
- Risk (level; mitigation): medium — the panel can now spawn tools. Mitigated by the
  authorized gate (mirrors automatic mode), the declared-flags-only + no-shell properties,
  dry-run-first, and tests: `tests/test_web_runner.py` (12) — argv type mapping,
  unknown-key rejection, CLI-targeted argv, a real child-process stream asserting output +
  exit code, unknown-token stream, dry-run without executing, 400 unknown command, the 403
  traffic gate, launch returns a token, and stop of an unknown token. Suite 455 passed /
  6 skipped.
- Deliverables:
  - [x] `runner.py` (build_argv + async `Runner` + SSE stream + stop) — done.
  - [x] `/api/launch/dry-run`, `/api/launch`, `/api/launch/{token}/stream|stop` — done.
  - [x] Tests (pure argv, real-subprocess stream, endpoint gate) — done.
  - [ ] Launcher UI forms wired to these endpoints — Phase 1.
- Effectiveness (assessed 2026-09-21): effective — dry-run previews the exact command
  without traffic, the gate blocks unauthorized traffic tools, and a real child's output +
  exit code stream over SSE. HTTP-level SSE draining is validated live/in Phase 1 (reading
  an event-stream synchronously through TestClient is avoided; the Runner stream is tested
  directly).

### CC-UI-0012 — Frontend foundation: jinja2 + static assets + tab shell + SSE (Phase 0.2) (2026-09-21)
- Change: reworked `fuzzlab/web/app.py` from hand-rendered HTML f-strings to **jinja2
  templates** (`fuzzlab/web/templates/`: `base.html`, `index.html`, `run.html`,
  `not_found.html`; autoescaped) served alongside a **static asset pipeline**
  (`fuzzlab/web/static/app.css`, `app.js`) mounted at `/static`. The index is now a
  **tabbed shell** — Launcher / Proxy / Results / ML / Diagnostics — with all panels
  rendered server-side and a small vanilla-JS module toggling them (progressive
  enhancement: no-JS shows every panel). The Launcher tab previews every activity from the
  command-spec registry (CC-UI-0011) with gate pills; Results holds the existing runs
  dashboard; Proxy/ML/Diagnostics are stubs for Phases 2–4. Added `fuzzlab/web/sse.py`
  (`format_event`, `sse_response`) as the SSE plumbing for later live streams (first
  consumer: the Phase 0.3 runner). `jinja2` (already a declared `web` extra) is now used;
  FastAPI is imported at module scope so route `Request` annotations resolve. Templates and
  static files added to `[tool.setuptools.package-data]`.
- Impact (other components / project): UI-internal. No route/behavior change to the JSON
  API, no schema change, no traffic, and the read-only + loopback + no-auto-run invariants
  are unchanged (the only interactive form is still gated automatic mode). Sets up the
  Phase-1 launcher UI and the Phase-2/3/4 tabs.
- Risk (level; mitigation): low–medium — a rendering refactor of every panel. Mitigated by
  the unchanged launcher/results suites (13 tests: mode selection, 403-without-auth,
  injected-pipeline-not-run-on-load, loopback refusal, run-detail strings, empty-store
  no-create) plus new `tests/test_web_frontend.py` (10: static assets served, tab shell,
  activities preview, single-form invariant) and `tests/test_web_sse.py` (SSE formatting).
  Suite 443 passed / 6 skipped.
- Deliverables:
  - [x] jinja2 templates + `/static` pipeline; tab shell (5 tabs) — done.
  - [x] `fuzzlab/web/sse.py` + client `subscribe()` helper — done.
  - [x] Package-data for templates/static — done.
  - [x] Tests (frontend shell + SSE); existing web suites green — done.
  - [ ] Vendored charting lib (uPlot) — deferred to first use (Phase 4 diagnostics).
  - [ ] Launcher run controls (forms/dry-run/live output) — Phase 1 (needs the runner).
- Effectiveness (assessed 2026-09-21): effective — the panel renders as a tabbed shell with
  external CSS/JS, previews all activities from their parsers, and keeps every prior
  invariant; SSE plumbing is in place for the runner.

### CC-UI-0011 — Command-spec registry + `build_parser()` convention (Phase 0.1) (2026-09-21)
- Change: added `fuzzlab/web/commandspec.py` — a registry that introspects each launchable
  activity's own `argparse` parser into a machine-readable form schema
  (`OptionSpec`/`CommandSpec`: name, dest, type ∈ {bool,int,float,str,choice}, required,
  default, choices, multiple; plus per-command `sends_traffic`, `needs_authorized`,
  `destructive_gate`). The authorized/destructive gates are *derived* from the parser
  (presence of the flags), not restated. To supply the parsers without parsing, every tool
  now exposes a **`build_parser()`** returning its `ArgumentParser`; each `main()` delegates
  to it — a behavior-preserving refactor (see the per-component CC entries). This is the
  single-source-of-truth backbone for the Phase-1 launcher: a new tool flag appears in the
  UI automatically, with nothing hand-mirrored (PA-0001/PA-0003). Parsers are imported
  lazily and the registry survives a single tool's optional-dep import failure.
- Impact (other components / project): the launcher (Phase 1) renders controls from these
  specs. Touches the tool modules across CRAWL/AUD/FUZZ/MUT/PROXY/SESS + UI(report) to add
  `build_parser()` (CC-CRAWL-0006, CC-AUD-0014, CC-FUZZ-0018, CC-MUT-0007, CC-PROXY-0014,
  CC-SESS-0009). No CLI behavior, flags, or defaults change; no schema change; no traffic.
- Risk (level; mitigation): low — a refactor + a pure read-only introspection module.
  Mitigated by `tests/test_web_commandspec.py` (17 tests: type mapping in isolation,
  subparser recursion, long-flag naming, every activity builds + is JSON-serializable, the
  gate/traffic matrix, gates-derived-from-parser, defaults-read-from-parser-not-a-constant)
  and the unchanged full suite. Suite 433 passed / 6 skipped.
- Deliverables:
  - [x] `fuzzlab/web/commandspec.py` (introspection + registry) — done.
  - [x] `build_parser()` on all launchable tools; `main()` delegates — done.
  - [x] `tests/test_web_commandspec.py` — done.
  - [ ] Consume the spec in the launcher UI (Phase 1) — next.
- Effectiveness (assessed 2026-09-21): effective — the registry yields correct form schemas
  for all 10 activities from their real parsers, and the tests pin the mapping + the
  no-hand-mirror invariant.

### CC-UI-0010 — Web UI revamp implementation plan (design record) (2026-09-21)
- Change: added `docs/UI_REVAMP_PLAN.md` — the tracked design plan to take the read-only
  control panel to a full local control plane: (1) an activity launcher with per-tool
  flag forms, dry-run preview, and live output; (2) a proxy workbench (history, intercept
  edit/drop/forward, repeater, scope/match-replace); (3) a dedicated ML tab; (4) a
  TensorBoard-like diagnostics tab. Records the target tab architecture, the Phase-0
  foundations (jinja2 + vendored static assets + SSE; an argparse-introspecting command
  spec; a subprocess runner; a unified serve mode that hosts an in-process proxy for live
  interception), the honest exists-vs-needs-building split (most proxy/ML backends exist;
  time-series charts need a new `metric_series` table + per-step emitters), and how every
  new capability preserves the no-auto-run / loopback / authorized / read-only / redaction
  invariants.
- Impact (other components / project): design only — no code, no schema change. Scopes
  upcoming work across UI (#12), the intercepting proxy (#11 — a response-intercept hook),
  and core (#2 — a `metric_series` migration). New FR-UI entries and the two Phase-0
  decisions (UI-launches-tools-as-gated-subprocesses; unified-serve-in-process-proxy) will
  be recorded when Phase 0 lands.
- Risk (level; mitigation): none (documentation). The plan itself calls out the invariants
  each phase must preserve and the tests each ships with.
- Deliverables:
  - [x] `docs/UI_REVAMP_PLAN.md` recorded — done.
  - [ ] Phase 0 foundations (command spec, runner, frontend stack, unified serve) — next.
  - [ ] Phases 1–4 (launcher, proxy workbench, ML tab, diagnostics) — planned.
- Effectiveness (assessed 2026-09-21): effective as a design record — the plan is grounded
  in a full survey of the web/proxy/ML/instrumentation code and preserves the component's
  requirements (D11/D14/D15, NFR-UI-*).

### CC-UI-0009 — Reproducible evaluation report + `fuzzlab report` (T10.4) (2026-09-21)
- Change: added `fuzzlab/report/` — `build_report(store, run_id)` assembles a
  **deterministic** report from a stored run (run/config identity, target fingerprint,
  pipeline counts, confirmed findings, `run_metrics`, deployed models, and the active
  plugin set from migration 10), with every list stably sorted; `format_json` renders
  canonical (sorted-key) JSON for diffing, `format_text` a human summary. Wired as a
  read-only `fuzzlab report [--run latest|<id>] [--json]` command (dispatched from
  `fuzzlab/cli.py`).
- Impact (other components / project): the reproducibility artifact for Phase 10 — a run
  can be captured, diffed, and re-verified, and it records exactly what produced a result
  (config hash, feature/model versions, plugin set, schema version). Pure reads, no
  traffic; no schema change.
- Risk (level; mitigation): low — read-only, offline, deterministic. Mitigated by 6 tests
  (`tests/test_report.py`): captures run/target/counts/findings/metrics/models/plugins/
  reproducibility; canonical JSON is byte-identical across builds and valid; defaults to
  the latest run; empty store; text summary; and the `fuzzlab report` CLI (text + `--json`).
  Suite 381 passed / 4 skipped.
- Deliverables:
  - [x] `build_report` + `format_json`/`format_text` (T10.4) — done.
  - [x] `fuzzlab report` CLI dispatch — done.
  - [ ] Surface the report in the web panel — optional follow-up.
- Effectiveness (assessed 2026-09-21): effective in tests — the report renders
  deterministically over a run and names the versions/plugins that produced it; a live
  reproduce-a-run demonstration is part of the T10.6 exit.

### CC-UI-0008 — Panel surfaces advisory model scores (Phase 5) (2026-09-21)
- Change: `web/results.py::run_detail` now includes the latest `model` and the run's
  top advisory-scored candidates with their conformal flag/abstain/drop decision; the
  run-detail page renders a "Model scores (advisory)" card. Read-only.
- Impact (other components / project): the scores/triage the classifier writes
  (CC-ML-0003) are visible in the panel, clearly marked advisory (never findings).
- Risk (level; mitigation): low — read-only rendering. Mitigated by
  `tests/test_web_results.py::test_run_page_surfaces_model_scores`. Suite 192 passed / 2 skipped.
- Deliverables:
  - [x] `run_detail` model + scored candidates + decision; run-page card — done.
- Effectiveness (assessed 2026-09-21): effective — the run page shows scored candidates
  and their decision after a `--score` run.

### CC-UI-0007 — Web control panel: results review + full dashboard (D11) (2026-09-21)
- Change: built out the local web control panel beyond the Phase-0 launcher. Added
  `fuzzlab/web/results.py` (pure, store-backed `list_runs` / `run_detail` / `store_exists`)
  and expanded `fuzzlab/web/app.py` with a **runs dashboard** (index lists every run
  with its finding count), **run-detail** views (`GET /runs/{id}` HTML and
  `GET /api/runs/{id}` JSON) showing the score (TP/FP/FN/TN, precision/recall), the
  target fingerprint, dataset counts (candidates, negatives, evaluations, attempts,
  pages), the oracle findings table, and all run metrics, plus `GET /api/runs`. Manual
  mode now surfaces the selectable categories (D14) and the pre-wired commands use the
  `fuzzlab` CLI (crawl/audit/fuzz/auto). The panel is **read-only** over the store — it
  never creates the store file and never sends traffic (no-auto-run preserved).
- Impact (other components / project): turns the store into a reviewable dashboard —
  the results of any crawl/audit/fuzz/auto run (findings, negatives, fingerprint,
  score, request metrics) are browsable locally. Reads the store written by every
  other component; no schema change.
- Risk (level; mitigation): low — read-only and loopback-only (serve() refuses
  non-loopback). Store opened only when the file already exists (no accidental
  creation / no cwd pollution). Mitigated by tests: the existing launcher tests
  (no-auto-run, mode selection, 403 without authorization, injected pipeline) plus
  `tests/test_web_results.py` (results functions; `/api/runs`; run detail + 404; the
  run HTML renders findings + score; index runs table; missing-store shows no runs and
  creates no file). Suite 160 passed / 2 skipped.
- Deliverables:
  - [x] `web/results.py` (list_runs / run_detail) — done.
  - [x] Dashboard + run-detail HTML + `/api/runs[/{id}]` — done.
  - [x] Manual category surfacing; CLI-based pre-wired commands — done.
  - [x] Tests (results review; read-only/no-create invariant) — done.
  - [ ] Live use on the host (`fuzzlab web`, review real runs) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests and a rendered preview — runs
  list, run detail shows the score/fingerprint/findings/negatives/metrics, and the
  panel stays read-only and loopback-only.

### CC-UI-0006 — No-ground-truth fail-safe for automatic runs (spec) (2026-09-21)
- Change: added FR-UI-nogt (D15). An automatic run against a target with no
  ground-truth contract must not auto-select or test everything; it requires an
  explicit category selection, fails loudly if none is given, runs unscored
  (findings shown, no TP/FP/FN), and keeps all safety gates on. Complements D14
  (which covers the known-lab and manual cases). Spec only — no code.
- Impact (other components / project): governs automatic runs on external
  validation labs / unknown targets; the integration harness must skip scoring
  without ground truth (and never fabricate a score); ties to D10 external
  validation. Recorded as D15 + a cross-cutting safety principle in
  `DECISIONS_AND_ROADMAP.md` and `ARCHITECTURE.md`; `oracle-confirmation.md` and
  `PHASE_2_PLAN.md` (T2.10) updated.
- Risk (level; mitigation): this change reduces risk — it prevents a surprise
  "test everything" or a silent no-op against an unknown target. Residual risk is a
  missing/instructive error message; mitigated by fail-loud with clear guidance.
- Deliverables:
  - [x] FR-UI-nogt + D15 + cross-cutting principle recorded — done.
  - [ ] Implement: detect no ground truth; require categories; unscored run; gates — todo (Phase 2, T2.10).
- Effectiveness (assessed or pending): pending — spec. Judged when an automatic run
  on a no-ground-truth target fails loudly without `--categories` and runs unscored
  with them, gates on.

### CC-UI-0005 — Injection-category selection by run mode (spec) (2026-09-21)
- Change: added FR-UI-categories (D14) — automatic mode auto-selects injection
  categories from the lab's ground truth; manual mode presents a category selector
  and passes a `--categories` flag to the tools. The selection scopes the auditor's
  rules, payload sources, and which oracle `ConfirmationStrategy` classes run.
  Spec only — no code.
- Impact (other components / project): threads category scope from the launcher
  through the auditor (#5), payload catalogs (#6), and the oracle (#7,
  `architecture/oracle-confirmation.md`). Recorded as D14; no store-schema change.
- Risk (level; mitigation): low — a selection/scoping control; the default is
  conservative (automatic = exactly the ground-truth set; manual = only what the
  user picks). No-auto-run (D11) unchanged.
- Deliverables:
  - [x] FR-UI-categories + D14 recorded; oracle doc updated — done.
  - [ ] Implement the selector + `--categories` flag + ground-truth derivation — todo (Phase 2).
- Effectiveness (assessed or pending): pending — spec. Judged when the selector and
  flag land and a manual run tests only the chosen categories while an automatic lab
  run tests exactly the ground-truth set.

### CC-UI-0004 — Minimal web launcher + integration harness (2026-09-21)
- Change: built the Phase 0 minimal local web launcher (`fuzzlab/web/app.py`,
  FastAPI): a control panel that shows target/scope/mode and offers **automatic**
  vs **manual**, sending nothing to the target until the user acts; `serve()`
  binds to loopback only and refuses a non-loopback host. Automatic mode is gated
  on `authorized` and runs an injected pipeline callable. Added a `fuzzlab` CLI
  entry point (`web`, `crawl`, `audit`, `fuzz`, `build-db`, `version`) that also
  sends nothing on its own. Built the integration harness that automatic mode
  drives (T0.7): `fuzzlab/harness/scoring.py` (TP/FP/TN/FN + precision/recall/F1/
  MCC, matching by case key) and `integration.py` (`assert_known_vulns` reads the
  oracle's findings, scores against the ground-truth contract, records
  `run_metrics`). Realizes Phase 0 T0.9 and T0.7.
- Impact (other components / project): gives the project its no-auto-run entry
  point (D11) and its assert-known-vulns evaluation. The harness reads LAB's
  ground-truth contract (CC-LAB-0002) and the oracle's `finding` rows (self-
  describing via CC-CORE-0003). The pipeline runner is injected, so the crawler →
  auditor → fuzzer wiring drops in once the tools write to the store (T0.8).
- Risk (level; mitigation): low–medium. A local web server is a surface; mitigated
  by loopback-only binding (asserted, with a non-loopback refusal), the
  authorization gate on automatic mode, and the invariant that loading the panel
  runs nothing (a test asserts the injected pipeline is not called on GET). Harness
  correctness is covered by scoring tests (perfect run, misses, false alarms,
  wrong-class-on-right-param, and a store round-trip).
- Deliverables:
  - [x] Minimal web control panel with automatic/manual selection (T0.9) — done.
  - [x] Loopback-only serve with non-loopback refusal (T0.9) — done.
  - [x] `fuzzlab` CLI entry point + headless tool passthrough — done.
  - [x] Integration harness: scoring + assert-known-vulns + run_metrics (T0.7) — done.
  - [x] Web (6) + harness (5) tests passing — done.
  - [ ] Wire the real crawler→auditor→fuzzer pipeline into automatic mode — todo (needs T0.8).
  - [ ] Full dashboard (live runs, results tables) — todo (later UI phase).
- Effectiveness (assessed 2026-09-21): effective — panel offers both modes and
  stays idle on load; automatic mode is blocked without authorization and runs the
  injected pipeline only on explicit POST; harness scores a seeded store run as a
  pass with correct metrics. Real-pipeline wiring pending T0.8.

### CC-UI-0003 — Primary UI is a local web app, not a `textual` TUI (2026-09-21)
- Change: adopt decision D11 — the primary interface becomes a **local web
  application** (control panel + dashboard on localhost) instead of a `textual`
  TUI. The no-auto-run launcher (CC-UI-0002) now lives on the web page; the
  `textual` TUI is dropped as the primary UI. A plain CLI entry point per tool is
  kept for headless/automation use (FR-UI-cli). Datasette stays for deep store
  exploration. Adds NFR-UI-localhost (loopback-only, never exposed, separate from
  the target). Supersedes FR-UI-1 (was a `textual` TUI) and the TUI parts of
  CC-UI-0001/CC-UI-0002.
- Impact (other components / project): confined to this component and the docs —
  `DECISIONS_AND_ROADMAP.md` (new D11; Phase 6 UI line; deferred-list wording),
  `ARCHITECTURE.md` (component map, component #12, no change to the store
  contract), and `PHASE_0_PLAN.md` (T0.9 becomes a minimal local web panel). No
  other component's interface changes; the web app remains a `core/` store reader
  that orchestrates the tools in automatic mode. Reason: results and output are far
  easier to review in a browser, and it composes with the already-planned Datasette.
- Risk (level; mitigation): low–medium. A local web server is a new surface;
  mitigated by binding to loopback only, never exposing it, and serving it
  separately from the vulnerable target (different origin/port; never in the
  target's web root) so the control plane is never confused with, or an attack
  path into, the system under test. The no-auto-run guarantee is unchanged.
- Risk justification (accepted): a web app is more implementation work than a TUI;
  accepted for far better result review and reuse of the Datasette web view. Exact
  stack is deferred to build time.
- Deliverables:
  - [ ] Minimal local web control panel hosting the automatic/manual launcher — todo (Phase 0 T0.9).
  - [ ] Loopback-only binding, separate origin/port from the target — todo (Phase 0 T0.9).
  - [ ] Plain CLI entry point per tool (headless) — todo (Phase 0).
  - [ ] Full web dashboard (live runs/interception/results) — todo (later UI phase).
  - [ ] Confirm web stack (FastAPI/Flask + frontend; Datasette embed vs link) — todo.
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  results being reviewable in the browser and the panel being reachable only on
  localhost, with the no-auto-run guarantee intact.

### CC-UI-0002 — Launcher with run-mode selection; no auto-run (2026-09-21)
- Change: add a launcher as a UI subcomponent (FR-UI-launcher, NFR-UI-no-auto-run).
  Bringing up the lab no longer starts tool traffic; instead a UI offers two run
  modes — automatic (run the pipeline + integration harness against the lab) or
  manual (leave the lab up and expose the tools for hand-driven use) — and nothing
  is sent to the target until the user chooses. A minimal launcher lands in
  Phase 0 (T0.9); the full `textual` TUI elaborates it later.
- Impact (other components / project): establishes a project-wide "no auto-run"
  principle (recorded in `DECISIONS_AND_ROADMAP.md` cross-cutting principles,
  `ARCHITECTURE.md` integration model + Security-and-safety, and `PHASE_0_PLAN.md`
  Goal/T0.7/T0.9/exit criterion). Gives this component an orchestration role in
  automatic mode (it invokes crawler → auditor → fuzzer → harness), beyond
  read-only diagnostics; those tools still write their own results. No change to
  the store contract or to other components' interfaces.
- Risk (level; mitigation): low, and safety-reducing on balance — the change
  removes an implicit auto-run and puts the user in control of when tools touch
  the target. Residual risk is a mode selector that mis-wires the target/store in
  manual mode; mitigated by pre-wiring from the same `core/` config the automatic
  path uses, and by `--dry-run`.
- Deliverables:
  - [ ] Minimal launcher with automatic/manual selection — todo (Phase 0 T0.9).
  - [ ] Manual mode: print pre-wired ready-to-run commands / interactive shell — todo (Phase 0 T0.9).
  - [ ] Automatic mode: invoke the pipeline + integration harness — todo (Phase 0 T0.7/T0.9).
  - [ ] Full launcher/mode UI folded into the `textual` TUI — todo (later).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  bring-up stopping at the launcher with zero requests to the target until a mode
  is chosen, and by both modes behaving as specified.

### CC-UI-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented;
  today's observability is per-tool stdout plus the root `CHANGELOG.md`/
  `ERROR_LOG.md`.
- Impact (other components / project): read-only over the store, so it adds no
  hard dependency for any tool; it relies on `core/`'s store and structured
  logging existing. Adds a `run_metrics` table to the store contract. Realizes the
  research-platform diagnostics posture (D2) used to verify functionality and find
  bugs.
- Risk (level; mitigation): low — read-only and off the data path. Main risk is
  rendering secrets; mitigated by redaction-on-write in `core/` and a
  render-redacted-only rule here.
- Deliverables:
  - [ ] `textual` TUI for live runs/interception — todo.
  - [ ] Datasette-over-the-store exploration — todo.
  - [ ] `run_metrics` table — todo.
  - [ ] Structured audit/debug logs (`run_id`/`tool`/`identity`/`flow_id`) — todo.
  - [ ] `--dry-run` mode — todo.
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  whether a live run is legible in the TUI and bugs are locatable from the store
  and logs without instrumenting each tool by hand.
