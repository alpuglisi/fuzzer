# Web UI — implementation plan for the remaining work

**Status: fully task-broken-down with a parallel lane map, 2026-09-21.** Companion to
`docs/UI_REVAMP_PLAN.md` (feature phases) and `docs/UI_LAYOUT_REDESIGN.md` (layout/IA), and
the UI-side peer of `docs/LAB_IMPLEMENTATION_PLAN.md`. It carries the settled build policy,
the outstanding deliverables (each clear, concise, and executable), and a lane/dependency map
sized for maximum concurrent agent dispatch under this project's standing multi-lane policy.

Research markers `[R-nn]` flag places that need external research, added context, references,
or more clarity; they are gathered in **§5 Research queue** and resolved in refinement rounds
(**§6 Refinement log**).

---

## 1. Build policy (settled 2026-09-21)

**One line:** *No build step, ever; everything stays offline and loopback-only; hand-roll where
vanilla is cheap (tables, filters, layout, theming); vendor exactly one zero-dependency static
file only where hand-rolling is genuinely expensive (interactive charts).*

Locked decisions:

| # | Decision | Consequence |
|---|---|---|
| D1 | **MPA routes** (retire hash-tabs) | U0 splits each section behind a real route |
| D2 | **Vendor one zero-dep charting lib** → **uPlot 1.6.32** (MIT, ~16 KB gz) (R-02) | U5 charts; no bundler, offline |
| D3 | **Split assets, no bundler** (per-section ES modules + CSS partials) | makes U1–U5 file-independent |
| D4 | **Hand-roll** tables/filters | U2 + store explorer, no table dependency |
| D5 | **Include `lab-generate`** in the launcher, own group | X0 |

## 2. Non-negotiable invariants (must survive every lane)

- **No-auto-run** — nothing hits the target except by an explicit user action.
- **Loopback-only** — the panel and the in-process proxy bind to 127.0.0.1 only.
- **Authorized gate** — traffic-sending actions require `authorized: true` (+ `--authorized`).
- **UI writes no result tables** — tools write `finding`/`attempt`/`candidate`/flows; the UI
  reads. The one exception already sanctioned is `run_metrics` / (new) `metric_series` emitted
  by the components themselves, never by the UI.
- **Secrets never render** — redaction on write; the UI shows redacted values only.
- **No build step; fully offline** — no CDN, no bundler; every asset served from `/static`.
- **Accessible + keyboard-operable** — WCAG 2.2 AA target; native semantics over ARIA widgets;
  meaning never by color alone; contrast verified per theme (see R-11 below).
- **Not itself an attack surface** — the new POST surface is guarded by Host/Origin/Fetch-Metadata
  validation + a tight CSP so a hostile web page can't drive it (U6 / R-13); this operationalizes
  NFR-UI-localhost.

> ✅ **[R-11 resolved · round 3]** **Accessibility (cross-cutting; WCAG 2.2 AA).** **DataTable =
> native `<table>`, NOT `role="grid"`** (grid forces an arrow-key composite-widget model wrong for
> read-only sort + row-link): `<caption>`, `<th scope>`, a sort `<button>` inside each `<th>` with
> single-active `aria-sort`, a real `<a href="/finding/{id}">` in the primary cell (whole-row click
> is a JS enhancement, never the only path), specifically-named row-action buttons, + a
> visually-hidden `aria-live="polite"` sort announcer. **Facets = APG Disclosure** (header `<button
> aria-expanded aria-controls>` → hideable panel) + native checkboxes with the **count inside the
> `<label>`**, grouped via `fieldset`/`role=group`. **Chips** = `role=group` "Applied filters"; each
> a `<button aria-label="Remove filter: …">` (× is `aria-hidden`); **move focus on removal** (never
> to `<body>`); "Clear all"; a live match-count region. **Splitter = APG Window Splitter**:
> `role="separator" tabindex=0`, `aria-controls`, `aria-valuemin/max/now`,
> `aria-orientation="vertical"` + **Left/Right** arrows for side-by-side panes (Home/End; optional
> Enter-collapse / F6). **Textarea:** labelled, `spellcheck/autocorrect/autocapitalize=off`, **Tab
> not trapped** (2.1.2). **Charts:** `<canvas aria-hidden="true">` + a sibling **visually-hidden
> `<table>`** (clip method + `white-space:nowrap` so it can't cause page scroll; never
> `display:none`) inside a `<figure>` with `<figcaption>` + a one-line text summary; optional "View
> as data table" disclosure. **Shell:** skip-link → `<main id="main" tabindex="-1">`, one `<h1>`/
> page, landmarks with unique labels, `nav` `aria-current="page"` (+ a non-color indicator),
> `:focus-visible` ring ≥2px meeting 3:1 in **both** themes, no focus traps (rely on the browser's
> native focus reset on real navigations — don't script focus-on-load for a true-routes MPA).
> **Color:** 4.5:1 text / 3:1 non-text; **severity/status = text (+shape), never hue alone**; verify
> each severity/status/focus token's ratio **per theme** (an explicit acceptance criterion); respect
> `forced-colors`. Build one shared `aria-live` results region + sort announcer at page load.

## 3. Outstanding deliverables

Each block: **scope** (what to build), **files** (surface it touches — the unit of lane
independence), **depends on**, **sub-lanes** (recursive independent splits), **acceptance**
(how "done + validated" is judged). IDs match the tracked task list.

### U0 — MPA routes + asset split  *(enabling refactor; Wave 0; one agent)*
- **Scope:** replace the hash-switched single page with real per-section routes; retire
  `initTabs`. Split `index.html` into per-section templates, `app.js` into per-section ES
  modules, `app.css` into per-section partials. Sidebar links become real `href`s with
  server-rendered active state.
- **Files:** `app.py` (routes + per-view context), `base.html` (nav active state), split
  `templates/index.html` → `templates/sections/*.html`, `static/app.js` → `static/js/*.js`,
  `static/app.css` → `static/css/*.css`.
- **Depends on:** — . **Sub-lanes:** none (it is the serialization-breaker).
- **Acceptance:** every section reachable at its own URL; deep-links work; no-JS renders each
  section; existing web tests pass (updated for routes); real-browser nav smoke passes.
> ✅ **[R-01 resolved · round 1]** **Full-page MPA navigation; do NOT vendor HTMX.** On loopback
> a full-page GET is sub-millisecond, so HTMX's no-reload benefit is moot, and it would *add* an
> `HX-Request` partial/full code path rather than remove one — the vendoring trigger isn't met.
> **Pattern:** `base.html` shell + one template per section; a single `NAV = [(id,label,href),…]`
> source of truth passed with an `active` id, compared in the nav loop for server-rendered active
> state (`aria-current="page"`). Use the modern `TemplateResponse(request, name, ctx)` signature
> (request first). Deep-linking, back/forward, and no-JS degradation come free (native `<a>`/
> `<form>`). **Keep the existing no-FOUC inline `<head>` script** — under MPA it runs on every
> page load, which is required (a stored theme/density would otherwise flash); it's a per-page
> inline snippet, not a vendored lib, so it's within policy. Revisit HTMX only for a future
> per-widget *live/partial* need (e.g. streaming a running job's output), never for section nav.
> ✅ **[R-07 resolved · round 2]** **Cross-section pivots & state (pattern for all lanes).**
> State-mutating pivots (Findings "send to Repeater" / "open request") = **Post/Redirect/Get with
> 303**: the row is a `<form method="post">` → `POST /proxy/repeater/from-flow` calls the existing
> `create_from_flow(flow_id)` (whose SQLite tab row *is* the handoff) → **`RedirectResponse(...,
> status_code=303)`** to `/proxy?repeater_tab=ID`. (FastAPI's default 307 re-POSTs to the GET route
> → 405; 303 forces GET, keeps the POST out of history, makes refresh safe.) **Never put seed bytes
> in the URL** — they carry Authorization/Cookie/token and URLs leak via logs/history/Referer; keep
> real bytes server-side (redaction is a render-time transform) and put only the opaque tab id on
> the wire. **State decision rule:** deep-linkable view or pointer to shared data → **URL query**
> (`?view=`, filter, sort, `?sel=id`); durable/sensitive content → **server/SQLite**; per-viewer
> convenience (scroll, drafts, column widths, collapsed groups) → **session/localStorage**. Detail
> = real route `/findings/{id}`; a highlight = `?sel=id`. Treat every `?…=ID` as a **hint** (fall
> back to default; never 404 the page). Guard double-submit (disable-on-submit; optional idempotency
> key). Back/Forward + per-state restore come free from real GET URLs — the MPA payoff.

### U1 — Overview dashboard  *(Wave 1)*
- **Scope:** landing route (`/`): KPI row (recent runs, findings by severity, last-run score),
  recent-runs list, quick actions (launch auto / open proxy). Read-only over the store.
- **Files:** `sections/overview.html`, `js/overview.js`, `css/overview.css`, `app.py` route.
- **Depends on:** U0. **Sub-lanes:** KPI tiles / recent-runs / quick-actions.
- **Acceptance:** renders with an empty store and with seeded runs; no result-table writes.
> ↳ **See [R-03]** (U2) for the reusable read-only DataTable this reuses for recent runs.
> ✅ **[R-10 resolved · round 2]** **Overview spec.** KPI tile row (5, big numbers, each clickable →
> filtered view): (1) **Findings** = `len(findings)` + severity-split sub-line; (2) **Runs** =
> `len(runs)` + "N in last 7d"; (3) **Last run** = newest run's status badge + tool→target +
> relative time; (4) **Detection quality** = latest *completed* run `scores.F1` (sub: MCC or P/R;
> em-dash if unscored); (5) **Efficiency** = `run_metrics.requests_per_finding` (sub: total
> requests). Panels: **A — Recent runs table** (primary; MLflow/W&B pattern; ~10 newest, row → run
> detail; the shared DataTable minus the sidebar); **B — Findings by severity** as a horizontal
> segmented/stacked bar (uPlot is poor at donuts) + an optional uPlot **sparkline** of F1- or
> findings-per-run (the cheap "trend" panel, uPlot already loaded); **C — Quick actions** (primary
> Launch auto, secondary Open proxy, tertiary Model registry / Compare). Serve from **one aggregate
> endpoint** (counts + pre-aggregated findings-by-severity + latest ~10 runs joined) — no heavy
> per-run joins on load. **Skip** (enterprise noise): asset inventory, SLA countdowns, remediation
> tickets, compliance widgets, scheduled-scan calendars. **Empty state** (0 runs) = one centered
> onboarding card ("No runs yet" + a primary Launch-auto action), not a grid of zeros;
> **partial-empty** (unscored) = em-dash in tiles 4/5, never `0`. Reuse severity/status color tokens.

### U2 — Findings workbench  *(Wave 1)*
- **Scope:** faceted filters + saved views over `finding`/`attempt`; list→detail; "send to
  Repeater / open request" pivot. Render multi-artifact ground truth from the LAB push
  (`primary_endpoint`, `primary_role`, `related_endpoints`, `flow_variant`) in the detail.
- **Files:** `sections/findings.html`, `js/findings.js`, shared `js/datatable.js`,
  `css/findings.css`, `app.py` read route(s).
- **Depends on:** U0. **Sub-lanes:** facets / saved-views / detail+related-endpoints.
- **Acceptance:** filter + saved-view round-trip; DOM-safe rendering of untrusted fields;
  "send to Repeater" seeds a tab; reads only.
> ✅ **[R-03 resolved · round 1]** **Findings workbench:** collapsible **left facet sidebar**
> (multi-select checkboxes **with live counts** — OR within a group, AND across groups; ~4–6
> groups: vuln class, severity, method, confidence/mechanism, endpoint) + a top **quick-filter**
> (debounced substring over url/param/endpoint) + **applied-filter chips** (per-chip × + "Clear
> all") + a **saved-view** chip row. Severity color tokens everywhere (Critical=red, High=deep-
> orange, Med=orange, Low=amber, Info=blue — ZAP/CVSS convention; render as a **badge**, not just
> colored text). **Saved views live server-side in SQLite** — `saved_views(id, table_key, name,
> spec_json, is_pinned, created_at, updated_at)` via `GET/POST/PUT/DELETE /api/views?table=` —
> durable + backend-readable; `localStorage` (try/catch) holds only throwaway per-viewer state
> (last view id, draft filter text, collapsed groups). `spec_json` = `{version, name, pinned,
> filter:{text, facets:{}, predicates:[{field,op,value}]}, sort, columns}` (facets OR/AND as
> above; Tenable-style predicates ship later). **Shared hand-rolled `DataTable`** (reused by U1
> recent-runs and U5 store explorer, *minus* the sidebar): in-memory **filter→sort→fragment-
> render**, **no virtualization** (a few thousand rows are fine; cap/paginate is the only
> escalation lever). Every cell value via **`textContent`** (never innerHTML — untrusted url/param/
> payload); pivots go through a JS handler and any rendered `<a href>` is **scheme-checked (http/
> https only)** to block `javascript:`/`data:`. API: `columns[]` (`render`→Node/primitive +
> `sortValue`), `data`, `onRowClick`, `rowActions` ("send to Repeater / open request"),
> `textFilterKeys`; severity/confidence sort via a fixed rank map.

### U3 — Proxy workbench rebuild  *(Wave 1)*
- **Scope:** re-lay the existing Proxy (History / Intercept / Repeater / Scope+Match-Replace,
  already built in Phase 2.1–2.4) on a shared HTTP **message editor** + resizable panes +
  sub-nav in the design system. Backend unchanged (RepeaterController now thread-safe,
  BUG-0021).
- **Files:** `sections/proxy.html`, `js/proxy.js` (+ `js/msgeditor.js` shared), `css/proxy.css`.
- **Depends on:** U0. **Sub-lanes:** message-editor / resizable-panes / sub-nav.
- **Acceptance:** all four sub-views work as before (live-intercept + repeater browser tests
  green); byte-exact editing preserved (CRLF `toWire` retained); redaction intact.
> ✅ **[R-04 resolved · round 1]** **One shared `<message-editor>` ES module** (Intercept +
> Repeater): `{editable, bytes, meta}` in, `getBytes()` out. Request (editable) | Response
> (read-only) + horizontal/vertical layout toggle; per-pane **Raw | Pretty** (+ read-only **Hex**
> on the response); **Raw is the only editable mode and the default** (Pretty never round-trips
> bytes). Add a status/timing strip (status+reason · ms · byte length · content-type), Ctrl-F
> in-message search (paint via CSS Custom Highlight ranges over a read-only mirror — never
> span-inject the buffer), and a CRLF/non-printing-char toggle. **Skip:** Render tab, Burp
> Inspector, editable Hex (v1). **Resizable splitter = vanilla**: CSS grid with one rewritable
> `--a` track + a pointer-capture handle (~15 lines; `min-*:0`, `touch-action:none`, arrow-key
> a11y, persist px to localStorage) — no lib. **Highlighting verdict: HAND-ROLL, do NOT vendor.**
> Keep the editable buffer a plain monospace `<textarea>` (its `.value` is the byte-exact source
> of truth); `contenteditable` and the CSS Custom Highlight API are byte-hostile / can't target a
> textarea → disqualified for the editable pane. v1 = plain textarea; optional v1.5 = a
> "backing-`<pre>` overlay" (transparent textarea over an `aria-hidden` `<pre>` fed by a ~50-line
> HTTP/JSON tokenizer) — cosmetic color that can't touch bytes; `getBytes()` reads the textarea
> only. Keep the existing `toWire` CRLF-restore as the single documented `\r\n`→`\n`
> normalization point; verify no lone-`\r`/NUL via the Hex view.

### U4 — ML tab  *(Wave 1; feature Phase 3)*
- **Scope:** read-only surfacing of model internals already in the store — classifier
  metrics/calibration/weights, ranker (nDCG/precision + score distributions), conformal
  flag/abstain/drop, anomaly, active-learning disagreement, bandit posteriors (Beta), mutation
  variants. Kept separate from the primary panel.
- **Files:** `sections/ml.html`, `js/ml.js`, `css/ml.css`, `app.py` read route; charts via the
  vendored lib (D2).
- **Depends on:** U0 (+ D2 lib chosen). **Sub-lanes:** one panel per model family.
- **Acceptance:** renders from a seeded store; advisory framing (never presents scores as
  labels); reads only.
> ✅ **[R-06 resolved · round 1]** **ML tab = read-only, advisory.** Cross-cutting: a persistent
> (non-dismissible) banner "Model output is advisory; confirmed findings come from the oracle";
> every score shows an uncertainty companion + N + data split + an inline **baseline**; lead with
> **categorical bands** (flag/review/abstain/drop), raw numbers on hover; verb hygiene
> ("scored/ranked/flagged", never "detected/vulnerable/confirmed"); a neutral blue/amber palette
> so ML panels never read as the oracle's red/green. Panels (each reduces to line/bar/scatter/
> histogram + reference line, or a colored table; fed from stored fields with only trivial client
> math): **PR curve** + operating point w/ prevalence baseline; **reliability diagram** (binned,
> 45° line, count-hist below) + ECE — the advisory anchor; **logistic weights** diverging bar
> (log-odds; global β vs per-instance β·x, labeled separately); **nDCG@k / precision@k vs random**
> grouped bars; **rank score & uncertainty** histograms (+ score-vs-uncertainty scatter);
> **conformal flag/abstain/drop** stacked bar (tab summary) + nonconformity histogram w/ threshold
> lines; **anomaly (ECOD)** score histogram + threshold/flagged-rate ("unusual ≠ malicious");
> **committee disagreement** histogram + top-N query queue (collapse if AL isn't daily); **bandit
> Beta posteriors** overlaid density per arm (~15-line lgamma on a ~200-pt grid) + a forest/
> interval table (mean ±90% CI, pulls, cost) as the default view; **mutation variants**
> killed/survived table + score. **Omit** as single-user noise: ROC, confusion-matrix heatmaps,
> multi-model leaderboards, animated posteriors, interactive re-thresholding sliders (read-only!),
> per-feature drill-downs (expander only). Lead the tab with banner + flag/abstain/drop split +
> calibration diagram.

### U5 — Diagnostics + store explorer  *(Wave 1; feature Phase 4a)*
- **Scope:** cross-run trend lines over `run_metrics`, intra-run series (via `created_at`, and
  `metric_series` once B0 lands), distributions/snapshots (candidate scores, bandit arm state,
  model registry timeline), and a lightweight read-only **store explorer** (FR-UI-2).
- **Files:** `sections/diagnostics.html`, `js/diagnostics.js`, shared `js/chart.js` (vendored
  lib wrapper) + `js/datatable.js`, `css/diagnostics.css`, `app.py` read routes.
- **Depends on:** U0 (+ D2 lib). Enriched by B0 but not blocked by it. **Sub-lanes:** per chart
  group / store explorer.
- **Acceptance:** charts render from existing `run_metrics` with no new backend; dark-mode +
  density correct; store explorer is strictly read-only and injection-safe.
> ✅ **[R-02 resolved · round 1]** **uPlot v1.6.32** (MIT, zero deps, ~16 KB gz; canvas). Vendor
> **two static files** — `uPlot.esm.js` + `uPlot.min.css` — into `/static/vendor/uplot/` and
> `import` the ESM directly from a vanilla module (no build). Beat-outs: Chart.js's ESM needs an
> import map or a 2nd vendored file; Plotly is ~22× the gz size; Frappe/SVG dies at thousands of
> points; hand-rolled SVG is fine only for sparklines. One lib covers trends, intra-run/training
> curves, distributions (`uPlot.paths.bars()`), and KPI sparklines (axes/legend/cursor off), with
> built-in hover + drag-zoom. **Gotchas that shape U5:** canvas can't read CSS vars — read tokens
> via `getComputedStyle`, pass as options, and **rebuild on theme change** (MutationObserver on
> `[data-theme]` + `matchMedia`); the legend/cursor/axis DOM *does* honor CSS. Data is **columnar**
> (`[xs, ys…]`); x in **unix seconds**. a11y: canvas is opaque to screen readers → ship a shared
> "chart + offscreen `<table>` fallback" component. Pin 1.6.32. `dataviz` skill governs palette.
> ✅ **[R-05 resolved · round 1]** **Diagnostics UX.** Panels: cross-run scalar trends (overlay
> one line per run), intra-run step series & training curves (train/valid loss, grad_norm),
> bandit cumulative-regret + per-arm posterior-mean with a min/max CI band, coverage-growth,
> pre-binned distributions, model-registry timeline. Controls (the value — all three big tools
> have them): run multi-select w/ per-run color; metric picker grouped by `source` (collapsible)
> + substring filter; **EMA smoothing slider** 0–0.99 applied **client-side after downsampling**
> (must be instant); x-axis toggle step | relative-time | wall-clock; y-axis log toggle.
> **Skip** (multi-tenant/scale overkill): auth/sharing, alerting, reports/notes, HP-sweep
> parallel-coords, system metrics, media logging, websocket streaming (manual refresh — or a
> light poll only while a run is active — suffices offline). **Render order: downsample
> server-side → send → EMA client-side.**
> ✅ **[R-12 resolved · round 3]** **Shared `createChart(el, {id, type, data, series, opts})`
> wrapper** (consumed by U4 + U5). **Theme/density change → full `destroy()` + recreate** (uPlot
> bakes colors into the canvas at draw and measures axis geometry at construction; density also
> changes axis sizing) — `setData()` for data-only, `setSize()` for resize. **Resolve tokens via a
> hidden probe** (`probe.style.color='var(--tok)'` → `getComputedStyle(probe).color` → concrete
> `rgb()`), because `getPropertyValue('--tok')` yields unresolved `color-mix()`/`var()` chains the
> canvas can't parse; use `getPropertyValue`+`parseFloat` only for numeric tokens. **Density →
> discrete sizing buckets** off `data-density` (comfortable/compact: font 12/11, x-gutter 34/28,
> y-gutter 50/44, tick 6/4, gap 6/4, tick-space 60·40 / 48·30, point 5/4); use uPlot's **HTML
> legend** (DOM → inherits tokens) with line-height tied to `--row`; height from a per-density
> `--chart-h` token. **Responsive:** debounced **`ResizeObserver` on the parent cell** (not the
> uPlot root — feedback loop), coalesced with `requestAnimationFrame` (dodges the RO-loop warning) →
> `setSize`; re-`resize()` when a hidden panel is revealed. **Retheme** wires BOTH a MutationObserver
> on `<html>` (`data-theme`/`data-density`) and `matchMedia` to one idempotent handler; preserve
> x-zoom (`scales.x.min/max`) and series toggles across rebuild. **Teardown (critical — RO/MO hold
> refs → leak):** `destroy()` disconnects RO+MO, removes the matchMedia listener, cancels rAFs, calls
> `u.destroy()`, drops the id from the registry. **`window.__charts`** = a Map id→handle (`getData()`
> + live `.u`) for the R-09 tests; each chart also builds a `visually-hidden` `<table>` (canvas
> `aria-hidden`, wrapper `role="img"`+label, ~200-row cap), kept current on `setData` — the R-09
> fallback + R-11 a11y surface.

### B0 — `metric_series` table + emitters  *(Wave 0; backend; feature Phase 4b)*
- **Scope:** additive migration `metric_series(run_id, source, key, step, ts, value)`; then
  per-step emitters — GBT/logistic (training curves), the bandit loop (posterior/regret),
  coverage frontier (growth), `MutationSearch` (reward/novelty), stage wall-clock/throughput.
  Optional: a queryable log sink.
- **Files:** `core/store.py` (migration), emitters in ML / SCHED / MUT / greybox / FUZZ. **No UI
  files** — fully independent of the shell.
- **Depends on:** — . **Sub-lanes:** table first, then one emitter per component in parallel.
- **Acceptance:** migration is additive + reversible-safe; each emitter unit-tested; existing
  suites unaffected.
> ✅ **[R-05 resolved · round 1]** Our `(run_id, source, key, step, ts, value)` matches MLflow's own
> `metrics` shape — correct model. Refinements: `run_id INTEGER REFERENCES runs(id)`; `value REAL
> NOT NULL` and **reject non-finite at emit** (drop + warn; no `is_nan` column, no NaN read-branch);
> `source` = subsystem bucket mirroring existing `run_metrics` prefixes (`gbt`, `logreg`, `bandit`,
> `coverage`, `rank`, `ml`); `key` = slash-delimited path (`train/loss`, `regret/cumulative`,
> `posterior/arm_3/mean`, `coverage/lines`); indexes `(run_id,source,key,step)` [one series] and
> `(source,key,run_id,step)` [cross-run overlay]; **keys must be bounded** (no per-example/feature
> keys; distributions stored **pre-binned**). **Read-side downsampling = LTTB** (~1000 pts/series;
> preserves loss spikes / regret jumps that bucket-averaging erases), ~30 lines pure Python
> server-side; offer a min/max-per-bucket **envelope** mode for the bandit CI band. Emitter API:
> `log_scalar(store, run_id, source, key, step, value, ts=None)` + a buffered `MetricLogger(store,
> run_id, source, flush_every=200)` context manager (GBT rounds, logistic iters, bandit pulls,
> coverage steps).
> ✅ **[R-08 resolved · round 2]** **WAL is right for this multi-process, single-host, local layout**
> (readers never block writers → the UI charts live while a loop writes); single-writer still holds,
> so brief write locks are the whole game. **Central `open_store()`** that every process *and test*
> routes through: `journal_mode=WAL` (persistent — flip on an idle store, re-assert harmlessly) +
> per-connection `busy_timeout=10000`, `synchronous=NORMAL` (WAL-safe; drops a per-commit fsync),
> `foreign_keys=ON` if used (`sqlite3.connect(path, timeout=10.0)`). **Writer:** one dedicated
> long-lived connection per loop (pinned to its thread); buffer + `executemany` in **`BEGIN
> IMMEDIATE`…COMMIT every ~200 rows or ~1 s**; never hold the write txn across a compute step; flush
> on exit/exception. `BEGIN IMMEDIATE` is the rule for every read-then-write path (busy_timeout does
> NOT rescue a DEFERRED→write upgrade — instant SQLITE_BUSY). **UI reads stay short/self-contained**
> (one SELECT per poll, commit/close at once) or they pin WAL frames and `-wal` grows unbounded;
> keep default PASSIVE auto-checkpoint + a periodic `PRAGMA wal_checkpoint(TRUNCATE)` from the loop
> to cap `-wal`. **De-risk global WAL:** `-wal`/`-shm` sidecars → any backup/copy/delete touching
> only `.db` gets a stale DB (checkpoint-TRUNCATE or `VACUUM INTO` before copy, or copy all three);
> WAL needs write access to the store's *directory*; `:memory:` fixtures ignore it; add a smoke test
> asserting `PRAGMA journal_mode == 'wal'`. **Sequencing:** `open_store()`/WAL is a **CORE
> prerequisite** landing with B0's migration, adopted by all writers (labgen, crawler, auditor, …).

### X0 — Register `lab-generate` in the launcher  *(Wave 0)*
- **Scope:** add a `build_parser()` to `fuzzlab/labgen/cli.py` and a `_REGISTRY` entry (with a
  group label) so `lab-generate` appears in the launcher under a **"Lab / authoring"** group.
  No `authorized` gate (renders files; sends no traffic).
- **Files:** `web/commandspec.py` (+ optional `group` field), `labgen/cli.py`. Independent of the
  shell files.
- **Depends on:** — . **Sub-lanes:** none.
- **Acceptance:** the activity appears grouped; dry-run previews the exact command; a form field
  per flag from the parser; command-spec introspection test covers it.

### U6 — Control-plane hardening  *(Wave 0/1; guards every POST; new — from R-13)*
- **Scope:** a global middleware + security headers so the MPA's new state-changing POST surface
  can't be driven by a hostile web page — preserving **NFR-UI-localhost**. **Two independent gates
  (need both):** (a) a **Host allow-list** (exact `host:port` set) on *every* request — the only
  DNS-rebinding defense (roll our own; Starlette's `TrustedHostMiddleware` strips the port and can't
  pin it); (b) on POST/PUT/DELETE: **Origin == exact** allow-list **+ `Sec-Fetch-Site ==
  same-origin`** (reject *same-site* — the target lab is same-site on a sibling port!), a
  **custom-header** (`X-Fuzzlab-Client: 1`) requirement on `/api/*` (forces a CORS preflight a
  cross-origin page can't satisfy), and a Referer fallback for form POSTs / non-browser clients.
  Fail closed; stay **cookieless** (SameSite wouldn't help — lab is same-site). Tight offline
  **CSP** (`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
  form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`) + `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, COOP/CORP same-origin, `Cache-Control:
  no-store` on API/results. Bind 127.0.0.1/[::1] only.
- **Prerequisite:** **upgrade Starlette ≥ 1.0.1** (CVE-2026-48710 "BadHost" — pre-1.0.1 Host-header
  validation bypass; our hardening keys off Host/path, so this is a hard prereq).
- **Files:** `web/app.py` (middleware + headers) — small/localized; **coordinate with U0's app.py
  edits**. **Depends on:** — (guards current *and* future POSTs; lands with or right after U0).
  **Sub-lanes:** none.
- **Acceptance:** wrong-Host → 421/403; cross-site *and* same-site POST → 403; `/api/*` without the
  client header → 403; same-origin form + API POST pass; CSP present on responses; a test matrix
  over these cases. Cross-checks: the `authorized` gate stays **independent of any request-body
  field** (a rebound/same-site page can't flip it), and a send/replay **target is validated to equal
  the configured lab host:port** (a forged body can't redirect traffic elsewhere).
> ✅ **[R-13 resolved · round 3]** Two independent layers are required because each attack defeats
> the other's single defense: DNS-rebinding sends `Sec-Fetch-Site: same-origin` + attacker Origin
> but a wrong **Host** (only the Host allow-list catches it); classic CSRF sends the right Host but
> cross-site **Origin**/Sec-Fetch (only Origin/Fetch-Metadata catches it). **Same-site landmine:** a
> "site" is scheme+registrable-domain and **port-independent**, so the control plane and the
> deliberately-vulnerable lab are *same-site* on `127.0.0.1` → require **same-origin only** and stay
> cookieless. No CSRF token/session store needed (no ambient credential) — header validation
> suffices. Loopback is a secure context, so `Sec-Fetch-*`/`Origin` are reliably sent. High impact
> here: `/api/launch` + `/api/run/automatic` spawn subprocesses and the repeater sends traffic, so a
> forged request is code/traffic execution, not a nuisance.

### Deferred (not lanes yet)
- **D6 — a "Lab" UI section** surfacing labgen manifests/verdicts/conformance. Revisit once the
  generator's data model stabilizes on the LAB track.
- **Greybox "new-code reward = 0.000"** investigation (standing).

## 4. Lane / dependency map (waves)

| Wave | Lanes (parallel) | Gate |
|---|---|---|
| **0** | **U0** (MPA + split) · **B0** (metric_series→emitters) · **X0** (lab-generate) · **U6** (control-plane hardening — shares `app.py`, so land with/right after U0) | none — dispatch now |
| **1** | **U1** Overview · **U2** Findings · **U3** Proxy · **U4** ML · **U5** Diagnostics | U0 landed; U5 also needs D2 lib chosen (R-02); every POST route observes U6's gate |

- **Critical path:** U0 → U3 / U5 (the two heaviest). U0 is the only cross-lane bottleneck; it
  gets priority and stays one agent to avoid self-conflict.
- **Independence rule:** two lanes are independent only when they share no files. U0's asset
  split is what makes U1–U5 (separate `sections/*`, `js/*`, `css/*`) independent. B0 and X0
  share no UI files, so they run from minute one.
- **Recursive fan-out:** each Wave-1 lane lists sub-lanes; an agent may spawn sub-agents for them
  in isolated worktrees.

## 5. Research queue

| ID | Area | Deliverable(s) | Round | Status |
|---|---|---|---|---|
| R-01 | MPA + FastAPI/Jinja partial-render (HTMX?) pattern | U0 | 1 | ✅ resolved |
| R-02 | Charting library selection + offline vendoring | U5, policy | 1 | ✅ resolved (uPlot) |
| R-03 | Faceted filters + saved views + vanilla DataTable | U2, U1, U5 | 1 | ✅ resolved |
| R-04 | HTTP message editor / repeater UX + resizable panes + highlighting | U3 | 1 | ✅ resolved |
| R-05 | Diagnostics/experiment-tracking UX + scalar-series schema | U5, B0 | 1 | ✅ resolved |
| R-06 | Read-only ML model-internals presentation | U4 | 1 | ✅ resolved |
| R-07 | **Cross-section state/pivot in an MPA** — carrying a seed ("send to Repeater", "open request") + selection/filter across a full-page navigation | U0, U2, U3 | 2 | ✅ resolved (PRG+303) |
| R-08 | **SQLite concurrency for `metric_series`** — WAL/busy_timeout under our per-request connection model; safe writer(loop)+reader(UI)+labgen coexistence | B0, CORE | 2 | ✅ resolved (WAL) |
| R-09 | **Test strategy for the MPA + canvas charts + DataTable** — route/no-JS/active-nav/deep-link tests; asserting uPlot canvas + facets in a real browser | all UI, process | 2 | ✅ resolved (node:test + TestClient + Playwright) |
| R-10 | **Overview dashboard content** — which KPIs/widgets a security+ML overview should lead with (VM-tool patterns), read-only + fast | U1 | 2 | ✅ resolved |
| R-11 | **Accessibility & keyboard model** across the shell — ARIA for the DataTable/grid, facet disclosure, resizable splitter, canvas-chart alternatives, focus order | all UI | 3 | ✅ resolved (native `<table>`) |
| R-12 | **uPlot theming/density/responsive integration** — wiring tokens + density (row→chart sizing), ResizeObserver, and the shared chart-component API | U4, U5 | 3 | ✅ resolved |
| R-13 | **Loopback web-app security hardening** — DNS-rebinding, CSRF, Origin/Host checks for the new POST routes (pivot, saved-views, launch) on a local server | U0, all POST → **U6** | 3 | ✅ resolved (new lane U6) |

## 6. Refinement log

- **Round 1 — complete (2026-09-21/22).** Six web agents (R-01…R-06) returned; all folded into
  the deliverables. Key outcomes: U0 = full-page MPA, no HTMX; D2 = vendor **uPlot 1.6.32**
  (2 files, canvas, re-theme on `[data-theme]`); U2 = facet sidebar + SQLite-backed saved views +
  hand-rolled DataTable (no virtualization, `textContent` only, scheme-checked pivots); U3 = one
  shared `<message-editor>`, vanilla grid splitter, **hand-rolled highlighting** (textarea stays
  byte-exact); U5/B0 = TensorBoard-style controls, validated `metric_series` schema + `MetricLogger`
  emitter, **LTTB** server-side downsample → EMA client-side; U4 = advisory-framed read-only panels
  (PR/reliability/weights/nDCG/conformal/anomaly/Beta-posteriors), lead with the advisory banner.
- **Round 2 — complete (2026-09-22).** Four web agents (R-07…R-10) returned; folded in. Outcomes:
  U0 gains the **PRG+303** cross-section pivot + a URL/server/localStorage state decision rule
  (R-07); B0 gains a **WAL + `open_store()`** concurrency design and batched-`BEGIN IMMEDIATE`
  writer with checkpoint policy (R-08); §7 gains a **three-layer test strategy** (`node:test` units
  + `TestClient` route/no-JS + Playwright via offscreen table & `window.__charts`, no new deps,
  R-09); U1 gains a concrete **Overview spec** (5 KPI tiles + recent-runs table + severity bar +
  quick actions + empty states, R-10).
- **Round 3 — complete (2026-09-22).** Three web agents (R-11…R-13) returned; folded in. Outcomes:
  a cross-cutting **accessibility** spec (native `<table>` not `role=grid`; APG Disclosure/Splitter;
  canvas + visually-hidden table; skip-link/landmarks/focus-visible; not-color-alone per theme —
  R-11); the **shared `createChart` wrapper** (probe-resolved tokens, destroy+recreate on
  theme/density, ResizeObserver, leak-safe teardown, `window.__charts` + a11y table — R-12); and a
  **new lane U6, control-plane hardening** (Host allow-list + Origin/`Sec-Fetch-Site=same-origin` +
  `/api/*` custom-header + tight CSP; Starlette ≥ 1.0.1 for CVE-2026-48710; the "same-site lab"
  landmine — R-13). Two invariants added to §2 (accessible; not-itself-an-attack-surface); U6 added
  to the deliverables + wave map.
- **Loop complete.** All 13 research markers resolved across 3 rounds; deliverables are executable
  and lane-organized. Remaining open items are product decisions, not research: task #19 (whether
  the UI surfaces labgen outputs) and the deferred greybox reward=0.000 investigation.

## 7. Process / bookkeeping (per CLAUDE.md)

Each lane ships with: updated `components/12-diagnostics-and-ui/requirements.md` (FR-UI-*) and,
where the proxy/store change, `11-intercepting-proxy` / `02-core-library`; `ARCHITECTURE.md`
#12 edits; a decision entry where a lane settles one; per-component change-control entries
(CC-UI-*, CC-CORE-* for the B0 migration); `CHANGELOG.md`; and tests (route tests, command-spec
introspection, dry-run-sends-nothing, loopback-refusal, redaction, real-browser smokes).

> ✅ **[R-09 resolved · round 2]** **Test strategy — three layers, ~zero new deps.** **(A) Unit
> (pure JS)** via **`node:test`** (built into Node; `node --test`) for DataTable filter/sort, LTTB,
> EMA, and the HTTP/JSON tokenizer — keep pure logic in modules that touch no `window`/`document`
> at import (`*.core.js`, `downsample.js`, `smoothing.js`, `tokenizer.js`) with relative-path ESM so
> the same files load in Node *and* the browser. **(B) Route + no-JS** via pytest + Starlette
> `TestClient` (already have): assert `response.template.name` + `response.context["active"]`
> (compute `active` in the handler) instead of HTML-string matching; TestClient runs no JS, so its
> body *is* the no-JS assertion; one parametrized test over every section route covers routing +
> deep-link + template + active-nav; add stable hooks (`aria-current="page"`, `data-section`).
> **(C) Real-browser smoke** via Playwright/Chromium (already have): assert charts through the
> **shipped offscreen `<table>` fallback** + a small **`window.__charts`** hook (post-LTTB/EMA
> arrays per chart id, read via `page.evaluate`) + the `.u-legend` DOM — **never canvas pixels**;
> `expect.poll` for readiness (uPlot has no animations), fixed viewport + deviceScaleFactor, seeded
> fixtures, loopback server. Push each assertion to the lowest layer that can prove it. **No new
> dependencies** (the Node runner is built in; the `window.__charts` hook + offscreen table ship
> anyway for a11y). Per-lane: U0 = parametrized route/no-JS + one nav smoke; U2 = filter/sort units
> + server-rendered rows + filter/sort browser smoke; U3 = tokenizer unit + byte-exact editor smoke;
> U4/U5 = LTTB/EMA units + `window.__charts`/table chart assertions.
