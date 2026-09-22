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

### U1 — Overview dashboard  *(Wave 1)*
- **Scope:** landing route (`/`): KPI row (recent runs, findings by severity, last-run score),
  recent-runs list, quick actions (launch auto / open proxy). Read-only over the store.
- **Files:** `sections/overview.html`, `js/overview.js`, `css/overview.css`, `app.py` route.
- **Depends on:** U0. **Sub-lanes:** KPI tiles / recent-runs / quick-actions.
- **Acceptance:** renders with an empty store and with seeded runs; no result-table writes.
> 🔎 **[R-03]** covers the reusable read-only table used here for recent runs.

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
> 🔎 **[R-05]** (shared) **Scalar time-series schema + emitter patterns** — how MLflow/TensorBoard
> model scalar series in a relational/columnar store; validate our `(run_id, source, key, step,
> ts, value)` shape (indexing, cardinality, downsampling for read); the emitter API contributors
> call.

### X0 — Register `lab-generate` in the launcher  *(Wave 0)*
- **Scope:** add a `build_parser()` to `fuzzlab/labgen/cli.py` and a `_REGISTRY` entry (with a
  group label) so `lab-generate` appears in the launcher under a **"Lab / authoring"** group.
  No `authorized` gate (renders files; sends no traffic).
- **Files:** `web/commandspec.py` (+ optional `group` field), `labgen/cli.py`. Independent of the
  shell files.
- **Depends on:** — . **Sub-lanes:** none.
- **Acceptance:** the activity appears grouped; dry-run previews the exact command; a form field
  per flag from the parser; command-spec introspection test covers it.

### Deferred (not lanes yet)
- **D6 — a "Lab" UI section** surfacing labgen manifests/verdicts/conformance. Revisit once the
  generator's data model stabilizes on the LAB track.
- **Greybox "new-code reward = 0.000"** investigation (standing).

## 4. Lane / dependency map (waves)

| Wave | Lanes (parallel) | Gate |
|---|---|---|
| **0** | **U0** (MPA + split) · **B0** (metric_series→emitters) · **X0** (lab-generate) | none — dispatch now |
| **1** | **U1** Overview · **U2** Findings · **U3** Proxy · **U4** ML · **U5** Diagnostics | U0 landed; U5 also needs D2 lib chosen (R-02) |

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
| R-07 | **Cross-section state/pivot in an MPA** — carrying a seed ("send to Repeater", "open request") + selection/filter across a full-page navigation | U0, U2, U3 | 2 | 🔎 dispatched |
| R-08 | **SQLite concurrency for `metric_series`** — WAL/busy_timeout under our per-request connection model; safe writer(loop)+reader(UI)+labgen coexistence | B0, CORE | 2 | 🔎 dispatched |
| R-09 | **Test strategy for the MPA + canvas charts + DataTable** — route/no-JS/active-nav/deep-link tests; asserting uPlot canvas + facets in a real browser | all UI, process | 2 | 🔎 dispatched |
| R-10 | **Overview dashboard content** — which KPIs/widgets a security+ML overview should lead with (VM-tool patterns), read-only + fast | U1 | 2 | 🔎 dispatched |

## 6. Refinement log

- **Round 1 — complete (2026-09-21/22).** Six web agents (R-01…R-06) returned; all folded into
  the deliverables. Key outcomes: U0 = full-page MPA, no HTMX; D2 = vendor **uPlot 1.6.32**
  (2 files, canvas, re-theme on `[data-theme]`); U2 = facet sidebar + SQLite-backed saved views +
  hand-rolled DataTable (no virtualization, `textContent` only, scheme-checked pivots); U3 = one
  shared `<message-editor>`, vanilla grid splitter, **hand-rolled highlighting** (textarea stays
  byte-exact); U5/B0 = TensorBoard-style controls, validated `metric_series` schema + `MetricLogger`
  emitter, **LTTB** server-side downsample → EMA client-side; U4 = advisory-framed read-only panels
  (PR/reliability/weights/nDCG/conformal/anomaly/Beta-posteriors), lead with the advisory banner.
- **Round 2 — dispatched 2026-09-22.** Four web agents on the gaps round 1 exposed: R-07
  cross-section pivot/state in an MPA, R-08 SQLite concurrency for `metric_series`, R-09 test
  strategy for the MPA+charts+DataTable, R-10 Overview KPI/widget selection. Findings pending.
- Round 3 — pending.

## 7. Process / bookkeeping (per CLAUDE.md)

Each lane ships with: updated `components/12-diagnostics-and-ui/requirements.md` (FR-UI-*) and,
where the proxy/store change, `11-intercepting-proxy` / `02-core-library`; `ARCHITECTURE.md`
#12 edits; a decision entry where a lane settles one; per-component change-control entries
(CC-UI-*, CC-CORE-* for the B0 migration); `CHANGELOG.md`; and tests (route tests, command-spec
introspection, dry-run-sends-nothing, loopback-refusal, redaction, real-browser smokes).
