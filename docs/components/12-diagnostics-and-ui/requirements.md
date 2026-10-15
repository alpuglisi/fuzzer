# Diagnostics and UI — Requirement Specification

Component code: **UI** · Status: `[planned]` · Last updated: 2026-10-13

Related: `ARCHITECTURE.md` #12; `DECISIONS_AND_ROADMAP.md` (D2, D5, D11);
`./change-control.md`.

## 1. Purpose
Make the platform observable in a browser and keep the user in control of when the
tools touch the target: a **local web application** (D11) that hosts the launcher
(automatic vs manual, never auto-running tools), shows runs and interception live,
presents results, explores the store, and helps verify functionality and locate
bugs — the research-platform diagnostics of decision D2.

## 2. Scope
- **In:** a local web control panel + dashboard hosting the launcher (run-mode
  selection), live run/interception views, results review, store exploration, a
  metrics table, structured logs, a dry-run mode, and a plain CLI entry point per
  tool for headless use.
- **Out:** producing findings or scores itself (it does not write result tables;
  in automatic mode it invokes the tools, which write results).

## 3. Functional requirements
- **FR-UI-launcher** After the lab is up, open a local web control panel that
  offers two run modes and does nothing to the target until the user acts:
  - **automatic** — run the discovery → fuzz pipeline and the integration harness
    against the lab, and show results;
  - **manual** — leave the lab running and make the tools available for hand-driven
    use (from the panel, and/or as ready-to-run commands with target/store
    pre-wired), sending nothing to the target until the user invokes a tool.
  Bringing up the lab must never trigger tool traffic on its own (the no-auto-run
  principle). A minimal panel ships in Phase 0; the full dashboard elaborates it.
- **FR-UI-categories** Injection-category selection follows the run mode (D14):
  - **automatic** (against our lab) auto-selects the categories from the lab's
    ground truth (`labels.json`); the panel shows them but the user does not pick.
  - **manual** presents a **category selector** (which vulnerabilities to test);
    only selected categories run, backed by a `--categories` flag on the tools.
  The selection scopes the auditor's rules, payload sources, and which oracle
  strategies run.
- **FR-UI-nogt** No-ground-truth fail-safe (D15): an automatic run against a target
  with no ground-truth contract must **not** auto-select or test-everything — it
  requires an explicit category selection, **fails loudly** if none is given, runs
  **unscored** (findings shown, no TP/FP/FN), and keeps all safety gates on
  (destructive off, scope-enforced, authorized).
- **FR-UI-1** A local web dashboard showing live interception, in-progress runs,
  and results in the browser.
- **FR-UI-cli** Retain a plain CLI entry point for each tool (automation,
  scripting, power use) that works without the web app.
- **FR-UI-2** Datasette (or equivalent) over the store for ad-hoc exploration of
  pages, candidates, attempts, findings, and flows.
  *(Realized: lane U5, CC-UI-0032, 2026-09-22 — a read-only store explorer on the
  Diagnostics tab (`GET /api/store/tables`, `GET /api/store/tables/{name}`),
  covering every ordinary table in the store, not only the five named above.
  Table names are always re-validated against `sqlite_master` before use
  (never interpolated from the request unchecked), and every cell renders
  client-side via `textContent` only — see `fuzzlab/web/diagnostics.py` and
  `js/datatable.js`.)* *(CC-UI-0045:)* the sealed holdout tables
  (`core.sealed.SEALED_TABLES`) are neither listed nor browsable — they read as "no
  such table" (FR-ML-19).
- **FR-UI-3** A `run_metrics` table populated per run (requests, findings,
  precision, budget used, timing).
- **FR-UI-4** Structured audit and debug logs carrying `run_id`, `tool`,
  `identity`, and `flow_id`.
- **FR-UI-5** A `--dry-run` mode that plans and reports actions without sending
  traffic.
- **FR-UI-6** An **activity launcher**: the panel offers a control for every flag of
  every launchable activity (crawl, audit, fuzz, auto, greybox-run, proxy, mutate-run,
  report, session), a dry-run preview of the exact command before anything runs, an
  explicit gated Run/Stop, and live output. The flag controls are **derived from each
  tool's own `argparse` parser** (single source of truth — never hand-mirrored), so a new
  tool flag appears in the UI automatically. Launching still sends nothing until the user
  acts and stays behind the `authorized` gate (no-auto-run, NFR-UI-no-auto-run).
  *(Realized: Phase 0.1 the command-spec registry, Phase 0.3 the dry-run/gated-run/SSE
  runner, Phase 1 the launcher UI — per-tool forms, dry-run preview, live output, the D14
  category picker, and the plugins panel.)*
  **Job lifetime** *(CC-UI-0053, 2026-10-14, BUG-0125 D18)*: a launched job (and the Lab
  page's `labctl.sh` calls) runs under `fuzzlab.procutil`'s supervisor and is tied to
  the UI's life: *Stop* ends its whole process tree, the UI's shutdown stops every live
  job, and the job stops if the UI process dies. An unrequested stop is reported on the
  job's stream. To outlive the UI, run the previewed command from the CLI.
- **FR-UI-7** The panel is organized as a **multi-page app with real per-section
  routes**: **Overview** (`/`, the landing dashboard), **Launcher** (`/launcher`, run
  controls), **Proxy** (`/proxy`, traffic review/edit/drop/forward/repeat),
  **Findings** (`/findings`, the faceted findings workbench — see FR-UI-13),
  **Results** (`/results`, runs dashboard), **ML** (`/ml`,
  classifier/ranker/conformal/anomaly/active-learning/bandit/mutation — kept
  **separate** from the primary panel), and **Diagnostics** (`/diagnostics`, a
  TensorBoard-like view for performance review and deep troubleshooting), plus
  `/runs/{id}` (a Results sub-page) and `/findings/{id}` (a Findings sub-page). Each
  route is independently deep-linkable, renders
  its full section server-side, and degrades fully without JavaScript (a plain GET on any
  route returns the complete section). *(Realized incrementally: Phase 0.2 built the shell
  + Results as hash-switched panels on one page; Proxy/ML/Diagnostics filled in Phases 2–4
  the same way. **Superseded at U0 (CC-UI-0025, 2026-09-22)**: the hash-switched single
  page and its client-side `initTabs()` router were retired in favor of the real routes
  above — a full-page MPA per resolved marker R-01 in `UI_IMPLEMENTATION_PLAN.md`, chosen
  over HTMX because a loopback full-page GET is sub-millisecond and HTMX's benefit doesn't
  apply. State-mutating cross-section pivots (e.g. Proxy's "send to Repeater") follow
  **POST/Redirect/GET with a 303** (R-07): the state-changing action is a real
  `<form method="post">`, the redirect carries only an opaque id in the query string
  (`?repeater_tab=`), and raw bytes never appear on the wire. U1–U5 build out each
  section's content on top of this split. **U3 (CC-UI-0030, 2026-09-22)** filled in the
  Proxy route's content: History / Intercept / Repeater re-laid on the shared
  `<message-editor>` (FR-UI-9) plus resizable panes and a sub-nav. **Superseded
  again at U1 (CC-UI-0028, 2026-09-22)**: `/` now renders the new Overview
  dashboard (FR-UI-10) rather than the Launcher, which moved to its own route,
  `/launcher`, with unchanged behavior — see FR-UI-10 and NAV in
  `fuzzlab/web/app.py`.)*
- **FR-UI-9 (shared message editor)** *(added U3, CC-UI-0030, R-04)* The Proxy
  section's History (read-only detail), Intercept (held-flow edit), and Repeater
  (request edit / response view) byte editors share one component,
  `js/msgeditor.js`'s `<message-editor>`: `{editable, bytes, meta}` in as
  properties, `getBytes()` out. Request panes are **editable** (a plain
  `<textarea>`, whose `.value` is the single byte-exact source of truth) with
  **Raw as the only editable mode and the default**; Response panes are
  **read-only** (Raw | Pretty | Hex). Pretty and Hex render into a read-only
  `<pre>` mirror built only with `createElement`/`textContent` (never
  `innerHTML`, consistent with the untrusted-flow-content discipline
  `js/proxy.js` already follows for table rows). A status/timing strip shows
  status+reason/elapsed-ms/byte-length/content-type. A CRLF/non-printing-byte
  toggle changes **display only** (Unicode control-picture glyphs), never the
  underlying bytes. Ctrl-F search paints match ranges via the **CSS Custom
  Highlight API** (`CSS.highlights`/`Highlight`) over the read-only mirror —
  never by span-injecting the buffer — with graceful no-paint degradation
  where unsupported; an editable Raw pane shows a synced read-only overlay of
  the same bytes only for the duration of a search, the textarea underneath
  untouched. No vendored highlighting/editor library. A companion
  `attachSplitter()` in the same module is a **vanilla CSS-grid resizable
  splitter** (one `--a` grid-track custom property + pointer-capture drag +
  arrow-key a11y + localStorage-persisted size, no library) used for the
  request/response pane pairs, each with a horizontal/vertical layout toggle.
  The existing `toWire()` CRLF-restore in `common.js` remains the single
  documented `\n`→`\r\n` normalization point applied right before a
  byte-exact send; `msgeditor.js` does not duplicate it.
- **FR-UI-8** The panel is framed by an **app shell**: a persistent **left-sidebar
  navigation** (grouped Workbench / Analysis sections, rendered from one `NAV` source of
  truth as real `<a href>` links with server-computed active state —
  `aria-current="page"` plus a non-color indicator, never color alone) and a **top context
  bar** showing the current target, scope, authorization state, and proxy status. The
  shell is shared by every route (every section, run detail, not-found) via one
  `base.html` template; `app.py` computes the active section per request
  (`_shell_context(cfg, active=...)`) rather than the client inferring it from a hash. A
  **design-token stylesheet** (`tokens.css`) is the single source of truth for color,
  elevation, and density; it supports **light / dark / system** theme (system by default,
  with an explicit override) and a **compact density**, both persisted per-viewer in
  `localStorage` and applied before first paint via an inline `<head>` script (no flash —
  this script runs on every full-page MPA navigation, which is required under FR-UI-7's
  real routes). The shell is chrome only: it changes no launcher / proxy / results
  behavior and touches none of the NFR-UI invariants.
  *(Realized: R0 of the layout redesign — `base.html` shell, `tokens.css`, retokenized
  `app.css`, and `initShell()` for theme/density/collapse persistence + the proxy chip. The
  **Launch view** was then rebuilt as the approved **master-detail** (a grouped, gate-tagged
  activity picker → the selected activity's form; `initLaunchNav()`, CC-UI-0022) — brought
  forward from R1. **U0 (CC-UI-0025, 2026-09-22)** split the shell's own assets into a
  shared `css/shell.css` + `js/shell.js` (loaded on every route) plus one CSS partial and
  one ES module per section (`css/<section>.css`, `js/<section>.js`, D3 — no bundler), and
  gave the sidebar real per-section `href`s. The Overview dashboard and the Findings / Proxy
  rebuilds still follow in Wave 1 (U1–U5), per `docs/UI_LAYOUT_REDESIGN.md` and
  `docs/UI_IMPLEMENTATION_PLAN.md`.)*
- **FR-UI-10** *(added CC-UI-0028, 2026-09-22)* **Overview dashboard** — the landing
  route (`/`) is a read-only, single-aggregate-endpoint summary of the store, per
  resolved marker R-10 in `UI_IMPLEMENTATION_PLAN.md`:
  - a **KPI tile row of 5**, each clickable through to a filtered/detail view:
    (1) Findings (total + severity-split sub-line), (2) Runs (total + "N in last
    7d"), (3) Last run (status badge + tool→target + timestamp), (4) Detection
    quality (latest *scored* run's F1, + MCC or P/R sub-line), (5) Efficiency
    (`pipeline_requests_per_finding`, + total requests sub-line);
  - **Panel A — Recent runs**: the ~10 newest runs, newest first;
  - **Panel B — Findings by severity**: a horizontal segmented bar (severity
    derived read-only from `finding.vuln_class` via a fixed category→severity map,
    since the store has no `finding.severity` column — see
    `fuzzlab/web/results.py::severity_of`/`_SEVERITY_BY_VULN_CLASS`);
  - **Panel C — Quick actions**: primary Launch auto, secondary Open proxy,
    tertiary Model registry / Compare runs;
  - **Empty state** (0 runs): one centered onboarding card ("No runs yet" + a
    primary Launch-auto action) instead of a grid of zeros;
  - **Partial-empty state** (a run exists but is unscored/unbudgeted): tiles 4/5
    show an em-dash, never a bare `0`.
  Served from one aggregate read (`fuzzlab/web/results.py::overview_summary`) —
  counts + pre-aggregated severity + the joined recent-runs list in a handful of
  queries, no heavy per-run join per KPI. Strictly read-only: never creates the
  store, never writes a result-table row (NFR-UI-read-only). *(Realized: U1,
  CC-UI-0028 — `sections/overview.html`, `js/overview.js` (a small hand-rolled
  click-to-sort for the recent-runs table; not yet the shared `DataTable` reserved
  for U2/U5 by R-03, since `js/datatable.js` did not exist when this lane ran),
  `css/overview.css`, `app.py::overview_page`/`_overview_context`.)*

- **FR-UI-11** *(added CC-UI-0031, lane U4)* The **ML tab** (`/ml`) is **read-only and
  advisory** (R-06): a persistent, non-dismissible banner ("Model output is advisory;
  confirmed findings come from the oracle") leads the tab, followed by the conformal
  flag/abstain/drop split and the classifier's reliability diagram — the advisory
  anchor. Every score shows an uncertainty companion, its N, and (where meaningful) a
  baseline. Verb hygiene: model output is "scored/ranked/flagged", never
  "detected/vulnerable/confirmed" (`fuzzlab/web/static/js/ml.js`, `templates/sections/
  ml.html`). Palette is neutral blue/amber only (`--accent`/`--warn`) — never the
  oracle's red/green (`--crit`/`--ok`, reserved for Results/Findings). Panels: PR curve
  + reliability/ECE, the saved logistic model's **standardised coefficients**
  (*amended CC-UI-0038:* log-odds per SD, other features held fixed, explicitly not
  feature importance; read from the saved model, FR-ML-13; a stated reason for a tree,
  fallback, legacy or incompatible model), nDCG@k/precision@k vs. random, rank
  score/uncertainty histograms + a score-vs-uncertainty scatter (*amended CC-UI-0048:*
the ranker's nDCG@k and precision@k baselines are computed by the trainer's
`evaluate_vs_random` over the same rows and groups), the conformal stacked
  split + nonconformity histogram, the ECOD anomaly histogram, committee-disagreement
  histogram + a top-N query queue, bandit Beta posteriors (overlaid density + a
  forest/interval table; *CC-UI-0048:* pulls are the scheduler's recorded `cost_n`,
  never `α + β − 2`; *CC-UI-0049:* backoff parent contexts are labelled "(pooled)",
  with mean cost "n/a (pooled)"), and a mutation killed/survived table. `GET /api/ml/data`
  (`fuzzlab/web/mlview.py`) is the sole data source — read-only over the store,
  optionally filtered by `run_id`; degrades to a documented "not available" reason per
  panel (never an error) on an empty or partially-populated store.
  *(Note, CC-UI-0043.)* A run picker (`/ml?run=N`) selects that filter. Only the latest
  choice renders, every panel is reset before re-rendering, and the bandit panel is
  labelled "(all runs)".
  *(Amended CC-UI-0034/CC-UI-0035, BUG-0061/BUG-0062.)*
  - The conformal split is gated by the classifier that scored the run, read through
    `fuzzlab.ml.train.latest_classifier(store, run_id)` (FR-ML-10). It is never "the
    newest `model` row", which may be the ranker's or another run's. *(Amended
    CC-UI-0042, BUG-0067.)* Every row is gated by **its own run's** classifier, and
    judges only the score that gate was calibrated for (`train.gate_input`, FR-ML-16).
    Rows with no such score are counted `n/a`; the run page shows each row's decision
    score.
  - **Recomputed metrics.** PR-AUC/ECE and nDCG@k/precision@k are recomputed from
    stored scores: the out-of-fold `score_oof` / `rank_score_oof` where a run-mode
    model stored them (`evaluation: "out-of-fold (labelled rows)"`), else the deploy
    score. For legacy rows that is **in-sample**, labelled `"in-sample (deploy
    fit)"`. `ml.js` shows the label. Beside it is an `oof`
    object: the out-of-fold numbers of the model that wrote those scores, from its
    `model` row (ranker's at that model's own training `at_k`). `oof` is `null` when no
    such model exists, for a fallback or legacy row, or in the all-runs view unless the
    selected row is a store-wide train. `run_metrics` is not read for these.
  *(Note, CC-UI-0040.)*
  - **Earlier-trained scores.** For scores written by a model trained on earlier runs
    (FR-ML-14), `evaluation` reads `"not trained on this run's labels (trained on
    earlier runs)"`.
  - **All-runs view.** It labels the pool from every pooled run's scoring model, and
    reads `"mixed"` when they disagree.
  - **`oof` payload.** It carries `scope` (`"this run"` / `"earlier runs"`). For an
    earlier-trained model it also carries `forward` (or `null`), its
    `forward_skipped_reason`, `seen_fraction` and `train_run_ids`.
  - **Display.** `ml.js` shows all of these. It never calls them out-of-sample.
  - *(Note CC-UI-0044, BUG-0070.)* The conformal panel shows a "never flags / never
    drops" threshold as "never" (never `1.0` or `-0.0`) with `train.gate_notes`, and the
    pre-BUG-0070 note when any pooled gate lacks `gate_rule`. The anomaly panel shows
    "at most k" (`anomaly.flag_budget`) and the tie reason.
  - *(Note CC-UI-0045.)* Recomputed out-of-fold metrics leave out a run-mode model's
    sealed held-out rows (`train.metric_input`, per row with its own run's model).
    *(CC-UI-0050, BUG-0091:)* Every sealed row is left out of the classifier panel
    (PR, reliability, ECE) and the ranker panel, whatever model scored it:
    `holdout.held_ids` is passed as `metric_input`'s required `held`. The disagreement
    panel never fits its committee on a sealed row. On an unknown holdout membership,
    every row of the target is sealed and the disagreement panel is unavailable. The
    reliability panel shows a calibrated classifier's out-of-fold ECE raw → cross-fitted
    (FR-ML-20), or "calibration: none (degenerate fit)".
  - *(Note CC-UI-0046.)* Ranker panel: a pairwise ranker shows its objective, the
    trainer's run-wide per-fold NDCG ("per-fold scales — not pooled") and "uncertainty
    n/a (pairwise)" (no uncertainty chart or scatter). Anomaly panel: per run it shows
    the **stored** flags with the method and contamination the run's stage recorded
    ("unknown (assumed ECOD)" without one) and a per-method axis; only with nothing
    stored, and always in the all-runs pooled view, it recomputes ECOD, labelled
    "recomputed (ECOD, c)".
- **FR-UI-12** *(added CC-UI-0031, lane U4, resolved R-02/R-12)* A shared charting
  layer, consumed by both the ML tab (U4) and Diagnostics (U5): **uPlot 1.6.32**
  (MIT, vendored verbatim as two static files, `static/vendor/uplot/uPlot.esm.js` +
  `uPlot.min.css` — no bundler, no CDN) behind one wrapper,
  `static/js/chart.js::createChart(el, {id, type, data, series, opts})`. Canvas can't
  read CSS custom properties and uPlot bakes resolved colors into the canvas at
  construction, so a theme or density change is a full `destroy()` + recreate (data-only
  updates use `setData()`; size-only updates use `setSize()`); color tokens are resolved
  through a hidden-probe element's computed style (`getPropertyValue` alone can hand
  back an unresolved `var()`/`color-mix()` chain the canvas can't parse). Density maps
  to discrete sizing buckets off `data-density`. Responsive via a debounced
  `ResizeObserver` on the chart's parent cell (not uPlot's own root — an RO feedback
  loop), coalesced with `requestAnimationFrame`. Retheme wires a `MutationObserver` on
  `<html>` (`data-theme`/`data-density`) plus a `matchMedia` listener for an unforced
  system-preference change. `window.__charts` is a `Map<id, handle>` for tests/
  debugging; every chart also renders a visually-hidden `<table>` a11y fallback next to
  the (`aria-hidden`) canvas, since a canvas chart is opaque to screen readers.
  Teardown (`handle.destroy()`) disconnects the `ResizeObserver`/`MutationObserver`,
  removes the `matchMedia` listener, cancels any pending `requestAnimationFrame`, calls
  `uPlot.destroy()`, and drops the chart from the registry — required because the
  observers otherwise hold references and leak across an MPA navigation.
  *(Amended CC-UI-0036, BUG-0063.)* Options are passed in the exact shape the vendored
  source handles: uPlot's `class` is **one** token (`fl-chart`); the per-type modifier
  `fl-chart--<type>` is added to `u.root` inside `build()` so a rebuild keeps it. Callers
  pass only their y series (`createChart` prepends the x series) and use the documented
  `opts` (`xLabel`, `caption`, `scales`, …). The mount is `role="figure"` (so its a11y
  table stays exposed) with an `aria-label` from `caption` that chart.js refreshes on
  every build when it set it, and never overwrites when a template set it. On the ML tab
  each panel renders in isolation: one that throws shows "Could not render this panel"
  and the rest still render.

- **FR-UI-13** *(added CC-UI-0029, U2)* The **Findings workbench** (`/findings`,
  `/findings/{id}`) offers faceted filtering + saved views over `finding`/`attempt`,
  read-only, plus a "send to Repeater" pivot:
  - A **left facet sidebar** (severity, vuln class, method, confirmation
    mechanism, endpoint) with **live counts** (multi-select checkboxes — OR
    within a group, AND across groups — each group's counts computed against
    every *other* active group's filter), a debounced quick-filter (substring
    over url/param/vuln_class/mechanism), **applied-filter chips** (each
    individually removable, "Clear all"), and a **saved-view chip row**.
    Filtering/sorting is entirely client-side over one bounded snapshot
    (`GET /api/findings`) — no server-side faceted-count endpoint, per D4/R-03.
  - **Severity** is not a store column — the schema has none — so it is a
    UI-only, advisory band derived from `vuln_class`
    (`fuzzlab.web.findingsview.derive_severity`), rendered as a text+color
    badge (never color alone) and never written back to the store.
  - **Saved views** are named filter/sort/column specs persisted server-side
    (`saved_views`, FR-CORE-9) via `GET/POST/PUT/DELETE /api/views?table=`,
    durable and shared across the panel's own readers; only throwaway
    per-viewer state (collapsed facet groups, last-applied view id, draft
    quick-filter text) lives in `localStorage`.
  - The **detail view** (`/findings/{id}`) shows the finding's full record —
    evidence, the confirming attempt, and, when present, the multi-artifact
    ground-truth fields (`primary_endpoint`/`primary_role`/`related_endpoints`/
    `flow_variant`, CR-LAB-0001 Addendum B) carried in its `evidence` — these
    are additive/optional (no current writer attaches them; the oracle itself
    must not read ground truth, D9/D10) and are rendered only when present,
    never invented.
  - **"Send to Repeater / open request"** follows the same PRG+303 pattern as
    the Proxy History pivot (FR-UI-7's note): a real `<form method="post">` to
    `/findings/repeater/from-finding` creates a Repeater tab server-side, then
    a `303` redirect carries only the opaque tab id
    (`/proxy?repeater_tab=ID`) — never bytes on the wire. Findings/attempts
    carry no raw request bytes (only proxy flow history does), so the tab is
    a best-effort **reconstruction** from the finding's own `url`/`method`/
    `param`, explicitly labeled as such (never presented as a byte-exact
    replay).
  - The list and detail views, and the shared `js/datatable.js` component they
    use (below), are strictly **read-only** over `finding`/`attempt`; the
    only write path this section owns is `saved_views` (view *definitions*,
    not a result table — see NFR-UI-read-only).
  - **`js/datatable.js`** is a standalone, dependency-free ES module (D3) —
    a native `<table>` (never `role="grid"`: read-only sort + a row link is
    not a composite-widget grid), every cell rendered via `textContent`
    (never `innerHTML` — cell data is target-derived and untrusted), a real
    `<a href>` in the primary column wrapping JS-rendered content (row-click
    is an enhancement, never the only path), named row-action buttons, and
    `safeHref()` scheme-checking (http/https/same-origin-relative only) on
    every rendered pivot href. Its API —
    `createDataTable(root, {caption, columns, data, getRowId, rowHref,
    onRowClick, rowActions, textFilterKeys, emptyMessage, liveRegion}) ->
    {setData, setTextFilter, setFilter, setSort, getSort, getVisible,
    element}` — is intended for reuse by U1's recent-runs table and U5's
    store explorer (each minus the facet sidebar, which is Findings-specific
    UI built in `js/findings.js`, not part of the shared module).
- **FR-UI-14** *(added CC-UI-0032, lane U5, R-05)* The **Diagnostics** route
  (`/diagnostics`) is a TensorBoard-like view over the store: cross-run scalar
  trend lines over `run_metrics` (one line per selected metric key, x = the
  selected runs); intra-run and cross-run overlay step series over
  `metric_series` (one line per run for a chosen `source`/`key`), downsampled
  server-side to ≈1000 points/series via LTTB before being sent, with EMA
  smoothing (0–0.99, a slider) applied client-side *after* that downsampling
  so it is instant; an x-axis toggle (step / relative-time / wall-clock) and
  a y-axis log toggle; a run multi-select with a stable per-run color; and a
  metric picker grouped by `source` (collapsible) with a substring filter.
  Snapshot panels: a pre-binned candidate-score histogram per run, the
  current bandit arm posteriors (`bandit_posteriors`, with posterior mean),
  and the model-registry timeline (`model`). Charts render via the shared,
  vendored charting library (uPlot 1.6.32, MIT, first vendored by lane U4)
  behind one wrapper (`js/chart.js`'s `createChart()`) that resolves design
  tokens for canvas colors, buckets sizing by density, is responsive via a
  debounced `ResizeObserver`, and fully rebuilds on theme/density change. No
  websocket streaming — a manual page refresh (or re-running the query)
  picks up new data from an active run. See FR-UI-2 for the store-explorer
  half of this same route.
- **FR-UI-15** *(added CC-UI-0033, 2026-10-13)* The **Lab** route (`/lab`) lists every
  service of the target lab's `lab/compose.yaml` -- derived from that file, never a
  hand-kept list -- with its live container state, its first compose profile, its
  published loopback URL, and a Start/Stop switch. `GET /api/lab/services` returns the
  rows merged with the container engine's real state (via `labctl.sh ps`; an engine or
  lab error is reported in the payload rather than guessed around); `POST
  /api/lab/{service}/{start|stop}` resolves the name against the compose-derived list
  (unknown → 404) and runs `lab/labctl.sh <action> <service>` as a gated child process
  through the launcher's `Runner` (argv list, no shell, the service's profile passed as
  `PFF_PROFILE`), streaming its output over the existing `/api/launch/{token}/stream`.
  Rendering the page runs nothing (no-auto-run, D11); the switches are explicit POSTs
  behind the control-plane gate (NFR-UI-control-plane-hardened). Nothing on the route
  sends traffic to a target, so it is not `--authorized`-gated.

- **FR-UI-16** *(added CC-UI-0034, 2026-10-13, BUG-0061)* The run-detail page
  (`/runs/{id}`, `web/results.py::run_detail`) shows a read-only **"Model scores
  (advisory)"** card. It lists the run's top advisory-scored candidates (`candidate.score`)
  with the conformal flag/abstain/drop decision of the classifier that scored that run.
  The classifier is read through `fuzzlab.ml.train.latest_classifier(store, run_id)`
  (FR-ML-10): never another model family's row (e.g. the ranker's), never another
  run's. The decision is `n/a` only when that classifier has no conformal calibration
  (a `prevalence-fallback`). Scores are advisory and never presented as findings.

- **FR-UI-17** *(added CC-UI-0039, 2026-10-13, BUG-0066)* `fuzzlab report` for a run
  pins **that run's own** models: `models` and `reproducibility.model_versions` come
  from `latest_classifier` / `latest_ranker(store, run_id)` (FR-ML-10). They are never
  the store's newest version of each name. `reproducibility.model_params_sha256` gives
  each pinned model's saved-params sha (FR-ML-13), or `null` for a model trained
  before models were saved.
  *(Extended CC-UI-0040.)* `reproducibility.model_training` gives each pinned model's
  `{trained_on, train_run_ids}`. This is `{"trained_on": "earlier", "train_run_ids":
  [...]}` for a model trained on earlier runs (FR-ML-14), and `{"trained_on": "run",
  "train_run_ids": null}` for a `run`-mode or legacy row. The text report marks an
  earlier-trained model "(trained on earlier runs …)".
  *(Extended CC-UI-0042.)* A saved-model row reports `{"trained_on": "saved",
  "train_run_ids", "source_model_id"}`, and the text report marks it "(saved model #ID,
  trained on runs …)".
  *(Extended CC-UI-0041.)* `plugins` items carry `config`, `status` and `error`.
  `reproducibility` gains `plugin_config` and `plugin_status`. A failed plugin is
  marked `(FAILED)` in the text report.
  *(Changed CC-UI-0047, BUG-0069 — a JSON contract change.)*
  `reproducibility.feature_versions` is `{"candidate": [...], "flow": [...]}`: the
  candidate versions the run's pinned models, stored candidate rows and feature-reading
  stages (anomaly tripwire, budget prioritizer) used, and the flow tripwire's version;
  `[]` when no stage read that vector. The text report prints `feature versions:
  candidate …, flow …`.
- **FR-UI-18** *(added CC-UI-0041, 2026-10-13)* The web app and report work without the
  `fuzzlab.ml` package (FR-ML-6).
  - **ML tab:** its ML-backed panels (classifier, weights, ranker, conformal, anomaly,
    disagreement) report "ML components are not installed". Bandit and mutation are
    unaffected.
  - **Run page:** it still lists the stored scores, with decision `n/a` and that
    reason.
  - **Report:** it gives `models_unavailable` instead of claiming no models.
  - **No direct imports:** nothing in `web/` or `report/` imports `fuzzlab.ml` except
    through `import_ml`.

- **FR-UI-19** *(added CC-UI-0043, 2026-10-13)* A run's page shows its ML context.
  These are plain per-run store reads, so they work without the ML package.
  - **Oracle coverage:** checked / skipped (budget) / no confirmer / unrecorded counts,
    plus pending (not reached: run interrupted, or stopped by a safety breaker) and
    inconclusive (could not be decided: a cost cap stopped a started check, or no
    mechanism could place the point; CC-UI-0052, widened by CC-FUZZ-0068), followed by
    the mechanism and count of each kind (`unplaceable`, or the capped mechanism such as
    `boolean-differential`) from the pipeline's `pipeline_oracle_inconclusive_<mechanism>`
    run metrics (`web.results.inconclusive_by`; none for runs recorded before it).
  - **Anomaly flags:** the stored top flagged candidates (`core.anomaly_flags`), with the
    run's own `anomaly_flagged` and the anomaly stage's config as provenance. The flags
    are the last fit's values for that run. *(CC-UI-0044:)* the card also shows
    `core.anomaly_flags.flag_note` — the pre-BUG-0070 label, or why fewer than k were
    flagged — and appears for a note even when nothing was flagged.
  - **Anomaly method** *(CC-UI-0046):* the anomaly card names the detector that wrote
    the stored flags.
  - **Gate notes** *(CC-UI-0044):* the "Model scores" card lists `train.gate_notes`
    (pre-BUG-0070 thresholds, or never flags / never drops with the counts).
  - **Plugins and ML stages:** each attached plugin with its config and status
    (unknown / attached — run did not finish / FAILED: error / ok).
  - **Safety:** every value renders as text.

### Project files *(added CC-UI-0450, 2026-10-15; Burp/ZAP-style projects)*

- **FR-UI-450** A project is one fuzzlab store file (`.fuzzlab`, the fuzzlab SQLite
  `application_id`; FR-CORE-450). The UI has at most one open project; every page reads
  it and every UI write goes into it (`web.projects.ProjectBoundConfig`:
  `cfg.get("store_path")` is the open project, or `None` when none is open). At start-up
  the configured `store_path` is the open project (an empty `store_path` starts with
  none); its metadata row is created on its first open (FR-CORE-450).
- **FR-UI-451** Lifecycle, on `/projects` (plain POST forms, PRG): **new** (a name),
  **open** (a file listed in the projects directory, a recent entry, or a leftover
  temporary project), **temporary** (a throwaway file in `<projects_dir>/.temporary/`),
  **save as** (a backup-API copy, FR-CORE-450, plus the project's own directory; the
  copy becomes the open project), **close**. The projects directory is
  `cfg["projects_dir"]`, else `$FUZZLAB_PROJECTS_DIR`, else
  `~/.local/share/fuzzlab/projects`; it is created only by an action that needs it.
- **FR-UI-452** The **recent list** (`<projects_dir>/recent.json`, 10 entries, newest
  first) is updated under an interprocess lock (`core.secretfile.locked`), replaced
  atomically, and read through one validating parser (malformed entries skipped and
  counted). An entry whose file is gone is shown as missing, not dropped.
- **FR-UI-453** Leaving a **temporary project** (close, open, new, another temporary)
  deletes it and needs an explicit confirmation (`discard`); without it the action is
  refused with a message offering Save as. Deletion removes exactly the files the
  project owns: its file, its SQLite side files and the known files of its directory,
  each checked to be a regular file of this user, the main file matched to the inode
  recorded at creation; anything else is left and reported. Shutdown deletes nothing;
  leftover temporaries are listed for Open or Discard, and one another `fuzzlab web`
  holds open (its owner lock) is refused.
- **FR-UI-454** The open project is shown on **every page** (the topbar chip: name,
  `temporary`, its path as the tooltip, linking to `/projects`); when none is open, a
  migration is waiting, or the file was refused, a banner says so. *(The page layout
  beyond this skeleton follows the UI research; see CC-UI-0450.)*
- **FR-UI-455** `/project` shows the open project's **metadata** (name, file, created,
  last opened, schema and fuzzlab versions; editable notes and targets) and its **run
  history** (`core.project.run_history`): each run's command (the UI launch's command
  and redacted argv, or the tool name for a run made outside the UI), target, start
  time, status (`aborted` from the run's own notes first; else the launch's
  `succeeded` / `failed` / `stopped` / `unknown`, `running` only for a job live in this
  UI; else `recorded`), finding and candidate counts, linked to `/runs/{id}` and its
  findings. A launch that recorded no run is listed as "no run recorded".
- **FR-UI-456** **Jobs pin to the project.** Every launched command that has a
  `--store` option runs with `--store <open project>`, and with its intermediate files
  (crawl `--db`, `--spider-db`, audit `--out`, fuzz `--output`) in the project's own
  directory (`<file>.d/`), overriding the form (`web.projects.pin_values`, from the
  exhaustive `OPTION_CLASS` table). Each such job is recorded in the project's `launch`
  table (command, redacted argv, redacted target; FR-CORE-451) and its target is added
  to the project's targets; it runs with `umask 077`. The dry run shows the pinned
  command and creates nothing. A pinned command with no project open is refused (409).
  Commands without a store (session, build-db, lab-generate) and lab switches are not
  pinned, record nothing and keep the normal umask.
- **FR-UI-457** **Schema mismatch.** A file whose schema is older than this build's is
  not opened, read or written until the operator accepts the migration offer; accepting
  writes a verified backup (`<file>.d/backups/`) and then migrates (FR-CORE-452 covers a
  partial failure). A newer file, a non-fuzzlab SQLite file, a file with triggers or
  views, or one failing `quick_check` is refused with the reason. With `--with-proxy`,
  a start-up project that is waiting or refused stops the start with the remedy (start
  once without `--with-proxy`).

## 4. Non-functional requirements
- **NFR-UI-localhost** The web app binds to loopback only, is never exposed, and is
  served separately from the vulnerable target (different origin/port; never in the
  target's web root) so the control plane is never itself an attack surface. (D11)
  Operationalized by **NFR-UI-control-plane-hardened** below: binding to loopback alone
  does not stop a hostile page the operator's browser visits from driving this app, since
  the panel is still reachable over HTTP like any other loopback service.
  - Enforced by: `web.app.serve` via `core.net.require_loopback` — `tests/test_web_launcher.py::test_serve_refuses_non_loopback`, `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`, `tests/test_web_proxy_serve.py::test_serve_refuses_non_loopback_proxy_host`
  - Not yet enforced: "served separately from the target" is not checked (only the default ports differ). (BUG-0111 sweep.)
- **NFR-UI-control-plane-hardened** *(added CC-UI-0026, R-13)* Every request is checked
  against an exact Host (`host:port`) allow-list (rolled ourselves — not Starlette's
  `TrustedHostMiddleware`, which strips the port and so cannot pin against DNS
  rebinding). Every state-changing request (POST/PUT/DELETE) additionally requires
  Origin == that allow-list **and** `Sec-Fetch-Site == same-origin` — **same-site is
  rejected too**, because the deliberately-vulnerable lab this panel drives is same-site
  with it (same registrable domain, `127.0.0.1`, only the port differs) — plus a custom
  `X-Fuzzlab-Client: 1` header on `/api/*` JSON requests (forces a CORS preflight a
  cross-origin page cannot satisfy; exempted for `application/x-www-form-urlencoded` /
  `multipart/form-data` bodies, which a native `<form>` can never set a custom header on
  and which Origin/Sec-Fetch-Site alone already defend). Clients sending no Fetch
  Metadata (older browsers, non-browser/API clients) fall back to Origin, then Referer.
  Stays cookieless (no CSRF token/session store — there is no ambient credential for a
  forged request to ride on, and SameSite would not help given the same-site landmine
  above). Fails closed on any ambiguity. A tight, offline CSP plus `X-Content-Type-
  Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, COOP/CORP
  `same-origin`, and `Cache-Control: no-store` (off `/static/`) are set on every
  response, success or denial. Requires Starlette ≥1.0.1 (CVE-2026-48710, "BadHost":
  pre-1.0.1 Host-header validation bypass — this hardening keys off Host, so a bypass
  there defeats it). Implementation: `fuzzlab.web.app.SecurityGateMiddleware`.
  - Enforced by: `web.app.SecurityGateMiddleware` — `tests/test_web_security.py::test_wrong_host_rejected_on_a_get`, `tests/test_web_security.py::test_dns_rebinding_wrong_host_but_perfect_fetch_metadata_still_rejected`, `tests/test_web_security.py::test_cross_origin_post_rejected_classic_csrf`, `tests/test_web_security.py::test_same_site_sibling_port_post_rejected`, `tests/test_web_security.py::test_same_origin_but_missing_custom_header_rejected_on_api`, `tests/test_web_security.py::test_form_post_same_origin_without_custom_header_passes`, `tests/test_web_security.py::test_no_fetch_metadata_falls_back_to_origin`, `tests/test_web_security.py::test_no_fetch_metadata_and_no_origin_falls_back_to_referer`, `tests/test_web_security.py::test_no_fetch_metadata_untrusted_referer_rejected`, `tests/test_web_security.py::test_security_headers_present_on_success`, `tests/test_web_security.py::test_security_headers_present_on_denial_too`, `tests/test_web_security.py::test_static_assets_are_not_marked_no_store`
  - Not yet enforced (untested): Host port pinning, PUT/DELETE rejection, `Sec-Fetch-Site: same-origin` with a bad Origin, the multipart exemption, the fail-closed cases (no Host; no Origin/Referer/Fetch-Metadata), cookieless, the Starlette pin. (BUG-0111 sweep.)
- **NFR-UI-no-auto-run** No tool traffic reaches the target as a side effect of
  bring-up; only an explicit automatic-mode selection or a manual tool invocation
  sends requests.
  - Enforced by: `web.app` (POST + `authorized` to run) — `tests/test_web_launcher.py::test_index_offers_both_modes_and_does_not_run`, `tests/test_web_lab.py::test_page_loading_does_not_touch_containers`, `tests/test_web_proxy_serve.py::test_web_main_requires_authorized_for_proxy`, `tests/test_web_launcher.py::test_automatic_blocked_without_authorization`, `tests/test_web_runner.py::test_launch_blocks_traffic_tool_without_authorization`, `tests/test_web_repeater.py::test_routes_list_create_and_send_gate`
- **NFR-UI-read-only** The UI itself does not write result tables
  (`finding`/`attempt`/`candidate`); in automatic mode those are written by the
  tools it invokes, not by the UI. `saved_views` (FR-UI-13, FR-CORE-9) is a
  deliberate exception: it holds view *definitions* a person authored in
  the panel (filter/sort/column specs), never tool output, so writing it does
  not violate this invariant. *(CC-UI-0450:)* so are the project records — the
  `project` metadata row and the `launch` rows (what the UI started, never tool
  output) — and deleting a temporary project the operator discarded.
  - Enforced by: `tests/test_web_overview.py::test_overview_is_read_only_get_makes_no_writes`, `tests/test_web_findings.py::test_api_findings_and_page_are_read_only`, `tests/test_holdout_seal_table.py::test_readers_never_write_on_an_upgraded_store`, `tests/test_web_ml.py::test_anomaly_panel_is_read_only`, `tests/test_web_diagnostics.py::test_diagnostics_routes_are_read_only_no_store_file`
  - Not yet enforced: read-only by convention (a read-write `Store`); attempt/candidate counts and the /results, /runs/{id} and /proxy routes are unchecked; the Repeater writes `repeater_tab`/`run`/`flow`. (BUG-0111 sweep.)
- **NFR-UI-browser-verified** *(added CC-UI-0036/CC-UI-0037, BUG-0063/BUG-0064,
  PA-0065)* Every HTML page loads in a real browser with zero page errors, zero console
  errors and zero CSP violations. The check is `tests/test_web_pages_browser.py`, which
  walks every non-`/api` GET route of the app (a new page is covered automatically) plus
  the not-found page, and asserts each page's key rendered output (ML/Diagnostics charts,
  saved preferences, the severity bar). No template contains markup the app's own CSP
  blocks: inline `<script>`, `<style>`, `style=`, `on*=`, `javascript:`
  (`tests/test_web_templates_csp.py`). Browser tests skip only when the real browser
  cannot run, and `FUZZLAB_REQUIRE_BROWSER=1` turns that skip into a failure. A change to
  `fuzzlab/web/templates/` or `fuzzlab/web/static/` is verified with it set.
- **NFR-UI-project-private** *(added CC-UI-0450)* Every file and directory the UI
  creates for a project is private from creation: project files, their SQLite side
  files, copies and backups 0600; the projects directory, `.temporary/` and each
  project's own directory 0700 (an existing directory that is not 0700 and ours is
  refused); pinned jobs run with `umask 077`, so files the tools create there are 0600.
  A legacy store readable by others is reported with a "make private" action, never
  changed silently.
  - Enforced by: `core.project.create` / `copy_to`, `web.projects.ProjectManager._ensure_dir`, `Runner.launch(umask=)` — `tests/test_core_project.py::test_create_is_private_exclusive_and_never_follows_a_link`, `tests/test_core_project.py::test_side_files_inherit_the_private_mode`, `tests/test_core_project.py::test_copy_is_complete_under_a_live_writer_and_private`, `tests/test_web_projects.py::test_a_real_job_records_provenance_privately_and_blocks_switching`, `tests/test_web_projects.py::test_a_launch_umask_reaches_the_whole_tree`, `tests/test_web_projects.py::test_lifecycle_new_open_save_as_close`, `tests/test_web_projects.py::test_a_shared_or_linked_projects_directory_is_refused`
- **NFR-UI-project-paths-confined** *(added CC-UI-0450)* The browser never names a
  project path: it sends a name (`NAME_RE`) or a listed file name (`FILE_RE`), placed
  directly in the projects directory; an opened file must be a regular file of this user
  there (no symlink, no subdirectory) or the operator's configured `store_path`; a recent
  entry is re-validated on every reopen. No web module opens a store that can create
  one, except the one creation site under the project lock.
  - Enforced by: `web.projects` — `tests/test_web_projects.py::test_bad_project_names_are_refused`, `tests/test_web_projects.py::test_open_refuses_traversal_symlinks_and_foreign_files`, `tests/test_web_projects.py::test_a_recent_entry_outside_the_projects_directory_is_refused`, `tests/test_web_projects.py::test_no_web_module_opens_a_store_that_can_create`, `tests/test_web_projects.py::test_the_creating_open_guard_catches_synthetic_offenders`, `tests/test_web_projects.py::test_every_project_action_is_refused_cross_site`
  - Not yet enforced: the window between validating a path and SQLite opening it (another process of the same user could swap the file) is a stated residual; other tools' own path flags (input paths such as `--ground-truth`) are typed by the operator, as before.
- **NFR-UI-project-provenance-redacted** *(added CC-UI-0450)* What the UI records about
  a job or a project (`launch.argv`, `launch.target`, `project.targets`) goes through
  `core.redaction.redact_for_record` (URL userinfo, sensitive query values, a sensitive
  option's value), written only by `core.project`; a project file never holds a
  credential the UI handled.
  - Enforced by: `core.project.insert_launch` / `set_meta` / `add_target` — `tests/test_web_projects.py::test_a_project_file_never_contains_a_credential_value`, `tests/test_web_projects.py::test_only_core_project_writes_the_project_record_tables`, `tests/test_core_project.py::test_redact_for_record_removes_every_planted_secret_shape`, `tests/test_core_project.py::test_redact_for_record_keeps_benign_values`
  - Not yet enforced: `repeater_tab.raw_request` stores operator-typed requests as typed (an existing behaviour, see NFR-UI-redacted); notes are plain text the operator writes (labelled so on the page).
- **NFR-UI-project-switch-safe** *(added CC-UI-0450)* A project is never switched, saved
  as, closed or deleted while it is being written: one lock covers every transition and
  every launch from the busy check to the act; a job counts as writing until its end is
  recorded in its project; the in-process proxy and an automatic run count too. A
  reader racing a discard can never recreate the file.
  - Enforced by: `web.projects.ProjectManager` (`lock`, `busy_reasons`), `web.runner.Runner` (`recorded`) — `tests/test_web_projects.py::test_a_real_job_records_provenance_privately_and_blocks_switching`, `tests/test_web_projects.py::test_busy_lasts_until_the_jobs_end_is_recorded`, `tests/test_web_projects.py::test_a_switch_issued_during_a_launch_waits_and_is_refused`, `tests/test_web_projects.py::test_a_spawn_failure_marks_the_launch_failed_and_never_leaves_it_busy`, `tests/test_web_projects.py::test_the_in_process_proxy_creates_its_project_and_keeps_it_busy`, `tests/test_web_projects.py::test_temporary_project_discard_needs_confirmation_and_removes_only_its_files`
  - Not yet enforced: a `fuzzlab` CLI process writing the same file outside the UI is not visible to it (stated residual).
- **NFR-UI-live** Live views reflect the current run without blocking the tools.
- **NFR-UI-redacted** Secrets never render; the UI shows redacted values only.
  - Enforced by (at write time): `tests/test_proxy_redaction.py::test_no_secret_reaches_any_persisted_copy`
  - Not yet enforced: the Repeater returns and lists raw requests/responses; `run.html` renders plugin `config` unredacted; no UI test seeds a secret. (BUG-0111 sweep; reported to the operator.)

## 5. Interfaces and data contracts
A local HTTP server on loopback serving the control panel/dashboard. Reads the
store (all result tables) and structured logs; writes only the `run_metrics` table
and its own view/UI state. *(CC-UI-0450:)* "the store" is the open project file;
the UI also writes that project's `project` and `launch` rows and its
`<projects_dir>/recent.json`, and passes `--store <project>` and
`FUZZLAB_LAUNCH_TOKEN` to every pinned job it starts. No dependency on any tool's API — it reads the shared
contract (D5). In automatic mode it invokes the tools as subprocesses/functions;
they write their own results.

## 6. Dependencies (components)
`core/` (store and logging). In automatic mode the web app invokes the tools
(crawler, auditor, fuzzer, harness) — orchestration only; the tools still write
their own results.

## 7. Acceptance criteria
- Bring-up opens the local web panel and reaches it only on localhost; no request
  reaches the target until the user selects automatic mode or manually runs a tool.
- Automatic mode runs the pipeline/harness and shows results; manual mode leaves
  the tools ready to invoke by hand.
- The web dashboard reflects an in-progress run and interception without stalling
  tools.
- Datasette view exposes the result tables for exploration.
- `run_metrics` is populated per run; `--dry-run` sends no traffic.
- No secret is ever rendered.
- A request with an unrecognized Host is rejected (421); a cross-origin or same-site
  (but not same-origin) state-changing request is rejected (403); an `/api/*` JSON
  POST/PUT/DELETE without `X-Fuzzlab-Client: 1` is rejected; a legitimate same-origin
  request (JSON with the header, or a form-encoded POST) succeeds; every response
  carries the CSP and related security headers.

## 8. Open questions
- Web stack (e.g. FastAPI or Flask + a light frontend; Datasette embedded vs
  linked) — to confirm during build.
- Metric set and refresh cadence for live views.
