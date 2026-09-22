# Diagnostics and UI — Requirement Specification

Component code: **UI** · Status: `[built — command-spec-driven launcher, control-plane
hardening middleware, the app shell (sidebar nav + theme/density), Overview,
Findings workbench + saved views, the Proxy workbench (shared message-editor +
splitter), a read-only advisory ML tab, a Diagnostics chart tab + read-only store
explorer, a per-run reproducibility report, and a per-run technology-fingerprint
panel]` · Last updated: 2026-09-22 · see CC-UI-0034

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
- **FR-UI-7** The panel is organized as a **tabbed shell**: **Launcher** (run controls),
  **Proxy** (traffic review/edit/drop/forward/repeat), **Results** (runs dashboard),
  **ML** (classifier/ranker/conformal/anomaly/active-learning/bandit/mutation — kept
  **separate** from the primary panel), and **Diagnostics** (a TensorBoard-like view for
  performance review and deep troubleshooting). Panels render server-side and degrade
  without JavaScript. *(Realized incrementally: Phase 0.2 builds the shell + Results;
  Proxy/ML/Diagnostics fill in Phases 2–4. Re-housed in the FR-UI-8 app shell at R0:
  the five sections became a persistent left-sidebar nav, still switching the same
  server-rendered `.panel` sections by hash — see D-UI-shell and CC-UI-0021.)*
- **FR-UI-8** The panel is framed by an **app shell**: a persistent **left-sidebar
  navigation** (grouped Workbench / Analysis sections) and a **top context bar** showing
  the current target, scope, authorization state, and proxy status. The shell is shared by
  every page (index, run detail, not-found) via one base template. A **design-token
  stylesheet** (`tokens.css`) is the single source of truth for color, elevation, and
  density; it supports **light / dark / system** theme (system by default, with an explicit
  override) and a **compact density**, both persisted per-viewer in `localStorage` and
  applied before first paint (no flash). The shell is chrome only: it changes no launcher /
  proxy / results behavior and touches none of the NFR-UI invariants.
  *(Realized: R0 of the layout redesign — `base.html` shell, `tokens.css`, retokenized
  `app.css`, and `initShell()` for theme/density/collapse persistence + the proxy chip. The
  **Launch view** was then rebuilt as the approved **master-detail** (a grouped, gate-tagged
  activity picker → the selected activity's form; `initLaunchNav()`, CC-UI-0022) — brought
  forward from R1. Deep-linkable per-section routes, the Overview dashboard, and the Findings /
  Proxy rebuilds still follow in R1–R3, per `docs/UI_LAYOUT_REDESIGN.md`.)*

- **FR-UI-9** The control panel is a true multi-page app: every top-level sidebar section
  (Launcher, Proxy, Results, ML, Diagnostics) is served at its own GET route with its own
  URL, is deep-linkable, and renders fully with JavaScript disabled (progressive
  enhancement only, never a JS-only view). The current section is determined server-side
  by the route handler and passed explicitly to the shared shell template, which renders
  it as `aria-current="page"` on the matching sidebar link — never inferred from the URL
  by client script. There is no client-side router; page-to-page navigation is native
  browser `<a>`/`<form>` navigation. Section templates, per-section ES modules, and
  per-section CSS partials are independent files so that a change to one section's
  presentation cannot conflict with another's. *(Realized: Wave-0 lane U0, CC-UI-0025 —
  supersedes the hash-based section switching described under FR-UI-7/FR-UI-8's
  "Realized" notes, which is retired.)*
- **FR-UI-10** Control-plane hardening: every request to the web control panel is checked
  against an exact host:port allow-list (self-derived from the server's own bound
  address — never a client-supplied header); every POST/PUT/DELETE additionally requires
  Origin-exact-match + `Sec-Fetch-Site: same-origin` (same-site is rejected too) or,
  absent Fetch Metadata, a matching Referer; `/api/*` routes additionally require a
  custom `X-Fuzzlab-Client: 1` header. Any check failing responds 421/403 and never
  reaches route logic (fail-closed). Every response carries a fixed CSP +
  nosniff/frame-options/referrer-policy/COOP/CORP, and `Cache-Control: no-store` on
  `/api/*`/`/results`/`/runs/*`. This gate is independent of, and does not weaken, the
  existing `authorized` no-auto-run gate (FR-UI-5 et al.), which stays sourced only from
  server-side `Config`. *(Realized: Wave-0 lane U6, CC-UI-0026; prerequisite: Starlette
  `>=1.0.1,<2`, CVE-2026-48710 "BadHost".)*
- **FR-UI-11** Overview dashboard (`GET /`, the landing route): a 5-tile KPI row
  (Findings w/ severity split, Runs w/ 7-day count, Last run, Detection quality [F1/MCC,
  em-dash if unscored], Efficiency [requests-per-finding, em-dash if unscored]), each
  tile linking to an existing route; Panel A recent-runs table (≤10, newest first, via
  the shared `DataTable`, FR-UI-12); Panel B a findings-by-severity bar; Panel C quick
  actions (Launch auto, Open proxy, Model registry). Served from one aggregate read per
  request; writes no result tables. Zero runs → a single onboarding card, never a
  zero-grid. The Launcher (FR-UI-6) lives at `/launch`, its own route, not `/`.
  *(Realized: Wave-1 lane U1, CC-UI-0027.)*
- **FR-UI-12** Findings workbench (`/findings`, `/findings/{id}`): a collapsible left facet
  sidebar (multi-select, live counts; OR within a group, AND across groups — vuln class,
  severity, method, confidence/mechanism, endpoint), a debounced quick-filter over
  url/param/endpoint, applied-filter chips with a "Clear all", and a saved-view chip row.
  Every cell renders via `textContent` only (never `innerHTML` — url/param/payload fields
  are untrusted) and any rendered link is scheme-checked (http/https only) to block
  `javascript:`/`data:`. The detail view exposes ground-truth fields
  (`primary_endpoint`/`primary_role`/`related_endpoints`/`flow_variant`) only when the
  store actually carries them for that finding — never fabricated; today they live only
  on the out-of-band `Case` dataclass, not on `finding`/`attempt`, so the detail view
  shows the raw `case_id` and an explicit "ground truth not available" state instead. A
  "send to Repeater" pivot uses Post/Redirect/Get (a `POST` handoff, then a 303 redirect
  to a GET); it never carries payload bytes in the URL. The workbench is built on a
  shared, hand-rolled `DataTable` module (`static/js/datatable.js`,
  `createDataTable({container, columns, data, onRowClick, rowActions, textFilterKeys,
  cap, emptyMessage})`) that provides in-memory filter→sort→fragment-render with no
  virtualization (a fixed row cap, default 2000, is the only escalation lever) — the
  single implementation any other section needing a row-oriented table (e.g. Overview's
  recent-runs, Diagnostics' store explorer) is expected to reuse rather than
  re-implementing table behavior per lane. *(Realized: Wave-1 lane U2, CC-UI-0028.)*
- **FR-UI-13** Saved views are named, durable, per-table filter/sort/column presets stored
  server-side (`saved_views(id, table_key, name, spec_json, is_pinned, created_at,
  updated_at)`, CORE migration 12 / FR-CORE-9), exposed via `GET/POST/PUT/DELETE
  /api/views?table=`. `spec_json` is `{version, name, pinned, filter:{text, facets,
  predicates}, sort, columns}`. `localStorage` (wrapped in try/catch, degrading silently
  if unavailable) holds only throwaway per-viewer convenience state — last selected view
  id, an in-progress filter draft, which facet groups are collapsed — never durable or
  shared data. *(Realized: Wave-1 lane U2, CC-UI-0028.)*
- **FR-UI-14** The Proxy section's History, Intercept, Repeater, and Scope/Match-Replace
  views are switched by an in-page sub-nav (not separate routes) and render any raw HTTP
  message through one shared `<message-editor>` component (`static/js/msgeditor.js`):
  Raw (the only editable view, a plain `<textarea>` whose `.value` is the byte-exact
  source of truth) | Pretty (view-only, never round-trips) tabs, plus a read-only Hex tab
  on non-editable panes; a status/timing strip; Ctrl-F search painted via the CSS Custom
  Highlight API over a read-only mirror (never by injecting markup into the live editable
  buffer); and a CRLF/non-printing-char display toggle. Any two-pane view (request/
  response) is joined by a hand-rolled, library-free resizable splitter (pointer-capture
  drag, arrow-key `separator` a11y, persisted size) with a horizontal/vertical layout
  toggle. The one documented newline transform (`\n`→`\r\n` on send/forward) stays in
  `toWire` (`js/http.js`), applied only at the actual network call site — never inside
  the editor component. *(Realized: Wave-1 lane U3, CC-UI-0029.)*
- **FR-UI-15** The ML tab (`/ml`) renders a read-only, advisory summary of classifier,
  ranker, conformal-triage, anomaly, active-learning, bandit, and mutation-search state
  already persisted in the store (`run_metrics`, `metric_series`, `model`, `candidate`,
  `bandit_posteriors`, `payload_variant`). It never trains a model, writes to the
  store, or influences the fuzzing loop, and a family with no persisted data reports
  itself unavailable rather than fabricating a value. Charts render through the same
  shared `static/js/charts.js` wrapper Diagnostics uses (FR-UI-16) — not a second
  hand-rolled implementation. *(Realized: Wave-1 lane U4, CC-UI-0030.)*
- **FR-UI-16** The Diagnostics tab renders one chart per populated `metric_series`
  `(source, key)`, downsampled server-side before transmission (LTTB for a plain trend
  line; a min/max envelope for a CI-band-style series, e.g. bandit posterior/regret) so
  the client never receives more than ~1000 points per series. Every chart exposes its
  post-downsample data via `window.__charts` (id → a handle with `getData()`) and ships
  an offscreen `<table>` fallback (capped rows) kept in sync with the data — informative
  with JS disabled, and the surface real-browser tests assert against instead of canvas
  pixels. The shared chart wrapper (`static/js/charts.js`, over vendored uPlot 1.6.32)
  is the one implementation any section rendering a chart uses — Diagnostics and the ML
  tab (FR-UI-15) both import it rather than each hand-rolling their own.
  *(Realized: Wave-1 lane U5, CC-UI-0031.)*
- **FR-UI-17** The Diagnostics tab offers read-only, paginated browsing of any store
  table (`GET /api/store/tables`, `GET /api/store/{table}`). Any column whose name
  matches a secret-like substring (password/secret/token/credential/cookie/
  authorization) is redacted, and any BLOB-valued column renders only as
  `<blob: N bytes>` — both at render time, before the response leaves the server; the
  explorer never writes to the store. *(Realized: Wave-1 lane U5, CC-UI-0031.)*
- **FR-UI-18** A run's detail page (`/runs/{run_id}`) surfaces the reproducible
  evaluation report (schema version, config hash, feature version(s), deployed
  models, active plugins) built by `fuzzlab.report.build_report`, and offers it as
  a downloadable canonical JSON artifact at `GET /runs/{run_id}/report.json` —
  byte-identical to what `fuzzlab report --json` prints for the same run, since
  both go through `fuzzlab.report.format_json`. Pure read; no traffic; a missing
  store or run id is a 404, never a store-creation side effect.
  *(Realized: CC-UI-0032.)*
- **FR-UI-19** A run's detail page shows a "Technologies" panel: every web
  application/service technology signal recorded for the run (FR-AUD-7), grouped
  by category, each with its name, version (when known), and confidence — only
  rendered when at least one signal exists. `fuzzlab.report.build_report`'s
  `technologies` list (and `format_text`'s matching section) carry the same data,
  so the JSON/text reports and the page agree. Pure read of already-stored data
  (NFR-UI-read-only); untrusted fields (name/version/evidence/source_url, since
  they derive from response content) render only via autoescaped `{{ }}`, never
  `|safe`. *(Realized: CC-UI-0034.)*

## 4. Non-functional requirements
- **NFR-UI-localhost** The web app binds to loopback only, is never exposed, and is
  served separately from the vulnerable target (different origin/port; never in the
  target's web root) so the control plane is never itself an attack surface. (D11)
- **NFR-UI-no-auto-run** No tool traffic reaches the target as a side effect of
  bring-up; only an explicit automatic-mode selection or a manual tool invocation
  sends requests.
- **NFR-UI-read-only** The UI itself does not write result tables
  (`finding`/`attempt`/`candidate`); in automatic mode those are written by the
  tools it invokes, not by the UI.
- **NFR-UI-live** Live views reflect the current run without blocking the tools.
- **NFR-UI-redacted** Secrets never render; the UI shows redacted values only.

## 5. Interfaces and data contracts
A local HTTP server on loopback serving the control panel/dashboard. Reads the
store (all result tables) and structured logs; writes only the `run_metrics` table
and its own view/UI state. No dependency on any tool's API — it reads the shared
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

## 8. Open questions
- Web stack (e.g. FastAPI or Flask + a light frontend; Datasette embedded vs
  linked) — to confirm during build.
- Metric set and refresh cadence for live views.
