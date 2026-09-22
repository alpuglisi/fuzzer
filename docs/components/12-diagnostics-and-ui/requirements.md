# Diagnostics and UI — Requirement Specification

Component code: **UI** · Status: `[planned]` · Last updated: 2026-09-22

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
  + reliability/ECE, logistic weights (documented not-available — see
  `10-ml-components/requirements.md` FR-ML-8), nDCG@k/precision@k vs. random, rank
  score/uncertainty histograms + a score-vs-uncertainty scatter, the conformal stacked
  split + nonconformity histogram, the ECOD anomaly histogram, committee-disagreement
  histogram + a top-N query queue, bandit Beta posteriors (overlaid density + a
  forest/interval table), and a mutation killed/survived table. `GET /api/ml/data`
  (`fuzzlab/web/mlview.py`) is the sole data source — read-only over the store,
  optionally filtered by `run_id`; degrades to a documented "not available" reason per
  panel (never an error) on an empty or partially-populated store.
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

## 4. Non-functional requirements
- **NFR-UI-localhost** The web app binds to loopback only, is never exposed, and is
  served separately from the vulnerable target (different origin/port; never in the
  target's web root) so the control plane is never itself an attack surface. (D11)
  Operationalized by **NFR-UI-control-plane-hardened** below: binding to loopback alone
  does not stop a hostile page the operator's browser visits from driving this app, since
  the panel is still reachable over HTTP like any other loopback service.
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
- **NFR-UI-no-auto-run** No tool traffic reaches the target as a side effect of
  bring-up; only an explicit automatic-mode selection or a manual tool invocation
  sends requests.
- **NFR-UI-read-only** The UI itself does not write result tables
  (`finding`/`attempt`/`candidate`); in automatic mode those are written by the
  tools it invokes, not by the UI. `saved_views` (FR-UI-13, FR-CORE-9) is the
  one deliberate exception: it holds view *definitions* a person authored in
  the panel (filter/sort/column specs), never tool output, so writing it does
  not violate this invariant.
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
- A request with an unrecognized Host is rejected (421); a cross-origin or same-site
  (but not same-origin) state-changing request is rejected (403); an `/api/*` JSON
  POST/PUT/DELETE without `X-Fuzzlab-Client: 1` is rejected; a legitimate same-origin
  request (JSON with the header, or a form-encoded POST) succeeds; every response
  carries the CSP and related security headers.

## 8. Open questions
- Web stack (e.g. FastAPI or Flask + a light frontend; Datasette embedded vs
  linked) — to confirm during build.
- Metric set and refresh cadence for live views.
