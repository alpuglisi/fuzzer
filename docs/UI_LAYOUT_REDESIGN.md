# Web UI Layout Redesign

Component: **UI** (#12, `fuzzlab/web/`) · Status: `[R0, R1 built; R2/R3 proposed]` ·
Last updated: 2026-09-22

Related: `docs/UI_REVAMP_PLAN.md` (the feature revamp, Phases 0–4), `ARCHITECTURE.md` #12,
`DECISIONS_AND_ROADMAP.md` (D11 local web app). This doc redesigns the **layout / IA**;
the revamp plan covers the *features*. They compose: this says where the Phase 1–4 surfaces
live and how new ones slot in.

## 1. Motivation

The panel grew from a read-only viewer into a real control plane (launcher, proxy
workbench, and — coming — ML and diagnostics). The current layout is a **single page with a
top row of hash-tabs** (Launcher / Proxy / Results / ML / Diagnostics), every panel rendered
into one document. That does not scale: the DOM grows unbounded, there is no deep-linking to
a sub-view, no landing/overview, no persistent context, no consistent list→detail model, and
the proxy workbench is a long vertical stack of cards rather than a real workbench.

Goal: make the UI **intuitive, organized, robust, scalable, and flexible**, informed by how
mature security tools lay themselves out.

## 2. What the reference tools do (research synthesis)

Reviewed the VM/scanner platforms **Rapid7 InsightVM**, **Tenable** (Nessus / Vulnerability
Management / .sc), **Qualys VMDR**, **Greenbone/OpenVAS (GSA)**, **NodeWare**, and the
intercepting proxies **Burp Suite** and **OWASP ZAP**. Convergent patterns:

**Scanner/VM platforms**
- **Primary nav = persistent left sidebar** (Tenable VM, InsightVM cloud, NodeWare). Qualys
  is the outlier (a cross-app "App Picker" launchpad + in-module top tabs); Greenbone uses a
  top menu bar. Net: **left rail is the modern norm**, plus a global product/app switcher
  once there are multiple modules.
- **Dashboard landing** is table-stakes: **drag-and-drop, resizable widget cards**, a
  **starter/template library**, **multiple saved dashboards**, **PDF export**, and
  **click-a-widget-to-drill-down**. NodeWare adds a single **hero KPI** (its 0–1000 Network
  Score) over a wall of tables.
- **List→detail** is uniform: a **table with severity color-coding**, a **left faceted-filter
  plane**, and **saved queries/views**, drilling into a detail page (description, score, CVEs,
  remediation, affected assets/evidence).
- **A saved-query / query language layer** is what makes them scale — InsightVM **Query
  Builder**, Tenable **Query Builder**, Qualys **QQL**, Greenbone **powerfilter**. Plus
  **tags / dynamic grouping** as the organizing layer. (Anti-pattern to avoid: Tenable's hard
  35-filter cap.)
- **Object model** differs: Tenable's co-equal **Findings ↔ Assets workbench** pivot is the
  cleanest exploration model; Greenbone's reusable **Target × Scan-Config → Task** decoupling
  is powerful but has the steepest learning curve; NodeWare drops "scans" entirely (continuous,
  **findings/asset-centric**).
- **Scan config**: Tenable's **template gallery → tabbed settings form → Save vs Save &
  Launch** is the friendliest; InsightVM uses a tabbed Site config; Qualys is profile-driven.
- **Reporting** is template-based with PDF/CSV/HTML/JSON export and scheduling.
- **Gap / opportunity:** none of the VM tools documents a **dark mode or density/compact
  setting** — a cheap, real differentiator.

**Intercepting proxies**
- **Burp:** a flat, always-visible **top tool-tab bar** (Dashboard, Target, Proxy, Repeater,
  Intruder, …) with **two-level nesting** (Proxy → Intercept / HTTP history / …). A
  **Dashboard** as mission-control (tasks + event log + live issue feed).
- **ZAP:** a fixed **3-pane spatial layout** (Sites tree left, request/response workspace
  top-right, information tabs — History/Alerts/Output — bottom), with **progressive
  disclosure** (on-demand "+" tabs) and the **HUD** in-browser overlay.
- Both share the borrowable core:
  1. **One reusable message editor** everywhere (intercept, history, repeater) — Pretty / Raw
     / Hex views + a **structured Inspector** side panel for headers/params/cookies.
  2. **Layout-orientation toggle** per editor (side-by-side / stacked / tabs).
  3. **"Send to <tool>" chaining** (right-click / shortcut) as the connective tissue.
  4. **Filter bar docked above every table** (simple + power/script mode).
  5. **Separate long-running automation from hands-on tools.**
  6. **Global scope/context as a filtering lens**; **native dark mode + persisted layout**.

Sources are listed at the end.

## 3. fuzzlab is a hybrid

fuzzlab is **both** a scanner/fuzzer (runs → findings → attempts, ML, coverage/metrics — the
VM-tool shape) **and** an intercepting proxy (flows, intercept, repeater — the Burp/ZAP
shape). The redesign therefore adopts a **scanner-style app shell** (left nav + top context
bar + dashboard + list→detail) and nests a **Burp/ZAP-style workbench** inside the Proxy
section. Central nouns: **runs, findings, attempts, flows, target, models, coverage**.

## 4. Proposed information architecture

An **app shell** = a persistent **left sidebar** (primary nav, collapsible to icons) + a
persistent **top context bar**, with a routed **content area**. Primary sections:

| Section | Purpose | Maps to |
|---|---|---|
| **Overview** | Dashboard landing: hero KPIs + recent runs + posture + quick actions | new |
| **Launch** | Activity launcher grouped Discovery / Attack / Analysis; dry-run + live output | Phase 1 |
| **Findings** | Findings-centric workbench: facets + table + saved views → finding detail | new (data exists) |
| **Runs** | Runs list → run detail (score, metrics, findings, fingerprint) | Phase 2.1 Results |
| **Proxy** | Workbench: History · Intercept · Repeater · Scope/Rules (sub-nav + panes) | Phase 2 |
| **ML** | Classifier / ranker / conformal / anomaly / bandit / mutation (kept separate) | Phase 3 |
| **Diagnostics** | TensorBoard-like trends + store explorer | Phase 4 |
| **Reports** | Template-based reproducible reports + export (`fuzzlab report` exists) | later |

The **top context bar** carries what must always be visible (Burp/scanner pattern): the
**target base-URL + scope**, an **authorized** indicator, **proxy status** (running / intercept
/ pending), **request-budget** usage, a **global "Run"/command palette**, and the **theme +
density** toggles. It makes the safety invariants (no-auto-run, authorized, loopback,
redaction) legible at a glance.

## 5. Layout primitives (a small design system)

Shared, reused across every section — the thing that makes it organized and scalable:

- **Design tokens** (`static/tokens.css`): color, spacing, radius, typography as CSS
  variables, with **light / dark / system** and **density (comfortable / compact)** — the
  differentiator the VM tools lack. A dedicated **severity/confidence palette** (critical /
  high / medium / low / info; confidence high/med/low) and **status** colors.
- **List→detail**: a master list (left) + detail pane (right), **resizable** and
  **deep-linkable**, with **breadcrumbs**. Used by Findings, Runs, Proxy History.
- **DataTable**: sortable columns, **column chooser**, a **faceted filter plane**, **saved
  views**, pagination/virtualization, and severity/status **chips**. One component, many tables
  (findings, flows, attempts, variants). (No hard filter cap — the Tenable anti-pattern.)
- **Message editor** (proxy): Pretty / Raw (Hex later) + a structured **Inspector**; an
  **orientation toggle** (side-by-side / stacked); reused by History view, Intercept edit, and
  Repeater — learn it once (the Burp/ZAP principle).
- **Command palette + "send to" chaining**: keyboard-driven quick actions (e.g. a flow → "Send
  to Repeater", a finding → "Open request"), the connective tissue Burp/ZAP rely on.
- **Consistent empty / loading / error states** and toasts.
- **Per-viewer preferences** in `localStorage` (theme, density, collapsed sidebar, pane
  sizes, saved views) — wrapped in try/catch, degrading cleanly.

## 6. Per-view layouts (sketches)

- **Overview** — a hero row of KPI tiles (findings by severity, last-run score, coverage
  lines seen, request-budget used, proxy status), a "recent runs" table, a target-posture
  card, and quick-action buttons (Launch, Start proxy). Later: user-composable widgets +
  PDF export (the VM-tool dashboard pattern).
- **Launch** — activity cards grouped **Discovery / Attack / Analysis**; each expands to its
  parser-derived form (Phase 1) with dry-run preview and a live-output drawer. A right rail
  shows the active/last run.
- **Findings** — the Tenable-style **workbench**: left **faceted filters** (vuln_class,
  confidence, category, run, has-evidence) + a **saved-views** bar; a severity/confidence
  color-coded table; a detail pane with the finding's evidence, the attempt's request/response
  (the shared message editor), oracle mechanism, and ground-truth case. Pivots to Runs and
  (its) request in Proxy Repeater via "send to".
- **Runs** — runs table → run detail (TP/FP/FN/TN score, precision/recall, fingerprint,
  metrics, findings) — today's Results, in the list→detail frame.
- **Proxy** — a workbench with **sub-nav** (History · Intercept · Repeater · Scope & Rules)
  and the **shared message editor** with resizable request/response panes; a docked filter
  bar above History; "→ Repeater" chaining. This replaces today's vertical card stack.
- **ML** — kept out of the primary flow (your ask): tabs/cards for the classifier (PR-AUC,
  calibration, weights/explain), ranker (NDCG/precision), conformal triage, anomaly, **bandit
  posteriors** (per-arm Beta), and **mutation variants**.
- **Diagnostics** — cross-run metric trend charts, intra-run reward/coverage/latency series,
  bandit arm state, and a **store explorer** (built-in table browser, Datasette optional).

## 7. Architecture: a shared shell over a multi-page app

Move from the single hash-tab document to a **multi-page app (MPA) with a shared shell** —
**real, deep-linkable routes** per section, each a jinja template that `extends shell.html`
(sidebar + top bar + `{% block content %}`). Routes such as `/`, `/launch`, `/findings`,
`/findings/{id}`, `/runs`, `/runs/{id}`, `/proxy/history`, `/proxy/intercept`,
`/proxy/repeater`, `/proxy/scope`, `/ml`, `/diagnostics`. Rationale:

- **Scalable** — each section is an independent page (small DOM, loads only what it shows);
  the current all-in-one document does not grow well.
- **Robust & shareable** — real URLs give browser history, bookmarks, and deep links to a
  finding/run/flow; matches how the VM tools are structured.
- **Dependency-light** — stays jinja + vanilla-JS ES modules, **no build step, no SPA
  framework** (the project ethos). Live surfaces (launcher SSE, proxy polling) keep using the
  existing `fetch`/SSE within their page. Shared behavior (DataTable, message editor, list→
  detail, theme/density) lives in reusable `static/*.js` modules.

A global **client router** is intentionally *not* adopted (it would pull in framework weight);
navigation is plain links, the shell just marks the active section. Per-viewer prefs and
in-page state persist in `localStorage`.

## 8. How this satisfies the five goals

- **Intuitive** — dashboard landing, a stable left-nav spine, one consistent list→detail
  pattern, a severity/confidence color language, breadcrumbs, and "send to" chaining.
- **Organized** — clear IA sections, proxy sub-nav, **one** message editor and **one**
  DataTable, design tokens instead of ad-hoc CSS.
- **Robust** — deep-linkable routes, consistent empty/error/loading states, the safety
  invariants surfaced in the context bar, and the existing test discipline extended per view.
- **Scalable** — MPA per-section pages, a DataTable with pagination/virtualization + **saved
  views + tags**, and a token/component layer so a new section is "add a nav item + a
  template", not "grow the monolith".
- **Flexible** — light/dark/density, collapsible sidebar, resizable + orientation-toggle
  panes, saved views/filters, a command palette, and per-viewer persistence.

## 9. Migration path (incremental; each step tested, invariants preserved)

- **R0 — shell + tokens (no behavior change).** Add `shell.html` (sidebar + top context bar),
  `tokens.css` (theme + density), and extract shared JS (DataTable, message editor, list→
  detail, prefs). Render the *existing* sections inside the shell first. `[built; CC-UI-0021]`
- **R1 — routes per section + Overview.** Split `index.html` into per-section templates behind
  real routes; add the Overview dashboard. Retire the hash-tabs. `[built; CC-UI-0025, FR-UI-9]`
  — real routes (`/`, `/launch`, `/proxy`, `/runs`, `/ml`, `/diagnostics`; `/runs/{id}`
  unchanged), each its own template under `templates/sections/` extending `base.html`; the
  sidebar's `href`s mark the active section server-side (`section` context var, no client
  router); `app.js`'s hash-tab switching (`initTabs`) removed. The Overview dashboard
  (`results.overview_summary()`) ships the fixed-layout KPI row + recent-runs table + quick
  actions from §11's "lean to fixed first" call — composable widgets remain a later option.
  Findings-by-category (not "by severity" — see FR-UI-9) is a horizontal chip row for now;
  the segmented-bar/sparkline treatment described in §6 is left for a follow-up pass once a
  charting story exists (R3+/Phase 4).
- **R2 — Findings workbench.** Faceted filters + saved views over the existing `finding`/
  `attempt` data; wire "send to Repeater / open request". `[built; CC-UI-0026, FR-UI-10]`
  — `/findings` (facet plane + table) and `/findings/{id}` (detail: location, linked
  attempt/candidate, full evidence), both server-rendered per R1's route pattern;
  `results.list_findings/finding_facets/finding_detail` (category derived by joining out
  to the linked candidate's audit-rule evidence — the store has no `category` column on
  `finding`); saved views are per-viewer `localStorage` (name -> querystring); "send to
  Repeater" reuses the existing `RepeaterController.create_tab` write path History's
  flow-to-Repeater pivot already established, reconstructing a raw request from the
  finding's `url`/`method`/`param` + `evidence['payload']` (no raw bytes are stored for a
  finding) via `results.build_finding_raw_request()`.
- **R3 — Proxy workbench rebuild.** Re-lay Proxy on the shared message editor + resizable
  panes + sub-nav (folding in Phase 2.1–2.4).
- Phases **3 (ML)** and **4 (Diagnostics)** then land as sections in the shell rather than new
  top tabs.

This supersedes the Phase-0.2 top-tab shell (CC-UI-0012); it will be recorded as a decision
(UI shell = left-nav MPA) and new FR-UI entries when adopted.

## 10. Deliberate differentiators

- **Native dark mode + density** (absent from the VM tools reviewed).
- **The scanner + proxy blend** in one shell — few tools do both; the "send to Repeater from a
  finding" pivot is a genuine advantage.
- **Local, single-user speed** — no multi-tenant weight; instant, offline, loopback-only.

## 11. Open questions

- Query language now vs later — ship **faceted filters + saved views** first; add a
  powerfilter/QQL-style query bar only if needed (and never a hard filter cap).
- Composable dashboard widgets in Overview now, or a fixed hero layout first (lean to fixed
  first, composable later).
- Charting lib for Diagnostics (uPlot, still deferred to first use).
- Whether to add a ZAP-HUD-style in-lab overlay (likely out of scope; loopback panel suffices).

## 12. Sources

Burp Suite: portswigger.net/burp/documentation/desktop/tools (tools, dashboard, message-editor,
inspector, proxy/intercept, proxy/http-history, target/scope), settings/ui/display.
OWASP ZAP: zaproxy.org/docs/desktop/ui/ (3-pane, sites, break), addons/hud/, addons/requester,
ui/dialogs/options/view/, 2.10 FlatLaf themes.
Rapid7 InsightVM: docs.rapid7.com/insightvm (tour-the-home-page, dashboards, cards,
query-builder, working-with-asset-groups, what-is-a-site, working-with-vulnerabilities,
report-creation-wizard).
Tenable: docs.tenable.com/vulnerability-management (Explore/Findings, Dashboards/ManageWidgets,
Scans/Templates, FindingsFilters) and docs.tenable.com/nessus (CreateAScan, SearchAndFilterResults).
Qualys VMDR: docs.qualys.com/en/vmdr, docs.qualys.com/en/ud (Unified Dashboard),
qql_overview, option_profiles; blog.qualys.com (App Picker / UI 4.0, Unified Dashboard).
Greenbone/GSA: docs.greenbone.net/GSM-Manual (web-interface, scanning, reports), Filterkeywords PDF.
Nessus: docs.tenable.com/nessus (Folders, CreateAScan, ScanAndPolicyTemplates, Severity, Vulnerabilities).
NodeWare: nodeware.com (key-features, manage), support.nodeware.com (Network Score, Dashboards).
