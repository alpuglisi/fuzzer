# Diagnostics and UI — Requirement Specification

Component code: **UI** · Status: `[planned]` · Last updated: 2026-09-21

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
