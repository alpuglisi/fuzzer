# Diagnostics and UI — Change Control Log

Component code: **UI**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-UI-0025 — R1: deep-linkable per-section routes + Overview dashboard (2026-09-22)
- Change: built R1 of the layout redesign (`docs/UI_LAYOUT_REDESIGN.md` §9), the enabling
  routing refactor plus the Overview dashboard it was sequenced with.
  - **Real routes, hash-tabs retired.** Split the single `templates/index.html` (five
    `<section class="panel" id="tab-*">` blocks toggled by `app.js`'s `initTabs`/hash
    listener) into `templates/sections/{overview,launch,proxy,runs,ml,diagnostics}.html`,
    each its own small page extending `base.html`. `app.py` gained one route per section
    (`GET /`, `/launch`, `/proxy`, `/runs`, `/ml`, `/diagnostics`; `/runs/{id}` unchanged)
    instead of one `index()` handler assembling the whole document. `base.html`'s sidebar
    now links to real `href`s (`/`, `/launch`, …) with the active item marked **server-side**
    from a new `section` context field (`_shell_context(cfg, section)`) via `aria-current`
    — no client router, per the project's no-build/no-SPA-framework policy. `app.js` lost
    `PANELS`/`TABS`/`activate`/`currentTab`/`initTabs` (dead once every section is its own
    document); `initShell`, `initLaunchNav`, `initLaunchForms`, and the proxy-workbench
    initializers are unchanged and still self-guard on missing elements, so they no-op
    correctly on pages that don't have their markup.
  - **Overview dashboard** (`/`, FR-UI-9): a new `results.overview_summary(store)` (pure,
    testable without FastAPI, one query pass, never creates a missing store) returns
    total findings + a **by-category** breakdown (the store has no severity field yet —
    `finding.confidence` is a free-text oracle-mechanism label, not a severity enum, so R1
    groups by `vuln_class` instead of inventing a severity taxonomy the schema doesn't
    have), total/last-7-days run counts, the latest run, the latest *scored* run's
    detection quality (F1 + MCC from `run_metrics`; added `f1` to `results._SCORE_KEYS`),
    the latest run with an efficiency metric (`requests_per_finding`), and a bounded
    recent-runs slice. `sections/overview.html` renders it as five KPI tiles (an em-dash,
    never a bare `0`, when a run is unscored or has no efficiency metric yet), a recent-runs
    table linking to `/runs/{id}`, and quick actions to `/launch` and `/proxy`.
  - `run.html`/`not_found.html`'s "back" link now points at `/runs` (the Runs list route)
    instead of `/` (now Overview).
- Impact (other components / project): UI only. No new store writes (`overview_summary` is
  read-only; NFR-UI-read-only holds) and no schema change — `f1` was already written to
  `run_metrics` by `harness/integration.py::record_metrics` (report.as_dict()), just not
  previously surfaced through `results._SCORE_KEYS`. The command-spec/launcher contract
  (FR-UI-6, X0's `group` field) is untouched: `/launch` renders the same activity-picker
  markup `initLaunchNav()` expects, just under its own route. The Proxy workbench's DOM ids
  (`#flow-table`, `#intercept-card`, `#repeater-card`, `#scope-card`, …) are unchanged, just
  moved to `/proxy` — U3 (the Proxy rebuild) still has a stable base to build on. Deliberately
  **not** in this pass (left for a follow-up under U0's own tracked scope in
  `docs/UI_IMPLEMENTATION_PLAN.md`): splitting `app.js`/`app.css` into per-section modules —
  R1's acceptance criteria in `docs/UI_LAYOUT_REDESIGN.md` §9 are routes + Overview, and the
  single-file assets still work correctly per-page (each page's init functions self-guard on
  missing elements).
- Risk (level; mitigation): low-medium (a routing/template refactor touching every page, but
  no new state, no new writes, and the API surface is untouched). Mitigation: every existing
  web test that assumed launcher/proxy/results content lived at `/` was updated to its new
  route (`tests/test_web_frontend.py`, `test_web_launcher.py`, `test_web_proxy_history.py`,
  `test_web_results.py`) rather than left to silently pass against the wrong page; a new
  `tests/test_web_overview.py` covers `overview_summary` on an empty store, a seeded store
  (real findings/runs/metrics, not mocked), the recent-runs limit, and the `/` route's
  rendering (empty-state copy, real KPI values, quick-action links); a new pair of frontend
  tests assert every section route resolves inside the shell and marks itself active, and
  that the sidebar's `href`s match the retired hash-tab names 1:1. The two Playwright browser
  smokes (`test_web_launcher_browser.py`, `test_web_repeater_browser.py`) still pass: the
  first now `goto`s `/launch` directly (it was exercising the Launcher, not Overview) and its
  in-page `nav.tabs a[data-tab="proxy"]` click now does a real page navigation to `/proxy`
  instead of a hash change — Playwright's `.click()` on an `<a>` handles that transparently,
  no test logic changed; the second was already navigating to `/` then clicking through to
  Proxy, unaffected.
- Deliverables:
  - [x] `templates/sections/{overview,launch,proxy,runs,ml,diagnostics}.html` + one route
    each in `app.py` (`overview`, `launch_page`, `proxy_page`, `runs_page`, `ml_page`,
    `diagnostics_page`) — done; `templates/index.html` removed.
  - [x] `base.html` real `href`s + server-rendered active state (`section` context var) —
    done.
  - [x] `app.js`: hash-tab switching removed (`initTabs` and its helpers) — done.
  - [x] `results.overview_summary()` + `f1` in `_SCORE_KEYS` — done.
  - [x] `sections/overview.html` KPI tiles + recent runs + quick actions — done.
  - [x] `run.html`/`not_found.html` back-links repointed at `/runs` — done.
  - [x] Existing web tests repointed at their new routes; `tests/test_web_overview.py` added
    (route resolution + Overview data-wiring); focused web suite green (91 passed) — done.
  - [x] Full fast suite (`pytest -q -m "not slow"`): 1542 passed, 8 skipped, 11 deselected,
    3 failed — the 3 failures are pre-existing, unrelated `test_labgen_*`
    (`dom_innerhtml_echo` Laravel emitter) failures from concurrent uncommitted work already
    in the shared tree before this lane started, not a regression from this change — done.
- Effectiveness (assessed 2026-09-22): effective — the panel now has real, bookmarkable/
  shareable URLs per section and a landing dashboard wired to live data, closing the R1 gap
  UI_LAYOUT_REDESIGN.md flagged as blocker-free and first in sequence. Re-assess once R2
  (Findings workbench) lands on top of these routes.

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
