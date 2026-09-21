# Diagnostics and UI — Change Control Log

Component code: **UI**. Entry format and required fields: see `../README.md`.
Newest first.

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
