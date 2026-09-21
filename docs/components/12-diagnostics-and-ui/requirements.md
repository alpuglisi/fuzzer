# Diagnostics and UI — Requirement Specification

Component code: **UI** · Status: `[planned]` · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #12; `DECISIONS_AND_ROADMAP.md` (D2, D5);
`./change-control.md`.

## 1. Purpose
Make the platform observable and keep the user in control of when the tools touch
the target: present a launcher that offers automatic vs manual operation (never
auto-running tools), watch runs and interception live, explore the store, verify
functionality, and locate bugs — the research-platform diagnostics of decision D2.

## 2. Scope
- **In:** a launcher with run-mode selection (automatic vs manual); a TUI for live
  runs/interception; store exploration; a metrics table; structured logs; a dry-run
  mode.
- **Out:** producing findings or scores itself (it does not write result tables;
  in automatic mode it invokes the tools, which write results).

## 3. Functional requirements
- **FR-UI-launcher** After the lab is up, present a user interface that offers two
  run modes and does nothing to the target until the user chooses:
  - **automatic** — run the discovery → fuzz pipeline and the integration harness
    against the lab;
  - **manual** — leave the lab running and make the tools available for hand-driven
    use (print ready-to-run commands with target/store pre-wired, and/or an
    interactive shell), sending nothing to the target until the user invokes a
    tool.
  Bringing up the lab must never trigger tool traffic on its own (the no-auto-run
  principle). A minimal launcher ships in Phase 0; the full TUI elaborates it.
- **FR-UI-1** A `textual` TUI showing live interception and in-progress runs.
- **FR-UI-2** Datasette (or equivalent) over the store for ad-hoc exploration of
  pages, candidates, attempts, findings, and flows.
- **FR-UI-3** A `run_metrics` table populated per run (requests, findings,
  precision, budget used, timing).
- **FR-UI-4** Structured audit and debug logs carrying `run_id`, `tool`,
  `identity`, and `flow_id`.
- **FR-UI-5** A `--dry-run` mode that plans and reports actions without sending
  traffic.

## 4. Non-functional requirements
- **NFR-UI-no-auto-run** No tool traffic reaches the target as a side effect of
  bring-up; only an explicit automatic-mode selection or a manual tool invocation
  sends requests.
- **NFR-UI-read-only** The UI itself does not write result tables
  (`finding`/`attempt`/`candidate`); in automatic mode those are written by the
  tools it invokes, not by the UI.
- **NFR-UI-live** Live views reflect the current run without blocking the tools.
- **NFR-UI-redacted** Secrets never render; the UI shows redacted values only.

## 5. Interfaces and data contracts
Reads the store (all result tables) and structured logs; writes only the
`run_metrics` table and its own view/UI state. No dependency on any tool's API —
it reads the shared contract (D5).

## 6. Dependencies (components)
`core/` (store and logging). In automatic mode the launcher invokes the tools
(crawler, auditor, fuzzer, harness) — orchestration only; the tools still write
their own results.

## 7. Acceptance criteria
- Bring-up stops at the launcher; no request reaches the target until the user
  selects automatic mode or manually runs a tool.
- Automatic mode runs the pipeline/harness; manual mode leaves the tools ready to
  invoke by hand.
- Live TUI reflects an in-progress run and interception without stalling tools.
- Datasette view exposes the result tables for exploration.
- `run_metrics` is populated per run; `--dry-run` sends no traffic.
- No secret is ever rendered.

## 8. Open questions
- Metric set and refresh cadence for live views.
- Whether Datasette ships bundled or is documented as an optional add-on.
