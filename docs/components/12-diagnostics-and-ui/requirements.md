# Diagnostics and UI — Requirement Specification

Component code: **UI** · Status: `[planned]` · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #12; `DECISIONS_AND_ROADMAP.md` (D2, D5);
`./change-control.md`.

## 1. Purpose
Make the platform observable: watch runs and interception live, explore the store,
verify functionality, and locate bugs — the research-platform diagnostics of
decision D2.

## 2. Scope
- **In:** a TUI for live runs/interception, store exploration, a metrics table,
  structured logs, a dry-run mode.
- **Out:** producing findings or scores (read-only over the store; it does not
  write results).

## 3. Functional requirements
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
- **NFR-UI-read-only** The UI reads the store and logs; it does not write results
  (`finding`/`attempt`/`candidate`).
- **NFR-UI-live** Live views reflect the current run without blocking the tools.
- **NFR-UI-redacted** Secrets never render; the UI shows redacted values only.

## 5. Interfaces and data contracts
Reads the store (all result tables) and structured logs; writes only the
`run_metrics` table and its own view/UI state. No dependency on any tool's API —
it reads the shared contract (D5).

## 6. Dependencies (components)
`core/` (store and logging).

## 7. Acceptance criteria
- Live TUI reflects an in-progress run and interception without stalling tools.
- Datasette view exposes the result tables for exploration.
- `run_metrics` is populated per run; `--dry-run` sends no traffic.
- No secret is ever rendered.

## 8. Open questions
- Metric set and refresh cadence for live views.
- Whether Datasette ships bundled or is documented as an optional add-on.
