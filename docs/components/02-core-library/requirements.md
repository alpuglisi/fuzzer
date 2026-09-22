# core/ Shared Library — Requirement Specification

Component code: **CORE** · Status: `[built — store + migrations 1-12, config, structured
logging, budget+mutex, versioned features, the HTTP send seam, plugin registry,
per-host credential store, and metric_series/log_scalar/MetricLogger]` (Phase 0,
extended through Phases 1-10 as later phases needed new store contracts) ·
Last updated: 2026-09-22 · see CC-CORE-0019

Related: `ARCHITECTURE.md` #2; `DECISIONS_AND_ROADMAP.md` (D5, D6); the store
contract; `./change-control.md`.

## 1. Purpose
Provide the shared foundation every tool imports: the project store, config,
logging, the request budget, feature extraction, an HTTP send seam, and the
plugin registry. It is the layer that makes the store the integration bus.

## 2. Scope
- **In:** store access and migrations; config; logging; budget and concurrency;
  versioned features; HTTP send seam; plugin registry.
- **Out:** any tool-specific logic; network protocols beyond a basic send seam
  (the proxy owns those).

## 3. Functional requirements
- **FR-CORE-1** Manage a single SQLite project store: schema, PRAGMAs (WAL,
  `synchronous=NORMAL`, `busy_timeout`, foreign keys), content-addressed bodies,
  and a numbered, forward-only migration runner.
- **FR-CORE-2** Provide versioned feature extraction (`extract_vN`) writing
  `features_json` + `feature_version`.
- **FR-CORE-3** Provide layered config (defaults → file → env → CLI), validated,
  and hashed onto the `run` row.
- **FR-CORE-4** Provide structured logging carrying `run_id`, `tool`, `identity`,
  and `flow_id` where applicable, plus an audit log of every request.
- **FR-CORE-5** Provide a request-budget manager with per-component caps and a
  per-host mutex that serializes timing-sensitive traffic to concurrency 1.
- **FR-CORE-6** Provide an HTTP send helper that requires a session context and
  records raw bytes.
- **FR-CORE-7** Provide a plugin registry (entry points plus hooks).
- **FR-CORE-8** Provide a `metric_series(run_id, source, key, step, ts, value)` table,
  additive to `run_metrics`, for per-step time-series metrics (training curves, bandit
  posterior/regret, coverage growth, mutation reward/novelty). `source` is a subsystem
  bucket mirroring `run_metrics` prefixes (`gbt`, `logreg`, `bandit`, `coverage`, `rank`,
  `ml`); `key` is a bounded, slash-delimited path (e.g. `train/loss`,
  `posterior/arm_3/mean`) — never a per-example/per-feature key; distributions are stored
  pre-binned, never raw. `value` is `REAL NOT NULL`; a non-finite value is rejected at
  emit time (dropped + warned), never persisted. Indexed for both a single series
  (`run_id, source, key, step`) and cross-run overlay queries (`source, key, run_id,
  step`). All writes go through `core.store.log_scalar()` or the buffered
  `core.store.MetricLogger` context manager — no other write path is permitted. All
  SQLite connections are opened through `core.store.open_store()`, which sets
  `journal_mode=WAL`, `busy_timeout=10000`, `synchronous=NORMAL`, `foreign_keys=ON`, and a
  10s driver-level connect timeout; every writer loop uses one dedicated long-lived
  connection pinned to its thread, and every read-then-write transaction uses `BEGIN
  IMMEDIATE` (never relies on `busy_timeout` alone to rescue a DEFERRED-to-write upgrade).
- **FR-CORE-9** Provide a `saved_views(id, table_key, name, spec_json, is_pinned,
  created_at, updated_at)` table (migration 12) — a UI-owned view-preference store
  (named filter/sort/column presets a viewer can save and reuse), explicitly not a
  result table (`finding`/`attempt`/`candidate`); the UI writing it does not violate
  NFR-UI-read-only.

## 4. Non-functional requirements
- **NFR-CORE-single-writer** All store writes go through one writer path; readers
  never block the writer (WAL).
- **NFR-CORE-deterministic** Feature extraction is a pure function of
  (request, response, baseline); recomputable over history.
- **NFR-CORE-secrets** Secrets are referenced, never stored in the store or
  config; redaction on write.
- **NFR-CORE-no-bypass** No tool constructs HTTP or session state outside core.

## 5. Interfaces and data contracts
Owns the store schema and migrations. Writes `run`, `schema_version`,
`request_budget`, `model`. Exposes Python APIs consumed by every tool and ML
component.

## 6. Dependencies (components)
None (foundational layer; it manages the project store).

## 7. Acceptance criteria
- A fresh database is created by the migration runner; re-running is idempotent.
- A run records its config hash; budget checkouts and the timing mutex are
  enforced.
- Golden-file feature tests pass; a feature change bumps `feature_version`.

## 8. Open questions
- Package name.
- Per-project database files plus a small global config database, versus one
  global database.
