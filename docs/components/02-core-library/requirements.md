# core/ Shared Library — Requirement Specification

Component code: **CORE** · Status: `[planned]` (Phase 0) · Last updated: 2026-09-22

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
- **FR-CORE-8** Provide a generic cross-run scalar time-series sink,
  `metric_series(run_id, source, key, step, ts, value)`, for per-step
  emitters from any subsystem (training curves, bandit posterior/regret,
  coverage-frontier growth, mutation-search reward/novelty, stage
  wall-clock/throughput) to write through, plus the write API:
  `log_scalar(store, run_id, source, key, step, value, ts=None)` and a
  buffered `MetricLogger(store, run_id, source, flush_every=200)` context
  manager. Non-finite values (NaN/inf) are rejected at emit (dropped, with a
  warning) — never stored. `key` values are bounded/slash-delimited paths;
  distributions are pre-binned by the writer, never stored per-example.
  Indexed for both a single series within a run and a cross-run overlay of
  the same series. (Added by CC-CORE-0018; per-component emitters that write
  through this API are separate components' scope, not CORE's.)
- **FR-CORE-9** Provide `saved_views(id, table_key, name, spec_json, is_pinned,
  created_at, updated_at)`: a durable store for named filter/sort/column specs
  a faceted UI workbench saves, keyed by `table_key` (the logical dataset the
  view is over, e.g. `"finding"`) so more than one workbench can share the
  table. `spec_json` is opaque to CORE — owned and shaped entirely by its
  caller (`fuzzlab.web.savedviews`); CORE only provides the table and index.
  (Added by CC-CORE-0019, for the Findings workbench, `CC-UI-0029`.)

- **FR-CORE-10** `_VULN_TO_CATEGORY` (in `fuzzlab.core.runmode`) maps a ground-truth
  `vuln_class` to the audit-rule/oracle category it corresponds to, when one with a
  real, working confirmer exists — an unmapped class falls through
  `to_category()`'s own fallback unchanged and is never nominated by
  `evaluate()`, so it always scores as an honest false negative rather than a
  mis-wired one. Currently maps `sqli`→`sql-injection`, `xss-reflected`/
  `xss-stored`/`xss-dom`→`xss`, and `ssti`→`server-side-template-injection`
  (added by `CC-CORE-0020`, verified live against TrackerNest's real vulnerable
  and secure `ssti` twins before landing). A class is added here only once it has
  a real, independently-verified rule+confirmation-strategy pairing — adding an
  entry for a class with no confirmer would only relabel a false negative as a
  mis-wired candidate, not improve detection, so category 3's other 5 new classes
  (`xxe`/`insecure_deserialization`/`webhook_signature_bypass`/`ssrf`/
  `outbound_header_injection`) stay unmapped until each has one.

- **FR-CORE-11** *(`open_redirect`→`open-redirect` mapping; `CC-CORE-0021`,
  2026-09-23).* Extends `FR-CORE-10`'s map with `open_redirect`→
  `open-redirect` (category 5, Booking.com's real vulnerable cell,
  `CC-LAB-0210`), verified live end to end through
  `fuzzlab.harness.multitarget.run_targets`'s own real scoring (`PA-0042`),
  not just `ConfirmationStrategy.confirm()` in isolation — that stricter
  verification bar caught two real, distinct pre-existing defects
  (`BUG-0039`: `RequestsProbeSender` followed redirects into an attacker-
  controlled canary host; `BUG-0040`: `OpenRedirectStrategy.vuln_class`'s
  spelling didn't match ground truth's own convention), both fixed before
  this mapping was considered complete — see `CC-CORE-0021`'s own entry for
  the full record and `CC-FUZZ-0027` for the fixes' own component-owner
  entry. Real, verified result: `tp=1, fn=2, fp=0` against Booking.com's
  real, locally-booted deployment. Scoped to `open_redirect` only — category
  5's other three built classes have no verified confirmer yet.

- **FR-CORE-12** *(`price_integrity_bypass`→`price-integrity-bypass`
  mapping; `CC-CORE-0022`, 2026-09-23).* Extends `FR-CORE-10`'s map with
  `price_integrity_bypass`→`price-integrity-bypass` (category 5,
  Booking.com's real vulnerable cell `LABGEN-BC-0005`, `CC-LAB-0212`),
  paired with a genuinely new rule+strategy (`R-PRICE-INTEGRITY`/
  `PriceIntegrityBypassStrategy`, `CC-FUZZ-0029`, this component's own
  FUZZ counterpart — see `FR-FUZZ-16`). Verified live end to end through
  `fuzzlab.harness.multitarget.run_targets`'s own real scoring (`PA-0042`),
  not just `ConfirmationStrategy.confirm()` in isolation. Real, verified
  result: `tp=2, fn=1, fp=0` against Booking.com's real, locally-booted
  deployment (recall `1/3 -> 2/3`). Scoped to `price_integrity_bypass`
  only — `csv_formula_injection` (Booking.com) and
  `insecure_deserialization` (Expedia) still have no verified confirmer.

- **FR-CORE-13** *(`csv_formula_injection`→`csv-formula-injection`
  mapping; `CC-CORE-0023`, 2026-09-23).* Extends `FR-CORE-10`'s map with
  `csv_formula_injection`→`csv-formula-injection` (category 5,
  Booking.com's real vulnerable cell `LABGEN-BC-0003`, `CC-LAB-0211`),
  paired with a genuinely new rule+strategy (`R-CSV-FORMULA-INJECTION`/
  `CsvFormulaInjectionStrategy`, `CC-FUZZ-0030`, this component's own FUZZ
  counterpart — see `FR-FUZZ-17`). Verified live end to end through
  `fuzzlab.harness.multitarget.run_targets`'s own real scoring (`PA-0042`).
  Real, verified result: `tp=3, fn=0, fp=0` against Booking.com's real,
  locally-booted deployment (recall `2/3 -> 1.0`) — this app's own full
  ground truth, zero false negatives, closing Booking.com's toolkit-side
  detection coverage entirely. This is category 5's fourth real detection
  and the last of Booking.com's own classes; only Expedia's own
  `insecure_deserialization` remains unmapped in this category.

## 4. Non-functional requirements
- **NFR-CORE-single-writer** All store writes go through one writer path; readers
  never block the writer (WAL).
- **NFR-CORE-central-connection** Every process and test that opens the store
  connection directly (not via `Store`) routes through the single central
  `open_store()` constructor (WAL, `busy_timeout=10000`, `synchronous=NORMAL`,
  `foreign_keys=ON`, connect-time `timeout=10.0`), so the WAL/concurrency
  design lives in one place. `connect()` is a backward-compatible alias for it.
- **NFR-CORE-deterministic** Feature extraction is a pure function of
  (request, response, baseline); recomputable over history.
- **NFR-CORE-secrets** Secrets are referenced, never stored in the store or
  config; redaction on write.
- **NFR-CORE-no-bypass** No tool constructs HTTP or session state outside core.

## 5. Interfaces and data contracts
Owns the store schema and migrations. Writes `run`, `schema_version`,
`request_budget`, `model`, `metric_series`, `saved_views`. Exposes Python APIs
consumed by every tool and ML component.

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
