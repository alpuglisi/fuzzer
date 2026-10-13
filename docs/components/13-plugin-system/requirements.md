# Plugin System — Requirement Specification

Component code: **PLUG** · Status: `[built]` (Phase 10) · Last updated: 2026-10-13

Related: `ARCHITECTURE.md` #13; `DECISIONS_AND_ROADMAP.md` (D6, Phase 10);
`./change-control.md`.

## 1. Purpose
Let the toolkit be extended — ML models, extra rules, custom oracles, payload
sources — without changing core code, via a registry of hooks on `core/`.

## 2. Scope
- **In:** entry-point discovery, a hook registry, per-plugin isolation and
  priority.
- **Out:** the plugins themselves (ML components, rules, oracles) — they are
  consumers of this system.

## 3. Functional requirements
- **FR-PLUG-1** Discover plugins via `importlib.metadata` entry points.
- **FR-PLUG-2** Provide a hook registry: `on_request`, `on_response`,
  `on_candidate`, `on_finding`, `register_rules`, `register_payload_source`,
  `register_oracle`. *(Extended CC-PLUG-0005.)* Also `register_prioritizer` (a
  confirmation-budget order, FR-PLUG-8) and `after_run(store, run_id)` (post-run
  stages, FR-PLUG-7), where the ML stages attach (FR-ML-6).
- **FR-PLUG-3** Isolate plugins so one plugin's failure does not crash a run
  (errors are contained and logged). *(CC-PLUG-0008, BUG-0076:)* containment covers
  every per-plugin step:
  - load;
  - **metadata / registration**: any exception from `plugin_info` (e.g. `priority =
    "high"`), and a bool priority, rejects only that plugin, with its reason in
    `rejections()`;
  - **hook lookup**: a raising attribute disables only that plugin;
  - hook calls, prioritizer collection and `after_run`.
- **FR-PLUG-4** Support deterministic ordering via per-plugin priority.
- **FR-PLUG-5** Enforce that plugins honor the oracle/advisory split: a plugin may
  `register_oracle` but ML-style plugins write scores/uncertainty, not `finding`
  labels.
- **FR-PLUG-6** *(advisory write guard; CC-PLUG-0005).* While `after_run` plugins or
  a contributed prioritizer run, an **allowlist** SQLite authorizer is installed on
  the shared connection (`plugins/guard.py`).
  - **Prioritizer:** read-only.
  - **`after_run`:** plus exactly `ADVISORY_WRITES`: INSERT into `model`,
    `run_metrics` and `metric_series`, and UPDATE of `candidate.score`, `rank_score`,
    `rank_uncertainty`, `anomaly_score` and `anomaly_flag` — plus, *(CC-PLUG-0006)*,
    `score_oof` and `rank_score_oof`, and *(CC-PLUG-0007)* INSERT into
    `holdout_metric` (the sealed holdout metrics), and *(CC-PLUG-0009, BUG-0104)* INSERT
    into `holdout_seal`: a stage can add a seal, never update or delete one.
    `holdout_reveal` and `holdout_seal_meta` are never written by a plugin.
  - **Denied:** every other write (`finding`; label-defining `candidate` state;
    UPDATE/DELETE of the output tables), all DDL including `IF NOT EXISTS`,
    ATTACH/DETACH, and PRAGMA assignment.
  - **Scope:** this prevents *accidental* label writes through the shared connection.
    It is not a trust boundary: an in-process plugin can open its own connection or
    unset the authorizer (§8). It checks tables and columns, not rows.
- **FR-PLUG-7** *(post-run unit of work and run record; CC-PLUG-0005, migration 15).*
  - **Unit of work:** each `after_run` plugin commits on success and rolls back on
    failure; outstanding work is committed before dispatch. Rollback undoes a failed
    plugin's writes since its last commit. A plugin's own commits, and every write
    once it switched the transaction mode, cannot be undone.
  - **Failures:** a plugin that adds a `run_metrics` key the run already has (or for
    another run, or twice) has those rows deleted and fails. Switching
    `isolation_level` / `autocommit` fails the plugin, and the mode is restored.
  - **Run record:** `record()` writes every registered plugin with its `config`
    (canonical JSON) and `status`. `finalize()` sets `ok` or `failed` plus `error`.
    Containment is per run: it resets from the second run on, and a failure before the
    first run is kept. A duplicate plugin name is refused.
- **FR-PLUG-8** *(one budget prioritizer; CC-PLUG-0005).*
  - **One source:** at most one plugin may contribute a prioritizer; two are a
    conflict. With ML installed, `fuzzlab auto --confirm-budget` always attaches
    `ml-budget`, so a `--plugins` prioritizer cannot be combined with it.
  - **Failure:** a raise, a malformed order, or a transaction-mode switch fails the
    plugin and yields a row-order `FailedBudgetOrder`, so the cap still holds.
    `pipeline_confirm_budget_error=1` is recorded.
  - **`None`:** a valid prioritizer returning `None` still means "confirm everything"
    (thin data).
  - **Comparisons:** `budget_method` is result-only, so comparisons across runs must
    filter on `pipeline_confirm_budget_error`.
- **FR-PLUG-9** *(the optional-ML door; CC-PLUG-0005).* Outside `fuzzlab/ml/`, the ML
  package is reached only through `fuzzlab.plugins.optional.import_ml`, enforced by
  `tests/test_ml_import_guard.py`. It returns `None` only when `fuzzlab.ml` itself is
  missing, or is a namespace leftover with no `__file__`. Any other import error
  re-raises.

## 4. Non-functional requirements
- **NFR-PLUG-optional** The toolkit runs fully with zero plugins; enabling ML or
  extra rules is a config/packaging change, not a core edit (D6). *(Note, CC-UI-0041.)*
  With the `fuzzlab.ml` package absent, the scan, report and web app work. This is
  tested by simulated absence in `tests/test_no_ml.py`, including a real browser.
- **NFR-PLUG-safe** Plugins run in-process but are contained; a misbehaving plugin
  is disabled rather than allowed to corrupt the store.
  - Enforced by: `plugins.registry.contain`, `plugins.guard.guarded` — `tests/test_plugins.py::test_failing_plugin_is_disabled_not_fatal`, `tests/test_plugins_post_run.py::test_a_failed_stage_leaves_no_uncommitted_writes_behind`, `tests/test_plugins_post_run.py::test_guard_blocks_each_label_write_vector`, `tests/test_plugins_post_run.py::test_read_only_guard_denies_every_write`
- **NFR-PLUG-reproducible** The set and versions of active plugins are recorded
  onto the run.

## 5. Interfaces and data contracts
Exposes the hook API from `core/`; plugins register against it. Plugins read/write
the store only through `core/` interfaces, subject to the same contract (e.g. only
an oracle may write `finding`).

## 6. Dependencies (components)
`core/`.

## 7. Acceptance criteria
- A sample plugin registers on each hook and runs at the right point.
- A failing plugin is contained and logged without aborting the run.
- Active plugins/versions are recorded on the run; running with none works.

## 8. Open questions
- Trust model for third-party plugins (this is a lab tool; how much isolation is
  warranted).
- Whether hooks need an async variant for the proxy data path.
