# Plugin System — Change Control Log

Component code: **PLUG**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-PLUG-0006 — The advisory write allowlist gains the out-of-fold columns (2026-10-13)
- Change: `guard.ADVISORY_WRITES["update_candidate"]` gains `score_oof` and
  `rank_score_oof` (migration 16). Run-mode stages write them, and every other scoring
  pass clears them, under the `after_run` guard.
- Impact: FR-PLUG-6 text updated. Nothing else changes in the guard.
- Risk: low.
- Deliverables:
  - [x] Allowlist — done
  - [x] Test: the declared set is updated; every built-in stage still runs under the
    guard (`test_ml_plugins.py`) — done
- Review: pre-change review gate cleared 3/3 over drafts v1 to v4 (the proposing agent plus 2 independent reviewer agents; every raised issue adopted).
  - **Process note:** `core/oracle_status.py`, `core/urls.canonical_origin`, the dataset changes and `--hybrid` were drafted in the working tree **before** agreement. They were kept uncommitted and reconciled with the agreed v4.
  - **Reverted:** my early in-column version of D-c was reverted; reviewer B's separate-column design replaced it.
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (ML, auto, web incl. browser smoke, plugins, report, no-ML, harness, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 705 passed, including `test_ml_saved_and_decisions.py` 39 and `test_auto_train_on.py` 13. Mutation-checked on a copy with bytecode caches cleared: all 20 mutants are killed. The first run left two survivors, and each got a new test (noisy data where in-sample and out-of-fold PR-AUC differ; an earlier-trained saved source). Killed:
  - **gates:** the legacy gate on in-sample scores, `score_oof` ignored, the run page or conformal panel judging `score`;
  - **out-of-fold columns:** not written, not cleared by earlier mode, ranker out-of-fold dropped;
  - **saved selector:** any scope run, a bool scope, copies chosen, the wrong `train_run_ids`;
  - **targets and labels:** the localhost alias dropped, an empty host matching, no_confirmer labelled, exact-text target matching;
  - **UI and report:** the tab's metrics on deploy scores, the out-of-fold label missing, the report's saved block missing;
  - **CLI:** `--hybrid` allowed with saved.
  Full-suite result (on commit c16477e, `FUZZLAB_REQUIRE_BROWSER=1`): 3113 passed, 65
  skipped, 9 xfailed, 33 failed. The 33 failures are exactly the known environmental
  labgen failures (no scipy, sklearn or gitleaks), identical to the step-3 baseline.

### CC-PLUG-0005 — Post-run and budget-order hooks; advisory write guard; the run record (2026-10-13)
- Change:
  - **Two new hooks** (`plugins/hooks.py`):
    - **`after_run(store, run_id)`**, a new post-run kind. It runs after the pipeline,
      in ascending priority, through `PluginManager.after_run(store, run_id) ->
      list[HookOutcome(info, ok, result, error)]`.
    - **`register_prioritizer()`**, a registration hook. It returns a
      confirmation-budget prioritizer `(store, run_id, candidate_ids) -> order | None`.
      `PluginManager.prioritizers()` collects them once per manager, and
      `guarded_prioritizer()` returns the single one wrapped. Two contributors raise
      `PluginConflict`.
  - **Each `after_run` plugin is one unit of work** (`manager.py`):
    - Outstanding work (the scan's results) is committed first.
    - After each plugin: **commit** on success, **rollback** on failure.
    - **Metric shadowing:** the manager snapshots `max(run_metrics.id)` and the run's
      metric keys before **each** plugin. It deletes, explicitly, any row the plugin
      inserted that belongs to another run, repeats a key the run already had, or
      repeats a key the plugin inserted twice. The plugin then fails. An explicit delete
      is needed because plugins, the built-ins included, commit their own writes.
    - **Transaction mode:** switching `isolation_level` / `autocommit` fails the plugin.
      The mode is restored and then rolled back, in that order.
    - **Honest limit:** a plugin's own commits cannot be undone. That includes
      `MetricLogger`'s mid-fit `with conn:`, and every write once the transaction mode
      was switched.
  - **Advisory write guard** (`plugins/guard.py`, FR-PLUG-6). An allowlist SQLite
    authorizer sits on the shared connection while these hooks run, and is removed in
    `finally`.
    - **Prioritizer:** read-only.
    - **`after_run`:** the read-only set, plus exactly `ADVISORY_WRITES`:
      - INSERT into `model`, `run_metrics` and `metric_series`;
      - UPDATE of `candidate.score`, `rank_score`, `rank_uncertainty`, `anomaly_score`
        and `anomaly_flag`.
    - **Everything else is denied:** any write to `finding`, label-defining `candidate`
      state, and UPDATE/DELETE on the output tables; every CREATE/DROP/ALTER (closing the
      rename round-trip, trigger and temp-shadow vectors); ATTACH/DETACH; and PRAGMA
      assignment.
    - **Scope:** accident prevention on the shared connection. It is not a trust
      boundary, and it checks tables and columns, not rows. DDL is denied even as
      `IF NOT EXISTS`, so `Store.schema_version()` cannot run inside a guarded hook.
  - **Prioritizer failure.** A raise, a malformed order, or a transaction-mode switch
    fails the plugin. The wrapper then returns `FailedBudgetOrder`: the given ids in row
    order with `error`, so the confirmation cap still holds. A valid `None` still means
    "confirm everything" (thin data).
  - **Registry** (`registry.py`):
    - A duplicate name is refused and listed in `rejected()`.
    - The first contained error per plugin is kept (`errors()`).
    - `handlers`, `contain`, `fail`, `reset` and `registered` are public.
    - `PluginInfo` gains `config`: canonical JSON of the plugin's `config` dict, built
      in one place by `plugin_config`. A non-dict or non-serialisable config gives `""`.
  - **Run record:**
    - `record()` starts a run scope. From the second run on it resets containment; a
      failure before the first run (e.g. at registration) is kept.
    - It writes **every** registered plugin, with config and `status='attached'`, or
      `'failed'` plus the error if it had already failed.
    - New `finalize()` marks each one `ok` or `failed` with its error (migration 15,
      CC-CORE-0028).
    - `from_entry_points(extra=…)` registers built-ins ahead of entry points.
  - **New `plugins/optional.py`** (FR-PLUG-9) is the one door into `fuzzlab.ml`.
    - `import_ml(module)` returns `None` only when `fuzzlab.ml` itself is missing, or
      is a namespace leftover with no `__file__`. Any other import error re-raises.
    - It also provides `ml_available()` and `ML_UNAVAILABLE`.
- Impact:
  - The ML stages attach here (CC-ML-0017), and `run_auto` dispatches the new hooks
    (CC-FUZZ-0050).
  - With zero plugins everything is a no-op.
  - **Behaviour changes for existing plugin users:**
    - a duplicate name is refused;
    - `record()` now writes disabled plugins too, as `failed`. `test_plugins.py`'s
      record test was updated to this contract.
  - FR-PLUG-2 extended; FR-PLUG-6/7/8/9 added; header `[planned]` → `[built]`.
- Risk: medium-low. The guard is an allowlist, so a new legitimate write needs a
  declared entry. The tests run every real stage under it (CC-ML-0017).
- Deliverables:
  - [x] Hooks, unit of work, guard, prioritizer wrapper, registry and record changes — done
  - [x] `tests/test_plugins_post_run.py` (56) — done:
    - dispatch order and containment;
    - rollback of a failed stage's uncommitted writes;
    - 23 guard vectors, each asserting the write is absent: a self-swallowing plugin
      tries INSERT/UPDATE/DELETE/REPLACE/INSERT…SELECT on `finding`, `executescript`,
      the rename round-trip, DROP COLUMN/TABLE, persistent and temp triggers, a view
      with an INSTEAD OF trigger, a temp shadow table, `writable_schema`, `oracle_status`
      (alone and alongside `score`), `evidence`, `run_id`, INSERT/DELETE on `candidate`,
      UPDATE/DELETE on `run_metrics`, and DELETE on `model`;
    - a statement prepared before dispatch is re-checked;
    - exactly the advisory writes pass, and the guard is removed afterwards;
    - DDL is denied with `IF NOT EXISTS`; the read-only guard denies writes;
    - metric shadowing: committed by the plugin, for another run, the same plugin twice,
      a key from an earlier plugin;
    - a transaction-mode switch;
    - the prioritizer: read-only, five failure shapes giving `FailedBudgetOrder`, `None`
      passing through, conflict, collected once;
    - a duplicate name; per-run reset; a pre-run failure recorded; canonical config;
    - migration 15;
    - the authorizer itself denies each DDL, ATTACH and PRAGMA-assignment action, and
      any non-`main` database, in both modes. DDL is also refused through the
      schema-table writes it implies, so the behavioural vectors alone cannot show which
      layer acted; this test pins the first layer;
    - `import_ml`: present, absent, namespace leftover, a broken submodule, and a present
      package whose own dependency is missing (which must raise, not read as "not
      installed"), the last four in subprocesses.
- Implementation divergence (written back per the review gate):
  1. The prioritizer wrapper returns `FailedBudgetOrder` when its plugin was already
     disabled earlier in the run. It also checks the transaction mode and rolls back
     after the read-only call.
  2. A non-callable returned by `register_prioritizer` is a failure.
  3. `import_ml` raises `ValueError` for a non-ML module name.
- Preventive-action compliance:
  - **PA-0003:** one options→plugins mapping, one config serialisation, one ML door.
  - **PA-0021:** typed `import_ml` errors.
  - **PA-0034(2):** every guard is proven on bad input.
  - **PA-0063/0067:** `run_plugin` is read per run by its only reader.
  - **PA-0064(1):** a crashed prioritizer gives an explicit failed order, never a stand-in
    that looks valid.
  - **PA-0065:** web changes verified with `FUZZLAB_REQUIRE_BROWSER=1`.
- Review: pre-change review gate cleared 3/3. The proposing agent and 2 independent reviewer agents went through DRAFT v1 to v4.
  - Reviewer A focused on architecture and spec fit; reviewer B on adversarial correctness, safety and tests, with SQLite experiments.
  - Every raised issue was adopted.
  - v1's guard was bypassable (a rename round-trip, a later-firing trigger, a temp shadow table, label state outside `finding`, an unguarded prioritizer). v1's failed-stage writes could also be committed by the next stage. Both were redesigned before any code.
- Effectiveness (assessed 2026-10-13): effective offline. `tests/test_plugins_post_run.py` 56 passed and `tests/test_plugins.py` 12 passed. Mutation-checked on a copy of the tree, with bytecode caches cleared and `FUZZLAB_REQUIRE_BROWSER=1`: all 26 mutants are killed. The first run left two survivors, and each got a new test:
  - allowing DDL in the guard was masked by its second layer (DDL implies schema-table writes), so a direct authorizer test was added;
  - treating any missing module as "ML absent" was uncovered for a present package whose own dependency is missing, so that subprocess case was added.
  Killed:
  - **guard:** inserts, update columns, the read-only mode;
  - **unit of work:** rollback, metric shadowing, duplicate key, transaction-mode restore;
  - **run record:** run-scope reset, pre-run failure recorded, duplicate names;
  - **budget prioritizer:** failed order → confirm-all, foreign ids, `pipeline` budget error, CLI budget line;
  - **without ML:** module-level ML import in `mlview`, no panel degrade, report marker, run-page marker, the ML-absent CLI error, `import_ml` namespace;
  - **dispatch and wiring:** `run_auto` dispatch, CLI exit code, a plugin's `train_on`;
  - **output:** a one-character summary drift. Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 3062 passed, 33 failed, 68 skipped, 9 xfailed. The 33 failures are the identical environmental labgen set as at `a3b782d` and `882cda8` (diffed: no scipy, scikit-learn or `gitleaks` binary here). Every skip is in lab/labgen/corpus tests guarded on toolchains or services, none in a file this change touches; the +3 against `882cda8`'s run is in that environment-dependent set. Whether a third-party plugin uses the hooks well in practice is still to be shown (T10.6).

### CC-PLUG-0004 — register_payload_source consumer (payload pool) (2026-09-21)
- Change: wired the last hook end-to-end. `fuzzlab/mutation/payloads.py::PayloadPool`
  aggregates seed payloads per vuln class from a small built-in catalog plus any plugin
  **payload sources** (`register_payload_source`, objects with `payloads_for(vuln_class,
  sink_context)`), deduped and contained (a bad source is skipped). `PayloadPool.from_plugins`
  folds in `PluginManager.payload_sources()`, and `MutationSearch.search_pool(pool, …)`
  consumes it — plugin-contributed payloads become the bases the mutation engine evolves
  against a filter. This closes the T10.2 follow-up: all seven FR-PLUG-2 hooks now have a
  consumer.
- Impact (other components / project): a plugin can now extend the toolkit's payload
  catalog without core edits, feeding the Phase 8 mutation search. Built-ins keep the pool
  useful with zero plugins. No store or dependency change.
- Risk (level; mitigation): low — additive, contained (bad sources skipped), advisory.
  Mitigated by 5 tests (`tests/test_mutation_payloads.py`): built-ins present + unknown
  class empty; sources merge + dedupe (built-ins first); a raising source is skipped;
  `from_plugins` collects `register_payload_source`; `search_pool` runs one search per
  seed. Suite 390 passed / 4 skipped.
- Deliverables:
  - [x] `PayloadPool` + `from_plugins` + `MutationSearch.search_pool` — done.
- Effectiveness (assessed 2026-09-21): effective in tests — plugin payload sources flow
  through the pool into the mutation search; all seven hooks are now consumed.

### CC-PLUG-0003 — Hooks wired into the pipeline (T10.2) (2026-09-21)
- Change: attached the hooks at their real seams, all no-ops with zero plugins (D6).
  `core/http.py::HttpClient` takes an optional `plugins` and fires **on_request** (folded,
  may edit the outgoing request — re-checked against scope) and **on_response** (observe).
  `audit/engine.py::evaluate` gains `plugins`: **register_rules** contributes extra rules
  and **on_candidate** is notified per emitted candidate. `oracle/oracle.py::Oracle` gains
  `plugins`: **register_oracle** appends plugin confirmers (the only plugin path to a
  finding-writer) and **on_finding** is notified per confirmed finding. `plugins` is
  threaded through `run_pipeline`/`run_auto`, which also `record()`s the active set onto
  the run; `fuzzlab auto --plugins` discovers entry-point plugins (default off).
- Impact (other components / project): ML models, extra rules, and custom oracles can now
  extend a real run without core edits. The oracle/advisory split holds at the boundary:
  observation-hook returns are ignored, so an `on_finding`/`on_candidate` observer cannot
  write a label — only a `register_oracle` confirmer can. `register_payload_source` is
  collectable via `PluginManager.payload_sources()`; its consumer (a central payload pool
  in the fuzz/mutation layer) is a documented follow-up, so no dead wiring is added.
- Risk (level; mitigation): low — every attachment is behind an optional `plugins` param
  defaulting to None (zero behavior change without plugins). Mitigated by 7 tests
  (`tests/test_plugins_wiring.py`): on_request reaches the wire + on_response observes +
  no-plugins unchanged; register_rules fires a candidate + on_candidate sees it; a plugin
  oracle writes a finding + on_finding observes; an observer alone writes nothing; and
  run_auto records the active plugin set. Suite 367 passed / 4 skipped.
- Deliverables:
  - [x] on_request/on_response at the HTTP seam — done.
  - [x] register_rules/on_candidate in the auditor — done.
  - [x] register_oracle/on_finding in the oracle; `run_auto` records + `--plugins` — done.
  - [ ] register_payload_source consumer (fuzz/mutation payload pool) — follow-up.
- Effectiveness (assessed 2026-09-21): effective in tests — plugins observe/mutate at the
  right points, only oracles reach the writer, and zero-plugin runs are unchanged; a live
  sample-plugin-extends-without-core-change demonstration is the T10.6 exit.

### CC-PLUG-0002 — Plugin registry, hooks, discovery, isolation (T10.1) (2026-09-21)
- Change: implemented the plugin system. `fuzzlab/plugins/` — `hooks.py` (the seven
  FR-PLUG-2 hooks classified as mutation/observation/registration), `registry.py`
  (`HookRegistry`: priority ordering, `chain`/`notify`/`collect` dispatch, and
  contain-log-**disable** isolation so one plugin's error never aborts a run),
  `discovery.py` (`importlib.metadata` entry-point discovery in the `fuzzlab.plugins`
  group, injectable for tests, bad plugins skipped), and `manager.py` (`PluginManager`:
  the pipeline-facing dispatch surface + `record()` onto migration 10's `run_plugin`).
  The oracle/advisory split holds through plugins (FR-PLUG-5): observation-hook returns
  are ignored, so only a `register_oracle` plugin reaches the finding-writer. Zero
  plugins is a full no-op (D6/NFR-PLUG-optional).
- Impact (other components / project): gives the toolkit its extension surface — ML
  models, extra rules, custom oracles, payload sources attach here without core edits
  (T10.2 wires the attachment points into the pipeline). Adds migration 10's `run_plugin`
  for reproducible plugin recording (see CC-CORE-0016). No behavior change with no plugins.
- Risk (level; mitigation): low — additive, optional, contained; nothing runs unless a
  plugin is installed/registered. Mitigated by 12 tests (`tests/test_plugins.py`):
  migration-10 schema; priority ordering + mutation fold (None keeps prior); observation
  returns ignored (advisory split) and oracle-only writer path; registration collectors;
  a failing plugin is disabled not fatal; zero-plugin no-op; entry-point discovery
  (incl. a factory and a contained load failure); `record` writes only active plugins;
  bare-plugin defaults. Suite 360 passed / 4 skipped.
- Deliverables:
  - [x] Registry + 7 hooks + priority + isolation (FR-PLUG-1..5) — done.
  - [x] Entry-point discovery + `PluginManager` + `run_plugin` recording — done.
  - [ ] Wire hooks into the pipeline (T10.2); anomaly detector (T10.3); report (T10.4);
        multi-target transfer (T10.5); exit (T10.6) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — plugins dispatch in priority
  order, a failing one is contained, only oracles reach the writer, and zero plugins is a
  no-op; the sample-plugin-extends-without-core-change exit follows once the hooks are
  wired in (T10.2).

### CC-PLUG-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented. The
  hook set is defined so later components (ML, extra rules, custom oracles) can be
  built as plugins from the start.
- Impact (other components / project): once built, the ML components attach here,
  and extra rules/payload sources/oracles register through it — it is how the
  toolkit extends without core edits (D6). Depends only on `core/`. It enforces
  part of the store contract at the boundary (only an oracle plugin may write
  `finding`).
- Risk (level; mitigation): low–medium — in-process plugins could destabilize a
  run or (via `register_oracle`) write labels wrongly. Mitigated by per-plugin
  isolation with contained failures, recorded plugin versions for reproducibility,
  and enforcing the oracle/advisory split at the hook boundary. Sequenced last
  (Phase 10), after the components that will consume it are understood.
- Deliverables:
  - [ ] Entry-point discovery (`importlib.metadata`) — todo (Phase 10).
  - [ ] Hook registry (request/response/candidate/finding/rules/payload/oracle) — todo (Phase 10).
  - [ ] Per-plugin isolation + priority ordering — todo (Phase 10).
  - [ ] Oracle/advisory split enforced at the boundary — todo (Phase 10).
  - [ ] Active-plugin set/versions recorded on the run — todo (Phase 10).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by a
  sample plugin registering on each hook, a failing plugin being contained without
  aborting the run, and the toolkit running unchanged with zero plugins.
