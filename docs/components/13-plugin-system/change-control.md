# Plugin System — Change Control Log

Component code: **PLUG**. Entry format and required fields: see `../README.md`.
Newest first.

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
