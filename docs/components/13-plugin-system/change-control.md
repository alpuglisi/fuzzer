# Plugin System — Change Control Log

Component code: **PLUG**. Entry format and required fields: see `../README.md`.
Newest first.

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
