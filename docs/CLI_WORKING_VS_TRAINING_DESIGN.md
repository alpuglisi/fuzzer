# CLI simplification: a default store, working runs vs training runs

Status: **design (gate pending)**. Owner request (2026-10-15): the CLI is too complicated.
They want two things. First, `--store` should never be required. Second, *working* runs
(fuzzlab used as a tool) should be separate from *training/benchmark* runs (ground truth,
scoring, model training, holdouts, calibration, the model registry).

This doc is the design gate's subject. It covers the command taxonomy, the per-flag
classification, the default store, back-compatibility, the two build phases, the tests,
the docs to change, and the draft change-control entries (Appendix A; the pre-change
review gate in `docs/components/README.md`).

## 0. Constraints this lane works under

- **Locked files.** Another session has unpushed work in these files. Until
  `origin/ccr-27885270-9ahcdd` carries a BUG-0138 commit, this lane must not edit them:
  `harness/auto.py`, `harness/auto_cli.py`, `harness/pipeline.py`,
  `greybox/greybox_cli.py`, `greybox/run.py`, `tools/spider.py`, `tools/fetcher.py`,
  `tools/store_adapter.py`, `session/*`, `core/http.py`, `core/urls.py`, the oracle and
  browser modules, and `proxy/session_capture.py`. **Phase 1** touches none of them.
  **Phase 2** begins only after that merge.
- **`fuzzlab/web/` is not edited.** The UI builds argv from the tools' own parsers
  (`web/commandspec.py`), so every old command name and flag keeps working unchanged.
  The UI keeps passing `--store` explicitly.
- **No store migrations** in this lane.
- **Reserved numbers:** `CC-*-0400…0449`, `BUG-/PA-0400…0449`, `FR-*-400+`.

## 1. Facts verified in the code (2026-10-15, at `cdde39f`)

- `fuzzlab/cli.py` dispatches `web session crawl audit fuzz auto greybox-run proxy
  mutate-run report reveal-holdout flow-anomaly lab-generate build-db version`. Its help
  is one flat list.
- `--store` is **required** in `auto`, `greybox-run`, `mutate-run`, `report`,
  `reveal-holdout` and `flow-anomaly`. It is **optional** in `crawl`, `audit` and `fuzz`
  (opt-in consolidation) and in `proxy` (opt-in flow recording).
- **Ground truth never trains a model.** `ml/dataset.py` labels come from the oracle:
  a confirmed finding is a positive, and a checked candidate the oracle did not confirm
  is a negative. Ground truth does three things: it scores a run (`harness/scoring.py`);
  it supplies `--points ground-truth` (contract points instead of a crawl); and under
  D14 it auto-derives the categories (`core/runmode.resolve_run`).
- **An existing store setting.** `core/config.DEFAULTS["store_path"] = "fuzzlab.db"`
  (relative to the cwd), overridable through `FUZZLAB_STORE_PATH`. The web UI reads it
  (`web/app.py`, `cfg.get("store_path", "fuzzlab.db")`). No CLI reads it. Note that
  `load_config()` reads no config file unless it is given a path.
- `cli_dryrun.report(name, args)` builds its plan from `web.commandspec.spec(name)`. A
  new command without a commandspec entry cannot use it unchanged.
- `crawl` sends traffic but has no `--authorized` gate (it predates D11's gate). This
  lane does not change that. `scan` (Phase 2) requires `--authorized` for the whole
  pipeline, the crawl included.

## 2. Command taxonomy

### 2.1 Groups

| Group | Commands | What it is for |
| --- | --- | --- |
| **Working** (fuzzlab as a tool) | `scan <url>` *(Phase 2)*, `crawl`, `audit`, `fuzz`, `session`, `proxy`, `report`, `web` | Point it at a target you may test and run it. No ground truth. ML only as it is *used* (apply saved models, bandit, budget, anomaly flags). |
| **Training / benchmark** | `train run <url>`, `train models`, `train reveal-holdout`, `train flow-anomaly`, `train mutate` | Ground truth, scored runs, model training and its modulators, holdouts, calibration, the model registry, and the research learners. |
| **Lab** | `lab-generate`, `build-db`, `greybox-run` (needs the instrumented lab's side channel); lab control is `lab/labctl.sh` or the web UI's Lab page | Building and driving our own lab. |
| **Other** | `version`, `help` | |

**Decisions.**

- **D-1. One training group, named `train`. No separate `benchmark` command.** A
  benchmark run is a `train run` given `--ground-truth`. The same engine and flags serve
  both, and two top-level names for one parser is the kind of complexity the owner
  asked us to remove. The help text says "training and benchmark" so the word is still
  findable.
- **D-2. `mutate-run` moves to `train mutate`.** It learns WAF evasion and records
  `payload_variant` rows (research data). It produces no findings.
- **D-3. `greybox-run` goes in the Lab group.** It needs the lab's coverage/DB-fault
  shim (ON_HOST_RUNBOOK Part E) and cannot run against an arbitrary target. Its
  `--ground-truth`/`--points` therefore stay; Lab is not a working group.
- **D-4. `flow-anomaly` goes in training** (per the owner's brief). It fits a detector
  on recorded flows. It stays reachable under its old name.
- **D-5. `train models`** is a new, read-only listing of saved models. Use it to find a
  `--model-id`. It prints only label-free facts: id, name, version, feature version,
  creation time, `trained_on`, the run scope, and whether params are saved. It never
  prints a metric, so no sealed holdout number can leak (PA-0092).

### 2.2 Grouped help (`fuzzlab`, `fuzzlab --help`)

The text is printed from one table, `cli_taxonomy.COMMANDS` (§6). A test asserts that
every dispatchable name appears in the help exactly once, in exactly one group.
Phase 1 does not list `scan`, because the help never advertises a command that does not
exist yet (PA-0015's spirit). Phase 2 adds it.

```
usage: fuzzlab <command> [args]      (fuzzlab <command> --help for its options)

Working runs: use fuzzlab as a tool against a target you are authorized to test
  crawl [args]         crawl the target ...
  audit [args]         ...
  fuzz [args]          ...
  session <sub>        ...
  proxy [args]         ...
  report [args]        ...
  web [--with-proxy]   ...

Training and benchmark: ground truth, scored runs, model training, holdouts, models
  train run <url>      a run scored against ground truth and/or that trains models
  train models         list saved models (the model registry; read-only)
  train reveal-holdout print a run's sealed holdout metrics (counts the reveal)
  train flow-anomaly   flag each host's most unusual recorded flows
  train mutate         learn + evade the live lab WAF, record variants

Lab
  lab-generate [args]  ...
  build-db [args]      ...
  greybox-run [args]   ...

Other
  version

Older names (still work, unchanged): auto (= train run with --base-url/--store),
  mutate-run, reveal-holdout, flow-anomaly

Store: --store PATH, else $FUZZLAB_STORE, else $FUZZLAB_STORE_PATH,
       else ~/.local/share/fuzzlab/default.db (created on first use)
Lab-only. Nothing runs against a target until you ask it to (no auto-run).
```

## 3. Flag classification

The classes:

- **W** (working): available in working runs.
- **T** (training): only in `train …`. In a working command it is refused loudly, and
  the message names the training command.
- **B** (both): same meaning in both.
- **W\*** (working, with narrowed semantics): stated per row.

The table lives in code as `cli_taxonomy.FLAG_CLASSES` (§6). A guard test fails on any
parser dest the table does not classify, so a new flag cannot reach a working command
unclassified.

### 3.1 `auto` (the engine of `scan` and `train run`)

| Flag | Class | Reason |
| --- | --- | --- |
| `--base-url` | B | The target. Positional `<url>` in `scan` and `train run`; `--base-url` kept as an alias. |
| `--spider-db` | B | Crawl input. Internal in `scan` (it runs the crawl itself, §4.5). Explicit in `train run`. |
| `--store` | B | Optional everywhere; resolved by `core.storepath` (§4). |
| `--ground-truth` | **T** | Known answers: scoring, contract points, D14 category derivation. Never a working option (owner). |
| `--mode` | **T** | `automatic` only matters with ground truth (D14 derives the categories; without it, D15 demands `--categories`). A working run is hand-driven tool use, i.e. D14's *manual* mode. `scan` always runs manual with explicit categories. |
| `--points` | **T** | `ground-truth` sourcing is a benchmark. A working run always uses crawl points. |
| `--categories` | B | Which categories to test. **In `scan` it is required** (D15: never "test everything" by default); the literal `all` is the explicit opt-in to every known category. |
| `--identity` | B | Authenticated run. |
| `--auth-origin` *(arrives with BUG-0138)* | B | Credential origin allow-list; a session/safety option. Pre-classified so the merge stays green. |
| `--browser` | B | M6 confirmation mechanism. |
| `--oob` | B | M8 confirmation mechanism (loopback listener). |
| `--greybox-coverage-file`, `--greybox-dbfault-file` | B | M10 confirmation inputs (default off). |
| `--bandit` | B | Adjusts ML use while testing: it orders mechanisms. Its posteriors update online, which is use, not a training run (owner's list). |
| `--score` | **W\*** | `scan`: **apply** the saved classifier (`--train-on saved` implied). `train run`: train (run/earlier) or apply. Refuses on a store with no saved model, naming `fuzzlab train run --score`. |
| `--rank` | **W\*** | Same as `--score`, for the ranker. |
| `--model-id`, `--ranker-model-id` | B | Pick which saved model to apply. |
| `--train-on` | **T** | Chooses training data. `scan` fixes it to `saved`. |
| `--rank-objective` | **T** | A fitting choice. |
| `--calibrate` | **T** | Fits a calibrator; a training modulator. |
| `--holdout` | **T** | Sealed blind holdout: evaluation hygiene for training. |
| `--hybrid` | **T** | Adds a training feature. |
| `--confirm-budget`, `--budget-method`, `--budget-seed` | B | Adjust ML use while testing (owner's list). The ordering model is fit on *earlier* runs' oracle labels at run time and never saved. |
| `--anomaly`, `--anomaly-contamination`, `--anomaly-method` | B | Label-free tripwire over this run's candidates; adjusts how ML is used. |
| `--plugins` | B | Tool behaviour. |
| `--header-points`, `--fuzz-json-writes` | B | Injection points. |
| `--authorized` | B | Safety gate. |
| `--dry-run` | B | Plan only. |

### 3.2 `crawl`

Every flag is **W**: `--start` (positional `<url>` in `scan`), `--max-depth`,
`--db` (internal in `scan`), `--engine`, `--timeout`, `--resume` (not offered by
`scan`, which always crawls fresh), `--store`, `--identity`,
`--follow-selector-forms`, `--no-spa-routes`, `--submit-spa-forms`, `--no-reveal`,
`--dry-run`. Arriving with BUG-0138: `--auth-origin` and `--no-spa-query`, both W.
Crawling uses no ground truth and no ML.

### 3.3 `greybox-run` (Lab group)

| Flag | Class | Reason |
| --- | --- | --- |
| `--ground-truth`, `--points` | T | Benchmark sourcing. Allowed here because Lab is not a working group (D-3). |
| `--base-url`, `--store`, `--spider-db`, `--cov-dir`, `--app-root`, `--labctl`, `--reset`, `--identity`, `--settle`, `--mutation-variants`, `--max-mutation-variants`, `--allow-destructive`, `--authorized`, `--dry-run` (+ `--auth-origin` with BUG-0138) | B | The lab target, its side channel, and the safety gates. `--store` becomes optional in Phase 2 (file locked now). |

### 3.4 `mutate-run` → `train mutate`

All flags are **T** because the command is training-group:
`--url --param --store --vuln-class --method --location --base --identity --cov-dir
--app-root --seed --budget --allow-destructive --authorized --dry-run`. `--store`
becomes optional.

### 3.5 `report` (Working, read-only)

`--store` (optional), `--run`, `--json`: all **W**. `report` reads any run, scored or
not. Reading is not training.

### 3.6 `reveal-holdout` → `train reveal-holdout`

`--store` (optional), `--run`: **T**. Revealing sealed metrics is evaluation hygiene.

### 3.7 `flow-anomaly` → `train flow-anomaly`

`--store` (optional), `--run`, `--method`, `--contamination`, `--seed`: **T** (D-4).

## 4. The default store

### 4.1 Resolution: one function (PA-0003, PA-0021)

New module `fuzzlab/core/storepath.py`.

`resolve_store(value: str | None) -> pathlib.Path` is **pure**: no filesystem writes.
It returns an absolute, `~`-expanded path. The first non-empty of these wins:

1. `value` (the `--store` flag);
2. `$FUZZLAB_STORE`;
3. `$FUZZLAB_STORE_PATH`. This is the existing config key's environment form. Honouring
   it means one variable already moves both the web UI (which reads `store_path`) and
   the CLI. It is kept for compatibility; `FUZZLAB_STORE` is the documented name.
4. The **per-user default**, `$XDG_DATA_HOME/fuzzlab/default.db`. An unset or relative
   `XDG_DATA_HOME` is ignored, per the XDG spec, and `~/.local/share` is used instead.

An empty string at any step counts as unset. If the home directory cannot be determined
at step 4, `resolve_store` raises `StorePathError`, a typed `ValueError` (PA-0021). Each
CLI turns it into a usage error that says to pass `--store` or set `FUZZLAB_STORE`.

`is_default(path) -> bool` says whether a path is the per-user default.

`prepare_store(path) -> Path` is for **writers only**. When `path` is the per-user
default, it creates the parent directory with mode `0700` (the store holds redacted
traffic and non-secret session state, so it should be private to the user). For any
other path it does nothing: an explicit path's missing parent fails exactly as it does
today. It never creates the store file itself; `Store(path)` does that.

`describe(path) -> str` gives the one-line form printed in summaries, for example
`store: /home/u/.local/share/fuzzlab/default.db (default)` or
`store: /x/y.db (FUZZLAB_STORE)`. The source label comes from the same resolution.

### 4.2 Side-effect order (PA-0079)

- **Writers** (`train run`, `train mutate`, `proxy --record`, and Phase 2's `scan` and
  `greybox-run`) follow this order:
  1. parse the arguments;
  2. run every usage check that does not need the store;
  3. resolve the store path (pure);
  4. `prepare_store` (only the per-user data directory, only for the default path);
  5. open `Store`.

  `train run` delegates its semantic checks to `auto_cli.main`, which runs them before
  it opens the store. Step 4 can therefore leave an empty `~/.local/share/fuzzlab/`
  directory behind a later usage error. That directory is the application's data
  directory, not a store and not a run row. Creating it is first-run setup, the same as
  the CA directory (`~/.fuzzlab/ca`) is for `proxy --export-ca`. This is stated, not
  hidden. Phase 2 can remove it by moving validation in front.
- **Readers** (`report`, `train reveal-holdout`, `train flow-anomaly`, `train models`)
  **never create** a store. On a missing path they exit 2 with
  `no such store: <path> (<source>); …`. Today `report` silently creates an empty store
  at a mistyped path. That changes, deliberately: with a default store, a read-only
  command must not be the thing that creates it. `reveal-holdout` and `flow-anomaly`
  already refuse a missing store.

### 4.3 Where the path is printed

- **Every run summary** (stdout) ends with the `describe()` line. This covers
  `train run` (printed after the engine's summary), `train mutate`, `mutate-run`,
  `train flow-anomaly` and `flow-anomaly`, and Phase 2's `scan`.
- **Read-only output** (`report`, `train reveal-holdout`, `train models`) prints it to
  **stderr**, so stdout stays the report itself (`report --json` stays byte-identical,
  canonical JSON).
- The proxy prints it in its "recording flows to …" banner.

### 4.4 Proxy

`proxy` records nothing unless asked: `--store` was always optional, and recording is
an opt-in (it persists redacted traffic). That stays. A new `--record` flag records
into the *resolved* store, so the proxy can use the default store without making
recording silent. `--store PATH` alone still records there (back-compat). With both,
`--store` wins.

### 4.5 Does `spider_results.db` fold into the store?

**Logically yes, physically not in this lane.** The crawl DB is already *imported*
into the store by `auto`/`scan` (`store_adapter.import_spider`), so the store is the
durable record.

- Standalone `crawl` keeps writing `--db spider_results.db` (default unchanged), so
  scripts and the UI keep working.
- `scan` (Phase 2) crawls into a **private temporary crawl DB** (`tempfile.mkstemp` in
  the store's directory, mode 0600). It hands that DB to the engine, which imports it
  into the store. It deletes the temp DB in a `finally`, so no `spider_results.db` is
  left in the user's cwd. A crawl that fails leaves no run row (the import never ran).
- Having the spider write store tables directly would need spider changes (locked) and
  probably a migration (forbidden here). It is recorded as a follow-up for the
  integrator.

### 4.6 The web UI

The UI keeps passing `--store` explicitly; nothing in `fuzzlab/web/` depends on
`resolve_store`. Two consequences are recorded as UI follow-ups (§9):

- **Two defaults exist until the UI moves.** The UI's `store_path` defaults to
  `./fuzzlab.db`; the CLI defaults to the per-user store. `FUZZLAB_STORE_PATH` set once
  aligns both today.
- **Planned UI follow-up:** read `storepath.resolve_store(None)` in place of
  `cfg.get("store_path", "fuzzlab.db")`.
- `config.DEFAULTS["store_path"]` is **not** changed in this lane: it would silently
  move the UI's store under a parallel UI session.

## 5. Back-compatibility and refusal

- **D-6. Old commands stay real commands, unchanged.** The web UI invokes them by name
  with today's flags:
  - `auto` keeps every flag, `--store` included. In Phase 1 it is untouched (the file
    is locked). In Phase 2 its `--store` becomes optional (default store).
  - `mutate-run`, `reveal-holdout` and `flow-anomaly` stay dispatchable under their old
    names. They print **one stderr line**, for example
    `fuzzlab: 'mutate-run' is now 'fuzzlab train mutate' (the old name still works)`,
    and stdout is unchanged.
  - In Phase 1, `auto` prints no note, because its working replacement (`scan`) does
    not exist yet. In Phase 2 it prints
    `fuzzlab: 'auto' is now 'fuzzlab scan' (working) or 'fuzzlab train run' (ground truth, training)`.

  The UI's job stream will show that line. It is informational only, and its tests read
  stdout.
- **D-7. No hidden options in the new commands, except URL aliases.** `scan` and
  `train run` take the target as a positional `<url>`. `--base-url` stays as a
  **hidden** alias (argparse `SUPPRESS`) for people pasting old commands. It is refused
  when it disagrees with the positional.
- **D-8. Training flags in a working command are refused loudly and named.** A working
  parser carries every **T** flag of its source command as a *hidden refusing option*.
  Using one exits 2 with:

  ```
  fuzzlab scan: error: --calibrate is a training option; use `fuzzlab train run` (see `fuzzlab train run --help`)
  ```

  Ground truth is worded the same way, and the message adds that ground truth is never
  a working option. Hidden refusing options are used, not unknown-argument errors,
  because argparse's "unrecognized arguments" would name nothing. A flag's value (for
  example `--ground-truth DIR`) is consumed so the message names the flag, not the
  path.

## 6. Mechanism (new modules)

`fuzzlab/cli_taxonomy.py` is a pure module: no traffic, no store. It holds:

- `COMMANDS`: the grouped command table (name, group, one-line summary, the old name it
  replaces). It drives `fuzzlab --help` and the alias notes.
- `FLAG_CLASSES[command][dest] -> "W" | "T" | "B" | "W*"`, with pending entries for
  BUG-0138's dests.
- `copy_parser(source, *, prog, url_positional=False, store_optional=True,
  refuse=frozenset(), refuse_to="")`. It builds a new parser from a source parser's
  actions:
  - it re-adds each action with the same option strings and kwargs (no re-typing of
    flags, so PA-0001/PA-0003 hold: the source parser stays the one definition);
  - it makes `--store` optional with default `None`;
  - optionally, it adds a positional `url` and hides `--base-url`;
  - it turns each dest in `refuse` into a hidden option whose action raises
    `parser.error(...)` naming `refuse_to`.
- `to_argv(parser, namespace, *, skip=())`. It serializes a namespace back into argv
  for the source parser, handling `store_true`, `append`, `nargs='?'` (with `const`)
  and `nargs='*'/'+'`. Defaults are omitted. A round-trip test runs over every action
  of every classified parser:
  `parse(to_argv(parse(argv))) == parse(argv)`.

`fuzzlab/train_cli.py` is the `fuzzlab train <sub>` dispatcher. **`train run`** works
like this:

1. Parse with `copy_parser(auto_cli.build_parser(), prog="fuzzlab train run",
   url_positional=True)`.
2. Resolve the store (pure).
3. Call `prepare_store`.
4. Call `auto_cli.main(to_argv(...) + ["--store", path])`.
5. Print the store line.

In Phase 1, error messages raised inside `auto_cli.main` still say `fuzzlab auto:`.
That is a known wart, fixed in Phase 2 by letting `auto_cli.main` take `prog`. `train
run --dry-run` reports through the `auto` commandspec and shows the equivalent
`fuzzlab auto …` command. That command is exactly what will run, so it is the honest
display. The other subcommands delegate to the existing CLIs, after resolving the
store.

`fuzzlab/core/storepath.py` (§4) holds the resolver.

## 7. Phases

### Phase 1 (now; touches no locked file)

1. `core/storepath.py` and its tests.
2. `report`, `mutate-run`, `reveal-holdout`, `flow-anomaly`: `--store` becomes optional,
   resolved by `storepath`. Readers refuse a missing store and never create one; writers
   call `prepare_store`; the path is printed (§4.3).
3. `proxy --record` (§4.4).
4. `cli_taxonomy.py` (table, copy/serialize, refusal) and its guard tests.
5. `train_cli.py`: `train run | models | reveal-holdout | flow-anomaly | mutate`.
6. `ml.model_registry.list_models(store)`: a label-free listing for `train models`.
   It is a new reader of `model`. It selects no "current" row, so PA-0063's guard does
   not apply, but it is checked against that guard.
7. Grouped help and the alias notes in `cli.py`.
8. Docs and bookkeeping (§8 and Appendix A).

### Phase 2 (after BUG-0138 lands on `ccr-27885270-9ahcdd`; merge it first)

1. `auto_cli.py`:
   - `--store` becomes optional (`storepath`);
   - `main(argv, *, prog=None)`;
   - the deprecation note;
   - `train run` stops going through argv for `prog`.
2. `greybox_cli.py`: `--store` becomes optional.
3. `tools/spider.py`'s CLI tail. Keep `--auth-origin` and `--no-spa-query`. `scan`
   reuses `spider_kwargs`/`session_manager_for` rather than `runpy`.
4. `session/cli.py`: no flag change is expected beyond what BUG-0138 brings. It is
   re-checked for `--store`.
5. `scan <url>`, a new file. It runs crawl (into a temp DB) and then the engine with
   `points=crawl` and `mode=manual`. `--categories` is required (`all` allowed). Training
   flags are refused via `copy_parser`. `--authorized` is required **before** the crawl
   starts. Every usage check runs before the crawl. The default store is used. Tests:
   end to end against the loopback fixture apps.

## 8. Docs to change (Phase 1 unless noted)

- `README.md`: the quick start uses the default store and the groups (scan in Phase 2).
- `docs/ON_HOST_RUNBOOK.md`: a note that `--store` is optional and how it resolves.
  The existing commands stay valid, so they are left as they are.
- `requirements.md` for CORE 02 (FR-CORE-400), FUZZ 07 (FR-FUZZ-400/401), ML 10
  (FR-ML-400), MUT 09 (FR-MUT-400), PROXY 11 (FR-PROXY-400) and UI 12
  (FR-UI-400/401).
- `docs/ARCHITECTURE.md`: the CLI taxonomy and the store-resolution convention under
  cross-cutting concerns.
- `CHANGELOG.md`: one line.

## 9. Follow-ups

**For the UI session.** `commandspec` entries that should move:

- `auto` → `scan` and `train run`;
- `mutate-run` → `train mutate`;
- `flow-anomaly` → `train flow-anomaly`;
- add `train models` and `train reveal-holdout`;
- group the launcher by `cli_taxonomy.COMMANDS`;
- read `storepath.resolve_store(None)` instead of `cfg.get("store_path", "fuzzlab.db")`;
- `cli_dryrun` needs specs for the new names.

**For the integrator.** Spider tables folded into the store (needs a migration). The
`crawl --authorized` gap.

## 10. Risks

- **The UI and CLI defaults diverge** until the UI follow-up lands. Mitigated by
  `FUZZLAB_STORE_PATH`, by the printed path, and by the UI passing `--store`.
- **`copy_parser` uses argparse internals** (`_actions`), as `commandspec` already does.
  It is guarded by the round-trip test over every action.
- **`report` now refuses a missing store.** That is a behaviour change, to the safe
  side, and it is tested.
- **Classification drift** when BUG-0138's flags merge. They are pre-classified, and
  the guard test fails on any unclassified dest.

## Appendix A: draft change-control entries (pre-change gate)

(Each is appended to its component's log once agreed; Effectiveness is `pending` until built.)

- **CC-CORE-0400**: `core/storepath.py`, the default store resolver (FR-CORE-400). Pure
  resolve; writer-only `prepare_store` (0700, default only); typed `StorePathError`;
  `describe`. Impact: every CLI that takes `--store`. Risk: low. Two defaults until the
  UI moves (stated). Deliverables: module, tests (precedence, env, empty values, XDG
  relative/unset, no-home error, no write on resolve, 0700 only for the default).
- **CC-FUZZ-0400**: `fuzzlab train` group and `cli_taxonomy` (FR-FUZZ-400/401);
  `reveal-holdout`/`flow-anomaly` default store and old-name notes. Impact: CLI surface;
  the UI is unaffected (old names unchanged). Risk: medium (argparse internals; argv
  round-trip). Mitigation: round-trip guard over every action, unclassified-dest guard,
  refusal tests.
- **CC-UI-0400**: grouped `fuzzlab --help` from `cli_taxonomy.COMMANDS`; `report`'s
  `--store` optional, printed to stderr, refusing a missing store (FR-UI-400/401). Risk:
  low; `report` no longer creates a store at a mistyped path.
- **CC-MUT-0400**: `mutate-run`/`train mutate` `--store` optional; path printed
  (FR-MUT-400). Risk: low.
- **CC-PROXY-0400**: `proxy --record` into the resolved store (FR-PROXY-400). Risk: low;
  recording stays opt-in.
- **CC-ML-0400**: `model_registry.list_models` (label-free) for `train models`
  (FR-ML-400). Risk: low. It never reads calibration metrics, so no sealed number is
  shown, which is tested by planting one.
