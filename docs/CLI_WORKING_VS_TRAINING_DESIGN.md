# CLI simplification: a default store, working runs vs training runs

Status: **design, revision 2**. Round 1 was reviewed by reviewers A and B (both "agree
with fixes"). Appendix B lists every round-1 finding and how it is resolved.

The owner's request (2026-10-15): the CLI is too complicated. They want:

1. **A default store.** `--store` is never required.
2. **Working runs separated from training runs.** A *working* run uses fuzzlab as a
   tool: point it at a URL and run. A *training/benchmark* run covers ground truth,
   scoring, model training, holdouts, calibration and the model registry.

This doc is the design gate's subject. Appendix A drafts the change-control entries
(the pre-change gate in `docs/components/README.md`).

## 0. Constraints this lane works under

- **Locked files.** Another session has unpushed work in these files. Until
  `origin/ccr-27885270-9ahcdd` carries a BUG-0138 commit, this lane must not edit:
  - `harness/auto.py`, `harness/auto_cli.py`, `harness/pipeline.py`;
  - `greybox/greybox_cli.py`, `greybox/run.py`;
  - `tools/spider.py`, `tools/fetcher.py`, `tools/store_adapter.py` and several other
    `tools/*`;
  - `session/*`;
  - `core/http.py`, `core/urls.py`;
  - the oracle modules;
  - `proxy/session_capture.py`.

  **Phase 1** touches none of them. **Phase 2** begins only after that merge.
- **`fuzzlab/web/` is not edited.**
- **No store migrations.**
- **Reserved numbers:** `CC-*-0400…0449`, `BUG-/PA-0400…0449`, `FR-*-400+`.

## 1. Facts verified in the code (at `cdde39f`; both reviewers re-verified them)

**Commands and the store flag**

- `fuzzlab/cli.py` dispatches:
  - `web`, `session`;
  - `crawl`, `audit`, `fuzz`, `auto`, `greybox-run`, `proxy`;
  - `mutate-run`, `report`, `reveal-holdout`, `flow-anomaly`;
  - `lab-generate`, `build-db`, `version`.

  Its help is one flat list.
- `--store` is **required** in `auto`, `greybox-run`, `mutate-run`, `report`,
  `reveal-holdout` and `flow-anomaly`.
- `--store` is **optional** in:
  - `crawl`, `audit` and `fuzz`, where it means opt-in consolidation (with no `--store`
    they write nothing to any store);
  - `proxy`, where it means opt-in flow recording.

**Ground truth**

- **Ground truth never trains a model.** `ml/dataset.py` takes its labels from the
  oracle.
- Ground truth does three things:
  - it scores a run;
  - it supplies `--points ground-truth`;
  - under D14 it derives the categories.

**The web UI and the existing store setting**

- **The web UI does not pass `--store` on its own.**
  - The launcher form is built from each parser. `--store` is a blank text field,
    marked `*` only while `required=True` (`web/templates/sections/launcher.html`).
  - `web/runner.build_flags` drops empty values.
  - Nothing in `web/` pre-fills a store path.
  - So once a parser's `--store` becomes optional, a blank UI field means the CLI's
    default store.
- **An existing store setting.**
  - `core/config.DEFAULTS["store_path"] = "fuzzlab.db"`, relative to the cwd, can be
    overridden through `FUZZLAB_STORE_PATH`.
  - The web UI reads it for every page (`web/app.py`, `cfg.get("store_path",
    "fuzzlab.db")`) and for `web --with-proxy` recording.
  - `.gitignore` calls `/fuzzlab.db` "the shared SQLite project store".

**Dry runs and gates**

- `cli_dryrun.report(name, args)` builds its plan from `web.commandspec.spec(name)` and
  `web.runner.build_flags`.
- **That display mis-serializes some flags** (reproduced; this is BUG-0400, §9):
  - `nargs='*'` prints as `[]`;
  - an option whose `const` is `""` is dropped;
  - a value that starts with `-` prints space-separated, so it cannot be re-parsed.
- `crawl` sends traffic but has no `--authorized` gate.
- The anonymous probe sender applies no `scope_hosts` check. That is pre-existing;
  see §9.

## 2. Command taxonomy

### 2.1 Groups

| Group | Commands | What it is for |
| --- | --- | --- |
| **Working** (lab-only; fuzzlab as a tool) | `scan <url>` *(Phase 2)*; `auto` *(the current working engine until `scan` exists)*; `crawl`, `audit`, `fuzz`, `session`, `proxy`, `report`, `web` | Point it at a lab target you are authorized to test. No ground truth. ML only as *used*. |
| **Training / benchmark** | `train run <url>`, `train models`, `train reveal-holdout`, `train flow-anomaly`, `train mutate` | Ground truth, scored runs, model training and its modulators, holdouts, calibration, the model registry, and the research learners. |
| **Lab** | `lab-generate`, `build-db`, `greybox-run` (needs the instrumented lab's side channel). Lab control is `lab/labctl.sh` or the web UI's Lab page. | Building and driving our own lab. |
| **Other** | `version`, `help` | |

**Decisions.**

- **D-1. One training group, `train`. No `benchmark` command.** A benchmark is a
  `train run` with `--ground-truth`. The help says "training and benchmark".
- **D-2. `mutate-run` becomes `train mutate`.** It learns WAF evasion, records
  research data, and produces no findings.
- **D-3. `greybox-run` is in the Lab group.** It needs the lab shim, so its
  `--ground-truth`/`--points` stay.
- **D-4. `flow-anomaly` becomes `train flow-anomaly`.**
- **D-5. `train models` lists saved models.** It shows only label-free facts, through
  an explicit allowlist (§6.4).
- **D-9. `train run` must carry at least one training or benchmark choice.** It refuses
  otherwise, with exit 2, before any side effect, naming `fuzzlab auto` (Phase 2:
  `fuzzlab scan`). The choices are:
  - `--ground-truth`;
  - `--score` or `--rank` (in `train run` these train, unless `--train-on saved`);
  - `--holdout`, `--calibrate`, `--hybrid`, `--train-on`, `--rank-objective`;
  - a non-`score` `--budget-method` or a `--budget-seed`;
  - `--mode`, `--points`.

  A run with none of these is a working run under a training name.
- **D-10. `fuzzlab train` with no subcommand** prints the train group's usage and exits
  2. `fuzzlab train --help` exits 0.

### 2.2 Grouped help (`fuzzlab`, `fuzzlab --help`)

The help is printed from one table, `cli_taxonomy.COMMANDS`. Each row has a name, a
group, a summary and a `replaced_by`.

The counting rule, tested:
- every **dispatchable top-level name** appears exactly once;
- an old name appears only in the "Older names" block;
- each `train <sub>` appears once, under Training;
- `help` and `-h`/`--help` are entry points, not rows.

`scan` is absent in Phase 1, because the help never advertises an unbuilt command.

```
usage: fuzzlab <command> [args]      (fuzzlab <command> --help for its options)

Working runs (lab-only): use fuzzlab as a tool against a lab target you are authorized to test
  auto [args]          crawl results -> audit -> oracle-confirm pipeline (requires --authorized)
  crawl [args]   ...   audit [args] ...   fuzz [args] ...   session <sub> ...
  proxy [args]   ...   report [args] ...  web [--with-proxy] ...

Training and benchmark: ground truth, scored runs, model training, holdouts, models
  train run <url>      a run scored against ground truth and/or that trains models
  train models         list saved models (the model registry; read-only)
  train reveal-holdout print a run's sealed holdout metrics (counts the reveal)
  train flow-anomaly   flag each host's most unusual recorded flows
  train mutate         learn + evade the live lab WAF, record variants

Lab
  lab-generate [args] ...  build-db [args] ...  greybox-run [args] ...

Other
  version

Older names (still work): mutate-run, reveal-holdout, flow-anomaly

Store: --store PATH, else $FUZZLAB_STORE / $FUZZLAB_STORE_PATH, else
       ~/.local/share/fuzzlab/default.db (created on first use; the web UI uses the same).
       auto and greybox-run still need --store until they gain the default (Phase 2).
Lab-only. Nothing runs against a target until you ask it to (no auto-run).
```

## 3. Flag classification

The classes:

| Class | Meaning |
| --- | --- |
| **W** | Working only. |
| **T** | Training only. Refused in a working command, and the message names `fuzzlab train run`. |
| **B** | Both. |
| **W\*** | Narrowed in working commands, as stated per row. |
| **L** | Needs our instrumented lab. Refused in `scan`, with the message naming `fuzzlab train run` (or `greybox-run`). Allowed in `train run` and in Lab commands. |

The table is `cli_taxonomy.FLAG_CLASSES`, one entry for **every dispatchable command**
(`COMMANDS`). The guard test is two-directional:

- it fails on a parser dest that has no class;
- it fails on a stale entry (a dest that is no longer in the parser);
- it keeps an explicit `PENDING` set for BUG-0138's dests (`auth_origin`,
  `no_spa_query`), and fails once a pending dest exists in a parser but is still
  marked pending.

Commands without an argparse parser are listed with that reason: `web` (it has its own
`web_main` argv handling), `build-db`, `version`, and `session` (its parser is in a
locked file and is classified when Phase 2 opens it; it has no ML or ground-truth
flags).

### 3.1 `auto` (the engine of `scan` and `train run`)

| Flag | Class | Reason |
| --- | --- | --- |
| `--base-url` | B | The target. Positional `<url>` in `scan` and `train run`; `--base-url` is a hidden alias (§5). |
| `--spider-db` | B | The crawl input. Internal in `scan`. |
| `--store` | B | Optional (§4). |
| `--ground-truth` | **T** | Known answers: scoring, contract points, D14. Never a working option. |
| `--mode` | **T** | A working run has no ground truth, so `scan` runs **automatic** mode, where `resolve_run` enforces D15 itself (§7, Phase 2). `--mode manual` (all categories by default) is a benchmark/experiment choice. |
| `--points` | **T** | `ground-truth` sourcing is a benchmark. Working runs use crawl points. |
| `--categories` | B | Required by D15 in `scan` (enforced by `resolve_run`). `all` expands to the explicit known list (§7). |
| `--identity`, `--auth-origin` *(BUG-0138, pending)* | B | Session and safety. |
| `--browser`, `--oob` | B | Confirmation mechanisms. |
| `--greybox-coverage-file`, `--greybox-dbfault-file` | **L** | They read the lab shim's side channel (D-3's reason). |
| `--bandit` | B | Orders mechanisms while testing (owner's list). Its posteriors are store-wide; see §4.7. |
| `--score`, `--rank` | **W\*** | In `scan`: *apply* a saved model (`--train-on saved` implied). In `train run`: train, or apply. Refusal semantics: §7. |
| `--model-id`, `--ranker-model-id` | B | Pick which saved model to apply. |
| `--train-on`, `--rank-objective`, `--calibrate`, `--holdout`, `--hybrid` | **T** | Training data, fit choices, and modulators. |
| `--confirm-budget` | B | Budget (owner's list). |
| `--budget-method` | **W\*** | `scan` accepts only `score`, i.e. "most findings per request". `uncertainty` and `committee` are active-learning orders, "best for improving the model", and `random` is a seeded control. All three are refused in `scan`, naming `train run`. |
| `--budget-seed` | **T** | It seeds only the experiment orders (`random`, `committee`). |
| `--anomaly`, `--anomaly-contamination`, `--anomaly-method` | B | A label-free tripwire over this run's own candidates. |
| `--plugins`, `--header-points`, `--fuzz-json-writes` | B | Tool behaviour and injection points. |
| `--authorized`, `--dry-run` | B | The safety gate and plan-only mode. |

### 3.2 `crawl`

Every flag is **B**:
- `--start`, which becomes `<url>` in `scan`;
- `--max-depth`;
- `--db`, which is internal in `scan`;
- `--engine`, `--timeout`;
- `--resume`, which `scan` does not offer because it always crawls fresh;
- `--store`, `--identity`;
- `--follow-selector-forms`, `--no-spa-routes`, `--submit-spa-forms`, `--no-reveal`;
- `--dry-run`.

Two more arrive pending with BUG-0138: `--auth-origin` and `--no-spa-query`.

### 3.3 `audit` and `fuzz`

**`audit`** (`tools/fetcher.py`): every flag is **B**: `--spider-db`, `--base-url`,
`--store` (opt-in consolidation), the auth flags, the timeouts and `--dry-run`. It has
no ground truth and no ML.

**`fuzz`** (`tools/blind_sqli_fuzzer.py`): every flag is **B**. Its observation CSV is a
by-product of tool use. It is not a training run: it has no ground truth and fits no
model, so it stays Working. The guard test lists both parsers' dests from the code.

### 3.4 `greybox-run` (Lab)

| Flag | Class |
| --- | --- |
| `--ground-truth`, `--points` | T, allowed because Lab is not Working |
| `--cov-dir`, `--app-root`, `--labctl`, `--reset`, `--settle` | L |
| everything else (+ `--auth-origin` pending) | B |

### 3.5 `proxy` (Working)

All flags are **B**, including the new `--record` (§4.5).

### 3.6 `mutate-run` / `train mutate`

All flags are **T**, because the command is training-group.

### 3.7 `report` (Working)

`--store`, `--run`, `--json`: **B**. Reading a scored run is not training.

### 3.8 `reveal-holdout` / `train reveal-holdout`, and `flow-anomaly` / `train flow-anomaly`

All flags are **T**.

### 3.9 `lab-generate`

Its flags are classified **L**. It is a Lab command and has no store.

## 4. The default store

### 4.1 One resolution, shared by the CLI and the web UI (PA-0003, PA-0021)

Both reviewers found that a CLI-only default would silently split UI-launched jobs from
the UI's pages. So there is **one** resolution, in `fuzzlab/core/storepath.py`, and
`core/config.load_config()` delegates `store_path` to it. That makes the UI and the CLI
agree by construction, with no `web/` edit.

```python
@dataclass(frozen=True)
class ResolvedStore:
    path: pathlib.Path      # absolute, ~-expanded
    source: str             # "--store" | "FUZZLAB_STORE" | "FUZZLAB_STORE_PATH" | "default"

def resolve(value: str | None, *, environ=None) -> ResolvedStore   # pure: no FS writes
def resolve_store(value: str | None) -> pathlib.Path                # == resolve(value).path
```

The first of these wins:

1. **`value`, the `--store` flag.** An explicit `--store ""` (or whitespace) is a
   **usage error**. Malformed is not absent (PA-0105).
2. **`$FUZZLAB_STORE`.**
3. **`$FUZZLAB_STORE_PATH`**, the existing config key's environment form.
   - If both variables are set to **different** paths, the result is `StorePathError`
     (fail loud on ambiguity), so the two names can never send the UI and the CLI to
     different stores.
   - An empty variable counts as unset.
4. **The per-user default**, `$XDG_DATA_HOME/fuzzlab/default.db`. An unset or relative
   `XDG_DATA_HOME` is ignored, per the XDG spec, and `~/.local/share` is used instead.
   - If the home directory is unknown, the result is `StorePathError`.
   - This is not `~/.fuzzlab/`, where the CA lives. The XDG data directory is the
     standard home for application data. The CA directory is a pre-existing,
     separately-configurable trust-root location (`--ca-dir`), and is left alone.

**Why both names?** The owner asked for `FUZZLAB_STORE`. `FUZZLAB_STORE_PATH` has
existed since Phase 0 and is what the UI documents. Both are honoured; neither can
diverge from the other; `FUZZLAB_STORE` is the documented one.

**Config delegation (`core/config.py`).** `DEFAULTS["store_path"]` becomes `None` ("use
the resolver"). After `load_config` has merged defaults, the file, the environment and
the overrides:
- if `store_path` is still `None`, it is set to
  `str(storepath.resolve(None, environ=environ).path)`;
- the generic `FUZZLAB_STORE_PATH` environment layer still applies first, and the
  resolver agrees with it (step 3);
- an explicit `overrides`/file value wins.

**Visible effect on the UI.** Its default store moves from `./fuzzlab.db` (cwd) to the
per-user default. This is the point of the change: one default database for the whole
toolkit.
- `FUZZLAB_STORE_PATH=fuzzlab.db` restores the old location for both the UI and the CLI.
- It is flagged in the final report for the owner and the UI session.
- Every web test passes an explicit `store_path` override, verified by grep.

**Typed errors at the boundary (PA-0021).** These checks are pure stats, no writes:

| Function | Raises `StorePathError` when |
| --- | --- |
| `check_readable(rs)` | the path is missing, or is a directory or another non-regular file |
| `check_writable(rs)` | an explicit path's parent is missing, or the path is a directory |

`StorePathError` is a `ValueError`. Every CLI turns it into `parser.error(...)` (exit
2), and the message names the source, e.g. `no such store:
/x/default.db (default store); …`.

**`prepare(rs)`, for writers only.**
- For the per-user default, it creates the parent with `os.makedirs(..., mode=0o700)`.
  On an *existing* directory that is group- or world-writable it prints one stderr
  warning and changes nothing (the user may have chosen it).
- It never creates the store file; `Store` does that.
- For non-default paths it does nothing.

**`describe(rs) -> str`.** The printed form, for example
`store: /home/u/.local/share/fuzzlab/default.db (default)`.

### 4.2 Side-effect order (PA-0079)

Writers follow this order, and nothing is created before step 5:

1. Parse the arguments.
2. Handle `--dry-run` (print the plan, which includes the resolved store, and exit).
3. Run every usage and safety check that needs no store, `--authorized` included.
4. `resolve`, then `check_writable`.
5. `prepare`.
6. Open `Store`.

`train run` checks `--authorized` and D-9 itself, before step 5. It then delegates to
`auto_cli.main`, whose remaining semantic checks (for example `--hybrid` needs
`--score`) run before it opens the store.

**Residual, stated.** A semantic usage error inside `auto_cli.main` can still leave an
empty, private (0700) `~/.local/share/fuzzlab/` directory. It is never a store file and
never a run row. Phase 2 removes the residual by extracting `auto_cli`'s checks into one
`validate()` (§7). Tests assert "no store file, no run row" on every path, and "no
directory" on the dry-run, no-`--authorized` and D-9 paths.

**Command kinds:**

| Kind | Commands | Missing store |
| --- | --- | --- |
| Writers | `train run`, `train mutate`/`mutate-run`, `proxy --record`/`--store`; Phase 2: `scan`, `auto`, `greybox-run` | Creates it |
| Non-creating | `report` (read-only); `train flow-anomaly`/`flow-anomaly` (writes `flow.anomaly_*`); `train reveal-holdout`/`reveal-holdout` (records the reveal); `train models` | Refused with exit 2; they never create one |

`report` used to create an empty store silently at a mistyped path. That is a
deliberate behaviour change.

### 4.3 The counted reveal is never spent on an implied store

`auto`'s holdout hint prints `fuzzlab reveal-holdout --run N` with no `--store`. The
file is locked, so the hint can't change in Phase 1. Pasting it after a non-default run
would count a reveal on the wrong store, and run ids are per-store.

So **`reveal-holdout` / `train reveal-holdout` refuse the implicit per-user default.**
They need `--store` or one of the environment variables. The message reads: "a reveal
is counted and cannot be undone: name the store with --store PATH (or FUZZLAB_STORE)".

They also print `describe()` to stderr **before** the reveal is counted, and the reveal
header names the store.

This is the one stated exception to "`--store` is never required". It is a safety
property, recorded as FR-FUZZ-402. Phase 2 also adds `--store` to `auto`'s hint.

### 4.4 Where the path is printed

- **Run summaries.** `train run` prints the `describe()` line after the engine's
  summary. `train mutate`/`mutate-run` and `train flow-anomaly`/`flow-anomaly` print it
  on stdout, as an added line; the existing lines are unchanged, and only substring
  assertions exist.
- `mutate-run`'s `sqlite3 <path>` hint uses the resolved path.
- **stderr:** `report` (so `--json` stays canonical), `train models`, and
  `reveal-holdout`.
- The proxy's banner.
- **Dry runs:** each dry-run prints the resolved store on an extra line, because the
  argv display omits a defaulted `--store`.

### 4.5 Proxy

Recording stays opt-in. A new `--record` records into the resolved store. `--store
PATH` alone still records there. Both together: `--store` wins.

The order is: `require_loopback`, then `--authorized`, then `resolve`/`prepare`, then
`Store`. The CA is created only on `--export-ca`, as today.

### 4.6 `spider_results.db`

**Logically folded, physically not in this lane.**
- Standalone `crawl` keeps `--db spider_results.db`.
- `scan` (Phase 2) crawls into a `tempfile.TemporaryDirectory()` created in the store's
  directory (mode 0700). Its crawl DB and every `-wal`/`-shm`/`-journal` sidecar go
  with that directory. The engine imports the DB into the store, and the directory is
  removed in a `finally`.
- Folding the spider tables into the store needs a migration: integrator follow-up.

### 4.7 One store holds working and benchmark state (stated risk)

Several kinds of state are store-wide:
- bandit posteriors (not keyed by target);
- holdout reveal counts;
- `report --run latest`;
- `--train-on earlier` and the budget's training pool, which take earlier runs against
  the **same target**.

Before this change, a required `--store` tended to keep experiments apart. Now:
- the default store is the working store;
- the `train run` help and the README say: **give benchmark and training runs their
  own `--store`** (or `FUZZLAB_STORE`) when reproducibility matters;
- every summary prints the store.

A separate default for training (`train.db`) was considered and rejected. `scan --score`
would then not find a model trained under `train run` without an explicit `--store`,
and two defaults is the complexity the owner asked us to remove.

## 5. Back-compatibility and refusal

- **D-6. Old commands stay real commands.**
  - `auto` keeps every flag, `--store` required (locked file). Phase 2 makes `--store`
    optional and adds a deprecation note once `scan` exists.
  - `mutate-run`, `reveal-holdout` and `flow-anomaly` stay dispatchable. Each prints one
    **stderr** line naming the new name. Their stdout gains only the store line (§4.4).
- **D-7. Hidden options in the new commands are of two kinds only.**
  - (a) `--base-url`, a hidden alias for the positional `<url>`. **Exactly one** of the
    two is required, and they are refused if both are given and disagree.
  - (b) **Refusing options** (D-8).
  - No other option is hidden.
- **D-8. Training flags in a working command are refused loudly, by name.** A working
  parser carries every **T**/**L** flag of its source as a hidden refusing option, and
  every **W\*** flag with its allowed values. Using one exits 2:

  ```
  fuzzlab scan: error: --calibrate is a training option; use `fuzzlab train run` (see `fuzzlab train run --help`)
  fuzzlab scan: error: --ground-truth is a benchmark option and never part of a working run; use `fuzzlab train run`
  fuzzlab scan: error: --budget-method committee is a training choice (scan orders by score); use `fuzzlab train run`
  ```

  Refusal is a flag-level check: the refusing action raises when argparse meets the
  flag. Its value is consumed, so the message names the flag, never the path.

  Note for the UI: `commandspec.introspect` does not skip `SUPPRESS` options, so the
  hidden refusing options would show as fields if `scan` got a spec unchanged (§9).

## 6. Mechanism (new modules, Phase 1)

### 6.1 `fuzzlab/core/storepath.py`

As in §4.1. It imports only the stdlib (it is checked against the send-nothing AST
guards).

### 6.2 `fuzzlab/cli_taxonomy.py` (pure)

It holds `COMMANDS`, `FLAG_CLASSES` and `PENDING`, plus:

- **`copy_parser(source, *, prog, url_positional=False, store_optional=True,
  refuse=(), restrict={}, refuse_to="")`.** It adds a `copy.copy(action)` of each
  source action to a fresh parser with `parser._add_action`. It never re-adds from
  kwargs, which reviewer B showed fails for `store_true` actions. On the copies it sets:
  - `required=False` on `--store`;
  - with `url_positional`, `required=False` and `help=SUPPRESS` on `--base-url`, plus a
    positional `url` with `nargs='?'`.

  `refuse` dests become refusing actions with the same option strings and the same
  nargs, so values are consumed. `restrict` wraps a W\* action, allowing only the
  listed values. The source parser is never mutated, which is tested by identity.

  `copy_parser` takes **one** source parser. Phase 2's `scan` composes crawl and auto
  through kwargs (`spider_kwargs`, `auto`'s extracted `validate`), not by merging the
  two parsers. That avoids the `--store`/`--identity`/`--dry-run` collisions B found.
- **URL-swallowing hazard (B6).** A flag with an optional value (`--header-points`,
  `nargs='?'`) can eat the URL. The `<url>`, when given positionally, must be the
  **first** argument. When `url` is missing and an optional-value flag holds a
  URL-shaped value, the error says: "put the <url> first, or use --base-url".
- **No `to_argv` in Phase 1** (B5c). `train run` forwards the user's own argv
  verbatim: `["--base-url", url, *rest]`, plus `["--store", path]` only when the user
  gave none. Values are never re-serialized, so the dash-leading and `const`
  serialization hazards cannot arise. Phase 2 decides `scan`'s composition with kwargs.

### 6.3 `fuzzlab/train_cli.py`

This is the `fuzzlab train <sub>` dispatcher.

**`train run`:**
1. Validate with `copy_parser(auto_cli.build_parser(), prog="fuzzlab train run",
   url_positional=True)`.
2. D-9 check, then the `--authorized` check (unless `--dry-run`).
3. `resolve`, then `check_writable`.
4. `prepare`, skipped on `--dry-run`.
5. `auto_cli.main(forwarded argv)`.
6. Print the store line.

Known Phase-1 warts, removed in Phase 2 by `auto_cli.main(argv, *, prog=)`:
- errors raised *inside* `auto_cli.main` say `fuzzlab auto:`;
- `--dry-run` shows the equivalent `fuzzlab auto …` argv through the shared dry-run
  display. That display has BUG-0400's limits for `nargs='*'`/`const=""`/dash-leading
  values, none of which `auto`'s own flags hit except a dash-leading value.

**`train mutate`, `train reveal-holdout` and `train flow-anomaly`** pass argv through to
the existing CLI's `main(argv, prog=...)`. Each CLI resolves its own store **once**; the
wrappers never resolve. Each existing `main` gains a keyword `prog`.

**`train models`** calls `ml.model_registry.list_models`.

### 6.4 `ml.model_registry.list_models(store)`: an explicit allowlist (B8)

**What it returns.**
- Rows `(id, name, version, feature_version, created_at, has_params)`, ordered by
  **ascending** id. That is a listing, not a "newest" selection, and it is checked
  against `test_no_module_reads_model_as_newest_row_of_any_family`.
- From the `calibration` JSON it takes **only** allowlisted keys:
  - `trained_on`;
  - `run_id`, the scope;
  - `source_model_id`;
  - `len(scored_run_ids)`, as a count.
- It never reads `params`, any metric key, or `holdout.*` (whose `rows` equals a sealed
  number).
- It never touches `SEALED_TABLES`.

**Malformed rows (PA-0108).** A row whose calibration does not parse prints
`unreadable`, never default facts.

**Test.** It plants:
- a calibration metric (`oof_pr_auc_raw`, `brier_*`);
- `calibration.holdout.rows`;
- a `holdout_metric` row with distinctive values.

It asserts none of those values appears in the output. It also asserts the SQL never
names a sealed table, with a control that proves the check is live.

## 7. Phases

### Phase 1 (now; touches no locked file and no `web/` file)

1. `core/storepath.py`, plus `core/config.py` delegating to it.
2. Default store for `report`, `mutate-run`, `reveal-holdout` (refusing an implied
   default) and `flow-anomaly`.
3. `proxy --record`.
4. `cli_taxonomy.py`.
5. `train_cli.py`.
6. `list_models`.
7. Grouped help.
8. A `tests/conftest.py` autouse isolation fixture (§8).
9. BUG-0400 filed and pinned (§9).
10. Docs and bookkeeping.

### Phase 2 (after BUG-0138 lands; merge `origin/ccr-27885270-9ahcdd` first)

1. **`auto_cli.py`.**
   - Extract every usage check into `validate(p, args) -> Plan`, called by `main` and
     by `scan` (PA-0003).
   - `main(argv, *, prog=None)`.
   - `--store` becomes optional (`storepath`).
   - Put `--store` in the reveal hint when the store is not the default.
   - Add the deprecation note.
   - `_precheck_header_budget` needs the crawl DB. In `scan` it runs as an explicit
     post-crawl, pre-probe, pre-store refusal.
2. **`greybox_cli.py`:** `--store` becomes optional.
3. **`tools/spider.py`:** `scan` reuses `spider_kwargs`/`session_manager_for`. Keep
   `--auth-origin` and `--no-spa-query`.
4. **`session/cli.py`:** classify its parser in `FLAG_CLASSES`. Check whether it takes
   `--store`.
5. **`scan <url>`, a new file.**
   - `--authorized` is required **before** the crawl.
   - All of `auto`'s `validate()` runs before the crawl.
   - **Categories.** Automatic mode, no ground truth, so `resolve_run` enforces D15
     itself.
     - `--categories` blank or whitespace-only is refused.
     - `all` expands to `known_categories()` in **one** function
       (`core.runmode.expand_selection`) and is recorded as the explicit list. It is
       never passed through as "no selection".
     - The `all` opt-in is recorded as a D15 amendment in
       `docs/DECISIONS_AND_ROADMAP.md`.
   - **`--score`/`--rank`.** A read-only, pre-crawl check refuses when no saved model
     qualifies for **this target**, using the same function as the run
     (`model_registry.saved_source` over the target's earlier runs). The message names
     `fuzzlab train run --score`.
   - It crawls into the temp directory (§4.6).
   - **Tests:** end to end against the loopback fixture apps with `--authorized`. These
     must exit 2 with zero sends (counted): `--categories ""`, `" , "`, a missing
     `--categories`, every T/L flag, and `--ground-truth`.

## 8. Tests (Phase 1)

**Isolation.** `tests/conftest.py` gains an autouse fixture. It sets `XDG_DATA_HOME` to
a per-test tmp directory, which child processes inherit, and deletes `FUZZLAB_STORE`
and `FUZZLAB_STORE_PATH`. A guard test asserts that `resolve(None)` under pytest lies
inside tmp.

**`storepath`.**
- Precedence, the conflict error, empty values, explicit `""`.
- `XDG_DATA_HOME` relative or unset; no home.
- `resolve` does no writes.
- `check_readable`/`check_writable` on a missing file, a missing parent, a directory,
  and a FIFO.
- `prepare` creates 0700 for the default only; it warns on a group-writable existing
  directory.
- Config delegation:
  - `load_config()` with no override equals `resolve(None)`;
  - `FUZZLAB_STORE_PATH` and `FUZZLAB_STORE` each move both the CLI and `load_config`;
  - an override wins.
- The default store is created on first write and reused on the second; `--store`
  wins.

**Per CLI (`report`, `mutate-run`, `train mutate`, `flow-anomaly`, `train
flow-anomaly`, `reveal-holdout`, `train reveal-holdout`, `train models`, `proxy`).**
- The default store is used.
- A missing store is refused, and nothing is created.
- `--dry-run` creates nothing.
- The store line appears on the right stream.
- `report --json` stays parseable.
- `reveal-holdout` refuses an implied default, and accepts `FUZZLAB_STORE`.
- The proxy order: `require_loopback` before any store work (extend
  `tests/test_loopback_listeners.py`).

**`train run`.**
- Parser parity: every dest of `auto` is present, and the source is not mutated.
- The URL positional and the `--base-url` alias; exactly-one and disagree errors.
- The URL-swallow hint.
- D-9 refusal; no `--authorized`.
- `--dry-run` creates nothing.
- Argv forwarding is verbatim, including dash-leading values.
- PA-0079(3): every usage path leaves no store file and no run row.

**Taxonomy.**
- Every dispatchable command is classified.
- Two-directional dest coverage; the `PENDING` behaviour.
- A help-counting test.
- Refusal and restriction through `copy_parser` on auto's parser: each T, L and W\*
  flag exits 2, naming `fuzzlab train run`; `--ground-truth` is refused with its own
  message; and all of this happens without importing any sender (the "working view"
  `scan` will use).

**Web compatibility.**
- Every `commandspec` spec still builds.
- For each spec, a values dict filling required fields builds an argv that the real
  parser accepts, and dry-runs where supported.
- Pins: `spec("report")`'s store option has `required is False`, and the proxy gains
  `--record`.

**NFR traces (PA-0112).** NFR-FUZZ-safe and NFR-FUZZ-dry-run gain `Enforced by:` lines
for `train run` tests. NFR-MUT-safe and NFR-MUT-dry-run gain them for `train mutate`.
No new NFR is added; the store's 0700 directory is FR-CORE-400.

**Mutation checks.** For each new mechanism, revert it, show its named test fails, then
restore it:
- refusal;
- D-9;
- the reveal refusal;
- the `list_models` allowlist;
- the conflict error;
- the reader no-create rule.

## 9. Bugs found, docs, follow-ups

**Docs.** Commands in docs come from executed runs (PA-0015). Phase 1's commands are
run against a local store and the loopback fixtures, or tagged `[design]`.
- `README.md`.
- `docs/ON_HOST_RUNBOOK.md`: one note on store resolution.
- The requirement specs:
  - CORE 02: FR-CORE-400;
  - FUZZ 07: FR-FUZZ-400, 401, 402;
  - ML 10: FR-ML-400;
  - MUT 09: FR-MUT-400;
  - PROXY 11: FR-PROXY-400;
  - UI 12: FR-UI-400, 401.
- `docs/ARCHITECTURE.md`.
- `CHANGELOG.md`.

**BUG-0400 (found while reviewing).**
- *Defect:* the shared dry-run display (`web/runner.build_flags`, used by
  `cli_dryrun`) mis-serializes several flags:
  - `nargs='*'` prints as `[]`;
  - `const=""` options are dropped;
  - a dash-leading value is printed space-separated.

  So the "exact command" a dry run prints is not the command that would run.
- *Disposition:* it is in `web/`, which this lane cannot edit.
  - Full bug protocol: ERROR_LOG, BUG-0400, PA-0400.
  - Pinned by a strict xfail in this lane's tests (PA-0054(3)/PA-0115(3)).
  - The fix is handed to the UI session.

**Follow-ups for the UI session.**
- `commandspec`: `auto` becomes `scan` and `train run`; `mutate-run` becomes `train
  mutate`; `flow-anomaly` becomes `train flow-anomaly`; add `train models` and `train
  reveal-holdout`.
- Group the launcher by `cli_taxonomy.COMMANDS`.
- `introspect` must skip `SUPPRESS` options.
- The UI's default store moved to the per-user path (§4.1).
- `web/diagnostics.model_registry_timeline` is the UI's own model listing; align it
  with `list_models`' allowlist.
- Fix BUG-0400.
- `cli_dryrun` needs specs for the new names.

**Follow-ups for the integrator.**
- Spider tables folded into the store (needs a migration).
- The `crawl --authorized` gap.
- The anonymous sender has no `scope_hosts` check (D15 says "in-scope hosts only").

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| The UI's default store moves | Intentional; `FUZZLAB_STORE_PATH=fuzzlab.db` restores the old location; flagged. |
| One store mixes working and benchmark state | §4.7. |
| `copy_parser` relies on argparse internals | Copies, never rebuilds; tested by identity and parity. |
| `report` now refuses a missing store | Safe direction; tested. |
| `reveal-holdout` now needs a named store | A safety exception; FR-FUZZ-402. |
| BUG-0138 flags merge in | `PENDING` plus the two-directional guard. |

## Appendix A: draft change-control entries

Each is appended once agreed. Deliverables start as `todo`. LOC are estimates.

- **CC-CORE-0400** — `core/storepath.py`, and `config.load_config` delegating
  `store_path` (FR-CORE-400). ~170 LOC module, ~15 LOC config, ~260 LOC tests.
  - *Impact:* every CLI that takes `--store`; the web UI's default store location
    (stated in §4.1); the config hash of crawler runs now records the resolved path.
  - *Risk:* medium (a UI-visible default moves).
  - *Mitigation:* the environment restores the old location; the conflict error; test
    isolation.
- **CC-FUZZ-0400** — `cli_taxonomy.py`, `train_cli.py`, the `reveal-holdout` and
  `flow-anomaly` defaults, `main(prog=)`, and NFR traces (FR-FUZZ-400/401/402).
  ~260 + ~200 LOC, ~450 LOC tests.
  - *Impact:* the CLI surface; old names unchanged.
  - *Risk:* medium (argparse copying; verbatim forwarding).
  - *Mitigation:* parity and identity tests, refusal tests, PA-0079 path tests.
- **CC-UI-0400** — grouped help from `COMMANDS`. `report`: optional `--store`, stderr
  store line, refuses a missing store (FR-UI-400/401). ~80 LOC, ~120 LOC tests.
  - *Risk:* low.
- **CC-MUT-0400** — `mutate-run`/`train mutate` default store, store line, dry-run
  store line, `prog` (FR-MUT-400). ~25 LOC, ~80 LOC tests.
  - *Risk:* low.
- **CC-PROXY-0400** — `proxy --record` (FR-PROXY-400). ~20 LOC, ~60 LOC tests.
  - *Risk:* low; recording stays opt-in.
- **CC-ML-0400** — `model_registry.list_models` allowlist (FR-ML-400). ~45 LOC,
  ~90 LOC tests.
  - *Risk:* low; the planted-secret test applies.

## Appendix B: round-1 findings and their resolution

Reviewer A's findings (numbered A1–A27) and reviewer B's (B1–B15):

| Finding | Resolution |
| --- | --- |
| A1, B1 | §4.1: one resolution; config delegates; the UI agrees by construction. |
| A2, B10 | §8 isolation fixture and guard; affected tests updated. |
| A3 | §3.3/§3.5/§3.9; every command classified or excluded with a reason. |
| A4 | `--budget-method` W\*, `--budget-seed` T. |
| A5 | §4.7: stated risk, guidance, rejected alternative. |
| A6, B3 | Both names honoured through one resolver; a conflict is an error. |
| A7 | `check_readable`/`check_writable`. |
| A8, B4 | §4.2 order. |
| A9 | Non-creating kind; reveal prints the store before counting. |
| A10 | §8 NFR traces. |
| A11 | `auto` listed under Working in Phase 1; D-9. |
| A12 | §7 Phase 2: pre-crawl `saved_source` check; message corrected. |
| A13 | §9 executed-run docs. |
| A14, B8 | §6.4. |
| A15 | `ResolvedStore`. |
| A16 | Explicit `""` is a usage error. |
| A17 | `prepare` warns. |
| A18 | Class L. |
| A19, B2 | §7: automatic mode, D15 stays in `resolve_run`, one `all` expansion, D15 amendment, blank refused. |
| A20 | §4.6: TemporaryDirectory. |
| A21 | §5/§9. |
| A22 | `PENDING` plus the two-directional guard. |
| A23 | §2.2 counting rule; D-10. |
| A24 | §4.4. |
| A25, B5 | `to_argv` dropped from Phase 1; forwarding is verbatim. |
| A26 | D-7(a). |
| A27, B15 | Appendix A. |
| B6 | §6.2. |
| B7 | §4.3. |
| B9 | §7 Phase 2 `validate()` and the header-budget timing. |
| B11 | Lab-only in the help; scope gap as a follow-up. |
| B12 | BUG-0400; §6.3 qualifies the display claim. |
| B13 | D-6/D-7/D-8 wording; the help's Store note; kinds renamed; D-10. |
| B14 | §4.1 XDG vs `~/.fuzzlab/`; explicit `""`; the warning; sidecars. |
