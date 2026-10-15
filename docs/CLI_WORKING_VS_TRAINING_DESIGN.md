# CLI simplification: a default store, working runs vs training runs

Status: **AGREED (design gate 3/3 after round 3, 2026-10-15); Phase 1 BUILT (CC-*-0400); Phase 2 gated on BUG-0138** — revision 3 with the round-3 fixes
(Appendix D) folded in; both reviewers stated no further round is needed. Two reviewers (A, B) reviewed rounds 1 and 2; both said
"agree with fixes". Appendix B maps round 1's findings to resolutions, Appendix C maps
round 2's.

The owner's request (2026-10-15): the CLI is too complicated. They want:

1. **A default store.** `--store` is never required.
2. **Working runs separated from training runs.**
   - A *working* run uses fuzzlab as a tool: point it at a URL and run.
   - A *training/benchmark* run covers ground truth, scoring, model training, holdouts,
     calibration and the model registry.

## 0. Constraints this lane works under

- **Locked files.** Until `origin/ccr-27885270-9ahcdd` carries a BUG-0138 commit, these
  are off limits: `harness/{auto,auto_cli,pipeline}.py`,
  `greybox/{greybox_cli,run}.py`, several `tools/*` (`spider`, `fetcher`,
  `store_adapter`, `authhttp`, `probesender`, …), `session/*`,
  `core/{http,urls}.py`, the oracle modules and `proxy/session_capture.py`.
  - **Phase 1** touches none of them.
  - **Phase 2** starts after that merge.
- **`fuzzlab/web/` is not edited.**
- **No store migrations.**
- **Reserved numbers:** `CC-*-0400…0449`, `BUG-/PA-0400…0449`, `FR-*-400+`.
- **Cross-lane rule (orchestration §5).** A change that would move another lane's
  behaviour (the web UI's store) is not forced through. It is built only as far as it
  is safe and verifiable, and the decision goes to the owner (§4.8).

## 1. Facts verified in the code (at `cdde39f`; re-verified by both reviewers)

**Commands and the store flag**

- `fuzzlab/cli.py` dispatches `web session crawl audit fuzz auto greybox-run proxy
  mutate-run report reveal-holdout flow-anomaly lab-generate build-db version`. The
  help is one flat list.
- `--store` is **required** in `auto`, `greybox-run`, `mutate-run`, `report`,
  `reveal-holdout` and `flow-anomaly`.
- `--store` is **optional** in:
  - `crawl`, `audit` and `fuzz`, as opt-in consolidation (with no `--store` they write
    to no store);
  - `proxy`, as opt-in recording.

**Ground truth**

- Ground truth never trains a model (`ml/dataset.py` labels come from the oracle).
- It does three things: scoring, `--points ground-truth`, and D14 category
  derivation.

**The web UI and the shared store setting**

- **The web UI does not inject `--store`.** The launcher form comes from each parser.
  A blank field is dropped by `web/runner.build_flags`. Once a parser's `--store` is
  optional, a blank UI field means "the CLI's default". UI-launched jobs inherit the
  UI's cwd and environment (`procutil.astart_server`, no `cwd`).
- **The existing shared store setting.** `core/config.DEFAULTS["store_path"] =
  "fuzzlab.db"`, relative to the cwd, can be overridden through `FUZZLAB_STORE_PATH`
  (generic `_from_env`). The web UI reads it for every page, for saved views, for the
  Repeater, and for `web --with-proxy` recording. `.gitignore` calls `/fuzzlab.db` "the
  shared SQLite project store".
- **Callers that pass `environ`.** About a dozen web and config tests call
  `load_config(…, environ={})` with no `store_path` override:
  - `tests/test_web_{security,lab,launcher,runner,scope,intercept,proxy_serve,frontend,overview}.py`;
  - `test_core_foundations.py`.

  `test_proxy_rules_and_scope.py:53` calls `load_config()` with the real
  environment.
- **Store-agnostic callers.** `load_config()` is called on paths that never touch the
  store: `session/cli.py`, `tools/authhttp.py`, `greybox_cli.py`, `auto_cli.py`, and the
  `start_run(…, load_config().hash())` sites. `Config.hash()` covers `store_path`.

**Dry runs and gates**

- `cli_dryrun.report` builds its display from `web.commandspec` plus
  `web.runner.build_flags`.
- **`build_flags` also builds the web launcher's *real* argv** (`web/app.py`,
  `build_argv`). It mis-serializes several flags (BUG-0400, §9):
  - `nargs='*'` prints as `[]`;
  - a `const=""` flag is dropped;
  - a dash-leading value is printed space-separated.
- `crawl` sends traffic and has no `--authorized` gate.
- The anonymous probe sender does no `scope_hosts` check.

## 2. Command taxonomy

### 2.1 Groups

| Group | Commands | What it is for |
| --- | --- | --- |
| **Working** (lab-only; fuzzlab as a tool) | `scan <url>` *(Phase 2)*; `auto` *(the working engine until `scan` exists)*; `crawl`, `audit`, `fuzz`, `session`, `proxy`, `report`, `web` | Point it at a lab target you are authorized to test. No ground truth. ML only as *used*. |
| **Training / benchmark** | `train run <url>`, `train models`, `train reveal-holdout`, `train flow-anomaly`, `train mutate` | Ground truth, scored runs, model training and its modulators, holdouts, calibration, the model registry, and the research learners. |
| **Lab** | `lab-generate`, `build-db`, `greybox-run` (needs the lab's instrumentation); lab control is `lab/labctl.sh` or the UI's Lab page | Building and driving our own lab. |
| **Other** | `version`, `help` | |

**Decisions**

- **D-1.** There is one training group, `train`. A benchmark is `train run
  --ground-truth …`. There is no `benchmark` command; the help says "training and
  benchmark".
- **D-2.** `mutate-run` becomes `train mutate`. It is research and produces no findings.
- **D-3.** `greybox-run` goes in the Lab group. It needs the lab shim, so its
  `--ground-truth` and `--points` flags stay.
- **D-4.** `flow-anomaly` becomes `train flow-anomaly`.
- **D-5.** `train models` lists saved models. It is label-free and uses an explicit
  allowlist (§6.4).
- **D-9.** `train run` must carry at least one training or benchmark choice. Otherwise
  it exits 2 before any side effect and names `fuzzlab auto` (Phase 2: `fuzzlab
  scan`). Choices are detected by **presence on the command line**, never by comparing
  values with defaults (copied training dests get a sentinel default). A choice is one
  of:
  - `--ground-truth`, `--holdout`, `--calibrate`, `--hybrid`, `--rank-objective`;
  - `--budget-seed`, or a `--budget-method` other than `score`;
  - `--mode manual`, `--points ground-truth` (an explicit `--mode automatic` or
    `--points crawl` is a working choice and does not count);
  - `--score` or `--rank`, **unless** `--train-on saved` is also given, since applying
    a saved model is working use;
  - `--train-on run` or `--train-on earlier`.
- **D-10.** `fuzzlab train` with no subcommand prints the group's usage and exits 2.
  `fuzzlab train --help` exits 0.

### 2.2 Grouped help

The help is printed from `cli_taxonomy.COMMANDS`. Each row carries a name, a group, a
summary, `replaced_by`, and `store_default` (whether `--store` defaults; this drives the
dry-run store line, §4.4).

The counting rule (tested):
- every dispatchable top-level name appears exactly once;
- an old name appears only under "Older names";
- each `train <sub>` appears once;
- `help`, `-h` and `--help` are entry points, not rows.

`scan` is absent in Phase 1.

```
usage: fuzzlab <command> [args]      (fuzzlab <command> --help for its options)

Working runs (lab-only): use fuzzlab as a tool against a lab target you are authorized to test
  auto [args]          crawl results -> audit -> oracle-confirm pipeline (requires --authorized;
                       ground-truth and training flags: use `train run`)
  crawl … audit … fuzz … session <sub> … proxy … report … web [--with-proxy] …

Training and benchmark: ground truth, scored runs, model training, holdouts, models
  train run <url>  train models  train reveal-holdout  train flow-anomaly  train mutate

Lab
  lab-generate …  build-db …  greybox-run …

Other
  version

Older names (still work): mutate-run, reveal-holdout, flow-anomaly

Store: --store PATH, else $FUZZLAB_STORE, else $FUZZLAB_STORE_PATH, else ./fuzzlab.db
       in the current directory (the web UI uses the same rule). auto and greybox-run still need --store until
       Phase 2.
Lab-only. Nothing runs against a target until you ask it to (no auto-run).
```

## 3. Flag classification

| Class | Meaning |
| --- | --- |
| **B** | Both working and training. |
| **T** | Training only. Refused in a working command; the message names `fuzzlab train run`. |
| **W\*** | Narrowed in working commands, as stated per row. |
| **L** | Needs our instrumented lab. Refused in `scan`; allowed in `train run` and in Lab commands. |

The table lives in `cli_taxonomy.FLAG_CLASSES` and covers **every dispatchable
command's parser**. Subparsers are walked, so `session`'s subcommands are classified
too. Its guard test checks both directions:

- it fails on a parser dest with no class;
- it fails on a stale entry;
- `PENDING` (BUG-0138's `auth_origin`, `no_spa_query`) fails once a pending dest exists
  in a parser but is still marked pending.

Exclusions, with reasons:
- `web`: its parser lives inside `web_main` and is not exposed as `build_parser()`. Its
  flags are UI-server options.
- `build-db` and `version`: no parser.

### 3.1 `auto` (the engine of `scan` and `train run`)

| Flag | Class | Reason |
| --- | --- | --- |
| `--base-url` | B | The target. In `scan`/`train run` it is the positional `<url>` (hidden alias, §5). |
| `--spider-db` | B | Crawl input; internal in `scan`. |
| `--store` | B | Optional (§4). |
| `--ground-truth` | **T** | Known answers. Never a working option. |
| `--mode` | **T** | `scan` always runs **automatic**, so `resolve_run` enforces D15 itself. Manual "all by default" is an experiment choice. |
| `--points` | **T** | `ground-truth` sourcing is a benchmark. |
| `--categories` | B | Required by D15 in `scan`. `all` is expanded in one function (§7). |
| `--identity`, `--auth-origin` (pending) | B | Session and safety. |
| `--browser`, `--oob` | B | Confirmation mechanisms. |
| `--greybox-coverage-file`, `--greybox-dbfault-file` | **L** | They read the lab shim's side channel. |
| `--bandit` | B | Ordering while testing (owner's list). Its posteriors are store-wide (§4.7). |
| `--score`, `--rank` | **W\*** | `scan` *applies* a saved model (`--train-on saved` implied). `train run` trains or applies. |
| `--model-id`, `--ranker-model-id` | B | Which saved model to apply. |
| `--train-on`, `--rank-objective`, `--calibrate`, `--holdout`, `--hybrid` | **T** | Training data, fit choices, modulators. |
| `--confirm-budget` | B | Budget (owner's list). |
| `--budget-method` | **W\*** | `scan` allows `score` only. `uncertainty`/`committee` are active learning; `random` is a control. |
| `--budget-seed` | **T** | It seeds only the experiment orders. |
| `--anomaly`, `--anomaly-contamination`, `--anomaly-method` | B | A label-free tripwire over this run. |
| `--plugins`, `--header-points`, `--fuzz-json-writes`, `--authorized`, `--dry-run` | B | Tool behaviour, injection points, the gate, and plan-only mode. |

### 3.2 Other commands

- **`crawl`.** Every flag is B. `--start` becomes `<url>` and `--db` is internal in
  `scan`. `--resume` is not offered by `scan`. Pending: `--auth-origin`,
  `--no-spa-query`.
- **`audit`, `fuzz`.** Every flag is B. No ground truth, no model fitted. `fuzz`'s
  observation CSV is a by-product of tool use.
- **`session`.** Every subcommand flag is B (credentials and session state). It has no
  ML and no ground truth.
- **`greybox-run`** (Lab).
  - `--ground-truth`, `--points`: T, allowed in Lab.
  - `--cov-dir`, `--app-root`, `--labctl`, `--reset`, `--settle`: L.
  - Everything else: B.
- **`proxy`.** Every flag is B, the new `--record` included.
- **`report`.** B. Reading a scored run is not training.
- **`mutate-run`/`train mutate`, `reveal-holdout`/`train reveal-holdout`,
  `flow-anomaly`/`train flow-anomaly`.** T.
- **`lab-generate`.** L.

## 4. The default store

### 4.1 One resolution, one function per concern (PA-0003, PA-0021)

The new module is `fuzzlab/core/storepath.py`. It imports only the stdlib.

```python
DEFAULT_STORE = "fuzzlab.db"            # the one literal; config.DEFAULTS references it

def from_environ(environ) -> tuple[str, str] | None
    # (value, source): FUZZLAB_STORE, else FUZZLAB_STORE_PATH; empty/whitespace = unset;
    # `~` expanded. NEVER raises. The one place both names are read.

@dataclass(frozen=True)
class ResolvedStore: path: Path; source: str   # "--store" | "FUZZLAB_STORE" | "FUZZLAB_STORE_PATH" | "default"

def resolve(value: str | None, *, environ=None) -> ResolvedStore     # pure; absolute path
def resolve_store(value: str | None) -> Path                         # == resolve(value).path
```

**Order:**
1. `--store`. An explicit `--store ""` or whitespace raises `StorePathError` (malformed
   is not absent, PA-0105).
2. `$FUZZLAB_STORE`.
3. `$FUZZLAB_STORE_PATH`.
4. `DEFAULT_STORE`, relative to the cwd.

**When both variables are set.** `FUZZLAB_STORE` wins, everywhere. There is no
conflict error. A raising rule would make `load_config()` raise from store-agnostic
commands (§1); a deterministic precedence, applied by the one function both sides call,
keeps the CLI and the UI in step.

**Config uses the same function.** This is a minimal change: the default is
**unchanged**.
- `config.DEFAULTS["store_path"] = storepath.DEFAULT_STORE` (same value, single
  literal).
- After merging, `load_config` sets `store_path` from
  `storepath.from_environ(environ)` when it returns a value. `overrides` still win.
  This replaces the generic layer for that one key.
- Effects:
  - `FUZZLAB_STORE` now also moves the UI;
  - `~` is expanded for both sides;
  - an empty variable means "unset" for both sides (today config would hold `""`);
  - `load_config` never raises because of the store;
  - for an unset environment, `store_path` and `Config.hash()` are **byte-identical** to
    today (tested).

**How the CLI and UI agree.**
- The default is the same relative `fuzzlab.db`, and UI-launched children inherit the
  UI's cwd.
- Both environment variables go through `from_environ`.
- No home directory is consulted, so nothing can fail on a home-less UID.
- `environ=` keeps its meaning (it governs `FUZZLAB_*`).

**Typed checks at the boundary.** These are pure stats that raise `StorePathError` (a
`ValueError`). CLIs turn it into `parser.error`, exit 2, and the message names the
source.
- `check_readable(rs)`: the store is missing, or is a directory or another non-regular
  file.
- `check_writable(rs)`: the parent directory is missing, or the path is a directory or
  another non-regular file.

There is no directory creation at all. The default's parent is the cwd, and an
explicit path's missing parent is a usage error, as before but now typed.

`describe(rs)` prints, for example, `store: /home/u/proj/fuzzlab.db (default)` or
`store: /x.db (FUZZLAB_STORE)`.

### 4.2 Side-effect order (PA-0079)

Writers follow this order:

1. Parse the arguments, and (for `train run`) apply D-9, which is pure, so a dry run never plans
   a command that would be refused.
2. Handle `--dry-run`: print the plan, which includes the store line (§4.4), and exit.
3. Run the usage checks that need no store, in this order:
   1. explicit `--store ""` (it fails the argparse parse);
   2. D-9 (`train run`);
   3. `--authorized`;
   4. the command's other pre-store checks.

   D-9 precedes `--authorized`, so a mis-aimed `train run` is told so first.
4. `resolve`, then `check_writable`.
5. Open `Store` (which creates the file).

`train run` performs steps 1–4 itself and then delegates to `auto_cli.main`. That
function's own semantic checks run before it opens the store, so a usage error leaves
**no file and no run row** on every path (tested; no residual).

**Command kinds:**

| Kind | Commands | Missing store |
| --- | --- | --- |
| Writers | `train run`, `train mutate`/`mutate-run`, `proxy --record`/`--store`; Phase 2: `scan`, `auto`, `greybox-run` | Created |
| Non-creating | `report` (reads); `flow-anomaly` (writes `flow.anomaly_*`); `reveal-holdout` (records the reveal); `train models` | Refused (exit 2), never created |

`report` used to create an empty store silently at a mistyped path. That stops, on
purpose.

### 4.3 Reveals name their store before they count

`reveal-holdout` / `train reveal-holdout` resolve the store like every other command,
so `--store` is never required. This follows the owner's request; round 2's reviewer A
asked for owner sign-off on the refusal revision 2 proposed, and it is withdrawn.

To keep the counted reveal from being spent unknowingly:
- the `describe()` line goes to **stderr before** `reveal()` is called;
- the header line names the store.

`reveal()` counts only when that store's run actually has sealed metrics
(`core/sealed.py`).

Residual: `auto`'s locked hint (`fuzzlab reveal-holdout --run N`) omits `--store`.
Phase 2 adds it whenever the store is not the default.

### 4.4 Where the path is printed

- **Run summaries (stdout, one added line).**
  - `train run` prints it after the engine's summary.
  - `train mutate` / `mutate-run`. Their `sqlite3 <path>` hint uses the resolved path.
  - `train flow-anomaly` / `flow-anomaly`.
- **stderr.**
  - `report`, so `--json` stays canonical.
  - `train models`.
  - `reveal-holdout`, before the reveal.
- **The proxy banner.**
- **Dry runs.** Only commands with `COMMANDS[...].store_default` print a store line.
  `crawl`, `audit` and `fuzz` do not, because they write no store without `--store`.
  `proxy` prints one only when `--record` or `--store` is given.

### 4.5 Proxy

Recording stays opt-in. The new `--record` records into the resolved store. `--store
PATH` alone records there; given both, `--store` wins.

The order is:
1. `--dry-run`, `--export-ca`;
2. `--authorized`, then `require_loopback` (the existing order, unchanged);
3. `resolve`, then `check_writable`;
4. `Store`.

### 4.6 `spider_results.db`

The crawl DB is folded into the store logically, not physically, in this lane:
- Standalone `crawl` keeps `--db spider_results.db`.
- `scan` (Phase 2) crawls into a `tempfile.TemporaryDirectory()` (mode 0700) next to the
  store. Its DB and every `-wal`/`-shm`/`-journal` sidecar go with that directory. The
  engine imports the DB into the store, and the directory is removed in a `finally`.
- Folding the spider tables into the store needs a migration. That is an integrator
  follow-up.

### 4.7 One store holds working and benchmark state (a stated risk)

Several things are store-wide:
- bandit posteriors;
- holdout reveal counts;
- `report --run latest`;
- `--train-on earlier` and the budget pool, which take earlier runs against the same
  target.

Before this change, a required `--store` kept experiments apart. Now:
- the default store is the working store;
- the `train run` help and the README say to **give benchmark and training runs their
  own `--store`** when reproducibility matters;
- every summary prints the store.

A separate training default was rejected: two defaults is the complexity the owner asked
us to remove, and `scan --score` would then miss models trained under `train run`.

### 4.8 Open decision for the owner: move the default to a per-user location?

The session brief proposed `$XDG_DATA_HOME/fuzzlab/default.db` ("proposed as"). Round 2 showed that doing it
safely needs changes across lanes:

| Required change | Why |
| --- | --- |
| Create the 0700 parent at first open, in `core/store.open_store`, for the default only | The UI's own writers (saved views, Repeater, `web --with-proxy`) open `Store` directly and would fail on a fresh machine. |
| Take `store_path` out of `Config.hash()` | Otherwise every crawl, audit and fuzz run's hash would carry a per-user absolute path. |
| A one-line hint when `./fuzzlab.db` exists but the default moved | Existing users' runs, flows and saved views would otherwise vanish from the UI. |
| A data-home test hook | The `environ={}` web tests would otherwise read the developer's real home store. |
| The UI session's agreement | Its store moves. |

**Recommendation:** adopt it, as a coordinated follow-up with the UI session, after
Phase 2. Phase 1 keeps the shared `./fuzzlab.db` default.
- Phase 1 delivers the owner's actual requirement (`--store` never required; one default
  database the CLI and UI share).
- It delivers it with zero cross-lane movement.
- The switch then becomes one constant, plus the four items above.

The open question "per-project vs one global database" in
`docs/components/02-core-library/requirements.md` §8 is answered "per project
directory (current); per-user pending the owner's decision".

## 5. Back-compatibility and refusal

- **D-6. Old commands stay real commands.**
  - `auto` is unchanged (locked); Phase 2 gives it the default store.
  - `mutate-run`, `reveal-holdout` and `flow-anomaly` stay dispatchable. Each prints one
    **stderr** line naming its new name. Their stdout gains only the store line (§4.4).
- **D-7. Hidden options in the new commands are of two kinds only.**
  - (a) `--base-url`, an alias for the positional `<url>`. **Exactly one** of the two
    is required; refused when both are given and disagree.
  - (b) Refusing options (D-8).
- **D-8. Training, benchmark and lab flags in a working command are refused loudly, by
  name.** The refusing action raises as argparse meets the flag. Its value is consumed,
  so the message names the flag and never the path. A W\* flag is restricted to its
  allowed values. Examples:

  ```
  fuzzlab scan: error: --calibrate is a training option; use `fuzzlab train run` (see `fuzzlab train run --help`)
  fuzzlab scan: error: --ground-truth is a benchmark option and never part of a working run; use `fuzzlab train run`
  fuzzlab scan: error: --budget-method committee is a training choice (scan orders by score); use `fuzzlab train run`
  fuzzlab scan: error: --greybox-coverage-file needs the instrumented lab; use `fuzzlab train run` or `fuzzlab greybox-run`
  ```

  Note for the UI: `commandspec.introspect` does not skip `SUPPRESS`.

## 6. Mechanism (Phase 1)

### 6.1 `fuzzlab/core/storepath.py`

As described in §4.1.

### 6.2 `fuzzlab/cli_taxonomy.py` (pure)

**Contents:** `COMMANDS`, `FLAG_CLASSES`, `PENDING`, `training_choices(args)` (D-9),
and the parser helpers below.

**`copy_parser(source, *, prog, url_positional=False, refuse=None, restrict=None,
refuse_to="", sentinel_dests=None)`**
- It adds a `copy.copy(action)` of each source action to a fresh parser through
  `_add_action`. Actions are never rebuilt from their kwargs.
- On the copies it sets `required=False` (default `None`) on `--store`.
- With `url_positional`, it sets `--base-url` to `required=False` and
  `help=SUPPRESS`, and adds a positional `url` with `nargs='?'`.
- `sentinel_dests` get a unique sentinel default, so presence can be detected (D-9).
- Refusing and restricted actions keep their option strings and nargs.
- The source parser is never mutated (tested by identity and by value).

**The URL must be first, and this is enforced.** When the parsed `url` is set and
`argv[0]` is not exactly that token, the parser gives a usage error: "put the <url>
first, or use --base-url". This covers `train run --authorized http://x`, a `--`
separator, and an abbreviated flag before the URL. When `url` is missing and an
optional-value flag (`--header-points`) holds a URL-shaped value, the error gives the
same hint.

**No `to_argv` in Phase 1.** `train run` forwards the user's argv **verbatim**:
`["--base-url", url, *argv[1:]]` for the positional form (the `--base-url` alias form
is forwarded unchanged), plus `["--store", path]` only when
`namespace.store is None`. That check reads the namespace, so an abbreviation like
`--sto` counts as giving the flag.

### 6.3 `fuzzlab/train_cli.py`

**`train run`** follows §4.2 and then calls `auto_cli.main(forwarded)`. It prints the
store line after the engine's summary.

Phase-1 warts, removed in Phase 2 by `auto_cli.main(argv, *, prog=)`:
- errors raised inside `auto_cli.main` say `fuzzlab auto:`;
- `--dry-run` shows the equivalent `fuzzlab auto …` argv, subject to BUG-0400's
  display limits.

**`train mutate` / `reveal-holdout` / `flow-anomaly`** forward argv to the existing
CLI's `main(argv, prog=...)`. Each CLI resolves its own store once.

**`train models`** runs `check_readable`, then `list_models`.

### 6.4 `ml.model_registry.list_models(store)`: an explicit allowlist

It returns `(id, name, version, feature_version, created_at, has_params)`, in
**ascending** id order. That is a listing, not a "newest" selection; it passes the
PA-0063 guard.

From `calibration` it reads **only**:
- `trained_on`;
- `run_id` (the scope);
- `source_model_id`;
- `len(scored_run_ids)`.

It never reads `params`, any metric, `holdout.*`, or `SEALED_TABLES`. A malformed
calibration prints `unreadable` (PA-0108).

The test plants a metric, `holdout.rows`, and a `holdout_metric` row, and asserts none
of their values appears. A control proves the check is live.

## 7. Phases

### Phase 1 (now; no locked file, no `web/` file)

1. `core/storepath.py`, with `core/config.py` using `from_environ` and `DEFAULT_STORE`.
2. Default store for `report`, `mutate-run`, `reveal-holdout` and `flow-anomaly`.
3. `proxy --record`.
4. `cli_taxonomy.py`.
5. `train_cli.py`.
6. `list_models`.
7. Grouped help.
8. Test isolation (§8).
9. BUG-0400.
10. Docs and bookkeeping.

### Phase 2 (after BUG-0138; merge `origin/ccr-27885270-9ahcdd` first)

1. **`auto_cli.py`.**
   - Extract the usage checks into `validate(p, args)`, called by `main` and by
     `scan`.
   - `main(argv, *, prog=None)`.
   - Optional `--store` (`storepath`).
   - The reveal hint carries `--store` when the store is not the default.
   - A deprecation note once `scan` exists.
   - The header budget runs in `scan` as a post-crawl, pre-probe, pre-store refusal.
2. **`greybox_cli.py`:** optional `--store`.
3. **`tools/spider.py`:** `scan` reuses `spider_kwargs`/`session_manager_for`. Keep
   `--auth-origin` and `--no-spa-query`.
4. **`session/cli.py`:** re-classify after the merge (`PENDING`).
5. **`scan <url>`, a new file.**
   - `--authorized` before the crawl.
   - `validate()` before the crawl.
   - Automatic mode, so D15 stays in `resolve_run`. A blank `--categories` is refused.
     `all` is expanded in `core.runmode.expand_selection`, which is recorded as a D15
     amendment.
   - `--score`/`--rank`: a pre-crawl check, `check_readable` and then `saved_source`
     over this target's runs, refuses with no model. Opening an existing store runs its
     migrations, which is stated. This already holds in Phase 1 for every non-creating
     command (`report`, `train models`, `reveal-holdout`, `flow-anomaly`): they never
     create a store, but they do migrate an older one when they open it.
   - Temp crawl directory (§4.6).
   - Loopback end-to-end tests. These cases must send zero requests (counted):
     `--categories ""`, `" , "`, no `--categories`, each T/L flag, `--ground-truth`.
6. **The owner decision (§4.8)**, if accepted, with the UI session.

## 8. Tests (Phase 1)

**Isolation (`tests/conftest.py`).** An autouse fixture deletes `FUZZLAB_STORE` and
`FUZZLAB_STORE_PATH`. `HOME` is not touched, because Playwright's cache lives there.
`.gitignore` ignores `fuzzlab.db` at **any depth** (a writer run from a subdirectory must never
leave a committable store). A session-scoped guard also fails on a new `fuzzlab.db` anywhere in
the tree, and snapshots `(exists, size, mtime_ns, inode)` of `fuzzlab.db` and its
`-wal`/`-shm` sidecars in the repository root and the pytest invocation cwd at session
start, and fails the run on **any** change: a new file or a write to a developer's
existing store. Tests that
exercise the default `chdir` into `tmp_path`.

**`storepath`.**
- Precedence and the source labels; `FUZZLAB_STORE` over `FUZZLAB_STORE_PATH`.
- Empty or whitespace variables count as unset. An explicit `""` is an error. `~` is
  expanded.
- `resolve` performs no writes.
- `check_readable`/`check_writable` on a missing store, a missing parent, a directory,
  and a FIFO.
- Config:
  - with no environment, `load_config(environ={})["store_path"] == "fuzzlab.db"`, and
    `hash()` is unchanged from a frozen pre-change value;
  - `FUZZLAB_STORE` and `FUZZLAB_STORE_PATH` each move both `load_config` and the CLI;
  - an override wins;
  - an empty variable is unset on both sides;
  - with both variables set, `FUZZLAB_STORE` wins on both sides.
- The default store is created by the first writer and reused by the second; `--store`
  wins.

**Per CLI.** Covers `report`, `mutate-run`, `train mutate`, `flow-anomaly`, `train
flow-anomaly`, `reveal-holdout`, `train reveal-holdout`, `train models` and `proxy`.
- The default is used.
- A missing store is refused and nothing is created.
- `--dry-run` creates nothing and prints the store line only where `store_default`.
- The store line goes to the right stream; `report --json` still parses.
- Reveal: the store line is on stderr before any number.
- Proxy: `require_loopback` before any store work.

**`train run`.**
- Parity: every dest of `auto` is present, and the source is unmutated.
- The URL: positional or alias; exactly one; disagreeing; not first; swallowed.
- D-9: presence-based, with `--score --train-on saved` refused.
- No `--authorized`.
- `--dry-run` creates nothing.
- Forwarding is verbatim (dash-leading values, `--sto` abbreviation).
- PA-0079(3): every usage path leaves no file and no run row.

**Taxonomy.**
- Every dispatchable command is classified, subparsers included.
- Coverage checks both directions; `PENDING` behaves as specified.
- Help counting.
- Each T/L/W\* flag is refused through `copy_parser` on auto's parser, naming `train
  run`, and opens no socket (importing `auto`'s parser imports its sender module
  today; `auto_cli` is locked, so Phase 2 makes that import lazy).

**Web compatibility.**
- Every `commandspec` spec builds.
- For each spec (special-casing `session`'s subcommands), a values dict filling the
  required fields builds an argv that the real parser accepts.
- Pins: `spec("report")` store `required is False`; the proxy gains `--record`.

**NFR traces (PA-0112).** NFR-FUZZ-safe and NFR-FUZZ-dry-run gain `Enforced by:` lines
naming the `train run` tests. NFR-MUT-safe and NFR-MUT-dry-run gain them for `train
mutate`. No new NFR.

**Mutation checks.** For each, revert it and show the named test fails, then restore:
- refusal;
- the W\* restriction;
- D-9;
- URL-first;
- the reader no-create rule;
- `from_environ` precedence (config side);
- the `list_models` allowlist;
- the reveal store line before counting.

## 9. Bugs, docs, follow-ups

**BUG-0400.**
- *Defect:* `web/runner.build_flags` serializes argv wrongly for:
  - `nargs='*'`, which it prints as `[]`;
  - `const=""`, which it drops;
  - a dash-leading value, which it splits so it cannot be re-parsed.
- *Affected:* both `cli_dryrun`'s display and the **web launcher's real launch argv**.
  From the UI, a bare `--follow-selector-forms` cannot be enabled, and
  `--submit-spa-forms` with no routes becomes the route "[]".
- *Handling:*
  - Full protocol: ERROR_LOG, BUG-0400, PA-0400.
  - PA-0002 sweep: every argv builder in `fuzzlab/`.
  - Pinned by strict xfails.
  - The fix is handed to the UI session (`web/` is out of scope here).

**Docs.** Every command shown comes from an executed run (PA-0015), against a local
store or the loopback fixtures; anything else is tagged `[design]`.
- `README.md`.
- `docs/ON_HOST_RUNBOOK.md`.
- `requirements.md` updates:
  - CORE 02: FR-CORE-400; §8 open question;
  - FUZZ 07: FR-FUZZ-400/401;
  - ML 10: FR-ML-400;
  - MUT 09: FR-MUT-400;
  - PROXY 11: FR-PROXY-400;
  - UI 12: FR-UI-400/401.
- `docs/ARCHITECTURE.md`.
- `CHANGELOG.md`.

**Follow-ups for the UI session.**
- `commandspec`:
  - `auto` → `scan` + `train run`;
  - `mutate-run` → `train mutate`;
  - `flow-anomaly` → `train flow-anomaly`;
  - add `train models` and `train reveal-holdout`.
- Group the launcher by `COMMANDS`.
- `introspect` should skip `SUPPRESS`.
- BUG-0400.
- `cli_dryrun` specs for the new names.
- `web/diagnostics.model_registry_timeline` should be aligned with `list_models`'
  allowlist.
- The §4.8 decision.

**Follow-ups for the integrator.**
- Folding the spider tables into the store (a migration).
- `crawl --authorized`.
- The anonymous sender's `scope_hosts` gap.

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| The default is cwd-relative, so different directories get different stores | It is the existing shared convention: the UI and CLI agree, and the path is printed everywhere. Per-user is §4.8. |
| One store mixes working and benchmark state | §4.7. |
| `copy_parser` relies on argparse internals | It copies, never rebuilds; identity and parity tests. |
| `report` refuses a missing store | That is the safe direction; tested. |
| BUG-0138 drift | `PENDING` plus a two-directional guard. |
| The config change | The default is byte-identical (hash test). Only the environment-variable handling changes, made consistent with the CLI. |

## Appendix A: draft change-control entries (LOC estimates; deliverables start `todo`)

**CC-CORE-0400.** `core/storepath.py` (FR-CORE-400), with `config` taking
`DEFAULT_STORE` and `from_environ`. About 120 LOC, 10 LOC config, 220 LOC tests.
- *Impact:* every `--store` CLI. The UI now also honours `FUZZLAB_STORE`, and `~`
  and empty values are treated consistently. The default and the hash are unchanged.
- *Risk:* low.

**CC-FUZZ-0400.** `cli_taxonomy.py`, `train_cli.py`, the defaults for `reveal-holdout`
and `flow-anomaly`, `main(prog=)`, NFR traces (FR-FUZZ-400/401). About 280 + 220 LOC,
500 LOC tests.
- *Risk:* medium.
- *Mitigation:* parity and identity, refusal, URL-first, D-9, and PA-0079 path tests.

**CC-UI-0400.** Grouped help; `report`'s optional store, stderr line, and no-create rule
(FR-UI-400/401). About 90 LOC, 130 LOC tests.
- *Risk:* low.

**CC-MUT-0400.** `mutate-run`/`train mutate` defaults (FR-MUT-400). About 25 LOC,
80 LOC tests.
- *Risk:* low.

**CC-PROXY-0400.** `proxy --record` (FR-PROXY-400). About 20 LOC, 60 LOC tests.
- *Risk:* low.

**CC-ML-0400.** `list_models` allowlist (FR-ML-400). About 45 LOC, 90 LOC tests.
- *Risk:* low.

## Appendix B: round-1 resolutions

Unchanged from revision 2, except where Appendix C supersedes a resolution.

- **A1, B1.** A single resolution: config uses `from_environ`/`DEFAULT_STORE` (§4.1).
- **A2, B10.** §8 isolation.
- **A3.** §3.2.
- **A4.** W\*/T.
- **A5.** §4.7.
- **A6, B3.** One function reads both names (§4.1).
- **A7.** The checks.
- **A8, B4.** §4.2.
- **A9.** The non-creating kind.
- **A10.** §8 NFR traces.
- **A11.** `auto` under Working; D-9.
- **A12.** Phase 2 pre-crawl check.
- **A13.** Docs from executed runs.
- **A14, B8.** §6.4.
- **A15.** `ResolvedStore`.
- **A16.** Explicit `""` is an error.
- **A17.** Moot (no directory creation in Phase 1).
- **A18.** L.
- **A19, B2.** Automatic mode.
- **A20.** TemporaryDirectory.
- **A21.** §5/§9.
- **A22.** `PENDING`.
- **A23.** Counting rule; D-10.
- **A24.** §4.4.
- **A25, B5.** Verbatim forwarding.
- **A26.** D-7.
- **A27, B15.** Appendix A.
- **B6.** §6.2.
- **B7.** §4.3, revised (Appendix C, A6).
- **B9.** Phase 2 `validate()`.
- **B11.** Lab-only wording; follow-up.
- **B12.** BUG-0400.
- **B13.** Wording, D-10.
- **B14.** §4.6, explicit `""`.

## Appendix C: round-2 resolutions

**Reviewer A, round 2:**
- **A1 (the `environ={}` meaning; the false grep claim).** No home or XDG lookup
  remains. `environ` governs only `FUZZLAB_*`; the default is relative. The grep claim
  is removed and the affected tests are listed in §1.
- **A2 (UI writers on a fresh install).** Moot: the default is unchanged. Recorded as a
  precondition in §4.8.
- **A3 (the env layer bypasses the resolver).** Config reads the environment through
  `from_environ` (tilde, empty, precedence), with tests on both sides.
- **A4 (`load_config` raising).** `from_environ` never raises; no home lookup remains.
- **A5 (cross-lane impact).** The UI default does not move. It is the owner's decision
  (§4.8).
- **A6 (reveal refusal deviates from the owner).** The refusal is withdrawn; the store
  line prints before counting (§4.3).
- **A7 (BUG-0400 scope).** The launch-argv impact is stated (§9).
- **A8 (session/web).** `session` is classified, with subparsers walked; the `web`
  reason is corrected.
- **A9.** `session` is special-cased in the web-compatibility test.
- **A10.** D-9 is presence-based and excludes `--train-on saved`.
- **A11.** URL-first is enforced.
- **A12, A13.** Moot (no directory; the hash is unchanged); both are recorded in §4.8.
- **A14.** The `auto` help line.
- **A15.** `None` defaults.

**Reviewer B, round 2:**
- **R2-1.** Moot; §4.8 precondition.
- **R2-2.** A non-raising, consistent `from_environ`; tests run on both sides.
- **R2-3.** The claim is corrected; there is no home dependence; the fixture and the
  `fuzzlab.db` guard.
- **R2-4.** The hash is unchanged, tested against a frozen value; §4.8 precondition.
- **R2-5.** It is now an explicit owner decision with a recommendation; the §8 open
  question is answered.
- **R2-6.** URL-first is enforced, `--`/abbreviation cases included.
- **R2-7.** Sentinel defaults; store presence is read from the namespace.
- **R2-8.** `store_default` per command.
- **R2-9.** FR-FUZZ-402 is withdrawn along with the refusal.
- **R2-10.** §4.2 states the order.
- **R2-11.** Phase 2: `check_readable` first; migrations stated.

## Appendix D — round-3 resolutions (reviewer A)

A-R3-1 guard snapshots size/mtime/inode (any write fails); A-R3-2 existing proxy order kept;
A-R3-3 alias-form forwarding stated; A-R3-4 D-9 counts `--mode manual`/`--points ground-truth`
only; A-R3-5 proxy store line depends on `--record`/`--store`; A-R3-6 help wording + mechanism
name; A-R3-7 non-creating commands migrate an existing store (stated); A-R3-8 attribution is the
session brief's "proposed as".

## Appendix E — round-3 resolutions (reviewer B)

- N1: `.gitignore` → `fuzzlab.db` at any depth; the guard checks the whole tree for a new one; Phase 2's
  scan temp dir gets the fixed prefix `.fuzzlab-scan-` and is ignored too.
- N2: when `--holdout` is given, `train run` prints a store-qualified hint after the engine summary
  (`fuzzlab train reveal-holdout --store <path> --run <id>`); the reveal header names the run's
  tool, host and start time, so a wrong-store reveal is obvious.
- N3: D-9 runs before the dry-run branch (§4.2 step 1).
- N4: help wording (applied with A-R3-6).
- N5: the unchanged-hash test asserts `load_config(environ={}).hash() == Config(values=dict(DEFAULTS)).hash()`
  — derived from the source of truth, no frozen literal (PA-0001).
- N6: mechanism name (applied with A-R3-6).
- N7: a default store is created with the umask's mode, as any explicit path today (no regression);
  stated in FR-CORE-400 and tied to the §4.8 per-user follow-up (private mode at creation).
