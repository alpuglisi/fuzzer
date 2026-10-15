"""FR-FUZZ-400, FR-ML-400: ``fuzzlab train <sub>`` — the training and benchmark group.

`train run` carries `auto`'s flags with the target first and ``--store`` optional; it
must carry a training or benchmark choice (D-9), forwards the user's argv verbatim
(PA-0400(3)), and leaves no store file and no run row behind any usage error (PA-0079).
`train models` lists saved models with label-free facts only (an allowlist, PA-0092).
"""

from __future__ import annotations

import ast
import inspect
import json

import pytest

from fuzzlab import train_cli
from fuzzlab.cli import main as fuzzlab_main
from fuzzlab.core.storepath import DEFAULT_STORE
from fuzzlab.core.store import Store

URL = "http://127.0.0.1:9"     # nothing listens; no test here reaches a network send


@pytest.fixture
def cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def forwarded(monkeypatch):
    """Capture what `train run` hands the engine (and run nothing)."""
    from fuzzlab.harness import auto_cli
    seen: list[list[str]] = []
    monkeypatch.setattr(auto_cli, "main", lambda argv: seen.append(list(argv)) or 0)
    return seen


def _exit_code(argv) -> int:
    with pytest.raises(SystemExit) as exc:
        train_cli.run_main(argv)
    return exc.value.code


# --- D-9: a training run carries a training or benchmark choice ------------------------

@pytest.mark.parametrize("extra", [
    [], ["--categories", "xss"], ["--bandit", "--anomaly"],
    ["--score", "--train-on", "saved"], ["--rank", "--train-on", "saved"],
    ["--mode", "automatic"], ["--points", "crawl"], ["--budget-method", "score",
                                                     "--confirm-budget", "3"],
    # choices the engine would ignore, or equal to the working default (review A1)
    ["--train-on", "run"], ["--train-on", "earlier"], ["--calibrate", "none"],
    ["--rank-objective", "pointwise"], ["--budget-seed", "3"],
    ["--budget-method", "random"],
])
def test_a_working_run_under_a_training_name_is_refused(extra, cwd, forwarded, capsys):
    assert _exit_code([URL, *extra, "--authorized"]) == 2
    assert "no training or benchmark choice" in capsys.readouterr().err
    assert forwarded == [] and list(cwd.iterdir()) == []


@pytest.mark.parametrize("extra", [
    ["--ground-truth", "gt"], ["--score"], ["--rank"], ["--holdout"],
    ["--calibrate", "platt"], ["--hybrid"], ["--rank-objective", "pairwise"],
    ["--score", "--train-on", "earlier"], ["--confirm-budget", "3", "--budget-seed", "0"],
    ["--confirm-budget", "3", "--budget-method", "random"],
    ["--mode", "manual"], ["--points", "ground-truth"],
])
def test_each_training_or_benchmark_choice_qualifies(extra, cwd, forwarded):
    assert train_cli.run_main([URL, *extra, "--authorized"]) == 0
    assert forwarded and forwarded[0][:2] == ["--base-url", URL]


def test_choices_are_detected_by_presence_not_by_value():
    p = train_cli.build_run_parser()
    ns = p.parse_args([URL, "--confirm-budget", "2", "--budget-seed", "0"])
    assert train_cli.training_choices(ns) == ["--budget-seed"]   # equals its default
    assert train_cli.training_choices(p.parse_args([URL, "--score"])) == ["--score"]
    assert train_cli.training_choices(p.parse_args([URL])) == []


@pytest.mark.parametrize("argv", [[URL], [URL, "--dry-run"], [URL, "--authorized"]])
def test_d9_runs_before_the_dry_run_and_before_the_gate(argv, cwd, forwarded, capsys):
    """Design §4.2 / N3 (review B4): a working run is refused whatever else is given."""
    assert _exit_code(argv) == 2
    assert "no training or benchmark choice" in capsys.readouterr().err
    assert forwarded == [] and list(cwd.iterdir()) == []


def test_an_explicit_empty_store_fails_first(cwd, capsys):
    assert _exit_code([URL, "--store", ""]) == 2         # no choice, no --authorized either
    assert "--store: empty path" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["", "--score"], ["--base-url", " ", "--score"]])
def test_an_empty_target_is_a_usage_error(argv, cwd, forwarded, capsys):
    assert _exit_code([*argv, "--authorized"]) == 2
    assert "empty target" in capsys.readouterr().err and forwarded == []


# --- the target: first argument, or the --base-url alias ------------------------------

def test_the_url_must_come_first(cwd, forwarded, capsys):
    assert _exit_code(["--score", URL, "--authorized"]) == 2
    assert "put the <url> first" in capsys.readouterr().err
    assert _exit_code(["--authorized", "--", URL, "--score"]) == 2
    assert _exit_code(["--auth", URL, "--score"]) == 2              # abbreviated flag first
    assert forwarded == []


def test_one_target_only_and_one_is_required(cwd, forwarded, capsys):
    assert _exit_code([URL, "--base-url", URL, "--score", "--authorized"]) == 2
    assert "not both" in capsys.readouterr().err
    assert _exit_code(["--score", "--authorized"]) == 2
    assert "a target <url> is required" in capsys.readouterr().err


def test_a_url_swallowed_by_an_optional_value_flag_is_explained(cwd, capsys):
    assert _exit_code(["--header-points", URL, "--score"]) == 2
    assert "--header-points took the URL" in capsys.readouterr().err


# --- forwarding: verbatim, with the resolved store ------------------------------------

def _engine_store(argv):
    from fuzzlab.harness.auto_cli import build_parser
    return build_parser().parse_args(argv).store


def test_the_users_argv_is_forwarded_verbatim_plus_the_resolved_store(cwd, forwarded):
    argv = [URL, "--identity=-bob", "--score", "--categories", "xss", "--authorized"]
    assert train_cli.run_main(argv) == 0
    assert forwarded == [["--base-url", URL, *argv[1:], "--store",
                          str(cwd / DEFAULT_STORE)]]


def test_the_alias_form_is_forwarded_unchanged(cwd, forwarded):
    argv = ["--base-url", URL, "--holdout", "--score", "--authorized"]
    assert train_cli.run_main(argv) == 0
    assert forwarded[0][:len(argv)] == argv


@pytest.mark.parametrize("store", ["mine.db", "~/x.db", "./a/../mine.db"])
@pytest.mark.parametrize("form", ["--store={}", "--sto {}", "--store {}"])
def test_the_engine_opens_exactly_the_store_resolved_and_printed(store, form, cwd,
                                                                  forwarded, capsys):
    """BUG-0401: the printed and checked store is the one the engine opens -- whatever
    spelling the user gave (``~``, ``..``, an abbreviation, ``=``)."""
    from fuzzlab.core.storepath import resolve
    (cwd / "a").mkdir()
    flag = form.format(store).split(" ")
    assert train_cli.run_main([URL, *flag, "--score", "--authorized"]) == 0
    expected = resolve(store, environ={}).path
    assert _engine_store(forwarded[0]) == str(expected)
    assert f"store: {expected} (--store)" in capsys.readouterr().out


def test_fuzzlab_store_is_honoured(cwd, forwarded, monkeypatch):
    monkeypatch.setenv("FUZZLAB_STORE", str(cwd / "env.db"))
    assert train_cli.run_main([URL, "--score", "--authorized"]) == 0
    assert forwarded[0][-2:] == ["--store", str(cwd / "env.db")]


# --- PA-0079: no store file, no run row behind a usage error --------------------------

@pytest.mark.parametrize("argv", [
    [URL, "--score"],                                         # no --authorized
    [URL, "--authorized"],                                    # D-9
    [URL, "--score", "--store", "", "--authorized"],          # explicit empty store
    [URL, "--score", "--store", "no/such/dir/x.db", "--authorized"],
    [URL, "--hybrid", "--authorized"],                        # engine: --hybrid needs --score
    [URL, "--score", "--calibrate", "platt", "--train-on", "saved", "--authorized"],
    [URL, "--holdout", "--authorized"],                       # engine: --holdout needs …
    [URL, "--score", "--anomaly-contamination", "0.9", "--authorized"],
])
def test_no_usage_error_leaves_a_store_or_a_run_row(argv, cwd):
    assert _exit_code(argv) == 2
    assert list(cwd.iterdir()) == []


def test_a_dry_run_creates_nothing_and_names_the_store(cwd, capsys):
    assert train_cli.run_main([URL, "--ground-truth", "/no/such/gt", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out and f"store: {cwd / DEFAULT_STORE} (default)" in out
    assert list(cwd.iterdir()) == []


# --- end to end (the real engine, offline: no crawl DB, so no point and no request) ---

def test_the_default_store_is_created_then_reused_and_the_store_wins(cwd, capsys):
    argv = [URL, "--score", "--categories", "sql-injection", "--authorized"]
    assert fuzzlab_main(["train", "run", *argv]) == 0
    assert (cwd / DEFAULT_STORE).exists()
    out = capsys.readouterr().out
    assert "requests: 0" in out and f"store: {cwd / DEFAULT_STORE} (default)" in out
    assert fuzzlab_main(["train", "run", *argv]) == 0
    with Store(cwd / DEFAULT_STORE) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 2
    assert fuzzlab_main(["train", "run", *argv, "--store", str(cwd / "x.db")]) == 0
    with Store(cwd / "x.db") as store:
        assert store.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1


def test_a_holdout_run_prints_a_store_qualified_reveal_hint(cwd, capsys):
    import shlex
    spaced = cwd / "my dir"
    spaced.mkdir()
    store = spaced / "s.db"
    assert train_cli.run_main([URL, "--score", "--holdout", "--categories", "xss",
                               "--store", str(store), "--authorized"]) == 0
    out = capsys.readouterr().out
    assert f"fuzzlab train reveal-holdout --store {shlex.quote(str(store))}" in out


def test_no_reveal_hint_when_the_run_failed(cwd, monkeypatch, capsys):
    from fuzzlab.harness import auto_cli
    monkeypatch.setattr(auto_cli, "main", lambda argv: 1)
    assert train_cli.run_main([URL, "--score", "--holdout", "--authorized"]) == 1
    assert "reveal the sealed holdout" not in capsys.readouterr().out


# --- the group --------------------------------------------------------------------------

def test_the_group_without_a_subcommand_exits_2_and_help_exits_0(capsys):
    assert fuzzlab_main(["train"]) == 2
    assert "usage: fuzzlab train" in capsys.readouterr().err
    assert fuzzlab_main(["train", "nope"]) == 2
    assert fuzzlab_main(["train", "--help"]) == 0
    assert "Training and benchmark" in capsys.readouterr().out


def test_train_run_help_shows_the_url_first_and_hides_the_alias(capsys):
    with pytest.raises(SystemExit) as exc:
        train_cli.run_main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("usage: fuzzlab train run <url> [options]")
    assert "--base-url" not in out and "--ground-truth" in out and "--calibrate" in out
    assert "own --store" in " ".join(out.split()) and "FUZZLAB_STORE" in out


# --- PA-0400(1): forwarding round-trips over every action of the engine's parser ------

def test_forwarding_round_trips_every_action_of_the_engine(tmp_path, monkeypatch):
    """The namespace `auto` parses from the forwarded argv equals the one `train run`
    validated -- for every action, discovered from the engine's parser (not a list)."""
    from fuzzlab.core.storepath import resolve
    from fuzzlab.harness.auto_cli import build_parser
    from tests.test_cli_taxonomy import action_variants
    monkeypatch.chdir(tmp_path)
    engine = build_parser()
    copy = train_cli.build_run_parser()
    checked = 0
    for action, extra in action_variants(engine, skip={"base_url", "store"}):
        argv = [URL, *extra]
        ns = copy.parse_args(argv)
        fwd = train_cli.forward(argv, ns, URL, resolve(ns.store, environ={}))
        got = vars(engine.parse_args(fwd))
        # the values `train run` validated (its presence-suppressed dests at the engine's
        # default) -- never the forwarded argv parsed again (review B round 2)
        want = {d: getattr(ns, d, engine.get_default(d)) for d in got
                if d not in ("base_url", "store")}
        assert {d: got[d] for d in want} == want, (action.dest, extra)
        assert got["base_url"] == URL
        assert got["store"] == str(tmp_path / DEFAULT_STORE)
        checked += 1
    assert checked > 30


@pytest.mark.parametrize("sub, old, prog", [
    ("reveal-holdout", "reveal-holdout", "fuzzlab train reveal-holdout"),
    ("flow-anomaly", "flow-anomaly", "fuzzlab train flow-anomaly"),
    ("mutate", "mutate-run", "fuzzlab train mutate"),
])
def test_old_names_still_work_with_a_stderr_note_and_the_new_names_use_their_prog(
        sub, old, prog, cwd, capsys):
    with pytest.raises(SystemExit):
        fuzzlab_main(["train", sub, "--bogus"])
    assert f"{prog}: error" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        fuzzlab_main([old, "--bogus"])
    err = capsys.readouterr().err
    assert f"'{old}' is now 'fuzzlab train {sub}'" in err


# --- train models: label-free, allowlisted --------------------------------------------

def _trained_store(path):
    from fuzzlab.ml.train import train_and_score
    from tests.test_ml_holdout_calibration import _seed
    with Store(path) as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        # distinctive values in every label-derived place a listing must never read
        row = store.conn.execute("SELECT id, calibration FROM model ORDER BY id ASC"
                                 ).fetchall()[-1]
        cal = json.loads(row["calibration"])
        assert "holdout" in cal                       # the producer wrote one
        cal["holdout"]["rows"] = 424242
        cal["oof_pr_auc_raw"] = 0.987654321
        cal["brier_raw"] = 0.123456789
        store.conn.execute("UPDATE model SET calibration=? WHERE id=?",
                           (json.dumps(cal), row["id"]))
        store.conn.execute("UPDATE holdout_metric SET value=13579.2468")
        store.conn.commit()
        return r


def test_models_lists_only_label_free_facts(cwd, capsys):
    from fuzzlab.ml.model_registry import list_models
    _trained_store(cwd / DEFAULT_STORE)
    with Store(cwd / DEFAULT_STORE) as store:
        rows = list_models(store)
        hm = store.conn.execute("SELECT COUNT(*) FROM holdout_metric").fetchone()[0]
    assert hm > 0
    assert rows and [r["id"] for r in rows] == sorted(r["id"] for r in rows)
    assert set(rows[0]) == {"id", "name", "version", "feature_version", "created_at",
                            "has_params", "unreadable", "trained_on", "scope",
                            "source_model_id", "scored_runs"}
    assert fuzzlab_main(["train", "models"]) == 0
    out = capsys.readouterr().out
    for secret in ("424242", "0.987654321", "0.98765", "0.123456789", "13579"):
        assert secret not in out and secret not in json.dumps(rows)
    assert "logistic" in out and "run " in out


def test_models_never_names_a_sealed_table_or_a_metric_key():
    from fuzzlab.core.sealed import SEALED_TABLES
    from fuzzlab.ml import model_registry
    src = inspect.getsource(model_registry.list_models)
    strings = [n.value for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for table in SEALED_TABLES:
        assert not any(table in s for s in strings)
    assert set(model_registry.LISTING_KEYS) == {"trained_on", "run_id", "source_model_id",
                                                 "scored_run_ids"}
    # the check is live (PA-0034(2)): a string naming a sealed table is found
    bad = "def f(s): return s.execute('SELECT * FROM holdout_metric')"
    assert any("holdout_metric" in n.value for n in ast.walk(ast.parse(bad))
               if isinstance(n, ast.Constant) and isinstance(n.value, str))


def test_models_reports_an_unreadable_calibration_as_unreadable(cwd, capsys):
    with Store(cwd / DEFAULT_STORE) as store:
        store.conn.execute("INSERT INTO model (name, version, calibration) "
                           "VALUES ('logistic', 1, '{not json')")
        store.conn.commit()
    assert fuzzlab_main(["train", "models"]) == 0
    assert "unreadable calibration" in capsys.readouterr().out


def test_models_refuses_a_missing_store_and_creates_none(cwd, capsys):
    with pytest.raises(SystemExit) as exc:
        fuzzlab_main(["train", "models"])
    assert exc.value.code == 2 and "no such store" in capsys.readouterr().err
    assert list(cwd.iterdir()) == []


# --- safety NFR traces through the new entry points (PA-0112, PA-0123(4)) -------------

def _explode(*a, **k):
    raise AssertionError("must not be reached")


def test_train_run_dry_run_sends_nothing(cwd, monkeypatch, capsys):
    """NFR-FUZZ-dry-run through `fuzzlab train run`: no store, no sender, no pipeline."""
    from fuzzlab.harness import auto_cli
    monkeypatch.setattr(auto_cli, "make_probe_sender", _explode)
    monkeypatch.setattr(auto_cli, "run_auto", _explode)
    monkeypatch.setattr(auto_cli.Store, "__init__", _explode)
    assert fuzzlab_main(["train", "run", URL, "--ground-truth", "gt", "--score",
                         "--dry-run"]) == 0
    assert "DRY RUN" in capsys.readouterr().out and list(cwd.iterdir()) == []


def test_train_run_without_authorized_sends_nothing(cwd, monkeypatch):
    """NFR-FUZZ-safe (lab-only gate) through `fuzzlab train run`."""
    from fuzzlab.harness import auto_cli
    monkeypatch.setattr(auto_cli, "make_probe_sender", _explode)
    monkeypatch.setattr(auto_cli, "main", _explode)
    with pytest.raises(SystemExit) as exc:
        fuzzlab_main(["train", "run", URL, "--ground-truth", "gt"])
    assert exc.value.code == 2 and list(cwd.iterdir()) == []


def test_train_mutate_dry_run_sends_nothing(cwd, monkeypatch, capsys):
    """NFR-MUT-dry-run through `fuzzlab train mutate`."""
    from fuzzlab.mutation import cli as mcli
    monkeypatch.setattr(mcli.mrun, "run_mutation", _explode)
    monkeypatch.setattr(mcli.Store, "__init__", _explode)
    monkeypatch.setattr(mcli, "make_probe_sender", _explode)
    assert fuzzlab_main(["train", "mutate", "--url", URL + "/x", "--param", "id",
                         "--dry-run"]) == 0
    assert "DRY RUN" in capsys.readouterr().out and list(cwd.iterdir()) == []


def test_train_mutate_keeps_the_destructive_gate_off_by_default(cwd, monkeypatch):
    """NFR-MUT-safe through `fuzzlab train mutate`: the same entry point, gate default
    off, and no send without --authorized."""
    from fuzzlab.mutation import cli as mcli
    seen = {}
    monkeypatch.setattr(mcli, "make_probe_sender", lambda *a, **k: object())
    monkeypatch.setattr(mcli.mrun, "run_mutation", lambda **kw: seen.update(kw) or {
        "bases": 0, "blocked": 0, "bypasses": 0, "recorded": 0, "results": []})
    assert fuzzlab_main(["train", "mutate", "--url", URL + "/x", "--param", "id",
                         "--authorized"]) == 0
    assert seen["allow_destructive"] is False
    seen.clear()
    monkeypatch.setattr(mcli, "make_probe_sender", _explode)
    with pytest.raises(SystemExit):
        fuzzlab_main(["train", "mutate", "--url", URL + "/x", "--param", "id"])
    assert seen == {}


def test_models_shows_run_earlier_and_saved_provenance_from_real_producers(cwd):
    """Review B10: rows written by the real trainers -- own run, earlier runs, a saved
    model applied -- are listed with the provenance `report` reads (one function)."""
    from fuzzlab.core.modelinfo import trained_on
    from fuzzlab.ml.model_registry import list_models
    from fuzzlab.ml.train import train_and_score
    from tests.test_ml_holdout_calibration import _seed
    with Store(cwd / DEFAULT_STORE) as store:
        r1 = _seed(store, seed=1)
        train_and_score(store, r1, model_kind="logistic")
        r2 = _seed(store, seed=2)
        train_and_score(store, r2, model_kind="logistic", train_on="earlier")
        r3 = _seed(store, seed=3)
        train_and_score(store, r3, train_on="saved")
        rows = list_models(store)
        cals = [json.loads(r["calibration"] or "{}") for r in store.conn.execute(
            "SELECT calibration FROM model ORDER BY id ASC")]
    assert [r["trained_on"] for r in rows] == [trained_on(c) for c in cals]
    kinds = [r["trained_on"] for r in rows]
    assert {"run", "earlier", "saved"} <= set(kinds)
    saved = next(r for r in rows if r["trained_on"] == "saved")
    assert saved["source_model_id"] in [r["id"] for r in rows]
    assert all(r["scope"].startswith("run ") for r in rows)


def test_list_models_reads_no_metric_key():
    """The listing's source names only allowlisted calibration keys (PA-0092)."""
    from fuzzlab.ml import model_registry
    import re
    src = inspect.getsource(model_registry.list_models)
    tree = ast.parse(src)
    fn = tree.body[0]
    body = fn.body[1:] if ast.get_docstring(fn) else fn.body      # code, not the docstring
    consts = [n.value for stmt in body for n in ast.walk(stmt)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for c in consts:
        for forbidden in ("oof", "brier", "ece_", "pr_auc", "holdout", "t_lo", "t_hi",
                          "metric"):
            assert forbidden not in c, (forbidden, c)
    assert set(model_registry.LISTING_KEYS) >= {"trained_on"}
    sql = " ".join(c for c in consts if "SELECT" in c or "FROM" in c)
    assert re.findall(r"\bparams\b(?! IS NOT NULL)", sql) == []   # never the params blob


def test_models_without_the_ml_package_exits_2_with_the_standard_message(cwd, monkeypatch,
                                                                         capsys):
    """BUG-0403: `train models` reaches `fuzzlab.ml` only through `import_ml` (FR-ML-6)."""
    from fuzzlab.plugins import optional
    with Store(cwd / DEFAULT_STORE):
        pass
    monkeypatch.setattr(optional, "import_ml", lambda module: None)
    assert fuzzlab_main(["train", "models"]) == 2
    assert optional.ML_UNAVAILABLE in capsys.readouterr().err
