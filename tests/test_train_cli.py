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
])
def test_a_working_run_under_a_training_name_is_refused(extra, cwd, forwarded, capsys):
    assert _exit_code([URL, *extra, "--authorized"]) == 2
    assert "no training or benchmark choice" in capsys.readouterr().err
    assert forwarded == [] and list(cwd.iterdir()) == []


@pytest.mark.parametrize("extra", [
    ["--ground-truth", "gt"], ["--score"], ["--rank"], ["--holdout"],
    ["--calibrate", "platt"], ["--hybrid"], ["--rank-objective", "pairwise"],
    ["--train-on", "earlier"], ["--budget-seed", "0"], ["--budget-method", "random"],
    ["--mode", "manual"], ["--points", "ground-truth"],
])
def test_each_training_or_benchmark_choice_qualifies(extra, cwd, forwarded):
    assert train_cli.run_main([URL, *extra, "--authorized"]) == 0
    assert forwarded and forwarded[0][:2] == ["--base-url", URL]


def test_choices_are_detected_by_presence_not_by_value():
    p = train_cli.build_run_parser()
    ns = p.parse_args([URL, "--budget-seed", "0", "--train-on", "run"])
    assert "--budget-seed" in train_cli.training_choices(ns)      # equals its default
    assert "--train-on run" in train_cli.training_choices(ns)
    assert train_cli.training_choices(p.parse_args([URL])) == []


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

def test_the_users_argv_is_forwarded_verbatim_plus_the_resolved_store(cwd, forwarded):
    argv = [URL, "--identity=-bob", "--score", "--categories", "xss", "--authorized"]
    assert train_cli.run_main(argv) == 0
    assert forwarded == [["--base-url", URL, *argv[1:], "--store",
                          str(cwd / DEFAULT_STORE)]]


def test_the_alias_form_is_forwarded_unchanged(cwd, forwarded):
    argv = ["--base-url", URL, "--holdout", "--score", "--authorized"]
    assert train_cli.run_main(argv) == 0
    assert forwarded[0][:len(argv)] == argv


def test_an_explicit_store_is_not_added_twice_even_abbreviated(cwd, forwarded):
    assert train_cli.run_main([URL, "--sto", "mine.db", "--score", "--authorized"]) == 0
    assert forwarded[0].count("--store") == 0 and "--sto" in forwarded[0]


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
    assert train_cli.run_main([URL, "--score", "--holdout", "--categories", "xss",
                               "--authorized"]) == 0
    assert (f"fuzzlab train reveal-holdout --store {cwd / DEFAULT_STORE}"
            in capsys.readouterr().out)


# --- the group --------------------------------------------------------------------------

def test_the_group_without_a_subcommand_exits_2_and_help_exits_0(capsys):
    assert fuzzlab_main(["train"]) == 2
    assert "usage: fuzzlab train" in capsys.readouterr().err
    assert fuzzlab_main(["train", "nope"]) == 2
    assert fuzzlab_main(["train", "--help"]) == 0
    assert "Training and benchmark" in capsys.readouterr().out


def test_train_run_help_shows_the_url_and_hides_the_alias(capsys):
    with pytest.raises(SystemExit) as exc:
        train_cli.run_main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "fuzzlab train run" in out and "url" in out and "--base-url" not in out
    assert "--ground-truth" in out and "--calibrate" in out


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
