"""`fuzzlab auto --train-on {run,earlier}` (CC-FUZZ-0049, FR-FUZZ-33): --score/--rank
trained on earlier runs against the same target, never this run's labels."""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.ml.rank_train import latest_ranker
from fuzzlab.ml.train import latest_classifier
from tests.test_auto_budget import _earlier_runs, _last_run, _main


def _metrics(store, run_id) -> set[str]:
    return {r["key"] for r in store.conn.execute(
        "SELECT key FROM run_metrics WHERE run_id=?", (run_id,))}


def test_cli_scores_and_ranks_from_earlier_runs(tmp_path, monkeypatch, capsys):
    with Store(tmp_path / "s.db") as store:
        _earlier_runs(store)
    assert _main(tmp_path, monkeypatch, "--score", "--rank", "--train-on", "earlier") == 0
    out = capsys.readouterr().out
    store, run_id = _last_run(tmp_path)
    with store:
        clf, (_, rank_calib) = latest_classifier(store, run_id), latest_ranker(store, run_id)
        for calib in (clf.calibration, rank_calib):
            assert calib["run_id"] == run_id and calib["trained_on"] == "earlier"
            assert calib["train_run_ids"] == [1, 2]
        keys = _metrics(store, run_id)
        assert {"ml_pr_auc_forward", "rank_ndcg_forward",
                "ml_seen_fraction", "rank_seen_fraction"} <= keys
        assert not {"ml_pr_auc", "rank_ndcg"} & keys            # no run-mode keys
        seen = round(100 * clf.calibration["seen_fraction"])
        scored = store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND score IS NOT NULL "
            "AND rank_score IS NOT NULL", (run_id,)).fetchone()["c"]
        total = store.conn.execute("SELECT COUNT(*) c FROM candidate WHERE run_id=?",
                                   (run_id,)).fetchone()["c"]
        assert scored == total > 0
    for label in ("ml", "ranker"):
        line = next(ln for ln in out.splitlines() if ln.startswith(f"  {label} ("))
        assert ("trained on 40 earlier labelled candidate(s) from this target (runs 1, 2), "
                "not on this run's labels;") in line
        assert f"{seen}% of this run's candidates were seen in training" in line
        assert "no forward" not in line
    assert "forward PR-AUC=" in out and "(prevalence " in out
    assert "forward NDCG@10=" in out and "(random " in out


@pytest.mark.parametrize("setup", ["no-earlier-runs", "other-target-only"])
def test_cli_refuses_without_usable_earlier_labels(tmp_path, monkeypatch, capsys, setup):
    if setup == "other-target-only":
        with Store(tmp_path / "s.db") as store:
            _earlier_runs(store, base_url="http://elsewhere:9000")
    assert _main(tmp_path, monkeypatch, "--score", "--rank", "--train-on", "earlier") == 0
    out = capsys.readouterr().out
    store, run_id = _last_run(tmp_path)
    with store:
        assert store.conn.execute("SELECT COUNT(*) c FROM model").fetchone()["c"] == 0
        assert not {k for k in _metrics(store, run_id) if k.startswith(("ml_", "rank_"))}
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND (score IS NOT NULL OR "
            "rank_score IS NOT NULL)", (run_id,)).fetchone()["c"] == 0
    assert ("  ml: NOT scored — no usable earlier labels for this target (use --train-on "
            "run to train on this run's labels)") in out
    assert "  ranker: NOT ranked — no usable earlier labels for this target" in out


def test_cli_train_on_needs_score_or_rank(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit):
        _main(tmp_path, monkeypatch, "--train-on", "earlier")
    assert "--train-on needs --score and/or --rank" in capsys.readouterr().err


def test_launcher_renders_train_on_as_a_choice():
    from fuzzlab.web.commandspec import spec
    field = {o.dest: o for o in spec("auto").options}["train_on"]
    assert field.type == "choice" and set(field.choices) == {"run", "earlier"}
    assert field.default == "run"
