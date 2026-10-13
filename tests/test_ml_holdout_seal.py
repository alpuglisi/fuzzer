"""The blind holdout is sealed per target, at every producer (BUG-0091, FR-ML-19,
PA-0092).

The finding: trained with ``train_on="earlier", holdout=True``, flipping only 9
held-out labels moved the public forward PR-AUC from 0.668 to 0.761, with no reveal
recorded — the forward evaluation (and the ML tab's panels in earlier/saved mode) read
every labelled row. The fix seals a target once any of its models recorded a holdout:
every trainer applies an implied holdout, every forward evaluation and panel reads the
public rows only. The central test flips every sealed label and asserts that every
public ML number, and every trained model, is bit-for-bit unchanged.
"""

from __future__ import annotations

import ast
import json
import shutil
from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from fuzzlab.ml import holdout as ho
from fuzzlab.ml.active import prioritize, propose_queries
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.rank_train import train_and_rank
from fuzzlab.ml.train import (_forward_evaluation, latest_classifier, metric_input,
                              train_and_score)
from fuzzlab.web import mlview
from tests import test_auto_budget as _budget
from tests.test_ml_holdout_calibration import TARGET, _flip_labels, _held_ids, _seed

confirm_calls = _budget.confirm_calls                      # the shared pytest fixture

REPO = Path(__file__).resolve().parent.parent


def _runs(store):
    return [r["id"] for r in store.conn.execute("SELECT id FROM run ORDER BY id")]


def _base(tmp_path) -> Path:
    """Three runs of one target; the first trained with --holdout (the target sealed)."""
    path = tmp_path / "base.db"
    with Store(path) as store:
        a = _seed(store, seed=3)
        _seed(store, seed=4)
        _seed(store, seed=5)
        train_and_score(store, a, model_kind="logistic", holdout=True)
        train_and_rank(store, a, holdout=True)          # a saved-mode source ranker
    return path


def _copy(src: Path, name: str) -> Path:
    dst = src.with_name(name)
    shutil.copy(src, dst)
    return dst


def _panel(p, *keys):
    return tuple(json.dumps(p.get(k), sort_keys=True) for k in keys)


def _run_metrics(store, run_id):
    return sorted((r["key"], r["value"]) for r in store.conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,)))


def _numbers(path: Path) -> dict:
    """Every public ML number and model identity a later run of the sealed target can
    produce — none of them trained with --holdout."""
    out = {}
    with Store(path) as store:
        a, _b, now = _runs(store)
        ids = build_dataset(store, now, include_unlabelled=True).ids
        # the prioritizer (score + committee) on earlier runs
        out["prio"] = (prioritize(store, now, ids).model_sha256,
                       prioritize(store, now, ids, method="committee").model_sha256)
        out["queries"] = propose_queries(store, now, 5, method="committee")
        # run mode, calibrated: training-time numbers, gate, params
        r = train_and_score(store, now, model_kind="auto", calibrate="platt")
        c = latest_classifier(store, now).calibration
        out["run"] = (r["model"], r["pr_auc"], r["baseline_prevalence"], r["baseline_sigma"],
                      r["params_sha256"], json.dumps(r.get("model_selection")),
                      *(c.get(k) for k in ("oof_pr_auc", "brier_oof_raw",
                                           "brier_oof_calibrated", "ece_oof_raw",
                                           "ece_oof_calibrated", "t_lo", "t_hi")))
        out["clf_panel"] = _panel(mlview.classifier_panel(store, now), "n", "pr_auc",
                                  "pr_curve", "reliability", "calibration")
        # the ranker, auto objective (the selection itself must not move)
        rr = train_and_rank(store, now, objective="auto", k=3)
        out["rank"] = (rr["ndcg"], rr["precision"], rr.get("objective_used"),
                       rr["params_sha256"], rr.get("ndcg_global"))
        out["rank_panel"] = _panel(mlview.ranker_panel(store, now), "n", "ndcg_at_k",
                                   "precision_at_k", "global")
        out["disagreement"] = _panel(mlview.disagreement_panel(store, now), "queue")
        # earlier mode (forward evaluation included)
        e = train_and_score(store, now, train_on="earlier", model_kind="logistic")
        out["earlier"] = (e["pr_auc_earlier"], e.get("pr_auc_forward"),
                          e.get("forward_skipped_reason"), e["params_sha256"])
        out["earlier_panel"] = _panel(mlview.classifier_panel(store, now), "n", "pr_auc",
                                      "reliability")
        er = train_and_rank(store, now, train_on="earlier")
        out["rank_earlier"] = (er["ndcg_earlier"], er.get("ndcg_forward"),
                               er.get("objective_used"), er["params_sha256"])
        # saved mode: the forward evaluation of an applied model
        s = train_and_score(store, now, train_on="saved")
        sr = train_and_rank(store, now, train_on="saved")
        assert not s["refused"] and not sr["refused"]
        out["saved"] = (s.get("pr_auc_forward"), s.get("forward_skipped_reason"),
                        sr.get("ndcg_forward"), sr.get("forward_skipped_reason"))
        out["saved_panel"] = _panel(mlview.classifier_panel(store, now), "n", "pr_auc")
        # a store-wide train (every run, every target)
        w = train_and_score(store, None, model_kind="logistic")
        out["store_wide"] = (w.get("pr_auc"), w["params_sha256"])
        # the report's ML metrics: what every run_metrics row of the later run says
        out["run_metrics"] = _run_metrics(store, now)
    return out


def test_flipping_every_sealed_label_moves_no_public_number(tmp_path):
    base = _base(tmp_path)
    flipped, control = _copy(base, "flipped.db"), _copy(base, "control.db")
    with Store(flipped) as store:
        for run in _runs(store):
            assert _flip_labels(store, run, _held_ids(store, run)) > 0
    with Store(control) as store:                  # non-vacuity: public labels DO move it
        for run in _runs(store):
            ds = build_dataset(store, run)
            held = set(_held_ids(store, run))
            assert _flip_labels(store, run, [c for c in ds.ids if c not in held][:8]) > 0
    want, got, moved = _numbers(base), _numbers(flipped), _numbers(control)
    for key in want:
        assert got[key] == want[key], key
    for key in ("prio", "run", "clf_panel", "rank", "earlier", "rank_earlier", "saved",
                "store_wide", "run_metrics"):
        assert moved[key] != want[key], key


def test_the_findings_repro_forward_metric_is_unmoved(tmp_path):
    """f2: train earlier-mode with --holdout; flip only held-out labels."""
    with Store(tmp_path / "f.db") as store:
        _seed(store, seed=3)
        _seed(store, seed=4)
        now = _seed(store, seed=5)
        res = train_and_score(store, now, train_on="earlier", model_kind="logistic",
                              holdout=True)
        rows = store.conn.execute("SELECT id, score FROM candidate WHERE run_id=?",
                                  (now,)).fetchall()
        ids, scores = [r["id"] for r in rows], [r["score"] for r in rows]
        assert _flip_labels(store, now, _held_ids(store, now)) > 0
        again, _ = _forward_evaluation(store, now, ids, scores)
        assert again["pr_auc_forward"] == res["pr_auc_forward"]
        assert store.conn.execute("SELECT COUNT(*) FROM holdout_reveal").fetchone()[0] == 0


def test_a_sealed_target_implies_the_holdout_for_every_trainer(tmp_path):
    base = _base(tmp_path)
    with Store(base) as store:
        a, _b, now = _runs(store)
        held = len(_held_ids(store, now))
        r = train_and_score(store, now, model_kind="logistic")
        assert r["holdout"] == {"rows": held, "sealed": True, "implied": True}
        assert latest_classifier(store, now).calibration["holdout"] == {
            "version": 1, "fraction": 0.2, "rows": held, "implied": True}
        assert r["rows"] == len(build_dataset(store, now)) - held
        rr = train_and_rank(store, now)
        assert rr["holdout"]["implied"] is True and rr["rows"] == r["rows"]
        # store-wide: every sealed row of the target left out, recorded, never sealed
        w = train_and_score(store, None, model_kind="logistic")
        every = sum(len(_held_ids(store, x)) for x in _runs(store))
        assert w["holdout"]["rows"] == every and w["holdout"]["sealed"] is False
        assert latest_classifier(store, None).calibration["holdout"]["scope"] == "store"


def test_an_unsealed_target_still_trains_on_every_row(tmp_path):
    with Store(tmp_path / "u.db") as store:
        r = _seed(store)
        other = _seed(store, target="http://127.0.0.1:9090")
        train_and_score(store, other, model_kind="logistic", holdout=True)  # another target
        res = train_and_score(store, r, model_kind="logistic")
        assert "holdout" not in res and res["rows"] == len(build_dataset(store, r))
        assert ho.sealing_for_run(store, r) is None
        assert ho.sealing_for_run(store, other) == (ho.SEALED, frozenset({1}))


def test_the_cli_prints_an_implied_holdout(capsys):
    from fuzzlab.harness.auto_cli import _print_ml_extras
    _print_ml_extras({"holdout": {"rows": 3, "sealed": True, "implied": True,
                                  "endpoints": 4}}, 7)
    assert "4 endpoint(s) of this run held out (implied: target sealed)" in \
        capsys.readouterr().out


# --- the membership registry and the fail-closed "unknown" ---------------------------

def test_the_registry_reproduces_the_original_membership():
    import hashlib
    for i in range(500):
        p = f"/p{i}.php"
        d = hashlib.sha256(f"fuzzlab-holdout-v1|{TARGET}|{p}".encode()).hexdigest()
        assert ho.in_holdout(TARGET, p, 1) == (int(d, 16) / 2 ** 256 < 0.2)
        assert ho.in_holdout(TARGET, p) == ho.in_holdout(TARGET, p, 1)


def _poison(store, run_id, record):
    store.conn.execute("INSERT INTO model (name, version, feature_version, calibration) "
                       "VALUES ('logistic', 99, 1, ?)",
                       (json.dumps({"run_id": run_id, "holdout": record}),))
    store.conn.commit()


@pytest.mark.parametrize("record", [{"version": 99, "fraction": 0.2},
                                    {"version": 1, "fraction": 0.3},
                                    {"version": True, "fraction": 0.2}, "yes"])
def test_an_unknown_membership_fails_closed_everywhere(tmp_path, record):
    from fuzzlab.ml.holdout import SealingUnknown
    with Store(tmp_path / "x.db") as store:
        a = _seed(store, seed=3)
        _seed(store, seed=4)
        now = _seed(store, seed=5)
        train_and_score(store, now, model_kind="logistic")           # scores to read
        _poison(store, a, record)
        assert ho.sealing_for_run(store, now) == ho.UNKNOWN
        with pytest.raises(SealingUnknown):
            train_and_score(store, now, model_kind="logistic")
        with pytest.raises(SealingUnknown):
            train_and_rank(store, now)
        for fn in (train_and_score, train_and_rank):
            for mode in ("earlier", "saved"):
                res = fn(store, now, train_on=mode)
                assert res["refused"] is True and "unknown" in res["reason"], (fn, mode)
        ids = build_dataset(store, now, include_unlabelled=True).ids
        with pytest.raises(SealingUnknown):                         # never None
            prioritize(store, now, ids)
        # readers: every row of the target is sealed — nothing shown, nothing raised
        assert mlview.classifier_panel(store, now)["available"] is False
        assert mlview.disagreement_panel(store, now)["available"] is False
        # a store-wide train leaves that target out and says so
        other = _seed(store, seed=6, target="http://127.0.0.1:9090")
        w = train_and_score(store, None, model_kind="logistic")
        assert w["rows"] == len(build_dataset(store, other))
        assert latest_classifier(store, None).calibration["holdout"][
            "excluded_unknown_targets"] == [ho.run_origin(store, now)]


def test_an_unregistered_version_bump_refuses_to_train(tmp_path, monkeypatch):
    """A bump must register its membership; until then nothing trains on the target."""
    from fuzzlab.ml.holdout import SealingUnknown
    with Store(tmp_path / "b.db") as store:
        r = _seed(store)
        monkeypatch.setattr(ho, "HOLDOUT_VERSION", 2)
        with pytest.raises(SealingUnknown):
            train_and_score(store, r, holdout=True)


def test_an_unknown_target_keeps_the_budget_cap_and_exits_1(tmp_path, monkeypatch,
                                                            capsys, confirm_calls):
    """B's must-raise: under the plugin contract None means "confirm everything"."""
    from tests.test_auto_budget import BASE, _earlier_runs, _last_run, _main, _metric
    with Store(tmp_path / "s.db") as store:
        _earlier_runs(store)
        first = store.conn.execute("SELECT MIN(run_id) r FROM target").fetchone()["r"]
        _poison(store, first, {"version": 99, "fraction": 0.2})
    rc = _main(tmp_path, monkeypatch, "--confirm-budget", "2")
    out = capsys.readouterr().out
    assert rc == 1 and "ml-budget FAILED — SealingUnknown" in out
    assert len(set(confirm_calls)) == 2                           # the cap held
    store, run_id = _last_run(tmp_path)
    with store:
        assert _metric(store, run_id, "pipeline_confirm_budget_error") == 1
    assert BASE


# --- one mechanism, one required argument ----------------------------------------------

def metric_input_calls_without_held(source: str) -> list[int]:
    """Lines calling `metric_input` without an explicit ``held=`` keyword."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name == "metric_input" and not any(k.arg == "held" for k in node.keywords):
                out.append(node.lineno)
    return out


def test_every_metric_input_call_says_whether_the_row_is_sealed():
    offenders = {str(p.relative_to(REPO)): lines
                 for p in sorted((REPO / "fuzzlab").rglob("*.py"))
                 if (lines := metric_input_calls_without_held(p.read_text()))}
    assert offenders == {}


def test_the_guard_catches_an_offender():
    assert metric_input_calls_without_held("x = train.metric_input(c, s, 1, None)") == [1]
    assert metric_input_calls_without_held("metric_input(c, s, 1, None, held=h)") == []
    with pytest.raises(TypeError):
        metric_input({}, "confirmed", 0.5, None)                   # required, no default


def test_no_trainer_or_reader_uses_the_today_only_split():
    """`holdout.split` / `mask` evaluate today's membership only; producers must use
    `sealed_split` / `held_ids` (every recorded version, per target)."""
    hits = []
    for p in sorted((REPO / "fuzzlab").rglob("*.py")):
        if p.name == "holdout.py":
            continue
        for node in ast.walk(ast.parse(p.read_text())):
            if isinstance(node, ast.Attribute) and node.attr in ("split", "mask") and \
                    isinstance(node.value, ast.Name) and node.value.id == "ho":
                hits.append(f"{p.name}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and node.module == "fuzzlab.ml.holdout" \
                    and any(a.name in ("split", "mask") for a in node.names):
                hits.append(f"{p.name}:{node.lineno}")
    assert hits == []
