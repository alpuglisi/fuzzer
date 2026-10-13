"""Blind holdout (FR-ML-19) and Platt calibration (FR-ML-20) — CC-ML-0020, CC-CORE-0030,
CC-FUZZ-0053, CC-UI-0045, CC-PLUG-0007."""

from __future__ import annotations

import json
import math
import random

import pytest

from fuzzlab.core.oracle_status import SKIPPED_BUDGET
from fuzzlab.core.sealed import SEALED_TABLES, reveal
from fuzzlab.core.store import Store
from fuzzlab.ml import holdout as ho
from fuzzlab.ml import train as train_mod
from fuzzlab.ml.active import prioritize
from fuzzlab.ml.calibration import PlattScaler, cross_fit, fit_platt
from fuzzlab.ml.conformal import ConformalGate
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.metrics import brier, ece, mcc, pr_auc, precision_at_recall, reliability
from fuzzlab.ml.persist import ModelParamsError, dumps_model, loads_model
from fuzzlab.ml.rank_train import latest_ranker, train_and_rank
from fuzzlab.ml.train import (gate_input, latest_classifier, load_classifier, metric_input,
                              train_and_score)
from fuzzlab.web import mlview
from tests.test_ml_budget_and_scope import _target
from tests.test_ml_train import _cand, _finding

TARGET = "http://127.0.0.1:8080"


def _seed(store, n=40, seed=1, target=TARGET):
    """``n`` endpoints, two candidates each; a sink makes sqli likely confirmed."""
    rng = random.Random(seed)
    r = store.start_run("auto", "127.0.0.1:8080")
    for i in range(n):
        sink = rng.random() < 0.5
        _cand(store, r, f"/e{i}.php", "id", "sql-injection", sink="html" if sink else None)
        _cand(store, r, f"/e{i}.php", "q", "xss")
        if (sink and rng.random() < 0.8) or rng.random() < 0.1:
            _finding(store, r, f"/e{i}.php", "id", "sqli")
    store.conn.commit()
    if target:
        _target(store, r, target)
    return r


def _col(store, cid, col):
    return store.conn.execute(f"SELECT {col} FROM candidate WHERE id=?", (cid,)).fetchone()[0]


def _held_ids(store, run_id):
    ds = build_dataset(store, run_id)
    return [c for c, h in zip(ds.ids, ho.mask(store, ds)) if h]


def _flip_labels(store, run_id, ids):
    """Flip the oracle label of the given sqli candidates (add/remove their finding);
    returns how many labels actually changed (asserted by callers: non-vacuous)."""
    from fuzzlab.core.urls import to_path
    before = dict(zip(*(lambda d: (d.ids, d.y))(build_dataset(store, run_id))))
    for cid in ids:
        ev = json.loads(_col(store, cid, "evidence"))
        if ev["category"] != "sql-injection":
            continue
        path = to_path(ev["url"])
        hit = store.conn.execute("SELECT id FROM finding WHERE run_id=? AND url=? AND param=?",
                                 (run_id, path, ev["param"])).fetchone()
        if hit:
            store.conn.execute("DELETE FROM finding WHERE id=?", (hit["id"],))
        else:
            _finding(store, run_id, path, ev["param"], "sqli")
    store.conn.commit()
    after = dict(zip(*(lambda d: (d.ids, d.y))(build_dataset(store, run_id))))
    return sum(1 for c in before if before[c] != after.get(c))


def _sealed(store, run_id):
    return {r["key"]: r["value"] for r in store.conn.execute(
        "SELECT key, value FROM holdout_metric WHERE run_id=?", (run_id,))}


# --- calibration: the Platt map ------------------------------------------------------

def test_platt_recovers_a_known_sigmoid_and_is_strictly_increasing():
    rng = random.Random(0)
    scores, labels = [], []
    for _ in range(4000):
        s = rng.uniform(0.01, 0.99)
        z = 2.0 * math.log(s / (1 - s)) - 0.5
        scores.append(s)
        labels.append(1 if rng.random() < 1 / (1 + math.exp(-z)) else 0)
    p = fit_platt(scores, labels)
    assert abs(p.a - 2.0) < 0.25 and abs(p.b + 0.5) < 0.25
    grid = [i / 100 for i in range(1, 100)]
    out = p.transform(grid)
    assert all(b > a for a, b in zip(out, out[1:]))


def test_platt_refuses_degenerate_fits():
    assert fit_platt([0.2, 0.4], [1, 1]) is None                  # one class
    rng = random.Random(1)
    s = [rng.random() for _ in range(200)]
    assert fit_platt(s, [1 if x < 0.5 else 0 for x in s]) is None   # anti-correlated: a<0


def test_cross_fit_uses_only_the_other_folds():
    rng = random.Random(2)
    s = [rng.random() for _ in range(60)]
    y = [1 if rng.random() < x else 0 for x in s]
    folds = [(list(range(20, 60)), list(range(20))), (list(range(20)) + list(range(40, 60)),
                                                      list(range(20, 40))),
             (list(range(40)), list(range(40, 60)))]
    out = cross_fit(s, y, folds)
    for train, test in folds:
        p = fit_platt([s[i] for i in train], [y[i] for i in train])
        assert [out[i] for i in test] == p.transform([s[i] for i in test])


# --- metric helpers --------------------------------------------------------------------

def test_metric_helpers_on_hand_examples():
    assert brier([1, 0], [0.75, 0.25]) == pytest.approx(0.0625)
    assert ece([1, 0, 1, 0], [0.9, 0.1, 0.9, 0.1]) == pytest.approx(0.1)
    bins, total = reliability([1, 0], [0.95, 0.05])
    assert bins[9]["count"] == 1 and bins[0]["observed"] == 0.0 and total == pytest.approx(0.05)
    assert mcc([1, 1, 0, 0], [1, 1, 0, 0]) == 1.0 and mcc([1, 0], [0, 0]) == 0.0
    assert precision_at_recall([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.1], 0.9) == pytest.approx(2 / 3)
    assert precision_at_recall([0, 0], [0.5, 0.4]) == 0.0


def test_ml_tab_reliability_is_the_shared_helper(tmp_path):
    with Store(tmp_path / "r.db") as store:
        r = _seed(store)
        train_and_score(store, r)
        panel = mlview.classifier_panel(store, r)
        scores, labels, _ = mlview._scored_pairs(store, build_dataset(store, r), r)
        assert panel["reliability"]["ece"] == round(ece(labels, scores), 4)


# --- persistence: format 1 untouched, format 2 fail-closed ------------------------------

def _fitted():
    return LogisticRegression().fit([[0.0, 1.0], [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]],
                                    [1, 0, 1, 0])


def test_no_calibrator_keeps_the_format_1_text():
    text, _ = dumps_model("logistic", _fitted(), feature_names=["a", "b"], feature_version=1)
    env = json.loads(text)
    assert env["format"] == 1 and "calibrator" not in env


def test_format_2_round_trips_and_reproduces_calibrated_scores():
    m, platt = _fitted(), PlattScaler(1.7, -0.3)
    text, sha = dumps_model("logistic", m, feature_names=["a", "b"], feature_version=1,
                            calibrator=platt)
    assert json.loads(text)["format"] == 2
    loaded = loads_model(text, sha)
    X = [[0.2, 0.9], [0.8, 0.1]]
    assert loaded.predict_proba(X) == platt.transform(m.predict_proba(X))


def _tamper(env):
    text = json.dumps(env, sort_keys=True, separators=(",", ":"))
    import hashlib
    return text, hashlib.sha256(text.encode()).hexdigest()


@pytest.mark.parametrize("mutate", [
    lambda e: e["calibrator"].update(a=0.0),
    lambda e: e["calibrator"].update(a=-1.0),
    lambda e: e["calibrator"].pop("b"),
    lambda e: e["calibrator"].update(extra=1),
    lambda e: e["calibrator"].update(kind="isotonic"),
    lambda e: e["calibrator"].update(a="1"),
    lambda e: e.update(calibrator=None),
    lambda e: e.pop("calibrator"),
    lambda e: e.update(format=1),
    lambda e: e.update(format=True),
    lambda e: e.update(format=3),
])
def test_malformed_calibrated_envelopes_are_refused(mutate):
    text, _ = dumps_model("logistic", _fitted(), feature_names=["a", "b"], feature_version=1,
                          calibrator=PlattScaler(1.0, 0.0))
    env = json.loads(text)
    mutate(env)
    with pytest.raises(ModelParamsError):
        loads_model(*_tamper(env))


def test_a_nan_slope_and_a_calibrated_ranker_or_prevalence_are_refused():
    text, _ = dumps_model("logistic", _fitted(), feature_names=["a", "b"], feature_version=1,
                          calibrator=PlattScaler(1.0, 0.0))
    nan_text = text.replace('"a":1.0', '"a":NaN')
    import hashlib
    with pytest.raises(ModelParamsError):
        loads_model(nan_text, hashlib.sha256(nan_text.encode()).hexdigest())
    from fuzzlab.ml.baselines import PrevalenceBaseline
    with pytest.raises(ModelParamsError, match="calibrator"):
        dumps_model("prevalence", PrevalenceBaseline().fit([[0.0]], [1]),
                    feature_names=["a"], feature_version=1, calibrator=PlattScaler(1, 0))
    with pytest.raises(ModelParamsError, match="calibrator"):
        dumps_model("constant", 0.0, feature_names=["a"], feature_version=1,
                    calibrator=PlattScaler(1, 0))


# --- calibration in training ------------------------------------------------------------

def test_platt_training_stores_cross_fitted_oof_and_calibrated_deploy_scores(tmp_path):
    with Store(tmp_path / "p.db") as store:
        r = _seed(store)
        result = train_and_score(store, r, model_kind="logistic", calibrate="platt")
        assert result["calibration"]["calibrator"] == "platt"
        ds = build_dataset(store, r)
        raw = train_mod._oof_scores(ds, LogisticRegression, 5)
        from fuzzlab.ml.metrics import oof_folds
        cross = cross_fit(raw, ds.y, oof_folds(ds.groups, k=5, seed=0))
        assert [_col(store, c, "score_oof") for c in ds.ids] == [round(v, 6) for v in cross]
        clf = latest_classifier(store, r)
        stored = [_col(store, c, "score_oof") for c in ds.ids]
        want = ConformalGate.calibrate(stored, ds.y, alpha=0.1)
        assert (clf.gate.t_lo, clf.gate.t_hi) == (want.t_lo, want.t_hi)
        c = clf.calibration
        assert c["oof_pr_auc"] == pr_auc(ds.y, cross)
        assert c["oof_pr_auc_raw"] == pr_auc(ds.y, raw)
        assert c["ece_oof_raw"] == ece(ds.y, raw) and c["ece_oof_calibrated"] == ece(ds.y, cross)
        every = build_dataset(store, r, include_unlabelled=True)
        loaded = load_classifier(store, clf)
        assert loaded.calibrator is not None
        assert [round(p, 6) for p in loaded.predict_proba(every.X)] == \
            [_col(store, i, "score") for i in every.ids]
        # the per-side bound holds on the calibrated, stored values (PA-0069)
        flagged = sum(1 for v, y in zip(stored, ds.y) if not y and clf.gate.decide(v) == "flag")
        dropped = sum(1 for v, y in zip(stored, ds.y) if y and clf.gate.decide(v) == "drop")
        assert flagged <= 0.1 * (len(ds) - ds.positives) and dropped <= 0.1 * ds.positives


def test_a_degenerate_fold_calibrates_nothing(tmp_path, monkeypatch):
    from fuzzlab.ml import calibration
    with Store(tmp_path / "a.db") as store, Store(tmp_path / "b.db") as plain:
        r, r2 = _seed(store), _seed(plain)
        train_and_score(plain, r2, model_kind="logistic")
        real, calls = calibration.fit_platt, {"n": 0}

        def flaky(s, y, **kw):
            calls["n"] += 1
            return None if calls["n"] == 3 else real(s, y, **kw)     # a fold fails
        monkeypatch.setattr(calibration, "fit_platt", flaky)
        result = train_and_score(store, r, model_kind="logistic", calibrate="platt")
        assert result["calibration"] == {"calibrator": "none (degenerate fit)"}
        a, b = latest_classifier(store, r), latest_classifier(plain, r2)
        assert a.params_sha256 == b.params_sha256                   # format 1, unchanged
        assert (a.gate.t_lo, a.gate.t_hi) == (b.gate.t_lo, b.gate.t_hi)
        assert [r_[0] for r_ in store.conn.execute("SELECT score_oof FROM candidate")] == \
            [r_[0] for r_ in plain.conn.execute("SELECT score_oof FROM candidate")]


def test_earlier_mode_calibrates_too(tmp_path):
    with Store(tmp_path / "e.db") as store:
        _seed(store, seed=3)
        _seed(store, seed=4)
        now = _seed(store, seed=5)
        result = train_and_score(store, now, train_on="earlier", model_kind="logistic",
                                 calibrate="platt")
        assert result["calibration"]["calibrator"] == "platt"
        assert load_classifier(store, latest_classifier(store, now)).calibrator is not None


def test_calibrate_validation():
    with pytest.raises(ValueError, match="calibrate"):
        train_and_score(None, 1, calibrate="isotonic")
    with pytest.raises(ValueError, match="saved"):
        train_and_score(None, 1, train_on="saved", calibrate="platt")


# --- holdout membership ------------------------------------------------------------------

def test_membership_is_deterministic_endpoint_level_and_about_a_fifth():
    paths = [f"/p{i}.php" for i in range(5000)]
    held = [ho.in_holdout("http://127.0.0.1:8080", p) for p in paths]
    assert held == [ho.in_holdout("http://127.0.0.1:8080", p) for p in paths]
    assert 0.18 < sum(held) / len(held) < 0.22
    assert not ho.in_holdout(None, "/p1.php")
    other = [ho.in_holdout("http://127.0.0.1:9090", p) for p in paths]
    assert held != other                                      # keyed by the target too


def test_origins_are_canonical(tmp_path):
    with Store(tmp_path / "o.db") as store:
        a = _seed(store, target="http://localhost:8080")
        b = _seed(store, target="http://127.0.0.1:8080/")
        ma, mb = (ho.mask(store, build_dataset(store, x)) for x in (a, b))
        assert ma == mb and any(ma)
        c = _seed(store, target=None)                          # no target: never held
        assert not any(ho.mask(store, build_dataset(store, c)))


# --- holdout in training -----------------------------------------------------------------

def test_held_out_rows_never_train_run_mode(tmp_path):
    """Identity: flipping held-out labels leaves the model unchanged; flipping a
    training label changes it (non-vacuous)."""
    with Store(tmp_path / "h.db") as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        train_and_rank(store, r, holdout=True)
        base = (latest_classifier(store, r).params_sha256, latest_ranker(store, r)[0]["id"])
        held = _held_ids(store, r)
        assert held
        assert _flip_labels(store, r, held) > 0
        train_and_score(store, r, model_kind="logistic", holdout=True)
        assert latest_classifier(store, r).params_sha256 == base[0]
        from fuzzlab.ml.model_registry import params_sha256_for
        rk = [params_sha256_for(store, latest_ranker(store, r)[0]["id"])]
        train_and_rank(store, r, holdout=True)
        rk.append(params_sha256_for(store, latest_ranker(store, r)[0]["id"]))
        assert rk[0] == rk[1]
        ds = build_dataset(store, r)
        kept = [c for c in ds.ids if c not in held]
        assert _flip_labels(store, r, kept[:6]) > 0
        train_and_score(store, r, model_kind="logistic", holdout=True)
        assert latest_classifier(store, r).params_sha256 != base[0]


def test_held_rows_have_no_oof_score_and_are_judged_on_score(tmp_path):
    with Store(tmp_path / "g.db") as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        clf = latest_classifier(store, r)
        held = set(_held_ids(store, r))
        for row in store.conn.execute(
                "SELECT id, score, score_oof, oracle_status FROM candidate WHERE run_id=?",
                (r,)):
            if row["id"] in held:
                assert row["score_oof"] is None
                assert gate_input(clf.calibration, row["oracle_status"], row["score"],
                                  None) == row["score"]
                assert metric_input(clf.calibration, row["oracle_status"], row["score"],
                                    None) is None
        ds = build_dataset(store, r)
        assert mlview.classifier_panel(store, r)["n"] == len(ds) - len(held)


def test_holdout_metrics_equal_a_recomputation_from_stored_scores(tmp_path):
    with Store(tmp_path / "m.db") as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        train_and_rank(store, r, holdout=True)
        sealed = _sealed(store, r)
        ds = build_dataset(store, r)
        mask = ho.mask(store, ds)
        y = [v for v, h in zip(ds.y, mask) if h]
        s = [_col(store, c, "score") for c, h in zip(ds.ids, mask) if h]
        assert sealed["ml_pr_auc_holdout"] == pr_auc(y, s)
        assert sealed["ml_brier_holdout"] == pytest.approx(brier(y, s))
        assert sealed["ml_ece_holdout"] == pytest.approx(ece(y, s))
        gate = latest_classifier(store, r).gate
        assert sealed["ml_mcc_holdout"] == pytest.approx(
            mcc(y, [1 if gate.decide(v) == "flag" else 0 for v in s]))
        assert sealed["holdout_rows"] == len(y) and sealed["holdout_positives"] == sum(y)
        assert "rank_ndcg_holdout" in sealed
        # never in run_metrics, never in the model row's calibration
        keys = {k for (k,) in store.conn.execute(
            "SELECT key FROM run_metrics WHERE run_id=?", (r,))}
        assert not any("holdout" in k for k in keys)
        assert latest_classifier(store, r).calibration["holdout"] == {
            "version": 1, "fraction": 0.2, "rows": len(y)}


def test_holdout_metrics_are_gated(tmp_path):
    with Store(tmp_path / "x.db") as store:
        r = _seed(store)
        store.conn.execute("UPDATE candidate SET oracle_status=? WHERE id=(SELECT MAX(id) "
                           "FROM candidate WHERE run_id=?)", (SKIPPED_BUDGET, r))
        store.conn.commit()
        result = train_and_score(store, r, holdout=True)
        assert result["holdout"]["skipped_reason"] == "budget-selected labels"
        assert _sealed(store, r) == {}
        thin = _seed(store, n=4)
        result = train_and_score(store, thin, holdout=True)
        assert result["fallback"] and result["holdout"]["skipped_reason"] == "fallback model"
        with pytest.raises(ValueError, match="holdout needs a run"):
            train_and_score(store, None, holdout=True)


def test_a_version_bump_never_reclassifies_an_old_models_rows(tmp_path, monkeypatch):
    with Store(tmp_path / "v.db") as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        before = mlview.conformal_panel(store, r)["counts"]
        monkeypatch.setattr(ho, "HOLDOUT_VERSION", 2)
        monkeypatch.setattr(ho, "HOLDOUT_SALT", "fuzzlab-holdout-v2")
        assert mlview.conformal_panel(store, r)["counts"] == before


def test_earlier_mode_and_the_prioritizer_drop_held_endpoints(tmp_path):
    with Store(tmp_path / "p.db") as store:
        a = _seed(store, seed=3)
        _seed(store, seed=4)
        now = _seed(store, seed=5)
        prior = build_dataset(store, before_run_id=now, target=TARGET)
        kept = len(prior) - sum(ho.mask(store, prior))
        res = train_and_score(store, now, train_on="earlier", holdout=True)
        assert res["train_rows"] == kept < len(prior)
        assert res["holdout"]["rows"] == len(_held_ids(store, now))
        ids = build_dataset(store, now, include_unlabelled=True).ids
        assert prioritize(store, now, ids, holdout=True).training_rows == kept
        assert prioritize(store, now, ids).training_rows == len(prior)
        # identity: held-out earlier labels never move the prioritizer's model
        sha = prioritize(store, now, ids, holdout=True).model_sha256
        assert _flip_labels(store, a, _held_ids(store, a)) > 0
        assert prioritize(store, now, ids, holdout=True).model_sha256 == sha
        assert prioritize(store, now, ids).model_sha256 != \
            prioritize(store, now, ids, holdout=True).model_sha256


def test_saved_mode_reports_holdout_only_for_the_current_membership(tmp_path, monkeypatch):
    with Store(tmp_path / "s.db") as store:
        first = _seed(store, seed=3)
        train_and_score(store, first, model_kind="logistic", holdout=True)
        now = _seed(store, seed=5)
        res = train_and_score(store, now, train_on="saved", holdout=True)
        assert res["holdout"]["sealed"] is True and "ml_pr_auc_holdout" in _sealed(store, now)
        assert latest_classifier(store, now).calibration["holdout"]["version"] == 1
        monkeypatch.setattr(ho, "HOLDOUT_VERSION", 2)
        later = _seed(store, seed=6)
        res = train_and_score(store, later, train_on="saved", holdout=True)
        assert res["holdout"]["skipped_reason"] == \
            "source model not trained with the current holdout"


# --- sealed surfaces ----------------------------------------------------------------------

def test_the_holdout_is_sealed_from_every_summary_surface(tmp_path):
    from starlette.testclient import TestClient
    from fuzzlab.core.config import load_config
    from fuzzlab.report.report import build_report, format_json, format_text
    from fuzzlab.web import diagnostics
    from fuzzlab.web.app import create_app
    path = tmp_path / "w.db"
    with Store(path) as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        train_and_rank(store, r, holdout=True)
        report = build_report(store, r)
        texts = [format_json(report), format_text(report)]
        assert diagnostics.browse_table(store, "holdout_metric") is None
        assert diagnostics.browse_table(store, "holdout_reveal") is None
        assert not set(SEALED_TABLES) & set(diagnostics.list_tables(store))
    cfg = load_config(overrides={"store_path": str(path), "web_port": 8765,
                                 "target_base_url": TARGET}, environ={})
    client = TestClient(create_app(cfg), base_url="http://127.0.0.1:8765")
    for url in (f"/api/runs/{r}", "/api/diagnostics/metrics", "/api/store/tables",
                f"/api/ml/data?run_id={r}", f"/runs/{r}", "/api/diagnostics/models"):
        resp = client.get(url)
        assert resp.status_code == 200, url               # the check is not vacuous
        texts.append(resp.text)
    assert "ml_pr_auc" in texts[0] and "holdout" in texts[7]    # the surfaces are real
    for t in texts:
        assert "_holdout" not in t and "holdout_metric" not in t
    for name in SEALED_TABLES:                    # refused exactly like a missing table
        assert client.get(f"/api/store/tables/{name}").status_code == \
            client.get("/api/store/tables/no_such_table").status_code == 404


def test_reveal_counts_per_version_and_records_nothing_without_metrics(tmp_path):
    with Store(tmp_path / "rv.db") as store:
        r = _seed(store)
        empty = reveal(store, r)
        assert empty == {"metrics": {}, "reveals": 0}
        assert store.conn.execute("SELECT COUNT(*) c FROM holdout_reveal").fetchone()["c"] == 0
        train_and_score(store, r, model_kind="logistic", holdout=True)
        assert reveal(store, r)["reveals"] == 1
        out = reveal(store, r)
        assert out["reveals"] == 2 and out["version"] == 1
        assert "ml_pr_auc_holdout" in next(iter(out["metrics"].values()))


def test_reveal_cli(tmp_path, capsys):
    from fuzzlab.cli import main
    with Store(tmp_path / "c.db") as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        other = _seed(store)
    assert main(["reveal-holdout", "--store", str(tmp_path / "c.db"), "--run", str(r)]) == 0
    out = capsys.readouterr().out
    assert "reveal #1 of holdout version 1" in out and "ml_pr_auc_holdout = " in out
    assert main(["reveal-holdout", "--store", str(tmp_path / "c.db"),
                 "--run", str(other)]) == 0
    assert "nothing to reveal" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["reveal-holdout", "--store", str(tmp_path / "missing.db"), "--run", "1"])


# --- `fuzzlab auto` flags (CC-FUZZ-0053) ----------------------------------------------------

@pytest.mark.parametrize("flags, message", [
    (["--calibrate", "platt"], "--calibrate needs --score"),
    (["--score", "--train-on", "saved", "--calibrate", "platt"], "keeps its own calibrator"),
    (["--holdout"], "--holdout needs --score, --rank or --confirm-budget"),
    (["--anomaly", "--holdout"], "--holdout needs"),
])
def test_cli_flag_validation(tmp_path, monkeypatch, capsys, flags, message):
    from tests.test_auto_budget import _main
    with pytest.raises(SystemExit):
        _main(tmp_path, monkeypatch, *flags)
    assert message in capsys.readouterr().err
    assert not (tmp_path / "s.db").exists() or Store(tmp_path / "s.db").conn.execute(
        "SELECT COUNT(*) c FROM run").fetchone()["c"] == 0


def test_cli_holdout_and_calibrate_print_only_label_free_facts(tmp_path, monkeypatch, capsys):
    from tests.test_auto_budget import _earlier_runs, _last_run, _main
    with Store(tmp_path / "s.db") as store:
        _earlier_runs(store)
    assert _main(tmp_path, monkeypatch, "--score", "--rank", "--train-on", "earlier",
                 "--calibrate", "platt", "--holdout") == 0
    out = capsys.readouterr().out
    store, run_id = _last_run(tmp_path)
    with store:
        held = ho.held_endpoints(store, run_id)
        plugins = {r["name"]: json.loads(r["config"]) for r in store.conn.execute(
            "SELECT name, config FROM run_plugin WHERE run_id=?", (run_id,))}
        sealed = _sealed(store, run_id)
    assert plugins["ml-classifier"]["calibrate"] == "platt"
    assert plugins["ml-classifier"]["holdout"] is True and plugins["ml-ranker"]["holdout"]
    assert f"holdout: {held} endpoint(s) of this run held out" in out
    assert "calibration: " in out
    assert "_holdout" not in out
    import re
    lines = [ln for ln in out.splitlines() if "holdout" in ln]
    assert len(lines) == 2                        # one per stage; only label-free facts
    pattern = (r"    holdout: \d+ endpoint\(s\) of this run held out; (metrics sealed — "
               r"read with `fuzzlab reveal-holdout --run \d+` \(each read is counted\)|"
               r"no sealed metrics \([a-z -]+\))")
    assert all(re.fullmatch(pattern, ln) for ln in lines), lines
    assert sealed or all("no sealed metrics" in ln for ln in lines)


def test_cli_default_configs_are_unchanged(tmp_path, monkeypatch):
    """Without the new flags a stage's recorded config is exactly what it was."""
    from fuzzlab.ml.plugins import stage_plugins
    cfg = {p.name: p.config for p in stage_plugins(score=True, rank=True,
                                                   confirm_budget=3)}
    assert cfg == {"ml-budget": {"method": "score", "seed": 0},
                   "ml-classifier": {"train_on": "run", "model_kind": "auto", "hybrid": False},
                   "ml-ranker": {"train_on": "run"}}


def test_ml_tab_shows_the_calibration_evidence_in_a_real_browser(tmp_path):
    """CC-UI-0045 (PA-0065(3)): the reliability panel's meta line carries the Platt
    evidence — out-of-fold ECE raw → cross-fitted — as text."""
    from tests._browser import Server, free_port, launch_browser_or_skip, require_modules
    require_modules()
    from playwright.sync_api import sync_playwright
    from fuzzlab.core.config import load_config
    from fuzzlab.web import labcontrol
    from fuzzlab.web.app import create_app
    from tests.test_web_pages_browser import _Page
    path = tmp_path / "b.db"
    with Store(path) as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", calibrate="platt", holdout=True)
        c = latest_classifier(store, r).calibration
    mp = pytest.MonkeyPatch()

    async def no_engine():
        return {}, None
    mp.setattr(labcontrol, "fetch_states", no_engine)
    port = free_port()
    cfg = load_config(overrides={"store_path": str(path), "web_port": port,
                                 "target_base_url": TARGET}, environ={})
    server = Server(create_app(cfg), port)
    server.start()
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            tab = _Page(browser, f"http://127.0.0.1:{port}")
            page = tab.open(f"/ml?run={r}", ".uplot")
            page.wait_for_timeout(800)
            meta = page.inner_text('#panel-calibration [data-field="summary"]')
            assert (f"Platt-calibrated: out-of-fold ECE {round(c['ece_oof_raw'], 4)} raw → "
                    f"{round(c['ece_oof_calibrated'], 4)} cross-fitted") in meta
            assert "_holdout" not in page.content()
            assert tab.problems() == []
            tab.close()
            browser.close()
    finally:
        server.stop()
        mp.undo()
