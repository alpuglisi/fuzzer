"""The ML stages as built-in plugins (CC-ML-0017, FR-ML-6).

Run through the `PluginManager` — so under the advisory write guard and as one unit of
work each — every stage must compute exactly what the direct call computes. Compared on
two identical stores, since a second training call on one store bumps the model version.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.ml.active import prioritize
from fuzzlab.ml.anomaly import detect_anomalies
from fuzzlab.ml.plugins import (ML_PLUGIN_VERSION, STAGE_NAMES, AnomalyPlugin, BudgetPlugin,
                                ClassifierPlugin, RankerPlugin, stage_plugins)
from fuzzlab.ml.rank_train import train_and_rank
from fuzzlab.ml.train import train_and_score
from fuzzlab.plugins import PluginManager
from fuzzlab.plugins.manager import FailedBudgetOrder
from tests.test_ml_budget_and_scope import _current_run, _prior_runs, _target
from tests.test_ml_train import _seed_rich


def _store(path):
    store = Store(path)
    _prior_runs(store)
    run_id = _seed_rich(store)
    _target(store, run_id)
    return store, run_id


def _state(store, run_id):
    q = store.conn.execute
    return {
        "candidates": [tuple(r) for r in q(
            "SELECT id, score, rank_score, rank_uncertainty, anomaly_score, anomaly_flag "
            "FROM candidate WHERE run_id=? ORDER BY id", (run_id,))],
        "models": [tuple(r) for r in q(
            "SELECT name, version, calibration, params_sha256 FROM model ORDER BY id")],
        "metrics": sorted(tuple(r) for r in q(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,))),
    }


DIRECT = {
    "classifier-run": (lambda: ClassifierPlugin(train_on="run"),
                       lambda s, r: train_and_score(s, r, model_kind="auto", train_on="run")),
    "classifier-earlier": (lambda: ClassifierPlugin(train_on="earlier"),
                           lambda s, r: train_and_score(s, r, model_kind="auto",
                                                        train_on="earlier")),
    "ranker-run": (lambda: RankerPlugin(train_on="run"),
                   lambda s, r: train_and_rank(s, r, train_on="run")),
    "ranker-earlier": (lambda: RankerPlugin(train_on="earlier"),
                       lambda s, r: train_and_rank(s, r, train_on="earlier")),
    "anomaly": (lambda: AnomalyPlugin(contamination=0.2),
                lambda s, r: detect_anomalies(s, r, contamination=0.2)),
}


@pytest.mark.parametrize("case", sorted(DIRECT))
def test_a_stage_plugin_computes_exactly_what_the_direct_call_does(tmp_path, case):
    make, direct = DIRECT[case]
    store_a, run_a = _store(tmp_path / "a.db")
    store_b, run_b = _store(tmp_path / "b.db")
    with store_a, store_b:
        expected = direct(store_a, run_a)
        [outcome] = PluginManager(plugins=[make()]).after_run(store_b, run_b)
        assert outcome.ok, outcome.error                 # it ran under the guard
        got = dict(outcome.result)
        got.pop("top", None)                             # the anomaly stage's extra
        assert got == expected
        assert _state(store_b, run_b) == _state(store_a, run_a)


def test_the_budget_plugin_orders_like_prioritize_under_the_read_only_guard(tmp_path):
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)
        run_id, ids = _current_run(store)
        for method in ("score", "uncertainty", "committee", "random"):
            run = PluginManager(plugins=[BudgetPlugin(method=method, seed=3)]) \
                .guarded_prioritizer()
            got = run(store, run_id, ids)
            assert not isinstance(got, FailedBudgetOrder), getattr(got, "error", None)
            want = prioritize(store, run_id, ids, method=method, seed=3)
            assert (got.order, got.method, got.model_sha256) == \
                (want.order, want.method, want.model_sha256)
            assert run.plugin_name == "ml-budget"


@pytest.mark.parametrize("flags, names", [
    ({}, []),
    ({"score": True}, ["ml-classifier"]),
    ({"rank": True, "anomaly": True}, ["ml-ranker", "ml-anomaly"]),
    ({"confirm_budget": 2, "score": True, "rank": True, "anomaly": True},
     ["ml-budget", "ml-classifier", "ml-ranker", "ml-anomaly"]),
])
def test_stage_plugins_maps_options_to_plugins(flags, names):
    plugins = stage_plugins(**flags)
    assert [p.name for p in plugins] == names
    assert all(p.version == ML_PLUGIN_VERSION for p in plugins)
    assert {p.flag: p.name for p in plugins} == {f: STAGE_NAMES[f] for f in
                                                 {p.flag for p in plugins}}


def test_stage_options_reach_the_plugins_and_the_run_record(tmp_path):
    plugins = stage_plugins(score=True, rank=True, anomaly=True, contamination=0.25,
                            train_on="earlier", confirm_budget=3, budget_method="committee",
                            budget_seed=7)
    by = {p.name: p.config for p in plugins}
    assert by == {"ml-budget": {"method": "committee", "seed": 7},
                  "ml-classifier": {"train_on": "earlier", "model_kind": "auto",
                                    "hybrid": False},
                  "ml-ranker": {"train_on": "earlier"},
                  "ml-anomaly": {"contamination": 0.25}}
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "h")
        PluginManager(plugins=plugins).record(store, run_id)
        rows = dict(store.conn.execute("SELECT name, config FROM run_plugin").fetchall())
        assert rows["ml-classifier"] == '{"hybrid":false,"model_kind":"auto","train_on":"earlier"}'
        assert rows["ml-anomaly"] == '{"contamination":0.25}'
