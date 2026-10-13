"""Batch 4 of the remaining ML work: pairwise learning-to-rank (FR-ML-21), Isolation
Forest (FR-ML-22), flow anomalies (FR-ML-23) — CC-ML-0021, CC-CORE-0031, CC-FUZZ-0054,
CC-UI-0046."""

from __future__ import annotations

import ast
import json
import math
import random
from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from fuzzlab.ml import anomaly, flow_anomaly
from fuzzlab.ml.persist import ModelParamsError, dumps_model, loads_model
from fuzzlab.ml.rank_train import _fold_global, latest_ranker, train_and_rank
from fuzzlab.ml.ranker import MAX_PAIRS, Ranker, sample_pairs
from fuzzlab.ml.ranking import ndcg_at_k, precision_at_k
from fuzzlab.web import mlview
from tests.test_ml_budget_and_scope import _target
from tests.test_ml_train import _cand, _finding

TARGET = "http://127.0.0.1:8080"
#: The pointwise ranker's sha on the fixture below, recorded from the code BEFORE the
#: pairwise objective was added (CC-ML-0021, A1): a pointwise ranker's canonical text
#: must stay byte-identical.
POINTWISE_SHA = "d21f003b9c02eb19bcdb96b91c61932914a151c7729998999dc7399f0d944c7f"


def _fixture():
    X = [[float((i * 7 + j) % 5) for j in range(11)] for i in range(24)]
    texts = [f"param{i % 6} /page{i % 4}.php xss GET" for i in range(24)]
    y = [1 if (i % 5 in (0, 3)) else 0 for i in range(24)]
    return X, texts, y


def _seed(store, n=16, seed=1, target=TARGET):
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


# --- pairwise learning-to-rank ------------------------------------------------------------

def test_pointwise_ranker_text_is_byte_identical_to_before():
    from fuzzlab.ml.dataset import FEATURE_VERSION
    X, texts, y = _fixture()
    r = Ranker(seed=0).fit(X, texts, y)
    text, sha = dumps_model("ranker", r, feature_names=r.feature_names,
                            feature_version=FEATURE_VERSION)
    assert sha == POINTWISE_SHA and '"objective"' not in text


def test_pairs_are_positive_negative_seeded_and_capped():
    y = [1] * 3 + [0] * 4
    pairs = sample_pairs(y, seed=0)
    assert len(pairs) == 12 and all(y[i] == 1 and y[j] == 0 for i, j in pairs)
    big = [1] * 100 + [0] * 100                              # 10000 pairs > cap
    a, b = sample_pairs(big, 1), sample_pairs(big, 1)
    assert len(a) == MAX_PAIRS and a == b and a != sample_pairs(big, 2)
    assert sample_pairs([1, 1], 0) == [] and sample_pairs([], 0) == []


def test_pairwise_fit_is_symmetric_and_round_trips():
    X, texts, y = _fixture()
    r = Ranker(seed=0, objective="pairwise").fit(X, texts, y)
    assert r.objective_used == "pairwise"
    assert abs(r.model._b) < 1e-9                          # both orders: no intercept bias
    text, sha = dumps_model("ranker", r, feature_names=r.feature_names, feature_version=1)
    assert json.loads(text)["params"]["objective"] == "pairwise"
    loaded = loads_model(text, sha)
    assert loaded.model.objective_used == "pairwise"
    assert loaded.score(X, texts) == r.score(X, texts)


def test_pairwise_without_a_pair_falls_back_to_pointwise():
    X, texts, _ = _fixture()
    r = Ranker(seed=0, objective="pairwise").fit(X, texts, [1] * len(X))
    assert r.objective_used == "pointwise" and "objective" not in r.to_params()


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(objective="pointwise"),
    lambda p: p.update(objective="listwise"),
    lambda p: p.update(objective=None),
])
def test_bad_objectives_are_refused(mutate):
    import hashlib
    X, texts, y = _fixture()
    r = Ranker(seed=0, objective="pairwise").fit(X, texts, y)
    env = json.loads(dumps_model("ranker", r, feature_names=r.feature_names,
                                 feature_version=1)[0])
    mutate(env["params"])
    text = json.dumps(env, sort_keys=True, separators=(",", ":"))
    with pytest.raises(ModelParamsError):
        loads_model(text, hashlib.sha256(text.encode()).hexdigest())
    with pytest.raises(ValueError):
        Ranker(objective="listwise")


def test_fold_global_is_per_fold_then_averaged(tmp_path):
    from fuzzlab.ml.dataset import build_dataset
    from fuzzlab.ml.metrics import oof_folds
    with Store(tmp_path / "g.db") as store:
        ds = build_dataset(store, _seed(store))
    oof = [((i * 37) % 11) / 11 for i in range(len(ds))]
    nd, pr = [], []
    for _, test in oof_folds(ds.groups, k=5, seed=0):
        y = [ds.y[i] for i in test]
        if any(y):
            nd.append(ndcg_at_k(y, [oof[i] for i in test], 10))
            pr.append(precision_at_k(y, [oof[i] for i in test], 10))
    assert _fold_global(ds, oof, 5, 0, 10) == (round(sum(nd) / len(nd), 6),
                                                round(sum(pr) / len(pr), 6))


def test_train_and_rank_pairwise_and_auto(tmp_path):
    with Store(tmp_path / "p.db") as store:
        r = _seed(store)
        res = train_and_rank(store, r, objective="pairwise")
        assert res["objective"] == res["objective_used"] == "pairwise"
        c = latest_ranker(store, r)[1]
        assert c["objective_used"] == "pairwise" and "rank_ndcg_global" in c
        assert store.conn.execute("SELECT COUNT(*) FROM candidate WHERE run_id=? AND "
                                  "rank_uncertainty IS NOT NULL", (r,)).fetchone()[0] == 0
        panel = mlview.ranker_panel(store, r)
        assert panel["uncertainty_available"] is False and panel["scatter"] == []
        assert panel["objective"] == "pairwise" and panel["global"]["ndcg"] == \
            c["rank_ndcg_global"]
        keys = {k for (k,) in store.conn.execute(
            "SELECT key FROM run_metrics WHERE run_id=?", (r,))}
        assert {"rank_ndcg_global", "rank_precision_global"} <= keys
        res = train_and_rank(store, r, objective="auto")
        c = latest_ranker(store, r)[1]
        by = c["oof_ndcg_global_by_objective"]
        want = "pairwise" if by["pairwise"] > by["pointwise"] else "pointwise"
        assert c["objective_selected"] == want and c["selection_biased"] is True
        assert c["rank_ndcg_global"] == by[want]
        train_and_rank(store, r)                                   # pointwise again
        c = latest_ranker(store, r)[1]
        assert "objective" not in c and "rank_ndcg_global" not in c
        assert mlview.ranker_panel(store, r)["uncertainty_available"] is True


def test_objective_validation():
    with pytest.raises(ValueError, match="objective"):
        train_and_rank(None, 1, objective="listwise")
    with pytest.raises(ValueError, match="saved"):
        train_and_rank(None, 1, train_on="saved", objective="pairwise")


def test_earlier_and_saved_modes_carry_the_objective(tmp_path):
    with Store(tmp_path / "e.db") as store:
        _seed(store, seed=3)
        _seed(store, seed=4)
        now = _seed(store, seed=5)
        res = train_and_rank(store, now, train_on="earlier", objective="pairwise")
        assert res["objective_used"] == "pairwise"
        later = _seed(store, seed=6)
        res = train_and_rank(store, later, train_on="saved")
        assert res["refused"] is False
        assert latest_ranker(store, later)[1]["objective_used"] == "pairwise"
        assert store.conn.execute("SELECT COUNT(*) FROM candidate WHERE run_id=? AND "
                                  "rank_uncertainty IS NOT NULL",
                                  (later,)).fetchone()[0] == 0


def test_the_budget_prioritizer_stays_pointwise():
    """FR-ML-21: `prioritize` always fits the pointwise ranker (its order model)."""
    import inspect
    from fuzzlab.ml import active
    src = inspect.getsource(active.prioritize)
    assert "Ranker(seed=seed)" in src and "objective" not in src


# --- Isolation Forest ---------------------------------------------------------------------

def test_average_path_length_is_exact_for_small_n():
    assert anomaly.average_path_length(0) == anomaly.average_path_length(1) == 0.0
    assert anomaly.average_path_length(2) == 1.0
    assert anomaly.average_path_length(3) == pytest.approx(2 * 1.5 - 4 / 3)
    assert anomaly.average_path_length(256) == pytest.approx(
        2 * sum(1 / i for i in range(1, 256)) - 2 * 255 / 256)


def test_iforest_is_deterministic_and_finds_planted_outliers():
    rng = random.Random(0)
    X = [[rng.gauss(0, 1), rng.gauss(0, 1), float(rng.random() < 0.5)] for _ in range(80)]
    X += [[9.0, 9.0, 1.0], [-8.0, 9.5, 0.0], [10.0, -9.0, 1.0]]
    a = anomaly.IsolationForest(n_trees=20, seed=3).fit(X).scores(X)
    assert a == anomaly.IsolationForest(n_trees=20, seed=3).fit(X).scores(X)
    assert a != anomaly.IsolationForest(n_trees=20, seed=4).fit(X).scores(X)
    top = sorted(range(len(X)), key=lambda i: a[i], reverse=True)[:3]
    assert set(top) == {80, 81, 82}
    assert all(0 < s < 1 for s in a)


def test_iforest_edge_cases():
    for X in ([[1.0]], [[1.0], [2.0]]):
        assert anomaly.IsolationForest(n_trees=20).fit(X).scores(X) == [0.5] * len(X)
    same = [[1.0, 0.0]] * 10                    # nothing to split: every row a root leaf
    s = anomaly.IsolationForest(n_trees=20).fit(same).scores(same)
    assert s == [0.5] * 10                       # path = c(ψ) exactly → 2^-1
    assert sum(anomaly.flag_top(s, 0.1)) == 0
    # a constant feature is never split on: a two-valued column isolates in one cut
    two = [[7.0, float(i % 2)] for i in range(8)]
    f = anomaly.IsolationForest(n_trees=20, max_samples=8).fit(two)
    assert all(t[0] == "split" and t[1] == 1 for t in f._trees)


def test_detect_anomalies_with_iforest(tmp_path):
    with Store(tmp_path / "i.db") as store:
        r = _seed(store)
        res = anomaly.detect_anomalies(store, r, method="iforest")
        assert res["method"] == "iforest" and res["flagged"] <= res["flag_budget"]
        from fuzzlab.ml.dataset import build_dataset
        X = build_dataset(store, r, include_unlabelled=True).X
        want = anomaly.IsolationForest(seed=0).fit(X).scores(X)
        stored = [v for (v,) in store.conn.execute(
            "SELECT anomaly_score FROM candidate WHERE run_id=? ORDER BY id", (r,))]
        assert stored == want and all(0 < v < 1 for v in stored)
        tiny = store.start_run("auto", "h")
        _cand(store, tiny, "/a.php", "id", "xss")
        store.conn.commit()
        res = anomaly.detect_anomalies(store, tiny, method="iforest")
        assert res["flagged"] == 0 and res["flag_budget"] == 0
        assert res["flag_reason"] == "too few candidates to isolate (n ≤ 2)"
        with pytest.raises(ValueError, match="method"):
            anomaly.detect_anomalies(store, r, method="lof")


def test_anomaly_plugin_config_and_panel_follow_what_was_stored(tmp_path):
    from fuzzlab.ml.plugins import AnomalyPlugin, stage_plugins
    from fuzzlab.web.results import run_detail
    assert AnomalyPlugin().config == {"contamination": 0.1}
    assert AnomalyPlugin(method="iforest").config == {"contamination": 0.1,
                                                      "method": "iforest"}
    assert {p.name: p.config for p in stage_plugins(rank=True)} == {
        "ml-ranker": {"train_on": "run"}}
    assert {p.name: p.config for p in stage_plugins(rank=True, rank_objective="auto")} == {
        "ml-ranker": {"train_on": "run", "objective": "auto"}}
    with Store(tmp_path / "s.db") as store:
        r = _seed(store)
        anomaly.detect_anomalies(store, r, method="iforest", contamination=0.2)
        store.conn.execute("INSERT INTO run_plugin (run_id, name, version, priority, config) "
                           "VALUES (?,?,?,?,?)", (r, "ml-anomaly", "2", 30,
                                                  '{"contamination":0.2,"method":"iforest"}'))
        store.conn.commit()
        p = mlview.anomaly_panel(store, r)
        assert (p["source"], p["method"], p["contamination"]) == ("stored", "iforest", 0.2)
        assert p["axis"] == "Isolation Forest score (0–1)"
        stored = store.conn.execute("SELECT COUNT(*) FROM candidate WHERE run_id=? AND "
                                    "anomaly_flag=1", (r,)).fetchone()[0]
        assert p["flagged"] == stored
        assert run_detail(store, r)["anomaly"]["method"] == "iforest"
        bare = _seed(store, seed=2)
        anomaly.detect_anomalies(store, bare)                # no stage row recorded
        assert mlview.anomaly_panel(store, bare)["method"] == "unknown (assumed ECOD)"
        assert run_detail(store, bare)["anomaly"]["method"] == "unknown (assumed ECOD)"
        none = _seed(store, seed=7)
        assert mlview.anomaly_panel(store, none)["source"] == "recomputed (ECOD, 0.1)"


# --- flow anomalies ----------------------------------------------------------------------

def _flow(store, run_id, url, *, host=None, status=200, elapsed=12.0, method="GET",
          protocol=None, in_scope=None, req=None, resp=b"<html>ok</html>"):
    req_sha = store.put_body(req) if req is not None else None
    resp_sha = store.put_body(resp) if resp is not None else None
    cur = store.conn.execute(
        "INSERT INTO flow (run_id, method, url, host, status, elapsed_ms, protocol, "
        "in_scope, req_body_sha, resp_body_sha) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (run_id, method, url, host, status, elapsed, protocol, in_scope, req_sha, resp_sha))
    return cur.lastrowid


def test_migration_18_adds_the_flow_columns(tmp_path):
    with Store(tmp_path / "m.db") as store:
        cols = {r[1] for r in store.conn.execute("PRAGMA table_info(flow)")}
        assert {"anomaly_score", "anomaly_flag"} <= cols


def test_flow_vectors_are_exact_including_missing_values(tmp_path):
    with Store(tmp_path / "f.db") as store:
        r = store.start_run("proxy", "h")
        _flow(store, r, "http://h/a/b?x=1&y=2", status=404, elapsed=9.0, method="POST",
              protocol="h2", req=b"abc", resp=b"0123456789")
        _flow(store, r, "http://h/", status=None, elapsed=None, protocol=None, resp=None)
        store.conn.commit()
        ids, hosts, X, out = flow_anomaly.flow_features(store, r)
    assert hosts == ["h", "h"] and out == 0
    assert X[0] == [4.0, 0.0, math.log1p(9.0), 0.0, math.log1p(10), 0.0, math.log1p(3), 0.0,
                    2.0, 2.0, 1.0, 0.0, 1.0, 0.0]
    assert X[1] == [0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
    assert len(X[0]) == len(flow_anomaly.FLOW_FEATURE_NAMES)


def test_flows_are_scored_per_host_in_scope_and_rewritten_each_pass(tmp_path):
    with Store(tmp_path / "h.db") as store:
        r = store.start_run("proxy", "h")
        for i in range(20):
            _flow(store, r, f"http://a/p{i % 4}", host="a", elapsed=10.0 + i % 3)
        odd = _flow(store, r, "http://a/admin/x/y/z?a=1&b=2&c=3", host="a", status=500,
                    elapsed=5000.0, method="POST", resp=b"x" * 50000)
        _flow(store, r, "http://b/one", host="b")                 # host with 2 flows
        _flow(store, r, "http://b/two", host="b")
        out_id = _flow(store, r, "http://c/x", host="c", in_scope=0)
        store.conn.execute("UPDATE flow SET anomaly_flag=1, anomaly_score=9 WHERE id=?",
                           (out_id,))                              # stale value
        store.conn.commit()
        res = flow_anomaly.detect_flow_anomalies(store, r, contamination=0.1)
        assert res["out_of_scope"] == 1 and res["skipped_hosts"] == ["b"]
        assert res["hosts"]["a"]["flows"] == 21
        assert res["hosts"]["a"]["flagged"] <= anomaly.flag_budget(21, 0.1)
        assert res["top"] and res["top"][0]["id"] == odd
        rows = {x["id"]: x for x in store.conn.execute(
            "SELECT id, host, anomaly_score, anomaly_flag FROM flow WHERE run_id=?", (r,))}
        assert rows[out_id]["anomaly_score"] is None and rows[out_id]["anomaly_flag"] is None
        assert all(x["anomaly_score"] is None for x in rows.values() if x["host"] == "b")
        assert rows[odd]["anomaly_flag"] == 1


def test_flow_anomaly_cli_end_to_end(tmp_path, capsys):
    from fuzzlab.cli import main
    with Store(tmp_path / "c.db") as store:
        r = store.start_run("proxy", "h")
        for i in range(12):
            _flow(store, r, f"http://a/p{i}", host="a", elapsed=10.0 + i)
        store.conn.commit()
    assert main(["flow-anomaly", "--store", str(tmp_path / "c.db"), "--run", str(r),
                 "--method", "iforest"]) == 0
    out = capsys.readouterr().out
    assert "iforest" in out and "a: " in out and "never labels" in out
    with pytest.raises(SystemExit):
        main(["flow-anomaly", "--store", str(tmp_path / "c.db"), "--run", str(r),
              "--contamination", "0.9"])
    from fuzzlab.web import commandspec
    assert "flow-anomaly" in commandspec.command_names()


def test_flow_anomaly_modules_send_nothing():
    root = Path(flow_anomaly.__file__).parents[1]
    for rel in ("ml/flow_anomaly.py", "harness/flow_anomaly_cli.py"):
        tree = ast.parse((root / rel).read_text())
        mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | \
            {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not {m for m in mods if m and any(
            m.startswith(x) for x in ("fuzzlab.tools", "fuzzlab.core.http", "requests",
                                      "socket", "http.client", "urllib.request"))}, rel


# --- `fuzzlab auto` flags -------------------------------------------------------------------

@pytest.mark.parametrize("flags, message", [
    (["--rank-objective", "pairwise"], "--rank-objective needs --rank"),
    (["--rank", "--train-on", "saved", "--rank-objective", "auto"], "saved ranker keeps"),
    (["--anomaly-method", "iforest"], "--anomaly-method needs --anomaly"),
])
def test_cli_flag_validation(tmp_path, monkeypatch, capsys, flags, message):
    from tests.test_auto_budget import _main
    with pytest.raises(SystemExit):
        _main(tmp_path, monkeypatch, *flags)
    assert message in capsys.readouterr().err


def test_cli_iforest_summary_label(tmp_path, monkeypatch, capsys):
    from tests.test_auto_budget import _main
    assert _main(tmp_path, monkeypatch, "--anomaly", "--anomaly-method", "iforest") == 0
    assert "  anomaly (iforest): flagged " in capsys.readouterr().out


def test_ml_tab_pairwise_and_iforest_text_in_a_real_browser(tmp_path):
    """CC-UI-0046 (PA-0065(3)): the ranker panel says the objective, the per-fold
    run-wide metric and "uncertainty n/a (pairwise)"; the anomaly panel names the stored
    method and its axis."""
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
        train_and_rank(store, r, objective="pairwise")
        anomaly.detect_anomalies(store, r, method="iforest")
        store.conn.execute("INSERT INTO run_plugin (run_id, name, version, priority, config) "
                           "VALUES (?,?,?,?,?)", (r, "ml-anomaly", "2", 30,
                                                  '{"contamination":0.1,"method":"iforest"}'))
        store.conn.commit()
        glob = latest_ranker(store, r)[1]["rank_ndcg_global"]
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
            ranker = page.inner_text('#panel-ranker [data-field="summary"]')
            assert "objective pairwise" in ranker
            assert f"run-wide nDCG@k {glob} (per-fold scales — not pooled)" in ranker
            assert "uncertainty n/a (pairwise)" in ranker
            assert page.locator("#chart-rank-scatter .uplot").count() == 0
            meta = page.inner_text('#panel-anomaly [data-field="summary"]')
            assert meta.startswith("stored · method iforest · contamination 0.1")
            assert tab.problems() == []
            tab.close()
            browser.close()
    finally:
        server.stop()
        mp.undo()


@pytest.mark.parametrize("pw, pp, want", [(0.7, 0.6, "pointwise"), (0.6, 0.6, "pointwise"),
                                          (0.5, 0.6, "pairwise")])
def test_auto_deploys_the_better_run_wide_ndcg_ties_to_pointwise(monkeypatch, pw, pp, want):
    """`auto` picks by the per-fold run-wide NDCG; a tie stays pointwise (mutation-proven)."""
    from fuzzlab.ml import rank_train
    monkeypatch.setattr(rank_train, "_oof_scores",
                        lambda ds, texts, k, seed, objective="pointwise": [objective])
    monkeypatch.setattr(rank_train, "_fold_global",
                        lambda ds, oof, k, seed, at_k: (pw, 0.1) if oof == ["pointwise"]
                        else (pp, 0.2))
    chosen, oof, info = rank_train._choose_objective(None, None, 5, 0, 10, "auto")
    assert chosen == want == info["objective_selected"] and oof == [want]
    assert info["oof_ndcg_global_by_objective"] == {"pointwise": pw, "pairwise": pp}
    assert info["rank_ndcg_global"] == (pw if want == "pointwise" else pp)
