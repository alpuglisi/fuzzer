"""Tests for the ML tab (U4): read-only, advisory model-internals dashboard.

Mirrors test_web_results.py's pattern: seed the store with rows the real
fuzzlab/ml, fuzzlab/oracle, fuzzlab/scheduler, and fuzzlab/mutation writers would have
left behind, then assert both the pure `web/mlview.py` functions and the rendered
`/ml` route (Starlette's TestClient runs no JS, so this doubles as the no-JS check per
the R-09 test strategy). Never trains anything and never writes to the store.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import MetricLogger, Store, log_scalar  # noqa: E402
from fuzzlab.web import mlview  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402

from ._web_client import web_client  # noqa: E402


def _client(path):
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    return web_client(create_app(cfg))


def _seed_full(path) -> int:
    """A run with real rows for every ML family this tab reads."""
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")

        # classifier: a confirmed finding + two scored candidates (one matches -> y=1)
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "sql-injection", 1, "error-signature", "{}",
             "/product.php", "GET", "id"))
        c1 = store.conn.execute(
            "INSERT INTO candidate (run_id, evidence, score, rank_score, "
            "rank_uncertainty) VALUES (?,?,?,?,?)",
            (run_id, json.dumps({"url": "/product.php", "param": "id",
                                 "category": "sql-injection"}), 0.91, 0.8, 0.4)).lastrowid
        c2 = store.conn.execute(
            "INSERT INTO candidate (run_id, evidence, score, rank_score, "
            "rank_uncertainty) VALUES (?,?,?,?,?)",
            (run_id, json.dumps({"url": "/search.php", "param": "q",
                                 "category": "xss"}), 0.12, 0.2, 0.9)).lastrowid
        assert c1 and c2
        for k, v in {"ml_pr_auc": 0.82, "ml_pr_auc_prevalence": 0.5,
                     "ml_pr_auc_sigma": 0.55, "rank_ndcg": 0.7, "rank_precision": 0.6,
                     "rank_ndcg_random": 0.3, "rank_precision_random": 0.2,
                     "anomaly_flagged": 1.0}.items():
            store.conn.execute(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (run_id, k, float(v)))
        store.conn.execute(
            "INSERT INTO model (name, version, feature_version, calibration) "
            "VALUES (?,?,?,?)",
            ("logistic", 1, 1, json.dumps({"alpha": 0.1, "feature_version": 1,
                                          "t_lo": 0.2, "t_hi": 0.8})))
        store.conn.execute(
            "INSERT INTO model (name, version, feature_version, calibration) "
            "VALUES (?,?,?,?)",
            ("ranker", 1, 1, json.dumps({"at_k": 10})))
        store.conn.commit()   # MetricLogger's flush() needs BEGIN IMMEDIATE, not a
                              # transaction sqlite3's driver already opened implicitly

        with MetricLogger(store, run_id, "logreg") as ml:
            for step, loss in enumerate((0.9, 0.6, 0.4, 0.35), start=1):
                ml.log("train/loss", step, loss)

        # bandit: one arm's posterior (global table) + this run's regret series
        store.conn.execute(
            "INSERT INTO bandit_posteriors (context, arm, alpha, beta, cost_sum, "
            "cost_n) VALUES (?,?,?,?,?,?)",
            ("sql-injection:query", "error-signature", 6.0, 2.0, 12.0, 4))
        for step, regret in enumerate((0.0, 1.0, 1.0, 1.5), start=1):
            log_scalar(store, run_id, "bandit", "regret/cumulative", step, regret)

        # mutation: one recorded (evaded + semantics-preserving) variant
        store.conn.execute(
            "INSERT INTO payload_variant (run_id, vuln_class, base_payload, variant, "
            "operators, sink_context, bypassed_rule, semantics_ok, coverage_gain) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, "sql-injection", "1 union select 1", "1/**/union/**/select 1",
             json.dumps(["comment-split"]), "query", "R-SQLI-UNION", 1, 2.0))
        store.conn.commit()
        with MetricLogger(store, run_id, "mutation") as ml:
            ml.log("reward", 1, 0.6)
            ml.log("novelty", 1, 2.0)

        store.conn.commit()
        return run_id


def test_empty_store_reports_every_family_unavailable(tmp_path):
    ctx = mlview.empty_context()
    assert all(v["available"] is False for v in ctx.values())
    r = _client(tmp_path / "nope.db").get("/ml")
    assert r.status_code == 200
    assert "advisory" in r.text.lower()
    assert r.text.count("unavailable") >= 5 or "No classifier run recorded" in r.text


def test_mlview_reads_seeded_store_directly(tmp_path):
    path = tmp_path / "ml.db"
    run_id = _seed_full(path)
    with Store(path) as store:
        ctx = mlview.ml_context(store)

    clf = ctx["classifier"]
    assert clf["available"] and clf["run_id"] == run_id
    assert clf["pr_auc"] == pytest.approx(0.82)
    assert clf["training_curve"]["values"] == [0.9, 0.6, 0.4, 0.35]
    assert clf["score_label_pairs"] == 2       # both candidates matched to y via evidence

    rk = ctx["ranker"]
    assert rk["available"] and rk["ndcg"] == pytest.approx(0.7)
    assert rk["scored"] == 2

    cf = ctx["conformal"]
    assert cf["available"] and cf["t_lo"] == 0.2 and cf["t_hi"] == 0.8
    # score 0.91 >= t_hi -> flag; score 0.12 <= t_lo -> drop
    assert cf["counts"] == {"flag": 1, "abstain": 0, "drop": 1}

    an = ctx["anomaly"]
    assert an["available"] and an["flagged"] == 1.0 and an["rows"] == 2
    assert an["score_histogram_available"] is False

    al = ctx["active_learning"]
    assert al["available"] and al["committee_available"] is False
    assert len(al["queue"]) == 2
    assert al["queue"][0]["id"] == c2_id(store_path=path)   # highest uncertainty first
    assert al["queue"][0]["uncertainty"] == pytest.approx(0.9)

    bd = ctx["bandit"]
    assert bd["available"]
    arm = bd["arms"][0]
    assert arm["context"] == "sql-injection:query" and arm["pulls"] == 4
    assert arm["mean"] == pytest.approx(0.75)
    assert arm["ci_lo"] < arm["mean"] < arm["ci_hi"]
    assert bd["regret"]["values"] == [0.0, 1.0, 1.0, 1.5]

    mu = ctx["mutation"]
    assert mu["available"] and len(mu["variants"]) == 1
    assert mu["variants"][0]["bypassed_rule"] == "R-SQLI-UNION"
    assert mu["killed_tracked"] is False
    assert mu["reward"]["values"] == [0.6]


def c2_id(store_path):
    # the higher-uncertainty candidate (0.9) is the one the queue should surface first
    with Store(store_path) as store:
        row = store.conn.execute(
            "SELECT id FROM candidate WHERE rank_uncertainty=0.9").fetchone()
        return row["id"]


def test_ml_route_renders_seeded_data_with_advisory_framing(tmp_path):
    path = tmp_path / "ml.db"
    _seed_full(path)
    r = _client(path).get("/ml")
    assert r.status_code == 200
    assert r.template.name == "sections/ml.html"
    assert r.context["active"] == "ml"
    body = r.text
    # advisory banner (persistent, non-dismissible — no dismiss control at all)
    assert "advisory" in body.lower() and "oracle" in body.lower()
    assert 'data-action="dismiss"' not in body
    # verb hygiene: never "detected"/"vulnerable"/"confirmed" for model output
    for bad in ("detected", "confirmed by the model", "vulnerable"):
        assert bad not in body.lower()
    # classifier
    assert "0.820" in body  # pr_auc
    assert "logistic" in body
    # conformal flag/abstain/drop counts, from the seeded scores
    assert "flag (1)" in body and "drop (1)" in body and "abstain (0)" in body
    # bandit forest table + mutation variant table
    assert "sql-injection:query" in body and "error-signature" in body
    assert "R-SQLI-UNION" in body
    # the embedded chart-data blob is valid JSON mirroring mlview's output
    start = body.index('id="ml-data">') + len('id="ml-data">')
    end = body.index("</script>", start)
    blob = json.loads(body[start:end])
    assert blob["classifier"]["available"] is True
    assert blob["bandit"]["arms"][0]["arm"] == "error-signature"


def test_static_ml_assets_are_served():
    client = _client("does-not-exist.db")
    r = client.get("/static/css/ml.css")
    assert r.status_code == 200 and ".ml-banner" in r.text
    r = client.get("/static/js/ml.js")
    assert r.status_code == 200 and "betaPdf" in r.text
    r = client.get("/static/js/charts.js")
    assert r.status_code == 200 and "createChart" in r.text
    r = client.get("/static/js/downsample.js")
    assert r.status_code == 200 and "export function lttb" in r.text
    r = client.get("/static/vendor/uplot/uPlot.esm.js")
    assert r.status_code == 200 and "v1.6.32" in r.text
    r = client.get("/static/vendor/uplot/uPlot.min.css")
    assert r.status_code == 200
