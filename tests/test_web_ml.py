"""Tests for the ML tab (U4/CC-UI-0031, CC-ML-0010): read-only, advisory (R-06).

Covers the pure ``mlview`` functions (module-level, no FastAPI needed), the
``/api/ml/data`` read route, the ``/ml`` page's advisory framing, and the new static
assets (vendored uPlot, the shared `chart.js` wrapper, `ml.js`/`ml.css`).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web import mlview  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from tests._webclient import web_client  # noqa: E402


def _seed_candidate(store, run_id, *, param, category, score=None, rank_score=None,
                    rank_uncertainty=None, positive=False, url="/product.php"):
    evidence = json.dumps({"url": url, "param": param, "category": category,
                           "method": "GET", "location": "query"})
    cur = store.conn.execute(
        "INSERT INTO candidate (run_id, evidence, score, rank_score, rank_uncertainty, "
        "sink_context) VALUES (?,?,?,?,?,?)",
        (run_id, evidence, score, rank_score, rank_uncertainty, "sql" if category == "sql-injection" else None))
    cid = cur.lastrowid
    if positive:
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, url, method, param) "
            "VALUES (?,?,1,?,?,?)", (run_id, category, url, "GET", param))
    return cid


def _seed(path, *, n=14):
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        cats = ["sql-injection", "xss"]
        for i in range(n):
            positive = i % 4 == 0        # a quarter confirmed
            score = round(0.15 + 0.7 * (i / n), 4)
            rank_score = round(1.0 - i / n, 4)
            rank_unc = round(abs(0.5 - i / n), 4)
            _seed_candidate(store, run_id, param=f"p{i}", category=cats[i % 2],
                           score=score, rank_score=rank_score, rank_uncertainty=rank_unc,
                           positive=positive, url=f"/e{i % 3}.php")
        # a trained model row with a conformal calibration (mirrors train.py's write)
        store.conn.execute(
            "INSERT INTO model (name, version, feature_version, calibration) VALUES (?,?,?,?)",
            ("logistic", 1, 1, json.dumps({"alpha": 0.1, "t_lo": 0.3, "t_hi": 0.7})))
        # bandit posteriors (two arms)
        store.conn.execute(
            "INSERT INTO bandit_posteriors (context, arm, alpha, beta, cost_sum, cost_n) "
            "VALUES (?,?,?,?,?,?)", ("sqli", "boolean-blind", 12.0, 4.0, 30.0, 10))
        store.conn.execute(
            "INSERT INTO bandit_posteriors (context, arm, alpha, beta, cost_sum, cost_n) "
            "VALUES (?,?,?,?,?,?)", ("sqli", "time-blind", 3.0, 9.0, 40.0, 8))
        # mutation variants (one survived, one killed)
        store.conn.execute(
            "INSERT INTO payload_variant (run_id, vuln_class, base_payload, variant, "
            "operators, bypassed_rule, semantics_ok, coverage_gain) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "sqli", "' OR 1=1--", "' /*!OR*/ 1=1--", json.dumps(["comment-inline"]),
             "R-SQLI-1", 1, 0.02))
        store.conn.execute(
            "INSERT INTO payload_variant (run_id, vuln_class, base_payload, variant, "
            "operators, bypassed_rule, semantics_ok, coverage_gain) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "sqli", "' OR 1=1--", "' OR 1=1--garbled", json.dumps(["noise"]),
             None, 0, None))
        store.conn.commit()
        return run_id


def _client(path):
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    return web_client(create_app(cfg))


# --- mlview: pure, read-only functions ------------------------------------------

def test_classifier_panel_from_seeded_store(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    with Store(path) as store:
        panel = mlview.classifier_panel(store)
    assert panel["available"] is True
    assert panel["n"] > 0
    assert 0.0 <= panel["pr_auc"] <= 1.0
    assert panel["reliability"]["ece"] >= 0.0
    assert panel["pr_curve"]  # non-empty since positives exist


def test_ranker_panel_from_seeded_store(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    with Store(path) as store:
        panel = mlview.ranker_panel(store, k=5)
    assert panel["available"] is True
    assert panel["score_hist"]["counts"]
    assert panel["uncertainty_hist"]["counts"]
    assert len(panel["scatter"]) == panel["n"]


def test_conformal_panel_splits_flag_abstain_drop(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    with Store(path) as store:
        panel = mlview.conformal_panel(store)
    assert panel["available"] is True
    assert panel["counts"]["flag"] + panel["counts"]["abstain"] + panel["counts"]["drop"] == panel["n"]
    assert panel["t_lo"] == 0.3 and panel["t_hi"] == 0.7


def test_anomaly_panel_is_read_only(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    with Store(path) as store:
        before = store.conn.execute("SELECT COUNT(*) c FROM run_metrics").fetchone()["c"]
        panel = mlview.anomaly_panel(store)
        after = store.conn.execute("SELECT COUNT(*) c FROM run_metrics").fetchone()["c"]
    assert panel["available"] is True
    assert 0 <= panel["flagged"] <= panel["n"]
    # unlike fuzzlab.ml.anomaly.detect_anomalies, the read-only panel writes nothing
    assert before == after


def test_disagreement_panel_from_seeded_store(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path, n=14)
    with Store(path) as store:
        panel = mlview.disagreement_panel(store, n_members=3)
    assert panel["available"] is True
    assert panel["n"] == 14
    assert len(panel["queue"]) <= 10


def test_bandit_panel_beta_posteriors(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    with Store(path) as store:
        panel = mlview.bandit_panel(store)
    assert panel["available"] is True
    arms = {a["arm"]: a for a in panel["arms"]}
    assert "boolean-blind" in arms and "time-blind" in arms
    hi_mean_arm = arms["boolean-blind"]      # alpha=12, beta=4 -> higher mean
    lo_mean_arm = arms["time-blind"]         # alpha=3, beta=9 -> lower mean
    assert hi_mean_arm["mean"] > lo_mean_arm["mean"]
    assert hi_mean_arm["ci_low"] < hi_mean_arm["mean"] < hi_mean_arm["ci_high"]
    assert len(hi_mean_arm["density"]["x"]) == len(hi_mean_arm["density"]["y"]) == 200
    assert hi_mean_arm["pulls"] == 14  # alpha+beta-2 = 12+4-2


def test_mutation_panel_killed_survived(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    with Store(path) as store:
        panel = mlview.mutation_panel(store)
    assert panel["available"] is True
    assert panel["survived"] == 1 and panel["killed"] == 1
    statuses = {v["status"] for v in panel["variants"]}
    assert statuses == {"survived", "killed"}


def test_ml_overview_degrades_gracefully_on_empty_store(tmp_path):
    path = tmp_path / "empty.db"
    with Store(path):
        pass
    with Store(path) as store:
        overview = mlview.ml_overview(store)
    for key in ("classifier", "ranker", "conformal", "anomaly", "disagreement", "bandit", "mutation"):
        assert overview[key]["available"] is False
        assert "reason" in overview[key]


# --- /api/ml/data route ----------------------------------------------------------

def test_api_ml_data_seeded(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    r = _client(path).get("/api/ml/data")
    assert r.status_code == 200
    data = r.json()
    assert data["available_any"] is True
    assert data["classifier"]["available"] is True
    assert data["bandit"]["available"] is True


def test_api_ml_data_no_store_is_empty_not_error(tmp_path):
    path = tmp_path / "missing.db"
    r = _client(path).get("/api/ml/data")
    assert r.status_code == 200
    assert r.json()["available_any"] is False


# --- /ml page: advisory framing (R-06), reads only ------------------------------

_FORBIDDEN_VERBS = ("detected a", "is vulnerable", "confirmed vulnerability")


def test_ml_page_has_persistent_advisory_banner(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    body = _client(path).get("/ml").text
    assert "advisory" in body.lower()
    normalized = " ".join(body.lower().split())
    assert "confirmed findings come from the oracle" in normalized
    # non-dismissible: no close/dismiss control on the banner card
    banner_start = body.index('class="card ml-banner"')
    banner_end = body.index("</div>", banner_start)
    banner_html = body[banner_start:banner_end]
    assert "dismiss" not in banner_html.lower() and "close" not in banner_html.lower()


def test_ml_page_avoids_oracle_verbs():
    from pathlib import Path
    here = Path(__file__).resolve().parents[1]
    html = (here / "fuzzlab/web/templates/sections/ml.html").read_text().lower()
    js = (here / "fuzzlab/web/static/js/ml.js").read_text().lower()
    for phrase in _FORBIDDEN_VERBS:
        assert phrase not in html
        assert phrase not in js


def test_ml_page_references_uplot_and_shared_chart_module():
    path_html = "fuzzlab/web/templates/sections/ml.html"
    from pathlib import Path
    here = Path(__file__).resolve().parents[1]
    html = (here / path_html).read_text()
    assert "/static/vendor/uplot/uPlot.min.css" in html
    assert "/static/js/ml.js" in html
    ml_js = (here / "fuzzlab/web/static/js/ml.js").read_text()
    assert 'from "/static/js/chart.js"' in ml_js
    chart_js = (here / "fuzzlab/web/static/js/chart.js").read_text()
    assert 'from "/static/vendor/uplot/uPlot.esm.js"' in chart_js
    assert "window.__charts" in chart_js


def test_ml_page_renders_from_seeded_store_route(tmp_path):
    path = tmp_path / "ml.db"
    _seed(path)
    body = _client(path).get("/ml").text
    # server-rendered shell (client JS fills panels from /api/ml/data); mount points present
    for mount in ("panel-conformal", "panel-calibration", "panel-ranker", "panel-anomaly",
                 "panel-disagreement", "panel-bandit", "panel-mutation"):
        assert f'id="{mount}"' in body


# --- static assets -----------------------------------------------------------

def test_vendored_uplot_files_served():
    c = _client("nonexistent.db")
    css = c.get("/static/vendor/uplot/uPlot.min.css")
    js = c.get("/static/vendor/uplot/uPlot.esm.js")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]
    assert js.status_code == 200
    assert "uPlot" in js.text


def test_chart_js_and_ml_assets_served():
    c = _client("nonexistent.db")
    for path in ("/static/js/chart.js", "/static/js/ml.js", "/static/css/ml.css"):
        r = c.get(path)
        assert r.status_code == 200, path


def test_chart_height_token_declared():
    c = _client("nonexistent.db")
    r = c.get("/static/tokens.css")
    assert "--chart-h" in r.text
