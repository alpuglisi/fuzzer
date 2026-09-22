"""Tests for the automatic-mode pipeline (Phase 2 T2.8 integration)."""

from fuzzlab.audit import InjectionPoint
from fuzzlab.core.runmode import RunPlan
from fuzzlab.core.store import Store
from fuzzlab.harness.pipeline import run_pipeline
from fuzzlab.labels import contract
from fuzzlab.oracle.probe import Probe

GT_DIR = "lab/ground-truth"


class PipelineSender:
    """URL-aware fake: product/blog_post -> SQL error on quotes; search -> reflects.

    Server-level headers (Server, X-Powered-By) are emitted on *every* response,
    as a real PHP/Apache host does, so fingerprinting off any baseline probe works.
    """
    # Global server headers, present on all responses like a real PHP/Apache stack.
    HEADERS = {"Server": "Apache", "X-Powered-By": "PHP/8.3"}

    def send(self, url, param, value, timing=False):
        if "/search.php" in url:
            return Probe(200, f"<html><body>Results for {value}</body></html>",
                         headers=dict(self.HEADERS))
        if "/product.php" in url or "/blog_post.php" in url:
            if "'" in value or '"' in value:
                return Probe(500, "You have an error in your SQL syntax",
                             headers=dict(self.HEADERS))
            return Probe(200, "<html>product page</html>", headers=dict(self.HEADERS))
        return Probe(200, "ok", headers=dict(self.HEADERS))


def _points():
    return [
        InjectionPoint("http://localhost/product.php", "id", "GET", "query"),
        InjectionPoint("http://localhost/search.php", "q", "GET", "query", sink_context="html"),
        InjectionPoint("http://localhost/blog_post.php", "id", "GET", "query"),
    ]


def test_run_pipeline_scored_end_to_end(tmp_path):
    gt = contract.load(GT_DIR)
    plan = RunPlan("automatic", ["sql-injection", "xss"], scored=True, source="ground-truth")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("pipeline", "h")
        result = run_pipeline(_points(), store, run_id, PipelineSender(), plan,
                              ground_truth=gt)

        assert result.negatives > 0                    # negatives are logged (T2.3)
        assert result.findings == 3                    # product sqli, blog_post sqli, search xss
        # Findings are the oracle's, scored by the harness.
        assert result.report is not None and result.report.tp >= 3 and result.report.fp == 0
        keys = {(d["url"], d["param"], d["vuln_class"]) for d in [
            {"url": r["url"], "param": r["param"], "vuln_class": r["vuln_class"]}
            for r in store.conn.execute(
                "SELECT url, param, vuln_class FROM finding WHERE run_id=?", (run_id,))]}
        assert ("/product.php", "id", "sqli") in keys
        assert ("/search.php", "q", "xss-reflected") in keys
        # Fingerprint recorded a target row.
        target = store.conn.execute(
            "SELECT framework FROM target WHERE run_id=?", (run_id,)).fetchone()
        assert target["framework"] == "PHP/8.3"
        # Pipeline metrics recorded.
        metrics = {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,))}
        assert metrics["pipeline_findings"] == 3.0
        assert metrics["pipeline_scored"] == 1.0
        # The same baseline probe also feeds the richer multi-technology signal set
        # (no extra request) — at least the PHP/Apache signals from every response's
        # shared headers should have landed.
        signals = {(r["category"], r["name"]) for r in store.conn.execute(
            "SELECT category, name FROM fingerprint_signal WHERE run_id=?", (run_id,))}
        assert ("language", "PHP") in signals
        assert ("server", "Apache") in signals


def test_run_pipeline_records_technology_signal_evidence_and_confidence(tmp_path):
    gt = contract.load(GT_DIR)
    plan = RunPlan("automatic", ["sql-injection", "xss"], scored=True, source="ground-truth")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("pipeline", "h")
        run_pipeline(_points(), store, run_id, PipelineSender(), plan, ground_truth=gt)

        row = store.conn.execute(
            "SELECT version, confidence, evidence, source_url FROM fingerprint_signal "
            "WHERE run_id=? AND category='language' AND name='PHP'", (run_id,)
        ).fetchone()
        assert row is not None
        assert row["version"] == "8.3"
        assert 0.0 < row["confidence"] <= 1.0
        assert "x-powered-by" in row["evidence"].lower()
        assert row["source_url"] == "http://localhost/product.php"


def test_pipeline_unscored_when_plan_unscored(tmp_path):
    plan = RunPlan("automatic", ["sql-injection"], scored=False, source="user")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("pipeline", "h")
        result = run_pipeline(_points(), store, run_id, PipelineSender(), plan)
        assert result.report is None                   # D15: unscored
        assert result.findings >= 2                    # SQLi still confirmed
        # only the sql-injection category ran (xss scoped out)
        cats = {r["category"] for r in store.conn.execute(
            "SELECT DISTINCT category FROM evaluation WHERE run_id=?", (run_id,))}
        assert cats == {"sql-injection"}


def test_pipeline_dedup_collapses_same_template(tmp_path):
    # Two product URLs with an identical DOM skeleton -> audited once.
    skeleton = "<html><body><h1>x</h1><p>y</p><span>z</span></body></html>"
    points = [
        InjectionPoint("http://localhost/product.php?id=1", "id", "GET", "query"),
        InjectionPoint("http://localhost/product.php?id=2", "id", "GET", "query"),
    ]
    pages = {p.url: skeleton for p in points}
    plan = RunPlan("automatic", ["sql-injection"], scored=False, source="user")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("pipeline", "h")
        result = run_pipeline(points, store, run_id, PipelineSender(), plan,
                              pages_html=pages)
        assert result.points_audited == 1             # deduped to one representative
