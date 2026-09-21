"""Tests for the automatic-mode entry point (Phase 2 T2.8 live glue)."""

import pytest

from fuzzlab.core.runmode import RunModeError
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import (
    injection_points_from_store,
    points_from_ground_truth,
    run_auto,
)
from fuzzlab.labels import contract
from fuzzlab.oracle.probe import Probe

GT_DIR = "lab/ground-truth"


class AutoSender:
    """URL-aware fake: product/blog_post SQL-error on quotes; search reflects.

    Accepts method/location (POST body points are now audited) — this fake treats
    them all the same, so POST controls simply don't confirm (as they should).
    """
    HEADERS = {"Server": "Apache", "X-Powered-By": "PHP/8.3"}

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        if "/search.php" in url:
            return Probe(200, f"<html><body>Results for {value}</body></html>",
                         headers=dict(self.HEADERS))
        if "/product.php" in url or "/blog_post.php" in url:
            if "'" in value or '"' in value:
                return Probe(500, "You have an error in your SQL syntax",
                             headers=dict(self.HEADERS))
            return Probe(200, "<html>product</html>", headers=dict(self.HEADERS))
        return Probe(200, "ok", headers=dict(self.HEADERS))


def _seed_crawl(store, run_id):
    """Insert endpoint/parameter rows as a crawl+import would (path-form URLs)."""
    def ep(path):
        cur = store.conn.execute(
            "INSERT INTO endpoint (run_id, url, method, source) VALUES (?,?,?,?)",
            (run_id, path, "GET", "link"))
        return cur.lastrowid

    for path, param in [("/product.php", "id"), ("/search.php", "q"),
                        ("/blog_post.php", "id")]:
        eid = ep(path)
        store.conn.execute(
            "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
            "VALUES (?,?,?,?,?)", (run_id, eid, param, "query", "1"))
    store.conn.commit()


def test_injection_points_use_full_url_no_query(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        points = injection_points_from_store(store, run_id, "http://127.0.0.1:8080/")
        urls = {(p.url, p.param) for p in points}
        assert ("http://127.0.0.1:8080/product.php", "id") in urls
        assert ("http://127.0.0.1:8080/search.php", "q") in urls
        assert all("?" not in p.url for p in points)     # sender adds the query


def test_run_auto_scored_against_ground_truth(tmp_path):
    gt = contract.load(GT_DIR)
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        result = run_auto(base_url="http://localhost", store=store, run_id=run_id,
                          sender=AutoSender(), mode="automatic", ground_truth=gt,
                          points_source="crawl")
        # D14: categories derived from ground truth; scored.
        assert result.plan.scored is True and result.plan.source == "ground-truth"
        assert result.metrics["points_source"] == "crawl"
        assert result.findings >= 2 and result.report is not None
        assert result.report.tp >= 2 and result.report.fp == 0
        # Request cost was measured (counting sender wired as the budget).
        assert result.metrics["requests"] > 0
        assert result.negatives > 0                       # negatives logged


def test_points_from_ground_truth_filters_to_testable():
    gt = contract.load(GT_DIR)
    points, skipped = points_from_ground_truth(gt, "http://127.0.0.1:8080")
    tested = {(p.url, p.param, p.method) for p in points}
    # GET/query AND POST/body, server-rendered points are audited...
    assert ("http://127.0.0.1:8080/product.php", "id", "GET") in tested
    assert ("http://127.0.0.1:8080/search.php", "q", "GET") in tested
    assert ("http://127.0.0.1:8080/login.php", "username", "POST") in tested   # POST body
    # ...only client-only/DOM (fragment / js) points are skipped, needing M6.
    skipped_keys = {(path, param) for path, _m, param, _r in skipped}
    assert ("/reviews.php", "author") in skipped_keys        # fragment / DOM
    assert ("/feedback.php", "ref") in skipped_keys          # client-only DOM
    assert ("/login.php", "username") not in skipped_keys    # now testable via POST
    assert all("?" not in p.url for p in points)
    assert all(r.endswith("M6)") for _p, _m, _pm, r in skipped)   # only DOM gaps remain


def test_run_auto_ground_truth_points_beats_crawl_coverage(tmp_path):
    gt = contract.load(GT_DIR)
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)   # only 3 crawl points
        result = run_auto(base_url="http://localhost", store=store, run_id=run_id,
                          sender=AutoSender(), mode="automatic", ground_truth=gt,
                          points_source="ground-truth")
        assert result.metrics["points_source"] == "ground-truth"
        # Audits the enumerated GET/query points (more than the 3 crawl points).
        assert result.points_audited > 3
        assert result.report is not None and result.report.fp == 0
        assert result.report.tp >= 3          # product/blog SQLi + search XSS at least
        assert result.metrics["skipped_points"]   # POST/DOM gaps reported


class _RecordingSender:
    """Records transport used; SQL error on a quote regardless of method."""
    def __init__(self):
        self.calls = []

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        self.calls.append((method, location))
        if "'" in value or '"' in value:
            return Probe(500, "You have an error in your SQL syntax", headers={})
        return Probe(200, "ok", headers={})


def test_post_body_candidate_probed_via_post():
    from fuzzlab.oracle import Candidate, Oracle
    sender = _RecordingSender()
    verdict = Oracle().confirm(
        Candidate(url="http://h/login.php", param="username", method="POST",
                  location="body", vuln_class="sqli"), sender)
    assert verdict is not None and verdict.confirmed
    assert sender.calls and all(m == "POST" and loc == "body" for m, loc in sender.calls)


def test_run_auto_with_browser_confirms_dom_points(tmp_path):
    from fuzzlab.oracle.browser import FakeBrowserExecutor
    gt = contract.load(GT_DIR)
    # Live-like fake: only the genuinely client-vulnerable DOM pages "execute".
    browser = FakeBrowserExecutor(
        vulnerable=lambda req: "/reviews.php" in req.url or "/feedback.php" in req.url)
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        result = run_auto(base_url="http://localhost", store=store, run_id=run_id,
                          sender=AutoSender(), mode="automatic", ground_truth=gt,
                          points_source="ground-truth", browser=browser)
        # DOM points are now audited (not skipped) and confirmed as xss-dom.
        assert result.metrics["skipped_points"] == []
        assert result.report is not None and result.report.fp == 0
        classes = {r["vuln_class"] for r in store.conn.execute(
            "SELECT vuln_class FROM finding WHERE run_id=?", (run_id,))}
        assert "xss-dom" in classes                       # M6 confirmed the DOM XSS


def test_run_auto_no_ground_truth_requires_categories(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        # D15 fail-safe: automatic + no ground truth + no selection -> loud failure.
        with pytest.raises(RunModeError):
            run_auto(base_url="http://localhost", store=store, run_id=run_id,
                     sender=AutoSender(), mode="automatic", ground_truth=None)


def test_run_auto_no_ground_truth_unscored_with_categories(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        result = run_auto(base_url="http://localhost", store=store, run_id=run_id,
                          sender=AutoSender(), mode="automatic", ground_truth=None,
                          selected_categories=["sql-injection"])
        assert result.report is None                      # D15: unscored
        assert result.plan.categories == ["sql-injection"]
        assert result.findings >= 1                       # SQLi still confirmed
