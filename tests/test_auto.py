"""Tests for the automatic-mode entry point (Phase 2 T2.8 live glue)."""

import pytest

from fuzzlab.core.runmode import RunModeError
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import (
    _CountingSender,
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


def test_points_from_ground_truth_now_includes_header_points():
    # CC-FUZZ-0028/FR-FUZZ-15: a header-carried point (Twitch's webhook-signature
    # case, location="header") is now a real, audited point -- FR-FUZZ-13's own
    # gap (no header-injection point/sender convention) is closed, so it no
    # longer needs a distinct skip reason at all.
    gt = contract.load("lab/ground-truth-twitch-clone")
    points, skipped = points_from_ground_truth(gt, "http://127.0.0.1:8080")

    tested = {(p.url, p.param, p.method, p.location) for p in points}
    assert ("http://127.0.0.1:8080/generated/labgen-go-0003", "url", "GET", "query") in tested
    assert ("http://127.0.0.1:8080/generated/labgen-go-0001", "X-Signature-256",
            "POST", "header") in tested

    skipped_by_param = {param: reason for _p, _m, param, reason in skipped}
    assert "X-Signature-256" not in skipped_by_param   # no longer skipped


def test_points_from_ground_truth_sets_body_content_type_only_for_json_cases():
    # CC-FUZZ-0028/FR-FUZZ-15: a whole-body point (`param="body"`) only gets a
    # declared `body_content_type` when the ground truth marks it
    # `rendering="server-json"` -- never assumed for a body point in general
    # (e.g. TrackerNest's XXE/insecure-deserialization cases stay `None`,
    # unaffected -- checked directly here since a wrong assumption would be a
    # silent false-negative risk the moment those categories get a rule).
    netflix_gt = contract.load("lab/ground-truth-netflix-clone")
    points, _ = points_from_ground_truth(netflix_gt, "http://127.0.0.1:8080")
    (body_point,) = [p for p in points if p.param == "body"]
    assert body_point.body_content_type == "application/json"

    trackernest_gt = contract.load("lab/ground-truth-trackernest")
    points, _ = points_from_ground_truth(trackernest_gt, "http://127.0.0.1:8080")
    body_points = [p for p in points if p.param == "body"]
    assert len(body_points) == 2   # the XXE and insecure-deserialization cases
    assert all(p.body_content_type is None for p in body_points)


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


def test_run_auto_stored_xss_with_browser(tmp_path):
    from fuzzlab.oracle.browser import FakeBrowserExecutor
    gt = contract.load(GT_DIR)
    # Fire only for the stored flow: a store step, observed on the render page.
    browser = FakeBrowserExecutor(
        vulnerable=lambda req: req.store is not None and "/profile.php" in req.url)
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        result = run_auto(base_url="http://localhost", store=store, run_id=run_id,
                          sender=AutoSender(), mode="automatic", ground_truth=gt,
                          points_source="ground-truth", browser=browser)
        row = store.conn.execute(
            "SELECT url, param, method FROM finding "
            "WHERE vuln_class='xss-stored' AND run_id=?", (run_id,)).fetchone()
        assert row is not None                            # stored XSS auto-wired + confirmed
        assert row["url"] == "/profile.php" and row["param"] == "bio"
        assert result.report is not None and result.report.fp == 0


def test_points_from_ground_truth_stored_needs_browser():
    gt = contract.load(GT_DIR)
    # No browser: the stored observe point is reported as a skipped gap, not audited.
    points, skipped = points_from_ground_truth(gt, "http://h", browser_available=False)
    assert ("/profile.php", "bio") in {(p, pm) for p, _m, pm, _r in skipped}
    assert not any(p.url.endswith("/profile.php") for p in points)
    # With a browser: it is audited (a point carrying the store endpoint).
    points, _ = points_from_ground_truth(gt, "http://h", browser_available=True)
    stored = [p for p in points if p.url.endswith("/profile.php")]
    assert stored and stored[0].store_url == "http://h/edit_profile.php"


def test_run_auto_with_bandit_learns_and_persists(tmp_path):
    from fuzzlab.oracle.strategies import default_strategies
    from fuzzlab.scheduler import ThompsonBandit, arm_priors
    gt = contract.load(GT_DIR)
    bandit = ThompsonBandit(priors=arm_priors(default_strategies()))
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        run_auto(base_url="http://localhost", store=store, run_id=run_id,
                 sender=AutoSender(), mode="automatic", ground_truth=gt,
                 points_source="crawl", scheduler=bandit)
        # The oracle consulted + updated the bandit; posteriors persist to the store.
        assert bandit.mean("sql-injection:query", "sqli:error-signature") != 0.5
        bandit.save(store)
        n = store.conn.execute("SELECT COUNT(*) c FROM bandit_posteriors").fetchone()["c"]
        assert n > 0


def test_run_auto_with_bandit_emits_metric_series(tmp_path):
    """CC-SCHED-0005: with a MetricLogger attached (the `fuzzlab auto --bandit` wiring
    in auto_cli.py), each bandit pull made while confirming candidates in a real
    run_auto() pass lands regret/cumulative + posterior/arm_<N>/mean rows in
    metric_series under source="bandit"."""
    from fuzzlab.core.store import MetricLogger
    from fuzzlab.oracle.strategies import default_strategies
    from fuzzlab.scheduler import ThompsonBandit, arm_priors

    gt = contract.load(GT_DIR)
    bandit = ThompsonBandit(priors=arm_priors(default_strategies()))
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        _seed_crawl(store, run_id)
        bandit.attach_metrics(MetricLogger(store, run_id, "bandit", flush_every=200))
        run_auto(base_url="http://localhost", store=store, run_id=run_id,
                 sender=AutoSender(), mode="automatic", ground_truth=gt,
                 points_source="crawl", scheduler=bandit)
        bandit.flush_metrics()

        rows = store.conn.execute(
            "SELECT source, key FROM metric_series WHERE run_id=?", (run_id,)).fetchall()

    assert rows                                           # at least one bandit pull happened
    assert all(r["source"] == "bandit" for r in rows)
    keys = {r["key"] for r in rows}
    assert "regret/cumulative" in keys
    assert any(k.startswith("posterior/arm_") and k.endswith("/mean") for k in keys)


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


def test_counting_sender_forwards_content_type():
    # CC-FUZZ-0028/FR-FUZZ-15: a real bug found while wiring this in --
    # _CountingSender's own send() dropped `content_type` silently (it wasn't
    # even in its signature), which would have made every whole-body-JSON
    # point revert to form-encoding the moment it passed through run_auto's
    # real pipeline (every sender is wrapped in this counter). Fixed before
    # it could ever fire for real; this test pins the fix directly.
    calls = []

    class _Recorder:
        def send(self, url, param, value, timing=False, method="GET",
                 location="query", content_type=None):
            calls.append({"method": method, "location": location, "content_type": content_type})
            return Probe(200, "ok")

    counting = _CountingSender(_Recorder())
    counting.send("http://h/api/playback/resume", "body", '{"a":1}',
                  method="POST", location="body", content_type="application/json")
    assert calls == [{"method": "POST", "location": "body", "content_type": "application/json"}]
    assert counting.count == 1
