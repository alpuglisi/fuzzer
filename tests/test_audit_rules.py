"""Tests for rules-as-data + full evaluation logging (Phase 2 T2.3)."""

from fuzzlab.audit import InjectionPoint, evaluate, load_rules, matches
from fuzzlab.core.store import Store


def test_rules_load_as_data():
    rules = load_rules()
    assert len(rules) >= 6
    ids = {r.id for r in rules}
    assert {"R-SQLI-PARAM", "R-XSS-REFLECT", "R-OPEN-REDIRECT"} <= ids
    # rules are data: category + declarative predicate, no code
    sqli = next(r for r in rules if r.id == "R-SQLI-PARAM")
    assert sqli.category == "sql-injection" and "location_in" in sqli.when


def test_matches_predicate():
    rules = {r.id: r for r in load_rules()}
    q = InjectionPoint(url="/p.php", param="id", location="query")
    assert matches(rules["R-SQLI-PARAM"], q)                 # any query param
    assert not matches(rules["R-XSS-REFLECT"], q)            # no sink context
    redir = InjectionPoint(url="/go.php", param="returnUrl", location="query")
    assert matches(rules["R-OPEN-REDIRECT"], redir)
    html = InjectionPoint(url="/s.php", param="q", location="query", sink_context="html")
    assert matches(rules["R-XSS-REFLECT"], html)
    assert matches(rules["R-SSTI"], html)


def test_evaluate_logs_negatives_and_candidates(tmp_path):
    points = [
        InjectionPoint(url="/product.php", param="id", location="query"),
        InjectionPoint(url="/search.php", param="q", location="query", sink_context="html"),
        InjectionPoint(url="/go.php", param="returnUrl", location="query"),
    ]
    rules = load_rules()
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("audit", "h")
        counts = evaluate(points, store, run_id, rules=rules)

        # Every (point, rule) pair is recorded.
        assert counts["evaluation"] == len(points) * len(rules)
        assert counts["candidate"] + counts["negative"] == counts["evaluation"]
        # There ARE negatives in the store (the point of T2.3).
        assert counts["negative"] > 0
        neg = store.conn.execute(
            "SELECT COUNT(*) c FROM evaluation WHERE fired=0").fetchone()["c"]
        assert neg == counts["negative"] and neg > 0
        # Fired evaluations produced candidate rows.
        cand = store.conn.execute("SELECT COUNT(*) c FROM candidate").fetchone()["c"]
        assert cand == counts["candidate"]
        # product.php?id fired SQLi (a positive), and it also has SSTI/XSS negatives.
        rows = store.conn.execute(
            "SELECT rule_id, fired FROM evaluation WHERE url='/product.php'").fetchall()
        outcomes = {r["rule_id"]: r["fired"] for r in rows}
        assert outcomes["R-SQLI-PARAM"] == 1
        assert outcomes["R-XSS-REFLECT"] == 0                # no sink context -> negative


def test_evaluate_category_filter_scopes_rules(tmp_path):
    points = [InjectionPoint(url="/p.php", param="id", location="query")]
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("audit", "h")
        counts = evaluate(points, store, run_id, categories=["sql-injection"])
        # Only the SQLi rule ran (category selection hook, D14/T2.9).
        assert counts["evaluation"] == 1
        assert store.conn.execute(
            "SELECT DISTINCT category FROM evaluation").fetchone()["category"] == "sql-injection"
