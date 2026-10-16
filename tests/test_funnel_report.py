"""`scripts/funnel_report.py`: where each answer-key case is lost (goal metric, BUG-0141
recurrence of 2026-10-15). Offline, on a synthetic store."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from fuzzlab.core.store import Store

ROOT = Path(__file__).resolve().parent.parent
GT = ROOT / "lab" / "ground-truth-juice-shop"


def _funnel():
    spec = importlib.util.spec_from_file_location("funnel_report",
                                                  ROOT / "scripts" / "funnel_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.funnel


def test_each_case_reports_the_furthest_stage_and_confirmation_is_class_aware(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        c = store.conn
        ep = c.execute("INSERT INTO endpoint (run_id, url, method, source) VALUES (?,?,?,?)",
                       (run, "http://127.0.0.1:3000/profile", "POST", "crawl")).lastrowid
        c.execute("INSERT INTO parameter (run_id, endpoint_id, name, location) "
                  "VALUES (?,?,?,?)", (run, ep, "username", "body"))
        c.execute("INSERT INTO candidate (run_id, rule, evidence) VALUES (?,?,?)",
                  (run, "SSTI", json.dumps({"url": "http://127.0.0.1:3000/profile",
                                            "param": "username",
                                            "category": "server-side-template-injection"})))
        c.execute("INSERT INTO finding (run_id, vuln_class, label, url, method, param) "
                  "VALUES (?,?,?,?,?,?)", (run, "ssti", 1, "/profile", "POST", "username"))
        c.commit()
    rows = {r["case"]: r["stage"] for r in _funnel()(str(tmp_path / "u.db"), str(GT))}
    assert rows["JUICE-0006"] == "confirmed"          # ssti on /profile username
    assert rows["JUICE-0008"] == "reached"            # same input, stored XSS: not confirmed
    assert rows["JUICE-0009"] == "not reached"


def _store(tmp_path, rows, candidates=()):
    """A store with ``rows`` of (url, method, param, location) points and candidates of
    (evidence dict), in a fresh directory under ``tmp_path``."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        c = store.conn
        for url, method, name, location in rows:
            ep = c.execute("INSERT INTO endpoint (run_id, url, method, source) "
                           "VALUES (?,?,?,?)", (run, url, method, "crawl")).lastrowid
            c.execute("INSERT INTO parameter (run_id, endpoint_id, name, location) "
                      "VALUES (?,?,?,?)", (run, ep, name, location))
        for ev in candidates:
            c.execute("INSERT INTO candidate (run_id, rule, evidence) VALUES (?,?,?)",
                      (run, "R", json.dumps(ev)))
        c.commit()
    return {r["case"]: r for r in _funnel()(str(tmp_path / "s.db"), str(GT))}


def test_a_point_on_another_method_or_location_never_reaches_a_case(tmp_path):
    """JUICE-0003 is POST body /rest/user/login email. Before 2026-10-16 the funnel was
    method-insensitive, so a GET or query point with that name 'reached' it."""
    login = "http://127.0.0.1:3000/rest/user/login"
    rows = _store(tmp_path, [(login, "GET", "email", "query")])
    assert rows["JUICE-0003"]["stage"] == "not reached"
    rows = _store(tmp_path / "b", [(login, "POST", "email", "query")])
    assert rows["JUICE-0003"]["stage"] == "not reached"


def test_a_json_body_field_reaches_a_body_case_exactly(tmp_path):
    rows = _store(tmp_path, [("http://127.0.0.1:3000/rest/user/login", "POST", "email",
                              "json")])
    assert rows["JUICE-0003"]["stage"] == "reached"
    assert rows["JUICE-0003"]["attribution"] == "exact"


def test_a_record_without_method_or_location_matches_only_partially(tmp_path):
    rows = _store(tmp_path, [], candidates=[
        {"url": "http://127.0.0.1:3000/rest/products/search", "param": "q",
         "category": "sql-injection"}])
    assert rows["JUICE-0002"]["stage"] == "candidate"
    assert rows["JUICE-0002"]["attribution"] == "partial"
    rows = _store(tmp_path / "c", [], candidates=[
        {"url": "http://127.0.0.1:3000/rest/products/search", "param": "q",
         "category": "sql-injection", "method": "POST", "location": "body"}])
    assert rows["JUICE-0002"]["stage"] == "not reached"   # a known method disagrees


def test_a_finding_takes_its_location_from_the_one_matching_candidate(tmp_path):
    """A finding row has no location; the run's candidate of its class for the same
    input supplies it. Two candidate locations for one input leave it partial."""
    url = "http://127.0.0.1:3000/rest/products/search"

    def run(locations, sub):
        d = tmp_path / sub
        d.mkdir()
        with Store(d / "s.db") as store:
            rid = store.start_run("auto", "h")
            for loc in locations:
                store.conn.execute("INSERT INTO candidate (run_id, rule, evidence) "
                                   "VALUES (?,?,?)", (rid, "R", json.dumps(
                                       {"url": url, "param": "q", "method": "GET",
                                        "location": loc, "category": "sql-injection"})))
            store.conn.execute("INSERT INTO finding (run_id, vuln_class, label, url, method, "
                               "param) VALUES (?,?,?,?,?,?)",
                               (rid, "sqli", 1, "/rest/products/search", "GET", "q"))
            store.conn.commit()
        return {r["case"]: r for r in _funnel()(str(d / "s.db"), str(GT))}["JUICE-0002"]

    one = run(["query"], "one")
    assert (one["stage"], one["attribution"]) == ("confirmed", "exact")
    two = run(["query", "header"], "two")
    assert (two["stage"], two["attribution"]) == ("confirmed", "partial")
