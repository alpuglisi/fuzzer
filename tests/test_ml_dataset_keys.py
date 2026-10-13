"""Dataset label and seen-key joins use every identity field both sides record — the HTTP
method included (BUG-0075, PA-0076)."""

from __future__ import annotations

import json

from fuzzlab.core.store import Store
from fuzzlab.ml.dataset import build_dataset, candidate_keys, method_key, seen_fraction

URL = "http://127.0.0.1:8080/search"


def _candidate(store, run_id, method, location="query"):
    ev = {"url": URL, "param": "q", "category": "sql-injection", "location": location}
    if method is not None:
        ev["method"] = method
    cur = store.conn.execute("INSERT INTO candidate (run_id, rule, evidence, oracle_status) "
                             "VALUES (?,?,?,'checked')", (run_id, "x", json.dumps(ev)))
    return cur.lastrowid


def _finding(store, run_id, method):
    store.conn.execute(
        "INSERT INTO finding (run_id, vuln_class, label, confidence, url, method, param) "
        "VALUES (?,?,1,?,?,?,?)", (run_id, "sqli", "error-signature", "/search", method, "q"))


def _labels(store, run_id):
    ds = build_dataset(store, run_id)
    return dict(zip(ds.ids, ds.y))


def test_method_key_normalises_both_sides():
    assert method_key("post") == method_key("POST") == "POST"
    assert method_key(None) == method_key("") == method_key(3) == "GET"


def test_a_post_only_finding_labels_only_the_post_candidate(tmp_path):
    with Store(tmp_path / "a.db") as store:
        rid = store.start_run("auto", "h")
        get, post = _candidate(store, rid, "GET"), _candidate(store, rid, "POST", "body")
        _finding(store, rid, "POST")
        store.conn.commit()
        assert _labels(store, rid) == {get: 0, post: 1}     # GET used to read 1


def test_a_missing_evidence_method_is_get_and_case_is_ignored(tmp_path):
    with Store(tmp_path / "a.db") as store:
        rid = store.start_run("auto", "h")
        bare, post = _candidate(store, rid, None), _candidate(store, rid, "post", "body")
        _finding(store, rid, "get")
        store.conn.commit()
        assert _labels(store, rid) == {bare: 1, post: 0}


def test_a_finding_without_a_method_still_matches_any_method(tmp_path):
    """Legacy / hand-written findings with no recorded method keep the old behaviour."""
    with Store(tmp_path / "a.db") as store:
        rid = store.start_run("auto", "h")
        get, post = _candidate(store, rid, "GET"), _candidate(store, rid, "POST", "body")
        _finding(store, rid, None)
        store.conn.commit()
        assert _labels(store, rid) == {get: 1, post: 1}


def test_seen_fraction_tells_methods_apart(tmp_path):
    with Store(tmp_path / "a.db") as store:
        r1, r2 = store.start_run("auto", "h"), store.start_run("auto", "h")
        old_get = _candidate(store, r1, "GET")
        now_get, now_post = _candidate(store, r2, "get"), _candidate(store, r2, "POST", "body")
        store.conn.commit()
        assert candidate_keys(store, [now_post])[0][3] == "POST"
        assert seen_fraction(store, [old_get], [now_get, now_post]) == 0.5
