"""Crawled URLs keep their origin on import (FR-CORE-504, FR-AUD-27): a URL on the run's
main origin is stored as its path (as before), one on another origin as its absolute
URL, so a page's API on another port is probed there, never re-rooted at the base; a
path on two origins is two endpoints. `auto` probes another origin only when it is
loopback (D11)."""

from __future__ import annotations

import sqlite3

from fuzzlab.core.store import Store
from fuzzlab.core.urls import canonical_origin, store_url, stored_absolute
from fuzzlab.tools import store_adapter

PAGE = "http://127.0.0.1:3078"
API = "http://localhost:8080"


def test_store_url_keeps_another_origin_and_reads_back():
    main = canonical_origin(PAGE)
    assert store_url(PAGE + "/live?x=1", main) == "/live"
    assert store_url(API + "/live?x=1", main) == "http://127.0.0.1:8080/live"
    assert store_url(API + "/#/s?q=1", main, route=True) == "http://127.0.0.1:8080/#/s"
    assert store_url(API + "/live", None) == "/live"              # no main origin: a path
    assert stored_absolute("/live", PAGE) == PAGE + "/live"
    assert stored_absolute("http://127.0.0.1:8080/live", PAGE) == "http://127.0.0.1:8080/live"
    assert stored_absolute("/go/http://x", PAGE) == PAGE + "/go/http://x"   # still a path


def _spider(tmp_path, urls):
    db = tmp_path / "spider.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE discovered_pages (url TEXT, status_code INT, source TEXT)")
    con.executemany("INSERT INTO discovered_pages VALUES (?,200,'link')",
                    [(u,) for u in urls])
    con.commit()
    con.close()
    return db


def _endpoints(store, run_id):
    return sorted((r[0], r[1], r[2]) for r in store.conn.execute(
        "SELECT e.url, p.name, p.location FROM parameter p JOIN endpoint e "
        "ON p.endpoint_id = e.id WHERE p.run_id = ?", (run_id,)))


def test_a_path_on_two_origins_is_two_endpoints_each_probed_at_its_origin(tmp_path):
    from fuzzlab.harness.auto import injection_points_from_store
    db = _spider(tmp_path, [PAGE + "/search?q=a", API + "/search?q=b",
                            API + "/live/username/alice", API + "/live/username/bob"])
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_spider(db, store, run, base_url=PAGE + "/")
        assert _endpoints(store, run) == [
            ("/search", "q", "query"),
            ("http://127.0.0.1:8080/live/username/{username}", "username", "path"),
            ("http://127.0.0.1:8080/search", "q", "query")]
        urls = sorted(p.url for p in injection_points_from_store(store, run, PAGE + "/"))
    assert urls == [PAGE + "/search", "http://127.0.0.1:8080/live/username/{username}",
                    "http://127.0.0.1:8080/search"]


def test_without_a_base_the_first_crawled_url_is_the_main_origin(tmp_path):
    db = _spider(tmp_path, [PAGE + "/a?x=1", API + "/b?y=1"])
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_spider(db, store, run)
        assert _endpoints(store, run) == [("/a", "x", "query"),
                                          ("http://127.0.0.1:8080/b", "y", "query")]


def test_another_origin_off_the_machine_is_never_probed(tmp_path):
    from fuzzlab.harness.auto import injection_points_from_store
    db = _spider(tmp_path, [PAGE + "/a?x=1", "http://api.example.com/b?y=1"])
    skipped = []
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_spider(db, store, run, base_url=PAGE)
        points = injection_points_from_store(store, run, PAGE + "/", skipped=skipped)
    assert [p.url for p in points] == [PAGE + "/a"]
    assert ("http://api.example.com:80/b", "GET", "y",
            "another origin, not loopback (D11)") in skipped


def test_a_disco_run_keeps_its_api_origin(tmp_path):
    from fuzzlab.disco.capture import append_record, make_record
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    for url in (PAGE + "/?x=1", API + "/api/items/12"):
        append_record(run_dir / "capture.jsonl", make_record(
            kind="http", t=1.0, action_id="act-1", method="GET", url=url, req_headers={},
            req_body=None, status=200, res_headers={"Content-Type": "application/json"},
            res_body=b"{}"))
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_disco(run_dir, store, run, base_url=PAGE)
        assert ("http://127.0.0.1:8080/api/items/{id}", "id", "path") in \
            _endpoints(store, run)


def test_a_base_under_a_subpath_keeps_its_paths(tmp_path):
    """PA-0034: `--base-url .../bWAPP/` names the main origin only; the crawled paths
    are stored whole, never re-rooted or doubled."""
    base = "http://127.0.0.1:8090/bWAPP/"
    db = _spider(tmp_path, [base + "sqli_1.php?title=x", base + "item/5"])
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_spider(db, store, run, base_url=base)
        assert _endpoints(store, run) == [("/bWAPP/item/{id}", "id", "path"),
                                          ("/bWAPP/sqli_1.php", "title", "query")]
        assert store_adapter._main_origin(base, []) == "http://127.0.0.1:8090"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    from fuzzlab.disco.capture import append_record, make_record
    append_record(run_dir / "capture.jsonl", make_record(
        kind="http", t=1.0, action_id="act-1", method="GET", url=base + "list/7",
        req_headers={}, req_body=None, status=200,
        res_headers={"Content-Type": "application/json"}, res_body=b"{}"))
    with Store(tmp_path / "d.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_disco(run_dir, store, run, base_url=base)
        assert _endpoints(store, run) == [("/bWAPP/list/{id}", "id", "path")]
