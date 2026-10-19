"""The spider records which page led to each page, and when it saw it (FR-CRAWL-29,
FR-AUD-28).

A small loopback site is crawled in-process by the legacy spider -- both engines (the
static ``requests`` engine and a real Chromium), one worker and two -- and its DB is
read back: every page row but the crawl's own entries carries ``found_from``, the URL of
the page whose load queued it (a link, a script's fetch, a redirect); the start URL and
the origin's well-known files carry NULL; ``seen_at`` lies inside the crawl's wall
window and never precedes the parent's. A spider DB from before FR-CRAWL-29 keeps
working: the spider upgrades it (old rows NULL), and its trace events stay ``t`` None
with no referer. A new DB's trace events carry ``t`` and the referer, path only, and the
spider sequence shows it."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from fuzzlab.core import trace
from fuzzlab.core.redaction import redact_url
from fuzzlab.core.store import Store
from fuzzlab.tools import spider as sp
from fuzzlab.tools import store_adapter

SECRET = "hunter2secret"
GO = f"/go?password={SECRET}"
_PAGES = {
    "/": '<a href="/a">a</a> <a href="/b">b</a>',
    "/a": f'<a href="/c">c</a> <a href="/b">b again</a> <a href="{GO}">go</a>',
    "/b": ('<a href="/d">d</a><script>fetch("/api/items");'
           'fetch("/api/save", {method: "POST", headers: {"Content-Type": '
           '"application/json"}, body: JSON.stringify({name: "x"})});</script>'),
    "/c": "c", "/d": "d", "/landing": "landed",
}
#: page path -> the path of the page whose load queued it (None: the crawl's own entry)
PARENTS = {"/": None, "/robots.txt": None, "/sitemap.xml": None, "/a": "/", "/b": "/",
           "/c": "/a", GO: "/a", "/landing": GO, "/d": "/b"}
#: what only a browser sees: the page's script fetches them (an XHR target is queued
#: as a URL whatever its method)
RENDERED_PARENTS = {"/api/items": "/b", "/api/save": "/b"}


class _Site:
    def __init__(self):
        self.posts: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", ctype="text/html", headers=()):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urlsplit(self.path).path
                if path == "/go":
                    return self._send(302, headers=[("Location", "/landing")])
                if path == "/api/items":
                    return self._send(200, b'{"items": []}', "application/json")
                if path in _PAGES:
                    return self._send(200, f"<!doctype html><html><body>{_PAGES[path]}"
                                           f"</body></html>".encode())
                # robots.txt, sitemap.xml, GET /api/save. A body, so Chromium shows it:
                # an empty error answer makes the browser commit its own error page,
                # and the spider's teardown of a failed load (``about:blank``, BUG-0136
                # X1) then interrupts the next load (measured 29 of 40; reported with
                # BUG-0509 as a separate open defect) -- a page rendered or not by
                # chance would make this module's exact expectations depend on it
                return self._send(404, b"<!doctype html><html><body>none</body></html>")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                site.posts.append(self.path)
                return self._send(200, b'{"ok": true}', "application/json")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="module")
def site():
    s = _Site()
    yield s
    s.close()


def _rel(url):
    """A stored URL as the site's path (with its query), None for None."""
    if url is None:
        return None
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


_CRAWLS: dict = {}


def _crawl(site, tmp_path_factory, engine, workers):
    """One crawl per (engine, workers), shared by this module's tests."""
    key = (engine, workers)
    if key not in _CRAWLS:
        db = tmp_path_factory.mktemp(f"trace-{engine}-{workers}") / "spider.db"
        spider = sp.LocalSpider(site.url, max_depth=3, db_name=str(db), engine=engine,
                                workers=workers, reveal=False, timeout_ms=10000)
        t0 = time.time()
        if engine == "playwright":
            from tests._spa_fixture import run_crawl
            with pytest.MonkeyPatch.context() as mp:
                from tests._spa_fixture import chromium_or_skip
                chromium_or_skip(mp)
                run_crawl(spider)
        else:
            spider.crawl()
        t1 = time.time()
        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        try:
            pages = [dict(r) for r in con.execute(
                "SELECT rowid AS rid, url, source, found_from, seen_at "
                "FROM discovered_pages ORDER BY rowid")]
            reqs = [dict(r) for r in con.execute(
                "SELECT id, page_url, url, seen_at FROM discovered_requests ORDER BY id")]
        finally:
            con.close()
        _CRAWLS[key] = {"db": db, "t0": t0, "t1": t1, "pages": pages, "reqs": reqs}
    return _CRAWLS[key]


ENGINES = [("requests", 1), ("requests", 3), ("playwright", 1), ("playwright", 2)]


@pytest.mark.parametrize("engine,workers", ENGINES,
                         ids=[f"{e}-{w}" for e, w in ENGINES])
def test_every_page_row_names_the_page_that_queued_it(site, tmp_path_factory, engine,
                                                       workers):
    crawl = _crawl(site, tmp_path_factory, engine, workers)
    rows = {_rel(r["url"]): r for r in crawl["pages"]}
    expected = dict(PARENTS)
    if engine == "playwright":
        expected.update(RENDERED_PARENTS)
    assert set(rows) == set(expected), sorted(rows)
    for path, parent in expected.items():
        want = parent if path != "/landing" else _rel(redact_url(site.url[:-1] + parent))
        assert _rel(rows[path]["found_from"]) == want, (path, rows[path]["found_from"])
    assert rows["/landing"]["source"] == "redirect"
    # the start URL and the well-known files are the crawl's own entries
    assert rows["/"]["found_from"] is None and rows["/"]["url"] == site.url
    # a non-NULL found_from is always a page row of this crawl (as stored there), except
    # at the redirect's write site, which stores it redacted as it stores the landing
    stored = {r["url"] for r in crawl["pages"]}
    for path, row in rows.items():
        if row["found_from"] is None:
            continue
        if path == "/landing":
            assert row["found_from"] == redact_url(site.url.rstrip("/") + GO)
            assert SECRET not in row["found_from"]
        else:
            assert row["found_from"] in stored, (path, row["found_from"])


@pytest.mark.parametrize("engine,workers", ENGINES,
                         ids=[f"{e}-{w}" for e, w in ENGINES])
def test_seen_at_lies_in_the_crawl_and_never_precedes_the_parent(site, tmp_path_factory,
                                                                  engine, workers):
    crawl = _crawl(site, tmp_path_factory, engine, workers)
    pages = crawl["pages"]
    by_url = {r["url"]: r for r in pages}
    for r in pages:
        assert crawl["t0"] <= r["seen_at"] <= crawl["t1"], r
        if r["found_from"] in by_url:
            assert r["seen_at"] >= by_url[r["found_from"]]["seen_at"], r
    landing = next(r for r in pages if _rel(r["url"]) == "/landing")
    go = next(r for r in pages if _rel(r["url"]) == GO)
    assert landing["seen_at"] == go["seen_at"]            # one load: the redirect's
    if workers == 1:
        # one worker stores the pages in the order it loads them
        times = [r["seen_at"] for r in pages]
        assert times == sorted(times)
    for r in crawl["reqs"]:
        assert crawl["t0"] <= r["seen_at"] <= crawl["t1"], r


def test_a_captured_request_is_timed_after_its_page_began(site, tmp_path_factory):
    crawl = _crawl(site, tmp_path_factory, "playwright", 1)
    (req,) = [r for r in crawl["reqs"] if _rel(r["url"]) == "/api/save"]
    b = next(r for r in crawl["pages"] if _rel(r["url"]) == "/b")
    assert _rel(req["page_url"]) == "/b"
    assert b["seen_at"] <= req["seen_at"] <= crawl["t1"]


def _trace(tmp_path, spider_db):
    store = Store(tmp_path / "store.db")
    run_id = store.start_run("auto", "h")
    rec = trace.TraceRecorder(store, run_id)
    try:
        with trace.recording(rec):
            store_adapter.import_spider(spider_db, store, run_id)
    finally:
        rec.close()
    events = [dict(r) | {"body": json.loads(r["body"])} for r in store.conn.execute(
        "SELECT key, kind, t, body FROM trace_event WHERE run_id=? AND scope='spider' "
        "ORDER BY seq", (run_id,))]
    return store, run_id, events


def test_the_trace_carries_the_time_and_the_referer_path(site, tmp_path_factory,
                                                         tmp_path):
    crawl = _crawl(site, tmp_path_factory, "playwright", 1)
    store, run_id, events = _trace(tmp_path, crawl["db"])
    try:
        pages = {r["rid"]: r for r in crawl["pages"]}
        page_events = [e for e in events if ":page:" in e["key"]]
        assert len(page_events) == len(pages)
        for e in page_events:
            row = pages[e["body"]["order"]]
            assert e["key"].endswith(f":page:{row['rid']}")     # keys unchanged
            assert e["t"] == row["seen_at"]
            parent = _rel(row["found_from"])
            if parent is None:
                assert e["body"].get("referer") is None
            else:
                assert e["body"]["referer"] == urlsplit(parent).path   # path only
        (save,) = [e for e in events if ":request:" in e["key"]]
        (req,) = [r for r in crawl["reqs"] if _rel(r["url"]) == "/api/save"]
        assert save["t"] == req["seen_at"] and save["body"]["referer"] == "/b"
        dump = json.dumps(events)
        assert SECRET not in dump
        # the data flow's initiator attribute, and the spider sequence, show it
        conn = store.conn
        origin = sp.canonical_origin(site.url)
        flow = conn.execute("SELECT attrs, first_seen FROM dg_flow WHERE run_id=? AND "
                            "dst=?", (run_id, f"iface:{origin}|GET|/c")).fetchone()
        assert json.loads(flow["attrs"])["initiator"] == ["/a"]
        assert flow["first_seen"] is not None
        from fuzzlab.report import diagram
        seq = diagram.sequence(conn, run_id, "spider")
        labels = [s["label"] for s in seq["steps"] if s.get("kind") == "request"]
        assert any(lbl.startswith("GET /c ") and lbl.endswith("from /a") for lbl in labels)
    finally:
        store.close()


_OLD_PAGES = ("CREATE TABLE discovered_pages (id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "url TEXT UNIQUE, status_code INTEGER, depth INTEGER, title TEXT, "
              "content TEXT, rendered INTEGER DEFAULT 0, source TEXT DEFAULT 'link')")
_OLD_REQS = ("CREATE TABLE discovered_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, "
             "page_url TEXT, method TEXT, url TEXT, content_type TEXT, body_json TEXT, "
             "source TEXT, signature TEXT UNIQUE)")


def _old_db(path):
    con = sqlite3.connect(path)
    con.execute(_OLD_PAGES)
    con.execute(_OLD_REQS)
    con.executemany("INSERT INTO discovered_pages (url, status_code, depth, source) "
                    "VALUES (?, 200, ?, 'link')",
                    [("http://127.0.0.1:9/", 0), ("http://127.0.0.1:9/a", 1)])
    con.execute("INSERT INTO discovered_requests (page_url, method, url, content_type, "
                "body_json, source, signature) VALUES (?,?,?,?,?,?,?)",
                ("http://127.0.0.1:9/a", "POST", "http://127.0.0.1:9/api/save",
                 "application/json", '{"name": ""}', "passive", "s"))
    con.commit()
    con.close()


def test_an_old_spider_db_imports_with_time_and_referer_unknown(tmp_path):
    db = tmp_path / "old.db"
    _old_db(db)
    store, _run, events = _trace(tmp_path, db)
    try:
        assert len(events) == 3
        for e in events:
            assert e["t"] is None
            if e["kind"] == "observe.page":
                assert e["body"].get("referer") is None
    finally:
        store.close()


def test_the_spider_upgrades_an_old_db_and_its_old_rows_stay_unknown(tmp_path):
    db = tmp_path / "old.db"
    _old_db(db)
    storage = sp.StorageManager(str(db))
    try:
        assert storage.mark_visited("http://127.0.0.1:9/b", 200, 2,
                                    found_from="http://127.0.0.1:9/a", seen_at=12.5)
        assert storage.record_request("http://127.0.0.1:9/b", "POST",
                                      "http://127.0.0.1:9/api/other", "application/json",
                                      b'{"q": 1}', "passive", seen_at=13.0) is None
    finally:
        storage.close()
    con = sqlite3.connect(db)
    try:
        assert con.execute("SELECT url, found_from, seen_at FROM discovered_pages "
                           "ORDER BY id").fetchall() == [
            ("http://127.0.0.1:9/", None, None), ("http://127.0.0.1:9/a", None, None),
            ("http://127.0.0.1:9/b", "http://127.0.0.1:9/a", 12.5)]
        assert con.execute("SELECT seen_at FROM discovered_requests ORDER BY id"
                           ).fetchall() == [(None,), (13.0,)]
    finally:
        con.close()


# --- BUG-0509: a crawl worker copied from another kept its Playwright listeners --------
def test_a_cloned_worker_never_inherits_playwrights_cached_listeners(tmp_path):
    """Playwright caches a bound-method listener's wrapper on the method's object; a
    worker copied after the first worker's browser started must not carry those."""
    pytest.importorskip("playwright")
    from playwright._impl._impl_to_api_mapping import ImplToApiMapping
    s = sp.LocalSpider("http://127.0.0.1:9/", db_name=str(tmp_path / "c.db"),
                       engine="requests", workers=2)
    try:
        wrapper = ImplToApiMapping().wrap_handler(s._on_request)   # what `page.on` does
        cached = [k for k in vars(s) if k.startswith(sp._PW_HANDLER_CACHE)]
        assert cached and vars(s)[cached[0]] is wrapper           # the mechanism holds
        other = s._clone()
        assert not [k for k in vars(other) if k.startswith(sp._PW_HANDLER_CACHE)]
        assert ImplToApiMapping().wrap_handler(other._on_request) is not wrapper
    finally:
        s.storage.close()


def test_each_workers_page_events_reach_that_worker(site, tmp_path, monkeypatch):
    """Real browsers, judged by what each worker recorded itself (PA-0511): the second
    worker loads the page whose script fetches, the first worker loads a page that
    fetches nothing. Before BUG-0509's fix the second worker's page events reached the
    first worker's handler: its fetches were filed under the first worker's page."""
    from tests._browser import skip_or_fail
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    first = sp.LocalSpider(site.url, db_name=str(tmp_path / "w.db"), engine="playwright",
                           workers=2, reveal=False, timeout_ms=10000)
    try:
        first._start_browser()
    except Exception as exc:  # noqa: BLE001 - a launch failure is no verdict
        first.storage.close()
        skip_or_fail(f"chromium could not launch: {exc}")
    got: dict = {}
    try:
        second = first._clone()                 # as `_crawl_parallel` does: after start

        def run():
            second._start_browser()
            try:
                got["second"] = second._fetch_rendered(site.url + "b")[5]
            finally:
                second._stop_browser()

        t = threading.Thread(target=run, name="second-worker")
        t.start()
        t.join(60)
        assert not t.is_alive()
        got["first_before"] = list(first._xhr_urls)    # nothing of the second's page
        got["first"] = first._fetch_rendered(site.url + "c")[5]
    finally:
        first._stop_browser()
        first.storage.close()
    assert sorted(_rel(u) for u in got["second"]) == ["/api/items", "/api/save"]
    assert got["first_before"] == [] and got["first"] == []
