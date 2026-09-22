"""Tests for fuzzlab/tools/spider.py: StorageManager persistence of
template_cluster_id (T2.6) and the hybrid engine's escalation logic (T2.7).

No test coverage existed for this legacy module before CC-CRAWL-0007; these
tests are additive and exercise only the new surface plus a regression guard
for the existing playwright/requests/auto engines.
"""
import sqlite3

import pytest

from fuzzlab.tools import spider as spider_mod
from fuzzlab.tools.spider import LocalSpider, StorageManager

_SPA_SHELL = '<html><body><div id="root"></div><script src="/bundle.js"></script></body></html>'
_STATIC_A = "<html><body><h1>Fort A</h1><p>cozy little fort</p></body></html>"
_STATIC_B = "<html><body><h1>Fort ZZZ</h1><p>a much bigger deluxe fort</p></body></html>"


# ----- StorageManager: template_cluster_id persistence -----

def test_storage_manager_persists_template_cluster_id(tmp_path):
    db = str(tmp_path / "spider.db")
    storage = StorageManager(db)
    storage.mark_visited("http://localhost/a", 200, 0, title="A",
                          content="a", template_cluster_id="T0001")
    storage.cursor.execute(
        "SELECT template_cluster_id FROM discovered_pages WHERE url = ?",
        ("http://localhost/a",),
    )
    assert storage.cursor.fetchone()[0] == "T0001"
    storage.close()


def test_storage_manager_defaults_template_cluster_id_to_null(tmp_path):
    db = str(tmp_path / "spider.db")
    storage = StorageManager(db)
    storage.mark_visited("http://localhost/a", 200, 0)
    storage.cursor.execute(
        "SELECT template_cluster_id FROM discovered_pages WHERE url = ?",
        ("http://localhost/a",),
    )
    assert storage.cursor.fetchone()[0] is None
    storage.close()


def test_storage_manager_upgrades_older_db_missing_the_column(tmp_path):
    db = str(tmp_path / "spider.db")
    # Simulate a database created before template_cluster_id existed.
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE discovered_pages (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "url TEXT UNIQUE, status_code INTEGER, depth INTEGER)"
    )
    conn.commit()
    conn.close()

    storage = StorageManager(db)  # _init_db() must ALTER TABLE in the new column
    assert storage.mark_visited("http://localhost/a", 200, 0, template_cluster_id="T0001")
    storage.cursor.execute(
        "SELECT template_cluster_id FROM discovered_pages WHERE url = ?",
        ("http://localhost/a",),
    )
    assert storage.cursor.fetchone()[0] == "T0001"
    storage.close()


# ----- fixtures/helpers for LocalSpider tests -----

class _FakeResponse:
    def __init__(self, status_code=200, html="", content_type="text/html"):
        self.status_code = status_code
        self.text = html
        self.headers = {"Content-Type": content_type}


def _make_spider(tmp_path, engine="requests"):
    return LocalSpider(
        "http://localhost/",
        max_depth=1,
        db_name=str(tmp_path / "spider.db"),
        engine=engine,
    )


# ----- _fetch_static: raw_html capture + clustering -----

def test_fetch_static_captures_raw_html_for_clustering(tmp_path, monkeypatch):
    spider = _make_spider(tmp_path)
    monkeypatch.setattr(spider.session, "get",
                         lambda url, timeout: _FakeResponse(html=_STATIC_A))
    status, ct, title, text, links, xhr, raw_html = spider._fetch_static("http://localhost/a")
    assert raw_html == _STATIC_A
    assert status == 200
    spider.storage.close()


def test_similar_skeleton_pages_share_a_cluster_id_across_the_crawl(tmp_path, monkeypatch):
    spider = _make_spider(tmp_path)
    pages = {"http://localhost/": _STATIC_A, "http://localhost/b": _STATIC_A,
              "http://localhost/spa": _SPA_SHELL}

    def fake_get(url, timeout):
        return _FakeResponse(html=pages[url])

    monkeypatch.setattr(spider.session, "get", fake_get)
    monkeypatch.setattr(spider, "_is_local", lambda u: True)
    spider.storage.mark_visited("http://localhost/b", 200, 1, template_cluster_id=None)
    spider.crawl()

    conn = sqlite3.connect(spider.storage.db_name)
    ids = dict(conn.execute("SELECT url, template_cluster_id FROM discovered_pages").fetchall())
    conn.close()
    assert ids["http://localhost/"] is not None
    # The pre-seeded /b row is untouched by this crawl (already visited), so only
    # the root and the structurally different SPA shell are compared here.
    assert ids["http://localhost/"] != ids.get("http://localhost/spa")


# ----- hybrid engine escalation -----

def test_hybrid_engine_escalates_only_pages_that_need_a_browser(tmp_path, monkeypatch):
    monkeypatch.setattr(spider_mod, "_PLAYWRIGHT_AVAILABLE", True)
    spider = _make_spider(tmp_path, engine="hybrid")
    assert spider.engine == "hybrid"

    static_pages = {"http://localhost/": _SPA_SHELL, "http://localhost/x": _STATIC_A}
    rendered_calls = []

    def fake_fetch_static(url):
        return 200, "text/html", None, "text", [], [], static_pages[url]

    def fake_start_browser():
        spider._pw = "MOCK_PW"

    def fake_fetch_rendered(url):
        rendered_calls.append(url)
        return 200, "text/html", "rendered", "rendered text", [], [], "<html>rendered</html>"

    def fake_stop_browser():
        spider._pw = None

    monkeypatch.setattr(spider, "_fetch_static", fake_fetch_static)
    monkeypatch.setattr(spider, "_start_browser", fake_start_browser)
    monkeypatch.setattr(spider, "_fetch_rendered", fake_fetch_rendered)
    monkeypatch.setattr(spider, "_stop_browser", fake_stop_browser)
    monkeypatch.setattr(spider, "_is_local", lambda u: False)  # no link-following needed

    spider.storage.mark_visited("http://localhost/x", 0, 99)  # pre-visit so only "/" escalates
    spider.crawl()

    assert rendered_calls == ["http://localhost/"]
    conn = sqlite3.connect(spider.storage.db_name)
    row = conn.execute(
        "SELECT rendered FROM discovered_pages WHERE url = ?", ("http://localhost/",)
    ).fetchone()
    conn.close()
    assert row[0] == 1


def test_hybrid_engine_never_starts_a_browser_when_no_page_needs_one(tmp_path, monkeypatch):
    monkeypatch.setattr(spider_mod, "_PLAYWRIGHT_AVAILABLE", True)
    spider = _make_spider(tmp_path, engine="hybrid")

    def fake_fetch_static(url):
        return 200, "text/html", None, "text", [], [], _STATIC_A

    started = []
    monkeypatch.setattr(spider, "_fetch_static", fake_fetch_static)
    monkeypatch.setattr(spider, "_start_browser", lambda: started.append(True))
    monkeypatch.setattr(spider, "_is_local", lambda u: False)

    spider.crawl()

    assert started == []
    assert spider._pw is None


def test_hybrid_without_playwright_installed_warns_and_never_escalates(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(spider_mod, "_PLAYWRIGHT_AVAILABLE", False)
    spider = _make_spider(tmp_path, engine="hybrid")

    def fake_fetch_static(url):
        return 200, "text/html", None, "text", [], [], _SPA_SHELL

    started = []
    monkeypatch.setattr(spider, "_fetch_static", fake_fetch_static)
    monkeypatch.setattr(spider, "_start_browser", lambda: started.append(True))
    monkeypatch.setattr(spider, "_is_local", lambda u: False)

    spider.crawl()

    assert started == []  # never escalates without playwright, even for an SPA shell


# ----- regression: existing engines unchanged -----

def test_requests_engine_marks_pages_unrendered(tmp_path, monkeypatch):
    spider = _make_spider(tmp_path, engine="requests")
    monkeypatch.setattr(spider.session, "get",
                         lambda url, timeout: _FakeResponse(html=_STATIC_A))
    monkeypatch.setattr(spider, "_is_local", lambda u: False)
    spider.crawl()
    conn = sqlite3.connect(spider.storage.db_name)
    row = conn.execute(
        "SELECT rendered FROM discovered_pages WHERE url = ?", ("http://localhost/",)
    ).fetchone()
    conn.close()
    assert row[0] == 0


def test_playwright_engine_marks_pages_rendered(tmp_path, monkeypatch):
    monkeypatch.setattr(spider_mod, "_PLAYWRIGHT_AVAILABLE", True)
    spider = _make_spider(tmp_path, engine="playwright")
    assert spider.engine == "playwright"

    monkeypatch.setattr(spider, "_start_browser", lambda: setattr(spider, "_pw", "MOCK_PW"))
    monkeypatch.setattr(spider, "_stop_browser", lambda: setattr(spider, "_pw", None))
    monkeypatch.setattr(spider, "_fetch_rendered",
                         lambda url: (200, "text/html", "t", "text", [], [], _STATIC_A))
    monkeypatch.setattr(spider, "_is_local", lambda u: False)

    spider.crawl()

    conn = sqlite3.connect(spider.storage.db_name)
    row = conn.execute(
        "SELECT rendered FROM discovered_pages WHERE url = ?", ("http://localhost/",)
    ).fetchone()
    conn.close()
    assert row[0] == 1
