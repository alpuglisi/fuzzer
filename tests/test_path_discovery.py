"""Path parameters from crawls (FR-CORE-503, FR-AUD-26): `core.pathtemplate` turns a
run's concrete URLs into one-placeholder templates (by id shape, or by variation), both
importers store them as ``path`` parameters, and `fuzzlab auto` probes them. The URLs
in the first test are the ones disco captured on secdevlabs-streaming (2026-10-19)."""

from __future__ import annotations

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

from fuzzlab.core.pathtemplate import id_shaped, path_templates
from fuzzlab.core.store import Store
from fuzzlab.tools import store_adapter


def _t(urls):
    return [(t.origin, t.path, t.param, t.example) for t in path_templates(urls)]


def test_the_streaming_crawls_urls_give_their_templates():
    got = _t(["http://127.0.0.1:3078/", "http://127.0.0.1:3078/main.js",
              "http://localhost:8080/live",
              "http://127.0.0.1:3078/assets/images/lives/matthewpets/thumb.png",
              "http://127.0.0.1:3078/assets/images/lives/mr.robot/thumb.png",
              "http://localhost:8080/live/username/matthewpets",
              "http://localhost:8080/live/username/mr.robot",
              "http://127.0.0.1:3078/play/@matthewpets", "http://127.0.0.1:3078/play/@mr.robot",
              "http://127.0.0.1:3078/robots.txt"])
    assert got == [("http://127.0.0.1:8080", "/live/username/{username}", "username",
                    "matthewpets"),
                   ("http://127.0.0.1:3078", "/play/{play}", "play", "@matthewpets")]


def test_an_id_shaped_segment_is_a_parameter_seen_once():
    assert _t(["http://h/ticket/680f1206-1ab0-40bc-8690-b13c5a44bcc2?format=json",
               "http://h/api/products/12/reviews", "http://h/commit/9fceb02d0ae598e9"]) == [
        ("http://h:80", "/ticket/{id}", "id", "680f1206-1ab0-40bc-8690-b13c5a44bcc2"),
        ("http://h:80", "/api/products/{id}/reviews", "id", "12"),
        ("http://h:80", "/commit/{id}", "id", "9fceb02d0ae598e9")]
    assert [s for s in ("12", "v2", "2026", "deadbeef", "abcdefgh", "about")
            if id_shaped(s)] == ["12", "2026"]


def test_two_parameters_give_two_templates_each_with_the_other_concrete():
    assert [p for _o, p, _n, _e in _t(["http://h/users/5/posts/7"])] == \
        ["/users/{id}/posts/7", "/users/5/posts/{id}"]


@pytest.mark.parametrize("urls", [
    ["http://h/about", "http://h/contact"],                    # the first segment: pages
    ["http://h/a/index.php", "http://h/b/index.php"],          # a file name, not a value
    ["http://h/img/a/x.png", "http://h/img/b/x.png"],          # assets
    ["http://h/docs/intro"],                                   # one word: no evidence
    ["http://h/x/a", "http://h/x/{y}"],                        # a placeholder is no value
])
def test_no_template_without_evidence(urls):
    assert _t(urls) == []


def test_variation_needs_one_origin_and_is_named_after_the_segment_before():
    assert _t(["http://h/docs/intro", "http://g/docs/setup"]) == []
    assert _t(["http://h/docs/intro", "http://h/docs/setup/"]) == [
        ("http://h:80", "/docs/{docs}", "docs", "intro")]


# --- the importers -------------------------------------------------------------------
def _spider(tmp_path, rows):
    db = tmp_path / "spider.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE discovered_pages (url TEXT, status_code INT, source TEXT)")
    con.executemany("INSERT INTO discovered_pages VALUES (?,?,?)", rows)
    con.commit()
    con.close()
    return db


def _path_params(store, run_id):
    return sorted((r[0], r[1], r[2]) for r in store.conn.execute(
        "SELECT e.url, p.name, p.example FROM parameter p JOIN endpoint e "
        "ON p.endpoint_id = e.id WHERE p.run_id = ? AND p.location = 'path'", (run_id,)))


def test_a_crawl_stores_path_parameters_and_blanks_an_identifier(tmp_path):
    db = _spider(tmp_path, [
        ("http://h/product/1", 200, "link"), ("http://h/product/2", 200, "link"),
        ("http://h/ticket/680f1206-1ab0-40bc-8690-b13c5a44bcc2", 200, "link"),
        ("http://h/order/9", 404, "link"),                   # a broken link: no evidence
        ("http://h/seed/5", 200, "spa-query-writes")])       # a write seed: never a point
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        counts = store_adapter.import_spider(db, store, run)
        assert _path_params(store, run) == [("/product/{id}", "id", "1"),
                                            ("/ticket/{id}", "id", "")]
        assert counts["path_parameter"] == 2


def test_a_disco_runs_api_get_gives_a_path_parameter(tmp_path):
    from tests.test_disco_import import _rec, _run_dir
    run_dir = _run_dir(tmp_path, [_rec("GET", "/api/products/12"),
                                  _rec("GET", "/api/products/13"),
                                  _rec("GET", "/api/missing/4", status=404)])
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_disco(run_dir, store, run)
        assert _path_params(store, run) == [("/api/products/{id}", "id", "12")]


# --- auto probes a crawled path parameter --------------------------------------------
class _Shop(BaseHTTPRequestHandler):
    """``/product/<id>`` builds SQL from the segment: a quote breaks it."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        seg = unquote(self.path.split("?")[0].rsplit("/", 1)[-1])
        if self.path.startswith("/product/") and "'" in seg:
            body, status = b"You have an error in your SQL syntax near ''' at line 1", 500
        else:
            body, status = b"<html>a product</html>", 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_auto_confirms_sql_injection_in_a_crawled_path_segment(tmp_path):
    from fuzzlab.core.runmode import resolve_run  # noqa: F401 - plan via run_auto
    from fuzzlab.harness.auto import injection_points_from_store, run_auto
    from fuzzlab.tools.probesender import RequestsProbeSender
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Shop)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    db = _spider(tmp_path, [(base + "/product/1", 200, "link"),
                            (base + "/product/2", 200, "link")])
    try:
        with Store(tmp_path / "s.db") as store:
            run = store.start_run("auto", "h")
            store_adapter.import_spider(db, store, run)
            (point,) = injection_points_from_store(store, run, base + "/")
            assert (point.url, point.location, point.base_entries) == \
                (base + "/product/{id}", "path", (("id", "1"),))
            result = run_auto(base_url=base + "/", store=store, run_id=run,
                              sender=RequestsProbeSender(), mode="manual",
                              selected_categories=["sql-injection"], points_source="crawl")
            findings = [tuple(r) for r in store.conn.execute(
                "SELECT url, param, vuln_class FROM finding WHERE run_id = ?", (run,))]
    finally:
        server.shutdown()
    assert ("/product/{id}", "id", "sqli") in findings, (findings, result)
