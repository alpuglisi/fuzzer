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


# --- BUG-0507: the evidence the variation rule lacked (measured on Juice Shop) ---------
#: URLs a Juice Shop crawl requested (2026-10-19): sibling API routes, a directory
#: listing's files, and two URLs the app built from an empty variable.
JUICE = ["http://127.0.0.1:3000/api/Cards", "http://127.0.0.1:3000/api/Challenges",
         "http://127.0.0.1:3000/rest/admin/application-version",
         "http://127.0.0.1:3000/rest/admin/application-configuration",
         "http://127.0.0.1:3000/rest/languages", "http://127.0.0.1:3000/rest/memories",
         "http://127.0.0.1:3000/ftp/legal.md", "http://127.0.0.1:3000/ftp/acquisitions.md",
         "http://127.0.0.1:3000/ftp/incident-support.kdbx",
         "http://127.0.0.1:3000/rest/track-order/undefined",
         "http://127.0.0.1:3000/rest/basket/NaN"]
#: ... and the segments its scripts hold (`code_segments` of its bundle: these names
#: are hard-coded there, e.g. ``this.host + '/application-version'``).
JUICE_CODE = frozenset({"api", "Cards", "Challenges", "rest", "admin",
                        "application-version", "application-configuration",
                        "languages", "memories", "track-order", "basket", "ftp"})


def test_routes_the_code_names_are_not_values_and_placeholders_are_parameters():
    got = _t(JUICE)
    # without the code's evidence the sibling routes look like one parameter (the defect)
    assert ("http://127.0.0.1:3000", "/api/{api}", "api", "Cards") in got
    assert [(t.path, t.example) for t in path_templates(JUICE, code=JUICE_CODE)] == [
        ("/rest/track-order/{id}", "undefined"), ("/rest/basket/{id}", "NaN")]


def test_the_streaming_values_are_data_its_code_never_names():
    """The other measured lab: its scripts hold ``live``, ``username`` and ``play``
    (its fixed segments), never a username; its templates stay."""
    urls = ["http://localhost:8080/live/username/matthewpets",
            "http://localhost:8080/live/username/mr.robot",
            "http://127.0.0.1:3078/play/@matthewpets", "http://127.0.0.1:3078/play/@mr.robot"]
    code = frozenset({"live", "username", "play", "assets", "images"})
    assert [t.path for t in path_templates(urls, code=code)] == \
        ["/live/username/{username}", "/play/{play}"]


def test_a_value_the_code_names_leaves_too_few_values():
    urls = ["http://h/u/admin", "http://h/u/alice"]
    assert _t(urls) and path_templates(urls, code=frozenset({"admin"})) == []
    urls.append("http://h/u/bob")
    assert [t.example for t in path_templates(urls, code=frozenset({"admin"}))] == ["alice"]


@pytest.mark.parametrize("name", ["legal.md", "notes.yml", "db.kdbx", "dump.sql",
                                  "site.tar", "app.jar"])
def test_a_document_or_archive_name_is_a_file_not_a_value(name):
    assert _t(["http://h/ftp/" + name, "http://h/ftp/other"]) == []


def test_shape_and_variation_on_one_segment_are_one_parameter():
    """Disco saw ``/rest/track-order/undefined`` and ``/rest/track-order/fuzzlab``
    (its route seed): one parameter, named by its shape."""
    assert _t(["http://h/rest/track-order/undefined", "http://h/rest/track-order/fuzzlab"]) \
        == [("http://h:80", "/rest/track-order/{id}", "id", "undefined")]


def test_code_segments_are_names_never_keys():
    from fuzzlab.core.pathtemplate import MAX_CODE_SEGMENTS, code_segments
    text = ('a="/api/Cards";b=h+"/application-version";c=`/rest/${x}/b?`;'
            'd="/keys/9f8e7d6c5b4a39281706f5e4d3c2b1a0/";e="no slash";f=1/2')
    assert code_segments(text) == {"api", "Cards", "application-version", "rest", "b",
                                   "keys"}
    many = "".join(f'"/s{i}"' for i in range(MAX_CODE_SEGMENTS + 10))
    assert len(code_segments(many)) == MAX_CODE_SEGMENTS


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


def test_both_importers_read_the_crawls_code_segments(tmp_path):
    """FR-CRAWL-28: the spider's ``script_segments`` table and a disco run's
    ``script_segments.json`` reach the variation rule; an older crawl without them
    imports as before."""
    rows = [(u, 200, "xhr") for u in JUICE]
    db = _spider(tmp_path, rows)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE script_segments (segment TEXT PRIMARY KEY)")
    con.executemany("INSERT INTO script_segments VALUES (?)", [(s,) for s in JUICE_CODE])
    con.commit()
    con.close()
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_spider(db, store, run)
        assert [p for p, _n, _e in _path_params(store, run)] == \
            ["/rest/basket/{id}", "/rest/track-order/{id}"]
    from tests.test_disco_import import _rec, _run_dir
    (tmp_path / "d").mkdir()
    run_dir = _run_dir(tmp_path / "d", [_rec("GET", "/api/Cards"),
                                        _rec("GET", "/api/Challenges")])
    with Store(tmp_path / "d.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_disco(run_dir, store, run)
        assert _path_params(store, run) != []                  # no evidence: as before
    (run_dir / "script_segments.json").write_text('["api", "Cards", "Challenges"]')
    with Store(tmp_path / "e.db") as store:
        run = store.start_run("crawl", "h")
        store_adapter.import_disco(run_dir, store, run)
        assert _path_params(store, run) == []


# --- SP-45: one variation decision -----------------------------------------------------
def _calls(tree, name) -> int:
    import ast
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Call)
               and getattr(n.func, "attr", getattr(n.func, "id", None)) == name)


def test_every_path_templating_rule_decides_variation_through_the_one_owner():
    """BUG-0507: `core.pathtemplate` was written as a second variation rule beside
    `disco.synth.template_paths` (BUG-0501's fix) and repeated the defect BUG-0501 had
    fixed. Both decide through `varying_is_parameter`."""
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "fuzzlab"
    for rel, fn in (("core/pathtemplate.py", "path_templates"),
                    ("disco/synth.py", "template_paths")):
        tree = ast.parse((root / rel).read_text())
        (func,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                   and n.name == fn]
        assert _calls(func, "varying_is_parameter") >= 1, rel


def test_the_variation_guard_flags_a_rule_of_its_own():
    import ast
    assert _calls(ast.parse("if len(values) >= 2: k = 'slug'"), "varying_is_parameter") == 0


def test_the_one_decision_takes_both_kinds_of_evidence():
    from fuzzlab.core.pathtemplate import varying_is_parameter as v
    assert v({"alice", "bob"}) and not v({"Cards", "Challenges"}, code={"Cards",
                                                                      "Challenges"})
    assert not v({"alice", "bob"}, data={"alice"})                # bob never seen as data
    assert v({"alice", "bob", "carol"}, data={"alice", "bob", "carol"}, min_distinct=3)
