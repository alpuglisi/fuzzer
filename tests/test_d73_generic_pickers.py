"""D73 (owner, 2026-10-17): a generic run goes through selector forms (pickers) without
naming them -- POST ones too, in a loopback lab -- behind one POST-picker rule shared
with the importer (CC-CRAWL-0047, FR-CRAWL-8).

The variations here are not bWAPP's: a delete picker with a hidden verb, a checkout
picker, a "Save" picker, an add-to-cart picker that redirects to the same cart page, and
a picker that re-renders its own page with results. Every server is loopback.
"""

from __future__ import annotations

import argparse
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest
from bs4 import BeautifulSoup

from fuzzlab.core.forms import form_record
from fuzzlab.tools import formnav


def _rec(html, page="http://127.0.0.1/app/p.php"):
    return form_record(BeautifulSoup(html, "html.parser").find("form"), page)


def _picker(action="/app/portal.php", select="bug", button="<button name='form_bug' "
            "value='submit'>Hack</button>", hidden="", n=3):
    opts = "".join(f"<option value='{i}'>Page {i}</option>" for i in range(n))
    return (f"<form action='{action}' method='POST'>{hidden}<select name='{select}'>"
            f"{opts}</select>{button}</form>")


# --- the one POST-picker rule -------------------------------------------------------
@pytest.mark.parametrize("html, word", [
    (_picker(), None),                                                    # bWAPP's
    (_picker(select="security_level", button="<button>Set</button>"), "settings"),
    (_picker(hidden="<input type=hidden name=op value=delete>"), "destructive"),
    (_picker(action="/booking/checkout", select="room_type"), "transaction"),
    (_picker(button="<button>Save</button>"), "sets something"),
    (_picker(button="<input type=submit value='Apply'>"), "sets something"),
    (_picker(select="pg"), "too short"),
    (_picker(button="<button disabled>Go</button>"), "no enabled submit"),
    (_picker(button="<button formaction='/elsewhere'>Go</button>"), "overrides"),
    (_picker(action="/app/reset.php"), "reset"),          # account and destructive
    # review round 2: account words with no password control, a destructive label
    (_picker(action="/admin/users.php", select="user_id",
             button="<button>Impersonate</button>"), "credential-change"),
    (_picker(button="<button name='go' value='1'>Delete</button>"), "destructive"),
])
def test_an_unnamed_post_picker_is_judged_by_the_importers_rule_and_more(html, word):
    why = formnav.refusal(_rec(html), formnav.ALL_SELECTS, True, lambda u: True)
    if word is None:
        assert why is None
    else:
        assert why and word in why, why


def test_the_importer_and_the_crawler_share_the_short_name_rule():
    from fuzzlab.tools import store_adapter
    assert store_adapter.MIN_JUDGEABLE_SELECT_NAME is formnav.MIN_JUDGEABLE_SELECT_NAME


def test_a_named_run_keeps_its_old_meaning():
    rec = _rec(_picker())
    assert "not named" in formnav.refusal(rec, frozenset(), True, lambda u: True)
    assert formnav.refusal(rec, frozenset({"bug"}), True, lambda u: True) is None
    get = _rec(_picker().replace("method='POST'", "method='GET'"))
    assert formnav.refusal(get, formnav.ALL_SELECTS, False, lambda u: True) is None


# --- the stall: one counter, never exempted by earlier finds -------------------------
class _App:
    def __init__(self, answer):
        self.sent, self.answer = [], answer

    def submit(self, method, url, entries):
        value = dict(entries)["bug"]
        self.sent.append(value)
        return self.answer(value)


def test_a_picker_that_redirects_to_one_page_stops_within_the_bound():
    """An add-to-cart picker: every option redirects to /cart.php. One page found, then
    five that add nothing: six submissions, not 500."""
    rec = _rec(_picker(n=40))
    app, verdicts = _App(lambda v: (302, {"Location": "/app/cart.php"})), []
    found = formnav.enumerate_form(rec, app.submit, lambda u: True,
                                   on_verdict=verdicts.append)
    assert found == ["http://127.0.0.1/app/cart.php"]
    assert len(app.sent) == 1 + formnav.MAX_SELF_REDIRECTS
    assert verdicts == ["navigation"]


def test_a_post_picker_redirecting_to_one_path_with_a_new_query_stalls():
    """Review round 2 (M1): a PRG writer whose every option redirects to
    ``/cart.php?added=<n>`` is one page by path: six submissions, not 40. A GET picker
    (a read) still counts each new URL."""
    rec = _rec(_picker(n=40))
    app = _App(lambda v: (302, {"Location": f"/app/cart.php?added={v}"}))
    assert len(formnav.enumerate_form(rec, app.submit, lambda u: True)) == 1
    assert len(app.sent) == 1 + formnav.MAX_SELF_REDIRECTS
    get = _rec(_picker(n=12).replace("method='POST'", "method='GET'"))
    app = _App(lambda v: (302, {"Location": f"/app/list.php?cat={v}"}))
    assert len(formnav.enumerate_form(get, app.submit, lambda u: True)) == 12


def test_self_redirects_after_a_find_stop_too():
    rec = _rec(_picker(n=40))
    pages = {"0": "/app/a.php"}
    app = _App(lambda v: (302, {"Location": pages.get(v, "/app/portal.php")}))
    formnav.enumerate_form(rec, app.submit, lambda u: True)
    assert len(app.sent) == 1 + formnav.MAX_SELF_REDIRECTS


def test_bwapps_measured_runs_never_reach_the_bound():
    """bWAPP's 159 options, measured on the local build (2026-10-17): the longest run of
    options that add nothing (a redirect to portal.php or to a page already found) is 3.
    A pattern of that shape (3 empty, 1 new, ...) is never stopped."""
    rec = _rec(_picker(n=60))
    app = _App(lambda v: (302, {"Location": f"/app/p{v}.php" if int(v) % 4 == 3
                                else "/app/portal.php"}))
    found = formnav.enumerate_form(rec, app.submit, lambda u: True)
    assert len(app.sent) == 60 and len(found) == 15


# --- the CLI: on by default, an off switch, the narrowing kept -----------------------
def _args(argv):
    from fuzzlab.tools.spider import parse_args
    return parse_args(["--start", "http://127.0.0.1:1/", *argv])


def test_the_cli_default_follows_every_picker_and_the_flags_narrow_or_stop_it():
    from fuzzlab.tools.spider import spider_kwargs
    assert spider_kwargs(_args([]))["selector_forms"] is formnav.ALL_SELECTS
    assert spider_kwargs(_args(["--no-follow-selector-forms"]))["selector_forms"] is None
    assert spider_kwargs(_args(["--follow-selector-forms"]))["selector_forms"] == []
    assert spider_kwargs(_args(["--follow-selector-forms", "bug"]))["selector_forms"] == \
        ["bug"]
    with pytest.raises(SystemExit):
        _args(["--follow-selector-forms", "bug", "--no-follow-selector-forms"])


def test_the_dry_run_says_what_pickers_will_be_submitted():
    from fuzzlab.tools.spider import selector_forms_plan
    assert "unnamed POST pickers are submitted" in selector_forms_plan(_args([]))
    assert selector_forms_plan(_args(["--no-follow-selector-forms"])).startswith("off")
    remote = argparse.Namespace(start="http://example.test/", follow_selector_forms=None,
                                no_follow_selector_forms=False)
    assert "GET pickers only" in selector_forms_plan(remote)


def test_a_library_spider_keeps_selector_navigation_off(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:1/", db_name=str(tmp_path / "s.db"))
    assert sp._selector_forms is None


def test_unnamed_post_pickers_are_followed_only_in_a_loopback_lab(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://example.test/", db_name=str(tmp_path / "a.db"),
                     selector_forms=formnav.ALL_SELECTS)
    assert sp._selector_forms == frozenset()                 # GET pickers only
    sp = LocalSpider("http://127.0.0.1:1/", db_name=str(tmp_path / "b.db"),
                     selector_forms=formnav.ALL_SELECTS)
    assert sp._selector_forms is formnav.ALL_SELECTS


# --- a crawl of a loopback app -------------------------------------------------------
_PAGE = ("<html>" + _picker() +
         _picker(action="/app/portal.php", select="security_level",
                 button="<button name='form_security_level'>Set</button>") +
         _picker(action="/app/items.php", select="item_id",
                 hidden="<input type=hidden name=op value=delete>",
                 button="<button>Go</button>") +
         _picker(action="/app/cart.php", select="product", n=12,
                 button="<button>Add</button>") +
         _picker(action="/app/prefs.php", select="colour",
                 button="<button>Save</button>") +
         "<a href='/app/movies.php'>movies</a></html>")
_MOVIES = ("<html><form action='/app/movies.php' method='POST'><select name='movie'>"
           + "".join(f"<option value='{i}'>Film {i}</option>" for i in range(8))
           + "</select><button name='action' value='go'>Go</button></form>"
           "<p>RESULTS</p></html>")


class _Shop(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body="", status=200, headers=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.server.lab.append(("GET", self.path, None))
        if self.path.startswith("/app/portal.php"):
            self._send(_PAGE)
        elif self.path.startswith("/app/movies.php"):
            self._send(_MOVIES)
        else:
            self._send(f"<html><p>{self.path}</p></html>")

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.server.lab.append(("POST", self.path, body))
        if self.path.startswith("/app/portal.php"):
            self._send(status=302, headers=[("Location", f"page{body['bug'][0]}.php")])
        elif self.path.startswith("/app/cart.php"):
            self._send(status=302, headers=[("Location", "/app/cart_view.php")])
        elif self.path.startswith("/app/movies.php"):
            self._send(_MOVIES.replace("RESULTS", f"film {body['movie'][0]}"))
        else:
            self._send(status=302, headers=[("Location", "/app/portal.php")])


def _crawl(tmp_path, **kw):
    from fuzzlab.tools.spider import LocalSpider
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Shop)
    server.lab = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}/app/portal.php"
    try:
        sp = LocalSpider(base, max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="requests", selector_forms=formnav.ALL_SELECTS, **kw)
        for name, value in kw.pop("_patch", {}).items():
            setattr(sp, name, value)
        yield sp, server.lab
    finally:
        server.shutdown()
        server.server_close()


def test_a_generic_crawl_goes_through_unnamed_pickers_and_refuses_the_rest(tmp_path):
    gen = _crawl(tmp_path)
    sp, lab = next(gen)
    sp.crawl()
    gen.close()
    posts = [(p.split("?")[0], b) for m, p, b in lab if m == "POST"]
    paths = [p for p, _b in posts]
    assert [b["bug"] for p, b in posts if p == "/app/portal.php"] == [["0"], ["1"], ["2"]]
    assert all("security_level" not in b for _p, b in posts)      # settings: never
    assert "/app/items.php" not in paths                           # hidden op=delete
    assert paths.count("/app/cart.php") == 1 + formnav.MAX_SELF_REDIRECTS   # bounded
    assert paths.count("/app/movies.php") == formnav.MAX_SELF_REDIRECTS     # stopped
    gets = [p for m, p, _b in lab if m == "GET"]
    assert {"/app/page0.php", "/app/page1.php", "/app/page2.php"} <= set(gets)
    db = sqlite3.connect(tmp_path / "s.db")
    verdicts = [r[0] for r in db.execute("SELECT verdict FROM selector_verdicts")]
    assert verdicts.count("settings") == 0                         # the movie picker kept
    c = sp.spa_counts
    assert c["picker_forms_enumerated"] == 3 and c["picker_forms_refused"] == 3
    assert "/app/prefs.php" not in paths                           # a "Save" button
    assert c["picker_posts_sent"] == len(posts)


def test_the_movie_picker_is_still_imported_as_a_point(tmp_path):
    """D73 review M1: the re-rendering movie picker (bWAPP sqli_13's shape) was stopped
    without a settings verdict, so the importer still fuzzes its select."""
    from fuzzlab.core.store import Store
    from fuzzlab.harness.auto import injection_points_from_store
    from fuzzlab.tools.store_adapter import import_spider
    gen = _crawl(tmp_path)
    sp, _lab = next(gen)
    base = sp.start_url.rsplit("/", 1)[0] + "/"
    sp.crawl()
    gen.close()
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "127.0.0.1")
        import_spider(tmp_path / "s.db", store, run)
        pts = injection_points_from_store(store, run, base, skipped=[])
    assert any(p.param == "movie" and p.method == "POST" for p in pts), \
        sorted((p.param, p.method) for p in pts)
    # review round 2 (M4): the importer judges a stored POST picker's button as the
    # crawler does (SP-38): the "Save" picker the crawl refused is never fuzzed either
    assert not any(p.param == "colour" for p in pts)


def test_a_lost_session_stops_selector_navigation(tmp_path):
    gen = _crawl(tmp_path)
    sp, lab = next(gen)
    sp._authenticated = True
    sp._live_session_intact = lambda: (False, "test: the server refused the session")
    sp.crawl()
    gen.close()
    assert sp.selector_stopped and "session was lost" in sp.selector_stopped
    assert sp.spa_counts["picker_forms_enumerated"] == 1          # the first only
