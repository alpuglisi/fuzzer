"""Option 4(a) (owner, 2026-10-17): a selector form whose submission answers 200 with
HTML is the chosen page itself; it is read as a page, never requested again
(CC-CRAWL-0045, FR-CRAWL-8).

The gates are unchanged: a POST picker is enumerated only when its select is named, a
cookie stops it as a settings form, and answers that add nothing new count as
self-redirects. Every server here is loopback.
"""

from __future__ import annotations

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from bs4 import BeautifulSoup

from fuzzlab.core.forms import form_record
from fuzzlab.tools import formnav

PICKER = ("<form action='/app/portal.php' method='POST'><select name='bug'>"
          "<option value='1'>SQL injection</option><option value='2'>XSS</option>"
          "<option value='3'>Command injection</option></select>"
          "<button name='form_bug' value='submit'>Hack</button></form>")


def _rec(html=PICKER, page="http://h/app/portal.php"):
    return form_record(BeautifulSoup(html, "html.parser").find("form"), page)


def _page(n):
    return (f"<html><a href='bug{n}.php'>bug {n}</a>"
            f"<form method=get action='bug{n}.php'><input name='q{n}'></form></html>")


class _App:
    """A picker endpoint that answers 200 with the chosen page."""

    def __init__(self, answer=None):
        self.sent = []
        self.answer = answer or (lambda v: (200, {"Content-Type": "text/html"},
                                            _page(v)))

    def submit(self, method, url, entries):
        value = dict(entries)["bug"]
        self.sent.append(value)
        return self.answer(value)


def test_a_200_html_answer_is_read_as_a_page_and_enumeration_goes_on():
    app, read, verdicts = _App(), [], []
    found = formnav.enumerate_form(_rec(), app.submit, lambda u: True,
                                   on_verdict=verdicts.append,
                                   on_page=lambda a, h: read.append((a, h)) or 1)
    assert app.sent == ["1", "2", "3"]
    assert [a for a, _h in read] == ["http://h/app/portal.php"] * 3
    assert "bug2.php" in read[1][1]
    assert found == [] and verdicts == ["navigation"]


def test_without_a_reader_or_without_html_a_200_still_stops():
    app = _App()
    assert formnav.enumerate_form(_rec(), app.submit, lambda u: True) == []
    assert app.sent == ["1"]                                   # no reader: stopped
    app = _App(lambda v: (200, {"Content-Type": "application/json"}, None))
    assert formnav.enumerate_form(_rec(), app.submit, lambda u: True,
                                  on_page=lambda a, h: 1) == []
    assert app.sent == ["1"]                                   # not HTML: stopped
    app = _App(lambda v: (500, {"Content-Type": "text/html"}, "<html>err</html>"))
    formnav.enumerate_form(_rec(), app.submit, lambda u: True, on_page=lambda a, h: 1)
    assert app.sent == ["1"]                                   # an error page: stopped


def test_a_200_that_sets_a_cookie_is_a_settings_form():
    verdicts = []
    app = _App(lambda v: (200, {"Content-Type": "text/html", "Set-Cookie": "lvl=1"},
                          _page(v)))
    formnav.enumerate_form(_rec(), app.submit, lambda u: True,
                           on_verdict=verdicts.append, on_page=lambda a, h: 1)
    assert app.sent == ["1"] and verdicts == ["settings"]


def test_five_answers_that_add_nothing_mark_a_settings_form():
    many = "".join(f"<option value='{i}'>opt {i}</option>" for i in range(8))
    rec = _rec(f"<form action='/app/s.php' method='POST'><select name='bug'>{many}"
               f"</select><button>Go</button></form>", page="http://h/app/s.php")
    app, verdicts = _App(lambda v: (200, {"Content-Type": "text/html"}, "<p>same</p>")), []
    formnav.enumerate_form(rec, app.submit, lambda u: True, on_verdict=verdicts.append,
                           on_page=lambda a, h: 0)
    assert len(app.sent) == 5 and verdicts == ["settings"]


def test_five_empty_answers_stop_a_form_even_after_a_page_was_read():
    many = "".join(f"<option value='{i}'>opt {i}</option>" for i in range(12))
    rec = _rec(f"<form action='/app/s.php' method='POST'><select name='bug'>{many}"
               f"</select><button>Go</button></form>", page="http://h/app/s.php")
    app, verdicts = _App(), []
    formnav.enumerate_form(rec, app.submit, lambda u: True, on_verdict=verdicts.append,
                           on_page=lambda a, h: 1 if "bug0." in h else 0)
    assert app.sent == [str(i) for i in range(6)] and verdicts == ["navigation"]


def test_a_settings_option_is_still_never_sent():
    rec = _rec(PICKER.replace("Command injection", "Set security level"))
    app = _App()
    formnav.enumerate_form(rec, app.submit, lambda u: True, on_page=lambda a, h: 1)
    assert app.sent == ["1", "2"]


# --- the crawler, against a loopback server, both engines -----------------------------
class _PickerApp(BaseHTTPRequestHandler):
    """``/app/portal.php``: a named POST picker answering 200 with the chosen page (one
    link, one form); a settings picker that would set a cookie; ``bugN.php`` pages."""

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, headers=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.server.lab.append(("GET", self.path, None))
        if self.path.startswith("/app/portal.php"):
            self._send("<html>" + PICKER +
                       "<form action='/app/portal.php' method='POST'>"
                       "<select name='security_level'><option value='0'>low</option>"
                       "<option value='1'>high</option></select><button>Set</button>"
                       "</form></html>")
        else:
            self._send(f"<html><p>{self.path}</p></html>")

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.server.lab.append(("POST", self.path, body))
        if "security_level" in body:
            self._send("<html>set</html>", headers=[("Set-Cookie", "security_level=1")])
            return
        self._send("<html>" + PICKER + _page(body["bug"][0]) + "</html>")


class _PrefsApp(_PickerApp):
    """``/app/prefs.php``: a named POST picker (8 options) that re-renders its own page
    on every answer -- nav links the crawl has not visited yet, a per-render nonce in a
    link and in the form's action -- and sets no cookie: a settings form (review M1)."""

    n = 0

    def _prefs(self):
        type(self).n += 1
        opts = "".join(f"<option value='{i}'>choice {i}</option>" for i in range(8))
        return (f"<html><a href='a.php'>A</a><a href='b.php?nonce={self.n}'>B</a>"
                f"<form action='/app/prefs.php?nonce={self.n}' method='POST'>"
                f"<select name='bug'>{opts}</select><button>Save</button></form></html>")

    def do_GET(self):
        self.server.lab.append(("GET", self.path, None))
        if self.path.startswith("/app/prefs.php"):
            self._send(self._prefs())
        else:
            self._send(f"<html><p>{self.path}</p></html>")

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.server.lab.append(("POST", self.path, body))
        self._send(self._prefs())


class _Latin1App(_PickerApp):
    """The picker answers in ISO-8859-1 with a byte that is not UTF-8 (review M2)."""

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.server.lab.append(("POST", self.path, body))
        data = ("<html><p>CAF\u00c9</p>" + _page(body["bug"][0]) + "</html>"
                ).encode("iso-8859-1")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=iso-8859-1")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _serve(handler=_PickerApp):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.lab = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _crawl(tmp_path, engine, handler=_PickerApp, page="portal.php"):
    from fuzzlab.tools.spider import LocalSpider
    server = _serve(handler)
    base = f"http://127.0.0.1:{server.server_address[1]}/app/{page}"
    try:
        sp = LocalSpider(base, max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine=engine, selector_forms=["bug"])
        if engine == "playwright":
            from tests._spa_fixture import run_crawl
            run_crawl(sp)
        else:
            sp.crawl()
    finally:
        server.shutdown()
        server.server_close()
    return sp, server.lab


def _check(tmp_path, sp, lab):
    posts = [b for m, _p, b in lab if m == "POST"]
    assert [p["bug"] for p in posts] == [["1"], ["2"], ["3"]]
    assert all("security_level" not in p for p in posts)        # never named
    gets = [p for m, p, _b in lab if m == "GET"]
    for n in (1, 2, 3):
        assert f"/app/bug{n}.php" in gets, gets                   # the pages' links
    db = sqlite3.connect(tmp_path / "s.db")
    actions = {r[0] for r in db.execute("SELECT action_url FROM discovered_forms")}
    for n in (1, 2, 3):
        assert any(a.endswith(f"/app/bug{n}.php") for a in actions), actions
    sources = dict(db.execute("SELECT url, source FROM discovered_pages"))
    assert any(u.endswith("/app/bug2.php") and s == "form" for u, s in sources.items())
    verdicts = [r[0] for r in db.execute("SELECT verdict FROM selector_verdicts")]
    assert verdicts == ["navigation"]
    assert sp.spa_counts["picker_pages_read"] == 3


def test_the_static_crawler_reads_a_pickers_200_answers(tmp_path):
    sp, lab = _crawl(tmp_path, "requests")
    _check(tmp_path, sp, lab)
    assert "security_level" not in sp.session.cookies


def test_the_browser_crawler_reads_a_pickers_200_answers(tmp_path, monkeypatch):
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    sp, lab = _crawl(tmp_path, "playwright")
    _check(tmp_path, sp, lab)


def _check_settings(tmp_path, lab):
    posts = [b for m, _p, b in lab if m == "POST"]
    assert len(posts) == 5, posts                    # five empty answers, then stopped
    db = sqlite3.connect(tmp_path / "s.db")
    assert [r[0] for r in db.execute("SELECT verdict FROM selector_verdicts")] == \
        ["settings"]
    gets = [p for m, p, _b in lab if m == "GET"]
    assert "/app/a.php" in gets                      # the page's own links still crawled


def test_a_picker_that_re_renders_itself_is_a_settings_form_static(tmp_path):
    _sp, lab = _crawl(tmp_path, "requests", _PrefsApp, "prefs.php")
    _check_settings(tmp_path, lab)


def test_a_picker_that_re_renders_itself_is_a_settings_form_browser(tmp_path,
                                                                    monkeypatch):
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    _sp, lab = _crawl(tmp_path, "playwright", _PrefsApp, "prefs.php")
    _check_settings(tmp_path, lab)


def test_a_latin1_answer_is_read_by_the_browser_crawler(tmp_path, monkeypatch):
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    sp, lab = _crawl(tmp_path, "playwright", _Latin1App)
    _check(tmp_path, sp, lab)
