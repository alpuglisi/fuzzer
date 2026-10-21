"""The legacy spider's static engine carries the identity it was given (audit defect 5,
BUG-0545, FR-CRAWL-34).

Before: authentication was wired into the browser's start only. `_fetch_static` -- the
``requests`` engine, Playwright's absence and the browser's fallback -- sent through the
bare ``requests`` session: no session-manager preparation, no observation, no Cookie or
Authorization. An identity-scoped crawl silently became an anonymous one.

Now every static hop goes through the core seam (`core.http.HttpClient`) with the session
manager as its addon: the crawl's per-hop scope and destructive rules still decide each
redirect, a hop to another origin than the session's is never followed, the session is
validated (`verify_live`, SP-61) before any page is crawled, a loss the manager sees on a
send makes that page's answer no evidence (retried after the re-login), and an identity
the engine cannot carry, or a login that fails, stops the crawl with an explicit error --
never an anonymous crawl.

Every site here is a loopback server this test starts; it records each request with its
Cookie. The session manager fetches ``/`` and ``/login`` itself (login discovery, the
health check), so the crawler's own requests are judged on every other path, and ``/``
by what the crawl stored."""

from __future__ import annotations

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.session.manager import SessionAuthError, SessionManager
from fuzzlab.session.state import SessionState
from fuzzlab.tools import spider as sp
from tests.test_session_origin_scope import LOGIN_FORM, PASSWORD, USER, _creds


class _IdSite:
    """A loopback app: ``/login`` (a form; a right POST sets a fresh ``sid``), ``/`` (with
    a live ``sid``: a welcome page linking the protected pages; else an anonymous page;
    both carry ``home_extra``), ``/secret`` and ``/deeper`` (200 with a live ``sid``,
    else a 302 to ``/login``), ``/expiring`` (its first credentialed GET drops every
    session, as an expiry, and answers the 302; then as ``/secret``), ``/go`` (a 302 to
    ``other``), ``/pick`` (a selector form's GET target: 302 to ``/secret``). Every
    request is recorded as ``(method, path, Cookie, User-Agent)``.

    ``home_extra`` is on the anonymous page too (BUG-0545 review, B2), so a crawl that
    dropped the identity (c483dc1's anonymous static engine) still reaches ``/go``,
    ``/pick`` and an alias link, and each test that uses it fails there on its own
    behaviour, not only on the first test's."""

    def __init__(self, host="127.0.0.1", other=None, home_extra=""):
        self.sessions: set[str] = set()
        self.requests: list[tuple[str, str, str, str]] = []
        self.logins = 0
        self.expired: set[str] = set()
        self.other = other
        self.home_extra = home_extra
        self._lock = threading.Lock()
        require_loopback(host)                   # PA-0130: a loopback listener only
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _live(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "sid" and value in site.sessions:
                        return True
                return False

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _record(self, method):
                with site._lock:
                    site.requests.append((method, self.path, self.headers.get("Cookie") or "",
                                          self.headers.get("User-Agent") or ""))

            def do_GET(self):  # noqa: N802 - http.server API
                self._record("GET")
                path = self.path.split("?", 1)[0]
                live = self._live()
                if path == "/login":
                    return self._send(200, LOGIN_FORM.encode())
                if path == "/":
                    if not live:
                        return self._send(200, ("<html><body><p>home</p>" + site.home_extra
                                                + "</body></html>").encode())
                    body = ("<html><body><p>welcome alice</p><a href='/secret'>s</a>"
                            "<a href='/expiring'>e</a>" + site.home_extra +
                            "</body></html>")
                    return self._send(200, body.encode())
                if path == "/expiring" and live and path not in site.expired:
                    with site._lock:
                        site.expired.add(path)
                        site.sessions.clear()                   # the session expires
                    return self._send(302, headers=[("Location", "/login")])
                if path in ("/secret", "/deeper", "/expiring"):
                    if not live:
                        return self._send(302, headers=[("Location", "/login")])
                    name = path.strip("/").upper()
                    more = "<a href='/deeper'>d</a>" if path == "/secret" else ""
                    return self._send(200, f"<html><body><p>{name}-PAGE</p>{more}"
                                           f"</body></html>".encode())
                if path == "/go" and site.other is not None:
                    return self._send(302, headers=[("Location", site.other + "land")])
                if path == "/pick":
                    return self._send(302, headers=[("Location", "/secret")])
                return self._send(404, b"no")

            def do_POST(self):  # noqa: N802 - http.server API
                self._record("POST")
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode()))
                if self.path == "/login" and form.get("user") == USER and \
                        form.get("pw") == PASSWORD:
                    with site._lock:
                        site.logins += 1
                        sid = f"sid-{len(site.sessions)}-{site.logins}-0123456789abcdef"
                        site.sessions.add(sid)
                    return self._send(200, b"<html><p>welcome alice</p></html>",
                                      [("Set-Cookie", f"sid={sid}; Path=/")])
                return self._send(200, LOGIN_FORM.encode())

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.base = f"http://{host}:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def crawler_gets(self) -> list[tuple[str, str]]:
        """``(path, Cookie)`` of every GET of a path only the crawler loads: the session
        manager's login and health fetches load ``/`` and ``/login`` (with the same
        browser User-Agent, measured), so those two are left out and ``/`` is judged by
        what the crawl stored."""
        with self._lock:
            return [(p, c) for m, p, c, _ua in self.requests
                    if m == "GET" and p.split("?", 1)[0] not in ("/", "/login")]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site():
    s = _IdSite()
    yield s
    s.close()


def _manager(host="127.0.0.1", password=PASSWORD) -> SessionManager:
    creds = _creds(host)
    if password != PASSWORD:
        creds.set(host, "user", USER, password)
    return SessionManager(creds, scope_hosts=[host], browser_login=False)


def _rows(db) -> dict[str, tuple[int, str]]:
    """The crawl's pages by path: ``(status, content)``."""
    con = sqlite3.connect(db)
    try:
        return {urlsplit(u).path: (s, c or "") for u, s, c in con.execute(
            "SELECT url, status_code, content FROM discovered_pages")}
    except sqlite3.Error:
        return {}
    finally:
        con.close()


def _crawl(site, tmp_path, mgr, **kw):
    db = str(tmp_path / "s.db")
    spider = sp.LocalSpider(site.base, max_depth=kw.pop("max_depth", 2), db_name=db,
                            engine="requests", session_manager=mgr, identity="user",
                            timeout_ms=5000, **kw)
    spider.crawl()
    return spider, db


def test_a_static_crawl_carries_the_identity_through_the_session_manager(site, tmp_path):
    """The requests engine crawls as the identity: the protected pages are extracted
    with the session, every page the crawler fetched carried a live session cookie,
    and the crawler's own anonymous jar never holds it. Before: every page anonymous
    (``home``, no protected page reached)."""
    spider, db = _crawl(site, tmp_path, _manager())
    rows = _rows(db)
    assert "welcome alice" in rows["/"][1], rows
    assert "SECRET-PAGE" in rows["/secret"][1] and "DEEPER-PAGE" in rows["/deeper"][1]
    gets = site.crawler_gets()
    assert {"/secret", "/deeper", "/robots.txt", "/sitemap.xml"} <= {p for p, _c in gets}
    assert all("sid=sid-" in c for _p, c in gets), gets
    assert not [c for c in spider.session.cookies if c.name == "sid"]


def test_a_session_lost_on_a_send_is_never_extracted_and_the_page_is_retried(
        site, tmp_path, monkeypatch):
    """``/expiring`` drops the session on its first credentialed GET and answers the
    login redirect: that answer is no evidence (the crawler neither follows it to the
    login page nor files it as the page); the page is retried after the session
    manager's re-login and extracted with the new session."""
    monkeypatch.setattr(sp, "RETRY_BASE_S", 0.01, raising=False)
    _spider, db = _crawl(site, tmp_path, _manager())
    rows = _rows(db)
    assert "EXPIRING-PAGE" in rows["/expiring"][1], rows
    assert rows["/expiring"][0] == 200
    assert site.logins >= 2                                 # the re-login happened
    assert "/login" not in rows                    # the login redirect was not followed
    assert [p for p, _c in site.crawler_gets()].count("/expiring") == 2


def test_an_identity_the_static_engine_cannot_carry_is_refused_never_crawled_anonymously(
        site, tmp_path):
    """A session that lives only in browser storage (a localStorage token, no cookie and
    no header a request can send) cannot be carried by the static engine: the crawl
    fails with the explicit unsupported-mode error before any page is fetched."""
    origin = site.base.rstrip("/")

    class BrowserOnly:
        """The two calls the static engine makes before anything else."""
        def ensure(self, host, identity, base_url, *, operator=False):
            return SessionState(host, identity, kind="none", valid=True,
                                browser_state={"cookies": [], "origins": [
                                    {"origin": origin, "localStorage": [
                                        {"name": "token", "value": "t"}]}]},
                                origins=frozenset({origin}))

        def session_headers(self, host, identity, base_url, *, operator=False):
            return {}

    with pytest.raises(Exception, match="cannot carry") as raised:
        _crawl(site, tmp_path, BrowserOnly())
    assert site.crawler_gets() == []
    assert isinstance(raised.value, sp.StaticIdentityUnsupported)


def test_a_failed_login_stops_the_crawl_and_nothing_is_crawled_anonymously(site, tmp_path):
    with pytest.raises(SessionAuthError):
        _crawl(site, tmp_path, _manager(password="not-the-password"))
    assert site.crawler_gets() == []
    assert _rows(str(tmp_path / "s.db")) == {}


def test_a_redirect_to_another_origin_is_never_followed_with_or_without_the_session(
        tmp_path):
    """An external crawl (127.0.0.2: its host on every port is in scope) of A, whose
    ``/go`` redirects to B on another port: the hop is not followed -- B receives
    nothing, neither the session nor an anonymous request -- and the landing is
    recorded as skipped on another origin (FR-SESS-20), as the browser does. Before
    (c483dc1): the anonymous crawl followed ``/go`` to B's ``/land``."""
    other = _IdSite("127.0.0.2")
    a = _IdSite("127.0.0.2", other=other.base, home_extra="<a href='/go'>go</a>")
    try:
        spider, db = _crawl(a, tmp_path, _manager("127.0.0.2"), max_depth=1)
    finally:
        a.close()
        other.close()
    assert other.requests == []
    assert other.base + "land" in spider.skipped_other_origin
    assert "welcome alice" in _rows(db)["/"][1]


def test_a_host_the_session_manager_does_not_serve_is_never_sent_without_the_session(
        site, tmp_path):
    """A loopback alias (``localhost``) of the start's origin is in the crawl's scope and
    on the session's own origin, but this manager's own host scope is ``127.0.0.1`` only,
    so its ``prepare`` would send the request without the session (applying nothing,
    deciding nothing). The request is refused before the transport (BUG-0545 review,
    R6): the site receives nothing for the alias, and the page is unresolved -- stored
    ``failed`` with that cause, counted, resumed -- never reported as another origin
    than the session's (it is the session's; ``--auth-origin`` cannot help). Before
    (c483dc1 and 9071440): the alias was requested with no cookie."""
    port = site.base.rsplit(":", 1)[1].strip("/")
    alias = f"http://localhost:{port}/deeper?via=alias"
    site.home_extra = f"<a href='{alias}'>alias</a>"
    spider, db = _crawl(site, tmp_path, _manager(), max_depth=1)
    with site._lock:
        sent = [(m, p, c) for m, p, c, _ua in site.requests if "via=alias" in p]
    assert sent == [], sent                    # nothing reached the alias, of any kind
    con = sqlite3.connect(db)
    try:
        row = con.execute("SELECT status_code, content, outcome, error FROM "
                          "discovered_pages WHERE url = ?", (alias,)).fetchone()
        stats = dict(con.execute("SELECT name, value FROM crawl_stats"))
    finally:
        con.close()
    assert row[:3] == (0, None, "failed"), row
    assert "does not serve host 'localhost'" in row[3], row
    assert "does not serve" in spider.failed_pages[alias]
    assert alias not in spider.skipped_other_origin
    assert stats["session_host_unserved"] == 1
    assert "welcome alice" in _rows(db)["/"][1]        # the session's own pages crawled
    reopened = sp.StorageManager(db)
    try:
        assert alias in [u for u, *_rest in reopened.unresolved()]
    finally:
        reopened.close()


def test_a_selector_form_is_submitted_with_the_session(site, tmp_path):
    """The static engine's selector-form submission (FR-CRAWL-8) carries the identity
    too: its GET reaches ``/pick`` with the session, and the protected page it
    redirects to is crawled. Before: submitted from the anonymous jar."""
    site.home_extra = ("<form action='/pick' method='get'><select name='bug'>"
                       "<option value='1'>one</option><option value='2'>two</option>"
                       "</select><button>Go</button></form>")
    _spider, db = _crawl(site, tmp_path, _manager(), selector_forms=[])
    picks = [c for p, c in site.crawler_gets() if p.startswith("/pick")]
    assert picks and all("sid=sid-" in c for c in picks), site.crawler_gets()
    assert "SECRET-PAGE" in _rows(db)["/secret"][1]
