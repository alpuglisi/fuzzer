"""The legacy spider's selector-form submission and the session material its page was
fetched on (BUG-0557's sweep, PA-0557(1); owner CRAWL; review round 1, SESSROT-B2).

A static identity crawl fetches a page on the session's cookie, and later submits the
selector form read from it (`tools/spider.py::_seam_submit`, FR-CRAWL-8 with
FR-CRAWL-34). Page fetches are not under the crawl's interaction lock, so with two or
more workers another worker's send can answer 403 in between; the session manager's
`observe` then runs `check_health`, and a LIVE answer that rotates the session id is
adopted in place (`_adopt_rotation`, FR-SESS-23). The submission then carries the page's
session-bound hidden field on the rotated cookie and is refused (403), and the crawl
loses that form's targets. `_seam_submit` opens no `session.manager.material_frame`
(SP-75), so nothing binds the submission to its page's material.

Here the race is made deterministic on one worker: the selector form's enumeration
(`formnav.enumerate_form`) first runs one LIVE check of the real manager against the
app, which rotates the id on that check only (``rotate_next``). The bound field is
``form_key`` (Magento's shape): a name `core.redaction` does not deem sensitive, so
`core.forms.form_record` keeps and sends its value (a CSRF-named field is sent as ``""``
and would be refused with or without a rotation). The control proves the same app
accepts the same submission when the check rotates nothing.

The pin is an offline strict xfail (PA-0531(4)), for the owner, CRAWL; this lane (SESS)
does not change `tools/spider.py`.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools import formnav
from fuzzlab.tools import spider as sp
from tests.test_session_origin_scope import LOGIN_FORM, PASSWORD, USER, _creds


def _form_key(sid: str) -> str:
    """The page's session-bound hidden value: derived from the id it was rendered for."""
    return "fk-" + hashlib.sha256(sid.encode()).hexdigest()[:16]


class _FormKeySite:
    """A loopback app (PA-0130) that binds a form's ``form_key`` to the session id:
    ``/login`` (a form; a right POST sets a fresh ``sid``), ``/`` (with a live ``sid``:
    a welcome page and a POST selector form whose hidden ``form_key`` is that id's; else
    a ``home`` page), ``/pick`` (POST: with a live ``sid`` and that id's ``form_key``, a
    302 to ``/secret``; else 403) and ``/secret`` (200 with a live ``sid``). With
    ``rotate_next`` set, the next logged-in ``GET /`` sets a new id (the old one stays
    live, as its form keys do: a PHP-like ``session_regenerate_id(false)``). Each
    ``/pick`` is recorded as ``(sid, accepted)``, each rendered form's id in
    ``page_sids``."""

    def __init__(self):
        self.sessions: set[str] = set()
        self.rotate_next = False
        self.rotations = 0
        self.picks: list[tuple[str, bool]] = []
        self.page_sids: list[str] = []
        self.logins = 0
        self._lock = threading.Lock()
        require_loopback("127.0.0.1")
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _sid(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "sid" and value in site.sessions:
                        return value
                return None

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                sid = self._sid()
                if path == "/login":
                    return self._send(200, LOGIN_FORM.encode())
                if path == "/":
                    if sid is None:
                        return self._send(200, b"<html><body><p>home</p></body></html>")
                    extra = []
                    with site._lock:
                        if site.rotate_next:
                            site.rotate_next = False
                            site.rotations += 1
                            sid = f"sid-r{site.rotations}-0123456789abcdef"
                            site.sessions.add(sid)
                            extra = [("Set-Cookie", f"sid={sid}; Path=/")]
                        site.page_sids.append(sid)
                    return self._send(200, (
                        "<html><body><p>welcome alice</p><form action='/pick' "
                        f"method='post'><input type='hidden' name='form_key' "
                        f"value='{_form_key(sid)}'><select name='bug'><option value='1'>"
                        "one</option></select><button>Go</button></form></body></html>"
                    ).encode(), extra)
                if path == "/secret":
                    if sid is None:
                        return self._send(302, headers=[("Location", "/login")])
                    return self._send(200, b"<html><body><p>SECRET-PAGE</p></body></html>")
                return self._send(404, b"no")

            def do_POST(self):  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode()))
                sid = self._sid()
                if self.path == "/login":
                    if form.get("user") == USER and form.get("pw") == PASSWORD:
                        with site._lock:
                            site.logins += 1
                            new = f"sid-{site.logins}-0123456789abcdef"
                            site.sessions.add(new)
                        return self._send(200, b"<html><p>welcome alice</p></html>",
                                          [("Set-Cookie", f"sid={new}; Path=/")])
                    return self._send(200, LOGIN_FORM.encode())
                if self.path == "/pick":
                    ok = sid is not None and form.get("form_key") == _form_key(sid)
                    with site._lock:
                        site.picks.append((sid or "", ok))
                    if ok:
                        return self._send(302, headers=[("Location", "/secret")])
                    return self._send(403, b"bad form key")
                return self._send(404, b"no")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site():
    s = _FormKeySite()
    yield s
    s.close()


def _rows(db) -> dict[str, str]:
    con = sqlite3.connect(db)
    try:
        return {urlsplit(u).path: c or "" for u, c in con.execute(
            "SELECT url, content FROM discovered_pages")}
    finally:
        con.close()


def _crawl_with_a_check_before_the_submission(site, tmp_path, monkeypatch, *, rotate):
    """A static identity crawl in which one LIVE health check of the real manager runs
    after the form's page was fetched and before its submission (another worker's send
    triggering it, made deterministic); ``rotate``: the app rotates the id on it.
    Returns ``(checks, rows)``: each check's state, the crawl's pages."""
    mgr = SessionManager(_creds(), scope_hosts=["127.0.0.1"], browser_login=False)
    real = formnav.enumerate_form
    checks: list[str] = []

    def a_check_between(record, submit, in_scope, **kw):
        site.rotate_next = rotate
        health, _moved = mgr.check_health("127.0.0.1", "user", use_cache=False)
        checks.append(health.state)
        return real(record, submit, in_scope, **kw)
    monkeypatch.setattr(formnav, "enumerate_form", a_check_between)
    db = str(tmp_path / "s.db")
    sp.LocalSpider(site.base, max_depth=2, db_name=db, engine="requests",
                   session_manager=mgr, identity="user", timeout_ms=5000,
                   selector_forms=["bug"]).crawl()
    return checks, _rows(db)


def test_the_selector_form_is_accepted_when_the_check_rotates_nothing(site, tmp_path,
                                                                     monkeypatch):
    """The control: the same crawl, a LIVE check between the page and the submission
    that rotates nothing. The submission carries the page's ``form_key`` on its id and
    is accepted, and the page it redirects to is crawled."""
    checks, rows = _crawl_with_a_check_before_the_submission(site, tmp_path, monkeypatch,
                                                             rotate=False)
    assert checks == ["live"] and site.rotations == 0
    assert site.picks and all(ok for _sid, ok in site.picks), site.picks
    assert "SECRET-PAGE" in rows.get("/secret", ""), sorted(rows)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0557 sweep, PA-0557(1); owner CRAWL (tools/spider.py::_seam_submit): a static "
    "identity crawl's selector-form submission is not bound to the session material its "
    "page was fetched on (no session.manager.material_frame), so a rotation a LIVE check "
    "adopts in between sends the page's session-bound form_key on the rotated cookie: "
    "403, and the form's targets are lost"))
def test_a_selector_form_submitted_after_a_rotation_is_refused_or_carries_its_pages_material(
        site, tmp_path, monkeypatch):
    """The LIVE check between the page fetch and the submission rotates the id, and the
    manager adopts it. Wanted: the submission is refused before it is sent (the page is
    fetched again, or the form given up), or it carries the material its page was
    fetched on -- never the page's ``form_key`` on another id."""
    checks, _rows_ = _crawl_with_a_check_before_the_submission(site, tmp_path,
                                                              monkeypatch, rotate=True)
    if checks != ["live"] or site.rotations != 1:            # the pin's premise, loud
        pytest.fail(f"precondition: one LIVE check that rotated the id ({checks}, "
                    f"{site.rotations} rotation(s))")
    if not site.page_sids:
        pytest.fail("precondition: the form's page was fetched with the session")
    stale = [sid for sid, ok in site.picks if not ok]
    assert stale == [], f"a submission carried the page's form_key on {stale}"
