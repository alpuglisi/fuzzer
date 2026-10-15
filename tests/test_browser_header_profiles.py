"""BUG-0152 / SP-38: a request carries the browser header profile of its own kind.

A browser sends two kinds of request: a **navigation** (a link, a typed URL, a form) and
a script's **fetch/XHR** (an API call). The requests-based probe senders sent the
navigation set (``Accept: text/html,…``, ``Sec-Fetch-Mode: navigate``) on every probe,
JSON API probes included, which no browser does. An app that negotiates its error
representation on ``Accept`` (RFC 9110 §12.5.1) then answers a generic HTML page where
its own client gets the JSON error detail.

The fetch profile is **measured** (real Chromium 141.0.7390.37, see BUG-0152):
``Accept: */*``, ``Sec-Fetch-Dest: empty``, ``Sec-Fetch-Mode: cors``,
``Sec-Fetch-Site: same-origin``, no ``Sec-Fetch-User``, no ``Upgrade-Insecure-Requests``.

The four loopback apps model how four frameworks negotiate, each from its documentation
(cited per class). Nothing here contacts a lab: every server is an in-process
``ThreadingHTTPServer`` on 127.0.0.1, port 0. Under the browser's own ``*/*`` the
documented rules give:

| style | ``*/*`` (fetch) | navigation ``text/html,…`` | ``application/json`` |
|---|---|---|---|
| Spring Boot ``BasicErrorController`` | JSON | HTML | JSON |
| Django REST Framework renderers | JSON | HTML | JSON |
| Express ``res.format`` (html first) | HTML | HTML | JSON |
| Rails ``respond_to`` (html first) | HTML | HTML | JSON |

So the fetch profile reveals the evidence for the first two, and for the html-first
two only an ``Accept`` the app's own client sends does (the caller's header wins; the
captured per-endpoint ``Accept`` is the follow-on, DISC-CAPTURE). Those two are strict
xfails, never asserted as passing.
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl

import pytest
import requests

from fuzzlab.core import http as core_http
from fuzzlab.core.http import (BROWSER_HEADER_RULES, FETCH_HEADERS, NAVIGATION_HEADERS,
                               browser_headers, is_json_media_type, request_kind,
                               requests_browser_headers, with_browser_headers)
from fuzzlab.oracle import Oracle
from fuzzlab.oracle.probe import Candidate
from fuzzlab.oracle.strategies import SqliErrorStrategy
from fuzzlab.tools import probesender
from fuzzlab.tools.probesender import RequestsProbeSender

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "fuzzlab"

#: The navigation-only headers a fetch never sends (measured absent).
NAVIGATION_ONLY = ("sec-fetch-user", "upgrade-insecure-requests")
GENERIC_PAGE = "<html><body><h1>We're sorry, but something went wrong.</h1></body></html>"


# --- content negotiation, as each framework documents it -------------------------------
def _accept(header: str | None) -> list[tuple[str, float, int]]:
    """``Accept`` as (media range, q, position), RFC 9110 §12.5.1."""
    out = []
    for i, part in enumerate((header or "").split(",")):
        fields = [f.strip() for f in part.split(";")]
        if not fields[0]:
            continue
        q = 1.0
        for f in fields[1:]:
            if f.lower().startswith("q="):
                try:
                    q = float(f[2:])
                except ValueError:
                    q = 0.0
        out.append((fields[0].lower(), q, i))
    return out


def _matches(media_range: str, media_type: str) -> bool:
    if media_range == "*/*":
        return True
    rtype, _, rsub = media_range.partition("/")
    mtype, _, msub = media_type.partition("/")
    return rtype == mtype and rsub in ("*", msub)


def _specificity(media_range: str) -> int:
    return 0 if media_range == "*/*" else 1 if media_range.endswith("/*") else 2


def express_format(accept: str | None, handlers: list[str]) -> str | None:
    """Express 4 ``res.format`` (expressjs.com/en/4x/api/response#res.format): "uses
    req.accepts() to select a handler … based on the acceptable types ordered by their
    quality values. If the header is not specified, the first callback is invoked";
    its own example: with ``*/*`` "the response will be" the first handler's. Ties go to
    the more specific range, then to the handlers' order."""
    ranges = _accept(accept)
    if not ranges:
        return handlers[0]
    best, best_key = None, None
    for order, media_type in enumerate(handlers):
        for rng, q, pos in ranges:
            if q > 0 and _matches(rng, media_type):
                key = (q, _specificity(rng), -pos, -order)
                if best_key is None or key > best_key:
                    best, best_key = media_type, key
    return best


#: actionpack/lib/action_dispatch/http/mime_negotiation.rb (Rails main).
RAILS_BROWSER_LIKE_ACCEPTS = re.compile(r",\s*\*/\*|\*/\*\s*,")


def rails_respond_to(accept: str | None, xhr: bool, order: list[str]) -> str:
    """Rails ``formats`` + ``negotiate_mime``: the Accept header is used only when it is
    "valid" (``!accept.match?(BROWSER_LIKE_ACCEPTS)``, or any Accept on an XHR); its
    comment: "unless you include */* in your list, in which case we assume you're a
    browser and send HTML". Otherwise ``[Mime[:js]]`` on an XHR, else ``[Mime[:html]]``.
    ``negotiate_mime`` returns ``order.first`` for ``*/*`` (Mime::ALL), else the first
    accepted format the action declares."""
    if accept and (xhr or not RAILS_BROWSER_LIKE_ACCEPTS.search(accept)):
        formats = [rng for rng, q, _pos in sorted(_accept(accept), key=lambda r: (-r[1], r[2]))
                   if q > 0]
    elif xhr:
        formats = ["text/javascript"]
    else:
        formats = ["text/html"]
    for priority in formats:
        if priority == "*/*":
            return order[0]
        if priority in order:
            return priority
    return "406"


def drf_select_renderer(accept: str | None, renderers: list[str]) -> str:
    """DRF ``DefaultContentNegotiation.select_renderer``
    (django-rest-framework.org/api-guide/content-negotiation/): "More specific media
    types are given preference to less specific media types"; between equals,
    "preference is given to based on the ordering of the renderers"; "'q' values are not
    taken into account". With ``*/*`` or no Accept, "REST framework will select the
    first renderer in the list" (api-guide/renderers/)."""
    ranges = [rng for rng, _q, _pos in _accept(accept)] or ["*/*"]
    for precedence in (2, 1, 0):
        tier = [r for r in ranges if _specificity(r) == precedence]
        for renderer in renderers:
            if any(_matches(r, renderer) for r in tier):
                return renderer
    return "406"


def spring_error_view(accept: str | None) -> str:
    """Spring Boot ``BasicErrorController`` (docs.spring.io/spring-boot/reference/web/
    servlet.html, Error Handling): "For machine clients, it produces a JSON response with
    details of the error … For browser clients, there is a 'whitelabel' error view";
    "the default is to handle text/html specifically and provide a fallback for
    everything else". An Accept that names text/html (or text/*) gets the HTML view."""
    for rng, q, _pos in _accept(accept):
        if q > 0 and rng in ("text/html", "text/*"):
            return "text/html"
    return "application/json"


class NegotiatingApp:
    """A loopback app in one framework's style. ``POST /api/items`` takes a JSON body,
    ``POST /items`` a form; each runs ``name`` through a real (in-memory) SQLite query,
    so a quote raises SQLite's own ``unrecognized token`` error. The error handler
    answers by content negotiation, as its style documents:

    * ``spring``: ``BasicErrorController`` with ``server.error.include-message=always``
      for the JSON fallback, and a custom generic ``error`` view for HTML;
    * ``drf``: the view raises an ``APIException`` with the database message as its
      detail; renderers ``[JSONRenderer, TemplateHTMLRenderer]``, whose HTML error is the
      generic ``500.html`` template ("Load and render a template named
      {status_code}.html", api-guide/renderers/);
    * ``express``: an error middleware with ``res.format({html, json})``, in the order of
      Express's own ``examples/error-pages`` handler (``html`` first);
    * ``rails``: ``rescue_from`` with ``respond_to { format.html; format.json }``, in the
      order of the jbuilder scaffold (``format.html`` first)."""

    STYLES = ("spring", "drf", "express", "rails")

    def __init__(self, style: str):
        assert style in self.STYLES
        self.style = style
        self.requests: list[dict[str, str]] = []      # each request's headers, lower-cased
        app = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):  # noqa: N802 - http.server API
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                headers = {k.lower(): v for k, v in self.headers.items()}
                app.requests.append(headers)
                if self.path == "/api/items":
                    name = json.loads(raw or b"{}").get("name", "")
                else:
                    name = dict(parse_qsl(raw.decode())).get("name", "")
                try:
                    db = sqlite3.connect(":memory:")
                    db.execute("CREATE TABLE items (name TEXT)")
                    db.execute(f"SELECT * FROM items WHERE name = '{name}'").fetchall()
                except sqlite3.Error as exc:
                    return self._error(headers, str(exc))
                self._reply(200, "application/json", b'{"items": []}')

            def _error(self, headers, message):
                ctype = app.negotiate(headers.get("accept"),
                                      headers.get("x-requested-with") == "XMLHttpRequest")
                if ctype == "application/json":
                    self._reply(500, "application/json",
                                json.dumps({"error": message}).encode())
                else:
                    self._reply(500, "text/html; charset=utf-8", GENERIC_PAGE.encode())

            def _reply(self, status, ctype, body):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def negotiate(self, accept: str | None, xhr: bool) -> str:
        if self.style == "spring":
            return spring_error_view(accept)
        if self.style == "drf":
            return drf_select_renderer(accept, ["application/json", "text/html"])
        if self.style == "express":
            return express_format(accept, ["text/html", "application/json"]) or "406"
        return rails_respond_to(accept, xhr, ["text/html", "application/json"])

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def app_of():
    apps = []

    def make(style):
        apps.append(NegotiatingApp(style))
        return apps[-1]
    yield make
    for a in apps:
        a.close()


def _json_probe(app, value="x'"):
    return RequestsProbeSender(timeout=5).send(
        app.base + "/api/items", "name", value, method="POST", location="json",
        entries=((("name",), "x"),))


def _form_probe(app, value="x'"):
    return RequestsProbeSender(timeout=5).send(
        app.base + "/items", "name", value, method="POST", location="body",
        entries=(("name", value),))         # a form point's entries carry the value


def _profile_on_wire(wire: dict[str, str], profile) -> list[str]:
    """Each ``profile`` header with another value on the wire (lower-cased names)."""
    return [f"{k}: {wire.get(k.lower())!r} != {v!r}" for k, v in profile.items()
            if wire.get(k.lower()) != v]


# --- the profiles on the wire ----------------------------------------------------------
def test_a_json_probe_sends_the_measured_fetch_set(app_of):
    """Rules fetch-accept-any, fetch-dest-empty, fetch-mode-cors, fetch-site-same-origin,
    fetch-no-user-activation, fetch-no-upgrade-insecure, kind-json-location-is-fetch."""
    app = app_of("spring")
    _json_probe(app, "x")
    wire = app.requests[-1]
    assert _profile_on_wire(wire, FETCH_HEADERS) == []
    assert wire["accept"] == "*/*" and wire["sec-fetch-mode"] == "cors"
    assert wire["sec-fetch-dest"] == "empty" and wire["sec-fetch-site"] == "same-origin"
    assert not any(h in wire for h in NAVIGATION_ONLY)
    assert wire["content-type"] == "application/json"


def test_a_form_probe_keeps_the_navigation_set(app_of):
    """Rules navigation-document, kind-otherwise-navigation."""
    app = app_of("spring")
    _form_probe(app, "x")
    wire = app.requests[-1]
    assert _profile_on_wire(wire, NAVIGATION_HEADERS) == []
    assert wire["content-type"] == "application/x-www-form-urlencoded"


def test_a_query_and_a_header_probe_keep_the_navigation_set():
    seen = []

    class Recorder(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            seen.append([(k.lower(), v) for k, v in self.headers.items()])
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        sender = RequestsProbeSender(timeout=5)
        sender.send(base + "/search", "q", "x")
        sender.send(base + "/search", "X-Trace", "zq1", location="header")
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)
    for raw in seen:
        assert _profile_on_wire(dict(raw), NAVIGATION_HEADERS) == []
    assert [v for k, v in seen[1] if k == "x-trace"] == ["zq1"]


def test_a_probed_accept_header_wins_and_is_sent_once():
    """Rule caller-wins, at the wire: a header point named ``accept`` keeps its value,
    once, over the profile's ``Accept``."""
    seen = []

    class Recorder(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            seen.append([(k.lower(), v) for k, v in self.headers.items()])
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        RequestsProbeSender(timeout=5).send(
            f"http://127.0.0.1:{srv.server_address[1]}/x", "accept", "application/json",
            location="header")
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)
    assert [v for k, v in seen[0] if k == "accept"] == ["application/json"]


def test_a_plus_json_whole_body_is_a_fetch():
    """Rule kind-json-body-is-fetch: a whole-body point declared ``+json`` (RFC 6839)."""
    session = _Recording()
    RequestsProbeSender(session=session).send(
        "http://localhost/api/patch", "body", '{"a":1}', method="PATCH", location="body",
        content_type="application/merge-patch+json")
    sent = session.calls[0]["headers"]
    assert sent["Accept"] == "*/*" and sent["Sec-Fetch-Mode"] == "cors"
    assert sent["Content-Type"] == "application/merge-patch+json"


def test_a_session_with_navigation_defaults_still_sends_only_the_fetch_set(app_of):
    """``requests`` merges session defaults under the request's headers; the owner sets
    each navigation-only name to ``None``, which ``requests`` documents as omitting a
    session-level key, so neither reaches the wire."""
    app = app_of("drf")
    session = requests.Session()
    session.headers.update(browser_headers("navigation"))
    RequestsProbeSender(session=session, timeout=5).send(
        app.base + "/api/items", "name", "x", method="POST", location="json",
        entries=((("name",), "x"),))
    wire = app.requests[-1]
    assert _profile_on_wire(wire, FETCH_HEADERS) == []
    assert not any(h in wire for h in NAVIGATION_ONLY)


class _Recording:
    cookies: dict = {}

    def __init__(self, status=200, location=None):
        self.calls, self._status, self._location = [], status, location

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        status, location = (self._status, self._location) if len(self.calls) == 1 \
            else (200, None)

        class R:
            status_code, text = status, "ok"
            headers = {"Content-Type": "text/html", **({"Location": location}
                                                       if location else {})}
        return R()


def test_a_prg_follow_up_keeps_the_probes_kind():
    """Rule redirect-keeps-kind: a fetch follows its 303 as the same fetch."""
    session = _Recording(status=303, location="/api/items/1")
    RequestsProbeSender(session=session).send(
        "http://localhost/api/items", "name", "x", method="POST", location="json",
        entries=((("name",), "x"),), prg=True)
    probe_headers, follow_headers = (c["headers"] for c in session.calls)
    assert follow_headers["Sec-Fetch-Mode"] == "cors" == probe_headers["Sec-Fetch-Mode"]
    assert follow_headers["Accept"] == "*/*" and "Content-Type" not in follow_headers
    session = _Recording(status=303, location="/items/1")
    RequestsProbeSender(session=session).send(
        "http://localhost/items", "name", "x", method="POST", location="body",
        entries=(("name", "x"),), prg=True)
    assert session.calls[1]["headers"]["Sec-Fetch-Mode"] == "navigate"


# --- the owner --------------------------------------------------------------------------
def test_the_merge_is_case_insensitive_sends_each_name_once_and_copies():
    """Rule caller-wins."""
    given = {"accept": "application/json", "content-type": "application/json"}
    merged = with_browser_headers(given, kind="fetch")
    assert [k for k in merged if k.lower() == "accept"] == ["accept"]
    assert merged["accept"] == "application/json"
    assert given == {"accept": "application/json", "content-type": "application/json"}
    merged["X"] = "y"
    assert "X" not in browser_headers("fetch")      # a fresh copy every call
    removed = requests_browser_headers({"Content-Type": "application/json"}, kind="fetch")
    assert removed["Sec-Fetch-User"] is None and removed["Upgrade-Insecure-Requests"] is None
    assert None not in requests_browser_headers(None, kind="navigation").values()


@pytest.mark.parametrize("value,expected", [
    ("application/json", True), ("Application/JSON; charset=utf-8", True),
    ("application/problem+json", True), ("application/vnd.api+json", True),
    (b"application/json", True), ("application/x-www-form-urlencoded", False),
    ("multipart/form-data; boundary=x", False), ("text/plain", False),
    ("application/jsonp", False), ("json", False), ("", False), (None, False), (3, False),
])
def test_what_counts_as_a_json_body(value, expected):
    """Rule kind-json-body-is-fetch; total on odd input."""
    assert is_json_media_type(value) is expected
    assert request_kind({"CONTENT-TYPE": value} if isinstance(value, str) else None) == \
        ("fetch" if expected and isinstance(value, str) else "navigation")


def test_the_kind_comes_from_the_request_only():
    """Rules kind-json-location-is-fetch, kind-otherwise-navigation."""
    assert request_kind(None, "json") == "fetch"
    for location in ("query", "body", "header", None):
        assert request_kind({"Content-Type": "application/x-www-form-urlencoded"},
                            location) == "navigation"
    with pytest.raises(ValueError):
        browser_headers("xhr")


def test_every_rule_has_a_fixture():
    """PA-0111(2): each emulated rule names the test that exercises it."""
    fixtures = {
        "fetch-accept-any": test_a_json_probe_sends_the_measured_fetch_set,
        "fetch-dest-empty": test_a_json_probe_sends_the_measured_fetch_set,
        "fetch-mode-cors": test_a_json_probe_sends_the_measured_fetch_set,
        "fetch-site-same-origin": test_a_json_probe_sends_the_measured_fetch_set,
        "fetch-no-user-activation": test_a_session_with_navigation_defaults_still_sends_only_the_fetch_set,
        "fetch-no-upgrade-insecure": test_a_session_with_navigation_defaults_still_sends_only_the_fetch_set,
        "navigation-document": test_a_form_probe_keeps_the_navigation_set,
        "kind-json-body-is-fetch": test_a_plus_json_whole_body_is_a_fetch,
        "kind-json-location-is-fetch": test_the_kind_comes_from_the_request_only,
        "kind-otherwise-navigation": test_a_query_and_a_header_probe_keep_the_navigation_set,
        "redirect-keeps-kind": test_a_prg_follow_up_keeps_the_probes_kind,
        "caller-wins": test_a_probed_accept_header_wins_and_is_sent_once,
    }
    assert set(fixtures) == set(BROWSER_HEADER_RULES)


# --- the four negotiating styles --------------------------------------------------------
_HTML_FIRST = pytest.mark.xfail(
    strict=True, reason="measured: under the browser's own Accept */* an html-first "
    "Express res.format / Rails respond_to answers its first format, HTML; only the "
    "app's own client Accept reveals the JSON detail (follow-on: replay the app's "
    "captured Accept per endpoint, DISC-CAPTURE)")
STYLE_PARAMS = [pytest.param("spring"), pytest.param("drf"),
                pytest.param("express", marks=_HTML_FIRST),
                pytest.param("rails", marks=_HTML_FIRST)]


@pytest.mark.parametrize("style", STYLE_PARAMS)
def test_a_json_probe_gets_the_json_evidence(app_of, style):
    app = app_of(style)
    probe = _json_probe(app)
    assert probe.status == 500
    assert "unrecognized token" in probe.text and probe.headers["Content-Type"] == \
        "application/json"


@pytest.mark.parametrize("style", NegotiatingApp.STYLES)
def test_a_form_probe_gets_the_generic_page_with_the_navigation_set(app_of, style):
    app = app_of(style)
    probe = _form_probe(app)
    assert probe.status == 500 and probe.text == GENERIC_PAGE
    assert _profile_on_wire(app.requests[-1], NAVIGATION_HEADERS) == []


@pytest.mark.parametrize("style", NegotiatingApp.STYLES)
def test_the_navigation_set_hides_the_json_evidence(app_of, style):
    """BUG-0152's defect: the same JSON probe with the navigation set (what every
    requests-based sender sent before) gets the generic page in every style."""
    app = app_of(style)
    r = requests.post(app.base + "/api/items", data=json.dumps({"name": "x'"}),
                      headers=requests_browser_headers(
                          {"Content-Type": "application/json"}, kind="navigation"),
                      timeout=5, allow_redirects=False)
    assert r.status_code == 500 and r.text == GENERIC_PAGE


@pytest.mark.parametrize("style", NegotiatingApp.STYLES)
def test_the_apps_own_accept_reveals_the_evidence_in_every_style(app_of, style):
    """Rule caller-wins: the hook a captured per-endpoint Accept will use. An Accept the
    app's client sends (``application/json``) wins over the profile and reveals the JSON
    detail in all four styles."""
    app = app_of(style)
    r = requests.post(app.base + "/api/items", data=json.dumps({"name": "x'"}),
                      headers=requests_browser_headers(
                          {"Content-Type": "application/json", "Accept": "application/json"},
                          kind="fetch"),
                      timeout=5, allow_redirects=False)
    assert app.requests[-1]["accept"] == "application/json"
    assert r.status_code == 500 and "unrecognized token" in r.json()["error"]


def test_the_designs_accept_is_a_browser_accept_to_rails():
    """The design's ``application/json, text/plain, */*`` (the axios / Angular HttpClient
    default, not the browser's) is "browser-like" to Rails, which then sends HTML unless
    the request is an XHR: no profile value alone serves every style."""
    angular = "application/json, text/plain, */*"
    order = ["text/html", "application/json"]
    assert rails_respond_to(angular, xhr=False, order=order) == "text/html"
    assert rails_respond_to(angular, xhr=True, order=order) == "application/json"
    assert rails_respond_to("*/*", xhr=False, order=order) == "text/html"
    assert express_format(angular, ["text/html", "application/json"]) == "application/json"
    assert express_format("*/*", ["text/html", "application/json"]) == "text/html"
    assert drf_select_renderer(NAVIGATION_HEADERS["Accept"],
                               ["application/json", "text/html"]) == "text/html"


@pytest.mark.parametrize("profile,confirms", [("fetch", True), ("navigation", False)])
def test_the_sqli_oracle_confirms_a_json_point_only_with_the_fetch_set(
        app_of, monkeypatch, profile, confirms):
    """End to end: M2's SQL error signature, at a JSON-body point of a Spring-style app,
    through ``RequestsProbeSender``. With the navigation set (the defect, forced here)
    the evidence is hidden and nothing confirms."""
    app = app_of("spring")
    if profile == "navigation":
        monkeypatch.setattr(probesender, "request_kind", lambda *a, **k: "navigation")
    cand = Candidate(url=app.base + "/api/items", param="name", method="POST",
                     location="json", vuln_class="sqli",
                     base_entries=((["name"], "x"),))
    verdict = Oracle(strategies=[SqliErrorStrategy()]).confirm(
        cand, RequestsProbeSender(timeout=5))
    assert (verdict is not None) is confirms
    if confirms:
        assert verdict.evidence["dbms"] == "SQLite"


# --- the whole-package guards -----------------------------------------------------------
#: Requests-session sends that do not take their headers from the owner, each with its
#: reason. A stale entry fails.
SESSION_SEND_ALLOWED = {
    ("fuzzlab/session/manager.py", "get"):
        "the session manager's login client (owned by the BUG-0148 lane): a login page "
        "and a form login are navigations; its session defaults carry the navigation "
        "set. A JSON-API login would need requests_browser_headers (reported, BUG-0152)",
    ("fuzzlab/session/manager.py", "post"):
        "as above: the login form's submission is a navigation",
    ("fuzzlab/tools/navguard.py", "get_checked"):
        "the crawler's and auditor's static page GET (owned by the DISC-CAPTURE lane): a "
        "document fetch, which is a navigation; the session defaults carry that set",
    ("fuzzlab/lab_fixtures/external.py", "_fetch_locked"):
        "the pinned bWAPP archive download for lab setup: not target traffic",
    ("fuzzlab/lab_fixtures/external.py", "request"):
        "the external lab's setup client (login, security level): server-rendered "
        "forms, navigations; its session defaults are browser_headers('navigation')",
}
#: Modules that may name a profile constant instead of calling the owner.
CONSTANT_ALLOWED = {
    "fuzzlab/session/manager.py":
        "the login client's session defaults (owned by the BUG-0148 lane; not editable "
        "here): DEFAULT_BROWSER_HEADERS is the navigation set",
    "fuzzlab/tools/spider.py":
        "the crawler's session defaults (owned by the DISC-CAPTURE lane; not editable "
        "here): page navigations; DEFAULT_BROWSER_HEADERS is the navigation set",
}
VERBS = {"request", "get", "post", "put", "patch", "delete", "head", "options"}
PROFILE_NAMES = {"DEFAULT_BROWSER_HEADERS", "NAVIGATION_HEADERS", "FETCH_HEADERS",
                 "BROWSER_HEADER_PROFILES"}
OWNER_MERGES = {"with_browser_headers", "requests_browser_headers"}


def _is_session(node: ast.AST) -> bool:
    """``sess`` and ``*session`` names, and ``self._session``/``self.session``."""
    if isinstance(node, ast.Name):
        return node.id == "sess" or node.id.endswith("session")
    return isinstance(node, ast.Attribute) and node.attr.endswith("session")


def _called(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        f = node.func
        return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) \
            else None
    return None


def session_send_offenders(tree: ast.Module, rel: str) -> set[tuple[str, str]]:
    """(module, function) of each requests-session send whose function never calls the
    owner's ``requests_browser_headers``."""
    out = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        inner = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        sends = [c for c in inner if isinstance(c.func, ast.Attribute)
                 and c.func.attr in VERBS and _is_session(c.func.value)]
        nested = {n for sub in ast.walk(fn) if sub is not fn
                  and isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
                  for n in ast.walk(sub)}
        sends = [c for c in sends if c not in nested]
        if sends and not any(_called(c) == "requests_browser_headers" for c in inner
                             if c not in nested):
            out.add((rel, fn.name))
    return out


def constant_offenders(tree: ast.Module, rel: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in PROFILE_NAMES:
            return True
        if isinstance(node, ast.Attribute) and node.attr in PROFILE_NAMES:
            return True
        if isinstance(node, ast.ImportFrom) and any(a.name in PROFILE_NAMES
                                                   for a in node.names):
            return True
    return False


def kindless_merges(tree: ast.Module, rel: str) -> list[int]:
    """Lines of owner-merge calls that leave the kind to the default (or pass a literal):
    a send states its kind from ``request_kind`` (or a name holding it)."""
    out = []
    for node in ast.walk(tree):
        if _called(node) in OWNER_MERGES:
            kind = next((k.value for k in node.keywords if k.arg == "kind"), None)
            if kind is None or not (isinstance(kind, ast.Name)
                                    or _called(kind) == "request_kind"):
                out.append(node.lineno)
    return out


def _package():
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel == "fuzzlab/core/http.py":
            continue
        yield rel, ast.parse(path.read_text(encoding="utf-8"), filename=rel)


pytestmark_guard = pytest.mark.package_guard


@pytestmark_guard
def test_every_requests_sender_takes_its_headers_from_the_owner():
    """SP-38: every requests-session send in ``fuzzlab/`` takes its per-request headers
    from ``core.http.requests_browser_headers``, with its kind from ``request_kind``;
    no module but ``core/http.py`` names a profile constant. Listed exceptions carry a
    reason; a stale exception fails. Stated limit: a session reached under a name that
    does not end in ``session`` (or is ``sess``) is not seen, nor a
    ``requests.request``/``requests.get`` module call: today the core seam's transport
    (no browser set on this branch; BUG-0119, unmerged) and the labgen identifier-SQLi
    runner (generated-lab harness; ``fuzzlab.labgen`` may not import ``core.http``)."""
    sends, constants, kindless = set(), set(), []
    for rel, tree in _package():
        sends |= session_send_offenders(tree, rel)
        if constant_offenders(tree, rel):
            constants.add(rel)
        kindless += [f"{rel}:{n}" for n in kindless_merges(tree, rel)]
    assert sends - set(SESSION_SEND_ALLOWED) == set()
    assert set(SESSION_SEND_ALLOWED) - sends == set(), "stale exception"
    assert constants - set(CONSTANT_ALLOWED) == set()
    assert set(CONSTANT_ALLOWED) - constants == set(), "stale exception"
    assert kindless == []


@pytestmark_guard
def test_the_header_guard_catches_synthetic_offenders():
    """PA-0034(2): each rule flags its offender and passes its compliant twin."""
    offender = ast.parse(
        "import requests\n"
        "from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS\n"
        "class S:\n"
        "    def __init__(self):\n"
        "        self._session = requests.Session()\n"
        "        self._session.headers.update(DEFAULT_BROWSER_HEADERS)\n"
        "    def send(self, url, body):\n"
        "        return self._session.request('POST', url, data=body,\n"
        "            headers={'Content-Type': 'application/json'})\n"
        "    def merge(self, h):\n"
        "        return with_browser_headers(h)\n")
    assert session_send_offenders(offender, "x.py") == {("x.py", "send")}
    assert constant_offenders(offender, "x.py")
    assert kindless_merges(offender, "x.py") == [11]
    compliant = ast.parse(
        "import requests\n"
        "from fuzzlab.core.http import browser_headers, request_kind, requests_browser_headers\n"
        "class S:\n"
        "    def __init__(self):\n"
        "        self._session = requests.Session()\n"
        "        self._session.headers.update(browser_headers('navigation'))\n"
        "    def send(self, url, body):\n"
        "        h = {'Content-Type': 'application/json'}\n"
        "        return self._session.request('POST', url, data=body,\n"
        "            headers=requests_browser_headers(h, kind=request_kind(h)))\n")
    assert session_send_offenders(compliant, "x.py") == set()
    assert not constant_offenders(compliant, "x.py")
    assert kindless_merges(compliant, "x.py") == []
    # a nested client's send is judged in its own function (the session manager shape)
    nested = ast.parse(
        "def factory(h):\n"
        "    sess = requests.Session()\n"
        "    requests_browser_headers(h, kind=request_kind(h))\n"
        "    class F:\n"
        "        def get(self, url):\n"
        "            return sess.get(url)\n"
        "    return F\n")
    assert session_send_offenders(nested, "x.py") == {("x.py", "get")}
    # the BUG-0119 branch's seam merge, unmerged here, states no kind: caught on merge
    assert kindless_merges(ast.parse("with_browser_headers(request.headers)\n"), "x") == [1]


def test_the_profiles_are_defined_in_the_owner_only():
    assert core_http.DEFAULT_BROWSER_HEADERS is core_http.NAVIGATION_HEADERS
    assert set(core_http.BROWSER_HEADER_PROFILES) == {"navigation", "fetch"}
