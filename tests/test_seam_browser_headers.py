"""BUG-0119 / PA-0119: the core seam sends the full browser header set (PA-0062).

Ported from the dropped branch ``bug-0118-v3`` on the owner's decision D69 ("We are
maintaining the use of real browser headers for every request"), without the SQLi
gate (D68). Integrated with BUG-0152: the set is the request's own kind's (SP-38), a
navigation's for a query or form, the measured fetch set for a JSON body.

`HttpClient`'s default transport called ``requests.request`` with only the request's
own headers, so every authenticated probe (`SeamProbeSender`), the auditor's and the
blind-SQLi fuzzer's seam paths went out as ``python-requests/x.y`` with ``Accept: */*``
-- while the session manager logged in with `DEFAULT_BROWSER_HEADERS`. An app that
binds its session to the client it logged in with saw a different client on every
probe. Each test here sends through the real transport to a real loopback server that
records what arrived on the wire (PA-0139(3): a realistic data path, not a fake
transport handed the request's own dict).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.http import (DEFAULT_BROWSER_HEADERS, FETCH_HEADERS, HttpClient,
                               Request, with_browser_headers)
from fuzzlab.core.net import require_loopback
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools.probesender import SeamProbeSender
from tests.test_credentials import FakeBackend

USER, PASSWORD = "alice", "PW-headers-5b1e"
LOGIN_FORM = ("<html><body><form method='post' action='/login'>"
              "<input name='user'><input type='password' name='pw'>"
              "<input type='submit' value='Sign in'></form></body></html>")


class _UaBoundApp:
    """A loopback app whose session is bound to the client that logged in: ``/api/me``
    answers 200 only with a live ``sid`` *and* the User-Agent the login came from (a
    common anti-session-theft check). Every request's headers are recorded, as a
    list of ``(name, value)`` pairs exactly as they arrived."""

    def __init__(self):
        self.seen: list[tuple[str, list[tuple[str, str]]]] = []
        self.sessions: dict[str, str] = {}            # sid -> the login's User-Agent
        self._lock = threading.Lock()
        require_loopback("127.0.0.1")                 # PA-0130: a loopback listener only
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self):
                with app._lock:
                    app.seen.append((self.path, list(self.headers.items())))

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _sid(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "sid" and app.sessions.get(value) == \
                            self.headers.get("User-Agent"):
                        return value
                return None

            def do_GET(self):  # noqa: N802 - http.server API
                self._record()
                path = self.path.split("?", 1)[0]
                if path == "/login":
                    return self._send(200, LOGIN_FORM.encode())
                if path == "/api/me":
                    return self._send(200, b"<p>welcome alice</p>") if self._sid() \
                        else self._send(401, b"<p>log in</p>")
                return self._send(200, b"<html><body>home</body></html>")

            def do_POST(self):  # noqa: N802 - http.server API
                self._record()
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode()))
                if self.path == "/login" and form.get("user") == USER \
                        and form.get("pw") == PASSWORD:
                    sid = f"sid-{len(app.sessions)}-0123456789abcdef"
                    with app._lock:
                        app.sessions[sid] = self.headers.get("User-Agent") or ""
                    return self._send(200, b"<html><p>welcome alice</p></html>",
                                      [("Set-Cookie", f"sid={sid}; Path=/")])
                return self._send(200, LOGIN_FORM.encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def headers_for(self, path_prefix: str) -> list[tuple[str, str]]:
        return [h for p, h in self.seen if p.startswith(path_prefix)][-1]


@pytest.fixture
def app():
    a = _UaBoundApp()
    try:
        yield a
    finally:
        a.close()


def _client(mgr=None) -> HttpClient:
    return HttpClient(RequestBudget(50), ["127.0.0.1"], session=mgr)


def _mgr() -> SessionManager:
    creds = CredentialStore(backend=FakeBackend())
    creds.set("127.0.0.1", "user", USER, PASSWORD)
    return SessionManager(creds, scope_hosts=["127.0.0.1"], browser_login=False)


def _by_name(pairs) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, value in pairs:
        out.setdefault(name.lower(), []).append(value)
    return out


def test_an_authenticated_seam_probe_carries_the_logins_browser_headers(app):
    """The session the manager established with the browser header set still works on
    the probe: the probe arrives with every `DEFAULT_BROWSER_HEADERS` header (once
    each), never ``python-requests``. Before BUG-0119's fix the probe came with
    ``python-requests/x.y`` and the UA-bound app answered 401."""
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", app.base, operator=True)
    sender = SeamProbeSender(_client(mgr), identity="user")
    probe = sender.send(app.base + "api/me", "q", "1")
    assert probe.status == 200 and "welcome alice" in probe.text
    got = _by_name(app.headers_for("/api/me"))
    for name, value in DEFAULT_BROWSER_HEADERS.items():
        assert got.get(name.lower()) == [value], name
    assert not any("python-requests" in v for vs in got.values() for v in vs)


def test_the_seam_sends_the_same_header_set_the_login_sent(app):
    """PA-0119: one client identity per run -- the login's headers and the probe's
    agree on every browser header."""
    mgr = _mgr()
    mgr.ensure("127.0.0.1", "user", app.base, operator=True)
    SeamProbeSender(_client(mgr), identity="user").send(app.base + "api/me", "q", "1")
    login = _by_name(app.headers_for("/login"))
    probe = _by_name(app.headers_for("/api/me"))
    for name in DEFAULT_BROWSER_HEADERS:
        assert probe[name.lower()] == login[name.lower()], name


def test_a_header_point_value_wins_and_is_sent_once(app):
    """A probe at the ``User-Agent`` header point sends its payload as the only
    User-Agent; the rest of the browser set still goes with it."""
    SeamProbeSender(_client()).send(app.base + "x", "User-Agent", "fz-ua-probe",
                                    location="header")
    got = _by_name(app.headers_for("/x"))
    assert got["user-agent"] == ["fz-ua-probe"]
    assert got["accept-language"] == [DEFAULT_BROWSER_HEADERS["Accept-Language"]]


def test_a_json_probe_keeps_its_own_content_type(app):
    """A JSON body is a script's fetch (BUG-0152): the seam sends the measured fetch set,
    each header once, with the probe's own content type."""
    SeamProbeSender(_client()).send(app.base + "j", "a", "1", method="POST",
                                    location="body", content_type="application/json")
    got = _by_name(app.headers_for("/j"))
    assert got["content-type"] == ["application/json"]
    for name, value in FETCH_HEADERS.items():
        assert got.get(name.lower()) == [value], name
    assert "sec-fetch-user" not in got and "upgrade-insecure-requests" not in got


def test_a_seam_json_leaf_probe_carries_the_fetch_set(app):
    """A JSON-leaf point (``location == "json"``) through the seam (BUG-0152)."""
    SeamProbeSender(_client()).send(app.base + "jl", "a", "1", method="POST",
                                    location="json", entries=((("a",), "x"),))
    got = _by_name(app.headers_for("/jl"))
    assert got["accept"] == ["*/*"] and got["sec-fetch-mode"] == ["cors"]
    assert got["sec-fetch-dest"] == ["empty"] and "sec-fetch-user" not in got


def test_the_merge_is_case_insensitive_and_never_mutates_the_request(app):
    req = Request("GET", app.base + "m", headers={"accept": "application/json"})
    _client().send(req)
    assert req.headers == {"accept": "application/json"}        # the caller's object
    got = _by_name(app.headers_for("/m"))
    assert got["accept"] == ["application/json"]
    merged = with_browser_headers({"user-agent": "x", "Cookie": "a=b"})
    assert [k for k in merged if k.lower() == "user-agent"] == ["user-agent"]
    assert merged["Cookie"] == "a=b"
    assert with_browser_headers(None) == DEFAULT_BROWSER_HEADERS


@pytest.mark.xfail(strict=True, reason="pending at integration: tools/spider.py is the "
                   "DISC-CAPTURE lane's file and was not edited here (BUG-0119 port, D69); "
                   "the change is listed in BUG-0119's corrective action")
def test_the_spiders_api_form_submit_sends_the_browser_header_set(tmp_path):
    """The crawler's scope-checked form submit through a Playwright API request context
    (BUG-0119 sweep): that client's own defaults are not a browser's, so it gets the
    same set, the session's own headers winning. A urlencoded form submit takes a
    navigation's set."""
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.2:3000/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    got = []

    class Ctx:
        def fetch(self, *a, **k):
            return type("R", (), {"status": 200, "headers": {}})()

        def dispose(self):
            pass

    class RequestApi:
        def new_context(self, storage_state=None, extra_http_headers=None):
            got.append(extra_http_headers)
            return Ctx()
    sp.engine = "playwright"
    sp._pw = type("PW", (), {"request": RequestApi()})()
    sp._page = type("P", (), {"context": type("C", (), {
        "storage_state": lambda _s: {"cookies": [], "origins": []}})()})()
    sp._isolated_submit("POST", "http://127.0.0.2:3000/f", [("a", "1")])
    sp._auth_headers = {"Authorization": "Bearer t"}
    sp._header_scope = lambda _u: True
    sp._isolated_submit("POST", "http://127.0.0.2:3000/f", [("a", "1")])
    assert got[0] == DEFAULT_BROWSER_HEADERS
    assert got[1] == {**DEFAULT_BROWSER_HEADERS, "Authorization": "Bearer t"}
    sp.storage.close()


def test_the_labgen_identifier_oracle_runner_is_a_lab_harness_exception(app):
    """The generator-time identifier-SQLi runner sends to the toolkit's own generated
    lab, like the conformance harnesses, and labgen may not import `fuzzlab.core`
    (`test_procutil_guard`): it is a listed exception, and it still sends the caller's
    header and cookie unchanged."""
    from fuzzlab.labgen.identifier_sqli_oracle import default_http_runner
    assert ("fuzzlab/labgen/identifier_sqli_oracle.py", "default_http_runner") in _ALLOWED
    result = default_http_runner(app.base + "r?col=name", {"X-Probe": "1"}, "a=b", 5.0)
    assert result.status_code == 200
    got = _by_name(app.headers_for("/r"))
    assert got["x-probe"] == ["1"] and got["cookie"] == ["a=b"]


# --- PA-0119: every non-browser HTTP client of fuzzlab gets the full browser set -------
import ast  # noqa: E402
from pathlib import Path  # noqa: E402

_REQUESTS_CALLS = {"request", "get", "post", "put", "patch", "delete", "head", "options"}
#: A Playwright API request context's verbs (``context.request.<verb>(...)``).
_PLAYWRIGHT_VERBS = {"get", "post", "put", "patch", "delete", "head", "fetch"}
#: Conformance harnesses of the generated loopback labs (review round 1, B3): they send
#: to the toolkit's **own** generated app to check its ground truth (each twin's
#: response to an exact request), not probe traffic to a target under test; the
#: browser set's ``Accept: text/html`` and ``Sec-Fetch-*`` would change the content
#: negotiation of the very responses those tests assert (a Spring or Rails error page
#: renders HTML instead of JSON), and the live boots cannot run in every environment
#: to verify such a change.
_LAB_HARNESS = ("a conformance harness request to the toolkit's own generated "
                "loopback lab, not target traffic (see `_LAB_HARNESS`)")
#: (module path, enclosing function) -> why that client needs no browser header set.
_ALLOWED = {
    ("fuzzlab/core/http.py", "_requests_transport"):
        "the seam's transport: `HttpClient.send` hands it `with_browser_headers(...)` "
        "(pinned by the real-server tests above, which fail without it)",
    ("fuzzlab/tools/spider.py", "_isolated_request"):
        "the guard's withheld fetches forward the routed browser request's own headers "
        "on every fetch (navguard.isolated_fetch), so the browser's set is what goes",
    ("fuzzlab/lab_fixtures/external.py", "_fetch_locked"):
        "downloads the pinned bWAPP archive for lab setup (https only, sha256-checked): "
        "never traffic to a target, so a browser's header set has no meaning there",
    ("fuzzlab/labgen/conformance/live_boot.py", "request"): _LAB_HARNESS,
    ("fuzzlab/labgen/identifier_sqli_oracle.py", "default_http_runner"): _LAB_HARNESS,
    ("fuzzlab/labgen/conformance/rails_live_boot.py", "request"): _LAB_HARNESS,
    ("fuzzlab/labgen/conformance/live_boot_spring_boot.py", "request"): _LAB_HARNESS,
    ("fuzzlab/labgen/conformance/go_live_boot.py", "request"): _LAB_HARNESS,
    ("fuzzlab/labgen/conformance/django_live_boot.py", "request"): _LAB_HARNESS,
    ("fuzzlab/labgen/conformance/django_live_boot.py", "external_http_probe"):
        "a capability probe that a well-known external URL is reachable before a test "
        "relies on it (PA-0035); never traffic to a target",
}


_PROFILE_NAMES = {"DEFAULT_BROWSER_HEADERS", "NAVIGATION_HEADERS", "FETCH_HEADERS"}
#: The owner's calls that return a browser set (SP-36, SP-38).
_OWNER_CALLS = {"with_browser_headers", "requests_browser_headers", "browser_headers"}


def _strict_set(node) -> bool:
    """A profile constant itself, or a call of the owner that returns a set
    (``with_browser_headers``, ``requests_browser_headers``, ``browser_headers``)."""
    if isinstance(node, ast.Name) and node.id in _PROFILE_NAMES:
        return True
    if isinstance(node, ast.Attribute) and node.attr in _PROFILE_NAMES:
        return True
    return isinstance(node, ast.Call) and (
        getattr(node.func, "id", None) in _OWNER_CALLS
        or getattr(node.func, "attr", None) in _OWNER_CALLS)


def _headers_update(n) -> tuple[ast.AST, ast.AST] | None:
    """``(<x>, arg)`` for a ``<x>.headers.update(arg)`` call, else None."""
    if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "update" and isinstance(n.func.value, ast.Attribute)
            and n.func.value.attr == "headers" and n.args):
        return n.func.value.value, n.args[0]
    return None


def _browser_sessions(tree) -> set[str]:
    """The expressions (``ast.unparse``) whose ``.headers`` were updated with the strict
    set anywhere in the module, or with another such session's ``.headers``."""
    pairs = [u for u in map(_headers_update, ast.walk(tree)) if u]
    sessions = {ast.unparse(x) for x, arg in pairs if _strict_set(arg)}
    grew = True
    while grew:
        grew = False
        for x, arg in pairs:
            if (isinstance(arg, ast.Attribute) and arg.attr == "headers"
                    and ast.unparse(arg.value) in sessions and ast.unparse(x) not in sessions):
                sessions.add(ast.unparse(x))
                grew = True
    return sessions


def _is_browser_set(node, sessions: set[str] = frozenset()) -> bool:
    """The strict set, or ``<x>.headers`` of a session ``<x>`` whose headers were
    updated with the set (review round 1, B3): any other ``.headers`` -- a response's,
    a request's -- is not the browser set."""
    if _strict_set(node):
        return True
    return (isinstance(node, ast.Attribute) and node.attr == "headers"
            and ast.unparse(node.value) in sessions)


def _assigned_targets(tree) -> dict[int, str]:
    """``id(call) -> ast.unparse(target)`` for every ``<target> = <call>``."""
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) \
                and len(n.targets) == 1:
            out[id(n.value)] = ast.unparse(n.targets[0])
    return out


def _headerless_clients(source: str, where: str) -> list[str]:
    """Sites that open or call a non-browser HTTP client without the browser header
    set: a ``requests.Session()`` not bound to a name whose headers the enclosing
    function updates with the set, a ``requests.<verb>(...)`` without ``headers=`` the
    set, a Playwright ``<x>.request.new_context(...)`` without ``extra_http_headers=``
    the set, a Playwright ``<x>.request.<verb>(...)`` without ``headers=`` the set, and
    a ``urllib.request.Request(...)`` without ``headers=`` the set or any
    ``urllib.request.urlopen(...)`` / bare ``urlopen(...)``. Sites inside an
    `_ALLOWED` function are skipped. Stated limits: a client reached through another
    name (``from requests import get``, ``from urllib.request import Request``, an
    opener's ``open``) or a session whose headers are replaced later is not seen; the
    real-server tests are the proof, this is a lint (PA-0130(4))."""
    tree = ast.parse(source)
    sessions = _browser_sessions(tree)
    targets = _assigned_targets(tree)
    out: list[str] = []

    def updated_in(scope, target: str) -> bool:
        return any(u and ast.unparse(u[0]) == target and _is_browser_set(u[1], sessions)
                   for u in map(_headers_update, ast.walk(scope)))

    def check(call, scope):
        f = call.func
        kw = {k.arg: k.value for k in call.keywords}
        if isinstance(f, ast.Name) and f.id == "urlopen":
            out.append(f"{where}:{call.lineno}: urlopen()")
            return
        if not isinstance(f, ast.Attribute):
            return
        if isinstance(f.value, ast.Name) and f.value.id == "requests":
            if f.attr == "Session":
                target = targets.get(id(call))
                if target is None or not updated_in(scope, target):
                    out.append(f"{where}:{call.lineno}: requests.Session()")
            elif f.attr in _REQUESTS_CALLS and not (
                    "headers" in kw and _is_browser_set(kw["headers"], sessions)):
                out.append(f"{where}:{call.lineno}: requests.{f.attr}()")
        elif (isinstance(f.value, ast.Attribute) and f.value.attr == "request"
              and isinstance(f.value.value, ast.Name) and f.value.value.id == "urllib"):
            if f.attr == "urlopen":
                out.append(f"{where}:{call.lineno}: urllib.request.urlopen()")
            elif f.attr == "Request" and not (
                    "headers" in kw and _is_browser_set(kw["headers"], sessions)):
                out.append(f"{where}:{call.lineno}: urllib.request.Request()")
        elif (f.attr == "new_context" and isinstance(f.value, ast.Attribute)
              and f.value.attr == "request" and not (
                  "extra_http_headers" in kw and _is_browser_set(
                      kw["extra_http_headers"], sessions))):
            out.append(f"{where}:{call.lineno}: request.new_context()")
        elif (f.attr in _PLAYWRIGHT_VERBS and isinstance(f.value, ast.Attribute)
              and f.value.attr == "request"
              and not (isinstance(f.value.value, ast.Name)
                       and f.value.value.id in ("urllib", "requests"))
              and not ("headers" in kw and _is_browser_set(kw["headers"], sessions))):
            out.append(f"{where}:{call.lineno}: request.{f.attr}()")

    def walk(node, scope):
        for child in ast.iter_child_nodes(node):
            inner = child if isinstance(child, (ast.FunctionDef,
                                                ast.AsyncFunctionDef)) else scope
            if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                    (where, inner.name) in _ALLOWED:
                continue
            if isinstance(child, ast.Call):
                check(child, scope)
            walk(child, inner)

    walk(tree, tree)
    return out


#: Known sites not fixed in this change, each pinned by a strict xfail (PA-0054(3)):
#: (module, call shape) -> why it is pending.
_PENDING = {
    ("fuzzlab/tools/spider.py", "request.new_context()"):
        "LocalSpider._isolated_submit (the DISC-CAPTURE lane's file): needs "
        "extra_http_headers=with_browser_headers(headers, kind=request_kind(None, "
        "'body')), applied at integration",
    ("fuzzlab/tools/browserexec.py", "request.post()"):
        "the M6 stored plant: outside the D69 port's listed parts; flagged",
}


def _scan():
    root = Path(__file__).resolve().parents[1]
    found, used = [], set()
    for path in sorted((root / "fuzzlab").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
        found += _headerless_clients(source, rel)
        used |= {key for key in _ALLOWED if key[0] == rel
                 and f"def {key[1]}(" in source}
    return found, used


def _shape(site: str) -> tuple[str, str]:
    """``("<module>", "<call shape>")`` of a ``module:line: shape`` finding."""
    module, _line, shape = site.split(":", 2)
    return module, shape.strip()


@pytest.mark.package_guard
def test_no_http_client_goes_out_without_the_browser_header_set():
    """PA-0119 / PA-0062: every ``requests`` session or call, every Playwright API
    request context or ``context.request`` call and every ``urllib.request`` client in
    fuzzlab carries the full browser header set (browser contexts are a real browser
    and are out of scope). Allowances are listed with a reason; a stale one fails. The
    pending sites (`_PENDING`, each pinned by the strict xfail below) are the only
    other findings allowed, and each must still be found."""
    found, used = _scan()
    assert {_shape(f) for f in found} == set(_PENDING)
    assert used == set(_ALLOWED), "stale allowance"


@pytest.mark.xfail(strict=True, reason="the _PENDING sites: tools/spider.py at integration "
                   "(DISC-CAPTURE lane); tools/browserexec.py not in the D69 port")
def test_no_pending_http_client_remains():
    found, _used = _scan()
    assert found == []


@pytest.mark.package_guard
def test_the_header_guard_flags_synthetic_offenders():
    """PA-0034(2): proven on each offending shape, BUG-0119's own transport line
    included, and quiet on the fixed forms."""
    rogue = (
        "import requests\n"
        "def transport(m, u, h):\n"
        "    return requests.request(m, u, headers=dict(h))\n"
        "def bare():\n"
        "    s = requests.Session()\n"
        "    return s\n"
        "def api(pw):\n"
        "    return pw.request.new_context(extra_http_headers={'A': 'b'})\n"
        "def get(u):\n"
        "    return requests.get(u)\n")
    assert _headerless_clients(rogue, "rogue.py") == [
        "rogue.py:3: requests.request()", "rogue.py:5: requests.Session()",
        "rogue.py:8: request.new_context()", "rogue.py:10: requests.get()"]
    fixed = (
        "import requests\n"
        "def transport(m, u, h):\n"
        "    return requests.request(m, u, headers=with_browser_headers(h))\n"
        "def bare():\n"
        "    s = requests.Session()\n"
        "    s.headers.update(DEFAULT_BROWSER_HEADERS)\n"
        "    return s\n"
        "def api(pw, h):\n"
        "    return pw.request.new_context(extra_http_headers=with_browser_headers(h))\n")
    assert _headerless_clients(fixed, "fixed.py") == []


def test_the_header_guard_flags_the_round1_shapes():
    """Review round 1 (reviewer B, B3): ``urllib.request`` clients, a Playwright
    ``context.request.<verb>``, and a bare ``<x>.headers`` that is not a session's
    browser set (a response's headers) -- each flagged; the fixed forms are quiet."""
    rogue = (
        "import urllib.request, requests\n"
        "def lab(url):\n"
        "    req = urllib.request.Request(url, headers={'X': '1'})\n"
        "    return urllib.request.urlopen(req)\n"
        "def plant(context, url):\n"
        "    return context.request.post(url, form={}, max_redirects=0)\n"
        "def echo(resp, url):\n"
        "    return requests.get(url, headers=resp.headers)\n"
        "def other():\n"
        "    s = requests.Session()\n"
        "    t = requests.Session()\n"
        "    t.headers.update(DEFAULT_BROWSER_HEADERS)\n"
        "    return s\n"
        "def bare(url):\n"
        "    return urlopen(url)\n")
    assert _headerless_clients(rogue, "rogue.py") == [
        "rogue.py:3: urllib.request.Request()", "rogue.py:4: urllib.request.urlopen()",
        "rogue.py:6: request.post()", "rogue.py:8: requests.get()",
        "rogue.py:10: requests.Session()", "rogue.py:15: urlopen()"]
    fixed = (
        "import urllib.request, requests\n"
        "class Spider:\n"
        "    def __init__(self):\n"
        "        self.session = requests.Session()\n"
        "        self.session.headers.update(DEFAULT_BROWSER_HEADERS)\n"
        "    def submit(self, url):\n"
        "        iso = requests.Session()\n"
        "        iso.headers.update(self.session.headers)\n"
        "        return requests.get(url, headers=self.session.headers)\n"
        "def lab(url, h):\n"
        "    return urllib.request.Request(url, headers=with_browser_headers(h))\n"
        "def plant(context, url, ua):\n"
        "    return context.request.post(url, form={}, max_redirects=0,\n"
        "                                headers=with_browser_headers({'User-Agent': ua}))\n")
    assert _headerless_clients(fixed, "fixed.py") == []


@pytest.mark.xfail(strict=True, reason="not ported: the M6 plant (tools/browserexec.py) "
                   "is outside the D69 port's listed parts; flagged to the coordinator")
def test_the_m6_stored_plant_sends_the_browser_set_with_the_contexts_own_agent():
    """Review round 1 (B3): `browserexec`'s stored-XSS plant goes through the
    context's Playwright API client, whose defaults are not a browser's; it gets the
    browser set, with the context's own User-Agent winning so the plant and the
    observe navigation present one client."""
    import ast as _ast
    from pathlib import Path as _Path
    src = (_Path(__file__).resolve().parents[1] / "fuzzlab" / "tools" /
           "browserexec.py").read_text(encoding="utf-8")
    posts = [c for c in _ast.walk(_ast.parse(src)) if isinstance(c, _ast.Call)
             and getattr(c.func, "attr", None) == "post"]
    assert len(posts) == 1
    headers = {k.arg: k.value for k in posts[0].keywords}["headers"]
    assert getattr(headers.func, "id", None) == "with_browser_headers"
    assert "navigator.userAgent" in src
