"""A browser context that carries a session never sends a request to a host the
session's cookies do not reach (SP-74, BUG-0559, FR-CRAWL-43).

Before: the legacy spider's load gate (`LocalSpider._session_host_refusal`, BUG-0545
review round 2) checked only where a load *starts*. In an identity browser crawl a
redirect hop inside a load, a selector form's submission and a navigation the page made
itself (``location.replace``, a meta refresh) went to a loopback alias of the start --
``localhost`` for a session cookie held host-only for ``127.0.0.1`` -- without the
cookie, and the anonymous landing was filed as the identity's page. The guard's own
origin rule folds the loopback aliases into one origin, so it let them through; the
auditor's browser fetcher and disco's explorer had the same carrier.

Now `navguard` owns the decision (`cookie_reaches`, `session_host_refusal`): the route of
every context that adopted a session refuses every request, hop and socket to such a host
before it is sent, and `checked_api_request` refuses an API request the same way. The
spider files the load failed (unresolved), the fetcher returns no page, disco counts it.

Every site here is a loopback server this test starts, recording each request with the
``Host`` it was sent to; the alias is the same server reached as ``localhost``."""

from __future__ import annotations

import ast
import json
import sqlite3
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from fuzzlab.session.manager import SessionManager
from fuzzlab.tools import navguard
from fuzzlab.tools import spider as sp
from tests.test_session_origin_scope import PASSWORD, USER, _creds, _HdrRoute, _Resp
from tests.test_spider_static_identity import _IdSite

ROOT = Path(__file__).resolve().parents[1]


# --- the predicate (SP-74) ---------------------------------------------------------------
def test_a_cookie_reaches_its_own_host_or_a_name_under_its_dotted_domain_never_an_ip():
    """RFC 6265's domain match as the browser holds the cookie (measured on Chromium 141,
    `scratchpad/lanes/BROWSERALIAS/measure/reach.out`): by URL or by a bare domain it is
    host-only; a dotted domain reaches the names under it, never an IP address."""
    reach = navguard.cookie_reaches
    by_url = {"name": "sid", "url": "http://127.0.0.1:8000/"}
    bare = {"name": "sid", "domain": "127.0.0.1"}
    dotted = {"name": "sid", "domain": ".example.test"}
    assert reach(by_url, "127.0.0.1") and not reach(by_url, "localhost")
    assert reach(bare, "127.0.0.1") and not reach(bare, "localhost")
    assert not reach(by_url, "::1") and not reach(bare, "127.0.0.2")
    assert reach(dotted, "example.test") and reach(dotted, "App.Example.TEST")
    assert not reach(dotted, "example.test.evil") and not reach(dotted, "badexample.test")
    assert not reach({"name": "sid", "domain": "example.test"}, "app.example.test")
    assert not reach({"name": "sid", "domain": ".0.0.1"}, "127.0.0.1")    # never an IP
    assert not reach({"name": "sid"}, "127.0.0.1") and not reach(bare, "")
    # BA-2 (BUG-0559 review round 1): Chromium holds an IPv6 cookie by domain with its
    # brackets, '[::1]' (measured: `test_an_ipv6_cookie_as_chromium_holds_it_...`); a
    # URL's hostname has none. Both spellings meet without them
    v6 = {"name": "sid", "domain": "[::1]"}
    assert reach(v6, "::1") and reach(v6, "[::1]")
    assert reach({"name": "sid", "url": "http://[::1]:8000/"}, "::1")
    assert not reach(v6, "127.0.0.1") and not reach(v6, "localhost")
    assert not reach({"name": "sid", "domain": "[::2]"}, "::1")


def test_the_session_is_unreached_where_any_of_its_cookies_has_no_copy_there():
    held = navguard.held_session_cookies(
        [{"name": "sid", "value": "1", "url": "http://127.0.0.1:8000/"}],
        {"cookies": [{"name": "sid", "value": "1", "domain": "localhost"},
                     {"name": "tok", "value": "2", "domain": "127.0.0.1"},
                     {"name": "lang", "value": "en", "domain": "localhost"}]},
        {"sid", "tok"})
    assert {c["name"] for c in held} == {"sid", "tok"}                  # ambient dropped
    assert navguard.session_host_refusal(held, "http://127.0.0.1:8000/a") is None
    why = navguard.session_host_refusal(held, "http://localhost:8000/a")
    assert "do not reach host 'localhost'" in why and "1 of 2" in why  # tok has no copy
    assert navguard.session_host_refusal([], "http://localhost:8000/a") is None
    # another origin than the session's is FR-SESS-20's (withheld), never this rule's
    assert navguard.session_host_refusal(held, "http://localhost:8000/a",
                                         cookie_scope=lambda u: False) is None
    with pytest.raises(navguard.SessionHostUnreached, match="'localhost'"):
        navguard.checked_api_request(lambda u: True, "http://localhost:8000/a",
                                     session_cookies=held)
    navguard.checked_api_request(lambda u: True, "http://127.0.0.1:8000/a",
                                 session_cookies=held)


def _explorer(start, state):
    """disco's explorer, never run: its session material is what a context adopts."""
    from fuzzlab.disco.explore import Explorer
    return Explorer(start, scope_urls=[start], storage_state=state, proxy="127.0.0.1:9")


def test_a_storage_states_ambient_cookie_on_another_host_never_refuses_its_start_host():
    """BA-1 (BUG-0559 review round 1): an operator's storage state (`disco capture
    --storage-state`) holding the session cookie for 127.0.0.1 and an ambient cookie for
    the alias. The scope filter keeps both (it folds the aliases), and disco cannot tell
    the credential from the ambient cookie: the session's cookies are those that reach
    the start host. Its start host is never refused for the ambient cookie; the alias
    still is, for the session cookie. Before (72297c9): every adopted cookie was the
    session's, so ``lang`` (no copy on 127.0.0.1) refused the start host -- the run's
    start navigation was aborted (measured: ``net::ERR_ABORTED``)."""
    base = "http://127.0.0.1:8000/"
    state = {"cookies": [{"name": "sid", "value": "v", "domain": "127.0.0.1", "path": "/"},
                         {"name": "lang", "value": "en", "domain": "localhost",
                          "path": "/"}], "origins": []}
    material = _explorer(base, state)._current_session()
    held = material.session_cookies()
    assert {c["name"] for c in held} == {"sid"}, held
    assert navguard.session_host_refusal(held, base) is None
    assert navguard.session_host_refusal(held, base + "deeper?x=1") is None
    why = navguard.session_host_refusal(held, "http://localhost:8000/")
    assert why is not None and "'localhost'" in why                # sid never goes there


def test_a_storage_state_whose_session_no_cookie_carries_never_refuses_its_start_host():
    """BB-1 (BUG-0559 review round 2): a storage state none of whose cookies reaches the
    start host -- its session lives in ``localStorage``, and it holds one ambient cookie
    for the alias -- has no credential cookie: ``credential_names`` is an empty set (no
    cookie is the session's), never None (every adopted cookie counted), so the start
    host is never refused for the ambient cookie. The cookie case beside it keeps its
    credential. Before (c6296bc): None, so ``lang`` -- the only adopted cookie -- was the
    session's and refused 127.0.0.1 ("1 of 1"); the run's start was aborted (measured by
    the review: ``net::ERR_ABORTED``), where 7393c90 explored it."""
    base = "http://127.0.0.1:8000/"
    token = {"origin": "http://127.0.0.1:8000", "localStorage": [
        {"name": "token", "value": "jwt"}]}
    lang = {"name": "lang", "value": "en", "domain": "localhost", "path": "/"}
    stored = _explorer(base, {"cookies": [lang], "origins": [token]})._current_session()
    assert stored.credential_names == frozenset()
    assert stored.session_cookies() == []
    assert navguard.session_host_refusal(stored.session_cookies(), base) is None
    assert stored.storage_state["origins"] and stored.storage_state["cookies"]  # adopted
    # the cookie case: the session cookie reaching the start host is the credential
    sid = {"name": "sid", "value": "v", "domain": "127.0.0.1", "path": "/"}
    cookie = _explorer(base, {"cookies": [sid, lang], "origins": []})._current_session()
    assert cookie.credential_names == frozenset({"sid"})
    assert navguard.session_host_refusal(cookie.session_cookies(), base) is None
    assert navguard.session_host_refusal(cookie.session_cookies(),
                                         "http://localhost:8000/") is not None
    # a state whose only cookie is held for the alias: no cookie is the session's either
    elsewhere = {"cookies": [dict(sid, domain="localhost")], "origins": []}
    held = _explorer(base, elsewhere)._current_session().session_cookies()
    assert held == [] and navguard.session_host_refusal(held, base) is None


def test_an_ipv6_cookie_as_chromium_holds_it_reaches_its_own_host_and_no_other(monkeypatch):
    """BA-2 (BUG-0559 review round 1), measured in the real browser: a cookie set for
    ``http://[::1]:8000/`` is held by Chromium with the domain ``[::1]`` -- brackets
    included -- and the browser sends it there (``context.cookies(url)``). SP-74's
    predicate agrees: the session reaches ``[::1]`` and not 127.0.0.1; disco's material
    from that storage state never refuses its own ``[::1]`` start. Before (72297c9):
    ``'[::1]' != '::1'``, so every request to the session's own IPv6 host was refused,
    the start page included. (No IPv6 socket is needed: nothing is sent.)"""
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
                navguard.browser_launch_args(["http://[::1]:8000/"])))
            try:
                ctx = browser.new_context()
                ctx.add_cookies([{"name": "sid", "value": "1", "url": "http://[::1]:8000/"}])
                state = ctx.storage_state()
                sent = [c["name"] for c in ctx.cookies("http://[::1]:8000/")]
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
        from tests._browser import skip_or_fail
        skip_or_fail(f"chromium could not launch: {exc}")
    assert [(c["name"], c["domain"]) for c in state["cookies"]] == [("sid", "[::1]")]
    assert sent == ["sid"]                                   # the browser sends it there
    held = navguard.held_session_cookies(None, state, None)
    assert navguard.session_host_refusal(held, "http://[::1]:8000/x") is None
    assert navguard.session_host_refusal(held, "http://127.0.0.1:8000/x") is not None
    start = "http://[::1]:8000/"
    material = _explorer(start, state)._current_session().session_cookies()
    assert [c["name"] for c in material] == ["sid"]
    assert navguard.session_host_refusal(material, start) is None


# --- preloads (BA-3, BUG-0559 review round 1) ---------------------------------------------
class _Page:
    def __init__(self, url):
        self._url = url

    @property
    def url(self):
        if isinstance(self._url, Exception):
            raise self._url
        return self._url


def test_a_document_committed_on_an_unreached_host_is_never_the_sessions():
    """`committed_session_refusal`: the consumers' defence in depth behind the route --
    the main frame's committed document on a host the session's cookies do not reach
    (one a preload served) is refused with SP-74's cause; its own host, a page with no
    session cookie, ``about:blank``, the error page and a closed page are not."""
    cookies = [{"name": "sid", "value": "s", "url": "http://127.0.0.1:3000/"}]
    refusal = navguard.committed_session_refusal
    why = refusal(_Page("http://localhost:3000/secret"), cookies)
    assert why is not None and "'localhost'" in why
    assert refusal(_Page("http://127.0.0.1:3000/secret"), cookies) is None
    assert refusal(_Page("http://localhost:3000/secret"), []) is None
    for url in ("about:blank", "chrome-error://chromewebdata/", RuntimeError("closed")):
        assert refusal(_Page(url), cookies) is None
    # another origin than the session's is FR-SESS-20's, never this rule's
    assert refusal(_Page("http://localhost:3000/"), cookies,
                   cookie_scope=lambda u: False) is None


def test_the_route_gives_no_speculation_rule_set():
    """The route's answers (doubles): a ``Speculation-Rules`` header is dropped from every
    answer it fulfils, an isolated answer's ``Set-Cookie`` with it; a main-frame
    document's parser-inserted ``<script type=speculationrules>`` is given with an inert
    type, whatever its spelling, and nothing else of the page changes."""
    given = []

    class Route:
        def fulfill(self, response=None, status=None, headers=None, body=None):
            given.append((response, status, headers, body))

    class Answer:
        status = 200

        def __init__(self, headers):
            self.headers = headers

        def body(self):
            return b"x"
    plain = Answer({"content-type": "text/html"})
    navguard._fulfil_preload_free(Route(), plain)
    assert given.pop() == (plain, None, None, None)           # unchanged: no header
    rules = Answer({"content-type": "text/html", "Speculation-Rules": '"/r.json"'})
    navguard._fulfil_preload_free(Route(), rules)
    assert given.pop() == (rules, None, {"content-type": "text/html"}, None)
    iso = Answer({"set-cookie": "b=1", "speculation-rules": '"/r.json"'})
    navguard._fulfil_preload_free(Route(), iso, "set-cookie")
    assert given.pop() == (iso, None, {"content-length": "1"}, None)   # never empty
    html = ("<p>a</p><SCRIPT TYPE=SpeculationRules>{}</SCRIPT>"
            "<script type=\" speculationrules \">{}</script><script>var t ="
            " 'speculationrules';</script><template shadowrootmode=closed>"
            "<script type='speculationrules'>{}</script></template>")
    navguard._fulfil_preload_free(Route(), Answer({"content-type": "text/html",
                                                   "content-length": "9",
                                                   "content-encoding": "gzip"}),
                                  html=html)
    _resp, status, headers, body = given.pop()
    text = body.decode()
    assert status == 200 and "speculationrules\">" not in text.lower()
    assert text.lower().count(navguard.INERT_RULES_TYPE) == 3
    assert "var t = 'speculationrules';" in text and "<p>a</p>" in text
    assert headers == {"content-type": "text/html", "content-length": str(len(body))}
    assert navguard._inert_rule_sets("<p>speculation rules</p>") is None


def test_every_guarded_context_neutralises_preloads_before_its_pages_run():
    """`guard_page` installs `PRELOAD_OFF_JS` on the context it guards (popups
    included), before the route: no guarded page registers a speculation rule set."""
    calls = []

    class Ctx:
        def add_init_script(self, script=None, path=None):
            calls.append(("init", script))

        def route(self, pattern, handler):
            calls.append(("route", pattern))

        def route_web_socket(self, pattern, handler):
            calls.append(("ws", pattern))
    navguard.guard_page(Ctx(), in_scope=lambda u: True)
    assert calls[0] == ("init", navguard.PRELOAD_OFF_JS) and calls[1] == ("route", "**/*")
    assert "speculationrules" in navguard.PRELOAD_OFF_JS


def test_the_route_refuses_every_request_and_hop_to_an_unreached_host_before_it_is_sent():
    """The route (doubles): a navigation, a subresource and a redirect hop to the alias
    are aborted -- never fetched, the hop never asked of the context's client -- each told
    with its kind; the cookie's own host is fetched as before; an unauthenticated route
    (no session cookies) is unchanged; a WebSocket there is never connected."""
    told, api_calls = [], []

    class Api:
        def fetch(self, url, method=None, max_redirects=None, data=None, headers=None):
            api_calls.append(url)
            return _Resp(200)
    cookies = [{"name": "sid", "value": "s", "url": "http://127.0.0.1:3000/"}]
    in_scope = lambda u: urlsplit(u).port == 3000                   # noqa: E731
    handler = navguard.make_route_handler(
        in_scope=in_scope, api=Api(), session_cookies=cookies,
        on_session_unreached=lambda u, k, src, why: told.append((u, k, src)))
    own = _HdrRoute("http://127.0.0.1:3000/a")
    handler(own)
    assert own.fetched and own.outcome == "fulfill"
    doc = _HdrRoute("http://localhost:3000/a")
    handler(doc)
    assert doc.outcome == "abort" and not doc.fetched and doc.abort_code == "aborted"
    img = _HdrRoute("http://[::1]:3000/i.png", navigation=False)
    handler(img)
    assert img.outcome == "abort" and not img.fetched
    site = {"http://127.0.0.1:3000/go": _Resp(302, {"location":
                                                    "http://localhost:3000/land"})}
    hop = _HdrRoute("http://127.0.0.1:3000/go", site)
    handler(hop)
    assert hop.fetched and hop.outcome == "abort" and api_calls == []   # never fetched
    assert told == [("http://localhost:3000/a", "document", "http://localhost:3000/a"),
                    ("http://[::1]:3000/i.png", "request", "http://[::1]:3000/i.png"),
                    ("http://localhost:3000/land", "landing", "http://127.0.0.1:3000/go")]
    anon = _HdrRoute("http://localhost:3000/a")
    navguard.make_route_handler(in_scope=in_scope)(anon)
    assert anon.fetched                                     # no session: nothing withheld
    connected = []

    class WS:
        url = "ws://localhost:3000/socket"

        def connect_to_server(self):
            connected.append(self.url)
    navguard.make_ws_handler(in_scope, session_cookies=cookies,
                             on_session_unreached=lambda *a: told.append(a[:2]))(WS())
    assert connected == [] and told[-1] == ("ws://localhost:3000/socket", "websocket")


# --- every context that adopts a session hands its cookies to the guard (AST) ------------
#: Calls that put a session into a browser context.
_ADOPTERS = {"apply_to_context", "context_options"}
#: A function that opens an API request context with a storage state, exempt from
#: passing the session's cookies to `checked_api_request`, with the reason.
API_STORAGE_EXEMPT = {
    "fuzzlab/disco/explore.py:_protected_get": (
        "its URL is a page the guarded context committed (`_find_protected_resource`), "
        "and the route refuses a navigation to a host the cookies do not reach (SP-74), "
        "no preload serves one past it (`PRELOAD_OFF_JS`), and the probe skips a page "
        "committed on such a host (`committed_session_refusal`, BUG-0559 review round "
        "1), so it is a host they reach; or it carries no session (storage None)"),
}


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _api_context(node: ast.Call) -> bool:
    """``<x>.request.new_context(...)``: Playwright's API request context."""
    f = node.func
    return isinstance(f, ast.Attribute) and f.attr == "new_context" and \
        isinstance(f.value, ast.Attribute) and f.value.attr == "request"


def reach_offenders(source: str, module: str, exempt=None) -> list[str]:
    """SP-74's wiring rule: a module that adopts a session into a browser context
    (`browserauth.apply_to_context` / `context_options`, or ``new_context(storage_state=)``
    on a browser) passes ``session_cookies=`` to every `guard_page` it makes; a function
    that opens an API request context with a storage state passes ``session_cookies=``
    to its `checked_api_request` (or is exempt, with a reason)."""
    exempt = API_STORAGE_EXEMPT if exempt is None else exempt
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    adopts = any(_call_name(c) in _ADOPTERS or
                 (_call_name(c) == "new_context" and not _api_context(c) and
                  any(k.arg == "storage_state" for k in c.keywords)) for c in calls)
    out = []
    if adopts:
        out += [f"{module}:{c.lineno}: guard_page without session_cookies" for c in calls
                if _call_name(c) == "guard_page" and
                not any(k.arg == "session_cookies" for k in c.keywords)]
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        inner = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        stores = any(_api_context(c) and any(k.arg == "storage_state" for k in c.keywords)
                     for c in inner)
        checked = any(_call_name(c) == "checked_api_request" and
                      any(k.arg == "session_cookies" for k in c.keywords) for c in inner)
        if stores and not checked and f"{module}:{fn.name}" not in exempt:
            out.append(f"{module}:{fn.name}: an API request context with a storage "
                       f"state, and no checked_api_request(session_cookies=)")
    return out


def test_every_context_that_adopts_a_session_hands_its_cookies_to_the_guard():
    offenders = []
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        module = str(path.relative_to(ROOT))
        offenders += reach_offenders(path.read_text(encoding="utf-8"), module)
    assert offenders == []
    # the guard sees the known adopters (it is not vacuous)
    for module in ("fuzzlab/tools/spider.py", "fuzzlab/tools/fetcher.py",
                   "fuzzlab/disco/explore.py"):
        assert "session_cookies=" in (ROOT / module).read_text(encoding="utf-8")


def test_the_reach_guard_catches_synthetic_offenders():
    """Proven on the shapes BUG-0559 had (PA-0034(2)): the spider's, fetcher's and
    disco's guard without the session's cookies, and an API submission without them."""
    no_cookies = ("def start(ctx, session):\n"
                  "    guard_page(ctx, in_scope=f)\n"
                  "    browserauth.apply_to_context(ctx, session.cookies)\n")
    assert reach_offenders(no_cookies, "m.py") == [
        "m.py:2: guard_page without session_cookies"]
    by_state = ("def start(browser, auth):\n"
                "    ctx = browser.new_context(storage_state=auth.storage_state)\n"
                "    navguard.guard_page(ctx, in_scope=f)\n")
    assert len(reach_offenders(by_state, "m.py")) == 1
    submit = ("def submit(self, url):\n"
              "    checked_api_request(self._in_scope, url)\n"
              "    ctx = self._pw.request.new_context(storage_state=self.state)\n")
    assert reach_offenders(submit, "m.py") == [
        "m.py:submit: an API request context with a storage state, and no "
        "checked_api_request(session_cookies=)"]
    fixed = ("def submit(self, url):\n"
             "    checked_api_request(self._in_scope, url, session_cookies=c)\n"
             "    ctx = self._pw.request.new_context(storage_state=self.state)\n"
             "def start(ctx, session):\n"
             "    guard_page(ctx, in_scope=f, session_cookies=c)\n"
             "    browserauth.apply_to_context(ctx, session.cookies)\n")
    assert reach_offenders(fixed, "m.py") == []
    anonymous = "def start(ctx):\n    guard_page(ctx, in_scope=f)\n"
    assert reach_offenders(anonymous, "m.py") == []          # carries no session


# --- real browser, loopback ---------------------------------------------------------------
def _alias(site) -> str:
    return f"http://localhost:{urlsplit(site.base).port}"


def _to_alias(site) -> list[tuple[str, str, str]]:
    """``(method, path, Cookie)`` of every request the site got sent to ``localhost``."""
    with site._lock:
        return [(m, p, c) for h, (m, p, c, _ua) in zip(site.hosts, site.requests)
                if h.split(":")[0] == "localhost"]


def _browser_crawl(monkeypatch, tmp_path, site, **kw):
    """An identity crawl of ``site`` as 'user' in the browser, the CLI's default
    manager scope (``localhost`` and ``127.0.0.1``: its ``prepare`` would carry the
    session to the alias, so the browser's cookie alone decides)."""
    from tests._spa_fixture import chromium_or_skip, run_crawl
    chromium_or_skip(monkeypatch)
    mgr = SessionManager(_creds("127.0.0.1"), scope_hosts=["localhost", "127.0.0.1"],
                         browser_login=False)
    db = str(tmp_path / "s.db")
    try:
        spider = sp.LocalSpider(site.base, max_depth=kw.pop("max_depth", 2), db_name=db,
                                engine="playwright", session_manager=mgr,
                                identity="user", timeout_ms=8000, **kw)
        run_crawl(spider)
    finally:
        site.close()
    con = sqlite3.connect(db)
    try:
        pages = {u: (s, c or "", o, e) for u, s, c, o, e in con.execute(
            "SELECT url, status_code, content, outcome, error FROM discovered_pages")}
        stats = dict(con.execute("SELECT name, value FROM crawl_stats"))
    finally:
        con.close()
    return spider, pages, stats


def _no_anonymous_landing(pages):
    """No page row is the alias's answer or its login redirect's (the anonymous
    landing), and nothing on the alias host is filed but as failed."""
    assert not [u for u in pages if urlsplit(u).path == "/login"], sorted(pages)
    assert not [u for u, row in pages.items()
                if urlsplit(u).hostname == "localhost" and row[2] != "failed"], pages


def test_a_redirect_hop_to_a_host_the_cookie_does_not_reach_is_never_sent(
        monkeypatch, tmp_path):
    """``/go`` answers a 302 to the alias's protected ``/secret``: the hop is refused by
    the route before it is sent, and ``/go`` is unresolved (stored failed with the cause,
    counted, resumed), never the alias's anonymous landing. Before (7393c90): the alias
    got ``GET /secret?x=land`` and an anonymous ``GET /login``, ``/go`` was stored
    visited with the login page, and ``localhost/login`` was stored visited."""
    site = _IdSite(protected=("/secret",), home_extra="<a href='/go'>go</a>")
    site.other = _alias(site) + "/secret?x="
    spider, pages, stats = _browser_crawl(monkeypatch, tmp_path, site)
    assert _to_alias(site) == []
    go = site.base + "go"
    assert pages[go][2] == "failed" and \
        "cookies do not reach host 'localhost'" in pages[go][3], pages[go]
    assert "do not reach host 'localhost'" in spider.failed_pages[go]
    _no_anonymous_landing(pages)
    assert stats["session_host_unserved"] >= 1
    assert "welcome alice" in pages[site.base][1]
    assert "SECRET-PAGE" in pages[site.base + "secret"][1]


def test_a_selector_form_whose_action_the_cookie_does_not_reach_is_never_submitted(
        monkeypatch, tmp_path):
    """A GET selector form (FR-CRAWL-8) whose action is on the alias: its submission
    (`_isolated_submit`'s browser branch, an API request) is refused before it is sent
    (`navguard.checked_api_request`), counted. Before: the alias got ``GET
    /pick?bug=1`` and ``?bug=2`` with no cookie."""
    site = _IdSite(protected=("/secret",))
    site.home_extra = (f"<form action='{_alias(site)}/pick' method='get'>"
                       "<select name='bug'><option value='1'>one</option>"
                       "<option value='2'>two</option></select><button>Go</button></form>")
    spider, pages, stats = _browser_crawl(monkeypatch, tmp_path, site, selector_forms=[])
    assert _to_alias(site) == []
    _no_anonymous_landing(pages)
    assert stats["session_host_unserved"] >= 1
    assert "welcome alice" in pages[site.base][1]


@pytest.mark.parametrize("how", ["location", "meta-refresh"])
def test_a_page_navigating_itself_to_a_host_the_cookie_does_not_reach_stays_its_own(
        monkeypatch, tmp_path, how):
    """The home page sends its own requests to the alias -- an image and a ``fetch``
    -- and navigates there (``location.replace``, or a meta refresh): each is refused by
    the route before it is sent; the home page is filed with its own (the identity's)
    content; the navigation's target is unresolved (failed, with the cause). Before:
    the alias got every one of them without a cookie and an anonymous ``/login``, and
    the anonymous landing was filed as the home page and as ``localhost/login``."""
    site = _IdSite(protected=("/secret",))
    target = f"{_alias(site)}/secret?via={how}"
    jump = (f"<script>location.replace('{target}')</script>" if how == "location" else
            f"<meta http-equiv='refresh' content='0;url={target}'>")
    site.home_extra = (f"<img src='{_alias(site)}/pixel.png'>"
                       f"<script>fetch('{_alias(site)}/data').catch(() => 0)</script>"
                       + jump)
    spider, pages, stats = _browser_crawl(monkeypatch, tmp_path, site)
    assert _to_alias(site) == []
    _no_anonymous_landing(pages)
    assert "welcome alice" in pages[site.base][1], pages[site.base]
    assert pages[target][2] == "failed" and \
        "do not reach host 'localhost'" in pages[target][3], pages.get(target)
    assert stats["session_host_unserved"] >= 3        # the image, the fetch, the jump


def test_the_auditors_browser_fetcher_never_audits_an_unreached_host_as_the_identity(
        monkeypatch):
    """The auditor's browser fetcher (`tools.fetcher.ContentFetcher`, CC-AUD-0060): a page
    on the alias, a redirect hop there and the page's own jump there are refused before
    they are sent; the alias's anonymous answer is never returned as the page (status
    0, no HTML, no static fallback), and each is counted. Before: the alias got every
    one of them without a cookie, and ``/go`` was audited as the login page."""
    from fuzzlab.tools.fetcher import ContentFetcher
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    site = _IdSite(protected=("/secret",))
    alias = _alias(site)
    site.other = alias + "/secret?x="
    mgr = SessionManager(_creds("127.0.0.1"), scope_hosts=["localhost", "127.0.0.1"],
                         browser_login=False)
    try:
        with ContentFetcher(engine="playwright", timeout_ms=8000, identity="user",
                            session_manager=mgr, auth_base_url=site.base) as fetcher:
            try:
                home = fetcher.fetch(site.base)
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                from tests._browser import skip_or_fail
                skip_or_fail(f"chromium could not launch: {exc}")
            direct = fetcher.fetch(alias + "/secret?via=direct")
            hop = fetcher.fetch(site.base + "go")
            site.home_extra = f"<script>location.replace('{alias}/secret?via=js')</script>"
            jumped = fetcher.fetch(site.base + "?jump=1")
    finally:
        site.close()
    assert _to_alias(site) == []
    assert "welcome alice" in home[2]
    assert direct[:3] == (0, "", "") and hop[:3] == (0, "", ""), (direct, hop)
    assert "welcome alice" in jumped[2] and "Sign in" not in jumped[2]
    assert fetcher.session_host_unreached.get("localhost", 0) >= 3


def _sid(site) -> str:
    body = f"user={USER}&pw={PASSWORD}".encode()
    with urllib.request.urlopen(urllib.request.Request(site.base + "login", data=body),
                                timeout=10) as resp:
        return resp.headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]


def _state_cookie(name, value, domain) -> dict:
    return {"name": name, "value": value, "domain": domain, "path": "/", "expires": -1,
            "httpOnly": False, "secure": False, "sameSite": "Lax"}


def _disco_capture(tmp_path, site, cookies, origins=()):
    """``disco capture --storage-state`` of ``site`` (real Chromium, the capture proxy),
    with a storage state holding ``cookies`` (and ``origins``' localStorage); the
    report. Only a browser or proxy that cannot start is a skip (a failure when
    required): an aborted start is the test's."""
    from tests._browser import skip_or_fail
    for mod in ("playwright.sync_api", "mitmproxy"):
        try:
            __import__(mod)
        except ImportError as exc:
            skip_or_fail(f"{mod} unavailable: {exc}")
    import glob
    import os
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        os.environ.setdefault("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.disco.explore import Explorer, ExploreOptions
    from fuzzlab.disco.proxyproc import CaptureProxy
    options = ExploreOptions(max_actions=6, deadline_s=60, max_states=4, idle_ms=200,
                             max_quiet_ms=3000)
    try:
        with CaptureProxy([site.base], out=tmp_path / "capture.jsonl",
                          profile="user") as proxy:
            ex = Explorer(site.base, scope_urls=[site.base], proxy=proxy.endpoint,
                          options=options,
                          storage_state={"cookies": cookies, "origins": list(origins)},
                          actions_log=tmp_path / "actions.jsonl")
            try:
                return ex.run()
            except PlaywrightError as exc:
                if "BrowserType.launch" in str(exc):
                    skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
                raise
    finally:
        site.close()


def _own_gets(site) -> list[tuple[str, str]]:
    """``(path, Cookie)`` of every GET the site got on its own host."""
    with site._lock:
        return [(p, c) for h, (m, p, c, _ua) in zip(site.hosts, site.requests)
                if h.split(":")[0] == "127.0.0.1" and m == "GET"]


def test_disco_never_explores_an_unreached_host_as_the_storage_states_session(tmp_path):
    """disco's explorer with an operator's storage state (`disco capture
    --storage-state`): its context holds ``sid`` host-only for ``127.0.0.1``; the start
    page links the alias, fetches from it and its harvest finds it. Nothing reaches the
    alias -- every request there is refused by the guard (SP-74) and counted in the
    report (``session_host_unreached``, explore.json) -- so no anonymous state of it is
    explored or captured as the session's. Before: the alias was loaded and captured
    with no cookie."""
    site = _IdSite(protected=("/secret",))
    alias = _alias(site)
    site.home_extra = (f"<a href='{alias}/secret?via=link'>alias</a>"
                       f"<script>fetch('{alias}/data').catch(() => 0)</script>")
    sid = _sid(site)
    report = _disco_capture(tmp_path, site, [_state_cookie("sid", sid, "127.0.0.1")])
    assert _to_alias(site) == []
    assert report.session_host_unreached.get("localhost", 0) >= 1, report
    assert json.loads(json.dumps(report.__dict__))["session_host_unreached"]
    own = [c for _p, c in _own_gets(site)]
    assert any(f"sid={sid}" in c for c in own), own     # its own host: with the session


def test_disco_explores_its_start_host_with_a_storage_state_that_holds_an_alias_cookie(
        tmp_path):
    """BA-1 (BUG-0559 review round 1), real Chromium: the operator's storage state holds
    the session cookie for 127.0.0.1 and an ambient ``lang`` cookie for the alias. The
    start host is explored with the session -- its start page and the page it links
    carry ``sid`` -- and the alias, which ``sid`` never reaches, receives nothing
    (refused and counted). Before (72297c9): the ambient cookie made the start host
    unreached and the start navigation was aborted (``net::ERR_ABORTED``): the run
    explored nothing."""
    site = _IdSite(protected=("/secret",))
    alias = _alias(site)
    site.home_extra = f"<a href='{alias}/secret?via=link'>alias</a>"
    sid = _sid(site)
    report = _disco_capture(tmp_path, site, [_state_cookie("sid", sid, "127.0.0.1"),
                                             _state_cookie("lang", "en", "localhost")])
    assert _to_alias(site) == []
    got = _own_gets(site)
    for path in ("/", "/secret"):
        assert any(p == path and f"sid={sid}" in c for p, c in got), got
    assert report.states >= 1 and report.session_host_unreached.get("localhost", 0) >= 1


def test_disco_explores_its_start_host_with_a_local_storage_session_and_an_alias_cookie(
        tmp_path):
    """BB-1 (BUG-0559 review round 2), real Chromium: the operator's storage state
    carries its session in the start origin's ``localStorage`` and holds one ambient
    ``lang`` cookie for the alias. No cookie is the session's, so the start host is
    explored -- its start page and the page it links are loaded there -- and nothing is
    refused for the ambient cookie. Before (c6296bc): every adopted cookie was the
    session's, ``lang`` made 127.0.0.1 unreached, the start navigation was aborted
    (``net::ERR_ABORTED``, measured by the review) and the run explored nothing."""
    site = _IdSite(protected=())
    site.home_extra = "<a href='/secret?via=link'>own</a>"
    origin = site.base.rstrip("/")
    report = _disco_capture(tmp_path, site, [_state_cookie("lang", "en", "localhost")],
                            [{"origin": origin,
                              "localStorage": [{"name": "token", "value": "jwt"}]}])
    assert _to_alias(site) == []
    paths = {p for p, _c in _own_gets(site)}
    assert {"/", "/secret"} <= {p.split("?", 1)[0] for p in paths}, paths
    assert report.states >= 1 and report.session_host_unreached == {}, report


class _PreloadSite:
    """A loopback app whose pages ask the browser to preload its loopback alias -- and,
    on its own host, a ``/logout`` -- in every way Chromium 141 acts on (measured,
    `scratchpad/lanes/BROWSERALIAS/r1meas2`): an inline rule set, one named by a
    ``Speculation-Rules`` header, one a script inserts, one in a closed declarative
    shadow root, same-origin document rules over a ``/logout`` link, and a popup
    (``window.open``, with an opener) carrying an inline and a script-inserted one.
    Every request is recorded as ``(method, host, path, Cookie, Sec-Purpose)``."""

    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")
        self.seen: list[tuple[str, str, str, str, str]] = []
        self._lock = threading.Lock()
        site = self

        def rules(*urls):
            return '{"prefetch":[{"source":"list","urls":[%s]}]}' % ",".join(
                f'"{u}"' for u in urls)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                with site._lock:
                    site.seen.append((self.command, (self.headers.get("Host") or "")
                                      .split(":")[0], self.path,
                                      self.headers.get("Cookie") or "",
                                      self.headers.get("Sec-Purpose") or ""))
                alias = site.alias
                kind, body, extra = "text/html", "<title>ANON</title>anonymous", {}
                if self.path == "/p":
                    extra = {"Speculation-Rules": '"/rules.json"'}
                    body = (
                        f"<title>OWN</title><script type=speculationrules>"
                        f"{rules(alias + '/a-inline')}</script>"
                        '<script type="speculationrules">{"prefetch":[{"where":'
                        '{"href_matches":"/*"},"eagerness":"immediate"}]}</script>'
                        f"<div><template shadowrootmode=closed><script "
                        f"type=speculationrules>{rules(alias + '/a-closed')}</script>"
                        f"</template></div>"
                        f"<a href='/logout'>out</a><a id=go href='{alias}/a-inline'>go</a>"
                        f"<script>var s = document.createElement('script');"
                        f"s.type = 'speculationrules';"
                        f"s.textContent = '{rules(alias + '/a-created')}';"
                        f"document.head.appendChild(s);</script>")
                elif self.path == "/rules.json":
                    kind, body = "application/speculationrules+json", rules(
                        alias + "/a-header")
                elif self.path == "/opener":
                    body = "<title>OWN</title><script>window.open('/pop')</script>"
                elif self.path == "/pop":
                    body = (f"<title>POP</title><script type=speculationrules>"
                            f"{rules(alias + '/pop-inline')}</script>"
                            f"<script>var d = document.createElement('script');"
                            f"d.type = 'speculationrules';"
                            f"d.textContent = '{rules(alias + '/pop-created')}';"
                            f"document.head.appendChild(d);</script>")
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", kind)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{port}/"
        self.alias = f"http://localhost:{port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_no_speculation_rules_preload_leaves_a_guarded_context(monkeypatch):
    """BA-3 (BUG-0559 review round 1), real Chromium: a guarded context carrying a
    session cookie host-only for 127.0.0.1 loads pages that ask the browser to preload
    the alias and a same-origin ``/logout``, in every way measured (`_PreloadSite`),
    then a link to the alias is clicked, and a popup with an opener loads its own rule
    sets. Nothing is preloaded: the alias receives no request at all, ``/logout`` and
    the external rule set are never requested, the click is refused by the route and
    told (no prefetch served it), the page keeps its own document, and the popup gets
    its own page, sent once. Before (72297c9): Chromium sent every prefetch from the
    browser process, past the route -- the alias got them with no cookie, ``/logout``
    went with the session past the destructive rule -- and the click committed the
    alias's anonymous page from the prefetch."""
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    from playwright.sync_api import sync_playwright

    from fuzzlab.core.urls import in_origin_scope, origin_scope
    site = _PreloadSite()
    told = []
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
                    navguard.browser_launch_args([site.base])))
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                from tests._browser import skip_or_fail
                skip_or_fail(f"chromium could not launch: {exc}")
            try:
                ctx = browser.new_context(service_workers="block")
                cookies = [{"name": "sid", "value": "S", "url": site.base}]
                origins = origin_scope(site.base)
                navguard.guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins),
                                    session_cookies=cookies,
                                    on_session_unreached=lambda u, k, s, w: told.append(
                                        (k, u)))
                ctx.add_cookies(cookies)
                page = ctx.new_page()
                navguard.navigate(page, site.base + "p", timeout_ms=8000)
                page.wait_for_timeout(1500)
                try:
                    page.click("#go", timeout=3000)
                except Exception:  # noqa: BLE001 - a refused click may time out
                    pass
                page.wait_for_timeout(800)
                own_url, own_title = page.url, page.title()
                with ctx.expect_page(timeout=8000) as popup_info:
                    navguard.navigate(page, site.base + "opener", timeout_ms=8000)
                popup = popup_info.value
                popup.wait_for_load_state()
                page.wait_for_timeout(1500)
                popup_url, popup_title = popup.url, popup.title()
            finally:
                browser.close()
    finally:
        site.close()
    with site._lock:
        seen = list(site.seen)
    assert [s for s in seen if s[1] == "localhost"] == [], seen
    assert not [s for s in seen if s[2] in ("/logout", "/rules.json")], seen
    assert not [s for s in seen if s[4]], seen                  # no Sec-Purpose at all
    assert ("document", f"{site.alias}/a-inline") in told, told
    assert (own_url, own_title) == (site.base + "p", "OWN")
    assert (popup_url, popup_title) == (site.base + "pop", "POP")
    assert [s[:3] for s in seen if s[2] == "/pop"] == [("GET", "127.0.0.1", "/pop")]


def _spec_page(alias_target: str, *, inline: bool) -> str:
    """A home page asking the browser to prefetch ``alias_target`` -- an inline rule
    set, or one its script inserts -- and jumping there 300 ms later."""
    rules = '{"prefetch":[{"source":"list","urls":["%s"]}]}' % alias_target
    insert = (f"<script type=speculationrules>{rules}</script>" if inline else
              f"<script>var s = document.createElement('script');"
              f"s.type = 'speculationrules'; s.textContent = '{rules}';"
              f"document.head.appendChild(s);</script>")
    return insert + (f"<script>setTimeout(function () {{ location.href = "
                     f"'{alias_target}'; }}, 300)</script>")


def _fetch_once(monkeypatch, site, url):
    """One rendered fetch of ``url`` as 'user' (the CLI's manager scope); the result,
    the fetcher and the kinds of every SP-74 refusal it was told."""
    from fuzzlab.tools.fetcher import ContentFetcher
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    mgr = SessionManager(_creds("127.0.0.1"), scope_hosts=["localhost", "127.0.0.1"],
                         browser_login=False)
    kinds = []
    try:
        with ContentFetcher(engine="playwright", timeout_ms=8000, identity="user",
                            session_manager=mgr, auth_base_url=site.base) as fetcher:
            note = fetcher._note_session_unreached

            def told(u, kind, source, reason):
                kinds.append(kind)
                note(u, kind, source, reason)
            fetcher._note_session_unreached = told
            try:
                got = fetcher.fetch(url)
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                from tests._browser import skip_or_fail
                skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        site.close()
    return got, fetcher, kinds


def test_the_auditors_fetcher_and_the_spider_never_preload_the_alias(monkeypatch,
                                                                     tmp_path):
    """BA-3, the consumers (real Chromium): the identity's page asks the browser to
    prefetch the alias's protected page and jumps there 300 ms later. The auditor's
    fetcher audits the page's own (the identity's) content -- the jump refused by the
    route, told -- and the alias receives nothing; an identity browser crawl of the same
    page stores no anonymous landing and the alias receives nothing. Before (72297c9):
    the alias got the prefetch and the anonymous ``/login`` with no cookie, and the
    fetcher returned the alias's login page as the identity's page (measured by the
    review: 200 and the ``Sign in`` form)."""
    site = _IdSite(protected=("/secret",))
    site.home_extra = _spec_page(_alias(site) + "/secret?via=spec", inline=True)
    got, fetcher, kinds = _fetch_once(monkeypatch, site, site.base + "?spec=1")
    assert _to_alias(site) == []
    assert "welcome alice" in got[2] and "Sign in" not in got[2], got
    assert "document" in kinds and fetcher.session_host_unreached.get("localhost", 0) >= 1
    crawled = _IdSite(protected=("/secret",))
    crawled.home_extra = _spec_page(_alias(crawled) + "/secret?via=spec", inline=False)
    _spider, pages, _stats = _browser_crawl(monkeypatch, tmp_path, crawled, max_depth=1)
    assert _to_alias(crawled) == []
    _no_anonymous_landing(pages)
    assert "welcome alice" in pages[crawled.base][1], pages[crawled.base]


def test_a_preload_past_the_guard_is_never_read_as_the_identitys_page(monkeypatch,
                                                                      tmp_path):
    """BA-3's defence in depth (`navguard.committed_session_refusal`): with the guard's
    preload neutraliser and the enforcer taken away -- the launch as c6296bc made it,
    ``--no-proxy-server`` -- as if a rule set slipped past both, the browser prefetches
    the alias and serves the page's jump from that prefetch, past the route. The
    auditor's fetcher then returns no page (status 0: the committed document is on a
    host the session's cookies do not reach, told as ``committed``), and the spider
    stores the load failed with that cause -- never the alias's anonymous page. Before
    (72297c9): the fetcher returned the alias's login page as the identity's (measured
    by the review: 200 and the ``Sign in`` form)."""
    monkeypatch.setattr(navguard, "PRELOAD_OFF_JS", "", raising=False)
    launch_args = navguard.browser_launch_args

    def unenforced(*a, **kw):
        args = [x for x in launch_args(*a, **kw)
                if not x.startswith(("--proxy-server=", "--proxy-bypass-list="))]
        return ["--no-proxy-server", *args]
    monkeypatch.setattr(navguard, "browser_launch_args", unenforced)
    site = _IdSite(protected=("/secret",))
    site.home_extra = _spec_page(_alias(site) + "/secret?via=spec", inline=False)
    got, _fetcher, kinds = _fetch_once(monkeypatch, site, site.base + "?spec=1")
    assert got[:3] == (0, "", ""), got
    assert "committed" in kinds, kinds
    crawled = _IdSite(protected=("/secret",))
    crawled.home_extra = _spec_page(_alias(crawled) + "/secret?via=spec", inline=False)
    _spider, pages, stats = _browser_crawl(monkeypatch, tmp_path, crawled, max_depth=1)
    _no_anonymous_landing(pages)
    home = pages[crawled.base]
    assert home[2] == "failed" and "do not reach host 'localhost'" in home[3], home
    assert stats["session_host_unserved"] >= 1


def test_disco_never_reads_a_state_or_a_protected_resource_on_an_unreached_host():
    """BA-3's defence in depth in disco (the cross-site prefetch itself is not sent
    through disco's capture proxy -- measured -- so the wiring is shown on doubles): a
    state read (`settled_fingerprint`) of a document the main frame committed on a host
    the session's cookies do not reach is None and counted, never read; the start
    page's protected-resource probe never GETs such a page with the context's cookies.
    Before (72297c9): both read it."""
    base = "http://127.0.0.1:8000/"
    ex = _explorer(base, {"cookies": [{"name": "sid", "value": "v", "domain": "127.0.0.1",
                                       "path": "/"}], "origins": []})
    ex._ctx_session_cookies = ex._current_session().session_cookies()
    ex._ctx_cookie_scope = None
    ex.fingerprint = lambda page, ctx: "READ"
    checks = []
    ex._context_check = lambda url=None: checks.append(url)
    assert ex.settled_fingerprint(_Page("http://localhost:8000/secret"), None) is None
    assert ex.report.session_host_unreached == {"localhost": 1}
    assert ex.settled_fingerprint(_Page(base + "secret"), None) == "READ"
    ex._find_protected_resource(_Page("http://localhost:8000/secret"))
    assert checks == []


# --- review round 2 (BUG-0559): the enforcer, BB-3 / BB-4(1) ----------------------------
class _HiddenPreloadSite:
    """A loopback app whose pages hide a speculation rule set from every layer that
    reads the page (measured by the review, `scratchpad/lanes/BROWSERALIAS`, round 2):
    ``/p`` -- a closed declarative shadow root whose rule set's type is written with a
    character reference (``&#115;peculationrules``: the parser decodes it after the
    route read the text), and a handler inside another closed root inserting a rule
    set into it (BB-4(1)); both name the alias and a same-origin ``/logout``; a link to
    the alias; a WebSocket to its own host. ``/pop``: a ``window.open()`` popup still on
    its initial ``about:blank`` given a rule set by its opener. Every request is
    recorded as ``(method, host, path, Cookie, Sec-Purpose)``."""

    def __init__(self):
        import base64
        import hashlib
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")
        self.seen: list[tuple[str, str, str, str, str]] = []
        self._lock = threading.Lock()
        site = self

        def rules(tag):
            return ('{"prefetch":[{"source":"list","urls":["%s/a-%s","/logout?%s"]}]}'
                    % (site.alias, tag, tag))

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                with site._lock:
                    site.seen.append((self.command, (self.headers.get("Host") or "")
                                      .split(":")[0], self.path,
                                      self.headers.get("Cookie") or "",
                                      self.headers.get("Sec-Purpose") or ""))
                if (self.headers.get("Upgrade") or "").lower() == "websocket":
                    key = self.headers.get("Sec-WebSocket-Key", "")
                    accept = base64.b64encode(hashlib.sha1(
                        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                    self.send_response(101)
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    self.send_header("Sec-WebSocket-Accept", accept.decode())
                    self.end_headers()
                    self.wfile.flush()
                    self.close_connection = True
                    try:
                        self.connection.settimeout(3)
                        self.connection.recv(64)
                    except OSError:
                        pass
                    return
                handler = ("var r = this.getRootNode(); var s = document.createElement("
                           "'script'); s.type = 'speculationrules'; s.textContent = '"
                           + rules("closeddyn") + "'; r.appendChild(s);")
                body, status = "<title>ANON</title>anonymous", 200
                if self.path == "/p":
                    body = (f"<title>OWN</title><div><template shadowrootmode=closed>"
                            f"<script type=\"&#115;peculationrules\">{rules('charref')}"
                            f"</script></template></div><div><template "
                            f"shadowrootmode=closed><img src=/nope onerror=\"{handler}\">"
                            f"</template></div><a href='/logout'>out</a>"
                            f"<a id=go href='{site.alias}/a-click'>go</a><script>"
                            f"var ws = new WebSocket('ws://127.0.0.1:{site.port}/ws');"
                            f"ws.onopen = function () {{ document.title = 'OWN-WS'; }};"
                            f"</script>")
                elif self.path == "/pop":
                    body = (f"<title>OPENER</title><script>var w = window.open();"
                            f"var s = w.document.createElement('script');"
                            f"s.type = 'speculationrules'; s.textContent = "
                            f"'{rules('popblank')}'; w.document.head.appendChild(s);"
                            f"</script>")
                elif self.path == "/nope":
                    status = 404
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}/"
        self.alias = f"http://localhost:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _binary(monkeypatch, which: str) -> None:
    """Launch ``which`` Chromium: the full browser (the pinned build, as every browser
    test here) or Playwright's headless shell (its default for a headless launch)."""
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    if which == "shell":
        monkeypatch.delenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", raising=False)


@pytest.mark.parametrize("which", ["full", "shell"])
def test_no_preload_a_page_hides_from_the_guard_leaves_the_browser(monkeypatch, which):
    """BB-3 and BB-4(1) (BUG-0559 review round 2), real Chromium, both binaries: a
    guarded context carrying a session cookie host-only for 127.0.0.1 loads pages whose
    rule sets no layer that reads the page can see -- a closed declarative shadow root
    with a character-referenced type, a handler inserting one into its closed root, a
    ``window.open()`` popup on ``about:blank`` given one -- naming the alias and a
    same-origin ``/logout``. The alias and ``/logout`` receive nothing (no request
    carries ``Sec-Purpose``): Chromium's own requests go through the enforcer, which
    refuses them (counted); the click to the alias is refused by the route and told; a
    WebSocket the guard admitted still opens through the enforcer. Before (c6296bc):
    the alias got the cookie-less prefetches and ``/logout`` got them with ``sid=S``,
    past the destructive rule (measured by the review on both binaries)."""
    _binary(monkeypatch, which)
    from playwright.sync_api import sync_playwright

    from fuzzlab.core.urls import in_origin_scope, origin_scope
    site = _HiddenPreloadSite()
    told = []
    before = getattr(navguard, "enforcer_refusals", dict)()
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
                    navguard.browser_launch_args([site.base])))
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                from tests._browser import skip_or_fail
                skip_or_fail(f"chromium ({which}) could not launch: {exc}")
            try:
                ctx = browser.new_context(service_workers="block")
                cookies = [{"name": "sid", "value": "S", "url": site.base}]
                origins = origin_scope(site.base)
                navguard.guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins),
                                    session_cookies=cookies,
                                    on_session_unreached=lambda u, k, s, w: told.append(
                                        (k, u)))
                ctx.add_cookies(cookies)
                page = ctx.new_page()
                navguard.navigate(page, site.base + "p", timeout_ms=8000)
                page.wait_for_timeout(2000)
                own_title = page.title()
                try:
                    page.click("#go", timeout=3000)
                except Exception:  # noqa: BLE001 - a refused click may time out
                    pass
                page.wait_for_timeout(800)
                own_url = page.url
                with ctx.expect_page(timeout=8000):
                    navguard.navigate(page, site.base + "pop", timeout_ms=8000)
                page.wait_for_timeout(2000)
            finally:
                browser.close()
    finally:
        site.close()
    with site._lock:
        seen = list(site.seen)
    assert [s for s in seen if s[1] == "localhost"] == [], seen
    assert not [s for s in seen if s[2].startswith("/logout")], seen
    assert not [s for s in seen if s[4]], seen                  # no Sec-Purpose at all
    assert ("document", f"{site.alias}/a-click") in told, told
    assert own_url == site.base + "p" and own_title == "OWN-WS", (own_url, own_title)
    assert [s[2] for s in seen if s[2] == "/ws"] == ["/ws"]     # admitted, tunnelled once
    after = navguard.enforcer_refusals()
    assert after["preload"] > before.get("preload", 0), (before, after)


def _raw(endpoint: str, head: bytes, then: bytes = b"") -> bytes:
    """Send ``head`` (and ``then``, once it is answered) to ``endpoint``; what came back."""
    import socket
    host, port = endpoint.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(head)
        got = s.recv(4096)
        if then and got.startswith(b"HTTP/1.1 200"):
            s.sendall(then)
        s.settimeout(2)
        try:                        # until it closes, the body arrives, or 2 s pass
            while not got.endswith(b"ok"):
                more = s.recv(4096)
                if not more:
                    break
                got += more
        except OSError:
            pass
        return got


def test_the_enforcer_refuses_what_the_browser_sends_itself_and_tunnels_admitted_sockets():
    """The enforcer (BUG-0559 review round 2, BB-3), on raw sockets: every launch's
    arguments name it (loopback forced through it, its address resolvable); a request
    Chromium sends itself -- a prefetch of a destructive URL, any other -- is refused
    (403) and counted, and never reaches the target; a ``CONNECT`` is tunnelled only
    for a socket a guard admitted (`admit_socket`), once; the re-request of a redirect
    landing the route checked (`admit_landing`) is forwarded once, never as a preload;
    through a capture proxy the admitted ``CONNECT`` is handed to it as it came."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    got = []

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            got.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_CONNECT(self):  # noqa: N802 - the capture proxy's role
            got.append(("CONNECT", self.path))
            self.send_response(200, "Connection established")
            self.end_headers()

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    port = target.server_address[1]
    try:
        args = navguard.browser_launch_args([f"http://127.0.0.1:{port}/"])
        (server,) = [a.split("=", 1)[1] for a in args if a.startswith("--proxy-server=")]
        endpoint = server.removeprefix("http://")
        assert endpoint.startswith("127.0.0.1:") and "--no-proxy-server" not in args
        assert "--proxy-bypass-list=<-loopback>" in args
        rules = [a for a in args if a.startswith("--host-resolver-rules=")][0]
        assert f"MAP {endpoint} {endpoint}" in rules and rules.endswith("MAP * ~NOTFOUND")
        before = navguard.enforcer_refusals()
        answer = _raw(endpoint, f"GET http://127.0.0.1:{port}/logout HTTP/1.1\r\nHost: "
                                f"127.0.0.1:{port}\r\nSec-Purpose: prefetch\r\nCookie: "
                                f"sid=S\r\n\r\n".encode())
        assert answer.startswith(b"HTTP/1.1 403")
        answer = _raw(endpoint, f"GET http://127.0.0.1:{port}/x HTTP/1.1\r\n\r\n".encode())
        assert answer.startswith(b"HTTP/1.1 403")
        connect = f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        assert _raw(endpoint, connect.encode()).startswith(b"HTTP/1.1 403")  # not admitted
        navguard.admit_socket(f"ws://127.0.0.1:{port}/ws")
        tunnelled = _raw(endpoint, connect.encode(), b"GET /ws HTTP/1.1\r\nHost: x\r\n\r\n")
        assert tunnelled.startswith(b"HTTP/1.1 200") and b"ok" in tunnelled, tunnelled
        assert _raw(endpoint, connect.encode()).startswith(b"HTTP/1.1 403")  # used once
        # a redirect landing the route checked (Playwright never routes the browser's
        # re-request of it): forwarded once, never as a preload
        landing = f"http://127.0.0.1:{port}/land%7Eed?a=%41"     # as the route wrote it
        navguard.admit_landing(landing)
        preload = f"GET {landing} HTTP/1.1\r\nSec-Purpose: prefetch\r\n\r\n".encode()
        assert _raw(endpoint, preload).startswith(b"HTTP/1.1 403")
        again = f"GET http://127.0.0.1:{port}/land~ed?a=A HTTP/1.1\r\nHost: h\r\n" \
                f"Proxy-Connection: keep-alive\r\n\r\n".encode()   # as Chromium sends it
        answer = _raw(endpoint, again)
        assert b" 200 " in answer.split(b"\r\n", 1)[0] and answer.endswith(b"ok"), answer
        assert _raw(endpoint, again).startswith(b"HTTP/1.1 403")            # once
        after = navguard.enforcer_refusals()
        assert after["preload"] == before["preload"] + 2
        assert after["request"] == before["request"] + 2
        assert after["connect"] == before["connect"] + 2
        assert got == ["/ws", "/land~ed?a=A"], got       # nothing refused reached it
        # through a capture proxy (disco): the admitted CONNECT goes to it as it came
        chained = navguard.browser_launch_args([f"http://127.0.0.1:{port}/"],
                                               proxy=f"127.0.0.1:{port}")
        (via,) = [a.split("=", 1)[1] for a in chained if a.startswith("--proxy-server=")]
        assert via != server
        navguard.admit_socket(f"ws://localhost:{port}/")
        other = f"CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
        answer = _raw(via.removeprefix("http://"), other.encode())
        assert b" 200 " in answer.split(b"\r\n", 1)[0], answer   # the recorder's answer
        assert got[-1] == ("CONNECT", f"localhost:{port}"), got
    finally:
        target.shutdown()
        target.server_close()


# --- review round 2: a document in its own charset (BB-4(2)) -----------------------------
def test_a_response_body_is_read_by_its_own_charset_never_raising():
    """`navguard.decoded_text` (BB-4(2)): the ``Content-Type``'s charset (a Latin-1 label
    read as windows-1252, as a browser does), else a byte-order mark's, else the
    document's ``<meta charset>``, else UTF-8, else windows-1252 -- never an exception;
    the codec is None only when the declared charset did not decode losslessly (that
    text is never re-encoded in place of the body)."""
    dec = navguard.decoded_text
    cafe = "<title>café</title>"
    assert dec(cafe.encode("latin-1"), "text/html; charset=ISO-8859-1") == (cafe, "cp1252")
    assert dec(cafe.encode("utf-8"), "text/html") == (cafe, "utf-8")
    assert dec(cafe.encode("latin-1"), "text/html") == (cafe, "cp1252")   # undeclared
    sjis = '<meta charset="shift_jis"><p>あ</p>'
    assert dec(sjis.encode("shift_jis"), "text/html") == (sjis, "shift_jis")
    assert dec(b"<p>\x81</p>", "text/html; charset=latin1") == ("<p>\x81</p>", "latin-1")
    assert dec(b"<p>\xff</p>", "text/html; charset=utf-8") == ("<p>�</p>", None)
    assert dec(b"x", "text/html; charset=no-such") == ("x", "utf-8")
    assert dec(None, None) == ("", "utf-8")

    class Gone:
        headers = {"content-type": "text/html"}

        def body(self):
            raise RuntimeError("the driver let it go")
    assert navguard.response_text(Gone()) is None


def test_a_guarded_page_loads_a_document_in_a_legacy_charset(monkeypatch):
    """BB-4(2) (BUG-0559 review round 2), real Chromium: a guarded page loads a main-frame
    document served as ISO-8859-1 -- one whose rule set the route makes inert, so it is
    given re-encoded in that charset -- and one naming windows-1252 only in a ``<meta>``.
    Each loads (the load state is reached), shows its own text, and `navigate` keeps the
    HTML it received. Before (c6296bc): `_note_received` read the body as strict UTF-8,
    the ``UnicodeDecodeError`` escaped the route handler, the request was never answered
    and the load timed out (measured: ``r1meas2/latin1.out``)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    from playwright.sync_api import sync_playwright

    from fuzzlab.core.urls import in_origin_scope, origin_scope
    pages = {"/iso": ("text/html; charset=iso-8859-1",
                      "<title>café</title><p>naïve</p><script type=speculation"
                      "rules>{}</script>"),
             "/meta": ("text/html", "<meta charset=windows-1252><title>résumé"
                                    "</title><p>“q”</p>")}

    class Site(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            ctype, text = pages.get(self.path, ("text/html", "x"))
            data = text.encode("cp1252")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    got = {}
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
                    navguard.browser_launch_args([base])))
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                from tests._browser import skip_or_fail
                skip_or_fail(f"chromium could not launch: {exc}")
            try:
                ctx = browser.new_context(service_workers="block")
                origins = origin_scope(base)
                navguard.guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins))
                page = ctx.new_page()
                for path in pages:
                    nav = navguard.navigate(page, base + path.lstrip("/"), timeout_ms=5000)
                    got[path] = (nav.reached, page.title(), nav.html,
                                 page.evaluate("document.body.innerText"),
                                 page.evaluate(f"document.querySelectorAll('script[type="
                                               f"{navguard.INERT_RULES_TYPE}]').length"))
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
    reached, title, html, text, inert = got["/iso"]
    assert reached and title == "café" and text.strip() == "naïve", got["/iso"]
    assert "naïve" in html and inert == 1      # given re-encoded in its own charset
    reached, title, html, text, _inert = got["/meta"]
    assert reached and title == "résumé" and "“q”" in text, got["/meta"]
    assert "“q”" in html


def test_no_module_reads_a_response_body_as_strict_utf8():
    """PA-0559(8) (BB-4(2)): no fuzzlab module calls ``.text()`` -- Playwright's strict
    UTF-8 read of a response body, which raises on a legacy charset -- but reads it with
    `navguard.response_text` / `decoded_text`. Review round 3 (BB-4(4)): nor reads a
    request's body with ``.post_data`` / ``.post_data_json`` (the same strict read: disco's
    `carries_value` dropped a Latin-1 form's body), but ``post_data_buffer`` through
    `decoded_text`. Proven on synthetic offenders."""
    def offenders(source: str, module: str) -> list[str]:
        out = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    node.func.attr == "text" and not node.args and not node.keywords:
                out.append(f"{module}:{node.lineno}")
            elif isinstance(node, ast.Attribute) and \
                    node.attr in ("post_data", "post_data_json"):
                out.append(f"{module}:{node.lineno}")
        return out
    found = []
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        found += offenders(path.read_text(encoding="utf-8"),
                           str(path.relative_to(ROOT)))
    assert found == [], found
    assert offenders("def f(resp):\n    return resp.text()\n", "x.py") == ["x.py:2"]
    assert offenders("def f(resp):\n    return resp.text\n", "x.py") == []
    assert offenders("def f(req):\n    return req.post_data or ''\n", "x.py") == ["x.py:2"]
    assert offenders("def f(req):\n    return req.post_data_json\n", "x.py") == ["x.py:2"]
    assert offenders("def f(req):\n    return req.post_data_buffer\n", "x.py") == []


# --- review round 2: one comparison of a cookie's domain with a host (BB-2) ---------------
def _runner_headers(tmp_path, base, cookies):
    """`disco.runner.Runner.auth_headers` for a ``storage_state`` profile of ``cookies``,
    against a contract whose base URL is ``base`` (the method alone: nothing is sent)."""
    from types import SimpleNamespace

    from fuzzlab.disco.runner import Runner
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"cookies": cookies, "origins": []}), encoding="utf-8")
    runner = Runner.__new__(Runner)
    runner.c = SimpleNamespace(base_url=base, profile=lambda _pid: {
        "kind": "storage_state", "ref": str(state)})
    return runner.auth_headers("p")


def test_a_storage_state_profile_sends_the_cookies_a_browser_would_send(tmp_path):
    """BB-2 (BUG-0559 review round 2): disco's contract runner, for a ``storage_state``
    auth profile, sends the state's cookies that reach the target's host by SP-74's
    predicate. A state saved on an IPv6 target holds its cookie as ``[::1]`` (measured,
    BA-2) and is sent to ``http://[::1]:8000/``; never to another loopback spelling; a
    host-only cookie never to a name under it. Before (c6296bc): its own comparison
    (``host == domain``) dropped the ``[::1]`` cookie -- every case of the contract went
    out anonymous, ``credentialed=False``, with nothing reported."""
    def sid(domain):
        return [{"name": "sid", "value": "v", "domain": domain, "path": "/"}]
    assert _runner_headers(tmp_path, "http://[::1]:8000/", sid("[::1]")) == {
        "Cookie": "sid=v"}
    assert _runner_headers(tmp_path, "http://127.0.0.1:8000/", sid("127.0.0.1")) == {
        "Cookie": "sid=v"}
    assert _runner_headers(tmp_path, "http://127.0.0.1:8000/", sid("[::1]")) == {}
    assert _runner_headers(tmp_path, "http://localhost:8000/", sid("127.0.0.1")) == {}
    assert _runner_headers(tmp_path, "http://app.example.org/", sid(".example.org")) == {
        "Cookie": "sid=v"}
    assert _runner_headers(tmp_path, "http://app.example.org/", sid("example.org")) == {}


def test_a_storage_state_is_adopted_by_where_its_cookies_reach_the_scope():
    """BB-2's sweep (`browserlogin.filter_storage_state`): a cookie is adopted when the
    browser sends it to a scope host, in every spelling the origin folds -- a loopback
    host's three, an IPv6 one held as ``[::1]`` -- by SP-74's predicate; a host-only
    cookie of a parent domain, which the browser never sends to the scope's host, is not
    (before, c6296bc: adopted by its own suffix comparison)."""
    from fuzzlab.session.browserlogin import filter_storage_state

    def kept(scope, *domains):
        state = {"cookies": [{"name": f"c{i}", "value": "v", "domain": d, "path": "/"}
                             for i, d in enumerate(domains)], "origins": []}
        return [c["domain"] for c in filter_storage_state(state, lambda u: True,
                                                          [scope])["cookies"]]
    assert kept("http://127.0.0.1:3000/", "127.0.0.1", "localhost", "[::1]",
                "10.0.0.5") == ["127.0.0.1", "localhost", "[::1]"]
    assert kept("http://[::1]:3000/", "[::1]", "127.0.0.1") == ["[::1]", "127.0.0.1"]
    assert kept("https://app.example.org/", ".example.org", "app.example.org",
                "example.org", "other.org") == [".example.org", "app.example.org"]


def test_no_cookie_domain_is_compared_with_a_host_outside_the_owner():
    """PA-0559(2)'s sweep held (BB-2): no fuzzlab module but `navguard` reads a cookie's
    ``domain`` to compare it with a host -- each asks `navguard.cookie_reaches`. The one
    exemption is flagged, not fixed, in BUG-0559 round 2 (a file another item holds).
    Proven on synthetic offenders."""
    exempt = {"fuzzlab/session/manager.py":
              "_jar_cookies (BUG-0132): flagged in BUG-0559 round 2 -- the file is held by "
              "another lane (SESSROT); its host side also drops an IPv6 host"}

    def offenders(source: str, module: str) -> list[str]:
        out = []
        for node in ast.walk(ast.parse(source)):
            key = None
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    node.func.attr == "get" and node.args and \
                    isinstance(node.args[0], ast.Constant):
                key = node.args[0].value
            elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                key = node.slice.value
            if key == "domain":
                out.append(f"{module}:{node.lineno}")
        return out
    found = []
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        module = str(path.relative_to(ROOT))
        if module in ("fuzzlab/tools/navguard.py", *exempt) or "/labgen/" in module:
            continue
        found += offenders(path.read_text(encoding="utf-8"), module)
    assert found == [], found
    assert offenders("def f(c, h):\n    return c.get('domain') == h\n", "x.py") == ["x.py:2"]
    assert offenders("def f(c, h):\n    return h.endswith(c['domain'])\n", "x.py") == [
        "x.py:2"]
    assert offenders("def f(c, h):\n    return cookie_reaches(c, h)\n", "x.py") == []


# --- review round 3 (BUG-0559, final): any charset label; an https landing's tunnel -------
def _codec_names() -> list[str]:
    """Every codec name Python registers (the ``encodings`` package's modules and every
    alias with its target): what a target may write as a charset label."""
    import encodings
    import encodings.aliases
    import pkgutil
    return sorted(set(encodings.aliases.aliases) | set(encodings.aliases.aliases.values())
                  | {m.name for m in pkgutil.iter_modules(encodings.__path__)})


def test_no_charset_label_a_target_writes_makes_the_decoder_raise():
    """BB-4 (BUG-0559 review round 3): `navguard.decoded_text` and `response_text` never
    raise, whatever charset the target names, for every codec name Python registers, in
    the ``Content-Type``, in a ``<meta>``, or both, on a body that decodes and one that
    does not. A codec that is no text encoding (``hex``, ``base64``, ``rot13``, ``zlib``,
    ``bz2``, ``uu``, ``quopri``) is an unknown label: the next one decides, else the
    undeclared order; one that refuses a document even with replacement (``idna``,
    ``undefined``) falls back to UTF-8 with replacement. Before (1b05e3f): ``LookupError:
    'hex' is not a text encoding`` and ``UnicodeError`` raised out of both."""
    dec = navguard.decoded_text
    names = _codec_names()
    assert len(names) > 300 and {"hex", "base64", "rot13", "zlib", "bz2", "uu", "quopri",
                                 "idna", "undefined"} <= set(names)
    raised = []
    for name in names:
        for ctype, body in ((f"text/html; charset={name}", b"<title>t</title>ok"),
                            ("text/html", f'<meta charset="{name}"><title>t</title>'
                                          .encode()),
                            (f"text/html; charset={name}",
                             f'<meta charset="{name}">\xe9\xff<p>'.encode("latin-1"))):
            try:
                text, codec = dec(body, ctype)
                assert isinstance(text, str) and (codec is None or isinstance(codec, str))
            except Exception as exc:  # noqa: BLE001 - the defect: collected, named
                raised.append((name, ctype.split(";")[0], type(exc).__name__))
    assert raised == [], raised[:20]
    # an unknown label gives way to the next one, then to the undeclared order
    cafe = '<meta charset="windows-1252"><title>café</title>'
    assert dec(cafe.encode("cp1252"), "text/html; charset=hex") == (cafe, "cp1252")
    assert dec(b"<title>t</title>", "text/html; charset=base64") == ("<title>t</title>",
                                                                     "utf-8")
    assert dec(b'<meta charset="rot13"><p>x', None) == ('<meta charset="rot13"><p>x',
                                                        "utf-8")
    assert dec("é".encode("latin-1"), "text/html; charset=undefined")[0] == "é"
    assert dec(b"<p>\xe9\xff</p>", "text/html; charset=idna") == ("<p>éÿ</p>", "cp1252")

    class Resp:
        def __init__(self, ctype, body):
            self.headers, self._body = {"content-type": ctype}, body

        def body(self):
            return self._body
    for ctype in ("text/css; charset=hex", "text/html; charset=undefined",
                  "text/html; charset=idna", "text/html; charset=uu"):
        assert isinstance(navguard.response_text(Resp(ctype, b"\xe9a.b\xff" * 20)), str)


def test_a_guarded_page_loads_a_document_whatever_charset_it_names(monkeypatch):
    """BB-4 (BUG-0559 review round 3), real Chromium, generated: a guarded page loads an
    ASCII document labelled with each codec name Python registers -- in its
    ``Content-Type`` and its ``<meta>`` -- through the route, and `navigate` returns its
    HTML; and the review's three shapes: ``charset=hex`` in the header, ``<meta
    charset=base64>`` alone, ``charset=idna`` on a body it refuses (that one raised out of
    `navigate` itself, through `response_text`). Before (1b05e3f): the route's decoder
    raised ``LookupError`` past `_note_received`, the request was never answered and
    ``goto`` timed out (measured by the review: pages that loaded at c6296bc)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import quote, unquote

    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    from playwright.sync_api import sync_playwright

    from fuzzlab.core.urls import in_origin_scope, origin_scope

    class Site(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            how, _sep, name = self.path.lstrip("/").partition("/")
            name = unquote(name)
            ctype, body = f"text/html; charset={name}", \
                f'<meta charset="{name}"><title>labelled</title>ok'.encode()
            if how == "hex":
                ctype, body = "text/html; charset=hex", b"<title>hexpage</title>ok"
            elif how == "b64":
                ctype, body = "text/html", b'<meta charset="base64"><title>b64page</title>'
            elif how == "idna":
                ctype, body = "text/html; charset=idna", \
                    "<title>idnapage</title>\xe9\xff".encode("latin-1")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    failed, titles = [], {}
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
                    navguard.browser_launch_args([base])))
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                from tests._browser import skip_or_fail
                skip_or_fail(f"chromium could not launch: {exc}")
            try:
                ctx = browser.new_context(service_workers="block")
                origins = origin_scope(base)
                navguard.guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins))
                page = ctx.new_page()
                for path in ["hex/", "b64/", "idna/"] + \
                        [f"label/{quote(n, safe='')}" for n in _codec_names()]:
                    try:
                        nav = navguard.navigate(page, base + path, timeout_ms=5000)
                        if not nav.reached or not isinstance(nav.html, str):
                            failed.append((path, nav.reached, type(nav.html).__name__))
                        elif not path.startswith("label/"):
                            titles[path] = page.title()
                    except Exception as exc:  # noqa: BLE001 - the defect: collected
                        failed.append((path, str(exc).splitlines()[0][:80]))
                    if len(failed) >= 3:            # a defect shows at once: never wait
                        break                       # out every label
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
    assert failed == [], failed
    assert titles == {"hex/": "hexpage", "b64/": "b64page", "idna/": "idnapage"}, titles


def test_a_legacy_charset_forms_submission_is_seen_carrying_its_value(monkeypatch):
    """BB-4(4) (BUG-0559 review round 3), real Chromium: a guarded ISO-8859-1 page's
    multipart form (a hidden ``h=café``, a filled ``q=zzfiller1``) is submitted; disco's
    `carries_value` sees the request carry ``zzfiller1`` and ``café``. Before (1b05e3f):
    it read Playwright's ``post_data`` -- strict UTF-8 --, which raised on the ``0xE9``
    byte, so the body was dropped and a submission that carried the value counted as not
    sent (measured by the review)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    from playwright.sync_api import sync_playwright

    from fuzzlab.core.urls import in_origin_scope, origin_scope
    from fuzzlab.disco.explore import carries_value

    class Site(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _page(self, text: str) -> None:
            data = text.encode("latin-1")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=iso-8859-1")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802 - http.server API
            self._page("<title>form</title><form method=post action=/send "
                       "enctype=multipart/form-data><input type=hidden name=h "
                       "value='café'><input name=q><button id=b>go</button></form>")

        def do_POST(self):  # noqa: N802 - http.server API
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._page("<title>sent</title>")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    posts = []
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
                    navguard.browser_launch_args([base])))
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                from tests._browser import skip_or_fail
                skip_or_fail(f"chromium could not launch: {exc}")
            try:
                ctx = browser.new_context(service_workers="block")
                origins = origin_scope(base)
                navguard.guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins))
                page = ctx.new_page()
                page.on("request", lambda r: posts.append(r) if r.method == "POST"
                        else None)
                navguard.navigate(page, base, timeout_ms=5000)
                page.fill("input[name=q]", "zzfiller1")
                with page.expect_navigation(timeout=5000):
                    page.click("#b")
                (req,) = posts
                body = req.post_data_buffer
                got = (b"zzfiller1" in body, b"caf\xe9" in body,
                       carries_value(req, ["zzfiller1"]), carries_value(req, ["café"]),
                       carries_value(req, ["absent-value"]))
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
    assert got == (True, True, True, True, False), got


class _TlsSite:
    """A loopback HTTPS app with HTTP/1.1 keep-alive (the review's round-3 repro), its
    certificate a leaf of the test's own CA (`proxy.ca.LocalCA` under ``tmp_path``, one
    per test; each site its own leaf key): ``/start*`` redirects
    (302) to ``/land*``, whose closed declarative shadow root holds a rule set with a
    character-referenced type prefetching ``/logout?tls`` and the alias; ``/wsp`` opens a
    ``wss`` WebSocket to it. Every request is recorded as ``(client port, path, Cookie,
    Sec-Purpose, ALPN)``. ``alpn``: the protocols it offers (``h2`` first: Chromium picks
    it when offered, measured); ``tls12``: TLS 1.2 at most."""

    def __init__(self, tmp_path, *, alpn=None, tls12=False):
        import base64
        import hashlib
        import ssl
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        pytest.importorskip("cryptography")
        from fuzzlab.core.net import require_loopback
        from fuzzlab.proxy.ca import LocalCA
        require_loopback("127.0.0.1")
        self.ca = LocalCA(tmp_path / "ca")               # one CA per test, shared
        cert, key = self.ca.leaf_cert_files("127.0.0.1")
        self.cert_pem = cert.read_bytes()                # this site's own leaf
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert), str(key))
        if alpn:
            tls.set_alpn_protocols(list(alpn))
        if tls12:
            tls.maximum_version = ssl.TLSVersion.TLSv1_2
        self.seen: list[tuple] = []
        self._lock = threading.Lock()
        site = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                with site._lock:
                    site.seen.append((self.client_address[1], self.path,
                                      self.headers.get("Cookie") or "",
                                      self.headers.get("Sec-Purpose") or "",
                                      self.connection.selected_alpn_protocol()))
                if (self.headers.get("Upgrade") or "").lower() == "websocket":
                    accept = base64.b64encode(hashlib.sha1(
                        (self.headers.get("Sec-WebSocket-Key", "")
                         + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                    self.send_response(101)
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    self.send_header("Sec-WebSocket-Accept", accept.decode())
                    self.end_headers()
                    self.wfile.flush()
                    self.close_connection = True
                    try:
                        self.connection.settimeout(3)
                        self.connection.recv(64)
                    except OSError:
                        pass
                    return
                if self.path.startswith("/start"):
                    self.send_response(302)
                    self.send_header("Location", "/land" + self.path[len("/start"):])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = "<title>OTHER</title>other"
                if self.path.startswith("/land"):
                    rules = ('{"prefetch":[{"source":"list","urls":["/logout?tls",'
                             '"https://localhost:%d/x"]}]}' % site.port)
                    body = (f"<title>LAND</title><div><template shadowrootmode=closed>"
                            f"<script type=\"&#115;peculationrules\">{rules}</script>"
                            f"</template></div>landed")
                elif self.path == "/wsp":
                    body = (f"<title>WSP</title><script>var ws = new WebSocket("
                            f"'wss://127.0.0.1:{site.port}/ws'); ws.onopen = function () "
                            f"{{ document.title = 'WS-OPEN'; }};</script>")
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass                     # a handshake the client abandoned: expected

        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True,
                                             do_handshake_on_connect=False)
        self.port = self.server.server_address[1]
        self.base = f"https://127.0.0.1:{self.port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def paths(self) -> list[str]:
        with self._lock:
            return [s[1] for s in self.seen]

    def spki_switch(self) -> str:
        """The test-only switch that has Chromium trust this site's own key -- and no
        other: TLS verification stays on (``--ignore-certificate-errors`` never)."""
        import base64
        import hashlib

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        leaf = x509.load_pem_x509_certificate(self.cert_pem)
        spki = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return ("--ignore-certificate-errors-spki-list="
                + base64.b64encode(hashlib.sha256(spki).digest()).decode())

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _guarded_https(pw, site, *, extra_args=(), ignore_https_errors=False, told=None):
    """A browser and a context guarded as every consumer guards one, carrying a session
    cookie host-only for ``site``'s ``127.0.0.1``; a launch failure is a skip."""
    from fuzzlab.core.urls import in_origin_scope, origin_scope
    kwargs = navguard.chromium_launch_kwargs(navguard.browser_launch_args([site.base]))
    kwargs["args"] = [*kwargs["args"], *extra_args]
    try:
        browser = pw.chromium.launch(**kwargs)
    except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
        from tests._browser import skip_or_fail
        skip_or_fail(f"chromium could not launch: {exc}")
    ctx = browser.new_context(service_workers="block",
                              ignore_https_errors=ignore_https_errors)
    cookies = [{"name": "sid", "value": "S", "url": site.base}]
    origins = origin_scope(site.base)
    navguard.guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins),
                        session_cookies=cookies,
                        on_session_unreached=lambda u, k, s, w: (told or []).append((k, u)))
    ctx.add_cookies(cookies)
    return browser, ctx


@pytest.mark.parametrize("which", ["full", "shell"])
def test_an_https_landing_and_socket_load_from_a_self_signed_target(monkeypatch, tmp_path,
                                                                    which):
    """BUG-0559 review round 3, the https redirect regression, real Chromium, both
    binaries: a self-signed target in a context with ``ignore_https_errors=True`` (as
    disco runs). The redirected navigation (``/start`` -> 302 -> ``/land``) loads its
    landing, and a page's ``wss`` WebSocket opens: the browser's retry after the
    certificate error is a second ``CONNECT``, which the landing's ticket (the socket's)
    admits. Nothing rides the landing's tunnel after its exchange (no ``/logout``).
    Before (1b05e3f): ``net::ERR_TUNNEL_CONNECTION_FAILED`` -- the one ticket was spent
    on the first ``CONNECT`` (measured by the review; the socket the same, measured in
    round 3; both loaded at c6296bc)."""
    _binary(monkeypatch, which)
    from playwright.sync_api import sync_playwright
    site = _TlsSite(tmp_path)
    try:
        with sync_playwright() as pw:
            browser, ctx = _guarded_https(pw, site, ignore_https_errors=True)
            try:
                page = ctx.new_page()
                try:
                    nav = navguard.navigate(page, site.base + "start", timeout_ms=8000)
                    landed = (nav.reached, page.url, page.title())
                except Exception as exc:  # noqa: BLE001 - the defect: reported below
                    landed = (False, str(exc).splitlines()[0][:120], "")
                page.wait_for_timeout(1500)
                navguard.navigate(page, site.base + "wsp", timeout_ms=8000)
                for _ in range(30):
                    if page.title() == "WS-OPEN":
                        break
                    page.wait_for_timeout(100)
                socket_title = page.title()
            finally:
                browser.close()
    finally:
        site.close()
    assert landed == (True, site.base + "land", "LAND"), landed
    assert socket_title == "WS-OPEN" and "/ws" in site.paths(), (socket_title,
                                                                site.paths())
    assert not [p for p in site.paths() if p.startswith("/logout")], site.paths()


@pytest.mark.parametrize("which", ["full", "shell"])
def test_no_request_rides_an_https_landings_tunnel_after_its_exchange(monkeypatch,
                                                                      tmp_path, which):
    """BB-3's https neighbour (BUG-0559 review round 3), real Chromium, both binaries,
    TLS verification on (the test trusts its own key only): a redirected navigation's
    landing loads through the one tunnel its ticket admits; the landing's closed shadow
    root prefetches ``/logout?tls`` with the session cookie on that idle tunnel, and the
    enforcer -- which reads the record layer, never decrypts -- closes it instead of
    forwarding that second request (counted ``reuse``); the browser's retry finds no
    ticket. A later redirect still lands; a server offering ``h2`` is spoken to in
    HTTP/1.1 (``--disable-http2``: a multiplexed tunnel would carry the prefetch beside
    the landing). Before (1b05e3f): ``GET /logout?tls`` with ``sid=S`` and
    ``Sec-Purpose: prefetch`` reached the server on the landing's own client port
    (measured by the review, and again here: TLS 1.2 and 1.3, both binaries)."""
    _binary(monkeypatch, which)
    from playwright.sync_api import sync_playwright
    site = _TlsSite(tmp_path)
    multi = _TlsSite(tmp_path, alpn=("h2", "http/1.1"))
    # the Playwright driver fetches every routed request: it trusts the test CA too
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(site.ca.ca_cert_path))
    before = navguard.enforcer_refusals()
    try:
        with sync_playwright() as pw:
            browser, ctx = _guarded_https(pw, site, extra_args=[site.spki_switch()])
            try:
                page = ctx.new_page()
                nav = navguard.navigate(page, site.base + "start", timeout_ms=8000)
                landed = (nav.reached, page.url, page.title())
                page.wait_for_timeout(2500)
                nav = navguard.navigate(page, site.base + "start2", timeout_ms=8000)
                again = (nav.reached, page.url)
                page.wait_for_timeout(1000)
            finally:
                browser.close()
            browser, ctx = _guarded_https(pw, multi, extra_args=[multi.spki_switch()])
            try:
                page = ctx.new_page()
                try:
                    nav = navguard.navigate(page, multi.base + "start", timeout_ms=8000)
                    multiplexed = (nav.reached, page.url)
                except Exception as exc:  # noqa: BLE001 - reported below
                    multiplexed = (False, str(exc).splitlines()[0][:120])
            finally:
                browser.close()
    finally:
        site.close()
        multi.close()
    after = navguard.enforcer_refusals()
    with site._lock:
        seen = list(site.seen)
    assert not [s for s in seen if s[1].startswith("/logout")], seen
    assert landed == (True, site.base + "land", "LAND"), landed
    assert [s[1] for s in seen].count("/land") == 2, seen     # the route's, the browser's
    assert after["reuse"] > before.get("reuse", 0), (before, after)
    assert again == (True, site.base + "land2"), again
    assert multiplexed == (True, multi.base + "land"), multiplexed
    with multi._lock:
        assert "h2" not in {s[4] for s in multi.seen}, multi.seen


def _tunnel(endpoint: str, port: int):
    """A ``CONNECT`` to ``127.0.0.1:port`` through the enforcer: the socket when it was
    tunnelled, else None (refused)."""
    import socket
    host, eport = endpoint.rsplit(":", 1)
    sock = socket.create_connection((host, int(eport)), timeout=5)
    sock.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                 .encode())
    head = b""
    while b"\r\n\r\n" not in head:
        more = sock.recv(1)
        if not more:
            break
        head += more
    if b" 200 " in head.split(b"\r\n", 1)[0]:
        return sock
    sock.close()
    return None


def _exchange(tls, path: str) -> bytes | None:
    """One keep-alive GET on ``tls``: the answer's body, or None when the tunnel closed."""
    import ssl
    try:
        tls.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: sid=S\r\n\r\n"
                    .encode())
        got = b""
        while b"\r\n\r\n" not in got:
            more = tls.recv(4096)
            if not more:
                return None
            got += more
        head, _sep, body = got.partition(b"\r\n\r\n")
        size = int([ln.split(b":", 1)[1] for ln in head.split(b"\r\n")
                    if ln.lower().startswith(b"content-length:")][0])
        while len(body) < size:
            more = tls.recv(4096)
            if not more:
                return None
            body += more
        return body
    except (OSError, ssl.SSLError):
        return None


@pytest.mark.parametrize("tls12", [False, True], ids=["tls1.3", "tls1.2"])
def test_the_enforcer_holds_an_https_tunnel_to_its_ticket(monkeypatch, tmp_path, tls12):
    """The enforcer's tunnels (BUG-0559 review round 3), on raw sockets, TLS 1.3 and 1.2,
    verification on against the test's own CA: an https landing's ticket admits the
    retry of a handshake the client abandoned on a certificate it refused (a second
    ``CONNECT``) and carries one exchange -- a second request on that tunnel never
    reaches the server, the tunnel is closed and counted (``reuse``), and no further
    ``CONNECT`` is admitted; a WebSocket's ticket admits the same retry and then carries
    the socket's traffic whole; a retry later than `_TICKET_RETRY_WINDOW_S` after the
    first tunnel is refused. Every launch keeps Chromium's own traffic on HTTP/1.1.
    Before (1b05e3f): the retry was refused (the one ticket spent on the abandoned
    handshake) and a landing's tunnel carried any number of requests."""
    import ssl
    import time
    site = _TlsSite(tmp_path, tls12=tls12)
    trusting = ssl.create_default_context(cafile=str(site.ca.ca_cert_path))
    refusing = ssl.create_default_context()        # the system's roots: not the test CA
    args = navguard.browser_launch_args([site.base])
    endpoint = [a for a in args if a.startswith("--proxy-server=")][0].split("//", 1)[1]
    before = navguard.enforcer_refusals()
    try:
        for kind in ("landing", "socket"):
            if kind == "landing":
                navguard.admit_landing(site.base + "land")
            else:
                navguard.admit_socket(f"wss://127.0.0.1:{site.port}/ws")
            first = _tunnel(endpoint, site.port)
            assert first is not None, kind
            with pytest.raises(ssl.SSLCertVerificationError):
                refusing.wrap_socket(first, server_hostname="127.0.0.1")
            first.close()
            retry = _tunnel(endpoint, site.port)
            assert retry is not None, f"{kind}: the retry was refused"
            tls = trusting.wrap_socket(retry, server_hostname="127.0.0.1")
            assert _exchange(tls, "/land") is not None, kind
            if kind == "landing":
                assert _exchange(tls, "/logout?tls") is None     # closed, never sent
            else:
                assert _exchange(tls, "/other") is not None      # the socket's own
            tls.close()
            assert _tunnel(endpoint, site.port) is None, kind    # the ticket is spent
        monkeypatch.setattr(navguard, "_TICKET_RETRY_WINDOW_S", 0.2)
        navguard.admit_landing(site.base + "late")
        first = _tunnel(endpoint, site.port)
        assert first is not None
        first.close()
        time.sleep(0.4)
        assert _tunnel(endpoint, site.port) is None               # outside the window
    finally:
        site.close()
    time.sleep(0.2)
    assert not [p for p in site.paths() if p.startswith("/logout")], site.paths()
    assert site.paths().count("/land") == 2 and "/other" in site.paths(), site.paths()
    after = navguard.enforcer_refusals()
    assert after["reuse"] == before.get("reuse", 0) + 1, (before, after)
    assert after["connect"] == before["connect"] + 3, (before, after)
    assert "--disable-http2" in args          # Chromium's own traffic: one request a time
