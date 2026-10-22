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
        "so it is a host they reach; or it carries no session (storage None)"),
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


def test_disco_never_explores_an_unreached_host_as_the_storage_states_session(tmp_path):
    """disco's explorer with an operator's storage state (`disco capture
    --storage-state`): its context holds ``sid`` host-only for ``127.0.0.1``; the start
    page links the alias, fetches from it and its harvest finds it. Nothing reaches the
    alias -- every request there is refused by the guard (SP-74) and counted in the
    report (``session_host_unreached``, explore.json) -- so no anonymous state of it is
    explored or captured as the session's. Before: the alias was loaded and captured
    with no cookie."""
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
    site = _IdSite(protected=("/secret",))
    alias = _alias(site)
    site.home_extra = (f"<a href='{alias}/secret?via=link'>alias</a>"
                       f"<script>fetch('{alias}/data').catch(() => 0)</script>")
    body = f"user={USER}&pw={PASSWORD}".encode()
    with urllib.request.urlopen(urllib.request.Request(site.base + "login", data=body),
                                timeout=10) as resp:
        sid = resp.headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]
    state = {"cookies": [{"name": "sid", "value": sid, "domain": "127.0.0.1", "path": "/",
                          "expires": -1, "httpOnly": False, "secure": False,
                          "sameSite": "Lax"}], "origins": []}
    options = ExploreOptions(max_actions=6, deadline_s=60, max_states=4, idle_ms=200,
                             max_quiet_ms=3000)
    try:
        with CaptureProxy([site.base], out=tmp_path / "capture.jsonl",
                          profile="user") as proxy:
            ex = Explorer(site.base, scope_urls=[site.base], proxy=proxy.endpoint,
                          options=options, storage_state=state,
                          actions_log=tmp_path / "actions.jsonl")
            try:
                report = ex.run()
            except PlaywrightError as exc:
                skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
    finally:
        site.close()
    assert _to_alias(site) == []
    assert report.session_host_unreached.get("localhost", 0) >= 1, report
    assert json.loads(json.dumps(report.__dict__))["session_host_unreached"]
    with site._lock:
        own = [c for h, (m, _p, c, _ua) in zip(site.hosts, site.requests)
               if h.split(":")[0] == "127.0.0.1" and m == "GET"]
    assert any(f"sid={sid}" in c for c in own), own     # its own host: with the session
