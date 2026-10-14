"""Forms phase 3, SPA routes (FR-CRAWL-12, CC-CRAWL-0016).

The live Juice Shop crawl collapsed every Angular hash route into ``/`` (the crawler
dropped the fragment) and never saw a form; ``localhost`` and ``127.0.0.1`` were two
sites; socket.io polling URLs were stored as pages, session id included. Now:

* route declarations are read from the page's **already-loaded** same-origin scripts
  (no extra request), by a linear scan with a size cap and a per-page script cap;
* hash routes (``#/x``, ``#!/x``) are distinct pages; history routes are paths;
* parameterised / wildcard routes and destructive routes are skipped and counted;
* pages dedupe on the canonical origin, so loopback aliases are one site;
* socket.io / engine.io transport URLs are not pages; identifier-like XHR query values
  are blanked;
* the crawl guard aborts a browser-initiated DELETE unless ``--submit-spa-forms`` named
  the route (counted).

Real-browser tests run Chromium against a loopback fake SPA (``tests/_spa_fixture.py``)
and fail rather than skip under ``FUZZLAB_REQUIRE_BROWSER=1``.
"""

from __future__ import annotations

import time

import pytest

from fuzzlab.tools import spa
from tests._spa_fixture import (IDENT, HashSpa, HistorySpa, Recorder, chromium_or_skip,
                                db_rows, run_crawl)


# =====================================================================================
# Route extraction: what is read, and that it is linear and bounded
# =====================================================================================
def test_angular_vue_and_react_declarations_are_read():
    body = ("const r=[{path:'login',component:A},{path:\"search\",component:B},"
            "{path:`contact`,component:C}];\n"
            "new VueRouter({routes: [ { path: '/about', component: X },\n"
            "  { path: '/users/:id' } ]});\n"
            "h(Route,{ path: \"/score\", element: S});\n"
            "'<Route exact path=\"/react-only\" />';\n"
            '{"path":"quoted-key"}')
    assert spa.scan_routes(body) == ["login", "search", "contact", "/about", "/users/:id",
                                     "/score", "/react-only", "quoted-key"]


@pytest.mark.parametrize("body", [
    "x.path = '/assignment';",            # not an object key
    "{xpath:'/no'}",                      # part of a longer name
    "{paths:'/no'}",
    "{path:someVariable}",                # not a literal
    "{path:'" + "a" * 200 + "'}",         # too long to be a route
    "<Route>path=\"/no\"",                # the attribute is outside the tag
    "<div path=\"/no\">",                 # not a <Route
    "{path:'never-closed",
])
def test_near_misses_are_not_routes(body):
    assert spa.scan_routes(body) == []


def _adversarial(size: int) -> dict:
    return {
        "unterminated path": "{path:'" * (size // 7),
        "jsx attribute run": "<Route path=" * (size // 12),
        "bare key run": "path" * (size // 4),
        "spaced key": ("{path" + " " * 7 + ":" + " " * 7 + "'") * (size // 21),
    }


def _time(body: str, cap: int) -> float:
    start = time.perf_counter()
    spa.scan_routes(body, max_bytes=cap)
    return time.perf_counter() - start


def test_the_scan_is_linear_on_adversarial_5mb_bodies():
    """PA-0095 / reviewer A9: near-miss bodies (an unterminated ``{path:'`` repeated, a
    5 MB bundle) are scanned in bounded time, and doubling the body roughly doubles the
    time (a quadratic scan would quadruple it)."""
    big = 5 * 1024 * 1024
    for name, body in _adversarial(big).items():
        assert _time(body, 8 * big) < 10.0, name
    for name in _adversarial(1024):
        small = _adversarial(512 * 1024)[name]
        large = _adversarial(1024 * 1024)[name]
        t_small = min(_time(small, big) for _ in range(3))
        t_large = min(_time(large, big) for _ in range(3))
        assert t_large < 3.5 * max(t_small, 1e-3), name


def test_a_script_over_the_size_cap_is_not_scanned():
    body = "{path:'hidden'}" + " " * spa.MAX_SCRIPT_BYTES
    assert spa.scan_routes(body) is None
    assert spa.scan_routes("{path:'shown'}") == ["shown"]


def test_one_script_yields_at_most_the_route_cap():
    body = "".join(f"{{path:'r{i}'}}," for i in range(spa.MAX_ROUTES_PER_SCRIPT + 50))
    assert len(spa.scan_routes(body)) == spa.MAX_ROUTES_PER_SCRIPT


# =====================================================================================
# Route classification and URLs
# =====================================================================================
@pytest.mark.parametrize("path,kind", [
    ("login", spa.ROUTE_OK), ("/about", spa.ROUTE_OK), ("track-result/new", spa.ROUTE_OK),
    ("product/:id", spa.ROUTE_PARAM), ("/users/:id/edit", spa.ROUTE_PARAM),
    ("**", spa.ROUTE_PARAM), ("files/*", spa.ROUTE_PARAM),
    ("logout", spa.ROUTE_DESTRUCTIVE), ("delete-account", spa.ROUTE_DESTRUCTIVE),
    ("/reset-password", spa.ROUTE_DESTRUCTIVE), ("signOut", spa.ROUTE_DESTRUCTIVE),
    ("", spa.ROUTE_ROOT), ("/", spa.ROUTE_ROOT),
    ("{path:", spa.ROUTE_INVALID), ("a b", spa.ROUTE_INVALID), ("a//b", spa.ROUTE_INVALID),
    ("http://evil.example/x", spa.ROUTE_INVALID),
])
def test_routes_are_classified(path, kind):
    assert spa.classify_route(path)[0] == kind


@pytest.mark.parametrize("path", ["//evil.example/x", "/\\evil.example", "evil.example"])
def test_a_route_url_never_leaves_the_page_origin(path):
    for hash_mode in (True, False):
        url = spa.route_url("http://127.0.0.1:3000/app/", path, hash_mode=hash_mode)
        assert url.startswith("http://127.0.0.1:3000/app/"), url


def test_route_urls_for_hash_hashbang_and_history_mode():
    page = "http://127.0.0.1:3000/app/#/home?x=1"
    assert spa.route_url(page, "login", hash_mode=True) == "http://127.0.0.1:3000/app/#/login"
    assert spa.route_url(page, "/login", hash_mode=True, hashbang=True) == \
        "http://127.0.0.1:3000/app/#!/login"
    assert spa.route_url("http://h/app/x/y", "/about", hash_mode=False,
                         base="http://h/app/") == "http://h/app/about"


def test_a_hash_route_is_destructive_by_its_fragment():
    """`destructive_reason` reads path and query only; a hash route's fragment is the
    route, so the crawler checks it too (a hash navigation sends no request the browser
    guard could see)."""
    assert spa.route_destructive_reason("http://h/#/logout") == "logout"
    assert spa.route_destructive_reason("http://h/#!/account/delete?x=1") == "delete"
    assert spa.route_destructive_reason("http://h/#/about") is None
    assert spa.route_destructive_reason("http://h/page#logout") is None   # not a route


# =====================================================================================
# Visit keys: SPA fragments kept, aliases one site
# =====================================================================================
@pytest.mark.parametrize("a,b,same", [
    ("http://localhost:3000/#/login", "http://127.0.0.1:3000/#/login", True),
    ("http://[::1]:3000/a?b=1", "http://127.0.0.1:3000/a?b=1", True),
    ("http://127.0.0.1:3000/#/login", "http://127.0.0.1:3000/#/contact", False),
    ("http://127.0.0.1:3000/#!/login", "http://127.0.0.1:3000/#/login", False),
    ("http://127.0.0.1:3000/page#top", "http://127.0.0.1:3000/page", True),
    ("http://127.0.0.1:3000/a?b=1", "http://127.0.0.1:3000/a?b=2", False),
    ("http://127.0.0.1:3000/", "http://127.0.0.1:3001/", False),
])
def test_visit_keys(a, b, same):
    assert (spa.visit_key(a) == spa.visit_key(b)) is same


def test_crawl_urls_keep_only_spa_fragments():
    assert spa.crawl_url("http://h/#/login", True) == "http://h/#/login"
    assert spa.crawl_url("http://h/#/login", False) == "http://h/"
    assert spa.crawl_url("http://h/p#section", True) == "http://h/p"


def test_loopback_aliases_are_one_site_in_the_spider_db(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    try:
        assert sm.mark_visited("http://localhost:3000/a", 200, 0)
        assert sm.is_visited("http://127.0.0.1:3000/a")
        assert not sm.mark_visited("http://127.0.0.1:3000/a", 200, 0)
        assert sm.mark_visited("http://127.0.0.1:3000/#/a", 200, 0)    # a route: distinct
    finally:
        sm.close()
    # a resumed crawl keeps the keys of what is already stored
    sm = StorageManager(str(tmp_path / "s.db"))
    try:
        assert sm.is_visited("http://[::1]:3000/a")
    finally:
        sm.close()


# =====================================================================================
# Transport noise and XHR identifiers
# =====================================================================================
@pytest.mark.parametrize("url,transport", [
    ("http://h/socket.io/?EIO=4&transport=polling&t=N&sid=abc", True),
    ("http://h/engine.io/?x=1", True),
    ("http://h/ws?EIO=3&transport=websocket", True),
    ("http://h/rest/socket.iox/a", False),
    ("http://h/rest/products?transport=car", False),
    ("http://h/api/socket", False),
])
def test_transport_urls(url, transport):
    assert spa.is_transport_url(url) is transport


def test_an_xhr_url_is_queued_with_identifiers_blanked_and_transports_dropped(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        base = "http://127.0.0.1:8080/"
        assert sp._queue_xhr(base, f"/rest/v?ref={IDENT}&lang=en") == \
            "http://127.0.0.1:8080/rest/v?ref=&lang=en"
        assert sp._queue_xhr(base, "/rest/v?token=abc") == \
            "http://127.0.0.1:8080/rest/v?token=__REDACTED__"
        assert sp._queue_xhr(base, f"/socket.io/?EIO=4&transport=polling&sid={IDENT}") is None
        assert sp.spa_counts["transport_urls_skipped"] == 1
    finally:
        sp.storage.close()


# =====================================================================================
# The crawl's DELETE rule and the guard's hooks
# =====================================================================================
class _Req:
    def __init__(self, url, method="GET", rtype="xhr", body=None, headers=None):
        self.url, self.method, self.resource_type = url, method, rtype
        self.post_data_buffer = body
        self.headers = headers or {}

    def is_navigation_request(self):
        return False


class _Resp:
    def __init__(self, status=200, body=b"", headers=None):
        self.status, self._body, self.headers = status, body, headers or {}
        self.read = 0

    def body(self):
        self.read += 1
        return self._body


class _Route:
    def __init__(self, req):
        self.request, self.outcome, self.fetched = req, None, 0

    def fetch(self, max_redirects=None):
        self.fetched += 1
        return _Resp()

    def abort(self):
        self.outcome = "abort"

    def fulfill(self, response=None, **kw):
        self.outcome = "fulfill"

    def continue_(self):
        self.outcome = "continue"


def test_the_guard_aborts_a_refused_method_before_any_fetch():
    from fuzzlab.tools.navguard import make_route_handler
    aborted = []
    handler = make_route_handler(
        frozenset(), lambda u, r: aborted.append((u, r)), in_scope=lambda u: True,
        method_refusal=lambda m, u: "browser-initiated DELETE" if m == "DELETE" else None)
    delete = _Route(_Req("http://h/api/Items/7", "DELETE"))
    handler(delete)
    assert (delete.outcome, delete.fetched) == ("abort", 0)
    assert aborted == [("http://h/api/Items/7", "browser-initiated DELETE")]
    get = _Route(_Req("http://h/api/Items/7"))
    handler(get)
    assert get.outcome == "fulfill"


def test_a_failing_observer_never_changes_the_answer():
    from fuzzlab.tools.navguard import make_route_handler

    def boom(req, resp):
        raise RuntimeError("observer bug")
    route = _Route(_Req("http://h/a.js", rtype="script"))
    make_route_handler(in_scope=lambda u: True, observe=boom)(route)
    assert route.outcome == "fulfill"


def test_the_spider_refuses_a_delete_unless_a_named_route_submission_sends_it(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        assert sp._method_refusal("DELETE", "http://127.0.0.1:8080/api/x/1")
        assert sp._method_refusal("PATCH", "http://127.0.0.1:8080/api/x/1") is None
        sp._delete_ok = True                         # only inside a named-route submission
        assert sp._method_refusal("DELETE", "http://127.0.0.1:8080/api/x/1") is None
        assert sp.spa_counts["deletes_blocked"] == 1
    finally:
        sp.storage.close()


def test_cross_origin_and_oversized_scripts_are_never_read(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        sp._doc_url = "http://127.0.0.1:8080/"
        other = _Resp(body=b"{path:'x'}")
        sp._observe(_Req("http://127.0.0.1:9090/x.js", rtype="script"), other, scripts=True)
        assert other.read == 0                                   # cross-origin: not read
        big = _Resp(body=b"{path:'x'}", headers={"content-length":
                                                  str(spa.MAX_SCRIPT_BYTES + 1)})
        sp._observe(_Req("http://127.0.0.1:8080/big.js", rtype="script"), big, scripts=True)
        assert big.read == 0 and sp.spa_counts["scripts_too_large"] == 1
        ok = _Resp(body=b"{path:'shown'}")
        sp._observe(_Req("http://localhost:8080/app.js", rtype="script"), ok, scripts=True)
        sp._observe(_Req("http://localhost:8080/app.js", rtype="script"), ok, scripts=True)
        assert ok.read == 1 and sp._pending_routes == ["shown"]   # read once, alias origin
        anon = _Resp(body=b"{path:'anon'}")
        sp._observe(_Req("http://127.0.0.1:8080/b.js", rtype="script"), anon, scripts=False)
        assert anon.read == 0                     # an unauthenticated context's scripts
    finally:
        sp.storage.close()


def test_scripts_per_page_are_capped(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        sp._doc_url = "http://127.0.0.1:8080/"
        reads = []
        for i in range(spa.MAX_SCRIPTS_PER_PAGE + 3):
            resp = _Resp(body=f"{{path:'r{i}'}}".encode())
            sp._observe(_Req(f"http://127.0.0.1:8080/s{i}.js", rtype="script"), resp,
                        scripts=True)
            reads.append(resp.read)
        assert sum(reads) == spa.MAX_SCRIPTS_PER_PAGE
        assert sp.spa_counts["scripts_over_page_cap"] == 3
    finally:
        sp.storage.close()


# =====================================================================================
# Real browser: the fake hash-mode and history-mode SPAs
# =====================================================================================
@pytest.fixture
def hash_lab(monkeypatch):
    chromium_or_skip(monkeypatch)
    other = Recorder()
    lab = HashSpa(other_port=other.server.server_address[1])
    try:
        yield lab, other
    finally:
        lab.close()
        other.close()


def _crawl(lab, tmp_path, start=None, **kw):
    from fuzzlab.tools.spider import LocalSpider
    db = str(tmp_path / "s.db")
    sp = LocalSpider(start or lab.base, max_depth=2, db_name=db, engine="playwright",
                     timeout_ms=5000, **kw)
    run_crawl(sp)
    return sp, db


def test_hash_routes_are_read_from_the_bundle_and_crawled_as_pages(hash_lab, tmp_path):
    lab, other = hash_lab
    sp, db = _crawl(lab, tmp_path)
    urls = {u for (u,) in db_rows(db, "SELECT url FROM discovered_pages")}
    for route in ("login", "about", "profile", "contact", "checkout", "archive"):
        assert lab.base + "#/" + route in urls, route
    rendered = {r[1] for r in lab.seen("GET", "/rest/marker/")}
    assert {"/rest/marker/login", "/rest/marker/contact"} <= rendered
    # destructive and parameterised routes never render
    assert not rendered & {"/rest/marker/L", "/rest/marker/D", "/rest/marker/P"}
    assert not any("logout" in u or "delete-account" in u or ":id" in u for u in urls)
    c = sp.spa_counts
    assert c["routes_skipped_destructive"] == 2            # logout, delete-account
    assert c["routes_skipped_parameterised"] == 2          # product/:id, **
    assert c["routes_visited"] >= 10 and c["scripts_scanned"] == 1
    # the bundle was read from the guard's own fetch: main.js requested once per document
    assert len(lab.seen("GET", "/main.js")) == 1
    # a form on a route is recorded
    pages = {p for (p,) in db_rows(db, "SELECT page_url FROM discovered_forms")}
    assert lab.base + "#/contact" in pages
    assert other.requests == []                            # nothing left the origin


def test_the_summary_reports_the_route_counts(hash_lab, tmp_path):
    lab, _other = hash_lab
    sp, _db = _crawl(lab, tmp_path)
    (line,) = [ln for ln in sp.spa_summary() if ln.startswith("SPA routes:")]
    assert "2 skipped as destructive" in line and "2 skipped as parameterised" in line
    assert f"{sp.spa_counts['routes_visited']} visited" in line


def test_spa_routes_can_be_turned_off(hash_lab, tmp_path):
    lab, _other = hash_lab
    sp, db = _crawl(lab, tmp_path, spa_routes=False)
    urls = {u for (u,) in db_rows(db, "SELECT url FROM discovered_pages")}
    assert not any("#" in u for u in urls)
    assert sp.spa_counts["routes_found"] == 0


def test_loopback_aliases_are_crawled_as_one_site(hash_lab, tmp_path):
    lab, _other = hash_lab
    _sp, db = _crawl(lab, tmp_path, start=lab.base.replace("127.0.0.1", "localhost"))
    urls = [u for (u,) in db_rows(db, "SELECT url FROM discovered_pages")]
    keys = [spa.visit_key(u) for u in urls]
    assert len(keys) == len(set(keys)) and len(urls) > 10


def test_socket_io_urls_are_not_pages_and_xhr_identifiers_are_blanked(hash_lab, tmp_path):
    lab, _other = hash_lab
    sp, db = _crawl(lab, tmp_path)
    urls = [u for (u,) in db_rows(db, "SELECT url FROM discovered_pages")]
    assert not any("socket.io" in u or "EIO" in u for u in urls)
    assert sp.spa_counts["transport_urls_skipped"] >= 2
    assert not any(IDENT in u for u in urls)
    assert any(u.endswith("/rest/version?sid=__REDACTED__&lang=en") for u in urls)


def test_a_browser_initiated_delete_is_aborted_and_counted(hash_lab, tmp_path):
    """Reviewer A6: the ``items`` route's own load sends a DELETE; the crawl never
    deletes (NFR-CRAWL-safe)."""
    lab, _other = hash_lab
    sp, _db = _crawl(lab, tmp_path)
    assert lab.seen("DELETE") == []
    assert sp.spa_counts["deletes_blocked"] >= 1
    assert any("DELETE" in ln for ln in sp.spa_summary())


def test_a_delete_is_sent_only_from_a_named_routes_submission(hash_lab, tmp_path):
    lab, _other = hash_lab
    _crawl(lab, tmp_path, submit_spa_forms=[])           # bare: archive not named
    assert lab.seen("DELETE") == []
    lab.requests.clear()
    sp, _db = _crawl(lab, tmp_path, submit_spa_forms=["archive"])
    assert [r[1] for r in lab.seen("DELETE")] == ["/api/Notes/3"]   # the click, once
    assert sp.spa_counts["deletes_blocked"] >= 1          # the items route's load: still


def test_history_mode_routes_are_paths_under_the_base(monkeypatch, tmp_path):
    chromium_or_skip(monkeypatch)
    lab = HistorySpa()
    try:
        sp, db = _crawl(lab, tmp_path)
    finally:
        lab.close()
    urls = {u for (u,) in db_rows(db, "SELECT url FROM discovered_pages")}
    assert {lab.base + "about", lab.base + "contact"} <= urls
    assert not any("users" in u or "signout" in u for u in urls)
    assert sp.spa_counts["routes_skipped_parameterised"] == 1
    assert sp.spa_counts["routes_skipped_destructive"] == 1
    assert not any(r[1].startswith("/users") or r[1].startswith("/signout")
                   for r in lab.requests)
