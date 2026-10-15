"""BUG-0138 / PA-0138: no guarded navigation waits for a load a refused navigation can
cancel.

Since BUG-0136 a refused navigation is aborted with ERR_ABORTED, which keeps the
current document. A page whose script navigates to a refused URL while it is being
parsed (a head script setting ``location.href = '/logout'``) has its loading stopped
there, so it never reaches ``domcontentloaded`` or ``load``. Every
``goto(wait_until="domcontentloaded")`` then waited out its whole timeout. The crawl
fell back to a second, static request; a query probe or seed load timed out and kept
nothing; the auditor did the same; the browser login waited out its own.

Now every guarded navigation goes through `navguard.navigate` / `reload`:
- the commit only (a refused own target still raises, BUG-0136);
- then the load state, bounded and suppressed, and cut short
  `SUPERSEDED_GRACE_MS` after a main-frame navigation fails;
- a page whose load never completed is read from what the browser received for it
  (`navguard.response_html`), never fetched again.

An AST guard holds every module of fuzzlab to the helper.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path

import pytest

from tests.test_navigation_aborts import _chromium_or_skip, _Site

FUZZLAB = Path(__file__).resolve().parent.parent / "fuzzlab"
_HEAD_NAV = "<script>location.href = '/logout'</script>"
_PAGE = (f"<html><head><title>A</title>{_HEAD_NAV}</head><body><p>A-OWN-CONTENT</p>"
         f"<a href='/next'>n</a></body></html>")
#: well under the 8 s navigation timeout the tests use
FAST = 3.5


def _timed(obj, name, durations):
    """Wrap ``obj.name(url, ...)`` to record each call's duration by URL."""
    real = getattr(obj, name)

    def timed(url, *a, **kw):
        started = time.monotonic()
        try:
            return real(url, *a, **kw)
        finally:
            durations.setdefault(url, []).append(time.monotonic() - started)
    setattr(obj, name, timed)


# --- the crawl ----------------------------------------------------------------------
def test_a_head_script_navigation_to_a_refused_url_is_not_waited_out(monkeypatch,
                                                                     tmp_path):
    """The crawl reads the page well under its timeout from the one request the
    browser made: its content and links are kept, nothing is sent twice, and the
    refused URL is never requested."""
    import sqlite3

    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages["/"] = _PAGE
    durations: dict = {}
    try:
        sp = LocalSpider(a.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000)
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        _timed(sp, "_goto_and_parse", durations)
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
    rows = dict(sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, content FROM discovered_pages").fetchall())
    assert max(durations[a.base]) < FAST, durations[a.base]
    assert a.requests.count("/") == 1                       # no static second request
    assert "A-OWN-CONTENT" in (rows.get(a.base) or "")       # content kept
    assert "/next" in a.requests                             # its link crawled
    assert "/logout" not in a.requests
    assert a.base + "logout" in sp.skipped_destructive       # the refusal, recorded


def test_a_slow_page_is_still_waited_for(monkeypatch, tmp_path):
    """The bound is the caller's own timeout, cut short only by a refused navigation:
    a page whose parsing waits 2.5 s for a script is still read whole, as before."""
    import sqlite3

    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages["/"] = ("<html><head><title>S</title><script src='/slow.js'></script>"
                    "</head><body><p>SLOW-CONTENT</p><a href='/next'>n</a></body></html>")
    a.pages["/slow.js"] = "window.slow = 1;"
    a.delays["/slow.js"] = 2.5
    try:
        sp = LocalSpider(a.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000)
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
    rows = dict(sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, content FROM discovered_pages").fetchall())
    assert "SLOW-CONTENT" in (rows.get(a.base) or "")
    assert a.requests.count("/") == 1 and "/next" in a.requests


# --- query probe and seed loads (FR-CRAWL-17) ----------------------------------------
_HN_JS = r"""
// the declarations are read by the scan, never run (no VueRouter on the page)
function declare() { return new VueRouter({mode: 'history', routes: [
  { path: '/trap', component: Trap },
  { path: '/calm', component: Calm },
]}); }
class Nav{go(t){this.router.navigate([`/trap`],{queryParams:{x:t}});
this.router.navigate([`/calm`],{queryParams:{z:t}})}
read(){return[this.route.snapshot.queryParams.term]}}
"""
_HN_INDEX = ("<!doctype html><html><head><title>hn</title><script src='/hn.js'></script>"
             "</head><body><p>shell</p><a href='/calm'>c</a></body></html>")


def _trap(handler):
    """``/trap``: the bare route is the app shell; with any query (a seed's or a
    probe's) its head script navigates to the refused ``/logout`` while parsing."""
    if "?" in handler.path:
        body = (f"<!doctype html><html><head><title>trap</title>{_HEAD_NAV}</head>"
                f"<body><p>TRAP-SEED-CONTENT</p><a href='/trapnext'>t</a></body></html>")
    else:
        body = _HN_INDEX
    handler._send(200, "text/html", body.encode())


def test_query_probe_and_seed_loads_are_not_waited_out(monkeypatch, tmp_path):
    """FR-CRAWL-17: the ``/trap`` seed (``?x=fuzzlab``) and its probe (``?term=<marker>``)
    each load once, well under the timeout; the seed's content and links are kept;
    ``/logout`` is never requested."""
    import sqlite3

    from tests._spa_fixture import _Lab, run_crawl
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)

    class HeadNavQuerySpa(_Lab):
        index = _HN_INDEX
        script = ("/hn.js", _HN_JS)
        history = True
        responders = {"/trap": _trap}
    lab = HeadNavQuerySpa()
    durations: dict = {}
    try:
        sp = LocalSpider(lab.base, max_depth=3, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000)
        _timed(sp, "_goto_and_parse", durations)
        run_crawl(sp)
        gets = [r[1] for r in lab.requests if r[0] == "GET"]
    finally:
        lab.close()
    seed = lab.base + "trap?x=fuzzlab"
    probes = [u for u in durations if u.startswith(lab.base + "trap?term=")]
    assert seed in durations and probes, sorted(durations)
    assert max(durations[seed]) < FAST and max(durations[probes[0]]) < FAST
    assert gets.count("/trap?x=fuzzlab") == 1                # one load, no re-send
    assert len([g for g in gets if g.startswith("/trap?term=")]) == len(probes)
    assert sp.spa_counts["spa_query_probe_loads"] >= 2       # /trap's and /calm's
    rows = dict(sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, content FROM discovered_pages").fetchall())
    assert "TRAP-SEED-CONTENT" in (rows.get(seed) or "")     # the seed's content
    assert "/trapnext" in gets                               # and its link
    assert "/logout" not in gets


# --- the auditor --------------------------------------------------------------------
def test_the_auditor_reads_the_page_without_waiting_it_out(monkeypatch):
    """CC-AUD-0043: the auditor's rendered fetch returns well under its timeout, from
    the one request the browser made, with the page's HTML (its fields and links)."""
    from tests._browser import skip_or_fail
    from fuzzlab.tools.fetcher import ContentFetcher
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages["/"] = _PAGE
    try:
        with ContentFetcher(engine="playwright", timeout_ms=8000) as fetcher:
            started = time.monotonic()
            try:
                status, _ct, html, _xhr = fetcher.fetch(a.base)
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                skip_or_fail(f"chromium could not launch: {exc}")
            took = time.monotonic() - started
    finally:
        a.close()
    assert took < FAST + 1.5, f"{took:.1f}s"                  # the launch included
    assert status == 200 and "A-OWN-CONTENT" in html and "/next" in html
    assert a.requests.count("/") == 1 and "/logout" not in a.requests


# --- the browser login --------------------------------------------------------------
def test_a_login_page_that_navigates_away_fails_loudly_and_fast(monkeypatch):
    """CC-SESS-0024: the login page's head script navigates to the refused /logout:
    the login fails loudly (no form), well under its 10 s timeout, and nothing is
    posted."""
    from tests._spa_fixture import chromium_or_skip
    from tests._spa_login_fixture import LoginSpa
    from tests.test_session_browser_login import _login, _manager, _password
    from fuzzlab.session.manager import SessionAuthError
    chromium_or_skip(monkeypatch)
    lab = LoginSpa(_password(), head_nav="/logout")
    try:
        started = time.monotonic()
        with pytest.raises(SessionAuthError, match="no login form"):
            _login(_manager(lab, lab.password), lab)       # a launch failure: a skip
        took = time.monotonic() - started
    finally:
        lab.close()
    assert took < 8.0, f"{took:.1f}s: the login page's load was waited out"
    assert lab.seen("POST") == [] and lab.seen("GET", "/logout") == []


# --- the rule, everywhere (PA-0138) -------------------------------------------------
#: Page / frame calls that navigate or wait for a navigation's load state: only
#: `navguard`'s helpers make them.
NAVIGATION_CALLS = frozenset({"goto", "reload", "go_back", "go_forward",
                              "wait_for_navigation", "expect_navigation",
                              "wait_for_load_state", "wait_for_url",
                              # a document set or an event awaited (review A-N1, B-N2)
                              "set_content", "wait_for_event", "expect_event"})
HELPER_MODULE = "navguard"


def navigation_offenders(source: str) -> list[tuple[int, str]]:
    """``(line, call)`` for every navigation or load-state wait not made through the
    `navguard` module (``navguard.navigate`` / ``navguard.reload``)."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in NAVIGATION_CALLS:
            receiver = node.func.value
            if isinstance(receiver, ast.Name) and receiver.id == HELPER_MODULE:
                continue
            out.append((node.lineno, node.func.attr))
    return out


def test_every_guarded_navigation_goes_through_the_one_helper():
    """PA-0138: outside `tools/navguard.py`, no module of fuzzlab navigates a page or
    waits for a load state itself."""
    offenders = {}
    for path in FUZZLAB.rglob("*.py"):
        if path.name == "navguard.py" and path.parent.name == "tools":
            continue
        found = navigation_offenders(path.read_text(encoding="utf-8"))
        if found:
            offenders[str(path.relative_to(FUZZLAB))] = found
    assert offenders == {}


@pytest.mark.parametrize("source", [
    "page.goto(url, wait_until='domcontentloaded')",
    "self._page.goto(url)",
    "page.reload(wait_until='load')",
    "page.wait_for_load_state('networkidle', timeout=5)",
    "with page.expect_navigation():\n    pass",
    "page.main_frame.goto(url)",
    "page.go_back()",
    "page.set_content('<p>x</p>', wait_until='load')",
    "page.wait_for_event('load')",
    "with page.expect_event('framenavigated'):\n    pass",
])
def test_the_navigation_guard_catches_synthetic_offenders(source):
    """PA-0034(2): the guard is proven on what it must catch, and lets the helper by."""
    assert navigation_offenders(source)
    assert not navigation_offenders("navguard.navigate(page, url, timeout_ms=1)\n"
                                    "navguard.reload(page, timeout_ms=1)")


# --- review of BUG-0138 (D58) -------------------------------------------------------
class _Request:
    def __init__(self, frame):
        self.frame = frame

    def is_navigation_request(self):
        return True


class _EarlyFailurePage:
    """A page double: the previous page's pending navigation is reported failed while
    ``goto`` is still running (before the commit), and ``load`` comes 500 ms later."""

    def __init__(self):
        self.main_frame, self._handlers, self._loaded_at = object(), [], None

    def on(self, event, fn):
        self._handlers.append(fn)

    def remove_listener(self, event, fn):
        self._handlers.remove(fn)

    def goto(self, url, **kw):
        for fn in list(self._handlers):          # before goto returns: before the commit
            fn(_Request(self.main_frame))
        self._loaded_at = time.monotonic() + 0.5
        return None

    def wait_for_load_state(self, state, timeout=None):
        from playwright.sync_api import TimeoutError as PlaywrightTimeout
        if time.monotonic() < self._loaded_at:
            time.sleep(min(timeout or 0, 100) / 1000)
            raise PlaywrightTimeout("not yet")


def test_a_failure_reported_before_the_commit_never_cuts_the_wait():
    """Q1 (A-S1 = B-S1): only main-frame failures reported at or after this
    navigation's commit count; an earlier one (the previous page's pending navigation,
    cancelled by this one) must not cut a load that comes 500 ms later."""
    from fuzzlab.tools import navguard
    nav = navguard.navigate(_EarlyFailurePage(), "http://127.0.0.1:9/b", timeout_ms=4000)
    assert nav.reached and not nav.superseded


def test_a_previous_pages_pending_navigation_never_cuts_the_next_load(monkeypatch):
    """Q1, real Chromium: the previous page has a slow navigation pending (its server
    answers in 3 s) when the next URL is loaded; Chromium cancels it, and the next
    page's ``domcontentloaded`` (about 1 s after its commit, a slow script) is still
    waited for."""
    from playwright.sync_api import sync_playwright

    from tests._browser import launch_browser_or_skip
    from fuzzlab.core.urls import in_origin_scope, origin_scope
    from fuzzlab.tools import navguard
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages["/"] = ("<html><body><p>A</p><script>window.addEventListener('load', "
                    "() => setTimeout(() => location.href = '/pending', 50))</script>"
                    "</body></html>")
    a.delays["/pending"] = 3.0
    a.pages["/b"] = ("<html><head><title>B</title><script src='/b.js'></script></head>"
                     "<body><p>B-CONTENT</p></body></html>")
    a.pages["/b.js"] = "window.b = 1;"
    a.delays["/b.js"] = 1.0
    origins = origin_scope(a.base)
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                ctx = browser.new_context(service_workers="block")
                navguard.guard_page(ctx, in_scope=lambda u: in_origin_scope(u, origins))
                page = ctx.new_page()
                navguard.navigate(page, a.base, timeout_ms=8000, wait_until="load")
                page.wait_for_timeout(300)                # /pending is now in flight
                nav = navguard.navigate(page, a.base + "b", timeout_ms=8000)
                content = page.content()
                navguard.release(ctx)
                ctx.close()
            finally:
                browser.close()
    finally:
        a.close()
    assert "/pending" in a.requests                       # it really was pending
    assert nav.reached and not nav.superseded
    assert "B-CONTENT" in content


def _crawl_rows(tmp_path, monkeypatch, pages, delays, timeout_ms=3000):
    """Crawl a site of ``pages`` (path -> HTML; ``delays`` path -> s) to depth 1; return
    ``(site, {url: (title, content)})``."""
    import sqlite3

    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages.update(pages)
    a.delays.update(delays)
    try:
        sp = LocalSpider(a.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=timeout_ms)
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
    rows = {u: (t, c) for u, t, c in sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, title, content FROM discovered_pages").fetchall()}
    return a, rows


def test_a_merely_slow_page_keeps_its_rendered_text(monkeypatch, tmp_path):
    """Q2 (B-S2): a page whose load outlasts the wait (a 5 s script, a 3 s timeout) but
    was not superseded keeps its DOM: the text its own script rendered is stored, not
    only the response's."""
    a, rows = _crawl_rows(tmp_path, monkeypatch, {
        "/": ("<html><head><title>SLOW</title></head><body><div id='o'></div><script>"
              "document.getElementById('o').textContent = 'JS-RENDERED-TEXT'</script>"
              "<script src='/slow.js'></script><p>tail</p></body></html>"),
        "/slow.js": "window.s = 1;"}, {"/slow.js": 5.0})
    title, content = rows[a.base]
    assert "JS-RENDERED-TEXT" in (content or "") and title == "SLOW"
    assert a.requests.count("/") == 1


def test_another_document_never_fills_this_urls_row(monkeypatch, tmp_path):
    """Q2 (A-S2): A's head script navigates to B, which is allowed but slow to load (a
    5 s script): B commits, so the page no longer shows A. A's row holds A's own
    title and links only, from A's response; none of B's title, links or URL."""
    a, rows = _crawl_rows(tmp_path, monkeypatch, {
        "/": ("<html><head><title>A-TITLE</title><script>location.href = '/b'</script>"
              "</head><body><p>A-TEXT</p><a href='/alink'>a</a></body></html>"),
        "/b": ("<html><head><title>B-TITLE</title></head><body><p>B-TEXT</p>"
               "<a href='/blink'>b</a><script src='/bslow.js'></script></body></html>"),
        "/bslow.js": "window.b = 1;"}, {"/bslow.js": 5.0})
    title, content = rows[a.base]
    assert title == "A-TITLE" and "A-TEXT" in (content or "")
    assert "B-TEXT" not in (content or "")
    assert "/alink" in a.requests and "/blink" not in a.requests
    assert a.base + "b" not in rows                        # never filed as A's landing


# --- review of 8350ab1 --------------------------------------------------------------
def test_a_same_path_document_with_another_query_never_fills_this_urls_row(monkeypatch,
                                                                         tmp_path):
    """Review A-S1: ``/p?a=1``'s head script navigates (allowed) to the slow
    ``/p?a=2``. A document is its path **and** query (`core.urls.document_key`): the
    page no longer shows ``/p?a=1``, so its row holds its own response's title, text and
    link, its final URL stays ``/p?a=1``, and nothing of ``/p?a=2`` is filed."""
    import sqlite3

    from tests._browser import skip_or_fail
    from fuzzlab.tools.spider import LocalSpider
    _chromium_or_skip(monkeypatch)
    a = _Site()
    a.pages["/p?a=1"] = ("<html><head><title>P-A1</title><script>location.href = "
                         "'/p?a=2'</script></head><body><p>A1-TEXT</p>"
                         "<a href='/a1link'>1</a></body></html>")
    a.pages["/p?a=2"] = ("<html><head><title>P-A2</title></head><body><p>A2-TEXT</p>"
                         "<a href='/a2link'>2</a><script src='/pslow.js'></script>"
                         "</body></html>")
    a.pages["/pslow.js"] = "window.p = 1;"
    a.delays["/pslow.js"] = 5.0
    finals = {}
    try:
        start = a.base + "p?a=1"
        sp = LocalSpider(start, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=3000)
        if sp.engine != "playwright":
            skip_or_fail("playwright engine unavailable")
        real = sp._goto_and_parse

        def goto_and_parse(url):
            try:
                return real(url)
            finally:
                finals[url] = sp._last_final_url
        sp._goto_and_parse = goto_and_parse
        try:
            sp.crawl()
        except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
            skip_or_fail(f"chromium could not launch: {exc}")
    finally:
        a.close()
    rows = {u: (t, c) for u, t, c in sqlite3.connect(str(tmp_path / "s.db")).execute(
        "SELECT url, title, content FROM discovered_pages").fetchall()}
    title, content = rows[start]
    assert title == "P-A1" and "A1-TEXT" in (content or "")
    assert "A2-TEXT" not in (content or "")
    assert finals[start] == start                         # never /p?a=2
    assert "/a1link" in a.requests and "/a2link" not in a.requests
    assert a.base + "p?a=2" not in rows
