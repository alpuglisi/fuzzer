"""The disco harvest (BUG-0505, PA-0505, FR-CRAWL-27).

Script routes: the routes and route-query seeds an app's scripts declare are read with
the spider's own scanner (`tools.spa.scan_script`, SP-47) and loaded first; the e2e
test runs it in a real browser, the guard here keeps it one scanner for both crawlers.

Document aliases: an HTML body already
loaded at another path is an alias -- the same app under another address (an SPA
server's catch-all answering ``/sitemap.xml`` with the shell, a soft 404) -- and is not
explored again, *unless* it renders a view of its own (a history-mode route served from
the same shell). Measured on Juice Shop (2026-10-19): ``/sitemap.xml`` answered with the
shell, every state was explored again under it, and its finding came out twice.

Fakes stand in for the driver's page and response; `tests/test_disco_e2e.py` runs the
same rules in a real browser."""

from __future__ import annotations

from fuzzlab.disco.explore import Explorer
from fuzzlab.disco.fingerprint import state_fingerprint

START = "http://127.0.0.1:3000/"
SHELL = b"<!doctype html><div id=root></div><script src=/app.js></script>"


class _Resp:
    def __init__(self, body: bytes):
        self._body = body

    def body(self) -> bytes:
        return self._body


class _Page:
    def __init__(self, url: str, hrefs=()):
        self.url = url
        self._hrefs = list(hrefs)

    def eval_on_selector_all(self, _sel, _js):
        return self._hrefs


def _explorer() -> Explorer:
    ex = Explorer(START, scope_urls=[START], proxy="http://127.0.0.1:9")
    ex._document_first(_Resp(SHELL), START)              # the start document
    return ex


HOME = [{"tag": "a", "label": "Home", "href": "/"}, {"tag": "button", "label": "Go"}]
ABOUT = [{"tag": "h1", "label": "About"}, {"tag": "button", "label": "Contact us"}]


def test_a_new_body_or_the_same_path_is_never_an_alias():
    ex = _explorer()
    assert ex._document_first(_Resp(b"<p>other</p>"), START + "help") is None
    assert ex._document_first(_Resp(SHELL), START + "?x=1") is None     # same path


def test_the_shell_under_another_path_of_a_hash_routed_app_is_an_alias():
    ex = _explorer()
    first = ex._document_first(_Resp(SHELL), START + "sitemap.xml")
    assert first == "/"
    # Juice Shop's router lands on ``/sitemap.xml#/``; an app that does not redirect
    # shows its hash routing in its links
    assert ex._alias_state(_Page(START + "sitemap.xml#/"), first, None)
    assert ex._alias_state(_Page(START + "sitemap.xml", ["http://127.0.0.1:3000/#/"]),
                           first, None)


def test_a_history_mode_route_from_the_same_shell_is_explored():
    """The regression a body-only rule would cause: every history-mode route answers
    with the shell, and its view is new."""
    ex = _explorer()
    ex._shared.known.add(state_fingerprint(START, HOME))
    first = ex._document_first(_Resp(SHELL), START + "about")
    page = _Page(START + "about", [START + "about", START + "contact"])
    assert first == "/"
    assert not ex._alias_state(page, first, ("fp", ABOUT))
    assert not ex._alias_state(page, first, None)          # nothing read: explored


def test_a_soft_404_rendering_a_known_state_is_an_alias():
    ex = _explorer()
    ex._shared.known.add(state_fingerprint(START, HOME))
    first = ex._document_first(_Resp(SHELL), START + "no/such/page")
    assert ex._alias_state(_Page(START + "no/such/page"), first, ("fp", HOME))


def test_the_explorer_counts_an_alias_and_explores_no_state_from_it(monkeypatch):
    """`_load` end to end on fakes: an alias adds no frontier state and is counted."""
    from fuzzlab.disco import explore
    ex = _explorer()

    class _Nav:
        response = type("R", (), {"headers": {"content-type": "text/html"},
                                   "body": lambda self: SHELL})()

    monkeypatch.setattr(explore.navguard, "navigate", lambda *a, **k: _Nav())
    monkeypatch.setattr(ex, "wait_quiet", lambda page: None)
    monkeypatch.setattr(ex, "_tag", lambda ctx, kind: None)
    monkeypatch.setattr(ex, "settled_fingerprint", lambda page, ctx: ("fp1", HOME))
    gathered = []
    monkeypatch.setattr(ex, "_gather", lambda page: gathered.append(page.url))
    page = _Page(START + "sitemap.xml#/")
    assert ex._load(START + "sitemap.xml", page) is page
    assert ex.report.harvest_aliases == 1 and ex.report.harvest_states == 0
    assert "fp1" not in ex._shared.known and gathered == []


# --- script routes ----------------------------------------------------------------------
APP_JS = ("const routes = [{path: 'search'}, {path: 'track-result'}, {path: 'product/:id'},"
          " {path: 'delete-account'}];"
          "this.router.navigate(['/track-result'], {queryParams: {id: t}});")


def test_a_scripts_routes_and_seeds_follow_the_pages_routing_mode():
    """Hash mode when the page or one of its links routes by fragment, else history
    mode; a parameterised or destructive route is left out (`classify_route`)."""
    ex = _explorer()
    hashed = ex._script_routes(APP_JS, _Page(START + "#/"))
    assert hashed == [START + "#/search", START + "#/track-result",
                      START + "#/track-result?id=fuzzlab"]
    linked = ex._script_routes(APP_JS, _Page(START, [START + "#/about"]))
    assert linked == hashed
    history = ex._script_routes(APP_JS, _Page(START))
    assert history[:2] == [START + "search", START + "track-result"]
    assert (ex.report.script_routes, ex.report.script_route_seeds) == (6, 3)


def test_a_script_too_large_to_scan_is_counted_not_fatal():
    from fuzzlab.tools.spa import MAX_SCRIPT_BYTES
    ex = _explorer()
    assert ex._script_routes("x" * (MAX_SCRIPT_BYTES + 1), _Page(START)) == []
    assert ex.report.scripts_too_large == 1


# --- SP-47: one route scanner for both crawlers ----------------------------------------
def _scan_script_calls(tree) -> int:
    import ast
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Call)
               and getattr(n.func, "attr", getattr(n.func, "id", None)) == "scan_script")


def test_both_crawlers_read_an_apps_routes_through_the_one_scanner():
    """BUG-0505: disco had no route scanner while the spider had one, and missed every
    route only a script declares. Each crawler calls `spa.scan_script`."""
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "fuzzlab"
    for rel in ("tools/spider.py", "disco/explore.py"):
        assert _scan_script_calls(ast.parse((root / rel).read_text())) >= 1, rel


def test_the_scanner_guard_flags_a_crawler_without_it():
    import ast
    assert _scan_script_calls(ast.parse("routes = re.findall(r'path:', text)")) == 0
    assert _scan_script_calls(ast.parse("got = spa.scan_script(text)")) == 1


# --- BUG-0522: harvest loads and restores after failed loads (a real browser) -----------
class _FailingSite:
    """``/missing<..>``: 404 with an empty body (Chromium commits its own error page);
    any other path: a small page."""

    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")              # PA-0130

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                if self.path.startswith("/missing"):
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"<html><body><a href='/x'>x</a><button>b</button></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


import pytest  # noqa: E402


@pytest.mark.parametrize("failures", [1, 2])
def test_disco_harvest_and_restore_after_failed_loads(failures, monkeypatch):
    """BUG-0522 in disco's real paths: harvest loads of empty error answers (`_load`
    catches each failure and goes on with the same page), then the next harvest load
    counts no error, and a `restore` (its about:blank, then its entry URL) lands -- its
    fingerprint check stubbed, so only its navigations are judged. Before: the late
    error page overtook them (C0: 13-17/20 lost)."""
    from playwright.sync_api import sync_playwright

    from fuzzlab.disco.explore import ExploreOptions, State
    from fuzzlab.tools import navguard
    from tests._browser import skip_or_fail
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    site = _FailingSite()
    try:
        ex = Explorer(site.base, scope_urls=[site.base], proxy="http://127.0.0.1:9",
                      options=ExploreOptions(idle_ms=100, max_quiet_ms=2000))
        ex.reproduces = lambda *a, **k: True
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**navguard.chromium_launch_kwargs(
                    navguard.browser_launch_args([site.base])))
            except Exception as exc:  # noqa: BLE001 - a launch failure is no verdict
                skip_or_fail(f"chromium could not launch: {exc}")
            ex._ctx = ex._new_context(browser, pw)
            page = ex._ctx.new_page()
            try:
                for i in range(4):
                    for j in range(failures):
                        ex._load(f"{site.base}missing{i}_{j}", page)
                    before = ex.report.errors
                    ex._load(f"{site.base}ok{i}", page)
                    assert ex.report.errors == before, f"rep {i}: the harvest load failed"
                    for j in range(failures):
                        ex._load(f"{site.base}missing{i}_r{j}", page)
                    assert ex.restore(page, ex._ctx, State(
                        "x", f"{site.base}ok{i}", f"{site.base}ok{i}")), f"rep {i}: restore"
            finally:
                navguard.release(ex._ctx)
                browser.close()
    finally:
        site.close()
