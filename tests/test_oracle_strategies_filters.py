"""OpenRedirectFilterBypassStrategy and `browser_resolve` (CC-FUZZ-0632, FR-FUZZ-632).
The fakes reproduce VulnerableApp's measured redirect shapes (Chromium 157:
`/\\host` leaves the origin at LEVEL_2..5, `@host` at LEVEL_6, nothing at LEVEL_7)."""

from __future__ import annotations

import pytest

from fuzzlab.oracle import strategies as S
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies_filters import OpenRedirectFilterBypassStrategy, browser_resolve

PAGE = "http://127.0.0.1:3093/VulnerableApp/Redirect/LEVEL_1"


@pytest.mark.parametrize("target,host", [
    ("//evil.example/cb", "evil.example"),
    ("/\\evil.example/cb", "evil.example"),
    ("\\/evil.example/cb", "evil.example"),
    ("\\\\evil.example/cb", "evil.example"),
    ("/\t/evil.example/cb", "evil.example"),
    (" \n//evil.example/cb", "evil.example"),
    ("http://127.0.0.1:3093@evil.example/cb", "evil.example"),
    ("http:\\\\evil.example\\cb", "evil.example"),
    ("http://127.0.0.1:3093//\\evil.example/cb", "127.0.0.1"),     # LEVEL_7's shape
    ("/cb?next=\\\\evil.example", "127.0.0.1"),                   # a backslash in a query
    ("javascript:alert(1)//\\evil.example", None),
])
def test_browser_resolve_reads_a_target_as_chromium_does(target, host):
    from urllib.parse import urlsplit
    assert urlsplit(browser_resolve(PAGE, target)).hostname == host


def _cand():
    return Candidate(url=PAGE, param="returnTo", category="open-redirect")


class _App:
    def __init__(self, location):
        self.location, self.sent = location, []

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        self.sent.append(value)
        loc = self.location(value)
        return Probe(302 if loc else 200, "", headers={"Location": loc} if loc else {})


def _prefix_filter(value):
    """LEVEL_3..5: refuse http, https, www and // prefixes; else Location = value."""
    low = value.lower()
    if low.startswith(("http", "https", "www", "//")):
        return None
    return value


def test_a_prefix_filter_is_passed_with_a_backslash():
    app = _App(_prefix_filter)
    assert S.OpenRedirectStrategy().confirm(_cand(), app) is None        # the measured gap
    v = OpenRedirectFilterBypassStrategy().confirm(_cand(), app)
    assert v and v.confirmed and v.vuln_class == "open_redirect"
    assert v.evidence["variant"] == "backslash" and v.evidence["sink"] == "location-header"


def test_an_app_prefixed_origin_is_passed_with_userinfo():
    """LEVEL_6: Location = scheme://own-authority + value (no `/` between)."""
    app = _App(lambda v: "http://127.0.0.1:3093" + v)
    v = OpenRedirectFilterBypassStrategy().confirm(_cand(), app)
    assert v and v.evidence["variant"] == "userinfo"


def test_an_origin_with_a_slash_after_it_is_never_left():
    """LEVEL_7 (FP fixture): scheme://own/ + the value, one leading `/` dropped."""
    app = _App(lambda v: "http://127.0.0.1:3093/" + (v[1:] if v.startswith("/") else v))
    assert OpenRedirectFilterBypassStrategy().confirm(_cand(), app) is None
    assert len(app.sent) == len(OpenRedirectFilterBypassStrategy.VARIANTS)


def test_an_allowlist_and_an_echo_in_the_body_are_no_redirect():
    """LEVEL_8 (allowlist) and a page that only prints the value (FP fixtures)."""
    assert OpenRedirectFilterBypassStrategy().confirm(_cand(), _App(lambda v: None)) is None

    class Echo:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, f"<p>next: {value}</p>", headers={"Content-Type": "text/html"})
    assert OpenRedirectFilterBypassStrategy().confirm(_cand(), Echo()) is None


def test_a_redirect_to_another_host_carrying_the_canary_is_not_a_landing():
    app = _App(lambda v: "https://github.com/x?u=" + v)
    assert OpenRedirectFilterBypassStrategy().confirm(_cand(), app) is None


def test_it_runs_after_the_plain_canary():
    names = [type(s).__name__ for s in S.default_strategies()]
    assert names.index("OpenRedirectFilterBypassStrategy") > names.index("OpenRedirectStrategy")


def test_browser_resolve_agrees_with_chromium():
    """The evidence for `browser_resolve` (owner directive: a behaviour relied on is shown
    on a target independent of the lab): a synthetic loopback server answers each shape as
    a `Location`, and Chromium's next request's host must be the one predicted."""
    import http.server
    import threading
    from urllib.parse import quote, unquote, urlsplit

    from tests._browser import launch_browser_or_skip, require_modules
    require_modules(module_level=False)
    from playwright.sync_api import sync_playwright

    shapes = ["//evil.example/cb", "/\\evil.example/cb", "\\/evil.example/cb",
              "/\t/evil.example/cb", "\\\\evil.example/cb", "ORIGIN@evil.example/cb",
              "ORIGIN/@evil.example/cb", "ORIGIN//\\evil.example/cb",
              "http:\\\\evil.example\\cb", "/cb?next=\\\\evil.example"]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/r/"):
                self.send_response(302)
                self.send_header("Location", unquote(self.path[3:]).replace("ORIGIN", origin))
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    origin = f"http://127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                page = browser.new_page()
                seen: list[str] = []
                page.on("request", lambda r: seen.append(r.url))
                for shape in shapes:
                    seen.clear()
                    url = f"{origin}/r/" + quote(shape, safe="")
                    try:
                        page.goto(url, timeout=5000)
                    except Exception:  # noqa: BLE001 - evil.example never resolves
                        pass
                    chrome = urlsplit(seen[1]).hostname if len(seen) > 1 else None
                    ours = urlsplit(browser_resolve(url, shape.replace("ORIGIN", origin))
                                    ).hostname
                    assert chrome == ours, (shape, chrome, ours)
            finally:
                browser.close()
    finally:
        srv.shutdown()
