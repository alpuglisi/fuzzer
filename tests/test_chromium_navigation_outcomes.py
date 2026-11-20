"""The raw-browser navigation facts SP-01 (`fuzzlab/tools/navguard.py`) relies on.

`navigate`, `_settle_failure`, `_error_page_loaded` and `end_failed_load` are built on
how Chromium ends a navigation that does not load: which failures raise from
``goto(wait_until="commit")``, which of them then commit Chromium's own error page
(``chrome-error://chromewebdata/``) -- and that this commit comes *after* ``goto``
raised (BUG-0522: a navigation started in between is overtaken by it) and is followed
by the error page's own ``load`` (BUG-0561: a navigation started while it still loads
can be dropped) --, and which leave the previous document in place (an
``ERR_ABORTED``: a guard's refusal, a 204). BUG-0670: the two Chromium binaries in this
container disagree on one of these -- the default headless shell (157) loads an
empty-body 4xx/5xx answer as an ordinary page, where the full Chromium (153) fails it
with ``ERR_HTTP_RESPONSE_CODE_FAILURE`` and commits its error page late.

So this module **measures**, in raw Playwright (no fuzzlab guard in the path), every
such outcome on both binaries -- ``pw.chromium.launch()`` ("shell") and
``pw.chromium.launch(channel="chromium")`` ("full") -- against a loopback server of
its own, and pins each cell as measured. A browser upgrade that changes one fails
here, naming the cell, before it silently changes what SP-01 waits for. Timings are
printed (``-s``) for citation, never asserted against a threshold; only robust facts
(the order of raise, commit and load; that an overtake happens) are asserted.
"""

from __future__ import annotations

import socket
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.core.net import require_loopback
from tests._browser import CHROMIUM_BINARIES as BINARIES
from tests._browser import free_port, skip_or_fail

ERROR_PAGE = "chrome-error://chromewebdata/"
GOTO_MS = 8000
#: how long an outcome that should commit nothing is watched for a late commit
QUIET_MS = 300
#: the most a failure's error page gets to commit and load
SETTLE_MS = 3000
REPS = 30

#: the build each per-binary expectation was measured on (printed with the results)
MEASURED_ON = {"shell": "157.0.8103.78", "full": "153.0.8010.12"}


class _Site:
    """``/empty/<status>``: that status, Content-Length 0; ``/onebyte404``: 404 with a
    1-byte body; ``/drop``: the connection closed with no response; ``/redir/<port>``:
    302 to ``http://127.0.0.1:<port>/``; ``/nocontent``: 204; ``/frame404``: a page
    whose iframe is ``/empty/404``; anything else (``/favicon.ico`` included): 200
    HTML."""

    def __init__(self):
        require_loopback("127.0.0.1")              # PA-0130

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                if body:
                    self.send_header("Content-Type", "text/html")
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self):  # http.server API
                path = self.path.split("?", 1)[0]
                if path.startswith("/empty/"):
                    return self._send(int(path.split("/")[2]))
                if path == "/onebyte404":
                    return self._send(404, b"x")
                if path == "/drop":
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return None
                if path.startswith("/redir/"):
                    port = path.split("/")[2]
                    return self._send(302, headers=[
                        ("Location", f"http://127.0.0.1:{port}/")])
                if path == "/nocontent":
                    return self._send(204)
                if path == "/blocked":                   # BUG-0672
                    return self._send(200, b"<html><body>b<script>addEventListener("
                                           b"'load',()=>setTimeout(()=>{while(true){}}"
                                           b",50))</script></body></html>")
                if path == "/frame404":
                    return self._send(200, b"<html><body><iframe src='/empty/404'>"
                                           b"</iframe></body></html>")
                return self._send(200, b"<html><body>ok</body></html>")

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._srv.daemon_threads = True
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self._srv.server_address[1]}"

    def close(self):
        self._srv.shutdown()
        self._srv.server_close()


@pytest.fixture(scope="module")
def site():
    s = _Site()
    yield s
    s.close()


@pytest.fixture(scope="module")
def pw():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    with sync_playwright() as p:
        yield p


@pytest.fixture(scope="module", params=sorted(BINARIES))
def browser(request, pw):
    try:
        b = pw.chromium.launch(headless=True, **BINARIES[request.param])
    except Exception as exc:  # noqa: BLE001 - a launch failure is no verdict
        skip_or_fail(f"chromium ({request.param}) could not launch: "
                     f"{str(exc).splitlines()[0]}")
    b.binary = request.param
    print(f"\n[{request.param}] Chromium {b.version} "
          f"(expectations measured on {MEASURED_ON[request.param]})")
    yield b
    b.close()


@pytest.fixture
def page(browser):
    p = browser.new_page()
    yield p
    p.close()


# --- the measurement ----------------------------------------------------------------
def _code(err: str | None) -> str | None:
    """``net::ERR_X`` from a ``goto`` error's first line (None: it did not raise)."""
    if err is None:
        return None
    for word in err.split():
        if word.startswith("net::ERR_"):
            return word
    return err.split(" at ")[0]


def _loaded(page, timeout_ms=SETTLE_MS) -> bool:
    try:
        page.wait_for_load_state("load", timeout=timeout_ms)
        return True
    except Exception:  # noqa: BLE001 - a timeout: not loaded
        return False


def _start(page, base):
    """A loaded document to navigate away from, with nothing of an earlier failure
    still on its way (a late error page would overtake the next navigation)."""
    page.goto(f"{base}/start", wait_until="load", timeout=GOTO_MS)
    page.wait_for_timeout(10)


def _commits_after(page, commits, since: int, *, error_page: bool) -> None:
    """Wait (bounded) for what a navigation still starts: its error page committed and
    loaded, or -- for an outcome that commits nothing -- `QUIET_MS` of quiet."""
    if not error_page:
        page.wait_for_timeout(QUIET_MS)
        return
    end = time.monotonic() + SETTLE_MS / 1000
    while time.monotonic() < end:
        if any(u == ERROR_PAGE for u, _ in commits[since:]):
            break
        page.wait_for_timeout(10)
    _loaded(page)
    page.wait_for_timeout(50)


def measure(page, base, url, route=None) -> dict:
    """One raw navigation of ``page`` to ``url`` from a loaded ``/start``: whether
    ``goto(wait_until="commit")`` raised (its ``net::`` code), the status it returned,
    the main-frame commits seen from before it started (URL, ms relative to the raise
    or return; negative: seen before it), and ``page.url`` once settled."""
    _start(page, base)
    if route is not None:
        page.route("**/*", route)
    commits: list[tuple[str, float]] = []

    def on_nav(frame):
        if frame.parent_frame is None:
            commits.append((frame.url, time.monotonic()))

    page.on("framenavigated", on_nav)
    err = status = None
    try:
        resp = page.goto(url, wait_until="commit", timeout=GOTO_MS)
        status = resp.status if resp is not None else None
    except Exception as exc:  # noqa: BLE001 - the outcome measured
        err = str(exc).splitlines()[0]
    t_end = time.monotonic()
    code = _code(err)
    _commits_after(page, commits, 0,
                   error_page=code is not None and code != "net::ERR_ABORTED")
    if status is not None:
        _loaded(page)
    page.remove_listener("framenavigated", on_nav)
    if route is not None:
        page.unroute("**/*")
    return {"code": code, "status": status,
            "commits": [(u, round((t - t_end) * 1000, 1)) for u, t in commits],
            "final": page.url}


def _nav_only(action):
    """A route handler that applies ``action`` to the navigation request only (the
    favicon and any subresource pass)."""
    def handler(route):
        if route.request.is_navigation_request():
            action(route)
        else:
            route.continue_()
    return handler


FETCH_RAISED: list[str] = []


def _fetch_route(route):
    """SP-01's route shape: the response fetched by Playwright and fulfilled; a fetch
    that raises is aborted with ``"aborted"``, as `navguard` aborts a document."""
    try:
        resp = route.fetch(max_redirects=0)
    except Exception as exc:  # noqa: BLE001 - the outcome measured
        FETCH_RAISED.append(str(exc).splitlines()[0])
        route.abort("aborted")
        return
    route.fulfill(response=resp)


def _show(binary, label, m):
    print(f"  [{binary}] {label}: code={m['code']} status={m['status']} "
          f"commits={m['commits']} final={m['final']}")


def _assert_error_page(m, code):
    """Raised ``code``, then committed the error page -- once, as the only commit --,
    which is where the page is left."""
    assert m["code"] == code, m
    assert [u for u, _ in m["commits"]] == [ERROR_PAGE], m
    assert m["final"] == ERROR_PAGE, m


def _assert_kept(m, base):
    """Raised ERR_ABORTED, committed nothing: the previous document is kept."""
    assert m["code"] == "net::ERR_ABORTED", m
    assert m["commits"] == [], m
    assert m["final"] == f"{base}/start", m


def _assert_page(m, url, status):
    """Did not raise: ``status`` returned, ``url`` committed and kept."""
    assert m["code"] is None and m["status"] == status, m
    assert [u for u, _ in m["commits"]] == [url], m
    assert m["final"] == url, m


# --- 1, 2: a route's abort ------------------------------------------------------------
def test_abort_aborted_keeps_the_document(page, site, browser):
    m = measure(page, site.base, f"{site.base}/x",
                _nav_only(lambda r: r.abort("aborted")))
    _show(browser.binary, "abort('aborted')", m)
    _assert_kept(m, site.base)


@pytest.mark.parametrize("abort_code,net", [("failed", "net::ERR_FAILED"),
                                            ("blockedbyclient",
                                             "net::ERR_BLOCKED_BY_CLIENT")])
def test_abort_with_an_error_commits_the_error_page(page, site, browser, abort_code,
                                                    net):
    m = measure(page, site.base, f"{site.base}/x",
                _nav_only(lambda r: r.abort(abort_code)))
    _show(browser.binary, f"abort({abort_code!r})", m)
    _assert_error_page(m, net)


# --- 3, 6: a refused host, directly and as a redirect's target ------------------------
@pytest.mark.parametrize("via", ["direct", "redirect"])
@pytest.mark.parametrize("host", ["unsafe-port", "closed-port"])
def test_a_refused_host_commits_the_error_page(page, site, browser, via, host):
    port = 1 if host == "unsafe-port" else free_port()
    url = (f"http://127.0.0.1:{port}/" if via == "direct"
           else f"{site.base}/redir/{port}")
    m = measure(page, site.base, url)
    _show(browser.binary, f"{host} {via}", m)
    _assert_error_page(m, "net::ERR_UNSAFE_PORT" if port == 1
                       else "net::ERR_CONNECTION_REFUSED")


# --- 4: empty-body HTTP answers (BUG-0670) ------------------------------------------
#: binary -> (status, body bytes) -> "error-page" | "page", as measured
EMPTY_BODY = {
    "shell": {(399, 0): "page", (400, 0): "page", (404, 0): "page", (500, 0): "page",
              (599, 0): "page", (404, 1): "page"},
    "full": {(399, 0): "page", (400, 0): "error-page", (404, 0): "error-page",
             (500, 0): "error-page", (599, 0): "error-page", (404, 1): "page"},
}


def _behaviour(m, url, status) -> str:
    """Which of the two known behaviours an empty-body answer had, or a description of
    a third one."""
    if (m["code"] == "net::ERR_HTTP_RESPONSE_CODE_FAILURE" and m["status"] is None
            and [u for u, _ in m["commits"]] == [ERROR_PAGE] and m["final"] == ERROR_PAGE):
        return "error-page"
    if (m["code"] is None and m["status"] == status
            and [u for u, _ in m["commits"]] == [url] and m["final"] == url):
        return "page"
    return f"other: {m}"


@pytest.mark.parametrize("via", ["direct", "fetch-route"])
@pytest.mark.parametrize("status,size", sorted(EMPTY_BODY["full"]))
def test_an_empty_body_answer(page, site, browser, via, status, size):
    url = (f"{site.base}/onebyte404" if size else f"{site.base}/empty/{status}")
    m = measure(page, site.base, url, _fetch_route if via == "fetch-route" else None)
    _show(browser.binary, f"{status} body={size} {via}", m)
    got = _behaviour(m, url, status)
    assert got in ("error-page", "page"), f"a third behaviour: {got}"
    assert got == EMPTY_BODY[browser.binary][(status, size)], m
    if got == "error-page":                         # committed after goto raised
        assert m["commits"][0][1] > -50, m


# --- 5: the connection closed with no response ----------------------------------------
def test_a_dropped_connection(page, site, browser):
    m = measure(page, site.base, f"{site.base}/drop")
    _show(browser.binary, "drop direct", m)
    _assert_error_page(m, "net::ERR_EMPTY_RESPONSE")
    FETCH_RAISED.clear()
    m = measure(page, site.base, f"{site.base}/drop", _fetch_route)
    _show(browser.binary, f"drop fetch-route (fetch raised: {FETCH_RAISED})", m)
    assert FETCH_RAISED and FETCH_RAISED[0].startswith("Route.fetch:"), FETCH_RAISED
    _assert_kept(m, site.base)                      # the route aborted it: "aborted"


# --- 9: 204 No Content ----------------------------------------------------------------
def test_a_204_keeps_the_document(page, site, browser):
    m = measure(page, site.base, f"{site.base}/nocontent")
    _show(browser.binary, "204", m)
    _assert_kept(m, site.base)


# --- 7: an iframe whose src is an empty-body 404 ----------------------------------------
#: binary -> what the iframe shows, as measured: on both, the empty 404 as its (empty)
#: document -- the full binary's ERR_HTTP_RESPONSE_CODE_FAILURE is a main-frame rule
FRAME_404 = {"shell": "page", "full": "page"}


def test_an_iframe_of_an_empty_404(page, site, browser):
    commits: list[str] = []
    page.on("framenavigated",
            lambda f: f.parent_frame is not None and commits.append(f.url))
    page.goto(f"{site.base}/frame404", wait_until="load", timeout=GOTO_MS)
    page.wait_for_timeout(QUIET_MS)
    child = page.frames[1]
    try:
        href, body = child.evaluate("[location.href, document.documentElement.outerHTML]")
    except Exception as exc:  # noqa: BLE001 - recorded
        href, body = f"<evaluate failed: {str(exc).splitlines()[0]}>", None
    print(f"  [{browser.binary}] iframe /empty/404: commits={commits} "
          f"frame.url={child.url} location.href={href} html={body!r}")
    url = f"{site.base}/empty/404"
    assert commits == [url] and child.url == url, (commits, child.url)
    got = "error-page" if href == ERROR_PAGE else "page" if href == url else href
    assert got in ("error-page", "page"), f"a third behaviour: {got}"
    assert got == FRAME_404[browser.binary], (commits, child.url, href)
    if got == "page":                               # nothing of an error page in it
        assert body == "<html><head></head><body></body></html>", body


# --- 8: the error page's timing, and the overtake it causes (BUG-0522, BUG-0561) -------
FAILURES = {"network-error": ("/drop", None),
            "abort-failed": ("/x", lambda r: r.abort("failed"))}


def _fail(page, base, kind):
    """Start a failing navigation of ``kind``; return its raise's monotonic time."""
    path, action = FAILURES[kind]
    if action is not None:
        page.route(f"{base}{path}", action)
    try:
        page.goto(f"{base}{path}", wait_until="commit", timeout=GOTO_MS)
    except Exception as exc:  # noqa: BLE001 - the failure measured
        assert "net::ERR_" in str(exc), exc
        return time.monotonic()
    raise AssertionError(f"{kind}: goto did not raise")


def _stats(xs):
    xs = sorted(xs)
    p95 = xs[min(len(xs) - 1, round(0.95 * (len(xs) - 1)))]
    return (f"n={len(xs)} min={xs[0]:.1f} p50={statistics.median(xs):.1f} "
            f"p95={p95:.1f} max={xs[-1]:.1f} ms")


@pytest.mark.parametrize("kind", sorted(FAILURES))
def test_the_error_page_commits_after_the_raise_then_loads(page, site, browser, kind):
    """Over `REPS` failures: the error page's commit comes after ``goto`` raised (at
    least sometimes -- what BUG-0522's wait is for) and it then fires its own ``load``
    every time (what BUG-0561's wait is for). The gaps are printed, not asserted."""
    to_commit, to_load = [], []
    for _ in range(REPS):
        _start(page, site.base)
        commits, loads = [], []
        on_nav = (lambda f, c=commits: f.parent_frame is None
                  and c.append((f.url, time.monotonic())))
        on_load = (lambda _p, ls=loads: ls.append(time.monotonic()))
        page.on("framenavigated", on_nav)
        page.on("load", on_load)
        t_raise = _fail(page, site.base, kind)
        end = time.monotonic() + SETTLE_MS / 1000
        while time.monotonic() < end and not any(u == ERROR_PAGE for u, _ in commits):
            page.wait_for_timeout(1)
        error_commits = [t for u, t in commits if u == ERROR_PAGE]
        assert len(error_commits) == 1 and len(commits) == 1, commits
        t_commit = error_commits[0]
        assert _loaded(page), "the error page never loaded"
        while time.monotonic() < end and not [t for t in loads if t >= t_commit]:
            page.wait_for_timeout(1)
        after = [t for t in loads if t >= t_commit]
        assert after, (f"no load event after the error page's commit "
                       f"(loads={loads}, commit={t_commit})")
        to_commit.append((t_commit - t_raise) * 1000)
        to_load.append((after[0] - t_commit) * 1000)
        page.remove_listener("framenavigated", on_nav)
        page.remove_listener("load", on_load)
        page.unroute_all()
    print(f"  [{browser.binary}] {kind}: raise -> error-page commit: "
          f"{_stats(to_commit)}; negative (commit seen before the raise): "
          f"{sum(x < 0 for x in to_commit)}/{REPS}")
    print(f"  [{browser.binary}] {kind}: commit -> error-page load: {_stats(to_load)}")
    assert any(x > 0 for x in to_commit), to_commit


@pytest.mark.parametrize("kind", sorted(FAILURES))
def test_a_navigation_right_after_the_raise_can_be_overtaken(page, site, browser, kind):
    """A navigation started as soon as a failed ``goto`` raised -- before its error
    page committed -- is, at least sometimes over `REPS` tries, interrupted by that
    error page (BUG-0522); and an overtaken navigation still lands afterwards: it
    commits after the error page, and loads (what `_settle_failure`'s "overtaken" kind
    waits for). Rates and every other outcome are printed."""
    outcomes: dict[str, int] = {}
    late: dict[str, int] = {}
    landed: list[list[str]] = []
    nxt = f"{site.base}/next"
    for _ in range(REPS):
        _start(page, site.base)
        commits: list[str] = []
        on_nav = (lambda f, c=commits: f.parent_frame is None and c.append(f.url))
        page.on("framenavigated", on_nav)
        _fail(page, site.base, kind)
        try:
            page.goto(nxt, wait_until="commit", timeout=SETTLE_MS)
            got = "landed" if page.url == nxt else f"landed:{page.url}"
        except Exception as exc:  # noqa: BLE001 - the outcome measured
            first = str(exc).splitlines()[0]
            if f'interrupted by another navigation to "{ERROR_PAGE}' in first:
                got = "overtaken"
            elif "Timeout" in first:
                got = "timeout"
            else:
                got = f"other:{_code(first)}"
        outcomes[got] = outcomes.get(got, 0) + 1
        # what is still on its way lands before the next rep: the error page, and the
        # overtaken navigation's own late commit
        end = time.monotonic() + SETTLE_MS / 1000
        while time.monotonic() < end and nxt not in commits:
            page.wait_for_timeout(5)
        if got == "overtaken":
            at = commits.index(ERROR_PAGE) if ERROR_PAGE in commits else None
            how = ("lands after the error page" if at is not None
                   and nxt in commits[at + 1:] else f"commits={commits}")
            if how.startswith("lands") and not _loaded(page):
                how = "commits after the error page, never loads"
            late[how] = late.get(how, 0) + 1
        elif got == "landed":
            landed.append([u.replace(site.base, "") for u in commits])
        _loaded(page)
        page.wait_for_timeout(20)
        page.remove_listener("framenavigated", on_nav)
        page.unroute_all()
    print(f"  [{browser.binary}] {kind}: navigation right after the raise: "
          f"{dict(sorted(outcomes.items()))} over {REPS}; after an overtake: {late}; "
          f"commits of each that landed: {landed}")
    assert outcomes.get("overtaken", 0) >= 1, outcomes
    assert set(late) == {"lands after the error page"}, late


# --- BUG-0672: what a page whose main thread is blocked still answers ---------------
def test_a_blocked_main_thread_answers_only_the_browsers_own_calls(browser, site):
    """A page in ``while(true){}``: freezing its scripts
    (``Emulation.setScriptExecutionDisabled``) and adding a context route are not
    answered (each bounded here by `navguard._bounded`; unbounded they never return),
    while ``Page.stopLoading``, a driver timer and closing the page are, on both
    binaries -- what `navguard.close_pages` relies on to stay bounded."""
    from fuzzlab.tools import navguard
    ctx = browser.new_context()
    try:
        page = ctx.new_page()
        page.goto(site.base + "/blocked", wait_until="load")
        page.wait_for_timeout(300)
        cdp = ctx.new_cdp_session(page)
        freeze = navguard._bounded(
            cdp, lambda: None,
            lambda impl, _w: impl.send(method="Emulation.setScriptExecutionDisabled",
                                       params={"value": True}), page, 1500)
        route = navguard._bounded(
            ctx, lambda: None,
            lambda impl, wrap: impl.route(url="**/*", handler=wrap(lambda r: r.abort())),
            page, 1500)
        t = time.monotonic()
        cdp.send("Page.stopLoading")
        page.wait_for_timeout(50)
        answered_ms = (time.monotonic() - t) * 1000
        t = time.monotonic()
        page.close()
        close_ms = (time.monotonic() - t) * 1000
        print(f"[{browser.binary}] blocked: freeze answered={freeze} route answered="
              f"{route} stopLoading+timer {answered_ms:.0f} ms close {close_ms:.0f} ms")
        assert (freeze, route) == (False, False)
        assert answered_ms < 1500 and close_ms < 5000
    finally:
        ctx.close()
