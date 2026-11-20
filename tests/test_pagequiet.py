"""SP-105 / FR-FUZZ-650: the M6 wait ends early only on a page that has gone quiet.

Real Chromium for every platform fact the rule rests on (timers, a request's answer,
intervals, animation frames, an early end on a static page); a fake page only for the
fail-closed edges a real browser cannot be made to show on demand (a frame without
the tracker, a read that raises)."""

from __future__ import annotations

import glob
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.tools import pagequiet
from fuzzlab.tools.pagequiet import PageQuiet

# --- real-browser pages -------------------------------------------------------------

_SINK = ("var m=location.hash.match(/[?&]q=([^&]*)/);"
         "if(m){document.getElementById('out').innerHTML=decodeURIComponent(m[1]);}")

PAGES = {
    # nothing pending after load: the wait ends early
    "/static": "<div id=out></div>",
    # the sink runs from a request's answer that takes 1.5 s
    "/fetch": ("<div id=out></div><script>fetch('/slow').then(function(){" + _SINK +
               "});</script>"),
    # the sink runs from an interval's third tick (1.5 s): an interval is never quiet
    "/interval": ("<div id=out></div><script>var n=0;setInterval(function(){"
                  "if(++n==3){" + _SINK + "}},500);</script>"),
    # an animation-frame loop that renders the sink after 1.5 s
    "/raf": ("<div id=out></div><script>var t0=performance.now();"
             "function f(){if(performance.now()-t0>1500){" + _SINK + "}else{"
             "requestAnimationFrame(f);}}requestAnimationFrame(f);</script>"),
    # a timer due long after the wait's deadline: not waited for
    "/late": "<div id=out></div><script>setTimeout(function(){}, 600000);</script>",
    # a timer chain: each task schedules the next, the sink on the fourth (1.6 s)
    "/chain": ("<div id=out></div><script>var n=0;function s(){if(++n==4){" + _SINK +
               "}else{setTimeout(s,400);}}setTimeout(s,400);</script>"),
}


def _server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            path = self.path.split("?")[0].split("#")[0]
            if path == "/slow":
                time.sleep(1.5)
                body = b"ok"
            else:
                body = ("<html><body>" + PAGES.get(path, "") + "</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def site(monkeypatch):
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])
    made: list[PageQuiet] = []

    class Recorded(PageQuiet):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            made.append(self)

    from fuzzlab.tools import browserexec
    monkeypatch.setattr(browserexec, "PageQuiet", Recorded)
    server = _server()
    yield f"http://127.0.0.1:{server.server_address[1]}", made
    server.shutdown()


def _run(base, path, *, early=True):
    """One M6 fragment observation of ``path`` with the first exec payload; returns
    whether the sentinel fired."""
    from tests._browser import skip_or_fail
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.oracle.probe import UnplaceableLocation
    from fuzzlab.oracle.strategies import _xss_exec_payloads
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor(timeout_ms=10000)
    executor.EARLY_END = early
    try:
        return executor.run(ExecRequest(url=f"{base}{path}#/s", param="q",
                                        value=_xss_exec_payloads("tok1")[0],
                                        location="fragment"), "tok1").executed
    except UnplaceableLocation as exc:
        skip_or_fail(f"chromium could not launch: {exc}")


def test_a_static_page_that_does_not_fire_ends_the_wait_early(site):
    base, made = site
    assert _run(base, "/static") is False
    assert made[-1].settled_at is not None and made[-1].reason is None


@pytest.mark.parametrize("path", ["/fetch", "/interval", "/raf", "/chain"])
def test_a_sink_run_by_pending_work_is_still_seen(site, path):
    """The sink fires 1.5 s or more after ``load``, from a request's answer, an
    interval, an animation-frame loop or a timer chain: the early end never comes
    first."""
    base, made = site
    assert _run(base, path) is True


def test_an_interval_keeps_the_whole_wait(site):
    """An interval never ends: the page is never quiet and keeps the whole
    `SETTLE_MS` (no sink here: the page reads a query the fragment URL has not)."""
    base, made = site
    PAGES["/interval-none"] = PAGES["/interval"].replace("location.hash",
                                                         "location.search")
    try:
        assert _run(base, "/interval-none") is False
    finally:
        PAGES.pop("/interval-none")
    assert made[-1].settled_at is None and made[-1].reason == "an interval"


def test_a_timer_due_after_the_deadline_is_not_waited_for(site):
    base, made = site
    assert _run(base, "/late") is False
    assert made[-1].settled_at is not None


def test_the_shadow_mode_waits_the_whole_window_and_records_the_end(site):
    """``EARLY_END = False`` (the measurement mode): the same verdict, and the time the
    early end would have come is recorded."""
    base, made = site
    assert _run(base, "/static", early=False) is False
    assert made[-1].settled_at is not None


# --- fail closed (fakes: states a real browser cannot be made to give on demand) -----

class _Error(Exception):
    pass


class _Frame:
    def __init__(self, state):
        self.state = state

    def evaluate(self, js, arg):
        if isinstance(self.state, Exception):
            raise self.state
        return self.state


class _Page:
    def __init__(self, *states):
        self.frames = [_Frame(s) for s in states]
        self.handlers: dict = {}

    def on(self, event, fn):
        self.handlers.setdefault(event, []).append(fn)


class _Context:
    def __init__(self):
        self.scripts = []

    def add_init_script(self, script):
        self.scripts.append(script)


QUIET = {"due": 0, "intervals": 0, "frames": 0, "idle": 0, "animations": 0}


def _installed(page, clock):
    q = PageQuiet(_Error, clock=clock)
    ctx = _Context()
    q.install(ctx, page)
    assert ctx.scripts == [pagequiet.TRACKER_JS]
    return q


@pytest.mark.parametrize("state,reason", [
    (None, "a frame without the tracker"),
    (_Error("Execution context was destroyed"), "a frame could not be read"),
    ({**QUIET, "due": 1}, "a timer due"),
    ({**QUIET, "intervals": 2}, "an interval"),
    ({**QUIET, "frames": 1}, "an animation frame"),
    ({**QUIET, "idle": 1}, "an idle callback"),
    ({**QUIET, "animations": 1}, "a running animation"),
    ({**QUIET, "animations": -1}, "a running animation"),     # unreadable: not quiet
])
def test_any_frame_that_is_not_quiet_keeps_the_wait(state, reason):
    now = [100.0]
    page = _Page(QUIET, state)                  # the main frame is quiet, a child not
    q = _installed(page, lambda: now[0])
    for _ in range(20):
        now[0] += 0.1
        assert q.settled(page, now[0] + 3) is False
    assert q.reason == reason


def test_a_defect_in_a_read_is_not_contained():
    """Only the Playwright error class is "not quiet" (PA-0106): a defect propagates."""
    page = _Page(TypeError("bug"))
    q = _installed(page, lambda: 1.0)
    with pytest.raises(TypeError):
        q.busy(page, 1.0)


def test_streams_workers_and_requests_keep_the_wait_and_activity_restarts_it():
    now = [100.0]
    page = _Page(QUIET)
    q = _installed(page, lambda: now[0])

    class Req:
        def __init__(self, kind):
            self.resource_type = kind

    def emit(event, *a):
        for fn in page.handlers.get(event, []):
            fn(*a)

    now[0] += 0.3
    assert q.settled(page, now[0] + 3) is False          # the quiet period starts
    now[0] += 0.3
    assert q.settled(page, now[0] + 3) is False          # quiet, not yet for 500 ms
    now[0] += 0.3
    assert q.settled(page, now[0] + 3) is True
    xhr = Req("xhr")
    emit("request", xhr)                                 # a request starts
    now[0] += 1.0
    assert q.settled(page, now[0] + 3) is False and q.reason == "a request in flight"
    emit("requestfinished", xhr)                         # its end restarts the period
    now[0] += 0.2
    assert q.settled(page, now[0] + 3) is False          # quiet again: a new period
    now[0] += 0.4
    assert q.settled(page, now[0] + 3) is False
    now[0] += 0.2
    assert q.settled(page, now[0] + 3) is True
    emit("request", Req("eventsource"))
    assert q.settled(page, now[0] + 3) is False and q.reason.startswith("a stream")

    page2 = _Page(QUIET)
    q2 = _installed(page2, lambda: now[0])
    for fn in page2.handlers["websocket"]:
        fn(object())
    assert q2.busy(page2, 3) == "a stream (WebSocket or EventSource)"
    page3 = _Page(QUIET)
    q3 = _installed(page3, lambda: now[0])
    for fn in page3.handlers["worker"]:
        fn(object())
    assert q3.busy(page3, 3) == "a worker"


def test_the_tracker_reads_the_horizon_and_counts_through_sp40():
    """The read passes the wait's remaining time (a timer due later is not waited for)
    and requests are counted by SP-40's `Inflight`, never a second counter."""
    import ast
    import inspect
    src = inspect.getsource(pagequiet)
    assert "from fuzzlab.tools.netquiet import STREAMING_TYPES, Inflight" in src
    names = {n.name for n in ast.walk(ast.parse(src))
             if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    assert not {n for n in names if "inflight" in n.lower()}
    seen = []

    class F(_Frame):
        def evaluate(self, js, arg):
            seen.append(arg)
            return QUIET

    page = _Page(QUIET)
    page.frames = [F(QUIET)]
    q = _installed(page, lambda: 10.0)
    q.busy(page, 2.5)
    assert seen == [[pagequiet.TRACKER_KEY, 2500]]


def test_the_executor_waits_through_the_tracker():
    """The M6 wait polls `PageQuiet.settled` only after ``load`` and installs the
    tracker before the first navigation (the one owner, SP-105)."""
    import inspect

    from fuzzlab.tools import browserexec
    src = inspect.getsource(browserexec.PlaywrightBrowserExecutor._in_browser)
    assert src.index("quiet.install(context, page)") < src.index("navigate(page")
    wait = inspect.getsource(browserexec.PlaywrightBrowserExecutor._wait_for_token)
    assert "load_at[0] is not None" in wait and "quiet.settled(page, deadline)" in wait
