"""BUG-0650 / PA-0650: the M6 executor's full observation window sees late sinks.

`fuzzlab.tools.browserexec.PlaywrightBrowserExecutor` waits up to ``SETTLE_MS`` after
``load`` for the sentinel. A withdrawn change (the quiet-settle early end, FR-FUZZ-650)
ended that wait once a timer/network tracker judged the page "quiet", and an
independent verifier found it missed sinks that fire late through mechanisms such a
tracker cannot see. Each case below is one such late-firing sink mechanism, served by a
loopback page and run through the real executor in real Chromium; the full window must
keep seeing every one of them (and never the escaping ``textContent`` twin). Each case
fires about 1.0-3.2 s after ``load``, inside the 4 s window; a 300 ms window misses it,
which proves the fixture really is late.

Under ``FUZZLAB_REQUIRE_BROWSER=1`` these fail rather than skip.
"""

from __future__ import annotations

import base64
import importlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.oracle.browser import ExecRequest, NotObserved
from fuzzlab.oracle.probe import UnplaceableLocation
from fuzzlab.oracle.strategies import _xss_exec_payloads
from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor

#: The DOM sink of `tests/test_browser_scope.py::_ASYNC_SINK`, as a function ``S``;
#: ``%s`` is ``innerHTML`` (the sink) or ``textContent`` (the safe twin).
_HEAD = ("<html><head><meta charset=utf-8></head><body><div id=out></div><script>"
         "function S(){var m=location.hash.match(/[?&]q=([^&]*)/);"
         "if(m){document.getElementById('out').%s=decodeURIComponent(m[1]);}}"
         "</script>")

#: path -> the page body after `_HEAD`: each runs ``S`` late, by its own mechanism.
_CASES = {
    # 1. SVG animation events (SMIL): not a timer, not a network request
    "svg-set-onend": (
        "<svg width=20 height=20><rect width=10 height=10>"
        "<set attributeName=width to=20 dur=1s onend='S()'/></rect></svg>"),
    "svg-animate-onend": (
        "<svg width=20 height=20><rect width=10 height=10>"
        "<animate attributeName=x from=0 to=5 dur=1s onend='S()'/></rect></svg>"),
    "svg-animate-onbegin": (
        "<svg width=20 height=20><rect width=10 height=10>"
        "<animate attributeName=x from=0 to=5 begin=1s dur=1s onbegin='S()'/>"
        "</rect></svg>"),
    # 2. the Prioritized Task Scheduling API's delayed task
    "post-task": (
        "<script>addEventListener('load',function(){"
        "scheduler.postTask(S,{delay:1000});});</script>"),
    # 3. a MessageChannel task chain: always a task pending, never a timer
    "message-channel": (
        "<script>addEventListener('load',function(){"
        "var c=new MessageChannel(),t0=performance.now();"
        "c.port1.onmessage=function(){if(performance.now()-t0<1000){"
        "c.port2.postMessage(0);}else{S();}};c.port2.postMessage(0);});</script>"),
    # 4. a window.postMessage loop
    "post-message": (
        "<script>addEventListener('load',function(){var t0=performance.now();"
        "addEventListener('message',function(e){if(e.data!=='k')return;"
        "if(performance.now()-t0<1000){postMessage('k','*');}else{S();}});"
        "postMessage('k','*');});</script>"),
    # 5. a meta refresh to a page that sinks at once, carrying the same fragment
    "meta-refresh": (
        "<script>document.write('<meta http-equiv=\"refresh\" content=\"1;url='"
        "+location.pathname.replace(/meta-refresh$/,'refreshed')"
        "+location.hash.replace(/\"/g,'%22')+'\">');</script>"),
    # 6. a media element event: a muted, autoplayed 1 s video's ``ended``. Measured in
    #    this Chromium (Playwright 1.63, its Chromium build 1243, headless): an ``<audio>`` -- muted
    #    or not, ``autoplay`` or a script ``play()`` -- never starts (``play()`` rejects
    #    with NotAllowedError, ``paused`` stays true at readyState 4), so its ``ended`` /
    #    ``timeupdate`` never fire; a muted ``<video autoplay>`` plays and ``ended``
    #    fires about 1.0-1.1 s after load. Hence a video, not audio.
    "media-ended": "<video muted autoplay playsinline src='/clip.webm' onended='S()'></video>",
    # 7. a fetch the server answers after 3.0 s
    "slow-fetch": (
        "<script>addEventListener('load',function(){"
        "fetch('/slow').then(function(r){return r.text();}).then(S);});</script>"),
    # 8. a timer, then the clocks/iterators a tracker might use are made to throw
    "hostile-globals": (
        "<script>setTimeout(S,1000);"
        "performance.now=function(){throw new Error('no clock');};"
        "Map.prototype[Symbol.iterator]=function(){throw new Error('no iterator');};"
        "</script>"),
}

#: A page whose main thread is blocked for 6 s after ``load``.
_BLOCKED = ("<script>addEventListener('load',function(){var t0=Date.now();"
            "while(Date.now()<t0+6000){}});</script>")

#: The fetch delay of the ``/slow`` endpoint (case 7).
SLOW_S = 3.0


#: A 1 s, 16x16, 5 fps black VP8 WebM (623 bytes; made with ``ffmpeg -f lavfi -i
#: color=c=black:s=16x16:r=5 -t 1 -c:v libvpx -b:v 10k``), for case 6.
_CLIP = base64.b64decode(
    "GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQJChYECGFOAZwEAAAAAAAI/EU2bdLpNu4tTq4QV"
    "SalmU6yBoU27i1OrhBZUrmtTrIHYTbuMU6uEElTDZ1OsggEeTbuMU6uEHFO7a1OsggIp7AEAAAAAAABZ"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVSalmsirXsYMPQkBNgI1MYXZmNjAuMTYuMTAwV0GN"
    "TGF2ZjYwLjE2LjEwMESJiECPQAAAAAAAFlSua8GuAQAAAAAAADjXgQFzxYh1h0DU4V6cfJyBACK1nIN1"
    "bmSIgQCGhVZfVlA4g4EBI+ODhAvrwgDgibCBELqBEJqBAhJUw2f8c3OgY8CAZ8iaRaOHRU5DT0RFUkSH"
    "jUxhdmY2MC4xNi4xMDBzc9ZjwItjxYh1h0DU4V6cfGfIoUWjh0VOQ09ERVJEh5RMYXZjNjAuMzEuMTAy"
    "IGxpYnZweGfIoUWjiERVUkFUSU9ORIeTMDA6MDA6MDEuMDAwMDAwMDAwAB9DtnVAhOeBAKOjgQAAgBAC"
    "AJ0BKhAAEAAARwiFhYiFhIgCAgAMDWAA/v+rUICjlYEAyACxAQABEBAAGAAYWC/0AAgAAKOVgQGQALEB"
    "AAEQEAAYABhYL/QACAAAo5WBAlgAsQEAARAQABgAGFgv9AAIAACjlYEDIACxAQABEBAAGAAYWC/0AAgA"
    "ABxTu2uRu4+zgQC3iveBAfGCAZ/wgQM=")


def _app():
    class Handler(BaseHTTPRequestHandler):
        def _send(self, body: bytes, ctype: str):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass                    # the visit ended before a slow answer came

        def do_GET(self):  # noqa: N802 - http.server API
            path = self.path.split("#", 1)[0].split("?", 1)[0]
            if path == "/clip.webm":
                return self._send(_CLIP, "video/webm")
            if path == "/slow":
                time.sleep(SLOW_S)
                return self._send(b"ok", "text/plain")
            safe = path.startswith("/safe/")
            name = path[len("/safe/"):] if safe else path.lstrip("/")
            sink = "textContent" if safe else "innerHTML"
            if name == "refreshed":
                body = "<script>S();</script>"
            elif name == "blocked":
                body = _BLOCKED
            elif name in _CASES:
                body = _CASES[name]
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(((_HEAD % sink) + body + "</body></html>").encode(),
                       "text/html")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _chromium_or_skip(monkeypatch):
    from tests._browser import skip_or_fail
    try:
        importlib.import_module("playwright.sync_api")
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    # the product's binary (the operator's PLAYWRIGHT_CHROMIUM_EXECUTABLE, else
    # Playwright's default), never one chosen by install path (BUG-0671, PA-0671)


@pytest.fixture
def base(monkeypatch):
    _chromium_or_skip(monkeypatch)
    server = _app()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _request(base: str, path: str) -> ExecRequest:
    return ExecRequest(url=f"{base}{path}#/s", param="q",
                       value=_xss_exec_payloads("tok1")[0], location="fragment")


def _executed(base: str, path: str, executor=None) -> bool:
    from tests._browser import skip_or_fail
    executor = executor or PlaywrightBrowserExecutor(timeout_ms=10000)
    try:
        return executor.run(_request(base, path), "tok1").executed
    except UnplaceableLocation as exc:
        skip_or_fail(f"chromium could not launch: {exc}")


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_full_window_sees_a_late_sink(base, case):
    """The sink fires about 1-3 s after ``load`` by ``case``'s mechanism: the full
    window confirms it."""
    assert _executed(base, f"/{case}") is True


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_escaping_twin_never_executes(base, case):
    """The same page writing ``textContent``: the payload never runs."""
    assert _executed(base, f"/safe/{case}") is False


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_fixture_really_is_late(base, case):
    """A 300 ms window (BUG-0126's fixed wait) misses each case: it fires late."""
    early = PlaywrightBrowserExecutor(timeout_ms=10000)
    early.SETTLE_MS = 300
    assert _executed(base, f"/{case}", early) is False


def test_a_blocked_main_thread_ends_the_run(base):
    """A page whose main thread spins for 6 s after ``load``: ``run`` ends -- an
    observation or the no-verdict signal -- and never hangs."""
    outcome: dict = {}

    def visit():
        try:
            outcome["obs"] = PlaywrightBrowserExecutor(timeout_ms=10000).run(
                _request(base, "/blocked"), "tok1")
        except BaseException as exc:  # noqa: BLE001 - classified below
            outcome["exc"] = exc

    worker = threading.Thread(target=visit, daemon=True)
    worker.start()
    worker.join(60)
    if worker.is_alive():
        pytest.fail("run() on a page with a blocked main thread did not end in 60 s")
    exc = outcome.get("exc")
    if exc is not None and not isinstance(exc, (NotObserved, UnplaceableLocation)):
        raise exc
    if "obs" in outcome:
        assert outcome["obs"].executed is False         # the page never sinks
