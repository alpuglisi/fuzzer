"""BUG-0139 / PA-0139: the M6 sentinel payloads are never all one quoting shape.

Every M6 payload called ``__fzlbHit('TOKEN')`` with single quotes. Juice Shop's
``GET /rest/track-order/:id`` evaluates the id inside a single-quoted string (a
MongoDB-style ``$where``): a ``'`` answers 500, so nothing is echoed and nothing
renders. Its ``#/track-result?id=`` DOM XSS, a true positive, was therefore checked
and never confirmed. Two payloads now carry the call without a single quote: one
with backticks, one with no quote character at all (``/TOKEN/.source``).

The fixture here is that data path, on loopback: a hash-route page that fetches
``/rest/track-order/<id>``. The server answers 500 on a ``'`` in the id, else echoes
the id as JSON, and the page writes it with ``innerHTML``.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from fuzzlab.core.net import require_loopback
from fuzzlab.oracle.browser import SENTINEL
from fuzzlab.oracle.strategies import _xss_exec_payloads
from tests.test_navigation_aborts import _chromium_or_skip

_RENDER_JS = """
const p = new URLSearchParams(location.hash.split('?')[1] || '');
const id = p.get('id');
if (id !== null) fetch('/rest/track-order/' + encodeURIComponent(id))
  .then(r => r.ok ? r.json() : null)
  .then(j => { if (j) document.getElementById('out').%s = j.data[0].orderId; });
"""


def _page(sink):
    return (f"<html><body><div id='out'></div><script>{_RENDER_JS % sink}</script>"
            f"</body></html>").encode()


class _TrackApp:
    """``/`` renders the echoed id with ``innerHTML``; ``/escaped`` with
    ``textContent``; ``/rest/track-order/<id>`` evaluates the id in a single-quoted
    string (500 on a ``'``); ``/json?q=`` is a JSON document echoing ``q``."""

    def __init__(self):
        require_loopback("127.0.0.1")                  # PA-0130
        self.track_requests: list[str] = []
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, ctype, body):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - http.server API
                parts = urlsplit(self.path)
                if parts.path == "/":
                    return self._send(200, "text/html", _page("innerHTML"))
                if parts.path == "/escaped":
                    return self._send(200, "text/html", _page("textContent"))
                if parts.path.startswith("/rest/track-order/"):
                    order_id = unquote(parts.path[len("/rest/track-order/"):])
                    app.track_requests.append(order_id)
                    # `$where: "this.orderId === '" + id + "'"`: a quote ends the
                    # string early, and the evaluation throws
                    if "'" in order_id:
                        return self._send(500, "application/json",
                                          b'{"error":"SyntaxError: Unexpected identifier"}')
                    return self._send(200, "application/json", json.dumps(
                        {"data": [{"orderId": order_id}]}).encode())
                if parts.path == "/json":
                    q = parse_qs(parts.query).get("q", [""])[0]
                    return self._send(200, "application/json",
                                      json.dumps({"q": q}).encode())
                return self._send(404, "text/plain", b"no")

            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def track_app(monkeypatch):
    _chromium_or_skip(monkeypatch)
    app = _TrackApp()
    try:
        yield app
    finally:
        app.close()


def _executor():
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    executor.SETTLE_MS = 1500
    return executor


def _confirm(executor, url, param, location):
    from tests._browser import skip_or_fail
    from fuzzlab.oracle.probe import Candidate, UnplaceableLocation
    from fuzzlab.oracle.strategies import DomXssStrategy
    cand = Candidate(url=url, param=param, category="xss", location=location)
    try:
        return DomXssStrategy(executor).confirm(cand, None)
    except UnplaceableLocation as exc:
        if str(exc).startswith("browser unavailable"):
            skip_or_fail(f"chromium could not launch: {exc}")
        raise


# --- the payload set ----------------------------------------------------------------
def test_the_sentinel_call_comes_in_three_quoting_shapes():
    """PA-0139: not one quoting shape. At least one payload has no single quote, and
    one has no quote character at all; every payload carries the token. Six
    payloads (four as before, two added)."""
    payloads = _xss_exec_payloads("a1b2c3d4")
    assert len(payloads) == 6
    assert all("a1b2c3d4" in p and SENTINEL in p for p in payloads)
    assert any("'" not in p for p in payloads)
    assert any(not set("'\"`") & set(p) for p in payloads)
    call = f"{SENTINEL}('a1b2c3d4')"
    assert payloads[:4] == [f"<img src=x onerror=\"{call}\">",      # as before, kept
                            f"\"><img src=x onerror=\"{call}\">",
                            f"<svg onload=\"{call}\">", f"<script>{call}</script>"]


@pytest.mark.parametrize("token", ["", "a b", "x')//", "/x/", "tok-1"])
def test_a_token_that_could_break_its_quoting_is_refused(token):
    """The token goes into JS strings of every quote and a regex literal: only an
    alphanumeric token (`_token` draws hex) is accepted."""
    with pytest.raises(ValueError):
        _xss_exec_payloads(token)


# --- the quote-sensitive data path (real Chromium) ----------------------------------
def test_a_sink_behind_a_single_quoted_evaluation_is_confirmed(track_app):
    """The bug, end to end: DomXssStrategy confirms the track-result DOM XSS whose id
    passes through a single-quoted server-side evaluation."""
    verdict = _confirm(_executor(), track_app.base + "#/track-result", "id", "fragment")
    assert verdict is not None and verdict.confirmed
    assert "'" not in verdict.evidence["payload"]
    # the quoted payloads went first, and each was refused by the evaluation (500)
    assert any("'" in i for i in track_app.track_requests)


def test_each_payload_against_the_quote_sensitive_path(track_app):
    """Which payloads carry the call there: none with a single quote (the server's 500
    renders nothing), and both quote-free ones (the backtick call and
    ``/TOKEN/.source`` really call the sentinel with the token)."""
    from fuzzlab.oracle.browser import ExecRequest
    executor = _executor()
    executor.SETTLE_MS = 800
    token = "c0ffee42"
    fired = []
    for payload in _xss_exec_payloads(token):
        obs = executor.run(ExecRequest(url=track_app.base + "#/track-result", param="id",
                                       value=payload, location="fragment"), token)
        fired.append(obs.executed)
    assert fired == [False, False, False, False, True, True]


# --- no false positive from a quote-free payload ------------------------------------
def test_an_escaped_render_is_never_confirmed(track_app):
    """The same data path written with ``textContent``: no payload executes."""
    assert _confirm(_executor(), track_app.base + "escaped#/track-result", "id",
                    "fragment") is None


def test_a_json_echo_is_never_confirmed(track_app):
    """A JSON document echoing the value: no payload executes (BUG-0127's negative,
    for the browser mechanism)."""
    assert _confirm(_executor(), track_app.base + "json", "q", "query") is None
