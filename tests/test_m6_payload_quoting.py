"""BUG-0139 / PA-0139: the M6 sentinel payloads are never all one quoting shape.

Every M6 payload called ``__fzlbHit('TOKEN')`` with single quotes. Juice Shop's
``GET /rest/track-order/:id`` evaluates the id inside a single-quoted string (a
MongoDB-style ``$where``): a ``'`` answers 500, so nothing is echoed and nothing
renders. Its ``#/track-result?id=`` DOM XSS, a true positive, was therefore checked
and never confirmed. Two payloads now carry the call without a single quote: one
with backticks, and one with no quote character, ``/`` or whitespace at all
(``String.fromCharCode(...)`` of the token).

The fixture here is that data path, on loopback: a page that fetches
``/rest/track-order/<id>``, with the id put into one path segment unencoded. The
server answers 500 on a ``'`` in the id, else echoes the id as JSON, and the page
writes it with ``innerHTML``.
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

#: The client puts the id into the API path **unencoded**, as Juice Shop's does
#: (`'/rest/track-order/' + id`): a ``/`` in it would split the path segment.
_RENDER_JS = """
const p = new URLSearchParams(%(source)s);
const id = p.get('id');
if (id !== null) fetch('%(api)s' + id)
  .then(r => r.ok ? r.json() : null)
  .then(j => { if (j) document.getElementById('out').%(sink)s = j.data[0].orderId; });
"""
_HASH = "location.hash.split('?')[1] || ''"


def _page(sink, api="/rest/track-order/", source=_HASH):
    js = _RENDER_JS % {"source": source, "api": api, "sink": sink}
    return f"<html><body><div id='out'></div><script>{js}</script></body></html>".encode()


class _TrackApp:
    """The pages, each fetching the id from one of the APIs and writing it into the
    page:
    - ``/`` (``innerHTML``) and ``/escaped`` (``textContent``), the id from the hash
      route's query;
    - ``/strict`` (``innerHTML``), through the stricter API;
    - ``/q?id=`` (``innerHTML``), the id from the page's own query (a query point).

    The APIs match **one** path segment, as Express's ``:id`` does:
    - ``/rest/track-order/<id>`` evaluates the id in a single-quoted string (500 on a
      ``'``);
    - ``/rest/strict-order/<id>`` also refuses a backtick.

    ``/json?q=`` is a JSON document echoing ``q``."""

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
                if parts.path == "/strict":
                    return self._send(200, "text/html", _page(
                        "innerHTML", api="/rest/strict-order/"))
                if parts.path == "/q":
                    return self._send(200, "text/html", _page(
                        "innerHTML", source="location.search"))
                for api, refused in (("/rest/track-order/", "'"),
                                     ("/rest/strict-order/", "'`")):
                    if not parts.path.startswith(api):
                        continue
                    segment = parts.path[len(api):]
                    if not segment or "/" in segment:        # one segment, as `:id`
                        return self._send(404, "text/plain", b"no route")
                    order_id = unquote(segment)
                    app.track_requests.append(order_id)
                    # `$where: "this.orderId === '" + id + "'"`: a quote ends the
                    # string early, and the evaluation throws
                    if set(refused) & set(order_id):
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
    """PA-0139: not one quoting shape, ordered by reach (review A-S2): the quoted
    ``<img>``, the backtick call, the ``String.fromCharCode`` call (no quote, no ``/``,
    no whitespace: a path segment carries it whole, review A-S1), then the other three
    quoted wrappers. Six payloads; the token in every one."""
    token = "a1b2c3d4"
    payloads = _xss_exec_payloads(token)
    call = f"{SENTINEL}('{token}')"
    codes = ",".join(str(ord(c)) for c in token)
    assert payloads == [
        f"<img src=x onerror=\"{call}\">",
        f"<img src=x onerror=\"{SENTINEL}(`{token}`)\">",
        f"<img src=x onerror={SENTINEL}(String.fromCharCode({codes}))>",
        f"\"><img src=x onerror=\"{call}\">",
        f"<svg onload=\"{call}\">",
        f"<script>{call}</script>"]
    bare = payloads[2]
    # the sentinel call has no quote, no ``/`` and no whitespace; the whole payload no
    # quote and nothing that splits a path segment or a URL (``/``, ``#``, ``?``). The
    # tag's own spaces stay: HTML separates attributes only by whitespace or ``/``.
    call_bare = bare[bare.index(SENTINEL):-1]
    assert not set("'\"`/ \t\r\n") & set(call_bare)
    assert not set("'\"`/#?") & set(bare)
    assert all(token in p for p in payloads if p != bare)


@pytest.mark.parametrize("token", ["", "a b", "x')//", "/x/", "tok-1"])
def test_a_token_that_could_break_its_quoting_is_refused(token):
    """The token goes into JS strings of every quote: only an alphanumeric token
    (`_token` draws hex) is accepted."""
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


def _fired(app, path, location="fragment"):
    from fuzzlab.oracle.browser import ExecRequest
    executor = _executor()
    executor.SETTLE_MS = 800
    token = "c0ffee42"
    return [executor.run(ExecRequest(url=app.base + path, param="id", value=payload,
                                     location=location), token).executed
            for payload in _xss_exec_payloads(token)]


def test_each_payload_against_the_quote_sensitive_path(track_app):
    """Which payloads carry the call there, through one path segment: none with a
    single quote (the server's 500 renders nothing), and both quote-free ones (the
    backtick call, and ``String.fromCharCode`` really calls the sentinel with the
    token)."""
    assert _fired(track_app, "#/track-result") == [False, True, True, False, False, False]


def test_only_the_fully_quote_free_payload_passes_a_stricter_path(track_app):
    """Review A-S1: a path that refuses backticks too: only the ``fromCharCode``
    payload (no quote, no ``/``) reaches the sink, and the strategy confirms by it."""
    assert _fired(track_app, "strict#/track-result") == [False, False, True, False,
                                                         False, False]
    verdict = _confirm(_executor(), track_app.base + "strict#/track-result", "id",
                       "fragment")
    assert verdict is not None and "fromCharCode" in verdict.evidence["payload"]


def test_the_quote_free_payloads_at_a_query_point(track_app):
    """Review B (gap): at a query point the payload is form-encoded (``+``, ``%2F``,
    ``%60``) and decoded by the page; both quote-free payloads still execute through
    the quote-sensitive path, and the strategy confirms."""
    assert _fired(track_app, "q", location="query") == [False, True, True, False,
                                                        False, False]
    verdict = _confirm(_executor(), track_app.base + "q", "id", "query")
    assert verdict is not None and verdict.confirmed


class _QuoteBreaksTheLoad:
    """An executor whose page load fails for any payload carrying ``'`` or a backtick
    (the path errors before anything is observed) and fires for a fully quote-free
    one."""

    def __init__(self):
        self.calls = []

    def run(self, request, token):
        from fuzzlab.oracle.browser import ExecObservation, NotObserved
        self.calls.append(request.value)
        if set("'`") & set(request.value):
            raise NotObserved("the browser could not load the page (TimeoutError: x)")
        return ExecObservation(executed=True, detail="scripted")


def test_the_quote_free_payload_is_still_tried_after_the_unobserved_stop():
    """Review B-S1: `MAX_NOT_OBSERVED` stops the loop after the quoted ``<img>`` and
    the backtick payload went unobserved; the first untried quote-free payload still
    gets its one load, and confirms."""
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import DomXssStrategy
    executor = _QuoteBreaksTheLoad()
    cand = Candidate(url="http://127.0.0.1:9/p", param="q", category="xss",
                     location="query")
    verdict = DomXssStrategy(executor).confirm(cand, None)
    assert verdict is not None and verdict.confirmed
    assert len(executor.calls) == 3 and "fromCharCode" in executor.calls[2]


# --- no false positive from a quote-free payload ------------------------------------
def test_an_escaped_render_is_never_confirmed(track_app):
    """The same data path written with ``textContent``: no payload executes."""
    assert _confirm(_executor(), track_app.base + "escaped#/track-result", "id",
                    "fragment") is None


def test_a_json_echo_is_never_confirmed(track_app):
    """A JSON document echoing the value: no payload executes (BUG-0127's negative,
    for the browser mechanism)."""
    assert _confirm(_executor(), track_app.base + "json", "q", "query") is None
