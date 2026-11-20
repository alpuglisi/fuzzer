"""A form store step replays its captured sibling entries (FR-FUZZ-692, CC-FUZZ-0692).

Many guestbooks store an entry only when the form's submit field is posted with it, so a
plant that sends the injected field alone stores nothing. A crawl-derived stored-XSS
point (FR-FUZZ-691) carries the write's full entry list; the executor sends it, the
payload in the target field. An invented app; real Chromium."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

import pytest


class _Book(BaseHTTPRequestHandler):
    """``POST /sign`` stores ``note`` only when ``go`` is posted too; ``/book`` shows
    every stored note raw."""
    notes: list = []
    posts: list = []

    def log_message(self, *a):
        pass

    def _send(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        form = parse_qsl(self.rfile.read(int(self.headers.get("Content-Length") or 0))
                         .decode(), keep_blank_values=True)
        type(self).posts.append(form)
        fields = dict(form)
        if self.path == "/sign" and "go" in fields:
            type(self).notes.append(fields.get("note", ""))
        self._send(200, b"ok")

    def do_GET(self):
        if self.path == "/book":
            return self._send(200, ("<ul>" + "".join(f"<li>{n}</li>" for n in
                                                    type(self).notes) + "</ul>").encode())
        self._send(404)


def test_a_form_plant_sends_every_captured_field_with_the_payload_in_its_own():
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import StoredXssStrategy
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _Book.notes, _Book.posts = [], []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Book)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with_entries = Candidate(url=base + "/book", param="note", category="xss",
                                 store_url=base + "/sign", store_param="note",
                                 store_method="POST", store_location="body",
                                 store_entries=(("note", "hi"), ("go", "Sign")))
        verdict = StoredXssStrategy(PlaywrightBrowserExecutor()).confirm(with_entries, None)
        alone = Candidate(url=base + "/book", param="note", category="xss",
                          store_url=base + "/sign", store_param="note")
        notes_before = len(_Book.notes)
        StoredXssStrategy(PlaywrightBrowserExecutor()).confirm(alone, None)
    finally:
        server.shutdown()
    if not _Book.posts:
        skip_or_fail("chromium could not run the store step")
    assert verdict is not None and verdict.confirmed and verdict.vuln_class == "xss-stored"
    assert all(("go", "Sign") in post for post in _Book.posts[:notes_before])
    # without entries (ground truth's form plant, unchanged) only the field is posted
    assert len(_Book.notes) == notes_before


@pytest.mark.parametrize("entries", [(("other", "x"),), ((("note",), "x"),)])
def test_a_form_plant_whose_entries_lack_the_field_is_refused_before_any_browser(entries):
    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    from fuzzlab.oracle.probe import UnplaceableLocation
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    with pytest.raises(UnplaceableLocation, match="unplaceable store"):
        PlaywrightBrowserExecutor().run(ExecRequest(url="http://h/a", store=StoreStep(
            url="http://h/s", param="note", value="v", entries=entries)), "t")
