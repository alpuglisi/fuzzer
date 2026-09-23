"""Live-boot conformance check for `php_laravel`'s outbound-header-injection
cell (`CC-LAB-0135`, Huddle Hub -- category 3's Slack pick, its third and
final designed cell).

Real, on-host integration test: assembles a real Laravel 13 project from
the checked-in skeleton plus this manifest's real `LaravelEmitter` output,
runs a real `composer install`, boots a real `php artisan serve`, and sends
real HTTP requests against it -- one cell per harness instance, mirroring
`ssrf_huddlehub_sample.yaml`'s own twin-pair precedent
(`test_labgen_ssrf_live_boot.py`).

**The proof.** This test spins up its own tiny local HTTP server on an
ephemeral loopback port -- bound and listening *before* the Laravel
harness's own boot is invoked, independent of `LiveBootHarness.
_find_free_port()`'s own port allocation for the Laravel app itself (no
shared allocation path, no collision risk) -- and points the booted app's
`HUDDLEHUB_WEBHOOK_URL` at it via `monkeypatch.setenv` (PA-0005-style env-
var test hygiene: never a bare `os.environ[...] =`, which would leak into
every other test in the process; `monkeypatch` undoes it automatically at
teardown). `HUDDLEHUB_WEBHOOK_URL` is set *before* the harness's context
manager is entered (before its `composer install`/`artisan key:generate`/
`artisan serve` subprocesses are started), so each of those subprocesses
inherits it as a real process environment variable -- `LiveBootHarness._run`
and its `artisan serve` `Popen` call both pass no explicit `env=`, so both
inherit the calling test process's environment at call time; the generated
PHP's own `env('HUDDLEHUB_WEBHOOK_URL', ...)` call falls through to that
inherited value because the harness's own generated `.env` file never
declares the key itself.

The vulnerable twin's crafted trigger word (containing a literal `\\r\\n`)
is asserted to result in the marker server genuinely receiving a real,
separate `X-Injected: proof` header -- verified here by inspecting the
marker server's own actually-parsed `email.message.Message` headers
(`BaseHTTPRequestHandler.headers`, which is exactly what a real destination
service would parse the raw bytes into), not merely asserted a priori. The
secure twin's same crafted value is rejected with a real HTTP 400 and the
marker server is never reached at all (asserted directly against its own
hit counter) -- Guzzle's PSR-7 `Request` constructor rejects any header
value containing CR/LF outright.

Skip-guarded (PA-0005) on `live_boot_available()`. Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import http.server
import threading

import pytest

from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)

_CRAFTED_TRIGGER_WORD = "innocuous\r\nX-Injected: proof"


class _MarkerHandler(http.server.BaseHTTPRequestHandler):
    hits = 0
    last_headers: "http.client.HTTPMessage | None" = None

    def do_POST(self) -> None:  # noqa: N802 - stdlib method name
        _MarkerHandler.hits += 1
        _MarkerHandler.last_headers = self.headers
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence stdlib's default logging
        pass


class _MarkerServer:
    """A tiny local HTTP server on an ephemeral loopback port -- bound and
    listening immediately on construction, independent of
    `LiveBootHarness._find_free_port()`'s own port allocation for the
    Laravel app itself (see this module's own docstring)."""

    def __init__(self) -> None:
        _MarkerHandler.hits = 0
        _MarkerHandler.last_headers = None
        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), _MarkerHandler)
        self.port = self._httpd.server_port
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def hits(self) -> int:
        return _MarkerHandler.hits

    @property
    def last_headers(self):
        return _MarkerHandler.last_headers

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def _cells():
    manifest = load_manifest("lab/manifests/header_injection_huddlehub_sample.yaml")
    return {c.cell_id: c for c in manifest.cells}


@pytest.mark.slow
def test_header_injection_vulnerable_twin_splices_a_real_extra_header(monkeypatch: pytest.MonkeyPatch) -> None:
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0005"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    marker = _MarkerServer()
    try:
        monkeypatch.setenv("HUDDLEHUB_WEBHOOK_URL", f"http://127.0.0.1:{marker.port}/")
        with LiveBootHarness(emitter, [cell]) as harness:
            url = served_url_for(cell)
            resp = harness.get(url, params={"triggerWord": _CRAFTED_TRIGGER_WORD})
            assert resp.status == 200, resp.body

        assert marker.hits == 1
        headers = marker.last_headers
        assert headers is not None
        # The genuinely spliced-in extra header, as the marker server's own
        # real HTTP parsing actually saw it -- not merely asserted a priori.
        assert headers.get("X-Injected") == "proof", dict(headers.items())
        # The original header the transform's own concatenation still
        # produced is also present, on its own line -- the injection *adds*
        # a header, it does not replace the one already being built.
        assert headers.get("X-Huddle-Trigger") == "innocuous", dict(headers.items())
    finally:
        marker.close()


@pytest.mark.slow
def test_header_injection_secure_twin_rejects_the_crafted_value_and_never_reaches_the_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0006"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    marker = _MarkerServer()
    try:
        monkeypatch.setenv("HUDDLEHUB_WEBHOOK_URL", f"http://127.0.0.1:{marker.port}/")
        with LiveBootHarness(emitter, [cell]) as harness:
            url = served_url_for(cell)
            resp = harness.get(url, params={"triggerWord": _CRAFTED_TRIGGER_WORD})
            assert resp.status == 400, resp.body

        assert marker.hits == 0, "the secure twin must never reach the marker server at all"
    finally:
        marker.close()


@pytest.mark.slow
def test_header_injection_secure_twin_accepts_an_ordinary_trigger_word(monkeypatch: pytest.MonkeyPatch) -> None:
    """Confirms the secure twin's own functional path still works for a
    legitimate value -- not just that it rejects a crafted one."""
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0006"]

    marker = _MarkerServer()
    try:
        monkeypatch.setenv("HUDDLEHUB_WEBHOOK_URL", f"http://127.0.0.1:{marker.port}/")
        with LiveBootHarness(emitter, [cell]) as harness:
            url = served_url_for(cell)
            resp = harness.get(url, params={"triggerWord": "deploy"})
            assert resp.status == 200, resp.body

        assert marker.hits == 1
        headers = marker.last_headers
        assert headers is not None
        assert headers.get("X-Huddle-Trigger") == "deploy", dict(headers.items())
    finally:
        marker.close()
