"""Live-boot conformance check for `php_laravel`'s SSRF-via-link-unfurling
cell (`CC-LAB-0134`, Huddle Hub -- category 3's Slack pick).

Real, on-host integration test: assembles a real Laravel 13 project from
the checked-in skeleton plus this manifest's real `LaravelEmitter` output,
runs a real `composer install`, boots a real `php artisan serve`, and sends
real HTTP requests against it -- one cell per harness instance, mirroring
`mass_assignment_laravel_sample.yaml`'s own twin-pair precedent.

**The proof, and why it's genuinely stronger than
`test_labgen_webhook_signature_live_boot.py`'s own (no probability-
infeasibility caveat needed here).** This test spins up its own tiny local
HTTP server on an ephemeral loopback port, serving a known marker string --
bound and listening *before* the Laravel harness's own boot is invoked, and
held open for the whole test (an independent port from whatever
`LiveBootHarness._find_free_port()` picks for the Laravel app itself; no
shared allocation path, so no collision risk). The booted Laravel app (also
on loopback) is then asked to fetch that marker server two ways: a bare IP
literal (`http://127.0.0.1:<port>/`) and a real hostname that resolves to
loopback (`http://localhost:<port>/`) -- the second form is required to
actually exercise `scheme_and_resolved_ip_allowlist`'s distinguishing
feature (`gethostbyname()` resolution; an IP literal makes resolution a
no-op and would pass even a naive string check). The vulnerable twin
succeeds and echoes the marker for both forms; the secure twin rejects both
with a real HTTP 400 and never reaches the marker server at all (asserted
directly against the marker server's own hit counter).

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

_MARKER = "SECRET-MARKER-fuzzlab-ssrf-live-boot-test"


class _MarkerHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        _MarkerHandler.hits += 1
        body = _MARKER.encode("utf-8")
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
        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), _MarkerHandler)
        self.port = self._httpd.server_port
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def hits(self) -> int:
        return _MarkerHandler.hits

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def _cells():
    manifest = load_manifest("lab/manifests/ssrf_huddlehub_sample.yaml")
    return {c.cell_id: c for c in manifest.cells}


@pytest.mark.slow
def test_ssrf_vulnerable_twin_reaches_the_local_marker_server_both_ways() -> None:
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0003"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    marker = _MarkerServer()
    try:
        with LiveBootHarness(emitter, [cell]) as harness:
            url = served_url_for(cell)

            ip_resp = harness.get(url, params={"url": f"http://127.0.0.1:{marker.port}/"})
            assert ip_resp.status == 200, ip_resp.body
            assert _MARKER in ip_resp.body, ip_resp.body

            host_resp = harness.get(url, params={"url": f"http://localhost:{marker.port}/"})
            assert host_resp.status == 200, host_resp.body
            assert _MARKER in host_resp.body, host_resp.body

        assert marker.hits == 2
    finally:
        marker.close()


@pytest.mark.slow
def test_ssrf_secure_twin_rejects_the_loopback_target_both_ways() -> None:
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0004"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    marker = _MarkerServer()
    try:
        with LiveBootHarness(emitter, [cell]) as harness:
            url = served_url_for(cell)

            ip_resp = harness.get(url, params={"url": f"http://127.0.0.1:{marker.port}/"})
            assert ip_resp.status == 400, ip_resp.body
            assert _MARKER not in ip_resp.body, ip_resp.body

            host_resp = harness.get(url, params={"url": f"http://localhost:{marker.port}/"})
            assert host_resp.status == 400, host_resp.body
            assert _MARKER not in host_resp.body, host_resp.body

        assert marker.hits == 0, "the secure twin must never reach the marker server at all"
    finally:
        marker.close()


@pytest.mark.slow
def test_ssrf_secure_twin_accepts_a_real_public_url() -> None:
    """Confirms the secure twin's own functional path still works for a
    legitimate target -- not just that it rejects loopback."""
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0004"]

    with LiveBootHarness(emitter, [cell]) as harness:
        url = served_url_for(cell)
        resp = harness.get(url, params={"url": "http://example.com/"})
        assert resp.status == 200, resp.body
