"""One real, skip-guarded integration test (PA-0005): the offline suite in
`test_labgen_zap_oracle.py` mocks the subprocess call via an injected fake
runner, so this file is what actually exercises
`fuzzlab.labgen.oracle_wrapper.default_runner` shelling out to a real,
installed ZAP (`zap.sh -cmd -autorun <plan>`).

Skipped cleanly (not failed) when ZAP isn't reachable -- via `PATH`, or via
`FUZZLAB_ZAP_PATH` if set. ZAP is not a repo dependency and, unlike the
CLI tools the other three oracle wrappers use, is a ~230MB JVM application
most environments (including CI) will not have installed; it was only
available in the session that first wrote this test, which downloaded the
official release tarball into the ephemeral scratchpad -- see
`docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md`.

This test target is deliberately NOT vulnerable to anything (a plain stdlib
HTTP server serving static text) -- the point is to prove the real ZAP
binary is really invoked end to end, actually crawls and scans the target,
and returns a real `confirmed_secure` verdict from a real parsed report, not
to re-litigate Spike 005's already-proven positive case (a real SSTI/XSS
finding on Spike 003's target, which takes much longer to set up here).
"""

import http.server
import os
import re
import shutil
import threading

import pytest

from fuzzlab.labgen.oracle_wrapper import Verdict, default_runner
from fuzzlab.labgen.zap_oracle import ZapWholeAppScanRequest, run_zap_whole_app_scan


def _find(env_var, name):
    explicit = os.environ.get(env_var)
    if explicit and shutil.which(explicit):
        return explicit
    return shutil.which(name)


ZAP_PATH = _find("FUZZLAB_ZAP_PATH", "zap.sh")


class _StaticHandler(http.server.BaseHTTPRequestHandler):
    """A trivial, non-vulnerable page: static HTML, nothing reflected, no
    parameters processed. Nothing for ZAP's active scanner to find beyond
    routine header/info-disclosure noise, which is exactly the "confirmed
    secure" case this test asserts for a specific, scoped alert class."""

    def do_GET(self):
        body = b"<html><body><h1>static page</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture()
def static_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _StaticHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.skipif(not ZAP_PATH, reason="ZAP (zap.sh) not installed in this environment")
def test_real_zap_reports_confirmed_secure_against_a_non_vulnerable_endpoint(static_server):
    request = ZapWholeAppScanRequest(
        target_url=f"http://127.0.0.1:{static_server}/",
        alert_name_pattern=re.compile(r"Server Side Template Injection|Cross Site Scripting"),
        tool_path=ZAP_PATH,
        timeout_s=180.0,
        spider_max_duration_min=1,
        passive_scan_max_duration_min=1,
        active_scan_max_duration_min=2,
    )
    verdict = run_zap_whole_app_scan(request, runner=default_runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE
    assert verdict.run is not None
    assert verdict.run.timed_out is False
    # the real scan still found *something* (routine header/info noise),
    # proving the tool genuinely ran end to end rather than exiting early
    assert len(verdict.all_alerts) > 0
