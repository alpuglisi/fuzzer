"""Real, skip-guarded integration tests (PA-0005) for
`fuzzlab.labgen.nuclei_oracle`: the offline suite in
`test_labgen_nuclei_oracle.py` mocks every subprocess call via an injected
fake runner, so this file is what actually exercises
`fuzzlab.labgen.nuclei_oracle.default_nuclei_runner` shelling out to a real
`nuclei` binary against real, local HTTP servers.

Skipped cleanly (not failed) when `nuclei` isn't reachable -- via `PATH`, or
via `FUZZLAB_NUCLEI_PATH` if set (`nuclei` is not a repo dependency; it was
only available in the session that first wrote this test via `go install`,
see `docs/spikes/SPIKE-004-nuclei-vs-dvwa.md`).

Three cases, matching the spike's own three-case methodology (the third case
is the one that caught BUG-0023 and is not optional): a genuinely vulnerable
endpoint, a genuinely secure endpoint, and an unreachable target -- proving
the real `nuclei` binary's actual output shape (not a guess at it) drives
each of the three verdicts.
"""

import http.server
import os
import shutil
import socketserver
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from fuzzlab.labgen.nuclei_oracle import (
    NucleiVerdict,
    PathTraversalOracleRequest,
    default_nuclei_runner,
    run_path_traversal_oracle,
)


def _find(env_var, name):
    explicit = os.environ.get(env_var)
    if explicit and shutil.which(explicit):
        return explicit
    return shutil.which(name)


NUCLEI_PATH = _find("FUZZLAB_NUCLEI_PATH", "nuclei")

_FAKE_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class _LfiHandler(http.server.BaseHTTPRequestHandler):
    """A trivial, deliberately vulnerable stand-in for DVWA's fi/low.php: any
    `page` value ending in a traversal to `etc/passwd` gets the fake passwd
    content back verbatim; anything else is a 403, exactly like DVWA's
    `impossible.php` allowlist rejection. This keeps the integration test
    hermetic (no PHP/MariaDB dependency) while reproducing the exact response
    shape the bundled template was written against and Spike 004 validated
    live -- the spike itself is what proves the template works against the
    real app; this test proves the *wrapper* drives real `nuclei` correctly.
    """

    vulnerable = True

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        page = query.get("page", [""])[0]
        if self.vulnerable and page.endswith("etc/passwd"):
            body = _FAKE_PASSWD.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"ERROR: File not found!"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


def _make_handler(vulnerable):
    class _Handler(_LfiHandler):
        pass
    _Handler.vulnerable = vulnerable
    return _Handler


@pytest.fixture()
def vulnerable_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _make_handler(True))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def secure_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _make_handler(False))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def closed_port():
    """A loopback port nothing is listening on, for the unreachable-target
    case (BUG-0023)."""
    server = socketserver.TCPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
    port = server.server_address[1]
    server.server_close()
    return port


@pytest.mark.skipif(not NUCLEI_PATH, reason="nuclei not installed in this environment")
def test_real_nuclei_reports_confirmed_vulnerable_against_a_real_lfi_endpoint(vulnerable_server):
    request = PathTraversalOracleRequest(
        target_base_url=f"http://127.0.0.1:{vulnerable_server}",
        endpoint_path="/",
        param_name="page",
        tool_path=NUCLEI_PATH,
        timeout_s=60.0,
    )
    verdict = run_path_traversal_oracle(request, runner=default_nuclei_runner)
    assert verdict.outcome is NucleiVerdict.CONFIRMED_VULNERABLE
    assert verdict.run is not None
    assert verdict.run.timed_out is False


@pytest.mark.skipif(not NUCLEI_PATH, reason="nuclei not installed in this environment")
def test_real_nuclei_reports_confirmed_secure_against_a_real_hardened_endpoint(secure_server):
    request = PathTraversalOracleRequest(
        target_base_url=f"http://127.0.0.1:{secure_server}",
        endpoint_path="/",
        param_name="page",
        tool_path=NUCLEI_PATH,
        timeout_s=60.0,
    )
    verdict = run_path_traversal_oracle(request, runner=default_nuclei_runner)
    assert verdict.outcome is NucleiVerdict.CONFIRMED_SECURE
    assert verdict.run is not None
    assert verdict.run.timed_out is False


@pytest.mark.skipif(not NUCLEI_PATH, reason="nuclei not installed in this environment")
def test_real_nuclei_reports_inconclusive_never_secure_against_an_unreachable_target(closed_port):
    """BUG-0023's real-binary regression guard: this is the exact case a
    naive classifier got wrong against the real tool."""
    request = PathTraversalOracleRequest(
        target_base_url=f"http://127.0.0.1:{closed_port}",
        endpoint_path="/",
        param_name="page",
        tool_path=NUCLEI_PATH,
        timeout_s=30.0,
    )
    verdict = run_path_traversal_oracle(request, runner=default_nuclei_runner)
    assert verdict.outcome is NucleiVerdict.INCONCLUSIVE
    assert verdict.outcome is not NucleiVerdict.CONFIRMED_SECURE
