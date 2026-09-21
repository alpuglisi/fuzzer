"""One real, skip-guarded integration test per tool (PA-0005): the offline
suite in `test_labgen_oracle_wrapper.py` mocks every subprocess call via an
injected fake runner, so this file is what actually exercises
`fuzzlab.labgen.oracle_wrapper.default_runner` shelling out to the real
sqlmap / commix binaries.

Skipped cleanly (not failed) when the binary isn't reachable -- via `PATH`, or
via `FUZZLAB_SQLMAP_PATH` / `FUZZLAB_COMMIX_PATH` if set (sqlmap/commix are
not repo dependencies; they were only available in the session that first
wrote this test by cloning them into the ephemeral scratchpad -- see
`docs/spikes/SPIKE-001-sqlmap-vs-vapi.md` / `SPIKE-002-commix-vs-dvwa.md`).

This test target is deliberately NOT injectable (a plain stdlib HTTP server
echoing the parameter back) -- the point is to prove the real tool is really
invoked end to end and returns a real "secure" verdict from real tool output,
not to re-litigate Spike 001/002's already-proven positive case.
"""

import http.server
import os
import shutil
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from fuzzlab.labgen.oracle_wrapper import (
    CommandInjectionOracleRequest,
    SqlInjectionOracleRequest,
    Verdict,
    default_runner,
    run_command_injection_oracle,
    run_sql_injection_oracle,
)


def _find(env_var, name):
    explicit = os.environ.get(env_var)
    if explicit and shutil.which(explicit):
        return explicit
    return shutil.which(name)


SQLMAP_PATH = _find("FUZZLAB_SQLMAP_PATH", "sqlmap")
COMMIX_PATH = _find("FUZZLAB_COMMIX_PATH", "commix")


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    """A trivial, non-vulnerable endpoint: echoes the query parameter back as
    plain text. No SQL, no shell -- there is nothing here for either tool to
    find, which is exactly the "confirmed secure" case this test asserts."""

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        value = query.get("id", query.get("ip", [""]))[0]
        body = f"ok: {value}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture()
def echo_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.skipif(not SQLMAP_PATH, reason="sqlmap not installed in this environment")
def test_real_sqlmap_reports_confirmed_secure_against_a_non_vulnerable_endpoint(echo_server):
    request = SqlInjectionOracleRequest(
        target_url=f"http://127.0.0.1:{echo_server}/?id=1",
        param_name="id",
        tool_path=SQLMAP_PATH,
        timeout_s=60.0,
        extra_args=["--level", "1", "--risk", "1", "--technique", "B"],
    )
    verdict = run_sql_injection_oracle(request, runner=default_runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE
    assert verdict.run is not None
    assert verdict.run.timed_out is False


@pytest.mark.skipif(not COMMIX_PATH, reason="commix not installed in this environment")
def test_real_commix_reports_confirmed_secure_against_a_non_vulnerable_endpoint(echo_server):
    request = CommandInjectionOracleRequest(
        target_url=f"http://127.0.0.1:{echo_server}/?ip=127.0.0.1",
        param_name="ip",
        tool_path=COMMIX_PATH,
        timeout_s=60.0,
    )
    verdict = run_command_injection_oracle(request, runner=default_runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE
    assert verdict.run is not None
    assert verdict.run.timed_out is False
