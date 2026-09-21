"""Real, unmocked integration tests (PA-0005) for
`fuzzlab.labgen.identifier_sqli_oracle`: the offline suite in
`test_labgen_identifier_sqli_oracle.py` exercises the classification logic
via an injected `FakeHttpRunner`, so this file is what actually exercises
`default_http_runner` making real HTTP calls (via `requests`, an existing
project dependency) against real, local, hermetic HTTP servers -- proving
the real code path end to end, not a guess at it.

No external tool binary is needed here (unlike the sqlmap spot-check
documented in the module's docstring / `CC-LAB-0029`): this oracle never
shells out, so there is nothing to skip-guard the way
`test_labgen_nuclei_oracle_integration.py` skips when `nuclei` isn't
installed. `requests` is always available (a declared project dependency).

Three servers, mirroring the spot-check's own three-case methodology:
- A vulnerable stand-in for `order_by_vuln.php` (the module docstring's
  case 1): a bare identifier substitution changes which of two fixed
  response bodies comes back, modeling a TRUE-condition CASE-WHEN landing
  on `id`-order vs a FALSE-condition landing on `name`-order.
- A secure stand-in: the query param is ignored entirely (as a
  parameterized/allowlisted endpoint would behave) -- the response is
  identical regardless of what identifier-shaped value is sent.
- An unreachable target (closed port) -- must never be misread as secure
  (PA-0025, applied here the same way it is in `identifier_sqli_oracle.py`'s
  baseline-health check).
"""

import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlparse

from fuzzlab.labgen.identifier_sqli_oracle import (
    IdentifierSqliOracleRequest,
    IdentifierSqliVerdict,
    default_http_runner,
    run_identifier_sqli_oracle,
)

_TRUE_ORDER_BODY = "1:charlie\n2:alpha\n3:bravo\n"
_FALSE_ORDER_BODY = "2:alpha\n3:bravo\n1:charlie\n"


class _VulnerableOrderByHandler(http.server.BaseHTTPRequestHandler):
    """Stand-in for the spot-check's `order_by_vuln.php`: any value equal to
    the baseline (`id`) or containing a TRUE-condition marker (`1=1`) comes
    back id-ordered; a FALSE-condition marker (`1=2`) comes back
    name-ordered -- a hermetic, deterministic model of the real differential
    without needing PHP/PDO/SQLite in this test process."""

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        sort = query.get("sort", [""])[0]
        if "1=2" in sort:
            body = _FALSE_ORDER_BODY.encode()
        else:
            body = _TRUE_ORDER_BODY.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


class _SecureHandler(http.server.BaseHTTPRequestHandler):
    """Stand-in for a parameterized/allowlisted endpoint: the `sort` value
    never affects the response at all."""

    def do_GET(self):
        body = _TRUE_ORDER_BODY.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _start(handler_cls):
    server = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _request(port):
    return IdentifierSqliOracleRequest(
        target_base_url=f"http://127.0.0.1:{port}",
        endpoint_path="/order_by_vuln.php",
        param_name="sort",
        column_a="id",
        column_b="name",
        timeout_s=5.0,
    )


def test_real_http_runner_reports_confirmed_vulnerable_against_a_real_differential_endpoint():
    server, thread = _start(_VulnerableOrderByHandler)
    try:
        port = server.server_address[1]
        verdict = run_identifier_sqli_oracle(_request(port), runner=default_http_runner)
        assert verdict.outcome is IdentifierSqliVerdict.CONFIRMED_VULNERABLE
        assert verdict.true_probe is not None and verdict.true_probe.status_code == 200
        assert verdict.false_probe is not None and verdict.false_probe.status_code == 200
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_real_http_runner_reports_confirmed_secure_against_a_real_hardened_endpoint():
    server, thread = _start(_SecureHandler)
    try:
        port = server.server_address[1]
        verdict = run_identifier_sqli_oracle(_request(port), runner=default_http_runner)
        assert verdict.outcome is IdentifierSqliVerdict.CONFIRMED_SECURE
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_real_http_runner_reports_inconclusive_never_secure_against_an_unreachable_target():
    """PA-0025's real-network regression guard: a closed port must never be
    misread as secure, matching this module's baseline-health check."""
    server = socketserver.TCPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
    port = server.server_address[1]
    server.server_close()  # closed before any request is fired: nothing is listening
    verdict = run_identifier_sqli_oracle(_request(port), runner=default_http_runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert verdict.outcome is not IdentifierSqliVerdict.CONFIRMED_SECURE
