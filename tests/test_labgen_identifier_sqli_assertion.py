"""Tests for `fuzzlab.labgen.identifier_sqli_assertion` (L-P1.2b): lane
L-P1.2a's identifier-SQLi differential prober wired in as the **build-time
security assertion** for this lane's identifier/alias-position cells.

Two layers, matching the convention the oracle modules themselves use:

* this file -- classification/wiring logic against an injected fake HTTP
  runner (no network, no target), including every fail-closed path; and
* the bottom section -- a *real*, unmocked end-to-end pass over real local
  HTTP servers that model a vulnerable and a hardened `/catalog.php?sort=`,
  so `default_http_runner` and the whole assertion path are exercised for
  real (PA-0005's "a real code path that test doubles bypass everywhere must
  still have at least one test exercising the real implementation").

The expected verdict is never hand-written here: it is derived from the real
`lab/safety_matrix.yaml` by `verdict()`, exactly as the assertion under test
derives it (NFR-LAB-label-accuracy).
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from fuzzlab.labgen.identifier_sqli_assertion import (
    IDENTIFIER_SINK_FAMILIES,
    IdentifierSqliAssertionError,
    IdentifierSqliTier2Oracle,
    assert_identifier_sqli_cell,
    build_identifier_sqli_request,
    is_identifier_sqli_cell,
)
from fuzzlab.labgen.identifier_sqli_oracle import HttpProbeResult
from fuzzlab.labgen.schema import Cell, ParamSpec, Pipeline, Route, SinkContext, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix

MANIFEST_PATH = "lab/manifests/phase1_harder_shapes_sample.yaml"
TARGET = "http://127.0.0.1:8080"

#: The page-profile probe metadata for /catalog.php, read from the emitter's
#: own page profile rather than duplicated here (PA-0001): the whole point of
#: the assertion module is that this metadata lives with the emitter, not in
#: the Cell IR.
from fuzzlab.labgen.emitters.php_current import _PAGE_PARAMS  # noqa: E402

CATALOG = _PAGE_PARAMS["/catalog.php"]


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def cells():
    return {c.cell_id: c for c in load_manifest(MANIFEST_PATH).cells}


class FakeHttpRunner:
    """Returns a scripted :class:`HttpProbeResult` per probe, keyed by which
    leg is being fired (baseline / TRUE / FALSE), and records every URL so a
    test can assert what was actually sent."""

    def __init__(self, baseline, true_probe, false_probe):
        self._scripted = [baseline, true_probe, false_probe]
        self.urls: list[str] = []

    def __call__(self, url, headers, cookie, timeout_s):
        self.urls.append(url)
        scripted = self._scripted[min(len(self.urls) - 1, len(self._scripted) - 1)]
        return HttpProbeResult(
            url=url,
            status_code=scripted[0],
            body=scripted[1],
            timed_out=scripted[2],
            elapsed_s=0.01,
        )


def _ok(body: str):
    return (200, body, False)


def _probe_kwargs(**overrides):
    kwargs = dict(
        target_base_url=TARGET,
        param_name=CATALOG["param_name"],
        column_a=CATALOG["column_a"],
        column_b=CATALOG["column_b"],
    )
    kwargs.update(overrides)
    return kwargs


# ---------------------------------------------------------------------------
# Shape gating
# ---------------------------------------------------------------------------


def test_identifier_families_are_exactly_the_two_new_sql_families() -> None:
    assert set(IDENTIFIER_SINK_FAMILIES) == {"sql_identifier", "sql_join_alias"}


def test_is_identifier_sqli_cell_selects_only_identifier_position_cells(cells) -> None:
    selected = {cid for cid, cell in cells.items() if is_identifier_sqli_cell(cell)}
    assert selected == {f"LABGEN-HS-{n:04d}" for n in range(1, 8)}


def test_building_a_request_for_a_value_position_cell_is_refused(cells) -> None:
    """A CASE-WHEN identifier differential means nothing at an HTML sink --
    refusing is the honest answer, not running and reporting 'secure'."""
    with pytest.raises(IdentifierSqliAssertionError, match="not an identifier/alias position"):
        build_identifier_sqli_request(cells["LABGEN-HS-0009"], **_probe_kwargs())


def test_building_a_request_uses_the_sink_endpoint_when_the_cell_has_one(cells) -> None:
    import dataclasses

    cell = dataclasses.replace(
        cells["LABGEN-HS-0001"],
        sink_endpoint=Route(method="GET", path="/catalog_view.php"),
        context_depth="stored_second_order",
    )
    request = build_identifier_sqli_request(cell, **_probe_kwargs())
    assert request.endpoint_path == "/catalog_view.php"


def test_building_a_request_refuses_a_non_query_parameter_location(cells) -> None:
    import dataclasses

    cell = dataclasses.replace(cells["LABGEN-HS-0001"], param=ParamSpec(location="cookie"))
    with pytest.raises(IdentifierSqliAssertionError, match="query-string URL only"):
        build_identifier_sqli_request(cell, **_probe_kwargs())


def test_building_a_request_refuses_a_non_raw_encoding(cells) -> None:
    import dataclasses

    cell = dataclasses.replace(cells["LABGEN-HS-0001"], param=ParamSpec(encoding="base64"))
    with pytest.raises(IdentifierSqliAssertionError, match="double-encoded/base64"):
        build_identifier_sqli_request(cell, **_probe_kwargs())


# ---------------------------------------------------------------------------
# Agreement: the assertion confirms the derived verdict
# ---------------------------------------------------------------------------


def test_raw_identifier_cell_is_confirmed_vulnerable(cells, matrix) -> None:
    runner = FakeHttpRunner(_ok("baseline"), _ok("true-order"), _ok("false-order"))
    result = assert_identifier_sqli_cell(cells["LABGEN-HS-0001"], matrix, runner=runner, **_probe_kwargs())
    assert result.derived.verdict == "VULNERABLE"
    assert result.oracle.confirmed_vulnerable is True
    assert result.matches is True
    # The probe really did substitute a CASE-WHEN over the page profile's two
    # real columns into the `sort` parameter.
    assert "sort=" in runner.urls[1]
    assert "CASE+WHEN" in runner.urls[1] and "name" in runner.urls[1] and "price" in runner.urls[1]


def test_allowlisted_identifier_cell_is_confirmed_secure(cells, matrix) -> None:
    """The allowlist collapses the CASE-WHEN value to the fallback
    identifier, so TRUE and FALSE come back identical *and healthy* -- which
    is the only shape of "identical" this oracle accepts as secure."""
    runner = FakeHttpRunner(_ok("rows"), _ok("rows"), _ok("rows"))
    result = assert_identifier_sqli_cell(cells["LABGEN-HS-0004"], matrix, runner=runner, **_probe_kwargs())
    assert result.derived.verdict == "SECURE"
    assert result.oracle.confirmed_secure is True
    assert result.matches is True


def test_param_bind_identifier_cell_is_confirmed_vulnerable(cells, matrix) -> None:
    """The cell that *looks* parameterized: the assertion still confirms it
    vulnerable, which is the whole reason this shape is in the corpus."""
    runner = FakeHttpRunner(_ok("baseline"), _ok("a"), _ok("b"))
    result = assert_identifier_sqli_cell(cells["LABGEN-HS-0003"], matrix, runner=runner, **_probe_kwargs())
    assert (result.derived.verdict, result.oracle.confirmed_vulnerable) == ("VULNERABLE", True)


def test_join_alias_cell_is_confirmed_vulnerable(cells, matrix) -> None:
    inventory = _PAGE_PARAMS["/inventory.php"]
    runner = FakeHttpRunner(_ok("baseline"), _ok("a"), _ok("b"))
    result = assert_identifier_sqli_cell(
        cells["LABGEN-HS-0005"],
        matrix,
        runner=runner,
        **_probe_kwargs(
            param_name=inventory["param_name"],
            column_a=inventory["column_a"],
            column_b=inventory["column_b"],
        ),
    )
    assert result.matches is True
    assert result.oracle.confirmed_vulnerable is True


# ---------------------------------------------------------------------------
# Fail-closed paths
# ---------------------------------------------------------------------------


def test_a_vulnerable_cell_the_oracle_calls_secure_fails_the_build(cells, matrix) -> None:
    """The assertion's reason for existing: if the generated code does not
    actually demonstrate its label, the build must fail."""
    runner = FakeHttpRunner(_ok("same"), _ok("same"), _ok("same"))
    with pytest.raises(IdentifierSqliAssertionError, match="disagrees with the build-time oracle"):
        assert_identifier_sqli_cell(cells["LABGEN-HS-0001"], matrix, runner=runner, **_probe_kwargs())


def test_a_secure_cell_the_oracle_calls_vulnerable_fails_the_build(cells, matrix) -> None:
    runner = FakeHttpRunner(_ok("baseline"), _ok("differs"), _ok("other"))
    with pytest.raises(IdentifierSqliAssertionError, match="disagrees with the build-time oracle"):
        assert_identifier_sqli_cell(cells["LABGEN-HS-0004"], matrix, runner=runner, **_probe_kwargs())


def test_an_unreachable_target_never_passes_a_secure_cell(cells, matrix) -> None:
    """PA-0025, at the assertion layer: an inconclusive probe is never
    accepted as confirmation of either label."""
    runner = FakeHttpRunner((None, "", True), (None, "", True), (None, "", True))
    with pytest.raises(IdentifierSqliAssertionError, match="inconclusive"):
        assert_identifier_sqli_cell(cells["LABGEN-HS-0004"], matrix, runner=runner, **_probe_kwargs())


def test_the_charset_filtered_cell_is_the_documented_case_when_blind_spot(cells, matrix) -> None:
    """The gap this lane names explicitly rather than building around: the
    filter 400s the CASE-WHEN payload, so both probes come back unhealthy and
    the oracle (correctly) refuses to conclude. The assertion then fails
    closed and its message points at the documented cause -- it does *not*
    quietly pass the cell.

    Confirming this cell needs an identifier-*swap* differential (two bare,
    legal identifiers), which L-P1.2a's request shape cannot express.
    """
    runner = FakeHttpRunner(_ok("rows"), (400, "bad identifier", False), (400, "bad identifier", False))
    with pytest.raises(IdentifierSqliAssertionError) as excinfo:
        assert_identifier_sqli_cell(cells["LABGEN-HS-0002"], matrix, runner=runner, **_probe_kwargs())
    message = str(excinfo.value)
    assert "inconclusive" in message
    assert "identifier_charset_filter" in message
    assert "identifier-swap" in message


def test_two_identical_error_pages_are_never_read_as_secure(cells, matrix) -> None:
    runner = FakeHttpRunner(_ok("rows"), (500, "boom", False), (500, "boom", False))
    with pytest.raises(IdentifierSqliAssertionError, match="inconclusive"):
        assert_identifier_sqli_cell(cells["LABGEN-HS-0004"], matrix, runner=runner, **_probe_kwargs())


def test_a_non_loopback_target_is_refused_before_any_request(cells, matrix) -> None:
    """Lab-only, non-negotiable: the reused `oracle_wrapper.assert_loopback`
    fires before the runner is ever called."""
    from fuzzlab.labgen.oracle_wrapper import OracleSafetyError

    runner = FakeHttpRunner(_ok("a"), _ok("b"), _ok("c"))
    with pytest.raises(OracleSafetyError):
        assert_identifier_sqli_cell(
            cells["LABGEN-HS-0001"], matrix, runner=runner, **_probe_kwargs(target_base_url="http://example.com")
        )
    assert runner.urls == []


# ---------------------------------------------------------------------------
# Tier-2 adapter
# ---------------------------------------------------------------------------


def test_tier2_adapter_plugs_into_run_tier2_case(cells) -> None:
    from fuzzlab.labgen.conformance.tier1 import build_tier1_case
    from fuzzlab.labgen.conformance.tier2 import run_tier2_case

    case = build_tier1_case(
        cells["LABGEN-HS-0001"],
        param_name=CATALOG["param_name"],
        payload="(CASE WHEN (1=1) THEN name ELSE price END)",
        evidence_marker="unused-by-this-oracle",
        expected_vulnerable=True,
    )
    oracle = IdentifierSqliTier2Oracle(
        target_base_url=TARGET,
        column_a=CATALOG["column_a"],
        column_b=CATALOG["column_b"],
        runner=FakeHttpRunner(_ok("baseline"), _ok("true"), _ok("false")),
    )
    outcome = run_tier2_case(case, oracle)
    assert outcome.confirmed_vulnerable is True
    assert outcome.matches_expectation is True


def test_tier2_adapter_raises_rather_than_reporting_inconclusive_as_not_vulnerable(cells) -> None:
    """Tier 2's `confirm()` returns a bool, which cannot represent
    "inconclusive" -- collapsing it to False would be a fail-open."""
    from fuzzlab.labgen.conformance.tier1 import build_tier1_case

    case = build_tier1_case(
        cells["LABGEN-HS-0001"],
        param_name=CATALOG["param_name"],
        payload="x",
        evidence_marker="x",
        expected_vulnerable=True,
    )
    oracle = IdentifierSqliTier2Oracle(
        target_base_url=TARGET,
        column_a=CATALOG["column_a"],
        column_b=CATALOG["column_b"],
        runner=FakeHttpRunner((None, "", True), (None, "", True), (None, "", True)),
    )
    with pytest.raises(IdentifierSqliAssertionError, match="fail-open"):
        oracle.confirm(case)


def test_tier2_adapter_refuses_a_body_parameter_case() -> None:
    from fuzzlab.labgen.conformance.tier1 import Tier1Case

    case = Tier1Case(
        cell_id="LABGEN-HS-0001",
        method="POST",
        path="/catalog.php",
        param_name="sort",
        location="body",
        payload="x",
        evidence_marker="x",
        expected_vulnerable=True,
    )
    oracle = IdentifierSqliTier2Oracle(target_base_url=TARGET, column_a="name", column_b="price")
    with pytest.raises(IdentifierSqliAssertionError, match="query-string parameter"):
        oracle.confirm(case)


# ---------------------------------------------------------------------------
# Real, unmocked end-to-end pass (PA-0005): real HTTP, real default runner
# ---------------------------------------------------------------------------


_ROWS_BY_NAME = "alpha|beta|gamma\n"
_ROWS_BY_PRICE = "gamma|alpha|beta\n"


class _VulnerableCatalogHandler(http.server.BaseHTTPRequestHandler):
    """Models `/catalog.php?sort=` with no transform at all: the substituted
    expression really changes which ordering comes back."""

    def do_GET(self):
        sort = parse_qs(urlparse(self.path).query).get("sort", [""])[0]
        body = (_ROWS_BY_PRICE if "1=2" in sort else _ROWS_BY_NAME).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _AllowlistedCatalogHandler(http.server.BaseHTTPRequestHandler):
    """Models `/catalog.php?sort=` with `identifier_allowlist`: anything not
    in the allowlist collapses to the fallback identifier, so every
    identifier-shaped or CASE-WHEN value yields the same page."""

    _ALLOWED = CATALOG["allowed_identifiers"]

    def do_GET(self):
        sort = parse_qs(urlparse(self.path).query).get("sort", [""])[0]
        effective = sort if sort in self._ALLOWED else self._ALLOWED[0]
        body = (_ROWS_BY_PRICE if effective == "price" else _ROWS_BY_NAME).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _CharsetFilteredCatalogHandler(http.server.BaseHTTPRequestHandler):
    """Models `/catalog.php?sort=` with `identifier_charset_filter`: a bare
    identifier is served, anything else is rejected with an HTTP 400 --
    exactly the generated PHP's behavior, and the reason the CASE-WHEN
    differential cannot conclude here."""

    def do_GET(self):
        sort = parse_qs(urlparse(self.path).query).get("sort", [""])[0]
        if not sort.isidentifier():
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = (_ROWS_BY_PRICE if sort == "price" else _ROWS_BY_NAME).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(handler_cls):
    server = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _real_kwargs(port: int):
    return _probe_kwargs(target_base_url=f"http://127.0.0.1:{port}", timeout_s=5.0)


def test_real_end_to_end_vulnerable_cell_passes_its_build_assertion(cells, matrix) -> None:
    server, thread = _serve(_VulnerableCatalogHandler)
    try:
        result = assert_identifier_sqli_cell(
            cells["LABGEN-HS-0001"], matrix, **_real_kwargs(server.server_address[1])
        )
        assert result.derived.verdict == "VULNERABLE"
        assert result.oracle.confirmed_vulnerable is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_real_end_to_end_secure_cell_passes_its_build_assertion(cells, matrix) -> None:
    server, thread = _serve(_AllowlistedCatalogHandler)
    try:
        result = assert_identifier_sqli_cell(
            cells["LABGEN-HS-0004"], matrix, **_real_kwargs(server.server_address[1])
        )
        assert result.derived.verdict == "SECURE"
        assert result.oracle.confirmed_secure is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_real_end_to_end_charset_filtered_cell_is_inconclusive_not_silently_passed(cells, matrix) -> None:
    """The documented blind spot, reproduced against a real HTTP server
    behaving exactly as the generated PHP does."""
    server, thread = _serve(_CharsetFilteredCatalogHandler)
    try:
        with pytest.raises(IdentifierSqliAssertionError, match="inconclusive"):
            assert_identifier_sqli_cell(
                cells["LABGEN-HS-0002"], matrix, **_real_kwargs(server.server_address[1])
            )
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_real_end_to_end_unreachable_target_is_never_a_pass(cells, matrix) -> None:
    server = socketserver.TCPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
    port = server.server_address[1]
    server.server_close()
    with pytest.raises(IdentifierSqliAssertionError, match="inconclusive"):
        assert_identifier_sqli_cell(cells["LABGEN-HS-0004"], matrix, **_real_kwargs(port))
