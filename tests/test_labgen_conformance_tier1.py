"""Tier 1 interface/decision-logic tests (T-LAB0.7).

**These tests never talk to a live app or a real database.**
`evaluate_tier1_response` is exercised against hand-written synthetic
response bodies, and `run_tier1_case` is exercised against a `FakeTier1Client`
test double that returns those same canned strings. A pass here proves the
harness's own decision logic is coherent -- it is not, and must never be
read as, a real vulnerability confirmation (see tier1.py's module
docstring). The on-host-required guard (`run_tier1_case(case, client=None)`)
is also asserted directly.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.tier1 import (
    OnHostRequiredError,
    Tier1Case,
    build_tier1_case,
    evaluate_tier1_response,
    run_tier1_case,
)
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

_PRODUCT_CELL = Cell(
    cell_id="LABGEN-RP-0001",
    vuln_class="sqli",
    stack_profile="php_current",
    route=Route(method="GET", path="/product.php"),
    sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list([]),
)

_LOGIN_CELL = Cell(
    cell_id="LABGEN-RP-0005",
    vuln_class="sqli",
    stack_profile="php_current",
    route=Route(method="POST", path="/login.php"),
    sink_context=SinkContext(family="sql_string_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list([]),
)


def test_build_tier1_case_derives_query_location_from_get() -> None:
    case = build_tier1_case(
        _PRODUCT_CELL,
        param_name="id",
        payload="1 OR 1=1",
        evidence_marker="SQL syntax error",
        expected_vulnerable=True,
    )
    assert case.location == "query"
    assert case.method == "GET"
    assert case.path == "/product.php"


def test_build_tier1_case_derives_body_location_from_post() -> None:
    case = build_tier1_case(
        _LOGIN_CELL,
        param_name="username",
        payload="admin' -- -",
        evidence_marker="Welcome back",
        expected_vulnerable=True,
    )
    assert case.location == "body"
    assert case.method == "POST"


def test_evaluate_tier1_response_detects_the_evidence_marker() -> None:
    case = Tier1Case(
        cell_id="X",
        method="GET",
        path="/product.php",
        param_name="id",
        location="query",
        payload="1 AND (SELECT 1 FROM (SELECT(SLEEP(0)))x)",
        evidence_marker="You have an error in your SQL syntax",
        expected_vulnerable=True,
    )
    outcome = evaluate_tier1_response(case, "... You have an error in your SQL syntax near ...")
    assert outcome.vulnerable_detected is True
    assert outcome.matches_expectation is True


def test_evaluate_tier1_response_absent_marker_matches_a_secure_expectation() -> None:
    case = Tier1Case(
        cell_id="X-secure",
        method="GET",
        path="/product.php",
        param_name="id",
        location="query",
        payload="1 OR 1=1",
        evidence_marker="You have an error in your SQL syntax",
        expected_vulnerable=False,
    )
    outcome = evaluate_tier1_response(case, "<html>Product not found</html>")
    assert outcome.vulnerable_detected is False
    assert outcome.matches_expectation is True


def test_evaluate_tier1_response_flags_a_mismatch() -> None:
    case = Tier1Case(
        cell_id="X-mismatch",
        method="GET",
        path="/product.php",
        param_name="id",
        location="query",
        payload="1 OR 1=1",
        evidence_marker="You have an error in your SQL syntax",
        expected_vulnerable=False,
    )
    # Secure cell shouldn't show the error marker; if it does, that's a
    # real mismatch this harness must surface, not swallow.
    outcome = evaluate_tier1_response(case, "... You have an error in your SQL syntax near ...")
    assert outcome.vulnerable_detected is True
    assert outcome.matches_expectation is False


def test_run_tier1_case_without_a_client_raises_on_host_required() -> None:
    case = build_tier1_case(
        _PRODUCT_CELL,
        param_name="id",
        payload="1 OR 1=1",
        evidence_marker="error",
        expected_vulnerable=True,
    )
    with pytest.raises(OnHostRequiredError):
        run_tier1_case(case, client=None)


class _FakeTier1Client:
    """A synthetic test double -- not a real app/DB. Returns a canned body
    mirroring what the real vulnerable/secure php_current output would
    plausibly produce, purely to exercise run_tier1_case's wiring."""

    def __init__(self, body: str) -> None:
        self._body = body

    def fetch(self, case: Tier1Case) -> str:  # noqa: ARG002 - case unused by this simple double
        return self._body


def test_run_tier1_case_wires_a_fake_client_through_to_evaluate_tier1_response() -> None:
    case = build_tier1_case(
        _PRODUCT_CELL,
        param_name="id",
        payload="1 AND (SELECT 1 FROM (SELECT(SLEEP(0)))x)",
        evidence_marker="You have an error in your SQL syntax",
        expected_vulnerable=True,
    )
    client = _FakeTier1Client("... You have an error in your SQL syntax near ...")
    outcome = run_tier1_case(case, client)
    assert outcome.vulnerable_detected is True
    assert outcome.matches_expectation is True
