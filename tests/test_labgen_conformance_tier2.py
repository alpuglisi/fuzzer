"""Tier 2 (container-based oracle) interface tests (T-LAB0.7).

**No real oracle exists or is invoked here.** These tests only prove (a)
`run_tier2_case` refuses to run without a real oracle
(`OnHostRequiredError`), and (b) its result-plumbing is wired correctly
given a test double. Neither is, or should ever be read as, a live
container-based confirmation -- see tier2.py's own module docstring.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.tier1 import OnHostRequiredError, build_tier1_case
from fuzzlab.labgen.conformance.tier2 import run_tier2_case
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

_PRODUCT_CELL = Cell(
    cell_id="LABGEN-RP-0001",
    vuln_class="sqli",
    stack_profile="php_current",
    route=Route(method="GET", path="/product.php"),
    sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list([]),
)


def test_run_tier2_case_without_an_oracle_raises_on_host_required() -> None:
    case = build_tier1_case(
        _PRODUCT_CELL,
        param_name="id",
        payload="1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)",
        evidence_marker="n/a",
        expected_vulnerable=True,
    )
    with pytest.raises(OnHostRequiredError):
        run_tier2_case(case, oracle=None)


class _FakeTier2Oracle:
    """A test double standing in for a real container-based oracle
    (e.g. a sqlmap/commix/SSTImap/ZAP wrapper). Proves run_tier2_case's own
    plumbing only -- this is not, and must never be presented as, a real
    confirmation."""

    def __init__(self, confirmed: bool, detail: str) -> None:
        self._confirmed = confirmed
        self._detail = detail

    def confirm(self, case) -> tuple[bool, str]:  # noqa: ANN001 - test double, case unused
        return self._confirmed, self._detail


def test_run_tier2_case_wires_a_fake_oracle_through() -> None:
    case = build_tier1_case(
        _PRODUCT_CELL,
        param_name="id",
        payload="1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)",
        evidence_marker="n/a",
        expected_vulnerable=True,
    )
    oracle = _FakeTier2Oracle(confirmed=True, detail="time-based delay observed (fake)")
    outcome = run_tier2_case(case, oracle)
    assert outcome.confirmed_vulnerable is True
    assert outcome.matches_expectation is True
    assert "fake" in outcome.oracle_detail


def test_run_tier2_case_flags_a_mismatch_between_oracle_and_expectation() -> None:
    case = build_tier1_case(
        _PRODUCT_CELL,
        param_name="id",
        payload="1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)",
        evidence_marker="n/a",
        expected_vulnerable=True,
    )
    oracle = _FakeTier2Oracle(confirmed=False, detail="no delay observed (fake)")
    outcome = run_tier2_case(case, oracle)
    assert outcome.confirmed_vulnerable is False
    assert outcome.matches_expectation is False
