"""Tier 2 (container-based oracle) tests (T-LAB0.7, ``CC-LAB-0061``).

Two groups, kept clearly separate:

1. **Offline interface tests** (`_FakeTier2Oracle`) -- prove (a)
   `run_tier2_case` refuses to run without a real oracle
   (`OnHostRequiredError`), and (b) its result-plumbing is wired correctly
   given a test double. Neither is, or should ever be read as, a live
   confirmation.
2. **Real, on-host, skip-guarded tests** for `LiveBootTier2Oracle`
   (`@pytest.mark.slow`, gated on
   `fuzzlab.labgen.conformance.live_boot.live_boot_available()`) -- these
   assemble, install, and boot a REAL synthetic ``php_laravel`` app (the
   same in-sandbox live-boot harness `CC-LAB-0054` proved for Tier 1) and
   run `LiveBootTier2Oracle` against it for real. This is a genuine, real
   confirmation of `LiveBootTier2Oracle`'s own narrower claim (see
   `tier2.py`'s module docstring) -- it is **never** the real, loopback-only
   Ryder's Puppy Fort Factory lab target, never requires ``--authorized``
   (D11/CLAUDE.md Safety), and it is still not the production-grade,
   dialect-sensitive, container-based oracle T-LAB0.7 describes (that stays
   `IdentifierSqliTier2Oracle`'s/a future real-target oracle's job).
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.conformance.tier1 import OnHostRequiredError, Tier1Case, build_tier1_case
from fuzzlab.labgen.conformance.tier2 import LiveBootTier2Oracle, run_tier2_case
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest

_PRODUCT_CELL = Cell(
    cell_id="LABGEN-RP-0001",
    vuln_class="sqli",
    stack_profile="php_current",
    route=Route(method="GET", path="/product.php"),
    sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list([]),
)


# ---------------------------------------------------------------------------
# 1. Offline interface tests -- no real oracle, no network, no live app.
# ---------------------------------------------------------------------------


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
    (e.g. a sqlmap/commix/SSTImap/ZAP wrapper, or `LiveBootTier2Oracle`
    below). Proves `run_tier2_case`'s own plumbing only -- this is not, and
    must never be presented as, a real confirmation."""

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


class _FakeTier2Client:
    """A synthetic test double for `LiveBootTier2Oracle`'s `Tier2Client`
    dependency -- returns canned per-value bodies, never a real HTTP
    response. Used only to exercise `LiveBootTier2Oracle`'s own control/
    payload differential logic offline, before trusting it against a real
    live-boot below."""

    class _Resp:
        def __init__(self, body: str) -> None:
            self.status = 200
            self.body = body

    def __init__(self, bodies_by_value: dict[str, str]) -> None:
        self._bodies_by_value = bodies_by_value

    def get(self, path: str, *, params: dict[str, str] | None = None):  # noqa: ARG002
        value = next(iter((params or {}).values()))
        return self._Resp(self._bodies_by_value[value])

    def post(self, path: str, *, data: dict[str, str] | None = None):  # noqa: ARG002
        value = next(iter((data or {}).values()))
        return self._Resp(self._bodies_by_value[value])


def _sqli_case(*, expected_vulnerable: bool) -> Tier1Case:
    return build_tier1_case(
        _PRODUCT_CELL,
        param_name="id",
        payload="1 OR 1=1",
        evidence_marker="Puppy Bed",
        expected_vulnerable=expected_vulnerable,
    )


def test_live_boot_tier2_oracle_confirms_when_marker_present_only_in_payload_response() -> None:
    case = _sqli_case(expected_vulnerable=True)
    client = _FakeTier2Client({
        "1 OR 1=1": "... Chew Toy ... Puppy Bed ...",  # both rows leaked
        "1": "... Chew Toy ...",  # control: only the matching row
    })
    oracle = LiveBootTier2Oracle(client, control_value="1")
    confirmed, detail = oracle.confirm(case)
    assert confirmed is True
    assert "confirmed" in detail


def test_live_boot_tier2_oracle_does_not_confirm_when_marker_absent_from_payload_response() -> None:
    case = _sqli_case(expected_vulnerable=False)
    client = _FakeTier2Client({
        "1 OR 1=1": "... Chew Toy ...",  # bound param: no differential
        "1": "... Chew Toy ...",
    })
    oracle = LiveBootTier2Oracle(client, control_value="1")
    confirmed, detail = oracle.confirm(case)
    assert confirmed is False
    assert "not confirmed" in detail


def test_live_boot_tier2_oracle_reports_inconclusive_when_control_already_shows_the_marker() -> None:
    """A control value that itself produces the marker cannot distinguish
    "vulnerable" from "the app always shows this" -- the oracle must fail
    closed (PA-0025), never guess a verdict from an ambiguous control."""
    case = _sqli_case(expected_vulnerable=True)
    client = _FakeTier2Client({
        "1 OR 1=1": "... Chew Toy ... Puppy Bed ...",
        "1": "... Chew Toy ... Puppy Bed ...",  # bad control: already shows the marker
    })
    oracle = LiveBootTier2Oracle(client, control_value="1")
    confirmed, detail = oracle.confirm(case)
    assert confirmed is False
    assert "inconclusive" in detail


def test_run_tier2_case_wires_live_boot_tier2_oracle_through() -> None:
    """`run_tier2_case`'s own plumbing exercised with `LiveBootTier2Oracle`
    itself (still against a fake `Tier2Client`, not a real boot) -- proves
    the real oracle class integrates with the existing `run_tier2_case`
    contract, distinct from the fully-fake-oracle tests above."""
    case = _sqli_case(expected_vulnerable=True)
    client = _FakeTier2Client({
        "1 OR 1=1": "... Chew Toy ... Puppy Bed ...",
        "1": "... Chew Toy ...",
    })
    oracle = LiveBootTier2Oracle(client, control_value="1")
    outcome = run_tier2_case(case, oracle)
    assert outcome.confirmed_vulnerable is True
    assert outcome.matches_expectation is True


# ---------------------------------------------------------------------------
# 2. Real, on-host, skip-guarded live-boot tests.
# ---------------------------------------------------------------------------

pytestmark_live = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)


@pytestmark_live
@pytest.mark.slow
def test_live_boot_tier2_oracle_confirms_the_real_vulnerable_numeric_twin() -> None:
    """`product.php`'s real raw-concatenation cell (`LABGEN-RPL-PRODUCT`):
    `LiveBootTier2Oracle`, driven against a genuinely booted `php_laravel`
    app, reports a real confirmed differential for the classic `1 OR 1=1`
    boolean-injection payload -- the seeded second product name
    ("Puppy Bed") leaks into the payload response but never into the
    control response for a normal, single-row id ("1")."""
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_numeric.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-RPL-PRODUCT"]

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        url = served_url_for(vulnerable)
        assert url == "/product.php"
        case = Tier1Case(
            cell_id=vulnerable.cell_id,
            method="GET",
            path=url,
            param_name="id",
            location="query",
            payload="1 OR 1=1",
            evidence_marker="Puppy Bed",
            expected_vulnerable=True,
        )
        oracle = LiveBootTier2Oracle(harness, control_value="1")
        outcome = run_tier2_case(case, oracle)
        assert outcome.confirmed_vulnerable is True, outcome.oracle_detail
        assert outcome.matches_expectation is True, outcome.oracle_detail


@pytestmark_live
@pytest.mark.slow
def test_live_boot_tier2_oracle_does_not_confirm_the_real_secure_numeric_twin() -> None:
    """The same `1 OR 1=1` payload against `product.php`'s real
    bound-parameter twin (`LABGEN-RPL-PRODUCT-BOUND`): the oracle reports a
    real, negative confirmation -- the seeded second product never leaks,
    matching this cell's own `expected_vulnerable=False` label."""
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_numeric.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    secure = cells["LABGEN-RPL-PRODUCT-BOUND"]

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        url = served_url_for(secure)
        case = Tier1Case(
            cell_id=secure.cell_id,
            method="GET",
            path=url,
            param_name="id",
            location="query",
            payload="1 OR 1=1",
            evidence_marker="Puppy Bed",
            expected_vulnerable=False,
        )
        oracle = LiveBootTier2Oracle(harness, control_value="1")
        outcome = run_tier2_case(case, oracle)
        assert outcome.confirmed_vulnerable is False, outcome.oracle_detail
        assert outcome.matches_expectation is True, outcome.oracle_detail
