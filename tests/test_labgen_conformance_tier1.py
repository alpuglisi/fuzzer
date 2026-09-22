"""Tier 1 interface/decision-logic tests (T-LAB0.7), plus (`CC-LAB-0060`/
`FR-LAB-56`) real live-boot-backed Tier-1 runs for the stack that already has
a real :class:`~fuzzlab.labgen.conformance.tier1.Tier1Client` implementation.

**Two halves, kept clearly distinct, per this module's own long-standing
convention:**

1. The original tests below never talk to a live app or a real database.
   `evaluate_tier1_response` is exercised against hand-written synthetic
   response bodies, and `run_tier1_case` is exercised against a
   `FakeTier1Client` test double that returns those same canned strings. A
   pass here proves the harness's own decision logic is coherent -- it is
   not, and must never be read as, a real vulnerability confirmation (see
   tier1.py's module docstring). The on-host-required guard
   (`run_tier1_case(case, client=None)`) is also asserted directly.
2. `TestTier1RealLiveBoot` below is the real thing for the one stack that
   currently has a real Tier1Client: `run_tier1_case`/`build_tier1_case`/
   `evaluate_tier1_response` are run against
   `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` -- a real,
   in-process Laravel build, booted for real with `php artisan serve`,
   answering real HTTP requests. This *is* a genuine Tier-1 result (a real
   app's observed behavior), though, per T-LAB0.7's own rule (restated in
   tier1.py's module docstring), it is still never Tier-2 oracle
   confirmation. Skip-guarded on `live_boot_available()` and marked
   `@pytest.mark.slow`, exactly like `tests/test_labgen_conformance_live_boot
   .py`'s own convention (a real `composer install` against Packagist) --
   this never touches the real, loopback-only lab target (D11); it is
   synthetic, in-sandbox, and does not need `--authorized`.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.conformance.tier1 import (
    OnHostRequiredError,
    Tier1Case,
    build_tier1_case,
    evaluate_tier1_response,
    run_tier1_case,
)
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


# ---------------------------------------------------------------------------
# Real live-boot-backed Tier-1 runs (`CC-LAB-0060`/`FR-LAB-56`).
#
# Everything below sends a real Tier1Case through run_tier1_case() against a
# real LiveBootHarness -- the first time this module's own public API
# (build_tier1_case/run_tier1_case/evaluate_tier1_response) has been proven
# against a genuinely running app+DB rather than a hand-written fake client.
# ---------------------------------------------------------------------------

pytestmark_live_boot = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)


@pytestmark_live_boot
class TestTier1RealLiveBoot:
    """Real Tier-1 checks, real app, real DB -- for the ``php_laravel``
    stack, the one stack with a real :class:`Tier1Client` implementation
    today (``LiveBootHarness``). Never touches the real, loopback-only lab
    target (D11) -- everything here assembles and boots its own throwaway,
    in-sandbox Laravel build, so no ``--authorized`` flag applies."""

    @pytest.mark.slow
    def test_product_sqli_numeric_twin_real_differential_via_run_tier1_case(self) -> None:
        """`product.php`'s vulnerable/secure twin (`LABGEN-RPL-PRODUCT` /
        `LABGEN-RPL-PRODUCT-BOUND`), the exact real-page pair
        `tests/test_labgen_conformance_live_boot.py`'s own numeric-manifest
        test proves a differential for -- but run here through
        `build_tier1_case`/`run_tier1_case`/`evaluate_tier1_response`
        themselves, not by hand-inspecting `harness.get()` responses
        directly. Both twins' real Tier1Outcome must match their manifest's
        own `expected_vulnerable` label.
        """
        manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_numeric.yaml")
        emitter = LaravelEmitter()
        cells = {c.cell_id: c for c in manifest.cells}
        vulnerable = cells["LABGEN-RPL-PRODUCT"]
        secure = cells["LABGEN-RPL-PRODUCT-BOUND"]

        # A boolean-injection payload that leaks every seeded row (including
        # the second product, "Puppy Bed") on the raw-concatenation cell,
        # and matches nothing extra on the bound-parameter cell -- the same
        # real differential the live_boot test module proves, now observed
        # through evaluate_tier1_response's own marker-in-body decision
        # logic rather than a bespoke row-count assertion.
        payload = "1 OR 1=1"
        evidence_marker = "Puppy Bed"

        with LiveBootHarness(emitter, list(manifest.cells)) as harness:
            vuln_case = Tier1Case(
                cell_id=vulnerable.cell_id,
                method=vulnerable.route.method,
                path=served_url_for(vulnerable),
                param_name="id",
                location="query",
                payload=payload,
                evidence_marker=evidence_marker,
                expected_vulnerable=True,
            )
            secure_case = Tier1Case(
                cell_id=secure.cell_id,
                method=secure.route.method,
                path=served_url_for(secure),
                param_name="id",
                location="query",
                payload=payload,
                evidence_marker=evidence_marker,
                expected_vulnerable=False,
            )

            vuln_outcome = run_tier1_case(vuln_case, harness)
            secure_outcome = run_tier1_case(secure_case, harness)

            assert vuln_outcome.vulnerable_detected is True, vuln_outcome.response_excerpt
            assert vuln_outcome.matches_expectation is True, vuln_outcome
            assert secure_outcome.vulnerable_detected is False, secure_outcome.response_excerpt
            assert secure_outcome.matches_expectation is True, secure_outcome

    @pytest.mark.slow
    def test_forms_manifest_escaped_xss_real_negative_via_run_tier1_case(self) -> None:
        """`contact.php`/`newsletter.php` (`LABGEN-PLRP-1005`/`1006`),
        secure-only escaped-echo forms: a real raw ``<script>`` payload must
        NOT survive unescaped in the real response body -- a real Tier-1
        negative (``expected_vulnerable=False``) via the module's own public
        API, for the one real-page group with no vulnerable twin at all.
        """
        manifest = load_manifest("lab/manifests/phase3_laravel_real_pages_forms.yaml")
        emitter = LaravelEmitter()
        cells = {c.cell_id: c for c in manifest.cells}
        contact = cells["LABGEN-PLRP-1005"]
        newsletter = cells["LABGEN-PLRP-1006"]
        marker = "<script>alert(1)</script>"

        with LiveBootHarness(emitter, list(manifest.cells)) as harness:
            for cell, param_name in ((contact, "message"), (newsletter, "email")):
                case = build_tier1_case(
                    cell,
                    param_name=param_name,
                    payload=marker,
                    evidence_marker=marker,
                    expected_vulnerable=False,
                )
                # served_url_for() is the same route-pinning rule the real
                # build's own routes/web.php is assembled from
                # (PA-0001/PA-0021) -- build_tier1_case() uses cell.route.path
                # directly, which is only correct here because neither cell
                # is a URL-relocated twin; overridden explicitly rather than
                # assumed, so a future twin variant cannot silently regress
                # this test to the wrong URL.
                case = Tier1Case(
                    cell_id=case.cell_id,
                    method=case.method,
                    path=served_url_for(cell),
                    param_name=case.param_name,
                    location=case.location,
                    payload=case.payload,
                    evidence_marker=case.evidence_marker,
                    expected_vulnerable=case.expected_vulnerable,
                )
                outcome = run_tier1_case(case, harness)
                assert outcome.vulnerable_detected is False, outcome.response_excerpt
                assert outcome.matches_expectation is True, outcome
