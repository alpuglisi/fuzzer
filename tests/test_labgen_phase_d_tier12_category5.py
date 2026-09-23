"""Phase D -- Tier 1/2 conformance for category 5's currently-built cells
(`CC-LAB-0216`/`FR-LAB-117`). Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`
§5: "run the proof," using each shape's own live-boot harness as the real,
in-process `Tier1Client`/`Tier2Client` this project's shared
`fuzzlab.labgen.conformance.tier1`/`tier2` modules need -- never a new,
stack-specific proof mechanism. Mirrors
`tests/test_labgen_phase_d_tier12_category4.py`'s own structure exactly.

**Three of this category's four built shapes fit Tier 1/2's marker-in-
response-body model cleanly (`csv_formula_injection`, `price_integrity_
bypass`, `spel_injection`); the fourth (`open_redirect`) genuinely does
not, and is not forced into it here.** `open_redirect`'s own evidence is
the `Location` *response header*, never the response body -- the exact
class of shape `evaluate_tier1_response`'s "marker appears in
`response_body`" model cannot express (confirmed by re-reading
`tests/test_labgen_open_redirect.py::test_live_boot_redirect_manifest_
blocks_the_bypass_shapes_the_allowlist_is_meant_to_catch`, which checks
`resp.headers.get("Location", "")`, never `resp.body`). Same honesty
rule category 4's own Phase D file already established for its webhook-
signature cell's timing side-channel: an open question recorded here
and in `FR-LAB-117`, not a todo silently worked around.
"""

from __future__ import annotations

import dataclasses

import pytest

from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.conformance.tier1 import Tier1Case, build_tier1_case, run_tier1_case
from fuzzlab.labgen.conformance.tier2 import LiveBootTier2Oracle, run_tier2_case
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.slow


# -- CSV formula injection (php_laravel, LABGEN-BC-0003/0004) ---------------

_CSV_MANIFEST = "lab/manifests/booking_csv_export_sample.yaml"
_CSV_TRIGGER_PAYLOAD = "=cmd|'/c calc'!A1"
_CSV_CONTROL_VALUE = "ordinary label"
#: The secure twin's fix *prefixes* a single quote rather than stripping
#: the trigger character -- the raw payload text alone therefore still
#: appears verbatim in BOTH twins' bodies (`'=cmd|...` still contains
#: `=cmd|...` as a substring) and cannot serve as `evidence_marker` on its
#: own. Including the newline that immediately precedes the CSV cell's
#: value distinguishes them: the vulnerable twin's row starts `\n=cmd|`
#: (no quote), the secure twin's starts `\n'=cmd|` (quote inserted) --
#: only the former contains this exact substring.
_CSV_EVIDENCE_MARKER = "\n" + _CSV_TRIGGER_PAYLOAD


def _tier1_case_at_served_url(
    cell, *, param_name: str, payload: str, evidence_marker: str, expected_vulnerable: bool
) -> Tier1Case:
    """`build_tier1_case` defaults `path` to `cell.route.path` -- the
    *literal* manifest route, which both twins of a `php_laravel` pair
    share (per `served_url_for`'s own docstring, the actual served URL is
    `/cell/<slug>`, unique per cell) -- so both twins can be booted
    together in one `LiveBootHarness` (this stack's own established
    convention, e.g. `tests/test_labgen_price_integrity.py`), never one
    boot per twin the way `spring_boot`'s own one-cell-per-route model
    needs. Overrides `path` to the real served URL after building."""
    case = build_tier1_case(
        cell, param_name=param_name, payload=payload,
        evidence_marker=evidence_marker, expected_vulnerable=expected_vulnerable,
    )
    return dataclasses.replace(case, path=served_url_for(cell))


@pytest.mark.skipif(not live_boot_available(), reason="php/composer live-boot harness not available (PA-0005)")
def test_csv_formula_injection_tier1_and_tier2_confirm_both_twins() -> None:
    manifest = load_manifest(_CSV_MANIFEST)
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    cases = {
        "LABGEN-BC-0003": _tier1_case_at_served_url(  # vulnerable: raw_concat
            cells["LABGEN-BC-0003"], param_name="label", payload=_CSV_TRIGGER_PAYLOAD,
            evidence_marker=_CSV_EVIDENCE_MARKER, expected_vulnerable=True,
        ),
        "LABGEN-BC-0004": _tier1_case_at_served_url(  # secure: csv_formula_neutralize
            cells["LABGEN-BC-0004"], param_name="label", payload=_CSV_TRIGGER_PAYLOAD,
            evidence_marker=_CSV_EVIDENCE_MARKER, expected_vulnerable=False,
        ),
    }
    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        for cell_id, case in cases.items():
            tier1 = run_tier1_case(case, harness)
            assert tier1.matches_expectation, (
                f"{cell_id}: Tier 1 mismatch -- expected_vulnerable={case.expected_vulnerable}, "
                f"detected={tier1.vulnerable_detected}, body={tier1.response_excerpt!r}"
            )
            oracle = LiveBootTier2Oracle(client=harness, control_value=_CSV_CONTROL_VALUE)
            tier2 = run_tier2_case(case, oracle)
            assert tier2.matches_expectation, (
                f"{cell_id}: Tier 2 mismatch -- expected_vulnerable={case.expected_vulnerable}, "
                f"confirmed={tier2.confirmed_vulnerable}, detail={tier2.oracle_detail!r}"
            )


# -- Price integrity (php_laravel, LABGEN-BC-0005/0006) ---------------------

_PRICE_MANIFEST = "lab/manifests/booking_price_integrity_sample.yaml"
_ATTACKER_AMOUNT = "0.01"
_CONTROL_AMOUNT = "12.34"  # an ordinary, non-canonical amount that neither
# twin's own real rate table (89.00/149.00/249.00) would ever produce --
# never itself able to appear as evidence_marker on either twin.


@pytest.mark.skipif(not live_boot_available(), reason="php/composer live-boot harness not available (PA-0005)")
def test_price_integrity_tier1_and_tier2_confirm_both_twins() -> None:
    manifest = load_manifest(_PRICE_MANIFEST)
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    cases = {
        "LABGEN-BC-0005": _tier1_case_at_served_url(  # vulnerable: client_trusted_amount
            cells["LABGEN-BC-0005"], param_name="amount", payload=_ATTACKER_AMOUNT,
            evidence_marker=_ATTACKER_AMOUNT, expected_vulnerable=True,
        ),
        "LABGEN-BC-0006": _tier1_case_at_served_url(  # secure: server_recomputed_amount
            cells["LABGEN-BC-0006"], param_name="amount", payload=_ATTACKER_AMOUNT,
            evidence_marker=_ATTACKER_AMOUNT, expected_vulnerable=False,
        ),
    }
    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        for cell_id, case in cases.items():
            tier1 = run_tier1_case(case, harness)
            assert tier1.matches_expectation, (
                f"{cell_id}: Tier 1 mismatch -- expected_vulnerable={case.expected_vulnerable}, "
                f"detected={tier1.vulnerable_detected}, body={tier1.response_excerpt!r}"
            )
            oracle = LiveBootTier2Oracle(client=harness, control_value=_CONTROL_AMOUNT)
            tier2 = run_tier2_case(case, oracle)
            assert tier2.matches_expectation, (
                f"{cell_id}: Tier 2 mismatch -- expected_vulnerable={case.expected_vulnerable}, "
                f"confirmed={tier2.confirmed_vulnerable}, detail={tier2.oracle_detail!r}"
            )


# -- SpEL injection (spring_boot, LABGEN-EXP-0001/0002) ----------------------

_SPEL_MANIFEST = "lab/manifests/expedia_spel_injection_sample.yaml"
_TYPE_REFERENCE_CANARY = "T(java.lang.Math).abs(-99)"
_SPEL_CONTROL_VALUE = "'price'"  # a benign, legitimate property-path
# expression -- both twins evaluate it successfully, so it can never
# itself produce the "99" evidence_marker on either twin.


class _SpringBootSpelTier12Client:
    """A minimal `Tier1Client`/`Tier2Client` adapter over
    `SpringBootLiveBootHarness`'s existing (unmodified) `get()` method --
    this shape is GET/query-only, mirroring `_GoSsrfTier12Client`'s own
    shape from category 4's Phase D file."""

    def __init__(self, harness: SpringBootLiveBootHarness) -> None:
        self._harness = harness

    def get(self, path: str, *, params: dict[str, str] | None = None):
        return self._harness.get(path, params=params)

    def fetch(self, case: Tier1Case) -> str:
        assert case.location == "query"
        return self.get(case.path, params={case.param_name: case.payload}).body


@pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason="live-boot harness requires java + mvn on PATH and real Maven Central reachability (PA-0005)",
)
def test_spel_injection_tier1_and_tier2_confirm_vulnerable_twin() -> None:
    manifest = load_manifest(_SPEL_MANIFEST)
    emitter = SpringBootEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    case = build_tier1_case(
        cells["LABGEN-EXP-0001"], param_name="sortBy", payload=_TYPE_REFERENCE_CANARY,
        evidence_marker="99", expected_vulnerable=True,
    )
    with SpringBootLiveBootHarness(emitter, cells["LABGEN-EXP-0001"]) as harness:
        client = _SpringBootSpelTier12Client(harness)
        tier1 = run_tier1_case(case, client)
        assert tier1.matches_expectation, (
            f"Tier 1 mismatch on the vulnerable twin: detected={tier1.vulnerable_detected}, "
            f"body={tier1.response_excerpt!r}"
        )
        oracle = LiveBootTier2Oracle(client=client, control_value=_SPEL_CONTROL_VALUE)
        tier2 = run_tier2_case(case, oracle)
        assert tier2.matches_expectation, (
            f"Tier 2 mismatch on the vulnerable twin: confirmed={tier2.confirmed_vulnerable}, "
            f"detail={tier2.oracle_detail!r}"
        )


@pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason="live-boot harness requires java + mvn on PATH and real Maven Central reachability (PA-0005)",
)
def test_spel_injection_tier1_and_tier2_confirm_secure_twin() -> None:
    manifest = load_manifest(_SPEL_MANIFEST)
    emitter = SpringBootEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    case = build_tier1_case(
        cells["LABGEN-EXP-0002"], param_name="sortBy", payload=_TYPE_REFERENCE_CANARY,
        evidence_marker="99", expected_vulnerable=False,
    )
    with SpringBootLiveBootHarness(emitter, cells["LABGEN-EXP-0002"]) as harness:
        client = _SpringBootSpelTier12Client(harness)
        tier1 = run_tier1_case(case, client)
        assert tier1.matches_expectation, (
            f"Tier 1 mismatch on the secure twin: detected={tier1.vulnerable_detected}, "
            f"body={tier1.response_excerpt!r}"
        )
        oracle = LiveBootTier2Oracle(client=client, control_value=_SPEL_CONTROL_VALUE)
        tier2 = run_tier2_case(case, oracle)
        assert tier2.matches_expectation, (
            f"Tier 2 mismatch on the secure twin: confirmed={tier2.confirmed_vulnerable}, "
            f"detail={tier2.oracle_detail!r}"
        )
