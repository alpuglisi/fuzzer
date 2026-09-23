"""Phase E: wire Booking.com (`php_laravel`, category 5's Booking.com pick)
into `fuzzlab.harness.multitarget` as its own real `TargetSpec`
(`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6/§9.4, `CC-LAB-0217`).

Runs the real thing end to end: a real `composer install` + `artisan
serve` boot of the whole assembled app (all three of Booking.com's
vulnerable cells at once -- each already has its own unique `/cell/<slug>`
URL via `served_url_for()`, so there is no same-route collision to avoid
booting them together), a real
`fuzzlab.tools.probesender.RequestsProbeSender` sending real HTTP over the
loopback socket, and `fuzzlab.harness.multitarget.run_targets`/
`transfer_summary` run against it for real.

Reuses `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` directly
(same shape as `tests/test_labgen_php_laravel_huddlehub_multitarget.py`,
which explicitly cites this app's own established convention): this
harness already accepts a **list** of cells with no single-cell
restriction, so no extension was needed here.

**Recall is 3/3 -- all of Booking.com's own ground truth genuinely
detects.** `open_redirect` (`CC-CORE-0021`/`FR-CORE-11`),
`price_integrity_bypass` (`CC-FUZZ-0029`), and `csv_formula_injection`
(`CC-FUZZ-0030`) each have a genuinely new or reused, live-verified
rule+strategy pair, mapped into `fuzzlab.core.runmode._VULN_TO_CATEGORY`.
This closes Booking.com's own toolkit-side detection coverage for this
pilot -- no honestly-unmapped class remains for this app.

Skip-guarded on `live_boot_available()` (PA-0005). Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.probesender import RequestsProbeSender

pytestmark = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)

GT_DIR = "lab/ground-truth-booking-clone"
MANIFESTS = (
    "lab/manifests/booking_open_redirect_sample.yaml",
    "lab/manifests/booking_csv_export_sample.yaml",
    "lab/manifests/booking_price_integrity_sample.yaml",
)
#: Only the vulnerable half of each cell pair -- ground truth (`CC-LAB-
#: 0210`/`0211`/`0212`) describes exactly this three-cell, all-vulnerable
#: deployment, matching Huddle Hub's own established convention.
VULNERABLE_CELL_IDS = {"LABGEN-BC-0001", "LABGEN-BC-0003", "LABGEN-BC-0005"}


def _vulnerable_cells():
    return [c for m in MANIFESTS for c in load_manifest(m).cells if c.cell_id in VULNERABLE_CELL_IDS]


@pytest.mark.slow
def test_booking_target_spec_runs_for_real_and_scores(tmp_path) -> None:
    cells = _vulnerable_cells()
    assert {c.cell_id for c in cells} == VULNERABLE_CELL_IDS
    emitter = LaravelEmitter()
    gt = contract.load(GT_DIR)

    with LiveBootHarness(emitter, cells) as harness:
        base_url = harness._base_url()  # noqa: SLF001 - see huddlehub's own
        # precedent (CC-LAB-0139's docstring) for this exact same-module
        # private-attribute-access pattern; this harness has no public
        # base-url accessor of its own, unlike SpringBootLiveBootHarness.

        spec = TargetSpec(
            name="php_laravel_booking", base_url=base_url,
            ground_truth=gt, points_source="ground-truth",
        )
        with Store(tmp_path / "u.db") as store:
            outcomes = run_targets([spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
            assert [o.name for o in outcomes] == ["php_laravel_booking"]
            outcome = outcomes[0]
            # Real target, real ground truth -> a real, scored report (D14: automatic
            # mode + ground truth is always scored, regardless of tp count).
            # `open_redirect` (`CC-CORE-0021`/`FR-CORE-11`, BKNG-0001),
            # `price_integrity_bypass` (`CC-FUZZ-0029`, BKNG-0003), and
            # `csv_formula_injection` (`CC-FUZZ-0030`, BKNG-0002) all
            # genuinely detect now -- Booking.com's own full ground truth,
            # zero false negatives.
            assert outcome.scored is True
            assert outcome.report is not None
            assert outcome.report.tp == 3 and outcome.report.fn == 0
            assert outcome.report.fp == 0
            assert outcome.report.recall == 1.0

            summary = transfer_summary(outcomes)
            assert summary["targets"] == 1
            assert "macro_precision" in summary and "macro_recall" in summary
            assert summary["generalizes"] is False


@pytest.mark.slow
def test_booking_endpoints_are_really_live() -> None:
    """Confirms the booted app is genuinely the real Booking.com build (not
    an empty skeleton `run_targets` merely failed to reach) -- a real,
    direct HTTP round trip against all three cells' own real payload
    differential, independent of the scoring path above."""
    cells = _vulnerable_cells()
    emitter = LaravelEmitter()

    with LiveBootHarness(emitter, cells) as harness:
        from fuzzlab.labgen.emitters.php_laravel import served_url_for

        redirect_cell = next(c for c in cells if c.cell_id == "LABGEN-BC-0001")
        resp = harness.get(served_url_for(redirect_cell), params={"return_to": "//evil.example"})
        assert resp.status in (301, 302, 303, 307, 308), resp.body
        assert "evil.example" in resp.headers.get("Location", ""), resp.headers

        csv_cell = next(c for c in cells if c.cell_id == "LABGEN-BC-0003")
        resp = harness.get(served_url_for(csv_cell), params={"label": "=cmd|'/c calc'!A1"})
        assert resp.status == 200, resp.body
        assert "=cmd|" in resp.body, resp.body

        price_cell = next(c for c in cells if c.cell_id == "LABGEN-BC-0005")
        resp = harness.post(served_url_for(price_cell), data={"amount": "0.01"})
        assert resp.status == 200, resp.body
        assert '"charged_amount":"0.01"' in resp.body.replace(" ", ""), resp.body
