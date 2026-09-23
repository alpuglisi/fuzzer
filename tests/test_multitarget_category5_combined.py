"""Category 5 (Travel/booking/marketplaces) §6 step 2: run both Phase E
`TargetSpec`s (Booking.com/`php_laravel`, `CC-LAB-0217`; Expedia/
`spring_boot`, `CC-LAB-0218`) through a single
`fuzzlab.harness.multitarget.run_targets` call -- the one remaining item
both apps' own individual Phase E tests flag as "not mine to do" (see
`tests/test_labgen_php_laravel_booking_multitarget.py` and
`tests/test_labgen_spring_boot_expedia_multitarget.py`, each of which only
proves its own app's wiring in isolation), mirroring category 3's own
combined test (`tests/test_multitarget_category3_combined.py`).

Simpler than category 3's own combined test: neither app here needs a
hand-rolled multi-cell boot fixture (Expedia's own ground truth is a
single cell, so `SpringBootLiveBootHarness`'s single-cell restriction is
not a limitation; Booking.com's `LiveBootHarness` already accepts a list
of cells natively) -- both harnesses are used directly as context
managers.

This closes the toolkit-side half of category 5's own Phase 10 `T10.6`-
style proof: `fuzzlab/harness/multitarget.py` actually accepting two real,
distinct, locally-booted second targets in one call and producing a real
combined `transfer_summary`. **`generalizes` is `True`** -- `open_redirect`
genuinely detects on Booking.com (`CC-CORE-0021`/`FR-CORE-11`, recall
1/3) and `spel_injection` genuinely detects on Expedia (`CC-FUZZ-0028`,
recall 1/1); `transfer_summary`'s own `generalizes` rule (`>= 2` scored
targets with `recall > 0`) is satisfied by two *independently* mapped
classes on two different stacks (PHP/Laravel and Java/Spring Boot), a
real cross-target result, not a coincidence of one class counted twice.
`csv_formula_injection`/`price_integrity_bypass` (Booking.com) remain
honestly unmapped -- no verified confirmer exists for either yet.

Skip-guarded on both `spring_boot_boot_available()` and
`live_boot_available()` (PA-0005/PA-0035). Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.probesender import RequestsProbeSender

BOOKING_GT_DIR = "lab/ground-truth-booking-clone"
BOOKING_MANIFESTS = (
    "lab/manifests/booking_open_redirect_sample.yaml",
    "lab/manifests/booking_csv_export_sample.yaml",
    "lab/manifests/booking_price_integrity_sample.yaml",
)
BOOKING_VULNERABLE_CELL_IDS = {"LABGEN-BC-0001", "LABGEN-BC-0003", "LABGEN-BC-0005"}

EXPEDIA_GT_DIR = "lab/ground-truth-expedia-clone"
EXPEDIA_MANIFEST = "lab/manifests/expedia_spel_injection_sample.yaml"
EXPEDIA_VULNERABLE_CELL_ID = "LABGEN-EXP-0001"


def _booking_cells():
    return [c for m in BOOKING_MANIFESTS for c in load_manifest(m).cells if c.cell_id in BOOKING_VULNERABLE_CELL_IDS]


def _expedia_cell():
    manifest = load_manifest(EXPEDIA_MANIFEST)
    return next(c for c in manifest.cells if c.cell_id == EXPEDIA_VULNERABLE_CELL_ID)


@pytest.mark.slow
def test_booking_and_expedia_run_together_in_one_call(tmp_path) -> None:
    if not live_boot_available():
        pytest.skip(
            "live-boot harness requires composer + php on PATH and real Packagist "
            "network reachability (PA-0005) -- see live_boot.live_boot_available()"
        )
    if not spring_boot_boot_available():
        pytest.skip(
            "live-boot harness requires java + mvn on PATH and real Maven Central "
            "network reachability (PA-0005) -- see live_boot_spring_boot.spring_boot_boot_available()"
        )

    booking_cells = _booking_cells()
    booking_emitter = LaravelEmitter()
    expedia_cell = _expedia_cell()
    expedia_emitter = SpringBootEmitter()
    booking_gt = contract.load(BOOKING_GT_DIR)
    expedia_gt = contract.load(EXPEDIA_GT_DIR)

    with (
        LiveBootHarness(booking_emitter, booking_cells) as booking_harness,
        SpringBootLiveBootHarness(expedia_emitter, expedia_cell) as expedia_harness,
    ):
        specs = [
            TargetSpec(
                name="php_laravel_booking", base_url=booking_harness._base_url(),  # noqa: SLF001
                ground_truth=booking_gt, points_source="ground-truth",
            ),
            TargetSpec(
                name="spring_boot_expedia", base_url=expedia_harness.base_url,
                ground_truth=expedia_gt, points_source="ground-truth",
            ),
        ]
        with Store(tmp_path / "u.db") as store:
            outcomes = run_targets(specs, store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
            assert [o.name for o in outcomes] == ["php_laravel_booking", "spring_boot_expedia"]
            booking_outcome, expedia_outcome = outcomes
            for outcome in outcomes:
                assert outcome.scored is True
                assert outcome.report is not None
            # Per-target assertions, not a shared loop -- CC-CORE-0020's own
            # adequacy review caught exactly this pitfall (a shared loop would
            # silently apply one target's own numbers to the other). Booking.com
            # genuinely detects open_redirect (CC-CORE-0021/FR-CORE-11);
            # Expedia genuinely detects spel_injection (CC-FUZZ-0028).
            assert booking_outcome.report.tp == 1 and booking_outcome.report.fn == 2
            assert booking_outcome.report.recall == 1 / 3
            assert expedia_outcome.report.tp == 1 and expedia_outcome.report.fn == 0
            assert expedia_outcome.report.recall == 1.0
            # Two independent real run_ids, one per target, in the same call.
            assert outcomes[0].run_id != outcomes[1].run_id

            summary = transfer_summary(outcomes)
            assert summary["targets"] == 2
            # Real cross-target transfer: two independently mapped classes,
            # two different stacks, each with recall > 0.
            assert summary["generalizes"] is True
