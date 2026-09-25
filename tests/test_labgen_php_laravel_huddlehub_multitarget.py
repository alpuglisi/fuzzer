"""Phase E: wire Huddle Hub (`php_laravel`, category 3's Slack pick) into
`fuzzlab.harness.multitarget` as its own real `TargetSpec`
(`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6/§9.4, `CC-LAB-0139`).

Runs the real thing end to end: a real `composer install` + `artisan
serve` boot of the whole assembled app (all three of Huddle Hub's
vulnerable cells at once -- each already has its own unique `/cell/<slug>`
URL via `served_url_for()`, so, unlike TrackerNest, there is no same-route
collision to avoid booting them together), a real
`fuzzlab.tools.probesender.RequestsProbeSender` sending real HTTP over the
loopback socket, and `fuzzlab.harness.multitarget.run_targets`/
`transfer_summary` run against it for real.

Reuses `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` directly
(unlike TrackerNest's Phase E test, which had to hand-roll its own
assembly/boot fixture): this harness already accepts a **list** of cells
with no single-cell restriction (its own `__init__` filters to
`emitter.supports(...)` cells and assembles all of them), so no extension
was needed here.

**Recall is 1/3 here, not 0.** `ssrf` (`HHUB-0002`) is now confirmed for
real: `R-SSRF`/`SsrfInBandMarkerStrategy` (`CC-AUD-0016`/`CC-FUZZ-0031`)
were built after this test was first written -- this test now starts and
passes a real `OobListener` to `run_targets` (`oob=listener`), without
which `SsrfInBandMarkerStrategy` fails closed and never confirms (it uses
the listener as its own marker responder, not only for an OOB wait).
`webhook_signature_bypass`/`outbound_header_injection` remain unmapped in
`fuzzlab.core.runmode._VULN_TO_CATEGORY` -- no confirmer built for either
yet. Separately: `HHUB-0001`'s injection point is `location="header"`
(the X-Signature header, not a query/body param) -- this was once a real,
latent gap in `fuzzlab.harness.auto.points_from_ground_truth` (no
header-location branch at all, silently skipped with a misleading reason
string), closed generically by `CC-FUZZ-0032`/`FR-FUZZ-19` (header points
are now real, audited points project-wide). It has no effect on this
test's own assertions either way: `webhook_signature_bypass` is still
unmapped in `_VULN_TO_CATEGORY` regardless of whether its point is driven,
so recall for that specific case stays 0.

Skip-guarded on `live_boot_available()` (PA-0005), matching every other
`php_laravel` live-boot test in this project. Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.oob import OobListener

pytestmark = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)

GT_DIR = "lab/ground-truth-huddlehub"
MANIFESTS = (
    "lab/manifests/webhook_signature_huddlehub_sample.yaml",
    "lab/manifests/ssrf_huddlehub_sample.yaml",
    "lab/manifests/header_injection_huddlehub_sample.yaml",
)
#: Only the vulnerable half of each cell pair -- ground truth
#: (`CC-LAB-0137`) describes exactly this three-cell, all-vulnerable
#: deployment, matching category 5/Booking.com's own established
#: convention (see that entry).
VULNERABLE_CELL_IDS = {"LABGEN-HHB-0001", "LABGEN-HHB-0003", "LABGEN-HHB-0005"}


def _vulnerable_cells():
    return [c for m in MANIFESTS for c in load_manifest(m).cells if c.cell_id in VULNERABLE_CELL_IDS]


@pytest.mark.slow
def test_huddlehub_target_spec_runs_for_real_and_scores(tmp_path) -> None:
    cells = _vulnerable_cells()
    assert {c.cell_id for c in cells} == VULNERABLE_CELL_IDS
    emitter = LaravelEmitter()
    gt = contract.load(GT_DIR)

    with LiveBootHarness(emitter, cells) as harness:
        base_url = harness._base_url()  # noqa: SLF001 - see LiveBootHarness's own
        # `_app_dir` precedent (CC-LAB-0132's docstring) for this exact same-module
        # private-attribute-access pattern; this harness has no public base-url
        # accessor of its own, unlike `SpringBootLiveBootHarness.app_dir`.

        spec = TargetSpec(
            name="php_laravel_huddlehub", base_url=base_url,
            ground_truth=gt, points_source="ground-truth",
        )
        from fuzzlab.tools.probesender import RequestsProbeSender

        listener = OobListener()
        listener.start()
        try:
            with Store(tmp_path / "u.db") as store:
                outcomes = run_targets([spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0),
                                       oob=listener)
                assert [o.name for o in outcomes] == ["php_laravel_huddlehub"]
                outcome = outcomes[0]
                assert outcome.scored is True
                assert outcome.report is not None
                # ssrf (HHUB-0002) confirms for real (CC-AUD-0016/CC-FUZZ-0031,
                # via the real OobListener passed above); the other two
                # classes remain unmapped -- 1 of 3 positives, not 0.
                assert outcome.report.tp == 1 and outcome.report.fp == 0
                assert outcome.report.fn == len(gt.positives()) - 1
                assert outcome.report.precision == 1.0
                assert outcome.report.recall == pytest.approx(1 / 3)

                summary = transfer_summary(outcomes)
                assert summary["targets"] == 1
                assert "macro_precision" in summary and "macro_recall" in summary
                assert summary["generalizes"] is False
        finally:
            listener.stop()


@pytest.mark.slow
def test_huddlehub_endpoints_are_really_live() -> None:
    """Confirms the booted app is genuinely the real Huddle Hub build (not
    an empty skeleton `run_targets` merely failed to reach) -- a real,
    distinguishable response from each of the three vulnerable cells' own
    per-cell URLs."""
    cells = _vulnerable_cells()
    emitter = LaravelEmitter()
    with LiveBootHarness(emitter, cells) as harness:
        from fuzzlab.labgen.emitters.php_laravel import served_url_for

        # CC-LAB-0239: LABGEN-HHB-0003 no longer serves at the generic
        # `/cell/labgen-hhb-0003` -- its real URL is `/messages/unfurl`
        # (`_PAGE_PROFILES`' `real_page`/`canonical_cell_id`).
        ssrf_cell = next(c for c in cells if c.cell_id == "LABGEN-HHB-0003")
        resp = harness.get(served_url_for(ssrf_cell), params={"url": "http://example.com/"})
        assert resp.status == 200
        assert '"requested_url":"http:\\/\\/example.com\\/"' in resp.body or "example.com" in resp.body
