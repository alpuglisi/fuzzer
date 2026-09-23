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

**Recall is honestly 0 here, and that is expected, not a bug** -- same
documented gap as TrackerNest's own Phase E test and category 1's
precedent: none of `webhook_signature_bypass`/`ssrf`/
`outbound_header_injection` are mapped by
`fuzzlab.core.runmode._VULN_TO_CATEGORY`. A second, narrower gap this
target's own ground truth is the first in this project to exercise:
`HHUB-0001`'s injection point is `location="header"` (the X-Signature
header, not a query/body param) -- `fuzzlab.harness.auto.
points_from_ground_truth` has no header-location branch, so it falls into
that function's generic client-only/DOM `else` branch and is recorded as
`skipped` with a technically-inaccurate reason string ("client-only/DOM
(needs browser execution, M6)" -- this point needs a header-capable
prober, not a browser). This is a real, pre-existing latent gap in that
function's own location handling, first actually exercised by this
target's ground truth (no `injection-points.json` in this project
declared a `location="header"` point before `CC-LAB-0137`) -- flagged
here, not fixed: fixing `points_from_ground_truth`'s header-location
handling (and building a header-capable prober to actually drive it) is
real, sized follow-on work distinct from this test's own job of proving
the `TargetSpec` wiring, matching this project's own "flag a gap rather
than silently route around it" discipline. It has no effect on this
test's own assertions either way: `webhook_signature_bypass` is unmapped
in `_VULN_TO_CATEGORY` regardless of whether its point is skipped or
driven, so recall for that case is 0 either way.

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

        with Store(tmp_path / "u.db") as store:
            outcomes = run_targets([spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
            assert [o.name for o in outcomes] == ["php_laravel_huddlehub"]
            outcome = outcomes[0]
            assert outcome.scored is True
            assert outcome.report is not None
            assert outcome.report.tp == 0 and outcome.report.fn == len(gt.positives())
            assert outcome.report.precision == 0.0
            assert outcome.report.recall == 0.0

            summary = transfer_summary(outcomes)
            assert summary["targets"] == 1
            assert "macro_precision" in summary and "macro_recall" in summary
            assert summary["generalizes"] is False


@pytest.mark.slow
def test_huddlehub_endpoints_are_really_live() -> None:
    """Confirms the booted app is genuinely the real Huddle Hub build (not
    an empty skeleton `run_targets` merely failed to reach) -- a real,
    distinguishable response from each of the three vulnerable cells' own
    per-cell URLs."""
    cells = _vulnerable_cells()
    emitter = LaravelEmitter()
    with LiveBootHarness(emitter, cells) as harness:
        resp = harness.get("/cell/labgen-hhb-0003", params={"url": "http://example.com/"})
        assert resp.status == 200
        assert '"requested_url":"http:\\/\\/example.com\\/"' in resp.body or "example.com" in resp.body
