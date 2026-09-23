"""Phase E: wire category 4's Netflix and Twitch apps into
`fuzzlab.harness.multitarget` for real (`CC-LAB-0176`/`FR-LAB-99`), per
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6. Both apps are booted
for real (`GoLiveBootHarness`, `SpringBootLiveBootHarness`) and run through
`run_targets` in one call, using the real HTTP `RequestsProbeSender` this
project already has (`fuzzlab.tools.probesender`) -- never a fake sender,
matching category 1's own "genuinely testable in this sandbox" Phase E bar.
A real, started `OobListener` is also passed through (`CC-FUZZ-0027` closed
the `run_targets()` passthrough gap and added the project's first `ssrf`
audit rule + oracle strategies).

**What this now proves, and what remains honestly open (recorded here, not
routed around).** Twitch now has three real cells (webhook-signature, SSRF,
and access-control/IDOR -- `CC-LAB-0178`, the "coherent page/route set"
depth work), and two of the three now confirm for real. The SSRF case
(`TWCH-0002`): `SsrfInBandMarkerStrategy` sees the vulnerable twin
(`LABGEN-GO-0003`) echo the OOB marker back in its own response body
(`io.Copy(w, resp.Body)`), and correctly does not confirm the secure twin
(`LABGEN-GO-0004`, blocked by its scheme/IP allowlist before any fetch). The
access-control/IDOR case (`TWCH-0003`, `CC-FUZZ-0029`):
`AccessControlIdorStrategy` sees the vulnerable twin (`LABGEN-GO-0005`)
accept and echo back any `channel_id`, and correctly does not confirm the
secure twin (`LABGEN-GO-0006`, blocked by its identity-match check).

Netflix's `NFLX-0001` (insecure-deserialization) is now also a real,
confirmed finding (`CC-FUZZ-0030`): the whole-body-JSON case
`CC-FUZZ-0028` made content-type-aware now succeeds end to end through
this exact generic pipeline (not just the dedicated Phase D Tier1/2 test) --
`InsecureDeserializationTypeConfusionStrategy` sees the vulnerable twin
(`LABGEN-JV-0001`) accept and successfully deserialize an attacker-named
JDK class via Jackson's `WRAPPER_ARRAY` polymorphic-type format, and
correctly does not confirm the secure twin (`LABGEN-JV-0002`, no
polymorphic typing configured at all).

`NFLX-0002` (XXE) now also has a real rule/strategy pair
(`R-XXE`/`XxeInBandMarkerStrategy`, `CC-FUZZ-0031`, verified live against
TrackerNest's own XXE twins -- `tests/test_labgen_spring_boot_xxe_live_boot.py`
and `tests/test_labgen_spring_boot_trackernest_multitarget.py`), but it is
**not yet exercised in this specific test**: `_netflix_cell()` below boots
only `LABGEN-JV-0001` (the insecure-deserialization vulnerable twin) via
`SpringBootLiveBootHarness`'s one-cell-per-boot constraint, so `NFLX-0002`'s
own point (a different route the booted app doesn't serve) is still a
structural false negative *here* -- not because detection is missing, but
because this test's own single-cell boot doesn't include it. Closing that
is its own separately-scoped follow-on (a hand-rolled multi-cell fixture
like TrackerNest's or category 3's `CC-LAB-0138`, or a second `TargetSpec`
booting `NFLX-0002` on its own), not attempted here. One gap remains open:

1. **No audit `Rule`/oracle strategy exists yet for `webhook_signature`**
   (`ssrf`/`access_control`/`insecure_deserialization`/`xxe` now all have
   one) -- `fuzzlab.core.runmode._VULN_TO_CATEGORY` doesn't map it, and it
   needs a genuinely new timing-statistics oracle (a single-request model
   cannot observe a comparison-timing side channel), not just a rule.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness, go_boot_available
from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.oob import OobListener
from fuzzlab.tools.probesender import RequestsProbeSender

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not (go_boot_available() and spring_boot_boot_available()),
        reason="requires both the go toolchain (PA-0035) and java+mvn+Maven Central (PA-0005)",
    ),
]


def _twitch_cells():
    webhook = load_manifest("lab/manifests/webhook_signature_go_sample.yaml").cells
    ssrf = load_manifest("lab/manifests/ssrf_go_sample.yaml").cells
    access_control = load_manifest("lab/manifests/access_control_go_sample.yaml").cells
    return webhook + ssrf + access_control


def _netflix_cell():
    cells = load_manifest("lab/manifests/insecure_deserialization_spring_boot_sample.yaml").cells
    return next(c for c in cells if c.cell_id == "LABGEN-JV-0001")


def test_both_apps_run_through_multitarget_for_real(tmp_path) -> None:
    go_emitter = GoEmitter()
    spring_emitter = SpringBootEmitter()
    listener = OobListener()
    listener.start()

    try:
        with GoLiveBootHarness(go_emitter, _twitch_cells()) as go_harness, \
                SpringBootLiveBootHarness(spring_emitter, _netflix_cell()) as spring_harness:
            twitch_gt = contract.load("lab/ground-truth-twitch-clone")
            netflix_gt = contract.load("lab/ground-truth-netflix-clone")
            specs = [
                TargetSpec("twitch-clone", go_harness.base_url, ground_truth=twitch_gt,
                           points_source="ground-truth"),
                TargetSpec("netflix-clone", spring_harness.base_url, ground_truth=netflix_gt,
                           points_source="ground-truth"),
            ]
            with Store(tmp_path / "u.db") as store:
                outcomes = run_targets(
                    specs, store, sender_for=lambda spec: RequestsProbeSender(timeout=10.0),
                    oob=listener,
                )
    finally:
        listener.stop()

    by_name = {o.name: o for o in outcomes}
    assert set(by_name) == {"twitch-clone", "netflix-clone"}
    # Both are scored (ground truth was supplied to both) -- the toolkit-side
    # wiring this phase proves, independent of what else was detected.
    assert by_name["twitch-clone"].scored
    assert by_name["netflix-clone"].scored
    # Real run against a real boot: distinct run IDs, no exception raised.
    assert by_name["twitch-clone"].run_id != by_name["netflix-clone"].run_id

    # Twitch: SSRF (TWCH-0002) and access-control/IDOR (TWCH-0003) are now
    # real, confirmed findings; the webhook-signature (TWCH-0001) case still
    # has no rule/point support (see module docstring) -- two of its three
    # positives, not all three.
    twitch_report = by_name["twitch-clone"].report
    assert twitch_report.tp == 2 and twitch_report.fp == 0
    assert round(twitch_report.recall, 4) == round(2 / 3, 4)

    # Netflix: insecure-deserialization (NFLX-0001) is now a real, confirmed
    # finding; XXE (NFLX-0002) still has no rule/strategy (see module
    # docstring) -- one of its two positives, not both (only NFLX-0001's
    # own vulnerable twin, LABGEN-JV-0001, is booted here).
    netflix_report = by_name["netflix-clone"].report
    assert netflix_report.tp == 1 and netflix_report.fp == 0
    assert round(netflix_report.recall, 4) == round(1 / 2, 4)

    summary = transfer_summary(outcomes)
    assert summary["targets"] == 2
    assert round(summary["macro_recall"], 4) == round(((2 / 3) + (1 / 2)) / 2, 4)
    # Both targets now show recall > 0 -- this project's own >= 2 "generalizes"
    # definition (transfer_summary's docstring) is met for the first time.
    assert summary["generalizes"] is True
