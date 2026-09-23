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
depth work). The SSRF case (`TWCH-0002`) is a real, confirmed finding:
`SsrfInBandMarkerStrategy` sees the vulnerable twin (`LABGEN-GO-0003`) echo
the OOB marker back in its own response body (`io.Copy(w, resp.Body)`), and
correctly does not confirm the secure twin (`LABGEN-GO-0004`, blocked by
its scheme/IP allowlist before any fetch). Two gaps remain open, both
already flagged and not fixed here:

1. **No audit `Rule`/oracle strategy exists yet for `webhook_signature`/
   `insecure_deserialization`/`access_control`** (only `ssrf` has one,
   `CC-FUZZ-0027`) -- `fuzzlab.core.runmode._VULN_TO_CATEGORY` still only
   maps `sqli`/`xss-*`/`ssti` beyond that, so these fall through to their
   own name as the category and find no matching rule. `access_control`'s
   own differential (an attacker-chosen `channel_id` vs. the caller's own
   identity) is a real, buildable follow-on -- not attempted in this entry.
2. **The whole-body-JSON deserialization case (`param="body"`) still can't
   succeed through this generic sender.** `CC-FUZZ-0028` made the sender
   content-type-aware (`RequestsProbeSender` now sends raw JSON for a point
   the ground truth marks `rendering="server-json"`), but Spring Boot's
   `JacksonBodySource` reads the raw request body directly
   (`request.getInputStream().readAllBytes()`), bypassing Spring's own
   `@RequestBody` binding -- this endpoint's real behavior has not yet been
   independently re-verified end to end through the full generic pipeline
   with the new sender, only via the dedicated Phase D Tier1/2 test.
   Header points (`TWCH-0001`) are now real, audited points, not skipped
   (`CC-FUZZ-0028`) -- that structural gap is closed, only the detection
   *capability* remains open for that class.
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

    # Twitch: SSRF (TWCH-0002) is now a real, confirmed finding; the
    # webhook-signature (TWCH-0001) and access-control/IDOR (TWCH-0003)
    # cases still have no rule/point support (see module docstring) --
    # one of its three positives, not all three.
    twitch_report = by_name["twitch-clone"].report
    assert twitch_report.tp == 1 and twitch_report.fp == 0
    assert round(twitch_report.recall, 4) == round(1 / 3, 4)

    # Netflix: still a real, structural zero -- the whole-body-JSON case
    # can't be expressed by the generic sender yet (see module docstring).
    netflix_report = by_name["netflix-clone"].report
    assert netflix_report.tp == 0

    summary = transfer_summary(outcomes)
    assert summary["targets"] == 2
    assert round(summary["macro_recall"], 4) == round((1 / 3) / 2, 4)
    # Only one of the two targets shows recall > 0 -- not yet "generalizes"
    # by this project's own >= 2 definition (transfer_summary's docstring).
    assert summary["generalizes"] is False
