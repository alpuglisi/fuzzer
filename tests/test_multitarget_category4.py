"""Phase E: wire category 4's Netflix and Twitch apps into
`fuzzlab.harness.multitarget` for real (`CC-LAB-0176`/`FR-LAB-99`), per
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6. Both apps are booted
for real (`GoLiveBootHarness`, `SpringBootLiveBootHarness`) and run through
`run_targets` in one call, using the real HTTP `RequestsProbeSender` this
project already has (`fuzzlab.tools.probesender`) -- never a fake sender,
matching category 1's own "genuinely testable in this sandbox" Phase E bar.

**What this proves, and what it honestly does not (recorded here, not
routed around).** `run_targets`/`transfer_summary` run against two real,
independently booted second/third targets without crashing, and produce a
scored `TargetOutcome` for each -- the toolkit-side wiring this phase asks
for. The actual detections are (expected, structural) zero, for two
already-precedented reasons, neither fixed here:

1. **No audit `Rule` exists yet for `webhook_signature`/`ssrf`/
   `insecure_deserialization`.** `fuzzlab.core.runmode._VULN_TO_CATEGORY`
   only maps `sqli`/`xss-*`; these three vuln classes fall through to
   their own name as the category, and `fuzzlab.audit.engine.evaluate`
   finds no rule in that category, so zero candidates are ever generated.
   Category 1's own Phase E entry already flagged this exact class of gap
   for its own new vuln classes and left it "not attempted" -- same here,
   not a regression.
2. **Two of this category's three ground-truth points can't be
   meaningfully expressed by the generic pipeline's point model.** The
   webhook-signature case (`location="header"`) isn't `query`/`body`, so
   `fuzzlab.harness.auto.points_from_ground_truth` skips it (mislabeled
   under the DOM/browser skip reason, since header-location isn't a case
   that function's skip path anticipates either -- a second, smaller open
   question, harmless here since the point is skipped either way). The
   whole-body-JSON deserialization case (`param="body"`) *is* included as
   a point, but `RequestsProbeSender`'s `location="body"` sends
   `data={"body": value}` -- form-urlencoded -- which Jackson cannot parse
   as JSON regardless of payload, so no injection could ever succeed
   through this generic sender for this case shape. Only the SSRF case
   (`location="query"`) is genuinely, meaningfully probed as designed.

Building a `webhook_signature`/`ssrf`/`insecure_deserialization` audit
Rule, a header-location point type, or a whole-body-JSON sender convention
are each real, sized follow-on work items -- not attempted in this
increment, exactly like category 1's own flagged gap.
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
    return webhook + ssrf


def _netflix_cell():
    cells = load_manifest("lab/manifests/insecure_deserialization_spring_boot_sample.yaml").cells
    return next(c for c in cells if c.cell_id == "LABGEN-JV-0001")


def test_both_apps_run_through_multitarget_for_real(tmp_path) -> None:
    go_emitter = GoEmitter()
    spring_emitter = SpringBootEmitter()

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
                specs, store, sender_for=lambda spec: RequestsProbeSender(timeout=10.0)
            )

    by_name = {o.name: o for o in outcomes}
    assert set(by_name) == {"twitch-clone", "netflix-clone"}
    # Both are scored (ground truth was supplied to both) -- the toolkit-side
    # wiring this phase proves, independent of whether anything was detected.
    assert by_name["twitch-clone"].scored
    assert by_name["netflix-clone"].scored
    # Real run against a real boot: distinct run IDs, no exception raised.
    assert by_name["twitch-clone"].run_id != by_name["netflix-clone"].run_id

    summary = transfer_summary(outcomes)
    assert summary["targets"] == 2
    # Expected, structural zero (see module docstring) -- not a bug in this
    # test or in Phase E's own wiring; recall is genuinely 0 until the
    # follow-on audit-rule/point-model work above is done.
    assert summary["macro_recall"] == 0.0
    assert summary["generalizes"] is False
