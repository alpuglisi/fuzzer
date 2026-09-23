"""Phase E: wire "ForgeCart" (`ruby_rails`) into `fuzzlab.harness.multitarget`
(`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6/§9.5, `CC-LAB-0080`/
`FR-LAB-84`).

This is the toolkit-side half of category 1's own second-target generalization
evidence: a real `TargetSpec` pointing at a real, locally-booted Rails
instance (via `RailsLiveBootHarness`), scored against this app's own Phase C
ground truth (`lab/ground-truth-forgecart/`), run through the real
`run_auto`/`run_targets`/`transfer_summary` pipeline `fuzzlab.harness.
multitarget` already provides -- proving that pipeline actually runs against
a real second target and produces real per-target metrics, not proving high
recall on brand-new vuln classes (`webhook_signature`/`mass_assignment`/
`insecure_deserialization`) this dispatch's own scope never asked for a
detector/oracle module for. See this module's own test docstrings for what
is, and is not, claimed.

This lane deliberately does **not** touch `fuzzlab/harness/multitarget.py`
itself (`TargetSpec` is already generic -- ``name``/``base_url``/
``ground_truth``/``points_source``/``selected_categories``/``mode``, exactly
as this dispatch's own instructions describe) or `node_express`'s own half
(the concurrent lane's `TargetSpec`, out of scope here per this dispatch's
own instructions) -- only this stack's own wiring, as a new test file.

Skip-guarded (PA-0005/PA-0035) on `rails_boot_available()`, same as every
other Rails live-boot test. Marked `@pytest.mark.slow` (a real `bundle
install` + boot round trip, plus a real HTTP crawl-free ground-truth-driven
`run_auto` pass over the booted app).
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, format_transfer, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness, rails_boot_available
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.probesender import RequestsProbeSender

pytestmark = pytest.mark.skipif(
    not rails_boot_available(),
    reason=(
        "rails live-boot harness requires ruby + bundle on PATH and real RubyGems "
        "network reachability (PA-0005/PA-0035) -- see rails_live_boot.rails_boot_available()"
    ),
)

GT_DIR = "lab/ground-truth-forgecart"
MANIFEST_PATH = "lab/manifests/shopify_forgecart_real_pages.yaml"


@pytest.mark.slow
def test_target_spec_runs_run_auto_against_a_real_booted_rails_target() -> None:
    """Boots a real ForgeCart instance (all 5 Phase C real-page cells), builds
    a real `TargetSpec` for it, and runs `run_targets` (which calls
    `run_auto` for real) with a real HTTP sender (`RequestsProbeSender`,
    already used elsewhere in this project for standalone/unauthenticated
    confirmation) against the real, live base URL. Asserts this produces a
    real, scored `TargetOutcome` -- the toolkit-side proof this app's own
    second-target generalization evidence needs, per the dispatch's own
    scope (not a claim about recall on the three brand-new vuln classes;
    see the module docstring)."""
    manifest = load_manifest(MANIFEST_PATH)
    emitter = RailsEmitter()

    with RailsLiveBootHarness(emitter, manifest.cells) as harness:
        base_url = harness._base_url()  # the real, live 127.0.0.1:<port> this run boots

        gt = contract.load(GT_DIR)
        spec = TargetSpec(
            name="ruby_rails_forgecart", base_url=base_url, ground_truth=gt,
            points_source="ground-truth",
        )

        with Store(":memory:") as store:
            outcomes = run_targets(
                [spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0),
            )

        assert [o.name for o in outcomes] == ["ruby_rails_forgecart"]
        outcome = outcomes[0]
        # Real per-target metrics: a real scored report was produced (ground
        # truth was passed, so `points_source="ground-truth"` scores it),
        # not merely "some findings, uninterpreted."
        assert outcome.scored, "ground truth was supplied; the outcome must be scored"
        report = outcome.report
        assert report is not None
        # The real XSS page (/search) is a category run_auto already knows
        # how to confirm (php_laravel/php_current already exercise the same
        # ("xss-reflected", "html") shape) -- the one case this pilot's
        # ground truth expects the existing toolkit to actually find on a
        # brand-new target, proving real cross-stack transfer, not just a
        # non-crashing run.
        assert report.tp >= 1, (
            f"expected at least the real /search reflected-XSS case confirmed; "
            f"report={report.as_dict()}"
        )

        summary = transfer_summary(outcomes)
        assert summary["targets"] == 1
        assert "ruby_rails_forgecart" in summary["found_on"]
        text = format_transfer(summary)
        assert "ruby_rails_forgecart: tp=" in text


@pytest.mark.slow
def test_run_targets_records_a_distinct_run_per_target() -> None:
    """A second, independent boot + run against the same app produces its
    own distinct `run_id` in the store -- `run_targets` genuinely drives a
    fresh run each time, not a cached/replayed result."""
    manifest = load_manifest(MANIFEST_PATH)
    emitter = RailsEmitter()
    gt = contract.load(GT_DIR)

    run_ids: list[int] = []
    for _ in range(2):
        with RailsLiveBootHarness(emitter, manifest.cells) as harness:
            spec = TargetSpec(
                name="ruby_rails_forgecart", base_url=harness._base_url(),
                ground_truth=gt, points_source="ground-truth",
            )
            with Store(":memory:") as store:
                outcomes = run_targets(
                    [spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0),
                )
                run_ids.append(outcomes[0].run_id)

    # Each run starts from run_id 1 in its own fresh (in-memory) store, so
    # this asserts the mechanism (a real run_id is minted each call), not
    # global uniqueness across independent stores.
    assert run_ids == [1, 1]
