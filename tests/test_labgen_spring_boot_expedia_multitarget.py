"""Phase E: wire Expedia (`spring_boot`, category 5's Expedia pick) into
`fuzzlab.harness.multitarget` as its own real `TargetSpec`
(`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6/§9.4, `CC-LAB-0218`).

Runs the real thing end to end: a real `mvn package` + `java -jar` boot,
a real `fuzzlab.tools.probesender.RequestsProbeSender` sending real HTTP
over the loopback socket, and `fuzzlab.harness.multitarget.run_targets`/
`transfer_summary` run against it for real.

**Scope: Expedia's own designed page set only, not every cell the
`spring_boot` package can render.** `lab/ground-truth-expedia-clone/`
(`CC-LAB-0214`) currently has exactly one case, `EXPD-0001` (the
`spel_injection` cell) -- the ported Netflix Jackson-deserialization cell
(`CC-LAB-0213`) is reused *infrastructure*, not a page Expedia's own
ground truth describes (its ground truth lives in
`lab/ground-truth-netflix-clone/`, a different app identity entirely).
Wiring the Jackson cell into Expedia's own `TargetSpec` too would need
either a second ground-truth case declared under `EXPD-*` for the same
underlying cell (double-counting a case that already exists under
`NFLX-0001`) or a still-unresolved policy decision about whether a
reused cell belongs to more than one app's ground truth at once -- out
of scope for this entry, flagged rather than guessed at. This mirrors
`tests/test_labgen_spring_boot_trackernest_multitarget.py`'s own
"describes exactly this ground truth" scoping principle, just resolving
to a *single*-cell deployment here rather than three.

**Reuses `SpringBootLiveBootHarness` directly** (unlike TrackerNest's own
Phase E test, which had to hand-roll a multi-cell fixture because that
harness is deliberately single-cell-only) -- Expedia's own one-cell scope
means the existing harness's restriction is not a limitation here at all,
and its public `.base_url` property (`CC-LAB-0132`'s own `app_dir`
precedent, extended) is exactly what a `TargetSpec` needs.

**Recall is 1/2**: `spel_injection` (`EXPD-0001`) genuinely detects
(`CC-FUZZ-0028`, a new rule+strategy pair built specifically for this
shape, live-verified before this test was updated to expect it).
`insecure_deserialization` (`EXPD-0002`, `CC-LAB-0220`) has no verified
confirmer yet -- an honest false negative, same documented gap as every
other category's own unmapped classes -- not a regression from this
ground truth directory growing to two cases.

Skip-guarded on `spring_boot_boot_available()` (PA-0005/PA-0035). Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.probesender import RequestsProbeSender

pytestmark = pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason=(
        "live-boot harness requires java + mvn on PATH and real Maven Central "
        "network reachability (PA-0005) -- see live_boot_spring_boot.spring_boot_boot_available()"
    ),
)

GT_DIR = "lab/ground-truth-expedia-clone"
MANIFEST = "lab/manifests/expedia_spel_injection_sample.yaml"
VULNERABLE_CELL_ID = "LABGEN-EXP-0001"


def _vulnerable_cell():
    manifest = load_manifest(MANIFEST)
    return next(c for c in manifest.cells if c.cell_id == VULNERABLE_CELL_ID)


@pytest.mark.slow
def test_expedia_target_spec_runs_for_real_and_scores(tmp_path) -> None:
    cell = _vulnerable_cell()
    emitter = SpringBootEmitter()
    gt = contract.load(GT_DIR)

    with SpringBootLiveBootHarness(emitter, cell) as harness:
        spec = TargetSpec(
            name="spring_boot_expedia", base_url=harness.base_url,
            ground_truth=gt, points_source="ground-truth",
        )
        with Store(tmp_path / "u.db") as store:
            outcomes = run_targets([spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
            assert [o.name for o in outcomes] == ["spring_boot_expedia"]
            outcome = outcomes[0]
            assert outcome.scored is True
            assert outcome.report is not None
            # spel_injection genuinely detects (CC-FUZZ-0028): EXPD-0001 -> tp.
            # insecure_deserialization (EXPD-0002, CC-LAB-0220) has no verified
            # confirmer yet -- an honest false negative, same documented gap
            # as every other category's own unmapped classes.
            assert outcome.report.tp == 1 and outcome.report.fn == 1
            assert outcome.report.fp == 0
            assert outcome.report.precision == 1.0
            assert outcome.report.recall == 0.5

            summary = transfer_summary(outcomes)
            assert summary["targets"] == 1
            assert "macro_precision" in summary and "macro_recall" in summary
            assert summary["generalizes"] is False


@pytest.mark.slow
def test_expedia_endpoint_is_really_live() -> None:
    """Confirms the booted app is genuinely the real Expedia build (not an
    empty skeleton `run_targets` merely failed to reach) -- a real, direct
    HTTP round trip against the cell's own real payload differential,
    independent of the scoring path above."""
    cell = _vulnerable_cell()
    emitter = SpringBootEmitter()

    with SpringBootLiveBootHarness(emitter, cell) as harness:
        resp = harness.get("/api/hotels/search-sort", params={"sortBy": "T(java.lang.Math).abs(-99)"})
        assert resp.status == 200, resp.body
        assert "99" in resp.body, resp.body
