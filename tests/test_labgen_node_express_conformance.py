"""Conformance-suite pass for `node_express` (L-P3.1, T-LAB0.7 Tiers 0/3).

- Tier 0 (lint): `node --check` on every generated controller and on the
  route accumulator, skip-guarded when `node` isn't on the build host
  (see `tests/test_labgen_node_express.py`, which owns those specific
  assertions already -- this module focuses on the whole-tree Tier-3 pass).
- Tier 3 (whole-lab regeneration): drives the real, shared
  `fuzzlab.labgen.conformance.tier3` module (owned by a sibling lane, not
  modified here) over `node_express`'s per-cell controller files -- the
  accumulator's own determinism is checked separately in
  `tests/test_labgen_node_express.py` since its cardinality
  (`accumulator`, fed by the whole cell set at once) does not fit the
  generic per-cell `render_whole_sample` harness -- see
  `fuzzlab.labgen.emitters.node_express`'s module docstring for why.

Tiers 1/2 are not attempted here, per T-LAB0.7's own scope: they need
on-host resources (a live container, a real database) this environment
does not have.
"""

from __future__ import annotations

from fuzzlab.labgen.conformance.tier3 import regenerate_and_diff_emitter, render_whole_sample
from fuzzlab.labgen.emitters.node_express import NodeExpressEmitter
from fuzzlab.labgen.schema import load_manifest


def test_regenerate_and_diff_emitter_passes_for_the_node_express_sample_manifest() -> None:
    manifest = load_manifest("lab/manifests/phase3_node_express_sample.yaml")
    emitter = NodeExpressEmitter()
    # Should not raise -- byte-identical across two full regenerations.
    regenerate_and_diff_emitter(emitter, manifest.cells)


def test_render_whole_sample_produces_one_unique_controller_path_per_cell() -> None:
    manifest = load_manifest("lab/manifests/phase3_node_express_sample.yaml")
    emitter = NodeExpressEmitter()
    tree = render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)
    assert all(path.startswith("routes/labgen-ne-") for path in tree)
