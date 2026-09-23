"""Conformance-suite pass for `java_spring_boot` (category 4 pilot,
`CC-LAB-0171`/`FR-LAB-77`, T-LAB0.7 Tier 3).

- Tier 0 (lint): `mvn -q compile` on the rendered output -- owned by
  `tests/test_labgen_java_spring_boot.py` already; this module focuses on
  the whole-tree Tier-3 pass, matching every other stack's own conformance
  test file's split.
- Tier 3 (whole-lab regeneration): drives the real, shared
  `fuzzlab.labgen.conformance.tier3` module over `java_spring_boot`'s
  per-cell controller files. Unlike `node_express`/`go_net_http`, this
  stack has no accumulator file at all (Spring Boot's component scanning
  needs none -- see `fuzzlab.labgen.emitters.java_spring_boot`'s own
  module docstring), so there is no separate accumulator-determinism test
  to write here.

Tiers 1/2 are not attempted here, per T-LAB0.7's own scope: Tier 2's
live-boot proof for this stack lives in
`tests/test_labgen_java_live_boot.py`, skip-guarded on
`java_boot_available()`, not gated behind a container.
"""

from __future__ import annotations

from fuzzlab.labgen.conformance.tier3 import regenerate_and_diff_emitter, render_whole_sample
from fuzzlab.labgen.emitters.java_spring_boot import JavaEmitter
from fuzzlab.labgen.schema import load_manifest


def test_regenerate_and_diff_emitter_passes_for_the_java_spring_boot_sample_manifest() -> None:
    manifest = load_manifest("lab/manifests/insecure_deserialization_java_sample.yaml")
    emitter = JavaEmitter()
    # Should not raise -- byte-identical across two full regenerations.
    regenerate_and_diff_emitter(emitter, manifest.cells)


def test_render_whole_sample_produces_one_unique_controller_path_per_cell() -> None:
    manifest = load_manifest("lab/manifests/insecure_deserialization_java_sample.yaml")
    emitter = JavaEmitter()
    tree = render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)
    assert all(
        path.startswith("src/main/java/com/fuzzlab/lab/cells/Cell") and path.endswith(".java")
        for path in tree
    )
