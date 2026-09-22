"""Conformance-suite pass for `spring_boot` (`CC-LAB-0090`, T-LAB0.7 Tiers 0/3).

- Tier 0 (compile check): a real `mvn compile` of the checked-in skeleton
  overlaid with one cell's generated controller, skip-guarded on
  `spring_boot_boot_available()` (PA-0005). Unlike PHP's `php -l`/Python's
  `py_compile` (which lint one file in isolation), a single generated
  `.java` file imports Spring/OGNL classes it cannot resolve without the
  real project's classpath -- so this stack's Tier 0 needs the assembled
  project, not a lone-file syntax check. With a warm local Maven cache
  (already populated by `spring_boot_boot_available()`'s own probe or a
  prior live-boot run) this completes in ~2s, well within Tier 0's "fast,
  no live app" bar -- it does not package a jar or boot anything, unlike
  `test_labgen_spring_boot_live_boot.py`.
- Tier 3 (whole-lab regeneration): drives the real, shared
  `fuzzlab.labgen.conformance.tier3` module over `spring_boot`'s per-cell
  controller files, exactly like every other emitter's own Tier-3 pass
  (see `tests/test_labgen_node_express_conformance.py` for the pattern this
  mirrors). No accumulator to check separately here (`SpringBootEmitter`
  has none -- see its own module docstring for why).

Tiers 1/2 beyond the one cell's live-boot proof are not attempted here, per
`CC-LAB-0090`'s stated scope.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SKELETON_DIR,
    spring_boot_boot_available,
)
from fuzzlab.labgen.conformance.tier3 import regenerate_and_diff_emitter, render_whole_sample
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest


def test_regenerate_and_diff_emitter_passes_for_the_spring_boot_sample_manifest() -> None:
    manifest = load_manifest("lab/manifests/ssti_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    # Should not raise -- byte-identical across two full regenerations.
    regenerate_and_diff_emitter(emitter, manifest.cells)


def test_render_whole_sample_produces_one_unique_controller_path_per_cell() -> None:
    manifest = load_manifest("lab/manifests/ssti_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    tree = render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)
    assert all(
        path.startswith("src/main/java/com/fuzzlab/trackernest/generated/") for path in tree
    )


@pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason="Tier 0 compile check requires java + mvn on PATH and Maven Central reachability (PA-0005)",
)
@pytest.mark.parametrize("cell_id", ["LABGEN-SSTI-0001", "LABGEN-SSTI-0002"])
def test_tier0_mvn_compile_passes_for_each_cell(cell_id: str) -> None:
    manifest = load_manifest("lab/manifests/ssti_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    cell = {c.cell_id: c for c in manifest.cells}[cell_id]

    with tempfile.TemporaryDirectory(prefix="fuzzlab-spring-boot-tier0-") as tmp:
        app_dir = Path(tmp) / "app"
        shutil.copytree(SKELETON_DIR, app_dir)
        for emitted in emitter.render(cell):
            dest = app_dir / emitted.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(emitted.content)

        result = subprocess.run(
            ["mvn", "-q", "-B", "compile"],
            cwd=app_dir,
            capture_output=True,
            text=True,
            timeout=120.0,
        )
        assert result.returncode == 0, f"mvn compile failed:\nstdout={result.stdout}\nstderr={result.stderr}"
