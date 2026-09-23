"""Conformance-suite pass for `spring_boot`
(`CC-LAB-0130`/`CC-LAB-0131`/`CC-LAB-0132`, T-LAB0.7 Tiers 0/3).

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
`CC-LAB-0130`'s stated scope.
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


#: Every `spring_boot` manifest this stack has as of `CC-LAB-0132` (SSTI,
#: `CC-LAB-0130`; XXE, `CC-LAB-0131`; insecure deserialization, `CC-LAB-0132`
#: -- TrackerNest's full, three-cell designed set) -- all go through the
#: same stack-agnostic Tier 0/3 checks below.
_MANIFEST_PATHS = [
    "lab/manifests/ssti_spring_boot_sample.yaml",
    "lab/manifests/xxe_spring_boot_sample.yaml",
    "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
]


@pytest.mark.parametrize("manifest_path", _MANIFEST_PATHS)
def test_regenerate_and_diff_emitter_passes_for_the_spring_boot_sample_manifest(manifest_path: str) -> None:
    manifest = load_manifest(manifest_path)
    emitter = SpringBootEmitter()
    # Should not raise -- byte-identical across two full regenerations.
    regenerate_and_diff_emitter(emitter, manifest.cells)


@pytest.mark.parametrize("manifest_path", _MANIFEST_PATHS)
def test_render_whole_sample_produces_one_unique_controller_path_per_cell(manifest_path: str) -> None:
    manifest = load_manifest(manifest_path)
    emitter = SpringBootEmitter()
    tree = render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)
    assert all(
        path.startswith("src/main/java/com/fuzzlab/trackernest/generated/") for path in tree
    )


def test_ssti_and_xxe_manifests_render_to_disjoint_paths_when_combined() -> None:
    """The two manifests' cells must be renderable into one combined tree
    with no path collision -- `render_whole_sample` itself enforces this
    (raises on a duplicate path), so this proves it rather than assuming it
    from each manifest's own separate pass above."""
    emitter = SpringBootEmitter()
    all_cells = [c for path in _MANIFEST_PATHS for c in load_manifest(path).cells]
    tree = render_whole_sample(emitter, all_cells)
    assert len(tree) == len(all_cells)


@pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason="Tier 0 compile check requires java + mvn on PATH and Maven Central reachability (PA-0005)",
)
@pytest.mark.parametrize(
    "manifest_path,cell_id",
    [
        ("lab/manifests/ssti_spring_boot_sample.yaml", "LABGEN-SSTI-0001"),
        ("lab/manifests/ssti_spring_boot_sample.yaml", "LABGEN-SSTI-0002"),
        ("lab/manifests/xxe_spring_boot_sample.yaml", "LABGEN-XXE-0001"),
        ("lab/manifests/xxe_spring_boot_sample.yaml", "LABGEN-XXE-0002"),
        ("lab/manifests/insecure_deserialization_spring_boot_sample.yaml", "LABGEN-DESER-0001"),
        ("lab/manifests/insecure_deserialization_spring_boot_sample.yaml", "LABGEN-DESER-0002"),
    ],
)
def test_tier0_mvn_compile_passes_for_each_cell(manifest_path: str, cell_id: str) -> None:
    manifest = load_manifest(manifest_path)
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
