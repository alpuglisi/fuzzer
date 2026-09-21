"""Tier 0 + Tier 3 conformance-suite pass for `python_fastapi` (L-P3.2, T-LAB0.7).

Tier 0: `python -m py_compile` lint (skip-guarded, PA-0005) +
minimal-pair diff. `fuzzlab.labgen.minimal_pair`'s real checker is
PHP-comment-syntax-specific (`// Module composition: ...`) by its own
documented scope, so this stack's own Tier-0 pass uses
`_naive_minimal_pair_check` directly rather than
`get_minimal_pair_checker()` -- see `fuzzlab.labgen.conformance.tier0`'s
module docstring for why, and `test_labgen_conformance_tier0.py` for the
PHP-side pass that does use the real checker.

Tier 3: whole-manifest regenerate-and-diff against
`lab/manifests/phase3_python_fastapi_sample.yaml`, using the exact same
stack-agnostic `fuzzlab.labgen.conformance.tier3` machinery `php_current`'s
own Tier-3 tests use.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.tier0 import _naive_minimal_pair_check, lint_python_emitted_files, python_available
from fuzzlab.labgen.conformance.tier3 import regenerate_and_diff_emitter, render_whole_sample
from fuzzlab.labgen.emitters.python_fastapi import PythonFastapiEmitter
from fuzzlab.labgen.schema import load_manifest

_MANIFEST_PATH = "lab/manifests/phase3_python_fastapi_sample.yaml"


@pytest.mark.skipif(not python_available(), reason="python interpreter not available on this build host (PA-0005)")
def test_tier0_lint_passes_for_every_sample_cell() -> None:
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = PythonFastapiEmitter()
    for cell in manifest.cells:
        assert emitter.supports(cell.vuln_class, cell.sink_context)
        results = lint_python_emitted_files(emitter.render(cell))
        assert results
        assert all(r.ok for r in results), (cell.cell_id, results)


def test_tier0_minimal_pair_diff_confirms_each_declared_pair() -> None:
    manifest = load_manifest(_MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = PythonFastapiEmitter()
    pairs = [
        ("LABGEN-PY-0001", "LABGEN-PY-0002"),
        ("LABGEN-PY-0003", "LABGEN-PY-0004"),
        ("LABGEN-PY-0005", "LABGEN-PY-0006"),
    ]
    for vuln_id, secure_id in pairs:
        result = _naive_minimal_pair_check(emitter.render(cells[vuln_id]), emitter.render(cells[secure_id]))
        assert result.is_minimal_pair is True, (vuln_id, secure_id, result.notes)
        assert result.differing_paths


def test_tier0_minimal_pair_diff_rejects_byte_identical_output() -> None:
    manifest = load_manifest(_MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = PythonFastapiEmitter()
    same = emitter.render(cells["LABGEN-PY-0001"])
    result = _naive_minimal_pair_check(same, same)
    assert result.is_minimal_pair is False


def test_tier3_regenerate_and_diff_passes_for_the_sample_manifest() -> None:
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = PythonFastapiEmitter()
    # Should not raise.
    regenerate_and_diff_emitter(emitter, manifest.cells)


def test_tier3_render_whole_sample_has_no_path_collisions() -> None:
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = PythonFastapiEmitter()
    tree = render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)
    assert all(path.startswith("app/routers/") for path in tree)
