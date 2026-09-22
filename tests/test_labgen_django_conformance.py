"""Conformance-suite pass for `django` Phase A (category 2 pilot,
`CC-LAB-0090`, T-LAB0.7 Tiers 0/3).

- Tier 0 (lint): `python -m py_compile` on every generated view module and
  on the route accumulator (`fuzlab_django_lab/urls.py`), skip-guarded when
  no interpreter is on the build host -- mirrors `test_labgen_node_express_
  conformance.py`'s own split (route accumulator determinism checked
  separately, since its cardinality does not fit the generic per-cell
  `render_whole_sample` harness).
- Tier 3 (whole-lab regeneration): drives the real, shared
  `fuzzlab.labgen.conformance.tier3` module (owned by a sibling lane, not
  modified here) over `django`'s per-cell view files.

Tiers 1/2 are proven separately, for real, in
`tests/test_labgen_django_live_boot_single_shape.py` (this environment does
have real network/venv access, unlike the on-host-only tiers T-LAB0.7
otherwise defers).
"""

from __future__ import annotations

from fuzzlab.labgen.conformance.tier0 import lint_python, lint_python_emitted_files, python_available
from fuzzlab.labgen.conformance.tier3 import regenerate_and_diff_emitter, render_whole_sample
from fuzzlab.labgen.emitters.django import DjangoEmitter
from fuzzlab.labgen.schema import load_manifest


def test_regenerate_and_diff_emitter_passes_for_the_django_sample_manifest() -> None:
    manifest = load_manifest("lab/manifests/phase_a_django_sample.yaml")
    emitter = DjangoEmitter()
    # Should not raise -- byte-identical across two full regenerations.
    regenerate_and_diff_emitter(emitter, manifest.cells)


def test_render_whole_sample_produces_one_unique_view_path_per_cell() -> None:
    manifest = load_manifest("lab/manifests/phase_a_django_sample.yaml")
    emitter = DjangoEmitter()
    tree = render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)
    assert all(path.startswith("fuzlab_django_lab/views/labgen_dj_") for path in tree)


def test_route_accumulator_is_deterministic_across_two_calls() -> None:
    """The accumulator's own determinism check (Addendum D's rule), separate
    from the generic per-cell Tier-3 harness -- mirrors
    `test_labgen_node_express_conformance.py`'s own split. Two calls with
    cells passed in reverse order must produce byte-identical output (sorted
    by cell ID at render time, never by call-site iteration order)."""
    manifest = load_manifest("lab/manifests/phase_a_django_sample.yaml")
    emitter = DjangoEmitter()
    forward = emitter.render_route_accumulator(manifest.cells)
    reversed_cells = list(reversed(manifest.cells))
    backward = emitter.render_route_accumulator(reversed_cells)
    assert forward.content == backward.content
    assert forward.path == "fuzlab_django_lab/urls.py"


def test_tier0_lint_passes_for_every_generated_cell_and_the_accumulator() -> None:
    if not python_available():
        import pytest

        pytest.skip("no python interpreter on PATH for py_compile (PA-0005)")

    manifest = load_manifest("lab/manifests/phase_a_django_sample.yaml")
    emitter = DjangoEmitter()
    for cell in manifest.cells:
        results = lint_python_emitted_files(emitter.render(cell))
        assert results, f"{cell.cell_id}: no .py files emitted to lint"
        for result in results:
            assert result.ok, f"{cell.cell_id} ({result.path}): {result.detail}"

    accumulator = emitter.render_route_accumulator(manifest.cells)
    result = lint_python(accumulator.path, accumulator.content)
    assert result.ok, f"{accumulator.path}: {result.detail}"
