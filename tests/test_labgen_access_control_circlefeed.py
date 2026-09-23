"""Unit + Tier 0/Tier 3 coverage for `php_laravel`'s access-control/IDOR
cell (`CC-LAB-0216`, CircleFeed -- category 2's Facebook pick, first
designed cell). Reuses `lab/safety_matrix.yaml`'s existing
`ownership_check_bypass` concern/`access_control` family
(`no_ownership_check`/`identity_match_before_fetch` x
`db_row_by_id_lookup`, added `CC-LAB-0063`) -- this project's first real
implementation of that family by any emitter.

No network/composer/php required beyond `php -l` (Tier 0), mirroring
`tests/test_labgen_ssrf.py`'s own generated-source assertions. The real,
executed differential (a genuine HTTP 200/404 distinction against two real
seeded users) is proven separately in
`tests/test_labgen_php_laravel_access_control_live_boot.py`.
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/access_control_circlefeed_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-CF-0001": "VULNERABLE",  # no_ownership_check
    "LABGEN-CF-0002": "SECURE",  # identity_match_before_fetch
}


def _cells():
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def test_manifest_loads_and_validates() -> None:
    assert set(_cells()) == set(_EXPECTED_VERDICTS)


def test_verdict_matches_expected() -> None:
    matrix = load_safety_matrix()
    for cell_id, cell in _cells().items():
        result = verdict(cell.transform, cell.sink_context, matrix)
        assert result.verdict == _EXPECTED_VERDICTS[cell_id], cell_id


def test_supports_every_sample_cell() -> None:
    emitter = LaravelEmitter()
    for cell in _cells().values():
        assert emitter.supports(cell.vuln_class, cell.sink_context) is True


def test_render_is_byte_deterministic_across_two_calls() -> None:
    emitter = LaravelEmitter()
    for cell in _cells().values():
        first = emitter.render(cell)
        second = emitter.render(cell)
        assert first == second


def test_vulnerable_twin_has_no_ownership_filter_secure_twin_does() -> None:
    emitter = LaravelEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-CF-0001"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-CF-0002"])[0].content.decode("utf-8")
    assert "->where('owner_id'" not in vulnerable_src
    assert "->where('owner_id', $__currentUserId)" in secure_src
    # Both twins still share the exact same unauthenticated guard and
    # primary-key fetch shape -- the minimal-pair invariant, stated
    # explicitly rather than only checked by the checker below.
    assert "$request->session()->get('user_id')" in vulnerable_src
    assert "$request->session()->get('user_id')" in secure_src
    assert "\\App\\Models\\Photo::where('id', $id)" in vulnerable_src
    assert "\\App\\Models\\Photo::where('id', $id)" in secure_src
    assert "firstOrFail()" in vulnerable_src
    assert "firstOrFail()" in secure_src


def test_access_control_controllers_have_disjoint_paths_from_huddlehub() -> None:
    """CircleFeed is a second, distinct app identity on this same
    `php_laravel` emitter (like Huddle Hub before it) -- its generated
    controllers must never collide on a file path with any of Huddle Hub's
    own cells."""
    emitter = LaravelEmitter()
    cf_paths = {emitter.render(c)[0].path for c in _cells().values()}
    webhook_manifest = load_manifest("lab/manifests/webhook_signature_huddlehub_sample.yaml")
    webhook_paths = {emitter.render(c)[0].path for c in webhook_manifest.cells}
    assert cf_paths.isdisjoint(webhook_paths)


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_cell() -> None:
    emitter = LaravelEmitter()
    for cell in _cells().values():
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin() -> None:
    """Every cell's only difference from the same cell with its pipeline
    emptied must be the transform region -- the same `_weakened_twin`
    convention `fuzzlab.labgen.cli`'s own --check uses. `identity` (the
    empty-pipeline transform module) is registered in both
    `fuzzlab.labgen.modules` and `fuzzlab.labgen.emitters.php_laravel.
    modules`'s shared vocabulary, so an emptied-pipeline cell still renders
    a classifiable composition line."""
    import dataclasses

    emitter = LaravelEmitter()
    checker = tier0.get_minimal_pair_checker()
    for cell in _cells().values():
        assert cell.transform.ops
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


def test_tier3_whole_manifest_regeneration_is_byte_identical() -> None:
    emitter = LaravelEmitter()
    manifest = load_manifest(_MANIFEST_PATH)
    first = tier3.render_whole_sample(emitter, manifest.cells)
    second = tier3.render_whole_sample(emitter, manifest.cells)
    assert first == second
    assert len(first) == len(manifest.cells)
