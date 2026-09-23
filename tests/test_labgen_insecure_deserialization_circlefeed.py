"""Unit + Tier 0/Tier 3 coverage for `php_laravel`'s account-settings
insecure-deserialization cell (`CC-LAB-0220`, CircleFeed -- category 2's
Facebook pick, fourth and final designed cell). This project's first real
implementation of `lab/safety_matrix.yaml`'s `object_deserialization` sink
family's PHP pair (`unrestricted_unserialize`/`json_decode_type_check`,
both existed, unimplemented, since the family was added).

No network/composer/php required beyond `php -l` (Tier 0), mirroring
`tests/test_labgen_header_injection_circlefeed.py`'s own structure. The
real, executed differential (a genuine unserialize()-RCE, a real marker
file written by a crafted payload's `__wakeup()` hook) is proven separately
in `tests/test_labgen_insecure_deserialization_circlefeed_live_boot.py`.
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/insecure_deserialization_circlefeed_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-CF-0007": "VULNERABLE",  # unrestricted_unserialize
    "LABGEN-CF-0008": "SECURE",  # json_decode_type_check
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


def test_vulnerable_twin_calls_bare_unserialize_secure_twin_uses_json_decode() -> None:
    emitter = LaravelEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-CF-0007"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-CF-0008"])[0].content.decode("utf-8")
    # Vulnerable: bare unserialize(), no allowed_classes restriction, never
    # json_decode().
    assert "@unserialize($__decoded)" in vulnerable_src
    assert "json_decode(" not in vulnerable_src
    # Secure: json_decode() plus an is_array() type check, never
    # unserialize().
    assert "json_decode($__decoded, true)" in secure_src
    assert "is_array($__parsed)" in secure_src
    assert "@unserialize(" not in secure_src
    # Both read the cookie the same way (the source is shared/byte-identical
    # between twins -- the differential lives entirely in the sink).
    assert "$request->cookie('pref')" in vulnerable_src
    assert "$request->cookie('pref')" in secure_src


def test_insecure_deserialization_controllers_have_disjoint_paths_from_sibling_circlefeed_cells() -> None:
    """CircleFeed's fourth cell must never collide on a generated file path
    with its first three (access-control, webhook-signature, header-
    injection)."""
    emitter = LaravelEmitter()
    deserialize_paths = {emitter.render(c)[0].path for c in _cells().values()}
    access_control_manifest = load_manifest("lab/manifests/access_control_circlefeed_sample.yaml")
    webhook_manifest = load_manifest("lab/manifests/webhook_signature_circlefeed_sample.yaml")
    header_manifest = load_manifest("lab/manifests/header_injection_circlefeed_sample.yaml")
    assert deserialize_paths.isdisjoint({emitter.render(c)[0].path for c in access_control_manifest.cells})
    assert deserialize_paths.isdisjoint({emitter.render(c)[0].path for c in webhook_manifest.cells})
    assert deserialize_paths.isdisjoint({emitter.render(c)[0].path for c in header_manifest.cells})


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_cell() -> None:
    emitter = LaravelEmitter()
    for cell in _cells().values():
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin() -> None:
    """Every cell's only difference from the same cell with its pipeline
    emptied must be the transform region. `identity` (the empty-pipeline
    transform module) is registered in both `fuzzlab.labgen.modules` and
    `fuzzlab.labgen.emitters.php_laravel.modules`'s shared vocabulary, so an
    emptied-pipeline cell still renders a classifiable composition line --
    and the sink template's `deserialize_method` Jinja2 lookup is guarded
    with `is defined` for exactly this identity-emptied twin, which never
    runs a transform and so never sets that flag (the same guard
    `CC-LAB-0218`'s own `header_delivery_mode` needed, caught here by
    actually running this test rather than by inspection alone)."""
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
