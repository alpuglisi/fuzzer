"""Unit + Tier 0/Tier 3 coverage for `php_laravel`'s response-header-
injection cell (`CC-LAB-0218`, CircleFeed -- category 2's Facebook pick,
third designed cell). This project's first real implementation of
`lab/safety_matrix.yaml`'s `http_response_header_value` sink family
(`raw_socket_response_write`/`allowlist_and_runtime_crlf_rejection`, both
existed, unimplemented, since the family was added).

No network/composer/php required beyond `php -l` (Tier 0), mirroring
`tests/test_labgen_access_control_circlefeed.py`'s own structure. The real,
executed differential (a genuine response-splitting proof, raw header
inspection both directions) is proven separately, at the raw-socket layer
-- not through this route, since PHP's own `header()` function
unconditionally rejects an embedded CR/LF since PHP 5.1.2 (see
`CC-LAB-0218`'s change-control entry) -- in
`tests/test_labgen_header_injection_circlefeed_live_boot.py`.
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/header_injection_circlefeed_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-CF-0005": "VULNERABLE",  # raw_socket_response_write
    "LABGEN-CF-0006": "SECURE",  # allowlist_and_runtime_crlf_rejection
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


def test_vulnerable_twin_concatenates_raw_secure_twin_validates_and_uses_away() -> None:
    emitter = LaravelEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-CF-0005"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-CF-0006"])[0].content.decode("utf-8")
    # Vulnerable: the literal raw-concatenation footgun, no CRLF/allowlist
    # check anywhere before it, and never Laravel's structured helper.
    assert 'header("Location: " . $next);' in vulnerable_src
    assert "redirect()->away" not in vulnerable_src
    assert "preg_match" not in vulnerable_src
    # Secure: the runtime CRLF/control-character rejection plus the
    # same-origin-relative-path allowlist, then the structured helper --
    # never the raw header() call.
    assert "preg_match('/[\\x00-\\x1F\\x7F]/'" in secure_src
    assert "abort(400, 'invalid redirect target')" in secure_src
    assert "redirect()->away($next)" in secure_src
    assert 'header("Location: "' not in secure_src


def test_header_injection_controllers_have_disjoint_paths_from_sibling_circlefeed_cells() -> None:
    """CircleFeed's third cell must never collide on a generated file path
    with its first two (access-control, webhook-signature) or with Huddle
    Hub's own header-injection cell on the same shared emitter."""
    emitter = LaravelEmitter()
    header_paths = {emitter.render(c)[0].path for c in _cells().values()}
    access_control_manifest = load_manifest("lab/manifests/access_control_circlefeed_sample.yaml")
    webhook_manifest = load_manifest("lab/manifests/webhook_signature_circlefeed_sample.yaml")
    huddlehub_header_manifest = load_manifest("lab/manifests/header_injection_huddlehub_sample.yaml")
    assert header_paths.isdisjoint({emitter.render(c)[0].path for c in access_control_manifest.cells})
    assert header_paths.isdisjoint({emitter.render(c)[0].path for c in webhook_manifest.cells})
    assert header_paths.isdisjoint({emitter.render(c)[0].path for c in huddlehub_header_manifest.cells})


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
