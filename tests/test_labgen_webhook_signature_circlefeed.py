"""Unit + Tier 0/Tier 3 coverage for `php_laravel`'s Groups webhook receiver
cell (`CC-LAB-0217`, CircleFeed -- category 2's Facebook pick, second
designed cell). Reuses `lab/safety_matrix.yaml`'s existing
`webhook_signature_verification` sink family / `weak_signature_comparison`
concern and the `loose_equality_compare`/`constant_time_compare` ops Huddle
Hub's own `/webhooks/events` cell already registers (`CC-LAB-0133`) -- pure
page-profile wiring (a new `/groups/webhook` page profile, own lab-only
secret), no new transform/sink module.

No network/composer/php required beyond `php -l` (Tier 0), mirroring
`tests/test_labgen_access_control_circlefeed.py`'s own structure. The real,
executed differential is proven separately in two files, mirroring Huddle
Hub's own split:

* `tests/test_labgen_php_laravel_webhook_signature_circlefeed_live_boot.py`
  -- ordinary HTTP correctness (a genuinely correct signature is accepted,
  a genuinely wrong one is rejected).
* `tests/test_labgen_webhook_signature_circlefeed_magic_hash.py` -- the
  actual PHP `==` "magic hash" type-juggling comparison-operator
  differential, executed by a real `php` interpreter (a live HTTP test
  cannot force a real SHA-256 HMAC output to itself be magic-hash-shaped).
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/webhook_signature_circlefeed_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-CF-0003": "VULNERABLE",  # loose_equality_compare
    "LABGEN-CF-0004": "SECURE",  # constant_time_compare
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


def test_vulnerable_twin_uses_loose_equality_secure_twin_uses_hash_equals() -> None:
    emitter = LaravelEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-CF-0003"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-CF-0004"])[0].content.decode("utf-8")
    assert "!= $__webhookSignature" in vulnerable_src
    assert "hash_equals(" not in vulnerable_src
    assert "hash_equals($__expectedSignature, $__webhookSignature)" in secure_src


def test_circlefeed_webhook_secret_is_distinct_from_huddlehubs() -> None:
    """A new, own lab-only secret -- never Huddle Hub's, so the two apps'
    cells can never be confused by a shared value."""
    emitter = LaravelEmitter()
    src = emitter.render(_cells()["LABGEN-CF-0003"])[0].content.decode("utf-8")
    assert "lab-only-circlefeed-webhook-secret" in src
    assert "lab-only-huddlehub-webhook-secret" not in src


def test_webhook_controllers_have_disjoint_paths_from_huddlehub_and_access_control() -> None:
    """CircleFeed's own two designed cells so far, plus Huddle Hub's, must
    never collide on a generated file path."""
    emitter = LaravelEmitter()
    cf_webhook_paths = {emitter.render(c)[0].path for c in _cells().values()}
    huddlehub = load_manifest("lab/manifests/webhook_signature_huddlehub_sample.yaml")
    hhub_paths = {emitter.render(c)[0].path for c in huddlehub.cells}
    cf_access_control = load_manifest("lab/manifests/access_control_circlefeed_sample.yaml")
    cf_ac_paths = {emitter.render(c)[0].path for c in cf_access_control.cells}
    assert cf_webhook_paths.isdisjoint(hhub_paths)
    assert cf_webhook_paths.isdisjoint(cf_ac_paths)


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_cell() -> None:
    emitter = LaravelEmitter()
    for cell in _cells().values():
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin() -> None:
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
