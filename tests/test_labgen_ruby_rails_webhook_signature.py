"""Webhook-signature verification (CC-LAB-0072, ``ruby_rails`` Phase B):
Rails Phase B's first real implementation of the existing
``webhook_signature_verification`` sink family (``lab/safety_matrix.yaml`` --
no emitter had implemented this family in code before this lane), reusing
the existing ``naive_string_compare``/``constant_time_compare`` op
vocabulary verbatim.

Offline coverage here (Tier 0 / Tier 3 / matrix/verdict checks). The real,
executed, on-host proof -- a genuine HTTP round trip against a booted Rails
app, plus the actual timing-safety divergence between plain ``==`` and
``ActiveSupport::SecurityUtils.secure_compare`` -- lives in the sibling
``tests/test_labgen_ruby_rails_webhook_signature_live_boot.py``.
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter
from fuzzlab.labgen.schema import Cell, Pipeline, SinkContext, load_manifest
from fuzzlab.labgen.verdict import Effect, load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/webhook_signature_rails_sample.yaml"

FAMILY = SinkContext(
    family="webhook_signature_verification", required_neutralizations=("weak_signature_comparison",)
)


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return RailsEmitter()


def _cell(manifest, cell_id: str) -> Cell:
    return next(c for c in manifest.cells if c.cell_id == cell_id)


# ---------------------------------------------------------------------------
# Safety matrix: ops reused verbatim, not minted new
# ---------------------------------------------------------------------------


def test_naive_string_compare_is_partial_not_no_effect(matrix) -> None:
    """D20's own distinction: this still correctly rejects a wrong signature
    and accepts a right one for any single well-formed request -- the
    vulnerability is a timing side channel, not a functional bypass."""
    entry = matrix.lookup("naive_string_compare", "webhook_signature_verification")
    assert entry.effect is Effect.PARTIAL
    assert entry.neutralizes == ("weak_signature_comparison",)


def test_constant_time_compare_neutralises(matrix) -> None:
    entry = matrix.lookup("constant_time_compare", "webhook_signature_verification")
    assert entry.effect is Effect.NEUTRALISES
    assert entry.neutralizes == ("weak_signature_comparison",)


# ---------------------------------------------------------------------------
# Derived verdicts
# ---------------------------------------------------------------------------

EXPECTED_VERDICTS = {
    "LABGEN-RR-0002": ("VULNERABLE", "easy"),
    "LABGEN-RR-0003": ("SECURE", None),
}


def test_every_cell_of_the_new_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_the_pair_is_a_minimal_pair_on_class_and_family(manifest) -> None:
    v = _cell(manifest, "LABGEN-RR-0002")
    s = _cell(manifest, "LABGEN-RR-0003")
    assert v.vuln_class == s.vuln_class == "webhook_signature"
    assert v.sink_context.family == s.sink_context.family == "webhook_signature_verification"
    assert v.sink_context.required_neutralizations == s.sink_context.required_neutralizations
    assert v.transform.ops != s.transform.ops


# ---------------------------------------------------------------------------
# Emitter: shape support, rendered content
# ---------------------------------------------------------------------------


def test_supports_the_webhook_signature_shape(emitter) -> None:
    assert emitter.supports("webhook_signature", FAMILY) is True


def test_vulnerable_cell_compares_with_naive_equality(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RR-0002"))[0].content.decode("utf-8")
    assert "if computed == provided" in content
    assert "ActiveSupport::SecurityUtils.secure_compare(computed, provided)" not in content


def test_secure_cell_compares_with_active_support_secure_compare(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RR-0003"))[0].content.decode("utf-8")
    assert "ActiveSupport::SecurityUtils.secure_compare(computed, provided)" in content


def test_both_cells_recompute_the_hmac_over_the_raw_body(emitter, manifest) -> None:
    for cell_id in ("LABGEN-RR-0002", "LABGEN-RR-0003"):
        content = emitter.render(_cell(manifest, cell_id))[0].content.decode("utf-8")
        assert "body = request.body.read" in content
        assert 'OpenSSL::HMAC.digest("sha256", secret, body)' in content


def test_every_cell_of_the_new_manifest_renders_and_has_no_view(emitter, manifest) -> None:
    for cell in manifest.cells:
        files = emitter.render(cell)  # must not raise
        assert len(files) == 1, cell.cell_id  # no view file for this shape
        assert files[0].path.endswith("_controller.rb")


# ---------------------------------------------------------------------------
# Conformance: static-precheck flag, Tier 0, Tier 3
# ---------------------------------------------------------------------------


def test_the_new_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        status = static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)
        assert status is static_precheck.StaticPrecheckStatus.UNINFORMATIVE


def test_tier3_whole_sample_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, manifest.cells)


def test_tier3_renders_one_unique_path_per_cell(emitter, manifest) -> None:
    tree = tier3.render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby interpreter not available on this build host (PA-0005)")
def test_tier0_ruby_syntax_check_passes_for_every_new_cell(emitter, manifest) -> None:
    for cell in manifest.cells:
        for result in tier0.lint_ruby_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: ruby -c failed: {result.detail}"


def test_tier0_naive_minimal_pair_check_holds_between_the_twins(emitter, manifest) -> None:
    """``fuzzlab.labgen.minimal_pair`` is PHP-oriented only (its own module
    docstring) -- ``ruby_rails`` is not wired into it yet (this stack's own
    Phase A docstring), so this stack's own Tier-0 minimal-pair check calls
    the naive, structural fallback directly, per ``tier0``'s own module
    docstring guidance for a non-PHP emitter."""
    vulnerable = emitter.render(_cell(manifest, "LABGEN-RR-0002"))
    secure = emitter.render(_cell(manifest, "LABGEN-RR-0003"))
    result = tier0._naive_minimal_pair_check(vulnerable, secure)
    assert result.is_minimal_pair is True
    assert result.differing_paths
