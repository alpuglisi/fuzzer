"""CWE-502 insecure deserialization (CC-LAB-0074, ``ruby_rails`` Phase B):
the first Ruby/Psych instance of the existing ``object_deserialization``
sink family (``lab/safety_matrix.yaml``, not previously implemented by any
emitter) -- ``YAML.unsafe_load`` vs ``YAML.safe_load``.

Offline coverage here (Tier 0 / Tier 3 / matrix/verdict checks). The real,
executed, on-host proof -- a genuine HTTP POST round trip against a booted
Rails app, showing a real ``!ruby/object:OpenStruct`` YAML payload actually
constructs an ``OpenStruct`` under ``unsafe_load`` and is rejected
(``Psych::DisallowedClass``) under ``safe_load`` -- lives in the sibling
``tests/test_labgen_ruby_rails_insecure_deserialization_live_boot.py``.
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter
from fuzzlab.labgen.schema import Cell, SinkContext, load_manifest
from fuzzlab.labgen.verdict import Effect, load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/insecure_deserialization_rails_sample.yaml"

FAMILY = SinkContext(family="object_deserialization", required_neutralizations=("insecure_deserialization",))


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
# Safety matrix: the two new Psych-specific ops
# ---------------------------------------------------------------------------


def test_yaml_unsafe_load_has_no_effect(matrix) -> None:
    entry = matrix.lookup("yaml_unsafe_load", "object_deserialization")
    assert entry.effect is Effect.NO_EFFECT
    assert entry.neutralizes == ()


def test_yaml_safe_load_neutralises_insecure_deserialization(matrix) -> None:
    entry = matrix.lookup("yaml_safe_load", "object_deserialization")
    assert entry.effect is Effect.NEUTRALISES
    assert entry.neutralizes == ("insecure_deserialization",)


# ---------------------------------------------------------------------------
# Derived verdicts
# ---------------------------------------------------------------------------

EXPECTED_VERDICTS = {
    "LABGEN-RR-0006": ("VULNERABLE", "trivial"),
    "LABGEN-RR-0007": ("SECURE", None),
}


def test_every_cell_of_the_new_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_the_pair_is_a_minimal_pair_on_class_and_family(manifest) -> None:
    v = _cell(manifest, "LABGEN-RR-0006")
    s = _cell(manifest, "LABGEN-RR-0007")
    assert v.vuln_class == s.vuln_class == "insecure_deserialization"
    assert v.sink_context.family == s.sink_context.family == "object_deserialization"
    assert v.sink_context.required_neutralizations == s.sink_context.required_neutralizations
    assert v.transform.ops != s.transform.ops


# ---------------------------------------------------------------------------
# Emitter: shape support, rendered content
# ---------------------------------------------------------------------------


def test_supports_the_insecure_deserialization_shape(emitter) -> None:
    assert emitter.supports("insecure_deserialization", FAMILY) is True


def test_vulnerable_cell_calls_unsafe_load(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RR-0006"))[0].content.decode("utf-8")
    assert "YAML.unsafe_load(raw_yaml)" in content
    assert "YAML.safe_load(raw_yaml)" not in content


def test_secure_cell_calls_safe_load(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RR-0007"))[0].content.decode("utf-8")
    assert "YAML.safe_load(raw_yaml)" in content
    assert "YAML.unsafe_load(raw_yaml)" not in content


def test_both_cells_report_the_result_or_the_raised_exception_class(emitter, manifest) -> None:
    for cell_id in ("LABGEN-RR-0006", "LABGEN-RR-0007"):
        content = emitter.render(_cell(manifest, cell_id))[0].content.decode("utf-8")
        assert "parsed.class.name" in content
        assert "rescue => e" in content
        assert "e.class.name" in content


def test_every_cell_of_the_new_manifest_renders_and_has_no_view(emitter, manifest) -> None:
    for cell in manifest.cells:
        files = emitter.render(cell)
        assert len(files) == 1, cell.cell_id
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
    vulnerable = emitter.render(_cell(manifest, "LABGEN-RR-0006"))
    secure = emitter.render(_cell(manifest, "LABGEN-RR-0007"))
    result = tier0._naive_minimal_pair_check(vulnerable, secure)
    assert result.is_minimal_pair is True
    assert result.differing_paths
