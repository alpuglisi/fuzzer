"""CWE-915 mass assignment (CC-LAB-0073, ``ruby_rails`` Phase B): the first
Ruby/Rails-idiomatic instance of the existing ``orm_entity_bulk_assign`` sink
family (``lab/safety_matrix.yaml``, previously implemented only by
``php_laravel``'s ``DB::table(...)->update($fields)`` twin) -- Rails' own
``permit!`` vs an explicit ``permit(:a, :b)`` strong-parameters allowlist.

Offline coverage here (Tier 0 / Tier 3 / matrix/verdict checks). The real,
executed, on-host proof -- a genuine HTTP PATCH round trip against a booted
Rails app and a real ActiveRecord/SQLite write, showing the attacker's
`role` field lands in the vulnerable twin and not the secure one -- lives in
the sibling ``tests/test_labgen_ruby_rails_mass_assignment_live_boot.py``.
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter
from fuzzlab.labgen.emitters.ruby_rails.modules import TRANSFORMS
from fuzzlab.labgen.schema import Cell, SinkContext, load_manifest
from fuzzlab.labgen.verdict import Effect, load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/mass_assignment_rails_sample.yaml"

FAMILY = SinkContext(family="orm_entity_bulk_assign", required_neutralizations=("mass_assignment",))


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
# Safety matrix: the two new, Rails-strong-parameters-specific ops
# ---------------------------------------------------------------------------


def test_permit_bang_unrestricted_has_no_effect(matrix) -> None:
    entry = matrix.lookup("permit_bang_unrestricted", "orm_entity_bulk_assign")
    assert entry.effect is Effect.NO_EFFECT
    assert entry.neutralizes == ()


def test_strong_params_explicit_allowlist_neutralises_mass_assignment(matrix) -> None:
    entry = matrix.lookup("strong_params_explicit_allowlist", "orm_entity_bulk_assign")
    assert entry.effect is Effect.NEUTRALISES
    assert entry.neutralizes == ("mass_assignment",)


# ---------------------------------------------------------------------------
# Derived verdicts
# ---------------------------------------------------------------------------

EXPECTED_VERDICTS = {
    "LABGEN-RR-0004": ("VULNERABLE", "trivial"),
    "LABGEN-RR-0005": ("SECURE", None),
}


def test_every_cell_of_the_new_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_the_pair_is_a_minimal_pair_on_class_and_family(manifest) -> None:
    v = _cell(manifest, "LABGEN-RR-0004")
    s = _cell(manifest, "LABGEN-RR-0005")
    assert v.vuln_class == s.vuln_class == "mass_assignment"
    # This stack is one controller/route per cell (unlike php_current/
    # php_laravel's shared-page-profile design), so a minimal pair here is
    # necessarily two distinct routes, not one shared route with a
    # differing transform -- both cells still target the same table/model,
    # same HTTP method, and the same sink family/required concern.
    assert v.route.method == s.route.method == "PATCH"
    assert v.sink_context.family == s.sink_context.family == "orm_entity_bulk_assign"
    assert v.sink_context.required_neutralizations == s.sink_context.required_neutralizations
    assert v.transform.ops != s.transform.ops


# ---------------------------------------------------------------------------
# Emitter: shape support, rendered content
# ---------------------------------------------------------------------------


def test_supports_the_mass_assignment_shape(emitter) -> None:
    assert emitter.supports("mass_assignment", FAMILY) is True


def test_vulnerable_cell_uses_permit_bang(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RR-0004"))[0].content.decode("utf-8")
    assert "attrs = attrs.permit!" in content
    assert "permit(:" not in content


def test_secure_cell_filters_to_the_shape_contexts_allowlist(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RR-0005"))[0].content.decode("utf-8")
    assert "attrs = attrs.permit(:username, :bio)" in content
    assert "permit!" not in content


def test_both_cells_write_via_the_same_active_record_update(emitter, manifest) -> None:
    """The sink never filters anything itself -- only the transform region
    differs between the twins."""
    for cell_id in ("LABGEN-RR-0004", "LABGEN-RR-0005"):
        content = emitter.render(_cell(manifest, cell_id))[0].content.decode("utf-8")
        assert 'User.find_by!(username: "shopper1")' in content
        assert "user.update!(attrs)" in content


def test_every_cell_of_the_new_manifest_renders_and_has_no_view(emitter, manifest) -> None:
    for cell in manifest.cells:
        files = emitter.render(cell)
        assert len(files) == 1, cell.cell_id
        assert files[0].path.endswith("_controller.rb")


# ---------------------------------------------------------------------------
# Module fragments: the authoring-gap guard, checked for real
# ---------------------------------------------------------------------------


def test_strong_params_explicit_allowlist_module_refuses_a_missing_allowlist() -> None:
    with pytest.raises(ValueError, match="allowed_fields"):
        TRANSFORMS["strong_params_explicit_allowlist"].render({"var_name": "attrs"})


def test_strong_params_explicit_allowlist_rejects_a_non_identifier_field() -> None:
    with pytest.raises(ValueError, match="bare identifier"):
        TRANSFORMS["strong_params_explicit_allowlist"].render(
            {"var_name": "attrs", "allowed_fields": ("bio); System.exit",)}
        )


# ---------------------------------------------------------------------------
# Conformance: static-precheck flag, Tier 0, Tier 3
# ---------------------------------------------------------------------------


def test_the_shape_reuses_the_existing_static_precheck_flag(manifest) -> None:
    """(mass_assignment, orm_entity_bulk_assign) was already registered by
    CC-LAB-0063/0064 for php_current/php_laravel -- static_precheck is keyed
    on (vuln_class, sink_family) only, not stack_profile, so this Rails
    cell reuses that same row rather than needing a new one."""
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
    vulnerable = emitter.render(_cell(manifest, "LABGEN-RR-0004"))
    secure = emitter.render(_cell(manifest, "LABGEN-RR-0005"))
    result = tier0._naive_minimal_pair_check(vulnerable, secure)
    assert result.is_minimal_pair is True
    assert result.differing_paths
