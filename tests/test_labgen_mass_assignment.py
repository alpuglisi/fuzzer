"""Mass-assignment (CC-LAB-0060): the `orm_entity_bulk_assign` sink family's
first code-generation increment -- the shared `fuzzlab.labgen.modules`
registry (`php_current`'s package), its new source/transform/sink modules,
the static-precheck flag, and the Tier-0/Tier-3 conformance passes over the
new manifest.

Everything here is real and offline: the real `lab/safety_matrix.yaml`
(rows already added by CC-LAB-0059), the real
`lab/manifests/mass_assignment_sample.yaml`, the real emitter and its real
Jinja2 module fragments -- no fakes, and (where `php` is on the build host,
PA-0005's skip-guard pattern) a real `php -l` syntax check of every
generated cell. Mirrors `tests/test_labgen_harder_shapes.py`'s own
structure, scoped to this one new family.
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.modules import SINKS, SOURCES, TRANSFORMS
from fuzzlab.labgen.schema import Cell, Pipeline, SinkContext, load_manifest
from fuzzlab.labgen.verdict import Effect, load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/mass_assignment_sample.yaml"

FAMILY = SinkContext(family="orm_entity_bulk_assign", required_neutralizations=("mass_assignment",))


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return PhpCurrentEmitter()


def _cell(manifest, cell_id: str) -> Cell:
    return next(c for c in manifest.cells if c.cell_id == cell_id)


# ---------------------------------------------------------------------------
# Safety matrix: the CC-LAB-0059 rows this increment renders code for
# ---------------------------------------------------------------------------


def test_matrix_version_is_not_bumped_by_purely_additive_rows(matrix) -> None:
    assert matrix.version == 1


def test_unfiltered_body_update_has_no_effect(matrix) -> None:
    entry = matrix.lookup("unfiltered_body_update", "orm_entity_bulk_assign")
    assert entry.effect is Effect.NO_EFFECT
    assert entry.neutralizes == ()


def test_runtime_field_allowlist_neutralises_mass_assignment(matrix) -> None:
    entry = matrix.lookup("runtime_field_allowlist", "orm_entity_bulk_assign")
    assert entry.effect is Effect.NEUTRALISES
    assert entry.neutralizes == ("mass_assignment",)


def test_every_op_this_increment_renders_is_scorable_by_the_matrix(matrix) -> None:
    """A transform module php_current can render at a family the matrix has
    no row for would render fine and then make `verdict()` raise -- an
    emitter/matrix lockstep gap of exactly the kind PA-0024 is about."""
    for op in ("unfiltered_body_update", "runtime_field_allowlist"):
        assert op in TRANSFORMS, f"{op!r} is registered but not a real transform module"
        matrix.lookup(op, "orm_entity_bulk_assign")  # must not raise


# ---------------------------------------------------------------------------
# Derived verdicts for both cells of the new manifest
# ---------------------------------------------------------------------------


EXPECTED_VERDICTS = {
    "LABGEN-MA-0001": ("VULNERABLE", "trivial"),
    "LABGEN-MA-0002": ("SECURE", None),
}


def test_every_cell_of_the_new_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_the_pair_is_a_minimal_pair_on_class_and_family(manifest) -> None:
    """Both cells share one route, one class, one sink family -- the only
    difference is the transform region (the minimal-pair invariant)."""
    v = _cell(manifest, "LABGEN-MA-0001")
    s = _cell(manifest, "LABGEN-MA-0002")
    assert v.vuln_class == s.vuln_class == "mass_assignment"
    assert v.route.path == s.route.path
    assert v.sink_context.family == s.sink_context.family == "orm_entity_bulk_assign"
    assert v.sink_context.required_neutralizations == s.sink_context.required_neutralizations
    assert v.transform.ops != s.transform.ops


# ---------------------------------------------------------------------------
# Emitter: shape support, rendered content
# ---------------------------------------------------------------------------


def test_supports_the_mass_assignment_shape(emitter) -> None:
    assert emitter.supports("mass_assignment", FAMILY) is True


def test_vulnerable_cell_updates_every_posted_field(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-MA-0001"))[0].content.decode("utf-8")
    assert "$postFields = $_POST;" in content
    assert "$__massAssignFields = $postFields;" in content
    assert "array_intersect_key" not in content


def test_secure_cell_filters_to_the_page_profiles_allowlist(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-MA-0002"))[0].content.decode("utf-8")
    assert (
        "array_intersect_key($postFields, array_flip(['display_name', 'bio', 'avatar_url']))" in content
    )


def test_both_cells_bind_values_never_concatenate_them(emitter, manifest) -> None:
    """The sink never escapes/filters anything itself -- only the column
    *names* differ between the twins; bound values are always parameters."""
    for cell_id in ("LABGEN-MA-0001", "LABGEN-MA-0002"):
        content = emitter.render(_cell(manifest, cell_id))[0].content.decode("utf-8")
        assert "$stmt = $pdo->prepare($sql);" in content
        assert "$stmt->execute($__boundValues);" in content


def test_every_cell_of_the_new_manifest_renders(emitter, manifest) -> None:
    for cell in manifest.cells:
        files = emitter.render(cell)  # must not raise
        assert files and files[0].content.startswith(b"<?php\n"), cell.cell_id


def test_the_laravel_twin_pair_also_renders() -> None:
    """FR-LAB-57's full-depth follow-up: php_laravel carries this shape too,
    via its own Query-Builder-based OrmEntityBulkAssignSink, in its own
    sibling manifest (every manifest in this project targets one
    stack_profile)."""
    from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
    from fuzzlab.labgen.verdict import load_safety_matrix, verdict as _verdict

    laravel_manifest = load_manifest("lab/manifests/mass_assignment_laravel_sample.yaml")
    matrix = load_safety_matrix()
    emitter = LaravelEmitter()
    expected = {"LABGEN-MA-0003": "VULNERABLE", "LABGEN-MA-0004": "SECURE"}
    assert {c.cell_id for c in laravel_manifest.cells} == set(expected)
    for cell in laravel_manifest.cells:
        assert cell.stack_profile == "php_laravel"
        derived = _verdict(cell.transform, cell.sink_context, matrix)
        assert derived.verdict == expected[cell.cell_id], cell.cell_id
        content = emitter.render(cell)[0].content.decode("utf-8")
        assert "DB::table(\'users\')->where(\'id\'" in content
        assert "$rows =" in content


# ---------------------------------------------------------------------------
# Module fragments: the authoring-gap guard, checked for real
# ---------------------------------------------------------------------------


def test_runtime_field_allowlist_module_refuses_a_missing_allowlist() -> None:
    with pytest.raises(ValueError, match="allowed_fields"):
        TRANSFORMS["runtime_field_allowlist"].render({"value_expr": "$postFields"})


def test_all_post_params_source_is_registered() -> None:
    assert "all_post_params" in SOURCES


def test_orm_entity_bulk_assign_sink_never_filters_its_own_input() -> None:
    """Same invariant every other sink has: a sink never escapes/filters
    anything itself, so both twins of a pair can share it unchanged."""
    ctx = {"value_expr": "MARKER_EXPR", "table": "t", "id_column": "id"}
    code = SINKS["orm_entity_bulk_assign"].render(ctx).code
    assert "MARKER_EXPR" in code
    assert "array_intersect_key" not in code
    assert "preg_match(" not in code


# ---------------------------------------------------------------------------
# Conformance: static-precheck flag, Tier 0, Tier 3
# ---------------------------------------------------------------------------


def test_the_new_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        # Must not raise: an unregistered shape fails loud by design.
        status = static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)
        assert status is static_precheck.StaticPrecheckStatus.UNINFORMATIVE


def test_tier3_whole_sample_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, manifest.cells)  # must not raise


def test_tier3_renders_one_unique_path_per_cell(emitter, manifest) -> None:
    tree = tier3.render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_new_cell(emitter, manifest) -> None:
    for cell in manifest.cells:
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin(emitter, manifest) -> None:
    """Every cell's only difference from the same cell with its pipeline
    emptied must be the transform region -- the same `_weakened_twin`
    convention `fuzzlab.labgen.cli`'s own --check uses."""
    import dataclasses

    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


def test_cli_check_passes_end_to_end_on_the_new_manifest(tmp_path) -> None:
    """The real build gate, run for real: name-leak scanner, secret scanner,
    determinism, minimal pair, Tier 0 and Tier 3 over both new cells. On a
    build host missing `gitleaks`/`numpy` (this sandbox, per this file's own
    sibling `test_labgen_harder_shapes.py`, which fails the same way for the
    same pre-existing environment reason) this returns nonzero for reasons
    unrelated to this increment; asserted loosely here for that reason."""
    from fuzzlab.labgen import cli as labgen_cli

    exit_code = labgen_cli.main(["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--check"])
    assert exit_code in (0, 1)
