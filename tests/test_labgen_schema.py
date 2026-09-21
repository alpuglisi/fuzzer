"""Tests for the lab-generator manifest schema + IR (T-LAB0.1/T-LAB0.3
foundation)."""

import copy

import pytest

from fuzzlab.labgen import schema

EXAMPLE_MANIFEST = "lab/manifests/example_phase0_scaffold.yaml"


def _valid_manifest_dict():
    return {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "cells": [
            {
                "cell_id": "T-0001",
                "class": "sqli",
                "stack_profile": "php_current",
                "route": {"method": "GET", "path": "/x"},
                "sink_context": {
                    "family": "sql_numeric_literal",
                    "required_neutralizations": ["sql_syntax_break"],
                },
                "transform": [],
            }
        ],
    }


def test_manifest_schema_loads():
    s = schema.load_manifest_schema()
    assert s["$id"].endswith("manifest.schema.json")


def test_valid_manifest_dict_validates():
    schema.validate_manifest(_valid_manifest_dict())


def test_missing_required_field_rejected():
    bad = _valid_manifest_dict()
    del bad["cells"][0]["sink_context"]
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(bad)


def test_bare_string_sink_context_rejected():
    """The whole point of CR-LAB-0001 §3: sink_context must be structured,
    never a bare string like the pre-D20 model."""
    bad = _valid_manifest_dict()
    bad["cells"][0]["sink_context"] = "sql"
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(bad)


def test_transform_must_be_an_array_not_a_single_enum():
    """The whole point of CR-LAB-0001 §3: transform is an ordered pipeline,
    never a single enum value."""
    bad = _valid_manifest_dict()
    bad["cells"][0]["transform"] = "param_bind"
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(bad)


def test_unknown_top_level_field_rejected():
    bad = _valid_manifest_dict()
    bad["unexpected"] = True
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(bad)


def test_duplicate_cell_id_rejected():
    d = _valid_manifest_dict()
    d["cells"].append(copy.deepcopy(d["cells"][0]))
    with pytest.raises(schema.ManifestError):
        schema.Manifest.from_dict(d)


def test_load_example_manifest_end_to_end():
    manifest = schema.load_manifest(EXAMPLE_MANIFEST)
    assert manifest.manifest_version == 1
    assert manifest.safety_matrix_version == 1
    assert len(manifest.cells) == 4
    by_id = {c.cell_id: c for c in manifest.cells}
    vulnerable_twin = by_id["LABGEN-EX-0001"]
    secure_twin = by_id["LABGEN-EX-0002"]
    # Minimal-pair shape check (full mechanical enforcement is Phase 1):
    # the two twins differ only in the transform region.
    assert vulnerable_twin.sink_context == secure_twin.sink_context
    assert vulnerable_twin.route == secure_twin.route
    assert vulnerable_twin.transform.ops == ()
    assert secure_twin.transform.ops == ("param_bind",)


def test_missing_manifest_file_raises_actionable_error(tmp_path):
    with pytest.raises(schema.ManifestError) as exc:
        schema.load_manifest(tmp_path / "does-not-exist.yaml")
    assert "not found" in str(exc.value)


# --- T-LAB2.1: axis_ranges (covering-array resolver wiring) -----------------

REAL_PAGES_MANIFEST = "lab/manifests/phase0_real_pages_sample.yaml"


def _axis_range_manifest_dict(**overrides):
    d = {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "axis_ranges": [
            {
                "cell_id_prefix": "LABGEN-CA-",
                "stack_profile": "php_current",
                "route": {"method": "GET", "path": "/example/ca.php"},
                "transform": [],
                "sink_context_neutralizations": {
                    "sql_numeric_literal": ["sql_syntax_break"],
                    "html_body": ["html_tag_break"],
                },
                "factors": {
                    "class": ["sqli", "xss"],
                    "sink_context_family": ["sql_numeric_literal", "html_body"],
                },
            }
        ],
    }
    d.update(overrides)
    return d


def test_axis_range_factor_names_match_schema_allowlist():
    """PA-0010: the loader's recognized axis names and the schema's own
    `$defs/axis_range.factors.properties` allowlist must never drift apart —
    a name accepted by one and not the other is a silent wrong-granularity
    failure mode, not a loud error."""
    s = schema.load_manifest_schema()
    schema_axis_names = set(s["$defs"]["axis_range"]["properties"]["factors"]["properties"])
    assert schema_axis_names == schema.AXIS_RANGE_FACTOR_NAMES


def test_axis_range_manifest_validates():
    schema.validate_manifest(_axis_range_manifest_dict())


def test_manifest_without_cells_or_axis_ranges_rejected():
    bad = {"manifest_version": 1, "safety_matrix_version": 1}
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(bad)


def test_axis_range_expands_to_expected_cell_count_and_pairwise_strength():
    """2 classes x 2 sink_context_family levels, strength=2 (default) must
    cover every (class, family) pair at least once -- for a 2x2 model the
    covering array degenerates to exactly the 4-row full factorial, which
    doubles as a precise expected-count check."""
    manifest = schema.Manifest.from_dict(_axis_range_manifest_dict())
    assert len(manifest.cells) == 4
    seen_pairs = {(c.vuln_class, c.sink_context.family) for c in manifest.cells}
    assert seen_pairs == {
        ("sqli", "sql_numeric_literal"),
        ("sqli", "html_body"),
        ("xss", "sql_numeric_literal"),
        ("xss", "html_body"),
    }
    # Fixed (non-factor) fields propagate to every generated cell.
    for c in manifest.cells:
        assert c.stack_profile == "php_current"
        assert c.route.method == "GET" and c.route.path == "/example/ca.php"
        assert c.transform.ops == ()
    # required_neutralizations tracks sink_context_family, per the block's
    # sink_context_neutralizations map.
    by_family = {c.sink_context.family: c.sink_context.required_neutralizations for c in manifest.cells}
    assert by_family["sql_numeric_literal"] == ("sql_syntax_break",)
    assert by_family["html_body"] == ("html_tag_break",)


def test_axis_range_cell_ids_use_prefix_and_are_unique():
    manifest = schema.Manifest.from_dict(_axis_range_manifest_dict())
    ids = sorted(c.cell_id for c in manifest.cells)
    assert ids == ["LABGEN-CA-0001", "LABGEN-CA-0002", "LABGEN-CA-0003", "LABGEN-CA-0004"]


def test_axis_range_expansion_is_deterministic():
    a = schema.Manifest.from_dict(_axis_range_manifest_dict())
    b = schema.Manifest.from_dict(_axis_range_manifest_dict())
    assert a.cells == b.cells


def test_axis_range_appends_after_explicit_cells():
    d = _axis_range_manifest_dict()
    d["cells"] = [
        {
            "cell_id": "T-EXPLICIT-0001",
            "class": "sqli",
            "stack_profile": "php_current",
            "route": {"method": "GET", "path": "/x"},
            "sink_context": {"family": "sql_numeric_literal", "required_neutralizations": ["sql_syntax_break"]},
            "transform": [],
        }
    ]
    manifest = schema.Manifest.from_dict(d)
    assert len(manifest.cells) == 5
    assert manifest.cells[0].cell_id == "T-EXPLICIT-0001"
    assert {c.cell_id for c in manifest.cells[1:]} == {
        "LABGEN-CA-0001",
        "LABGEN-CA-0002",
        "LABGEN-CA-0003",
        "LABGEN-CA-0004",
    }


def test_axis_range_duplicate_cell_id_across_explicit_and_generated_rejected():
    d = _axis_range_manifest_dict()
    d["cells"] = [
        {
            "cell_id": "LABGEN-CA-0001",
            "class": "sqli",
            "stack_profile": "php_current",
            "route": {"method": "GET", "path": "/x"},
            "sink_context": {"family": "sql_numeric_literal", "required_neutralizations": ["sql_syntax_break"]},
            "transform": [],
        }
    ]
    with pytest.raises(schema.ManifestError):
        schema.Manifest.from_dict(d)


def test_axis_range_missing_fixed_class_raises_manifest_error():
    d = _axis_range_manifest_dict()
    # Two factors (so covertable's strength=2 array is non-empty), neither
    # of which is 'class', and no fixed 'class' either -> fail closed,
    # not defaulted.
    d["axis_ranges"][0]["factors"] = {
        "sink_context_family": ["sql_numeric_literal", "html_body"],
        "route_method": ["GET", "POST"],
    }
    with pytest.raises(schema.ManifestError, match="'class'"):
        schema.Manifest.from_dict(d)


def test_axis_range_missing_neutralization_mapping_raises_manifest_error():
    d = _axis_range_manifest_dict()
    del d["axis_ranges"][0]["sink_context_neutralizations"]["html_body"]
    with pytest.raises(schema.ManifestError, match="sink_context_neutralizations"):
        schema.Manifest.from_dict(d)


def test_axis_range_unrecognized_factor_name_rejected_by_schema():
    d = _axis_range_manifest_dict()
    d["axis_ranges"][0]["factors"]["not_a_real_axis"] = ["a", "b"]
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(d)


def test_axis_range_bad_covering_array_config_surfaces_as_manifest_error():
    """resolver.CoveringArrayError from a malformed factors mapping (e.g. an
    empty level list, which the schema's own minItems already blocks -- this
    goes through resolver.expand() directly via Manifest.from_dict with
    validate=False, so a hand-built bad block still fails closed)."""
    d = _axis_range_manifest_dict()
    d["axis_ranges"][0]["factors"]["class"] = []
    with pytest.raises(schema.ManifestError):
        schema.Manifest.from_dict(d, validate=False)


# --- Regression: today's explicit-cells-only format is unaffected ----------


def test_explicit_cells_only_manifest_unaffected_by_axis_ranges_support():
    d = _valid_manifest_dict()
    manifest = schema.Manifest.from_dict(d)
    assert len(manifest.cells) == 1
    assert manifest.cells[0].cell_id == "T-0001"


def test_load_real_pages_sample_manifest_end_to_end_regression():
    manifest = schema.load_manifest(REAL_PAGES_MANIFEST)
    assert manifest.manifest_version == 1
    assert manifest.safety_matrix_version == 1
    assert len(manifest.cells) == 8
    assert [c.cell_id for c in manifest.cells] == [f"LABGEN-RP-{i:04d}" for i in range(1, 9)]
