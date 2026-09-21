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
