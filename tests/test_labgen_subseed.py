"""Tests for sub-seed derivation + canonical serialization (T-LAB0.5
scaffold)."""

import json

import pytest

from fuzzlab.labgen.subseed import canonical_json, derive_subseed, render_cell_stub
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix

EXAMPLE_MANIFEST = "lab/manifests/example_phase0_scaffold.yaml"
REAL_MATRIX_PATH = "lab/safety_matrix.yaml"


def test_derive_subseed_is_deterministic():
    a = derive_subseed("root", "cell-1", transform=("param_bind",), sink_family="sql", stack_profile="php")
    b = derive_subseed("root", "cell-1", transform=("param_bind",), sink_family="sql", stack_profile="php")
    assert a == b


def test_derive_subseed_changes_with_any_input():
    base = derive_subseed("root", "cell-1", transform=("param_bind",), sink_family="sql", stack_profile="php")
    variants = [
        derive_subseed("other-root", "cell-1", transform=("param_bind",), sink_family="sql", stack_profile="php"),
        derive_subseed("root", "cell-2", transform=("param_bind",), sink_family="sql", stack_profile="php"),
        derive_subseed("root", "cell-1", transform=(), sink_family="sql", stack_profile="php"),
        derive_subseed("root", "cell-1", transform=("param_bind",), sink_family="html", stack_profile="php"),
        derive_subseed("root", "cell-1", transform=("param_bind",), sink_family="sql", stack_profile="node"),
    ]
    assert len({base, *variants}) == len(variants) + 1


def test_canonical_json_sorts_keys_and_is_compact():
    out = canonical_json({"b": 1, "a": 2})
    assert out == b'{"a":2,"b":1}\n'


def test_canonical_json_rejects_floats():
    with pytest.raises(ValueError):
        canonical_json({"x": 1.5})


def test_canonical_json_two_calls_byte_identical():
    obj = {"nested": {"z": [3, 2, 1], "a": "x"}}
    assert canonical_json(obj) == canonical_json(obj)


def test_render_cell_stub_is_deterministic_and_valid_json():
    manifest = load_manifest(EXAMPLE_MANIFEST)
    matrix = load_safety_matrix(REAL_MATRIX_PATH)
    cell = manifest.cells[0]
    a = render_cell_stub(cell, matrix, "seed-1")
    b = render_cell_stub(cell, matrix, "seed-1")
    assert a == b
    parsed = json.loads(a.decode("utf-8"))
    assert parsed["cell_id"] == cell.cell_id
    assert parsed["verdict"]["verdict"] in ("VULNERABLE", "SECURE")


def test_render_cell_stub_changes_with_root_seed():
    manifest = load_manifest(EXAMPLE_MANIFEST)
    matrix = load_safety_matrix(REAL_MATRIX_PATH)
    cell = manifest.cells[0]
    a = render_cell_stub(cell, matrix, "seed-1")
    b = render_cell_stub(cell, matrix, "seed-2")
    assert a != b
    # ...but the derived verdict itself must not depend on the seed.
    assert json.loads(a)["verdict"] == json.loads(b)["verdict"]
