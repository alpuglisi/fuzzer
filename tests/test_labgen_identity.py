"""Tests for the identity/ownership graph schema + loader (Phase 2,
CR-LAB-0001 §8, L-P2.1)."""

import copy
from pathlib import Path

import pytest

from fuzzlab.labgen import identity

EXAMPLE_IDENTITIES = "lab/identities/identities.yaml"
VERDICT_SOURCE = Path("fuzzlab/labgen/verdict.py")


def _valid_graph_dict():
    return {
        "schema_version": 1,
        "identities": [
            {"id": "user_a", "role": "standard_user"},
            {"id": "user_b", "role": "standard_user"},
            {"id": "admin_a", "role": "admin"},
        ],
        "resources": [
            {
                "resource_id": "profile_user_a",
                "owner": "user_a",
                "cell_ids": ["LABGEN-EX-IDENTITY-0001"],
            }
        ],
        "authz_expectations": [
            {
                "cell_id": "LABGEN-EX-IDENTITY-0001",
                "endpoint": "/profile/{id}",
                "accessing_identity": "user_b",
                "target_resource": "profile_user_a",
                "expected_outcome": "denied",
            }
        ],
    }


# --- schema validation -----------------------------------------------------


def test_identities_schema_loads():
    s = identity.load_identities_schema()
    assert s["$id"].endswith("identities.schema.json")


def test_valid_identities_dict_validates():
    identity.validate_identities(_valid_graph_dict())


def test_missing_required_top_level_field_rejected():
    bad = copy.deepcopy(_valid_graph_dict())
    del bad["authz_expectations"]
    with pytest.raises(identity.IdentityGraphError):
        identity.validate_identities(bad)


def test_missing_identity_role_rejected():
    bad = copy.deepcopy(_valid_graph_dict())
    del bad["identities"][0]["role"]
    with pytest.raises(identity.IdentityGraphError):
        identity.validate_identities(bad)


def test_bad_expected_outcome_rejected():
    """expected_outcome is a binary allowed|denied enum (D20), not a free string."""
    bad = copy.deepcopy(_valid_graph_dict())
    bad["authz_expectations"][0]["expected_outcome"] = "maybe"
    with pytest.raises(identity.IdentityGraphError):
        identity.validate_identities(bad)


def test_missing_resource_owner_rejected():
    bad = copy.deepcopy(_valid_graph_dict())
    del bad["resources"][0]["owner"]
    with pytest.raises(identity.IdentityGraphError):
        identity.validate_identities(bad)


def test_missing_schema_file_raises_typed_error(tmp_path):
    with pytest.raises(identity.IdentityGraphError):
        identity.load_identities_schema(tmp_path / "does-not-exist.json")


# --- load_identities() round trip ------------------------------------------


def test_example_identities_file_loads():
    graph = identity.load_identities(EXAMPLE_IDENTITIES)
    assert graph.schema_version == 1
    assert {i.id for i in graph.identities} == {"user_a", "user_b", "admin_a"}
    assert graph.identity_by_id("user_a").role == "standard_user"
    assert graph.identity_by_id("nonexistent") is None
    assert graph.resource_by_id("profile_user_a").owner == "user_a"
    assert len(graph.expectations_for_cell("LABGEN-EX-IDENTITY-0001")) >= 1


def test_missing_identities_file_raises_typed_error(tmp_path):
    with pytest.raises(identity.IdentityGraphError):
        identity.load_identities(tmp_path / "does-not-exist.yaml")


def test_invalid_yaml_raises_typed_error(tmp_path):
    bad_path = tmp_path / "identities.yaml"
    bad_path.write_text("this: is: not: valid: yaml: [", encoding="utf-8")
    with pytest.raises(identity.IdentityGraphError):
        identity.load_identities(bad_path)


# --- duplicate-ID checks (mirrors fuzzlab.labels.contract.load_labels) -----


def test_duplicate_identity_id_rejected(tmp_path):
    data = copy.deepcopy(_valid_graph_dict())
    data["identities"].append({"id": "user_a", "role": "admin"})
    _write_yaml(tmp_path, data)
    with pytest.raises(identity.IdentityGraphError, match="duplicate identities"):
        identity.load_identities(tmp_path / "identities.yaml")


def test_duplicate_resource_id_rejected(tmp_path):
    data = copy.deepcopy(_valid_graph_dict())
    data["resources"].append(copy.deepcopy(data["resources"][0]))
    _write_yaml(tmp_path, data)
    with pytest.raises(identity.IdentityGraphError, match="duplicate resources"):
        identity.load_identities(tmp_path / "identities.yaml")


# --- dangling-reference checks ----------------------------------------------


def test_resource_with_unknown_owner_rejected(tmp_path):
    data = copy.deepcopy(_valid_graph_dict())
    data["resources"][0]["owner"] = "nonexistent_identity"
    _write_yaml(tmp_path, data)
    with pytest.raises(identity.IdentityGraphError, match="unknown owner"):
        identity.load_identities(tmp_path / "identities.yaml")


def test_authz_expectation_with_unknown_accessing_identity_rejected(tmp_path):
    data = copy.deepcopy(_valid_graph_dict())
    data["authz_expectations"][0]["accessing_identity"] = "nonexistent_identity"
    _write_yaml(tmp_path, data)
    with pytest.raises(identity.IdentityGraphError, match="unknown accessing_identity"):
        identity.load_identities(tmp_path / "identities.yaml")


def test_authz_expectation_with_unknown_target_resource_rejected(tmp_path):
    data = copy.deepcopy(_valid_graph_dict())
    data["authz_expectations"][0]["target_resource"] = "nonexistent_resource"
    _write_yaml(tmp_path, data)
    with pytest.raises(identity.IdentityGraphError, match="unknown target_resource"):
        identity.load_identities(tmp_path / "identities.yaml")


def _write_yaml(tmp_path, data):
    import yaml

    (tmp_path / "identities.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")


# --- decoupling from the verdict engine (mirrors
# test_labgen_gates.py::test_provenance_is_one_directional_no_leak_into_verdict_source)


def test_verdict_module_never_imports_identity():
    """fuzzlab.labgen.verdict must carry zero reference to identity.py — the
    verdict-deriving code path stays independent of ownership/authz-
    expectation data, the same separation provenance.yaml has (CR-LAB-0001
    Addendum A)."""
    verdict_src = VERDICT_SOURCE.read_text("utf-8")
    assert "identity" not in verdict_src


def test_verdict_module_has_no_ast_import_of_identity():
    """Belt-and-suspenders check via AST rather than substring search alone,
    in case a future rename makes the substring check pass vacuously."""
    import ast

    tree = ast.parse(VERDICT_SOURCE.read_text("utf-8"))
    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.add(node.module)
            imported_names.update(alias.name for alias in node.names)
    assert not any("identity" in name for name in imported_names)
