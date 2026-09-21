"""Tests for the covering-array resolver (T-LAB0.3).

Follows this repo's existing golden-file convention (see
tests/test_features_golden.py, tests/test_labgen_verdict.py): a fixed
synthetic axis-set model must always produce the recorded covering array.
Set FUZZLAB_REGEN_GOLDEN=1 to regenerate after a deliberate covertable
version bump (documented in fuzzlab/labgen/resolver.py as equivalent to a
manifest_version bump).
"""

import json
import os
from pathlib import Path

import pytest

from fuzzlab.labgen.resolver import (
    CoveringArrayError,
    expand,
    validate_covering_array_config,
)

GOLDEN = Path(__file__).parent / "golden" / "labgen_covering_array_v1.json"

# A synthetic axis-set model (not the real Phase 0/1 corpus, which doesn't
# need this yet) — three axes with realistic-looking cardinality so the
# strength=2 array is small but non-trivial (more than one row per axis).
SYNTHETIC_FACTORS = {
    "class": ["sqli", "xss", "ssrf"],
    "stack_profile": ["php_current", "node_express", "python_fastapi"],
    "sink_context_family": ["sql_string_literal", "html_body", "html_attribute_unquoted"],
}


# --- validate_covering_array_config ---------------------------------------


def test_valid_config_passes_through_with_defaults():
    out = validate_covering_array_config({"factors": SYNTHETIC_FACTORS})
    assert out["factors"] == SYNTHETIC_FACTORS
    assert out["strength"] == 2
    assert out["sub_models"] == []
    assert out["constraints"] == []


def test_unrecognized_kwarg_is_rejected_not_silently_swallowed():
    """The whole point of this module: covertable.make() itself silently
    ignores an unrecognized kwarg (verified directly against the installed
    package — see the reproduction in this test). The adapter must not."""
    from covertable import make, sorters

    # Demonstrate covertable's own silent-swallow behavior first, so this
    # test documents *why* the adapter's rejection matters, not just that it
    # rejects something.
    factors = {"a": [1, 2], "b": ["x", "y"]}
    swallowed = make(factors, strength=2, sorter=sorters.hash, this_is_not_a_real_kwarg=True)
    assert swallowed  # covertable ran fine and ignored the bogus kwarg

    with pytest.raises(CoveringArrayError):
        validate_covering_array_config({"factors": factors, "this_is_not_a_real_kwarg": True})


def test_missing_factors_rejected():
    with pytest.raises(CoveringArrayError):
        validate_covering_array_config({})


def test_empty_factors_rejected():
    with pytest.raises(CoveringArrayError):
        validate_covering_array_config({"factors": {}})


def test_factor_with_no_levels_rejected():
    with pytest.raises(CoveringArrayError):
        validate_covering_array_config({"factors": {"a": []}})


def test_non_positive_strength_rejected():
    with pytest.raises(CoveringArrayError):
        validate_covering_array_config({"factors": SYNTHETIC_FACTORS, "strength": 0})


def test_bool_strength_rejected():
    # bool is a subclass of int in Python; must not slip past the int check.
    with pytest.raises(CoveringArrayError):
        validate_covering_array_config({"factors": SYNTHETIC_FACTORS, "strength": True})


def test_sub_model_referencing_unknown_factor_rejected():
    with pytest.raises(CoveringArrayError):
        validate_covering_array_config(
            {"factors": SYNTHETIC_FACTORS, "sub_models": [{"fields": ["class", "nonexistent"]}]}
        )


def test_non_json_serializable_config_rejected():
    with pytest.raises(CoveringArrayError):
        validate_covering_array_config({"factors": {"a": [object()]}})


# --- expand() ---------------------------------------------------------------


def test_expand_covers_every_pairwise_combination_at_least_once():
    rows = expand({"factors": SYNTHETIC_FACTORS, "strength": 2})
    seen_pairs = set()
    for row in rows:
        keys = sorted(row)
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                seen_pairs.add(((keys[i], row[keys[i]]), (keys[j], row[keys[j]])))

    from itertools import combinations, product

    axis_names = sorted(SYNTHETIC_FACTORS)
    for a1, a2 in combinations(axis_names, 2):
        for v1, v2 in product(SYNTHETIC_FACTORS[a1], SYNTHETIC_FACTORS[a2]):
            assert ((a1, v1), (a2, v2)) in seen_pairs, f"uncovered pair {(a1, v1), (a2, v2)}"


def test_expand_is_deterministic_across_processes():
    """The pinned hash sorter (FNV-1a32) is not Python's randomized string
    hash, so two independent processes must agree byte-for-byte — a
    stronger check than same-process determinism, since PYTHONHASHSEED
    randomization would otherwise be invisible to a same-process test."""
    import subprocess
    import sys

    script = (
        "import json; from fuzzlab.labgen.resolver import expand; "
        "print(json.dumps(expand({'factors': " + repr(SYNTHETIC_FACTORS) + "}), sort_keys=True))"
    )
    outputs = set()
    for seed in ("0", "1", "1234567"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env, check=True)
        outputs.add(result.stdout.strip())
    assert len(outputs) == 1, f"array differs across PYTHONHASHSEED values: {outputs}"


def test_expand_raises_covering_array_error_for_invalid_config():
    with pytest.raises(CoveringArrayError):
        expand({"factors": {}})


def test_expand_never_lets_a_caller_override_the_pinned_sorter():
    """A `sorter` key is not in the allowlist at all -- even if a caller's
    raw config tried to supply one, it must be rejected, not merged in."""
    with pytest.raises(CoveringArrayError):
        expand({"factors": SYNTHETIC_FACTORS, "sorter": "whatever"})


def test_expand_respects_sub_models_mixed_strength():
    factors = {"a": ["a1", "a2"], "b": ["b1", "b2"], "c": ["c1", "c2", "c3"]}
    rows = expand(
        {
            "factors": factors,
            "strength": 2,
            "sub_models": [{"fields": ["a", "b", "c"], "strength": 3}],
        }
    )
    # Strength-3 sub-model over a,b,c must cover every triple at least once.
    triples = {(r["a"], r["b"], r["c"]) for r in rows}
    from itertools import product as _product

    expected = set(_product(factors["a"], factors["b"], factors["c"]))
    assert expected <= triples


def test_expand_honors_declarative_constraints():
    factors = {"a": ["a1", "a2"], "b": ["b1", "b2"]}
    constraints = [
        {
            "operator": "not",
            "condition": {"operator": "and", "conditions": [
                {"operator": "eq", "left": "a", "value": "a1"},
                {"operator": "eq", "left": "b", "value": "b1"},
            ]},
        }
    ]
    rows = expand({"factors": factors, "constraints": constraints})
    assert not any(r["a"] == "a1" and r["b"] == "b1" for r in rows)


# --- Snapshot test (golden file) -------------------------------------------


def test_expand_matches_snapshot():
    computed = expand({"factors": SYNTHETIC_FACTORS, "strength": 2})
    if os.environ.get("FUZZLAB_REGEN_GOLDEN") == "1" or not GOLDEN.exists():
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(computed, indent=2, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert computed == expected
