"""Tests for the regenerate-and-diff CI gate (T-LAB0.5) and the name-leak
scanner build gate (T-LAB0.6), plus the pattern-provenance one-directional
gate (CR-LAB-0001 Addendum A)."""

from pathlib import Path

import pytest

from fuzzlab.labgen.gates import (
    Leak,
    RegenerateDiffError,
    generate_source_tree,
    regenerate_and_diff,
    scan_generated_tree_for_name_leaks,
    scan_name_leaks,
)
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix

EXAMPLE_MANIFEST = "lab/manifests/example_phase0_scaffold.yaml"
REAL_MATRIX_PATH = "lab/safety_matrix.yaml"
VERDICT_SOURCE = Path("fuzzlab/labgen/verdict.py")
MANIFEST_FILES = list(Path("lab/manifests").glob("*.yaml"))


# --- Regenerate-and-diff gate (T-LAB0.5) ----------------------------------


def test_regenerate_and_diff_passes_for_the_real_example_manifest():
    manifest = load_manifest(EXAMPLE_MANIFEST)
    matrix = load_safety_matrix(REAL_MATRIX_PATH)
    regenerate_and_diff(manifest, matrix, root_seed="phase0-ci-gate")  # must not raise


def test_regenerate_and_diff_catches_a_nondeterministic_generator(monkeypatch):
    manifest = load_manifest(EXAMPLE_MANIFEST)
    matrix = load_safety_matrix(REAL_MATRIX_PATH)

    call_count = {"n": 0}
    real_generate = generate_source_tree

    def flaky_generate(manifest_, matrix_, root_seed_):
        call_count["n"] += 1
        tree = dict(real_generate(manifest_, matrix_, root_seed_))
        if call_count["n"] == 2:
            # Corrupt exactly one byte on the second run only, simulating a
            # real nondeterminism bug (e.g. an unsorted dict/clock leak).
            first_key = sorted(tree)[0]
            tree[first_key] = tree[first_key] + b" "
        return tree

    monkeypatch.setattr("fuzzlab.labgen.gates.generate_source_tree", flaky_generate)
    with pytest.raises(RegenerateDiffError):
        regenerate_and_diff(manifest, matrix, root_seed="phase0-ci-gate")


def test_generate_source_tree_one_file_per_cell():
    manifest = load_manifest(EXAMPLE_MANIFEST)
    matrix = load_safety_matrix(REAL_MATRIX_PATH)
    tree = generate_source_tree(manifest, matrix, root_seed="s")
    assert set(tree) == {f"{c.cell_id}.json" for c in manifest.cells}


# --- Name-leak scanner build gate (T-LAB0.6) ------------------------------
# A positive-fixture corpus (should_flag / should_not_flag), per
# docs/LAB_PHASE_0_PLAN.md T-LAB0.6: a scanner with silent false negatives is
# worse than no scanner, and that property is only established by testing it
# against known-leaky inputs, not by code review.

SHOULD_FLAG = [
    ("param", "xss_payload"),
    ("param", "test-sqli"),
    ("url", "/admin/xss1"),
    ("filename", "sqli.php"),
    ("param", "IDOR_id"),  # case-insensitive
]

SHOULD_NOT_FLAG = [
    # The classic word-boundary collision the plan calls out by name.
    ("header", "maxssl"),
    # Ordinary vocabulary that happens to contain a denylist substring
    # mid-word, with letters on both sides.
    ("body", "invulnerable"),
    ("param", "category"),
    ("url", "/products.php"),
    # The out-of-band label files themselves are true negatives.
    ("filename", "labels.json"),
    ("filename", "expectedresults.csv"),
    ("param", "case_id"),
]


@pytest.mark.parametrize("label,text", SHOULD_FLAG)
def test_scanner_flags_known_leaky_names(label, text):
    leaks = scan_name_leaks([(label, text)])
    assert leaks, f"expected a leak for {text!r}"


@pytest.mark.parametrize("label,text", SHOULD_NOT_FLAG)
def test_scanner_does_not_flag_known_clean_names(label, text):
    leaks = scan_name_leaks([(label, text)])
    assert not leaks, f"unexpected leak(s) for {text!r}: {leaks}"


def test_scanner_reports_matched_term():
    leaks = scan_name_leaks([("param", "sqli_test")])
    assert leaks == [Leak(context="param", text="sqli_test", matched_term="sqli")]


def test_generated_example_tree_is_clean():
    """The example scaffold manifest's cell_ids/routes must not leak a
    vulnerability-class name, even though the manifest's own `class` field
    (generator-input only, never emitted) does name one."""
    manifest = load_manifest(EXAMPLE_MANIFEST)
    matrix = load_safety_matrix(REAL_MATRIX_PATH)
    tree = generate_source_tree(manifest, matrix, root_seed="s")
    leaks = scan_generated_tree_for_name_leaks(tree)
    assert not leaks, f"name leak(s) in generated tree: {leaks}"


def test_scanner_crash_is_not_swallowed():
    with pytest.raises(TypeError):
        scan_name_leaks([("param", None)])  # type: ignore[list-item]


# --- Pattern-provenance one-directional gate (CR-LAB-0001 Addendum A) -----


def test_provenance_is_one_directional_no_leak_into_verdict_source():
    """No card ID and no `pattern://`-style reference may appear anywhere in
    a manifest or in the verdict module's source — the artifact must be
    unchanged by whether provenance for it exists."""
    verdict_src = VERDICT_SOURCE.read_text("utf-8")
    assert "pattern://" not in verdict_src
    assert "pc-" not in verdict_src
    for manifest_path in MANIFEST_FILES:
        text = manifest_path.read_text("utf-8")
        assert "pattern://" not in text
        assert "pc-" not in text, f"{manifest_path} appears to reference a pattern card directly"
