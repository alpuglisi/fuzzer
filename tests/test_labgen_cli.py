"""End-to-end tests for `fuzzlab lab-generate` (T-LAB0.10).

Exercises the real CLI (`fuzzlab.labgen.cli.main`) against the real example
manifest (`lab/manifests/example_phase0_scaffold.yaml`) and the real
`php_current` emitter: a clean render + `--check` must pass, and each
individual gate wired into `--check` must fail loud on its own known-bad
fixture. Per this task's own scope discipline, the known-bad fixtures are
reused from each gate's own test module rather than re-authored here.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest
import yaml

from fuzzlab.labgen import cli as labgen_cli
from fuzzlab.labgen.fingerprint_gate import FingerprintIndependenceError, run_fingerprint_gate
from fuzzlab.labgen.denylist import VULN_CLASS_DENYLIST
from fuzzlab.labgen.emitter import EmittedFile, Emitter
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.schema import Manifest, Pipeline, load_manifest

from tests.test_labgen_fingerprint_gate import (
    _balanced_independent_corpus,
    _skewed_but_covered_corpus,
)
from tests.test_labgen_gates import EXAMPLE_MANIFEST
from tests.test_labgen_minimal_pair import _base_cell
from tests.test_labgen_secret_scanner import GITLEAKS_AVAILABLE, SHOULD_FLAG as SECRET_SHOULD_FLAG

EXAMPLE_CELL_IDS = {"LABGEN-EX-0001", "LABGEN-EX-0002", "LABGEN-EX-0003", "LABGEN-EX-0004"}
#: Which of the example manifest's cells this emitter renders, **derived from
#: the emitter's own `supports()`** rather than hardcoded (PA-0001): the set
#: changes as `_MODULE_SET_BY_SHAPE` is widened -- e.g. L-P1.2b added
#: (xss, html_attribute_unquoted), so LABGEN-EX-0003 (skipped since Phase 0
#: as "declare unsupported and skip") now renders too. A hardcoded literal
#: here would have to be edited by hand on every such widening, which is
#: exactly the per-shape/per-record lockstep drift PA-0024 was written about.
SUPPORTED_CELL_IDS = {
    cell.cell_id
    for cell in load_manifest(EXAMPLE_MANIFEST).cells
    if PhpCurrentEmitter().supports(cell.vuln_class, cell.sink_context)
}


class _WrappedEmitter(Emitter):
    """Delegates to a real emitter, letting a test inject a fault into one
    rendered output without hand-authoring a whole new emitter or manifest.
    ``fault`` is a callable ``(cell, files) -> files`` applied after the real
    render."""

    def __init__(self, inner: Emitter, fault):
        self._inner = inner
        self._fault = fault

    def supports(self, vuln_class, sink_context):
        return self._inner.supports(vuln_class, sink_context)

    def render(self, cell):
        files = self._inner.render(cell)
        return self._fault(cell, files)


def _register(monkeypatch: pytest.MonkeyPatch, name: str, factory) -> None:
    registry = dict(labgen_cli.EMITTER_REGISTRY)
    registry[name] = factory
    monkeypatch.setattr(labgen_cli, "EMITTER_REGISTRY", registry)


@pytest.fixture()
def out_dir(tmp_path: Path) -> Path:
    return tmp_path / "out"


# ---------------------------------------------------------------------------
# Happy path: clean tree, --check passes
# ---------------------------------------------------------------------------


def test_lab_generate_writes_only_supported_cells(out_dir: Path):
    rc = labgen_cli.main(["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir)])
    assert rc == 0
    written = {p.name for p in out_dir.glob("generated/*.php")}
    assert written == {f"{cid.lower()}.php" for cid in SUPPORTED_CELL_IDS}


def test_lab_generate_check_passes_on_the_clean_example_manifest(out_dir: Path):
    rc = labgen_cli.main(["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir), "--check"])
    assert rc == 0


def test_lab_generate_default_emitter_is_php_current(out_dir: Path):
    # No --emitter passed; must not raise and must behave identically to an
    # explicit `--emitter php_current`.
    rc = labgen_cli.main(["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir)])
    assert rc == 0


def test_lab_generate_rejects_an_unknown_emitter_name(out_dir: Path):
    with pytest.raises(SystemExit):
        labgen_cli.main(["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir), "--emitter", "no_such_emitter"])


def test_lab_generate_reports_missing_manifest(out_dir: Path, capsys):
    rc = labgen_cli.main(["--manifest", "does/not/exist.yaml", "--out", str(out_dir)])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# --check fails loud: name-leak scanner (gates.py), reusing its own denylist
# ---------------------------------------------------------------------------


def test_check_fails_loud_on_a_name_leak(out_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    leaky_term = VULN_CLASS_DENYLIST[0]

    def leak_fault(cell, files):
        return tuple(
            dataclasses.replace(f, path=f"generated/{leaky_term}_{cell.cell_id.lower()}.php") for f in files
        )

    _register(monkeypatch, "leaky", lambda: _WrappedEmitter(PhpCurrentEmitter(), leak_fault))
    rc = labgen_cli.main(
        ["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir), "--emitter", "leaky", "--check"]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "name-leak scanner" in err
    assert leaky_term in err


# ---------------------------------------------------------------------------
# --check fails loud: secret scanner, reusing test_labgen_secret_scanner's
# own SHOULD_FLAG fixture corpus (an unmarked, real-shaped AWS key).
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not GITLEAKS_AVAILABLE, reason="gitleaks binary not found on PATH")
def test_check_fails_loud_on_a_secret_leak(out_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    leaky_content = SECRET_SHOULD_FLAG["should_flag/aws_key.php"]

    def secret_fault(cell, files):
        return tuple(dataclasses.replace(f, content=f.content + b"\n" + leaky_content) for f in files)

    _register(monkeypatch, "secretful", lambda: _WrappedEmitter(PhpCurrentEmitter(), secret_fault))
    rc = labgen_cli.main(
        ["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir), "--emitter", "secretful", "--check"]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "secret scanner" in err


# ---------------------------------------------------------------------------
# --check fails loud: regenerate-and-diff determinism check
# ---------------------------------------------------------------------------


def test_check_fails_loud_on_nondeterministic_render(out_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    # Corrupt every *second* render of each individual cell, counted per
    # cell_id rather than globally: a single global counter only alternates
    # between two consecutive whole-tree renders when the manifest happens to
    # hold an odd number of *supported* cells, so it silently stopped
    # detecting nondeterminism when L-P1.2b widened php_current's supported
    # shapes from 3 of the example manifest's cells to 4. Per-cell counting is
    # independent of the cell count. See docs/bugs/BUG-0025-*.md and PA-0027.
    render_counts: dict[str, int] = {}

    def flaky_fault(cell, files):
        render_counts[cell.cell_id] = render_counts.get(cell.cell_id, 0) + 1
        if render_counts[cell.cell_id] % 2 == 0:
            first = files[0]
            files = (dataclasses.replace(first, content=first.content + b" "), *files[1:])
        return files

    _register(monkeypatch, "flaky", lambda: _WrappedEmitter(PhpCurrentEmitter(), flaky_fault))
    rc = labgen_cli.main(
        ["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir), "--emitter", "flaky", "--check"]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "determinism check" in err or "regeneration" in err


# ---------------------------------------------------------------------------
# --check fails loud: minimal-pair checker (minimal_pair.py), reusing the
# same "unrelated identifier rename" failure mode
# tests/test_labgen_minimal_pair.py's own fixture exercises.
# ---------------------------------------------------------------------------


def test_check_fails_loud_on_a_minimal_pair_violation(out_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    # The CLI checks the minimal-pair invariant (fuzzlab.labgen.cli's
    # `_weakened_twin`) by rendering LABGEN-EX-0001 (whose declared
    # `transform` is already empty) against itself. An emitter that is not
    # even self-consistent between two renders of the *same* cell -- an
    # unrelated content change with no corresponding composition change,
    # the identical failure mode tests/test_labgen_minimal_pair.py's own
    # "unrelated identifier rename" fixture exercises -- must be caught by
    # this checker exactly as it is there.
    # Counted per cell_id, not globally, for the same reason as
    # `flaky_fault` above (PA-0027): a global counter's parity at any one
    # cell's render depends on how many *other* supported cells precede it in
    # the pass, so it silently stops (or starts) injecting the fault whenever
    # the emitter's supported-shape set changes.
    render_counts: dict[str, int] = {}

    def rename_fault(cell, files):
        render_counts[cell.cell_id] = render_counts.get(cell.cell_id, 0) + 1
        if cell.cell_id != "LABGEN-EX-0001" or render_counts[cell.cell_id] % 2 != 0:
            return files
        return tuple(
            dataclasses.replace(f, content=f.content + b"\n// unrelated content change, not a transform/sink edit\n")
            for f in files
        )

    _register(monkeypatch, "renamed", lambda: _WrappedEmitter(PhpCurrentEmitter(), rename_fault))
    rc = labgen_cli.main(
        ["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir), "--emitter", "renamed", "--check"]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "minimal-pair checker" in err
    assert "differ outside any declared transform/sink change" in err


# ---------------------------------------------------------------------------
# --check fails loud: conformance Tier 0 lint, reusing
# tests/test_labgen_conformance_tier0.py's own broken-PHP fixture literal.
# ---------------------------------------------------------------------------


def test_check_fails_loud_on_a_tier0_lint_failure(out_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    from fuzzlab.labgen.conformance import tier0 as tier0_module

    if not tier0_module.php_available():
        pytest.skip("php CLI not found on PATH -- Tier 0 lint is skip-guarded per PA-0005")

    broken_php = b"<?php\nif (true) {\n"  # unclosed brace -- same literal test_labgen_conformance_tier0.py uses

    def lint_fault(cell, files):
        if cell.transform.ops:
            return files
        first = files[0]
        return (dataclasses.replace(first, content=broken_php), *files[1:])

    _register(monkeypatch, "brokenphp", lambda: _WrappedEmitter(PhpCurrentEmitter(), lint_fault))
    rc = labgen_cli.main(
        ["--manifest", EXAMPLE_MANIFEST, "--out", str(out_dir), "--emitter", "brokenphp", "--check"]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "Tier 0 lint" in err


# ---------------------------------------------------------------------------
# run_checks() directly against a hand-built manifest reusing
# tests/test_labgen_minimal_pair.py's own `_base_cell` helper, proving the
# CLI's generic weakened-twin pairing (`_weakened_twin`) works for a cell
# that is not part of the example manifest at all.
# ---------------------------------------------------------------------------


def test_run_checks_generic_weakened_twin_pairing_passes_for_an_arbitrary_cell():
    cell = _base_cell(cell_id="LABGEN-CLI-TEST-0001", transform=Pipeline(("param_bind",)))
    manifest = Manifest(manifest_version=1, safety_matrix_version=1, cells=(cell,))
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    assert failures == []


# ---------------------------------------------------------------------------
# --check step 8: the fingerprint-independence gate (L-P3.4 /
# docs/LAB_IMPLEMENTATION_PLAN.md §4.4).
#
# The two-stack corpus fixtures below are built by *relabelling* the real
# php_current real-pages sample manifest's cells onto a second stack --
# reusing real, renderable cells rather than hand-authoring a synthetic
# emitter-incompatible manifest -- and the record-shaped balanced/confounded
# corpora come from tests/test_labgen_fingerprint_gate.py's own fixtures, per
# this lane's scope discipline ("reuse fingerprint_gate.py's own existing test
# fixtures/patterns, don't re-author them").
# ---------------------------------------------------------------------------

REAL_PAGES_MANIFEST = "lab/manifests/phase0_real_pages_sample.yaml"
SECOND_STACK = "node_express"


def _real_pages_cells():
    return load_manifest(REAL_PAGES_MANIFEST).cells


def _restacked(cell, stack: str):
    """The same cell on another stack, with a distinct cell_id (php_current
    derives handler names from cell_id, so two cells sharing one id would not
    be a legitimate corpus)."""
    return dataclasses.replace(
        cell, cell_id=cell.cell_id.replace("LABGEN-RP-", "LABGEN-FP-"), stack_profile=stack
    )


def _two_stack_balanced_manifest() -> Manifest:
    """Every cell of the real php_current sample, plus an exact copy of each on
    a second stack: both stacks carry both classes in the same proportion, so
    stack and vuln_class are perfectly independent (the gate must pass)."""
    cells = _real_pages_cells()
    return Manifest(
        manifest_version=1,
        safety_matrix_version=1,
        cells=tuple(cells) + tuple(_restacked(c, SECOND_STACK) for c in cells),
    )


def _two_stack_confounded_manifest(replicas: int = 4) -> Manifest:
    """The same cells split so that every php_current cell is sqli and every
    second-stack cell is xss -- CR-LAB-0001 §3's exact leakage shape ("every
    Flask cell is SSTI"), one stack per class.

    Replicated ``replicas`` times (each replica re-suffixed to a unique
    cell_id) purely for sample size: at the sample manifest's own 8 cells the
    2x2 table is so small that scipy's Yates continuity correction leaves
    p just above 0.05, so a single copy would exercise only the gate's
    coverage half. Four copies make the *statistical* half fire too, which is
    the point of having both.
    """
    cells = _real_pages_cells()
    split = tuple(c for c in cells if c.vuln_class == "sqli") + tuple(
        _restacked(c, SECOND_STACK) for c in cells if c.vuln_class == "xss"
    )
    replicated = tuple(
        dataclasses.replace(c, cell_id=f"{c.cell_id}-R{n}") for n in range(replicas) for c in split
    )
    return Manifest(manifest_version=1, safety_matrix_version=1, cells=replicated)


def test_corpus_records_from_manifest_uses_every_cell_and_the_gate_key_names():
    manifest = _two_stack_balanced_manifest()
    records = labgen_cli.corpus_records_from_manifest(manifest)
    assert len(records) == len(manifest.cells)
    assert all(set(r) == {"stack", "vuln_class"} for r in records)
    assert {r["stack"] for r in records} == {"php_current", SECOND_STACK}
    # No `verdict` key: deliberately not derived here (see the function's
    # docstring), which is exactly the gate's documented skip path.
    report = run_fingerprint_gate(records, **labgen_cli.fingerprint_gate_config(records))
    assert report.chi2_stack_verdict is None


def test_fingerprint_gate_config_derives_expectations_from_the_actual_corpus():
    records = labgen_cli.corpus_records_from_manifest(_two_stack_balanced_manifest())
    config = labgen_cli.fingerprint_gate_config(records)
    assert config["expected_stacks"] == sorted({r["stack"] for r in records})
    assert config["expected_classes"] == sorted({r["vuln_class"] for r in records})
    assert config["min_stacks_per_class"] == labgen_cli.MIN_STACKS_FOR_FINGERPRINT_GATE
    # Ceiling, not a flat requirement: this corpus authors only 2 classes.
    assert config["min_classes_per_stack"] == len(config["expected_classes"])
    assert config["min_classes_per_stack"] <= labgen_cli.CANONICAL_MIN_CLASSES_PER_STACK


def test_fingerprint_gate_config_caps_min_classes_at_the_canonical_value():
    # Reuses the gate module's own balanced fixture (3 stacks x 3 classes), so
    # the cap -- not the corpus size -- is what binds here.
    records = _balanced_independent_corpus()
    config = labgen_cli.fingerprint_gate_config(records)
    assert config["min_classes_per_stack"] == labgen_cli.CANONICAL_MIN_CLASSES_PER_STACK


def test_run_checks_fingerprint_gate_passes_on_a_balanced_two_stack_manifest():
    manifest = _two_stack_balanced_manifest()
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    assert not [f for f in failures if "fingerprint-independence" in f]


def test_run_checks_fingerprint_gate_fails_loud_on_a_confounded_two_stack_manifest():
    manifest = _two_stack_confounded_manifest()
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    gate_failures = [f for f in failures if "fingerprint-independence" in f]
    assert len(gate_failures) == 1
    message = gate_failures[0]
    assert "'sqli'" in message and "'xss'" in message
    assert "NOT independent" in message


def test_cli_gate_config_still_catches_a_covered_but_skewed_corpus():
    # Reuses the gate module's own "coverage passes, chi-square must still
    # catch it" fixture, run through the CLI's derived config -- proving the
    # CLI's min_classes_per_stack ceiling does not defang the statistical half.
    records = _skewed_but_covered_corpus()
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        run_fingerprint_gate(records, **labgen_cli.fingerprint_gate_config(records))
    assert "NOT independent" in str(exc_info.value)


def test_run_checks_skips_the_gate_on_a_single_stack_manifest_with_a_printed_reason(capsys):
    manifest = load_manifest(REAL_PAGES_MANIFEST)
    assert len({c.stack_profile for c in manifest.cells}) == 1
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    assert not [f for f in failures if "fingerprint-independence" in f]
    out = capsys.readouterr().out
    assert "fingerprint-independence gate SKIPPED" in out
    assert "php_current" in out


def test_run_checks_fingerprint_gate_fails_closed_when_scipy_is_missing(monkeypatch):
    # Same simulated-absence pattern tests/test_labgen_fingerprint_gate.py uses
    # (scipy is installed in this dev environment), asserting the CLI turns the
    # typed MissingStatsDependencyError into a --check failure rather than an
    # uncaught traceback or a silent pass.
    monkeypatch.setitem(sys.modules, "scipy.stats", None)
    manifest = _two_stack_balanced_manifest()
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    gate_failures = [f for f in failures if "fingerprint-independence" in f]
    assert len(gate_failures) == 1
    assert "missing dependency" in gate_failures[0]
    assert "labgen-stats" in gate_failures[0]


def test_lab_generate_check_end_to_end_fails_on_a_confounded_two_stack_manifest(
    out_dir: Path, tmp_path: Path, capsys
):
    """The gate is wired into the real CLI, not only into `run_checks`: a
    confounded two-stack manifest on disk must make `--check` exit nonzero."""
    manifest = _two_stack_confounded_manifest()
    manifest_path = tmp_path / "confounded.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "manifest_version": manifest.manifest_version,
                "safety_matrix_version": manifest.safety_matrix_version,
                "cells": [
                    {
                        "cell_id": c.cell_id,
                        "class": c.vuln_class,
                        "stack_profile": c.stack_profile,
                        "route": c.route.to_dict(),
                        "sink_context": c.sink_context.to_dict(),
                        "transform": list(c.transform.ops),
                    }
                    for c in manifest.cells
                ],
            }
        ),
        "utf-8",
    )
    rc = labgen_cli.main(["--manifest", str(manifest_path), "--out", str(out_dir), "--check"])
    assert rc == 1
    assert "fingerprint-independence gate" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# --check step 9: the metadata leakage gate (L-P1.3 /
# docs/LAB_IMPLEMENTATION_PLAN.md SS2.3).
#
# The corpora below are built by *re-pathing* the real php_current real-pages
# sample manifest's cells between the two renderable depths php_current already
# has page profiles for (`/product.php` vs `/example/product.php`,
# `/profile.php` vs `/example/profile.php`) -- reusing real, renderable cells,
# the same construction the fingerprint-gate block above uses, rather than
# hand-authoring an emitter-incompatible synthetic manifest. `path_depth` is the
# one allowlisted feature a manifest actually carries (see
# `labgen_cli.MANIFEST_DERIVABLE_LEAKAGE_FEATURES`), so making it correlate with
# `vuln_class` is exactly the "a feature that trivially predicts the class"
# leakage shape this gate exists to catch.
# ---------------------------------------------------------------------------

HARDER_SHAPES_MANIFEST = "lab/manifests/phase1_harder_shapes_sample.yaml"

#: (depth-1 path, depth-2 path) pairs php_current has a real page profile for.
DEEPER_PAGE = {"/product.php": "/example/product.php", "/profile.php": "/example/profile.php"}


def _leakage_manifest(*, leaky: bool, replicas: int = 6) -> Manifest:
    """A manifest big enough for `leakage_probe`'s own sufficiency floors, in
    which `path_depth` either perfectly predicts `vuln_class` (`leaky=True`) or
    is balanced across classes (`leaky=False`).

    Replicated `replicas` times purely for sample size:
    `leakage_probe.MIN_CELLS_FOR_GATE` cells and
    `MIN_CELLS_PER_CLASS_FOR_GATE` per class are what make the gate consent to
    judge a corpus at all, and the 8-cell sample manifest is far below both.
    """
    base = _real_pages_cells()
    cells = [
        dataclasses.replace(c, cell_id=f"{c.cell_id.replace('LABGEN-RP-', 'LABGEN-LK-')}-R{n}")
        for n in range(replicas)
        for c in base
    ]

    def deepen(cell):
        deeper = DEEPER_PAGE.get(cell.route.path)
        if deeper is None:
            return cell
        return dataclasses.replace(cell, route=dataclasses.replace(cell.route, path=deeper))

    out = []
    if leaky:
        # Every xss cell goes deep, every sqli cell stays shallow: path_depth
        # IS the class.
        for cell in cells:
            out.append(deepen(cell) if cell.vuln_class == "xss" else cell)
    else:
        # Exactly half of each class goes deep (among the cells that have a
        # deeper page at all), so path_depth carries no class information.
        for vuln_class in sorted({c.vuln_class for c in cells}):
            members = [c for c in cells if c.vuln_class == vuln_class]
            eligible = [i for i, c in enumerate(members) if c.route.path in DEEPER_PAGE]
            deep = set(eligible[: len(members) // 2])
            out.extend(deepen(c) if i in deep else c for i, c in enumerate(members))
    return Manifest(manifest_version=1, safety_matrix_version=1, cells=tuple(out))


def test_leakage_probe_records_from_manifest_reuses_the_shared_rule_id():
    from fuzzlab.labgen import corpus_analysis

    manifest = load_manifest(HARDER_SHAPES_MANIFEST)
    records = labgen_cli.leakage_probe_records_from_manifest(manifest)
    assert len(records) == len(manifest.cells)
    assert all(set(r) == {"label", "rule_id", "features"} for r in records)
    # The grouping key is the SHARED generating-rule ID, not a second,
    # independently-derived one (PA-0003/PA-0021).
    assert [r["rule_id"] for r in records] == [
        corpus_analysis.generating_rule_id(c) for c in manifest.cells
    ]
    assert [r["label"] for r in records] == [c.vuln_class for c in manifest.cells]
    # Only the manifest-derivable features, never an imputed live-response one.
    assert all(
        set(r["features"]) == set(labgen_cli.MANIFEST_DERIVABLE_LEAKAGE_FEATURES) for r in records
    )


def test_manifest_derivable_features_are_a_strict_subset_of_the_closed_allowlist():
    from fuzzlab.labgen import leakage_probe

    scope = set(labgen_cli.MANIFEST_DERIVABLE_LEAKAGE_FEATURES)
    assert scope and scope < set(leakage_probe.FEATURE_ALLOWLIST)


def test_path_depth_counts_non_empty_segments():
    assert labgen_cli.path_depth("/product.php") == 1
    assert labgen_cli.path_depth("/example/product.php") == 2
    assert labgen_cli.path_depth("/") == 0


def test_run_checks_skips_the_leakage_gate_on_the_harder_shapes_manifest(capsys):
    """Today's real Phase-1 manifest is far below the gate's own sufficiency
    floors, so the required step must SKIP with an explicit printed reason --
    mirroring the fingerprint gate's single-stack skip -- and never fail."""
    from fuzzlab.labgen import leakage_probe

    manifest = load_manifest(HARDER_SHAPES_MANIFEST)
    assert len(manifest.cells) < leakage_probe.MIN_CELLS_FOR_GATE
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    assert not [f for f in failures if "metadata leakage gate" in f]
    out = capsys.readouterr().out
    assert "metadata leakage gate SKIPPED" in out
    assert str(leakage_probe.MIN_CELLS_FOR_GATE) in out
    # The reason names the in-scope feature set, so a reader can see *why* the
    # probe is thin here rather than guessing.
    assert "path_depth" in out


def test_run_checks_leakage_gate_passes_on_a_balanced_corpus_and_prints_its_report(capsys):
    manifest = _leakage_manifest(leaky=False)
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    assert not [f for f in failures if "metadata leakage gate" in f]
    out = capsys.readouterr().out
    # Really ran -- not skipped.
    assert "metadata leakage gate SKIPPED" not in out
    assert "metadata leakage gate passed" in out
    # The provisional-vs-calibrated annotation is printed on the PASS path too
    # (plan SS2.3: a future pass must be able to see which numbers need work).
    assert "PROVISIONAL" in out
    assert "per-class thresholds" in out


def test_run_checks_leakage_gate_fails_loud_when_a_feature_trivially_predicts_the_class():
    manifest = _leakage_manifest(leaky=True)
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    gate_failures = [f for f in failures if "metadata leakage gate" in f]
    assert len(gate_failures) == 1
    message = gate_failures[0]
    assert "one-vs-rest AUC" in message
    assert "'xss'" in message and "'sqli'" in message


def test_run_checks_leakage_gate_fails_closed_when_sklearn_is_missing(monkeypatch):
    # Same simulated-absence pattern as the scipy case above: a missing optional
    # dependency must become a --check failure, never a silent pass. Both the
    # already-bound package attribute and the sys.modules entry have to go --
    # `from fuzzlab.labgen import leakage_probe` prefers the attribute and would
    # otherwise never reach the import system at all.
    import fuzzlab.labgen as labgen_pkg

    monkeypatch.delattr(labgen_pkg, "leakage_probe", raising=False)
    monkeypatch.setitem(sys.modules, "fuzzlab.labgen.leakage_probe", None)
    manifest = load_manifest(HARDER_SHAPES_MANIFEST)
    emitter = PhpCurrentEmitter()
    tree = labgen_cli.render_manifest(emitter, manifest)
    failures = labgen_cli.run_checks(emitter, manifest, tree)
    gate_failures = [f for f in failures if "metadata leakage gate" in f]
    assert len(gate_failures) == 1
    assert "fail-closed, missing dependency" in gate_failures[0]
