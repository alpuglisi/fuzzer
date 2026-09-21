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
from pathlib import Path

import pytest

from fuzzlab.labgen import cli as labgen_cli
from fuzzlab.labgen.denylist import VULN_CLASS_DENYLIST
from fuzzlab.labgen.emitter import EmittedFile, Emitter
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.schema import Manifest, Pipeline, load_manifest

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
