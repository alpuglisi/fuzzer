"""``fuzzlab lab-generate`` -- render a manifest to real source files via a
selected emitter, and (with ``--check``) run the offline build-gate suite
against the rendered output (T-LAB0.10).

Usage::

    fuzzlab lab-generate --manifest <path> --out <dir> [--emitter NAME] [--check]

This is a thin CLI over already-built pieces:

- ``fuzzlab.labgen.schema.load_manifest`` -- manifest loading/validation.
- an :class:`~fuzzlab.labgen.emitter.Emitter`, looked up by name from
  ``EMITTER_REGISTRY`` (default ``"php_current"``) -- **never hardcoded**,
  so Phase 3's additional emitters (built by parallel lanes) register here
  without a CLI rewrite.
- ``--check``, run in this order: the name-leak scanner (``gates.py``), the
  secret scanner (``secret_scanner.py``), the regenerate-and-diff
  determinism check, the minimal-pair checker (``minimal_pair.py``), the
  Tier 0 (lint + minimal-pair) and Tier 3 (whole-lab regeneration)
  conformance checks (``fuzzlab.labgen.conformance``), and -- once T-LAB0.9
  lands -- the regression/additive-only gate.

Resolver note (axis-range expansion, T-LAB0.3/T-LAB0.9's "L-P1.1"): as of
this module's authoring, ``fuzzlab.labgen.schema.load_manifest`` does no
covering-array expansion (see that module's own docstring: "this loader
does no expansion"), and it exposes no resolver-wiring hook to call
instead. This CLI therefore loads manifests as explicit cell lists only,
which is what every Phase 0 manifest under ``lab/manifests/`` already is.
Once L-P1.1 lands a resolver-wiring hook into ``schema.py``, this module
should switch to it -- there is no other change needed here for that to
"just work" transparently, the same forward-compatible convention this
project already uses (e.g. ``conformance.tier0.get_minimal_pair_checker``).
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

from fuzzlab.labgen import gates, minimal_pair, secret_scanner
from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.schema import Cell, Manifest, ManifestError, Pipeline, load_manifest

#: Emitter name -> factory. Looked up by name (``--emitter``, default
#: ``"php_current"``) rather than hardcoded, so a future emitter (Phase 3)
#: registers here without a CLI rewrite.
EMITTER_REGISTRY: dict[str, type[Emitter]] = {
    "php_current": PhpCurrentEmitter,
}

DEFAULT_ROOT_SEED = "lab-generate-cli"


class LabGenCliError(RuntimeError):
    """Raised for a CLI-level failure (bad args, unknown emitter, a failed
    ``--check`` gate) -- always caught in :func:`main` and turned into a
    printed message + nonzero exit, never an uncaught traceback for an
    expected failure mode."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuzzlab lab-generate")
    parser.add_argument("--manifest", required=True, help="path to a manifest YAML/JSON file")
    parser.add_argument("--out", required=True, help="directory to write rendered files into")
    parser.add_argument(
        "--emitter",
        default="php_current",
        choices=sorted(EMITTER_REGISTRY),
        help="which emitter to render with (default: php_current)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="run the offline build-gate suite against the rendered output",
    )
    return parser


def _get_emitter(name: str) -> Emitter:
    factory = EMITTER_REGISTRY.get(name)
    if factory is None:
        raise LabGenCliError(f"unknown emitter {name!r} -- known emitters: {sorted(EMITTER_REGISTRY)}")
    return factory()


def _supported_cells(emitter: Emitter, manifest: Manifest) -> list[Cell]:
    """Cells ``emitter`` declares support for, in manifest order. Unsupported
    cells are skipped -- "declare unsupported and skip," per
    ``fuzzlab.labgen.emitter.Emitter``'s own documented contract -- never an
    error."""
    return [c for c in manifest.cells if emitter.supports(c.vuln_class, c.sink_context)]


def render_manifest(emitter: Emitter, manifest: Manifest) -> dict[str, bytes]:
    """Render every cell ``emitter`` supports, keyed by output path.

    Thin wrapper over ``fuzzlab.labgen.conformance.tier3.render_whole_sample``
    -- the one existing helper that already renders a whole cell set through
    a real :class:`Emitter` and returns the same ``{path: content}`` shape
    ``fuzzlab.labgen.gates``/``fuzzlab.labgen.secret_scanner`` already
    consume, so this CLI does not re-implement tree assembly.
    """
    return tier3.render_whole_sample(emitter, manifest.cells)


def write_tree(out_dir: Path, tree: dict[str, bytes]) -> None:
    for rel_path, content in tree.items():
        dest = out_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)


def _weakened_twin(cell: Cell) -> Cell:
    """The same cell with its transform pipeline emptied -- used as a
    generic, manifest-agnostic "other half" of a minimal pair (mirrors
    ``tests/test_labgen_minimal_pair.py``'s own fixture convention: same
    cell identity, only ``transform`` toggled). This lets the minimal-pair
    checkers below run against *any* manifest, not only one that happens to
    author explicit vulnerable/secure twin cells."""
    return dataclasses.replace(cell, transform=Pipeline(()))


def run_checks(emitter: Emitter, manifest: Manifest, tree: dict[str, bytes]) -> list[str]:
    """Run the offline ``--check`` gate suite against the already-rendered
    ``tree``. Returns the list of failure messages (empty == all gates
    passed). Never raises for an expected gate failure -- only for a setup
    problem the caller should not swallow (e.g. a missing external tool)."""
    failures: list[str] = []
    cells = _supported_cells(emitter, manifest)

    # 1. Name-leak scanner (gates.py).
    leaks = gates.scan_generated_tree_for_name_leaks(tree)
    if leaks:
        failures.append(
            "name-leak scanner: vulnerability-class name(s) leaked into the generated tree: "
            + "; ".join(f"{leak.context}={leak.text!r} (matched {leak.matched_term!r})" for leak in leaks)
        )

    # 2. Secret scanner (secret_scanner.py, Gitleaks-backed).
    try:
        secret_result = secret_scanner.scan_tree_for_secrets(tree)
    except secret_scanner.ToolNotFoundError as exc:
        failures.append(f"secret scanner: {exc}")
    except secret_scanner.SecretScanError as exc:
        failures.append(f"secret scanner crashed (fail-closed): {exc}")
    else:
        if not secret_result.passed:
            failures.append(
                "secret scanner: secret(s) found in the generated tree: "
                + "; ".join(f"{leak.file}:{leak.start_line} ({leak.rule_id})" for leak in secret_result.leaks)
            )

    # 3. Regenerate-and-diff determinism check, over the real emitter output
    #    (fuzzlab.labgen.conformance.tier3 -- the emitter-level counterpart
    #    of fuzzlab.labgen.gates.regenerate_and_diff, which only proves this
    #    property for the Phase-0 scaffold renderer, not a real Emitter).
    try:
        tier3.regenerate_and_diff_emitter(emitter, cells)
    except tier3.RegenerateDiffError as exc:
        failures.append(f"regenerate-and-diff determinism check: {exc}")

    # 4. Minimal-pair checker (minimal_pair.py), against a generic
    #    transform-emptied twin of each supported cell (see
    #    `_weakened_twin`) -- works for any manifest, not only one that
    #    authors explicit vulnerable/secure twin cell pairs.
    for cell in cells:
        weakened = _weakened_twin(cell)
        if not emitter.supports(weakened.vuln_class, weakened.sink_context):
            continue
        try:
            vulnerable_render = emitter.render(weakened)
            twin_render = emitter.render(cell)
            minimal_pair.check_minimal_pair(vulnerable_render, twin_render)
        except minimal_pair.MinimalPairError as exc:
            failures.append(f"minimal-pair checker ({cell.cell_id}): {exc}")

    # 5. TODO(L-P0.9): wire the regression/additive-only gate here once it
    #    lands (fuzzlab/labgen/regression_gate.py or similar) -- not present
    #    in this worktree as of this CLI's authoring; see
    #    docs/LAB_IMPLEMENTATION_PLAN.md L-P0.9 (§1.1, T-LAB0.9).

    # 6. Conformance Tier 0 (lint + minimal-pair diff) -- offline, real.
    if tier0.php_available():
        for cell in cells:
            for result in tier0.lint_emitted_files(emitter.render(cell)):
                if not result.ok:
                    failures.append(f"conformance Tier 0 lint: {result.path}: {result.detail}")
    checker = tier0.get_minimal_pair_checker()
    for cell in cells:
        weakened = _weakened_twin(cell)
        if not emitter.supports(weakened.vuln_class, weakened.sink_context):
            continue
        try:
            pair_result = checker(emitter.render(weakened), emitter.render(cell))
        except minimal_pair.MinimalPairError as exc:
            # The real checker (once it has landed -- see
            # `tier0.get_minimal_pair_checker`) raises rather than
            # returning a `MinimalPairResult`; the naive fallback instead
            # returns one with `is_minimal_pair=False`. Handle both shapes.
            failures.append(f"conformance Tier 0 minimal-pair diff ({cell.cell_id}): {exc}")
            continue
        if pair_result is not None and not pair_result.is_minimal_pair:
            failures.append(f"conformance Tier 0 minimal-pair diff ({cell.cell_id}): {pair_result.notes}")

    # 7. Conformance Tier 3 (whole-lab regeneration) -- offline, real.
    try:
        tier3.regenerate_and_diff_emitter(emitter, cells)
    except tier3.RegenerateDiffError as exc:
        failures.append(f"conformance Tier 3 whole-lab regeneration: {exc}")

    return failures


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"lab-generate: {exc}", file=sys.stderr)
        return 2

    try:
        emitter = _get_emitter(args.emitter)
    except LabGenCliError as exc:
        print(f"lab-generate: {exc}", file=sys.stderr)
        return 2

    tree = render_manifest(emitter, manifest)
    out_dir = Path(args.out)
    write_tree(out_dir, tree)
    print(f"lab-generate: wrote {len(tree)} file(s) to {out_dir} ({len(manifest.cells)} cell(s) in manifest)")

    if args.check:
        failures = run_checks(emitter, manifest, tree)
        if failures:
            print(f"lab-generate --check: {len(failures)} gate(s) FAILED:", file=sys.stderr)
            for msg in failures:
                print(f"  - {msg}", file=sys.stderr)
            return 1
        print("lab-generate --check: all gates passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
