"""``fuzzlab lab-generate`` -- render a manifest to real source files via a
selected emitter, and (with ``--check``) run the offline build-gate suite
against the rendered output (T-LAB0.10).

Usage::

    fuzzlab lab-generate --manifest <path> --out <dir> [--emitter NAME] [--check]
                         [--corpus-report <path>]

This is a thin CLI over already-built pieces:

- ``fuzzlab.labgen.schema.load_manifest`` -- manifest loading/validation.
- an :class:`~fuzzlab.labgen.emitter.Emitter`, looked up by name from
  ``EMITTER_REGISTRY`` (default ``"php_current"``) -- **never hardcoded**,
  so Phase 3's additional emitters (built by parallel lanes) register here
  without a CLI rewrite.
- ``--check``, run in this order: the name-leak scanner (``gates.py``), the
  secret scanner (``secret_scanner.py``), the regenerate-and-diff
  determinism check, the minimal-pair checker (``minimal_pair.py``), and the
  Tier 0 (lint + minimal-pair) and Tier 3 (whole-lab regeneration)
  conformance checks (``fuzzlab.labgen.conformance``), and the
  fingerprint-independence gate (``fuzzlab.labgen.fingerprint_gate``,
  ``CR-LAB-0001`` §3) -- the last of these only when the manifest's cells
  actually span two or more ``stack_profile`` values, since that gate is
  ill-defined for a single-stack corpus (see
  ``MIN_STACKS_FOR_FINGERPRINT_GATE``). The regression/
  additive-only gate (``fuzzlab.labgen.regression_gate``, T-LAB0.9) is not
  yet wired here -- see the ``# TODO(L-P0.9-integration)`` in ``run_checks``.
- ``--corpus-report <path>``, which writes the corpus-analysis **artifact**
  (``corpus_analysis.corpus_report``: near-duplicate rate + class x transform x
  verdict diversity counts, plan §2.4). Deliberately independent of
  ``--check`` and never able to fail the build -- it is informative output,
  not a gate, so it must not share the gate suite's pass/fail path.

Resolver note (axis-range expansion, T-LAB2.1/"L-P1.1"): ``fuzzlab.labgen
.schema.Manifest.from_dict`` now expands an ``axis_ranges`` block internally
before ``load_manifest`` ever returns, so this CLI needs no resolver-wiring
hook of its own -- it "just works" transparently, the same
forward-compatible convention this project already uses (e.g.
``conformance.tier0.get_minimal_pair_checker``).
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

from fuzzlab.labgen import corpus_analysis, fingerprint_gate, gates, minimal_pair, secret_scanner
from fuzzlab.labgen.conformance import tier0, tier3
from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import Cell, Manifest, ManifestError, Pipeline, load_manifest
from fuzzlab.labgen.verdict import SafetyMatrix, SafetyMatrixError, load_safety_matrix

#: Emitter name -> factory. Looked up by name (``--emitter``, default
#: ``"php_current"``) rather than hardcoded, so a future emitter (Phase 3)
#: registers here without a CLI rewrite.
EMITTER_REGISTRY: dict[str, type[Emitter]] = {
    "php_current": PhpCurrentEmitter,
    # L-P3.3b: the Laravel emitter, once it carries the full shape inventory,
    # is a real build target rather than a foundation -- so it registers here
    # and `--emitter php_laravel --check` runs the whole offline gate suite
    # over lab/manifests/phase3_php_laravel_sample.yaml (§4.3 step 3). The
    # registry is looked up by name for exactly this reason: a new emitter
    # registers without a CLI rewrite.
    "php_laravel": LaravelEmitter,
}

DEFAULT_ROOT_SEED = "lab-generate-cli"

#: Minimum number of distinct ``Cell.stack_profile`` values a manifest must
#: span before the fingerprint-independence gate (``fingerprint_gate.py``,
#: ``CR-LAB-0001`` §3) is run at all -- and simultaneously the
#: ``min_stacks_per_class`` the gate is run with. Both are the same number for
#: the same reason: "every vulnerability class appears on >= 2 stacks" is
#: unsatisfiable, and the chi-square test's contingency table is degenerate,
#: for a corpus with only one stack. This is ``CR-LAB-0001`` §3/§4's own
#: canonical value, and matches ``fingerprint_gate.run_fingerprint_gate``'s
#: own default (see ``docs/LAB_IMPLEMENTATION_PLAN.md`` §4.4, which makes this
#: dependency explicit: "the fingerprint-independence gate specifically needs
#: **two** stacks landed (``min_stacks_per_class >= 2``)").
MIN_STACKS_FOR_FINGERPRINT_GATE = 2

#: ``CR-LAB-0001`` §3/§4's canonical "every stack carries >= N classes" value,
#: used as a *ceiling* rather than a flat requirement -- see
#: :func:`fingerprint_gate_config` for why.
CANONICAL_MIN_CLASSES_PER_STACK = 3


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
    parser.add_argument(
        "--corpus-report",
        metavar="PATH",
        default=None,
        help=(
            "write the corpus-analysis ARTIFACT (de-duplication rate + class x transform x "
            "verdict diversity counts) as JSON to PATH. Informative only -- never fails the "
            "build, independent of --check (see fuzzlab.labgen.corpus_analysis, plan SS2.4)"
        ),
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


def corpus_records_from_manifest(manifest: Manifest) -> list[dict[str, str]]:
    """The manifest's cells as ``fingerprint_gate``-shaped corpus records.

    ``fingerprint_gate`` is deliberately schema-independent (a record is just a
    mapping with ``stack``/``vuln_class`` keys, never a :class:`Cell`), so this
    is the one adapter between the two -- the gate keeps knowing nothing about
    :mod:`fuzzlab.labgen.schema`, per PA-0003/PA-0021's "one shared conversion
    at one site" shape.

    Scoped to ``manifest.cells``, **not** to :func:`_supported_cells`:
    fingerprint independence is a property of the *authored corpus's* metadata
    shape (`CR-LAB-0001` §3), not of whichever subset one emitter happens to
    render, and a multi-stack manifest is by construction never fully
    renderable by any single emitter.

    No ``verdict`` key is emitted: a cell's verdict is *derived* (never
    authored) from the safety matrix by :mod:`fuzzlab.labgen.verdict`, whose
    matrix lives at a repo-relative default path that no production code
    currently loads -- reading it here would make ``--check`` silently
    cwd-dependent. ``run_fingerprint_gate`` already documents and tests the
    "verdict key absent -> skip the stack/verdict check" path, so this degrades
    explicitly rather than by accident. Wiring the stack/verdict half is a real
    remaining deliverable, not an oversight (see ``CC-LAB`` entry for L-P3.4).
    """
    return [{"stack": cell.stack_profile, "vuln_class": cell.vuln_class} for cell in manifest.cells]


def fingerprint_gate_config(records: list[dict[str, str]]) -> dict[str, object]:
    """The ``run_fingerprint_gate`` kwargs for ``records``, with
    ``expected_classes``/``expected_stacks`` derived from the corpus actually
    at hand (`docs/LAB_IMPLEMENTATION_PLAN.md` §4.4: "populated from whichever
    stacks/classes actually exist at that point (not hand-waved
    placeholders)").

    ``min_classes_per_stack`` is ``min(CANONICAL_MIN_CLASSES_PER_STACK, <number
    of distinct classes in the corpus>)``. The canonical 3 is a *ceiling*, not
    a flat requirement, because a corpus whose whole class vocabulary is
    smaller than 3 cannot satisfy it for a reason that has nothing to do with
    fingerprint leakage -- today's manifests only author two classes
    (``sqli``/``xss``), so a flat 3 would fail every real manifest while
    telling us nothing about stack/class entanglement. The requirement it
    enforces is therefore "every stack carries *every* class the corpus has,
    up to the canonical 3", which is the actual anti-fingerprint property and
    tightens automatically as more classes land.
    """
    stacks = sorted({r["stack"] for r in records})
    classes = sorted({r["vuln_class"] for r in records})
    return {
        "min_stacks_per_class": MIN_STACKS_FOR_FINGERPRINT_GATE,
        "min_classes_per_stack": min(CANONICAL_MIN_CLASSES_PER_STACK, len(classes)),
        "expected_classes": classes,
        "expected_stacks": stacks,
    }


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

    # 5. TODO(L-P0.9-integration): fuzzlab.labgen.regression_gate landed with
    #    L-P0.9, but wiring it here needs a Cell-to-GroundTruth converter
    #    (deriving labels.json/injection-points.json/expectedresults.csv-shaped
    #    data from a rendered manifest's cells) that does not exist yet -- a
    #    separate, real deliverable; see docs/LAB_IMPLEMENTATION_PLAN.md L-P0.9
    #    (§1.1, T-LAB0.9).

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

    # 8. Fingerprint-independence gate (fingerprint_gate.py, CR-LAB-0001 §3) --
    #    a REQUIRED step whenever, and only whenever, the manifest's cells
    #    actually span >= MIN_STACKS_FOR_FINGERPRINT_GATE distinct
    #    stack_profile values. For a single-stack manifest the gate is not
    #    merely unhelpful but ill-defined (see MIN_STACKS_FOR_FINGERPRINT_GATE),
    #    so it is skipped with an explicit printed reason -- never a silent
    #    no-op, and never a failure for "a corpus that has not gone multi-stack
    #    yet", which is not a leakage problem.
    records = corpus_records_from_manifest(manifest)
    stacks = sorted({r["stack"] for r in records})
    if len(stacks) < MIN_STACKS_FOR_FINGERPRINT_GATE:
        print(
            f"lab-generate --check: fingerprint-independence gate SKIPPED -- this manifest's "
            f"cells span only {len(stacks)} distinct stack_profile value(s) {stacks}; the gate "
            f"needs >= {MIN_STACKS_FOR_FINGERPRINT_GATE} to be meaningful (a one-stack corpus "
            f"cannot put a class on two stacks, and its chi-square contingency table is "
            f"degenerate). Not a failure: single-stack is not a leakage problem."
        )
    else:
        try:
            fingerprint_gate.run_fingerprint_gate(records, **fingerprint_gate_config(records))
        except fingerprint_gate.MissingStatsDependencyError as exc:
            failures.append(f"fingerprint-independence gate (fail-closed, missing dependency): {exc}")
        except fingerprint_gate.FingerprintIndependenceError as exc:
            failures.append(f"fingerprint-independence gate: {exc}")

    return failures


def write_corpus_report_artifact(manifest: Manifest, path: str | Path) -> Path:
    """Write the `--corpus-report` artifact for `manifest` (plan §2.4).

    Deliberately reports over **every** cell in the manifest, not only the
    cells the selected emitter supports: this describes the authored corpus,
    not one emitter's rendering of it. The safety matrix is loaded
    best-effort -- if it is missing or invalid the artifact is still written,
    with every verdict recorded as
    `corpus_analysis.UNDERIVABLE_VERDICT`, because an informative artifact
    must never take a build down (`corpus_analysis`'s own doctrine).
    """
    try:
        matrix: SafetyMatrix | None = load_safety_matrix()
    except SafetyMatrixError:
        matrix = None
    return corpus_analysis.write_corpus_report(path, corpus_analysis.corpus_report(manifest.cells, matrix))


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

    if args.corpus_report:
        report_path = write_corpus_report_artifact(manifest, args.corpus_report)
        print(f"lab-generate: wrote corpus-analysis artifact (informative, not a gate) to {report_path}")

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
