"""Cutover coverage gate (L-P3.3c-CUT prep, `CC-LAB-0053`/`FR-LAB-51`,
``docs/LAB_IMPLEMENTATION_PLAN.md`` §4.3.6.6 point 3).

Builds only the *gate*, not the cutover it gates. The atomic cutover
(``L-P3.3c-CUT``, retiring ``puppy-fort-factory/``) is deliberately not run by
this module or anything it calls: it is blocked on human sign-off because it
deletes the ground-truth fixture and re-points production code/deploy config
(§4.3.6.5). This module answers a narrower, always-answerable question: does
every ``PFF-`` case in ``lab/ground-truth/labels.json`` map to at least one
emitted ``php_laravel`` cell, or to a reviewed entry in the migration-exemption
register (``lab/ground-truth/migration-exemptions.yaml``)? A case in neither
list fails loud, so a case added to ``labels.json`` later without a matching
``php_laravel`` cell or exemption entry breaks the build rather than silently
going uncovered.

Deliberately its own module rather than an addition to
:mod:`fuzzlab.labgen.regression_gate`: that gate diffs two already-loaded
:class:`~fuzzlab.labels.contract.GroundTruth` snapshots (schema-shaped,
independent of manifests/emitters, by design -- see its own module
docstring); this gate instead walks manifest cells through an emitter's
``supports()`` predicate (PA-0001/PA-0027: the covered set is derived, never a
hand-maintained literal), which is a different shape of computation over
different inputs. Mirrors that module's own two-function convention
(``diff_*`` non-raising, ``assert_*`` raising) rather than inventing a third
shape.
"""

from __future__ import annotations

import dataclasses
import glob as _glob
from pathlib import Path
from typing import Iterable

import yaml

from fuzzlab.labels import contract
from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, ground_truth_cases_for
from fuzzlab.labgen.schema import load_manifest

__all__ = [
    "CutoverGateError",
    "CutoverCoverageDiff",
    "DEFAULT_EXEMPTIONS_PATH",
    "DEFAULT_MANIFESTS_GLOB",
    "DEFAULT_LABELS_DIR",
    "load_exemptions",
    "compute_php_laravel_coverage",
    "diff_cutover_coverage",
    "assert_cutover_coverage",
]

#: Conventional locations, overridable by callers/tests -- the same
#: injectable-path convention ``regression_gate.check_no_regression``'s
#: ``loader`` uses, so a test never needs to touch the real repo files to
#: exercise the gate logic.
DEFAULT_EXEMPTIONS_PATH = Path("lab/ground-truth/migration-exemptions.yaml")
DEFAULT_MANIFESTS_GLOB = "lab/manifests/*.yaml"
DEFAULT_LABELS_DIR = "lab/ground-truth"


class CutoverGateError(AssertionError):
    """Raised when a ``PFF-`` case in ``labels.json`` is neither reproduced by
    any emitted ``php_laravel`` cell nor named in the exemption register, or
    when the exemption register itself is malformed."""


@dataclasses.dataclass(frozen=True)
class CutoverCoverageDiff:
    """The result of checking every ``labels.json`` case against derived
    ``php_laravel`` coverage and the exemption register.

    ``covering_cells`` is informational (which cells contributed each covered
    case's coverage, for diagnostics); ``uncovered_case_ids`` is what makes
    the gate fail.
    """

    covered_case_ids: tuple[str, ...] = ()
    exempted_case_ids: tuple[str, ...] = ()
    uncovered_case_ids: tuple[str, ...] = ()
    covering_cells: dict[str, tuple[str, ...]] = dataclasses.field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return not self.uncovered_case_ids

    def describe(self) -> str:
        return (
            "PFF- case(s) with neither a php_laravel cell nor a migration-exemptions.yaml "
            "entry: " + ", ".join(sorted(self.uncovered_case_ids))
        )


def load_exemptions(path: str | Path = DEFAULT_EXEMPTIONS_PATH) -> dict[str, str]:
    """Load the migration-exemption register: ``PFF-`` case id -> reason.

    A missing file loads as empty (no exemptions declared yet) rather than
    erroring, so a fresh checkout without the file still gets a loud,
    specific gate failure naming every uncovered case, instead of a file-not-
    found traceback. A *malformed* file (present but not shaped as expected)
    raises :class:`CutoverGateError`, naming the entry at fault -- fail loud
    on a broken register rather than silently treating it as empty.
    """
    path = Path(path)
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text("utf-8")) or {}
    if not isinstance(raw, dict) or "exemptions" not in raw:
        raise CutoverGateError(f"{path}: expected a top-level 'exemptions' list")
    entries = raw["exemptions"]
    if not isinstance(entries, list):
        raise CutoverGateError(f"{path}: 'exemptions' must be a list, got {type(entries).__name__}")

    exemptions: dict[str, str] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or "pff_case" not in entry or "reason" not in entry:
            raise CutoverGateError(
                f"{path}: exemptions[{i}] must be a mapping with 'pff_case' and 'reason' keys"
            )
        case_id, reason = entry["pff_case"], entry["reason"]
        if not isinstance(case_id, str) or not case_id.startswith("PFF-"):
            raise CutoverGateError(f"{path}: exemptions[{i}].pff_case must be a 'PFF-...' string, got {case_id!r}")
        if not isinstance(reason, str) or not reason.strip():
            raise CutoverGateError(f"{path}: exemptions[{i}].reason must be a non-empty string")
        if case_id in exemptions:
            raise CutoverGateError(f"{path}: duplicate exemption entry for {case_id!r}")
        exemptions[case_id] = reason
    return exemptions


def compute_php_laravel_coverage(
    manifest_paths: Iterable[str | Path] | None = None,
    *,
    emitter: Emitter | None = None,
) -> dict[str, tuple[str, ...]]:
    """``PFF-`` case id -> the cell ids (across every manifest) that
    reproduce it.

    Derived from ``emitter.supports()`` over every cell of every manifest
    (default: every ``lab/manifests/*.yaml`` file, sorted) plus
    :func:`fuzzlab.labgen.emitters.php_laravel.ground_truth_cases_for`'s own
    page-profile-derived mapping -- never a hand-maintained case-id list
    (PA-0001/PA-0027), so a case that gains or loses a reproducing cell
    changes what this returns without a second list to keep in sync.
    Non-``php_laravel`` cells (a manifest can carry cells for more than one
    stack) and cells the emitter declares unsupported are skipped, exactly
    like every other ``supports()``-gated whole-manifest walk in this
    project (``PA-0024``).
    """
    emitter = emitter if emitter is not None else LaravelEmitter()
    if manifest_paths is None:
        manifest_paths = sorted(_glob.glob(DEFAULT_MANIFESTS_GLOB))
    coverage: dict[str, list[str]] = {}
    for manifest_path in manifest_paths:
        manifest = load_manifest(manifest_path)
        for cell in manifest.cells:
            if cell.stack_profile != "php_laravel":
                continue
            if not emitter.supports(cell.vuln_class, cell.sink_context):
                continue
            for case_id in ground_truth_cases_for(cell):
                coverage.setdefault(case_id, []).append(cell.cell_id)
    return {case_id: tuple(cell_ids) for case_id, cell_ids in coverage.items()}


def diff_cutover_coverage(
    *,
    labels_dir: str | Path = DEFAULT_LABELS_DIR,
    manifest_paths: Iterable[str | Path] | None = None,
    exemptions_path: str | Path = DEFAULT_EXEMPTIONS_PATH,
    emitter: Emitter | None = None,
) -> CutoverCoverageDiff:
    """Classify every ``PFF-`` case in ``labels.json`` as covered, exempted,
    or uncovered. Never raises -- see :func:`assert_cutover_coverage` for the
    gate itself."""
    cases = contract.load_labels(labels_dir)
    coverage = compute_php_laravel_coverage(manifest_paths, emitter=emitter)
    exemptions = load_exemptions(exemptions_path)

    covered: list[str] = []
    exempted: list[str] = []
    uncovered: list[str] = []
    for case in cases:
        if case.case_id in coverage:
            covered.append(case.case_id)
        elif case.case_id in exemptions:
            exempted.append(case.case_id)
        else:
            uncovered.append(case.case_id)

    return CutoverCoverageDiff(
        covered_case_ids=tuple(sorted(covered)),
        exempted_case_ids=tuple(sorted(exempted)),
        uncovered_case_ids=tuple(sorted(uncovered)),
        covering_cells=coverage,
    )


def assert_cutover_coverage(
    *,
    labels_dir: str | Path = DEFAULT_LABELS_DIR,
    manifest_paths: Iterable[str | Path] | None = None,
    exemptions_path: str | Path = DEFAULT_EXEMPTIONS_PATH,
    emitter: Emitter | None = None,
) -> CutoverCoverageDiff:
    """Raise :class:`CutoverGateError` unless every ``PFF-`` case in
    ``labels.json`` is covered by at least one emitted ``php_laravel`` cell or
    named in the exemption register; otherwise return the (clean)
    :class:`CutoverCoverageDiff`."""
    diff = diff_cutover_coverage(
        labels_dir=labels_dir,
        manifest_paths=manifest_paths,
        exemptions_path=exemptions_path,
        emitter=emitter,
    )
    if not diff.is_clean:
        raise CutoverGateError(
            "cutover coverage gate failed (docs/LAB_IMPLEMENTATION_PLAN.md §4.3.6.6 point 3): "
            + diff.describe()
        )
    return diff
