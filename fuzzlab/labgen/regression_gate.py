"""Regression/additive-only build gate (T-LAB0.9).

The generator must never quietly reduce functionality: once a case exists in
the hand-authored ground truth (``lab/ground-truth/``), a later generator run
must keep emitting that same case ID at the same page with the same verdict.
New cases are fine (additive-only is the whole point); removing, relocating,
or re-verdicting an existing one is a build-breaking regression.

This gate is deliberately schema-shaped, not manifest-shaped: it diffs two
already-loaded :class:`fuzzlab.labels.contract.GroundTruth` snapshots (the
"baseline" — normally the hand-authored ``lab/ground-truth/`` — and the
"candidate" — normally the generator's freshly emitted output), the same way
``fingerprint_gate.py`` stays independent of ``fuzzlab.labgen.schema``. That
keeps this module usable now, before ``fuzzlab lab-generate`` (T-LAB0.10)
exists to produce a candidate directory to point at, and reusable later as
that CLI's ``--check`` gate without a rewrite.

Mirrors the existing gate convention (``gates.py``/``secret_scanner.py``/
``fingerprint_gate.py``): a typed error that names every violation (not just
the first), no silent pass, and the file-loading step is dependency-injectable
(``loader``) so tests never need to shell out or touch the real ground-truth
directory to exercise the diff logic.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Callable

from fuzzlab.labels import contract
from fuzzlab.labels.contract import GroundTruth

__all__ = [
    "RegressionGateError",
    "PageChange",
    "VerdictChange",
    "RegressionDiff",
    "GroundTruthLoader",
    "diff_ground_truth",
    "assert_no_regression",
    "check_no_regression",
]


class RegressionGateError(AssertionError):
    """Raised when a candidate ground truth removes, relocates, or
    re-verdicts a case that exists in the baseline (violates the
    never-reduce-functionality / additive-only contract, T-LAB0.9)."""


@dataclasses.dataclass(frozen=True)
class PageChange:
    case_id: str
    baseline_url: str
    candidate_url: str


@dataclasses.dataclass(frozen=True)
class VerdictChange:
    case_id: str
    baseline_verdict: bool
    candidate_verdict: bool


@dataclasses.dataclass(frozen=True)
class RegressionDiff:
    """The result of comparing a candidate ground truth against a baseline.

    ``added_case_ids`` is informational only (additive growth is allowed and
    expected); the other three fields are what makes the gate fail.
    """

    missing_case_ids: tuple[str, ...] = ()
    changed_pages: tuple[PageChange, ...] = ()
    changed_verdicts: tuple[VerdictChange, ...] = ()
    added_case_ids: tuple[str, ...] = ()

    @property
    def is_clean(self) -> bool:
        return not (self.missing_case_ids or self.changed_pages or self.changed_verdicts)

    def describe(self) -> str:
        parts: list[str] = []
        if self.missing_case_ids:
            parts.append(
                "missing case IDs (present in baseline, absent from candidate): "
                + ", ".join(sorted(self.missing_case_ids))
            )
        for c in sorted(self.changed_pages, key=lambda x: x.case_id):
            parts.append(
                f"{c.case_id}: page changed ({c.baseline_url!r} -> {c.candidate_url!r})"
            )
        for c in sorted(self.changed_verdicts, key=lambda x: x.case_id):
            parts.append(
                f"{c.case_id}: verdict changed "
                f"({c.baseline_verdict!r} -> {c.candidate_verdict!r})"
            )
        return "; ".join(parts)


def diff_ground_truth(baseline: GroundTruth, candidate: GroundTruth) -> RegressionDiff:
    """Diff ``candidate`` against ``baseline`` by ``case_id``.

    Every case present in ``baseline`` must still be present in
    ``candidate`` at the same page (``url``) with the same verdict
    (``expected_vulnerable``); a case ``candidate`` adds beyond ``baseline``
    is recorded but never flagged.
    """
    baseline_by_id = {c.case_id: c for c in baseline.cases}
    candidate_by_id = {c.case_id: c for c in candidate.cases}

    missing = tuple(sorted(set(baseline_by_id) - set(candidate_by_id)))
    added = tuple(sorted(set(candidate_by_id) - set(baseline_by_id)))

    changed_pages: list[PageChange] = []
    changed_verdicts: list[VerdictChange] = []
    for case_id, base_case in baseline_by_id.items():
        cand_case = candidate_by_id.get(case_id)
        if cand_case is None:
            continue  # already recorded in `missing`
        if base_case.url != cand_case.url:
            changed_pages.append(PageChange(case_id, base_case.url, cand_case.url))
        if base_case.expected_vulnerable != cand_case.expected_vulnerable:
            changed_verdicts.append(
                VerdictChange(case_id, base_case.expected_vulnerable, cand_case.expected_vulnerable)
            )

    return RegressionDiff(
        missing_case_ids=missing,
        changed_pages=tuple(changed_pages),
        changed_verdicts=tuple(changed_verdicts),
        added_case_ids=added,
    )


def assert_no_regression(baseline: GroundTruth, candidate: GroundTruth) -> RegressionDiff:
    """Raise :class:`RegressionGateError` if ``candidate`` regresses
    ``baseline``; otherwise return the (clean, possibly additive) diff."""
    diff = diff_ground_truth(baseline, candidate)
    if not diff.is_clean:
        raise RegressionGateError(
            "regression/additive-only gate failed (T-LAB0.9): the candidate "
            "ground truth removed or changed an existing case: " + diff.describe()
        )
    return diff


GroundTruthLoader = Callable[[str | Path], GroundTruth]


def check_no_regression(
    baseline_dir: str | Path,
    candidate_dir: str | Path,
    *,
    loader: GroundTruthLoader = contract.load,
) -> RegressionDiff:
    """Load both ground-truth directories with ``loader`` (default:
    :func:`fuzzlab.labels.contract.load`) and assert the candidate is an
    additive-only superset of the baseline.

    ``loader`` is injectable so tests (and any future CLI wiring, e.g.
    T-LAB0.10's ``--check``) can point this at a generator's freshly emitted
    output directory without this module knowing how that directory came to
    exist.
    """
    baseline = loader(baseline_dir)
    candidate = loader(candidate_dir)
    return assert_no_regression(baseline, candidate)
