"""Corpus analysis: stratified splits, de-duplication, diversity reporting
(`docs/LAB_IMPLEMENTATION_PLAN.md` §2.4, lane L-P1.4).

Three read-only analyses over an already-built cell set (a
`fuzzlab.labgen.schema.Manifest`'s `cells`, or any sequence of `Cell`). This
module never builds, renders, or mutates a cell — it is generator-build-time
tooling, the same category as `gates.py`/`fingerprint_gate.py`, not a runtime
component.

**Why a new module** rather than an addition to an existing one: the three
pieces here share one concept (the *generating-rule group* a cell belongs to)
and none of the existing modules owns that concept. `gates.py` holds
pass/fail build gates; `fingerprint_gate.py` is specifically the χ²
stack-independence *gate*; `leakage_probe.py` is the (non-gating) metadata
leakage probe. Two of the three things here are deliberately **not** gates
(§2.4: "a diversity report ... as a build artifact, not a gate"), so folding
them into either gate module would blur exactly the distinction the plan
draws.

The three pieces:

1. **Stratified split** (`stratified_split`) — a train/holdout split grouped
   by **generating-rule ID**, so near-duplicate cells never land on both
   sides. It reuses `leakage_probe.grouped_cv` — the same
   `StratifiedGroupKFold` construction the leakage probe already uses for its
   own cross-validation — rather than re-deriving a grouping strategy here
   (§2.4 says so explicitly, and PA-0003/PA-0021 require one shared function
   for a convention with more than one participant).
2. **De-duplication** (`duplication_report`) — "near-duplicate" for this
   corpus is defined as an identical `DuplicateSignature`:
   `(vuln_class, sink_context, transform-shape)` **regardless of cell ID**,
   route, or stack profile. Reported as a rate, never enforced.
3. **Diversity report** (`diversity_report`) — class × transform × verdict
   counts, plus the marginals. Purely informative: it has no thresholds, no
   pass/fail, and raises nothing on a "bad" distribution. It is the
   descriptive companion to `fingerprint_gate.py`'s χ²-balance gate, not a
   second copy of it: the gate asks "is stack↔class dependence significant,
   fail the build if so"; this asks "what is actually in the corpus".

`corpus_report` bundles (2) and (3) into the one artifact a build writes
(`write_corpus_report`).

Definitional choices, stated because they are judgement calls, not facts:

- **`transform_shape` is the ordered op tuple**, not an unordered multiset and
  not just the op count. `fuzzlab.labgen.verdict.verdict()` is explicitly
  order-sensitive over `pipeline.ops` (a `neutralises` op followed by an
  `introduces` op derives a different verdict from the reverse), so two cells
  whose pipelines differ only in order are genuinely different cells and must
  not be collapsed as duplicates.
- **`stack_profile` is NOT part of the signature**, matching the plan's
  candidate tuple. That makes groups *larger* (a php and a node cell of the
  same class/sink/transform share a group), which is the conservative
  direction for a split: it can only reduce train/holdout leakage, never
  increase it. Stack-vs-class balance is `fingerprint_gate.py`'s job.
- **`route` is NOT part of the signature** either — which is what makes the
  existing corpus's real near-duplicates visible (e.g.
  `lab/manifests/phase0_real_pages_sample.yaml`'s `/product.php` and
  `/blog_post.php` cells are deliberately the same shape on two different
  real pages). A route-sensitive definition would report a 0% duplicate rate
  and tell us nothing.
- **Generating-rule ID is derived from the signature**, because no `Cell`
  field records which rule produced it (`Cell` is out of scope for this lane,
  and `cell_id` prefixes are per-manifest namespaces like `LABGEN-RP-`, too
  coarse to group by — every cell in a manifest would be one group). The
  signature is the best available proxy and is *exactly* the right one for
  this purpose: grouping by it makes "no near-duplicate spans the split" true
  by construction rather than by hope. If a future `Cell` gains a real
  `rule_id`, `generating_rule_id` is the single place to change (PA-0003).
"""

from __future__ import annotations

import dataclasses
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from .schema import Cell
from .verdict import SafetyMatrix, SafetyMatrixError, verdict as derive_verdict

__all__ = [
    "CorpusSplitError",
    "MissingSplitDependencyError",
    "DuplicateSignature",
    "DuplicateGroup",
    "DuplicationReport",
    "DiversityCount",
    "DiversityReport",
    "CorpusSplit",
    "CorpusReport",
    "UNDERIVABLE_VERDICT",
    "duplicate_signature",
    "generating_rule_id",
    "group_cells_by_rule",
    "duplication_report",
    "diversity_report",
    "stratified_split",
    "corpus_report",
    "write_corpus_report",
]


#: Recorded as a cell's verdict in the diversity report when the safety matrix
#: cannot derive one (an `(op, sink_family)` pair it does not cover). The
#: report counts these separately instead of raising: this artifact is
#: informative and must never fail a build, but an authoring gap still has to
#: be *visible* rather than silently dropped from the counts.
UNDERIVABLE_VERDICT = "UNDERIVABLE"


class CorpusSplitError(RuntimeError):
    """Raised when a corpus cannot be split as asked — too few
    generating-rule groups for the requested number of folds, fewer than two
    label classes, or (as a defensive post-condition) a split that would put
    one generating-rule group on both sides."""


class MissingSplitDependencyError(RuntimeError):
    """Raised instead of letting a raw `ImportError` propagate when
    `scikit-learn` (the `labgen` extra) isn't installed. Only
    `stratified_split` needs it; the de-duplication and diversity reports are
    pure-Python and work without it. Typed-error-at-the-boundary per
    PA-0021, mirroring `fingerprint_gate.MissingStatsDependencyError`."""


@dataclasses.dataclass(frozen=True, order=True)
class DuplicateSignature:
    """The corpus's definition of a near-duplicate: two cells are
    near-duplicates iff their signatures are equal.

    Deliberately excludes `cell_id`, `route`, `sink_endpoint`, `param`, and
    `stack_profile` — see this module's docstring for why each.
    """

    vuln_class: str
    sink_family: str
    required_neutralizations: tuple[str, ...]
    transform_shape: tuple[str, ...]

    @property
    def rule_id(self) -> str:
        """A stable, human-readable ID for the generating-rule group this
        signature stands for. Used as the grouping key for
        `stratified_split`."""
        neutralizations = "+".join(self.required_neutralizations) or "-"
        transform = ">".join(self.transform_shape) or "raw"
        return f"{self.vuln_class}|{self.sink_family}[{neutralizations}]|{transform}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "vuln_class": self.vuln_class,
            "sink_family": self.sink_family,
            "required_neutralizations": list(self.required_neutralizations),
            "transform_shape": list(self.transform_shape),
        }


def duplicate_signature(cell: Cell) -> DuplicateSignature:
    """The near-duplicate signature of one cell. The **one** place this
    corpus's "same shape" convention is defined (PA-0003); every other
    function here goes through it."""
    return DuplicateSignature(
        vuln_class=cell.vuln_class,
        sink_family=cell.sink_context.family,
        # Sorted: `required_neutralizations` is a set of concerns, not an
        # ordered pipeline, so authoring order must not split one group in two.
        required_neutralizations=tuple(sorted(cell.sink_context.required_neutralizations)),
        transform_shape=tuple(cell.transform.ops),
    )


def generating_rule_id(cell: Cell) -> str:
    """The generating-rule group ID for `cell` — the grouping key both the
    de-duplication report and `stratified_split` use, so "cells the dedup
    report calls near-duplicates" and "cells the split keeps together" can
    never drift apart."""
    return duplicate_signature(cell).rule_id


def group_cells_by_rule(cells: Sequence[Cell]) -> dict[str, tuple[Cell, ...]]:
    """`{generating_rule_id: cells}`, insertion-ordered by first appearance."""
    groups: dict[str, list[Cell]] = {}
    for cell in cells:
        groups.setdefault(generating_rule_id(cell), []).append(cell)
    return {rule_id: tuple(members) for rule_id, members in groups.items()}


# --- (2) De-duplication ------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class DuplicateGroup:
    """One set of two or more cells sharing a signature."""

    signature: DuplicateSignature
    cell_ids: tuple[str, ...]

    @property
    def size(self) -> int:
        return len(self.cell_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature.to_dict(),
            "cell_ids": list(self.cell_ids),
            "size": self.size,
        }


@dataclasses.dataclass(frozen=True)
class DuplicationReport:
    """Duplicate/near-duplicate rate across a cell set. Informative — nothing
    here raises on a high rate."""

    n_cells: int
    n_signatures: int
    #: Cells that are not the first occurrence of their signature, i.e. how
    #: many cells could be removed without losing a distinct shape.
    n_redundant_cells: int
    #: `n_redundant_cells / n_cells` (0.0 for an empty corpus).
    duplicate_rate: float
    #: Every signature carried by >= 2 cells, largest group first, then by
    #: signature for a stable order.
    duplicate_groups: tuple[DuplicateGroup, ...]
    #: Size of the largest duplicate group (1 when every cell is unique).
    max_group_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_cells": self.n_cells,
            "n_signatures": self.n_signatures,
            "n_redundant_cells": self.n_redundant_cells,
            "duplicate_rate": self.duplicate_rate,
            "max_group_size": self.max_group_size,
            "duplicate_groups": [g.to_dict() for g in self.duplicate_groups],
        }


def duplication_report(cells: Sequence[Cell]) -> DuplicationReport:
    """Report the duplicate/near-duplicate rate over `cells` (§2.4).

    "Near-duplicate" is `duplicate_signature` equality. An empty corpus is a
    valid (all-zero) report, not an error — this is a descriptive measure, and
    a caller that cares about emptiness already knows.
    """
    by_signature: dict[DuplicateSignature, list[str]] = {}
    for cell in cells:
        by_signature.setdefault(duplicate_signature(cell), []).append(cell.cell_id)

    groups = tuple(
        DuplicateGroup(signature=sig, cell_ids=tuple(ids))
        for sig, ids in sorted(by_signature.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        if len(ids) > 1
    )
    n_cells = len(cells)
    n_redundant = n_cells - len(by_signature)
    return DuplicationReport(
        n_cells=n_cells,
        n_signatures=len(by_signature),
        n_redundant_cells=n_redundant,
        duplicate_rate=(n_redundant / n_cells) if n_cells else 0.0,
        duplicate_groups=groups,
        max_group_size=max((len(ids) for ids in by_signature.values()), default=1),
    )


# --- (3) Diversity report (artifact, NOT a gate) -----------------------------


@dataclasses.dataclass(frozen=True)
class DiversityCount:
    """One `(class, transform, verdict)` cell of the diversity cross-tab."""

    vuln_class: str
    transform_shape: tuple[str, ...]
    verdict: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "transform_shape": list(self.transform_shape),
            "verdict": self.verdict,
            "count": self.count,
        }


@dataclasses.dataclass(frozen=True)
class DiversityReport:
    """Class × transform × verdict counts plus marginals, as a build
    **artifact**. Informative by construction: it carries no thresholds and
    `diversity_report` never raises on a skewed corpus (contrast
    `fingerprint_gate.run_fingerprint_gate`, which is a gate and does)."""

    n_cells: int
    #: The full class × transform × verdict cross-tab, sorted for stability.
    counts: tuple[DiversityCount, ...]
    class_counts: Mapping[str, int]
    transform_counts: Mapping[str, int]
    verdict_counts: Mapping[str, int]
    stack_counts: Mapping[str, int]
    sink_family_counts: Mapping[str, int]
    #: Cells whose verdict the supplied matrix could not derive (counted, not
    #: raised — see `UNDERIVABLE_VERDICT`).
    n_underivable_verdicts: int
    #: The `safety_matrix_version` verdicts were derived under, or None when
    #: no matrix was supplied (then every verdict is `UNDERIVABLE_VERDICT`).
    safety_matrix_version: Optional[int]

    #: Stated in the artifact itself so a reader can never mistake this for a
    #: pass/fail result (§2.4: "informative alongside the χ² gate").
    gating: str = "informative-only: this report is a build artifact, never a build gate"

    def to_dict(self) -> dict[str, Any]:
        return {
            "gating": self.gating,
            "n_cells": self.n_cells,
            "safety_matrix_version": self.safety_matrix_version,
            "n_underivable_verdicts": self.n_underivable_verdicts,
            "class_counts": dict(self.class_counts),
            "transform_counts": dict(self.transform_counts),
            "verdict_counts": dict(self.verdict_counts),
            "stack_counts": dict(self.stack_counts),
            "sink_family_counts": dict(self.sink_family_counts),
            "class_transform_verdict_counts": [c.to_dict() for c in self.counts],
        }


def _transform_label(ops: Sequence[str]) -> str:
    """Human-readable key for a transform pipeline; `"raw"` for the empty
    pipeline (matching `schema.Pipeline`'s "empty means the raw/unmediated
    value")."""
    return ">".join(ops) or "raw"


def _cell_verdict(cell: Cell, matrix: Optional[SafetyMatrix]) -> str:
    if matrix is None:
        return UNDERIVABLE_VERDICT
    try:
        return derive_verdict(cell.transform, cell.sink_context, matrix).verdict
    except SafetyMatrixError:
        # An (op, sink_family) pair the matrix does not cover. `verdict()`
        # fails loud by design, and a *gate* should let that propagate -- but
        # this is an informative artifact, so it records the gap as a counted
        # UNDERIVABLE rather than taking a build down with it.
        return UNDERIVABLE_VERDICT


def diversity_report(cells: Sequence[Cell], matrix: Optional[SafetyMatrix] = None) -> DiversityReport:
    """Build the class × transform × verdict diversity artifact for `cells`.

    `matrix` is optional: without it every verdict is `UNDERIVABLE_VERDICT`
    and the class × transform half of the report is still fully usable. No
    matrix is loaded implicitly — a caller that wants verdicts passes the one
    its manifest's `safety_matrix_version` pins, so this function cannot
    silently report verdicts derived under a different matrix than the corpus
    was built with.
    """
    triples: Counter = Counter()
    class_counts: Counter = Counter()
    transform_counts: Counter = Counter()
    verdict_counts: Counter = Counter()
    stack_counts: Counter = Counter()
    sink_family_counts: Counter = Counter()
    n_underivable = 0

    for cell in cells:
        ops = tuple(cell.transform.ops)
        cell_verdict = _cell_verdict(cell, matrix)
        if cell_verdict == UNDERIVABLE_VERDICT:
            n_underivable += 1
        triples[(cell.vuln_class, ops, cell_verdict)] += 1
        class_counts[cell.vuln_class] += 1
        transform_counts[_transform_label(ops)] += 1
        verdict_counts[cell_verdict] += 1
        stack_counts[cell.stack_profile] += 1
        sink_family_counts[cell.sink_context.family] += 1

    counts = tuple(
        DiversityCount(vuln_class=cls, transform_shape=ops, verdict=v, count=n)
        for (cls, ops, v), n in sorted(triples.items())
    )
    return DiversityReport(
        n_cells=len(cells),
        counts=counts,
        class_counts=dict(sorted(class_counts.items())),
        transform_counts=dict(sorted(transform_counts.items())),
        verdict_counts=dict(sorted(verdict_counts.items())),
        stack_counts=dict(sorted(stack_counts.items())),
        sink_family_counts=dict(sorted(sink_family_counts.items())),
        n_underivable_verdicts=n_underivable,
        safety_matrix_version=None if matrix is None else matrix.version,
    )


# --- (1) Stratified, rule-grouped split -------------------------------------


@dataclasses.dataclass(frozen=True)
class CorpusSplit:
    """One train/holdout split, grouped by generating-rule ID."""

    train_cell_ids: tuple[str, ...]
    holdout_cell_ids: tuple[str, ...]
    train_rule_ids: tuple[str, ...]
    holdout_rule_ids: tuple[str, ...]
    n_splits: int
    fold: int
    random_state: int
    #: Class -> count, per side; recorded so a caller can see how well the
    #: stratification actually held for a small corpus (StratifiedGroupKFold
    #: balances classes only as far as the group structure allows).
    train_class_counts: Mapping[str, int]
    holdout_class_counts: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_splits": self.n_splits,
            "fold": self.fold,
            "random_state": self.random_state,
            "train_cell_ids": list(self.train_cell_ids),
            "holdout_cell_ids": list(self.holdout_cell_ids),
            "train_rule_ids": list(self.train_rule_ids),
            "holdout_rule_ids": list(self.holdout_rule_ids),
            "train_class_counts": dict(self.train_class_counts),
            "holdout_class_counts": dict(self.holdout_class_counts),
        }


def stratified_split(
    cells: Sequence[Cell],
    *,
    n_splits: int = 5,
    fold: int = 0,
    random_state: int = 0,
) -> CorpusSplit:
    """Split `cells` into train/holdout, stratified by `vuln_class` and
    **grouped by generating-rule ID**, so no near-duplicate cell pair spans
    the split (§2.4).

    Uses `leakage_probe.grouped_cv` — the same `StratifiedGroupKFold`
    construction the leakage probe already uses — rather than a second,
    independently-derived grouping strategy. `fold` selects which of the
    `n_splits` folds becomes the holdout side (so the whole set of folds is
    reachable, e.g. for k-fold cross-validation, not just one 1/k holdout).

    Raises `CorpusSplitError` for a corpus that cannot be split as asked, and
    `MissingSplitDependencyError` when scikit-learn is absent. Never returns a
    split whose two sides share a generating-rule group — that post-condition
    is re-checked and raised on, rather than trusted.
    """
    try:
        from .leakage_probe import grouped_cv
    except ImportError as exc:  # pragma: no cover - only when sklearn is absent
        raise MissingSplitDependencyError(
            "scikit-learn is required for the rule-grouped stratified split "
            "(declared in the 'labgen' optional dependency group; see pyproject.toml). "
            "Install it with `pip install fuzzlab[labgen]` or `pip install scikit-learn`. "
            "The de-duplication and diversity reports in this module do not need it."
        ) from exc

    if n_splits < 2:
        raise CorpusSplitError(f"n_splits must be >= 2, got {n_splits}")
    if not 0 <= fold < n_splits:
        raise CorpusSplitError(f"fold must be in [0, {n_splits}), got {fold}")

    labels = [cell.vuln_class for cell in cells]
    rule_ids = [generating_rule_id(cell) for cell in cells]
    distinct_classes = sorted(set(labels))
    distinct_rules = sorted(set(rule_ids))

    if len(distinct_classes) < 2:
        raise CorpusSplitError(
            "a stratified split needs at least two distinct vuln_class values, got "
            f"{distinct_classes}"
        )
    if n_splits > len(distinct_rules):
        raise CorpusSplitError(
            f"n_splits ({n_splits}) exceeds the number of distinct generating-rule groups "
            f"({len(distinct_rules)}); reduce n_splits or author more distinct cell shapes "
            "(the split groups by generating-rule ID, so it cannot make more folds than "
            "there are groups)"
        )

    cv = grouped_cv(n_splits=n_splits, random_state=random_state)
    # StratifiedGroupKFold only needs `X`'s row count, never its values.
    x_placeholder = [[0]] * len(cells)
    splits = list(cv.split(x_placeholder, labels, groups=rule_ids))
    train_index, holdout_index = splits[fold]

    train = [cells[i] for i in train_index]
    holdout = [cells[i] for i in holdout_index]
    train_rules = {generating_rule_id(c) for c in train}
    holdout_rules = {generating_rule_id(c) for c in holdout}

    overlap = train_rules & holdout_rules
    if overlap:  # pragma: no cover - would be an sklearn contract violation
        raise CorpusSplitError(
            "generating-rule group(s) landed on BOTH sides of the split, which would let "
            f"near-duplicate cells leak across it: {sorted(overlap)}"
        )

    return CorpusSplit(
        train_cell_ids=tuple(c.cell_id for c in train),
        holdout_cell_ids=tuple(c.cell_id for c in holdout),
        train_rule_ids=tuple(sorted(train_rules)),
        holdout_rule_ids=tuple(sorted(holdout_rules)),
        n_splits=n_splits,
        fold=fold,
        random_state=random_state,
        train_class_counts=dict(sorted(Counter(c.vuln_class for c in train).items())),
        holdout_class_counts=dict(sorted(Counter(c.vuln_class for c in holdout).items())),
    )


# --- The bundled build artifact ---------------------------------------------


@dataclasses.dataclass(frozen=True)
class CorpusReport:
    """The one artifact a build writes: de-duplication rate + diversity
    cross-tab. Informative only; `corpus_report` raises nothing about the
    corpus's shape."""

    duplication: DuplicationReport
    diversity: DiversityReport
    n_generating_rules: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "gating": self.diversity.gating,
            "n_generating_rules": self.n_generating_rules,
            "duplication": self.duplication.to_dict(),
            "diversity": self.diversity.to_dict(),
        }


def corpus_report(cells: Sequence[Cell], matrix: Optional[SafetyMatrix] = None) -> CorpusReport:
    """Build the bundled corpus-analysis artifact for `cells`."""
    return CorpusReport(
        duplication=duplication_report(cells),
        diversity=diversity_report(cells, matrix),
        n_generating_rules=len(group_cells_by_rule(cells)),
    )


def write_corpus_report(path: str | Path, report: CorpusReport) -> Path:
    """Write `report` as pretty-printed, key-sorted JSON (deterministic, so
    the artifact itself is diffable and cannot break
    NFR-LAB-reproducible). Creates parent directories. Returns the path
    written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
    return path
