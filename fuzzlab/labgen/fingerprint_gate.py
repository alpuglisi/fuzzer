"""Fingerprint-independence build gate (`CR-LAB-0001` §3).

Once the generator goes multi-stack (Phase 3), a corpus whose *shape* lets a
stack fingerprint (`Server: Werkzeug`, a framework's default error page, …)
predict the vulnerability class is a leakage risk independent of any single
cell's content: a detector could learn "every Flask cell is SSTI" instead of
the real signal, exactly the failure mode `CR-LAB-0001` §3 names. This is a
**mandatory build gate**, not the (explicitly non-gating) leakage-probe
reference implementation (`leakage_probe.py`, owned by another lane) — this
module checks the corpus's aggregate *metadata shape*, not any one cell's
source text.

Deliberately schema-independent: a "corpus record" is a plain mapping with a
`stack`, a `vuln_class`, and (optionally) a `verdict` key — never a
`fuzzlab.labgen.schema.Manifest`/`Cell` object, so this gate can run against
a metadata export, a test fixture, or a future manifest without this module
depending on that schema's shape (or that schema depending on this one).

Two independent checks, both able to fail loud with a typed error naming
exactly what fell short:

1. **Coverage checks** (`check_min_stacks_per_class`/`check_min_classes_per_stack`):
   every vulnerability class must appear on at least `min_stacks_per_class`
   distinct stacks, and every stack must carry at least `min_classes_per_stack`
   distinct classes. This is the cheap, deterministic half — no stack should
   be a de facto proxy for one class (or vice versa) just because the corpus
   never gave it a chance to co-occur with anything else.
2. **Statistical independence** (`check_stack_class_independence`/
   `check_stack_verdict_independence`): a chi-square test of independence
   (`scipy.stats.chi2_contingency`) between `stack` and `vuln_class` (and
   separately `stack` and `verdict`). A low p-value rejects the null
   hypothesis that the two are independent — i.e. the corpus's stack
   composition and its class/verdict composition are statistically
   entangled, the same risk the coverage checks catch structurally but
   phrased as a quantitative significance test rather than a raw count.

`run_fingerprint_gate` runs all four and raises one `FingerprintIndependenceError`
naming every violation found (not just the first), or returns a
`FingerprintGateReport` with the computed statistics when everything passes.
"""

from __future__ import annotations

import dataclasses
from collections import defaultdict
from typing import Mapping, Optional, Sequence

__all__ = [
    "FingerprintIndependenceError",
    "MissingStatsDependencyError",
    "ChiSquareResult",
    "FingerprintGateReport",
    "check_min_stacks_per_class",
    "check_min_classes_per_stack",
    "chi_square_independence",
    "check_stack_class_independence",
    "check_stack_verdict_independence",
    "run_fingerprint_gate",
]

CorpusRecord = Mapping[str, str]


class FingerprintIndependenceError(RuntimeError):
    """Raised when a corpus's metadata shape would let a classifier learn a
    stack fingerprint instead of the real vulnerability signal (`CR-LAB-0001`
    §3) — insufficient stack/class coverage, or a statistically significant
    stack↔class or stack↔verdict dependency."""


class MissingStatsDependencyError(RuntimeError):
    """Raised instead of letting a raw `ImportError` propagate when `scipy`
    (the `labgen-stats` extra) isn't installed (BUG-0007/PA-0021's pattern:
    a validation boundary raises a typed error for every foreseeable failure,
    including a missing optional dependency, not just a missing binary)."""


@dataclasses.dataclass(frozen=True)
class ChiSquareResult:
    """One `scipy.stats.chi2_contingency` result, kept for inspection/reporting
    regardless of whether it was significant."""

    row_key: str
    col_key: str
    rows: Sequence[str]
    cols: Sequence[str]
    observed: Sequence[Sequence[int]]
    expected: Sequence[Sequence[float]]
    statistic: float
    p_value: float
    dof: int

    @property
    def independent_at(self) -> float:
        """The largest alpha at which independence would still be rejected
        (i.e. `p_value` itself) — a convenience alias for readability at call
        sites that just want to log/compare it."""
        return self.p_value


@dataclasses.dataclass(frozen=True)
class FingerprintGateReport:
    """Returned by `run_fingerprint_gate` only when every check passes."""

    stacks: Sequence[str]
    classes: Sequence[str]
    chi2_stack_class: ChiSquareResult
    chi2_stack_verdict: Optional[ChiSquareResult]


def _contingency_table(records: Sequence[CorpusRecord], row_key: str, col_key: str):
    rows = sorted({r[row_key] for r in records})
    cols = sorted({r[col_key] for r in records})
    row_index = {v: i for i, v in enumerate(rows)}
    col_index = {v: i for i, v in enumerate(cols)}
    table = [[0] * len(cols) for _ in rows]
    for r in records:
        table[row_index[r[row_key]]][col_index[r[col_key]]] += 1
    return rows, cols, table


def _stack_diversity_violations(
    records: Sequence[CorpusRecord],
    min_stacks_per_class: int,
    stack_key: str,
    class_key: str,
    expected_classes: Optional[Sequence[str]],
) -> list:
    stacks_by_class: dict = defaultdict(set)
    if expected_classes:
        for cls in expected_classes:
            stacks_by_class[cls]  # seed so a wholly-absent class still shows a 0-count shortfall
    for r in records:
        stacks_by_class[r[class_key]].add(r[stack_key])
    return [
        f"vuln_class {cls!r} appears on only {len(stacks)} stack(s) {sorted(stacks)} "
        f"(need >= {min_stacks_per_class})"
        for cls, stacks in sorted(stacks_by_class.items())
        if len(stacks) < min_stacks_per_class
    ]


def _class_diversity_violations(
    records: Sequence[CorpusRecord],
    min_classes_per_stack: int,
    stack_key: str,
    class_key: str,
    expected_stacks: Optional[Sequence[str]],
) -> list:
    classes_by_stack: dict = defaultdict(set)
    if expected_stacks:
        for stack in expected_stacks:
            classes_by_stack[stack]
    for r in records:
        classes_by_stack[r[stack_key]].add(r[class_key])
    return [
        f"stack {stack!r} carries only {len(classes)} class(es) {sorted(classes)} "
        f"(need >= {min_classes_per_stack})"
        for stack, classes in sorted(classes_by_stack.items())
        if len(classes) < min_classes_per_stack
    ]


def check_min_stacks_per_class(
    records: Sequence[CorpusRecord],
    min_stacks_per_class: int = 2,
    stack_key: str = "stack",
    class_key: str = "vuln_class",
    expected_classes: Optional[Sequence[str]] = None,
) -> None:
    """Raise `FingerprintIndependenceError` naming every vulnerability class
    that appears on fewer than `min_stacks_per_class` distinct stacks. Pass
    `expected_classes` to also fail loud on a class that is wholly absent
    from `records` (0 stacks), rather than silently not checking it. The
    default of 2 is `CR-LAB-0001` §3/§4's own canonical value ("every class
    in >= 2 stacks")."""
    violations = _stack_diversity_violations(records, min_stacks_per_class, stack_key, class_key, expected_classes)
    if violations:
        raise FingerprintIndependenceError(
            "insufficient stack diversity per vulnerability class:\n  - " + "\n  - ".join(violations)
        )


def check_min_classes_per_stack(
    records: Sequence[CorpusRecord],
    min_classes_per_stack: int = 3,
    stack_key: str = "stack",
    class_key: str = "vuln_class",
    expected_stacks: Optional[Sequence[str]] = None,
) -> None:
    """Raise `FingerprintIndependenceError` naming every stack that carries
    fewer than `min_classes_per_stack` distinct vulnerability classes. The
    default of 3 is `CR-LAB-0001` §3/§4's own canonical value ("every stack
    carries >= 3 classes")."""
    violations = _class_diversity_violations(records, min_classes_per_stack, stack_key, class_key, expected_stacks)
    if violations:
        raise FingerprintIndependenceError(
            "insufficient vulnerability-class diversity per stack:\n  - " + "\n  - ".join(violations)
        )


def chi_square_independence(records: Sequence[CorpusRecord], row_key: str, col_key: str) -> ChiSquareResult:
    """Compute (never raises on the *statistical* result itself, only on a
    degenerate table or a missing `scipy`) a chi-square test of independence
    between `row_key` and `col_key` over `records`."""
    try:
        from scipy.stats import chi2_contingency
    except ImportError as exc:
        raise MissingStatsDependencyError(
            "scipy is required for the fingerprint-independence chi-square check "
            "but is not installed. Install the `labgen-stats` extra "
            "(`pip install fuzzlab[labgen-stats]`) or `pip install scipy`."
        ) from exc

    rows, cols, table = _contingency_table(records, row_key, col_key)
    if len(rows) < 2 or len(cols) < 2:
        raise FingerprintIndependenceError(
            f"cannot test independence of {row_key!r} and {col_key!r}: need at least 2 "
            f"distinct values for each, got {len(rows)} {row_key}(s) {rows} and "
            f"{len(cols)} {col_key}(s) {cols}"
        )
    try:
        statistic, p_value, dof, expected = chi2_contingency(table)
    except ValueError as exc:
        # scipy raises ValueError for a table with an all-zero row/column
        # (e.g. a stack or class present in `rows`/`cols` but never actually
        # co-occurring with anything, or an internal frequency of exactly 0
        # that a strict expected-frequency check flags) -- a degenerate
        # table is itself evidence of a fingerprint-independence problem,
        # not a code defect, so this becomes a `FingerprintIndependenceError`
        # (fail loud) rather than letting the raw `ValueError` propagate.
        raise FingerprintIndependenceError(
            f"cannot test independence of {row_key!r} and {col_key!r}: the contingency "
            f"table is degenerate (a value never co-occurs with anything) -- {exc}"
        ) from exc
    return ChiSquareResult(
        row_key=row_key,
        col_key=col_key,
        rows=rows,
        cols=cols,
        observed=table,
        expected=[list(row) for row in expected],
        statistic=float(statistic),
        p_value=float(p_value),
        dof=int(dof),
    )


def check_stack_class_independence(
    records: Sequence[CorpusRecord],
    alpha: float = 0.05,
    stack_key: str = "stack",
    class_key: str = "vuln_class",
) -> ChiSquareResult:
    """Raise `FingerprintIndependenceError` if `stack` and `vuln_class` are
    NOT independent at significance level `alpha` (p_value < alpha); returns
    the `ChiSquareResult` when they are independent (the gate passes)."""
    result = chi_square_independence(records, stack_key, class_key)
    if result.p_value < alpha:
        raise FingerprintIndependenceError(
            f"stack and vulnerability class are NOT independent "
            f"(chi2={result.statistic:.3f}, dof={result.dof}, p={result.p_value:.4g} < "
            f"alpha={alpha}) -- this corpus's shape would let a classifier learn 'which "
            f"stack' instead of 'is this vulnerable'. stacks={result.rows}, "
            f"classes={result.cols}, observed={result.observed}"
        )
    return result


def check_stack_verdict_independence(
    records: Sequence[CorpusRecord],
    alpha: float = 0.05,
    stack_key: str = "stack",
    verdict_key: str = "verdict",
) -> ChiSquareResult:
    """Same as `check_stack_class_independence`, for `stack` vs. `verdict`
    (D20's binary VULNERABLE/SECURE) — a stack that is disproportionately
    vulnerable or secure is the same leakage risk one level removed."""
    result = chi_square_independence(records, stack_key, verdict_key)
    if result.p_value < alpha:
        raise FingerprintIndependenceError(
            f"stack and verdict are NOT independent "
            f"(chi2={result.statistic:.3f}, dof={result.dof}, p={result.p_value:.4g} < "
            f"alpha={alpha}) -- a classifier could learn 'which stack' instead of 'is "
            f"this vulnerable'. stacks={result.rows}, verdicts={result.cols}, "
            f"observed={result.observed}"
        )
    return result


def run_fingerprint_gate(
    records: Sequence[CorpusRecord],
    min_stacks_per_class: int = 2,
    min_classes_per_stack: int = 3,
    alpha: float = 0.05,
    stack_key: str = "stack",
    class_key: str = "vuln_class",
    verdict_key: str = "verdict",
    check_verdict_independence: bool = True,
    expected_classes: Optional[Sequence[str]] = None,
    expected_stacks: Optional[Sequence[str]] = None,
) -> FingerprintGateReport:
    """Run every fingerprint-independence check and raise ONE
    `FingerprintIndependenceError` listing every violation found (not just
    the first), or return a `FingerprintGateReport` when the corpus passes
    all of them. This is the one entry point meant to be wired as a build
    gate once a real multi-stack corpus exists (Phase 3) -- not yet done
    here, since there isn't one to run it against.
    """
    if not records:
        raise FingerprintIndependenceError("cannot run the fingerprint gate on an empty corpus")

    violations = []
    violations += _stack_diversity_violations(records, min_stacks_per_class, stack_key, class_key, expected_classes)
    violations += _class_diversity_violations(records, min_classes_per_stack, stack_key, class_key, expected_stacks)

    chi2_stack_class: Optional[ChiSquareResult] = None
    try:
        chi2_stack_class = chi_square_independence(records, stack_key, class_key)
        if chi2_stack_class.p_value < alpha:
            violations.append(
                f"stack and vuln_class are NOT independent (chi2={chi2_stack_class.statistic:.3f}, "
                f"dof={chi2_stack_class.dof}, p={chi2_stack_class.p_value:.4g} < alpha={alpha})"
            )
    except FingerprintIndependenceError as exc:
        violations.append(str(exc))

    chi2_stack_verdict: Optional[ChiSquareResult] = None
    if check_verdict_independence and all(verdict_key in r for r in records):
        try:
            chi2_stack_verdict = chi_square_independence(records, stack_key, verdict_key)
            if chi2_stack_verdict.p_value < alpha:
                violations.append(
                    f"stack and verdict are NOT independent (chi2={chi2_stack_verdict.statistic:.3f}, "
                    f"dof={chi2_stack_verdict.dof}, p={chi2_stack_verdict.p_value:.4g} < alpha={alpha})"
                )
        except FingerprintIndependenceError as exc:
            violations.append(str(exc))

    if violations:
        raise FingerprintIndependenceError(
            f"fingerprint-independence gate failed with {len(violations)} violation(s):\n  - "
            + "\n  - ".join(violations)
        )

    assert chi2_stack_class is not None  # guaranteed: no violations means it computed cleanly
    return FingerprintGateReport(
        stacks=chi2_stack_class.rows,
        classes=chi2_stack_class.cols,
        chi2_stack_class=chi2_stack_class,
        chi2_stack_verdict=chi2_stack_verdict,
    )
