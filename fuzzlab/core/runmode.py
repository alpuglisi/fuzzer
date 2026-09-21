"""Run-mode category selection and the no-ground-truth fail-safe (D14 / D15).

Decides which injection categories a run tests, and whether it is scored, from the
launcher run mode and whether the target has ground truth:

- **automatic + ground truth** (our lab): categories auto-derived from the ground
  truth; scored (a detection benchmark). (D14)
- **automatic + no ground truth** (validation lab / unknown target): requires an
  explicit selection, else **fails loudly**; unscored. (D15 fail-safe)
- **manual**: the user selects; unselected defaults to all known categories;
  unscored. (D14)

Pure and dependency-light: callers pass the ground-truth categories and the set of
known categories in (the harness/audit layer provides them), so this never inverts
the layering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

AUTOMATIC = "automatic"
MANUAL = "manual"

# Ground-truth vuln_class values normalized to reference-style category slugs.
_VULN_TO_CATEGORY = {
    "sqli": "sql-injection",
    "xss-reflected": "xss",
    "xss-stored": "xss",
    "xss-dom": "xss",
}


class RunModeError(RuntimeError):
    """Fail-loud: an invalid or unsafe run-mode/category selection."""


@dataclass
class RunPlan:
    mode: str
    categories: list[str]
    scored: bool
    source: str            # 'ground-truth' | 'user' | 'default'


def to_category(vuln_class: str) -> str:
    return _VULN_TO_CATEGORY.get(vuln_class, vuln_class)


def categories_from_vuln_classes(vuln_classes: Iterable[str]) -> list[str]:
    """Normalize ground-truth vuln classes to a sorted category set (excl. 'none')."""
    return sorted({to_category(v) for v in vuln_classes if v and v != "none"})


def resolve_run(mode: str, *, ground_truth_categories: list[str] | None = None,
                selected_categories: Iterable[str] | None = None,
                all_categories: Iterable[str] | None = None) -> RunPlan:
    """Resolve the active categories + scoring for a run, enforcing D14/D15."""
    selected = list(selected_categories) if selected_categories else []
    known = set(all_categories) if all_categories is not None else None
    if known is not None and selected:
        unknown = [c for c in selected if c not in known]
        if unknown:
            raise RunModeError(f"unknown categor(y/ies): {unknown}; known: {sorted(known)}")

    if mode == AUTOMATIC:
        if ground_truth_categories is not None:
            # D14: auto-derive from the lab's ground truth; scored benchmark.
            return RunPlan(AUTOMATIC, list(ground_truth_categories), True, "ground-truth")
        # D15 fail-safe: no ground truth -> must be explicit, else fail loud; unscored.
        if not selected:
            raise RunModeError(
                "automatic run against a target with no ground truth requires an "
                "explicit category selection (fail-safe); pass --categories")
        return RunPlan(AUTOMATIC, selected, False, "user")

    if mode == MANUAL:
        if selected:
            return RunPlan(MANUAL, selected, False, "user")
        return RunPlan(MANUAL, sorted(known) if known else [], False, "default")

    raise RunModeError(f"unknown run mode {mode!r}")
