"""Metadata leakage probe (T-LAB0.11 reference implementation).

Detects whether a generated corpus's *non-payload* metadata (status code,
response length, header count, latency, parameter-name length, path depth,
content-type) statistically leaks the vulnerability label — i.e. whether a
classifier could cheat by learning superficial fingerprints of a generating
rule instead of the actual vulnerability signal the tool under test is
supposed to detect.

This is a **reference implementation**, not a build-gating step. Per
`docs/LAB_PHASE_0_PLAN.md` T-LAB0.11: "Full build-gating only starts in
Phase 1 once real variation exists." Nothing in this module raises or exits
a build; it returns a `LeakageResult` for callers (tests, future gates,
reports) to interpret.

Design (settled, from the plan):

1. A **closed feature allowlist** (`FEATURE_ALLOWLIST`) — never anything
   payload- or body-derived. `probe_leakage` raises `ValueError` if any cell
   carries a feature key outside this allowlist, so a future caller cannot
   silently smuggle a payload-derived signal in.
2. `scikit-learn` `LogisticRegression` + `StandardScaler` (numeric features)
   / `OneHotEncoder` (the one categorical feature, `content_type`) —
   deliberately weak: a stronger model would find faint signals a real
   detector would never exploit.
3. `StratifiedGroupKFold`, grouped by **generating-rule ID** — never a
   random split. Near-duplicate cells from the same generating rule must
   land on the same side of the split, or the leakage score inflates.
4. A **permutation-null threshold**: shuffle the labels ~200 times, take the
   99th percentile of the resulting cross-validated-AUC distribution as the
   pass/fail line — not a fixed constant, since the "chance" AUC depends on
   the corpus's own group/class structure.
5. **Per-class feature exclusions** (`PER_CLASS_FEATURE_EXCLUSIONS`) for
   legitimate metadata signal — e.g. `latency_ms` is excluded when a
   time-based-blind-SQLi or race-condition class is present in the corpus,
   because timing *is* the vulnerability there, not a fingerprint leak.
   Each exclusion carries a written one-line justification, and every probe
   result reports the total exclusion count, so this mechanism cannot be
   used to quietly make a red build green.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

try:
    from sklearn.compose import ColumnTransformer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
except ImportError as exc:  # pragma: no cover - exercised only when sklearn is absent
    raise ImportError(
        "fuzzlab.labgen.leakage_probe requires scikit-learn (declared in the "
        "'labgen' optional dependency group; see pyproject.toml). Install it with "
        "`pip install fuzzlab[labgen]` or `pip install scikit-learn`."
    ) from exc


# --- Feature allowlist (closed; PA-0005-style: only these names are ever read) ---

#: The only metadata fields the probe is permitted to look at. Never a
#: payload- or response-body-derived field. Adding a new field here is a
#: deliberate scope change to the leakage-probe design and should update
#: `docs/components/01-target-lab/requirements.md` (FR-LAB-8) accordingly.
FEATURE_ALLOWLIST: tuple[str, ...] = (
    "status_code",
    "response_length",
    "header_count",
    "latency_ms",
    "param_name_length",
    "path_depth",
    "content_type",
)

#: The one categorical feature; everything else in the allowlist is numeric.
_CATEGORICAL_FEATURES = ("content_type",)
_NUMERIC_FEATURES = tuple(f for f in FEATURE_ALLOWLIST if f not in _CATEGORICAL_FEATURES)

#: Per-class feature exclusions: vulnerability-class label -> {feature: one-line
#: justification}. Applied only when a cell of that class is present in the
#: corpus being probed. This is an *exclusion of a feature from consideration*,
#: never a per-class threshold change — a per-class threshold would just
#: disable the gate for that class, which is exactly the loophole this
#: mechanism must not become (see module docstring, point 5).
PER_CLASS_FEATURE_EXCLUSIONS: dict[str, dict[str, str]] = {
    "sqli_blind_time": {
        "latency_ms": (
            "Time-based blind SQLi is detected by response latency; latency IS the "
            "vulnerability signal for this class, not a superficial fingerprint."
        ),
    },
    "race_condition": {
        "latency_ms": (
            "Race-condition classes are distinguished by timing/response-window "
            "behavior; latency IS the vulnerability signal for this class."
        ),
    },
}


@dataclass(frozen=True)
class LeakageResult:
    """Outcome of one leakage-probe run against a corpus."""

    #: Cross-validated AUC of the (weak) classifier predicting the label from
    #: the allowed metadata features alone.
    observed_auc: float
    #: The 99th-percentile (by default) AUC from the label-permutation null
    #: distribution. The pass/fail line.
    null_threshold: float
    #: Full null-distribution AUC samples, for inspection/plotting.
    null_distribution: tuple[float, ...]
    #: True if observed_auc exceeds null_threshold — i.e. metadata leaks the
    #: label above what chance/group-structure alone would produce.
    leaks: bool
    #: Feature names actually used for this run (allowlist minus exclusions).
    features_used: tuple[str, ...]
    #: (class_label, feature, justification) tuples actually applied for this
    #: run, because that class was present in the corpus.
    exclusions_applied: tuple[tuple[str, str, str], ...]
    #: len(exclusions_applied) — reported explicitly so the mechanism's use is
    #: always visible, never silently used to inflate the pass rate.
    exclusion_count: int
    n_samples: int
    n_groups: int
    n_classes: int
    n_splits: int
    n_permutations: int
    null_percentile: float


def _validate_cells(cells: Sequence[Mapping[str, Any]], label_key: str, group_key: str) -> None:
    if not cells:
        raise ValueError("probe_leakage requires at least one cell")
    for i, cell in enumerate(cells):
        if label_key not in cell:
            raise ValueError(f"cell {i} is missing label key '{label_key}'")
        if group_key not in cell:
            raise ValueError(f"cell {i} is missing group key '{group_key}' (generating-rule ID)")
        features = cell.get("features")
        if not isinstance(features, Mapping):
            raise ValueError(f"cell {i} must carry a 'features' mapping")
        unknown = set(features) - set(FEATURE_ALLOWLIST)
        if unknown:
            raise ValueError(
                f"cell {i} has feature(s) outside the closed allowlist: {sorted(unknown)} "
                f"(allowed: {FEATURE_ALLOWLIST}); the leakage probe must never see "
                "payload- or body-derived fields"
            )


def _resolve_exclusions(labels: Sequence[str]) -> tuple[tuple[str, ...], tuple[tuple[str, str, str], ...]]:
    """Return (features_used, exclusions_applied) for the classes present."""
    present = set(labels)
    exclusions_applied: list[tuple[str, str, str]] = []
    excluded_features: set[str] = set()
    for cls in sorted(present):
        for feature, justification in PER_CLASS_FEATURE_EXCLUSIONS.get(cls, {}).items():
            excluded_features.add(feature)
            exclusions_applied.append((cls, feature, justification))
    features_used = tuple(f for f in FEATURE_ALLOWLIST if f not in excluded_features)
    return features_used, tuple(exclusions_applied)


def _build_pipeline(features_used: Sequence[str], random_state: int) -> Pipeline:
    # ColumnTransformer selects by position (not name) because the feature
    # matrix is a plain numpy object array, not a DataFrame; positions must
    # match the column order `_feature_matrix` produces for `features_used`.
    numeric = [i for i, f in enumerate(features_used) if f in _NUMERIC_FEATURES]
    categorical = [i for i, f in enumerate(features_used) if f in _CATEGORICAL_FEATURES]
    transformers = []
    if numeric:
        transformers.append(("num", StandardScaler(), numeric))
    if categorical:
        transformers.append(("cat", OneHotEncoder(handle_unknown="ignore"), categorical))
    preprocessor = ColumnTransformer(transformers=transformers)
    # Deliberately weak model: plain L2-regularized logistic regression. A
    # stronger model (gradient boosting, deep net, etc.) would find faint
    # signals a real vulnerability-detection tool would never exploit, which
    # would make the probe over-sensitive and useless as a sanity check.
    clf = LogisticRegression(max_iter=1000, random_state=random_state)
    return Pipeline([("preprocess", preprocessor), ("clf", clf)])


def _feature_matrix(cells: Sequence[Mapping[str, Any]], features_used: Sequence[str]) -> np.ndarray:
    # Build a plain object array (mixed numeric/categorical); the pipeline's
    # ColumnTransformer selects columns by position, matching features_used order.
    rows = []
    for cell in cells:
        feats = cell["features"]
        rows.append([feats.get(f) for f in features_used])
    return np.array(rows, dtype=object)


def _auc_from_proba(y: np.ndarray, proba: np.ndarray, classes: np.ndarray) -> float:
    if len(classes) == 2:
        # roc_auc_score wants the score for the positive (second) class.
        pos_index = 1
        return float(roc_auc_score(y, proba[:, pos_index]))
    return float(roc_auc_score(y, proba, multi_class="ovr", average="macro", labels=classes))


def _cross_val_auc(
    X: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray,
    features_used: Sequence[str],
    n_splits: int,
    random_state: int,
) -> float:
    classes = np.unique(y)
    pipeline = _build_pipeline(features_used, random_state)
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    with warnings.catch_warnings():
        # Small synthetic/fixture corpora can trigger benign convergence or
        # class-imbalance warnings from sklearn; they don't affect the AUC
        # computation and would otherwise be noisy in test output.
        warnings.simplefilter("ignore")
        proba = cross_val_predict(
            pipeline, X, y, cv=cv, groups=groups, method="predict_proba"
        )
    return _auc_from_proba(y, proba, classes)


def probe_leakage(
    cells: Iterable[Mapping[str, Any]],
    *,
    label_key: str = "label",
    group_key: str = "rule_id",
    n_splits: int = 5,
    n_permutations: int = 200,
    null_percentile: float = 99.0,
    random_state: int = 0,
) -> LeakageResult:
    """Run the metadata leakage probe against a corpus of cells.

    Each cell is a mapping with:
      - `label_key` (default "label"): the vulnerability-label ground truth.
      - `group_key` (default "rule_id"): the generating-rule ID (grouping key
        for `StratifiedGroupKFold` — near-duplicate cells from the same rule
        never split across train/test).
      - "features": a mapping restricted to `FEATURE_ALLOWLIST` keys.

    Returns a `LeakageResult`. This function never raises on a "leaky"
    result — `leaks=True` is data for the caller to act on, not an error.
    It *does* raise `ValueError` on malformed input (missing keys, or a
    feature key outside the closed allowlist).
    """
    cells = list(cells)
    _validate_cells(cells, label_key, group_key)

    labels_raw = [cell[label_key] for cell in cells]
    groups_raw = [cell[group_key] for cell in cells]
    y = np.array(labels_raw)
    groups = np.array(groups_raw)

    n_classes = len(np.unique(y))
    n_groups = len(np.unique(groups))
    if n_classes < 2:
        raise ValueError("probe_leakage requires at least two distinct label classes")
    if n_splits > n_groups:
        raise ValueError(
            f"n_splits ({n_splits}) exceeds the number of distinct generating-rule "
            f"groups ({n_groups}); reduce n_splits or provide more grouped data"
        )

    features_used, exclusions_applied = _resolve_exclusions(labels_raw)
    if not features_used:
        raise ValueError(
            "all allowlisted features were excluded for the classes present; "
            "the probe would have nothing left to evaluate"
        )

    X = _feature_matrix(cells, features_used)

    observed_auc = _cross_val_auc(X, y, groups, features_used, n_splits, random_state)

    rng = np.random.default_rng(random_state)
    null_samples = []
    for _ in range(n_permutations):
        y_shuffled = rng.permutation(y)
        # A permutation can (rarely) collapse a fold to a single class for tiny
        # fixtures; skip and resample rather than let cross_val_predict raise.
        if len(np.unique(y_shuffled)) < 2:
            continue
        try:
            auc = _cross_val_auc(X, y_shuffled, groups, features_used, n_splits, random_state)
        except ValueError:
            continue
        null_samples.append(auc)

    if not null_samples:
        raise RuntimeError(
            "no valid permutation samples were produced; corpus is too small/degenerate "
            "for the requested n_splits/n_permutations"
        )

    null_threshold = float(np.percentile(null_samples, null_percentile))
    leaks = observed_auc > null_threshold

    return LeakageResult(
        observed_auc=observed_auc,
        null_threshold=null_threshold,
        null_distribution=tuple(null_samples),
        leaks=leaks,
        features_used=features_used,
        exclusions_applied=exclusions_applied,
        exclusion_count=len(exclusions_applied),
        n_samples=len(cells),
        n_groups=n_groups,
        n_classes=n_classes,
        n_splits=n_splits,
        n_permutations=len(null_samples),
        null_percentile=null_percentile,
    )
