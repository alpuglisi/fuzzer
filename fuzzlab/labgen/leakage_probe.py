"""Metadata leakage probe (T-LAB0.11) — reference mechanism **and** build gate.

Detects whether a generated corpus's *non-payload* metadata (status code,
response length, header count, latency, parameter-name length, path depth,
content-type) statistically leaks the vulnerability label — i.e. whether a
classifier could cheat by learning superficial fingerprints of a generating
rule instead of the actual vulnerability signal the tool under test is
supposed to detect.

`probe_leakage` itself is still the pure **measurement** entry point: it never
raises on a leaky result, it returns a `LeakageResult` for callers (tests,
gates, reports) to interpret. What changed in Phase 1 (lane L-P1.3,
`docs/LAB_IMPLEMENTATION_PLAN.md` §2.3) is that a *gate* wrapper now sits on
top of it — :func:`run_leakage_gate`, which raises
:class:`MetadataLeakageError` — and that wrapper is wired into
``fuzzlab lab-generate --check`` as a required step, alongside
`fingerprint_gate.py`. `docs/LAB_PHASE_0_PLAN.md` T-LAB0.11's "full
build-gating only starts in Phase 1 once real variation exists" is that
condition being met, not a change of design.

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
6. **Per-class AUC thresholds** (`PER_CLASS_AUC_THRESHOLDS`), the decision
   `docs/LAB_IMPLEMENTATION_PLAN.md` §2.3 settled on 2026-09-21: per-class
   thresholds rather than one global 0.55-0.60 band, extending the existing
   per-generating-rule grouping (point 3) rather than adding new machinery.

   Point 5 above warns that a per-class *threshold* would be a loophole —
   "a per-class threshold would just disable the gate for that class". That
   warning is honored, not overridden, by making the override **one-directional
   and fail-closed**: a class's effective pass line is
   ``min(per-class permutation-null percentile, configured per-class
   threshold)``, so a configured number can only ever make the gate
   **stricter** for that class, never looser. Raising a class's configured
   threshold above its own permutation null has no effect at all; there is
   therefore no way to use this dict to turn a red class green, which is
   exactly the property point 5 asks for.

   Every configured threshold carries a `status` of `"provisional"` or
   `"calibrated"` (`THRESHOLD_STATUSES`) plus a written justification. Phase 1
   is the *first* point real corpus data exists to calibrate against, so every
   value currently shipped is `"provisional"`, seeded from the report's
   0.55-0.60 band; `format_leakage_report` prints each class's status so a
   future pass can tell at a glance which numbers still need revisiting
   against a properly-sized permutation-null distribution. Nothing here is
   claimed as calibrated until a class's number has actually been derived from
   one.
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
#: distinct from `PER_CLASS_AUC_THRESHOLDS` (docstring point 6): a per-class
#: threshold must never be usable to *disable* the gate for a class, which is
#: why that dict is applied fail-closed (strictest-of-two) rather than as a
#: replacement pass line. See module docstring, points 5 and 6.
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


#: The two allowed `ClassThreshold.status` values. `"provisional"` means the
#: number was seeded from the report's 0.55-0.60 band (or from judgement) and
#: has NOT been derived from a properly-sized permutation-null distribution;
#: `"calibrated"` means it has. Every value shipped today is provisional --
#: Phase 1 is the first point real corpus data exists at all (plan §2.3).
THRESHOLD_STATUSES: tuple[str, ...] = ("provisional", "calibrated")

#: The band `docs/LAB_IMPLEMENTATION_PLAN.md` §2.3 names as the starting point
#: for every per-class threshold ("set from the report's 0.55-0.60 band as a
#: starting point per class"). Held as a constant so the provisional values
#: below can be asserted to lie inside it rather than being loose literals
#: (PA-0001: derive the expectation from the source of truth).
PROVISIONAL_THRESHOLD_BAND: tuple[float, float] = (0.55, 0.60)


@dataclass(frozen=True)
class ClassThreshold:
    """One per-class absolute-AUC pass line, with its calibration provenance.

    `auc_threshold` is an *upper* line on that class's one-vs-rest AUC. It is
    never used on its own: the effective line for a class is
    ``min(auc_threshold, that class's permutation-null percentile)``, so a
    configured number can only tighten the gate (module docstring, point 6).
    """

    auc_threshold: float
    status: str
    justification: str

    def __post_init__(self) -> None:
        if self.status not in THRESHOLD_STATUSES:
            raise ValueError(
                f"ClassThreshold.status must be one of {THRESHOLD_STATUSES}, got {self.status!r}"
            )
        if not 0.5 <= self.auc_threshold <= 1.0:
            raise ValueError(
                f"ClassThreshold.auc_threshold must be in [0.5, 1.0] (an AUC below 0.5 is "
                f"worse than chance and would make the gate unsatisfiable), got "
                f"{self.auc_threshold}"
            )
        if not self.justification.strip():
            raise ValueError("ClassThreshold.justification must be a non-empty written line")


#: Per-class absolute-AUC thresholds (plan §2.3's settled decision). Keyed by
#: the same vulnerability-class label the corpus carries in `label_key`, so the
#: coarse manifest vocabulary (`sqli`/`xss`) and the finer-grained labels the
#: probe's own fixtures use (`sqli_error`, `sqli_blind_time`, ...) can both be
#: registered. Any class NOT listed falls back to `DEFAULT_CLASS_THRESHOLD`.
#:
#: **Every entry below is `provisional`.** They are seeded from
#: `PROVISIONAL_THRESHOLD_BAND` and must be revisited once Phase 1 produces
#: enough real cells per class to compute that class's permutation null
#: properly; `format_leakage_report` prints the status next to each number so
#: that revisit is discoverable from the gate's own output.
PER_CLASS_AUC_THRESHOLDS: dict[str, ClassThreshold] = {
    "sqli": ClassThreshold(
        auc_threshold=0.58,
        status="provisional",
        justification=(
            "Mid-band seed: SQLi is the corpus's densest class (most cells, most "
            "transforms), so its null is the best-estimated of any class and the "
            "mid-band value is the least arbitrary starting point."
        ),
    ),
    "xss": ClassThreshold(
        auc_threshold=0.58,
        status="provisional",
        justification=(
            "Mid-band seed, same reasoning as `sqli`: the other class the current "
            "corpus authors at comparable density."
        ),
    ),
    "sqli_error": ClassThreshold(
        auc_threshold=0.58,
        status="provisional",
        justification=(
            "Mid-band seed: the error-based SQLi refinement of `sqli`, which carries the "
            "same feature availability, so it takes the same starting number."
        ),
    ),
    "secure": ClassThreshold(
        auc_threshold=0.58,
        status="provisional",
        justification=(
            "Mid-band seed: the negative class. Registered explicitly rather than left on "
            "the default, because in a two-class corpus its one-vs-rest AUC is the mirror "
            "of the positive class's and must not be judged on a looser line than it."
        ),
    ),
    "sqli_blind_time": ClassThreshold(
        auc_threshold=0.60,
        status="provisional",
        justification=(
            "Top-of-band seed: this class's legitimate-signal feature (latency_ms) is "
            "excluded by PER_CLASS_FEATURE_EXCLUSIONS, leaving fewer features and a "
            "noisier AUC estimate, so the looser end of the band avoids a false red."
        ),
    ),
    "race_condition": ClassThreshold(
        auc_threshold=0.60,
        status="provisional",
        justification=(
            "Top-of-band seed, same reasoning as `sqli_blind_time`: latency_ms is "
            "excluded for this class, so its AUC estimate rests on fewer features."
        ),
    ),
}

#: The fallback for a class with no entry in `PER_CLASS_AUC_THRESHOLDS`. The
#: loose end of the band, deliberately: an unregistered class is one nobody has
#: reasoned about yet, and the gate's job there is to catch a blatant leak, not
#: to fail a build on an un-thought-through number. Its own permutation null
#: still applies (and still binds whenever it is tighter).
DEFAULT_CLASS_THRESHOLD = ClassThreshold(
    auc_threshold=PROVISIONAL_THRESHOLD_BAND[1],
    status="provisional",
    justification=(
        "Unregistered class: the loose end of the plan's band, pending a per-class "
        "decision. Only binds when it is tighter than this class's permutation null."
    ),
)


class MetadataLeakageError(RuntimeError):
    """Raised by :func:`run_leakage_gate` when a corpus's non-payload metadata
    predicts the vulnerability label above the pass line -- globally, or for
    any single class. The measurement function :func:`probe_leakage` never
    raises this; only the gate wrapper does."""


class InsufficientCorpusError(RuntimeError):
    """Raised by :func:`run_leakage_gate` when the corpus is too small or too
    degenerate for the probe to mean anything (too few cells, too few
    generating-rule groups, fewer than two classes, or no feature with any
    variance).

    Deliberately a *separate* type from :class:`MetadataLeakageError`: "we
    could not measure" is not "we measured a leak", and a caller wiring this as
    a build gate must be able to tell them apart in order to skip with a
    printed reason rather than fail the build (which is what
    ``fuzzlab.labgen.cli.run_checks`` does, mirroring the fingerprint gate's
    single-stack skip)."""


def class_threshold(label: str) -> ClassThreshold:
    """The configured :class:`ClassThreshold` for `label`, or
    :data:`DEFAULT_CLASS_THRESHOLD`. The one place that fallback is applied, so
    the gate and the report can never disagree about which number a class got
    (PA-0003/PA-0021)."""
    return PER_CLASS_AUC_THRESHOLDS.get(label, DEFAULT_CLASS_THRESHOLD)


def grouped_cv(*, n_splits: int, random_state: int) -> StratifiedGroupKFold:
    """The one place this package constructs its generating-rule-grouped
    cross-validator (module docstring, point 3: grouped by generating-rule ID,
    never a random split).

    Extracted so a second consumer reuses this exact construction instead of
    re-deriving a grouping strategy of its own (PA-0003/PA-0021: a convention
    shared by more than one participant lives in one shared function). Used
    here by `_cross_val_proba` and by
    `fuzzlab.labgen.corpus_analysis.stratified_split`
    (`docs/LAB_IMPLEMENTATION_PLAN.md` §2.4, which names this reuse
    explicitly).
    """
    return StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)


@dataclass(frozen=True)
class ClassLeakageResult:
    """One class's leakage verdict under the per-class-threshold design
    (`docs/LAB_IMPLEMENTATION_PLAN.md` §2.3)."""

    #: The class label this row is about.
    label: str
    #: Number of cells carrying this label.
    n_samples: int
    #: This class's one-vs-rest cross-validated AUC.
    observed_auc: float
    #: The `null_percentile`-th percentile of THIS class's one-vs-rest AUC
    #: under label permutation -- the empirically-derived line.
    null_threshold: float
    #: The configured absolute line for this class (`class_threshold(label)`).
    configured: ClassThreshold
    #: ``min(null_threshold, configured.auc_threshold)`` -- fail-closed, so a
    #: configured number can only ever tighten the gate (docstring point 6).
    effective_threshold: float
    #: Which of the two produced `effective_threshold`: `"permutation_null"`
    #: or `"configured_threshold"`. When it is `"configured_threshold"` and
    #: `configured.status == "provisional"`, this class's pass/fail decision
    #: currently rests on a number nobody has calibrated yet -- precisely what
    #: the report is required to surface.
    binding_line: str
    #: True if `observed_auc` exceeds `effective_threshold`.
    leaks: bool

    @property
    def decided_by_uncalibrated_threshold(self) -> bool:
        """True when a provisional, not-yet-calibrated configured number is the
        line this class was judged against."""
        return self.binding_line == "configured_threshold" and self.configured.status == "provisional"


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
    #: Per-class rows under the §2.3 per-class-threshold design. Appended (with
    #: a default) rather than inserted, so every pre-existing keyword
    #: construction of this dataclass still works unchanged.
    per_class: tuple[ClassLeakageResult, ...] = ()
    #: True if ANY class row leaks. Kept separate from `leaks` (which stays the
    #: global-AUC-vs-global-null verdict it always was) so existing callers and
    #: tests reading `leaks` are unaffected by this lane.
    per_class_leaks: bool = False

    @property
    def gate_passes(self) -> bool:
        """The build-gate verdict: neither the global check nor any per-class
        check flagged. This -- not `leaks` -- is what
        :func:`run_leakage_gate` keys on."""
        return not (self.leaks or self.per_class_leaks)

    @property
    def provisional_classes(self) -> tuple[str, ...]:
        """Classes whose verdict rests on an uncalibrated configured number."""
        return tuple(row.label for row in self.per_class if row.decided_by_uncalibrated_threshold)


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


def _resolve_exclusions(
    labels: Sequence[str], base_features: Sequence[str] = FEATURE_ALLOWLIST
) -> tuple[tuple[str, ...], tuple[tuple[str, str, str], ...]]:
    """Return (features_used, exclusions_applied) for the classes present.

    `base_features` defaults to the whole closed allowlist (the pre-existing
    behavior); a caller may narrow it via `probe_leakage(feature_scope=...)`
    when only a subset of the allowlist is actually observable for that corpus.
    Narrowing can never widen the allowlist -- `probe_leakage` intersects and
    validates before calling this.
    """
    present = set(labels)
    exclusions_applied: list[tuple[str, str, str]] = []
    excluded_features: set[str] = set()
    for cls in sorted(present):
        for feature, justification in PER_CLASS_FEATURE_EXCLUSIONS.get(cls, {}).items():
            excluded_features.add(feature)
            exclusions_applied.append((cls, feature, justification))
    features_used = tuple(f for f in base_features if f not in excluded_features)
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


def _per_class_auc(y: np.ndarray, proba: np.ndarray, classes: np.ndarray) -> dict[str, float]:
    """One-vs-rest AUC per class, from the same cross-validated probabilities
    the global AUC is computed from -- never a second, separately-fitted model
    (that would let the global and per-class verdicts disagree about what the
    classifier actually learned)."""
    per_class: dict[str, float] = {}
    for i, cls in enumerate(classes):
        binary = (y == cls).astype(int)
        if len(np.unique(binary)) < 2:  # pragma: no cover - guarded by n_classes >= 2
            continue
        per_class[str(cls)] = float(roc_auc_score(binary, proba[:, i]))
    return per_class


def _cross_val_proba(
    X: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray,
    features_used: Sequence[str],
    n_splits: int,
    random_state: int,
) -> tuple[np.ndarray, np.ndarray]:
    classes = np.unique(y)
    pipeline = _build_pipeline(features_used, random_state)
    cv = grouped_cv(n_splits=n_splits, random_state=random_state)
    with warnings.catch_warnings():
        # Small synthetic/fixture corpora can trigger benign convergence or
        # class-imbalance warnings from sklearn; they don't affect the AUC
        # computation and would otherwise be noisy in test output.
        warnings.simplefilter("ignore")
        proba = cross_val_predict(
            pipeline, X, y, cv=cv, groups=groups, method="predict_proba"
        )
    return proba, classes




def probe_leakage(
    cells: Iterable[Mapping[str, Any]],
    *,
    label_key: str = "label",
    group_key: str = "rule_id",
    n_splits: int = 5,
    n_permutations: int = 200,
    null_percentile: float = 99.0,
    random_state: int = 0,
    feature_scope: Sequence[str] | None = None,
) -> LeakageResult:
    """Run the metadata leakage probe against a corpus of cells.

    Each cell is a mapping with:
      - `label_key` (default "label"): the vulnerability-label ground truth.
      - `group_key` (default "rule_id"): the generating-rule ID (grouping key
        for `StratifiedGroupKFold` — near-duplicate cells from the same rule
        never split across train/test).
      - "features": a mapping restricted to `FEATURE_ALLOWLIST` keys.

    `feature_scope` (optional) narrows the base feature set to the subset of
    `FEATURE_ALLOWLIST` this corpus can actually observe — for a corpus derived
    from a *manifest*, only build-time-known metadata exists (no status code, no
    response length, no latency), and handing the probe `None` for the rest
    would be fabricating observations the real pipeline never produced (PA-0006).
    It can only ever narrow: a name outside `FEATURE_ALLOWLIST` raises
    `ValueError`.

    Returns a `LeakageResult`. This function never raises on a "leaky"
    result — `leaks=True`/`per_class_leaks=True` is data for the caller to act
    on, not an error; :func:`run_leakage_gate` is the wrapper that turns it into
    a build failure. It *does* raise `ValueError` on malformed input (missing
    keys, or a feature key outside the closed allowlist).
    """
    cells = list(cells)
    _validate_cells(cells, label_key, group_key)

    if feature_scope is None:
        base_features: tuple[str, ...] = FEATURE_ALLOWLIST
    else:
        requested = tuple(feature_scope)
        outside = [f for f in requested if f not in FEATURE_ALLOWLIST]
        if outside:
            raise ValueError(
                f"feature_scope names feature(s) outside the closed allowlist: {sorted(outside)} "
                f"(allowed: {FEATURE_ALLOWLIST}); feature_scope may only NARROW the allowlist, "
                "never widen it"
            )
        if not requested:
            raise ValueError("feature_scope, when given, must name at least one allowlisted feature")
        # Preserve allowlist order so the feature matrix's column order stays
        # canonical regardless of the order a caller happened to pass.
        base_features = tuple(f for f in FEATURE_ALLOWLIST if f in set(requested))

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

    features_used, exclusions_applied = _resolve_exclusions(labels_raw, base_features)
    if not features_used:
        raise ValueError(
            "all allowlisted features were excluded for the classes present; "
            "the probe would have nothing left to evaluate"
        )

    missing = sorted(
        {f for f in features_used for cell in cells if f not in cell["features"]}
    )
    if missing:
        raise ValueError(
            f"feature(s) {missing} are in scope for this run but absent from at least one "
            "cell's 'features' mapping; pass feature_scope to restrict the probe to the "
            "features this corpus actually observes rather than leaving them unset "
            "(an unset feature would be silently imputed, which is exactly the "
            "fabricated-upstream-input shape PA-0006 forbids)"
        )

    X = _feature_matrix(cells, features_used)

    proba, classes = _cross_val_proba(X, y, groups, features_used, n_splits, random_state)
    observed_auc = _auc_from_proba(y, proba, classes)
    observed_per_class = _per_class_auc(y, proba, classes)

    rng = np.random.default_rng(random_state)
    null_samples = []
    per_class_null: dict[str, list[float]] = {label: [] for label in observed_per_class}
    for _ in range(n_permutations):
        y_shuffled = rng.permutation(y)
        # A permutation can (rarely) collapse a fold to a single class for tiny
        # fixtures; skip and resample rather than let cross_val_predict raise.
        if len(np.unique(y_shuffled)) < 2:
            continue
        try:
            perm_proba, perm_classes = _cross_val_proba(
                X, y_shuffled, groups, features_used, n_splits, random_state
            )
        except ValueError:
            continue
        null_samples.append(_auc_from_proba(y_shuffled, perm_proba, perm_classes))
        for label, auc in _per_class_auc(y_shuffled, perm_proba, perm_classes).items():
            if label in per_class_null:
                per_class_null[label].append(auc)

    if not null_samples:
        raise RuntimeError(
            "no valid permutation samples were produced; corpus is too small/degenerate "
            "for the requested n_splits/n_permutations"
        )

    null_threshold = float(np.percentile(null_samples, null_percentile))
    leaks = observed_auc > null_threshold

    label_counts: dict[str, int] = {}
    for label in labels_raw:
        label_counts[str(label)] = label_counts.get(str(label), 0) + 1

    per_class_rows: list[ClassLeakageResult] = []
    for label in sorted(observed_per_class):
        samples = per_class_null.get(label) or null_samples
        class_null = float(np.percentile(samples, null_percentile))
        configured = class_threshold(label)
        # Fail-closed: strictest of the empirical null and the configured line,
        # so a configured number can only ever tighten the gate (module
        # docstring, point 6) -- never disable it for that class.
        if configured.auc_threshold < class_null:
            effective, binding = configured.auc_threshold, "configured_threshold"
        else:
            effective, binding = class_null, "permutation_null"
        per_class_rows.append(
            ClassLeakageResult(
                label=label,
                n_samples=label_counts.get(label, 0),
                observed_auc=observed_per_class[label],
                null_threshold=class_null,
                configured=configured,
                effective_threshold=effective,
                binding_line=binding,
                leaks=observed_per_class[label] > effective,
            )
        )

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
        per_class=tuple(per_class_rows),
        per_class_leaks=any(row.leaks for row in per_class_rows),
    )


# --- The build gate (plan §2.3, lane L-P1.3) ---------------------------------

#: Minimum cells a corpus needs before :func:`run_leakage_gate` will judge it.
#: Below this the permutation null is dominated by sampling noise and a
#: pass/fail line means nothing -- the gate raises
#: :class:`InsufficientCorpusError` (skip, with a reason) rather than pass or
#: fail on a number it cannot stand behind. The value is the smallest corpus for
#: which a 5-fold grouped split leaves a double-digit holdout on both sides.
MIN_CELLS_FOR_GATE = 40

#: Minimum distinct generating-rule groups. Grouped CV cannot make more folds
#: than there are groups, and with a handful of groups the null distribution is
#: a handful of points.
MIN_GROUPS_FOR_GATE = 6

#: Minimum cells per class. A class with fewer contributes a one-vs-rest AUC
#: estimated from a couple of positives, which its per-class threshold would
#: then be compared against -- meaningless precision.
MIN_CELLS_PER_CLASS_FOR_GATE = 8


@dataclass(frozen=True)
class LeakageGateReport:
    """Returned by :func:`run_leakage_gate` when the gate passes. Carries the
    full `LeakageResult` plus the rendered report text, so a caller can print
    the provisional-vs-calibrated annotations without re-deriving them."""

    result: LeakageResult
    report_text: str


def insufficiency_reason(
    cells: Sequence[Mapping[str, Any]],
    *,
    label_key: str = "label",
    group_key: str = "rule_id",
    feature_scope: Sequence[str] | None = None,
) -> str | None:
    """Why this corpus is too small/degenerate for the gate to mean anything,
    or `None` if it is big enough.

    Exposed separately from :func:`run_leakage_gate` so a build gate can decide
    to **skip with an explicit printed reason** before doing any work, exactly
    as ``fuzzlab.labgen.cli`` does for the fingerprint gate's single-stack case.
    "Not enough data to be meaningful" is never a build failure: it is not a
    leakage problem.
    """
    if not cells:
        return "the corpus is empty"
    labels = [str(cell.get(label_key)) for cell in cells]
    groups = {cell.get(group_key) for cell in cells}
    distinct_labels = sorted(set(labels))
    if len(distinct_labels) < 2:
        return (
            f"the corpus carries only {len(distinct_labels)} distinct label class "
            f"{distinct_labels}; a leakage probe needs >= 2 (there is nothing to "
            "discriminate between)"
        )
    if len(cells) < MIN_CELLS_FOR_GATE:
        return (
            f"the corpus has {len(cells)} cell(s); the gate needs >= {MIN_CELLS_FOR_GATE} "
            "for its permutation null to be anything but sampling noise"
        )
    if len(groups) < MIN_GROUPS_FOR_GATE:
        return (
            f"the corpus spans only {len(groups)} distinct generating-rule group(s); the "
            f"gate needs >= {MIN_GROUPS_FOR_GATE} (grouped CV cannot make more folds than "
            "there are groups)"
        )
    counts = {label: labels.count(label) for label in distinct_labels}
    thin = {label: n for label, n in counts.items() if n < MIN_CELLS_PER_CLASS_FOR_GATE}
    if thin:
        return (
            f"class(es) {sorted(thin)} carry fewer than {MIN_CELLS_PER_CLASS_FOR_GATE} cells "
            f"({thin}); a per-class one-vs-rest AUC estimated from that few positives cannot "
            "be compared against a per-class threshold meaningfully"
        )
    scope = tuple(feature_scope) if feature_scope is not None else FEATURE_ALLOWLIST
    informative = [
        f for f in scope if len({str(cell.get("features", {}).get(f)) for cell in cells}) > 1
    ]
    if not informative:
        return (
            f"none of the {len(scope)} in-scope feature(s) {sorted(scope)} varies across this "
            "corpus; with no feature variance every AUC is chance by construction and the "
            "probe cannot detect leakage either way"
        )
    return None


def format_leakage_report(result: LeakageResult) -> str:
    """Render `result` as the gate's own report, annotating **each** per-class
    threshold with its calibration status.

    The provisional-vs-calibrated annotation is a hard requirement of the §2.3
    decision, not decoration: Phase 1 is the first point real corpus data
    exists, so a future pass must be able to read this output and tell which
    numbers still need deriving from a properly-sized permutation null.
    """
    lines = [
        f"metadata leakage probe: global AUC {result.observed_auc:.4f} vs "
        f"p{result.null_percentile:g} permutation null {result.null_threshold:.4f} "
        f"-> {'LEAK' if result.leaks else 'ok'}",
        f"  corpus: {result.n_samples} cell(s), {result.n_groups} generating-rule group(s), "
        f"{result.n_classes} class(es), {result.n_splits}-fold grouped CV, "
        f"{result.n_permutations} valid permutation(s)",
        f"  features used ({len(result.features_used)}): {list(result.features_used)}",
        f"  per-class feature exclusions applied: {result.exclusion_count}",
    ]
    for cls, feature, justification in result.exclusions_applied:
        lines.append(f"    - {cls}/{feature}: {justification}")
    lines.append("  per-class thresholds (plan SS2.3; effective = min(null, configured)):")
    for row in result.per_class:
        lines.append(
            f"    - {row.label}: AUC {row.observed_auc:.4f} vs effective "
            f"{row.effective_threshold:.4f} [{row.binding_line}] "
            f"-> {'LEAK' if row.leaks else 'ok'}"
        )
        lines.append(
            f"        null p{result.null_percentile:g}={row.null_threshold:.4f}, "
            f"configured={row.configured.auc_threshold:.4f} "
            f"({row.configured.status.upper()}), n={row.n_samples}"
        )
        lines.append(f"        configured-threshold rationale: {row.configured.justification}")
    provisional = result.provisional_classes
    if provisional:
        lines.append(
            "  NOTE: the binding pass line for class(es) "
            f"{list(provisional)} is a PROVISIONAL configured threshold, not one derived "
            "from a properly-sized permutation-null distribution. Revisit these numbers "
            "once the corpus is large enough per class (docs/LAB_IMPLEMENTATION_PLAN.md "
            "SS2.3)."
        )
    else:
        lines.append(
            "  NOTE: every class's binding pass line is its own permutation null, so no "
            "verdict above currently rests on an uncalibrated configured threshold."
        )
    return "\n".join(lines)


def run_leakage_gate(
    cells: Iterable[Mapping[str, Any]],
    *,
    label_key: str = "label",
    group_key: str = "rule_id",
    n_splits: int = 5,
    n_permutations: int = 200,
    null_percentile: float = 99.0,
    random_state: int = 0,
    feature_scope: Sequence[str] | None = None,
) -> LeakageGateReport:
    """Run the leakage probe as a **build gate**.

    Raises :class:`InsufficientCorpusError` when the corpus is too small or too
    degenerate to judge (the caller is expected to treat that as a skip with a
    printed reason, mirroring the fingerprint gate's single-stack skip), and
    :class:`MetadataLeakageError` — naming **every** violation found, global and
    per-class, not just the first — when it is big enough and leaks. Returns a
    :class:`LeakageGateReport` when it passes.
    """
    cells = list(cells)
    reason = insufficiency_reason(
        cells, label_key=label_key, group_key=group_key, feature_scope=feature_scope
    )
    if reason is not None:
        raise InsufficientCorpusError(reason)

    result = probe_leakage(
        cells,
        label_key=label_key,
        group_key=group_key,
        n_splits=n_splits,
        n_permutations=n_permutations,
        null_percentile=null_percentile,
        random_state=random_state,
        feature_scope=feature_scope,
    )
    report_text = format_leakage_report(result)
    if result.gate_passes:
        return LeakageGateReport(result=result, report_text=report_text)

    violations: list[str] = []
    if result.leaks:
        violations.append(
            f"global metadata AUC {result.observed_auc:.4f} exceeds the p"
            f"{result.null_percentile:g} permutation null {result.null_threshold:.4f}"
        )
    for row in result.per_class:
        if row.leaks:
            violations.append(
                f"class {row.label!r} one-vs-rest AUC {row.observed_auc:.4f} exceeds its "
                f"effective threshold {row.effective_threshold:.4f} "
                f"(binding line: {row.binding_line}; configured "
                f"{row.configured.auc_threshold:.4f} [{row.configured.status}], null p"
                f"{result.null_percentile:g} {row.null_threshold:.4f})"
            )
    raise MetadataLeakageError(
        f"metadata leakage gate failed with {len(violations)} violation(s) -- this corpus's "
        "non-payload metadata predicts the vulnerability label, so a detector could cheat "
        "instead of finding the real signal:\n  - "
        + "\n  - ".join(violations)
        + "\n"
        + report_text
    )
