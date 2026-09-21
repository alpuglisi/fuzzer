# Phase 5 — Detection classifier + conformal (plan)

Learn to **rank and triage** candidates so the toolkit beats dumb baselines on
held-out endpoints, with calibrated abstention. Strict oracle/advisory split: the
classifier produces **scores** and a flag/abstain/drop decision — it never writes
`finding` labels (the oracle stays the sole label authority).

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (Phase 5), the advisory
`score`/`uncertainty` columns in `fuzzlab/core/migrations.py`, and the trainable
dataset (findings + negatives) the store now holds after Phases 2–4.*

## Goal

On held-out endpoints, a detection classifier beats the prevalence and mean+kσ
baselines on PR-AUC, and a split-conformal gate turns its scores into calibrated
flag / abstain / drop decisions — routing the confident cases automatically and the
uncertain middle to review, without ever confirming.

## Status (2026-09-21)

`[in progress — honest-eval + models core built offline]`. Dependency-light (pure
Python — no numpy/sklearn). Built and unit-tested (`fuzzlab/ml/`, 5 tests):
- **metrics** — `pr_auc` (average precision) and `group_kfold` (never splits an
  endpoint across folds — no leakage);
- **baselines** — `PrevalenceBaseline` and `SigmaBaseline` (mean+kσ anomaly), the
  floors a real model must beat;
- **logistic** — a pure-Python `LogisticRegression` (standardized, L2, class-balanced);
- **conformal** — `ConformalGate.calibrate/decide` (flag/abstain/drop at a target
  error rate).

A test proves the exit in miniature: on a synthetic separable dataset the logistic
model beats **both** baselines on GroupKFold PR-AUC, and the conformal gate's
false-flag / false-drop rates are bounded by `alpha`.

## Principles (this phase)

- **Advisory only.** ML writes scores/uncertainty (the `score`/`uncertainty` columns),
  never `finding` labels. The oracle confirms; the model triages.
- **Honest evaluation.** GroupKFold by endpoint/template (correlated points never span
  a split); PR-AUC as the headline (positives are rare); always compare to the dumb
  baselines — beat both or it does not ship.
- **Calibrated abstention.** Automate only the confident tails; hand the uncertain
  middle to review. A model absent / low-data path falls back to the baseline.
- **Dependency-light first.** Pure-Python logistic + baselines now; gradient-boosted
  trees (numpy/sklearn) are an optional later add behind the same interface.

## Tasks

- **T5.1 — Honest-eval + models core (done, offline).** `metrics` (PR-AUC,
  GroupKFold), `baselines` (prevalence, mean+kσ), `logistic`, `conformal`; the
  beat-both-baselines + calibrated-abstention tests. `fuzzlab/ml/`.
- **T5.2 — Store-trained dataset.** Assemble `(X, y, groups)` from the store — positives
  from oracle findings, negatives from rejected candidates / non-fired evaluations,
  grouped by endpoint; dedup positives before splitting; a fallback when the model is
  absent or data is thin. Feature vectors from the recorded `features_json`.
- **T5.3 — Train + score + persist.** Fit on the store's dataset, write advisory
  `score`/`uncertainty` to `candidate`/`attempt`, persist the model row (`model`
  table), and surface scores + the conformal decision in the web panel.
- **T5.4 — Gradient-boosted trees (optional).** Add a GBT model (numpy/sklearn) behind
  the same `fit`/`predict_proba` interface, class-balanced + calibrated, when the
  dependency is acceptable.
- **T5.5 — Held-out exit.** Show held-out PR-AUC beats both baselines and the conformal
  abstain rate is calibrated, on the store's real dataset.

## Exit criterion

Held-out PR-AUC beats both the prevalence and mean+kσ baselines (GroupKFold by
endpoint), and the conformal gate's abstain/flag/drop rates are calibrated — all
advisory, with the oracle still the sole label authority.

## Component mapping

- **ML (10)** — the `fuzzlab/ml/` package (metrics, baselines, logistic, conformal,
  the store dataset, optional GBT).
- **CORE (02)** — the advisory `score`/`uncertainty` columns + the `model` table
  (reserved; no migration).
- **UI (12)** — surface scores + conformal decisions in the panel (T5.3).

## Out of scope for Phase 5 (deferred)

- Writing labels from ML (never — oracle-only).
- New reward/feature *sources* (grey-box is Phase 3; this phase consumes features).
