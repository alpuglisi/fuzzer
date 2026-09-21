# ML Components — Change Control Log

Component code: **ML**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-ML-0002 — Detection classifier + conformal groundwork (Phase 5 T5.1) (2026-09-21)
- Change: added `fuzzlab/ml/` (pure Python, no numpy/sklearn): `metrics` (`pr_auc`
  average precision + leakage-free `group_kfold`), `baselines` (`PrevalenceBaseline`,
  `SigmaBaseline` mean+kσ), `logistic` (standardized, L2, class-balanced
  `LogisticRegression`), and `conformal` (`ConformalGate.calibrate/decide` →
  flag/abstain/drop). All **advisory**: scores/decisions only, never `finding` labels
  (oracle/advisory split). Wrote `docs/PHASE_5_PLAN.md`; roadmap points to it.
- Impact (other components / project): gives Phase 5 its honest-evaluation harness,
  the baselines any model must beat, a working classifier, and calibrated triage — the
  scoring/triage layer over the trainable dataset Phases 2–4 produce. No labels
  written; the store-trained dataset + persistence are T5.2/T5.3.
- Risk (level; mitigation): low — pure, dependency-light logic, advisory-only. Mitigated
  by 5 tests (`tests/test_ml.py`): PR-AUC perfect/degenerate; GroupKFold never splits a
  group; the logistic model beats **both** baselines on held-out GroupKFold PR-AUC; the
  prevalence baseline predicts the base rate; the conformal gate's false-flag /
  false-drop rates are bounded by alpha. Suite 188 passed / 2 skipped.
- Deliverables:
  - [x] `metrics`, `baselines`, `logistic`, `conformal` + tests — done.
  - [x] `docs/PHASE_5_PLAN.md`; roadmap pointer — done.
  - [ ] Store-trained dataset (T5.2) + train/score/persist (T5.3) — next.
  - [ ] Optional gradient-boosted trees (T5.4); held-out exit on real data (T5.5) — later.
- Effectiveness (assessed 2026-09-21): effective in tests — the model beats both
  baselines and the conformal gate is calibrated on synthetic data; the real-dataset
  exit follows the store-training tasks.

### CC-ML-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented. The
  oracle/advisory split is fixed: ML writes scores/uncertainty only, never labels.
- Impact (other components / project): the ranker reorders the auditor's
  candidates (zero requests); the classifier screens fuzzer attempts; the anomaly
  detector tags proxy flows; the active learner allocates oracle budget. All depend
  on the oracle for training labels and on `core/`'s versioned features. Adds
  `model` rows and score columns to the store contract. Attaches via the plugin
  system, so the toolkit ships and runs correctly with ML disabled.
- Risk (level; mitigation): medium — a miscalibrated or leaky model could mislead
  triage or, worse, be mistaken for ground truth. Mitigated structurally by the
  oracle/advisory split (ML cannot write labels), calibration + conformal
  abstention, leakage-safe cell/transform splits with a permanent blind holdout,
  external validation (WAVSEP/Juice Shop), versioned features/models, and
  advisory-only output. Sequenced late (Phases 5, 7, 10) once enough oracle labels
  exist.
- Deliverables:
  - [ ] Detection classifier (GBDT + calibration + conformal) — todo (Phase 5).
  - [ ] Candidate ranker (learning-to-rank, 0 requests) — todo (Phase 7).
  - [ ] Anomaly detector (ECOD/IsolationForest → hybrid) — todo (Phase 7).
  - [ ] Active learner (uncertainty + committee) — todo (Phase 7).
  - [ ] Training/eval on cell/transform splits + blind holdout + external validation — todo.
  - [ ] Plugin attachment on `core/` hooks; `model` rows — todo (Phase 10).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  ranker ordering lift at zero request cost, calibrated classifier abstention that
  cuts oracle load without missing holdout findings, and no label writes from ML.
