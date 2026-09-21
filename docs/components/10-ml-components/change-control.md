# ML Components — Change Control Log

Component code: **ML**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-ML-0006 — Pointwise candidate ranker + train/rank/persist (T7.2) (2026-09-21)
- Change: implemented the candidate ranker (A.2). `fuzzlab/ml/ranker.py::Ranker`
  augments the Phase-5 structural feature vector with char n-gram TF-IDF over the
  candidate text and fits a **pointwise** scorer (the pure-Python logistic model reused),
  exposing per-candidate **explanations** (top signed feature contributions).
  `fuzzlab/ml/rank_train.py::train_and_rank` runs OOF GroupKFold, scores it with
  NDCG@k/Precision@k against a **random-order baseline**, writes advisory
  `candidate.rank_score` + `candidate.rank_uncertainty` (migration 7; uncertainty peaks
  at the 0.5 boundary), persists a `model` row + the metrics to `run_metrics`, and falls
  back to a constant order on thin data. Wired as `fuzzlab auto --rank`.
- Impact (other components / project): the auditor's candidates can now be **ordered at
  zero request cost** so real vulnerabilities surface first — the ranker half of Phase 7.
  Kept in its own `rank_score`/`rank_uncertainty` columns so it coexists with the Phase-5
  detection classifier's `candidate.score`. Advisory only; the oracle stays the sole
  labeler (train_and_rank writes no findings). No new dependency.
- Risk (level; mitigation): low — pure logic, advisory-only writes, honest OOF eval vs a
  random control. Mitigated by 7 tests (`tests/test_ml_ranker.py`): migration-7 schema;
  ranker scores a positive above a negative; explanations are named; train_and_rank beats
  the random baseline on NDCG@k, ranks every candidate, persists a model + metrics, and
  writes no findings; uncertainty peaks at the boundary; thin-data fallback. Suite 266
  passed / 3 skipped.
- Deliverables:
  - [x] `Ranker` (structural + TF-IDF, pointwise, explanations) — done.
  - [x] `train_and_rank` (OOF NDCG@k/P@k vs random, advisory ranks, persist, fallback) — done.
  - [x] `fuzzlab auto --rank` wiring — done.
  - [ ] Active learning (T7.3); held-out exit on real lab data (T7.4) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the ranker beats a random
  order on held-out pages and ranks candidates advisory-only; the real-lab held-out exit
  is on-host.

### CC-ML-0005 — Phase 7 groundwork: ranking metrics + char n-gram TF-IDF (T7.1) (2026-09-21)
- Change: started the candidate ranker (A.2). `fuzzlab/ml/ranking.py` adds per-page
  ranking metrics — `ndcg_at_k`, `precision_at_k`, and grouped `mean_ndcg_at_k`/
  `mean_precision_at_k` (averaged over pages that have a positive; ties break to input
  order so a constant scorer can't win). `fuzzlab/ml/text_features.py::CharNgramVectorizer`
  is a bounded, deterministic, L2-normalized pure-Python char n-gram TF-IDF (no
  numpy/sklearn), with `candidate_text` (param/path/category/method) as the source text.
  Wrote `docs/PHASE_7_PLAN.md`.
- Impact (other components / project): gives Phase 7 its ordering-quality yardstick
  (NDCG@k/Precision@k) and the weak-signal text features (param/path names) the pointwise
  ranker (T7.2) augments the structural vector with. Advisory-only; no store change yet
  (rank columns are T7.2's migration 7). Builds on Phase 5's `metrics`/`dataset`.
- Risk (level; mitigation): low — pure, dependency-light logic; no writes. Mitigated by
  11 tests (`tests/test_ml_ranking.py`): NDCG perfect/worst/zero-positive and a
  hand-computed value; Precision@k; tie-break to input order; per-page means skip
  positive-less pages; vectorizer determinism/bounding/L2-norm, similar-name proximity,
  and short/unseen text. Suite 259 passed / 3 skipped.
- Deliverables:
  - [x] Ranking metrics (NDCG@k, Precision@k, per-page) — done.
  - [x] Char n-gram TF-IDF vectorizer + `candidate_text` — done.
  - [ ] Pointwise ranker + `candidate.rank_score` (T7.2); active learning (T7.3);
        held-out exit (T7.4) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — the metrics rank a good order
  above a bad one and the vectorizer places similar param names closer; the real ordering
  lift is measured in T7.2/T7.4.

### CC-ML-0004 — Gradient-boosted trees + model auto-selection (T5.4) (2026-09-21)
- Change: added `fuzzlab/ml/gbt.py::GradientBoostedTrees` — a pure-Python logistic-loss
  gradient-boosting model over shallow **weighted** regression trees (class-balanced,
  deterministic), behind the same `fit`/`predict_proba` interface as the logistic model
  (no numpy/sklearn dependency, so it runs and is tested in-sandbox). `train_and_score`
  gained `model_kind` (`logistic` | `gbt` | `auto`); `auto` out-of-fold-selects the
  better of the two on PR-AUC and deploys the winner (reported as `model_selection`).
  `fuzzlab auto --score` uses `auto`.
- Impact (other components / project): the detection layer can now capture non-linear
  feature interactions the linear model misses, chosen honestly per dataset. Still
  advisory (scores only); the deployed model is persisted in the `model` table as
  before. No new dependency.
- Risk (level; mitigation): low — pure logic, advisory-only, deterministic. Mitigated by
  tests (`tests/test_gbt.py`: probabilities in range; GBT beats logistic + both
  baselines on a non-linear boundary under GroupKFold; `tests/test_ml_train.py`:
  `model_kind="gbt"` persists a gbt model + scores; `auto` compares both and deploys the
  winner). Suite 196 passed / 2 skipped.
- Deliverables:
  - [x] `GradientBoostedTrees` (weighted trees, logistic loss, class-balanced) — done.
  - [x] `train_and_score` model_kind logistic/gbt/auto; `auto --score` uses auto — done.
  - [x] Tests (beats logistic + baselines nonlinear; gbt/auto persistence) — done.
  - [ ] Held-out exit on real lab data (T5.5) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — GBT beats the linear model
  on non-linear data and auto picks the OOF winner; real-lab held-out exit is on-host.

### CC-ML-0003 — Store-trained dataset + train/score/persist (T5.2/T5.3) (2026-09-21)
- Change: `fuzzlab/ml/dataset.py::build_dataset` assembles a trainable dataset from the
  store — one example per candidate, label = a matching oracle finding exists, grouped
  by endpoint, with a fixed versioned feature vector. `fuzzlab/ml/train.py::train_and_score`
  runs honest out-of-fold GroupKFold (logistic vs prevalence + sigma baselines),
  calibrates a `ConformalGate` on the OOF scores, fits the final model on all data,
  writes **advisory** `candidate.score` (never labels), persists a `model` row (with the
  conformal calibration) and the OOF metrics (`ml_pr_auc*`) to `run_metrics`, and falls
  back to the prevalence baseline on thin data. Wired as `fuzzlab auto --score`.
- Impact (other components / project): turns the ML core into a real scorer over the
  store's dataset — advisory scores rank candidates and the conformal gate triages them,
  while the oracle remains the sole label authority. The panel surfaces the scores
  (CC-UI-0008). No schema change (uses the reserved `candidate.score` + `model` table).
- Risk (level; mitigation): low — advisory-only writes; a fallback for thin data; honest
  OOF evaluation avoids leakage. Mitigated by tests (`tests/test_ml_train.py`: dataset
  labels/groups; train writes scores + model + metrics and writes no findings;
  thin-store fallback). Suite 192 passed / 2 skipped.
- Deliverables:
  - [x] `build_dataset` (labels from findings, grouped by endpoint) — done.
  - [x] `train_and_score` (OOF eval, conformal, advisory scores, model persist, fallback) — done.
  - [x] `fuzzlab auto --score` wiring; panel surfacing — done.
  - [ ] Optional gradient-boosted trees (T5.4); held-out exit on real lab data (T5.5) — later.
- Effectiveness (assessed 2026-09-21): effective in tests — scores + model + metrics are
  written, no labels leak, and thin data falls back cleanly; the real-lab held-out exit
  is on-host.

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
