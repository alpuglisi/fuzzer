# ML Components — Requirement Specification

Component code: **ML** · Status: `[built offline — classifier, ranker, active learner, anomaly detector; held-out exits on-host]` (Phases 5, 7, 10) · Last updated: 2026-10-13

Related: `ARCHITECTURE.md` #10; `DECISIONS_AND_ROADMAP.md` (D1, D2, D10);
`./change-control.md`.

## 1. Purpose
Add learned assistance — screening, ranking, anomaly flagging, and budget
allocation — **without ever writing labels**. ML writes scores and uncertainty;
the oracle owns truth (the oracle/advisory split).

## 2. Scope
- **In:** detection classifier, candidate ranker, anomaly detector, active
  learner; training, calibration, and versioning.
- **Out:** confirming a vulnerability (oracle only). ML never writes `finding`
  labels.

## 3. Functional requirements
- **FR-ML-1 (classifier, A.1)** Gradient-boosted trees over `attempt.features_json`
  with probability calibration and a conformal flag/abstain/drop decision; writes
  scores + uncertainty, never labels.
- **FR-ML-2 (ranker, A.2)** Learning-to-rank over parameters/forms from candidate
  features; writes `candidate.score`; costs **zero** requests.
- **FR-ML-3 (anomaly, A.5)** ECOD / Isolation Forest tripwire over flows, later an
  XGBOD-style hybrid; tags anomalous responses. *(ECOD over candidates is wired as
  `fuzzlab auto --anomaly` and persisted per candidate — FR-ML-12. Isolation Forest and
  flows are not built.)*
- **FR-ML-4 (active learner, A.6.5)** Allocate scarce oracle budget by model
  uncertainty and committee disagreement. *(Wired as `fuzzlab auto --confirm-budget N`
  — FR-ML-11. The user chose `score`, most-likely-first, as the default, because it
  maximises findings per confirmation; uncertainty and committee remain available.)*
- **FR-ML-5** Read features via the `core/` versioned feature store; a model
  records the `feature_version` it was trained against.
- **FR-ML-6** Attach as **plugins** on `core/` hooks; shipping without ML is a
  config change, not a code change.
- **FR-ML-7** Train and evaluate against the lab's cell/transform splits with a
  permanent blind holdout, plus external validation (WAVSEP / Juice Shop) (D10).
- **FR-ML-9** *(added CC-ML-0010, lane U4)* Model internals already written to the
  store are surfaced **read-only** by the web control panel's ML tab (`GET /ml`,
  `GET /api/ml/data`; see `12-diagnostics-and-ui/requirements.md` FR-UI-11): classifier
  PR curve + reliability/ECE, ranker nDCG@k/precision@k + score/uncertainty
  distributions, the conformal flag/abstain/drop split, the ECOD anomaly tripwire, the
  active-learning committee's disagreement, the bandit's Beta posteriors, and mutation
  variants. `fuzzlab/web/mlview.py` reads only — it computes derived views (PR curve
  points, a reliability diagram, a histogram, a Beta density, a lightweight bootstrap
  committee) from stored feature vectors and scores; it never writes a row, including
  no `run_metrics` write even where the equivalent training-time helper
  (`fuzzlab.ml.anomaly.detect_anomalies`) does. **Known gap:** the logistic
  classifier's coefficients (log-odds weights) are not persisted anywhere in the store
  — `train_and_score` fits a fresh model per request and writes only the
  conformal calibration thresholds (plus, since CC-ML-0011, its run scope and
  out-of-fold numbers — FR-ML-10) to `model.calibration`, never `_w`/`_b` — so the
  UI's "logistic weights diverging bar" panel (R-06) renders a documented
  not-available state rather than a value; making it real needs either a schema change
  (persist trained weights) or a training-time change (write on every `train_and_score`
  call), both out of scope for a read-only lane.
- **FR-ML-8 (training telemetry, CC-ML-0009)** When trained with a `run_id`, the
  GBT and logistic classifiers (`FR-ML-1`) emit per-round/per-epoch scalar
  training metrics (at minimum `train/loss`) to `core/`'s cross-run
  `metric_series` sink (`log_scalar`/`MetricLogger`), under `source="gbt"` /
  `source="logreg"` respectively, for the deploy fit only (not the per-fold
  out-of-fold fits used for model selection/calibration). Without a `run_id`,
  or when the training falls back to the prevalence baseline (no GBT/logistic
  model is fit), no rows are emitted. Purely observational: emission never
  changes what is fit or what scores/labels are written (`NFR-ML-advisory`,
  `NFR-ML-reproducible` both hold unchanged).

- **FR-ML-10 (model-row selection, CC-ML-0011, BUG-0061)** The `model` table is
  written by more than one model family (classifier: `train.CLASSIFIER_MODEL_NAMES` =
  `logistic`/`gbt`/`prevalence-fallback`, derived from `_MODELS`; ranker:
  `rank_train.RANKER_MODEL_NAMES` = `ranker`/`rank-prevalence-fallback`) and by every
  run's training. Each trainer records in the row's `calibration` JSON the `run_id` it
  trained on (null = store-wide train, which re-scores every run). On a non-fallback
  train it also records its out-of-fold evaluation: classifier `oof_pr_auc`,
  `oof_pr_auc_prevalence`, `oof_pr_auc_sigma`; ranker `oof_ndcg`, `oof_precision`,
  `oof_ndcg_random`, `oof_precision_random`, at its `at_k`. Every reader that needs "the
  deployed model of a family for a run" goes through
  `fuzzlab.ml.model_registry.select_latest` (via `train.latest_classifier` /
  `rank_train.latest_ranker`). That returns the newest row of that family whose scope
  covers the run (same `run_id`, null, or absent for legacy rows), never "the newest row
  of any kind" (PA-0063, enforced by a source-scan guard test).

- **FR-ML-11 (budget prioritizer, CC-ML-0013)** `fuzzlab.ml.active.prioritize(store,
  run_id, candidate_ids, method=…)` orders a run's confirmable candidates for a
  confirmation budget.
  - **Training data:** a model trained only on **earlier runs** (`run_id < current`)
    **against the same target** (exact match on the pipeline's `target.base_url`; runs
    with no `target` row never qualify). It never uses the current run's labels.
  - **Methods:**
    - `score` (default): highest ranker score first, i.e. most likely vulnerable;
    - `uncertainty`: closest to the 0.5 boundary first;
    - `committee`: largest bootstrap-committee disagreement first;
    - `random`: a seeded shuffle, the control for T7.4.
  - **Thin data:** fewer than 20 rows or 5 positives, no negatives, or fewer than 2
    endpoints gives `None`, so the pipeline confirms everything and says so. `random`
    never needs data.
  - **Skipped candidates:** those the oracle skipped for budget (`oracle_status=
    'skipped_budget'`) are never training rows, since they have no label. The trainers
    still give them advisory `score` / `rank_score`.
  - **Known limitations:**
    - Candidate text includes the URL path, so a model trained on earlier runs of the
      same app partly memorises vulnerable endpoints. A T7.4 "beats random" claim must
      be measured on held-out endpoints.
    - `localhost:8080` and `127.0.0.1:8080` count as different targets.
    - `no_confirmer` rows still train as negatives, although
      `pipeline_oracle_rejected` excludes them. That divergence is flagged for a
      decision.
- **FR-ML-12 (anomaly persistence, CC-ML-0013)** `detect_anomalies(store, run_id,
  contamination)` scores **every** candidate of the run with ECOD (label-free, so
  budget-skipped ones included).
  - It writes `candidate.anomaly_score` / `anomaly_flag` and records
    `run_metrics.anomaly_flagged`.
  - `contamination` must be in (0, 0.5].
  - A flag is relative to the candidates scored together. The CLI scores per run; a
    later store-wide call would overwrite per-run flags.
  - Advisory only: unusual is not vulnerable, and it writes no labels.

## 4. Non-functional requirements
- **NFR-ML-advisory** ML output is advisory: it can reorder, screen, or flag, but
  the oracle's verdict is final and independent.
- **NFR-ML-reproducible** Deterministic pipeline: fixed seeds, versioned features,
  versioned models, recorded metrics.
- **NFR-ML-no-leak** Train/test split prevents leakage across cells/transforms; the
  blind holdout is never trained on. *(Amended CC-ML-0014, BUG-0065:)* a candidate's
  label and rule counts come from its **own run** only. `build_dataset` keys finding and
  evaluation lookups by `run_id`, so a store-wide dataset equals the per-run datasets
  concatenated. *(Amended CC-ML-0012, BUG-0062.)*
  - `group_kfold` never yields a fold whose train and test overlap. With `k < 2` or
    fewer than 2 distinct groups it yields no fold.
  - Every out-of-fold scorer goes through `metrics.oof_folds`, which fails closed unless
    each row is held out exactly once.
  - Both trainers fall back (no OOF metrics) when distinct endpoints
    `< max(2, min_groups)` (default `min_groups=2`, the correctness floor) or `k < 2`.
  - Metrics recomputed from stored `candidate.score`/`rank_score` are in-sample (deploy
    fit) and must be labelled so wherever shown (PA-0064).
- **NFR-ML-calibrated** Classifier probabilities are calibrated; abstention is
  preferred to a confident wrong screen.

## 5. Interfaces and data contracts
Reads `attempt`/`candidate`/`flow` features and oracle `finding` labels (for
training); writes `candidate.score`, attempt scores/uncertainty, `model` rows
(versions, calibration — including `run_id` scope and `oof_*` metrics, read back only
through `model_registry.select_latest`, FR-ML-10). Never writes `finding`. Runs as `core/` plugins.
Optionally writes `core/`'s `metric_series` rows (`source="gbt"`/`"logreg"`,
`key` a slash-delimited path such as `train/loss`) via `log_scalar`/
`MetricLogger` when training is given a `run_id` (FR-ML-8) — read-only from
ML's perspective of the rest of the system; no other component depends on
these rows existing.

## 6. Dependencies (components)
`core/`, the oracle (labels), and the component that produces each model's inputs
(auditor for the ranker, fuzzing harness for the classifier, proxy/flows for the
anomaly detector). Plugin system for attachment.

## 7. Acceptance criteria
- Ranker improves candidate ordering at zero request cost on the lab.
- Classifier is calibrated and its abstain/drop reduces oracle load without missing
  known findings on the holdout.
- No ML component ever writes a `finding` label.
- Models reproduce from recorded seeds/feature versions.

## 8. Open questions
- Minimum labeled volume before each model is worth enabling.
- Drift handling as the lab/catalog evolve.
- Committee composition for active-learning disagreement.
