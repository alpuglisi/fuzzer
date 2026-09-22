# ML Components — Requirement Specification

Component code: **ML** · Status: `[planned]` (Phases 5, 7, 10) · Last updated: 2026-09-21

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
  XGBOD-style hybrid; tags anomalous responses.
- **FR-ML-4 (active learner, A.6.5)** Allocate scarce oracle budget by model
  uncertainty and committee disagreement.
- **FR-ML-5** Read features via the `core/` versioned feature store; a model
  records the `feature_version` it was trained against.
- **FR-ML-6** Attach as **plugins** on `core/` hooks; shipping without ML is a
  config change, not a code change.
- **FR-ML-7** Train and evaluate against the lab's cell/transform splits with a
  permanent blind holdout, plus external validation (WAVSEP / Juice Shop) (D10).
- **FR-ML-8** *(added CC-ML-0010, lane U4)* Model internals already written to the
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
  — `train_and_score` fits a fresh model per request and only ever writes the
  conformal calibration thresholds to `model.calibration`, never `_w`/`_b` — so the
  UI's "logistic weights diverging bar" panel (R-06) renders a documented
  not-available state rather than a value; making it real needs either a schema change
  (persist trained weights) or a training-time change (write on every `train_and_score`
  call), both out of scope for a read-only lane.

## 4. Non-functional requirements
- **NFR-ML-advisory** ML output is advisory: it can reorder, screen, or flag, but
  the oracle's verdict is final and independent.
- **NFR-ML-reproducible** Deterministic pipeline: fixed seeds, versioned features,
  versioned models, recorded metrics.
- **NFR-ML-no-leak** Train/test split prevents leakage across cells/transforms; the
  blind holdout is never trained on.
- **NFR-ML-calibrated** Classifier probabilities are calibrated; abstention is
  preferred to a confident wrong screen.

## 5. Interfaces and data contracts
Reads `attempt`/`candidate`/`flow` features and oracle `finding` labels (for
training); writes `candidate.score`, attempt scores/uncertainty, `model` rows
(versions, calibration). Never writes `finding`. Runs as `core/` plugins.

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
