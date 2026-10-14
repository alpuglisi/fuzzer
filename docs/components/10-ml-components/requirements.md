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
  scores + uncertainty, never labels. *(Note CC-ML-0019, BUG-0070: the conformal
  decision keeps its stated per-side bound — see FR-ML-18.)* *(Note CC-ML-0020:
  probability calibration is Platt scaling, opt-in — FR-ML-20.)* *(Not built, flagged
  CC-ML-0021: the **response-feature** classifier. No response features are linked to
  candidates or labels — greybox and fuzz-CSV `attempt` rows never set `candidate_id`,
  and crawl `page.status` is per page — and the only per-candidate responses are the
  oracle's own confirmation probes, which decide the label (D10: features must not
  encode the label). Unblocking change: candidate-linked attempts. The built
  classifier reads the candidate features, FR-ML-5.)*
- **FR-ML-2 (ranker, A.2)** Learning-to-rank over parameters/forms from candidate
  features; writes `candidate.score`; costs **zero** requests. *(CC-ML-0021: a pairwise
  learning-to-rank objective is built, opt-in — FR-ML-21.)* *(CC-ML-0023, BUG-0073:)*
  NDCG@k / precision@k **average over tied scores**, giving the exact expectation over
  every order of a tie: a constant scorer equals the random-order expectation, whatever
  the input order. Non-finite scores are refused. A metric and its seeded random control
  come from one function, `rank_train.evaluate_vs_random`, used by the trainer and the
  ML tab, on scores rounded to the stored 6 dp.
- **FR-ML-3 (anomaly, A.5)** ECOD / Isolation Forest tripwire over flows, later an
  XGBOD-style hybrid; tags anomalous responses. *(ECOD over candidates is wired as
  `fuzzlab auto --anomaly` and persisted per candidate — FR-ML-12. *(CC-ML-0021:)*
  Isolation Forest is built as an alternative detector — FR-ML-22 — and the tripwire
  over flows — FR-ML-23. Tagging anomalous *responses* inside a fuzzing loop is not.)*
- **FR-ML-4 (active learner, A.6.5)** Allocate scarce oracle budget by model
  uncertainty and committee disagreement. *(Wired as `fuzzlab auto --confirm-budget N`
  — FR-ML-11. The user chose `score`, most-likely-first, as the default, because it
  maximises findings per confirmation; uncertainty and committee remain available.)*
- **FR-ML-5** Read features via the `core/` versioned feature store; a model
  records the `feature_version` it was trained against. *(2026-10-14, CC-ML-0028: a
  candidate whose SQLi check was stopped by its cost cap is `inconclusive`, unlabelled,
  and never a training negative. Training rows recorded after this are not comparable
  with earlier ones, where such rows were `checked` negatives.)* *(Partially met, CC-ML-0021 /
  CC-CORE-0031: the candidate vector is computed by `core/features.extract_candidate_v1`
  (versioned, golden-pinned) and **recomputed on read**; `candidate.features_json` /
  `feature_version` stay unwritten. Flagged.)* *(CC-ML-0023 note:)* the `rules_fired`
  feature counts fired evaluations by `(run, path, param)` with no method. Keying it by
  method (BUG-0075's label fix) would change a feature's meaning, so it needs a
  `FEATURE_VERSION` bump. It is flagged as a versioned follow-up. Labels and seen keys
  are method-aware already (FR-ML-17).
- **FR-ML-6** Attach as **plugins** on `core/` hooks; shipping without ML is a
  config change, not a code change. *(Implemented CC-ML-0017 / CC-PLUG-0005 /
  CC-FUZZ-0050 / CC-UI-0041.)*
  - **Plugins:** the classifier, ranker and anomaly stages are `after_run` plugins, and
    the budget order is a `register_prioritizer` plugin (`fuzzlab/ml/plugins.py`). They
    run under the advisory write guard (FR-PLUG-6), one unit of work each (FR-PLUG-7),
    and are recorded on the run with their options.
  - **Attachment:** `fuzzlab auto`'s `--score/--rank/--anomaly/--confirm-budget` flags
    attach them. Nothing outside `fuzzlab/ml/` imports ML except through
    `plugins.optional.import_ml` (FR-PLUG-9).
  - **Without the package:** the scan, report and web app work (tested by simulated
    absence).
  - **No-ML build** *(verified CC-ML-0022, BUG-0068):* the switch is **two lines** —
    `[tool.setuptools.packages.find] exclude = ["fuzzlab.ml*"]` **and**
    `[tool.setuptools.exclude-package-data] "fuzzlab" = ["ml/*"]` (the recursive
    package-data rule would otherwise ship the ML modules as data). A real no-ML build
    passes the same checks as the simulated absence
    (`tests/test_no_ml.py::test_a_real_no_ml_build_passes_the_same_checks`).
- **FR-ML-7** Train and evaluate against the lab's cell/transform splits with a
  permanent blind holdout, plus external validation (WAVSEP / Juice Shop) (D10).
  *(Partially implemented, CC-ML-0020 — FR-ML-19:)* a deterministic, versioned,
  endpoint-keyed blind holdout, opt-in (`--holdout`), with sealed metrics. **Not built:**
  the lab's cell/transform split (the endpoint key is an interim choice behind
  `HOLDOUT_VERSION`) and external validation (WAVSEP / Juice Shop need those apps on
  the host).
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
  call), both out of scope for a read-only lane. *(Gap closed by CC-ML-0015 /
  CC-UI-0038: trained models are saved (FR-ML-13), and the panel shows the saved
  logistic model's standardised coefficients.)*
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
  covers the run, never "the newest row of any kind" (PA-0063, enforced by a
  source-scan guard test).

  *(Amended CC-ML-0023, BUG-0074.)* "Covers" means:
  - an int scope: that run;
  - a null scope (store-wide train): the runs it recorded in
    `calibration.scored_run_ids`;
  - a null scope without that list, or a legacy row with no scope key: a run only when
    that run holds a non-NULL score in the family's column.

  `select_latest` takes that column as a required keyword (`score_column`: `score` /
  `rank_score`). A model is never cited for a run it never scored.

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
    - ~~`localhost:8080` and `127.0.0.1:8080` count as different targets.~~
      *Resolved CC-ML-0018:* targets match as canonical origins (FR-ML-17).
    - ~~`no_confirmer` rows still train as negatives.~~ *Resolved CC-ML-0018:* they
      are unlabelled (FR-ML-17).
- **FR-ML-12 (anomaly persistence, CC-ML-0013)** `detect_anomalies(store, run_id,
  contamination)` scores **every** candidate of the run with ECOD (label-free, so
  budget-skipped ones included).
  - It writes `candidate.anomaly_score` / `anomaly_flag` and records
    `run_metrics.anomaly_flagged`.
  - `contamination` must be in (0, 0.5].
  - *(Amended CC-ML-0019, BUG-0070's sweep.)* At most `k = max(1, round(n·c))`
    candidates are flagged (`anomaly.flag_budget`), **whole tie groups only**: when the
    top tie group alone exceeds k, nothing is flagged. `detect_anomalies` records
    `anomaly_flag_budget` and `anomaly_flag_rule = 2`, and returns `flag_reason` when
    fewer than k were flagged. A run with stored flags and no `anomaly_flag_rule` used
    the earlier rule (ties could exceed k), and readers label it
    (`core.anomaly_flags.flag_note`).
  - A flag is relative to the candidates scored together. The CLI scores per run; a
    later store-wide call would overwrite per-run flags.
  - Advisory only: unusual is not vulnerable, and it writes no labels.
  - *(CC-ML-0021)* `method="ecod"` (default) or `"iforest"` (FR-ML-22); the anomaly
    stage's config records `method` only when not `ecod`, and readers show the method
    that wrote the stored flags ("unknown (assumed ECOD)" with no stage row).
  - *(CC-ML-0022, BUG-0069)* When it persists flags for a run it records
    `run_metrics.anomaly_feature_version` (the candidate feature version read); the
    read-only refit records nothing.
  - *(CC-ML-0024, BUG-0094)* `flag_top` counts tie groups in one pass,
    `O(n + u log u)`, with an operation-count bound under test. A non-finite score
    raises `ValueError` (contained as a FAILED stage); ECOD and Isolation Forest score
    finite features finitely.

- **FR-ML-13 (saved models, CC-ML-0015)** Every `model` row written by
  `train_and_score` / `train_and_rank` carries the trained model itself.
  - **Storage:** `params` holds canonical JSON (`fuzzlab.ml.persist.dumps_model`:
    sorted keys, compact separators, no NaN/Infinity) of the fitted state needed to
    predict, and `params_sha256` holds the sha256 of exactly that text.
  - **Kinds:** `logistic`, `gbt`, `prevalence`, `ranker` (with its vectorizer and nested
    logistic model) and `constant`. A hybrid classifier also stores its fitted ECOD.
  - *(CC-ML-0021)* A pairwise ranker's params carry `"objective": "pairwise"`; absent
    means pointwise, so a pointwise ranker's text and sha are unchanged (pinned by a
    recorded sha). Any other stored objective is refused.
  - *(CC-ML-0020)* **Format 2** = format 1 plus `"calibrator": {"kind": "platt", "a",
    "b"}`, written only when a `logistic` / `gbt` classifier is calibrated (finite `a > 0`
    and `b`; refused on any other kind). Without a calibrator the text — and so the sha
    — is exactly format 1. `LoadedModel.predict_proba` applies ECOD, the model, then the
    calibrator, so a reloaded model reproduces its stored scores.
  - **Loading:** `loads_model` rebuilds the model with exactly equal predictions, and
    fails closed with `ModelParamsError` on anything malformed (sha mismatch, non-JSON
    or pickle input, NaN/Infinity, runaway nesting, unknown format or kind, bad types or
    lengths, malformed trees, unsorted ECOD columns). It never uses
    `pickle`/`marshal`/`eval` (CWE-502).
  - *(CC-ML-0024, BUG-0095)* **Extremes and sizes are typed refusals too.**
    - An int too large for a float (`10**1000`), `1e400` and an int literal past
      Python's digit limit are `ModelParamsError`. `OverflowError` / `MemoryError` are
      wrapped at the boundary, and the validation predicates are total.
    - **Size limits, enforced on dump and load:**
      - `MAX_PARAMS_BYTES` = 8 MiB, checked before hashing or parsing;
      - `MAX_MODEL_ELEMENTS` = 2,000,000 values model-wide;
      - `MAX_TREES` = 1000 and `MAX_DEPTH` = 32.

      A hybrid model's stored ECOD columns bound it to about 35k training rows, and a
      larger one is refused at save time (stated limit).
  - *(CC-ML-0025, BUG-0103)* **Arithmetic closure.** `std ≥ STD_FLOOR` (1e-12): the
    trainer scales a near-constant feature by 1.0, and the loader rejects anything
    smaller. `LoadedModel` checks each standardised feature and logit, and every output
    (finite, a probability in [0, 1]), before returning any. Otherwise it raises
    `ModelParamsError`, and saved mode refuses.
  - **Identity, not authentication:** the sha detects corruption and pins identity;
    anyone who can write the store can recompute it.
  - **Compatibility:** `LoadedModel.check_compatible()` raises `ModelIncompatibleError`
    unless the stored `feature_version` and exact feature-name order match the current
    layout. Callers check it before using a saved model on new data.
  - **Readers:** `train.load_classifier` and `rank_train.load_ranker`, through
    `model_registry.params_for`. Rows trained before migration 14 load as `None`.
  - **Budget prioritizer:** not saved as a `model` row. Its `Prioritized.model_sha256`
    pins the model that ordered a budget: a ranker sha, or for `committee`
    `sha256("committee/1:" + member shas)`.
- **FR-ML-14 (train on earlier runs, CC-ML-0016)** `train_and_score` and
  `train_and_rank` take `train_on="run"` (the default, unchanged) or `"earlier"`.
  - **Training data.** `earlier` trains on the labelled, non-budget-skipped candidates
    of **earlier runs against the same target** (`dataset.target_of`, `build_dataset(…,
    before_run_id=run_id, target=…)`), each labelled from its own run. It scores or
    ranks **every** candidate of this run with that model.
  - **No leakage.** This run's labels are never read for training, model selection or
    calibration. The saved model's sha and training calibration do not change when this
    run, a later run, or another target's run changes.
  - **Refusal.** With no target row, or earlier data too thin for the trainers' gate,
    it refuses and writes nothing (no scores, model row or metrics). It never falls
    back to in-sample training. After a refusal this run has no model row of its own,
    so a store-wide or legacy row that covers every run may still be selected for its
    run page / ML tab (existing FR-ML-10 behaviour).
  - **Saved row.** Its calibration records `trained_on: "earlier"`, `train_run_ids`,
    `train_rows`, `train_positives`, `seen_fraction`, the seed, `k`, `min_*`,
    `feature_version`, `oof_scope: "earlier runs"` and the OOF numbers on the earlier
    data.
  - **Metrics.** `*_earlier` (out-of-fold on the earlier data) and `*_seen_fraction`.
    The `*_forward` metrics (this run's stored scores against its own oracle labels,
    after the fact) are written only when no label was budget-selected and both
    classes are present; otherwise the skip reason is recorded. No `run`-mode metric
    keys and no training curves are written.
  - **Wording.** The scores are "not trained on this run's labels", **not
    out-of-sample**: endpoints recur across runs of one target, and `seen_fraction` (the
    share of this run's `(path, param, category)` keys present in training) says how
    much.
  - **Conformal gate.** Calibrated on earlier out-of-fold scores, its error bound is
    nominal, valid only under exchangeability, which recurring endpoints and drift
    break.
  - Wired as `fuzzlab auto --train-on earlier` (FR-FUZZ-33). Making it the default
    waits on the on-host T5.5 / T7.4 runs.

- **FR-ML-15 (saved-model scoring, CC-ML-0018)** `train_and_score` /
  `train_and_rank(train_on="saved", model_id=None)` score or rank every candidate of a
  run with a saved earlier model, **without training**.
  - **Selection** (`model_registry.saved_source`): the original trained row, newest by
    scope run then id. Its scope must be an `int` (not a bool) naming an earlier run
    against this run's target (canonical, FR-ML-17). Its row must have params.
    - **Never selected:** store-wide, legacy, non-int and fallback rows. Copies written
      by saved mode itself are never chosen; a pinned copy resolves to its original. A
      pin must be of the right family.
  - **Refusal:** no target, no qualifying model, or a model that cannot be applied
    (corrupt params, or feature-layout drift via `check_compatible`). It writes nothing.
  - **Copy row.** A copy row scoped to the run (same params and sha) lets the run-scoped
    readers find it. It records `trained_on: "saved"`, `source_model_id`,
    `source_run_id`, `train_run_ids` (the original's when known), a recomputed
    `seen_fraction`, and the original's gate and OOF numbers under an explicit
    `oof_scope`.
  - **Metrics.** Forward metrics and `*_seen_fraction` are recorded as for `earlier`.
  - **Invariant (every model-writing mode):** the runs a model trained on are at or
    below its scope (`calibration.run_id`). This is what makes "scope is an earlier
    run" imply "never read this run's labels". Later work (holdout, calibration) must
    keep it.
- **FR-ML-16 (stored-score sources, CC-ML-0018, BUG-0067)**
  - **Columns.** `candidate.score` / `rank_score` are always the deployed model's scores
    (the saved model reproduces them, FR-ML-13). In run mode each labelled row also
    stores its **out-of-fold** score in `score_oof` / `rank_score_oof`. Every scoring
    pass writes or clears both columns for the rows it scores.
  - **`score_source`.** A model row records it: `oof-labelled`, `deploy`, `earlier` or
    `saved-model`; it is absent on legacy rows.
  - **Gate input.** A conformal gate judges only the score `train.gate_input` returns:
    a labelled run-mode row's `score_oof`; a row nobody checked, or an earlier- or
    saved-model score, as `score`; nothing for a legacy run-mode row except a
    budget-skipped one ("n/a (in-sample score)").
- **FR-ML-17 (unlabelled statuses; canonical targets, CC-ML-0018)**
  - **Unlabelled.** `oracle_status` in `core.oracle_status.UNLABELLED` (`skipped_budget`,
    `no_confirmer`, and `pending` — CC-CORE-0033: a row a crashed run never reached) is
    unlabelled: never trained or evaluated on, still scored. NULL
    (legacy) rows keep the old meaning, so a store written before this change mixes
    both semantics for no-confirmer categories.
  - **Method-aware labels** *(CC-ML-0023, BUG-0075)*. A candidate is positive when
    its run has a finding with the same path, param, category **and HTTP method**,
    normalised by `dataset.method_key` (upper-case; missing → GET). A finding with no
    recorded method matches any method. `candidate_keys` / `seen_fraction` include the
    method.
  - **Canonical targets.** Target matching for cross-run training and budget ordering
    compares `core.urls.canonical_origin`, so loopback aliases are one target and an
    unusable origin matches nothing.
- **FR-ML-18 (conformal gate rule, CC-ML-0019, BUG-0070)**
  - **Finite-sample split-conformal thresholds.** For n negative and m positive
    calibration scores, the gate flags `score > q_hi` (the `ceil((n+1)(1-α))`-th
    smallest negative) and drops `score < q_lo` (the `floor((m+1)α)`-th smallest
    positive), with ranks computed exactly from α's binary value.
  - **The bound.** On the calibration set at most α·n negatives are flagged and α·m
    positives dropped, ties included. On new exchangeable data each side errs with
    probability ≤ α.
  - **Small classes.** With fewer than `min_class_size(α) = ceil(1/α) - 1` rows of a
    class (9 at α = 0.1) the gate **never flags** (negatives) / **never drops**
    (positives). Readers say so, with the counts (`train.gate_notes`).
  - **Stored as non-strict thresholds.** `decide` keeps `>= t_hi` / `<= t_lo`, so
    stored rows keep their meaning: `t_hi = nextafter(q_hi, +inf)`, `t_lo =
    nextafter(q_lo, -inf)`; "never" is `nextafter(1.0, inf)` / `nextafter(0.0, -inf)`.
  - **Calibrated on stored values.** The gate is calibrated on the out-of-fold scores
    rounded as `score_oof` stores them.
  - **α** must be in (0, 1); `train_and_score` checks it before any write.
  - **Provenance.** New rows record `gate_rule: "split-conformal"`, `n_pos`, `n_neg`,
    and saved copies carry them. A row without `gate_rule` used the earlier rule (it
    could exceed α by about 1/n). It is applied as recorded and labelled
    "pre-BUG-0070" on the run page and in the ML tab, including the pooled view when
    any pooled gate lacks it.

- **FR-ML-19 (blind holdout, CC-ML-0020; FR-ML-7 partial)**
  - **Membership.** `ml/holdout.in_holdout(origin, endpoint, version=None)` —
    `sha256(salt | canonical origin | endpoint) / 2^256 < fraction` for the version's
    registered `(salt, fraction)` in `holdout.MEMBERSHIPS` (today `{1:
    ("fuzzlab-holdout-v1", 0.2)}`; `HOLDOUT_VERSION = 1`). A version bump adds a
    registry entry and never removes one (CC-ML-0024). The endpoint is `dataset.endpoint_key` (the group-k-fold group), so
    folds and the holdout never split an endpoint; a run with no target row is never
    held out.
  - **Guarantee (per model)** — *superseded by the per-target seal below
    (CC-ML-0024)*, which keeps it. With `holdout=True` the classifier, ranker (run,
    earlier, saved modes) and budget prioritizer never train on, select with or
    calibrate on a held-out endpoint, including earlier runs' held-out endpoints.
    Label-free components (the hybrid's ECOD) may see their features (transductive). A
    store-wide train with `holdout=True` raises `ValueError`.
  - **Seal per target (CC-ML-0024, BUG-0091).** Once any model of a target records a
    holdout, the target is **sealed**: `holdout.sealing_for_run` returns `("sealed",
    versions)`. Sealing never turns off.
    - From then on, every producer of a label-derived ML **evaluation** number for the
      target leaves out the rows held out under every version the target recorded,
      through one mechanism (`holdout.sealed_split`, and `held_ids` for readers):
      - **every trainer** applies an **implied holdout** without `--holdout`:
        `train_and_score` and `train_and_rank` in run and earlier mode (model
        selection and the ranker's `auto` objective included), the budget prioritizer
        and its committee, and `propose_queries`. The model records `holdout: {version,
        fraction, rows, "implied": true}`, sealed metrics are written as for an explicit
        holdout, and the CLI says "(implied: target sealed)";
      - **forward evaluations** (classifier and ranker, earlier and saved) read the
        public rows only (`train.forward_rows`);
      - **the ML tab's panels** (FR-UI, CC-UI-0050).
    - `train.metric_input(..., *, held)` takes `held` as a required keyword; an AST
      guard checks every call.
    - **Store-wide trains** leave out, per row, every sealed target's held rows. They
      write no sealed metrics, and their record says `"scope": "store"`.
    - **Unknown membership** (a recorded version not in the registry, or a fraction that
      differs) fails closed:
      - run-scoped trainers raise `holdout.SealingUnknown`;
      - earlier and saved modes refuse with the reason;
      - the prioritizer raises, never returning `None` ("confirm everything"), so the
        guarded wrapper keeps the budget cap and the run exits 1;
      - a store-wide train leaves that target's labelled rows out and records
        `excluded_unknown_targets`;
      - readers treat every row of the target as sealed, and the disagreement panel is
        unavailable.
    - **Behaviour change:** later runs of a sealed target train on about 20% fewer
      endpoints.
    - **Scope:** ML evaluation numbers only. Findings lists and counts, oracle coverage
      and anomaly flags are the product, and public by design.
    - **Residuals:**
      - forward metrics written before CC-ML-0024 are not rewritten;
      - a saved-mode copy carries its source's pre-seal numbers, which were already
        public.
    - **Tested** by flipping every sealed label and asserting every public number and
      every trained artefact is unchanged, with a control flip proving the check is
      live.
  - **Durable seals (CC-ML-0025, BUG-0104).**
    - Seals live in `holdout_seal` (FR-CORE-26). Every trainer that records a holdout
      writes one in its model row's transaction (`holdout.write_seal`; the plugin
      guard allows INSERT only, CC-PLUG-0009).
    - Readers use the table, plus calibration records above the backfill watermark.
    - A **present** `holdout` value is always a record, so a malformed one (`{}`,
      `None`, `False` …) is `UNKNOWN`, never read as "no seal".
    - An unparseable calibration at or below the watermark makes every target
      `UNKNOWN`, naming the model id.
  - **Stored facts.** Held-out labelled rows keep `score_oof` NULL; the model's
    calibration records `holdout: {version, fraction, rows}` (no label counts). A labelled
    row of such a model with no `score_oof` is held out, so `gate_input` judges it on
    `score` and `train.metric_input` leaves it out of every shown out-of-fold metric —
    decided from stored facts, so a version bump never re-classifies an old model's rows.
  - **Sealed metrics.** On the run's held-out labelled rows, from the deploy model's
    stored scores: classifier `ml_pr_auc_holdout`, `ml_pr_auc_prevalence_holdout`,
    `ml_mcc_holdout` (at the conformal flag threshold), `ml_precision_at_recall90_holdout`,
    `ml_brier_holdout`, `ml_ece_holdout` (the *measured* calibration); ranker
    `rank_ndcg_holdout`, `rank_precision_holdout` and their random controls; plus
    `holdout_rows` / `holdout_positives`. Written to `holdout_metric` (FR-CORE-19), never
    `run_metrics`, only when the held-out labels are two-class and nothing in the run was
    budget-skipped; otherwise (and for a fallback model) the reason is recorded. A saved
    model reports them only when its holdout record matches today's version and fraction.
  - **Staying blind.** The only reader is `fuzzlab reveal-holdout` (FR-FUZZ-36), which
    counts each reveal per version. Tuning on the holdout uses it up; bumping
    `HOLDOUT_VERSION` (new salt) refreshes it. Sealed against the toolkit's summary
    surfaces, not against inspection: the run page still lists stored scores and the
    SQLite file can be opened directly.
  - Opt-in; making it the default waits on the on-host T5.5 / T7.4 runs (thin data).
- **FR-ML-20 (probability calibration, CC-ML-0020; FR-ML-1)**
  - `train_and_score(calibrate="platt")` (run and earlier modes; `ValueError` with
    `saved`): `p = sigmoid(a·logit(s) + b)`, Newton-fitted with Platt's smoothed targets,
    `a > 0` (strictly monotone, never reorders or ties). Isotonic is not offered (ties
    break the gate's per-side bound and change PR-AUC; it overfits at lab sizes).
  - **Where each map goes.** `score_oof` holds **cross-fitted** calibrated out-of-fold
    scores (each fold through a Platt fitted on the other folds); the gate is calibrated
    on those (rounded as stored, PA-0069(3)). The Platt fitted on all out-of-fold scores
    is applied to the deploy `score` and saved (format 2). The gate therefore sees a
    mixture of nearly equal monotone maps; the per-side ≤ α invariant on the stored
    values is the check.
  - **Evidence.** The calibration records `calibrator`, `platt_a` / `platt_b`,
    `oof_pr_auc` (of the stored cross-fitted scores) and `oof_pr_auc_raw`, and
    `brier_oof_raw` / `brier_oof_calibrated`, `ece_oof_raw` / `ece_oof_calibrated`
    (`metrics.brier` / `metrics.ece`, the ML tab's binning). The deploy `score`'s
    calibration on new data is *expected*, not measured; the measured one is the sealed
    `ml_ece_holdout` / `ml_brier_holdout`.
  - **All-or-nothing.** A degenerate full or fold fit (one class, no convergence, `a ≤
    1e-9`) calibrates nothing: `calibrator: "none (degenerate fit)"`, format-1 model.
  - Opt-in (`--calibrate`, default `none`); the thin-data fallback is never calibrated.
- **FR-ML-21 (pairwise learning-to-rank, CC-ML-0021; FR-ML-2)**
  - `Ranker(objective="pairwise")` fits the logistic model on pair differences
    `x_pos − x_neg` (label 1) and `x_neg − x_pos` (label 0) over **every (positive,
    negative) pair in the training set** — run-wide, because consumers order the whole
    run (within-endpoint pairs would cancel every endpoint-level feature) — a seeded
    sample capped at 5000 pairs. With no pair it falls back to pointwise
    (`objective_used`). Pure Python, so a fit costs O(epochs × pairs × features).
  - `train_and_rank(objective="pointwise"|"pairwise"|"auto")` (run and earlier modes;
    `saved` applies whatever the saved ranker is). `pointwise` is the default and
    unchanged. `auto` deploys the better **run-wide** out-of-fold NDCG, ties to
    pointwise, recorded `selection_biased: true` (with `--holdout` the sealed number is
    the honest one).
  - **Run-wide metrics per fold.** `rank_ndcg_global` / `rank_precision_global` are
    computed within each fold's test set and averaged — fold models' scales differ, so
    pooled out-of-fold scores are never compared across folds. The ML tab shows that
    stored number ("per-fold scales — not pooled"); per-endpoint NDCG stays valid
    (an endpoint is never split across folds).
  - **No uncertainty.** A pairwise score is not a probability: `rank_uncertainty` is
    NULL and the ML tab says "uncertainty n/a (pairwise)".
  - **The budget prioritizer stays pointwise.** *(CC-ML-0022)* `Prioritized` carries the
    `feature_version` its order model read (none for `random`), recorded by the pipeline
    for the report (BUG-0069). `detect_flow_anomalies` likewise records
    `flow_anomaly_feature_version`.
- **FR-ML-22 (Isolation Forest, CC-ML-0021; FR-ML-3)**
  - `anomaly.IsolationForest(n_trees=100, max_samples=256, seed)`: seeded random
    isolation trees to depth `ceil(log2 ψ)`, splits only on features with range > 0, a
    node with none is a leaf; score `2^(−E[h]/c(ψ))` in (0, 1), `c(n)` with the exact
    harmonic number. Deterministic per `(seed, n_trees, max_samples)`.
  - With ≤ 2 rows every score is 0.5; `detect_anomalies(method="iforest")` then flags
    nothing (budget 0, reason "too few candidates to isolate").
  - ECOD stays the default and the hybrid's feature. Detector state is not persisted
    (scores are written per run).
- **FR-ML-23 (flow anomalies, CC-ML-0021; FR-ML-3)**
  - `ml/flow_anomaly.py`: a versioned vector per in-scope flow (`FLOW_FEATURE_VERSION =
    1`): status class (+ missing), `log1p` elapsed (+ missing), `log1p` decoded request /
    response body length from `LENGTH(data)` in SQL (+ missing — body content is never
    loaded), path depth, query-parameter count, POST, protocol one-hots (`ws`, `h2`,
    `http/1.1`; NULL counts as `http/1.1`).
  - `detect_flow_anomalies(store, run_id, method, contamination, seed)` fits **per host**
    (a host with < 3 flows is not scored), flags with `flag_top`, writes
    `flow.anomaly_score` / `anomaly_flag` (migration 18) and clears every other flow of
    the run in the same pass. `in_scope = 0` flows are ignored; NULL (HTTP client) is in
    scope.
  - Contamination is a **forced per-host fraction**: up to that share of every scored
    host's flows is flagged, even on a clean host — "most unusual", not "malicious".
  - Advisory only; no labels. No UI panel yet (the proxy history page could show it).

- **FR-ML-24 (evidence quarantine, CC-ML-0025, BUG-0107)**
  - `build_dataset` parses evidence with `core.evidence.parse_evidence`. An unreadable
    row is **quarantined**: skipped and counted in `Dataset.quarantined` /
    `scope_total`, never replaced by defaults.
  - **Trainers refuse** (`quarantine_refusal`: run mode raises `DatasetEvidenceError`,
    earlier mode refuses with the reason, the prioritizer and `propose_queries` raise)
    when either holds:
    - a run with a quarantined row has a finding no readable candidate matches (a label
      may be lost);
    - more than 5% of the scope's candidates are quarantined.
  - **Otherwise they record** `quarantined_rows` in the model calibration, the result
    and `run_metrics.ml_quarantined_rows`, and the CLI prints a line.
  - Quarantined ids are scored by no model, and the prioritizer orders them after the
    scored candidates.

## 4. Non-functional requirements
- **NFR-ML-advisory** ML output is advisory: it can reorder, screen, or flag, but
  the oracle's verdict is final and independent.
  - Enforced by: the plugin write guard and the oracle as the only writer — `tests/test_plugins_post_run.py::test_guard_blocks_each_label_write_vector`, `tests/test_ml_anomaly.py::test_detect_anomalies_is_advisory`, `tests/test_plugins.py::test_oracle_is_the_only_plugin_path_to_a_writer`
- **NFR-ML-reproducible** *(Amended CC-ML-0015: models are now versioned **and
  stored**, so a model reproduces from its row, sha-pinned. Note CC-ML-0018: the
  run-mode out-of-fold columns reproduce by deterministic, seeded re-training, not by
  loading the model.)* Deterministic pipeline: fixed seeds, versioned features,
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
  - *(Note, CC-ML-0016.)* `train_on="earlier"` scores a run with a model whose
    training, selection and calibration never read that run's labels, pinned by
    model-identity tests. Such scores are labelled "not trained on this run's labels",
    not out-of-sample (FR-ML-14).
- **NFR-ML-calibrated** Classifier probabilities are calibrated; abstention is
  preferred to a confident wrong screen.

## 5. Interfaces and data contracts
Reads `attempt`/`candidate`/`flow` features and oracle `finding` labels (for
training); writes `candidate.score`, attempt scores/uncertainty, `model` rows
(versions, calibration — including `run_id` scope and `oof_*` metrics, read back only
through `model_registry.select_latest`, FR-ML-10). Never writes `finding`. Attaches as plugins on the
`after_run` / `register_prioritizer` hooks under the advisory write guard (FR-ML-6); the rest of
the toolkit reaches it only through `fuzzlab.plugins.optional.import_ml`.
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
