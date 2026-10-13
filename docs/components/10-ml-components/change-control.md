# ML Components — Change Control Log

Component code: **ML**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-ML-0014 — Store-wide dataset keys labels and rule counts by run (BUG-0065) (2026-10-13)
- Change: `ml/dataset.py::build_dataset` builds `positives` from
  `(run_id, path, param, category)` and `fired` from `(run_id, path, param)`. A
  candidate therefore takes its label and its `rules_fired` from its own run only,
  never from another run's (or another target's) findings or evaluations.
  - Per-run calls (`run_id=N`) are unchanged.
  - Store-wide calls (`run_id=None`: the ML tab's default view, the store-wide trainers,
    `propose_queries(None)`) stop leaking labels and stop inflating counts.
- Impact: the ML tab's all-runs metrics change on multi-run stores, becoming correct.
  Per-run behavior is identical. No schema change.
- Risk: low. Fixes a silent label leak. Existing tests use single-run stores, and a new
  multi-run regression covers the fix.
- Deliverables:
  - [ ] Run-keyed `positives` / `fired` — done
  - [ ] Regression: two copies of `_seed_rich` where run 2 has fewer findings. Store-wide
    labels equal the per-run labels concatenated, and `rules_fired` equals the
    single-run value. Both fail on the old code — done
  - [ ] Full bug protocol: ERROR_LOG, BUG-0065, PA-0066, recurrence review against
    BUG-0061/PA-0063 (cross-run scope) — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; the budget-ordering objective was put to the user, who chose `score` as the default; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — the two-run and two-target regressions pass, and each fails with either half of the old keying restored (mutation-checked: label key, fired key). Store-wide dataset == per-run datasets concatenated, labels and features. Full suite: see the follow-up record.

### CC-ML-0013 — Budget prioritizer trained on earlier same-target runs; skipped candidates scored but never trained on; anomaly scores persisted (2026-10-13)
- Change:
  - **`ml/dataset.py`:**
    - `Dataset` gains `labelled: list[bool]`.
    - `build_dataset(store, run_id=None, *, include_unlabelled=False, before_run_id=None,
      target=None)` gains three filters:
      - Rows with `oracle_status = 'skipped_budget'` are excluded by default, because
        the oracle never looked at them. They are kept, with `labelled=False`, when
        `include_unlabelled=True`.
      - `before_run_id` restricts to `run.id < before_run_id`.
      - `target` restricts to runs whose pipeline `target.base_url` equals `target`.
        A run with no `target` row (one that is not a pipeline run) never matches. The
        URL is compared exactly as the pipeline recorded it (`scheme://netloc`), so
        `localhost:8080` and `127.0.0.1:8080` count as different targets. That is
        recorded in FR-ML-11; loopback-alias normalisation is not done here.
    - Existing calls are unchanged, and with no skipped rows the result is identical.
  - **Trainers (`train.py::train_and_score`, `rank_train.py::train_and_rank`):** fit,
    evaluate and calibrate on the labelled dataset, then write `score` / `rank_score`
    for **every** row of the run (`include_unlabelled=True`, same fitted model).
    Skipped candidates therefore get advisory scores.
    - With `hybrid=True`, ECOD is fitted **once**, on the all-rows set (it is
      label-free), and the same fitted detector augments both the training rows and the
      scored rows. The model is never applied to a feature computed differently from
      the one it was trained on.
  - **`ml/active.py`:** `Prioritized(order, method, training_rows, training_positives)`
    and `prioritize(store, run_id, candidate_ids, *, method="score", n_members=5,
    seed=0, min_rows=20, min_positives=5, min_groups=2) -> Prioritized | None`.
    - It trains only on **earlier runs against the same target**
      (`before_run_id=run_id`, `target=<this run's target.base_url>`, which the
      pipeline writes before the prioritizer is called), never on the current run.
    - It returns `None` (meaning "confirm all") on thin data: fewer than `min_rows` rows,
      fewer than `min_positives` positives, no negatives, or fewer than `min_groups`
      endpoints. `method="random"` needs no training data and never returns `None`.
    - The current run's features come from `build_dataset(store, run_id,
      include_unlabelled=True)`. These are audit-time features only (rules fired, sink
      context, parameter/path text), so no label leaks in.
    - Orderings:
      - `score`: one `Ranker`, highest score first.
      - `uncertainty`: one `Ranker`, highest `uncertainty(score)` first.
      - `committee`: a bootstrap `Committee`, highest disagreement first.
      - `random`: `random.Random(seed)` shuffle.
      - Ties keep candidate-id order.
    - `propose_queries` uses `include_unlabelled=True`.
  - **`ml/anomaly.py::detect_anomalies(store, run_id=None, contamination=0.1, *,
    persist=True)`:**
    - Uses `include_unlabelled=True`; ECOD is label-free.
    - Recorded limitation (FR-ML-12): `anomaly_flag` is relative to the set of
      candidates scored together. A later store-wide call (`run_id=None`) would
      overwrite per-run flags. The CLI always passes `run_id`.
    - Validates `contamination` to the range (0, 0.5].
    - When `persist` is set, writes each row's `anomaly_score` / `anomaly_flag`. It
      still records `run_metrics.anomaly_flagged`.
  - **`web/mlview.py` (read-only):** `anomaly_panel` and `disagreement_panel` use
    `include_unlabelled=True`, so they cover the same population as `detect_anomalies`
    and the query queue. The classifier and ranker metric panels stay on labelled rows.
- PA-0063(2) reader audit. Every `FROM candidate` reader in `fuzzlab/`:
  - `pipeline.py:86` is rewritten (CC-FUZZ-0048).
  - `dataset.py:88` adds the filter.
  - `mlview.py:146` and `:186` join scores onto the labelled dataset. Metrics are
    computed on labelled rows, which is correct.
  - `mlview.py:230` (conformal split), `results.py:58` (top scored), `diagnostics.py:181`
    (score histogram) now include skipped candidates' advisory scores. That is
    intended: they are the ones awaiting triage.
  - `report.py:48` (candidate count) and `:73` (feature versions) are unaffected. The
    report also lists the new `pipeline_oracle_*` metrics.
  - `active.py:98` (`rank_uncertainty`) and `rank_train.py:37` (texts by id) are
    unaffected.
- Recorded limitation: `candidate_text` includes the path (`text_features.py:24-30`), so
  a prior-run model partly memorizes which endpoints were vulnerable. That is useful for
  re-testing the same app. T7.4's "positives per confirmation vs random" must therefore
  be measured on held-out endpoints (PA-0017/PA-0064), recorded in FR-ML-11 and in
  ON_HOST_TASKS' T7.4 note.
- Divergence noted in FR-ML-11: `no_confirmer` rows still train as negatives (unchanged),
  while `pipeline_oracle_rejected` now excludes them. Flagged for a decision, not
  changed.
- Impact: FUZZ calls `prioritize` through an injected callable. CORE supplies the
  columns. FR-ML-11 (prioritizer, scope, limitation), FR-ML-12 (anomaly persistence),
  FR-ML-3 and FR-ML-4 annotated "wired".
- Risk: medium-low. Fallbacks keep today's behavior. Cross-run use depends on
  CC-ML-0014.
- Deliverables:
  - [ ] `build_dataset` filters + `labelled` — done
  - [ ] Trainers score every row (including a `hybrid=True` test proving the scored
    rows' anomaly feature equals the training rows') — done
  - [ ] `prioritize` (4 methods) + `Prioritized`; `propose_queries` unlabelled — done
  - [ ] `detect_anomalies` persistence + validation; mlview anomaly/disagreement unlabelled — done
  - [ ] Tests:
    - skipped rows are excluded from training, included with `include_unlabelled`, and
      still scored or ranked;
    - `before_run_id` and `target` filters work;
    - `prioritize` returns None for: no earlier runs, a later run only, another target
      only, thin data, one class, one endpoint;
    - current-run findings do not change the order;
    - each method is deterministic, returns exactly the given ids, and `score` puts the
      highest-scored first;
    - anomaly values are persisted, the flagged count equals the metric, and
      contamination is validated — done
  - [ ] ML requirements updated — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; the budget-ordering objective was put to the user, who chose `score` as the default; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — `tests/test_ml_budget_and_scope.py` 20 passed (skipped rows excluded from training / included and labelled False on request / still scored and ranked; one ECOD fit for `hybrid`; `prioritize` falls back for no-earlier, later-only, other-target, one-class data; all four methods deterministic over exactly the given ids; `score` puts the earlier-runs' vulnerable shape first; current-run labels never change the order; committee queue and anomaly panel cover skipped rows; anomaly values persisted and equal to the metric; contamination validated). Mutation-checked: training on the current run, ignoring the target, not excluding skipped rows, scoring labelled rows only, a second ECOD fit, and not persisting anomaly values each make a test fail. Full suite: see the follow-up record.

### CC-ML-0012 — Out-of-fold evaluation can never be in-sample (BUG-0062) (2026-10-13)
- Change:
  - `fuzzlab/ml/metrics.py::group_kfold`: `k < 2` or fewer than 2 distinct groups yields
    **no folds** (was one `(idx, idx)` fold — train == test, contradicting its own
    "never splitting a group" contract). Docstring states it.
  - `train.py::train_and_score` / `rank_train.py::train_and_rank`: new keyword
    `min_groups: int = 2`; `groups = len(set(ds.groups))` computed **before** the gate and
    in the result on every path; gate becomes `n < min_rows or pos < min_positives or
    (n - pos) < 1 or groups < max(2, min_groups) or k < 2` -> the existing fallback (no
    `ml_pr_auc*`/`rank_*` run_metrics, no OOF calibration keys, `*-fallback` model row).
    Rationale for 2: the correctness floor — the least that makes any held-out split
    exist, which is exactly what the bug violated. Quality floors (positives spread across
    groups; labgen's `MIN_GROUPS_FOR_GATE = 6` serves a permutation test, a different
    purpose) are separate policy like `min_positives`, left to callers and the on-host
    T5.5/T7.4 exits; a one-class training fold yields a weak model, not leakage.
  - Both `_oof_scores` raise `ValueError` unless every row index was scored exactly once
    across the folds (fail closed: an unscored row would silently stay 0.0 and skew
    PR-AUC / conformal thresholds). Unreachable through the public trainers once the gate
    holds; guards direct callers.
- Impact (other components / project): new keyword + `groups` result key; the OOF numbers
  the trainers now also write into calibration (`CC-ML-0011`) inherit this guarantee.
  Behavior changes only for one-endpoint datasets and `k < 2` calls: documented fallback
  instead of in-sample metrics labelled out-of-fold and a possibly false
  `beats_baselines` (the T5.5/T7.4 exit signals, `docs/ON_HOST_TASKS.md`). labgen's
  grouped CV (sklearn `StratifiedGroupKFold` + `MIN_GROUPS_FOR_GATE`) already correct,
  untouched. Existing `group_kfold` tests use 10–24 groups, unaffected. UI: CC-UI-0035.
- Risk (level; mitigation or accepted-risk justification): low. Only non-test callers of
  `group_kfold` are the two `_oof_scores`; the re-exported contract becomes stricter.
- Deliverables:
  - [ ] `group_kfold` degenerate branch yields nothing — done
  - [ ] `min_groups` + `k<2` gate, `groups` in result (both trainers) — done
  - [ ] exactly-once check in both `_oof_scores` — done
  - [ ] tests: `group_kfold` 1 group / k=1 / k=0 yields nothing; randomized property — every fold non-empty, disjoint train/test groups, each row tested exactly once; both trainers on >=20 rows / >=5 positives all on one path -> `fallback=True`, `groups == 1`, no OOF metric rows or calibration keys; both trainers with `k=1` on 10 groups -> fallback, no raise; `_oof_scores` raises on a one-group dataset — done
  - [ ] `requirements.md` NFR-ML-no-leak amended — done
- Implementation divergence (reflected back per the review gate): the exactly-once check is one shared helper, `fuzzlab.ml.metrics.oof_folds` (also raising on a fold whose train and test overlap), called by both `_oof_scores` instead of being duplicated in each (PA-0003). A guard test, `tests/test_ml_oof.py::test_no_out_of_fold_scorer_bypasses_oof_folds`, fails if any module outside `metrics.py` calls `group_kfold` directly (PA-0064). Tests live in `tests/test_ml_oof.py`.
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, four rounds v1→v4; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — `tests/test_ml_oof.py` 19 passed; with `group_kfold`'s old `(idx, idx)` branch restored, 7 of them fail (degenerate-branch, partition, fail-closed). The one-endpoint / `k=1` reproductions now take the documented fallback with `groups` reported and no OOF metrics. Related files (`tests/test_ml*.py`, `test_gbt.py`, `test_web_ml.py`, `test_web_results.py`, `test_report.py`, `test_web_diagnostics.py`, `test_auto*.py`): 160 passed. Full suite (2026-10-13, whole `tests/`): 2801 passed, 33 failed, 67 skipped, 9 xfailed. All 33 failures are labgen `--check`/fingerprint-gate tests that fail identically on an `origin/main` @ `0800e42` worktree (re-run: the same 33 fail) because this environment lacks `scipy`/`scikit-learn` (the declared `labgen`/`labgen-stats` extras) and the `gitleaks` binary — environmental, not caused by this change. Browser tests were among the skips (Playwright not yet installed when that run started); see CC-UI-0036 for the browser-verified run.

### CC-ML-0011 — One run-scoped reader for the shared `model` table; OOF metrics stored on the model row (BUG-0061) (2026-10-13)
- Change:
  - **New `fuzzlab/ml/model_registry.py`** — the one place the "which `model` row is the
    deployed model of a family for a run" convention lives (PA-0003/PA-0021).
    `select_latest(store, names, run_id=None) -> tuple[sqlite3.Row, dict] | None`: walks
    `SELECT id, name, version, feature_version, calibration FROM model WHERE name IN (...)
    ORDER BY id DESC` and returns the first row whose scope covers `run_id`, with its
    calibration JSON parsed (bad/absent JSON -> `{}`). Scope covers when `run_id is None`,
    or calibration `run_id` equals it, or calibration `run_id` is null (store-wide train,
    which re-scores every run's candidates), or the key is absent (legacy row written
    before this change — its scope is unknowable, old behavior kept). It is the only
    `FROM model ... ORDER BY id DESC` query in `fuzzlab/`.
  - `fuzzlab/ml/train.py`: `PREVALENCE_FALLBACK_NAME = "prevalence-fallback"` (replaces
    the inline literal); `CLASSIFIER_MODEL_NAMES = tuple(_MODELS) + (PREVALENCE_FALLBACK_NAME,)`
    (derived from `_MODELS` — PA-0001/PA-0027); the `calibration` JSON `train_and_score`
    writes gains `run_id` (null for a store-wide train) and, on a non-fallback train, the
    OOF evaluation it already computes: `oof_pr_auc`, `oof_pr_auc_prevalence`,
    `oof_pr_auc_sigma` (same values as the `ml_pr_auc*` `run_metrics` rows, which are
    still written unchanged as the T5.5 exit signal). New plain dataclass
    `ClassifierModel(name, version, feature_version, calibration: dict, gate:
    ConformalGate | None)` and `latest_classifier(store, run_id=None)` =
    `select_latest(store, CLASSIFIER_MODEL_NAMES, run_id)` + gate built only when
    `t_lo`/`t_hi` are present.
  - `fuzzlab/ml/rank_train.py`: `RANKER_NAME = "ranker"`, `RANK_FALLBACK_NAME =
    "rank-prevalence-fallback"`, `RANKER_MODEL_NAMES` (replace literals at
    `rank_train.py:65,77`); the ranker's `calibration` gains `run_id` and, on a
    non-fallback train, `oof_ndcg`, `oof_precision`, `oof_ndcg_random`,
    `oof_precision_random` (the `at_k` they were computed at is the existing `at_k`
    key); `run_metrics` `rank_*` rows unchanged (T7.4 exit signal). New
    `latest_ranker(store, run_id=None) -> (row, calibration) | None` =
    `select_latest(store, RANKER_MODEL_NAMES, run_id)`.
- Impact (other components / project): UI readers switch to these (`CC-UI-0034`,
  `CC-UI-0035`). Unchanged readers, checked: `report/report.py:65` (`GROUP BY name`,
  per-family correct), `web/diagnostics.py:219-222` (lists every row, passes calibration
  JSON through). Calibration JSON gains keys; every existing reader ignores unknown keys.
  `model_registry` imports nothing from `train`/`rank_train` (no cycle). FR-ML-10 added.
- Risk (level; mitigation or accepted-risk justification): low. Read helpers + extra JSON
  keys; nothing trained/scored/written changes otherwise. New classifier kinds in
  `_MODELS` are picked up automatically. Legacy rows keep today's behavior (accepted).
- Deliverables:
  - [ ] `fuzzlab/ml/model_registry.py::select_latest` — done
  - [ ] `train.py`: constants, `run_id` + OOF keys in calibration, `ClassifierModel`, `latest_classifier` — done
  - [ ] `rank_train.py`: constants, `run_id` + OOF keys in calibration, `latest_ranker` — done
  - [ ] `tests/test_ml_model_selection.py`: `select_latest` scope rules (per-run, store-wide null covers all, legacy absent key covers all, newest covering row wins, bad JSON -> `{}`, no matching family -> `None`); classifier then ranker -> `latest_classifier` returns the classifier with a gate; ranker-only -> `None`; two runs -> each run gets its own row, `None` -> newest; `prevalence-fallback` -> `gate is None`, no OOF keys; OOF keys equal the returned `pr_auc`/`ndcg`; `CLASSIFIER_MODEL_NAMES` derived from `_MODELS` and disjoint from `RANKER_MODEL_NAMES` — done
  - [ ] guard test (same file): `ast`-walk `fuzzlab/**/*.py`, collect string `Constant`s and `JoinedStr`s (constant parts joined, formatted parts -> placeholder); flag a string matching `\bFROM\s+model\b` AND (`\bDESC\b` or `\bLIMIT\s+1\b`) AND NOT `\bWHERE\s+name\b`, exempting only `model_registry.select_latest`'s body; plus `latest_classifier`/`latest_ranker` contain no `FROM model` string. Proven first on fixtures (PA-0034(2)/PA-0022): must trip — the old one-line query, a split-literal variant, an f-string variant; must not — diagnostics timeline query, report.py's `GROUP BY` query, `_next_version`'s `WHERE name=?`, a `FROM model_variant ... DESC` string — done
  - [ ] `requirements.md` FR-ML-10 — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, four rounds v1→v4; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — `tests/test_ml_model_selection.py` 14 passed; with the old inline query restored in `results.py`, the two regression tests and the source-scan guard fail. Related files: 160 passed. Full suite (2026-10-13, whole `tests/`): 2801 passed, 33 failed, 67 skipped, 9 xfailed. All 33 failures are labgen `--check`/fingerprint-gate tests that fail identically on an `origin/main` @ `0800e42` worktree (re-run: the same 33 fail) because this environment lacks `scipy`/`scikit-learn` (the declared `labgen`/`labgen-stats` extras) and the `gitleaks` binary — environmental, not caused by this change. Browser tests were among the skips (Playwright not yet installed when that run started); see CC-UI-0036 for the browser-verified run.

### CC-ML-0010 — Lane U4: read-only ML-internals surfacing for the web panel's ML tab (2026-09-22)
- Change: no change to any ML training/scoring/inference code in this component — this
  entry records the **consumer-side** change: `fuzzlab/web/mlview.py` (component #12,
  see `CC-UI-0031` for the full detail) reads this component's stored outputs
  (`candidate.score`/`rank_score`/`rank_uncertainty`, `model.calibration`,
  `bandit_posteriors`, `payload_variant`) and reuses its pure-Python helpers
  (`fuzzlab.ml.metrics.pr_auc`, `fuzzlab.ml.ranking.mean_ndcg_at_k`/
  `mean_precision_at_k`, `fuzzlab.ml.conformal.ConformalGate`, `fuzzlab.ml.anomaly.ECOD`/
  `flag_top`, `fuzzlab.ml.active.Committee`/`disagreement`) to render the ML tab's
  advisory panels. Recorded here (dual bookkeeping, per this lane's reserved numbers)
  because it establishes a **new read-only consumer** of this component's contract and
  surfaces a genuine gap against it.
- Impact (other components / project): none on this component's own behavior — every
  `fuzzlab.ml.*` function keeps its existing signature and contract (`NFR-ML-advisory`,
  `NFR-ML-no-leak`, `NFR-ML-calibrated` all unaffected). The gap: `FR-ML-9` (new,
  `requirements.md`) documents that the logistic classifier's trained coefficients
  (`_w`/`_b`) are never written to the store — `fuzzlab.ml.train.train_and_score`
  fits a fresh model in-memory per call and persists only the conformal calibration
  thresholds to `model.calibration` — so the UI's "logistic weights diverging bar"
  panel (R-06) cannot be populated from stored data and instead renders a documented
  not-available state. Closing that gap for real is a future ML-component change
  (persist `_w`/`_b`, e.g. as a JSON column or blob on `model`), not something this
  read-only web lane does on its own initiative.
- Risk (level; mitigation): none to this component — no code here changed. The
  read-only consumer's own risk (a synchronous bootstrap-committee fit inside a web
  `GET` handler, capped and exception-guarded) is assessed under `CC-UI-0031`.
- Deliverables:
  - [x] Confirmed every `mlview.py` panel function reads this component's existing
    contract without needing a new column/table — done (one exception recorded as
    the FR-ML-9 gap above, not a deliverable of this lane).
  - [x] `requirements.md` FR-ML-9 added, documenting the read-only consumer and the
    weights gap — done.
  - [ ] Persist trained logistic-regression coefficients to the store, closing the
    weights-panel gap — future ML-component work, not this lane's scope.
- Effectiveness (assessed 2026-09-22): effective as a record — the gap is named with
  its root cause and the exact code path, so a future change closing it knows what to
  touch (`fuzzlab/ml/train.py::train_and_score`) and which UI panel starts working the
  moment it does (no web-side change needed then, `mlview.py`'s panel just needs the
  new field wired in).
### CC-ML-0009 — GBT/logistic per-step metric_series emitter (build lane B0, Wave 1b) (2026-09-22)
- Change: wired the classifier training loops into B0-table's cross-run
  `metric_series` sink (`CC-CORE-0018`, `fuzzlab/core/store.py`'s
  `log_scalar`/`MetricLogger`). `GradientBoostedTrees.fit` (`fuzzlab/ml/gbt.py`)
  gained an optional `on_round(step, {"train/loss", "train/mean_abs_update"})`
  callback fired once per boosting round; `LogisticRegression.fit`
  (`fuzzlab/ml/logistic.py`) gained an optional `on_epoch(step, {"train/loss",
  "train/l2_norm"})` callback fired once per gradient-descent epoch. Both
  models stay dependency-free of `core/store` — the callback is a plain
  `Callable`, not a `MetricLogger` reference, so `fuzzlab/ml/gbt.py`/
  `logistic.py` do not import `core.store`. `fuzzlab/ml/train.py` adds
  `_fit_with_metrics(model, X, y, store, run_id, name)`, which wraps the
  deploy fit (the final "fit on all data" call in `train_and_score`, not the
  per-fold out-of-fold fits used only for model selection/calibration) in a
  `MetricLogger(store, run_id, source)` when `run_id is not None`, with
  `source="gbt"` or `source="logreg"` per the B0-table schema note (`source`
  = subsystem bucket mirroring existing prefixes). With `run_id is None`, or
  for the `prevalence-fallback` path (no GBT/logistic model is fit at all),
  no rows are written — purely additive, opt-in instrumentation.
- Impact (other components / project): none on CORE (consumes B0-table's
  already-landed, unmodified `log_scalar`/`MetricLogger` API/schema — no
  migration change). No change to `train_and_score`'s return value, to
  `candidate.score`/`model`/`run_metrics` writes, or to model outputs
  (`predict_proba` is bit-identical with/without the callback — see the
  `*_fit_without_on_*_is_unaffected` tests). Populates `metric_series` for
  U4 (ML tab) and U5 (metric_series/store-exploration tab), both later Wave-2
  UI lanes that read this table; no coordination needed since those lanes
  only read.
- Risk (level; mitigation): low — additive-only optional callback parameters,
  no existing call site invoked without `run_id` changes behavior, and the
  callback path is exercised by dedicated tests. Mitigated by 8 new tests:
  `tests/test_ml.py`'s `test_logistic_on_epoch_callback_fires_once_per_epoch_
  with_finite_loss`, `test_logistic_fit_without_on_epoch_is_unaffected`,
  `test_gbt_on_round_callback_fires_once_per_round_with_finite_loss`,
  `test_gbt_fit_without_on_round_is_unaffected` (unit-level: callback arity,
  step sequencing, finite values, and non-interference with `predict_proba`);
  `tests/test_ml_train.py`'s `test_train_and_score_logistic_emits_metric_
  series`, `test_train_and_score_gbt_emits_metric_series` (end-to-end: real
  rows land in `metric_series` with the right `source`/`key`/monotonic
  `step`), `test_train_and_score_no_run_id_emits_no_metric_series`,
  `test_train_and_score_fallback_emits_no_metric_series` (negative cases —
  no orphaned rows). Full suite green; see project CHANGELOG for pass/skip
  counts at time of landing.
- Deliverables:
  - [x] `GradientBoostedTrees.fit(on_round=...)` emitting `train/loss` +
    `train/mean_abs_update` — done.
  - [x] `LogisticRegression.fit(on_epoch=...)` emitting `train/loss` +
    `train/l2_norm` — done.
  - [x] `fuzzlab/ml/train.py::_fit_with_metrics` wiring the deploy fit to a
    `MetricLogger` with `source="gbt"`/`"logreg"` — done.
  - [x] Tests confirming rows land in `metric_series` — done.
  - [ ] U4/U5 UI consumption of these rows — out of scope for this lane (later
    Wave-2 UI lanes).
- Effectiveness (assessed 2026-09-22): effective in tests — training curves
  for both models are now recorded per-step in `metric_series` under the
  correct `source`, with no change to deployed model behavior or scores;
  real-world usefulness (debugging convergence, spotting overfitting) is
  best judged once U4/U5 render this data, which is out of this lane's scope.

### CC-ML-0008 — Anomaly detector (ECOD) + XGBOD-style hybrid (T10.3) (2026-09-21)
- Change: added the anomaly-detection tripwire (A.5). `fuzzlab/ml/anomaly.py::ECOD` is a
  parameter-free, pure-Python Empirical-CDF outlier detector (per-feature left/right/skew-
  auto tail aggregates, score = their max; no numpy/sklearn, no labels). `flag_top`
  flags the top contamination fraction; `augment` appends the ECOD score as an extra
  feature (the XGBOD-style hybrid); `detect_anomalies(store, run_id)` fits over the run's
  candidate vectors, flags outliers, and records `anomaly_flagged` in `run_metrics`.
  `train_and_score(hybrid=True)` augments the classifier's features with the (label-free)
  anomaly score.
- Impact (other components / project): a tripwire over the store's feature vectors and a
  hybrid feature for the Phase 5 classifier — the last ML piece. **Advisory only**: it
  produces scores/flags and a feature, never `finding` labels (the oracle/advisory split
  holds). No schema change (records a metric; hybrid appends an in-memory feature). No new
  dependency.
- Risk (level; mitigation): low — pure logic, advisory, no labels. Mitigated by 8 tests
  (`tests/test_ml_anomaly.py`): same-direction outliers score highest; determinism;
  empty/degenerate handling; `flag_top`; `augment` appends the score; `detect_anomalies`
  flags + records a metric + writes no findings; empty store; and the hybrid path
  augments features, scores every candidate, and writes no labels. Suite 375 passed / 4 skipped.
- Deliverables:
  - [x] `ECOD` tripwire + `flag_top` + `detect_anomalies` (A.5) — done.
  - [x] XGBOD-style hybrid (`augment`, `train_and_score(hybrid=True)`) — done.
  - [ ] Held-out anomaly evaluation on real lab flows — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — ECOD flags outliers advisory-
  only and the hybrid feature is wired into the classifier; the real-flow evaluation is on-host.

### CC-ML-0007 — Active learning: uncertainty sampling + query-by-committee (T7.3) (2026-09-21)
- Change: implemented the active learner (A.6.5). `fuzzlab/ml/active.py`:
  `uncertainty_sampling` picks candidates nearest the 0.5 decision boundary (reusing the
  ranker's advisory `rank_uncertainty`, no retraining); `query_by_committee` +
  `Committee` (a bootstrap committee of rankers) pick the candidates members most
  disagree on (score variance); `propose_queries(store, run_id, budget, method)` returns
  the top-`budget` candidate ids for the oracle to confirm next. Advisory only — it
  proposes what to confirm; the oracle alone confirms.
- Impact (other components / project): lets a run spend its scarce oracle budget where a
  label is most informative — the active-learning half of Phase 7. Composes with the
  ranker (uncertainty) and needs only stored candidates (committee). No store change; no
  new dependency.
- Risk (level; mitigation): low — pure logic, advisory, no writes. Mitigated by 7 tests
  (`tests/test_ml_active.py`): boundary uncertainty; uncertainty sampling order + budget
  bounds + id mapping; committee disagreement math + selection; committee training/shape
  on the store dataset; `propose_queries` uncertainty (descending order) and committee
  (valid budget of ids). Suite 273 passed / 3 skipped.
- Deliverables:
  - [x] `uncertainty_sampling` + `query_by_committee` + `Committee` — done.
  - [x] `propose_queries` store-facing helper — done.
  - [ ] Held-out exit: AL budget captures more positives per confirmation than random
        (T7.4) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — both strategies select the
  most-informative candidates; the live budget-vs-random exit is on-host.

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
