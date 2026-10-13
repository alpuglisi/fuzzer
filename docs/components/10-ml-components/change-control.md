# ML Components — Change Control Log

Component code: **ML**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-ML-0021 — Pairwise learning-to-rank (FR-ML-21), Isolation Forest (FR-ML-22), flow anomalies (FR-ML-23); candidate features read from core (2026-10-13)
- **Context:** batch 4 of the remaining ML work, built while the user is away, taking
  my own recommendation at each decision point. Decisions taken:
  - **R-1:** pairwise is opt-in and pointwise stays the default;
  - **A-1:** Isolation Forest is an alternative detector, and ECOD stays the default;
  - **F-1:** the response-feature classifier is not built (flagged with the reason in
    FR-ML-1).
- Change:
  - **`ml/ranker.py`:**
    - `Ranker(objective=)`, `sample_pairs` (every (positive, negative) pair, a seeded
      sample capped at `MAX_PAIRS` = 5000);
    - the pairwise fit on symmetric pair differences, with a pointwise fallback when
      there is no pair (`objective_used`);
    - `to_params` adds `"objective": "pairwise"` only for a pairwise model.
  - **`ml/persist.py`:** the ranker key set with an optional `objective` that must be
    `"pairwise"`.
  - **`ml/rank_train.py`:**
    - `objective=` in run and earlier modes, with `RANK_OBJECTIVES`, `_choose_objective`,
      `_fold_global` (run-wide metrics within each fold, averaged) and
      `_objective_record`;
    - `_write_ranks(probabilistic=)` writes NULL uncertainty for pairwise, saved mode
      included;
    - `rank_ndcg_global` / `rank_precision_global` metrics are recorded only for a
      non-pointwise objective;
    - `_SAVED_CARRY` gains the objective keys.
  - **`ml/anomaly.py`:**
    - `average_path_length`, `IsolationForest`, `ANOMALY_METHODS` and `fit_detector`;
    - `detect_anomalies(method=, seed=)`: with ≤ 2 rows under iforest, budget 0 with a
      reason.
  - **`ml/flow_anomaly.py` (new):** `flow_vector`, `flow_features` and
    `detect_flow_anomalies`.
  - **`ml/dataset.py`:** the feature names, version and extractor now come from
    `core/features.py` (CC-CORE-0031) under the old names.
  - **`ml/plugins.py`:** `AnomalyPlugin(method)`, `RankerPlugin(objective)` (keys only
    when not the default) and `stage_plugins(anomaly_method, rank_objective)`.
- Impact:
  - **CORE (CC-CORE-0031):** migration 18 and the candidate extractor.
  - **FUZZ (CC-FUZZ-0054):** the two flags and `fuzzlab flow-anomaly`.
  - **UI (CC-UI-0046):** the ranker panel's pairwise display, the anomaly panel reading
    stored flags, the run page's anomaly method, and the launcher entry.
  - **Defaults are bit-identical.**
    - The pointwise ranker's sha is pinned against the pre-change code (`d21f003b…`).
    - The golden summaries (incl. the prioritizer's `model 184ee66b22cc`) are unchanged.
    - The candidate vectors are pinned by the golden file.
- Risk: medium-low.
  - **Pairwise runtime.** A pure-Python pairwise fit is slower (~30 s for ~700 pairs ×
    6 fits). It is opt-in, and the cap bounds it.
  - **`auto` is optimistic by selection.** This is recorded.
  - **Forced per-host contamination.** It is stated everywhere.
  - **Anomaly panel behaviour change.** A run's anomaly panel now shows its stored
    flags, not a fresh ECOD refit, so it agrees with the run page and CLI.
- Deliverables:
  - [x] pairwise ranker + objective selection + persistence — done
  - [x] Isolation Forest + method selection — done
  - [x] flow anomalies — done
  - [x] candidate features from core — done
  - [x] Tests: `tests/test_ml_batch4.py` (30) — done. It covers:
    - the pointwise sha pin;
    - pairs (positive/negative only, seeded, capped, empty);
    - the pairwise symmetric fit with zero intercept, the round trip, and the
      no-pair fallback;
    - bad objectives refused;
    - `_fold_global` recomputed by hand;
    - pairwise/auto training: NULL uncertainty, panel fields, `auto` choosing the
      recorded winner, pointwise afterwards back to the old keys;
    - validation, earlier/saved carrying the objective, and the prioritizer staying
      pointwise;
    - `c(n)` exact;
    - iforest deterministic per seed and finding planted outliers;
    - iforest edge cases n = 1 and 2 and identical rows;
    - `detect_anomalies(iforest)`, plugin configs, and the panel/run page reading
      stored method / unknown / recomputed;
    - migration 18;
    - flow vectors exact with missing values;
    - per-host scoring, out-of-scope, small hosts, and stale values cleared;
    - the flow CLI end to end;
    - no network imports;
    - CLI validation and the iforest summary label;
    - a real browser.

    plus the `auto` selection rule (pointwise wins / tie → pointwise / pairwise wins), and
    iforest constant-feature and stored-score checks;
    `tests/test_candidate_features_core.py` (3, 45 golden cases) — done.
  - [x] Requirements FR-ML-1/2/3/5/12/13 notes, FR-ML-21/22/23; ARCHITECTURE;
    CHANGELOG — done
- Implementation divergence (from the agreed draft v2, written back here):
  - **The all-runs anomaly view always recomputes ECOD.** It pools runs that were
    scored separately, possibly with different methods. It is labelled "recomputed
    (ECOD, c)". The per-run view reads the stored flags as agreed.
  - **Key name.** The `auto` record key is `oof_ndcg_global_by_objective` (per-fold
    run-wide NDCG), not `oof_ndcg_by_objective`, because it holds the global metric.
  - **iforest with ≤ 2 rows records `anomaly_flag_budget = 0`** and the reason "too
    few candidates to isolate (n ≤ 2)". The draft said only "nothing is flagged"; a
    budget of 0 keeps the tie note from mis-explaining it.
  - **A flow pass writes every flow of the run.** It clears out-of-scope and
    small-host flows to NULL (PA-0068(3)), and writes no `run_metrics`.
  - **Pairwise uses both orders of each pair,** as agreed, so the logistic intercept
    stays at 0. The runtime cost is stated.
- Review: the pre-change review gate cleared 3/3 over drafts v1 and v2 (the proposing
  agent plus 2 independent reviewer agents; every raised issue adopted). It was
  renumbered from CC-ML-0020 after BUG-0070 and batch 3 (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (61 files incl. real-browser, no-ML, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 953 passed. Batch-4 files (`test_ml_batch4.py`, `test_candidate_features_core.py`, `test_no_ml.py`, `test_web_ml_context.py`): 57 passed after the mutation-driven additions. Mutation-checked on a copy with bytecode caches cleared: all 28 mutants are killed. The first pass left 4 survivors, and each got a test: `auto` always pairwise (a direct `_choose_objective` test: pointwise wins / tie / pairwise wins); iforest splitting constant features (identical rows score exactly 0.5; a constant column is never split on); the method ignored (stored scores equal an `IsolationForest(seed=0)` refit); a regex word dropped (golden extended with one case per name-regex alternative, from the pre-move commit).

### CC-ML-0020 — Sealed blind holdout (FR-ML-19, FR-ML-7 partial) and Platt calibration (FR-ML-20) (2026-10-13)
- **Context:** the user asked me to build the remaining ML work while away, taking my
  own recommendation at each decision point. This is batch 3 of that work. It builds on
  CC-ML-0018 (`score_oof`, `gate_input`) and CC-ML-0019 (the split-conformal gate).
  Decisions taken:
  - **H-1:** the holdout is opt-in, with fixed, versioned membership;
  - **C-1 / C-2:** calibration is opt-in and Platt only.
- Change:
  - **`ml/holdout.py` (new):**
    - `HOLDOUT_VERSION` / `HOLDOUT_FRACTION` (0.2) / `HOLDOUT_SALT`, and `in_holdout(origin,
      endpoint)` (sha256, keyed by canonical origin plus endpoint);
    - `record()`, `matches_current()`, `mask()`, `split()`, `subset()` and
      `held_endpoints()`.
  - **`dataset.endpoint_key(ev)`** is the one endpoint definition, used both for the
    fold groups and for holdout membership (PA-0003).
  - **`ml/calibration.py` (new):** `PlattScaler`, and `fit_platt` (Newton with smoothed
    targets; `None` when degenerate). `cross_fit` returns `None` if any fold fit is
    degenerate.
  - **`ml/metrics.py`:** adds `brier`, `reliability` / `ece` (the ML tab's binning,
    moved here; `mlview._reliability` delegates), `mcc` and `precision_at_recall`.
  - **`ml/persist.py`:** format 2 (see FR-ML-13). A model without a calibrator keeps
    byte-identical format-1 text.
  - **`train_and_score(calibrate=, holdout=)`** (run and earlier modes; saved mode takes
    `holdout`). It adds:
    - `metric_input`, the shared metric rule;
    - the `gate_input` held-out rule;
    - helpers `_calibrate`, `_gate_on`, `_holdout_metrics`, `_insert_model` and `_seal`.
  - **`train_and_rank(holdout=)`** (all three modes), with `_holdout_ranking` and
    `_holdout_record`. Its duplicate `_next_version` is removed; it uses
    `train._insert_model`.
  - **`active.prioritize(holdout=)`** drops held-out endpoints from the earlier-run
    training.
  - **`ml/plugins.py`:**
    - `ClassifierPlugin(calibrate, holdout)`, `RankerPlugin(holdout)` and
      `BudgetPlugin(holdout)`;
    - each config key appears only when set;
    - `stage_plugins(calibrate, holdout)`;
    - the label-free `holdout.endpoints` count is added to stage results.
    `ML_PLUGIN_VERSION` stays "2": these are new options, not changed meanings.
- Impact:
  - **CORE (CC-CORE-0030):** migration 17 and `core/sealed.py`.
  - **PLUG (CC-PLUG-0007):** `holdout_metric` is INSERT-allowed.
  - **FUZZ (CC-FUZZ-0053):** `--holdout`, `--calibrate` and `fuzzlab reveal-holdout`.
  - **UI (CC-UI-0045):** held-out rows are excluded from the shown out-of-fold metrics,
    the calibration evidence is shown, and the sealed tables are hidden.
  - **Bit-identical without the new options.** Without `calibrate` / `holdout`, the
    stored scores, model rows (params, sha, calibration keys), `run_metrics` and plugin
    configs are exactly as before. The existing suites pass unchanged, apart from one
    test that pinned the guard's insert set.
- Risk: medium-low.
  - **Mitigations:**
    - both features are opt-in;
    - all-or-nothing calibration;
    - fail-closed format-2 validation;
    - the sealed tables have no reader except the counted reveal;
    - held-out status is read from stored facts, so a version bump is safe.
  - **Accepted, and stated in FR-ML-19:**
    - the endpoint key is an interim deviation from D10's cell/transform split;
    - the seal is against summary surfaces, not inspection;
    - the hybrid's ECOD sees held-out features (transductive).
- Deliverables:
  - [x] holdout membership, split, sealed metrics in all trainers and the prioritizer — done
  - [x] Platt calibration (run + earlier), format-2 persistence, evidence — done
  - [x] metric helpers moved and shared — done
  - [x] Tests: `tests/test_ml_holdout_calibration.py` (42) — done. It covers:
    - Platt recovery, monotonicity, degenerate refusal, and cross-fit fold isolation;
    - the metric helpers on hand examples, and the ML tab using the shared ECE;
    - format 1 unchanged, a format-2 round trip, and 14 malformed envelopes (NaN,
      a ≤ 0, missing or extra keys, unknown kind, wrong type, a calibrator on a
      prevalence or constant model, format mismatches, a bool format);
    - stored cross-fitted `score_oof` recomputed independently, the gate on stored
      values, the evidence keys, the loaded model reproducing the calibrated score, and
      the per-side ≤ α invariant;
    - an engineered degenerate fold giving an identical uncalibrated model;
    - earlier-mode calibration, and validation;
    - membership: deterministic, about 20%, keyed by target, canonical origins, no
      target means never held;
    - identity (held-out flips change nothing; a training flip changes the model) for
      run mode, the ranker and the prioritizer, with every flip asserted to change a
      label;
    - held rows: no `score_oof`, gated on `score`, excluded from metrics;
    - sealed metrics equal a recomputation, are never in `run_metrics`, and the record
      carries no label counts;
    - gating: budget-skipped, fallback, and store-wide refusal;
    - a version bump leaves decisions unchanged;
    - earlier mode and the prioritizer drop held endpoints;
    - saved mode reports only for the current membership;
    - the sealed surfaces (report JSON and text, `/api/runs/{id}`, diagnostics metrics
      and models, store tables, the ML data API and the run page);
    - the reveal counter, and nothing recorded when there is nothing to reveal;
    - the reveal CLI;
    - the auto CLI validation and its label-free summary lines;
    - default configs unchanged;
    - a real-browser calibration note.
  - [x] Requirements: FR-ML-7 (partial), FR-ML-1 note, FR-ML-13 (format 2), FR-ML-19,
    FR-ML-20; ARCHITECTURE; CHANGELOG — done
- Implementation divergence (from the agreed draft v3, written back here):
  - **The reveal is its own command.** It is `fuzzlab reveal-holdout --store S --run N`,
    not `fuzzlab auto --reveal-holdout`. `auto` requires `--base-url` and `--authorized`
    for a pass that sends traffic, and a reveal sends none. It is also kept out of the
    web launcher, so every reveal is a deliberate command. `reveal()` returns a dict
    `{metrics, reveals, version}`, not a tuple.
  - **Positives are sealed too.** The model's `holdout` record holds `{version,
    fraction, rows}`, without `positives`. The held-out positive count is label
    information, so it is sealed (`holdout_positives` in `holdout_metric`). The sealed
    set also gains `ml_brier_holdout`, `ml_ece_holdout` (the measured calibration) and
    `holdout_rows`.
  - **The endpoint count prints on every `--holdout` run,** not only the first per
    target. It is label-free.
  - **The ranker's vocabulary is fitted on the kept rows only,** which is stricter than
    the draft's transductive allowance. The hybrid ECOD remains transductive.
  - **No `holdout: null` key.** A model trained without the holdout records no
    `holdout` key, rather than `holdout: null`, to keep the default path bit-identical
    (the draft's own "without `--holdout`, bit-identical" requirement wins).
  - **Calibration evidence location.** It lives in the model's calibration and the
    stage result, not `run_metrics`, as v2 settled.
- Review: the pre-change review gate cleared 3/3 over drafts v1 to v3 (the proposing
  agent plus 2 independent reviewer agents; every raised issue adopted). It was
  renumbered from CC-ML-0019 after BUG-0070 took that number (PA-0031). The BUG-0070
  review's A5 added the rounding rule: cross-fitted `score_oof` is rounded before the
  gate is calibrated on it.
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (58 files: ML, auto, web incl. real-browser, plugins, report, no-ML, harness, multitarget, pipeline, diagnostics, core, CLI, store, migrations; `FUZZLAB_REQUIRE_BROWSER=1`): 901 passed. `tests/test_ml_holdout_calibration.py`: 42 passed. Mutation-checked on a copy with bytecode caches cleared: all 27 mutants are killed, with no survivors on the first pass. Killed: split no-op, fraction ignored, no-origin held, gate held→none, metric includes held, oof not cross-fitted, gate on raw, deploy uncalibrated, loader skips the calibrator, no slope check, calibrator on any kind, holdout ungated, no seal, prioritizer ignores, earlier trains held, saved any membership, tables listed, tables browsable, empty reveal counted, CLI unvalidated, config always holdout, ranker trains held, ranker panel includes held, cross-fit leaks, JS note missing, all-or-nothing off, held oof written.

### CC-ML-0019 — The conformal gate keeps its α bound (BUG-0070); anomaly flags never exceed their fraction (2026-10-13)
- **Context:** found while building batch 3 (calibration). Its agreed invariant test
  (each side's error ≤ α on the calibration set, ties included) failed on today's gate
  with no calibration at all. This is fixed first, as its own bug. Batch 3 becomes
  CC-ML-0020 and batch 4 becomes CC-ML-0021 (renumbered before anything was committed,
  PA-0031).
- Change:
  - **`conformal.py`: finite-sample split-conformal order statistics.**
    - The gate flags `score > q_hi`, where `q_hi` is the `ceil((n+1)(1-α))`-th smallest
      negative. It drops `score < q_lo`, where `q_lo` is the `floor((m+1)α)`-th smallest
      positive.
    - Ranks are computed in exact arithmetic with `fractions.Fraction(α)`. The helpers
      are `upper_index`, `lower_index` and `min_class_size = ceil(1/α) - 1`.
    - Out of range means the gate **never flags / never drops**.
    - `decide` (`>=` / `<=`) is unchanged, and the strict inequalities are stored as
      `t_hi = nextafter(q_hi, +inf)` and `t_lo = nextafter(q_lo, -inf)`. The "never"
      thresholds are `nextafter(1.0, inf)` and `nextafter(0.0, -inf)`. Stored rows
      therefore keep their exact meaning.
    - `check_alpha`: α must be a real number in (0, 1).
    - `_quantile` is removed.
  - **`train.py`:**
    - The gate is calibrated on `round(oof, 6)`, the stored values (PA-0069(3)).
    - `alpha` is checked before any write.
    - `_gate_record` adds `gate_rule: "split-conformal"`, `n_pos` and `n_neg` to new
      rows, in run and earlier modes. `_SAVED_CARRY` carries them to saved copies.
    - `gate_notes(calibration)` and `OLD_GATE_NOTE` are the reader text.
  - **`anomaly.py`:**
    - `flag_budget(n, c)` is the one definition of k.
    - `flag_top` flags **at most k, whole tie groups only**. Nothing is flagged when the
      top tie group alone exceeds k.
    - `flag_reason` explains a shortfall.
    - `FLAG_RULE = 2`. `detect_anomalies` also records `anomaly_flag_budget` and
      `anomaly_flag_rule`, and returns `flag_budget` and `flag_reason`.
- Behaviour changes, stated in FR-ML-1, FR-ML-12 and FR-ML-18:
  - at α = 0.1 a gate never drops with fewer than 9 positives and never flags with fewer
    than 9 negatives;
  - an empty negative class never flags (before, it flagged a score of exactly 1.0);
  - the tripwire flags fewer candidates when scores tie, possibly none.

  Every reader shows the reason.
- Impact:
  - **UI (CC-UI-0044):**
    - the run page shows gate notes and the anomaly note;
    - the ML tab shows "never" thresholds and the notes, including the pooled
      old-rule note;
    - the anomaly panel uses `flag_budget` and `flag_reason`.
  - **FUZZ (CC-FUZZ-0052):** the CLI prints the anomaly reason, and the
    `--anomaly-contamination` help text changes.
  - **CORE:** `core/anomaly_flags.flag_note` is a plain store read, no ML import. It is
    a reader added inside the existing module, recorded here and in CC-UI-0044 because
    no CORE contract changes.
  - **Store:** no schema change. New `run_metrics` keys `anomaly_flag_budget` and
    `anomaly_flag_rule`, and new calibration keys `gate_rule`, `n_pos` and `n_neg`.
  - **Old rows** are not rewritten. Their thresholds and flags are applied as recorded
    and labelled "pre-BUG-0070".
  - `ML_PLUGIN_VERSION` stays "2": the plugin config's meaning is unchanged, and the
    run's metrics record the rule.
- Risk: low-medium.
  - **Fewer automated decisions and flags on thin data.** That is the honest reading of
    the stated guarantee, and each reader says why.
  - **Two golden summaries regenerated deliberately.** In
    `tests/data/auto_summary/run.txt` and `earlier.txt`, "anomaly: flagged 8 of 46"
    becomes "flagged 4 of 46" plus a note: k = 5, and a tie group of 4 at 7.957 is
    followed by a tie group of 4 more. The fifth listed row (`/blog_post.php [id] xss
    6.571`) is gone.
  - Every other line is byte-identical.
- Deliverables:
  - [x] `conformal.py` split-conformal helpers and α validation — done
  - [x] `train.py` stored-value calibration, `_gate_record`, `gate_notes`, `_SAVED_CARRY` — done
  - [x] `anomaly.py` `flag_budget` / `flag_top` / `flag_reason`, budget and rule metrics — done
  - [x] Tests: `tests/test_conformal_bound.py` (new, 104) — done. It covers:
    - the calibration-set bound with ties at n ∈ {1..200} and α ∈ {0.05, 0.1, 0.2, 0.5};
    - non-vacuity, where exactly `n - k_hi` are flagged;
    - the overlap swap;
    - the sentinels;
    - `min_class_size`;
    - exact indices against a brute-force `Fraction` count over 157 α values;
    - α validation, including the trainer writing nothing;
    - the held-out Monte Carlo on both sides, two-sided;
    - new-row keys and the never-drop note;
    - old rows deciding as before;
    - stored-value calibration;
    - rounding across a threshold;
    - `flag_budget`, ties, the two-group cases, and the property "never above k, whole
      groups only";
    - `detect_anomalies` metrics and the old-run label.
  - [x] Updated tests:
    - `test_ml_saved_and_decisions.py`: a saved copy carries `gate_rule`, `n_pos`,
      `n_neg` and the thresholds;
    - `test_auto_budget.py`: flagged ≤ `anomaly_flag_budget`, still > 0;
    - `test_web_ml_context.py`: a browser test for the gate notes, anomaly note and
      reason; its fixture also anomaly-scores run 2;
    - the two golden files above;
    - `test_ml.py::test_conformal_decisions_and_calibration`: the tolerance tightens
      from 2α to α + 3·SE (A4).
  - [x] BUG-0070, ERROR_LOG, PA-0069, FR-ML-1 note, FR-ML-12 amended, FR-ML-18 new,
    CHANGELOG — done
- Review: the pre-change review gate cleared 3/3. Draft v1 drew 5 issues from A and 5
  from B; v2 drew 3 from A and 4 from B. Every issue was adopted. The main additions:
  - B: the `flag_top` sweep instance, α validation, the run-page marker, the reason text
    and `flag_budget`;
  - A: small-n disclosure, exact `Fraction` indices, the golden files named, and
    old-flag labelling.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Related suites** (ML, auto, web incl. real-browser, plugins, report, no-ML,
    harness, multitarget, pipeline, diagnostics; `FUZZLAB_REQUIRE_BROWSER=1`): 813
    passed, 1 skipped, 1 failed.
    - The failure, `test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real`,
      boots real lab servers with timeouts. It ran while a concurrent full suite held
      the CPU.
    - It passes alone and with its file (2 passed). It is not in the area changed; the
      next full suite re-checks it.
  - `tests/test_conformal_bound.py`: 104 passed.
  - **Mutation check.** On a copy, bytecode caches cleared: all 22 mutants are killed.
    - The first pass left 4 survivors, and each got a new test:
      - no overlap swap: the swap test now places the classes so the thresholds cross
        and asserts the swap;
      - no stored-value rounding: a constructed out-of-fold value that rounds up across
        the threshold;
      - no early α check: the thin-data path refuses a bad α and writes nothing;
      - no pooled old-rule note: the pooled view whose newest row is new-rule.
    - Killed: ceil→round, n instead of n+1 (both sides), no nextafter (both sides),
      float α instead of `Fraction`, no α check, `min_class_size` off by one, no
      `gate_rule`, no saved carry, no old-row note, ties split, budget off by one, no
      rule metric, no old-flag note, `-0.0` / never display, no CLI reason, no run-page
      gate note.

### CC-ML-0018 — no_confirmer unlabelled; canonical target matching; out-of-fold columns (BUG-0067); saved-model scoring; `--hybrid` (2026-10-13)
- **Context:** the user asked me to build the remaining ML work while away, taking my
  own recommendation at each decision point. This settles the three decisions flagged
  earlier (D-a, D-b, D-c) and adds two small features (F-1, F-2).
- Change:
  - **D-a: `no_confirmer` rows are unlabelled.** `build_dataset` treats `oracle_status`
    in `UNLABELLED` (budget-skipped **or** no confirmer) as unlabelled: never trained or
    evaluated on, still scored, ranked and anomaly-scored. "No finding" there means
    nobody could check. NULL (legacy) keeps its old meaning.
    `forward_skip_reason` stays budget-only.
  - **D-b: loopback aliases are one target.** `dataset.target_runs(store, target)`
    matches runs by `canonical_origin` (CC-CORE-0029), and the `target=` filter uses it.
    So `localhost:8080`, `127.0.0.1:8080` and `[::1]:8080` are one target for
    earlier-run training and budget ordering. An unusable origin matches nothing.
  - **D-c: out-of-fold columns** (BUG-0067).
    - **Classifier.** In run mode, `train_and_score` keeps `score` as the deploy model's
      score for every row and writes each labelled row's **out-of-fold** score to
      `score_oof`. Unlabelled rows, the thin fallback, and earlier/saved modes write
      NULL, so every scoring pass writes or clears the column (`_write_scores`,
      PA-0068(3)). Model calibration records `score_source`: `oof-labelled`, `deploy`,
      `earlier` or `saved-model`.
    - **Ranker.** `train_and_rank` does the same with `rank_score_oof`.
    - **`train.gate_input(calibration, oracle_status, score, score_oof)`** is the one
      rule for which stored score a conformal gate may judge (PA-0068(2)).
    - **Reproducibility.** The saved model still reproduces every stored `score`
      (CC-ML-0015 holds). The out-of-fold columns are reproducible by deterministic
      re-training (seeded `oof_folds`).
  - **F-1: `train_on="saved"`.** `_score_from_saved` / `_rank_from_saved` score or rank
    every candidate of the run with a saved earlier model, without training.
    - **Selection.** `model_registry.saved_source` (FR-ML-15) picks the **original**
      trained row:
      - the scope must be an `int` (not a bool) for an earlier run against this target;
        store-wide, legacy, non-int, fallback and no-params rows never qualify;
      - saved-mode copies are never chosen, and a pinned copy resolves to its original;
      - newest means highest scope run, then highest id;
      - `model_id` pins a row of the right family only.
    - **Refusal, writing nothing:** no target, no qualifying model, or a model that
      cannot be applied (`ModelParamsError` / `ModelIncompatibleError`).
    - **Copy row.** A copy row scoped to this run is written with the same params and
      sha. Its calibration records `trained_on: "saved"`, `source_model_id`,
      `source_run_id`, `train_run_ids` (from the original when present), a recomputed
      `seen_fraction` (`seen_fraction_recomputed: true`) and `score_source:
      "saved-model"`. It carries the original's gate and `oof_*`, with an explicit
      `oof_scope` "run #R (saved model #ID)".
    - **Forward metrics and `*_seen_fraction`** are recorded as in earlier mode, through
      the now-shared `_forward_evaluation` / `_forward_ranking` helpers.
  - **F-2: `hybrid`** reaches the classifier through `ClassifierPlugin(hybrid=)`.
    `hybrid` together with `saved` raises `ValueError`, since a saved model applies its
    own ECOD.
  - **`ml/plugins.py`:**
    - `ClassifierPlugin(train_on, model_kind, hybrid, model_id)` and
      `RankerPlugin(train_on, model_id)`;
    - `model_id` appears in the config only when set;
    - `stage_plugins(hybrid, model_id, ranker_model_id)`;
    - `ML_PLUGIN_VERSION` "1" → "2" (run-mode output and the training set change
      meaning).
- Impact:
  - **D-a is a behaviour change for existing stores.** Old runs that recorded
    `no_confirmer` rows lose those negatives retroactively, so training sizes can
    shrink, possibly into the thin fallback, and old ML-tab numbers may differ from
    their stored `oof_*`. NULL-status legacy rows in no-confirmer categories stay
    negatives, so a store mixes both semantics (FR-ML-17 says so).
  - **Golden summaries stay byte-identical:** every run-mode stage in them is a
    prevalence fallback, and the earlier-run seeds have NULL status.
  - **IDs:** FR-ML-15 (saved), FR-ML-16 (stored-score sources), FR-ML-17 (unlabelled
    statuses). The FR-ML-11 limitations (aliases, no_confirmer) are resolved.
- Risk: medium-low.
  - The run-mode `score` is unchanged.
  - The new columns are additive.
  - The saved selector is strict and tested against every leak path from review.
- Deliverables:
  - [x] Code — done
  - [x] `tests/test_ml_saved_and_decisions.py` (39) — done:
    - **D-a:** excluded from training but scored; no forward skip; earlier mode excludes
      earlier no_confirmer rows.
    - **D-b:** canonical cases; aliases (localhost, `[::1]`) train together, while a
      different port and an empty origin do not.
    - **D-c:**
      - run mode stores both columns, with a precondition that they differ;
      - the tab's PR-AUC equals `oof_pr_auc`, including on noisy data where in-sample
        differs;
      - the saved model reproduces every `score`;
      - unlabelled rows get NULL;
      - re-scoring clears the out-of-fold columns;
      - the run page decides on the out-of-fold score and shows it;
      - the `gate_input` truth table, and the legacy "n/a (in-sample score)" rule.
    - **F-1:**
      - saved scoring and ranking reproduce the loaded models exactly, with the same sha;
      - each never-qualifying row is refused when pinned and never auto-picked
        (store-wide, legacy, non-int, bool, no params, this run, a later run);
      - a copy resolves to its original; a wrong-family pin is refused;
      - refusal writes nothing; a corrupted model is refused;
      - an earlier-trained source passes its `train_run_ids` on;
      - the UI and report labels.
- Implementation divergence:
  1. `conformal_panel` now gates each row with **its own run's** classifier, which also
     closes the documented all-runs limitation (BUG-0067's sweep).
  2. The shared forward helpers are extracted (`_forward_evaluation`,
     `_forward_ranking`).
- Review: pre-change review gate cleared 3/3 over drafts v1 to v4 (the proposing agent plus 2 independent reviewer agents; every raised issue adopted).
  - **Process note:** `core/oracle_status.py`, `core/urls.canonical_origin`, the dataset changes and `--hybrid` were drafted in the working tree **before** agreement. They were kept uncommitted and reconciled with the agreed v4.
  - **Reverted:** my early in-column version of D-c was reverted; reviewer B's separate-column design replaced it.
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (ML, auto, web incl. browser smoke, plugins, report, no-ML, harness, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 705 passed, including `test_ml_saved_and_decisions.py` 39 and `test_auto_train_on.py` 13. Mutation-checked on a copy with bytecode caches cleared: all 20 mutants are killed. The first run left two survivors, and each got a new test (noisy data where in-sample and out-of-fold PR-AUC differ; an earlier-trained saved source). Killed:
  - **gates:** the legacy gate on in-sample scores, `score_oof` ignored, the run page or conformal panel judging `score`;
  - **out-of-fold columns:** not written, not cleared by earlier mode, ranker out-of-fold dropped;
  - **saved selector:** any scope run, a bool scope, copies chosen, the wrong `train_run_ids`;
  - **targets and labels:** the localhost alias dropped, an empty host matching, no_confirmer labelled, exact-text target matching;
  - **UI and report:** the tab's metrics on deploy scores, the out-of-fold label missing, the report's saved block missing;
  - **CLI:** `--hybrid` allowed with saved.
  Full-suite result (on commit c16477e, `FUZZLAB_REQUIRE_BROWSER=1`): 3113 passed, 65
  skipped, 9 xfailed, 33 failed. The 33 failures are exactly the known environmental
  labgen failures (no scipy, sklearn or gitleaks), identical to the step-3 baseline.

### CC-ML-0017 — The ML stages as built-in plugins (2026-10-13)
- Change: new `fuzzlab/ml/plugins.py`.
  - **The stages:**
    - `ClassifierPlugin(train_on, model_kind="auto")`, `ml-classifier`, priority 10;
    - `RankerPlugin(train_on)`, `ml-ranker`, 20;
    - `AnomalyPlugin(contamination)`, `ml-anomaly`, 30, which also returns the top
      flagged rows (`top_flagged`, moved from `auto_cli`);
    - `BudgetPlugin(method, seed)`, `ml-budget`, a `register_prioritizer` →
      `partial(prioritize, …)`.
  - **Every plugin carries:**
    - `version = ML_PLUGIN_VERSION = "1"`, which names option semantics; the model's
      `params_sha256` stays the real pin and is in the result;
    - a `config` dict of its options, recorded on the run;
    - the `flag` of the `fuzzlab auto` option that attaches it.
  - **One mapping.** `stage_plugins(...)` is the only options→plugins mapping
    (PA-0003), and `STAGE_NAMES` is derived from the classes.
  - **No entry points.** The stages are not registered as entry points, so `--plugins`
    is unchanged. The alternative, a separate `fuzzlab.stages` group, is flagged.
- Impact:
  - The stages compute exactly what they computed when `auto_cli` called them
    directly.
  - FR-ML-6 is implemented, with simulated absence tested (CC-UI-0041). A packaged
    no-ML build is flagged.
  - ML requirements §5 is aligned.
- Risk: low.
- Deliverables:
  - [x] `fuzzlab/ml/plugins.py` — done
  - [x] `tests/test_ml_plugins.py` (11) — done:
    - Through the guarded manager, each stage's result and written state (scores,
      model rows with sha and calibration, metrics) equal the direct call's, on two
      identical stores. Covered: classifier run and earlier, ranker run and earlier,
      anomaly.
    - The budget plugin's order, method and model sha equal `prioritize`'s for all four
      methods, under the read-only guard.
    - The options→plugins mapping; option values reach the plugins and the run record
      as canonical JSON.
- Implementation divergence: each plugin carries its `flag`, so `auto_cli` keys the
  summary by plugin name without hard-coding the names.
- Review: pre-change review gate cleared 3/3. The proposing agent and 2 independent reviewer agents went through DRAFT v1 to v4.
  - Reviewer A focused on architecture and spec fit; reviewer B on adversarial correctness, safety and tests, with SQLite experiments.
  - Every raised issue was adopted.
  - v1's guard was bypassable (a rename round-trip, a later-firing trigger, a temp shadow table, label state outside `finding`, an unguarded prioritizer). v1's failed-stage writes could also be committed by the next stage. Both were redesigned before any code.
- Effectiveness (assessed 2026-10-13): effective offline. `tests/test_ml_plugins.py` 11 passed: each stage, run through the guarded manager, reproduces the direct call's result and stored state exactly. Every existing ML suite passes unchanged. The `ml-plugin-wrong-train_on` mutant is killed (CC-PLUG-0005). Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 3062 passed, 33 failed, 68 skipped, 9 xfailed. The 33 failures are the identical environmental labgen set as at `a3b782d` and `882cda8` (diffed: no scipy, scikit-learn or `gitleaks` binary here). Every skip is in lab/labgen/corpus tests guarded on toolchains or services, none in a file this change touches; the +3 against `882cda8`'s run is in that environment-dependent set.

### CC-ML-0016 — Train on earlier runs; score and rank this run without its labels (2026-10-13)
- Change:
  - **Shared target helper.** `dataset.target_of(store, run_id) -> str | None` reads the
    pipeline's `target.base_url`. It moves from `active._target_of`, and `prioritize`
    imports it (PA-0003/0021). `dataset` also gains `candidate_keys`, `run_ids_of` and
    `seen_fraction`.
  - **New keyword.** `train_and_score(store, run_id, *, train_on="run"|"earlier", …)`
    and `train_and_rank(…, train_on=…)`. The default `"run"` path is unchanged. Any
    other value raises `ValueError`.
  - **`train_on="earlier"`** (`train._score_from_earlier`,
    `rank_train._rank_from_earlier`):
    - **Preconditions.** `run_id=None` raises `ValueError`. A run with no target row is a
      refusal: `{"refused": True, "reason": "no target recorded for this run"}`.
    - **Training set.** `prior = build_dataset(store, before_run_id=run_id,
      target=target_of(store, run_id))`. Labelled rows only (`skipped_budget` excluded),
      each labelled from its own run (CC-ML-0014). The ranker's texts come from
      `_candidate_texts(store, None, prior.ids)`.
    - **Refusal.** If `prior` fails the trainers' thin-data gate (`train._thin`: rows,
      positives, no negatives, `min_groups`, `k < 2`), nothing is written (no scores,
      no model row, no metrics). The result reads `{"train_on": "earlier", "refused":
      True, "reason": "no usable earlier labels for this target", "train_rows",
      "train_positives"}`. It never falls back to in-sample training.
    - **Hybrid.** ECOD is fitted once on the earlier rows of the target, including
      unlabelled rows (label-free). It augments the training rows and this run's rows,
      and is stored with the model.
    - **Evaluation and fit.**
      - Model selection (`auto`), PR-AUC against both baselines, NDCG/precision@k
        against random, and the conformal thresholds are computed out-of-fold on
        `prior` (`train._select_and_evaluate`, `rank_train._evaluate`).
      - The deploy model is fitted on all of `prior`, and every candidate of this run
        is scored or ranked with it.
      - This run's labels are never read for training, selection or calibration.
    - **Saved row.** The model is saved through `persist`. Its calibration holds:
      - `run_id` (this run), `trained_on: "earlier"`, `train_run_ids`, `train_rows`,
        `train_positives`, `seen_fraction`;
      - `seed`, `k`, `min_rows`, `min_positives`, `min_groups`, `feature_version`
        (classifier also `model_kind` and `alpha`; ranker `at_k`);
      - `oof_scope: "earlier runs"`, the `oof_*` keys and the conformal `t_lo`/`t_hi`;
      - `forward_*`, or `forward_skipped_reason`.
    - **Run metrics** (exact keys):
      - Out-of-fold on the earlier data: `ml_pr_auc_earlier`,
        `ml_pr_auc_prevalence_earlier`, `ml_pr_auc_sigma_earlier`, `rank_ndcg_earlier`,
        `rank_precision_earlier`, `rank_ndcg_random_earlier` and
        `rank_precision_random_earlier`.
      - `ml_seen_fraction` and `rank_seen_fraction`.
      - Forward evaluation of this run's stored scores against its own oracle labels,
        computed after scoring and never fed back: `ml_pr_auc_forward`,
        `ml_pr_auc_prevalence_forward`, `rank_ndcg_forward`, `rank_precision_forward`,
        `rank_ndcg_random_forward` and `rank_precision_random_forward`.
      - The forward keys are written only when this run has no `skipped_budget` row and
        its labels include both classes (`train.forward_skip_reason`). Otherwise
        `forward_skipped_reason` is `"budget-selected labels"` or `"one-class labels"`.
      - No `run`-mode keys (`ml_pr_auc`, `rank_ndcg`, …) and no `metric_series` training
        curves are written in this mode.
    - **Result dict.** It gains `train_on`, `refused`, `train_run_ids`, `train_rows`,
      `train_positives`, `seen_fraction`, the `*_earlier` and `*_forward` numbers, and
      `forward_skipped_reason`.
  - **Wording.** Results, docstrings and the UI say "not trained on this run's labels",
    never "out-of-sample". `seen_fraction` is the share of this run's candidates whose
    `(path, param, category)` key occurs among the training rows.
  - **Conformal gate.** It is calibrated on earlier out-of-fold scores grouped by
    endpoint and applied to this run, whose endpoints mostly recur. Its error bound is
    therefore nominal: valid only under exchangeability, which repeated endpoints and
    drift break (FR-ML-14).
- Impact:
  - Same tables, no schema change. The CLI is covered in CC-FUZZ-0049, and the UI and
    report in CC-UI-0040.
  - FR-ML-14 is added; NFR-ML-no-leak gets a note.
  - `train.py` is refactored into shared helpers (`_thin`, `_select_and_evaluate`,
    `_metric`, `forward_skip_reason`), which `rank_train` reuses. The `run` path's
    behaviour is unchanged, and its existing tests pass unmodified.
- Risk: medium-low. The `run` path is untouched in behaviour. Because `earlier` refuses,
  it never quietly changes meaning.
- Deliverables:
  - [x] `dataset.target_of` (`prioritize` uses it), `candidate_keys`, `run_ids_of`,
    `seen_fraction` — done
  - [x] `train_on` in both trainers — done
  - [x] Tests (`tests/test_ml_train_on_earlier.py`) — done:
    - **Model identity** (`params_sha256` and the training-related calibration) is
      unchanged when this run gains findings (including keys unlabelled in every
      earlier run), loses its findings, gains or loses candidates, when a later run is
      added, and when another target's run is added. Covered for logistic, hybrid,
      `auto` and the ranker, with a check that the identity can change (an earlier
      run's label).
    - A key labelled only in this run trains as negative.
    - Earlier `skipped_budget` rows are excluded: the same sha as deleting them.
    - Stored scores and ranks equal the saved model applied to this run's rows
      (hybrid included).
    - The ranker vocabulary comes from the earlier texts only.
    - `latest_classifier` / `latest_ranker` select the earlier-trained row for this
      run, and it does not cover the runs it trained on.
    - `seen_fraction` is exact.
    - The exact metric-key set; no `run`-mode keys; no `metric_series` rows.
    - The forward metrics equal PR-AUC / NDCG of this run's labels against the stored
      scores. They are absent, with the reason recorded, on a budget-skipped row or
      one-class labels.
    - Refusal with no earlier runs, with only another target's runs, and with no
      target row, each writing nothing.
    - `ValueError` for `run_id=None` and for an unknown `train_on`.
    - `run` mode unchanged.
  - [x] FR-ML-14; NFR-ML-no-leak note — done
- Implementation divergence (written back per the review gate):
  1. Calibration also records `forward_skipped_reason` when forward metrics are skipped,
     so the ML tab can say why.
  2. The classifier records `seed: 0`, the fixed seed of its folds.
  3. The shared-helper refactor of `train.py` described under Impact.
- Preventive-action compliance:
  - **PA-0064(2):** the earlier-data numbers go through `oof_folds`, and forward
    numbers are named as such.
  - **PA-0064(3):** every refusal and forward-skip branch has a test that enters it.
  - **PA-0066(2):** tests seed several runs and targets.
  - **PA-0063/0067:** every new `model` read goes through `latest_classifier` /
    `latest_ranker` with the run's id. The new `dataset` helpers read `candidate` by
    id, and `seen_fraction` compares content keys across runs on purpose (recurrence is
    what it measures).
  - **PA-0034(2):** the identity check is proven able to fail.
  - **PA-0003:** one `target_of`.
- Review: pre-change review gate cleared 3/3 (proposing agent and 2 independent
  reviewer agents, rounds v1 to v3; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline. `tests/test_ml_train_on_earlier.py` and `tests/test_auto_train_on.py`: 57 passed. Existing ML suites pass unchanged, except `test_ml_oof.py`'s exact `oof` payload, which gains `scope`. Mutation-checked with bytecode caches cleared before each run (`PYTHONDONTWRITEBYTECODE=1`, on a copy of the tree). 18 of 19 mutants are killed: training on this run, ranking on this run, dropping the target filter, filtering ranker texts to this run, fitting ECOD on this run, removing the thin-data refusal, removing the no-target refusal, removing either forward-skip condition, an ungated ranker forward, an inverted `seen_fraction`, writing a `run`-mode key, the UI never or always in-sample, the report always `run`, the CLI validation removed, the CLI flag ignored, and `seen_fraction` not saved. The survivor (forward PR-AUC over `scores[:len(now)]` instead of by id) is equivalent: forward metrics are written only when no row is budget-skipped, and then this run's labelled rows are exactly its scored rows, in the same order. Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 2973 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are exactly the same labgen `--check`/fingerprint-gate tests as at `a3b782d` and `369e887`, which fail identically in this environment because it has no scipy, scikit-learn or `gitleaks` binary. None is caused by this change. The on-host question (does an earlier-trained model beat the baselines on a fresh lab run: T5.5 / T7.4) is still open.

### CC-ML-0015 — Trained models are saved as verified JSON and reload to identical predictions (2026-10-13)
- Change:
  - **Per-class serialisation.** Each class gains `to_params()` and
    `classmethod from_params(d)`, holding only the hyperparameters and the fitted state
    needed to predict:
    - **`LogisticRegression`:** `{epochs, lr, l2, class_balanced, w, b, mean, std}`.
      Prediction is `sigmoid(Σ w·(x−mean)/std + b)` (`logistic.py:84-87`).
    - **`GradientBoostedTrees`:** `{n_estimators, lr, max_depth, min_leaf,
      class_balanced, f0, trees}`. Prediction is `sigmoid(f0 + lr·Σ tree(x))`
      (`gbt.py:155-159`). Each tree is a nested node: `{"f","t","l","r"}` for a split,
      `{"v"}` for a leaf. A depth-3 tree has at most 15 nodes, so 60 trees hold at most
      900. The per-sample training weights `_w` are not stored.
    - **`PrevalenceBaseline`:** `{rate}`.
    - **`CharNgramVectorizer`:** `{n, max_features, vocab, idf}`; `_index` is rebuilt
      from `vocab`. `_ngrams` behaviour on short texts depends only on `n`.
    - **`Ranker`:** `{seed, vectorizer, model: {"kind": "logistic", "params": …},
      feature_names}`. The ranker accepts an injected model (`ranker.py:32`), so the
      nested model carries its own kind.
    - **`ECOD`:** `{n, d, sorted, skew}`.
  - **New `fuzzlab/ml/persist.py`** is the only home of the envelope convention
    (PA-0003).
    - `dumps_model(kind, model, *, feature_names, feature_version, ecod=None) -> (text,
      sha256)`.
      - Envelope: `{"format": 1, "kind", "feature_names", "feature_version", "params",
        "ecod"}`.
      - Serialised canonically: `json.dumps(…, sort_keys=True, separators=(",", ":"),
        allow_nan=False)`.
      - Finite floats round-trip exactly (`repr`). A NaN or Infinity in a fitted model
        raises at dump time instead of being stored.
    - `loads_model(text, sha256) -> LoadedModel`. It **fails closed** with
      `ModelParamsError` (PA-0021) on any of:
      - a sha mismatch;
      - text that is not UTF-8 JSON (bytes, a pickle payload);
      - `NaN`/`Infinity` (`parse_constant` rejects them);
      - `RecursionError`, which is caught and mapped;
      - an unknown `format` or `kind`, or wrong types;
      - unequal lengths, checked as an explicit all-equal: logistic `w`/`mean`/`std`/
        feature names; ranker `len(w) == len(FEATURE_NAMES-shaped structural part) +
        len(vocab)`, `len(idf) == len(vocab)`; ECOD `len(sorted) == len(skew) == d`
        with each column holding `n` entries;
      - tree nodes that are not exactly a split (in-range feature index, finite
        threshold, both children) or a leaf (finite `v`), or deeper than `max_depth`.
    - The sha detects corruption and pins a model's identity for reproducibility. It is
      **not** authentication: anyone who can write the store can recompute it.
    - It never uses `pickle`, `marshal` or `eval`, since unpickling a movable store file
      would be CWE-502.
    - Kinds: `logistic`, `gbt`, `prevalence`, `ranker`, `constant` (the ranker fallback,
      `{value}`).
  - **`LoadedModel`:**
    - `check_compatible()` raises `ModelIncompatibleError` unless `feature_version ==
      dataset.FEATURE_VERSION` and the stored `feature_names` match the current ones
      exactly:
      - classifier kinds: `FEATURE_NAMES`, plus `anomaly_ecod` when an ECOD is stored;
      - ranker: `FEATURE_NAMES` plus its own vectorizer names.

      Every model reads features by position, so a reorder would otherwise misalign
      silently. Step 2 will call this before scoring a new run.
    - `predict_proba(X)` (classifier kinds) checks each row's width against the stored
      structural feature count and applies the stored ECOD augment itself, so callers
      pass plain `dataset` vectors.
    - `score(X, texts)` serves the ranker.
  - **Writers:**
    - `train_and_score` stores the deployed model (`logistic` / `gbt`, or `prevalence`
      on fallback), plus its fitted ECOD when `hybrid=True`.
    - `train_and_rank` stores the deployed `Ranker`, or `constant` on fallback.
    - Both write `params` and `params_sha256` in the same `INSERT`.
  - **Readers, all through `model_registry` (PA-0063):**
    - New `params_for(store, model_id) -> (text, sha) | None` fetches one row's params by
      id. `select_latest` keeps scanning only the narrow columns; it already returns
      `id`.
    - `ClassifierModel` gains `id` (from `row["id"]`) and `params_sha256` (from
      `params_for`).
    - New `train.load_classifier(store, clf)` and `rank_train.load_ranker(store, row)`
      each return a `LoadedModel`, or `None` for a pre-migration-14 row.
  - **Budget prioritizer identity.** It still retrains per call, and is not stored as a
    `model` row, which would add a third model family for every selector to exclude (the
    BUG-0061 hazard). `Prioritized` gains `model_sha256: str | None = None`, so existing
    constructions stay valid. It holds:
    - `score` / `uncertainty`: the sha from `dumps_model("ranker", …)` of the fitted
      ranker;
    - `committee`: `sha256(("committee/1:" + ",".join(member_shas)).encode())`, where
      `member_shas` are the members' own `dumps_model("ranker", …)` shas in member
      order. This is a defined, deterministic format that needs no new envelope kind,
      since the committee is never reloaded;
    - `random`: `None`.

    `Prioritized` also gains `seed: int = 0`. The pipeline adds `budget_seed` (an int)
    to the result metrics, so it also lands in `run_metrics` as `pipeline_budget_seed`
    (every numeric metric does, `pipeline.py:192-196`). `budget_model_sha256` is a
    string, so it stays in the result dict only. The CLI budget line prints the sha's
    first 12 characters.
- Impact:
  - UI: weights panel and report (CC-UI-0038/0039).
  - Step 2 will call `load_*` + `check_compatible` + `predict_proba`/`score`. Nothing
    else changes behaviour now.
  - `model` rows grow by tens of KB at most for GBT; a hybrid model's ECOD is about
    12 floats per training candidate.
  - FR-ML-13 is added. FR-ML-9's "weights not persisted" gap is closed.
    NFR-ML-reproducible: a model is reproducible from its stored row.
- Risk: medium-low. Additive, validated and fail-closed. Exact-equality round-trip tests
  cover float reproduction.
- Deliverables:
  - [ ] `to_params` / `from_params` on six classes — done
  - [ ] `persist.py`: dump/load, sha, validation, `ModelParamsError`,
    `ModelIncompatibleError`, `LoadedModel` — done
  - [ ] Trainers persist; `params_for`; `load_classifier`; `load_ranker`; `Prioritized.model_sha256` + pipeline/CLI — done
  - [ ] Tests:
    - Round trips for every kind, including hybrid logistic+ECOD, gbt and ranker,
      reproduce predictions exactly.
    - Rows from the trainers reload and reproduce the stored `score` / `rank_score`.
    - Rejection cases: tampering (sha), NaN/Infinity on dump and on load, a pickle
      payload, non-JSON bytes, deep nesting, unknown format/kind, length mismatches,
      a malformed tree (out-of-range feature, one child, too deep), a bad ECOD shape.
    - `check_compatible` fails on a feature_version bump, a reordered name, and a
      missing `anomaly_ecod`.
    - A row-width mismatch raises.
    - A legacy NULL row loads as `None`.
    - The same model dumped twice gives the same sha.
    - `persist.py` imports no `pickle` or `marshal`.
    - The prioritizer sha is deterministic and recorded, for `score` and `committee`,
      and `None` for `random`; `pipeline_budget_seed` is recorded. — done
  - [ ] FR-ML-13, FR-ML-9, NFR-ML-reproducible — done
- Implementation divergence (reflected back per the review gate): (1) `model_registry` also gained `params_sha256_for(store, id)`, so `latest_classifier` reads only the sha (not the params text) on every call; (2) the trainers' result dicts gain `params_sha256`; (3) the loader also requires that a classifier's names end in `anomaly_ecod` exactly when an ECOD is stored, a gap found while debugging the stale-bytecode episode.
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; both reviewers independently found BUG-0066; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — `tests/test_ml_persist.py` 47 passed: exact-equality round trips for logistic, gbt, prevalence, hybrid logistic+ECOD, ranker and constant; rows written by the trainers reload and reproduce the stored `score` / `rank_score` (logistic, gbt, hybrid; ranker); fallbacks saved; legacy NULL rows load as None; identical canonical text and sha on re-dump; fail-closed rejection of tampering, a pickle payload, non-JSON text, NaN/Infinity tokens (asserted to be refused at parse time), runaway nesting, unknown format/kind, length/type/key errors, a zero std, malformed and over-deep trees, an unsorted ECOD, and a hybrid name without its ECOD (and vice versa); non-finite models refused at dump (asserted at the serialiser); no pickle/marshal import; `check_compatible` rejects reordered names and a version bump; wrong-width rows refused; the prioritizer sha is deterministic per seed and None for random. Mutation-checked with bytecode caches cleared before every run (a stale-.pyc false result was caught and corrected during this work): removing the sha check, the NaN dump/parse guards, the depth check, the ECOD sort check, the row-width check, `check_compatible`, or saving the hybrid's ECOD each make a test fail. Related suites (ML, report, budget, web incl. browser smoke under `FUZZLAB_REQUIRE_BROWSER=1`): 174 + 270 passed. Full suite at `a3b782d` (2026-10-13, whole `tests/`, `FUZZLAB_REQUIRE_BROWSER=1`): 2915 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same environmental labgen tests as at `369e887` (diffed, identical set); none is caused by this change.

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
- Effectiveness (assessed 2026-10-13): effective offline — the two-run and two-target regressions pass, and each fails with either half of the old keying restored (mutation-checked: label key, fired key). Store-wide dataset == per-run datasets concatenated, labels and features. Full suite (2026-10-13, whole `tests/` at `369e887`, `FUZZLAB_REQUIRE_BROWSER=1`): 2868 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same labgen `--check`/fingerprint-gate tests that fail identically on `origin/main` in this environment (no scipy, scikit-learn or `gitleaks` binary); none is caused by this change.

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
- Effectiveness (assessed 2026-10-13): effective offline — `tests/test_ml_budget_and_scope.py` 20 passed (skipped rows excluded from training / included and labelled False on request / still scored and ranked; one ECOD fit for `hybrid`; `prioritize` falls back for no-earlier, later-only, other-target, one-class data; all four methods deterministic over exactly the given ids; `score` puts the earlier-runs' vulnerable shape first; current-run labels never change the order; committee queue and anomaly panel cover skipped rows; anomaly values persisted and equal to the metric; contamination validated). Mutation-checked: training on the current run, ignoring the target, not excluding skipped rows, scoring labelled rows only, a second ECOD fit, and not persisting anomaly values each make a test fail. Full suite (2026-10-13, whole `tests/` at `369e887`, `FUZZLAB_REQUIRE_BROWSER=1`): 2868 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same labgen `--check`/fingerprint-gate tests that fail identically on `origin/main` in this environment (no scipy, scikit-learn or `gitleaks` binary); none is caused by this change.

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
