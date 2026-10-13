# BUG-0073 — The ML tab's ranker "random baseline" was not comparable with its metric

- Date: 2026-10-13
- Status: fixed (CC-UI-0048, CC-ML-0023)
- Severity: medium. The ML tab told the reader that a ranker with no signal was about
  5× better than random. A second cause, found while fixing, let a constant ranker
  win or lose by input order in every ranker metric, the trainer's included.

## Description
`mlview.ranker_panel` had two problems:
- **Different statistics.** It showed `precision_at_k` as a per-page mean over pages
  that have a positive, against `random_baseline_precision_at_k` = the global
  prevalence. On a thin-data run (the constant fallback ranker) it showed precision@k
  0.5 against a "baseline" of 0.1.
- **No nDCG baseline.** The bars chart plotted nDCG against a hard-coded 0.

Fixing this exposed a second cause. `ml/ranking.py` broke tied scores by the items'
**input order** (a stable sort). The module docstring claimed this meant a constant
scorer "degrades to the input order rather than silently winning". But when the input
order happens to list positives first, as audit/insert order can, a constant scorer
gets a perfect nDCG. On the repro it scored 1.0 against a random-order expectation of
about 0.785.

## Where encountered
The error-review phase (a review agent; reproduced by me). The tie cause was found while
implementing the agreed fix, when the agreed test "a constant ranker's panel metric ≈
its baseline" failed. That divergence was reviewed by both reviewers, who agreed.

## What it caused to fail
- The ML tab's ranker panel: metric and baseline were not comparable.
- Every ranker metric over tied scores, the trainer's included: the fallback ranker,
  and any model with tied scores. These were order-dependent rather than neutral.

## What the bug was identified to be
1. The panel computed the metric and its baseline with **different functions over
   different rows**.
2. The metrics' tie handling was **input order**, which is not neutral.

## Root cause analysis
Five Whys:
1. *Why 0.5 vs 0.1?* The metric averages per page over pages with a positive; the
   baseline is a global prevalence.
2. *Why different?* The panel wrote its own baseline instead of calling the trainer's
   `_evaluate`, which already computed both over the same rows.
3. *Why did a constant ranker still beat the random order?* Ties were broken by input
   order, and the input order correlated with the labels.
4. *Why was input order thought safe?* The docstring asserted it without a test that a
   constant scorer equals the random expectation.
5. *Why did no rule catch either?* PA-0069 rule 2 requires an order-statistic
   threshold to state its tie handling. Its sweep (rule 4) listed *thresholds*, and a
   top-k *metric* is an order statistic too. No rule required a metric and its baseline
   to come from one function.

**Root cause:** a metric and its comparison baseline were derived separately, and a
score-ordered metric's tie handling was not neutral and not tested.

## Corrective action
- **One function (CC-ML-0023).** `rank_train._evaluate` is now the public
  `evaluate_vs_random`, the one function for a ranker metric and its seeded random
  control. The panel calls it over the same rows and groups, with the model's recorded
  seed. It returns `random_baseline_ndcg_at_k` and `random_baseline_precision_at_k`.
  The JS meta line and bars chart show both baselines (CC-UI-0048).
- **Ties averaged (CC-ML-0023).** `ndcg_at_k` and `precision_at_k` give each slot of a
  tied group the group's mean relevance. This is exactly the expectation over all
  orders of the tie (DCG and precision are linear in per-slot relevance; IDCG doesn't
  depend on order); it is sklearn's `ignore_ties=False` semantics. A constant scorer
  now equals the random-order expectation, whatever the input order.
- **Non-finite scores refused.** NaN never equals itself, so it would form its own tie
  group in an undefined order. A `ValueError` is raised instead.
- **The trainer ranks on stored values** (PA-0069(3)). `evaluate_vs_random` rounds
  scores to the 6 dp `_write_ranks` stores, so ties created by storage rounding are
  the ones the panel sees.
- **Tests:**
  - the old `test_ties_break_to_original_order` is replaced by an input-order-
    independence test with hand-computed partial ties;
  - a brute-force permutation test: a constant scorer equals the exact random
    expectation, for k ∈ {1, 2, 3, 5};
  - a NaN refusal test, and a 6-dp rounding test;
  - a panel test (`tests/test_web_ml.py::test_a_constant_ranker_shows_no_lift_over_its_baseline`):
    precision@k equals the baseline (0.5 = 0.5; it was 0.5 vs 0.1), and nDCG equals
    the permutation expectation (< 1.0).
  - Unchanged: no stored value, golden or other test moved (250 ML / web tests).
- **Semantics change, named:** newly recorded `rank_ndcg` / `rank_precision`, the
  forward and holdout numbers, and pairwise `auto` selection differ from old values
  **only where scores tie**. Old `model.calibration` `oof_*` values were computed under
  the old rule and are not rewritten. For a tied (e.g. fallback) model trained before
  this change, the panel's recomputed metric can differ from the stored `oof_ndcg`.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0070 / PA-0069** (the conformal gate exceeded α; finite-sample quantile; ties).
  **Same class for the tie cause:** a score-ordered computation whose tie handling was
  not stated and tested. PA-0069 rule 2 says an order-statistic threshold states its
  tie handling; rule 4 sweeps every order-statistic threshold.
- **PA-0003 / PA-0021** (one convention, one helper): the panel's private baseline
  re-derived what `_evaluate` already computed.

**Result:** a recurrence of BUG-0070's class. A prior-PA failure analysis follows.

## Prior-preventive-action failure analysis
- **PA-0069 rule 4's sweep was too narrow.** It was keyed on *thresholds* (`sorted(…)[k]`,
  quantiles, contamination), so top-k *metrics* in `ranking.py` were passed over,
  though precision@k and nDCG@k cut at the k-th order statistic exactly the same way.
- **PA-0003 was not applied to comparisons.** It is worded around stored conventions, so
  the panel's baseline was not recognised as a second derivation of the trainer's
  control.

## Preventive action
**PA-0074** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0069(2)/(4) and PA-0003:
1. **A metric and its baseline are computed by the same function over the same rows.**
   A displayed baseline that is not is a defect.
2. **Every score-ordered computation states its tie handling**: a threshold, a top-k
   metric, or a selection cut. Input order is never the tie-break for a metric or a
   guarantee. A constant scorer is tested to equal the random expectation.
3. **The PA-0002 sweep for this class covers every score-ordered computation.**

**Sweep (PA-0002):**
- **Metrics already tie-neutral:** `metrics.pr_auc`, `metrics.precision_at_recall` and
  `mlview._pr_curve` read precision and recall after whole tie groups. `mcc` takes 0/1
  predictions, so it has no ties to break.
- **Already fixed:** `anomaly.flag_top` (BUG-0070).
- **Out of class:** `active.prioritize`'s stable tie sort orders work, not a metric.
- **Fixed here:** `ranking.ndcg_at_k`, `ranking.precision_at_k`.
- **Baselines shown in `mlview`, the report and the CLI:**
  - the classifier's prevalence / σ baselines are computed in `_select_and_evaluate`
    on the same out-of-fold pairs as its PR-AUC, which is consistent;
  - the ranker's forward / holdout / OOF numbers use `evaluate_vs_random`, which is
    consistent;
  - the panel was fixed here.
