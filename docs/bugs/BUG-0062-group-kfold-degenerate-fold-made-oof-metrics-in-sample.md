# BUG-0062 — `group_kfold`'s degenerate fold made "out-of-fold" ML metrics in-sample

- Date: 2026-10-13
- Status: fixed
- Severity: medium (the T5.5/T7.4 "beats the control" exit signals could read true from
  in-sample numbers; reachable on a one-endpoint dataset or any `k < 2` call)

## Description
`fuzzlab.ml.metrics.group_kfold` promises folds that "never split a group across folds",
which is what makes the classifier's and ranker's out-of-fold (OOF) evaluation honest.
With fewer than 2 distinct groups (endpoints), or `k < 2`, it instead yielded a single
`(idx, idx)` fold: every row in both train and test. Both trainers then scored each row
with a model that had seen it, and reported the result as out-of-fold.

## Where encountered
Found in a code review of the ML components on `main` @ `0800e42` (2026-10-13):
`list(group_kfold(["/a"]*4, k=5)) == [([0,1,2,3], [0,1,2,3])]`. Both reviewer agents
of this change's pre-change review gate re-ran it end to end. With 24 candidates and 6
positives all on `/one.php`, `train_and_score(auto)` returned `fallback=False`,
`pr_auc=1.0`, `beats_baselines=True`, and `train_and_rank` returned `ndcg=1.0`,
`beats_baseline=True`. With 10 endpoints, `train_and_score(..., k=1)` also returned
`pr_auc=1.0`.

## What it caused to fail
- `run_metrics` rows `ml_pr_auc*` / `rank_ndcg*` / `rank_precision*` and the result
  dicts' `beats_baselines` / `beats_baseline` are the **T5.5 / T7.4 exit signals**
  (`docs/ON_HOST_TASKS.md`). On a dataset with a single endpoint, or with `k < 2`, they
  reported in-sample performance as held-out, and could claim to beat the baselines.
- The conformal gate was calibrated on those in-sample "OOF" scores, so its error-rate
  bound did not hold.
- Found by the PA-0002 sweep: the ML tab (`mlview.classifier_panel` / `ranker_panel`,
  `ml.js`) recomputed PR-AUC, ECE, nDCG@k and precision@k from the stored
  `candidate.score` / `rank_score`. Those are the deploy fit's scores on its own
  training rows, so in-sample for **every** dataset. The tab showed them unlabelled,
  beside a baseline, as if they were held-out numbers.

## What the bug was identified to be
1. `group_kfold`'s degenerate branch returned a result that violates the function's own
   stated invariant, where it should have returned nothing.
2. The trainers' thin-data gate (`n < min_rows or pos < min_positives or (n - pos) < 1`)
   counted rows and positives but not groups, and did not check `k`.
3. `_oof_scores` never checked that its folds formed a real held-out partition.
4. The ML tab's display presented in-sample numbers without saying so.

## Root cause analysis
Five Whys:
1. Why was the OOF PR-AUC 1.0? Each row was scored by a model trained on that row.
2. Why? `group_kfold` yielded `(idx, idx)` for a one-group dataset.
3. Why did it yield anything at all? Its author (`CC-ML-0002`) chose "degrade to one
   fold over everything" as the convenient behavior for a degenerate input, so callers
   would always get *some* scores. That convenience silently traded away the one
   property the function exists to provide.
4. Why didn't a caller notice? Neither caller checked the folds, and the gate that
   decides whether a model may be evaluated at all did not test the precondition the
   evaluation needs (at least 2 groups and `k >= 2`).
5. Why didn't a test notice? Every `group_kfold` test used 10–24 groups. No test
   entered the degenerate branch and asserted the invariant there.

**Root cause:** an evaluation helper met an input it could not handle honestly by
returning a contract-violating result (train == test) rather than no result. Nothing
downstream (the gate, the scorer, the tests, the display) checked that a number
presented as held-out actually came from a held-out partition.

## Corrective action
Delivered in `CC-ML-0012` (`docs/components/10-ml-components/change-control.md`) and
`CC-UI-0035` (`docs/components/12-diagnostics-and-ui/change-control.md`), after a
3/3-agreed pre-change review:
- `group_kfold` yields **no folds** when `k < 2` or there are fewer than 2 distinct
  groups.
- New `metrics.oof_folds` is the one entry point both `_oof_scores` use. It raises
  `ValueError` unless every row is held out exactly once and never trained on in its
  own fold, so an empty or partial partition fails closed.
- `train_and_score` / `train_and_rank` take `min_groups=2`, compute `groups` before the
  gate (it is in the result on every path), and fall back when
  `groups < max(2, min_groups)` or `k < 2`. A fallback writes no OOF metrics.
- The trainers also store their OOF numbers in their own `model` row's calibration
  (`CC-ML-0011`). The ML tab labels its recomputed numbers "in-sample (deploy fit)" and
  shows the scoring model's own OOF numbers beside them. It shows them only when they
  belong to the model that wrote the displayed scores, otherwise `null`.
- `tests/test_ml_oof.py` (19 tests) covers:
  - the degenerate branch, plus a randomized partition property;
  - `oof_folds` failing closed;
  - both trainers on one endpoint, with `k=1`, and with `min_groups`;
  - the private scorers;
  - the ML tab labels;
  - a guard that no module outside `metrics.py` calls `group_kfold` directly.

  With the old branch restored, the degenerate-branch, partition and fail-closed tests
  fail.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0016 / PA-0017**: an exit-criterion metric that could pass without measuring
  the capability it claimed (a global frontier, a request count dominated by
  discovery). **Same class.** `ml_pr_auc` / `rank_ndcg` vs their baselines are the
  T5.5/T7.4 exit metrics, and here they could pass while measuring memorization rather
  than generalization.
- **BUG-0027 / PA-0029**: a checker whose gated-off branch switched off its own
  invariant, with no test entering that branch. Same mechanism, in a different kind of
  artifact (a checker, not an evaluation split).
- **BUG-0024 / PA-0026**: a third-party call silently returning a degenerate result for
  an unsupported input shape. Related: there it was a library behind an adapter; here it
  is first-party code.
- `labgen`'s grouped CV (`leakage_probe.py`, `corpus_analysis.py`) already does the
  right thing. sklearn's `StratifiedGroupKFold` raises on too few groups, and
  `MIN_GROUPS_FOR_GATE` gates it.

**Result: a recurrence of the BUG-0016 / PA-0017 class**, by the BUG-0027 / PA-0029
mechanism.

## Prior-preventive-action failure analysis
- **PA-0017** did not prevent this because it covers how a metric is *designed* ("isolate
  the capability via a controlled comparison, not a proxy"). The design here was right:
  grouped OOF evaluation compared against two baselines. What failed was the evaluation
  machinery *degrading silently on degenerate input*, which PA-0017 does not address.
  It asks whether the metric is the right comparison, not whether the comparison still
  holds at the edge of its inputs. Too narrow.
- **PA-0029** did name the mechanism (a branch that gates off an invariant needs a test
  that enters it). But it is scoped to *checkers* whose "no violation" verdict depends
  on a gated branch. `group_kfold` is a split generator, so it never appeared to fall
  under the rule. The ML package also predates PA-0029 (2026-09-21 vs 2026-09-22), and
  PA-0029's own PA-0002 sweep looked at checkers of its kind, not evaluation helpers.
  Too narrow, and swept by artifact type rather than by mechanism. That is the failure
  PA-0018 already diagnosed for container operations.
- Neither rule is mechanically enforced for evaluation code. No test asserted the
  invariant on the degenerate branch.

## Preventive action
**PA-0064** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0017 and extends PA-0029
from checkers to evaluation machinery:
1. An evaluation helper (a splitter, a scorer, a metric) that cannot satisfy its contract
   for some input returns **no result or raises**. It never returns a contract-violating
   result. Callers treat "no result" as thin data, through the same documented fallback
   they already have.
2. A number presented as held-out (out-of-fold, holdout, an exit criterion) is computed
   only through a path that verifies the partition (`metrics.oof_folds`). A number
   recomputed from in-sample scores is labelled in-sample wherever it is displayed, and
   shown only beside the held-out numbers of the model that produced those scores.
3. Every degenerate or fallback branch of an evaluation helper has a test that enters
   it and asserts the contract there, not only on typical inputs.
4. Mechanically enforced for this package by
   `tests/test_ml_oof.py::test_no_out_of_fold_scorer_bypasses_oof_folds` (no raw
   `group_kfold` call outside `metrics.py`, proven first on fixtures per PA-0034(2)) and
   by the degenerate-branch tests.

**PA-0002 sweep, by mechanism (silent in-sample evaluation), across `fuzzlab/`.**
Fixed:
- `group_kfold`, both trainers' gates, both `_oof_scores`.
- The ML tab's classifier and ranker panels (`CC-UI-0035`).

Not instances:
- `labgen` grouped CV (sklearn raises, plus `MIN_GROUPS_FOR_GATE`).
- `active.Committee` fits on all data, but only to choose what to label next, not to
  evaluate.
- `anomaly.augment` in `hybrid=True` fits ECOD on all rows before CV. It is
  label-free, so it leaks no label.

Flagged, not fixed:
- `train_and_score` calibrates the conformal gate on OOF scores, but writes and gates
  the deploy model's in-sample scores (`train.py`, the deploy fit after
  `ConformalGate.calibrate`).
- `rank_uncertainty`, which `active.propose_queries` reads, likewise comes from
  in-sample rank scores.
- Neither is an instance of this class. Neither presents an in-sample number as
  held-out; both are the methodological question of what `candidate.score` should mean
  for candidates that are already labelled. Choosing an answer is a design decision,
  raised with the operator rather than made unilaterally here.
