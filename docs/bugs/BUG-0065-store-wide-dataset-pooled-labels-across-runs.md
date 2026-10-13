# BUG-0065 — The store-wide ML dataset pooled labels and rule counts across runs and targets

- Date: 2026-10-13
- Status: fixed
- Severity: medium (silent label leak. ML metrics, training sets and query queues built
  over more than one run were computed on wrong labels and inflated features. Advisory
  ML only: no `finding` row was affected.)

## Description
`fuzzlab/ml/dataset.py::build_dataset(store, run_id=None)`, the store-wide mode, joined
three tables on **content** rather than on run:
- each candidate's label came from a set of finding keys `(path, param, category)`;
- its `rules_fired` count came from a map of evaluations keyed `(path, param)`.

Both were collected across **every run in the store**. So a candidate took its label
from *any* run's finding for that path and parameter, and its rule count was the sum
over all runs. Per-run calls (`run_id=N`) were unaffected, because their finding and
evaluation lookups were already filtered to that run.

## Where encountered
Found on 2026-10-13 by a reviewer agent in the pre-change review gate for CC-ML-0013
(budgeted confirmation), which needs cross-run training. Independently reproduced:
- **Label leak:** two runs each have a candidate on `/p.php?id`, and only run 1's oracle
  confirmed it. The store-wide dataset labels both candidates `[1, 1]`; run 2's,
  which the oracle *rejected*, is labelled positive.
- **Count inflation:** `rules_fired` is `1.0` per run but `[2.0, 2.0]` store-wide. With
  two copies of `_seed_rich` it was 4.0 instead of 2.0.
- **Across targets:** the key drops the host (`to_path`), so two labs in one store
  share labels for a path such as `/index.php?id`.

## What it caused to fail
- **The ML tab's default view.** `GET /ml` loads `/api/ml/data` with no `run_id`, and
  `mlview.classifier_panel`, `ranker_panel`, `anomaly_panel` and `disagreement_panel`
  all call `build_dataset(store, None)`. On any store with more than one run of the same
  app, the tab's PR-AUC, reliability, nDCG@k, histograms and committee queue were
  computed on leaked labels and inflated features.
- **Store-wide training** (`train_and_score(store, None)`, `train_and_rank(store, None)`,
  `propose_queries(store, None, …)`) trained and evaluated on wrong labels. The CLI
  always passes a `run_id`, but these calls are public and used in the runbook.
- **Latent:** any future cross-run training, such as the budget prioritizer this change
  adds, would have learned from rejected candidates labelled positive. It would have
  scored new candidates against inflated counts it never sees at inference time.

## What the bug was identified to be
The joins of `finding`→`candidate` and `evaluation`→`candidate` inside `build_dataset`
were keyed only on `(path, param[, category])`, without `run_id`. That key is unique
within one run but not across runs.

## Root cause analysis
Five Whys:
1. Why was a rejected candidate labelled positive? Its `(path, param, category)` key
   was in the positives set, which another run's finding had put there.
2. Why could another run's finding match? The positives set was built from every
   finding in scope, and the store-wide scope is every run.
3. Why was the key missing `run_id`? `build_dataset` was written (`CC-ML-0003`) with
   per-run use in mind, where the scope filter makes `(path, param)` unique. The
   store-wide mode reused the same join, and a wider scope silently changes what the
   key means.
4. Why did no test catch it? Every `build_dataset` test seeds a single run, so the
   store-wide path was only ever exercised on stores where it equals the per-run path.
5. Why didn't BUG-0061's review catch this class? See below. PA-0063 was scoped to
   selecting *rows* from a shared table, not to *joining* rows across tables.

**Root cause:** a join between tables that are written per run was keyed on content that
is unique only within a run. Widening the query's scope to many runs silently turned
"the same point in this run" into "the same path in any run". No multi-run test pinned
the store-wide semantics.

## Corrective action
Delivered in `CC-ML-0014` (`docs/components/10-ml-components/change-control.md`), after a
3/3-agreed pre-change review, in the same commit as CC-CORE-0026, CC-ML-0013 and
CC-FUZZ-0048:
- `build_dataset` keys positives by `(run_id, path, param, category)` and `fired` by
  `(run_id, path, param)`, and reads each table's `run_id`. A candidate's label and rule
  count now come from its own run only, so the store-wide dataset is exactly the
  concatenation of the per-run datasets.
- The same change adds the scope filters the budget prioritizer needs: `before_run_id`,
  and `target` (the pipeline's `target.base_url`).
- `tests/test_ml_budget_and_scope.py`:
  - `test_store_wide_dataset_takes_labels_and_counts_from_each_rows_own_run` checks
    labels **and** features equal the per-run concatenation;
  - `test_store_wide_dataset_never_labels_across_targets` covers two targets.
  - With either half of the old keying restored, each test fails (mutation-checked).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0061 / PA-0063** (found earlier the same day). Readers of the shared `model`
  table picked "the newest row of any family, any run". **Same root-cause class:** a
  store read whose correctness depends on scope (family, run), written as if one scope
  were implied. There the symptom was *row selection*; here it is a *join key*.
- **BUG-0003 / PA-0003, BUG-0007 / PA-0021**: one convention, several sites, no shared
  function. Related through PA-0063, but this bug is a single site with the wrong key,
  not a duplicated convention.

**Result: a recurrence of the BUG-0061 / PA-0063 class**, in a different query shape.

## Prior-preventive-action failure analysis
PA-0063 did not prevent this, for two reasons:
1. **Too narrow: it named row selection.** It says that choosing "the current row" of a
   multi-producer table lives in one scoped reader, and its guard test catches "newest
   row" reads of `model`. A join that builds a lookup from one table and applies it to
   another (findings → candidates) is not a row selection, and the guard cannot see it.
2. **Its sweep was keyed on the trigger, not the mechanism.** BUG-0061's PA-0002 sweep
   grepped for "latest row" patterns (`DESC LIMIT 1`, `MAX(id)`, `ORDER BY id DESC`).
   That found every selection, but not content-keyed joins across runs. PA-0018
   diagnosed exactly this failure for container operations: sweeping by the symptom's
   shape instead of by the mechanism.

## Preventive action
**PA-0066** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0063 from row selection to
every multi-run read:
1. Any lookup built from one per-run table and applied to rows of another (labels,
   counts, features) is keyed by `run_id` plus the content key. Content such as
   `(path, param)` is unique only within a run, and across targets not even that.
2. Any function that can run at more than one scope (one run, or all runs) has a test
   that seeds **at least two runs** and asserts the wide-scope result equals the
   concatenation of the per-run results. A single-run fixture cannot distinguish a
   correctly scoped join from a leaking one.
3. The PA-0002 sweep for a scope bug runs by mechanism. Grep every query that reads a
   per-run table without a `run_id` filter or id join, not only the query shape that
   surfaced the bug.

**PA-0002 sweep (by mechanism):** every `FROM finding|evaluation|attempt` and every
`FROM candidate` read in `fuzzlab/` was checked.
- `integration.py:27`, `results.py:324` and the per-run pipeline reads filter on
  `run_id`.
- `proxycontrol.py:366` and `results.py:170`, `:219`, `:241` join on ids (`run_id`,
  `attempt_id`, `candidate_id`).
- `results.py:112`, `:379`, `:382` and `findingsview.py:81` are deliberate store-wide
  totals and lists, not keyed joins.
- `build_dataset` was the only content-keyed cross-run join. Fixed.
