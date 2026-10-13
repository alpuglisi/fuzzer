# BUG-0074 — A store-wide model was cited as the model of runs it never scored

- Date: 2026-10-13
- Status: fixed (CC-ML-0023)
- Severity: medium-low. Wrong provenance. The report, the run page and the conformal
  gate's owner named a model for runs it never scored (no score or label was changed).

## Description
`model_registry._covers` treated a `model` row with a NULL scope (a store-wide train,
`train_and_score(store, None)`) as covering **every** run, and a legacy row with no
scope key the same way. A run created after the store-wide train, or one with no
candidates at training time, was then reported with `models=[logistic v1]`,
`model_training={'trained_on': 'run'}`, and the run page named the model, although none
of its candidates had a score.

## Where encountered
The error-review phase. Repro: a store-wide train, then a later run with 0 scored
candidates → the report and run page cite the store-wide model.

## What it caused to fail
- `fuzzlab report`'s `models`, `model_versions`, `model_params_sha256` and
  `model_training` for such runs.
- The run page's model line, and the gate the run page's conformal decisions are read
  through, which judged nothing.

## What the bug was identified to be
An open-ended scope ("NULL = all runs") was read as a fact about each run. The writer
recorded no fact about which runs a store-wide train had actually scored.

## Root cause analysis
Five Whys:
1. *Why was the model cited?* `_covers` returned True for a NULL scope.
2. *Why NULL = all?* A store-wide train re-scores every candidate present, so it covered
   every run **at the time**. The rule had no notion of "at the time".
3. *Why no notion?* The writer recorded only `run_id: null`, not which runs it scored.
4. *Why did BUG-0061's and BUG-0066's work not catch it?* They fixed *which family* and
   *which run's* row a reader selects. They took the scope recorded on the row as given.
5. *Why did no test catch it?* The selection test pinned "a store-wide row covers run 3"
   for a run 3 the row never saw.

**Root cause:** a provenance claim ("this model scored this run") was inferred from an
open-ended recorded scope, not from a recorded fact about the run.

## Corrective action
In CC-ML-0023:
- **The writer records its scope.** A store-wide classifier or ranker train records the
  exact `scored_run_ids` in its calibration: the runs it wrote scores for. It is a list,
  not a maximum: a run below the newest with no candidates is not covered.
- **The coverage rule:**
  - an int scope covers exactly that run;
  - a NULL scope covers `run_id in scored_run_ids` when that is recorded;
  - a NULL scope without the list, or a legacy row with no scope key, covers a run only
    when the run holds at least one non-NULL score in **the family's column** (`score`
    for the classifier, `rank_score` for the ranker).
- **`select_latest`'s `score_column` is a required keyword**, validated against
  `SCORE_COLUMNS`. `latest_classifier` passes `score`, `latest_ranker` `rank_score`.
- **`dataset.run_ids_of`** is now one chunked `DISTINCT` query: a store-wide train
  passes every candidate id.
- **Tests:**
  - the store-wide pin in `test_select_latest_scope_rules` is updated deliberately:
    runs 1 and 3 are scored and covered, run 4 is not;
  - legacy rows are covered only for a run holding that family's score;
  - an invalid column is refused, and an omitted one raises `TypeError`;
  - real store-wide trains of both families record `[r1]`, and neither a run with no
    candidates nor a later run is cited by `latest_*` or the report;
  - each family reader uses its own column (a mutant passing `score` for the ranker is
    killed).
- **Fixtures** that hand-seeded scope-less `model` rows on unscored runs were scoped to
  their run, as production writes them (PA-0071): `test_report._seed`, two
  `test_ml_persist` tests, and the absent-key legacy report test, which now asserts
  both sides.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0061 / PA-0063:** row selection for the multi-producer `model` table, scoped by
  family and run. **Related:** the same reader, but that fix scoped by what the row
  *recorded*; this one is about what the writer failed to record.
- **BUG-0066 / PA-0067:** the report pinned store-wide newest models; a sweep verdict
  must name the reader's scope. **Related:** PA-0067 judged the *reader's* scope, and
  took each row's recorded scope as true.

**Result:** a recurrence of the "a model credited to a run it does not cover" class (the
third, after BUG-0061 and BUG-0066). A prior-PA failure analysis follows.

## Prior-preventive-action failure analysis
- **PA-0063(1)** said to "record [the scope] where the reader can see it (here … `run_id`)
  rather than guessing 'newest'". It accepted NULL as a recorded scope meaning "all".
  NULL is an open-ended claim, not a fact. **The rule was too narrow:** it covered
  recording a scope, not recording a *closed* one.
- **PA-0067(1)** made sweeps name each reader's scope. It never questioned the writer's
  recorded scope. **Wrong layer:** reader-side only.

## Preventive action
**PA-0075** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0063(1) and PA-0067:
1. **A provenance claim about a run ("this model scored / produced X for this run") is
   backed by a recorded fact about that run,** such as an explicit list or a stored
   value in that run's rows. It is never inferred from an open-ended scope (NULL = all,
   "newest", a maximum).
2. **A writer whose scope is open-ended records the closed set it acted on** (here,
   `scored_run_ids`).
3. **A reader of a legacy open-ended row falls back to a fact in the run's own data** (a
   stored score in the family's column), never to "covers everything".

**Sweep (PA-0002):** the other open-ended scopes that back a per-run claim:
- **`model` rows:** fixed (classifier, ranker). Earlier/saved copies carry an int scope.
- **`holdout_metric` / sealed rows:** keyed by run id, closed.
- **`run_plugin` / `run_metrics`:** keyed by run id, closed.
- **`bandit_posteriors`:** a store-wide state, never presented as a per-run fact.
- **`saved_source`:** already refuses NULL and absent scopes.
- **The report's feature versions (BUG-0069):** read from the run's own metrics and
  pinned models, closed.
