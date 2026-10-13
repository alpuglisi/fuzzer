# BUG-0067 — Out-of-fold conformal thresholds were applied to in-sample deploy scores

- Date: 2026-10-13
- Status: fixed
- Severity: medium. The run page and the ML tab showed wrong flag / abstain / drop
  triage decisions for every labelled candidate of a run-mode train. The decisions are
  advisory, so no finding, label or score was wrong; but the triage the conformal gate
  exists to provide was not the triage it promises.

## Description
`train_and_score` (run mode) calibrates the conformal gate on **out-of-fold** scores:
`ConformalGate.calibrate(oof, y)` sets `t_hi` / `t_lo` from quantiles of scores produced
by models that never saw each row. It then stores, for every candidate, the **deploy**
model's score (`candidate.score`), and that model was fitted on all labelled rows. Two
readers then applied the gate to those stored scores:

- `web/results.py::_scored_candidates`, the run page's "Model scores (advisory)"
  decisions;
- `web/mlview.py::conformal_panel`, the ML tab's flag / abstain / drop split.

For a labelled row the deploy score is in-sample, so it is pushed toward its own label.
Thresholds that bound the error rate on out-of-fold scores do not bound it on in-sample
ones.

## Where encountered
Flagged in this session's ML review as a design question ("`candidate.score` holds the
deploy fit's scores; the triage thresholds are set on held-out scores but applied to the
other kind"). While settling that question at the user's instruction (batch 1 of the
remaining ML work), reviewer A judged it a wrong result under CLAUDE.md's bug definition,
which made it a defect rather than a design choice.

## What it caused to fail
- On `_seed_rich` (a separable toy set), labelled rows looked confidently right: deploy
  scores are pushed to the extremes, so nearly every row was "flag" or "drop", and the
  "abstain" share was understated.
- The ML tab's flag / abstain / drop split had the same bias. Its all-runs view also
  applied the newest model's thresholds to every run's scores, which was a documented
  limitation.
- The conformal guarantee ("flag above `t_hi` keeps the false-positive rate ≤ α") did
  not hold for the decisions shown.

## What the bug was identified to be
A calibrated artefact (the gate's thresholds) was applied to scores from a different
distribution than the one it was calibrated on. The store kept only one score column, and
recorded nothing about where its values came from, so no reader could tell.

## Root cause analysis
Five Whys:
1. Why were the decisions wrong? The gate (out-of-fold thresholds) judged the stored
   deploy score, which is in-sample for labelled rows.
2. Why did it judge that score? The trainer stored only the deploy score. The
   out-of-fold scores existed only inside `train_and_score` and were thrown away.
3. Why didn't BUG-0062's fix catch it? BUG-0062 / PA-0064(2) dealt with **numbers
   presented as held-out**. The ML tab's recomputed metrics were labelled "in-sample",
   and the OOF numbers were shown next to them. A threshold applied to a score
   produces a *decision*, not a displayed number, so PA-0064's sweep (every place a
   held-out number is produced or displayed) did not cover it.
4. Why could a decision consumer not tell the difference? `candidate.score` carried no
   source. The same column held in-sample (run mode) and out-of-sample (earlier mode)
   values, and a reader had no field to check.
5. Why was there no such field? No rule tied a calibrated artefact to the distribution
   of the scores it is applied to, or required a stored score column to name its source.

**Root cause:** calibrated artefacts (thresholds, calibration maps, held-out metrics)
were not bound to the distribution of the scores they are applied to. The store kept one
unlabelled score column for several score distributions.

## Corrective action
Delivered in CC-ML-0018 / CC-CORE-0029 / CC-UI-0042 (with CC-PLUG-0006), after a 3/3
pre-change review:
- **Migration 16** adds `candidate.score_oof` and `rank_score_oof`. In run mode every
  labelled row gets its out-of-fold score; every scoring pass writes or clears both
  columns. `score` stays the deploy score, so the saved model still reproduces every
  stored `score` (CC-ML-0015 kept).
- **Each model row records `score_source`.**
- **One rule, `train.gate_input(calibration, oracle_status, score, score_oof)`,** gives
  the only score a gate may judge:
  - a labelled run-mode row's `score_oof`;
  - a row nobody checked, or any earlier- or saved-model score, as `score`;
  - a legacy run-mode row: nothing, shown as "n/a (in-sample score)", except a
    budget-skipped row.
- **The run page** decides with it and shows the "decision score" it used.
- **The conformal panel** decides each row with its own run's classifier and that rule,
  counts n/a rows separately, and so also closes the all-runs limitation.
- **The ML tab's metrics** are recomputed from `score_oof` and labelled "out-of-fold
  (labelled rows)".
- **Tests** (`tests/test_ml_saved_and_decisions.py`, `tests/test_web_ml.py`):
  - the run-page decisions use the out-of-fold score;
  - a legacy-shaped run gives "n/a (in-sample score)";
  - re-scoring in earlier mode clears the old out-of-fold scores;
  - the conformal panel gates out-of-fold scores, which the test makes contradict the
    deploy scores.

  Mutation-checked: making either reader judge `score`, ignoring `score_oof`, gating
  legacy rows, or not clearing the column each fails a test.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0062 / PA-0064**: in-sample metrics reported as out-of-fold. **The same root-cause
  class**: confusing in-sample with held-out scores. This is a recurrence in a new kind
  of consumer, a decision rather than a metric.
- **BUG-0061 / PA-0063**: the wrong model's gate on the run page. A different class (row
  selection), but the same reader. Its fix chose *which* gate; this one fixes *what the
  gate judges*.

**Result: a recurrence of the BUG-0062 / PA-0064 class.**

## Prior-preventive-action failure analysis
- **PA-0064(2) was too narrow.** It said held-out numbers come from a verified
  partition, and in-sample numbers are labelled in-sample wherever displayed. Its scope
  was *numbers*, so thresholds and calibration maps applied to stored scores fell
  outside it.
- **PA-0064(4)'s sweep** covered "every place a held-out number is produced or
  displayed". It found the ML tab's metrics and labelled them, but did not look at
  `gate.decide(score)` call sites, because those produce decisions, not numbers.
- **Not enforceable at the data layer.** No column recorded a score's source, so no
  test could check that a consumer read the right one.

## Preventive action
**PA-0068** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0064 from numbers to every
calibrated artefact:
1. **An artefact judges only its own distribution.** A threshold, calibration map or
   held-out metric is applied only to scores from the distribution it was calibrated or
   computed on. When none is available the consumer says so ("n/a (…)"); it never
   substitutes another score (PA-0064(1)).
2. **Stored scores name their source.** A model row records `score_source`. A
   distribution that must be kept gets its own column, never a mix in one column. One
   function decides which score a gate may judge (`train.gate_input`, PA-0003).
3. **Writers own their paired columns.** The writer of a score column writes or clears
   its paired columns in the same pass, so a re-scored run never keeps another model's
   values.
4. **Sweep by consumer.** The PA-0002 sweep for this class covers every *consumer* of a
   calibrated artefact: every `gate.decide`, every threshold comparison, every
   calibration applied. Producers alone are not enough.

**Sweep (PA-0002, judged by reader scope per PA-0067(1)):**
- `web/results.py::_scored_candidates` (one run's page): **instance**, fixed.
- `web/mlview.py::conformal_panel` (one run, or all runs): **instance**, fixed, now gated
  per run.
- `web/diagnostics.py` score histogram (distribution display, no threshold): not an
  instance.
- `ml/active.py` (prioritizer: ranks its own fresh model's scores; no stored-score
  threshold): not an instance.
- `harness/auto_cli` summary (prints OOF metrics from the trainer's result; no stored
  score): not an instance.
- The ML tab's recomputed classifier/ranker metrics (a held-out claim): now recomputed
  from `score_oof` and labelled, fixed.
