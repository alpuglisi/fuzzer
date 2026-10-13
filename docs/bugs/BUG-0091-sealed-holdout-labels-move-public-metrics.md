# BUG-0091 — Sealed holdout labels moved public forward metrics

- Date: 2026-10-13
- Status: fixed (CC-ML-0024, CC-UI-0050)
- Severity: high. The blind holdout (FR-ML-19) is the project's one honest
  generalisation number. Its labels leaked into public numbers, unrecorded, so it was
  no longer blind.

## Description
Trained with `train_on="earlier", holdout=True`, flipping only 9 held-out labels moved
the public forward PR-AUC from **0.667936 to 0.761404**, with the model and its scores
unchanged and **0 rows in `holdout_reveal`**.
- `train._forward_evaluation` and `rank_train._forward_ranking` read every labelled row
  of the run.
- The ML tab's `_scored_pairs` (PR curve, reliability, ECE) and `ranker_panel`
  (NDCG / precision) pooled held rows in earlier, saved and fallback modes.
  `train.metric_input` excluded a held row only for a run-mode out-of-fold score.
- `disagreement_panel` fit its committee on every labelled row.
- More widely: a later model trained **without** `--holdout` on a sealed target
  trained, selected, cross-validated and calibrated on held rows. Its training-time
  numbers, its gate, its saved params, the prioritizer's order and the ranker's `auto`
  choice all moved with the held labels.

## Where encountered
A third-party review of head `5eb4be9` (finding #2). Reproduced with
`scratchpad/ext/f2_holdout.py`.

## What it caused to fail
FR-ML-19: held-out labels never feed a public number, and reading them is counted
(`holdout_reveal`).

## What the bug was identified to be
The seal was a property of **one model's training run**, enforced at the run-mode
out-of-fold readers. Two other producers of public label-derived numbers existed and
were never checked against it:
- the forward evaluations of models that never read the run's labels;
- any model trained without `--holdout` on a target already used for a holdout.

## Root cause analysis
1. *Why did the forward PR-AUC move?* `_forward_evaluation` scored every labelled row,
   held ones included.
2. *Why was it not sealed?* The holdout's sealing (CC-ML-0020) was wired into the
   out-of-fold readers through `metric_input`'s run-mode rule. Forward evaluation is a
   different producer, added by earlier and saved modes, and nobody checked it.
3. *Why did a non-holdout model leak?* The seal was opt-in per training call. Nothing
   remembered that a target's held endpoints had been used as a holdout.
4. *Why undetected?* The holdout tests flipped held labels and checked the **model**
   (its params SHA), never every public number, under every mode.

**Root cause:** the seal was enforced per producer, by enumeration, instead of being a
property of the target that every producer must consult.

## Corrective action
- **Per-target sealing (CC-ML-0024, `ml/holdout.py`).**
  - `sealing_for_run(store, run_id, also=None)` returns `None`, `("sealed", versions)`
    or `"unknown"`, from the holdout records of every model of the run's target.
  - The membership registry `MEMBERSHIPS = {1: (salt, 0.2)}` and
    `in_holdout(origin, endpoint, version)` evaluate any recorded version exactly.
  - One mechanism, `sealed_split(store, ds, ...)` → `(public, held)`, with its reader
    form `held_ids(store, ds)`. Batched origin lookup.
- **Every trainer applies an implied holdout on a sealed target.**
  - `train_and_score` and `train_and_rank`: run and earlier mode, the `auto` / pairwise
    selection included.
  - `active.prioritize` and `propose_queries` (committee).
  - Held rows never train, select, cross-validate, calibrate or set the gate.
  - The model records `holdout: {version, fraction, rows, "implied": true}`, and sealed
    metrics are written as for an explicit holdout.
  - **Store-wide trains** leave out, per row, every sealed target's held rows. An
    unknown target's labelled rows are left out entirely and recorded
    (`excluded_unknown_targets`). No sealed metrics are written (there is no run).
- **Forward evaluation** (classifier and ranker, earlier and saved) reads only the
  public rows (`train.forward_rows`).
- **`metric_input(..., *, held)`**: `held` is required, with no default. An AST guard
  test asserts every call passes it, proven on a synthetic offender.
- **ML-tab readers (CC-UI-0050):**
  - `_scored_pairs` and `ranker_panel` pass `held` from `held_ids`;
  - `disagreement_panel` drops sealed rows from the committee fit, and is unavailable
    on an unknown membership.
- **Fail closed on `unknown`:**
  - run-mode trainers and the prioritizer raise `SealingUnknown`;
  - earlier and saved modes refuse with the reason;
  - readers treat every row of the target as sealed.

  The prioritizer raises rather than returning `None`, which would mean "confirm
  everything" past the operator's budget cap. Through the guarded wrapper, the cap is
  spent in row order, the stage reads FAILED, and the run exits 1.
- **The CLI** prints `holdout: N endpoint(s) of this run held out (implied: target
  sealed)`.
- **Behaviour change, listed:** later runs on a sealed target train on about 20% fewer
  endpoints, `--holdout` or not.
- **Stated residuals:**
  - Forward metrics and copies' calibration written by older code are not rewritten.
  - A saved-mode copy carries its source's pre-seal numbers, which are already public
    and cannot move with today's held labels.
  - The seal covers ML **evaluation** numbers. Findings lists, oracle coverage and
    anomaly flags are the product, and public by design.
- **Tests** (`tests/test_ml_holdout_seal.py`):
  - **The central test** flips **every** sealed label of every run of the target and
    asserts each of these is bit-for-bit unchanged:
    - a later run's non-holdout model: `ml_pr_auc`, `oof_*`, Brier, ECE, `t_lo` /
      `t_hi`, model selection and params SHA;
    - the classifier, ranker and disagreement panels;
    - the earlier-mode PR-AUC, forward and params;
    - the ranker `auto` choice, NDCG and params;
    - saved-mode forward metrics;
    - the prioritizer and committee SHAs, and the committee queries;
    - a store-wide model;
    - every `run_metrics` row.

    A control copy that flips public labels moves them (non-vacuity).
  - The review's repro.
  - The implied record, and an unsealed target trains on every row.
  - Unknown membership, four shapes: refuses everywhere and never `None`, and the
    budget cap holds at the CLI.
  - An unregistered version bump refuses.
  - The registry reproduces the original membership.
  - The AST guards.

  Two existing tests changed for the stated behaviour change:
  - `test_earlier_mode_and_the_prioritizer_drop_held_endpoints`: the prioritizer
    without `--holdout` now drops held endpoints once the target is sealed;
  - `metric_input`'s `held` is required.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0067 / PA-0068** (a gate applied to in-sample scores; "the held-out / in-sample
  distinction is applied per score source") and **CC-ML-0020** (the holdout itself). The
  same class: an evaluation-integrity property enforced at an enumerated set of readers.
  This is a recurrence of that class.

## Prior-preventive-action failure analysis
**PA-0068 was too narrow.** It required each **reader** of out-of-fold scores to apply
the distinction, and CC-ML-0020 sealed held rows exactly there. A **second producer**
of public label metrics (forward evaluation, added by earlier and saved modes), and
trainers called without `--holdout`, were outside the enumeration. The PA listed
readers, and nobody re-listed them when new producers appeared. Nothing made the seal a
property that a new producer could not forget.

## Preventive action
- **PA-0092** (strengthens PA-0068):
  1. **A sealed set is enforced at every producer of public label-derived numbers, by
     one predicate** (`holdout.sealed_split` / `held_ids`), keyed on durable state (the
     target's recorded memberships), never on a per-call flag.
  2. **A seal test flips the sealed labels and asserts every public number and every
     trained artefact is unchanged**, with a control flip proving the check is live.
  3. **The sealing argument is required where it can be forgotten** (`metric_input`'s
     `held`), with an AST guard.

**Sweep (PA-0002):** every reader of labels in `fuzzlab/ml` and `fuzzlab/web`:
- **Sealed now:** the trainers (run, earlier and saved), the prioritizer,
  `propose_queries`, the forward evaluations, `_scored_pairs`, `ranker_panel` and
  `disagreement_panel`.
- **Public by design** (A2, stated in FR-ML-19):
  - `conformal_panel` and `results._scored_candidates` (decisions; no labels);
  - `anomaly_panel` (label-free);
  - the report's findings and coverage (the product).
- **No producer left:** an AST guard asserts that no module but `holdout.py` itself
  uses the today-only `split` / `mask` helpers.
