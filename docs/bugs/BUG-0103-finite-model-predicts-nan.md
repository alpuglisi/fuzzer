# BUG-0103 — A finite subnormal standard deviation made a saved model predict NaN

- Date: 2026-10-13
- Status: fixed (CC-ML-0025)
- Severity: low-medium. The audit rated it Medium. It needs a crafted or damaged
  saved model, but it then writes non-probabilities into the store.

## Description
The loader accepted any finite nonzero `std`, including `5e-324` and negative values.
For an input of `1.0`, standardisation overflowed to `inf`, `0.0 * inf` gave `NaN`, and
`_sigmoid(NaN)` returned NaN: `predict_proba` gave `[nan]`. With a nonzero weight the
probability saturated to exactly 0 or 1 (B-S4).

## Where encountered
A third-party audit (finding #7), reproduced with `scratchpad/ext2/f07_nan.py`.

## What it caused to fail
FR-ML-13 (a loaded model reproduces valid scores); scores and gates downstream.

## What the bug was identified to be
Operand-level validation (each value finite) without validating the arithmetic.

## Root cause analysis
1. *Why NaN?* Finite operands overflowed in division.
2. *Why accepted?* `_check_logistic` rejected only `std == 0`.
3. *Why not caught?* PA-0096 tested operands at extremes, not the computations they
   feed.

**Root cause:** no closure check on a loaded model's arithmetic.

## Corrective action
- `_check_logistic` requires `std ≥ STD_FLOOR` (1e-12). The trainer now applies the
  same floor, so a near-constant feature is scaled by 1.0 and no saved model can fall
  below it.
- `LoadedModel` checks that every standardised `z` and logit is finite
  (`LogisticRegression.check_finite`), for classifiers and rankers. It also checks
  every output is finite (in [0, 1] for probabilities) **before returning any**.
  Otherwise it raises `ModelParamsError`.
- Saved mode scores inside its guard, so such a model is a refusal.
- **Tests** (`tests/test_ml_persist.py`):
  - 4 below-floor values → refused;
  - an overflowing input → refused at scoring;
  - a NaN output → refused;
  - the trainer floor;
  - existing saved-mode refusals.

## Recurrence review
- **BUG-0095 / PA-0096:** the same loader. A recurrence of the class.

## Prior-preventive-action failure analysis
**PA-0096 was too narrow.** It required extreme *operands*, not proof that the
arithmetic they feed stays finite.

## Preventive action
- **PA-0104:** a loaded model's intermediate values and outputs are validated (finite,
  in range) before use. Operand validation alone does not prove closure.

**Sweep:**
- GBT: the leaf values are finite and summed, which stays finite within the
  `MAX_TREES` bound;
- prevalence: a constant;
- ECOD: rank-based and bounded;
- Platt: `a > 0` finite, and its output is checked by `_closed`.
