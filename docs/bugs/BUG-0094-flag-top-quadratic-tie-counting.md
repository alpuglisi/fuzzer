# BUG-0094 — `flag_top` counted tie groups quadratically

- Date: 2026-10-13
- Status: fixed (CC-ML-0024)
- Severity: medium. The review rated it High. The output was always correct; the cost
  was CPU on the anomaly and flow-anomaly stages, quadratic in the number of scored
  rows when scores tie heavily.

## Description
`ml.anomaly.flag_top` counted each tie group with
`sum(1 for s in scores if s == value)` inside a loop over `set(scores)`: O(n·u)
equality comparisons, O(n²) when the distinct values grow with n.
- **Comparisons:** n=1k → 101,000; 2k → 402,000; 4k → 1,604,000.
- **Time:** 10k → 0.23 s, 20k → 0.99 s, 40k → 3.93 s.

It also runs in the flow tripwire, where proxy flow histories can be large.

## Where encountered
A third-party review of head `5eb4be9` (finding #5). Reproduced with
`scratchpad/ext/f5_quadratic.py`.

## What it caused to fail
FR-ML-12 (the anomaly tripwire) did not fail functionally. Its cost grows
quadratically on a per-candidate / per-flow path.

## What the bug was identified to be
A per-element scan nested inside a loop over the same collection's distinct values.

## Root cause analysis
1. *Why quadratic?* A count was recomputed by a full scan for every distinct value.
2. *Why written that way?* BUG-0070's sweep rewrote the function for correctness (whole
   tie groups) and reached for the most literal expression.
3. *Why not caught?* Tests asserted the flags, never the cost. No rule asked for an
   operation-count bound on per-candidate paths.

**Root cause:** no complexity requirement or test on per-candidate / per-flow
functions.

## Corrective action
- **CC-ML-0024.** One `Counter` pass, then a walk over the sorted distinct values,
  O(n + u log u), keeping the whole-tie-group rule bit for bit.
- **Behaviour change, stated:** a non-finite score raises `ValueError`, since NaN has
  no place in an ordering. Inside the anomaly / flow-anomaly stages it is contained
  (stage FAILED, exit 1). ECOD and Isolation Forest produce finite scores on finite
  features.
- **Tests** (`tests/test_ml_anomaly.py`):
  - an equivalence test against the old function (inlined verbatim as the reference)
    on 500 random tie-heavy lists × 5 contamination levels;
  - an operation-count test: equality and hash operations ≤ 10·n at n=4000 (the old
    function made 1.6 M);
  - NaN / ±inf → `ValueError`.

  4 of the new cases fail on `5eb4be9`. The equivalence test passes on both, by
  design.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`: no prior bug or PA on
algorithmic cost. BUG-0070's sweep wrote this function, for a different (correctness)
reason. **Not a recurrence.**

## Prior-preventive-action failure analysis
Not applicable: no prior PA covered complexity.

## Preventive action
- **PA-0095:**
  1. **A per-element loop over a collection inside a loop over the same collection's
     values is O(n²).** Count with `Counter` or a sort.
  2. **Any function on a per-candidate or per-flow path has a test bounding its
     operation count** at a size where the quadratic form would be visibly worse.

**Sweep (PA-0002):** `grep` for `for … in set(`, `.count(` and `.index(` inside loops,
and for `sum(1 for` inside loops, in `fuzzlab/ml`, `fuzzlab/oracle`, `fuzzlab/fuzz` and
`fuzzlab/web/mlview.py`:
- `text_features.fit` (per-document n-gram set, linear);
- `holdout._origins` (per run);
- `flag_reason` (linear, outside any loop);
- the metric helpers (single passes).

No other quadratic counting found.
