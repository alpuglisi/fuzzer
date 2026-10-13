# BUG-0070 — The conformal gate flagged and dropped more than α of its own calibration set

- Date: 2026-10-13
- Status: fixed (CC-ML-0019, CC-UI-0044, CC-FUZZ-0052)
- Severity: medium. Every conformal gate claimed a per-side error rate of α but, at the
  data sizes the lab produces (20–50 labelled rows per class), flagged up to **2α** of
  the negatives and dropped up to 2α of the positives. The decisions are advisory, so
  no label, finding or stored score was wrong; but the bound the gate exists to provide
  did not hold. The PA-0002 sweep found the same defect class in the anomaly tripwire,
  which flagged whole tie groups beyond its contamination fraction (30–33% instead of
  10% on the repo's own fixtures).

## Description
`ConformalGate.calibrate` set `t_hi = sorted_neg[round((1-α)(n-1))]`, and `decide`
flags `score >= t_hi`. The threshold element itself, and every negative tied with it,
was therefore flagged. That is an off-by-one in the finite-sample quantile. The drop
side was the mirror image (`t_lo = sorted_pos[round(α(m-1))]`, drop `score <= t_lo`).

Measured on the calibration set itself (uniform scores, α = 0.1):

| n per class | flag rate on negatives | drop rate on positives |
| --- | --- | --- |
| 5 | 0.20 | 0.20 |
| 10 | 0.20 | 0.20 |
| 20 | 0.15 | 0.15 |
| 50 | 0.12 | 0.12 |
| 100 | 0.11 | 0.11 |
| 200 | 0.105 | 0.105 |

On new exchangeable data the rate was also above α. For n = 20 the old rule flags a
fresh negative with probability 4/21 ≈ 0.19; the split-conformal rule gives 2/21 ≈ 0.095.

A second, smaller contributor: the gate was calibrated on **unrounded** out-of-fold
scores, but every reader applies it to the **stored** `score_oof`, which `_write_scores`
rounds to 6 decimal places. A stored value could round across a threshold.

**Sweep finding — `anomaly.flag_top`.** It computed `k = max(1, round(n·c))`, took the
k-th highest score as the threshold and flagged `score >= threshold`. That flags every
score tied with the k-th. ECOD scores over mostly one-hot candidate features tie
heavily. The test fixtures flagged 6 of 20 (30%) and 3 of 9 (33%) at contamination 0.1,
and the golden auto summary flagged 8 of 46 where k = 5. The CLI help promised a
"fraction of candidates".

## Where encountered
While implementing batch 3 (probability calibration). Its agreed invariant test was
"on the calibration set, the empirical flag error on negatives and drop error on
positives are each ≤ α, ties included". That test failed on today's gate before any
Platt map was applied.

## What it caused to fail
- **Gate decisions.** The flag / abstain / drop decisions on the run page
  (`results._scored_candidates`) and the ML tab's conformal panel flagged and dropped
  more than the stated α, most at lab sizes. Saved-mode copies carry the original's
  thresholds, so they inherit the excess.
- **Anomaly flags.** The tripwire flagged more candidates than its contamination
  fraction. Both the run page's "Flagged on this run" and `anomaly_flagged` overstated
  what the fraction promised.

## What the bug was identified to be
- **Gate.** The quantile index rule, the comparison operator and the tie handling were
  chosen separately and never derived together. `round(q·(n-1))` with `>=` is not a
  split-conformal quantile. The finite-sample rule is the `ceil((n+1)(1-α))`-th order
  statistic with a strict inequality.
- **Anomaly.** `flag_top` had the same shape: an order-statistic threshold with `>=`
  and no rule for ties.

## Root cause analysis
Five Whys:
1. *Why did the gate exceed α?* Its threshold index counted the threshold element (and
   its ties) into the flagged side.
2. *Why was that index used?* It is the usual "nearest-rank quantile" for describing a
   distribution. It was reused for a decision rule whose guarantee needs the
   finite-sample conformal index and a strict comparison.
3. *Why did no test catch it?* The only gate test (`test_conformal_decisions_and_calibration`)
   asserted `< 0.2` on held-out data at n = 400: a 2α tolerance, at a size where the
   bias is 0.25%. No test asserted the guarantee **as stated** (≤ α), at small n, or with
   ties.
4. *Why was the guarantee never tested as stated?* The project's preventive rules
   (PA-0017, PA-0064, PA-0068) govern *what data* a metric or gate sees. None requires
   that a stated statistical bound be checked at the sizes where it can fail.
5. *Why did the anomaly tripwire have the same flaw?* There is no shared helper or rule
   for order-statistic thresholds. Each one was hand-rolled with its own index,
   operator and (absent) tie handling.

**Root cause:** order-statistic thresholds were written without a finite-sample rule
that fixes the index, the comparison and the tie handling together. Their stated
guarantees were never tested as stated at small n.

## Corrective action
In CC-ML-0019 (with CC-UI-0044 and CC-FUZZ-0052):

**`fuzzlab/ml/conformal.py`** uses split-conformal order statistics, computed exactly.
- `upper_index(n, α) = ceil((n+1)(1-α))` and `lower_index(m, α) = floor((m+1)α)` are
  computed with `fractions.Fraction(α)` (exact for the α actually used). They return
  `None` when out of range.
- `min_class_size(α) = ceil(1/α) - 1` is the fewest rows of a class for which the gate
  can act at all: 9 at α = 0.1.
- The strict inequalities are stored as thresholds: `t_hi = nextafter(q_hi, +inf)`,
  `t_lo = nextafter(q_lo, -inf)`. "Never" is `nextafter(1.0, inf)` /
  `nextafter(0.0, -inf)`.
- **`decide` is unchanged**, so every stored row's thresholds keep their exact meaning.
- α outside (0, 1) is refused, including NaN and bools. Python's negative indexing
  would otherwise have silently picked a wrong threshold.

**`fuzzlab/ml/train.py`:**
- The gate is calibrated on `round(s, 6)`, the values exactly as stored.
- `alpha` is checked before any write.
- New rows record `gate_rule: "split-conformal"`, `n_pos` and `n_neg`, and saved-mode
  copies carry them (`_SAVED_CARRY`).
- `gate_notes(calibration)` is the one source of the reader text: "pre-BUG-0070 rule"
  for old rows, and "never flags / never drops: needs ≥ N … (has M)".

**`fuzzlab/ml/anomaly.py`:**
- `flag_budget(n, c)` is the one definition of k. `flag_top` flags **at most k, whole
  tie groups only**: identical scores are equally unusual. If the top tie group alone
  exceeds k, nothing is flagged.
- `flag_reason` says why fewer than k were flagged.
- `detect_anomalies` records `anomaly_flag_budget` and `anomaly_flag_rule = 2`.

**Readers** (CC-UI-0044):
- **Run page:** gate notes beside the decisions, and an anomaly note (an old-rule
  label, or why fewer than k were flagged) via `core.anomaly_flags.flag_note`. The note
  shows even when nothing was flagged.
- **ML tab conformal panel:** a never threshold is shown as "never", not `1.0` or
  `-0.0`, with the notes. The pooled view says "pre-BUG-0070" when any pooled gate
  lacks `gate_rule`.
- **ML tab anomaly panel:** uses `flag_budget`, `flag_top` and `flag_reason` instead of
  recomputing k itself.
- **CLI summary:** prints the anomaly reason. The `--anomaly-contamination` help text
  says "at most … whole tie groups only".

**Behaviour changes, stated:**
- At α = 0.1 a gate never drops with fewer than 9 positives and never flags with fewer
  than 9 negatives. An empty negative class now never flags (before, it flagged a score
  of exactly 1.0).
- The tripwire flags fewer candidates when scores tie, possibly none.

Both are the honest consequence of the stated guarantee, and both are shown to the user
with the reason.

**Old rows.** These are append-only history and are not rewritten. Their thresholds and
flags are still applied as recorded, and are labelled as from the earlier rule.
Retraining or re-running `--anomaly` gives the corrected values.

Tests: `tests/test_conformal_bound.py` (new). The existing tests whose expectations
change are listed in CC-ML-0019's verification.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0062 / PA-0064** (a degenerate fold made out-of-fold metrics in-sample) and
  **BUG-0067 / PA-0068** (the gate applied to in-sample scores). Both concern *which
  data* an honest-evaluation artefact sees. This bug is the artefact's own arithmetic.
  **Not the same defect, but the same failure family:** an honesty guarantee that was
  asserted but never tested at the size or in the case where it fails.
- **PA-0017** (a metric measures what it claims) is the nearest rule. It was applied to
  metrics, not to a decision rule's stated bound.

**Result:** a new root cause (the order-statistic rule), recurring in the
honest-evaluation family that PA-0064, PA-0068 and PA-0017 govern.

## Prior-preventive-action failure analysis
- **PA-0064(3) was too narrow.** It requires every degenerate or fallback branch to have
  a test that enters it and asserts the contract there. The gate's **main** guarantee at
  small n is not a degenerate branch, so it was never tested as stated.
- **PA-0064(4)'s enforcement had the wrong scope.** Its guard
  (`test_no_out_of_fold_scorer_bypasses_oof_folds`) covers out-of-fold scorers only, so
  `conformal.py` and `anomaly.flag_top` were never swept.
- **PA-0017 sat at the wrong layer.** "A metric measures what it claims" was applied to
  reported numbers, not to a decision rule's error bound or to a "fraction flagged".
- **PA-0068 governs inputs** (which score a gate judges), not the statistic the gate
  computes.

## Preventive action
**PA-0069** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0064(3)/(4) and PA-0017:
1. **A stated guarantee is tested as stated.** Examples are an error bound, a coverage
   level or a "fraction flagged". The test asserts the guarantee at the smallest sample
   size the toolkit accepts, ties included, plus a non-vacuity check.
2. **An order-statistic threshold states its rule whole, in one helper.** A threshold
   derived from an order statistic states its finite-sample rule, its comparison
   operator and its tie handling together, in one shared helper (PA-0003). The test
   asserts the claimed fraction or bound with ties.
3. **Calibrate on what is compared.** A threshold is calibrated on the exact values its
   consumers compare it with, after storage rounding.
4. **Sweep every order-statistic threshold.** The PA-0002 sweep for this class covers
   every order-statistic threshold in the codebase, not only the reported one.

**Sweep (PA-0002, PA-0069(4); by consumer per PA-0068(4)):**
- **Threshold producers.** Searched `sorted(` followed by an index, plus quantile,
  fraction and contamination code.
  - `ConformalGate.calibrate`: **instance**, fixed.
  - `anomaly.flag_top`: **instance**, fixed.
  - `mlview.anomaly_panel`'s recomputed k: **duplicate definition**, removed in favour of
    `flag_budget`.
  - `mlview._beta_ci`: a display credible interval read off a CDF grid, not a decision
    and not a stated bound. Not an instance.
  - The budget prioritizer and the rankers: they order candidates and set no threshold.
    Not instances.
- **`gate.decide` consumers:** `mlview.conformal_panel` and
  `results._scored_candidates`. `decide` is unchanged and both now show the gate notes.
- **Anomaly-flag consumers:** the run page card (`core.anomaly_flags.top_flagged`,
  `flag_note`), the CLI summary, and the ML tab panel. All three now show the rule or
  reason.
- `conformal._quantile` is deleted; it had no other caller.
- **Batch 3's planned Platt calibration** must round its cross-fitted `score_oof` before
  calibrating the gate (PA-0069(3)). This is recorded in its CC entry.
