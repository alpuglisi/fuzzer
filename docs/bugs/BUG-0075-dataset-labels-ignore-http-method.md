# BUG-0075 — Dataset labels and seen keys ignored the HTTP method

- Date: 2026-10-13
- Status: fixed (CC-ML-0023)
- Severity: latent. No current lab contract has a GET and a POST point sharing a path and
  a param with different outcomes. Where one existed, the training label was wrong.

## Description
`dataset.build_dataset` keyed positives on `(run, path, param, category)`. Both `finding`
and the candidate's evidence record `method`. A finding the oracle confirmed **only on
POST** `/search q` labelled the oracle-rejected **GET** candidate positive (`method=GET
label=1`). `candidate_keys` / `seen_fraction` likewise treated a GET and a POST point as
one key.

## Where encountered
The error-review phase (a review agent; reproduced by me: `candidate 1 method=GET
label=1`).

## What it caused to fail
- Training labels, in the latent case: false positives taught to the classifier and
  ranker.
- `seen_fraction` overstated how much of a run an earlier-trained model had seen.

## What the bug was identified to be
A join between two tables ignored an identity field that both tables record.

## Root cause analysis
Five Whys:
1. *Why was the GET labelled positive?* The positive key had no method.
2. *Why no method?* The key was written when every audited point was a GET query
   parameter; POST body points came later (CC-FUZZ-0032).
3. *Why was it not updated then?* Adding POST points changed what an identity is, and
   no rule said to revisit the joins keyed on it.
4. *Why did no test catch it?* Every fixture used GET on both sides.
5. *Why did no review catch it?* A join's key was never checked against the full set
   of identity fields both sides record.

**Root cause:** a join keyed on a subset of the identity fields both sides record. That
was harmless while the dropped field was constant, and wrong once it varied.

## Corrective action
In CC-ML-0023:
- **One normaliser.** `dataset.method_key` upper-cases the method; a missing or NULL
  method becomes `GET`, the evidence default. It is used on both sides of every
  label / seen-key join.
- **Positives** are keyed `(run, path, param, category, method)`. A finding with a NULL
  `method` (legacy or hand-written) still matches any method, so no old row flips.
- **`candidate_keys` / `seen_fraction`** key on `(path, param, category, method)`.
- **`rules_fired` (a model feature) is NOT changed.** Keying it by method would change a
  feature's meaning under the same `FEATURE_VERSION`. It is flagged as a versioned
  follow-up (FR-ML-5 note).
- **Unchanged:** the holdout / endpoint key stays path-only (an endpoint is a path), and
  `FEATURE_VERSION` is unchanged (these are labels, not features).
- **Tests** (`tests/test_ml_dataset_keys.py`):
  - a POST-only finding labels only the POST candidate;
  - a missing evidence method is GET, and case is ignored;
  - a method-less finding matches every method;
  - `seen_fraction` tells methods apart;
  - existing fixtures, GET on both sides, are unchanged (338 ML tests pass).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0065 / PA-0066:** labels were pooled across runs (the key lacked the run).
  **Same class:** a label join missing an identity field. PA-0066(1) requires a
  cross-table lookup to be keyed "by `run_id` plus the content key", and did not
  question what the content key itself contains.
- **BUG-0046 / PA-0048:** a lookup collapsing `sink_context`. Related: a key dropping a
  distinguishing field at point-build time.

**Result:** a recurrence of BUG-0065's class. A prior-PA failure analysis follows.

## Prior-preventive-action failure analysis
**PA-0066 was too narrow.** It required per-run scoping (the dimension that was missing
then) and took the content key `(path, param)` as given, rather than checking it against
**every** identity field both tables record. So the method, missing the same way,
survived its sweep.

## Preventive action
**PA-0076** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0066(1):
1. **A join between two tables keys on every identity field both sides record.** A field
   is omitted only with a stated reason (e.g. "an endpoint is a path").
2. **Both sides of the join normalise through one helper** (PA-0003).
3. **When a new value of an identity field becomes possible** (a new method, location,
   content type), sweep the joins keyed without it.

**Sweep (PA-0002):**
- **`candidate_keys`:** fixed.
- **`_confirmation_key`:** has url, param, method, location and category. It lacks
  `sink_context`, deliberately for now; that is the deferred defect logged in BUG-0072.
- **`scoring.score` keys:** `(url, method, param, vuln_class)`, complete.
- **The report's / finding view's joins** read `finding` by id or by run, with no
  partial key.
- **Holdout membership:** path only, by stated design.
- **`fired` counts (`rules_fired`):** the deferred, versioned follow-up above.
