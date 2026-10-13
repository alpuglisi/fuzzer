# BUG-0107 — Wrong-shape evidence crashed datasets; invalid JSON became a fabricated negative row

- Date: 2026-10-13
- Status: fixed (CC-ML-0025, CC-FUZZ-0059)
- Severity: low-medium. The audit rated it Medium. It needs damaged data.

## Description
`build_dataset` did `json.loads(evidence or "{}")` and then `.get`:
- `"[]"` crashed with `AttributeError: 'list' object has no attribute 'get'`;
- `"{not json"` was caught and replaced by `{}`, so a labelled candidate became a
  fabricated row (endpoint `/`, usually label 0) that silently contaminated training.

## Where encountered
A third-party audit (finding #11), reproduced with `scratchpad/ext2/f11_evidence.py`.

## What it caused to fail
Training-data integrity (the labels come only from the oracle, FR-ML-*).

## What the bug was identified to be
No validation of a stored JSON's shape, and a default that fabricated data.

## Root cause analysis
1. *Why a crash?* A non-dict reached `.get`.
2. *Why a fake row?* `{}` was used as the default.
3. *Why not caught?* The typed-boundary rule (PA-0096) was applied to the model loader
   only.

**Root cause:** stored JSON was read without one validating parser, and the default
invented data.

## Corrective action
- **One parser.** `core.evidence.parse_evidence` requires an object with string `url`,
  `param` and `category`, and `method` absent or a string; otherwise `None`.
  `display_evidence` is the display-only variant and never raises.
- **The ML path quarantines.**
  - `build_dataset` skips unreadable rows, recording `Dataset.quarantined` and
    `scope_total`.
  - `candidate_keys` gives them a unique key, and `_candidate_texts` gives them `""`.
- **Trainers refuse** (`dataset.quarantine_refusal`) when:
  - a run with a quarantined row has a finding no readable candidate matches (a label
    may be lost; S9 scopes it to such runs);
  - or more than 5% of the scope's candidates are quarantined.

  Run mode raises `DatasetEvidenceError`, earlier mode refuses with the reason, and the
  prioritizer raises.
- **The count is recorded:** `quarantined_rows` goes into the calibration, the result
  and `run_metrics` (`ml_quarantined_rows`). The CLI prints "N candidate(s) with
  unreadable evidence skipped".
- **Display readers** (`results`, `core.anomaly_flags`) use `display_evidence`.
- **Quarantined ids** are scored by no model. The prioritizer places them after the
  scored candidates, in row order.
- **Tests** (`tests/test_dataset_evidence.py`):
  - 7 bad shapes → quarantined, never fabricated;
  - a few quarantined rows: skipped, counted and recorded;
  - more than 5% → refusal;
  - a possibly lost label → refusal;
  - an orphan finding with no quarantine → no refusal (S9);
  - the golden `fuzzlab auto` scenarios and an offline multi-target store never trip
    it (A's invariant);
  - the CLI line.

## Recurrence review
- **PA-0096:** the typed boundary, applied to the model loader only. No prior evidence
  bug.

## Prior-preventive-action failure analysis
**PA-0096 was too narrow in scope.** It covered the model loader, not every reader of
stored JSON.

## Preventive action
- **PA-0108:** every reader of stored JSON validates shape and types at one parser.
  Malformed rows are quarantined and counted, never replaced by defaults that fabricate
  data.

**Sweep:**
- `pipeline.py` (reads its own just-written evidence);
- `web/results` finding evidence (display, already raw-safe);
- `proxycontrol` (finding evidence, display);
- calibration JSON (BUG-0104's reader).
