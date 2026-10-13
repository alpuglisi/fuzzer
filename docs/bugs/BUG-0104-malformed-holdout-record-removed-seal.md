# BUG-0104 — Malformed holdout metadata removed the seal instead of failing closed

- Date: 2026-10-13
- Status: fixed (CC-ML-0025, CC-CORE-0036, CC-PLUG-0009)
- Severity: medium. Damaged metadata turned a blind evaluation set into training data.

## Description
`holdout._recorded` skipped a model row whose `holdout` value was falsy (`{}`, `None`,
`False`, `0`, `""`) or whose calibration did not parse. With no other record, the
target read as never sealed (`sealing_for_run` → `None`), so ordinary training could
use its held-out labels. An invalid nonempty record correctly read as `UNKNOWN`.

## Where encountered
A third-party audit (finding #8), reproduced with `scratchpad/ext2/f08_seal.py`. I
wrote this code in `1619932`.

## What it caused to fail
FR-ML-19 (the seal is fail-closed, keyed on durable state, PA-0092).

## What the bug was identified to be
`if not rec: continue` conflated "absent" with "malformed". The seal lived only in
mutable calibration JSON.

## Root cause analysis
1. *Why unsealed?* Falsy records were skipped.
2. *Why skipped?* A truthiness test stood where a presence test belonged.
3. *Why could a damaged row erase a seal at all?* The only copy of the seal was inside
   the model's mutable JSON blob.
4. *Why not caught?* The fail-closed tests used invalid *non-empty* records.

**Root cause:** fail-closed state did not distinguish absent from malformed, and it
lived in a mutable blob.

## Corrective action
- **A present `holdout` key, whatever its value, is a record.** `_registered` rejects
  malformed ones → `UNKNOWN`.
- **Migration 19 adds `holdout_seal`** (append-only: origin, record, version, fraction,
  model id) **and `holdout_seal_meta`** (the backfill watermark).
- **The backfill runs as the migration's Python post-step**, in the same
  `BEGIN IMMEDIATE` transaction (`migrations.POST_STEPS`): readers, guarded hooks and
  the ML tab only ever read (A and B must-fix).
- **Trainers seal on write.** `_insert_model` → `holdout.write_seal`, in the model
  row's transaction.
- **The guard allows only adding a seal.** `plugins.guard.ADVISORY_WRITES` gains
  `holdout_seal` (INSERT only, CC-PLUG-0009).
- **The read rule:** the table, plus calibration records of rows above the watermark.
  An unparseable row at or below the watermark makes every target `UNKNOWN`, naming the
  model id, because its seal may have been lost.
- **Tests** (`tests/test_holdout_seal_table.py`):
  - 7 malformed shapes → `UNKNOWN`;
  - a seal survives its calibration being wiped;
  - a v18 → v19 upgrade backfills valid and malformed seals, with the watermark;
  - an unparseable legacy row fails closed;
  - the ML tab performs no writes (`total_changes`);
  - a guarded ADVISORY stage writes its seal, and a READ_ONLY prioritizer reads;
  - six concurrent upgraders backfill once.

## Recurrence review
- **BUG-0091 / PA-0092:** the same seal. A recurrence: my own fix.

## Prior-preventive-action failure analysis
**PA-0092 was not followed in full.** It keyed the seal on "durable state", but I
implemented it over mutable JSON. I also read malformed values as absent, so the
implementation was neither durable nor fail-closed on malformed input.

## Preventive action
- **PA-0105:**
  1. Fail-closed state distinguishes **absent** from **malformed**, and malformed is
     never read as absent.
  2. Safety state lives in its own append-only table, not inside a mutable blob. Any
     backfill runs in the migration, never on first use by a reader.

**Sweep:**
- the `holdout_metric` / reveal tables: their own tables already;
- `gate_input`'s `calibration.get("holdout")`: a read-side hint only, now also sealed
  per target.
