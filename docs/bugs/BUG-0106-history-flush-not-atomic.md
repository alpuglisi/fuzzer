# BUG-0106 — A failed history flush left a partial transaction and duplicated rows on retry

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0021)
- Severity: medium.

## Description
`HistoryWriter.flush` inserted record by record. When a later record raised (a
`RecursionError` from deep JSON, or any database error), earlier inserts stayed in an
open transaction holding the write lock, and the buffer was kept. A retry inserted them
again: one flow became two rows. Its docstring promised "one transaction".

## Where encountered
A third-party audit (finding #10), reproduced with `scratchpad/ext2/f10_flush.py`.

## What it caused to fail
FR-PROXY-3's history integrity, and the docstring's transaction claim.

## What the bug was identified to be
Redaction and insertion were interleaved, with no savepoint or rollback, and the buffer
was cleared only on success.

## Root cause analysis
1. *Why partial?* There was no rollback on error.
2. *Why duplicates?* The buffer was kept whole while some of it had been written.
3. *Why not caught?* No injected-failure test; PA-0088's sweep did not reach this
   docstring claim.

**Root cause:** a documented all-or-nothing batch with no failure test.

## Corrective action
- **Phase 1 prepares** (redacts) every record, with no database writes. A record whose
  redaction fails is stored with `__BODY_OMITTED__ (redaction failed)` bodies and its
  query-free URL, and counted in `errors` (B-N1, PA-0086).
- **Phase 2 writes** inside `SAVEPOINT history_flush`. On error it does `ROLLBACK TO`
  and `RELEASE`, then re-raises with the buffer intact.
- It commits only when no transaction was open before the flush (B-N1), and only the
  written records leave the buffer.
- An `RLock` guards `record` / `flush`.
- **Tests:**
  - an injected SQLite error mid-flush → no rows and no open transaction, and the retry
    writes each flow once;
  - a redaction failure → stored with omitted bodies and no secret;
  - an owner's transaction is left to the owner;
  - 4 threads × 50 records;
  - a deep body flushes.

## Recurrence review
- **BUG-0087 / PA-0088:** atomic transitions, for migrations.

## Prior-preventive-action failure analysis
**PA-0088's sweep was too narrow.** Rule 1 ("an all-or-nothing transition is tested by
injecting a mid-way failure") was applied to migrations only.

## Preventive action
- **PA-0107:** every documented batch or transaction claim has an injected-failure
  test. A batch writer prepares before it writes, and rolls back to its own savepoint.

**Sweep:**
- `HttpClient._record`: one insert and a commit;
- `train._insert_model` callers: the trainers commit once;
- the repeater: through `HistoryWriter`;
- `core.sealed.write_metrics`: one batch inside the trainer's transaction.
