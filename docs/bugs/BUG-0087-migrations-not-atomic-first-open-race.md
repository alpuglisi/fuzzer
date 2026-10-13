# BUG-0087 — Migrations were not atomic, and two first opens of a store raced

- Date: 2026-10-13
- Status: fixed (CC-CORE-0034; FR-CORE-24)
- Severity: medium. **13 of 20** concurrent first opens failed (`duplicate column name`,
  `table meta already exists`, `database is locked`). A failed migration left a store
  that could not be migrated again.

## Description
`migrate` ran each migration as `with conn: conn.executescript(sql)`. But
`executescript` issues a COMMIT first and runs in autocommit mode, so `with conn:` gave
no transaction:
- a migration failing mid-way left its earlier statements applied with no
  `schema_version` row, and the rerun then failed (`table a already exists`);
- nothing held a write lock between reading the version and applying a migration, so
  two processes opening a fresh store (the web UI and a CLI run) both applied it;
- the WAL switch in `open_store` can return SQLITE_BUSY immediately, bypassing the busy
  handler, when another connection holds the file.

## Where encountered
The error-review phase (`scratchpad/review7/r5_migrate.py`). Reviewer B predicted the
WAL BUSY, and implementation confirmed it.

## What it caused to fail
Any concurrent first use of a store, and recovery from a bad migration.

## What the bug was identified to be
"Check then act" without a lock, and an all-or-nothing step without a real
transaction.

## Root cause analysis
1. *Why partial state?* `executescript` committed each statement.
2. *Why not noticed?* `with conn:` looked transactional, and no test injected a
   mid-migration failure.
3. *Why the race?* The version was read with no write lock held.
4. *Why didn't the store contract prevent it?* `open_store`'s own docstring (R-08)
   says "callers doing read-then-write must use `BEGIN IMMEDIATE`", and `migrate`
   never did.
5. *Why the WAL error?* The journal-mode change is not covered by the busy handler.

**Root cause:** a read-then-write on shared storage without the documented lock, and a
transaction boundary that wasn't one.

## Corrective action
In CC-CORE-0034:
- **Explicit transactions.** `migrate` sets `isolation_level=None` (restored in a
  `finally`). Each pending migration then runs as follows:
  - `BEGIN IMMEDIATE` (which takes the write lock and waits up to `busy_timeout`);
  - **the version is re-read under the lock**, and a migration another process applied
    meanwhile is skipped;
  - its statements are executed one by one (`split_statements`, using SQLite's
    `complete_statement`, so trigger bodies and string literals are safe), then the
    version row is inserted;
  - `COMMIT`, or `ROLLBACK` and re-raise.
- **`open_store`** sets `busy_timeout` first, and retries the WAL switch with backoff
  for up to 10 s (`_set_wal`).
- **Tests** (`tests/test_migrations_atomic.py`):
  - a failing migration leaves only `schema_version`, and the fixed migration then
    applies;
  - the split handles a trigger body, a quoted `;`, a comment `;` and a final
    statement without `;`;
  - the built schema equals a reference build;
  - **4 processes × 10 fresh stores → 0 failures**, each at the latest version;
  - the race prototype ran 4 × 20 → 0.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **PA-0035** (capability probes): not related.
- **The store contract (R-08, `open_store`'s docstring):** the relevant prior rule
  (`BEGIN IMMEDIATE` for read-then-write). **Not followed, and not enforced.** It was a
  docstring rule with no PA and no test.

**Result:** a lapse of a documented-but-unenforced rule. No prior bug is in this area.

## Prior-preventive-action failure analysis
There was no PA. The rule lived only in a docstring, so nothing checked `migrate`
against it: the "not written as a rule, therefore not followed" mode.

## Preventive action
**PA-0088:**
1. A state transition that must be all-or-nothing is tested by injecting a mid-way
   failure.
2. A "check then act" on shared storage holds the write lock across the check
   (`BEGIN IMMEDIATE`, re-check inside).
3. `executescript` is never used where atomicity matters.
4. The store contract's docstring rules are tested by a concurrency test.

**Sweep (PA-0002):**
- **`executescript`:** only the labgen live-boot seeding of throwaway, single-writer
  lab databases uses it (a failure aborts the boot). Not an instance.
- **Read-then-write store code:**
  - `holdout_reveal` / `holdout_metric` counting: insert-only rows;
  - `MetricLogger`: buffered inserts;
  - `start_run`: an insert;
  - the `bandit_posteriors` upsert: `ON CONFLICT`.

  None is check-then-act.
