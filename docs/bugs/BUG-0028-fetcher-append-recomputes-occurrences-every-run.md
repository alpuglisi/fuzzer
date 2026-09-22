# BUG-0028 — `fetcher.py --append` recomputed `occurrences` from the row count on every run

## 1. Description
`fuzzlab/tools/fetcher.py::setup_results_db(append=True)` unconditionally re-derived
each finding's `occurrences` count from `COUNT(*)` of its (post-unique-index) rows
and then deleted duplicates, on **every** invocation — not only when migrating an
old, pre-index database that genuinely held one literal row per occurrence. Because
the unique index already collapses same-key findings into a single row from the
second run onward, that recompute step always saw exactly one row per key on a
current-schema database and reset `occurrences` to `1`, discarding every prior run's
accumulated count. `log_finding`'s own `ON CONFLICT ... occurrences + 1` then built
back up from `1` instead of from the true cumulative total, so repeated `--append`
runs never actually accumulated observation counts across runs.

## 2. Where encountered
Logged (without a fix) in `ERROR_LOG.md`'s "Open / low priority" section: "`fetcher.py`
`--append` occurrence counter: repeated `--append` runs recompute `occurrences` as
the current row count (1 after de-duplication) before the new audit bumps it, so
cumulative counts across runs are not preserved. The default (fresh) run is
unaffected." Found while surveying `ERROR_LOG.md` for other tracked-but-unfixed,
non-lab-track issues after closing BUG-0027 in the same session.

## 3. What it caused to fail
No test previously covered this (this file had zero test coverage before this fix).
Manually reproducing the documented symptom: seed a fresh DB via three `log_finding`
calls for the same key (`occurrences` correctly reaches 3 within one run); call
`setup_results_db(db, append=True)` again (simulating a second `--append` run's
startup) — `occurrences` for that key was reset to `1` before the second run's own
findings were even logged, so any subsequent accumulation started from the wrong
baseline. Over `N` `--append` runs, the reported `occurrences` for a
repeatedly-seen finding reflected only "however many times it was seen since the
row count last collapsed to 1" — effectively only the most recent run(s), not the
true cumulative total across the whole audit history the `--append` flag exists to
preserve.

## 4. What the bug was identified to be
The "collapse duplicates left by an older run" migration block in
`setup_results_db()` ran on every `append=True` call, unconditionally, regardless of
whether the database already had the unique index (and therefore an already-accurate,
already-cumulative `occurrences` column maintained incrementally by `log_finding`).

## 5. Root cause analysis (Five Whys)
1. Why did `occurrences` reset to 1 on the second `--append` run? Because the
   `UPDATE findings SET occurrences = (SELECT COUNT(*) ... )` migration statement ran
   again, and by then there was only one row per key (the unique index already
   guarantees that), so `COUNT(*)` was always `1`.
2. Why did that migration statement run again on an already-migrated database? Because
   nothing in `setup_results_db()` checked whether the migration had already happened —
   it ran the same "collapse rows, recompute occurrences from row count" block on
   every `append=True` call unconditionally.
3. Why was it written to run unconditionally? Because it was designed as a one-time
   upgrade path for "databases written by earlier versions" (per the function's own
   docstring) that held literal duplicate rows — the author reasoned about the
   *old-database* case but the code has no way to distinguish that case from
   "already-migrated database, second `--append` run of many."
4. Why does re-running a one-time upgrade step do active harm here, rather than
   being merely a wasted no-op? Because on an already-migrated database, the
   "recompute from row count" step is not a no-op — the row count itself is a
   fundamentally different, much smaller number (1, since the index already
   collapsed duplicates) than the actual cumulative `occurrences` that step is
   supposed to be reading, not overwriting.
5. Why wasn't this caught before shipping? No test existed for `setup_results_db`,
   `log_finding`, or the `--append` flag at all — the only record of this behavior
   was a manually-observed symptom line in `ERROR_LOG.md`, filed as "Open / low
   priority" and never revisited with a fix or a regression test.

**Root cause:** a schema-upgrade step meant to run exactly once (when migrating a
pre-index database) was instead re-run on every `--append` invocation with no guard
distinguishing "needs migrating" from "already migrated," and on an already-migrated
database it silently overwrote the very state (the cumulative `occurrences` count)
it was designed to only ever read from a different, incompatible schema shape.

## 6. Corrective action
`fuzzlab/tools/fetcher.py::setup_results_db()`: the collapse-duplicates-and-recompute
block now only runs when `idx_findings_target` does not already exist (checked via
`sqlite_master`) — i.e., only for a genuine pre-index database being migrated for the
first time. Once the index exists, `occurrences` is left untouched by `setup_results_db`
and continues to accumulate correctly via `log_finding`'s `ON CONFLICT ... + 1` across
every subsequent `--append` run. Delivered in `CC-AUD-0015`.

New test file `tests/test_fetcher_results_db.py` (no prior coverage existed):
non-append clears the table; append across two and three runs accumulates the true
cumulative count (3, then 5, then 6) instead of resetting; a genuine pre-index
database with literal duplicate rows is still correctly migrated on first `--append`.

## 7. Recurrence review
Checked every `docs/bugs/BUG-NNNN-*.md` title and body for "occurrence"/"recompute"/
"idempotent"/"migration" and the full `docs/PREVENTIVE_ACTIONS.md` rule list for a
prior instance of "a one-time migration/upgrade step re-runs on every invocation and
overwrites already-correct accumulated state." No match — the closest adjacent bugs
(BUG-0016's reward-starved-by-global-frontier, BUG-0024's silent-empty-result) are
about different failure shapes (a shared/global counter miscounting *within* one run;
a silent empty result), not a repeated migration clobbering cross-run persisted
state. **No prior occurrence found — this is a new bug class.**

## 8. Prior-preventive-action failure analysis
Not applicable — no prior occurrence found (step 7).

## 9. Preventive action
See `PA-0030` in `docs/PREVENTIVE_ACTIONS.md`.

## 10. Status
Fixed. Closes the `ERROR_LOG.md` "Open / low priority" entry for this symptom
(cross-referenced there).
