# BUG-0516 — The reducer depended on event order, and its counters waited for close

- Date: 2026-10-19
- Status: fixed (CC-CORE-0064; the post-implementation review of the diagrams series, F-076)
- Severity: low-medium. FR-CORE-505 promised order independence and rebuild = incremental, and the spec asked for dropped events and lag to be exposed; both were false in edge cases.

## Description
- An entity's kind (`page` or `interface`) was the first event's.
- A capped attribute kept the first 40 values seen and counted `_more` per batch, so a
  value seen again after falling out was counted twice (50 ids: 15 incrementally, 10
  after rebuild).
- `TraceRecorder` wrote `trace_*` only at `close`: a live run showed no dropped count
  or lag, and a killed process lost them.

## Where encountered
The two-reviewer gate (`docs/components/README.md`), run after the fact over the diagrams series (8f5efd0..a8d8d31) because it had been skipped (F-076). Both reviewers reproduced the order cases; both noted the counters.

## What it caused to fail
The model's equality with a rebuild; the status line of a live or killed run.

## What the bug was identified to be
Claims tested with one order and one batch size; counters designed for a run's end.

## Root cause analysis
**Root cause:** an order-independence claim tested by shuffling below the cap, with no
case at the cap boundary or for conflicting kinds; "exposed" read as "after the run".

## Corrective action
The kept set is the 40 smallest values in a fixed order and `_more` is a flag (both
order-free; proof in CC-CORE-0064); the kind is the strongest by rank; the counters are
written at the first flush, at most every second after, at once after a drop, and at
close. Tests: `tests/test_trace_model.py::test_kind_and_capped_attributes_do_not_depend_on_order`
(three orders, three batch sizes, past the cap, rebuild equal) and
`::test_the_counters_are_written_while_the_run_is_live`.

## Recurrence review
No earlier reducer bug. Related principle: PA-0135/PA-0511 (a property claimed for all
schedules is tested on several).

## Prior-preventive-action failure analysis
Not a recurrence.

## Preventive action
PA-0516: an order- or batching-independence claim is tested on permutations and batch
sizes that include every boundary the code has (a cap, a conflict, a flush).
