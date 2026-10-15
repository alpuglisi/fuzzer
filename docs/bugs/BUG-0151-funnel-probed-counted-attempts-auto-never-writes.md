# BUG-0151 — The funnel's "probed" stage counted `attempt` rows, which `auto` never writes

- Date: 2026-10-15
- Status: fixed (the funnel); one sibling reader open and pinned (`web/results.py`)
- Severity: medium (the goal metric's stage read wrong for every `auto` run)
- Numbering: BUG-0149 and BUG-0150 were already used in this lane; BUG-0151 / PA-0157
  are outside the lane's reserved block and flagged to the coordinator (PA-0031).

## Description
`scripts/funnel_report.py` (the per-case funnel the goal metric is read from) counted a
candidate as **probed** when an `attempt` row referenced it. `harness/auto`'s pipeline
never writes `attempt` rows: the oracle records what it did in `candidate.oracle_status`
and writes `finding` rows with no `attempt_id`. Only `greybox/run.py` and the fuzz-CSV
import (`store_adapter.import_fuzz_csv`) write attempts.

## Where encountered
The coordinator's review of the funnel stages while the DISC-CAPTURE lane added the
discovered / buildable / refused stages; confirmed by reading every writer of `attempt`
(`grep "INSERT INTO attempt"`) and `oracle.Oracle._write_finding`.

## What it caused to fail
For every `auto` run the funnel could not show "probed": a case moved from "candidate"
straight to "confirmed", so "probed" equalled "confirmed", and a candidate the oracle
checked and refuted read as never probed. The goal metric's stage between "candidate"
and "confirmed" was unmeasurable.

## What the bug was identified to be
A metric stage keyed on a table the measured pipeline never writes.

## Root cause analysis
Five Whys:
1. Why did "probed" read zero? It counted `attempt` rows, and `auto` writes none.
2. Why was the wrong table chosen? `attempt` reads as "a probe sent", and its
   `candidate_id` column suggests the link; nothing showed that `auto`'s oracle records
   its work elsewhere (`oracle_status`).
3. Why did the test not catch it? `tests/test_funnel_report.py` built its store by hand
   (an endpoint, a candidate, a finding) and never inserted an attempt, so it asserted
   "reached" and "confirmed" only; "probed" was never exercised.
4. Why by hand? The script is an offline reader, and its test was written as a reader's
   unit test, with no run of the pipeline it measures.
5. Why does that matter? A reader can depend only on what production writes (PA-0071),
   and PA-0071's guard checks contract **columns** have a writer, not that a reader uses
   the column its own measured pipeline writes.

**Root cause:** a metric was validated only against hand-built rows, never against a
store produced by the pipeline it measures, so it keyed on a table that pipeline does
not write.

## Corrective action
CC-FUZZ-0089 (amended): a candidate is probed when its `oracle_status` is `checked` or
`inconclusive` (`core.oracle_status`) or an attempt row exists; a candidate the oracle
never ran (`skipped_budget`, `no_confirmer`, `pending`) is reported refused with
`oracle: <status>`. Tests:
- `tests/test_funnel_report.py::test_a_checked_candidate_with_no_attempt_row_reads_probed`;
- `tests/test_capture_egress.py::test_a_captured_write_is_probed_by_default_and_never_with_the_opt_out`
  reads the funnel from the store a real crawl, import and `auto` run wrote (the old rule
  reads that case as "candidate", so the test fails on it).

## Recurrence review
- **BUG-0069 / PA-0071** ("a reader may depend only on what production writes"; the
  report read `candidate.feature_version`, which nothing wrote, and its test passed
  because the fixture wrote it by hand): the same root cause.
- BUG-0077 / PA-0078 (a displayed count reconstructed from parameters): a related
  display-metric defect with a different cause.
- BUG-0006 / PA-0006 (fixtures shaped unlike the real upstream): the same masking
  mechanism (a hand-built fixture), a different layer.

## Prior-preventive-action failure analysis
PA-0071 (from BUG-0069) did not prevent this because it was **enforced at the wrong
granularity**: its guard (`tests/test_contract_writers.py`) checks that each contract
column has some production writer, which `attempt.candidate_id` has (greybox). It does
not check that a reader's **own** measured pipeline writes what the reader keys on, and
its rule 1 ("a test must not supply by hand a value production never writes") was
satisfied: the funnel test supplied no attempt at all, so the gap was an untested
branch, not a fabricated value.

## Preventive action
**PA-0157** (strengthens PA-0071): a metric stage (a funnel stage, a report count, a
score) is tested against a real store produced by the pipeline it measures, not only
against hand-built rows; each stage it reports has at least one such test where the
stage is reached. The PA-0002 sweep for this class covers every reader of a table one
pipeline writes and another does not.

PA-0002 sweep, every reader of `attempt` (`grep "FROM attempt\|JOIN attempt"` over
`fuzzlab/` and `scripts/`), with the reader's scope (PA-0067(1)):
- `scripts/funnel_report.py` (any run's funnel): fixed;
- `web/findingsview.py` (one finding's detail): reads an attempt only when the finding
  has one: correct;
- `report/report.py` (a run's `attempts` count): counts what exists: correct;
- `greybox/greybox_cli.py` (a greybox run's own attempts): correct;
- `web/results.py` (`list_findings` / `finding_facets`: every finding's category,
  through finding -> attempt -> candidate): **the same defect** (an `auto` finding has
  no `attempt_id`, so no category facet, and a category filter drops it). Not fixed
  here (the UI component, outside the lane); pinned by
  `tests/test_attempt_readers.py::test_an_auto_findings_category_reaches_the_findings_facets`
  (strict xfail, PA-0054(3)) and reported.
