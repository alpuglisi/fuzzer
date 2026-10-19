# BUG-0525 — A disco capture accepted a directory holding an earlier run's files

- Date: 2026-10-19
- Status: fixed (CC-CRAWL-0050)
- Severity: medium. An earlier run's explorer actions, refusal counts, report or script
  segments could be imported (and, since FR-CRAWL-30, traced) as this run's.

## Description
`fuzzlab disco capture` refused an `--out` that already held `capture.jsonl` (PA-0450),
and nothing else. The explorer appends to `actions.jsonl`. The importer
(`store_adapter.import_disco`, `observe.observe_disco`) reads that file, together with
`capture.jsonl.stats.json`, `explore.json` and `script_segments.json`, as the run's own.

## Where encountered
DG-LIVEDISCO phase 1 (§Q4 of DRAFT-LIVEDISCO), while checking what the live trace would
read. `--dry-run` into a directory holding only `actions.jsonl` returned 0, and a real
capture would have appended to that file. Put in scope by the coordinator.

## What it caused to fail
- An earlier run's actions became this run's points (`_disco_actions` page URLs and
  visible fields) and this run's workflows.
- An earlier run's refusal counts became this run's external hosts.
- A crashed single-worker explore leaves the previous `script_segments.json` in place,
  and it fed path templating.

## What the bug was identified to be
The PA-0450 provenance check covered one file of a multi-file handoff.

## Root cause analysis
Five whys:
1. Why was the stale log accepted? `_capture` and `CaptureProxy.start` check
   `capture.jsonl` only.
2. Why only that file? PA-0450 was applied when disco was built (CC-CRAWL-0031) to the
   file that triggered BUG-0450's class, the capture. The other files were added
   later, one by one (`explore.json`, `script_segments.json` in CC-CRAWL-0046, the
   action ids in CC-CRAWL-0048), and each added a consumer read without revisiting the
   producer's check.
3. Why did nothing catch it? No test ran a capture over a directory holding any file
   but `capture.jsonl`. PA-0450(3) asks for one test per handoff, and this handoff is a
   set of files.
4. Why does appending matter? An appended log is indistinguishable, line by line, from
   this run's: nothing in a line says which run wrote it.

**Root cause:** a provenance check written per file for a producer whose output is a set
of files that consumers read together. The list of files the consumers read was nowhere
tied to the check.

## Corrective action
CC-CRAWL-0050:
- `disco.cli.RUN_FILES` lists `capture.jsonl`, `actions.jsonl`,
  `capture.jsonl.stats.json`, `explore.json` and `script_segments.json`. The last is
  beyond the three the coordinator named: the importer reads it, so the rule requires
  it.
- `_capture` refuses an `--out` holding any of them, right after the scope check and
  before `--dry-run`, so nothing is written, started or created.
- Tests:
  - `tests/test_disco_cli.py::test_capture_refuses_a_directory_holding_any_file_the_trace_reads`
    (4 files, with and without `--dry-run`). On the old code: "assert 0 == 2" for the
    dry runs, "Failed: a proxy was started" for the others.
  - `::test_every_file_the_import_and_the_trace_read_is_refused_when_stale`: an AST scan
    of the importer, the observer and the live trace for run-file names. It must be a
    subset of `RUN_FILES`.

## Recurrence review
I checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for provenance and stale-file
defects:
- **BUG-0450 / PA-0450:** `fuzz` imported a previous run's CSV because the file existed.
  This is the same root cause: an artifact attributed to this run because its path
  exists.
- BUG-0452 (tests created the default store): a different cause.

## Prior-preventive-action failure analysis
BUG-0450 and PA-0450 predate disco.
- PA-0450(1) ("only on a fact from its producer that this run wrote it") was followed
  for the one file its author thought of. `CaptureProxy` creates `capture.jsonl` and
  refuses an existing one, but the rule was not applied to the producer's other files.
- PA-0450(3)'s sweep "by mechanism" was a one-time sweep of the imports that existed
  then. It was never re-run when disco added new file handoffs, and its one enforcing
  test covers `fuzz` only.

The rule was right, but too narrow in its unit (a file, not the set a consumer reads),
and not enforced for new producers.

## Preventive action
**PA-0525** strengthens PA-0450(1) and (3):
1. A producer whose output is several files that a consumer reads as one run refuses an
   output location holding **any** of them, before any side effect.
2. The list of those files is one constant. A test fails when a consumer reads a run
   file that is not in it.

Enforced by:
- `tests/test_disco_cli.py::test_capture_refuses_a_directory_holding_any_file_the_trace_reads`
- `tests/test_disco_cli.py::test_every_file_the_import_and_the_trace_read_is_refused_when_stale`

PA-0002 sweep: the other multi-file producers. `disco ede` writes `ede.json` and refuses
it (one file). `disco run` refuses an existing `--results`. Its `--evidence`
files are overwritten per case id and cited by path from the results ledger; nothing
reads that directory as a set. `fuzzlab crawl` resets its DB tables (BUG-0450's disposition). No other
producer appends to a file a consumer reads as the run's.
