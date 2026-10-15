# BUG-0450 — `fuzz` imported a previous run's CSV as its own attempts

- Date: 2026-10-15
- Status: fixed
- Severity: medium

## Description
`fuzzlab fuzz --store S` writes its observations to `--output` (default
`blind_sqli_dataset.csv`, in the working directory), then always imports that file into
the store as this run's `attempt` rows. When the run collected no rows, `save_dataset`
wrote nothing, so the import read **whatever file was already at that path** — an earlier
run's, possibly against another target or written into another project — and recorded
it as this run's attempts.

## Where encountered
Design review of the UI project-files change (CC-UI-0450, reviewer A, round 1), while
classifying every path option the launcher passes: `fuzz --output` defaults to a shared
working-directory file, and `fuzzlab/tools/blind_sqli_fuzzer.py::main` imported it
unconditionally.

## What it caused to fail
- A fuzz run that collected nothing (an unreachable URL, every payload filtered, an
  interrupted cycle) gained attempt rows it never made, with their `reward` (timing
  detections) — training and screening data attributed to the wrong run and target.
- With project files, the same shared CSV would carry one project's attempts into
  another. A fresh checkout with no CSV instead crashed the run on `FileNotFoundError`
  (`[!] Critical error`), before the oracle's confirmation ran.

## What the bug was identified to be
`main` called `store_adapter.import_fuzz_csv(args.output, …)` whether or not this run had
written `args.output`; `save_dataset` returned nothing to tell it.

## Root cause analysis
Five Whys:
1. Why were stale attempts imported? The import read the path, not this run's output.
2. Why did the path hold another run's data? The default output is a fixed file in the
   working directory, shared by every run started there; an empty run leaves the last
   run's file in place.
3. Why did `main` not know? `save_dataset` swallowed the "nothing written" case in a
   print and returned `None` — the fact "this run wrote the file" was never returned.
4. Why did no test catch it? Every fuzz test produced rows, so the file was always this
   run's; none ran an empty cycle over a pre-existing file.
5. Why is this a class? A consumer attributed an artifact to the current run because the
   artifact **existed**, not because a recorded fact said this run produced it.

**Root cause:** provenance inferred from presence — the importer trusted that a file at a
default path was this run's output, with no fact from the producer to back it.

## Corrective action
`save_dataset` returns whether it wrote the file; `main` imports only when it did
(`{"attempt": 0}` otherwise), so the oracle confirmation still runs and the run records
no borrowed attempts (CC-FUZZ-0450). The web UI also pins `fuzz --output` to the open
project's own directory (FR-UI-456, CC-UI-0450), so two projects never share it. Test:
`tests/test_core_project.py::test_fuzz_never_imports_a_stale_csv_when_its_run_collected_nothing`
(mutation-checked: restoring the unconditional import fails it).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug or root cause:
- **BUG-0074 / PA-0075** — same root cause one layer away: a store-wide model was cited as
  having scored runs it never scored ("a provenance claim about a run is backed by a
  recorded fact about that run, never inferred from an open-ended scope").
- BUG-0069 / PA-0071 and BUG-0088 / PA-0089 (a reader depends on state its producer never
  wrote) — related (a consumer trusting state), but there the state did not exist at all;
  here it exists and belongs to another producer run. Not a match.
- BUG-0078 / PA-0079 (an aborted run left looking finished) — different root cause.
Result: a recurrence of **PA-0075**'s root cause.

## Prior-preventive-action failure analysis
PA-0075 (from BUG-0074) did not prevent this because it was **too narrow / wrong layer**:
it was written for, and its PA-0002 sweep covered, *rows in the store* (model rows and
the `select_latest` readers). A run's provenance can also be inferred from a **file on
disk** handed between steps of the same tool or between tools (a CSV, an intermediate
database), which no store reader or sweep looked at. Its rule 2 ("a writer whose scope is
open-ended records the closed set it acted on") had no counterpart for a writer that
writes nothing.

## Preventive action
**PA-0450** (strengthens PA-0075, from rows to file handoffs): a step imports, cites or
attributes an artifact to the current run only on a **fact from its producer** that this
run wrote it (a return value, a this-run token or record) — never because the path
exists. A fixed default output path shared by every run in a directory is a provenance
hazard: tools that write one must make "wrote nothing" visible to their consumer, and the
web UI pins such paths per project (FR-UI-456). Each such handoff has a test that runs the
producer empty over a pre-existing file.

PA-0002 sweep (by mechanism: every import of a file into the store; disposition per site):
- `tools/blind_sqli_fuzzer.py` (`import_fuzz_csv(args.output)`) — **fixed** here.
- `tools/spider.py:1993` (`import_spider(args.db)`) — not an instance: the crawl clears its
  tables at the start of every run (`DELETE FROM discovered_pages …`), except under
  `--resume`, whose purpose is to keep earlier results (documented).
- `tools/fetcher.py:964` (`import_spider(args.spider_db)`, `import_audit(args.out)`) — not
  an instance: the spider DB is the documented input (another tool's output, by design),
  and `--out` is reset at the start of the run (`setup_results_db`, unless `--append`,
  documented); with no targets the import is never reached.
- `harness/auto_cli.py:265`, `greybox/greybox_cli.py:135` (`import_spider(args.spider_db)`
  when the file exists) — not instances: the spider DB is the documented input from
  `fuzzlab crawl`; under the UI it is the project's own (FR-UI-456), so another project's
  crawl is never consumed.
