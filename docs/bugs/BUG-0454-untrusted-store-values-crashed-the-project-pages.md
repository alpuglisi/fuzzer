# BUG-0454 — values read from an untrusted project file were assumed well-formed, and crashed the project pages

- Date: 2026-10-15
- Status: fixed
- Severity: medium (a crafted project file made `/project` and `/api/project/history` a 500,
  `POST /projects/open` a 500, and — as the configured store — stopped the UI starting)

## Description
Two instances of one defect, both from code review round 3 (security reviewer, on
8569187):
1. **Deep JSON.** `_parse_metadata` (`project.targets`) and `run_history` (`launch.argv`)
   caught only `ValueError`/`TypeError` from `json.loads`. A value nested 200 000 deep
   raised `RecursionError`, which no handler converts: `inspect` raised it, the open route
   returned 500, and `ProjectManager.__init__` failed for a configured store.
2. **Mixed types.** SQLite's TEXT affinity stores a BLOB as-is. A file with
   `run.started_at = X'41'` passed `inspect` and `summary`; `run_history`'s sort then raised
   `TypeError: '<' not supported between 'str' and 'bytes'` on every render.

## Where encountered
Code review round 3 (CC-UI-0450 / CC-CORE-0450). Never merged. The deep-JSON case had
already been fixed for `recent.json` in round 2 — without a sweep of the other parsers.

## What it caused to fail
A project file from someone else (the case FR-UI-457 exists for) made the project pages
unusable while it was open, or the UI unable to start with it configured.

## What the bug was identified to be
Readers of an untrusted store treated column values as the types the schema declares and
JSON values as shallow, so an odd value raised an exception class no boundary handled.

## Root cause analysis
Five Whys:
1. Why a 500? `RecursionError` / `TypeError` escaped the readers.
2. Why did they escape? The readers caught the errors of *well-typed but malformed* values
   only.
3. Why assume well-typed? The store had always been written by fuzzlab itself; opening
   files from elsewhere is new with project files, and the readers predate that threat.
4. Why was deep JSON fixed in one place only? The round-2 fix for `recent.json` was made as
   an instance fix; PA-0002's sweep was not applied to the other JSON parsers.
5. Why did PA-0108 not cover it? It requires one parser per stored JSON that validates
   "shape and types" — but was applied to the JSON document's shape, not to the column's
   SQLite storage type or to the parser's own failure modes (recursion).

**Root cause:** values from a store that can now come from someone else were read with
the assumptions that hold for fuzzlab's own writes (declared column types, shallow JSON),
and a parser-limit fix was not swept across the parsers of the same input.

## Corrective action
- `core.project._text` / `_int` type every value a project reader shows (text is a `str`,
  capped at `MAX_SHOWN_CHARS`, or `None`; never fabricated); `_parse_metadata` and
  `run_history` use them for every column, and drop rows whose id is not an integer; an
  unknown launch status reads `unknown`; a non-string argv element empties the argv.
- `_JSON_ERRORS = (ValueError, TypeError, RecursionError)` for both JSON parsers (as
  `_parse_recent` already had).
- `ensure_metadata` types `MIN(applied_at)` before writing it into the new row.
- `project.html` shows a missing value as "unknown" rather than `None`.
- Tests: `tests/test_core_project.py::test_deep_json_in_a_project_file_reads_as_malformed`
  (targets, argv), `::test_odd_types_in_a_project_file_are_never_a_crash`,
  `tests/test_web_projects.py::test_a_malformed_project_identity_is_shown_as_unknown`.
  CC-CORE-0450, CC-UI-0450 (code review round 3).

## Recurrence review
- **BUG-0107 / PA-0108** (bad evidence crashed datasets or became a fabricated row): one
  parser per stored JSON, validating shape and types. **Same root cause** (a reader trusting
  stored values), at a new layer (a store from someone else).
- **BUG-0100 / PA-0101(2)** (the JSON redactor crashed on deep input): the same parser limit
  — recursion — at another parser.
- Round 2 of this change fixed `RecursionError` in `_parse_recent` only. **Recurrence within
  the change.**

## Prior-preventive-action failure analysis
- **PA-0108 was too narrow**: "every reader of stored JSON validates shape and types" was
  read as the JSON document's shape; it says nothing about a column's storage type (SQLite
  does not enforce the declared type) or the parser's own exceptions.
- **PA-0101(2)** named deep input for *redaction* only; it was not generalised to every
  parser.
- **PA-0002 was not followed** in round 2: the `recent.json` fix was not swept.

## Preventive action
**PA-0454** (strengthens PA-0108 and PA-0101(2)): every value read from a store or file that
can come from someone else is typed at one parser before use — its storage type checked
(a declared TEXT column can hold a BLOB or a number), its size capped, and a JSON value
parsed with `RecursionError` among the handled errors; an odd value reads as missing or
malformed, never fabricated, never an exception. A fix for one parser-limit crash is swept
across every parser of the same input source in the same change. PA-0002 sweep: the
project readers (`_parse_metadata`, `run_history`, `_parse_recent`, `summary`) are fixed;
the results pages that predate project files (`/runs/{id}`, findings, flows) also read the
open project and may still 500 on an odd value from a crafted file — recorded as a
follow-up in CC-UI-0450 (they render only after the file passed the schema allowlist, so
the residual is a page error, not code execution or a write).
