# BUG-0518 — The diagrams page lost origins, had no evidence for the application, and returned 500 on a bad scope

- Date: 2026-10-19
- Status: fixed (CC-UI-0062; the post-implementation review of the diagrams series, F-076)
- Severity: low. UI requirements FR-UI-510 ("every box opens its evidence", "a change reloads the run") were partly false, and a malformed URL gave a server error.

## Description
- `fillOrigins` returned early once a list existed, so an origin found later never
  appeared; with one selected, the list shrank to it.
- The application box had no click to its evidence.
- `sequence(scope="finding:abc")` raised, so `/sequence` and `/export/sequence.mmd`
  returned 500.

## Where encountered
The two-reviewer gate (`docs/components/README.md`), run after the fact over the diagrams series (8f5efd0..a8d8d31) because it had been skipped (F-076). Reviewer B (all three); reviewer A (the 500).

## What it caused to fail
The origin filter on a run whose origins grew while open; navigation from the application box; two routes on a malformed scope.

## What the bug was identified to be
A filter list built once from a filtered model; a missing click handler; an unchecked `int()`.

## Root cause analysis
**Root cause:** UI requirements stated for every element were tested on one element
and on the first load only.

## Corrective action
`dataflow` returns every origin of the run, and the page lists those; the application
heading opens its evidence; a malformed or unknown scope is a 400.
`tests/test_web_diagrams.py::test_the_page_renders_labels_as_text_navigates_evidence_and_updates_live`
(a later origin listed, both listed after choosing one, the application's evidence;
fails on the old script) and `::test_exports_download_and_bad_requests_are_refused`.

## Recurrence review
BUG-0136-era UI bugs were per-page; no earlier diagrams UI bug.

## Prior-preventive-action failure analysis
Not a recurrence.

## Preventive action
PA-0518: a UI requirement stated for "every" element or "a change" is tested on each kind
of element and on a change arriving after the first load.
