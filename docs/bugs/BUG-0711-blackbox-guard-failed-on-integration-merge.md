# BUG-0711 — The black-box guard failed on the integration merge (`graphql`)

## Description
After merging the integration branch (lane GQL's DVGA answer key) into lane BBOX's
branch, `tests/test_blackbox_detection.py::test_detection_code_names_no_lab_identifier`
failed: `graphql`, a path segment of DVGA's answer key, appears in string literals of
`audit/graphql_context.py`, `tools/apiop.py` and `tools/fetcher.py`.

## Where encountered
Lane RULESEL's first test run after `git merge origin/ccr-e5c7c0c6-r9ladz` (2026-11-20).

## What it caused to fail
The whole-package black-box guard (PA-0660) on the merged tree: every harness run of the
merged branch would be red.

## What the bug was identified to be
A protocol name (GraphQL's conventional `/graphql` endpoint) entered the lab-identifier
set when the first GraphQL answer key landed, while the detection code that reads
GraphQL documents legitimately names it. The guard's `CITED` table had no entry for it.
The two branches each passed alone; only their merge failed.

## Root cause analysis
1. Why did the guard fail? `graphql` is in DVGA's answer key and in detection literals.
2. Why was it not cited? BBOX wrote the guard before DVGA's key existed on its branch;
   GQL wrote its reader before the guard existed on its branch.
3. Why was it found only now? Neither lane ran the other's whole-package guard; the
   guard grows with every answer key by design (PA-0660(5)).
4. **Root cause:** a guard whose input set grows with data was merged with new data
   without re-running it before the merge, and a public protocol term was not cited.

## Corrective action
`CITED["graphql"]` in `tests/test_blackbox_detection.py` with independent sources
(GraphQL over HTTP specification; graphql.org "Serving over HTTP"). Lane RULESEL added it
first on its branch; the orchestrator landed the same fix on the integration branch
(82910aa) when it merged BBOX, and RULESEL's copy was dropped in favour of it at the merge.

## Recurrence review
Checked PA-0660 / BUG-0660 / BUG-0661 (the guard's origin) and PA-0031 / PA-0146 (merge
and concurrency). No prior failure of this guard; same class as PA-0146's "two items on
one file" for a data-driven guard.

## Preventive action
PA-0711: a lane that adds an answer key or a fixture, or merges one, runs the
whole-package black-box guard on the merged tree before pushing, and a public protocol or
standard term the guard flags is cited (with an independent source), never renamed in
detection code to dodge it. Enforced by the guard itself (it runs in every harness run as
a whole-package guard).
