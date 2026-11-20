# BUG-0720 — A whole-repo GraphQL guard named the one lab allowed GraphQL points

- Date: 2026-11-20
- Status: fixed (CC-AUD-0720)
- Severity: low. A test defect: the guard failed on a correct answer key. Nothing in the
  product changed behaviour, and nothing was scored wrongly.

## Description
`tests/test_graphql_args.py::test_no_other_labs_ground_truth_point_has_a_graphql_context`
checks that the auditor's GraphQL context (`fuzzlab/audit/graphql_context.py`, FR-AUD-601)
changes nothing for a body that is not a GraphQL request: every ground-truth point of
every lab, built as the harness builds it, has no GraphQL binding and is a data point. It
skipped GraphQL requests by naming the one lab that had them (`if gt.parent == DVGA_GT:
continue`).

## Where encountered
Lane HOLDOUT, onboarding the held-out lab DVWS-node (CC-LAB-0422). Its answer key has
three GraphQL negatives whose `json_body` is a GraphQL request (`query` + `variables`).
The onboarding subagent's run of the answer-key tests reported the failure; the
orchestrator reproduced it after merging the lab (`6dfb4e0`'s parent tree).

## What it caused to fail
The guard: `assert graphql_context.bindings(pt) == ()` on the new lab's
`variables.<name>` points, which are GraphQL variables and correctly have a binding. Had
it not been fixed, the lane's harness would have been red on a correct key, and the
only "fix" open to the onboarding lane (which may not edit the test, and may not name a
held-out lab in it, lab/HOLDOUT.md rule 4) was to drop correct cases from the key.

## What the bug was identified to be
The guard told GraphQL requests from other JSON bodies by the lab that carried them, not
by the body. Its premise ("only DVGA has GraphQL points") was true when written
(CC-CRAWL-0600 / CC-AUD-0600) and became false with the second GraphQL lab.

## Root cause analysis (Five Whys)
1. Why did the guard fail? A second lab's GraphQL points were not skipped.
2. Why were they not skipped? The skip was `gt.parent == DVGA_GT`, a literal lab.
3. Why a literal lab? The property it needed (this body is a GraphQL request) was
   expressed by the one example the author had, though the code already had a reader
   that decides it (`tools.apiop.graphql_variable_types` parses an executable document).
4. Why was that not caught? PA-0001 (derive expectations from the source of truth, do not
   hard-code) is a review convention with no enforcement, and the review of lane GQL
   looked at the GraphQL logic, not the guard's selection.
5. Why does it matter now? Answer keys are data that grows (and held-out keys must be
   checked without being named): **root cause — a whole-repo test over answer keys
   selected its exceptions by lab name instead of by a property of the point.**

## Corrective action
CC-AUD-0720 (in the HOLDOUT lane's DVWS-node merge, `6dfb4e0`): the guard skips a point
when `is_graphql_request(point)` — its `json_body.query` parses as an executable GraphQL
document by the same reader the auditor uses (SP-80) — for every lab, naming none; a new
test pins the predicate on a GraphQL body and on a REST body with a `query` field. The
guard still checks 50+ points.

## Recurrence review
Searched `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a hard-coded expectation that a
registry or the data defines: **BUG-0001** / **BUG-0002** (a schema version hard-coded in
tests), PA-0001 (the rule). Same root-cause class: a test expectation hand-written where it
could be derived. Sweep (PA-0002): every test that loops over `lab/ground-truth*/`
(`test_external_labs_static.py`, `test_forms_phase2.py`, `test_oracle.py`,
`test_replay_bindings.py`, `test_destructive_routes_external_labs.py`,
`test_front_controller_routes.py`, `test_graphql_args.py`) — only this guard singled a lab
out; `test_external_labs_static.py`'s literal `GT_DIRS` list (not an exclusion, but a
hand-written list of keys) was replaced by discovery in this lane (CC-LAB-0420).

## Prior-preventive-action failure analysis
PA-0001 (from BUG-0001) did not prevent this: it is **not enforced** ("applied in
review") and it is phrased for constants and registries in the code, so a selection by
*which data file* a case came from did not read as a hard-coded value to the author or
the reviewer. PA-0720 narrows it to the case that recurs with growing lab data and
enforces it mechanically: the held-out guard already refuses held-out lab names in any
other test file, and the GraphQL guard is now property-based and pinned.

## Preventive action
PA-0720 (`docs/PREVENTIVE_ACTIONS.md`).
