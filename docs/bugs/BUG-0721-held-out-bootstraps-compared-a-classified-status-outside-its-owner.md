# BUG-0721 — Two held-out lab bootstraps compared a classified status literal outside its owner

- Date: 2026-11-20
- Status: fixed (CC-LAB-0427)
- Severity: low. A guard failure on the lane branch, before any merge to the integration
  branch; the bootstraps behaved correctly on both labs.

## Description
`bootstrap_vampi` and `bootstrap_dvws_node` (`fuzzlab/lab_fixtures/external.py`, CC-LAB-0421 /
0422) verified their login with `anon.status_code != 401`. 401 is a status SP-56 classifies
(`core.comparability`); FR-CORE-507 / PA-0529(4) allow a literal comparison against one
outside the owner only on the reviewed allowance list of
`tests/test_core_comparability.py`.

## Where encountered
`scripts/verify_change.py --base e14c925` on 6ddac13 (lane HOLDOUT): 93 files, 4249 passed,
1 failed — `tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner`
(extra sites `bootstrap_vampi`, `bootstrap_dvws_node`).

## What it caused to fail
The whole-package guard. Adding allowance rows was not open: they are keyed by function name
and would name held-out labs in a test file other than the benchmark's (lab/HOLDOUT.md rule 4).

## What the bug was identified to be
A bootstrap's positive differential needs "the token matters" (200 with it, refused without
it), not "this answer is an auth failure": the exact 401 was a stricter, classifying check
than the differential needs.

## Root cause analysis (Five Whys)
1. Why did the guard fail? New code compared 401 literally outside the owner.
2. Why was it written so? Each onboarding subagent wrote the check from the status it
   measured on its lab.
3. Why was it not caught before the merge? The subagents ran the two test files their
   dispatch prompt named, and I ran a subset after each merge; the whole-package guard ran
   only in the harness at the end.
4. Why did the prompts name test files? I wrote "verify with pytest … tests/test_external_labs_static.py
   tests/test_holdout_benchmark.py" instead of the harness.
5. **Root cause: verification of delegated work used a hand-picked test list, so a
   whole-package guard the change tripped ran only at the lane's end.**

## Corrective action
CC-LAB-0427: both bootstraps require anonymous to be refused with a client error
(`400 <= status < 500`) and 200 with the token — the differential, with no classified
literal; the DVWS unit test covers 200, 302 and 500 anonymous answers.

## Recurrence review
Searched `docs/bugs/`, `docs/PREVENTIVE_ACTIONS.md` and the failure record for verification
by a hand-picked list: MULTI_AGENT_ORCHESTRATION §2 (born of a hand-picked list that missed
a broken test for three rounds), CLAUDE.md step 2, F-633 (a lane ran "only the oracle tests I
picked", a reviewed-set guard failed in its first harness run). Same root cause.

## Prior-preventive-action failure analysis
§2 / CLAUDE.md step 2 bind the verifier of a change; they were **not followed at the
delegation layer**: my dispatch prompts specified a test list for the subagents, so the rule
was broken by the instruction itself, and nothing checks a dispatch prompt. The harness did
catch it — at the end of the lane, not at each merge.

## Preventive action
PA-0721 (`docs/PREVENTIVE_ACTIONS.md`).
