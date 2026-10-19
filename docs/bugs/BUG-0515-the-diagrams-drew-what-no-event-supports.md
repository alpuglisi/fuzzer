# BUG-0515 — The diagrams drew what no event supports

- Date: 2026-10-19
- Status: fixed (CC-CORE-0064, CC-AUD-0052, CC-UI-0062; the post-implementation review of the diagrams series, F-076)
- Severity: medium. The data flow and the sequences stated more than the evidence: the core claim of the feature.

## Description
Six cases, one class:
1. a spider load that failed (status 0) was drawn as a reply "0";
2. a request learnt in the browser and blocked before sending was a solid, observed
   browser→interface flow;
3. the spider's own page loads came from the "Browser" actor, even with the static
   engine;
4. a refused external host was a solid Mermaid flow;
5. no interface was ever `inferred`, though a `{id}` grouping is an inference;
6. *executed* counted every answered exchange on its own URL: a follow-up, a restore or
   the fingerprint baseline counted on interfaces never scheduled, and a timed-out
   test send did not count.

## Where encountered
The two-reviewer gate (`docs/components/README.md`), run after the fact over the diagrams series (8f5efd0..a8d8d31) because it had been skipped (F-076). Reviewer B found 1, 3, 4 and 5; reviewer A 2; both 6.

## What it caused to fail
The diagrams' honesty requirement; coverage counts.

## What the bug was identified to be
The views mapped every observation to observed traffic by default, and the tests checked
that the expected elements were present, never that an unsupported one was absent.

## Root cause analysis
**Method: fault tree.** Each case is an element drawn by a default branch (status not
None, src not tool, flow kind http) whose negative case had no fixture.
**Root cause:** no negative fixture per kind of non-traffic (failed, blocked, refused,
grouped, not-a-test-send).

## Corrective action
1. status 0 is no status (`observe_spider`, the reducer); the spider sequence draws it
   lost;
2. `delivery` not `sent` makes a separate `blocked` flow with `refused`, drawn
   "blocked, never sent", dashed;
3. `by: crawler` (or an older `discovered_pages` event) draws from a "Spider (crawler,
   tool)" actor;
4. a refused flow is dashed and says "never sent" in Mermaid;
5. a templated interface is `inferred`;
6. *executed* counts a test's own sends, answered or not, on the test's interface; a
   follow-up, restore or retry never counts; units defined (`COVERAGE`).

Tests: `tests/test_diagram_e2e.py::test_a_failed_spider_load_is_drawn_lost_never_as_a_reply`,
`::test_the_data_flow_shows_the_application_and_keeps_testing_separate` (spider actor,
inferred, blocked and its Mermaid),
`tests/test_trace_model.py::test_executed_counts_a_tests_own_sends_on_its_interface`.

## Recurrence review
No earlier bug in the diagram views (new this day). Related: BUG-0510 (a follow-up
drawn from its observation).

## Prior-preventive-action failure analysis
Not a recurrence of a fixed bug.

## Preventive action
PA-0515: every drawn element and count names the event field that supports it, and each
view has a negative fixture for each kind of non-traffic it can receive.
