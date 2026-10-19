# BUG-0512 — Explorer actions were filed under another workflow than their requests

- Date: 2026-10-19
- Status: fixed (CC-AUD-0052, CC-CRAWL-0048; the post-implementation review of the diagrams series, F-076)
- Severity: medium. Every link click and harvest load of a disco run was shown twice: a workflow with the requests and no action, and one with the action and no requests. The sequence still claimed correlation by action id.

## Description
`tools.observe.observe_disco` (CC-AUD-0050) put every explorer action in scope
`workflow:act-<seq>`. Disco names an action `act-<n>`, `nav-<n>` (an element with an
href) or `harvest-<n>` (a route load), from one counter (`explore._tag`), and its
captured requests carry that id. The action's event key also embedded `n`, the count of
events before it, so re-importing a grown capture duplicated every action.

## Where encountered
The two-reviewer gate (`docs/components/README.md`), run after the fact over the diagrams series (8f5efd0..a8d8d31) because it had been skipped (F-076). Both reviewers found it, and each reproduced it with a scratch capture.

## What it caused to fail
The `workflow:` sequences of any disco run with a link click or a harvest load; the
idempotency of a re-import.

## What the bug was identified to be
The importer composed a correlation id from a number and an assumed prefix instead of
taking the id the producer wrote.

## Root cause analysis (Five Whys)
1. Why `act-2` and not `nav-2`? The importer wrote `act-` for every action.
2. Why compose it? `actions.jsonl` recorded only `seq`, not the id.
3. Why was that not noticed? The fixture logged one action, `act-1`, the one case the
   assumption holds for.
4. Why one case? The test checked that a workflow exists, never that each action shares
   a workflow with its own requests.
   **Root cause:** a correlation id reconstructed by the consumer, tested only where the
   reconstruction happens to agree.

## Corrective action
- `disco.explore` writes the action's id (`action_id`) on every `actions.jsonl` line
  (CC-CRAWL-0048).
- `observe_disco` uses it; for a log from before it, it takes the id a capture record
  with the same number carries (the counter is shared), and only then guesses by kind.
- An action's key is its line in the append-only log (`<tag>:action:line<n>`).
- `tests/test_diagram_e2e.py::test_a_capture_gives_origins_auth_contexts_workflows_and_external_refs`:
  a `nav-` action logged the old way and a `harvest-` action each share one workflow
  with their requests; the only workflows are the three ids; a second import writes
  nothing.

## Recurrence review
- **BUG-0510 / PA-0510** (the same day): the same root cause. The trace reconstructed
  a follow-up's send from its observation. PA-0510(1) says evidence is recorded where
  the action happens, never reconstructed.

## Prior-preventive-action failure analysis
PA-0510 was written after this code. Its PA-0002 sweep listed `tools.observe` as
"written from each imported row as it is read" and did not look at how a row's scope or
key was composed. It swept by event, not by every field a consumer derives.

## Preventive action
PA-0512 (strengthens PA-0510(1)): a correlation id or key is copied from what the
producer wrote, never composed by the consumer; the test covers every id form the
producer makes. The sweep: every `scope=` and `key=` in `tools/observe.py`,
`proxy/history.py` and `harness/tracing.py`: the others copy a producer's id (a row id,
a flow id, a record index in an append-only file).
