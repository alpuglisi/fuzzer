# BUG-0517 — An exchange's injection location was overwritten by its redirect target

- Date: 2026-10-19
- Status: fixed (CC-FUZZ-0101, CC-AUD-0052, CC-PROXY-0027; the post-implementation review of the diagrams series, F-076)
- Severity: low. The evidence of a probe answered with a redirect showed the wrong location (a path instead of query/body/header), and each retry copied it.

## Description
`TracingSender` put the response's `Location` header in the body key `location`, which
already held where the value was injected. A retry copies `location` (`_RETRY_KEEPS`).

## Where encountered
The two-reviewer gate (`docs/components/README.md`), run after the fact over the diagrams series (8f5efd0..a8d8d31) because it had been skipped (F-076). Reviewer A reproduced it (a POST body probe recorded with `location=/done?...`).

## What it caused to fail
The exchange's evidence and the retry events' parameter location.

## What the bug was identified to be
One body key with two meanings.

## Root cause analysis
**Root cause:** the event vocabulary was not checked for key collisions; the redirect key
was named after the HTTP header.

## Corrective action
The redirect target is `redirect` at every producer (`tracing`, `observe`,
`proxy.history`); readers fall back to an older event's `location` only when it holds a
path. `tests/test_diagram_e2e.py::test_a_redirect_is_shown_with_its_target` checks both.

## Recurrence review
No earlier key collision in the trace vocabulary (new this day).

## Prior-preventive-action failure analysis
Not a recurrence.

## Preventive action
PA-0517: an event body key has one meaning across every producer; a new field is checked
against the existing keys before it is named.
