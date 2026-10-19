# BUG-0514 — The trace kept tokens the record boundary already redacts

- Date: 2026-10-19
- Status: fixed (CC-CORE-0064; the post-implementation review of the diagrams series, F-076)
- Severity: high (secret exposure). URL userinfo, `;jsessionid=`, an implicit-grant `#access_token=` and a token path segment reached `trace_event`, the model, the JSON and Mermaid exports and the evidence pane.

## Description
`trace.safe_ref` (CC-CORE-0063) used `redact_url_identifiers`, which redacts query
values only. `scrub_event` sent only strings with `://` through it, so a relative
`/cb#access_token=…` under `location` passed untouched. `_interface` stored the raw URL
as `example` exactly when an id-shaped segment (a JWT) was grouped.

## Where encountered
The two-reviewer gate (`docs/components/README.md`), run after the fact over the diagrams series (8f5efd0..a8d8d31) because it had been skipped (F-076). Both reviewers reproduced it with scratch values; reviewer B end to end through a capture, the model and both exports.

## What it caused to fail
NFR redaction of every label, tooltip, preview and export (the owner's spec);
PA-0100's boundary.

## What the bug was identified to be
A second, weaker URL redactor for a new sink, while the project already had the stronger
one (`redaction.redact_for_record`: userinfo, matrix parameters, query-shaped fragments).

## Root cause analysis (Five Whys)
1. Why did a token survive? `safe_ref` redacted query values only.
2. Why only those? It reused the crawler's URL redactor, built for query strings.
3. Why not the record boundary's? It was not searched for; the new sink was treated as
   "like the crawler's".
4. Why did the tests not catch it? The secrets in the fixture were query values and a
   body field, the shapes the chosen redactor handles.
   **Root cause:** a new persistent sink for target-derived URLs was given an existing
   redactor chosen by analogy, not the strongest one, and tested only on the shapes that
   redactor covers.

## Corrective action
`safe_ref` = `redact_url_identifiers`, then `redact_for_record`, then identifier-like
matrix, fragment and path values blanked (a path token becomes `{redacted}`, grouped as
`{id}`); `scrub_event` sends any string with a `/` under a URL key through it;
interface ids drop `;name=value`. Tests:
`tests/test_trace_model.py::test_safe_ref_withholds_every_token_shape` (userinfo, matrix,
fragment, code, path, relative) and `::test_scrub_event_passes_relative_urls_under_url_keys`;
both fail on the old code.

## Recurrence review
- **BUG-0507 / PA-0507(2)**: before registering a mechanism, search for an existing
  implementation of the same decision. Here the decision was "redact a URL for a
  record", already owned by `redact_for_record` (CC-CORE-0450).
- **PA-0100**: one boundary per sink.

## Prior-preventive-action failure analysis
PA-0507(2) was written for shared-primitive registration and read as such; SP-48
registered the trace writer, not its URL redactor, so the search was never triggered.

## Preventive action
PA-0514 (strengthens PA-0507(2) and PA-0100): a new sink of target-derived text uses the
strongest existing redactor for each kind of value it stores, and is tested against the
project's full list of token shapes (userinfo, matrix parameter, fragment, path
segment, relative URL), not the fixture's.
