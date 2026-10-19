# BUG-0521 — An out-of-band payload's canary token survived in its trace preview

- Date: 2026-10-19
- Status: fixed (CC-CORE-0066)
- Severity: medium. The canary token of a command-injection payload (`$(curl …/cb/<tok>)`,
  `` `curl …/cb/<tok>` ``) was kept whole in the exchange's `value_preview`, so in
  `trace_event`, the evidence pane and the exports. Anyone reading a trace could replay
  the callback path.

## Description
`trace.safe_ref` (BUG-0514's fix) blanks a path segment when the whole segment looks like
an identifier. In a URL embedded in text, the last segment carries the text's next
character (`<tok>)`, `` <tok>` ``), which is outside the identifier alphabet, so the
segment was not judged an identifier and the token was kept.

## Where encountered
The pre-change gate for DG-M6M8 (CC-FUZZ-0102): reviewer 1 measured it on 9b17d0d;
reviewer 2 did not reproduce it with other templates; I re-ran it: the `$(…)` and
backtick forms leak, `;curl …` and the XXE entity do not.

## What it caused to fail
Redaction of every preview and export (FR-CORE-505, the owner's spec).

## What the bug was identified to be
An identifier test applied to a whole segment, never to the identifier-shaped run inside
it.

## Root cause analysis
**Method: change analysis.** The leaking and the safe payloads differ only in the character
after the token. **Root cause:** BUG-0514's token-shape list (userinfo, matrix, fragment,
path, relative) tested each shape alone, never a URL embedded in surrounding text, which
is how every out-of-band payload carries one.

## Corrective action
`_blank_identifiers` also replaces an identifier-like run (`[A-Za-z0-9_-+=]{8,}`) inside a
segment. Tests: two new token shapes in
`tests/test_trace_model.py::test_safe_ref_withholds_every_token_shape` and
`::test_a_payload_preview_never_keeps_its_canary_token` (four payload templates); all three
fail on the old code.

## Recurrence review
- **BUG-0514 / PA-0514** (the same day): the same sink and the same root class; this is a
  shape its fix missed.

## Prior-preventive-action failure analysis
PA-0514(2) listed the token shapes as standalone URLs. Its enforcement tested each shape as
a whole value; the shape the tool itself produces most (a URL inside a payload, followed
by shell syntax) was not on the list.

## Preventive action
PA-0521 (strengthens PA-0514(2)): the token-shape list includes each shape embedded in
text and followed by the punctuation the tool's own payloads use; a redactor judged on
whole segments also judges the identifier runs inside them.
