# BUG-0099 — The core HTTP client's recorder persisted URL and body secrets

- Date: 2026-10-13
- Status: fixed (CC-CORE-0036)
- Severity: medium (latent). The audit rated it High. No production caller attaches a
  store today (`tools/authhttp` passes none), but any that did would store secrets in
  cleartext.

## Description
`HttpClient._record` stored `request.url` and both bodies verbatim. A POST to
`…/login?token=URL_SECRET` with `{"password":"BODY_SECRET"}`, answered
`{"token":"RESPONSE_SECRET"}`, left all three secrets readable in `flow.url` and
`body.data`. FR-CORE-6 said the helper "records raw bytes", which contradicted
NFR-CORE-secrets ("secrets never stored… redaction on write").

## Where encountered
A third-party audit (finding #3), reproduced with
`scratchpad/ext2/f03_httprecord.py`.

## What it caused to fail
NFR-CORE-secrets; the persisted-traffic contract that proxy history already met.

## What the bug was identified to be
A second producer of persisted traffic that never used the redaction written for the
first (proxy history).

## Root cause analysis
1. *Why stored?* `_record` called `put_body` and inserted the URL directly.
2. *Why no redaction?* Redaction lived in `proxy/redact.py`, and `core` must not import
   `proxy`.
3. *Why not noticed?* BUG-0084 / BUG-0090's tests and sweeps covered `HistoryWriter`'s
   copies, not other producers. FR-CORE-6's "raw bytes" wording also made raw storage
   look intended.

**Root cause:** no single storage boundary, and no enumeration of the producers of
persisted traffic.

## Corrective action
- **One boundary in `core.redaction`:** `redact_url`, `redact_query`, `redact_body` and
  the per-type helpers move from `proxy/redact.py`, which re-exports them. It is fail
  closed (see BUG-0100).
- **`HttpClient._record`** stores `redact_url(url)` and `redact_body(body,
  content-type)` for both directions. The content type is looked up
  case-insensitively, and the wire request is never modified.
- **FR-CORE-6 is amended:** "records redacted bodies; the wire stays exact".
- **Tests** (`tests/test_storage_redaction.py`):
  - the repro → no secret in `flow` or `body`, benign content kept;
  - an AST guard: every function that INSERTs into `flow` / `flow_fts` calls a
    redactor, or is history's `_insert`, which is fed only prepared records. It is
    proven on a synthetic producer.

## Recurrence review
- **BUG-0084 / PA-0085 and BUG-0090 / PA-0091:** redaction gaps.
- **BUG-0091:** the "second producer" lesson, for label metrics.

## Prior-preventive-action failure analysis
**PA-0085 and PA-0091 were too narrow.** They required every *copy* that the history
writer persists to be searched for secrets, not every *producer*. PA-0092(1) ("every
producer") was written for evaluation numbers and never generalised to persisted
traffic.

## Preventive action
- **PA-0100:** every producer of persisted traffic goes through the one
  `core.redaction` storage boundary. An AST guard enumerates the producers, with a
  synthetic offender (PA-0034(2)).

**Sweep:**
- `HistoryWriter` (prepared records);
- `HttpClient._record` (fixed);
- the repeater (writes through `HistoryWriter`);
- labgen / tools: no flow inserts.
