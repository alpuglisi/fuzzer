# BUG-0084 — Proxy history persisted URL tokens, body passwords and redirect tokens

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0019, CC-CORE-0034)
- Severity: medium-high. Secrets landed in the store's `flow` rows, the body table and
  the full-text index, which are searchable from the web UI.

## Description
`proxy/redact.py` promised to redact "sensitive headers (and common token query
parameters)", but redacted only headers. A flow `POST /login?access_token=eyJ…` with
body `password=hunter2`, answered `Location: /home?session=…`, was persisted with all
three secrets: `flow.url`, the stored raw request and response, and FTS (which found
`hunter2`). `flow.req_body` / `resp_body` were stored unredacted too.

## Where encountered
The error-review phase (`scratchpad/review7/r9_redact.py`).

## What it caused to fail
NFR-PROXY-safe ("persisted data must not carry credentials in cleartext") and the
module's own docstring contract.

## What the bug was identified to be
The redaction covered one of several places secrets live (headers), while its
docstring claimed more. No test searched the persisted copies.

## Root cause analysis
1. *Why persisted?* Only header values were replaced.
2. *Why only headers?* The first cut handled the obvious case, and the docstring
   overstated it.
3. *Why undetected?* Tests checked the redacted headers, not every persisted copy
   (row, body table, FTS) for planted secrets.
4. *Why did the names need care?* The obvious fix, substring matching as in `obs`,
   would redact benign lab fields: the main lab's `author` injection point, `sidebar`.

**Root cause:** an untested docstring contract, and no shared notion of "sensitive
name".

## Corrective action
- **The predicate (CC-CORE-0034).** `core.redaction.is_sensitive_name` matches by name
  **token** (split on separators, camelCase and digits). It has a token set,
  `*sessid` / `*sessionid`, `key` only alone or qualified (`api`, `private`, …), and
  `code` only alone. `core.obs` uses it too. **Behaviour change, listed:** log extras
  `author` and `tokenizer` are no longer redacted, and `key` / `api_key` / `session_id`
  now are.
- **Redaction (CC-PROXY-0019).** `proxy.redact` now covers:
  - headers named sensitively;
  - query parameters of the request target and of `Location` / `Content-Location` /
    `Refresh`;
  - form, JSON (any depth) and multipart (non-file) **request and response** bodies.

  Content-Length is recomputed when it was consistent. A JSON body is re-serialised
  only on a hit, so a benign message stays byte-identical. Chunked or compressed bodies
  are stored as received: a stated residual, tested.
- **`HistoryWriter`** redacts `flow.url` and the separately stored bodies as well.
- **Trade-off, stated:** Repeater tabs seeded from history carry placeholders, so
  replaying a JWT / session / CSRF flow needs a fresh capture or `redact_secrets=False`.
  This also applies to payloads sent to the lab's own `password` injection point.
- **Tests** (`tests/test_proxy_redaction.py`):
  - the repro's secrets, plus a nested JSON key, a multipart field, a response
    `access_token` and an API key, absent from every persisted copy; benign content is
    kept;
  - byte-identical benign messages;
  - Content-Length;
  - multipart files untouched;
  - chunked and gzip residuals;
  - 13 sensitive and 16 benign names;
  - the obs behaviour change.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0069 / PA-0071** (a reader relied on a column production never wrote; a test
  fixture supplied it): related through the same failure of an unbacked contract.
- **BUG-0082** (this batch): a "never sent" docstring. **Same root cause:** an untested
  safety promise in a docstring.

**Result:** the "safety contract in prose, not in a test" class, together with
BUG-0082.

## Prior-preventive-action failure analysis
**PA-0071 was the wrong layer.** It covered data contracts (columns), not behavioural
promises in docstrings. No PA required a docstring's safety claim to have a test.

## Preventive action
- **PA-0083** (shared with BUG-0082): every "never / always" safety claim in a
  docstring is backed by a test that fails when it is broken.
- **PA-0085** (redaction-specific):
  1. Sensitivity is decided by one name-token predicate (`core.redaction`), never a
     local substring list.
  2. A redaction test plants each promised class of secret and searches **every**
     persisted copy (row, body table, FTS, separately stored bodies), with a benign
     list asserting nothing over-redacts.

**Sweep (PA-0002):**
- **obs logs:** moved to the predicate.
- **`config.redacted()`:** masks config keys containing `password` / `secret` /
  `token` / `credential` / `cookie` / `authorization` (a substring list over config
  names, not traffic). Config keys are project-defined, so the substring risk does not
  arise. Left as is, and noted.
- **Repeater tabs:** user-authored replay bytes, kept raw deliberately (documented).
- **`session_capture`:** captures to an in-memory session, never to history rows.
- **Report and run page:** show no raw requests.
- **Runner output:** CLI stdout; the CLIs never print secrets (the session manager logs
  `redacted()`).
