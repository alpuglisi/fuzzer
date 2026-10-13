# BUG-0100 — JSON redaction failed open on parse failures and crashed on deep input

- Date: 2026-10-13
- Status: fixed (CC-CORE-0036, CC-PROXY-0021)
- Severity: high. Passwords in proxied traffic could be stored in cleartext, and one
  deep body aborted a whole history flush.

## Description
`redact_body` returned the original body whenever `json.loads` raised. That covered
valid JSON with a 5,000-digit integer (Python's int-string limit), a trailing comma,
unquoted or single-quoted keys, and a form body labelled JSON: each kept its password.
A body nested about 1,100 deep raised `RecursionError`. Bodies typed `text/plain` or
untyped were never redacted, and chunked or compressed bodies were stored as received
(a stated residual).

## Where encountered
A third-party audit (finding #4), reproduced with `scratchpad/ext2/f04_redact.py`.
Reviewers A1 and B-S1 found the unquoted, single-quoted and form shapes; B-S2 found the
content-type bypass, and B-S3 the stored framing.

## What it caused to fail
FR-PROXY-11, NFR-PROXY-safe, and the module's own "JSON (any depth)" claim.

## What the bug was identified to be
The redactor's failure mode was "keep the original". It had no size or depth bound,
and it trusted the declared content type.

## Root cause analysis
1. *Why kept?* The `except ValueError: return body` branch.
2. *Why written so?* It aimed to keep malformed fuzz payloads readable, and the failure
   mode was never questioned.
3. *Why not caught?* PA-0091 planted every name × shape in **well-formed** JSON only,
   and PA-0096's extremes rule was applied to the model loader, not to the redactor.

**Root cause:** a redactor that failed open, with no tests at the parser's limits.

## Corrective action
In `core.redaction.redact_body`, the one boundary:
- **Size.** Bytes are capped at `MAX_REDACT_BYTES` (8 MiB); an oversized body becomes
  the marker.
- **Parse failure or depth.** The parse catches `ValueError`, `UnicodeDecodeError` and
  `RecursionError`, then an iterative depth check enforces `MAX_JSON_DEPTH` = 64. On
  either failure, a whole-body scan of every identifier-like token and every quoted
  string (`mentions_sensitive_name`) decides: any sensitive name → omitted; none → kept
  readable.
- **Sniffing.** An untyped or `text/plain` body is sniffed: JSON if it parses, form if
  it has the urlencoded shape.
- **Chunked and compressed bodies** (`proxy.redact`) are de-chunked and gzip/deflate
  decoded, bounded, which also bounds a decompression bomb. A clean one is stored
  byte-exact. One with a secret, or undecodable with a redactable type, is replaced by
  the marker, with `Transfer-Encoding` / `Content-Encoding` dropped and
  `Content-Length` set (B-S3). This closes the former residual.

**Tests** (`tests/test_storage_redaction.py`, `tests/test_proxy_redaction.py`):
- 8 failing shapes;
- 3 benign malformed bodies kept;
- the size cap;
- sniffing (3 types);
- the token scan;
- a deep body through `HistoryWriter`;
- chunked and gzip with a secret omitted with consistent framing, and clean ones kept;
- the bomb bound;
- a gzip body through history.

## Recurrence review
- **BUG-0090 / PA-0091:** the same module, a recurrence.
- **BUG-0095 / PA-0096:** the extremes rule.

## Prior-preventive-action failure analysis
- **PA-0091 was too narrow:** it covered well-formed inputs only.
- **PA-0096 was not applied to every typed boundary:** a redactor is one, so the
  extremes rule should have covered it.

## Preventive action
- **PA-0101:** a redactor **fails closed**. A body it cannot prove clean is omitted,
  never stored as received. It is tested with malformed, huge-number, deep, oversized,
  mislabelled, chunked and compressed bodies carrying secrets.

**Sweep:** `obs` log redaction redacts dicts, with no parsing; form and multipart bodies
get the cap; header redaction does no parsing.
