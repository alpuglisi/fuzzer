# BUG-0085 — A malformed match/replace or scope rule broke every proxied connection

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0019, CC-UI-0049)
- Severity: medium. One bad rule added from the Proxy tab made the proxy answer every
  request with an empty reply, and left unhandled task exceptions.

## Description
- **Bad rules were accepted.** `ProxyController.matchreplace_add("body", "café€", "x")`
  was accepted, then every request raised `UnicodeEncodeError` (latin-1) inside
  `_on_client`. That handler caught only `CancelledError`, so the client got nothing
  and the asyncio task died. `scope_add(host, "(unclosed")` did the same with
  `re.error`, and so did an invalid match regex.
- **No containment:** any engine or sender exception killed the connection with no
  reply.

## Where encountered
The error-review phase (`scratchpad/review7/r2_rule_crash.py`).

## What it caused to fail
FR-PROXY-5 (match/replace and scope) under user error; NFR-PROXY robustness.

## What the bug was identified to be
User-supplied rules were first evaluated on live traffic, and the per-connection
handler did not contain its own failures.

## Root cause analysis
1. *Why did every request fail?* The rule raised on each application.
2. *Why accepted?* Rules were plain dataclasses; validation checked only the target
   name.
3. *Why did the connection die silently?* `_on_client` caught `CancelledError` only.
4. *Why no test?* Tests added valid rules.

**Root cause:** no validation at rule creation, and no containment per connection.

## Corrective action
- **Validation at creation.** `MatchReplaceRule.__post_init__` encodes match and
  replace (latin-1: the proxy edits raw bytes) and compiles regex rules.
  `ScopeRule.__post_init__` compiles `path_regex`. A failure raises `ValueError`; the
  web API answers **400** for both scope and match/replace (CC-UI-0049).
- **Per-connection containment.** `_on_client` catches `Exception` and records it on
  `AsyncProxyServer.errors`.
  - It answers `502 Bad Gateway` if nothing was written yet, and otherwise just closes.
  - On the CONNECT path the `200` has already been written, so it never writes a 502
    into the tunnel.
  - The server keeps serving.
- **Tests** (`tests/test_proxy_rules_and_scope.py`):
  - three bad match/replace rules, plus a bad scope regex, are refused at creation;
  - the API answers 400;
  - a raising sender → 502, the next request succeeds, and no unhandled task
    exception.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0076 / PA-0077** (plugin containment covers every per-plugin step): the same
  containment idea at a different boundary (connections, not plugins).

**Result:** the containment class. PA-0077 was scoped to plugins.

## Prior-preventive-action failure analysis
**PA-0077 was too narrow:** plugins only. The proxy's connection handler is another
per-unit boundary.

## Preventive action
**PA-0086** (generalises PA-0077):
1. User-supplied rules (regexes, encodings, scope patterns) are validated when created,
   never first evaluated on live traffic.
2. Every per-unit handler (per connection, per plugin, per run) contains its own
   failures and reports them.

**Sweep (PA-0002):**
- **Intercept editor:** parses user text with `RawMessage`, which never raises on bytes.
- **Repeater raw edit:** sends through the same sender; errors are returned to the
  API.
- **Web `saved_views` filters:** `re` is not used. Filters are SQL-bound values.
- **`ws.py` / `h2transport.py`:** not wired into the server's connection loop. Their
  relay errors are typed and caught (`WSProtocolError`; socket timeouts).
