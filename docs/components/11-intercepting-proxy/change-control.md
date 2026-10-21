# Intercepting Proxy — Change Control Log

Component code: **PROXY**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-PROXY-0029 — The upstream sender keeps exactly framed connections (FR-PROXY-405, BUG-0549) (2026-10-21)
- Placement: pre-assigned to POOL24 (audit defect 24). CC-PROXY-0028 is AU-PROXY's, which
  rewrites the framing in lines ~35-105 of the same file; this change touches only the
  `SocketSender` class and adds helpers after it. Planned merge order: AU-PROXY, then
  POOL24.
- Change (`fuzzlab/proxy/socketsender.py`):
  - `SocketSender` builds one SSL context per sender (`_context`, under a lock) instead
    of one per call.
  - It keeps upstream connections in an `_IdlePool` per (host, port, TLS), only after an
    exchange that was exactly one well-formed HTTP/1.1 request (`reusable_request`) and
    one fully framed HTTP/1.1 answer (`reusable_response`, with a strict chunked parse
    `_chunked_exact`) with no `Connection: close`, upgrade or connection-bound
    authentication; anything else is closed after its exchange, as before.
  - Only a reusable, idempotent request takes a kept connection (`_IDEMPOTENT`: GET,
    OPTIONS, TRACE, PUT, DELETE), after a check (`_quiet`: nothing readable, no buffered
    TLS byte; idle at most `IDLE_SECONDS`, 4 s). When the peer closed it before a byte of
    answer (an empty read before the idle timeout, or `_PEER_CLOSED`), the request is
    sent once more on a fresh connection; a timeout is never resent.
  - Bounds: `MAX_IDLE_PER_UPSTREAM` (8) and `MAX_IDLE_TOTAL` (64), the oldest closed
    first, the expired closed at each return. New `close()` (idempotent; also run when
    the sender is collected, `weakref.finalize`) and `keep_alive=False` (one socket per
    call); `idle_seconds` and `max_idle` are configurable.
  - New `tests/test_socketsender_pooling.py` (6 tests, 19 cases) on the shared loopback
    peer `tests/_keepalive_peer.py` (CC-CORE-0075).
- Impact (other components / project):
  - The proxy engine, `fuzzlab proxy` and the web proxy's Repeater forward well-framed
    traffic on kept connections; bytes on the wire and the answers returned are
    unchanged (NFR-PROXY-byte-exact).
  - A deliberately malformed request (duplicate `Content-Length`, a transfer coding, a
    pipelined second request) never rides a kept connection and its connection is
    closed after it: the desync experiments keep a fresh connection.
  - UI: `fuzzlab/web/proxycontrol.py` and `fuzzlab/proxy/cli.py` (not this lane's files)
    do not call `close()` at stop; the idle connections are closed when the sender is
    collected (residual R2 in BUG-0549).
  - No store or wire contract change.
- Risk (medium):
  - A misbehaving upstream that sends bytes after a fully framed answer could have them
    read as the next request's answer if they arrive between the check and the next
    read. Mitigated: such bytes already waiting make the connection be closed, and only
    an exactly framed exchange is kept; accepted as the residual of any keep-alive
    client.
  - `reusable_response` parses the answer bytes a second time, strictly, beside
    `recv_http_response`'s own framing (AU-PROXY's region). When AU-PROXY lands, the two
    must agree: if AU-PROXY exposes an exact-end decision, this check should call it
    (BUG-0549 R1).
  - A HEAD request is never kept (its answer's framing depends on the request the reader
    does not see).
- Deliverables:
  - [x] `SocketSender` kept connections, one SSL context, `close`, helpers — done
  - [x] `tests/test_socketsender_pooling.py`: well-framed (Content-Length and chunked)
    exchanges share a connection; 14 not-exactly-framed exchanges never leave their
    connection and a malformed request never rides a kept one; a stale kept connection
    resent once, a timeout never; TLS: one connection, one handshake, one context; 8
    threads each get their own answers on at most 8 connections; `close` and collection
    close the idle connections. Each failed on c483dc1 (one run) — done
  - [x] FR-PROXY-405 added; FR-PROXY-12 edited in place — done
- Effectiveness (assessed 2026-10-21): on loopback, 2 000 plain calls used 8 connections
  instead of 2 000; sequential calls/s 1 489 -> 10 271 (an earlier pair: 1 781 -> 4 650),
  8-thread 1 205 -> 3 140; over TLS 20 -> 3 826 sequential; a fresh TLS call built a
  20 ms system-CA context that is now built once (BUG-0549). The harness result is in this
  lane's report.

### CC-PROXY-0027 — A proxied flow's redirect target keeps its own key (BUG-0517) (2026-10-19)
- Change (`fuzzlab/proxy/history.py::flow_event`): the redacted `Location` is
  `redirect`, not `location`.
- Reason: one event key, one meaning across producers (PA-0517).
- Impact: proxy events gain `redirect`. Readers fall back to an older event's
  path-valued `location`.
- Risk: low.
- Review: this entry follows the two-reviewer gate run after the fact over the diagrams series (F-076); both reviewers disagreed, and every confirmed finding in this component is fixed here or answered below.
- Deliverables:
  - [x] code; `tests/test_proxy_trace.py` updated — done
- Effectiveness: verified offline.

### CC-PROXY-0026 — A closed proxy run records its end (FR-PROXY-13) (2026-10-19)
- Change:
  - `proxy/history.py`: `HistoryWriter.close(run_end=None)`. Given a status, it emits a
    `run.end` event through the writer's recorder (created if no flow made one), when
    no transaction it does not own is open, then writes the counters.
  - `proxy/cli.py`: `fuzzlab proxy` closes the writer with `complete` on Ctrl-C, or
    `aborted: <class>` when the loop raised.
  - `web/proxycontrol.py::ProxyController.stop` (UI component, CC-UI-0061) calls
    `close(run_end="complete")` instead of `flush()`.
- Reason: found in CC-PROXY-0025's lane report. A proxy run never recorded an end, so
  its diagram status always read `partial`. The web proxy's stop only flushed, so its
  trace counters were never written.
- Impact: one `run.end` event per closed proxy run. Flow history is unchanged.
- Risk: low. A failure to record the end is suppressed; the status then reads
  `partial`, which is honest.
- Deliverables:
  - [x] code; `tests/test_proxy_trace.py::test_stopping_the_web_proxy_records_its_end_and_its_counters`
    drives the real `ProxyController` with a store: after `stop()` the run's status is
    `complete` with its counters. It fails with the old `flush()` (`run_end` None) — done
  - [x] FR-PROXY-13 edited in place; CHANGELOG — done
- Effectiveness: verified offline (the test above).

### CC-PROXY-0025 — The proxy's recorded flows are trace events, live (FR-PROXY-13) (2026-10-19)
- Change:
  - **`proxy/history.py`:** `HistoryWriter` owns a `core.trace.TraceRecorder` (created
    on first use, on the writer's thread and store connection, under its lock, with the
    writer's `run_id`). After each flush has committed, `_trace` emits one
    `observe.exchange` event per written in-scope engine flow (scope `proxy`, key
    `proxy:flow:<flow id>`) and flushes it. New pure `flow_event` builds the body from
    the prepared (redacted) values; parameter names come from `tools.observe`
    (`_query_params`, `_body_params`, imported, not copied). A flush inside a
    transaction the writer does not own emits later, only for a flow still stored
    (`_still_stored`). `_insert` returns the flow id. `close()` emits what waited and
    writes the `trace_*` counters. `FlowRecord` gains `t`, `error`, `intercept` and
    `source` (none of them a stored column); `HistoryWriter` gains `trace=True`, and
    its `run_id` may be None (nothing traced).
  - **`proxy/server.py`:** `ProxyEngine.handle_request` stamps `t` when an in-scope
    request arrives; records the operator's held-message decisions (`request edited` /
    `request forwarded`, `response edited` / `response forwarded`); and records a flow
    whose upstream failed (no response, its error class) before re-raising, so the
    connection still answers 502.
  - **`proxy/repeater.py`:** repeater flows carry `source="repeater"` (not traced).
  - **`proxy/cli.py`:** `fuzzlab proxy` ends with `history.close()` (was `flush()`), so
    the counters are written.
- Reason: the intercepting proxy's history was missing from the trace, so the Diagrams
  page could not show user/browser traffic through the proxy (FR-CORE-505 gap).
- Impact (other components / project): new `trace_event` / `dg_*` rows for proxy runs
  (the trace's one writer, SP-48; no new writer of those tables). Consumers, found by
  searching `HistoryWriter(` and `FlowRecord(` across `fuzzlab/`: `proxy/cli.py`,
  `proxy/server.py`, `proxy/repeater.py`, `web/proxycontrol.py` (two constructions;
  unchanged, works as is: its `stop()` calls `flush()`, so its `trace_*` counters are
  written only after a dropped event, not at stop; the fix is `close()` there, outside
  this lane's files). `report.diagram` reads the events (CC-UI-0059). History gains a
  row for an in-scope flow whose upstream failed (status NULL); it used to be absent.
- Risk: low to medium. A trace failure is contained (counted `dropped`, logged) and
  never fails the history; the recorder commits only when no transaction is open.
  Cost, measured (400 flows, `batch_size=1`, two runs): median 0.30–0.38 ms per flow
  without the trace, 1.38–1.46 ms with it (p95 1.3–2.5 ms vs 5.8–13.4 ms), on the
  loop thread, like the history write itself (FR-PROXY-12). Accepted for hand-driven
  traffic; `HistoryWriter(trace=False)` turns it off.
- Deliverables:
  - [x] code — done
  - [x] tests: new `tests/test_proxy_trace.py` (11): the real `AsyncProxyServer` +
    `SocketSender` + `HistoryWriter(batch_size=1)` against a loopback upstream; one
    event per flow, live, stable keys; no Cookie / Authorization / password / token /
    JSON-key / Location secret in events, model or exports; out-of-scope and repeater
    flows give none; a failed upstream is a lost arrow; a re-flush, a failed flush and
    its retry, and re-processing add nothing; an owner's rollback traces nothing;
    intercept decisions recorded and drawn — done
  - [x] FR-PROXY-13; NFR-PROXY-safe's Enforced-by line; §5 interfaces — done
  - [ ] CHANGELOG, `docs/DIAGRAMS.md`, ARCHITECTURE — the orchestrator's (text in the
    lane report)
- Effectiveness (assessed 2026-10-19): 15 mutation runs against
  `tests/test_proxy_trace.py`; 13 were caught:
  - no in-scope / source filter; no rollback check; tracing inside an owner's
    transaction; no `t`; no failed-upstream record; `flush` raising after the trace
    call; no `proxy` scope listing;
  - a lost arrow drawn as a reply; a reply to the browser after a lost arrow; the
    Cookie header of the unredacted request in the body; query values as params; no
    edit note; no drop note.
  - two were not caught; both were mis-aimed first tries of mutations listed above. One
    changed the identical line in the capture sequence, not the proxy's. The other read
    the Cookie header from the prepared request, which is already redacted. Re-aimed
    at the proxy's own line and at the unredacted request, both are caught.

### CC-PROXY-0024 — The proxy's hand-written 501 says `Connection: close` (BUG-0147 sweep) (2026-10-15)
- Change: `fuzzlab/proxy/server.py`: the 501 sent for a CONNECT with no CA, after which
  the connection is closed, carries `Connection: close` (the 502 already did).
- Impact (other components / project): proxy clients only; no API, store or UI change.
  Found by BUG-0147's PA-0002 sweep of hand-written responses.
- Risk: low; one header.
- Residual recorded in BUG-0147 (not changed here): forwarded upstream responses keep
  their own `Connection` semantics although the proxy closes after each one. Rewriting
  the forwarded head is a design decision for this component.
- Deliverables:
  - [x] code — done
  - [x] guard (the same hand-written-response test, mutation-checked) — done
- Effectiveness (assessed 2026-10-15): full suite on 7c1fb91 (`scripts/verify_change.py --full`): 7106 passed, 0 failed, 42 skipped, 28 xfailed. `test_multitarget_category4` (BUG-0147's failure) passed; it had failed in the previous full run of the merged tree (7077 passed, 1 failed). `tests/test_probe_unobserved.py` 26 passed; 16 mutation checks each caught. Round 2 review: both reviewers AGREE.

### CC-PROXY-0023 — A captured session records the origins it was seen on (FR-SESS-20, BUG-0134) (2026-10-14)
- Change: `proxy/session_capture.py` records the canonical origin of every URL passed to
  `observe_request` / `observe_response` on the capture's host (loopback aliases one
  host) and sets `SessionState.origins`; `SessionManager.adopt` refuses a capture with
  none (O7).
- Impact: a captured session is sent only to the origins it was observed on; a capture
  fed without URLs can no longer be adopted (loud refusal).
- Risk: low (narrows). The proxy's own callers do not adopt yet (SessionCapture is used
  by tests and the planned FR-SESS-11 flow).
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_session_origin_scope.py`: recorded origins, refusal with none,
    an adopted capture never sent to another port; `test_proxy_session_capture.py` and
    `test_session_transport_binding.py` pass URLs) — done
  - [x] FR-PROXY-9 amended in place — done
- Effectiveness (assessed 2026-10-14): the capture tests pass; the prepare mutation
  (CC-SESS-0023) also fails the adopted-capture test.
- Review round 1 (2026-10-14; R5, A-N2): `SessionManager.adopt` unions the manager's
  `auth_origins` into an adopted capture's origins
  (`tests/test_session_origin_scope.py::test_adopt_adds_the_operators_auth_origins`).

### CC-PROXY-0402 — A bad `--store` fails before the dry-run plan is printed (2026-10-15)
- Change:
  - **`proxy/cli.py`:** in the dry-run branch, `_recording` runs before `report(...)`.
    `proxy --dry-run --store ""` used to print the whole plan and then exit 2 (reviews A
    and B, round 2).
- Impact (other components / project): none.
- Risk (level; mitigation or accepted-risk justification): low.
- Deliverables:
  - [x] code; FR-PROXY-400; test
    `tests/test_cli_default_store.py::test_proxy_dry_run_with_an_empty_store_prints_no_plan`
    — done
- Effectiveness (assessed 2026-10-15): reverting the order fails the test. Effective.

### CC-PROXY-0401 — `--export-ca` before any store resolution; `--store ""` is a usage error (2026-10-15)
- Change:
  - **`proxy/cli.py`:** store resolution (`_recording`) runs in the dry-run branch, and
    otherwise after `--export-ca`. `fuzzlab proxy --export-ca --store ""` exports the CA
    as before.
  - An explicit `--store ""` without `--export-ca` is now a usage error (PA-0105). It
    used to mean "do not record", because it was falsy. **This was not recorded in
    CC-PROXY-0400.**
  - The `--record` help comes from `storepath.DEFAULT_RULE`.
  - NFR-PROXY-dry-run gains a "Not yet enforced (BUG-0400)" line.
- Impact (other components / project): none beyond the proxy CLI.
- Risk (level; mitigation or accepted-risk justification): low.
- Deliverables:
  - [x] `proxy/cli.py`; FR-PROXY-400 updated — done
  - [x] tests: `tests/test_cli_default_store.py::test_proxy_export_ca_comes_before_any_store_resolution`,
    `::test_proxy_explicit_empty_store_is_a_usage_error` — done
- Effectiveness (assessed 2026-10-15): resolving before `--export-ca` (a mutation)
  fails the test. Effective.

### CC-PROXY-0400 — `proxy --record`: record flow history into the default store (FR-PROXY-400) (2026-10-15)
- Change:
  - **`proxy/cli.py`:**
    - New `--record` records into the resolved store (`core.storepath`). `--store PATH`
      alone still records there; with both, `--store` wins.
    - Recording stays **opt-in**.
    - The order is `--dry-run` / `--export-ca`, then `--authorized`, then
      `require_loopback` (the existing order), then `check_writable`, then `Store`.
    - The banner and the dry run name the store.
- Impact (other components / project):
  - The web launcher's proxy form gains a `--record` checkbox (commandspec
    introspection).
  - `web --with-proxy` is unchanged: it records to the UI's own `store_path`, which now
    resolves the same way.
- Risk (level; mitigation or accepted-risk justification): low.
  - Nothing is recorded unless asked.
  - The loopback and `--authorized` gates come before any store work, which is tested.
- Deliverables:
  - [x] `proxy/cli.py` — done
  - [x] tests: `tests/test_cli_default_store.py::test_proxy_records_nothing_unless_asked`,
    `::test_proxy_record_checks_come_before_any_store_work`;
    `tests/test_web_commandspec.py` and `tests/test_loopback_listeners.py` still green
    — done
  - [x] FR-PROXY-400 — done
- Effectiveness (assessed 2026-10-15): the dry runs name the store only when recording;
  usage errors leave nothing. Effective.

### CC-PROXY-0022 — Safety-NFR traceability lines (PA-0112, BUG-0111/0112 sweep; documentation only) (2026-10-13)
- Change: `requirements.md` gains `Enforced by:` / `Not yet enforced:` lines under
  NFR-PROXY-safe, NFR-PROXY-dry-run, naming the enforcing code and the test functions that fail without it
  (checked by `tests/test_requirements_traceability.py`). Open: the Repeater has no scope check; `--dry-run` over `--export-ca` is untested. No code change.
- Impact: none at run time. The guard now fails if these lines go stale (a renamed or
  deleted test) or if a new NFR is left unclassified.
- Risk: none (documentation, plus a test that reads it).
- Deliverables:
  - [x] traceability lines — done
  - [x] open clauses recorded and reported to the operator — done
- Review: reviewers A and B (BUG-0111/0112 draft v2, AGREED) asked for one doc-only entry
  per touched component.
- Effectiveness: verified by the guard (3 passed, incl. synthetic offenders).

### CC-PROXY-0021 — Fail-closed history redaction incl. framed bodies (BUG-0100); bounded upstream reads off the loop (BUG-0101); atomic history flush (BUG-0106) (2026-10-13)
- Change:
  - **`proxy/redact.py` (BUG-0100).**
    - It delegates body and URL redaction to `core.redaction`.
    - Chunked or compressed bodies are decoded with bounds (de-chunked;
      gzip/deflate) and checked: a clean one is kept byte-exact; a secret, or an
      undecodable redactable body, becomes the marker, with TE/CE dropped and
      Content-Length set.
    - `redact_body_for` follows the same rule.
  - **`proxy/socketsender.py` (BUG-0101).**
    - One bytearray and no per-chunk copy.
    - `MAX_HEAD_BYTES`, `max_body` and an overall `deadline`, breached with
      `UpstreamResponseError`.
    - `SocketSender(max_body=, deadline=)` and `fuzzlab proxy --max-response-bytes /
      --response-deadline`.
  - **`proxy/server.py`.** Both sender calls use `await asyncio.to_thread(...)`.
  - **`proxy/history.py` (BUG-0106).**
    - `flush` prepares first, contains a failed record with omitted bodies, and writes
      in `SAVEPOINT history_flush` (roll back and re-raise on error).
    - It commits only a transaction it owns, and keeps only the written records out of
      the buffer.
    - An `RLock` guards `record` / `flush`.
  - **`proxy/session_capture.py`.** `secure_only` is set from https URLs or `Secure`
    cookies (BUG-0098).
- Impact (other components / project):
  - **CORE:** the boundary.
  - **SESS:** capture.
  - **Behaviour changes:**
    - the former framed-body residual is closed;
    - an oversized or unparseable sensitive body is stored as a marker;
    - long-lived or large responses are cut off at the configurable bounds;
    - history `errors` lists contained records.
- Risk: medium. These are proxy data-path changes. The proxy suites pass, and bounds
  and containment are tested.
- Deliverables:
  - [x] framed-body redaction — done
  - [x] bounded reads + thread offload + CLI options — done
  - [x] atomic flush — done
  - [x] tests: `test_proxy_upstream_and_flush` (new), `test_proxy_redaction` (the
        residual test replaced), `test_storage_redaction` — done
  - [x] FR-PROXY-11 amended, FR-PROXY-12 added — done
- Implementation divergence: none.
- Review: the review-9 draft (all 13 findings reproduced first on `1619932`) went v1 → v4 through both reviewers. A: 2 must-fix, 6 should-fix and 4 nits on v1, then 1 must-fix and 1 nit on v2. B: 2 must-fix, 7 should-fix and 5 nits on v1, then 1 must-fix on v2, and S9 on v3. AGREED 3/3 on v3. S9, a narrowing, was adopted as v4 with A's confirmation.
- Effectiveness (assessed 2026-10-13): effective offline. All 13 findings were reproduced on `1619932` (`scratchpad/ext2/f01..f13`). Each now has a test that fails there (or cannot import there, its repro script showing the old behaviour), and the repros show the fixed behaviour on the new tree. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 47 mutants across the 13 fixes. 45 were killed on the first pass. The 2 survivors each showed a test gap, and both gaps were closed: the in-scope path of the event-loop test, and the thread lock without `fcntl`. Result: 47/47. Full non-labgen suite (150 files, `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 2003 passed, 13 skipped, 2 xfailed. The 1 error was `test_no_ml`'s real build, which builds from git-tracked files; it passes once the new files are staged (the no-ML and packaging files: 17 passed, 1 known environmental skip). The two gap-closing test files, re-run after the suite: 55 passed. The labgen half was not re-run, since no labgen code changed.

### CC-PROXY-0020 — Whole-subtree JSON redaction (BUG-0090); CA key never silently replaced, pair checked, atomic leaf writes (BUG-0096) (2026-10-13)
- Change:
  - **Redaction (BUG-0090).** `proxy.redact._redact_json` replaces a sensitive key's
    **whole value**, whatever its type (scalar, list, object or nested). It no longer
    recurses into a sensitive container. Plural names are sensitive through
    `core.redaction` (CC-CORE-0035).
  - **CA (BUG-0096).**
    - `ensure_ca` creates the CA key with `core.secretfile.create_secret` (`O_EXCL`), so
      a trust root is never silently replaced. It is written key first, then the cert,
      atomically.
    - On load the key must match the certificate (SPKI comparison), and a half CA (one
      file without the other) is refused. Both raise the new `CAError`, naming the fix.
    - `leaf_cert_files` writes the key, then the cert, each with `replace_secret`
      (complete, atomic, 0600).
- Impact (other components / project):
  - **CORE** (CC-CORE-0035): `create_secret`, `replace_secret`, the plural fold.
  - **Behaviour change, listed:** a JSON container under a sensitive key is now stored
    as the placeholder string, and its shape is not kept. A store whose CA directory
    holds only one of the two files, or a mismatched pair, now stops with `CAError`
    instead of re-minting the CA silently.
  - Leaf certs are now 0600 (they were umask-default). They are only read by the proxy
    itself.
- Risk: low to medium. These are safety controls, with hostile and benign fixtures. A
  user-visible stop on a broken CA is intended (re-trusting a new root is a deliberate
  act).
- Deliverables:
  - [x] whole-subtree JSON redaction — done
  - [x] CA `O_EXCL` key, pair check, half-CA refusal — done
  - [x] atomic leaf writes — done
  - [x] tests: `test_proxy_redaction` (name forms × value shapes through
        `HistoryWriter`), `test_secretfile` (CA and leaf cases) — done
  - [x] FR-PROXY-10 / FR-PROXY-11 amended — done
- Implementation divergence: the draft's "a mismatched leaf pair is re-minted on load".
  Leaves are never loaded from disk: they are rewritten from the in-memory pair on
  every use, and `ssl.load_cert_chain` refuses a mismatch itself. Stated in BUG-0096
  rather than built as dead code.
  - **Reviewed:** taken back to both reviewers under PA-0093(2), and AGREED 3/3.
  - **Cross-process residual (both reviewers' nit).** Two proxies sharing one `ca_dir`
    (the web panel's in-process proxy and `fuzzlab proxy`) each mint their own leaf
    for a host. The two files are replaced one at a time, so one process can load
    the other's key. `load_cert_chain` then raises, and per-connection containment
    closes that connection: a handshake failure, never a wrong certificate. A
    re-mint would not fix it; per-process leaf names would, if it ever matters.
  - **Pinned by** `test_a_corrupted_leaf_on_disk_heals_on_the_next_use`.
- Review: the review-8 draft (all seven findings reproduced first) went v1 → v4 through both reviewers. v1→v2: B, 4 should-fix + 4 nits. v2→v3: A, 1 must-fix + 4 should-fix + 3 nits. v3→v4: A and B, the same must-fix (an implied holdout for every trainer). v4 was AGREED 3/3, and the final optional nits (A: store-wide trains skip, not refuse, an unknown target; B: the prioritizer raises, never returns None) were adopted.
- Effectiveness (assessed 2026-10-13): effective offline. Every finding's reproduction is now a test that fails on `5eb4be9` (counts in each bug doc). Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 38 mutants across the seven fixes, 35 killed on the first pass. The 3 survivors each showed a test gap (the plural fold of `pass`, the loader boundary's `OverflowError` catch, the discovery-hop https floor), and each gap was closed with a new test, after which 3/3 were killed (38/38). Full non-labgen suite (145 files, `FUZZLAB_REQUIRE_BROWSER=1`): 1869 passed, 13 skipped, 2 xfailed, 0 failed. The review-8 test files, re-run after the gap tests: 327 passed, and `test_secretfile` 13/13 with the reviewers' self-healing test. The labgen half was not re-run, since no labgen code changed.

### CC-PROXY-0019 — CA leaf hardening (BUG-0079); loopback-only bind (BUG-0080); persisted-copy redaction (BUG-0084); rule validation and per-connection containment (BUG-0085); one scope decision and IPv6 authorities (BUG-0086) (2026-10-13)
- Change:
  - **CA (BUG-0079).**
    - `ca.leaf_host` validates a CONNECT host: an IP literal, or an IDNA, lower-cased
      hostname of `[a-z0-9_-]` labels, at most 253 characters.
    - IPv6 leaf files are named `ip6-<hex>`.
    - A path backstop keeps every leaf directly in `leaves/`.
    - Keys go through `core.secretfile.write_secret` (0600 from creation,
      `O_NOFOLLOW`), and the directories are `0700`.
  - **Loopback (BUG-0080).** The proxy CLI exits 2 on a non-loopback `--host`, and
    `AsyncProxyServer.start` refuses one too (`core.net.require_loopback`).
  - **Redaction (BUG-0084).**
    - `proxy.redact` covers sensitively named headers; query parameters of the request
      target and of `Location` / `Content-Location` / `Refresh`; and form / JSON / multipart
      request **and** response bodies.
    - Matching is by name token (`core.redaction`).
    - JSON is re-serialised only on a hit, and Content-Length is recomputed when it was
      consistent.
    - Chunked or compressed bodies are stored as received (a stated residual).
    - `HistoryWriter` also redacts `flow.url` and the separately stored bodies.
  - **Rules and containment (BUG-0085).** `MatchReplaceRule` and `ScopeRule` validate
    at creation (latin-1 encodability, regex compilation). `_on_client` contains any
    exception: `502` if nothing was written yet, else close; the CONNECT path never
    writes a 502 into the tunnel. Errors are kept on `AsyncProxyServer.errors`.
  - **Scope and IPv6 (BUG-0086).**
    - New `proxy/authority.py`: `split_authority` / `join_authority`.
    - The engine decides scope once, on the authority.
    - `_host_matches` parses both the pattern and the host.
    - Used by `parse_connect`, `target_from_request`, `_authority` and the CA.
- Impact (other components / project):
  - **CORE** (CC-CORE-0034): `core.net`, `core.redaction`, `core.secretfile`.
  - **UI** (CC-UI-0049): API 400s, the in-process proxy gate, `create_from_flow`
    IPv6.
  - **Trade-off, stated:** Repeater tabs seeded from history carry placeholders.
    Replaying JWT / session / CSRF flows needs a fresh capture or
    `redact_secrets=False`.
  - Underscore hostnames are allowed; anything outside the grammar is refused.
- Risk: medium. These are safety controls. Each one is tested against hostile input,
  and the benign paths (byte-identical messages, valid hosts, valid rules) are tested
  too.
- Deliverables:
  - [x] CA hardening — done
  - [x] loopback gate — done
  - [x] redaction — done
  - [x] rule validation and containment — done
  - [x] authority parser and single scope decision — done
  - [x] tests: `test_proxy_ca_hardening`, `test_loopback_listeners`,
        `test_proxy_redaction`, `test_proxy_rules_and_scope` — done
  - [x] FR-PROXY-10 / FR-PROXY-11 added; FR-PROXY-5 amended — done
- Implementation divergence:
  - The draft's "refuse underscore" is superseded by A's nit: `_` is allowed.
  - WebSocket and h2 are not in the server's connection loop, so their containment is
    noted in BUG-0085's sweep rather than coded.
- Review: the review-7 draft v1 got AGREE-with-changes from both reviewers (A: 2 must-fix, 7 should-fix, 3 nits; B: 6 should-fix, 4 nits), all adopted; v2 was agreed 3/3, with the final nits adopted.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Mutation check** (a copy of the worktree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **40 of 40** review-7 mutants killed. Six first survivors were killed after adding tests for: the leaf cache refusing directly; 0600 with `chmod` disabled; the path backstop alone; a same-origin 307; a line-comment-split `INSERT … INTO`; a JS string open at a newline.
  - **Suites:** **non-labgen suite** (143 files, real browser and lint required; ): **1730 passed, 13 skipped, 2 xfailed, 0 failed**. The live multitarget category-3 / category-4 runs pass with no concurrent load. Packaging / no-ML / contract writers / lint: 22 passed, 1 skipped (the wheel, the known Debian setuptools issue). The labgen suites are untouched by this batch; the last full run (review 6) failed only the 33 known environmental tests (no scipy, scikit-learn or gitleaks).

### CC-PROXY-0018 — Incidental: Proxy workbench UI rebuild on a shared message editor (lane U3) (2026-09-22)
- Change: lane U3 rebuilt the web control panel's Proxy section UI on a shared
  `<message-editor>` component and resizable panes (see `CC-UI-0030` for the
  full detail — this is the PROXY-side bookkeeping entry, per this lane's
  dual reservation). **No PROXY-component code changed**: `fuzzlab/proxy/*`
  (engine, interceptor, repeater, scope, match-replace, history) and
  `fuzzlab/web/proxycontrol.py` / `fuzzlab/web/proxyview.py` (the read/write
  surfaces the UI calls) are all untouched. This entry exists to record that
  PROXY-facing UI effect, the same pattern `CC-UI-0027`/`CC-PROXY-0017` used
  for D0a's cross-component UI note.
- Impact (other components / project): none on PROXY's own behavior or data
  contracts (`flow`/repeater-tab schema, scope/match-replace semantics,
  intercept hold/forward/drop) — purely a client-side re-lay of how those
  existing `/api/proxy/*` routes are displayed and edited. `RepeaterController`
  (`CC-PROXY-0016`, BUG-0021's per-thread SQLite fix) is unmodified. The
  `--authorized` gate on Repeater sends, and the "not running in-process"
  fallback messaging for Intercept/Repeater/Scope, are unchanged — proxy/
  desync tooling's default-off, lab-only posture (CLAUDE.md Safety) is not
  affected.
- Risk (level; mitigation): low — no PROXY code path changed; the only risk
  surface is the UI's byte-exact round-trip through the new editor, mitigated
  as described under `CC-UI-0030` (unchanged `toWire()` CRLF-restore path,
  `getBytes()` reading only the plain-textarea source of truth, existing
  Repeater/Intercept/History test suites re-run unmodified).
- Deliverables:
  - [x] Confirmed no `fuzzlab/proxy/*` or `fuzzlab/web/proxycontrol.py` /
    `fuzzlab/web/proxyview.py` changes were needed or made — done.
  - [x] Confirmed the existing proxy/repeater/intercept test suites
    (`tests/test_proxy_*.py`, `tests/test_web_intercept.py`,
    `tests/test_web_repeater*.py`, `tests/test_web_proxy_history.py`,
    `tests/test_web_scope.py`) pass unmodified against the new UI — see
    `CC-UI-0030`'s Effectiveness for the run's pass/skip counts.
- Effectiveness (assessed 2026-09-22): effective — the PROXY backend and its
  contract are provably untouched (no diff under `fuzzlab/proxy/` or the
  proxy control/view modules), and its test suites pass unmodified against
  the rebuilt UI.

### CC-PROXY-0017 — `--dry-run` CLI flag (lane D0a) (2026-09-22)
- Change: `fuzzlab/proxy/cli.py::build_parser()` gained `--dry-run` (via the shared
  `fuzzlab/cli_dryrun.add_dry_run_flag()`). `main()` checks `args.dry_run` first —
  before `LocalCA` is constructed, before the `--export-ca` branch, and before the
  `--authorized` gate — and calls `fuzzlab/cli_dryrun.report("proxy", args)`, reusing
  the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015), then returns 0. No listener is started, no
  CA file is written, and no upstream traffic is sent. `--dry-run` takes priority
  over `--export-ca` (both send no traffic, but `--export-ca` still writes files;
  `--dry-run` performs neither). Unchanged when `--dry-run` is absent.
- Impact (other components / project): PROXY only, plus an incidental UI effect —
  see CC-UI-0027 (introspected `build_parser()` surfaces the new checkbox in the web
  launcher automatically; `fuzzlab/web/app.py` untouched). No schema/store change.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect (including the `--export-ca` file write). Mitigated by
  `tests/test_cli_dry_run.py` (proxy case: flag present, report printed, `LocalCA`/
  `SocketSender`/`asyncio.run` patched to raise if called) and the unchanged full
  suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `proxy`'s parser — done.
  - [x] Short-circuit ahead of `LocalCA`/`--export-ca`/`--authorized` in `main()`,
    calling the shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab proxy --dry-run` prints
  the planned argv/command and returns 0 without creating a CA, opening a listener,
  or sending any traffic; verified directly and via the new tests.

### CC-PROXY-0016 — Fix (BUG-0021): `RepeaterController` per-thread SQLite connection (2026-09-21)
- Change: `fuzzlab/web/proxycontrol.py::RepeaterController` no longer caches one shared
  `Store`/`Repeater` on `self`. It now keeps them per calling OS thread
  (`threading.local()`), created lazily on that thread's first write, while a single
  `repeater` run row (`self._run_id`) is created once under a lock and shared by every
  thread's `Repeater` so tabs from any thread still appear together. `list_tabs()` and
  `create_from_flow()` use a new `_thread_store()` helper in place of the old shared
  `self._store` for their "open a throwaway connection when nothing persistent exists
  yet" read path.
- Impact (other components / project): fixes an intermittent
  `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that
  same thread` in `tests/test_web_repeater.py`'s route tests (found incidentally by
  another lane; see `ERROR_LOG.md` 2026-09-21 and `docs/bugs/BUG-0021-*`). No change to
  `Repeater`/`HistoryWriter`/`Store` themselves, to any HTTP route contract, or to
  `ProxyController` (the in-process proxy-engine controller, which remains correctly
  single-threaded by construction — its cached `self._store` is safe and unchanged).
- Risk (level; mitigation): low — internal correctness fix, no interface/schema change.
  Mitigated by: reproduced the race directly (a thread-churn stress harness driving the
  same route-handler path showed ~50-75% failure rates across 300-400 iterations before
  the fix; 0 failures across 600+ iterations after); `tests/test_web_repeater.py` (5
  tests) still green; full suite green (642 passed / 5 skipped across repeated runs; the
  2 `test_mutation_operators.py` failures are pre-existing and unrelated).
- Deliverables:
  - [x] Per-thread `Store`/`Repeater` in `RepeaterController` (`threading.local()`) — done.
  - [x] Shared `run_id` across threads under a lock — done.
  - [x] `list_tabs()`/`create_from_flow()` updated to the per-thread store helper — done.
  - [x] Stress-reproduced pre-fix, verified fixed post-fix; full suite re-run — done.
- Effectiveness (assessed 2026-09-21): effective — the same stress harness that
  reliably reproduced the cross-thread error pre-fix shows zero failures post-fix across
  600+ iterations, and the full suite is stable across repeated runs.

### CC-PROXY-0015 — Optional response interception (engine hook + Interceptor flag) (2026-09-21)
- Change: `ProxyEngine.handle_request` now runs an **awaited response-intercept hook** after
  the byte-exact forward: if the interceptor opts in, the response is wrapped as a
  `RawMessage`, held for a forward/edit/drop decision, and its `.raw` returned (a dropped
  response sends nothing). `Interceptor` gained `intercept_responses` (default **off**) and
  `set_intercept_responses(on)` (turning it off releases any held responses). The engine
  gates the hook on that flag, so the default path is unchanged and **byte-exact** (the
  wrap + `.raw` round-trips the exact bytes); request interception is unchanged.
- Impact (other components / project): completes the Burp-style intercept model — requests
  were already pausable; responses are now optionally pausable/editable — which the Phase-2.2
  web Intercept UI drives (CC-UI-0017). No schema change; no change to the record/forward
  path when response interception is off.
- Risk (level; mitigation): low — additive and gated. Mitigated by
  `tests/test_proxy_response_intercept.py` (request edit/forward, request drop sends
  nothing, response NOT held by default incl. byte-exact passthrough, response edit, response
  drop) and `tests/test_proxy_intercept_live.py` (a real request through `AsyncProxyServer`
  is paused, edited, forwarded, and reaches a threaded upstream with the edit). Existing
  proxy intercept/server/live suites still pass. Suite 484 passed / 6 skipped.
- Deliverables:
  - [x] Gated response hook in `ProxyEngine`; `Interceptor.intercept_responses` + setter — done.
  - [x] Engine + over-socket integration tests — done.
- Effectiveness (assessed 2026-09-21): effective — responses can be held/edited/dropped when
  enabled, and the default request-only path stays byte-exact; verified over real sockets.

### CC-PROXY-0014 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/proxy/cli.py` now factors its argparse setup into `build_parser()`;
  `main()` keeps the `p` reference (so `p.error(...)` on `--export-ca`/`--authorized` still
  works) and delegates parsing. Behavior-preserving — same flags, defaults, and gates.
- Impact: lets the web launcher introspect the proxy's flags (CC-UI-0011). Independent of
  the Phase-2 proxy-workbench wiring. No CLI behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `main()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds the proxy's spec
  from this parser.

### CC-PROXY-0013 — Fix (BUG-0012): proxy_e2e.sh self-test uses conflicting Content-Length (2026-09-21)
- Change: `scripts/proxy_e2e.sh` step 5 now sends **conflicting** Content-Length values
  (`0` and `5`) instead of two identical `0`s. Duplicate-*identical* Content-Length is
  valid per RFC 7230 (h11 accepts it), so the old assertion (`is_valid_request` is False)
  produced a false FAIL even though the proxy forwarded byte-exact correctly. Runbook
  Part I.4 clarified to use conflicting values.
- Impact (other components / project): the Part I exit self-test now matches the validated
  offline unit test (which already used 5/6) and passes on-host. No product-code change —
  the proxy's raw byte-exact forwarding was already correct.
- Risk (level; mitigation): low — test/script-only. The offline
  `test_async_server_forwards_duplicate_content_length_byte_exact` already covers the
  correct (conflicting) case. Suite 415 passed / 6 skipped.
- Deliverables:
  - [x] Conflicting-CL request in `proxy_e2e.sh`; runbook wording — done.
  - [x] RCA `docs/bugs/BUG-0012-*`; rule PA-0013; ERROR_LOG — done.
- Effectiveness (assessed 2026-09-21): the on-host Part I run's exit check now reflects the
  true HTTP contract (only conflicting CL is rejected) and passes.

### CC-PROXY-0012 — Fix (BUG-0010/BUG-0011): leaf-cert AKI/SKI + bounded async shutdown (2026-09-21)
- Change: fixed two on-host proxy defects found running Part I. (BUG-0010) `LocalCA` now
  mints certs strict verifiers accept — CA with SKI + keyCertSign KeyUsage; leaf with SKI,
  an AKI referencing the CA, serverAuth EKU, a leaf KeyUsage, and an IPAddress SAN for IP
  hosts; dropped deprecated `datetime.utcnow()`. (BUG-0011) `AsyncProxyServer` tracks and
  cancels its per-connection tasks and bounds `wait_closed()` with a 3s timeout so stop()
  can't hang on live connections (a Python 3.12+ behavior); the proxy CLI persists flow
  history per-record (`batch_size=1`, WAL) and `scripts/proxy_e2e.sh` bounds its shutdown
  with a `-KILL` fallback.
- Impact (other components / project): HTTPS interception now actually works on-host (the
  minted leaf verifies and a browser will trust it), and `fuzzlab proxy` /
  `scripts/proxy_e2e.sh` exit cleanly instead of hanging. No interface change; the flow
  store is written incrementally now (WAL-safe concurrent reads).
- Risk (level; mitigation): low — additive cert extensions + a more careful teardown.
  Mitigated by a skip-guarded extension-assertion test (leaf AKI matches CA SKI, serverAuth
  EKU, IP SAN) plus the existing on-host tunnel test that reproduced BUG-0010 and now
  passes; the offline connection tests still pass with the new stop(). Suite 415 passed /
  6 skipped.
- Deliverables:
  - [x] SKI/AKI/EKU/KeyUsage + IP SAN in `LocalCA`; non-deprecated UTC (BUG-0010) — done.
  - [x] Tracked+cancelled conns and bounded `wait_closed()`; per-record history; bounded
        script shutdown (BUG-0011) — done.
  - [x] RCAs `docs/bugs/BUG-0010-*`, `BUG-0011-*`; PA-0011/PA-0012; ERROR_LOG — done.
- Effectiveness (assessed 2026-09-21): offline suite green; the on-host CONNECT/TLS tunnel
  test that failed with "Missing Authority Key Identifier" now has the extensions it needs,
  and shutdown is bounded so the Part I script can no longer hang.

### CC-PROXY-0011 — Live h2c socket transport for the raw HTTP/2 client (Phase 9 on-host, T9.x) (2026-09-21)
- Change: built the Phase 9 on-host last mile so runbook Part K is a one-command flow. New
  `fuzzlab/proxy/h2transport.py::H2Transport` is the socket send/receive around the
  already-built `H2RawClient`/`h2frames`/`hpack`: `request(...)` opens a plaintext TCP
  socket to an h2c (prior-knowledge) endpoint, sends preface+SETTINGS+HEADERS, ACKs the
  server SETTINGS, reads to END_STREAM, and decodes an `H2Response` (`:status` when
  static-indexed; reassembled DATA body); `send_raw(...)` writes exactly the bytes from
  `build_raw(...)` for malformed/length-desync/CRLF-in-header primitives. Orchestration
  `scripts/h2_desync_e2e.sh`.
- Impact (other components / project): the from-scratch HTTP/2 client can now talk to the
  lab's opt-in h2→h1 downgrade front-end over a real socket — no TLS/ALPN/Upgrade needed
  (nginx `http2 on;` prior knowledge). Depends on the LAB desync profile (CC-LAB-0010 adds
  `PFF_PROFILE` to `labctl.sh`). No change to the byte-building modules. Dual-use protocol
  tooling; loopback + opt-in profile only.
- Risk (level; mitigation): low–medium — a real socket to a smuggling research target.
  Mitigated by: loopback-only, the front-end being opt-in (`desync` profile, default off),
  the transport reading with bounded timeouts, and tests (`tests/test_proxy_h2_transport.py`)
  that exercise the real socket path against a one-shot loopback server: a normal request
  decodes `:status`/body, `send_raw` puts a length-desync frame on the wire byte-exact, and
  a CRLF-in-header value is carried verbatim. The desync exit is framed as emitting the
  primitive (a patched nginx correctly rejects it), not a successful smuggle. Suite 411
  passed / 5 skipped.
- Deliverables:
  - [x] `H2Transport.request` / `send_raw` (live h2c socket) + tests — done.
  - [x] `scripts/h2_desync_e2e.sh`; runbook Part K rewritten to one command — done.
  - [ ] Live smuggle against a deliberately-mishandling front-end — out of scope (nginx is patched).
- Effectiveness (assessed 2026-09-21): effective offline — the transport round-trips a real
  h2 response and emits both desync primitives byte-exact over a socket. The live front-end
  exchange is driven by `scripts/h2_desync_e2e.sh`.

### CC-PROXY-0010 — Live upstream SocketSender + CONNECT/TLS termination + `fuzzlab proxy` CLI (Phase 6 on-host, T6.x) (2026-09-21)
- Change: built the Phase 6 on-host last mile so runbook Part I is a one-command flow.
  New `fuzzlab/proxy/socketsender.py::SocketSender` is a real upstream `Sender`
  (`(host,port,use_tls,raw)->bytes`): TCP/TLS-connect, send byte-exact, read the whole
  HTTP/1 response (Content-Length / chunked / close-delimited). `AsyncProxyServer` gained
  a `ca` param and a `_handle_connect` that replies `200 Connection Established`,
  TLS-terminates the client with a CA-minted per-host leaf (new
  `LocalCA.leaf_cert_files` materializes the leaf to 0600 files; server-side upgrade via
  `loop.start_tls`), and forwards tunnelled requests through the same engine to the HTTPS
  upstream; without a CA, CONNECT still answers 501. New `fuzzlab/proxy/cli.py`
  (`fuzzlab proxy`, dispatched in `cli.py`): `--export-ca` (no `--authorized`; sends
  nothing) and the run path (requires `--authorized`), with scope/store/ca-dir flags.
  Orchestration `scripts/proxy_e2e.sh`.
- Impact (other components / project): the proxy can now intercept live traffic against
  the lab and record flows to the store; HTTPS interception works once the CA is trusted.
  Reuses the existing sans-I/O engine/repeater seam unchanged (the sender is injected), so
  no change to match-replace/history/scope/intercept. Per D5 the proxy stays optional and
  out of the timing path. Depends on `cryptography` on-host for minting + the handshake.
- Risk (level; mitigation): medium — real sockets + a server-side `loop.start_tls`
  upgrade (an internal-ish streams idiom) and MITM TLS. Mitigated by: byte-exact
  forwarding (no reserialization), full upstream TLS verification by default
  (`--no-verify-tls` opt-in for self-signed lab origins), the CA key staying 0600 and
  never distributed, `--authorized` gating the run, loopback defaults, and tests —
  `tests/test_proxy_live.py`: SocketSender Content-Length + close-delimited reads, the
  byte-exact duplicate-Content-Length forward through the async server (parsed path
  rejects it), and a skip-guarded on-host CONNECT+TLS tunnel that forwards byte-exact.
  Suite 408 passed / 5 skipped.
- Deliverables:
  - [x] `SocketSender` (real upstream, byte-exact) + tests — done.
  - [x] CONNECT/TLS termination in `AsyncProxyServer` + `LocalCA.leaf_cert_files` — done.
  - [x] `fuzzlab proxy` CLI (+ `--export-ca`) and dispatch — done.
  - [x] `scripts/proxy_e2e.sh`; runbook Part I rewritten to one command — done.
  - [ ] Live browser-trust + HTTPS interception walk-through — on-host (script prints steps).
- Effectiveness (assessed 2026-09-21): effective offline — the real sender round-trips and
  the duplicate-Content-Length request forwards byte-exact while the parsed path rejects
  it. The CONNECT+TLS tunnel and CA minting are covered by skip-guarded tests that run
  on-host, and `scripts/proxy_e2e.sh` drives the live lab exit.

### CC-PROXY-0009 — HTTP/2 frames + minimal HPACK + raw-frame client (T9.2/T9.3) (2026-09-21)
- Change: from-scratch, byte-exact HTTP/2 for the raw path. `fuzzlab/proxy/h2frames.py`
  encodes/decodes the frame types (DATA/HEADERS/SETTINGS/WINDOW_UPDATE/RST_STREAM/PING/
  GOAWAY/…), the connection preface, and lets the caller **override the declared length**
  independent of the payload (a length-desync primitive). `fuzzlab/proxy/hpack.py` is a
  minimal HPACK (integer/string primitives, the static table, literal representations,
  decode of static-indexed + literal; dynamic table + Huffman-encode out of scope) that
  passes **arbitrary header bytes** through unchanged. `fuzzlab/proxy/h2client.py::H2RawClient`
  assembles a request (preface → SETTINGS → HEADERS → optional DATA) and, via `build_raw`,
  arbitrary/malformed frame sequences — the desync/smuggling tool for the **self-owned
  lab** (the T9.5 h2→h1 front-end). Dependency-light; the parsed `h2` path is declared +
  skip-guarded (on-host).
- Impact (other components / project): realizes the HTTP/2 half of protocol depth — raw
  frame construction with arbitrary bytes for authorized desync research, offline-testable.
  The live socket + TLS + ALPN override and sending to a real h2 endpoint are on-host
  (T9.4/T9.6). Lab-only posture unchanged; no store change.
- Risk (level; mitigation): medium (dual-use tooling) — mitigated structurally by scope
  enforcement, loopback/lab-only, no-auto-run, and the target being infrastructure we run
  ourselves; the raw client only *builds bytes* here (no network). Correctness mitigated
  by 13 tests (`tests/test_proxy_h2.py`): HPACK integer RFC vectors, header round-trip
  incl. arbitrary CRLF, static-indexed decode, Huffman-decode raises; frame round-trip +
  flags, the length-override desync primitive, all builders, multi/partial-tail decode,
  truncation errors; client request structure, body DATA frame + odd/incrementing stream
  ids, arbitrary-header passthrough, and arbitrary-frame `build_raw`. Suite 341 passed / 4 skipped.
- Deliverables:
  - [x] HTTP/2 frame layer (T9.2) — done.
  - [x] Minimal HPACK (T9.2) — done.
  - [x] HTTP/2 raw-frame client (T9.3, offline builder) — done.
  - [ ] Parsed `wsproto`/`h2` path (T9.4); lab h2→h1 front-end (T9.5); exit (T9.6) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — HPACK matches the RFC integer
  vectors and preserves arbitrary bytes, frames round-trip byte-exact with a working
  length-desync primitive, and the client builds valid and deliberately-malformed requests;
  live ALPN/socket + the desync exit are on-host.

### CC-PROXY-0008 — WebSocket framing + flow.protocol (Phase 9 T9.1) (2026-09-21)
- Change: began protocol depth. `fuzzlab/proxy/ws.py` is a from-scratch, byte-exact RFC
  6455 WebSocket frame codec — `encode_frame`/`decode_frame`/`decode_frames` (FIN/RSV/
  opcode, MASK, 7/16/64-bit lengths, masking key), `apply_mask` (self-inverse),
  `reassemble` (fragmented data frames → messages), control-frame handling, and the
  handshake (`accept_key`, `is_upgrade_request`/`is_upgrade_response`) reusing the
  HTTP/1.1 machinery. The Phase 6 history now tags each flow's protocol: `FlowRecord`
  gains `protocol` (default `http/1.1`) and the writer persists it (migration 9's
  `flow.protocol`). Dependency-light (stdlib); the `wsproto` parsed path is declared and
  skip-guarded (on-host).
- Impact (other components / project): the raw WebSocket path — inspect/edit/replay
  frames (including masked/malformed) without a library normalizing them — recorded and
  searchable in the existing history and replayable via the existing repeater (encoded
  frames are raw bytes). Sets up HTTP/2 (T9.2/T9.3) and the parsed-path integration
  (T9.4). No behavior change to HTTP/1.1 flows (protocol defaults to `http/1.1`).
- Risk (level; mitigation): low — pure, dependency-light byte logic; optional (D5).
  Mitigated by 11 tests (`tests/test_proxy_ws.py`): migration-9 schema; the RFC handshake
  vector; upgrade detection; byte-exact unmasked frame; masking hides payload + round-trips
  + self-inverse; 16/64-bit lengths; control frames; fragmentation reassembly; multi-frame
  + partial-tail decode; truncated-frame errors; history records the protocol tag. Suite
  328 passed / 4 skipped.
- Deliverables:
  - [x] WebSocket frame codec + handshake + history protocol tag (T9.1) — done.
  - [ ] HTTP/2 frames + HPACK (T9.2); raw-frame client (T9.3); parsed-path wsproto/h2
        (T9.4); lab downgrade front-end (T9.5); exit (T9.6) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — frames round-trip byte-exact
  (masked and unmasked), the handshake matches the RFC vector, and flows carry a protocol
  tag; live WS interception through the running proxy is on-host.

### CC-PROXY-0007 — Local CA, flow engine, and async server wiring (T6.6) (2026-09-21)
- Change: tied the proxy together. `fuzzlab/proxy/server.py::ProxyEngine` is the
  **sans-I/O** flow pipeline — scope check → match-and-replace → interception →
  byte-exact forward (via an injected upstream sender seam) → history — where
  FR-PROXY-1/3/5/6 meet; out-of-scope traffic is forwarded untouched and unrecorded.
  `parse_connect`/`target_from_request` handle CONNECT and rewrite absolute-form
  requests to origin-form. `AsyncProxyServer` is the asyncio socket layer; its
  **plain-HTTP** path is exercised offline over loopback. `fuzzlab/proxy/ca.py::LocalCA`
  is the local CA (FR-PROXY-2) with a per-host **leaf-cert cache** behind an injectable
  minter seam; the real X.509 minting is lazy `cryptography` (on-host).
- Impact (other components / project): completes the offline-buildable proxy stack — the
  engine, CONNECT/target parsing, the async plumbing, and the CA cache are all in place
  and tested. The **live last mile** is on-host: CONNECT + TLS socket serving and
  browser trust of the CA (the sandbox has no working `cryptography`/TLS), tracked in
  `docs/ON_HOST_TASKS.md`. Optional per D5; timing traffic bypasses it.
- Risk (level; mitigation): low offline (seam-isolated, pure pipeline); the security-
  sensitive TLS MITM is on-host with a local-only CA, scope enforcement, and redaction.
  Mitigated by 12 tests (`tests/test_proxy_server.py`, 1 skipped for broken sandbox
  crypto): CONNECT + absolute/origin/https target parsing; leaf-cache mints once per
  hostname (port-independent) + a skip-guarded real-minting test; engine forwards +
  records in scope, bypasses out-of-scope untouched/unrecorded, applies match-replace,
  and drops/edits via the interceptor; and the async server round-trips a plain-HTTP
  request over loopback (absolute→origin rewrite) and returns 501 for CONNECT offline.
  Suite 248 passed / 3 skipped.
- Deliverables:
  - [x] `ProxyEngine` sans-I/O pipeline (scope/match-replace/intercept/forward/log) — done.
  - [x] `parse_connect` + `target_from_request` (absolute↔origin) — done.
  - [x] `AsyncProxyServer` plain-HTTP path (offline loopback) — done.
  - [x] `LocalCA` leaf-cert cache + lazy `cryptography` minting — done.
  - [ ] Live CONNECT + TLS serving + browser trust of the CA — on-host.
  - [ ] Exit: browse the lab, hand-edit a duplicate `Content-Length`, see exact bytes — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the engine enforces scope,
  forwards byte-exact, intercepts, and records; the CA caches leaves per host; the async
  server round-trips plain HTTP. The live TLS browse-and-edit exit is on-host.

### CC-PROXY-0006 — Manual-login session capture + manager adoption (T6.5) (2026-09-21)
- Change: implemented FR-PROXY-9. `fuzzlab/proxy/session_capture.py::SessionCapture`
  watches the flows of a **manual browser login** through the proxy
  (`observe_request`/`observe_response`), accumulates the established cookies (from
  Set-Cookie and the browser's Cookie header) and any bearer token (with JWT `exp`,
  reusing `session/detect.py`), and builds a `SessionState`; `adopt_into(manager)` hands
  it to the session manager. Added `SessionManager.adopt(state)` (FR-SESS-11): marks the
  session valid, brings its host into scope, caches it for `prepare`/`apply`, and
  persists only NON-SECRET metadata. No per-host config file.
- Impact (other components / project): gives the session manager (#3) a way to stay
  authenticated on logins detection can't parse (MFA/CAPTCHA/multi-step/SPA) — the
  escape hatch D13 promised. Secrets live only in memory and are never written to the
  store (the `session_state` table has no secret columns), consistent with the D12
  secret model. Realizes CC-SESS-0004's spec (see CC-SESS-0007).
- Risk (level; mitigation): low — pure observation + in-memory handoff; adoption reuses
  the existing persistence path (non-secret only). Mitigated by 5 tests
  (`tests/test_proxy_session_capture.py`): cookie capture, bearer+exp capture, adoption
  authenticating `prepare` with no login handshake, and non-secret-only persistence.
  Suite 237 passed / 2 skipped.
- Deliverables:
  - [x] `SessionCapture` (cookie/token capture from flows) — done.
  - [x] `SessionManager.adopt` (FR-SESS-11) — done.
  - [ ] Live capture while browsing the lab through the running proxy — on-host (T6.6).
- Effectiveness (assessed 2026-09-21): effective in tests — a captured session
  authenticates the manager without a login handshake and no secret is persisted; the
  live browser capture is on-host.

### CC-PROXY-0005 — Interception (awaited future) + repeater (T6.4) (2026-09-21)
- Change: `fuzzlab/proxy/intercept.py::Interceptor` models interactive interception as
  an `asyncio.Future` (FR-PROXY-6): when enabled, the data path `await`s a per-message
  decision; `pending()`/`forward(id, edited?)`/`drop(id)` release it (edited via
  `RawMessage`), and disabling releases everything unedited — off means transparent
  pass-through (D5). `fuzzlab/proxy/repeater.py::Repeater` (FR-PROXY-4) persists tabs to
  `repeater_tab` (a saved raw request + target) and replays them through an injected
  **sender seam**, sending the exact bytes (raw path) and optionally recording the
  exchange to history.
- Impact (other components / project): the manual-testing surface — hold/edit/release
  and edit/replay — over the byte-exact core. The sender seam keeps it offline-testable
  (fake sender) while the on-host server supplies a real socket sender (T6.6).
- Risk (level; mitigation): low — sans-I/O logic behind seams; optional (D5). Mitigated
  by 9 tests (`tests/test_proxy_intercept.py`): disabled pass-through, forward-with-edit,
  forward-unedited, drop→None, disable-releases-held; tab persistence, byte-exact send,
  edited-raw replay persisting + sending exact bytes, and history recording.
- Deliverables:
  - [x] `Interceptor` awaited-future model (T6.4) — done.
  - [x] `Repeater` DB-persisted tabs + raw-path replay (T6.4) — done.
  - [ ] Wire both into the async server (T6.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — held flows release edited or
  dropped, and the repeater replays byte-exact requests through the seam.

### CC-PROXY-0004 — Flow history: migration 6 + batched writer + FTS5 (T6.3) (2026-09-21)
- Change: added the proxy's shared history. **Migration 6** extends `flow` with a
  `host`, an `in_scope` flag, and byte-exact `req_raw_sha`/`resp_raw_sha` (raw wire
  bytes content-addressed via `body`, like decoded bodies), adds a standalone `flow_fts`
  FTS5 index, and a `repeater_tab` table (registry head → 6).
  `fuzzlab/proxy/history.py::HistoryWriter` buffers `FlowRecord`s and flushes them in
  **one transaction** (batched, non-blocking data path — NFR-PROXY-nonblocking),
  content-addressing raw bytes + bodies, indexing the head text for search, and
  offering `search()` (FTS5, punctuation-safe phrase queries) and byte-exact
  `raw_request`/`raw_response` retrieval. Persisted bytes are **redacted** first
  (`fuzzlab/proxy/redact.py`) so secrets never land in the store or the FTS index
  (NFR-PROXY-safe); the wire path stays byte-exact.
- Impact (other components / project): realizes FR-PROXY-3 — flows land in searchable
  shared history with raw bytes the anomaly detector, UI, and analysis read (D5). Adds
  the store columns/tables the proxy contract needs without touching existing rows
  (append-only migration). `repeater_tab` is the persistence for T6.4's repeater.
- Risk (level; mitigation): low — additive schema, batched writes, redaction on write.
  Mitigated by 7 tests (`tests/test_proxy_history.py`): migration-6 schema; batching
  defers then auto-flushes; byte-exact raw round-trip when no secrets; secret
  redaction (not stored, not searchable); FTS search by url/host/header; content-
  addressed dedup of identical raw. Suite 224 passed / 2 skipped.
- Deliverables:
  - [x] Migration 6 (flow raw bytes + FTS5 + `repeater_tab`) — done.
  - [x] Batched `HistoryWriter` + redaction + FTS search (T6.3) — done.
  - [ ] Interception + repeater (T6.4); session capture (T6.5); CA + server (T6.6) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — flows persist with
  byte-exact raw bytes, secrets are redacted, and history is searchable; the live
  capture-while-browsing path is on-host.

### CC-PROXY-0003 — Dual-path core: message model, parsers, scope, match-and-replace (T6.1/T6.2) (2026-09-21)
- Change: began Phase 6 with the offline-testable heart of the proxy — the **dual
  path** (D4). `fuzzlab/proxy/message.py::RawMessage` is a byte-exact container: it
  round-trips received bytes unchanged, exposes head/body and duplicate-preserving
  header views, and edits by **byte surgery** (`with_appended_header`, `with_header`,
  `without_header`, `with_request_line`, `with_body`) that leave untouched lines
  verbatim (NFR-PROXY-byte-exact). `fuzzlab/proxy/parser.py` is the parsed path over
  `h11` (`parse_request`/`parse_response`/`is_valid_request`) that validates and
  normalizes. `fuzzlab/proxy/scope.py::Scope` is a **default-deny** include/exclude
  engine (host + optional path regex; subdomain-suffix and port-less matching).
  `fuzzlab/proxy/matchreplace.py` applies ordered byte-level rewrites to the
  request/status line, a named header, or the body. Wrote `docs/PHASE_6_PLAN.md`.
- Impact (other components / project): delivers the phase's exit criterion in
  miniature — a hand-edited request with a conflicting duplicate `Content-Length` is
  forwarded byte-for-byte on the raw path while the parsed path rejects the ambiguous
  framing — establishing the byte-exact substrate the history, repeater, interception,
  and session-capture tasks build on. No store change yet (that is T6.3, migration 6).
  `h11` is a declared dependency (already installed); no new runtime dep this task.
- Risk (level; mitigation): low — pure, dependency-light byte logic; the proxy is
  optional (D5) and untouched by the core pipeline. Mitigated by 21 tests
  (`tests/test_proxy_message.py`): byte-exact round-trip, LF-only preservation,
  duplicate-header order, the duplicate-`Content-Length` raw-exact-but-parsed-rejects
  case (+ CL/TE smuggling primitive), all edit helpers, parser happy paths, and the
  scope + match-and-replace engines. Suite 217 passed / 2 skipped.
- Deliverables:
  - [x] `RawMessage` byte-exact model + edits (T6.1) — done.
  - [x] `h11` parsed path (T6.1) — done.
  - [x] Scope engine + match-and-replace (T6.2) — done.
  - [ ] Flow history + migration 6 (T6.3); interception + repeater (T6.4); session
        capture (T6.5); CA + async server wiring (T6.6, live on-host) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — the raw path preserves
  malformed framing the parsed path rejects, which is the crux of the dual-path design;
  the live browse-and-forward exit is on-host.

### CC-PROXY-0002 — Planned: manual-login session capture (spec) (2026-09-21)
- Change: added FR-PROXY-9 — capture the authenticated session (cookies/tokens)
  from a **manual browser login** performed through the proxy and hand it to the
  session manager to adopt (FR-SESS-11). This is the escape hatch for logins the
  session manager's detection can't parse (MFA, CAPTCHA, multi-step, exotic SPA),
  with no per-host config. Spec only — no code (proxy is Phase 6).
- Impact (other components / project): gives the session manager (component #3) a
  way to stay authenticated on hosts detection can't handle; recorded in D13 and
  the Phase 6 roadmap; `ARCHITECTURE.md` #11 updated. No change to the store
  contract beyond the flows the proxy already records.
- Risk (level; mitigation): low (planning). Captured secrets are sensitive;
  mitigated by the proxy's existing redaction-on-write and lab-only/scope rules
  (NFR-PROXY-safe) and by not persisting them in cleartext.
- Deliverables:
  - [x] FR-PROXY-9 recorded — done.
  - [ ] Implement session capture + handoff to the session manager — todo (Phase 6).
- Effectiveness (assessed or pending): pending — built in Phase 6.

### CC-PROXY-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented.
  Decision D4 sets the build-from-scratch hybrid (sans-I/O parsed path + raw byte
  path); decision D5 fixes it as an optional observer on the shared store.
- Impact (other components / project): once built, it writes `flow` rows the
  anomaly detector, UI, and analysis read; it attaches the session manager as an
  addon so manual traffic is authenticated. Because it is optional (D5), no other
  component gains a hard dependency on it, and timing-sensitive fuzzing must be
  able to bypass it. Adds `flow` (+ raw bytes) to the store contract.
- Risk (level; mitigation): medium — a proxy in the data path can distort timing
  and is a security-sensitive component (TLS MITM, stored raw traffic). Mitigated
  by keeping it optional and out of the timing path (D5), a local-only CA, scope
  enforcement, redaction on write, and batched non-blocking history. The raw path
  isolates byte-exact study from the parsed path.
- Risk justification (accepted): building from scratch instead of adopting
  mitmproxy is accepted for the flexibility it buys (D4) — the byte-exact raw path
  and full control over interception — at the cost of more implementation work,
  sequenced after the session manager (Phase 6).
- Deliverables:
  - [ ] Async core; parsed (`h11`/`h2`/`wsproto`) + raw byte paths — todo (Phase 6).
  - [ ] CONNECT + TLS interception (local CA, cached leaf certs) — todo (Phase 6).
  - [ ] History: `flow` rows, FTS5, batched writes, content-addressed bodies — todo (Phase 6).
  - [ ] Repeater (DB-persisted tabs) + match-and-replace + scope engine — todo (Phase 6).
  - [ ] Interception-as-awaited-future workflow — todo (Phase 6).
  - [ ] Session-manager addon integration — todo (Phase 6).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  byte-exact replay, searchable shared history, and zero impact on timing-sensitive
  runs (which bypass it).
