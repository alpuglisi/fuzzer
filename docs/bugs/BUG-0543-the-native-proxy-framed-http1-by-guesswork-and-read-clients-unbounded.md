# BUG-0543 — The native proxy framed HTTP/1 by guesswork and read its clients unbounded

- Date: 2026-10-21
- Status: fixed (CC-PROXY-0028)
- Severity: high. In the lab-only proxy, a chunked upload never reached the lab app, a
  cut response was recorded and relayed as a whole one, and any local client could hold
  every connection, buffer and worker of the proxy.

## Description
The native intercepting proxy (`fuzzlab proxy`, the web UI's in-process proxy) read
HTTP/1 messages by heuristics, not by their framing, on both sides:

- **Requests (audit defect 18).** `server._read_http_message` read the head to the first
  CRLFCRLF and then a body only for a numeric `Content-Length`. A chunked request
  returned at its head: the head (still saying `Transfer-Encoding: chunked`) was
  forwarded with no body, and in the CONNECT/TLS keep-alive loop the unread chunk bytes
  were parsed as the next request. A request with both `Content-Length` and
  `Transfer-Encoding`, an invalid length or a bad chunk size was forwarded anyway.
- **Responses (audit defect 19).** `socketsender._body_complete` took a chunked body as
  complete when it *ended with* `0\r\n\r\n`, so chunk data such as `abc0\r\n\r\n` ended
  it. A trailer section never matched, so a complete response waited for the idle
  timeout. An idle timeout or a close returned whatever had arrived, so a declared
  10-byte body with 3 bytes, or a head cut in two, was returned as a response. There
  was no request method (a HEAD's `Content-Length` was waited for), no 204/304 rule, and
  a `103` head was taken for the response's.
- **Inbound bounds (audit defect 20).** `readexactly(int(Content-Length))` had no body
  cap and no deadline; a head over the stream reader's limit was dropped without an
  answer; nothing capped connections, so `asyncio.to_thread` queued one upstream call
  per connection without bound.

## Where encountered
The external audit (`audit.md`, defects 18-20), reproduced at 08e3eaa with a real
loopback client, the real `AsyncProxyServer`, the real `SocketSender` and a loopback
upstream socket (`tests/test_proxy_framing.py`, run once on the pre-fix code; see
"Corrective action").

## What it caused to fail
- Uploads and streaming request bodies through the proxy (the upstream got a chunked
  head and no body, and answered or hung on it); keep-alive TLS tunnels parsed body
  bytes as requests.
- FR-PROXY-3 / FR-PROXY-13: history and the trace recorded a cut response as a complete
  `200`; the browser got it as one.
- Latency: a response with a trailer, a HEAD, a 204, a 304 or an interim response was
  held to the upstream idle timeout (15 s by default).
- Availability of the local proxy: a client declaring a terabyte, dripping its body or
  opening connections without end held sockets, buffers and the upstream executor's
  queue.

## What the bug was identified to be
No HTTP/1 framing implementation: each reader guessed where a message ended (the first
blank line, a numeric `Content-Length`, a byte suffix, a quiet socket), and the bounds
PA-0102 put on the upstream read were never put on the listener's reads.

## Root cause analysis
Five Whys:
1. *Why was a chunked request forwarded without its body?* The listener's reader knew
   only `Content-Length`; anything else ended at the head.
2. *Why did the response reader end inside a chunk and return cut responses?* It tested
   a suffix and treated a close or an idle receive as the end, because no code parsed
   chunk sizes or knew which responses have no body. Its comment said so: "Good enough
   for lab traffic; the raw bytes are preserved regardless."
3. *Why two different guesses?* Framing had no owner. Each reader was written for its
   path (the listener for the browser's simple requests, the sender for byte-exact
   relay), and the byte-exact raw path (D4) was taken to excuse not parsing framing at
   all, though byte-exact relay needs framing to know where the bytes end.
4. *Why were the listener's reads unbounded after BUG-0101?* BUG-0101's sweep cleared
   `server._read_http_message` as "asyncio readers, with a stated limit": the stream
   reader's head limit was taken for a bound on the whole read. PA-0102(1) ("a network
   read has a byte cap and an overall deadline") was enforced only by tests of the
   upstream sender. BUG-0536 flagged the reader again and left it to this item.
5. *Why did nothing catch it?* Every proxy test fed a `Content-Length` request and a
   `Content-Length` or close-delimited response; none sent a chunked request, a trailer,
   a HEAD or a cut response, and none dripped or flooded the listener.

**Root cause:** the proxy's HTTP/1 reads had no single framing owner, so each reader
guessed where a message ended and a guess passed for completion; and the read bounds
were applied by direction (upstream only), cleared by the presence of a limit rather than
by a test of what it bounds.

## Corrective action
CC-PROXY-0028 (FR-PROXY-401, FR-PROXY-402, FR-PROXY-403):

- **One framing owner, SP-63: `fuzzlab/proxy/framing.py::MessageReader`.** It is
  sans-I/O (`feed` / `eof`) and implements RFC 9112 §6-7. Requests: chunked parsed,
  with trailers; `Transfer-Encoding` with `Content-Length`, a coding other than
  `chunked` alone, an invalid or conflicting `Content-Length`, a bad chunk line and a
  malformed request line are `FramingError`. Responses, given the request's method:
  `Content-Length`, chunked, close-delimited; none for HEAD / 1xx / 204 / 304; interim
  1xx passed over (at most 8). Head and body bounds are checked as bytes arrive
  (`OverLimit`); a close before the framed end is `Incomplete`. Every byte is copied a
  bounded number of times, counted (`copied`).
- **The listener** (`AsyncProxyServer._next_request`) reads each request whole through
  it and forwards a chunked one de-chunked with a `Content-Length` (trailer fields
  dropped). It answers 400 for what cannot be framed, 431 / 413 for a head / body over
  `InboundLimits`, 408 at the per-request deadline, and 503 for a connection over
  `max_connections`. Each closes the connection and is counted (`counts`). Bytes after
  a request are the next request (`_Inbound.leftover`). The TLS loop ends after a
  response that ends its connection. The defaults are SP-60's where one applies (body:
  `MAX_WIRE_BYTES`, deadline: `DEFAULT_SECONDS`). `fuzzlab proxy --max-connections /
  --max-request-bytes / --max-header-bytes / --request-deadline` set them.
- **The explicit raw mode** (`raw_framing`, `--raw-framing`, off by default) keeps D4's
  conflicting-`Content-Length` study: such a request is framed by its first value and
  forwarded byte-exact. `scripts/proxy_e2e.sh` (Part I step 5) runs the proxy in it.
- **The upstream sender** (`recv_http_response`) reads through it with the request's
  method. It returns the final response's exact bytes. It raises `UpstreamIncomplete`
  (`eof`, `idle`, `deadline`, `head`, `wire`) or `UpstreamFramingError`. It never returns
  a short response. A close before any byte is still `b""` (no response). The engine
  records an incomplete flow with no response and its error class, and answers 502.
- **Tests:** `tests/test_proxy_framing.py`, over real loopback sockets (a client, the
  listener, `SocketSender`, an upstream socket), and the SP-63 guard proven on the
  pre-fix shapes. `test_the_body_is_never_recopied_per_chunk` (PA-0102) now reads the
  reader's copy count. `test_async_server_forwards_duplicate_content_length_byte_exact`
  runs the listener in raw mode.
- **Proof on the pre-fix code** (one run: the new test file against 08e3eaa's
  `fuzzlab/`): see CC-PROXY-0028's deliverables for the per-test result.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for read bounds, framing and
"incomplete taken for complete":

- **BUG-0101 / PA-0102** (upstream reads unbounded, quadratic, blocking). The same
  class: a network read without a byte cap or deadline. Its sweep cleared the listener's
  read. **A recurrence.**
- **BUG-0536 / PA-0536** (reads bounded only after the work; one owner for target
  bodies over `requests`). The same class on another transport. It flagged "BUG-0101's
  cleared proxy readers (`proxy/server._read_http_message`, `h2client`, `ws`)" and
  left them to this item. **A recurrence of its root cause** (a bound cleared by
  presence; no owner for the read).
- **BUG-0528 / PA-0528(1)** (an exchange is complete only when its status, headers and
  whole body arrived): the contract runner's form of "a cut response is not a
  response". The proxy's sender is the same rule on a raw socket. **Same root cause,
  another reader.**
- **BUG-0086 / PA-0087** (one policy decision, one parser): authorities had many
  parsers. Framing had two guesses; the same shape for another mechanism.
- **BUG-0012** (the proxy self-test's duplicate-`Content-Length` premise): not a
  recurrence. It sets the Part I property that the explicit raw mode keeps.

## Prior-preventive-action failure analysis
- **PA-0102 (BUG-0101): applied by direction, cleared by presence.** Its rule names
  "a network read", but its sweep judged the listener's read bounded because the stream
  reader had "a stated limit". That limit bounds a head searched with `readuntil`, not a
  `readexactly` body, and not time. Its three enforcing tests all drive the upstream
  sender. Nothing tested the listener against a large or dripping client. PA-0536(2)
  later named this exact failure for `requests` timeouts ("a sweep verdict … cites a
  test against a dripping peer"). It was not re-applied to the proxy readers BUG-0536
  flagged.
- **PA-0536(1): an owner for one transport only.** It made `core.bodyread` the owner of
  bodies read over `requests`. The proxy reads raw sockets and builds its own framing,
  so it stayed outside the owner and its guard (`requests.Session` construction).
- **PA-0528(1): not enforced beyond its reader.** "An exchange is complete only when its
  … whole body arrived" was enforced on the contract runner. The proxy's sender kept
  returning a cut body as a response. No rule said where completeness is decided for a
  raw-socket reader.
- **PA-0087(2): stated for authorities only.** "One parser" was applied to authority
  strings, not to the other wire syntax the proxy parses: message framing.

## Preventive action
**PA-0543.** It strengthens PA-0102(1), PA-0528(1), PA-0536(1)/(2) and PA-0087(2):

1. **A message is complete only at its framed end, decided by one framing owner.** Every
   HTTP/1 read the proxy makes goes through SP-63 (`proxy/framing.py`), for requests and
   responses alike. A close, an idle receive or a byte pattern in the payload never ends
   a message. A read that stops first is typed incomplete (`UpstreamIncomplete`) and is
   never returned, recorded or relayed as a response. A message that cannot be framed
   is refused (400 / 502), never forwarded in part. An AST guard fails on hand framing
   outside the owner (`readuntil` / `readexactly`, a guessed last-chunk literal). It is
   proven on the pre-fix shapes.
2. **A read bound covers both directions and every dimension, enforced while reading.**
   The inbound read has its head, body and time bounds, as the upstream one does, and
   every accept path has an admission cap whose refusals are counted. A sweep that
   clears a reader names what each bound limits (head, body, time, count). For each it
   cites a test against an over-limit, dripping or flooding peer, never the presence of
   a limit.

**The PA-0002 sweep** (by mechanism: every HTTP/1 or raw-socket protocol read in
`fuzzlab/`, re-judging BUG-0101's and BUG-0536's cleared or flagged sites):

| Site | Reads | Disposition |
|---|---|---|
| `proxy/server.py::_read_http_message` (the listener, plain and TLS loop) | client requests | fixed: SP-63 + `InboundLimits` |
| `proxy/socketsender.py::recv_http_response` / `_body_complete` | upstream responses (engine and Repeater) | fixed: SP-63; typed incomplete |
| `proxy/redact.py::_dechunk` | a stored chunked body, for redaction only | R2: a second, lenient chunk decoder (`int(..., 16)` takes `0x`, `+`, `_`); it fails closed (an undecodable redactable body is omitted). Routing it to SP-63 is a redaction change (two reviews, PA-0541(1)); flagged |
| `proxy/h2transport.py::_drain` / `send_raw` | h2c responses (desync research sender) | R1: a deadline but no byte cap, and `decode_frames(bytes(buf))` per receive (the PA-0102(2) re-copy). Not on the listener's path; flagged for its own item |
| `proxy/ws.py`, `proxy/h2client.py`, `proxy/h2frames.py` | decode / build in memory; no socket read | out of class |
| `oracle/oob.py`, `labgen/conformance/*live_boot.py`, `procutil.py` | `http.server` handlers / port probes | out of class: the stdlib frames, or no HTTP read |
| every `requests` reader | target bodies | SP-60 (BUG-0536) |

- Enforced by: tests/test_proxy_framing.py::test_every_proxy_http1_read_goes_through_the_framing_owner, tests/test_proxy_framing.py::test_the_framing_guard_catches_synthetic_offenders, tests/test_proxy_framing.py::test_a_response_cut_before_its_framed_end_is_incomplete_never_returned, tests/test_proxy_framing.py::test_a_request_that_cannot_be_framed_is_answered_400_and_never_forwarded, tests/test_proxy_framing.py::test_a_dripped_request_is_answered_408_at_its_deadline_and_never_forwarded, tests/test_proxy_framing.py::test_connections_over_the_cap_are_answered_503_and_counted

## Review round 1 (2026-10-21)
Two reviewers and a skeptic reviewed d84f97e: REVISE, with five blocking findings, each
reproduced at d84f97e. They are fixed on top of it (CC-PROXY-0028, review-round note).

- **B1 (security): the fix itself kept a loose header parse.** `MessageReader` found the
  head's end at CRLF CRLF but read its fields through `RawMessage`, which splits at `\n\n`
  and skips lines it cannot match. Four inputs were framed and forwarded on the default
  path:
  - a bare-LF pipeline (`X: y\n\nGET /smuggled …`), which reaches the upstream as two
    valid requests after `_rebuild` normalises the line endings;
  - `Transfer-Encoding\t: chunked`, framed as no body, so the chunks became the next
    request in the tunnel (defect 18 again);
  - `Transfer-Encoding : chunked`, or an obs-folded one, beside `Content-Length: 5`,
    framed by the length;
  - `X: a\rContent-Length: 5`, framed as no body.

  *Why it happened:* the fix moved framing to one owner but left that owner reading
  fields through a lenient view built for byte-exact editing. The head end and the
  fields came from two parsers that disagree on line endings: the root cause of this bug
  again, one layer down. *Fix:* `framing.parse_head` decides the head end once and
  parses the fields from that same head, strictly (RFC 9112 §2.2, §5). It refuses a bare
  CR or LF, an empty start line, obs-fold, a field line with no colon or a non-token
  name, a NUL in a value, and a malformed request or status line: 400 for a request, a
  502 for a response.
- **AU-PROXY-1: an upstream failure inside the TLS tunnel was an empty close.** The
  tunnel loop let `UpstreamIncomplete` escape, and `written=True` suppressed the 502.
  An empty `b""` response did the same. Chromium retries an empty close on a reused
  connection, so a POST could reach the upstream twice. *Fix:* each request in the
  tunnel is contained; a failure or an empty response is answered 502 in the tunnel and
  the tunnel ends. The plain path answers an empty response with 502 as well.
- **B3:** the keep-alive case had only a sans-I/O test, so deleting the listener's
  leftover carry-over left the suite green. A real TLS-tunnel test now sends a chunked
  POST and a GET in one write.
- **B2 / AU-PROXY-2:** PA-0102's enforcing test kept only a hand-maintained counter. It
  now also checks the body buffer's identity after every receive, and the oracle is
  proven on an honestly counting quadratic reader (PA-0135(3)).
- **AU-PROXY-3:** PA-0543(2) claimed "every accept path has an admission cap", while
  this sweep marked `oracle/oob.py` out of class and did not list the web UI's listener.
  The orchestrator's option (a) applies. PA-0543(2)'s admission and time clause is
  scoped to the proxy listener (this item's reader), and the two other listeners are
  residuals:

| Site | Reads | Disposition |
|---|---|---|
| `oracle/oob.py::OobListener` (`ThreadingHTTPServer`) | out-of-band callbacks to the oracle's loopback listener | R9: a thread per connection, no connection cap, a 5 s socket timeout per read (no total deadline). FUZZ's listener: flagged, not changed here |
| `web/app.py::serve` (uvicorn) | the operator's control panel, loopback only | R10: uvicorn's own defaults (no `limit_concurrency`); UI's listener: flagged, not changed here |

**Preventive action, amended (supersedes PA-0543(2) as first written above):**
2. **A read bound covers both directions and every dimension, enforced while reading.**
   The proxy's inbound read has head, body and time bounds, as its upstream read does.
   The proxy listener has an admission cap whose refusals are counted. The admission and
   time clause is scoped to the proxy listener: other listeners (`oracle/oob.py`, the web
   UI) belong to other components and are recorded as residuals, not claimed. A sweep
   that clears a reader names what each bound limits (head, body, time, count). For each
   one it cites a test against an over-limit, dripping or flooding peer, never the
   presence of a limit.

PA-0543(1) gains a sentence: *the owner's own parse is the strict one: the head's end and
its fields come from one parse of the same bytes, never from a lenient view.* Enforced
additionally by
`tests/test_proxy_framing.py::test_a_request_that_cannot_be_framed_is_answered_400_and_never_forwarded`
(the four inputs) and
`tests/test_proxy_framing.py::test_a_response_head_that_does_not_parse_strictly_is_never_relayed`.

## Merge integration (lane INTEG, 2026-10-21)
Merged with POOL24 (BUG-0549) and HIST25 (BUG-0550) (3cfd912, then d83876f), the
harness counted 135 files: 4139 passed, 8 failed. Each lane was green on its own base.
Three findings were confirmed by a skeptic. Their fixes are recorded under
CC-PROXY-0029's merge-integration sub-bullet, on `integ/proxy-r1`. I2, a kept
connection holding bytes past its framed answer, is in BUG-0549's merge-integration
section. The other two follow.

- **I1: a history failure changed the client's answer.** HIST25 made
  `ProxyEngine._record` hand each flow to `history.submit`. AU-PROXY's
  `tests/test_proxy_framing.py` fake history had `record` only. The engine raised after
  the upstream had answered, the listener's containment turned that into a 502, and four
  tests failed: a chunked request got 502 instead of the relayed 200, and so did raw
  framing and the connection cap's admitted request; the cut-response test found no
  record.
  - *Test-side fix:* the fake gains `submit`, as HIST25's merge gave
    `test_proxy_rules_and_scope.py`'s. Swept: every fake handed to `ProxyEngine` in
    `tests/` (`test_proxy_rules_and_scope.py`, `test_proxy_history_writer_thread.py`;
    the others use a real `HistoryWriter`). None other lacks `submit`.
  - *Product defect, found by the finding's check:* a history that raises must never
    change the client's answer, and it could. `_record` let any exception from building
    or submitting the flow reach the flow. `HistoryWriter.submit` can raise (its first
    call starts the writer thread), and so can any history passed in. A relayed 200
    became a 502. On the upstream-failure path, the history's exception replaced the
    upstream's in `AsyncProxyServer.errors`. This is BUG-0550's item 3 ("a write that
    failed raised into the proxied connection's handler (a 502 for that client)") at the
    hand-over: HIST25 moved the store write to a thread, so a store error no longer
    reaches the handler, but the hand-over itself was left uncontained. The finding asked
    for the fix to be recorded here, with no new number.
  - *Fix:* `_record` contains any exception raised while building or submitting the
    flow and counts it in `ProxyEngine.history_failures` by error class.
    `fuzzlab proxy` prints that count at stop, beside the listener's refusals (PA-0086(2),
    PA-0554(2): contained and reported as a count the operator reads). The client gets
    the upstream's answer, or the 502 of the upstream's own failure with that failure in
    `errors`. Test:
    `tests/test_proxy_rules_and_scope.py::test_a_history_failure_never_changes_the_clients_answer`
    fails on d83876f's `server.py` (the relayed 200 is a 502) and passes now.
  - *Prior-preventive-action failure analysis:* PA-0086(2) (every per-unit handler
    contains its own failures) and PA-0554(2) (a writer never raises to its caller) both
    applied. BUG-0550 fixed the instance it measured, a store write, and **not the
    class**: an observing side channel failing the flow. Its loop guard
    (`test_the_proxy_loop_never_calls_store_or_redaction_work`) checks which history
    calls the loop makes, not what happens when they fail. Amendment proposed for
    PA-0550 (text in the lane's doc texts; no new number): a side channel that only
    observes a flow (history, trace) never changes the flow's answer. Its hand-over is
    contained and counted by the caller, and a test injects a raising side channel at
    the engine.
  - *Sweep (by mechanism: every place that records a flow after the upstream
    answered):*

    | Site | Disposition |
    |---|---|
    | `server.ProxyEngine._record` | fixed |
    | `proxy/repeater.py::Repeater.send`: synchronous `history.record` after the send; a store error (the flush re-raises, BUG-0106) replaces the response, and the operator may send again | pinned: `tests/test_proxy_repeater.py::test_a_history_failure_never_loses_the_repeaters_response` (strict xfail). Owner PROXY, with the UI's repeater routes for where a count is shown |
    | `HistoryWriter`'s trace events (FR-PROXY-13) | not this class: written on the writer's thread; failures counted `dropped` and never raised |

- **I3: SP-63's exceptions in POOL24's tests (test-side).** Three of POOL24's tests
  expected the pre-SP-63 reader: bytes back for two answers SP-63 cannot frame (a
  non-hex chunk size; chunked with `Content-Length`), and `b""` for a stall. SP-63's
  `UpstreamFramingError` and `UpstreamIncomplete("idle")` are by design (PA-0543(1)).
  The tests now expect them and still assert what POOL24 asserted: the connection is
  closed and never kept, and a stall is never resent. A clean close after part of an
  answer on a kept connection is `UpstreamIncomplete("eof")`, never resent. SP-63's
  exceptions are not `_PEER_CLOSED`, so a close or reset before any byte is still the
  one resend.
