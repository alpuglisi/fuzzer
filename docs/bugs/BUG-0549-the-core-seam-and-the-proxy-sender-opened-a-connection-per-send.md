# BUG-0549 — The core seam and the proxy's sender opened a connection per send

- Date: 2026-10-21
- Status: fixed (CC-CORE-0075, CC-PROXY-0029), with stated residuals; review round 1
  fixed three review findings (see "Review round 1")
- Severity: medium. The audit rated defect 24 PERF_DEGRADATION. No wrong answer came of
  it, but every authenticated probe paid a TCP (and TLS) setup, the proxy built a
  system-CA SSL context per TLS call, and a run's timing measurements carried a
  changing handshake cost.

## Description
Audit defect 24 ("Authenticated HTTP probes discard connection pools"):

1. **The core seam** (`fuzzlab/core/http.py::_requests_transport`, the default
   transport of `HttpClient`, through which every authenticated probe, the auditor's
   seam fetch and blind-SQLi's `SeamSender` go) built a fresh
   `bodyread.bound(requests.Session())` per send and closed it after the answer. Its
   comment said so: "A fresh session per send, as `requests.request` made." Every send
   opened a new connection.
2. **The proxy's upstream sender** (`fuzzlab/proxy/socketsender.py::SocketSender`, the
   sender of the proxy engine, `fuzzlab proxy` and the web proxy's Repeater) opened one
   socket per call and, for TLS, called `ssl.create_default_context()` and did a full
   handshake per call. Its docstring said "Stateless between calls (one socket per
   call)".

The anonymous `RequestsProbeSender` and the static crawler already kept their sessions,
so connection behaviour differed across modes.

## Where encountered
The external adversarial audit at 6552276 (defect 24), confirmed against the source at
c483dc1 (the transport had become the `bodyread.bound` form above in CC-CORE-0072).
Reproduced at c483dc1 by `tests/test_http_pooling.py` and
`tests/test_socketsender_pooling.py`, written first and run once on the unchanged code
(every one of their 24 cases failed there; the HEAD and "not framed" cases through their
two-exchange reuse prefix).

## What it caused to fail
Measured with `scripts/measure_pooling.py` (added by this change; `--tree` points it at an
extracted base package) on this host (4 cores, shared with other lanes' test runs: load
average 3.4 for the base run, 4.3-8.2 for this change's) against a loopback HTTP/1.1
keep-alive server it starts, base c483dc1 against this change, the median of 3 runs each.
Each run is 1 000 sequential sends then 8 threads x 125 concurrent sends in plain HTTP, and
296 then 8 x 37 over TLS (a leaf of a throw-away `LocalCA`; verification on, against that
CA). Output: `scratchpad/lanes/POOL24/measure_before.json`, `measure_after.json`.

| path | before seq/s | after seq/s | before 8-thread/s | after 8-thread/s | connections per run (before -> after) |
|---|---|---|---|---|---|
| core seam, plain | 549 | 1 065 | 397 | 722 | 2 000 -> 8 |
| SocketSender, plain | 1 489 | 10 271 | 1 205 | 3 140 | 2 000 -> 8 |
| core seam, TLS | 20 | 959 | 130 | 698 | 592 -> 8 |
| SocketSender, TLS | 20 | 3 826 | 147 | 1 878 | 592 -> 8 |

The runs vary with the host's load: an earlier pair with the same method (a scratch copy
of the script, load 3.5-5.8) gave seam plain 577 -> 1 248 seq and 474 -> 780 with 8
threads, SocketSender plain 1 781 -> 4 650 and 1 310 -> 2 723, seam TLS 20 -> 974, and
SocketSender TLS 21 -> 2 752, with the same connection counts. So: the seam about 2x in
plain HTTP, the proxy's sender 2.6-7x, and both 50x or more over TLS sequentially.

Where a fresh TLS send's time went (40 sends, medians, base run): building the context
0.89 ms with one CA file, **20.5 ms with the system CA store** (what `SocketSender` built
per call against a real upstream); connect 0.23 ms; handshake 3.06 ms; the first exchange
on the new connection 44.1 ms, against **0.03-0.10 ms** for an exchange on a kept
connection. The 44 ms is the measuring server's small writes after the TLS 1.3 session
tickets meeting the client's delayed ACK (the server sets no `TCP_NODELAY`); a server that
sets it pays the handshake and the context only, so the TLS rows overstate the gain for
such servers. The plain rows have no such effect: there the gain is the connect and, in
the seam, the per-send `requests.Session` construction (about 0.9 ms per send). Before
the change the connection count equalled the send count on every path.

## What the bug was identified to be
- The core transport's signature, `(method, url, headers, body, timeout)`, carried
  neither the request's identity nor its session generation. Pooling needs both as the
  key (a connection or a cookie jar shared across identities or sessions would mix
  them), so the only safe choice the function had was a session per send. `HttpClient`
  had no lifecycle (no `close`) to own a pool either.
- A pooled `requests.Session` also keeps a cookie jar that fills from every answer's
  `Set-Cookie` and adds those cookies to later requests that set no `Cookie` of their
  own (an anonymous send, a control). The seam sets `Cookie` explicitly through the
  session addon, so it needs no jar at all; a per-send session hid that the jar was
  never disabled.
- `SocketSender` read an answer with framing that was only good enough to stop reading
  (`_body_complete`: `endswith(b"0\r\n\r\n")`, `len(body) >= Content-Length`), so it could
  not tell that a connection was clean after an exchange, and it re-did the invariant
  TLS context per call.

## Root cause analysis
Five Whys:
1. *Why did every authenticated send open a connection?* The seam's transport made and
   closed a session per send, and the proxy's sender a socket (and an SSL context) per
   call.
2. *Why was that the design?* Each was written as a stateless function of one request:
   the transport's interface had no identity or generation to key a pool by and no owner
   to close one; the sender had no exact framing to prove a connection reusable. "Fresh
   per call" was the only choice that was safe with the facts the interface carried.
3. *Why was it never revisited?* No requirement stated connection reuse or a send-rate
   expectation for the seam or the sender, and no measurement of the per-send cost
   existed. CC-CORE-0072 (BUG-0536) rewrote the transport and kept "a fresh session per
   send, as `requests.request` made" explicitly, without measuring it.
4. *Why did no rule catch the repeated setup?* PA-0148(1) says invariant setup is done
   once and reused, keyed by everything it depends on, but it named build and test-
   harness setup (a dependency install, a pinned environment, a capability probe) and is
   enforced only by the live-boot harness tests; a per-request connection, SSL context
   or HTTP session was not seen as "setup".
5. *Why is reuse not simply switched on?* Reuse is safe only under conditions the old
   code did not track: the key (origin, identity, generation), a lifecycle (retire on a
   new generation, close at teardown), no per-connection identity state (cookie jar,
   NTLM), exact framing of the previous exchange, and a rule for a reused connection the
   peer closed. Without them, pooling trades a cost for wrong answers.

**Root cause:** the transports' interfaces did not carry the facts that decide whether a
connection may be reused (whose request, which session, whether the last exchange ended
exactly), so each implementation took the always-safe "fresh per call"; and the rule
that invariant setup is done once (PA-0148) was scoped to build and harness setup and
never applied to per-request runtime setup, which nobody measured.

## Corrective action
(CC-CORE-0075, CC-PROXY-0029; this lane's commit on `lane/POOL24`.)

**Core seam (`fuzzlab/core/http.py`, FR-CORE-509).**
- `PooledTransport` is `HttpClient`'s default transport: one `requests` session per
  (canonical origin (SP-05), identity, `session_generation`), each made by
  `bodyread.bound(requests.Session())` (SP-60) where it is made.
  - A newer generation of an (origin, identity) retires the older generations' sessions.
    A send prepared on an older generation than the newest seen gets a session of its
    own, closed after it, and displaces nothing. A retired session is closed when its
    last send in flight is done, never under one.
  - Each session's cookie jar keeps nothing (`set_cookie` is a no-op) and is cleared
    before each send: the session addon's explicit `Cookie` is the only cookie sent.
  - A session idle over `POOL_IDLE_SECONDS` (4 s, under the 5 s keep-alive default of
    Node's http server and Apache httpd) is retired before its next send; at most
    `MAX_POOLED_SESSIONS` (32) are kept, least recently used out first.
  - ~~Stale-connection rule: a send whose reused connection the peer closed or reset
    before any answer is sent once more on a fresh session when its method is
    idempotent.~~ *Removed in review round 1:* the resend ran below the sender that
    records each try (FR-FUZZ-61), so the target received a request no try recorded.
    The transport now makes one try per send; a failure raises as any transport failure
    (SP-34).
  - *(Review round 1.)* A send with a body goes on a session of its own, closed after
    it (CL.0: whether a target read a body cannot be observed).
  - The bookkeeping is under one lock; thread-safe.
- `HttpClient` passes `identity` and `session_generation` to a `PooledTransport` (an
  injected transport keeps the old five-argument call), owns the one it made, and gains
  `close()` and context-manager use; a client collected without `close` closes its pools
  (`weakref.finalize`). A send after `close` works, on a session closed after it.

**Proxy sender (`fuzzlab/proxy/socketsender.py`, FR-PROXY-405; the class and new helpers
after it only, outside AU-PROXY's framing region).**
- One SSL context per sender, built on first TLS use under a lock.
- An upstream connection is kept, per (host, port, TLS), only after an exchange that was
  exactly one well-formed, bodiless HTTP/1.1 request (`reusable_request`: a token method
  other than HEAD or CONNECT, strict head, no `Transfer-Encoding`, `Expect` or `Upgrade`
  nor an underscored framing header, no `Connection: close`, no NTLM/Negotiate, no body
  bytes and no `Content-Length` but `0`; *round 1 corrected this from "a body exactly its
  one `Content-Length`"*) and one
  fully framed HTTP/1.1 answer (`reusable_response`: a final status, keep-alive, exactly
  one `Content-Length` the body matches, or `Transfer-Encoding: chunked` alone with a
  body that parses as exactly one complete chunked body, or a bodiless 204/304).
  Everything else is closed after its exchange, as before.
- Only a reusable, idempotent request takes a kept connection, so a desync probe (a
  malformed request, or since round 1 a well-formed one with a body) goes on a fresh
  socket, closed after it. A kept connection is checked first (idle at most 4 s; nothing
  readable on it; no buffered TLS byte). When its peer closed it before any byte of answer
  came (empty read before the idle timeout, or a reset / broken pipe / TLS EOF with no
  answer byte received, counted by `_Counted` since round 1) the request is sent once
  more on a fresh connection; after an answer byte, or a timeout, it never is.
- *(Review round 1.)* The web Repeater's sender is built with `keep_alive=False`
  (`web/proxycontrol.py`): one upstream connection per tab send.
- At most 8 idle connections per upstream and 64 in all; `close()` closes the idle ones,
  as does collecting the sender; `keep_alive=False` restores one socket per call.

**Tests (each failed on c483dc1, passes now).**
- `tests/test_http_pooling.py`: sequential and 4-thread sends share connections, each
  answer its own; identities and generations never share a connection or a cookie jar, a
  new generation closes the old one's connection, a late old-generation send gets its own
  and displaces nothing; a generation change never closes a send in flight; ~~a stale
  reused connection is retried once for a GET and never for a POST~~ (round 1: never
  resent by the transport; a send with a body never pooled); `close` and collection
  close the pools.
- `tests/test_socketsender_pooling.py`: well-framed exchanges (Content-Length and
  chunked) reuse one connection; 14 not-exactly-framed exchanges (answer: `Connection:
  close`, close-delimited, bytes past its length, two lengths, HTTP/1.0, bad chunk size,
  chunked plus length, connection-bound auth; request: two lengths, chunked, `Connection:
  close`, pipelined, HEAD, NTLM) never leave their connection and a malformed request never
  rides a kept one; a stale kept connection is retried once and a timeout never; TLS
  reuses one connection, one handshake, one context; 8 threads get their own answers on
  at most 8 connections; `close` and collection close the idle connections.
- `tests/_keepalive_peer.py`: the loopback keep-alive peer both use.

## Recurrence review
Checked `docs/bugs/` (BUG-0001..BUG-0541, by title and by searching "connection",
"session per", "fresh", "pool", "keep-alive", "handshake", "setup once") and
`docs/PREVENTIVE_ACTIONS.md` (the same terms, and every PA naming the seam's transport or
the socket sender).
- **Same root cause, other domain: BUG-0142 / PA-0148(1)** ("install or probe invariant
  setup once and reuse it ... keyed by everything it depends on; never repeat it per
  test, per boot or per module"). Repeating invariant setup per unit of work, unmeasured
  (PA-0148(2)), is this bug's class.
- **Related, not the same:** BUG-0101 / PA-0102 (the socket sender's unbounded,
  re-copying reads; it fixed the read loop and kept one socket per call) and BUG-0536 /
  PA-0536 (the bounded reader; it kept the per-send session explicitly). BUG-0134 /
  PA-0134(4) round 3 ("that separate client sends an explicit empty `Cookie` on every
  request, since its own jar fills from the answers it fetches") is the same jar hazard
  this change had to close before pooling.

## Prior-preventive-action failure analysis
**PA-0148 (from BUG-0142)** did not prevent this because it was **too narrow and enforced
at the wrong layer**. Its rule (1) names build and harness setup only (a locked dependency
install, a pinned environment, a capability probe) and its enforcement is four live-boot
harness tests, so nothing tied it to runtime code; a per-request HTTP session, socket or
SSL context was not recognised as "setup". Its rule (2), measure a slow step before
calling it inherent, was written for steps "that take more than a few seconds"; a 1-50 ms
per-send cost multiplied by a run's sends never crossed that bar, and CC-CORE-0072 carried
the per-send session forward as "as before" with no measurement. PA-0148 also could not
say *when* reuse is safe: for a connection the key is the identity and the session
generation, and reuse needs a lifecycle and exact framing, none of which it covers.
**PA-0134(4) (from BUG-0134)** covered a cookie jar filling from answers only for the
browser guard's side client, as a per-request explicit `Cookie`; it was not stated for
pooled clients in general.

## Preventive action
**PA-0549** (strengthens PA-0148(1)/(2) from build setup to per-request runtime setup, and
generalises PA-0134(4)'s jar rule to every pooled client):
1. **Per-request setup a sender repeats is measured and, when it is invariant, kept:** a
   connection, an HTTP session, an SSL context. "As before" is not a reason to keep a
   per-send cost; a change that keeps one on a send path cites a measurement of it.
2. **A kept connection is keyed by everything it must not be shared across** (origin,
   identity, session generation), has an owner that retires it when the session changes
   and closes it at teardown (never under a send in flight), and carries no identity
   state of its own: no cookie jar (the request's credentials are explicit per send), no
   connection-bound auth.
3. **A connection is reused only after an exchange proven exactly framed and bodiless**
   (one well-formed request with no body bytes, one fully framed keep-alive answer,
   nothing after it); anything else, every deliberately malformed request, and every
   request with a body, gets a fresh connection closed after it. *(Corrected in review
   round 1: "exactly framed" let a well-formed CL.0 probe's connection be kept; see the
   round-1 section.)*
4. ~~**A reused connection's failure has one stated retry rule:** once, on a fresh
   connection, only when the peer closed it before any answer and only for an idempotent
   method; never a timeout, an incomplete body or a non-idempotent request.~~
   *Superseded in review round 1* by the rule there: a transport never re-sends below
   the code that records the try, and a raw sender re-sends only when no answer byte
   came, counted where it is read.
5. *(Review round 1.)* A sender used for deliberate, connection-sensitive experiments
   keeps fresh connections by construction; see the round-1 section.
- Enforced by: the tests listed in PA-0549 (`docs/PREVENTIVE_ACTIONS.md`).

**PA-0002 sweep (by mechanism: every place fuzzlab opens a target connection per call).**
- Fixed here: the core seam's transport, the proxy's `SocketSender`.
- Already kept (one `bodyread.bound` session per sender or crawl, made once):
  `RequestsProbeSender` (`tools/probesender.py`), blind-SQLi's `RequestsSender` session
  (`tools/blind_sqli_fuzzer.py`), greybox's sender (`greybox/run.py`), the spider's main
  session and its workers' clones (`tools/spider.py`), the contract runner's `watched`
  session (`disco/runner.py`, one per run).
- Left, with reasons:
  - `session/manager.py::_plain_fetch_factory`: the health GET makes a session per hop.
    It is one request per health check, not a probe path, and it keeps the cookies an
    answer sets on purpose (a rotated session id is adopted), so it must not share a
    pooled jar.
  - `tools/spider.py` static form submission (`iso`): a session per submitted form on
    purpose, an isolated copy of the crawl's cookies so a submission's `Set-Cookie` never
    reaches the crawl's jar; one per discovered form, not per probe.
  - `proxy/h2transport.py::H2Transport`: raw HTTP/2 probes byte-exact; a fresh connection
    per probe is the experiment (connection-sensitive, as the audit says to keep).
  - `procutil.py`'s readiness connect: a port check, not traffic.

## Residuals
- **R1 — AU-PROXY's framing.** `reusable_response` validates the bytes
  `recv_http_response` returned with its own strict parse. When AU-PROXY's strict
  framing (same file, lines ~35-105) lands first, the two should agree on one framing
  decision: if it exposes an exact-end decision, `reusable_response` should call it
  rather than keep a second chunked parser.
- **R2 — callers' teardown.** `fuzzlab/web/proxycontrol.py` and `fuzzlab/proxy/cli.py`
  (not this lane's files) do not call `SocketSender.close()` at stop; the idle
  connections close when the sender is collected or after 4 s idle at the next use.
  `fuzzlab/tools/authhttp.py`'s clients are closed when collected.
- **R3 — pool size.** `bodyread.bound` mounts adapters with urllib3's default pool of 10
  connections per host; more than 10 concurrent sends of one key open extra connections
  that are discarded after use (urllib3 logs a warning), as before the change.
- ~~**R4 — Repeater.** The Repeater's sender keeps well-framed connections too; a request
  that is not exactly framed still gets a fresh socket. An operator who needs a fresh
  connection for a well-formed request has no switch in the UI (`keep_alive=False`
  exists on the sender).~~ **Closed in review round 1** (finding B2): a security-relevant
  residual left in prose only (PA-0134(2)). The Repeater's sender is now
  `SocketSender(verify_tls=False, keep_alive=False)`: every send opens its own upstream
  connection, closed after it, pinned by
  `tests/test_web_repeater.py::test_each_repeater_send_gets_a_fresh_upstream_connection`.
- **R5 (round 1) — bodied requests pay a connect.** On the seam and the proxy's sender a
  request with a body (a form or JSON probe, a proxied POST/PUT/PATCH) gets a connection
  of its own, as before this change; only bodiless requests gain from kept connections.
  Whether a target read a body cannot be observed, so this is the safe side.
- **R6 (round 1) — the seam's stale race.** With no transport resend, a reused connection
  the server closes between urllib3's dropped-connection check and the request fails that
  send as not observed (recorded as such). The 4 s idle retirement and urllib3's check
  make it rare; a resend, if one is ever wanted, belongs in the sender that records it.

## Review round 1 (added in review, 2026-10-21)
Four findings of the POOL24 review (the CL.0 one reported twice), each reproduced by the
reviewers on 093685e with a loopback script and confirmed.

### Description, where encountered, what it caused to fail
- **B1: a CL.0 probe poisoned a kept upstream connection** (`proxy/socketsender.py`).
  `reusable_request` accepted any well-formed request whose body matched its one
  `Content-Length`, and `_finish` kept its connection once the answer was well framed. An
  upstream that answers without reading the body (CL.0) leaves those bytes at the head of
  the connection's next request. The reviewers' scripts (`review_pool24/cl0.py`,
  `revscripts/cl0_demo.py`) sent `POST /static` with a body that is a request prefix, then
  `GET /me` with `Cookie: sid=VICTIM-alice`, through one sender. One connection was
  opened. The server parsed the second request as the smuggled `GET /comments?store=`,
  with the victim's request line in an `X-Ignore` header and the victim's cookie, and the
  victim got the smuggled request's answer. A GET with a body could also take a kept
  connection. The next request could be another Repeater tab's, or another browser
  identity's through the proxy engine (`proxycontrol.py:64`, `proxy/cli.py:107`), and the
  wrong answer was recorded in history against it. At c483dc1 every call had its own
  socket.
- **B2: the Repeater shared kept connections across tabs and identities**
  (`web/proxycontrol.py:310`). Its per-thread sender, one for the life of the server
  under uvicorn, took the new keep-alive default. Tab "alice" (`Cookie: sid=alice`) and
  tab "bob" went on one upstream connection; at c483dc1 they used two. Audit defect 24
  asks to "retain fresh sockets for deliberate desynchronization probes and
  connection-sensitive experiments", and the Repeater is where they are sent. A
  first-request-validation probe's second send now rode the first send's connection. The
  lane had left this as residual R4, in prose only.
- **B2 (core): the seam's transport re-sent a probe that no try recorded**
  (`core/http.py::PooledTransport.__call__`). A GET whose reused connection the peer
  closed unanswered was sent again on a fresh session inside the transport.
  `SeamProbeSender` records one try per dispatch (FR-FUZZ-61), so the target received a
  request that no evidence recorded, and the probe's `elapsed_ms` included the failed
  try. In the reviewers' `attempts_demo.py`, the server received 3 requests
  (`(1,'/p?q=a'), (1,'/p?q=b'), (2,'/p?q=b')`) but 2 tries were recorded, and probe b's
  one try was a `response`. A payload that resets a connection (a WAF, a crashing worker)
  was delivered twice and the reset was lost as evidence. Every authenticated probe goes
  through this transport (`authhttp.make_auth_with_isolation`).
- **B3: the proxy's sender re-sent after part of an answer had arrived**
  (`proxy/socketsender.py::SocketSender.__call__`). The kept path caught `_PEER_CLOSED`
  from the whole exchange, but `recv_http_response` raises a reset after it has already
  buffered bytes. In the reviewers' `midreset_demo.py`, the upstream answered `/1`, then
  wrote `HTTP/1.1 500 Internal Server Er` for `/2` and reset. The sender returned
  `200 ... /2`, and the upstream saw `/2` twice. The partial 500 (a crash signal) was
  discarded, and history held one flow with the second answer. FR-PROXY-405 and the
  class docstring said "before a byte of answer".

### What the defects were
- B1: the keep decision treated "the request is well framed" as "the upstream consumed
  exactly that request". With a body, the second does not follow from the first, and the
  client cannot observe it.
- B2: the owner's new default (keep-alive) was not checked against each caller. The
  Repeater, whose purpose is connection-sensitive experiments, inherited it.
- B2 (core): a re-send was placed in a layer below the evidence producer, which records
  each try where it makes it. The producer could not see the transport's re-send.
- B3: "no byte of answer came" was inferred from the exception's class instead of being
  observed where the bytes are read.

### Root cause analysis
Five Whys (one chain; the four findings share it):
1. *Why could a kept connection carry another request's bytes, a hidden re-send, or a
   replay after a partial answer?* The reuse and resend decisions were made from what
   the client sent and the error class it saw. They were not made from what the client
   could observe of the peer: a body read, an answer byte received, a try recorded.
2. *Why were they made that way?* The design proved reuse safe by the framing of the
   bytes on the client's side (exactly one request, exactly one answer). It listed
   hazards by what the client sends malformed (duplicate lengths, chunked, pipelined):
   the desync classes the lane had in mind. CL.0 is a desync built from a well-formed
   request.
3. *Why did the tests not catch it?* Every "not framed" case was malformed on the
   client's side. No peer left a body unread or reset after a partial answer, and no test
   counted requests against recorded tries through the default transport (the trace
   tests use `Connection: close` servers and an injected transport). The claims "a
   desync probe always goes on a fresh socket" and "before a byte of answer" had no test
   that fails when they are broken (PA-0083(2)).
4. *Why was the Repeater left?* The sweep listed callers by whether they wanted reuse
   for speed, not by whether reuse changes what their experiment means. R4 was written as
   prose, with no switch (PA-0134(2)).
5. *Why was the seam's re-send not treated as evidence?* PA-0510(1) was read as a rule
   for senders. The transport was treated as plumbing below them, though it performs
   the action (a send) that the evidence records.

**Root cause:** the safety of reuse and of a resend was argued from the client's own
bytes and exception classes instead of from what can be observed of the peer. The hazard
list and the tests were drawn from the client-malformed desync classes only. A layer
below the evidence producer was allowed to act (re-send) without being treated as
performing the recorded action.

### Corrective action (review round 1; the round-1 notes of CC-PROXY-0029 and CC-CORE-0075)
- **B1:** `reusable_request` refuses any request with body bytes or a `Content-Length`
  other than `0`. It also refuses any framing header spelled with an underscore
  (`Transfer_Encoding`, `Content_Length`, which some servers honour). Such a request
  neither takes nor leaves a kept connection. Tests:
  `test_socketsender_pooling.py::test_a_body_the_upstream_leaves_unread_never_reaches_the_next_request`
  (a CL.0 peer, `KeepAlivePeer(unread_body=...)`) and two new `NOT_FRAMED` cases (a GET
  with a body, and `Transfer_Encoding`).
- **B2:** `RepeaterController._writer` builds `SocketSender(verify_tls=False,
  keep_alive=False)`. Test:
  `test_web_repeater.py::test_each_repeater_send_gets_a_fresh_upstream_connection`
  (alice, bob, alice through one controller: three upstream connections, each closed).
- **B2 (core):** the transport's resend is removed, with `IDEMPOTENT_METHODS`,
  `_peer_closed`, `_REUSE` and `_reuse_noting`. The transport makes one try per send.
  Tests:
  `test_trace_attempts.py::test_the_seams_default_transport_sends_exactly_the_tries_it_records`
  (the server's count equals the recorded tries through the default transport) and
  `test_http_pooling.py::test_a_reused_connection_closed_before_any_answer_is_never_resent_by_the_transport`.
  `SeamProbeSender._dispatch`'s docstring no longer says "each request has a fresh
  connection".
- **The sweep instance of B1 in the core seam:** a send with a body goes on a session of
  its own, closed after it. Test:
  `test_http_pooling.py::test_a_send_with_a_body_never_leaves_or_takes_a_pooled_connection`.
- **B3:** the kept path reads through `_Counted`, which counts answer bytes. A
  `_PEER_CLOSED` failure after a byte is raised and never resent. Test:
  `test_socketsender_pooling.py::test_a_kept_connection_reset_after_part_of_its_answer_is_never_resent`
  (`KeepAlivePeer` `Reset(b"HTTP/1.1 500 Internal Server Er")`). Measured first: on this
  host (Linux 6.18), a client `recv` returns the bytes queued before an RST even when the
  RST has already arrived, and only then raises `ConnectionResetError`
  (`scratchpad/lanes/POOL24/r1/rst_probe.py`, 3 of 3 runs), so the test's order is fixed.
- Each new test failed once on 093685e and passes now. The reviewers' four scripts, run
  on the fixed tree: for CL.0, two connections, with the victim intact and given its own
  answer (`/me`, `/`); the partial reset is raised and the upstream saw the request once;
  on the seam, 2 requests received and 2 tries recorded.

### Recurrence review (round 1)
Checked `docs/bugs/` for "re-send", "retry", "resend", "desync", "smuggl", "fresh
connection" and "evidence", and `docs/PREVENTIVE_ACTIONS.md` for the same terms and for
every PA naming the seam, the trace or the socket sender.
- **Same root cause: BUG-0510 / PA-0510.** The trace took a re-send counter and a
  follow-up's observation for the action. Rule (1) says evidence of an action is
  recorded where the action happens, by the code that performs it. B2 (core) repeats
  the bug: the transport performed a send that no evidence recorded.
- **Same class: BUG-0044 / PA-0046.** A Probe-building component must not silently apply
  a client default such as retry-on-error. The transport's resend was such a retry, one
  layer down.
- **Same class: BUG-0082 / PA-0083(2).** Every "never / always" safety claim is backed by
  a test that fails when the claim is broken. "A desync probe always goes on a fresh
  socket" and "resent only before a byte of answer" had no such test.
- **Same class: BUG-0134 / PA-0134(2).** A security exception is never deferred in prose
  only. R4 was.
- **Related: BUG-0147.** `RequestsProbeSender` re-sends only a connection error with no
  response and never a cut body ("the server had already answered"). B3 broke the same
  rule in the proxy's sender.
- No prior CL.0 defect (a desync through an unread body) is in `docs/bugs/`. The desync
  lab work (BUG-0013, BUG-0014, BUG-0015) is about the environment.

### Prior-preventive-action failure analysis (round 1)
- **PA-0510(1) (from BUG-0510)** was **read too narrowly**. It says "the code that
  performs it", but its sweep and its tests covered the senders and the trace. Its
  enforcement tests use `Connection: close` servers and an injected transport, so they
  never exercised a re-send inside the seam's real transport. PA-0510(2) asks for "a
  case for each way an action can miss its usual result (a re-send ...)". No such case
  ran through the default transport, and the lane did not add one when it changed that
  transport (not followed).
- **PA-0046 (from BUG-0044)** was **scoped to the sender's client defaults** (redirects,
  `requests` retries). The lane added the retry itself, below the sender, and nothing
  checks the transport for one (not enforced at that layer).
- **PA-0083(2) (from BUG-0082)** was **not followed.** The docstring and FR claims, a
  fresh socket "always" for a desync probe and a resend only "before a byte of answer",
  were added with tests of malformed requests and pre-answer closes only.
- **PA-0134(2) (from BUG-0134)** was **not followed.** R4 left a security-relevant switch
  in prose.
- **PA-0549 as first written** (this bug) was **wrong in content.** Its rule (3)'s "exactly
  framed" is a property of the client's bytes, and its rule (4) placed a re-send in the
  transport. It is corrected below, not restated.

### Preventive action (round 1): PA-0549 revised
PA-0549 (3) and (4) are corrected and (5) is added. The full text is in
`docs/PREVENTIVE_ACTIONS.md`:
3. **A connection is reused only after an exchange proven exactly framed and bodiless.**
   A request with body bytes always gets a connection of its own, closed after it,
   because whether the peer read a body cannot be observed (CL.0). A framing header in
   any spelling a server may honour counts as framing. A "fresh connection" claim for a
   probe class is pinned by a test whose peer leaves a body unread.
4. **A transport never re-sends below the code that records the try.** This strengthens
   PA-0510(1) and PA-0046 from senders to the layers beneath them: a re-send is the
   evidence producer's, made and recorded where it happens. A raw sender beneath no
   evidence producer re-sends a reused connection's request at most once, for an
   idempotent method, and only when no byte of answer came. That is counted where the
   bytes are read, never inferred from an exception class. It never re-sends after a
   timeout or a partial answer.
5. **A sender used for deliberate, connection-sensitive experiments keeps fresh
   connections by construction** (the Repeater). This is pinned by a test that counts
   upstream connections, and such a switch is never left as a residual in prose
   (PA-0134(2)).

**PA-0002 sweep (round 1).**
- *Re-sends below an evidence producer:* searched `fuzzlab/` for `max_retries`,
  `Retry(`, `HTTPAdapter(` and retry loops (`for attempt in`). The only resend of a
  target send was the core seam's transport (removed here). `RequestsProbeSender`'s loop
  is in the sender and recorded (FR-FUZZ-61). The other loops retry a lab boot harness's
  port bind, not a send. `bodyread.bound` mounts adapters with `requests`' default
  `max_retries=0`.
- *A resend after a partial answer:* the proxy's `SocketSender` (fixed).
  `RequestsProbeSender` resends only a `ConnectionError` with no response and never a cut
  body (BUG-0147). `H2Transport` never re-sends.
- *Reuse after a body:* the proxy's sender and the core seam (fixed: never). The
  pre-existing single-identity keep-alive sessions that send bodies (`RequestsProbeSender`,
  greybox's `RequestsCorrelatingSender`, the contract runner's `watched` session) reuse a
  connection after a POST, as every keep-alive client and browser does. Their traffic is
  one identity's own, they make no fresh-connection claim, they carry no
  operator-written raw bytes, and they predate this bug: residual R7, for the owner's
  decision. Blind-SQLi's `RequestsSender` sends GETs only, and the spider submits each
  form on a session of its own (`iso`).
- *Callers of `SocketSender` (by owner):* `proxycontrol.py:64` (the engine) and
  `proxy/cli.py:107` keep connections for bodiless requests, with B1 and B3 fixed in the
  owner. `proxycontrol.py:310` (the Repeater) is fresh (B2). `scripts/measure_pooling.py`
  measures GETs.
- *Callers of `HttpClient` (by owner):* `SeamProbeSender` makes one try per dispatch
  (FR-FUZZ-61 holds). Blind-SQLi's `SeamSender` and AUD's seam fetch
  (`tools/fetcher.py`) get a transport failure as any other; neither records per-try
  evidence.

### Residuals (round 1)
- **R7: pre-existing keep-alive sessions reuse a connection after a body** (above). This
  is a same-identity exposure to a CL.0 server, not a regression of this change; the fix
  would cost a connect per POST across the anonymous fuzzer.
- R1 now also covers `_Counted`. When AU-PROXY's reader lands first, it must keep
  receiving through `recv` / `recv_into` (it does at d84f97e) and let a reset from `recv`
  propagate. Its idle timeout raises `UpstreamIncomplete`, which is not `_PEER_CLOSED`,
  so a timeout is still never resent.
- No CC-UI or CC-FUZZ number was pre-assigned for the one-argument change in
  `web/proxycontrol.py` and the docstring line in `tools/probesender.py`. They are
  recorded under CC-PROXY-0029 and CC-CORE-0075, and the coordinator's entry texts are in
  the lane's doc texts.

## Merge integration (lane INTEG, 2026-10-21)
AU-PROXY (BUG-0543, SP-63), this bug's fix (POOL24) and HIST25 (BUG-0550) were each
green on its own base. Merged (3cfd912, then d83876f with SURROGATE), the harness
(`scripts/verify_change.py --base 08fe6ee`) counted 135 files: 4139 passed, 8 failed.
One of the three findings is a product defect of this bug's fix, found by its own
enforcing test: I2 below. I3 (POOL24's tests expecting the pre-SP-63 reader) is recorded
here too; I1 is in BUG-0543's integration notes.

### Description, where encountered, what it caused to fail
- **I2 (security): a kept connection could hold bytes past its framed answer.**
  `SocketSender._finish` kept a connection when `reusable_response(resp)` held. Before
  SP-63, `recv_http_response` returned bytes past an answer's `Content-Length` as part
  of `resp`, so `reusable_response` saw an answer longer than its length and refused it.
  SP-63's reader returns the framed answer only. Bytes read past it stay in
  `MessageReader.leftover`, which `recv_http_response` dropped, and bytes not yet read
  stay on the socket. The connection was kept. When an upstream answers once too often
  (a desynchronised upstream, or one answering a request it parsed as two), the stray
  answer was dropped unseen if it came with the first. If it came later, the next
  request on the connection, possibly another tab's or another identity's, was answered
  with it (a response desync).
- *Where:* the merged tree's harness run:
  `tests/test_socketsender_pooling.py::test_an_exchange_that_is_not_exactly_framed_never_leaves_its_connection[bytes past the answer's Content-Length]`
  (the connection was not closed).
- **I3 (test-side):** the same file's cases "a chunked answer whose chunk size is not
  hex" and "an answer with chunked and Content-Length" expected bytes back. SP-63 raises
  `UpstreamFramingError` for both, by design (PA-0543). `test_a_stale_pooled_connection_is_retried_once_and_a_timeout_never`
  expected `b""` from a stalled answer; SP-63 raises `UpstreamIncomplete("idle")`.

### What the defect was
`reusable_response` decided "nothing after the answer" by parsing the bytes the reader
returned. That held only while the reader returned trailing bytes. Once the framing
owner (SP-63) kept them apart, nothing in the sender looked at them.

### Root cause analysis
1. *Why was the connection kept?* `_finish` asked `reusable_response` about `resp`
   alone, and `resp` no longer held the trailing bytes.
2. *Why did `reusable_response` read `resp` for that?* POOL24 wrote it against the
   pre-SP-63 reader, whose return value held every byte received. It decided where the
   answer ended with its own parse (`_chunked_exact`, `_length_is`), a second framing
   decision beside the reader's.
3. *Why was that second decision not replaced at the merge?* R1 of this bug named the
   dependency ("when AU-PROXY lands, the two must agree; if it exposes an exact-end
   decision, `reusable_response` should call it") in prose. Nothing failed until the
   merged tree's harness ran this bug's own enforcing test.
4. *Why could the exact-end decision not be called?* SP-63 had one (`leftover`), but
   `recv_http_response` dropped it, so no caller could see it.

**Root cause:** a safety decision about where a message ended was made from a reader's
return value, a second derivation of a fact that the framing owner holds, while that
owner was being changed in the same window. The dependency was recorded as a residual
in prose, and PA-0543(1) ("decided by one framing owner") was not applied to POOL24's
check.

### Corrective action (CC-PROXY-0029, merge-integration sub-bullet; commit on `integ/proxy-r1`)
- `socketsender.read_http_response` returns `(response, past)`, `past` being SP-63's
  `MessageReader.leftover`. `recv_http_response` is its first element, so its callers
  are unchanged.
- `SocketSender._finish` keeps a connection only when `past` is empty,
  `reusable_response` holds, and `_quiet(sock)` finds nothing waiting on the socket.
  `_quiet` is the check `take` already made before reuse. The end decision is SP-63's
  alone. `reusable_response` and `_chunked_exact` stay as a stricter grammar filter: one
  `Content-Length` header, `chunked` alone, no whitespace in a chunk-size line, token
  trailer names. They can only refuse what SP-63 accepted; the finding allowed keeping
  the stricter rule when in doubt. R1 is closed for the end decision.
- I3: the tests expect `UpstreamFramingError` for the two unframeable answers and still
  assert that the connection is closed. The kept path's `except BaseException` closes it,
  as the fresh path's does. A stall raises `UpstreamIncomplete("idle")`, is never
  resent, and its connection is not kept. A new `/cut` case covers a clean close after
  part of an answer: `UpstreamIncomplete("eof")`, never resent. SP-63's exceptions are
  not `_PEER_CLOSED`, so a close or reset before any byte is still the resend case (the
  `/2` and `/none` cases).
- New `test_bytes_after_a_framed_answer_never_leave_its_connection_kept`, two cases. In
  the first, the upstream answers twice in one segment and the stray answer is read with
  the first, so it is in `leftover`. In the second, `READ_SIZE` is set to the first
  answer's length, so the stray answer waits on the socket. Each fails on d83876f's
  product files (the connection is kept) and passes now.
- Measured (`scratchpad/lanes/INTEG/measure_tls_keep.py`, loopback): with the new check,
  300 sequential calls kept one connection over plain HTTP, TLS 1.2 and TLS 1.3 (one
  handshake each). `_quiet` at `_finish` does not cost reuse against Python's `ssl`
  server, whose TLS 1.3 tickets come before the first answer. Other servers were not
  measured.

### Recurrence review (merge integration)
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for "leftover", "past its",
"trailing", "framed end", "second parse", "R1" and "merge".
- **Same root cause: BUG-0543 round 1, B1.** AU-PROXY's first fix read the head's end
  from one parser and its fields from another, and the two disagreed. PA-0543(1) answered
  that the owner's parse is the only one. Here a consumer of the owner, POOL24's keep
  check, made the second framing decision.
- **Same class: BUG-0549 round 1, B1/B3.** Reuse was decided from the client's own bytes
  and from exception classes, not from what was observed where the bytes are read.
  PA-0549(4) fixed that for resends ("counted where the bytes are read"); the
  keep-after-answer decision had the same flaw.
- **Same class: BUG-0134 / PA-0134(2).** A security-relevant dependency was deferred in
  prose (R1).

### Prior-preventive-action failure analysis (merge integration)
- **PA-0549(3) (this bug)** held in content ("one fully framed keep-alive answer, nothing
  after it"), and its enforcing test caught the break at the merge, before anything
  shipped. It failed **at the wrong layer**: it did not say where "nothing after it" is
  decided, so POOL24 decided it from the reader's return value.
- **PA-0543(1) (BUG-0543)** says a message is complete only at its framed end, decided
  by one framing owner. It was **not applied to a consumer**: its guard checks hand
  framing (`readuntil`, `readexactly`, a last-chunk literal), not a second end decision
  made by parsing the owner's output.
- **PA-0134(2) (BUG-0134)** was **not followed**: R1 left a security-relevant merge
  dependency in prose.

### Preventive action (merge integration): PA-0549(3) strengthened
No new PA number was assigned for this round. The amendment text for PA-0549 is in the
lane's doc texts for the coordinator:
- *(3), added:* whether anything followed an answer is decided from the framing owner's
  observation (SP-63's `leftover`) and the socket's state when the answer ended. It is
  never decided by re-parsing the bytes a reader returned.
- *(3), added:* a residual that names a dependency on another lane's change in flight is
  a test that fails until the dependency is met, never prose.
- Enforced additionally by
  `tests/test_socketsender_pooling.py::test_bytes_after_a_framed_answer_never_leave_its_connection_kept`.

**PA-0002 sweep (merge integration; by mechanism: every decision to keep a connection
after an answer).**

| Site | How it decides | Disposition |
|---|---|---|
| `proxy/socketsender.py::SocketSender._finish` | `reusable_response` on the returned bytes | fixed: SP-63's `leftover`, then `_quiet` |
| `core/http.py::PooledTransport` (requests over urllib3) | urllib3 checks only at checkout that the socket is not readable; bytes that came with an answer are buffered with it and dropped | measured (`scratchpad/lanes/INTEG/measure_seam_stray.py`): the next GET rode the same connection. Pinned: `tests/test_http_pooling.py::test_an_answer_followed_by_another_never_leaves_its_pooled_connection` (strict xfail). Owner CORE |
| other `requests` sessions (`RequestsProbeSender`, greybox, the contract runner, the spider, `tools/fetcher.py`, blind-SQLi, `tools/authhttp.py`) | the same urllib3 mechanism | one mechanism, one owner decision, pinned at the seam above; R7's class (pre-existing keep-alive sessions) |
| `proxy/h2transport.py`, `proxy/h2client.py` | HTTP/2 frames each stream (`END_STREAM`) | not this class |
| the listener's client side (`server._Inbound`) | bytes after a request are the next pipelined request (RFC 9112 §9.3, BUG-0543 B3) | not this class: a server reading pipelined requests in order |

### Residuals (merge integration)
- **R8: a stray answer that arrives late.** Bytes that arrive after `_finish`'s check
  and after `take`'s, but before the next answer is read, are still read as that answer.
  This is the residual of any keep-alive client, now narrowed to bytes sent late.
- R1 is closed for the end decision. The stricter grammar filter (`_chunked_exact`) is
  kept by choice.
