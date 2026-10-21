# BUG-0549 — The core seam and the proxy's sender opened a connection per send

- Date: 2026-10-21
- Status: fixed (CC-CORE-0075, CC-PROXY-0029), with stated residuals
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
  - Stale-connection rule: a send whose reused connection the peer closed or reset
    before any answer (`RemoteDisconnected`, reset, broken pipe, TLS EOF, inside a
    `requests.ConnectionError`) is sent once more on a fresh session when its method is
    idempotent (`IDEMPOTENT_METHODS`, RFC 9110 §9.2.2). A POST or PATCH is never
    replayed; a timeout, an incomplete body (`BodyIncomplete`) or a failed connect is
    never retried. Reuse is known exactly: the session's direct pools note, per thread,
    whether the connection urllib3 handed out was already connected (`_reuse_noting`).
  - The bookkeeping is under one lock; thread-safe.
- `HttpClient` passes `identity` and `session_generation` to a `PooledTransport` (an
  injected transport keeps the old five-argument call), owns the one it made, and gains
  `close()` and context-manager use; a client collected without `close` closes its pools
  (`weakref.finalize`). A send after `close` works, on a session closed after it.

**Proxy sender (`fuzzlab/proxy/socketsender.py`, FR-PROXY-405; the class and new helpers
after it only, outside AU-PROXY's framing region).**
- One SSL context per sender, built on first TLS use under a lock.
- An upstream connection is kept, per (host, port, TLS), only after an exchange that was
  exactly one well-formed HTTP/1.1 request (`reusable_request`: a token method other than
  HEAD or CONNECT, strict head, no `Transfer-Encoding`, `Expect` or `Upgrade`, no
  `Connection: close`, no NTLM/Negotiate, a body exactly its one `Content-Length`) and one
  fully framed HTTP/1.1 answer (`reusable_response`: a final status, keep-alive, exactly
  one `Content-Length` the body matches, or `Transfer-Encoding: chunked` alone with a
  body that parses as exactly one complete chunked body, or a bodiless 204/304).
  Everything else is closed after its exchange, as before.
- Only a reusable, idempotent request takes a kept connection, so a desync probe always
  goes on a fresh socket. A kept connection is checked first (idle at most 4 s; nothing
  readable on it; no buffered TLS byte). When its peer closed it before a byte of answer
  (empty read before the idle timeout, or a reset / broken pipe / TLS EOF) the request is
  sent once more on a fresh connection; an answer that timed out is never resent.
- At most 8 idle connections per upstream and 64 in all; `close()` closes the idle ones,
  as does collecting the sender; `keep_alive=False` restores one socket per call.

**Tests (each failed on c483dc1, passes now).**
- `tests/test_http_pooling.py`: sequential and 4-thread sends share connections, each
  answer its own; identities and generations never share a connection or a cookie jar, a
  new generation closes the old one's connection, a late old-generation send gets its own
  and displaces nothing; a generation change never closes a send in flight; a stale
  reused connection is retried once for a GET and never for a POST; `close` and
  collection close the pools.
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
3. **A connection is reused only after an exchange proven exactly framed** (one
   well-formed request, one fully framed keep-alive answer, nothing after it); anything
   else, and every deliberately malformed request, gets a fresh connection closed after
   it.
4. **A reused connection's failure has one stated retry rule:** once, on a fresh
   connection, only when the peer closed it before any answer and only for an idempotent
   method; never a timeout, an incomplete body or a non-idempotent request.
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
- **R4 — Repeater.** The Repeater's sender keeps well-framed connections too; a request
  that is not exactly framed still gets a fresh socket. An operator who needs a fresh
  connection for a well-formed request has no switch in the UI (`keep_alive=False`
  exists on the sender).
