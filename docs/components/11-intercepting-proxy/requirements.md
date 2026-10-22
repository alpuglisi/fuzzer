# Intercepting Proxy — Requirement Specification

Component code: **PROXY** · Status: `[built — offline stack + live upstream SocketSender, CONNECT/TLS termination, the fuzzlab proxy CLI, and the live h2c H2Transport; HTTPS interception + h2c send verified on-host]` (Phase 6 + Phase 9) · Last updated: 2026-10-21 · see CC-PROXY-0010, CC-PROXY-0011, CC-PROXY-0025, CC-PROXY-0028, CC-PROXY-0029, CC-PROXY-0030

Related: `ARCHITECTURE.md` #11; `DECISIONS_AND_ROADMAP.md` (D3, D4, D5);
`./change-control.md`.

## 1. Purpose
Provide a Burp-style intercepting proxy for inspecting, editing, and replaying
traffic — built from scratch for full control (D4) — as an **optional observer**
that shares the store, never a mandatory pipeline (D5).

## 2. Scope
- **In:** async proxy core, a parsed protocol path and a byte-exact raw path,
  TLS interception, shared history, repeater, match-and-replace, scope engine,
  interactive interception.
- **Out:** deciding what is vulnerable (auditor/oracle) and staying authenticated
  (session manager, attached as an addon).

## 3. Functional requirements
- **FR-PROXY-1** Async core with two paths: a **parsed** path (`h11`/`h2`/
  `wsproto`) for normal traffic and a **raw byte** path (byte-exact, single-use
  connections) for malformed-traffic study — the hybrid of D4. *(Amended
  CC-PROXY-0028, BUG-0543:)* the listener (`AsyncProxyServer`) is the browser's
  well-formed path: it frames every request by the protocol (FR-PROXY-401). Deliberately
  malformed requests go on the wire through the raw path: the Repeater and
  `SocketSender` send stored bytes verbatim, and the listener's explicit raw mode
  (`raw_framing`, `fuzzlab proxy --raw-framing`, off by default) frames a request with
  conflicting `Content-Length` values by the first and forwards it byte-exact.
- **FR-PROXY-2** CONNECT + TLS interception with a local CA and cached leaf certs.
- **FR-PROXY-3** Persist history to the store (FTS5 search, batched writes,
  content-addressed bodies) as `flow` rows with raw bytes, written off the proxy's event
  loop (FR-PROXY-404).
- **FR-PROXY-4** Repeater with DB-persisted tabs; edit and replay, including via
  the raw path.
- **FR-PROXY-5** Match-and-replace rules and a scope engine (only in-scope hosts
  are intercepted/recorded). *(Amended CC-PROXY-0019, BUG-0085 / BUG-0086:)*
  - **Rules are validated when created.** A match / replace that is not latin-1, or a
    regex or scope path regex that doesn't compile, raises `ValueError` (the API
    answers 400).
  - **One connection's failure is contained:** `502` when nothing was written yet,
    otherwise close; the server keeps serving.
  - **Scope is decided once, on the authority.** A port-less rule matches any port,
    and a port-specific exclude always wins.
  - **Authorities are parsed by `proxy.authority`** (IPv6 `[v6]:port` included).
- **FR-PROXY-6** Interactive interception modeled as an awaited future (hold,
  edit, release).
- **FR-PROXY-7** Attach the session manager as an addon so hand-driven browser
  traffic gets the same auth handling.
- **FR-PROXY-8** Remain optional: tools may route through it for unified history,
  but timing-sensitive traffic bypasses it (D5).
- **FR-PROXY-9 (session capture)** Capture the authenticated session from a
  **manual browser login** performed through the proxy — extract the established
  cookies/tokens for the `(host, identity)` and hand them to the session manager to
  adopt. This is the path for logins the session manager's detection can't parse
  (MFA, CAPTCHA, multi-step, exotic SPA), keeping the toolkit authenticated without
  a per-host config file. Captured secrets are redacted on write and never
  persisted in cleartext. *(CC-PROXY-0023, FR-SESS-20, BUG-0134:)* `SessionCapture`
  records the canonical origins of the URLs it observes on its host
  (`observe_request` / `observe_response` with `url=`); the adopted session is sent
  only to them (and to the manager's `auth_origins`, which `adopt` adds; review round
  1, R5), and the manager refuses a capture with no observed origin.

- **FR-PROXY-10 (CA leaf hygiene, CC-PROXY-0019, BUG-0079)** A leaf is minted only
  for a valid host: an IP literal, or an IDNA, lower-cased `[a-z0-9_-]` label
  hostname, at most 253 characters. The leaf file lives directly in `<ca_dir>/leaves/`
  (IPv6 as `ip6-<hex>`, with a resolved-path backstop). Every key (leaf and CA) is
  created 0600 with `O_NOFOLLOW`, and the CA directories are 0700. *(CC-PROXY-0020,
  BUG-0096:)*
  - **The CA key** is created with `O_EXCL` (`core.secretfile.create_secret`), so a
    trust root is never silently replaced. It is written key first, then the
    certificate (atomically).
  - **On load**, the key must match the certificate, and a half CA is refused. Both
    raise `CAError`, naming the fix.
  - **Leaf key and cert** are replaced atomically and in full
    (`core.secretfile.replace_secret`). `fuzzlab proxy` and `AsyncProxyServer` bind loopback only
  (`core.net.require_loopback`, BUG-0080).
- **FR-PROXY-11 (persisted-copy redaction, CC-PROXY-0019, BUG-0084)** Before history is
  written, these are redacted:
  - sensitively named headers;
  - query parameters of the request target and of `Location` / `Content-Location` /
    `Refresh`; *(BUG-0556, review round 1:)* every sensitively named URL value
    `core.redaction.redact_url` finds (`;` pairs and path parameters, a query-shaped
    fragment, nested values, a nested URL's userinfo), with or without a query: the
    target and those headers are always passed to it whole (a `;jsessionid=` path
    parameter in a URL with no query was kept). *(Review round 2, `CC-PROXY-0031`:)*
    **every value of every URL-bearing header**, duplicates included and rewritten in
    place (order and every other line byte-exact): `Location`, `Content-Location`,
    `Referer`, `Origin`, `Destination`, `X-Original-URL`, `X-Rewrite-URL`, `Ping-From`,
    `Ping-To`, any other header whose value starts as a URL (a scheme's `://` or `/`),
    each `<URI>` of `Link`, and `Refresh`'s URL as the HTML declarative-refresh steps
    read it (`url=`, `url = `, quoted, or bare after the delay); the request target is
    read whitespace-tolerantly (after the method and its run of spaces or tabs, up to
    the run before a final `HTTP/` version), so a malformed request line is redacted
    too. *(r6, BUG-0556, the owner's design, `CC-PROXY-0031`:)* **layered on the pushed
    redactor**: 7393c90's own `redact` (`core.redaction_floor.redact`, frozen verbatim)
    runs first on the raw message -- the sensitive headers, the request target's query,
    `Location`'s and `Content-Location`'s query and `Refresh`'s every `url=` run (quotes
    and the tail after them included), a duplicate of a `Location` or `Content-Location`
    it rewrites collapsed into the rewritten value (as `RawMessage.with_header` did),
    and the bodies -- and the walk above runs only on its output, so nothing the pushed
    tree redacted is kept. Where the floor raises (a URL `urlsplit` rejects in the
    request line or one of those headers), `redact` raises and the history writer stores
    the flow with every body `OMIT_FAILED` and its URL cut at the `?`
    (`_prepare_contained`), as on 7393c90. Pinned (owner CORE, BUG-0556 r6 family (a)):
    a name the floor's `urlsplit` reading joins across a removed tab (`?token=a&x<TAB>
    password=<w>`, which the floor returns as `xpassword=<w>`) in the request line,
    `Location` or `Content-Location`, kept on 7393c90 too;
  - form, JSON (any depth) and multipart (non-file) request and response bodies. *(CC-PROXY-0020,
    BUG-0090:)* a sensitive JSON key's **whole value** is replaced, whatever its type
    (scalar, list, object or nested), and plural names are sensitive
    (`core.redaction`). *(CC-PROXY-0021, BUG-0100:)* it fails closed through the shared
    boundary (FR-CORE-25). Chunked or compressed bodies are decoded with bounds
    (gzip / deflate): a clean one is stored byte-exact; one with a secret, or
    undecodable with a redactable type, is replaced by the marker, with
    `Transfer-Encoding` / `Content-Encoding` dropped and `Content-Length` set. The
    former residual is closed. `HistoryWriter.flush` is all-or-nothing (a savepoint;
    it commits only a transaction it owns), and a record whose redaction fails is
    stored with omitted bodies (BUG-0106);
  - `flow.url` and the separately stored bodies.

  Sensitivity is by name token (`core.redaction.is_sensitive_name`). Benign messages
  stay byte-identical, and Content-Length follows a changed body. Chunked or compressed
  bodies are stored as received (a residual). Trade-off: a Repeater tab seeded from
  history carries placeholders, and `HistoryWriter(redact_secrets=False)` is the
  lab-local opt-out.
- **FR-PROXY-12 (bounded upstream reads, CC-PROXY-0021, BUG-0101)**
  - `recv_http_response` accumulates in one buffer, never re-copied. *(CC-PROXY-0028:)*
    its buffers are SP-63's reader's, whose `copied` count stays linear in the bytes
    received.
  - **Bounds:** headers ≤ 64 KiB; the body ≤ `max_body` (default 64 MiB); an overall
    deadline (default the idle timeout × 4, SP-60's `DEADLINE_TIMEOUTS`). Breaching any
    of them raises `UpstreamResponseError` (*CC-PROXY-0028:* its subclass
    `UpstreamIncomplete`, reason `head`, `wire` or `deadline`), and the connection is
    answered with a 502. The 64 MiB ceiling is the proxy's own, not SP-60's 16 MiB wire
    ceiling: a browser's downloads are relayed byte-exact and never content-decoded.
  - **Configurable:** `SocketSender(max_body=, deadline=)` and `fuzzlab proxy
    --max-response-bytes / --response-deadline`. They cut off long-lived streams and
    very large downloads, by design.
  - **Off the event loop:** the engine runs the (thread-safe) sender with
    `asyncio.to_thread`, with at most min(32, CPUs + 4) concurrent upstream calls.
    History is written by the history writer's own thread; the loop only queues a flow
    (FR-PROXY-404, CC-PROXY-0030; it was recorded on the loop thread until BUG-0550). *(CC-PROXY-0029:)* the sender keeps
    exactly framed upstream connections between calls (FR-PROXY-405).
- **FR-PROXY-13 (proxied traffic in the trace, CC-PROXY-0025)** Every in-scope flow
  the proxy engine records is also one `observe.exchange` trace event (FR-CORE-505),
  so the Diagrams page shows proxied traffic while it happens (the `proxy` sequence,
  FR-UI-512).
  - **Where:** `HistoryWriter` owns a `core.trace.TraceRecorder`, on the writer's thread
    and store connection (the writer thread's own, once the engine's `submit` started
    it: FR-PROXY-404), under its lock, with the writer's `run_id`. After a flush has
    committed its flows, it emits their events and flushes them: they are visible as
    soon as the flow is (`batch_size=1` in `fuzzlab proxy` and the web proxy: written as
    soon as the writer thread takes the flow).
  - **The event:** `src` "proxy", `ref` "flow id <n>", method, URL (`trace.safe_ref` of
    the redacted URL), origin (`core.urls.canonical_origin`), status (None when no
    response came), `error` (the upstream failure's class), `outcome`, the redacted
    `Location`, the identity as `profile`, the request content type, `params` (query
    and form / JSON field *names* and locations, from `tools.observe`; never a value;
    a chunked or compressed body is not parsed), `via` (the protocol), and `intercept`
    when the operator held a message ("request edited" / "request forwarded",
    "response edited" / "response forwarded"). `t` is when the proxy received the
    request; key `proxy:flow:<flow id>`; scope `proxy`. `history.flow_event` is pure, so
    re-processing a flow is a duplicate.
  - **A failed upstream** (the sender raised) is recorded as a flow with no response and
    its error class, and the connection still answers 502 (FR-PROXY-5).
  - **A flush inside a transaction the writer does not own** emits nothing then. A later
    flush or `close` emits the events once the transaction is gone and the flow is
    still stored (compared by id, method, URL, status and identity). A rolled-back flow
    gets no event.
  - **Not traced:** out-of-scope flows (not recorded); messages the operator dropped
    (no flow is recorded for them); repeater sends (`FlowRecord.source="repeater"`: the
    operator's replays, not browser traffic); a writer with no `run_id` (a stored flow
    always has one: `flow.run_id` is NOT NULL); `HistoryWriter(trace=False)`.
  - **Failures** never fail the history: a trace event that cannot be built or written
    is counted `dropped`, logged, and the counters are written (`run_metrics`
    `trace_*`); `HistoryWriter.close()` writes them at the end.
  - **The run's end** (CC-PROXY-0026): `HistoryWriter.close(run_end=...)` records a
    `run.end` event. `fuzzlab proxy` passes `complete` on Ctrl-C or SIGTERM (a
    requested stop: the operator's, the web UI's Stop of a `proxy` job, a service
    manager's; FR-PROXY-404) and `aborted: <class>` on any other exit; the web proxy's
    `stop()` passes `complete`. A closed proxy run's diagram status is therefore `complete`, not
    `partial` for want of an end.
  - **Measured cost** (CC-PROXY-0025): 400 flows at `batch_size=1` on the event-loop
    thread; per flow, median 0.30–0.38 ms without the trace and 1.38–1.46 ms with it,
    p95 1.3–2.5 ms without and 5.8–13.4 ms with. That was an idle store; since
    CC-PROXY-0030 this cost is paid on the writer thread, not the loop (BUG-0550).
- **FR-PROXY-404 (history off the event loop, CC-PROXY-0030, BUG-0550)** The engine
  hands each in-scope flow to `HistoryWriter.submit`, which does bounded work on the
  loop: it reads nothing past each message's first line (`server._first_line_of`) and
  only queues the flow.
  - **A history failure never changes the flow** (merge integration, CC-PROXY-0029,
    BUG-0543): whatever building or submitting a flow raises is counted in
    `ProxyEngine.history_failures` by its error class and never raised into the flow.
    The client gets the upstream's answer, or the 502 of the upstream's own failure
    with that failure in `AsyncProxyServer.errors`; `fuzzlab proxy` prints the count
    when it stops. Enforced by:
    `tests/test_proxy_rules_and_scope.py::test_a_history_failure_never_changes_the_clients_answer`.
    **The Repeater too** *(review round 2, P2-2; BUG-0543)*: `Repeater.send` contains
    whatever building or recording the flow raises (a store error such as `database is
    locked`, which the synchronous `record`'s flush re-raises). It returns the
    upstream's response, counts the failure in `Repeater.history_failures` by error
    class, names it in `Repeater.last_history_error` (None when recorded), and logs the
    class only. The flow stays in the writer's buffer, so a later successful write
    stores it. The web UI's `RepeaterController.send` returns `history_error` and
    `history_failures` (the controller's count) in the JSON beside `response`, where the
    operator reads the Repeater's result. A failure is never a 500 for a request the
    target answered, and nothing is resent. Before, the store error replaced the
    response and the route answered 500. Enforced by:
    `tests/test_proxy_repeater.py::test_a_history_failure_never_loses_the_repeaters_response`,
    `tests/test_web_repeater.py::test_a_history_failure_answers_the_repeaters_response_and_says_so`.
    Not yet built: the Proxy page's script does not show `history_error` beside the
    response (a UI change, PA-0065).
  - **One writer thread per writer**, started by the first `submit`, opens its own
    `Store` on the writer's file (`create=False`) and does every redaction, hash,
    insert, commit and trace event, in submission order (flow ids follow it).
  - **Batches** are cut by count (`batch_size`), bytes (`flush_bytes`, default 4 MiB)
    or age (`flush_seconds`, default 0.5 s), whichever comes first. One transaction
    holds at most 500 flows and `flush_bytes` plus the flow that crosses it. The
    synchronous `record` path (the repeater) is also cut by `flush_bytes`.
  - **The queue** holds at most `max_pending_flows` (10,000) flows and
    `max_pending_bytes` (256 MiB) waiting or being written; one larger flow is admitted
    only into an empty queue. A flow that does not fit is dropped from the history,
    never from the traffic: counted (`HistoryWriter.stats`: `dropped`, `dropped_bytes`),
    logged, and written to `run_metrics` at once.
  - **A batch that cannot be written** is tried 3 times, then counted `failed` and
    logged; the writer goes on. A failed write, its commit included, leaves nothing
    behind, so a retry never duplicates a flow.
  - **`flush`** waits until every flow submitted before it is written or counted.
    **`close(run_end)`** writes everything pending, then the run's end and the
    counters, within 60 s; what is still pending then is counted `unwritten` and
    logged. Idempotent. A writer dropped without `close`, or open at interpreter exit,
    is still drained. *(Review round 2, P2-3; BUG-0550:)* the exit drain covers every
    writer whose thread started. A writer joins it only once its thread has started, so
    a thread that cannot start ("can't start new thread", which `submit` raises to its
    caller) leaves nothing for the drain to join. One writer whose close fails is
    reported, and the drain goes on to the others. Before, that writer stopped the drain
    ("cannot join thread before it is started") and the writers after it were never
    drained. Enforced by:
    `tests/test_proxy_history_writer_thread.py::test_a_writer_thread_that_cannot_start_never_stops_the_exit_drain`.
    A store the thread cannot open counts every flow and logs an
    error. A caller on an event loop closes with **`aclose(run_end)`**: the drain is
    awaited on a worker thread while the loop runs; a writer with a file store and
    nothing of its own on the caller's connection starts its thread for the close, so
    the run's end and the counters are written there too. The web proxy's `stop` uses
    it.
  - **Stopping and durability** (review round 1): a flow's response goes back before
    the flow is written. Every requested stop drains: `fuzzlab proxy` treats SIGTERM
    (`kill`, the web UI's Stop of a `proxy` job through procutil's supervisor, a service
    manager) as it treats Ctrl-C: the listener closes, then `close` writes every queued
    flow and the run's end `complete`. A hard kill (SIGKILL, the supervisor's after its
    grace, a crash) or a second signal during the drain loses whatever is still queued,
    up to the queue bound; the live counters show `accepted` against `written` as of
    their last rewrite.
  - **Counters** (`run_metrics`, rewritten live: at once on a new drop or failure,
    else at most once a second, and at close): `history_accepted`, `history_written`,
    `history_dropped`, `history_dropped_bytes`, `history_failed`, `history_unwritten`,
    `history_retries`, `history_batches`, `history_max_lag_ms`,
    `history_pending_bytes_peak`.
  - **Measured** (BUG-0550): with +50 ms per store write, p50/p95 latency through the
    proxy went from 433/726 ms to 20/42 ms and the loop's longest stall from 437 ms to
    23 ms; with the store's write lock held 2.0 s elsewhere, the longest stall went from
    2077 ms to 33 ms. No flow was lost in either.
    p95 1.3–2.5 ms without and 5.8–13.4 ms with.
- **FR-PROXY-405** *(kept upstream connections; `CC-PROXY-0029`, 2026-10-21,
  BUG-0549).* `SocketSender` keeps upstream connections between calls, only where reuse
  is provably clean:
  - **One SSL context per sender**, built on first TLS use (it built one per call; with
    the system CA store that is about 21 ms each, measured).
  - **Kept only after an exactly framed exchange.** A connection is left for reuse, per
    (host, port, TLS), only when its request was exactly one well-formed, bodiless
    HTTP/1.1 request (`reusable_request`: a token method other than HEAD or CONNECT;
    CRLF lines, token names, no obs-fold; no `Transfer-Encoding`, `Expect` or `Upgrade`,
    nor a framing header spelled with an underscore, such as `Transfer_Encoding`; no
    `Connection: close`; no NTLM / Negotiate authorization; no body bytes and no
    `Content-Length` but `0`) and its answer exactly one fully framed HTTP/1.1 answer
    (`reusable_response`: a final status; no `Connection: close` or upgrade; no NTLM /
    Negotiate challenge; exactly one `Content-Length` the body matches, or
    `Transfer-Encoding: chunked` alone with a body that is exactly one complete chunked
    body, or a 204 / 304 with no body and no transfer coding), and that answer ended
    exactly at its framed end: nothing read past it (SP-63's leftover, from
    `read_http_response`) and nothing waiting on the socket when it ended (`_quiet`).
    Where the answer ends is SP-63's decision alone; `reusable_response` only narrows
    it to the stricter grammar above. Everything else is closed after its exchange, as
    before: a close-delimited, over-long, short, doubly framed or HTTP/1.0 answer, one
    followed by any byte (a desynchronised upstream answering twice; merge
    integration, BUG-0549), one SP-63 cannot frame (`UpstreamFramingError`), and every
    deliberately malformed request. *(Review round 2:)* the same exact-end rule holds
    for the urllib3 pools of every `requests` session fuzzlab makes for a target,
    the core seam's included. It is decided in SP-60 (FR-CORE-509), because the seam's
    pooling had kept a connection with a stray answer behind it (P2-1, BUG-0549 round
    2).
  - **A body is never kept** *(review round 1)*. A request that carries body bytes, of
    any method, goes on a fresh socket and its connection is closed after it. Whether
    the upstream read the body cannot be observed: one that answers without reading it
    (CL.0) leaves its bytes at the head of the connection's next request, which may be
    another tab's or another browser identity's, and a well-framed answer proves
    nothing about it.
  - **Who takes a kept connection.** Only a request that is itself reusable and
    idempotent (GET, OPTIONS, TRACE, PUT, DELETE), so bodiless. A desync probe (a
    malformed request, or a well-formed one with a body), a POST, a PATCH and a HEAD go
    on a fresh socket; a bodiless POST's (`Content-Length: 0`) may be kept after it.
  - **Checked before use.** A kept connection idle more than `IDLE_SECONDS` (4 s), or with
    anything readable on it (a close, a reset, a stray byte) or a buffered TLS byte, is
    closed instead.
  - **Stale-connection rule.** When a kept connection's peer closed it before any byte
    of answer came (an empty read before the idle timeout, or a reset, broken pipe or
    TLS EOF with no answer byte received; `_Counted` counts them), the request is sent
    once more on a fresh connection. Once a byte of answer came, a reset reaches the
    caller (review round 1: a partial answer was discarded and the request replayed);
    an answer that stalls (SP-63's `UpstreamIncomplete`, reason `idle`) or that a close
    cuts after a byte (reason `eof`) is never resent, and its connection is closed.
  - **The web Repeater keeps fresh sockets** *(review round 1)*. Its sender
    (`web/proxycontrol.py::RepeaterController._writer`) is `SocketSender(...,
    keep_alive=False)`: every tab send opens its own upstream connection, closed after
    it, as audit defect 24 asks for deliberate desync and connection-sensitive probes,
    and no connection state crosses tabs or the identities their cookies carry. The
    proxy engine and `fuzzlab proxy` keep connections as above.
  - **Bounds and lifecycle.** At most `MAX_IDLE_PER_UPSTREAM` (8) idle connections per
    upstream and `MAX_IDLE_TOTAL` (64) per sender, the oldest closed first; expired ones
    are closed at each return. `close()` closes the idle connections (idempotent), as
    does collecting the sender. `keep_alive=False` gives one socket per call.
  - Thread-safe: one lock over the idle connections; a kept connection is used by one
    call at a time.
  - Measured (BUG-0549, loopback, `scripts/measure_pooling.py`): connections per 2 000
    plain GET calls fell from 2 000 to 8 (a call with a body is not kept), and the call rate rose 2.6-7x sequential and
    2-2.6x with 8 threads; over TLS from 20 to 2 750-3 830 calls/s sequential.
  - Enforced by: `tests/test_socketsender_pooling.py::test_well_framed_keep_alive_exchanges_reuse_one_upstream_connection`, `tests/test_socketsender_pooling.py::test_an_exchange_that_is_not_exactly_framed_never_leaves_its_connection`, `tests/test_socketsender_pooling.py::test_a_stale_pooled_connection_is_retried_once_and_a_timeout_never`, `tests/test_socketsender_pooling.py::test_a_body_the_upstream_leaves_unread_never_reaches_the_next_request`, `tests/test_socketsender_pooling.py::test_a_kept_connection_reset_after_part_of_its_answer_is_never_resent`, `tests/test_socketsender_pooling.py::test_bytes_after_a_framed_answer_never_leave_its_connection_kept`, `tests/test_web_repeater.py::test_each_repeater_send_gets_a_fresh_upstream_connection`, `tests/test_socketsender_pooling.py::test_tls_upstream_connections_are_reused_and_the_context_built_once`, `tests/test_socketsender_pooling.py::test_concurrent_exchanges_each_get_their_own_answer_on_reused_connections`, `tests/test_socketsender_pooling.py::test_closing_the_sender_closes_its_idle_upstream_connections`
- **FR-PROXY-400** *(`--record`; `CC-PROXY-0400`, 2026-10-15).* Flow recording stays
  opt-in.
  - `--record` records into the resolved store (FR-CORE-400).
  - `--store PATH` records there, as before; with both, `--store` wins.
  - The `--authorized` and loopback gates run before any store work.
  - `--export-ca` comes before any store resolution. In a dry run, the store is resolved
    before the plan is printed, so a bad `--store` prints no plan.
  - An explicit `--store ""` is now a usage error. It used to mean "do not record".

- **FR-PROXY-401 (request framing, CC-PROXY-0028, BUG-0543; audit defect 18)** The
  listener reads each request whole before it forwards anything, framed by SP-63
  (`proxy/framing.py::MessageReader`, RFC 9112 §6):
  - **The head is parsed once, strictly** (`framing.parse_head`, RFC 9112 §2.2, §5;
    review round 1): it ends at the first CRLF CRLF, and framing reads its fields from
    that same parse. Answered 400: a bare CR or LF anywhere in the head, an empty start
    line, an obs-folded field line, a field line with no colon or a name that is not a
    token (whitespace before the colon included), a NUL in a value. Empty lines (CRLF)
    before the request line are ignored.
  - **Chunked** bodies are parsed: `1*HEXDIG` sizes (extensions after `;`, at most
    8 KiB a line), CRLF after each chunk's data, and the trailer section to its empty
    line. The request is forwarded **de-chunked**: its payload with a `Content-Length` in
    place of `Transfer-Encoding`; the trailer fields are read and dropped (RFC 9110
    §6.5.1). Nothing of it is left on the connection: the next bytes are the next
    request (the CONNECT/TLS keep-alive loop).
  - **Answered 400 and never forwarded:** `Transfer-Encoding` with `Content-Length`; a
    transfer coding other than `chunked` alone; `Transfer-Encoding` on HTTP/1.0; an
    invalid `Content-Length` or conflicting values (identical duplicates are one length;
    `raw_framing` frames conflicting values by the first, FR-PROXY-1); a bad chunk size or
    chunk line; a malformed request line (method a token, one target, `HTTP/1.x`).
  - A request cut by the client's close is dropped, never forwarded in part. A request
    with a body is never forwarded as its head alone.
  - Enforced by: `tests/test_proxy_framing.py::test_a_chunked_request_reaches_the_upstream_whole_and_de_chunked`, `tests/test_proxy_framing.py::test_a_request_that_cannot_be_framed_is_answered_400_and_never_forwarded`, `tests/test_proxy_framing.py::test_raw_framing_forwards_conflicting_lengths_by_the_first_and_nothing_else`, `tests/test_proxy_framing.py::test_the_bytes_after_a_chunked_request_are_the_next_request`, `tests/test_proxy_framing.py::test_the_bytes_after_a_chunked_request_in_a_tunnel_are_the_next_request`, `tests/test_proxy_framing.py::test_every_proxy_http1_read_goes_through_the_framing_owner`
- **FR-PROXY-402 (response framing, CC-PROXY-0028, BUG-0543; audit defect 19)**
  `SocketSender` reads one response framed by SP-63, given its request's method: the
  status line, the headers, then a `Content-Length`, a parsed chunked body (trailers
  included) or a close-delimited body; none for HEAD, 1xx, 204, 304 and a 2xx to
  CONNECT. Interim responses (1xx but 101) are read and passed over, at most 8: the
  proxy holds whole messages, so the final one follows at once, and it is the response
  returned, recorded and relayed. `Transfer-Encoding` with `Content-Length`, an
  invalid `Content-Length`, or a head that fails the strict parse of FR-PROXY-401
  (`parse_head`: a bare CR or LF, obs-fold, a non-token field name; RFC 9112 §5.1/§5.2;
  review round 1) is `UpstreamFramingError` (502).
  - **A response is complete only at its framed end.** A close or an idle receive
    before it raises `UpstreamIncomplete` (reason `eof` / `idle`), never returns the
    bytes; the engine records the flow with no response and that error class
    (FR-PROXY-13) and the client gets a 502. A peer that closes before sending any byte
    returns `b""`: no response (recorded as "connection closed", as before), and the
    client gets a 502.
  - **Bytes past the framed end are no part of the response** (merge integration,
    BUG-0549): `read_http_response` returns them apart from it (SP-63's
    `MessageReader.leftover`); `recv_http_response` returns the response alone. A
    connection that had any is never kept (FR-PROXY-405).
  - **Inside the CONNECT/TLS tunnel too** (review round 1): a failed, cut or unanswered
    upstream is answered `502` with `Connection: close` in the tunnel, then the tunnel
    closes. It is never an empty close, which a browser retries on a reused connection
    (a POST sent twice). The failure is contained and listed in `errors`.
  - A response that ends its connection (close-delimited, a 101, or `Connection:
    close` on either side, `framing.closes_connection`) ends the CONNECT/TLS keep-alive
    loop after it is relayed.
  - Enforced by: `tests/test_proxy_framing.py::test_a_chunk_whose_data_looks_like_the_last_chunk_is_not_the_end`, `tests/test_proxy_framing.py::test_a_response_cut_before_its_framed_end_is_incomplete_never_returned`, `tests/test_proxy_framing.py::test_a_framed_response_ends_at_its_end_not_at_the_idle_timeout`, `tests/test_proxy_framing.py::test_a_response_head_that_does_not_parse_strictly_is_never_relayed`, `tests/test_proxy_framing.py::test_an_incomplete_upstream_response_is_a_502_recorded_as_no_response`, `tests/test_proxy_framing.py::test_a_cut_response_in_a_tunnel_is_a_502_never_an_empty_close`
- **FR-PROXY-403 (inbound bounds, CC-PROXY-0028, BUG-0543; audit defect 20)**
  `AsyncProxyServer(limits=InboundLimits(...))` bounds what clients send while it is
  read:
  - a request head over `max_header_bytes` (default 64 KiB, the upstream head cap) is
    answered 431;
  - a body over `max_body_bytes` wire bytes (default 16 MiB, SP-60's `MAX_WIRE_BYTES`)
    is answered 413: at once for a declared `Content-Length` or chunk size, else as soon
    as the bytes pass it;
  - one request must arrive whole within `request_deadline` seconds (default 60,
    SP-60's `DEFAULT_SECONDS`), else 408; a connection that sent nothing by then (an idle
    keep-alive) is closed;
  - at most `max_connections` client connections (default 64) are served at once; one
    over the cap is answered 503 and closed, never queued. So the upstream calls waiting
    for a worker thread are at most that many.
  - Every refusal answers with `Connection: close` and is counted in
    `AsyncProxyServer.counts` (`refused`, `malformed`, `oversized`, `timed_out`, `idle`);
    `fuzzlab proxy` prints the non-zero counts when it stops.
  - **Configurable:** `fuzzlab proxy --max-connections / --max-request-bytes /
    --max-header-bytes / --request-deadline`; a bound that is not positive is a usage
    error. Worst-case buffered bytes: connections × (head + body + one upstream
    response).
  - Enforced by: `tests/test_proxy_framing.py::test_an_over_limit_request_body_is_answered_413_before_it_is_read`, `tests/test_proxy_framing.py::test_a_dripped_request_is_answered_408_at_its_deadline_and_never_forwarded`, `tests/test_proxy_framing.py::test_a_head_over_its_bound_is_answered_431_while_it_arrives`, `tests/test_proxy_framing.py::test_connections_over_the_cap_are_answered_503_and_counted`, `tests/test_proxy_framing.py::test_every_listener_bound_is_configurable_from_the_cli`

## 4. Non-functional requirements
- **NFR-PROXY-byte-exact** The raw path preserves bytes exactly (no reserializing).
  *(CC-PROXY-0028:)* the listener forwards a request byte-exact except a chunked one,
  which it forwards de-chunked (FR-PROXY-401); a response is relayed byte-exact from its
  final status line to its framed end (FR-PROXY-402).
- **NFR-PROXY-safe** Scope-enforced and lab-only; the local CA never leaves the
  host; credentials/tokens redacted on write.
  - Enforced by: `proxy.scope`, `core.net.require_loopback`, `proxy.ca`, `proxy.history` redaction — `tests/test_proxy_server.py::test_engine_bypasses_out_of_scope_untouched`, `tests/test_proxy_rules_and_scope.py::test_scope_matches_authorities`, `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`, `tests/test_loopback_listeners.py::test_the_proxy_server_itself_refuses_a_non_loopback_bind`, `tests/test_proxy_ca_hardening.py::test_the_real_ca_key_is_0600_from_creation`, `tests/test_proxy_ca_hardening.py::test_the_path_backstop_holds_if_validation_were_bypassed`, `tests/test_proxy_redaction.py::test_no_secret_reaches_any_persisted_copy`, `tests/test_proxy_history.py::test_secrets_redacted_on_write`, `tests/test_proxy_trace.py::test_no_secret_reaches_the_trace_the_model_or_the_exports`, `tests/test_proxy_trace.py::test_an_out_of_scope_host_produces_no_event`
  - Not yet enforced: `Repeater.send` has no scope check; out-of-scope traffic is forwarded to any upstream (scope governs interception and recording only). (BUG-0111 sweep.)
- **NFR-PROXY-nonblocking** History writes are batched and must not stall the data
  path: no store, disk or redaction work runs on the proxy's event loop (FR-PROXY-404;
  built in CC-PROXY-0030, BUG-0550; it had been a deferral since Phase 6).
  - Enforced by: `proxy.history.HistoryWriter.submit`, `proxy.history.HistoryWriter.aclose`, `proxy.server.ProxyEngine._record` — `tests/test_proxy_history_writer_thread.py::test_a_blocked_store_write_never_stalls_proxied_traffic`, `tests/test_proxy_history_writer_thread.py::test_the_loop_parses_only_each_messages_first_line`, `tests/test_proxy_history_writer_thread.py::test_the_proxy_loop_never_calls_store_or_redaction_work`, `tests/test_proxy_history_writer_thread.py::test_stopping_the_web_proxy_drains_its_history_off_the_web_loop`, `tests/test_proxy_history_writer_thread.py::test_no_event_loop_path_blocks_on_a_history_writer`
  - Not yet enforced: the web app's repeater routes run a blocking upstream send and store writes on the web loop that also serves the in-process proxy (`--with-proxy`); pinned by the strict xfail `tests/test_proxy_history_writer_thread.py::test_no_web_handler_runs_a_repeater_send_or_write_on_the_event_loop` (UI component).
- **NFR-PROXY-optional** Nothing in the core pipeline requires the proxy to run.
- **NFR-PROXY-dry-run** `fuzzlab proxy` accepts `--dry-run`: plans and prints the
  exact argv/command it would run and sends nothing (no listener is started, no
  upstream traffic), for headless use outside the web UI. Distinct from
  `--export-ca` (which also sends no traffic but actually writes the CA file);
  `--dry-run` takes priority and performs neither action. Reuses the web
  launcher's dry-run plan/report logic (`fuzzlab/web/commandspec.py` +
  `fuzzlab/web/runner.py`) via the shared `fuzzlab/cli_dryrun.py` helper.
  - Enforced by: `cli_dryrun` — `tests/test_cli_dry_run.py::test_proxy_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_proxy_dry_run_reports_plan_and_sends_nothing`
  - Not yet enforced (exact argv display; BUG-0400, open, the UI lane's fix): the shared display `web/runner.build_flags` mis-serialises `nargs='*'` lists, a bare `const=""` flag and dash-leading values, so for those the printed plan is not the exact argv. Pinned by strict xfails in `tests/test_cli_argv_roundtrip.py`.
  - Not yet enforced: `--dry-run` taking priority over `--export-ca` holds by branch order but is untested. (BUG-0111 sweep.)

## 5. Interfaces and data contracts
Writes `flow` rows (+ raw bytes) to the store, read by the anomaly detector, UI,
and analysis; from the proxy engine, on the history writer's own thread and
connection (FR-PROXY-404), with its counters in `run_metrics` (`history_*`). Writes one `trace_event` (`observe.exchange`, scope `proxy`) per traced
flow through `core.trace.TraceRecorder` (FR-PROXY-13), read by `report.diagram`. Uses the session manager as an addon. Shares `core/` config, budget,
and logging. *(Note, U3/CC-PROXY-0018, 2026-09-22: the web UI's Proxy section was
re-laid on a shared message-editor component and resizable panes — see
`docs/components/12-diagnostics-and-ui/requirements.md`'s FR-UI-9 — purely a
client-side presentation change against these same unchanged `/api/proxy/*`
routes and `flow`/repeater-tab contracts; no interface or data-contract change
here.)*

## 6. Dependencies (components)
`core/`, session manager (attached as an addon).

## 7. Acceptance criteria
- Intercepts and replays HTTP/1.1, HTTP/2, and WebSocket traffic against the lab.
- Raw path reproduces byte-exact requests the parsed path would normalize.
- Flows land in shared history with raw bytes and are searchable; scope is
  enforced; timing-sensitive tool traffic can bypass the proxy.

## 8. Open questions
- TLS trust-store handling for the browser under test.
- History retention/rotation policy for large captures.
- HTTP/2 and WebSocket edge cases in the raw path.
