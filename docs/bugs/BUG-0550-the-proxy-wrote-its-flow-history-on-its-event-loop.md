# BUG-0550 — The proxy wrote its flow history on its event loop, in batches cut by count only

- Date: 2026-10-21
- Status: fixed (lane HIST25, CC-PROXY-0030)
- Severity: medium. The audit rated it PERF_DEGRADATION. In the lab-only proxy, one slow
  or blocked store write stalled every proxied connection for as long as the write
  took (up to SQLite's 10 s busy timeout per statement), and a batch held its raw
  messages whatever their size.

## Description
`ProxyEngine._record` called `HistoryWriter.record` on the event-loop thread. Both
production paths (`fuzzlab proxy --record` and the web proxy) build
`HistoryWriter(batch_size=1)`, so every in-scope flow ran, on the loop: redaction of
both raw messages and their bodies, SHA-256 of each copy, four `body` inserts, the
`flow` and `flow_fts` inserts, the commit, and the trace flush with its reduction and
commit. While any of that waited (another connection holding the store's write lock,
a slow disk), no other connection was served: not other in-scope flows, not the
out-of-scope bypass, not the interception futures. `_record` also read the response's
status through `RawMessage.from_bytes(resp).start_line`, which splits head from body:
a scan and a copy of the whole response on the loop.

Batches were cut by count only (`batch_size`, default 50). A batch held each flow's full
raw messages until written: with 64 MiB responses, about 3.1 GiB before prepared
copies. There was no byte bound, no age bound and no overflow policy.

## Where encountered
The third-party adversarial audit, defect 25 (proxy part): `fuzzlab/proxy/server.py`
148-168 and `fuzzlab/proxy/history.py` 74-95, 142-169 at `6552276` (the same code at
`c483dc1`). The defect's legacy-spider part (`tools/spider.py` 335-359) is lane SPIDER's.

## What it caused to fail
NFR-PROXY-nonblocking ("history writes ... must not stall the data path"), stated
since Phase 6 and never built. Measured with `scratchpad/lanes/HIST25/measure.py` (the
real `AsyncProxyServer` + `ProxyEngine` + `SocketSender` + `HistoryWriter(batch_size=1)`,
the loop on the main thread as `fuzzlab proxy` runs it; 8 loopback clients × 25
requests through the proxy to a loopback upstream; client-side latency from send to
the full response; the loop's longest stall from a 5 ms ticker on the proxy's own loop).
Host load average 8-9 on 4 CPUs (other lanes' test runs), the same for both columns,
which ran back to back:

| store | code | wall | p50 | p95 | max | loop's longest stall | `close` | flows stored |
|---|---|---|---|---|---|---|---|---|
| idle | before | 0.63 s | 21.5 ms | 43.7 ms | 57.0 ms | 32.4 ms | 0.00 s | 200 |
| idle | after | 0.59 s | 22.2 ms | 35.1 ms | 47.7 ms | 16.4 ms | 0.00 s | 200 |
| +50 ms per flow insert (a slow disk) | before | 10.92 s | 432.6 ms | 725.6 ms | 805.3 ms | 436.5 ms | 0.00 s | 200 |
| +50 ms per flow insert | after | 0.56 s | 20.4 ms | 42.4 ms | 52.7 ms | 23.0 ms | 9.83 s | 200 |
| write lock held 2.0 s by another connection | before | 2.99 s | 28.7 ms | 137.7 ms | 2099.6 ms | 2076.5 ms | 0.00 s | 200 |
| write lock held 2.0 s | after | 0.59 s | 17.5 ms | 57.1 ms | 69.0 ms | 33.3 ms | 0.18 s | 200 |

Before: the proxy's throughput was the store's (200 × 50 ms ≈ 10 s), and a lock held
elsewhere froze the loop for the whole hold. After: latency is the idle store's in both
cases; the store's time moves to the writer thread (the slow store's backlog is written
by `close`, 9.83 s, in order, all 200 flows, `batches` 3: group commits). An earlier run
of the same script showed a 1.04 s maximum in every row, before and after alike: the
loopback upstream's `listen` backlog of 5 dropping SYNs (one 1 s retry); the script now
sets 128 and those rows are not reported.

## What the bug was identified to be
1. Synchronous store and redaction work on the event loop (`_record` → `record` →
   `flush`), and a whole-message parse there.
2. A batch bounded by count only: no bytes, no age.
3. No overflow or failure policy: a write that failed raised into the proxied
   connection's handler (a 502 for that client), and nothing bounded what waited.

## Root cause analysis
Five Whys.
1. *Why did one slow write stall every connection?* `_record` ran `HistoryWriter.record`,
   and with `batch_size=1` its `flush`, on the loop thread.
2. *Why was the store write on the loop?* The engine was written sans-I/O with history
   as its last step. When BUG-0101 moved the blocking sender off the loop, its corrective
   action stated "History recording stays on the loop thread" (also FR-PROXY-12), and
   `history.py`'s docstring deferred the real off-load: "the true async offload is
   on-host, but the batching seam ... built and tested here".
3. *Why was that accepted?* PA-0102(3) ("Blocking I/O never runs on an event loop") was
   read as network I/O: BUG-0101's sweep listed network reads only
   (`_read_http_message`, `h2client`/`ws`, the senders), and its only enforcement test
   checks the sender. The one measurement of the history write (CC-PROXY-0025: median
   ~1.4 ms, p95 up to 13.4 ms per flow) was taken on an idle store; nobody measured a
   slow or a busy one.
4. *Why can a store write take seconds?* The project store is shared (D5): scans, the
   web UI and the proxy write it, SQLite admits one writer, and a connection waits up to
   its busy timeout (10 s) for the lock, then retries the next statement.
5. *Why count-only batches?* The batching seam was built for the commit shape (one
   commit per flush, BUG-0106), not for memory or latency; with no thread of its own the
   writer had no place for an age trigger.

**Root cause:** a non-functional requirement (NFR-PROXY-nonblocking) was left as a
deferral: store work was kept on the proxy's loop on an unmeasured belief that a store
write is short, and the rule against blocking I/O on an event loop (PA-0102(3)) was
swept and enforced for network reads only.

## Corrective action
CC-PROXY-0030 (lane HIST25; FR-PROXY-404, NFR-PROXY-nonblocking traced):
- **`HistoryWriter.submit`** (new): bounded work on the calling thread. It admits the
  flow into a queue and returns. The first call starts the writer's own thread, which
  opens its **own** `Store` on the writer's file (`create=False`; a SQLite connection is
  thread-affine, PA-0023; never a `to_thread` of the caller's connection) and does every
  redaction, hash, insert, commit and trace event there, in submission order.
- **Batches** are cut by count (`batch_size`), bytes (`flush_bytes`, 4 MiB) or age
  (`flush_seconds`, 0.5 s), whichever comes first, or at once for a `flush`/`close`. One
  transaction holds at most `BATCH_MAX_FLOWS` (500) flows and `flush_bytes` plus the
  flow that crosses it. Under load the thread takes everything waiting (group commit).
- **The queue** is bounded by flows (10,000) and bytes (256 MiB) waiting or being
  written. One flow larger than the byte bound is admitted only into an empty queue. A
  flow that does not fit is dropped from the history, never from the traffic: counted
  (`stats`: `dropped`, `dropped_bytes`), logged, and written to `run_metrics`
  (`history_*`) at once, while the run is live.
- **A failed batch** is tried 3 times (0.2 s, 0.4 s apart), then counted `failed` and
  logged; the writer goes on. `HistoryWriter._write` now also rolls back a failed
  commit (the transaction the write opened), so a retry never duplicates a flow
  (PA-0107(2) carried to the commit).
- **`flush`** waits until everything submitted before it is written; **`close`** writes
  everything still pending, records the run's end and the counters (`trace_*`,
  `history_*`) on the thread's connection, and stops, within `CLOSE_TIMEOUT` (60 s);
  what is left after that is counted `unwritten` and logged. A writer dropped without
  `close` is still drained (`weakref.finalize`), and so is one open at interpreter exit
  (`atexit`). A store the thread cannot open (an in-memory store; a removed file) makes
  every flow counted and an error logged.
- **`ProxyEngine._record`** calls `submit`, and reads the method, target and status
  from each message's first line only (`server._first_line_of`, which equals
  `RawMessage.start_line` on every line-end shape).
- **`record`** stays synchronous for the repeater and tests, now also cut by
  `flush_bytes`; once a writer has a thread, `record` hands over to it too (one writer of
  a run's flows).
- Callers unchanged: `fuzzlab proxy` closes the writer after its loop ends; the web
  proxy's `stop` closes it after the server stopped (a drain on the web loop at
  shutdown, bounded; see residuals).
- Tests: `tests/test_proxy_history_writer_thread.py` (16 tests, 28 cases; 20 of them
  fail on the pre-fix code, CC-PROXY-0030's effectiveness); `test_proxy_trace.py` waits for
  the thread where it read the store straight after a request, and closes its fixture's
  writer; `test_proxy_rules_and_scope.py`'s fake history gains `submit`.

## Recurrence review
Checked `docs/bugs/` for event loop, blocking, batch, flush, history, writer, queue,
backpressure, drop, and `docs/PREVENTIVE_ACTIONS.md` for PA-0012, PA-0023, PA-0095,
PA-0102, PA-0107, PA-0112, PA-0128, PA-0135, PA-0516.
- **BUG-0101 / PA-0102(3): the same class.** Blocking I/O in the proxy engine's
  coroutine; BUG-0101 fixed the sender and explicitly kept the history write there.
  A recurrence of the root cause one call further down the same coroutine.
- **BUG-0106 / PA-0107:** the same writer's atomicity. Not a recurrence, but the off-loop
  writer's retries depend on it, and a failed commit was a gap (fixed here).
- **BUG-0111, BUG-0112 / PA-0112:** NFRs specified and never built. The same shape
  (NFR-PROXY-nonblocking), but PA-0112 traces SAFETY NFRs only, and this one is
  classified "performance".
- The disco capture recorder (`disco/recorder.py`) applied PA-0102(3) to mitmproxy's
  hooks (one writer thread, a bounded queue, drops counted), so the rule was known and
  applied in a neighbouring capture path, but not swept back to the proxy.

## Prior-preventive-action failure analysis
**PA-0102(3) (BUG-0101) did not prevent this. Its sweep was too narrow, it was not
enforced beyond one call, and the exception it allowed was not measured.**
- *Too narrow:* BUG-0101's sweep enumerated network reads. The store write in the same
  coroutine was kept on the loop by name ("History recording stays on the loop thread"),
  so the rule was read as "network I/O", not "anything that can wait".
- *Not enforced:* `test_a_slow_sender_does_not_block_the_event_loop` covers the sender
  only; nothing failed when any other blocking call ran in the engine's coroutines.
- *Unmeasured:* the decision rested on idle-store timings (CC-PROXY-0025); a slow or busy
  store, the case the rule exists for, was never measured.
- **PA-0112 (BUG-0111/0112)** is the wrong layer here: it makes SAFETY NFRs traced to
  tests, and NFR-PROXY-nonblocking is NOT_SAFETY, so a deferred performance NFR carried
  no `Enforced by:` line and no test.

## Preventive action
**PA-0550** (strengthens PA-0102(3) and PA-0107; applies PA-0516(2) and PA-0023):
1. Blocking work on an event loop includes store and disk work (SQLite statements and
   commits, file writes) and work that grows with a message (redaction, hashing, parsing
   a body), not only network reads. A loop path does bounded work per message and hands
   the rest to a thread it owns; a thread-affine store connection is owned by one writer
   thread, never moved into `to_thread`.
2. A writer that buffers bounds what it holds by count, bytes and age, and states its
   overflow policy: backpressure, or drops counted, logged and written to the store while
   the run is live. A batch that cannot be written is retried a bounded number of times
   and counted; `close` drains within a stated timeout and counts what it could not.
3. Work kept on a loop because it is believed short cites a measurement against a slow
   and a busy dependency, not only an idle one.
4. A deferred non-functional requirement carries a test or a `Not yet enforced:` line in
   its `requirements.md`, whatever its class.

Enforced by the tests named in PA-0550's line: a write held on the writer thread while
two more requests are answered and nothing runs on the loop thread; a first-line-only
parse checked by the bytes `_split_head_body` sees; an AST guard over
`fuzzlab/proxy/server.py` (only `history.submit`; no store, flush, commit or redaction
call), proven on six synthetic offenders including the pre-fix line; the drop counters,
log and live `run_metrics`; a failing batch retried, counted and logged; close in order.

**PA-0002 sweep (by mechanism: every event-loop path in `fuzzlab/` that does store, disk
or message-sized work).** `grep -l "async def"` over `fuzzlab/`, each checked:
- `proxy/server.py`: fixed here (the engine's history write and parse).
- `proxy/cli.py::_serve`: no store work inside the coroutine; the writer is built before
  and closed after `asyncio.run`. Clean.
- `proxy/intercept.py`: awaits futures only. Clean.
- `web/proxycontrol.py::ProxyController.stop`: closes the writer (a drain) on the web
  loop, after the proxy server stopped, at lifespan shutdown only. No proxied traffic is
  stalled; the web loop waits up to `CLOSE_TIMEOUT`. Stated residual (UI component).
- `web/app.py` repeater routes: async on purpose (`RepeaterController` keeps a per-thread
  store), so `repeater_send` runs a blocking upstream send (up to its deadline) and a
  store write, and `repeater_create`/`repeater_from_flow`(`_prg`) store writes, on the
  web loop, which also serves the in-process proxy under `--with-proxy`. **Known, not
  fixed here (UI component's files); pinned by the strict xfail
  `tests/test_proxy_history_writer_thread.py::test_no_web_handler_runs_a_repeater_send_or_write_on_the_event_loop`**
  (PA-0531(4)).
- `web/app.py`, `web/projects.py`, `web/projectroutes.py` read-only handlers: SQLite
  reads under WAL do not wait for writers; not this class. Not changed.
- `web/runner.py`, `web/labcontrol.py`, `procutil.py`: subprocess and stream handling,
  no store work. Clean.
- `disco/recorder.py` (mitmproxy hooks, not `async def`): already one writer thread with
  a bounded queue, drops counted (count-bounded only: audit defect 22, another lane).

**Shared mechanism (PA-0507(2)).** The disco recorder's writer queue and this writer
thread decide the same thing (how an event-loop producer hands records to one writer
without blocking), and lane SPIDER's part of defect 25 may add a third. Not registered
as a shared primitive here, to keep this lane out of other lanes' files; flagged to the
orchestrator to choose one owner after the merges.
