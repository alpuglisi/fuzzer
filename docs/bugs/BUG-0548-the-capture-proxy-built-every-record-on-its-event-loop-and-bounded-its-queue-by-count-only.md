# BUG-0548 — The capture proxy built every record on its event loop, and bounded its queue by record count only

- Date: 2026-10-21
- Status: fixed (CC-CRAWL-0058), with stated residuals
- Severity: medium. The audit rated defect 22 PERF_DEGRADATION. Measured: a 1 MiB JSON
  response held mitmdump's loop, and with it every browser request in flight, for a
  median 104 ms (129 ms in a repeat); the loop stalled for up to 626 ms (944 ms). The
  queue's bound in records allowed gigabytes of backlog, and a full queue dropped
  observations.

## Description
`fuzzlab disco capture` sends the browser through mitmdump running
`fuzzlab/disco/recorder.py`. mitmproxy calls an addon's hooks on the one asyncio loop
that carries every proxied request.

At the base (c483dc1), `Recorder.response` / `error` / `websocket_message` called
`capture.make_record` in the hook. It did:
- `req.get_content()` / `res.get_content()`: mitmproxy decodes the whole body per
  `Content-Encoding`, without a ceiling;
- `redact_headers`, `redact_url`, and `redact_body` on each whole body (a JSON body is
  parsed, walked and re-serialised);
- a UTF-8 decode and the 200 000-character cut.

Only then did it `_enqueue` the record to the writer thread, which serialised it
(`to_json`) and appended it. The recorder's own docstring claimed "Hooks never block
the event loop (PA-0102(3))".

The queue was `queue.Queue(maxsize=10_000)`: bounded in records, not bytes. Each record
could hold two 200 000-character bodies plus unbounded headers and URL. A full queue
dropped the record (counted).

Found while fixing:
- A refusal's stats refresh was a queue item. On a full queue it was counted as a
  dropped record.
- Once the work moves to the writer, the shutdown drain lasts as long as the writer's
  backlog. `proxyproc.stop` gave mitmdump procutil's default 5 s grace before the kill,
  so a backlog and the final stats would be killed uncounted.
- With the work on a thread, the loop still waited for the GIL: up to CPython's 5 ms
  switch interval at each wake-up (measured below).
- Chromium asks the target for `zstd` through the proxy (measured, even to a
  plain-http loopback origin). SP-60 has no bounded `zstd` decoder, so a bounded
  decode would lose those bodies.

## Where encountered
The external adversarial audit at 6552276 (defect 22, `recorder.py` lines 37-38,
120-126, 169-179; `capture.py` lines 91-102, 126-148). Re-located at c483dc1:
`capture.py` had since gained BUG-0536's `JsonlTail`; the hand-off was unchanged.
Reproduced at c483dc1 by the tests below, and measured on a loopback page.

## What it caused to fail
**Measurement.** The script is in the lane's scratchpad (`tools/measure.py`,
`tools/timed_recorder.py`). The page and its server are a ThreadingHTTPServer on
127.0.0.1 that this script starts. The page fires N POST fetches (2 KiB JSON body
with a `password` field), with C at a time. Each answer is a gzip JSON list of user
objects with `password` fields.
- The proxy is a real mitmdump with the tree's own `Recorder`, wrapped to time each
  hook on the loop, plus a 2 ms asyncio sampler of loop lag.
- The browser is a real headless Chromium through the proxy (loopback not bypassed).
- Before = c483dc1's `fuzzlab/` (git archive); after = this change. Every pair ran
  back to back on the same host, under the same concurrent load from other lanes'
  pytest runs.
- "No recording" is the same mitmdump with the hook a no-op.
- The "after" column is the committed code. The "repeat" column is an earlier pair,
  taken with the same design at an earlier revision of its waiting line (turn
  counters in place of the data line), under heavier load.
- Result files: `scratchpad/lanes/DISCO22/measure/G-*-result.json` (final) and
  `F-*-result.json` (repeat, and no recording).

| Scenario | Metric | Before | After | Repeat: before / after | No recording |
|---|---|---|---|---|---|
| A: 1500 x 64 KiB (30 KB gzip), C=32 | response hook, median / p99 / max (ms) | 7.44 / 20.5 / 115 | 0.17 / 3.71 / 16.2 | 6.76 / 24.6 / 147 -- 0.116 / 2.29 / 11.6 | 0.005 / 0.04 / 0.6 |
| | hook time on the loop, total (s) | 13.1 | 0.44 | 12.6 -- 0.28 | 0.01 |
| | loop lag, median / p99 / max (ms) | 13.6 / 67.8 / 138 | 2.57 / 38.9 / 103 | 7.06 / 74.7 / 215 -- 1.26 / 34.4 / 115 | 0.36 / 11.8 / 83 |
| | page requests/s | 71.7 | 85.9 | 72.5 -- 75.6 | 103.4 |
| | records/s (first response to last record) | 71.7 | 71.8 | 72.4 -- 75.6 | -- |
| | records written / lost | 1501 / 0 | 1501 / 0 | 1501 / 0 -- 1501 / 0 | -- |
| B: 200 x 1 MiB (469 KB gzip), C=16 | response hook, median / p99 / max (ms) | 104 / 184 / 201 | 0.19 / 0.63 / 5.47 | 129 / 324 / 440 -- 0.150 / 0.45 / 1.08 | -- |
| | hook time on the loop, total (s) | 22.5 | 0.051 | 28.4 -- 0.033 | -- |
| | loop lag, median / p99 / max (ms) | 0.28 / 467 / 626 | 1.40 / 18.3 / 88 | 0.18 / 739 / 944 -- 1.30 / 17.8 / 82 | 0.17 / 19.4 / 48 |
| | page requests/s | 8.4 | 10.7 (paced by backpressure) | 6.5 -- 11.5 | 89.8 |
| | records/s | 8.4 | 7.4 | 6.6 -- 7.8 | -- |
| | records written / bodies omitted | 201 / 0 | 201 / 0 | 201 / 0 -- 201 / 0 | -- |
| | last record after the page finished (s) | 0 | 8.2 (the backlog's drain) | 0 -- 8.5 | -- |

**Intermediate measurements (they shaped the fix):**
- **The work on a thread alone (no switch interval).**
  - Scenario A: hook median 0.11 ms, but loop lag median 6.1 ms and p99 58.6 ms, and
    76.7 requests/s (before: 79.9).
  - With `sys.setswitchinterval(0.001)`: loop lag median 2.2 ms, p99 22.5 ms, and
    96.4 requests/s. With 0.0005: 1.6 / 28.5 ms, 90.7 requests/s.
- **The work on a thread with a byte budget but no backpressure** (scenario B):
  - 92 of 201 bodies were omitted for the backlog;
  - 94 records were still queued when the 10 s drain ended, so they were never
    written.
  - Backpressure and the drain and grace below fix both.
- **Accept-Encoding seen by the server:** `gzip, deflate, br, zstd` before;
  `gzip, deflate, br` after.

Reproduced at c483dc1 by the tests. All 13 new or changed tests ran once, in one
invocation, with c483dc1's `capture.py`, `recorder.py` and `proxyproc.py` in place, and
all 13 failed (`scratchpad/lanes/DISCO22/prefix_proof.log`):
- the hook ran `redact_body` twice on the loop's thread (`['redact', 'redact']`);
- the guard found `make_record` and its redaction reached from `Recorder.response`,
  `error` and `websocket_message`;
- a stats refresh on a full queue was counted as a dropped record (`dropped` 1);
- a record that could not be built raised `RuntimeError` out of the hook;
- the request kept `zstd`;
- `proxyproc` passed no `grace` (procutil's 5 s);
- the byte budget, backpressure, the body ceiling and the switch interval did not exist
  (`QUEUE_MAX_BYTES`, `BACKPRESSURE_WAIT_S`, `MAX_CAPTURE_BODY_BYTES`,
  `SWITCH_INTERVAL_S` missing).

## What the bug was identified to be
- **The hand-off sat after the work, not before it.** Only the append was off the
  loop. The decoding, redaction and record building, whose cost grows with the body,
  ran in the hook.
- **A queue bounded in the wrong unit, with no pacing.** A record-count bound does not
  bound bytes, and a full queue dropped observations rather than slowing the browser.
- **An unbounded decode of a target's body.** mitmproxy's `get_content` decodes whole,
  and it sat outside SP-60 (BUG-0536).
- **A miscount.** A stats refresh shared the record queue and its drop counter.

## Root cause analysis
Five Whys:
1. *Why did a large response stall every browser request?* The recorder's hook decoded,
   redacted and built the record on mitmproxy's loop before queueing it.
2. *Why was the work in the hook?* The design (CC-CRAWL-0031) read PA-0102(3), "Blocking
   I/O never runs on an event loop", as "move the file write off the loop". The
   redaction boundary (`make_record`, SP-35) was called where the exchange was
   observed: "redacted before it exists" was taken to mean "redacted in the hook".
3. *Why did no check catch it?* PA-0102's enforcement is three tests of the native
   proxy (`tests/test_proxy_upstream_and_flush.py`). Nothing looked at a mitmproxy
   addon's hooks, and nothing measured the capture proxy's loop.
4. *Why was the queue bounded by count, dropping when full?* A count is the parameter
   `queue.Queue` takes. The record's size and the writer's pace were never measured.
   With the work in the hook, the loop's stall throttled the browser implicitly and
   hid the question.
5. *Why did BUG-0536's sweep not find the unbounded decode?* PA-0536(1) owns "reading a
   target's HTTP body", and its sweep and guard enumerate `requests` readers. The
   capture proxy receives target bodies through mitmproxy, a different library, and
   decoded them with `get_content`.

**Root cause:** the event-loop rule (PA-0102(3)) was worded for blocking I/O and
enforced at the native proxy only. Work whose cost grows with untrusted input (body
decoding, redaction, serialisation) was not recognised as loop-blocking. No guard
covered the other proxy in the codebase. The queue that should carry that work off the
loop was sized by a parameter nobody measured.

## Corrective action
(CC-CRAWL-0058.)
- **The hook takes, the writer works.**
  - `capture.snapshot` builds a `HeldExchange`: the header pairs (mitmproxy's immutable
    `fields`) and each body as sent (`raw_content`), by reference, with its byte
    `size`. A body over `MAX_CAPTURE_BODY_BYTES` (8 MiB, = `MAX_REDACT_BYTES`) is not
    held; only its length is read.
  - The writer runs `capture.build_record`. Each body is decoded through SP-60's
    `read_body` (an in-memory `read1` stream) under that ceiling. Then `make_record`
    (redaction, cut), `to_json` and `append_record` run on the writer.
  - A body not captured whole is recorded as `null`, `*_truncated: true`: fail closed,
    PA-0455, since redaction needs the whole body.
  - Failures on the writer are contained, logged and counted `dropped`.
- **Bounded in records and bytes, with backpressure.**
  - `QUEUE_MAX` (10 000 records) and `QUEUE_MAX_BYTES` (32 MiB held).
  - An exchange that does not fit joins a line. Its hook returns an awaitable, which
    mitmproxy awaits: the flow waits and the loop runs on. Every later exchange waits
    behind it, so records keep their order.
  - The line is data, moved by every offer and every waiter, so a waiter that is never
    resumed holds no one back.
  - After `BACKPRESSURE_WAIT_S` (30 s) the exchange is queued without its bodies
    (`omitted.backlog`), or dropped. A waiting exchange whose flow is cancelled is
    `dropped`. At shutdown the line is handed to the writer: its exchanges are
    complete, and only the browser was held back.
  - The stats file gains `omitted` {`too_large`, `backlog`, `undecodable`}, `waited`
    and `queued`.
- **The stats refresh** is a flag and a wake-up item, never counted as a record.
- **`Accept-Encoding`** is narrowed per request to what SP-60 can bound
  (`bodyread.advertise`).
- **The GIL:** `Recorder.running` sets mitmdump's switch interval to 1 ms
  (`SWITCH_INTERVAL_S`).
- **Shutdown:** the recorder drains for `DRAIN_TIMEOUT_S` (30 s) in all.
  `proxyproc.STOP_GRACE_S` (45 s) is passed as procutil's `grace`, so the kill comes
  after the drain and the final stats. What is unwritten then is `queued` in them.
- **Tests:**
  - `tests/test_disco_capture.py`, 11 new and 1 changed:
    - the work runs on the writer's thread;
    - backpressure is lossless and ordered;
    - the bounded wait omits bodies, counted;
    - a waiter never resumed holds no one back, and the line is written at shutdown;
    - a cancelled waiter is counted and holds no one back;
    - too large, gzip bomb and `zstd` bodies are recorded without them, counted;
    - a stats refresh is never a drop;
    - a build failure is contained;
    - the switch interval;
    - the stop grace;
    - `Accept-Encoding`;
    - the full-queue test, changed for backpressure.
  - `tests/test_capture_hook_guard.py`, an AST guard: no per-flow hook of any
    `fuzzlab` mitmproxy addon reaches body or record work, followed through `self`
    methods and package functions. It is proven on synthetic offenders: the pre-fix
    shape, a helper and module-function chain, an imported `fuzzlab` function, and a
    clean writer-thread shape.

**Residuals (stated):**
- **R1, the writer shares the GIL.** After the fix, scenario A's loop lag p99 is
  38.9 ms (34.4 ms in the repeat) against 11.8 ms with no recording, at 85.9 (75.6)
  against 103.4 requests/s. The
  remaining cost is the writer's CPU (redaction and serialisation, the same work as
  before) competing for one interpreter. A separate writer process would remove it.
  That needs procutil to own a piped child of mitmdump, its crash and restart
  handling, and the stats aggregated across processes. It was not built.
- **R2, the writer's throughput is unchanged** (about 128 ms per 1 MiB JSON record).
  Under a body-heavy burst the browser is paced to it, which is the design. Where the
  writer stays behind past 30 s, bodies are omitted and counted.
- **R3, the drop counts reach the stats file and `explore.json`, not synthesis.** The
  records themselves say `*_truncated`. The CLI summary does not yet print `dropped`
  or `omitted` (`disco/cli.py` is outside this lane), and `synth` does not read the
  proxy's stats.
- **R4, a target body over 8 MiB** is now omitted, where before a non-JSON body (HTML,
  JS) was kept as its first 200 000 characters. Such a body cannot be redacted whole
  (PA-0455), and redaction already omitted JSON, form and multipart bodies over
  8 MiB.

**Sweep (PA-0002), by class: work that grows with untrusted input on an event-loop or
callback path:**
- **The native proxy** (`fuzzlab/proxy/server.py`, `proxy/history.py`): history
  recording runs on its loop, with count-only batches. Same class; it is audit defect
  25, another item, so it is flagged and not changed here.
- **Playwright event callbacks:**
  - `disco/explore.py::_on_response` keeps the response and reads it later ("never in
    the handler").
  - `explore._on_request` and `spider._on_request` read post data; the spider reads a
    64 KiB slice.
  - `navguard`, `netquiet`, `browserexec` and `fetcher` count or append URLs only.
  - None decodes or redacts a body in a callback.
- **Other mitmproxy addons in `fuzzlab/`:** none (the guard enumerates them).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for work on an event loop, queues
bounded in the wrong unit, and unbounded body decoding:
- **BUG-0101 / PA-0102:** event-loop-blocking, unbounded upstream reads in the native
  proxy. PA-0102(3) is the rule this recorder cited and broke. **Same root cause:**
  this is a recurrence.
- **BUG-0536 / PA-0536:** bounds checked on the finished artefact, and one owner for
  reading a target's body (SP-60). The capture proxy's whole-body decode is that class
  outside its sweep. **Same root cause:** a recurrence.
- **BUG-0094 / PA-0095, BUG-0135 / PA-0135:** complexity on per-flow paths. The hook's
  cost grew with the body (linear, not quadratic). Related; it is the per-flow path
  PA-0095(2) names.
- **BUG-0085 / PA-0086(2):** per-unit handlers contain their failures. It now applies to
  the writer thread, since the work moved there.

## Prior-preventive-action failure analysis
- **PA-0102(3) (BUG-0101), "Blocking I/O never runs on an event loop":**
  - **Too narrow.** It names I/O. A CPU-bound step whose cost grows with untrusted
    input (decompression, a JSON parse and re-dump, serialisation) blocks the loop the
    same way, and the recorder's author read the rule as satisfied once the file write
    moved to a thread. The docstring cited the rule.
  - **Not enforced where it applied.** Its tests exercise the native proxy only;
    nothing enumerated other event-loop code, so a second proxy (mitmproxy addons,
    added later by CC-CRAWL-0031) was never checked.
  - **Not measured.** No one timed the hook or the loop.
- **PA-0536(1) (BUG-0536), "Reading a target's HTTP body has one owner":**
  - **Wrong layer for its sweep.** The sweep and its AST guard enumerate `requests`
    sessions. A body that reaches fuzzlab through another library (mitmproxy's flow,
    decoded by `get_content`) is a target body read whole, and it was missed.

## Preventive action
**PA-0548** (strengthens PA-0102(3) and PA-0536(1)), recorded in
`docs/PREVENTIVE_ACTIONS.md`:
1. **An event-loop or callback path does no work whose cost grows with untrusted
   input** (decoding, decompression, redaction, parsing, serialisation, hashing,
   writing). It takes references and hands off. The hand-off comes before the work,
   and a claim that a hook does not block is backed by a measurement of the hook and
   of the loop.
2. **Every proxy hook in the package is enforced by a guard.** No per-flow hook of a
   `fuzzlab` mitmproxy addon reaches body or record work, followed through the class
   and the package's functions. A new addon module is enumerated automatically.
3. **A queue that carries work off a loop is bounded in the unit that costs: bytes,
   and records.** Past its bound it paces the producer without blocking the loop (an
   awaitable, an order-keeping line). A loss only comes after a bounded wait, and it is
   counted where the run's operator reads it. A consumer that waits for the drain (a
   stop's grace) waits longer than the drain.
4. **A target body that arrives through any library is decoded through SP-60** under a
   ceiling. Every request advertises only codings SP-60 can bound. PA-0536(1)'s sweep
   is by what is read (a target's body), not by the library it arrives through.
