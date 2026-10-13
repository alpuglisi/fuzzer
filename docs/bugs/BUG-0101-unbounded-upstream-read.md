# BUG-0101 — Upstream response reads were unbounded, quadratic and blocked the event loop

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0021)
- Severity: medium. The audit rated it High. In the lab-only proxy, a peer that
  streams without end could exhaust memory and CPU and stall every other connection.

## Description
`recv_http_response` had no byte cap and no overall deadline (only a per-read idle
timeout). It called `_body_complete(head, bytes(body))` per received chunk, copying the
whole body each time. Copy volume was 8.9 M / 34.6 M / 136 M / 541 M bytes for 1 / 2 /
4 / 8 MiB bodies, quadratic. `ProxyEngine.handle_request`, a coroutine, called the
blocking sender inline, so a slow upstream blocked the event loop.

## Where encountered
A third-party audit (finding #5), reproduced with `scratchpad/ext2/f05_recv.py`.

## What it caused to fail
NFR-PROXY-nonblocking; the proxy's availability.

## What the bug was identified to be
An unbounded read loop that re-copied its buffer, run synchronously inside async code.

## Root cause analysis
1. *Why quadratic?* `bytes(body)` sat inside the loop.
2. *Why unbounded?* The lab-only assumption "upstreams are well behaved" was never
   checked.
3. *Why blocking?* The engine was written sans-I/O, and the real sender was plugged in
   without offloading it.
4. *Why not caught?* PA-0095's sweep looked for counting patterns, not
   re-materialising copies, and no test bounded the read.

**Root cause:** no resource bounds on a network read path, and no rule against blocking
I/O in coroutines.

## Corrective action
- **One growing `bytearray`.** `_body_complete` reads `len` / `endswith`, with no copy.
- **Bounds:**
  - headers ≤ `MAX_HEAD_BYTES` (64 KiB);
  - body ≤ `max_body` (64 MiB);
  - a monotonic overall deadline (`timeout × 4`).

  Breaching any of them raises `UpstreamResponseError`, which per-connection
  containment answers with a 502.
- **Configurable** through `SocketSender(max_body=, deadline=)` and `fuzzlab proxy
  --max-response-bytes / --response-deadline`. FR-PROXY-12 states that they cut off
  long-lived streams.
- **Off the event loop.** Both sender calls run under `await asyncio.to_thread(...)`.
  `SocketSender` is stateless, and the default executor allows min(32, CPUs + 4)
  concurrent calls. History recording stays on the loop thread.
- **Tests** (`tests/test_proxy_upstream_and_flush.py`):
  - one buffer, never re-copied, at 8 MiB;
  - the body, header and deadline caps;
  - the bounds are configurable;
  - a slow sender doesn't block a second request on the same loop.

## Recurrence review
- **BUG-0094 / PA-0095:** quadratic work on a per-unit path. A recurrence of the class.

## Prior-preventive-action failure analysis
**PA-0095 was followed for the pattern it named, but its sweep was too narrow.** Its
sweep searched for counting inside loops, not for copying a buffer inside a loop. Its
operation-count rule was never applied to the proxy read path.

## Preventive action
- **PA-0102:**
  1. Network reads have a byte cap and an overall deadline.
  2. Accumulation never re-copies the buffer inside the read loop (`bytes(buf)` in a
     loop is the swept pattern).
  3. Blocking I/O never runs on an event loop.

**Sweep:**
- `server._read_http_message`: asyncio readers, with a stated limit;
- `h2client` / `ws`: frame reads are length-prefixed;
- greybox, probe and tool senders: `requests` with timeouts, outside asyncio.
