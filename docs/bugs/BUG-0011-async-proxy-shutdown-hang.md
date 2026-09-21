# BUG-0011 — Async proxy shutdown hangs on `wait_closed()` (live connections)

- Date: 2026-09-21
- Status: fixed
- Severity: medium (the proxy / `scripts/proxy_e2e.sh` hang on stop; no data loss)

## Description
`AsyncProxyServer.stop()` called `self._server.close()` then `await
self._server.wait_closed()` unconditionally. On Python 3.12+, `asyncio.Server.wait_closed()`
waits for **all active connections** to finish, not just for the listener to close. A
keep-alive / still-open client connection therefore makes `wait_closed()` block
indefinitely, so the proxy never exits on Ctrl-C / SIGINT and
`scripts/proxy_e2e.sh` hangs at its shutdown step.

## Where encountered
On the host: `scripts/proxy_e2e.sh` "has been hanging at 5/6 for a long time" — the step
that stops the proxy (`kill -INT` + `wait`) never returned because the proxy process was
stuck in `wait_closed()` during its shutdown `finally`.

## What it caused to fail
`fuzzlab proxy` would not exit cleanly on Ctrl-C when any connection lingered, and the
Part I script's `wait "$PROXY_PID"` blocked forever. No data was lost (flows persist), but
the run never completed.

## What the bug was identified to be
The teardown relied on `wait_closed()` returning promptly after `close()`. Under the
Python 3.12+ semantics it does not: it also awaits active connection tasks, which for a
proxy (keep-alive, or a connection mid-handling) may never end on their own. The
per-connection tasks spawned by `asyncio.start_server` were also untracked, so `stop()`
had no way to end them.

## Root cause analysis
Five Whys:
1. Why did the script hang? `wait "$PROXY_PID"` never returned — the proxy didn't exit.
2. Why didn't it exit? Its shutdown `finally` blocked in `await server.stop()`.
3. Why did stop() block? `await self._server.wait_closed()` waited on active connections.
4. Why did that wait never end? A lingering connection task kept the server "not closed";
   nothing cancelled in-flight connection tasks.
5. Why not caught in tests? The offline tests open a connection, exchange one message, and
   close it before `stop()`, so no connection lingered — the 3.12+ `wait_closed()` blocking
   behavior was never triggered.

**Root cause:** shutdown assumed `wait_closed()` completes once the listener closes, but on
Python 3.12+ it blocks on active connections, and the server never cancelled the
connection tasks it spawned.

## Corrective action
- `AsyncProxyServer` tracks its per-connection tasks (`self._conns`); `_on_client`
  registers/deregisters itself and treats `CancelledError` as a clean drop.
- `stop()` now `close()`s the listener, **cancels** all tracked connection tasks, and
  awaits `wait_closed()` under `asyncio.wait_for(..., timeout=3.0)` so teardown is bounded
  regardless.
- The proxy CLI writes flow history with `batch_size=1` (WAL) so records persist per
  request and shutdown timing can never lose them; `scripts/proxy_e2e.sh` bounds its
  `kill -INT` wait with a `-KILL` fallback so it can never hang.

## Preventive action
PA-0012 (see `docs/PREVENTIVE_ACTIONS.md`): tearing down an `asyncio` server must be
bounded and must not assume `wait_closed()` returns once the listener closes (3.12+ waits
for active connections) — track and cancel in-flight connection tasks and wrap the final
wait in a timeout. Persist important state as it is produced (not only on graceful
shutdown), so a forced stop loses nothing.
