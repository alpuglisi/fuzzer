"""Flow history — searchable shared history with byte-exact raw bytes (FR-PROXY-3).

The proxy records each flow to the shared store (D5): the request/response metadata,
the **raw bytes** (content-addressed via `body`, deduped), the decoded bodies, and an
FTS5 index for search. Writes are **batched**: one transaction per batch.

**Off the event loop (NFR-PROXY-nonblocking, FR-PROXY-404, BUG-0550).** The proxy
engine hands each flow over with `HistoryWriter.submit`, which does bounded work on the
calling thread (the event loop's): it admits the flow into a bounded queue and returns.
The writer's own thread, started by the first `submit`, opens its **own** store
connection on the writer's file (`create=False`; a SQLite connection is thread-affine,
PA-0023) and does every redaction, hash, insert, commit and trace event there, in
submission order. A batch is written once it holds `batch_size` flows or `flush_bytes`
bytes, or once its oldest flow has waited `flush_seconds`; one transaction holds at most
`BATCH_MAX_FLOWS` flows and `flush_bytes` bytes plus the flow that crosses it. The
queue holds at most `max_pending_flows` flows and `max_pending_bytes` bytes (waiting or
being written; one larger flow is admitted only into an empty queue). A flow that does
not fit is **dropped from the history, never from the traffic**: counted (`stats`),
logged, and written to ``run_metrics`` (``history_*``) while the run is live. A batch
that cannot be written is tried `WRITE_ATTEMPTS` times, then counted ``failed`` and
logged; the writer goes on with the next. `flush` waits until everything submitted
before it is written; `close` writes everything still pending, then ends the run, within
`CLOSE_TIMEOUT` (what is left after that is counted ``unwritten`` and logged); a caller
on an event loop closes with `aclose`, which waits for that drain on a worker thread. A
writer dropped without `close` is still drained, and so is one still open at interpreter
exit. A hard kill (SIGKILL, a crash) loses what is still queued, up to the queue bounds:
an owner whose process is stopped by a signal turns that signal into a requested stop
and closes the writer (`fuzzlab proxy` does for SIGTERM as for Ctrl-C).
`record` stays synchronous (the repeater, tests): it writes on the calling thread, also
cut by `flush_bytes`; once a writer has a thread, `record` hands over to it too.

Persisted bytes are **redacted** first (NFR-PROXY-safe) — the wire path stays
byte-exact, but history never stores credentials/tokens in cleartext.

**The trace (FR-PROXY-13).** Every in-scope flow the proxy engine records is also one
``observe.exchange`` event (`core.trace`; scope ``proxy``; key ``proxy:flow:<flow id>``),
written live by a `TraceRecorder` the writer owns. The recorder runs on the writer's
thread and store connection (the writer thread's, once `submit` started one), under the
writer's lock, with the writer's ``run_id``, right after the flush that wrote the flows
has committed. An event body is built from
the prepared (redacted) values only: method, URL (`trace.safe_ref`), origin, status or
the upstream error, the redacted ``Location``, the identity name, the parameter *names*.
Never a header, body or query value. A flush inside a transaction the writer does not
own emits nothing then: a later flush or `close` emits it once the transaction is gone
and the flow is still stored (the owner may have rolled it back). Not traced: repeater
sends (``source="repeater"``: the operator's replays, not browser traffic), out-of-scope
flows, messages the operator dropped (the proxy records no flow for them), and a writer
with no ``run_id``.
"""

from __future__ import annotations

import asyncio
import atexit
import collections
import contextlib
import hashlib
import sqlite3
import threading
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from fuzzlab.core.redaction import OMIT_FAILED
from fuzzlab.core.store import Store
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.redact import redact, redact_body_for, redact_url

#: The trace scope and event-key prefix of proxied flows (FR-PROXY-13).
TRACE_SCOPE = "proxy"
TRACE_KEY = "proxy:flow:"

# --- batching and the writer thread (FR-PROXY-404, BUG-0550) -------------------------------
#: A batch is written once it holds this many bytes (raw request and response plus the
#: decoded bodies), or `batch_size` flows, or once its oldest flow waited `FLUSH_SECONDS`.
FLUSH_BYTES = 4 << 20
FLUSH_SECONDS = 0.5
#: One transaction of the writer thread holds at most this many flows.
BATCH_MAX_FLOWS = 500
#: The queue's bounds: flows waiting or being written, and their bytes.
MAX_PENDING_FLOWS = 10_000
MAX_PENDING_BYTES = 256 << 20
#: How many times a batch is tried before its flows are counted ``failed``, and the
#: first pause between tries (doubled each time).
WRITE_ATTEMPTS = 3
RETRY_SECONDS = 0.2
#: How long `close` waits for the writer thread to write what is pending.
CLOSE_TIMEOUT = 60.0
#: How often the live counters (``run_metrics`` ``history_*``) are rewritten; a new drop
#: or failure writes them at once.
METRICS_SECONDS = 1.0
#: The counters a writer thread keeps (`HistoryWriter.stats`, ``history_<name>``).
STAT_NAMES = ("accepted", "written", "dropped", "dropped_bytes", "failed", "unwritten",
              "retries", "batches", "max_lag_ms", "pending_bytes_peak")


@dataclass
class FlowRecord:
    method: str
    url: str
    host: str
    status: int | None = None
    elapsed_ms: float | None = None
    identity: str | None = None
    in_scope: bool = True
    raw_request: bytes = b""
    raw_response: bytes = b""
    req_body: bytes | None = None
    resp_body: bytes | None = None
    protocol: str = "http/1.1"          # 'http/1.1' | 'h2' | 'ws' (Phase 9)
    #: when the proxy received the request (epoch seconds); None when the producer did
    #: not record it (the trace keeps None, never "now")
    t: float | None = None
    #: the upstream failure's class when no response came back (not a stored column)
    error: str | None = None
    #: the operator's interception decisions when a message was held, e.g. "request
    #: edited; response forwarded"; None when nothing was held (not a stored column)
    intercept: str | None = None
    #: "proxy" (traffic through the engine) or "repeater" (an operator's replay)
    source: str = "proxy"


def _size(rec: FlowRecord) -> int:
    """The bytes a flow holds until it is written (its raw messages and bodies)."""
    return (len(rec.raw_request or b"") + len(rec.raw_response or b"")
            + len(rec.req_body or b"") + len(rec.resp_body or b""))


@dataclass
class HistoryWriter:
    store: Store
    run_id: int | None
    batch_size: int = 50
    redact_secrets: bool = True
    #: also record each in-scope engine flow as a trace event (FR-PROXY-13)
    trace: bool = True
    #: a batch is also written once it holds this many bytes (FR-PROXY-404)
    flush_bytes: int = FLUSH_BYTES
    #: ... or, on the writer thread, once its oldest flow has waited this long
    flush_seconds: float = FLUSH_SECONDS
    #: the writer thread's queue bounds (flows and bytes waiting or being written)
    max_pending_flows: int = MAX_PENDING_FLOWS
    max_pending_bytes: int = MAX_PENDING_BYTES
    _buf: list[FlowRecord] = field(default_factory=list, init=False)
    #: records whose redaction failed: stored with omitted bodies (BUG-0106)
    errors: list[str] = field(default_factory=list, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False,
                                   repr=False)
    _recorder: object = field(default=None, init=False, repr=False)
    #: written flows whose events wait for a transaction the writer does not own
    _unsent: list = field(default_factory=list, init=False, repr=False)
    _buf_bytes: int = field(default=0, init=False, repr=False)
    #: the writer thread, once `submit` started it (BUG-0550)
    _pump: "_Pump | None" = field(default=None, init=False, repr=False)

    # --- ingest --------------------------------------------------------------
    def submit(self, rec: FlowRecord) -> bool:
        """Hand one flow to the writer's own thread and return at once: bounded work on
        the calling thread (an event loop's), never redaction, hashing or store work
        (BUG-0550). The first call starts the thread. Returns False when the flow did
        not fit the queue (or the writer is closed or cannot write): it is then counted
        ``dropped`` and reported, never silently lost."""
        pump = self._pump or self._start_pump()
        return pump.submit(rec)

    def record(self, rec: FlowRecord) -> None:
        """Buffer one flow and write the batch on the calling thread once it holds
        `batch_size` flows or `flush_bytes` bytes (the repeater; tests). A writer that
        `submit` has given a thread hands the flow to that thread instead."""
        if self._pump is not None:
            self._pump.submit(rec)
            return
        with self._lock:
            if self._pump is not None:
                self._pump.submit(rec)
                return
            self._buf.append(rec)
            self._buf_bytes += _size(rec)
            if len(self._buf) >= self.batch_size or self._buf_bytes >= self.flush_bytes:
                self.flush()

    @property
    def stats(self) -> dict:
        """The writer thread's counters (`STAT_NAMES`): all zero while it has none."""
        pump = self._pump
        return pump.snapshot() if pump is not None else dict.fromkeys(STAT_NAMES, 0)

    def _thread_path(self) -> Path | None:
        """The store's file, which the writer thread opens; None when there is nothing
        another thread could open (an in-memory store)."""
        path = getattr(self.store, "path", None)
        if path is None or str(path) == ":memory:":
            return None
        return Path(path).absolute()

    def _start_pump(self) -> "_Pump":
        """Start the writer thread, handing it whatever this writer still buffers, first
        (one writer of the run's flows, in order)."""
        with self._lock:
            if self._pump is None:
                path = self._thread_path()
                pump = _Pump(path, self.run_id, batch_size=self.batch_size,
                             redact_secrets=self.redact_secrets, trace=self.trace,
                             flush_bytes=self.flush_bytes,
                             flush_seconds=self.flush_seconds,
                             max_flows=self.max_pending_flows,
                             max_bytes=self.max_pending_bytes, errors=self.errors)
                for rec in self._buf:
                    pump.submit(rec)
                self._buf.clear()
                self._buf_bytes = 0
                weakref.finalize(self, pump.abandon)   # dropped unclosed: still drained
                self._pump = pump
            return self._pump

    def _prep(self, raw: bytes) -> bytes:
        return redact(raw) if (self.redact_secrets and raw) else raw

    def _put_body(self, data: bytes) -> str | None:
        """Content-address ``data`` without committing (batched flush commits once)."""
        if not data:
            return None
        digest = hashlib.sha256(data).hexdigest()
        self.store.conn.execute(
            "INSERT OR IGNORE INTO body (sha256, length, data) VALUES (?,?,?)",
            (digest, len(data), data),
        )
        return digest

    def _prepare(self, rec: FlowRecord) -> tuple:
        """Everything a flow row needs, redacted — no database writes."""
        req_raw = self._prep(rec.raw_request)
        resp_raw = self._prep(rec.raw_response)
        req_body, resp_body, url = rec.req_body or b"", rec.resp_body or b"", rec.url
        if self.redact_secrets:          # every persisted copy (BUG-0084)
            req_body = redact_body_for(rec.raw_request, req_body)
            resp_body = redact_body_for(rec.raw_response, resp_body)
            url = redact_url(url)
        return rec, url, req_raw, resp_raw, req_body, resp_body

    def _prepare_contained(self, rec: FlowRecord) -> tuple | None:
        """`_prepare`, or — if redaction fails — the flow with every body replaced by
        `OMIT_FAILED` and its URL query dropped, so it stays visible but never stored
        unredacted (PA-0086); ``None`` only if even that fails."""
        try:
            return self._prepare(rec)
        except Exception as exc:  # noqa: BLE001 - contained per record, reported
            self.errors.append(f"{rec.method} {rec.url.split('?', 1)[0]}: "
                               f"{type(exc).__name__}")
            try:
                url = rec.url.split("?", 1)[0]
                return rec, url, OMIT_FAILED, OMIT_FAILED, OMIT_FAILED, OMIT_FAILED
            except Exception:  # noqa: BLE001
                return None

    def flush(self) -> int:
        """Write all buffered flows and their FTS rows **all or nothing** (BUG-0106).

        Phase 1 prepares (redacts) every record with no database write. Phase 2 inserts
        them inside ``SAVEPOINT history_flush``: any error rolls back (to it, or the
        whole transaction the flush opened) and re-raises with the buffer intact, so a
        retry never duplicates a flow. It commits only when no transaction was open
        before it (the shared connection's owner commits its own); only the records it
        wrote leave the buffer. Then the written flows' trace events are emitted
        (`_trace`).

        A writer with a thread (`submit`): waits until every flow submitted before this
        call is written or counted, and returns how many the thread wrote meanwhile.
        That blocks the caller: never call it on an event loop."""
        pump = self._pump
        if pump is not None:
            return pump.drain()
        with self._lock:
            if not self._buf:
                return 0
            batch = list(self._buf)
            prepared = self._prepare_batch(batch)
            self._write_prepared(prepared)
            del self._buf[:len(batch)]
            self._buf_bytes = sum(_size(r) for r in self._buf)
            return len(prepared)

    def _prepare_batch(self, batch: list[FlowRecord]) -> list[tuple]:
        """Phase 1: every record redacted (contained per record), no database write."""
        return [p for p in (self._prepare_contained(r) for r in batch) if p]

    def _write_prepared(self, prepared: list[tuple]) -> int:
        """Phase 2 (`_write`), then the written flows' trace events (`_trace`)."""
        with self._lock:
            written = self._write(prepared)
            self._trace(written)
            return len(written)

    def _write(self, prepared: list[tuple]) -> list:
        """Insert prepared flows all or nothing and return the written ones for `_trace`.
        On any error nothing of them stays: the transaction this write opened is rolled
        back (a failed commit included), or, inside an owner's transaction, the write's
        savepoint; then the error is raised again."""
        conn = self.store.conn
        owned = not conn.in_transaction
        written = []
        conn.execute("SAVEPOINT history_flush")
        try:
            for rec, url, req_raw, resp_raw, req_body, resp_body in prepared:
                flow_id = self._insert(conn, rec, url, req_raw, resp_raw, req_body,
                                       resp_body)
                written.append((flow_id, rec, url, req_raw, resp_raw, owned))
            conn.execute("RELEASE history_flush")    # the outermost one commits
            if owned:
                conn.commit()
        except BaseException:
            _undo(conn, owned)
            raise
        return written

    def _insert(self, conn, rec, url, req_raw, resp_raw, req_body, resp_body) -> int:
        req_raw_sha = self._put_body(req_raw)
        resp_raw_sha = self._put_body(resp_raw)
        req_body_sha = self._put_body(req_body)
        resp_body_sha = self._put_body(resp_body)
        cur = conn.execute(
            "INSERT INTO flow (run_id, identity, method, url, host, status, "
            "elapsed_ms, in_scope, req_body_sha, resp_body_sha, req_raw_sha, "
            "resp_raw_sha, protocol) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.run_id, rec.identity, rec.method, url, rec.host, rec.status,
             rec.elapsed_ms, int(bool(rec.in_scope)), req_body_sha, resp_body_sha,
             req_raw_sha, resp_raw_sha, rec.protocol),
        )
        flow_id = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO flow_fts (url, method, host, req_head, resp_head, flow_id) "
            "VALUES (?,?,?,?,?,?)",
            (url, rec.method, rec.host, _head_text(req_raw), _head_text(resp_raw),
             flow_id),
        )
        return flow_id

    # --- the trace (FR-PROXY-13) ----------------------------------------------
    def _trace(self, written: list) -> None:
        """Emit and flush the events of flows already written (the module docstring).
        Called under the writer's lock, on its thread. Never raises: a failure is
        counted as dropped and logged, and the flow history is unaffected."""
        if not self.trace or self.run_id is None:
            return
        self._unsent.extend(w for w in written
                            if w[1].source == "proxy" and w[1].in_scope)
        conn = self.store.conn
        if not self._unsent or conn.in_transaction:
            return                        # its owner may still roll the flows back
        batch, self._unsent = self._unsent, []
        try:
            from fuzzlab.core.trace import TraceRecorder
            if self._recorder is None:
                self._recorder = TraceRecorder(self.store, self.run_id)
            recorder = self._recorder
            dropped = recorder.stats["dropped"]
            for flow_id, rec, url, req_raw, resp_raw, owned in batch:
                if not owned and not _still_stored(conn, self.run_id, flow_id, rec,
                                                   url):
                    continue              # rolled back by the transaction's owner
                try:
                    key, body, t = flow_event(flow_id, rec, url, req_raw, resp_raw)
                except Exception as exc:  # noqa: BLE001 - counted and logged
                    recorder.stats["dropped"] += 1
                    _log_trace_failure(exc)
                    continue
                recorder.emit("observe.exchange", body, key=key, scope=TRACE_SCOPE, t=t)
            recorder.flush()              # live: this flush's events are visible now
            if recorder.stats["dropped"] != dropped:
                recorder.close()          # record the counters: the view says partial
        except Exception as exc:  # noqa: BLE001 - the proxy's history must not fail
            _log_trace_failure(exc)

    # --- search --------------------------------------------------------------
    def search(self, query: str, raw_query: bool = False) -> list[dict]:
        """Full-text search over flow heads/URLs; returns flow rows (newest first).

        By default ``query`` is treated as a literal phrase (quoted for FTS5), so
        terms with punctuation — URLs, hosts like ``127.0.0.1`` — search cleanly. Pass
        ``raw_query=True`` to use FTS5 query syntax directly.
        """
        self.flush()
        match = query if raw_query else '"' + query.replace('"', '""') + '"'
        rows = self.store.conn.execute(
            "SELECT f.* FROM flow_fts JOIN flow f ON f.id = flow_fts.flow_id "
            "WHERE flow_fts MATCH ? AND f.run_id = ? ORDER BY f.id DESC",
            (match, self.run_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def raw_request(self, flow_id: int) -> bytes | None:
        return self._raw(flow_id, "req_raw_sha")

    def raw_response(self, flow_id: int) -> bytes | None:
        return self._raw(flow_id, "resp_raw_sha")

    def _raw(self, flow_id: int, col: str) -> bytes | None:
        row = self.store.conn.execute(
            f"SELECT {col} AS sha FROM flow WHERE id=?", (flow_id,)
        ).fetchone()
        if not row or row["sha"] is None:
            return None
        return self.store.get_body(row["sha"])

    def close(self, run_end: str | None = None) -> None:
        """Flush; emit the events still waiting for a transaction the writer did not
        own (when it is gone); record the run's end when the caller states it
        (``run_end``: ``complete`` for an operator's stop, ``aborted: <class>``
        otherwise), so the run's diagram status is not left partial; record the trace
        counters (``run_metrics`` ``trace_*``).

        A writer with a thread: the thread writes everything still pending, records the
        run's end and the counters (``trace_*``, ``history_*``) on its own connection,
        and stops, within `CLOSE_TIMEOUT`. That blocks the caller for the whole drain:
        on an event loop, use `aclose`. Idempotent."""
        pump = self._pump
        if pump is not None:
            pump.close(run_end)
            self._close_own()
            return
        self.flush()
        with self._lock:
            self._trace([])
            if run_end and self.trace and self.run_id is not None and \
                    not self.store.conn.in_transaction:
                with contextlib.suppress(Exception):
                    if self._recorder is None:
                        from fuzzlab.core.trace import TraceRecorder
                        self._recorder = TraceRecorder(self.store, self.run_id)
                    self._recorder.emit("run.end", {"status": run_end}, key="run.end")
            if self._recorder is not None:
                with contextlib.suppress(Exception):
                    self._recorder.close()

    async def aclose(self, run_end: str | None = None) -> None:
        """`close` for a caller on an event loop (the web proxy's `stop`; BUG-0550,
        review R3): the writer thread's drain, up to `CLOSE_TIMEOUT`, is waited for on a
        worker thread while the loop goes on. A writer with a file store that holds
        nothing on the caller's connection (no trace state from a synchronous `record`)
        and has no thread yet starts one here, so the run's end and the counters are
        written on the thread's connection too and nothing of the close runs on the
        loop. A writer that wrote synchronously on the caller's thread (`record`), or
        whose store no other thread can open, is closed there, as it wrote (PA-0023)."""
        pump = self._pump
        if pump is None and self._recorder is None and not self._unsent and \
                self._thread_path() is not None:
            pump = self._start_pump()
        if pump is None:
            self.close(run_end)
            return
        await asyncio.to_thread(pump.close, run_end)
        self._close_own()

    def _close_own(self) -> None:
        """After the writer thread closed: this writer's own leftovers, if any (events
        of flows it wrote synchronously inside a transaction it did not own; its own
        recorder's counters), on its own connection."""
        with self._lock:
            self._trace([])
            if self._recorder is not None:
                with contextlib.suppress(Exception):
                    self._recorder.close()

    def __enter__(self) -> "HistoryWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _undo(conn, owned: bool) -> None:
    """Leave nothing of a failed write (`HistoryWriter._write`). The original error is
    raised by the caller whatever happens here; a rollback that fails is reported."""
    try:
        if owned:
            if conn.in_transaction:
                conn.rollback()
        else:
            conn.execute("ROLLBACK TO history_flush")
            conn.execute("RELEASE history_flush")
    except sqlite3.Error as exc:
        _report("error", "proxy history rollback failed", error=type(exc).__name__)


def _report(level: str, msg: str, **fields) -> None:
    """Log one history event (drops, failures, an unwritable store): never raises."""
    with contextlib.suppress(Exception):
        from fuzzlab.core.obs import get_logger
        getattr(get_logger("proxy.history"), level)(msg, extra=fields)


#: Writer threads running, drained (bounded) at interpreter exit. A pump joins it only
#: once its thread has started (BUG-0550 review round 2).
_LIVE: "weakref.WeakSet[_Pump]" = weakref.WeakSet()


@atexit.register
def _close_live_pumps() -> None:
    """Drain every live writer at interpreter exit, each within 10 s. One that fails to
    close is reported and the others are still drained (BUG-0550 review round 2: an
    unstarted thread's "cannot join thread before it is started" stopped this loop, so
    the writers after it in `_LIVE` were never drained)."""
    for pump in list(_LIVE):
        try:
            pump.close(None, timeout=10.0)
        except Exception as exc:  # noqa: BLE001 - one writer's failure, the rest drain
            _report("error", "proxy history writer could not be drained at exit",
                    run_id=pump.run_id, error=type(exc).__name__)


class _Pump:
    """The writer thread of one `HistoryWriter` after its first `submit` (FR-PROXY-404,
    BUG-0550; the module docstring states the policy).

    **Single-threaded by construction (PA-0023).** The thread opens its own `Store` on
    the writer's file and is the only user of that connection and of the inner
    `HistoryWriter` built on it. Every other method touches only the queue and the
    counters, under `cond`, and never waits on the store: `submit` is the event loop's
    side. The pump holds no reference to its owner, so an owner dropped without `close`
    is still drained (`abandon`)."""

    def __init__(self, path: Path | None, run_id: int | None, *, batch_size: int,
                 redact_secrets: bool, trace: bool, flush_bytes: int,
                 flush_seconds: float, max_flows: int, max_bytes: int,
                 errors: list[str]) -> None:
        self.path, self.run_id = path, run_id
        self.batch_size = max(1, int(batch_size))
        self.redact_secrets, self.trace = redact_secrets, trace
        self.flush_bytes = max(1, int(flush_bytes))
        self.flush_seconds = max(0.0, float(flush_seconds))
        self.max_flows, self.max_bytes = max(1, int(max_flows)), max(1, int(max_bytes))
        self.errors = errors
        self.cond = threading.Condition()
        self.queue: collections.deque = collections.deque()   # (rec, size, queued at)
        self.queued_bytes = 0
        self.pending_flows = self.pending_bytes = 0            # queued or being written
        self.accepted = self.finished = 0                      # admitted / done with
        self.drains = 0                                        # waiting `drain` calls
        self.closing = False
        self.run_end: str | None = None
        self.broken: str | None = None                         # why it cannot write
        self.stats = dict.fromkeys(STAT_NAMES, 0)
        self._reported = (0, 0)                                # (dropped, failed) logged
        self._metrics_at: float | None = None
        self._metrics_seen = (0, 0)
        if path is None:                   # reported once, by the thread (`_break`)
            self.broken = "the store has no file another thread can open"
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name=f"fuzzlab-proxy-history-{run_id}")
        self.thread.start()               # raises when it cannot start: never live then
        _LIVE.add(self)

    # --- the submitting side (bounded work, never the store) --------------------------
    def submit(self, rec: FlowRecord) -> bool:
        size = _size(rec)
        with self.cond:
            if self.closing or self.broken is not None or \
                    self.pending_flows >= self.max_flows or \
                    (self.pending_flows and self.pending_bytes + size > self.max_bytes):
                self.stats["dropped"] += 1
                self.stats["dropped_bytes"] += size
                return False
            was_empty = not self.queue
            self.queue.append((rec, size, time.monotonic()))
            self.queued_bytes += size
            self.pending_flows += 1
            self.pending_bytes += size
            self.accepted += 1
            self.stats["accepted"] += 1
            self.stats["pending_bytes_peak"] = max(self.stats["pending_bytes_peak"],
                                                   self.pending_bytes)
            if was_empty or len(self.queue) >= self.batch_size or \
                    self.queued_bytes >= self.flush_bytes:
                self.cond.notify_all()
            return True

    def snapshot(self) -> dict:
        with self.cond:
            return dict(self.stats)

    def drain(self, timeout: float | None = None) -> int:
        """Wait until every flow admitted before the call is written or counted."""
        with self.cond:
            target, before = self.accepted, self.stats["written"]
            self.drains += 1
            self.cond.notify_all()
            try:
                self.cond.wait_for(lambda: self.finished >= target
                                   or not self.thread.is_alive(), timeout)
            finally:
                self.drains -= 1
            return self.stats["written"] - before

    def abandon(self) -> None:
        """The owner is gone: write what is pending and stop, without waiting here."""
        with self.cond:
            self.closing = True
            self.cond.notify_all()

    def close(self, run_end: str | None, timeout: float = CLOSE_TIMEOUT) -> bool:
        with self.cond:
            if not self.closing:
                self.closing = True
                self.run_end = run_end
            elif run_end is not None and self.run_end is None:
                self.run_end = run_end
            self.cond.notify_all()
        if self.thread is not threading.current_thread():
            self.thread.join(timeout)
        if self.thread.is_alive():
            with self.cond:
                self.stats["unwritten"] = self.pending_flows
            _report("error", "proxy history writer did not finish before its close "
                    "timeout; the flows still pending are unwritten",
                    run_id=self.run_id, unwritten=self.stats["unwritten"])
            return False
        return True

    # --- the writer thread --------------------------------------------------------------
    def _run(self) -> None:
        if self.broken is not None:
            self._break(self.broken)
            return
        try:
            store = Store(self.path, create=False)
        except Exception as exc:  # noqa: BLE001 - reported; every flow is counted
            self._break(f"the store cannot be opened ({type(exc).__name__})")
            return
        try:
            inner = HistoryWriter(store, self.run_id, batch_size=1 << 30,
                                  redact_secrets=self.redact_secrets, trace=self.trace,
                                  flush_bytes=1 << 62)
            inner.errors = self.errors
            while True:
                batch = self._take()
                if batch is None:
                    break
                self._write(inner, batch)
                self._metrics(store)
            with self.cond:
                run_end = self.run_end
            try:
                inner.close(run_end=run_end)  # the run's end and the trace counters
            except Exception as exc:  # noqa: BLE001 - reported, the flows are written
                _report("error", "proxy history close failed", run_id=self.run_id,
                        error=type(exc).__name__)
        except BaseException as exc:  # noqa: BLE001 - a defect here: reported, counted
            self._break(f"the writer stopped ({type(exc).__name__})")
        finally:
            self._metrics(store, force=True)
            self._log_counts(final=True)
            with contextlib.suppress(sqlite3.Error):
                store.close()
            with self.cond:
                self.cond.notify_all()

    def _take(self) -> list | None:
        """The next batch, once one is due (count, bytes, age, a drain or the close);
        None once closing with nothing left."""
        with self.cond:
            while True:
                if self.queue:
                    age = time.monotonic() - self.queue[0][2]
                    if len(self.queue) >= self.batch_size or self.closing or \
                            self.queued_bytes >= self.flush_bytes or self.drains or \
                            age >= self.flush_seconds:
                        batch, total = [], 0
                        while self.queue and len(batch) < BATCH_MAX_FLOWS and \
                                total < self.flush_bytes:
                            item = self.queue.popleft()
                            batch.append(item)
                            total += item[1]
                        self.queued_bytes -= total
                        return batch
                    self.cond.wait(self.flush_seconds - age)
                elif self.closing:
                    return None
                else:
                    self.cond.wait()

    def _write(self, inner: HistoryWriter, batch: list) -> None:
        """Write one batch: prepared once, tried `WRITE_ATTEMPTS` times; a batch that
        still fails is counted ``failed`` and reported, and the writer goes on."""
        recs = [item[0] for item in batch]
        lag_ms = (time.monotonic() - batch[0][2]) * 1000
        prepared = inner._prepare_batch(recs)
        written, error, retries = None, None, 0
        for attempt in range(WRITE_ATTEMPTS):
            try:
                written = inner._write_prepared(prepared)
                break
            except Exception as exc:  # noqa: BLE001 - retried, then counted and reported
                error = exc
                if attempt + 1 < WRITE_ATTEMPTS:
                    retries += 1
                    time.sleep(RETRY_SECONDS * (2 ** attempt))
        if written is None:
            _report("error", "proxy history batch not written", run_id=self.run_id,
                    flows=len(batch), error=type(error).__name__)
        with self.cond:
            if written is None:
                self.stats["failed"] += len(batch)
            else:
                self.stats["written"] += written
                self.stats["failed"] += len(batch) - written   # not even an omitted copy
            self.stats["retries"] += retries
            self.stats["batches"] += 1
            self.stats["max_lag_ms"] = max(self.stats["max_lag_ms"], round(lag_ms, 1))
            self.pending_flows -= len(batch)
            self.pending_bytes -= sum(item[1] for item in batch)
            self.finished += len(batch)
            self.cond.notify_all()

    def _break(self, why: str) -> None:
        """The thread cannot write any more: everything admitted and not written is
        counted ``failed``, and later flows are counted ``dropped``."""
        with self.cond:
            self.broken = self.broken or why
            self.stats["failed"] += self.pending_flows
            self.finished = self.accepted
            self.queue.clear()
            self.queued_bytes = self.pending_flows = self.pending_bytes = 0
            self.cond.notify_all()
        _report("error", "proxy history writer cannot write: " + why,
                run_id=self.run_id, failed=self.stats["failed"])

    def _metrics(self, store, force: bool = False) -> None:
        """Rewrite ``run_metrics`` ``history_*`` (live; at once on a new drop or failure)."""
        if store is None or self.run_id is None:
            return
        snap = self.snapshot()
        seen = (snap["dropped"], snap["failed"])
        now = time.monotonic()
        if not force and seen == self._metrics_seen and self._metrics_at is not None \
                and now - self._metrics_at < METRICS_SECONDS:
            return
        self._log_counts()
        self._metrics_at, self._metrics_seen = now, seen
        rows = [(self.run_id, f"history_{k}", float(v)) for k, v in snap.items()]
        try:
            store.conn.execute("DELETE FROM run_metrics WHERE run_id=? AND key LIKE "
                               "'history\\_%' ESCAPE '\\'", (self.run_id,))
            store.conn.executemany(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)", rows)
            store.conn.commit()
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                store.conn.rollback()
            _report("warning", "proxy history counters not written", run_id=self.run_id,
                    error=type(exc).__name__)

    def _log_counts(self, final: bool = False) -> None:
        """Log new drops and failures (totals), once per change."""
        snap = self.snapshot()
        now = (snap["dropped"], snap["failed"])
        if now != self._reported:
            self._reported = now
            _report("warning", "proxy history flows dropped or not written",
                    run_id=self.run_id, dropped=snap["dropped"],
                    dropped_bytes=snap["dropped_bytes"], failed=snap["failed"])
        elif final and any(now):
            _report("warning", "proxy history closed with flows dropped or not written",
                    run_id=self.run_id, dropped=snap["dropped"], failed=snap["failed"])


def flow_event(flow_id: int, rec: FlowRecord, url: str, req_raw: bytes,
               resp_raw: bytes) -> tuple[str, dict, float | None]:
    """``(key, body, t)`` of one written flow's ``observe.exchange`` event, built from
    its prepared (redacted) values (FR-PROXY-13). Pure: the same flow always gives the
    same event, so re-processing it is a duplicate the recorder ignores."""
    from fuzzlab.core import trace
    from fuzzlab.core.urls import canonical_origin
    from fuzzlab.tools.observe import _body_params, _query_params
    ref = trace.safe_ref(url)
    req = RawMessage.from_bytes(req_raw or b"")
    ctype = (req.get("Content-Type") or b"").decode("latin-1", "replace")
    params = _query_params(ref)
    # names only; a chunked or compressed body is not parsed (its bytes are not text)
    if req.body and req.get("Transfer-Encoding") is None \
            and req.get("Content-Encoding") is None:
        params += _body_params(ctype, req.body.decode("utf-8", "replace"))
    location = None
    if resp_raw:
        loc = RawMessage.from_bytes(resp_raw).get("Location")
        if loc:
            location = trace.safe_ref(loc.decode("latin-1", "replace")) or None
    if rec.status is not None:
        outcome = "response"
    elif resp_raw:
        outcome = "response without a status line"
    else:
        outcome = f"no response ({rec.error or 'connection closed'})"
    body = {"src": "proxy", "ref": f"flow id {flow_id}",
            "method": (rec.method or "GET").upper(), "url": ref,
            "origin": canonical_origin(url), "status": rec.status, "error": rec.error,
            "outcome": outcome, "redirect": location, "profile": rec.identity,
            "ctype": ctype.split(";", 1)[0].strip() or None, "params": params,
            "via": rec.protocol}
    if rec.intercept:
        body["intercept"] = rec.intercept
    return f"{TRACE_KEY}{flow_id}", body, rec.t


def _still_stored(conn, run_id: int, flow_id: int, rec: FlowRecord, url: str) -> bool:
    """Whether a flow written inside another owner's transaction survived it. The row is
    compared, not only its id: after a rollback, SQLite may give the id to a later flow."""
    row = conn.execute("SELECT method, url, status, identity FROM flow WHERE id=? AND "
                       "run_id=?", (flow_id, run_id)).fetchone()
    return row is not None and (row["method"], row["url"], row["status"],
                                row["identity"]) == (rec.method, url, rec.status,
                                                     rec.identity)


def _log_trace_failure(exc: BaseException) -> None:
    from fuzzlab.core.obs import get_logger
    get_logger("trace").warning("proxy trace event not written",
                                extra={"error": type(exc).__name__})


def _head_text(raw: bytes) -> str:
    """The head (start line + headers), decoded latin-1 for the FTS index."""
    if not raw:
        return ""
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    return head.decode("latin-1", "replace")
