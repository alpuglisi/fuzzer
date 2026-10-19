"""Flow history — searchable shared history with byte-exact raw bytes (FR-PROXY-3).

The proxy records each flow to the shared store (D5): the request/response metadata,
the **raw bytes** (content-addressed via `body`, deduped), the decoded bodies, and an
FTS5 index for search. Writes are **batched** so the data path is not stalled per flow
(NFR-PROXY-nonblocking); the true async offload is on-host, but the batching seam and
the single-commit-per-flush shape are built and tested here.

Persisted bytes are **redacted** first (NFR-PROXY-safe) — the wire path stays
byte-exact, but history never stores credentials/tokens in cleartext.

**The trace (FR-PROXY-13).** Every in-scope flow the proxy engine records is also one
``observe.exchange`` event (`core.trace`; scope ``proxy``; key ``proxy:flow:<flow id>``),
written live by a `TraceRecorder` the writer owns. The recorder runs on the writer's
thread and store connection, under the writer's lock, with the writer's ``run_id``,
right after the flush that wrote the flows has committed. An event body is built from
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

import contextlib
import hashlib
import threading
from dataclasses import dataclass, field

from fuzzlab.core.redaction import OMIT_FAILED
from fuzzlab.core.store import Store
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.redact import redact, redact_body_for, redact_url

#: The trace scope and event-key prefix of proxied flows (FR-PROXY-13).
TRACE_SCOPE = "proxy"
TRACE_KEY = "proxy:flow:"


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


@dataclass
class HistoryWriter:
    store: Store
    run_id: int | None
    batch_size: int = 50
    redact_secrets: bool = True
    #: also record each in-scope engine flow as a trace event (FR-PROXY-13)
    trace: bool = True
    _buf: list[FlowRecord] = field(default_factory=list, init=False)
    #: records whose redaction failed: stored with omitted bodies (BUG-0106)
    errors: list[str] = field(default_factory=list, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False,
                                   repr=False)
    _recorder: object = field(default=None, init=False, repr=False)
    #: written flows whose events wait for a transaction the writer does not own
    _unsent: list = field(default_factory=list, init=False, repr=False)

    # --- ingest --------------------------------------------------------------
    def record(self, rec: FlowRecord) -> None:
        with self._lock:
            self._buf.append(rec)
            if len(self._buf) >= self.batch_size:
                self.flush()

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
        them inside ``SAVEPOINT history_flush``: any error rolls back to it and
        re-raises with the buffer intact, so a retry never duplicates a flow. It commits
        only when no transaction was open before it (the shared connection's owner
        commits its own); only the records it wrote leave the buffer. Then the written
        flows' trace events are emitted (`_trace`)."""
        with self._lock:
            if not self._buf:
                return 0
            batch = list(self._buf)
            prepared = [p for p in (self._prepare_contained(r) for r in batch) if p]
            conn = self.store.conn
            owned = not conn.in_transaction
            written = []
            conn.execute("SAVEPOINT history_flush")
            try:
                for rec, url, req_raw, resp_raw, req_body, resp_body in prepared:
                    flow_id = self._insert(conn, rec, url, req_raw, resp_raw, req_body,
                                           resp_body)
                    written.append((flow_id, rec, url, req_raw, resp_raw, owned))
            except BaseException:
                conn.execute("ROLLBACK TO history_flush")
                conn.execute("RELEASE history_flush")
                raise
            conn.execute("RELEASE history_flush")
            if owned:
                conn.commit()
            del self._buf[:len(batch)]
            self._trace(written)
            return len(prepared)

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
        counters (``run_metrics`` ``trace_*``)."""
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

    def __enter__(self) -> "HistoryWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


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
            "outcome": outcome, "location": location, "profile": rec.identity,
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
