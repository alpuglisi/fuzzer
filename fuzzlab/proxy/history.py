"""Flow history — searchable shared history with byte-exact raw bytes (FR-PROXY-3).

The proxy records each flow to the shared store (D5): the request/response metadata,
the **raw bytes** (content-addressed via `body`, deduped), the decoded bodies, and an
FTS5 index for search. Writes are **batched** so the data path is not stalled per flow
(NFR-PROXY-nonblocking); the true async offload is on-host, but the batching seam and
the single-commit-per-flush shape are built and tested here.

Persisted bytes are **redacted** first (NFR-PROXY-safe) — the wire path stays
byte-exact, but history never stores credentials/tokens in cleartext.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field

from fuzzlab.core.redaction import OMIT_FAILED
from fuzzlab.core.store import Store
from fuzzlab.proxy.redact import redact, redact_body_for, redact_url


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


@dataclass
class HistoryWriter:
    store: Store
    run_id: int
    batch_size: int = 50
    redact_secrets: bool = True
    _buf: list[FlowRecord] = field(default_factory=list, init=False)
    #: records whose redaction failed: stored with omitted bodies (BUG-0106)
    errors: list[str] = field(default_factory=list, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False,
                                   repr=False)

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
        commits its own); only the records it wrote leave the buffer."""
        with self._lock:
            if not self._buf:
                return 0
            batch = list(self._buf)
            prepared = [p for p in (self._prepare_contained(r) for r in batch) if p]
            conn = self.store.conn
            owned = not conn.in_transaction
            conn.execute("SAVEPOINT history_flush")
            try:
                for rec, url, req_raw, resp_raw, req_body, resp_body in prepared:
                    self._insert(conn, rec, url, req_raw, resp_raw, req_body, resp_body)
            except BaseException:
                conn.execute("ROLLBACK TO history_flush")
                conn.execute("RELEASE history_flush")
                raise
            conn.execute("RELEASE history_flush")
            if owned:
                conn.commit()
            del self._buf[:len(batch)]
            return len(prepared)

    def _insert(self, conn, rec, url, req_raw, resp_raw, req_body, resp_body) -> None:
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

    def close(self) -> None:
        self.flush()

    def __enter__(self) -> "HistoryWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _head_text(raw: bytes) -> str:
    """The head (start line + headers), decoded latin-1 for the FTS index."""
    if not raw:
        return ""
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    return head.decode("latin-1", "replace")
