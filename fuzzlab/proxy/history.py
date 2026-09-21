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
from dataclasses import dataclass, field

from fuzzlab.core.store import Store
from fuzzlab.proxy.redact import redact


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


@dataclass
class HistoryWriter:
    store: Store
    run_id: int
    batch_size: int = 50
    redact_secrets: bool = True
    _buf: list[FlowRecord] = field(default_factory=list, init=False)

    # --- ingest --------------------------------------------------------------
    def record(self, rec: FlowRecord) -> None:
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

    def flush(self) -> int:
        """Write all buffered flows and their FTS rows in one transaction."""
        if not self._buf:
            return 0
        conn = self.store.conn
        written = 0
        for rec in self._buf:
            req_raw = self._prep(rec.raw_request)
            resp_raw = self._prep(rec.raw_response)
            req_raw_sha = self._put_body(req_raw)
            resp_raw_sha = self._put_body(resp_raw)
            req_body_sha = self._put_body(rec.req_body or b"")
            resp_body_sha = self._put_body(rec.resp_body or b"")
            cur = conn.execute(
                "INSERT INTO flow (run_id, identity, method, url, host, status, "
                "elapsed_ms, in_scope, req_body_sha, resp_body_sha, req_raw_sha, "
                "resp_raw_sha) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.run_id, rec.identity, rec.method, rec.url, rec.host, rec.status,
                 rec.elapsed_ms, int(bool(rec.in_scope)), req_body_sha, resp_body_sha,
                 req_raw_sha, resp_raw_sha),
            )
            flow_id = int(cur.lastrowid)
            conn.execute(
                "INSERT INTO flow_fts (url, method, host, req_head, resp_head, flow_id) "
                "VALUES (?,?,?,?,?,?)",
                (rec.url, rec.method, rec.host, _head_text(req_raw),
                 _head_text(resp_raw), flow_id),
            )
            written += 1
        conn.commit()
        self._buf.clear()
        return written

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
