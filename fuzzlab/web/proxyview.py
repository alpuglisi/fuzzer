"""Read-only, store-backed proxy flow history for the Proxy tab (Phase 2.1).

Mirrors `web/results.py`: pure functions over the shared store, no writes, and
the store file is never created. Flow history is written by the proxy component
(`proxy/history.py`) and is readable **cross-process** — the panel and a running
`fuzzlab proxy` share only the SQLite store. Persisted bytes are already redacted
on write, so what the viewer shows never contains cleartext secrets.
"""

from __future__ import annotations

from typing import Any

from fuzzlab.core.store import Store


_FLOW_COLS = ("id", "run_id", "method", "url", "host", "status", "elapsed_ms",
              "protocol", "in_scope", "created_at")


def _fts_match(query: str) -> str:
    """Quote a query as a literal FTS5 phrase (URLs/hosts search cleanly)."""
    return '"' + query.replace('"', '""') + '"'


def list_flows(store: Store, *, query: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """Recorded flows, newest first. With ``query``, full-text over head/url/host."""
    cols = ", ".join(f"f.{c}" for c in _FLOW_COLS)
    if query:
        rows = store.conn.execute(
            f"SELECT {cols} FROM flow_fts JOIN flow f ON f.id = flow_fts.flow_id "
            "WHERE flow_fts MATCH ? ORDER BY f.id DESC LIMIT ?",
            (_fts_match(query), limit),
        ).fetchall()
    else:
        rows = store.conn.execute(
            f"SELECT {cols} FROM flow f ORDER BY f.id DESC LIMIT ?", (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def _decode(store: Store, sha: str | None) -> str:
    """Fetch content-addressed bytes and decode for display (latin-1 = lossless)."""
    if not sha:
        return ""
    data = store.get_body(sha)
    return data.decode("latin-1", "replace") if data else ""


def flow_detail(store: Store, flow_id: int) -> dict[str, Any] | None:
    """One flow's metadata plus its redacted raw request/response, as text."""
    row = store.conn.execute("SELECT * FROM flow WHERE id = ?", (flow_id,)).fetchone()
    if row is None:
        return None
    r = dict(row)
    return {
        "id": r["id"],
        "run_id": r.get("run_id"),
        "method": r.get("method"),
        "url": r.get("url"),
        "host": r.get("host"),
        "status": r.get("status"),
        "elapsed_ms": r.get("elapsed_ms"),
        "protocol": r.get("protocol"),
        "in_scope": r.get("in_scope"),
        "created_at": r.get("created_at"),
        "raw_request": _decode(store, r.get("req_raw_sha")),
        "raw_response": _decode(store, r.get("resp_raw_sha")),
        "redacted": True,   # stored bytes are secret-redacted on write
    }
