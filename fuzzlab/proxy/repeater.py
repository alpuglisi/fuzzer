"""Repeater — DB-persisted tabs; edit and replay, including the raw path (FR-PROXY-4).

A repeater tab is a saved raw request plus its target (host/port/TLS). Tabs persist in
`repeater_tab` so they survive across sessions. Replay goes through an injected
**sender seam**: offline tests supply a fake sender; the on-host server supplies a real
socket sender. Because a tab stores raw bytes and the sender sends them verbatim, the
repeater replays byte-exact requests (the raw path) — a hand-edited duplicate
``Content-Length`` is sent exactly as saved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fuzzlab.core.store import Store
from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.message import RawMessage

# (host, port, use_tls, raw_request) -> raw_response bytes
Sender = Callable[[str, int, bool, bytes], bytes]


@dataclass
class RepeaterTab:
    id: int
    name: str
    host: str
    port: int
    use_tls: bool
    raw_request: bytes


class Repeater:
    def __init__(self, store: Store, run_id: int, sender: Sender,
                 history: HistoryWriter | None = None):
        self.store = store
        self.run_id = run_id
        self.sender = sender
        self.history = history

    # --- tab CRUD (persisted) ----------------------------------------------
    def create_tab(self, name: str, host: str, port: int, raw_request: bytes,
                   use_tls: bool = False) -> RepeaterTab:
        cur = self.store.conn.execute(
            "INSERT INTO repeater_tab (run_id, name, host, port, use_tls, raw_request) "
            "VALUES (?,?,?,?,?,?)",
            (self.run_id, name, host, port, int(bool(use_tls)), bytes(raw_request)),
        )
        self.store.conn.commit()
        return RepeaterTab(int(cur.lastrowid), name, host, port, bool(use_tls),
                           bytes(raw_request))

    def update_request(self, tab_id: int, raw_request: bytes) -> None:
        self.store.conn.execute(
            "UPDATE repeater_tab SET raw_request=?, updated_at=datetime('now') WHERE id=?",
            (bytes(raw_request), tab_id),
        )
        self.store.conn.commit()

    def get_tab(self, tab_id: int) -> RepeaterTab | None:
        row = self.store.conn.execute(
            "SELECT * FROM repeater_tab WHERE id=?", (tab_id,)).fetchone()
        return _row_to_tab(row) if row else None

    def list_tabs(self) -> list[RepeaterTab]:
        rows = self.store.conn.execute(
            "SELECT * FROM repeater_tab WHERE run_id=? ORDER BY id", (self.run_id,)
        ).fetchall()
        return [_row_to_tab(r) for r in rows]

    # --- replay -------------------------------------------------------------
    def send(self, tab_id: int, raw_request: bytes | None = None) -> bytes:
        """Replay a tab (optionally with an edited request) and return raw response.

        The exact bytes of ``raw_request`` (or the saved request) go on the wire — no
        reserialization. If a ``HistoryWriter`` is attached, the exchange is recorded.
        """
        tab = self.get_tab(tab_id)
        if tab is None:
            raise KeyError(f"no repeater tab {tab_id}")
        req = bytes(raw_request) if raw_request is not None else tab.raw_request
        if raw_request is not None:
            self.update_request(tab_id, req)
        resp = self.sender(tab.host, tab.port, tab.use_tls, req)
        if self.history is not None:
            msg = RawMessage.from_bytes(req)
            scheme = "https" if tab.use_tls else "http"
            self.history.record(FlowRecord(
                method=msg.method.decode("latin-1", "replace"),
                url=f"{scheme}://{tab.host}:{tab.port}"
                    f"{msg.target.decode('latin-1', 'replace')}",
                host=f"{tab.host}:{tab.port}",
                raw_request=req, raw_response=resp,
            ))
        return resp


def _row_to_tab(row) -> RepeaterTab:
    return RepeaterTab(row["id"], row["name"], row["host"], row["port"],
                       bool(row["use_tls"]), bytes(row["raw_request"]))
