"""Bounded upstream reads off the event loop (BUG-0101, FR-PROXY-12, PA-0102) and an
all-or-nothing history flush (BUG-0106, PA-0107)."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time

import pytest

import fuzzlab.proxy.socketsender as ss
from fuzzlab.core.store import Store
from fuzzlab.proxy.history import FlowRecord, HistoryWriter


class _Sock:
    def __init__(self, parts, delay=0.0):
        self.parts, self.delay = list(parts), delay

    def settimeout(self, t):
        pass

    def recv(self, n):
        if self.delay:
            time.sleep(self.delay)
        return self.parts.pop(0) if self.parts else b""


def _response(total, chunk=65536):
    return [b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % total] + \
        [b"x" * chunk] * (total // chunk)


# --- BUG-0101 -----------------------------------------------------------------------

def _read_8mib_through(monkeypatch, cls):
    """``recv_http_response`` of an 8 MiB body in 64 KiB receives through reader class
    ``cls``; returns the reader and, per receive, whether its body buffer is still the
    same object (identity, not ``id``: a freed buffer's id can be reused)."""
    made, same = [], []

    class Watched(cls):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            made.append(self)

        def feed(self, data):
            before = self.body
            super().feed(data)
            same.append(self.body is before)
    monkeypatch.setattr(ss.framing, "MessageReader", Watched)
    out = ss.recv_http_response(_Sock(_response(8 << 20)), 5)
    assert len(out) > 8 << 20
    (reader,) = made
    return reader, same


def _linear(reader) -> bool:
    """The copy oracle (PA-0135(2)): each received byte copied a bounded number of times."""
    return reader.copied <= 2 * reader.received


def test_the_body_is_never_recopied_per_chunk(monkeypatch):
    """The audit measured 541 MB copied for an 8 MiB body: `bytes(body)` per chunk.
    The framing reader (SP-63, BUG-0543) keeps one body buffer for the whole read
    (structural: the same object after every receive) and counts the bytes it copies
    (`copied`, PA-0135(2)), which stays linear in what was received."""
    from fuzzlab.proxy import framing
    reader, same = _read_8mib_through(monkeypatch, framing.MessageReader)
    assert reader.received > 8 << 20 and len(same) > 100
    assert type(reader.body) is bytearray and all(same)
    assert _linear(reader)


def test_the_copy_oracle_flags_a_quadratic_reader(monkeypatch):
    """PA-0135(3): the oracle above is proven on a deliberately quadratic reader that
    re-copies its body per receive and counts honestly: the count is over 60 times what
    was received, and the body is a new object after every receive."""
    from fuzzlab.proxy import framing

    class Quadratic(framing.MessageReader):
        def _keep(self, piece, payload):
            if payload or not self.dechunk:
                self.body = bytearray(bytes(self.body) + bytes(piece))
                self.copied += len(self.body)
    reader, same = _read_8mib_through(monkeypatch, Quadratic)
    assert not _linear(reader) and reader.copied > 60 * reader.received
    assert same.count(False) > 100


def test_a_body_over_the_cap_raises():
    with pytest.raises(ss.UpstreamResponseError, match="body exceeds"):
        ss.recv_http_response(_Sock(_response(4 << 20)), 5, max_body=1 << 20)


def test_headers_over_the_cap_raise():
    endless = [b"HTTP/1.1 200 OK\r\n"] + [b"X-Pad: " + b"a" * 1000 + b"\r\n"] * 200
    with pytest.raises(ss.UpstreamResponseError, match="headers exceed"):
        ss.recv_http_response(_Sock(endless), 5, max_head=16 * 1024)


def test_a_dripping_peer_hits_the_overall_deadline():
    drip = [b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n"] + [b"x"] * 1000
    t = time.monotonic()
    with pytest.raises(ss.UpstreamResponseError, match="deadline"):
        ss.recv_http_response(_Sock(drip, delay=0.01), 5, deadline=0.2)
    assert time.monotonic() - t < 2


def test_the_sender_is_configurable():
    s = ss.SocketSender(max_body=123, deadline=4.5)
    assert s._max_body == 123 and s._deadline == 4.5


@pytest.mark.parametrize("in_scope", [True, False])
def test_a_slow_sender_does_not_block_the_event_loop(in_scope):
    """Two requests through one engine: the second finishes while the first's
    (blocking) sender still runs — the sender runs in a worker thread, on the in-scope
    path and the transparent bypass alike."""
    from fuzzlab.proxy.scope import Scope
    from fuzzlab.proxy.server import ProxyEngine
    release = threading.Event()
    order = []

    def sender(host, port, use_tls, raw):
        if b"/slow" in raw:
            release.wait(5)
            order.append("slow")
        else:
            order.append("fast")
            release.set()
        return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    engine = ProxyEngine(scope=Scope().include("h") if in_scope else Scope(),
                         sender=sender)
    assert engine.scope.in_scope("h", "/") is in_scope

    async def main():
        slow = asyncio.create_task(engine.handle_request(
            b"GET /slow HTTP/1.1\r\nHost: h\r\n\r\n", "h", 80))
        await asyncio.sleep(0.05)
        fast = await asyncio.wait_for(engine.handle_request(
            b"GET /fast HTTP/1.1\r\nHost: h\r\n\r\n", "h", 80), 3)
        await slow
        return fast
    assert asyncio.run(main()).startswith(b"HTTP/1.1 200")
    assert order == ["fast", "slow"]


# --- BUG-0106 -----------------------------------------------------------------------

def _rec(path="/a", body=b'{"a":1}'):
    raw = (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: h\r\nContent-Type: "
           b"application/json\r\nContent-Length: " + str(len(body)).encode()
           + b"\r\n\r\n" + body)
    return FlowRecord("POST", f"http://h{path}", "h", 200, raw_request=raw,
                      raw_response=b"HTTP/1.1 200 OK\r\n\r\n", req_body=body)


def _rows(store):
    return store.conn.execute("SELECT COUNT(*) FROM flow").fetchone()[0]


def test_a_database_failure_mid_flush_rolls_back_and_a_retry_writes_once(tmp_path,
                                                                         monkeypatch):
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=100)
        for i in range(3):
            h.record(_rec(f"/p{i}"))
        real, calls = h._insert, []

        def failing(conn, rec, *a):
            calls.append(rec.url)
            if len(calls) == 2:
                raise sqlite3.OperationalError("disk I/O error")
            return real(conn, rec, *a)
        monkeypatch.setattr(h, "_insert", failing)
        with pytest.raises(sqlite3.OperationalError):
            h.flush()
        assert _rows(store) == 0 and not store.conn.in_transaction
        assert len(h._buf) == 3                          # nothing written, nothing lost
        monkeypatch.setattr(h, "_insert", real)
        assert h.flush() == 3
        assert _rows(store) == 3 and h._buf == []


def test_a_record_whose_redaction_fails_is_stored_with_omitted_bodies(tmp_path,
                                                                      monkeypatch):
    import fuzzlab.proxy.history as hist
    from fuzzlab.core.redaction import OMIT_FAILED
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=100)
        h.record(_rec("/ok"))
        h.record(_rec("/bad?token=URLSECRET", b'{"password":"SECRET"}'))
        real = hist.redact_body_for

        def boom(raw, body):
            if b"SECRET" in body:
                raise RuntimeError("redactor bug")
            return real(raw, body)
        monkeypatch.setattr(hist, "redact_body_for", boom)
        assert h.flush() == 2
        blob = b"".join((v if isinstance(v, bytes) else str(v).encode())
                        for t in ("flow", "body", "flow_fts")
                        for r in store.conn.execute(f"SELECT * FROM {t}") for v in tuple(r))
    assert b"SECRET" not in blob and OMIT_FAILED in blob
    assert len(h.errors) == 1 and "URLSECRET" not in h.errors[0]


def test_flush_leaves_an_owners_open_transaction_to_its_owner(tmp_path):
    """B-N1: commit only a transaction the flush itself opened."""
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("proxy", "x")
        h = HistoryWriter(store, run, batch_size=100)
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run, "owner_work", 1.0))
        assert store.conn.in_transaction
        h.record(_rec())
        h.flush()
        assert store.conn.in_transaction                 # still the owner's to commit
        store.conn.rollback()
        assert _rows(store) == 0                          # rolled back with the owner


def test_concurrent_records_are_all_written(tmp_path):
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=1000)
        threads = [threading.Thread(target=lambda k=k: [h.record(_rec(f"/t{k}-{i}"))
                                                         for i in range(50)])
                   for k in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert len(h._buf) == 200
        assert h.flush() == 200 and _rows(store) == 200
