"""The proxy's flow history is written off the event loop (BUG-0550, FR-PROXY-404,
NFR-PROXY-nonblocking, PA-0550).

`ProxyEngine` hands each in-scope flow to `HistoryWriter.submit`, which only queues it;
the writer's own thread (its own store connection) redacts, hashes, inserts, commits
and traces it. A batch is cut by count, bytes or age; the queue is bounded by flows and
bytes, and a flow that does not fit is dropped from the history (never from the
traffic), counted, logged and written to ``run_metrics`` (``history_*``) while the run
is live; ``close`` writes everything still pending, in submission order. Loopback and
temporary stores only: no lab is contacted."""

from __future__ import annotations

import ast
import asyncio
import sqlite3
import threading
import time
from pathlib import Path

import pytest

import fuzzlab.proxy.history as hist
from fuzzlab.core.store import Store
from fuzzlab.proxy.history import TRACE_KEY, FlowRecord, HistoryWriter
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.server import ProxyEngine

REPO = Path(__file__).resolve().parents[1]
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def _flow(i: int, pad: int = 0) -> FlowRecord:
    raw = f"GET /p{i} HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n".encode() + b"x" * pad
    return FlowRecord("GET", f"http://127.0.0.1:9/p{i}", "127.0.0.1:9", 200,
                      raw_request=raw, raw_response=OK, t=1000.0 + i)


def _until(pred, timeout: float = 30.0) -> bool:
    """Poll a presence claim (never an absence one, PA-0511) up to a generous bound."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return pred()


def _urls(store, run_id) -> list[str]:
    return [r[0] for r in store.conn.execute(
        "SELECT url FROM flow WHERE run_id=? ORDER BY id", (run_id,))]


def _metrics(store, run_id) -> dict:
    return {r[0]: r[1] for r in store.conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=? AND key LIKE 'history\\_%' "
        "ESCAPE '\\'", (run_id,))}


class _Gate:
    """Blocks the first store insert until released (or a safety bound passes), and
    records which threads did the store's and the redactor's work."""

    def __init__(self, monkeypatch, safety: float = 15.0):
        self.entered, self.release = threading.Event(), threading.Event()
        self.threads: set[int] = set()
        self.calls = 0
        real_insert, real_prepare = HistoryWriter._insert, HistoryWriter._prepare
        gate = self

        def insert(self, *a, **k):
            gate.threads.add(threading.get_ident())
            gate.calls += 1
            if gate.calls == 1:
                gate.entered.set()
                gate.release.wait(safety)
                gate.release.set()        # a pre-fix run gets here only when it timed out
            return real_insert(self, *a, **k)

        def prepare(self, rec):
            gate.threads.add(threading.get_ident())
            return real_prepare(self, rec)
        monkeypatch.setattr(HistoryWriter, "_insert", insert)
        monkeypatch.setattr(HistoryWriter, "_prepare", prepare)


# --- the defect: a slow store write stalled every proxied connection ----------------------

def test_a_blocked_store_write_never_stalls_proxied_traffic(tmp_path, monkeypatch):
    """The audit's defect 25: the engine wrote history on its event-loop thread, so one
    slow write (a busy store, a slow disk) held every connection. Here the first flow's
    insert is held; two more requests must be answered while it is still held, and no
    redaction or store work may run on the loop's thread. Pre-fix, the loop itself was
    the held thread, so the later requests completed only after the hold ended."""
    gate = _Gate(monkeypatch)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        history = HistoryWriter(store, run_id, batch_size=1)   # as the CLI and web build it
        engine = ProxyEngine(scope=Scope().include("127.0.0.1"), sender=lambda *a: OK,
                             history=history)
        answered_while_held: list[bool] = []

        def req(i):
            return engine.handle_request(
                f"GET /p{i} HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n".encode(), "127.0.0.1", 9)

        async def scenario():
            loop_thread = threading.get_ident()
            assert await req(0) == OK
            while not gate.entered.is_set():               # the first write is now held
                await asyncio.sleep(0.01)
            for i in (1, 2):
                assert await req(i) == OK
                answered_while_held.append(not gate.release.is_set())
            gate.release.set()
            return loop_thread

        loop_thread = asyncio.run(scenario())
        history.close(run_end="complete")
        assert answered_while_held == [True, True]
        assert loop_thread not in gate.threads and gate.threads
        assert _urls(store, run_id) == [f"http://127.0.0.1:9/p{i}" for i in range(3)]


def test_the_loop_parses_only_each_messages_first_line(tmp_path, monkeypatch):
    """Pre-fix, `_record` parsed the whole response (`RawMessage.from_bytes(resp)
    .start_line` splits the head from the body: a scan and a copy of every byte) on the
    loop. Now the method, target and status come from the first line alone."""
    import fuzzlab.proxy.message as message
    seen: list[int] = []
    real = message._split_head_body
    monkeypatch.setattr(message, "_split_head_body",
                        lambda raw: seen.append(len(raw)) or real(raw))
    big = b"HTTP/1.1 200 OK\r\nContent-Length: 4194304\r\n\r\n" + b"y" * (4 << 20)
    req = b"POST /up HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n" + b"z" * (4 << 20)

    class _Hist:
        def __init__(self):
            self.recs = []

        def submit(self, rec):
            self.recs.append(rec)

        record = submit                   # so the pre-fix engine reaches the assertion
    h = _Hist()
    engine = ProxyEngine(scope=Scope().include("127.0.0.1"), sender=lambda *a: big,
                         history=h)
    engine._record(message.RawMessage.from_bytes(req), big, "127.0.0.1", 9, False)
    assert seen and max(seen) <= len(b"POST /up HTTP/1.1\r\n") + 1
    (rec,) = h.recs
    assert (rec.method, rec.url, rec.status) == ("POST", "http://127.0.0.1:9/up", 200)
    assert rec.raw_request is req and rec.raw_response is big          # never copied


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody",
    b"HTTP/1.1 204 No Content\r\n\r\n",
    b"HTTP/1.1 200\r\n\nbody\n",              # a bare-LF separator right after the line
    b"HTTP/1.1 302 Found\r\r\nX: y\r\n\r\n",   # a stray CR before the line end
    b"HTTP/1.1 500 Internal\n\nrest",
    b"HTTP/1.1 200 OK",                        # no line end at all
    b"GET /a?b=1 HTTP/1.1\r\nHost: h\r\n\r\n",
    b"",
])
def test_the_first_line_read_agrees_with_the_full_parse(raw):
    from fuzzlab.proxy.message import RawMessage
    from fuzzlab.proxy.server import _first_line_of
    assert _first_line_of(raw).start_line == RawMessage.from_bytes(raw).start_line


# --- batching by count, bytes and age; ordered; flushed on close ---------------------------

def _spy_batches(monkeypatch) -> list[int]:
    sizes: list[int] = []
    real = HistoryWriter._write

    def write(self, prepared):
        sizes.append(len(prepared))
        return real(self, prepared)
    monkeypatch.setattr(HistoryWriter, "_write", write)
    return sizes


def test_a_batch_is_cut_by_count(tmp_path, monkeypatch):
    sizes = _spy_batches(monkeypatch)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=3, flush_bytes=1 << 30,
                          flush_seconds=3600)
        for i in range(3):
            h.submit(_flow(i))
        assert _until(lambda: h.stats["written"] == 3)
        for i in range(3, 6):
            h.submit(_flow(i))
        assert _until(lambda: h.stats["written"] == 6)
        h.close()
        assert sizes == [3, 3]


def test_a_batch_is_cut_by_bytes(tmp_path, monkeypatch):
    """A batch is written once it holds `flush_bytes`, and one transaction holds at most
    that much plus the flow that crosses it (bounded transactions)."""
    sizes = _spy_batches(monkeypatch)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=10_000, flush_bytes=1000,
                          flush_seconds=3600)
        each = hist._size(_flow(0, pad=400))
        assert 2 * each < 1000 <= 3 * each
        for i in range(6):
            h.submit(_flow(i, pad=400))
        assert _until(lambda: h.stats["written"] == 6)
        h.close()
        assert sizes == [3, 3]


def test_a_batch_is_cut_by_age(tmp_path, monkeypatch):
    """Neither the count nor the byte bound is reached and nobody flushes: the flows are
    still written, once the oldest has waited `flush_seconds`."""
    sizes = _spy_batches(monkeypatch)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=10_000, flush_bytes=1 << 30,
                          flush_seconds=0.2)
        h.submit(_flow(0))
        h.submit(_flow(1))
        assert _until(lambda: len(_urls(store, run_id)) == 2)
        assert sum(sizes) == 2 and h.stats["written"] == 2
        h.close()


def test_close_writes_every_pending_flow_in_submission_order(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=10_000, flush_bytes=1 << 30,
                          flush_seconds=3600)
        for i in range(30):
            h.submit(_flow(i))
        h.close(run_end="complete")
        assert _urls(store, run_id) == [f"http://127.0.0.1:9/p{i}" for i in range(30)]
        ids = [r[0] for r in store.conn.execute(
            "SELECT id FROM flow WHERE run_id=? ORDER BY id", (run_id,))]
        keys = [r[0] for r in store.conn.execute(
            "SELECT key FROM trace_event WHERE run_id=? AND kind='observe.exchange' "
            "ORDER BY seq", (run_id,))]
        assert keys == [f"{TRACE_KEY}{i}" for i in ids]          # traced in the same order
        assert store.conn.execute("SELECT COUNT(*) FROM trace_event WHERE run_id=? AND "
                                  "kind='run.end'", (run_id,)).fetchone()[0] == 1
        m = _metrics(store, run_id)
        assert m["history_accepted"] == m["history_written"] == 30.0
        assert m["history_dropped"] == m["history_failed"] == 0.0
        h.close()                                               # idempotent
        assert len(_urls(store, run_id)) == 30


def test_a_sync_writer_also_flushes_by_bytes(tmp_path):
    """The synchronous path (the repeater) bounds what it holds by bytes too."""
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=10_000, flush_bytes=1000)
        h.record(_flow(0, pad=400))
        h.record(_flow(1, pad=400))
        assert _urls(store, run_id) == []
        h.record(_flow(2, pad=400))
        assert len(_urls(store, run_id)) == 3 and h._buf == []


# --- overflow and failure: counted, reported, never silent ---------------------------------

def test_a_full_queue_drops_are_counted_reported_and_written_live(tmp_path, monkeypatch):
    gate = _Gate(monkeypatch)
    reports: list[tuple] = []
    monkeypatch.setattr(hist, "_report", lambda level, msg, **kw: reports.append(
        (level, msg, kw)))
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=1, max_pending_flows=2)
        flows = [_flow(i) for i in range(5)]
        h.submit(flows[0])
        assert gate.entered.wait(15)                       # flow 0 is being written
        for rec in flows[1:]:
            h.submit(rec)                                  # 1 fits; 2, 3, 4 do not
        s = h.stats
        assert (s["accepted"], s["dropped"]) == (2, 3)
        assert s["dropped_bytes"] == sum(hist._size(r) for r in flows[2:])
        gate.release.set()
        h.flush()
        assert _until(lambda: _metrics(store, run_id).get("history_dropped") == 3.0)
        assert any(level == "warning" and kw.get("dropped") == 3
                   for level, msg, kw in reports)          # logged, live
        h.close()
        assert _urls(store, run_id) == ["http://127.0.0.1:9/p0", "http://127.0.0.1:9/p1"]
        assert _metrics(store, run_id)["history_dropped_bytes"] == s["dropped_bytes"]


def test_the_byte_bound_admits_one_oversized_flow_only_into_an_empty_queue(tmp_path,
                                                                            monkeypatch):
    gate = _Gate(monkeypatch)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=1, max_pending_bytes=1000)
        h.submit(_flow(0, pad=5000))                       # larger than the bound: alone
        assert gate.entered.wait(15)
        h.submit(_flow(1))                                 # anything more is over it
        assert (h.stats["accepted"], h.stats["dropped"]) == (1, 1)
        gate.release.set()
        h.close()
        assert _urls(store, run_id) == ["http://127.0.0.1:9/p0"]


def test_a_failing_write_is_retried_then_counted_and_later_flows_still_write(
        tmp_path, monkeypatch):
    reports: list[tuple] = []
    monkeypatch.setattr(hist, "_report", lambda level, msg, **kw: reports.append(
        (level, msg, kw)))
    monkeypatch.setattr(hist, "RETRY_SECONDS", 0.0)
    real, attempts = HistoryWriter._insert, []

    def insert(self, conn, rec, *a):
        if rec.url.endswith("/p0"):
            attempts.append(1)
            raise sqlite3.OperationalError("database is locked")
        return real(self, conn, rec, *a)
    monkeypatch.setattr(HistoryWriter, "_insert", insert)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=1)
        h.submit(_flow(0))
        h.flush()
        h.submit(_flow(1))
        h.flush()
        s = h.stats
        assert len(attempts) == hist.WRITE_ATTEMPTS
        assert (s["failed"], s["written"], s["retries"]) == (1, 1, hist.WRITE_ATTEMPTS - 1)
        assert _until(lambda: _metrics(store, run_id).get("history_failed") == 1.0)
        assert any(level == "error" and kw.get("error") == "OperationalError"
                   for level, msg, kw in reports)
        h.close()
        assert _urls(store, run_id) == ["http://127.0.0.1:9/p1"]   # never a partial p0


def test_a_writer_that_cannot_open_its_store_counts_every_flow(monkeypatch):
    reports: list[tuple] = []
    monkeypatch.setattr(hist, "_report", lambda level, msg, **kw: reports.append(
        (level, msg, kw)))
    store = Store(":memory:")                     # no file: another thread cannot open it
    try:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=1)
        h.submit(_flow(0))
        h.close()
        h.submit(_flow(1))                         # after close: counted, never queued
        s = h.stats
        assert s["written"] == 0 and s["failed"] + s["dropped"] == 2
        assert any(level == "error" for level, msg, kw in reports)
    finally:
        store.close()


# --- the guard: nothing on the proxy's loop does store or redaction work -------------------

#: Calls the event-loop module must never make: store writes, a synchronous history
#: write, redaction (BUG-0550). `submit` is the history's only loop-side entry.
_LOOP_FORBIDDEN = {"record", "flush", "commit", "execute", "executemany", "executescript",
                   "put_body", "redact", "redact_body_for", "redact_url", "Store"}


def _loop_offenders(src: str) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
        if name in _LOOP_FORBIDDEN:
            out.append(f"{node.lineno}:{name}")
        if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Attribute) and \
                fn.value.attr == "history" and fn.attr != "submit":
            out.append(f"{node.lineno}:history.{fn.attr}")
    return out


def test_the_proxy_loop_never_calls_store_or_redaction_work():
    src = (REPO / "fuzzlab" / "proxy" / "server.py").read_text()
    assert _loop_offenders(src) == []
    assert "self.history.submit(" in src                  # not vacuous


@pytest.mark.parametrize("bad", [
    "def _record(self):\n    self.history.record(FlowRecord('GET', 'u', 'h'))\n",  # pre-fix
    "async def f(self):\n    self.history.flush()\n",
    "def f(self):\n    self.store.conn.commit()\n",
    "def f(raw):\n    return redact(raw)\n",
    "def f(self):\n    self.history.search('x')\n",
    "def f(p):\n    return Store(p)\n",
])
def test_the_loop_work_guard_catches_synthetic_offenders(bad):
    assert _loop_offenders(bad)


#: The repeater controller's calls that send upstream or write the store.
_REPEATER_BLOCKING = {"send", "create_tab", "create_from_flow"}


def _web_loop_offenders(src: str) -> list[str]:
    """Async web handlers that call a blocking repeater method on the event loop."""
    out = []
    for fn in ast.walk(ast.parse(src)):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    node.func.attr in _REPEATER_BLOCKING and \
                    getattr(node.func.value, "id", None) == "repeater_ctl":
                out.append(f"{fn.name}:{node.func.attr}")
    return out


def test_the_web_repeater_check_sees_its_shape():
    assert _web_loop_offenders("async def h():\n    return repeater_ctl.send(1, None)\n")
    assert not _web_loop_offenders(
        "async def h():\n    return await asyncio.to_thread(repeater_ctl.send, 1, None)\n")


@pytest.mark.xfail(strict=True, reason=(
    "BUG-0550 sweep, known and not fixed in this change: the web repeater's handlers "
    "run a blocking upstream send and store writes on the web app's event loop, which "
    "also serves the in-process proxy (`fuzzlab web --with-proxy`). Owner: the UI "
    "component (web/app.py repeater routes, web/proxycontrol.RepeaterController, whose "
    "per-thread store is why the handlers are async)."))
def test_no_web_handler_runs_a_repeater_send_or_write_on_the_event_loop():
    src = (REPO / "fuzzlab" / "web" / "app.py").read_text()
    assert _web_loop_offenders(src) == []
