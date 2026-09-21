"""Phase 6 T6.4: interception-as-awaited-future and the DB-persisted repeater."""

import asyncio

from fuzzlab.core.store import Store
from fuzzlab.proxy.history import HistoryWriter
from fuzzlab.proxy.intercept import Interceptor
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.repeater import Repeater

REQ = (b"POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
       b"Content-Length: 9\r\n\r\nuser=abcd")
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


async def _until_pending(interceptor, n=1):
    for _ in range(100):
        if len(interceptor.pending()) >= n:
            return
        await asyncio.sleep(0)
    raise AssertionError("flow never became pending")


# --- interception --------------------------------------------------------------
def test_disabled_passes_through_immediately():
    interceptor = Interceptor(enabled=False)
    msg = RawMessage.from_bytes(REQ)
    out = asyncio.run(interceptor.handle(msg, "request"))
    assert out is msg and interceptor.pending() == []


def test_forward_with_edit_releases_edited_message():
    interceptor = Interceptor(enabled=True)

    async def scenario():
        task = asyncio.create_task(
            interceptor.handle(RawMessage.from_bytes(REQ), "request", "127.0.0.1:8080"))
        await _until_pending(interceptor)
        pend = interceptor.pending()[0]
        assert pend.direction == "request" and pend.host == "127.0.0.1:8080"
        edited = pend.message.with_request_line(b"POST /admin HTTP/1.1")
        interceptor.forward(pend.id, edited)
        return await task

    out = asyncio.run(scenario())
    assert out.target == b"/admin"
    assert interceptor.pending() == []            # cleaned up after release


def test_forward_without_edit_returns_original():
    interceptor = Interceptor(enabled=True)

    async def scenario():
        task = asyncio.create_task(interceptor.handle(RawMessage.from_bytes(REQ)))
        await _until_pending(interceptor)
        interceptor.forward(interceptor.pending()[0].id)
        return await task

    assert asyncio.run(scenario()).raw == REQ


def test_drop_returns_none():
    interceptor = Interceptor(enabled=True)

    async def scenario():
        task = asyncio.create_task(interceptor.handle(RawMessage.from_bytes(REQ)))
        await _until_pending(interceptor)
        interceptor.drop(interceptor.pending()[0].id)
        return await task

    assert asyncio.run(scenario()) is None


def test_disabling_releases_held_flows():
    interceptor = Interceptor(enabled=True)

    async def scenario():
        task = asyncio.create_task(interceptor.handle(RawMessage.from_bytes(REQ)))
        await _until_pending(interceptor)
        interceptor.set_enabled(False)            # releases everything unedited
        return await task

    assert asyncio.run(scenario()).raw == REQ


# --- repeater ------------------------------------------------------------------
class _FakeSender:
    def __init__(self, response=RESP):
        self.response = response
        self.sent = []                            # (host, port, tls, raw)

    def __call__(self, host, port, use_tls, raw):
        self.sent.append((host, port, use_tls, raw))
        return self.response


def _repeater(tmp_path, sender, history=False):
    store = Store(tmp_path / "u.db")
    run_id = store.start_run("proxy", "127.0.0.1:8080")
    hist = HistoryWriter(store, run_id) if history else None
    return store, Repeater(store, run_id, sender, history=hist)


def test_tab_persists_and_lists(tmp_path):
    store, rep = _repeater(tmp_path, _FakeSender())
    tab = rep.create_tab("login", "127.0.0.1", 8080, REQ)
    assert tab.id and rep.get_tab(tab.id).raw_request == REQ
    assert [t.name for t in rep.list_tabs()] == ["login"]
    store.close()


def test_send_is_byte_exact(tmp_path):
    sender = _FakeSender()
    store, rep = _repeater(tmp_path, sender)
    tab = rep.create_tab("login", "127.0.0.1", 8080, REQ)
    resp = rep.send(tab.id)
    assert resp == RESP
    assert sender.sent[0] == ("127.0.0.1", 8080, False, REQ)   # exact bytes
    store.close()


def test_send_edited_raw_updates_tab_and_sends_exact(tmp_path):
    sender = _FakeSender()
    store, rep = _repeater(tmp_path, sender)
    tab = rep.create_tab("login", "127.0.0.1", 8080, REQ)
    edited = RawMessage.from_bytes(REQ).with_appended_header("Content-Length", "44").raw
    rep.send(tab.id, raw_request=edited)
    assert sender.sent[0][3] == edited                          # duplicate CL sent as-is
    assert rep.get_tab(tab.id).raw_request == edited            # persisted edit
    store.close()


def test_send_records_history_when_attached(tmp_path):
    sender = _FakeSender()
    store, rep = _repeater(tmp_path, sender, history=True)
    tab = rep.create_tab("prod", "127.0.0.1", 8080,
                         b"GET /product.php?id=1 HTTP/1.1\r\nHost: h\r\n\r\n")
    rep.send(tab.id)
    rep.history.flush()
    hits = rep.history.search("product.php")
    assert len(hits) == 1 and hits[0]["method"] == "GET"
    store.close()
