"""The intercepting proxy's history in the trace (FR-PROXY-13, FR-UI-512).

The real proxy path, in process: `AsyncProxyServer` + `ProxyEngine` + the real
`SocketSender` + `HistoryWriter(batch_size=1)` (as `fuzzlab proxy --record` builds it),
driven by a raw HTTP client against a loopback upstream. Each recorded flow is one
``observe.exchange`` event, written live, with a stable key; nothing secret reaches the
trace; the data flow and the ``proxy`` sequence show what passed through, including a
failed upstream as a lost arrow; an out-of-scope host and a repeater send produce none.
Loopback only: no lab container is contacted."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.core import trace
from fuzzlab.core.store import Store
from fuzzlab.proxy.history import TRACE_KEY, FlowRecord, HistoryWriter, flow_event
from fuzzlab.proxy.intercept import Interceptor
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.server import AsyncProxyServer, ProxyEngine
from fuzzlab.proxy.socketsender import SocketSender
from fuzzlab.report import diagram

SECRETS = ("SECRETCOOKIE77", "SECRETAUTH88", "SECRETPW99", "SECRETTOKEN1234567abc",
           "SECRETJSON55", "SECRETLOC66")


class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body=b"ok", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/hangup"):
            self.connection.shutdown(socket.SHUT_RDWR)       # no response at all
            return None
        return self._send(200, b"<html>page</html>")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.startswith("/login"):
            return self._send(302, b"", [("Location",
                                          f"/home?session={SECRETS[5]}&tab=1")])
        return self._send(201, b'{"ok":true}', [("Content-Type", "application/json")])


@pytest.fixture(scope="module")
def upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _request(method, url, *, headers=(), body=b"") -> bytes:
    host = url.split("/")[2]
    head = [f"{method} {url} HTTP/1.1", f"Host: {host}"] + list(headers)
    if body:
        head.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


async def _through(port, raw) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data


def _events(conn, run_id):
    return [dict(r) | {"body": json.loads(r["body"])} for r in conn.execute(
        "SELECT key, kind, scope, seq, t, body FROM trace_event WHERE run_id=? "
        "ORDER BY seq", (run_id,))]


@pytest.fixture(scope="module")
def proxied(upstream, tmp_path_factory):
    """Six flows through the real proxy: a login with every kind of secret, a JSON
    body, a page, a hang-up, a refused upstream, and an out-of-scope host."""
    path = tmp_path_factory.mktemp("pt") / "s.db"
    store = Store(path)
    run_id = store.start_run("proxy", "127.0.0.1")
    history = HistoryWriter(store, run_id, batch_size=1)
    engine = ProxyEngine(scope=Scope().include("127.0.0.1"),
                         sender=SocketSender(timeout=3.0), history=history,
                         identity="alice")
    base, dead = f"http://127.0.0.1:{upstream}", f"http://127.0.0.1:{_closed_port()}"
    live: list[int] = []
    t0 = time.time()

    async def scenario():
        server = await AsyncProxyServer(engine, "127.0.0.1", 0).start()
        try:
            login = await _through(server.port, _request(
                "POST", f"{base}/login?token={SECRETS[3]}&next=1",
                headers=(f"Cookie: sid={SECRETS[0]}",
                         f"Authorization: Bearer {SECRETS[1]}",
                         "Content-Type: application/x-www-form-urlencoded"),
                body=f"user=alice&password={SECRETS[2]}".encode()))
            # live: the flow's event is in the store before the proxy stops
            live.append(store.conn.execute(
                "SELECT COUNT(*) FROM trace_event WHERE run_id=?", (run_id,)).fetchone()[0])
            await _through(server.port, _request(
                "POST", f"{base}/api/items", headers=("Content-Type: application/json",),
                body=json.dumps({"name": "x", "api_key": SECRETS[4]}).encode()))
            await _through(server.port, _request("GET", f"{base}/page?q=1"))
            await _through(server.port, _request("GET", f"{base}/hangup?x=1"))
            refused = await _through(server.port, _request("GET", f"{dead}/refused"))
            await _through(server.port, _request(
                "GET", f"http://localhost:{upstream}/outside?token={SECRETS[3]}"))
            return login, refused, list(server.errors)
        finally:
            await server.stop()

    login, refused, errors = asyncio.run(scenario())
    yield {"store": store, "run": run_id, "history": history, "base": base,
           "dead": dead, "live": live, "login": login, "refused": refused,
           "errors": errors, "t0": t0, "t1": time.time()}
    store.close()


def _proxy_events(proxied):
    return [e for e in _events(proxied["store"].conn, proxied["run"])
            if e["kind"] == "observe.exchange"]


def test_each_recorded_flow_is_one_event_live_with_a_stable_key(proxied):
    conn, run_id = proxied["store"].conn, proxied["run"]
    assert proxied["login"].startswith(b"HTTP/1.0 302") or b" 302 " in proxied["login"]
    assert proxied["live"] == [1]                       # written before the proxy stopped
    flows = [r["id"] for r in conn.execute("SELECT id FROM flow WHERE run_id=? ORDER BY id",
                                           (run_id,))]
    events = _proxy_events(proxied)
    assert [e["key"] for e in events] == [f"{TRACE_KEY}{i}" for i in flows]
    assert len(flows) == 5                              # the out-of-scope flow: none
    for e, fid in zip(events, flows):
        b = e["body"]
        assert e["scope"] == "proxy" and b["src"] == "proxy"
        assert b["ref"] == f"flow id {fid}" and b["profile"] == "alice"
        assert proxied["t0"] <= e["t"] <= proxied["t1"]   # the flow's own time
    login = events[0]["body"]
    assert login["method"] == "POST" and login["status"] == 302
    assert login["origin"] == proxied["base"]
    assert login["location"].startswith(proxied["base"] + "/home") or \
        login["location"].startswith("/home")
    assert login["params"] == [["token", "query"], ["next", "query"],
                               ["user", "body"], ["password", "body"]]
    assert events[1]["body"]["params"] == [["name", "json"], ["api_key", "json"]]


def test_no_secret_reaches_the_trace_the_model_or_the_exports(proxied):
    conn, run_id = proxied["store"].conn, proxied["run"]
    texts = [r[0] for r in conn.execute("SELECT body FROM trace_event WHERE run_id=?",
                                        (run_id,))]
    texts += [r[0] for r in conn.execute(
        "SELECT attrs FROM dg_entity WHERE run_id=? UNION ALL SELECT label FROM dg_entity "
        "WHERE run_id=? UNION ALL SELECT attrs FROM dg_flow WHERE run_id=?",
        (run_id, run_id, run_id))]
    texts.append(json.dumps(diagram.export_json(conn, run_id)))
    texts.append(diagram.mermaid_flow(diagram.dataflow(conn, run_id)))
    texts.append(json.dumps(diagram.sequence(conn, run_id, "proxy")))
    texts.append(diagram.mermaid_sequence(diagram.sequence(conn, run_id, "proxy")))
    blob = "\n".join(texts)
    assert "/login" in blob and "password" in blob      # not vacuous: names are kept
    for secret in SECRETS:
        assert secret not in blob, secret


def test_an_out_of_scope_host_produces_no_event(proxied):
    blob = json.dumps([e["body"] for e in _events(proxied["store"].conn,
                                                  proxied["run"])])
    assert "/outside" not in blob
    assert proxied["store"].conn.execute(
        "SELECT COUNT(*) FROM flow WHERE url LIKE '%/outside%'").fetchone()[0] == 0


def test_the_data_flow_shows_the_proxied_interfaces_seen_from_the_browser(proxied):
    conn, run_id, base = proxied["store"].conn, proxied["run"], proxied["base"]
    model = diagram.dataflow(conn, run_id)
    ids = {n["id"]: n for n in model["nodes"]}
    login = f"iface:{base}|POST|/login"
    assert ids[trace.BROWSER]["kind"] == "actor" and login in ids
    flow = next(f for f in model["flows"] if f["dst"] == login)
    assert flow["src"] == trace.BROWSER and flow["view"] == "app"
    assert flow["attrs"]["basis"] == [f"browser instrumentation (proxy): flow id "
                                      f"{_proxy_events(proxied)[0]['body']['ref'][8:]}"]
    assert flow["attrs"]["auth"] == ["alice"] and flow["attrs"]["status"] == [302]
    assert "credential:body" in flow["attrs"]["data"]
    assert not [f for f in model["flows"] if f["src"] == trace.TOOL]   # not tool traffic
    # an answered proxied flow is captured browser traffic; a failed upstream is not
    cov = diagram.interface_coverage(conn, run_id)
    assert cov[login]["discovered"] == cov[login]["captured"] == 1
    refused = f"iface:{proxied['dead']}|GET|/refused"
    assert cov[refused]["discovered"] == 1 and cov[refused]["captured"] == 0


def test_the_proxy_sequence_forwards_and_draws_a_failed_upstream_lost(proxied):
    conn, run_id = proxied["store"].conn, proxied["run"]
    scopes = {s["scope"]: s for s in diagram.scopes(conn, run_id)}
    assert scopes["proxy"]["kind"] == "proxy"
    assert scopes["proxy"]["label"].startswith("proxied traffic (intercepting proxy)")
    seq = diagram.sequence(conn, run_id, "proxy")
    kinds = {p["id"]: p["kind"] for p in seq["participants"]}
    assert kinds["browser"] == "actor" and kinds["proxy"] == "tool"
    assert kinds[f"origin:{proxied['base']}"] == "target"
    assert "order" in seq["notes"][0]
    forwards = [s for s in seq["steps"] if s.get("kind") == "forward"]
    assert len(forwards) == 5 and all(s["label"] == "forwarded" for s in forwards)
    lost = [s for s in seq["steps"] if s["type"] == "lost"]
    assert [s["label"] for s in lost] == ["no response (connection closed)",
                                          "no response (ConnectionRefusedError)"]
    assert lost[1]["src"] == f"origin:{proxied['dead']}" and lost[1]["dst"] == "proxy"
    assert b"502" in proxied["refused"]                 # the browser still got its 502
    for s in lost:                                       # never a reply to the browser
        cited = [x for x in seq["steps"] if s["evidence"][0] in x["evidence"]]
        assert not [x for x in cited if x.get("kind") == "response"]
    replies = [s for s in seq["steps"] if s.get("kind") == "response"]
    assert {s["label"] for s in replies if s["dst"] == "browser"} == {"302", "201", "200"}
    assert "-x" in diagram.mermaid_sequence(seq)
    ts = [e["t"] for e in _proxy_events(proxied)]
    assert ts == sorted(ts)                              # drawn in the order received


def test_a_reflush_or_reprocessing_adds_nothing(proxied):
    store, run_id, history = proxied["store"], proxied["run"], proxied["history"]

    def count():
        return store.conn.execute("SELECT COUNT(*) FROM trace_event WHERE run_id=?",
                                  (run_id,)).fetchone()[0]
    before = count()
    assert history.flush() == 0 and count() == before
    history.close()
    stats = {r["key"]: r["value"] for r in store.conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,))}
    assert stats["trace_written"] == before and stats["trace_dropped"] == 0
    # re-processing each stored flow through a fresh recorder: duplicates only
    rec = trace.TraceRecorder(store, run_id)
    for e in _proxy_events(proxied):
        rec.emit(e["kind"], e["body"], key=e["key"], scope=e["scope"], t=e["t"])
    assert rec.close()["duplicates"] == before and count() == before


# --- the writer's own guarantees ----------------------------------------------------------
def _flow(path="/a", **kw):
    raw = (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n").encode()
    return FlowRecord("GET", f"http://127.0.0.1:9{path}", "127.0.0.1:9", 200,
                      raw_request=raw, raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
                      t=1000.0, **kw)


def _keys(store, run_id):
    return [r[0] for r in store.conn.execute(
        "SELECT key FROM trace_event WHERE run_id=? ORDER BY seq", (run_id,))]


def test_a_failed_flush_and_its_retry_give_one_event_per_flow(tmp_path, monkeypatch):
    import sqlite3
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=100)
        h.record(_flow("/p0"))
        h.record(_flow("/p1"))
        real = h._insert
        calls = []

        def failing(conn, rec, *a):
            calls.append(1)
            if len(calls) == 2:
                raise sqlite3.OperationalError("disk I/O error")
            return real(conn, rec, *a)
        monkeypatch.setattr(h, "_insert", failing)
        with pytest.raises(sqlite3.OperationalError):
            h.flush()
        assert _keys(store, run_id) == []               # nothing written, nothing traced
        monkeypatch.setattr(h, "_insert", real)
        assert h.flush() == 2
        ids = [r[0] for r in store.conn.execute("SELECT id FROM flow ORDER BY id")]
        assert _keys(store, run_id) == [f"{TRACE_KEY}{i}" for i in ids]


def test_an_owners_transaction_is_left_alone_and_a_rollback_traces_nothing(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=1)
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run_id, "owner_work", 1.0))
        h.record(_flow("/rolled-back"))
        assert store.conn.in_transaction                # the owner's, still open
        store.conn.rollback()
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run_id, "owner_work", 2.0))
        h.record(_flow("/kept"))
        store.conn.commit()                             # the owner commits this one
        assert _keys(store, run_id) == []
        h.close()
        (fid,) = [r[0] for r in store.conn.execute("SELECT id FROM flow")]
        assert _keys(store, run_id) == [f"{TRACE_KEY}{fid}"]
        body = json.loads(store.conn.execute("SELECT body FROM trace_event").fetchone()[0])
        assert body["url"].endswith("/kept")


def test_repeater_sends_and_a_writer_without_a_run_are_not_traced(tmp_path):
    from fuzzlab.proxy.repeater import Repeater
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=1)
        rep = Repeater(store, run_id, lambda *a: resp, history=h)
        tab = rep.create_tab("t", "127.0.0.1", 9, b"GET /r HTTP/1.1\r\nHost: x\r\n\r\n")
        rep.send(tab.id)
        assert store.conn.execute("SELECT COUNT(*) FROM flow").fetchone()[0] == 1
        assert _keys(store, run_id) == []
        none = HistoryWriter(store, None, batch_size=100)
        none._trace([(1, _flow(), "http://127.0.0.1:9/a", b"", b"", True)])
        assert _keys(store, run_id) == [] and none._recorder is None


def test_interception_decisions_are_recorded_and_drawn(upstream, tmp_path):
    """An operator's edit is carried as ``intercept`` and drawn on the forward; a
    synthetic drop (the proxy records no flow for one) is drawn with no forward."""
    base = f"http://127.0.0.1:{upstream}"
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("proxy", "x")
        h = HistoryWriter(store, run_id, batch_size=1)
        interceptor = Interceptor(enabled=True)
        engine = ProxyEngine(scope=Scope().include("127.0.0.1"),
                             sender=SocketSender(timeout=3.0), history=h,
                             interceptor=interceptor)

        async def scenario(edit):
            task = asyncio.create_task(engine.handle_request(
                f"GET /a HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\n\r\n".encode(),
                "127.0.0.1", upstream))
            for _ in range(200):
                if interceptor.pending():
                    break
                await asyncio.sleep(0)
            pend = interceptor.pending()[0]
            interceptor.forward(pend.id, pend.message.with_request_line(
                b"GET /b HTTP/1.1") if edit else None)
            return await task
        asyncio.run(scenario(True))
        asyncio.run(scenario(False))
        bodies = [e["body"] for e in _events(store.conn, run_id)]
        assert [b["intercept"] for b in bodies] == ["request edited", "request forwarded"]
        assert bodies[0]["url"] == f"{base}/b"
        rec = trace.TraceRecorder(store, run_id)
        rec.emit("observe.exchange", {"src": "proxy", "ref": "synthetic", "method": "GET",
                                      "url": f"{base}/c", "origin": base,
                                      "intercept": "request dropped"},
                 key="synthetic-drop", scope="proxy", t=time.time() + 60)
        rec.close()
        seq = diagram.sequence(store.conn, run_id, "proxy")
        forwards = [s["label"] for s in seq["steps"] if s.get("kind") == "forward"]
        assert forwards == ["forwarded (edited by the operator)", "forwarded"]
        last = seq["steps"][-2:]
        assert last[0]["kind"] == "request" and last[1]["type"] == "note"
        assert last[1]["label"].startswith("dropped by the operator")


def test_the_event_is_a_pure_function_of_the_written_flow():
    rec = _flow("/x?token=SECRETTOKEN1234567abc&a=1", identity="bob")
    a = flow_event(7, rec, rec.url, rec.raw_request, rec.raw_response)
    b = flow_event(7, rec, rec.url, rec.raw_request, rec.raw_response)
    assert a == b and a[0] == f"{TRACE_KEY}7" and a[2] == 1000.0
    assert "SECRETTOKEN1234567abc" not in json.dumps(a)
    assert a[1]["params"] == [["token", "query"], ["a", "query"]]


def test_stopping_the_web_proxy_records_its_end_and_its_counters(upstream, tmp_path):
    """The web proxy's stop closes the writer with the run's end, so a stopped proxy
    run reads complete, with the recorder's counters (never 'partial' for want of an
    end); the CLI does the same on Ctrl-C."""
    from fuzzlab.report import diagram
    from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController
    path = tmp_path / "s.db"
    Store(path).close()                  # the app makes the project file exist
    ctrl = ProxyController(ProxyConfig(port=0, scope_hosts=("127.0.0.1",),
                                       store_path=str(path)))

    async def scenario():
        await ctrl.start()
        try:
            await _through(ctrl.server.port,
                           _request("GET", f"http://127.0.0.1:{upstream}/page?q=1"))
        finally:
            await ctrl.stop()
    asyncio.run(scenario())
    with Store(path) as store:
        run = store.conn.execute("SELECT MAX(id) FROM run").fetchone()[0]
        doc = diagram.status(store.conn, run)
        assert doc["run_end"] == "complete" and doc["state"] == "complete"
        assert doc["by_kind"] == {"observe.exchange": 1, "run.end": 1}
        assert doc["recorder"]["written"] == 2.0 and doc["recorder"]["dropped"] == 0.0
