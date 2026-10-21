"""Tests for the Repeater (Phase 2.3): controller + routes."""

from __future__ import annotations

import socket
import threading

import pytest

from fuzzlab.core.config import load_config
from fuzzlab.core.store import Store
from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.web.proxycontrol import RepeaterController


def _cfg(path, **over):
    return load_config(overrides={"store_path": str(path), **over}, environ={})


def _threaded_upstream():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            target = data.split(b" ")[1] if b" " in data else b"/"
            body = b"echo=" + target
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%b" % (len(body), body))
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


# --- controller ------------------------------------------------------------

def test_create_list_and_send_with_injected_sender(tmp_path):
    seen = {}

    def fake(host, port, tls, raw):
        seen["req"] = raw
        return b"HTTP/1.1 200 OK\r\n\r\n"

    ctrl = RepeaterController(_cfg(tmp_path / "r.db"), sender=fake)
    assert ctrl.list_tabs() == []                       # read-only, no store yet
    assert not (tmp_path / "r.db").exists()
    # The controller never creates a store (CC-UI-0450): its routes first call
    # ProjectManager.require_writable(), which creates the project file; stand in here.
    Store(tmp_path / "r.db").close()
    tab = ctrl.create_tab("t", "127.0.0.1", 8080, "GET /a HTTP/1.1\r\nHost: h\r\n\r\n")
    tabs = ctrl.list_tabs()
    assert len(tabs) == 1 and tabs[0]["name"] == "t" and tabs[0]["port"] == 8080
    out = ctrl.send(tab["id"], "GET /edited HTTP/1.1\r\nHost: h\r\n\r\n")
    assert b"/edited" in seen["req"] and out["response"].startswith("HTTP/1.1 200")
    assert ctrl.send(99999) is None                      # unknown tab


def test_each_repeater_send_gets_a_fresh_upstream_connection(tmp_path):
    """BUG-0549 review round 1 (audit defect 24: "retain fresh sockets for deliberate
    desynchronization probes and connection-sensitive experiments"). The Repeater's
    sender is cached per server thread; with kept connections, tab "alice" and then tab
    "bob" went on one upstream connection, so connection state crossed tabs and
    identities. Wanted: each send on a connection of its own, closed after it."""
    from tests._keepalive_peer import KeepAlivePeer
    with KeepAlivePeer() as peer:
        Store(tmp_path / "r.db").close()               # stands in for require_writable
        ctrl = RepeaterController(_cfg(tmp_path / "r.db"))     # its own SocketSender
        tabs = {who: ctrl.create_tab(who, "127.0.0.1", peer.port,
                                     f"GET /{who} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                                     f"Cookie: sid={who}\r\n\r\n")
                for who in ("alice", "bob")}
        for who in ("alice", "bob", "alice"):
            assert ctrl.send(tabs[who]["id"])["response"].endswith(f"/{who}")
        assert peer.connections == 3
        assert peer.conn_of("/alice") == [1, 3] and peer.conn_of("/bob") == [2]
        assert peer.wait(lambda p: p.closed >= {1, 2, 3})


def test_create_from_flow(tmp_path):
    path = tmp_path / "r.db"
    with Store(path) as store:
        rid = store.start_run("proxy", "127.0.0.1")
        hw = HistoryWriter(store, rid, batch_size=1)
        hw.record(FlowRecord(method="GET", url="http://127.0.0.1:8080/p.php", host="127.0.0.1:8080",
                             raw_request=b"GET /p.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
                             raw_response=b"HTTP/1.1 200 OK\r\n\r\n"))
        hw.flush()
        fid = store.conn.execute("SELECT id FROM flow").fetchone()["id"]
    ctrl = RepeaterController(_cfg(path))
    tab = ctrl.create_from_flow(fid)
    assert tab["host"] == "127.0.0.1" and tab["port"] == 8080
    assert "GET /p.php" in tab["raw"]
    assert ctrl.create_from_flow(99999) is None


# --- routes ----------------------------------------------------------------

pytest.importorskip("fastapi")

from fuzzlab.web.app import create_app  # noqa: E402
from tests._webclient import web_client  # noqa: E402


def test_routes_list_create_and_send_gate(tmp_path):
    client = web_client(create_app(_cfg(tmp_path / "r.db", authorized=False)))
    assert client.get("/api/proxy/repeater/tabs").json()["tabs"] == []
    made = client.post("/api/proxy/repeater/tabs",
                       json={"name": "t", "host": "127.0.0.1", "port": 80,
                             "raw": "GET / HTTP/1.1\r\nHost: h\r\n\r\n"}).json()
    assert made["id"] and client.get("/api/proxy/repeater/tabs").json()["tabs"][0]["id"] == made["id"]
    # send is gated on authorization
    assert client.post(f"/api/proxy/repeater/tabs/{made['id']}/send", json={}).status_code == 403


def test_route_send_reaches_upstream_when_authorized(tmp_path):
    srv, port = _threaded_upstream()
    try:
        client = web_client(create_app(_cfg(tmp_path / "r.db", authorized=True)))
        tab = client.post("/api/proxy/repeater/tabs",
                          json={"name": "u", "host": "127.0.0.1", "port": port,
                                "raw": "GET /orig HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"}).json()
        out = client.post(f"/api/proxy/repeater/tabs/{tab['id']}/send",
                          json={"raw": "GET /edited HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"}).json()
        assert "echo=/edited" in out["response"]
        # unknown tab → 404
        assert client.post("/api/proxy/repeater/tabs/99999/send", json={}).status_code == 404
    finally:
        srv.close()


def test_route_from_flow_404_missing(tmp_path):
    client = web_client(create_app(_cfg(tmp_path / "r.db")))
    assert client.post("/api/proxy/repeater/from-flow/1").status_code == 404
