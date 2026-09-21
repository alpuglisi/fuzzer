"""Live-proxy last mile (Phase 6, runbook Part I): the real socket sender, byte-exact
forwarding of a malformed (duplicate Content-Length) request, and CONNECT/TLS.

The socket-sender and byte-exact tests are fully offline (loopback sockets / a recording
sender). The CONNECT+TLS end-to-end test is skip-guarded on a working `cryptography`
(the sandbox has none), so it runs on-host — the same guard the CA-minting test uses.
"""

import asyncio
import socket
import ssl
import threading

import pytest

from fuzzlab.proxy import parser
from fuzzlab.proxy.ca import LocalCA
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.server import AsyncProxyServer
from fuzzlab.proxy.socketsender import SocketSender
from tests.test_proxy_server import RESP, _engine


def _one_shot_server(response: bytes) -> tuple[str, int, threading.Thread]:
    """A loopback TCP server that accepts one connection, reads the request, replies
    with ``response``, and closes (so a close-delimited body terminates cleanly)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def handle() -> None:
        try:
            conn, _ = srv.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(response)
        finally:
            srv.close()

    t = threading.Thread(target=handle, daemon=True)
    t.start()
    return host, port, t


def test_socket_sender_reads_content_length_response():
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    host, port, t = _one_shot_server(resp)
    got = SocketSender(timeout=5)(host, port, False,
                                  b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    t.join(timeout=5)
    assert got == resp                     # exact bytes, headers + body


def test_socket_sender_reads_close_delimited_response():
    resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nno-length-body"
    host, port, t = _one_shot_server(resp)
    got = SocketSender(timeout=5)(host, port, False,
                                  b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    t.join(timeout=5)
    assert got == resp                     # read until the peer closed


def test_async_server_forwards_duplicate_content_length_byte_exact(tmp_path):
    """The raw path forwards a malformed request (duplicate Content-Length) verbatim,
    while the parsed path would reject it — the Part I exit property."""
    async def scenario():
        store, eng, sender, _hist = _engine(tmp_path)
        server = await AsyncProxyServer(eng, "127.0.0.1", 0).start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            req = (b"POST http://127.0.0.1:9/echo HTTP/1.1\r\n"
                   b"Host: 127.0.0.1:9\r\n"
                   b"Content-Length: 5\r\n"
                   b"Content-Length: 6\r\n\r\nhello")
            writer.write(req)
            await writer.drain()
            data = await reader.read(len(RESP))
            writer.close()
            return data, sender
        finally:
            await server.stop()
            store.close()

    data, sender = asyncio.run(scenario())
    assert data == RESP
    fwd = sender.sent[0][3]
    assert fwd.count(b"Content-Length:") == 2          # duplicate preserved on the wire
    assert fwd.endswith(b"\r\n\r\nhello")              # body intact, byte-exact
    assert parser.is_valid_request(fwd) is False       # parsed path would have rejected it


def test_connect_tls_tunnel_forwards_byte_exact(tmp_path):
    """On-host: CONNECT → 200 → TLS-terminate with a CA-minted leaf → forward the
    tunnelled request to the (TLS) upstream, byte-exact."""
    try:
        from cryptography import x509  # noqa: F401
        from cryptography.fernet import Fernet
        Fernet(Fernet.generate_key()).encrypt(b"probe")   # force the rust bindings
    except BaseException as exc:  # noqa: BLE001 - broken native build panics
        pytest.skip(f"cryptography unavailable/broken: {exc}")

    ca = LocalCA(tmp_path / "ca")
    ca.ensure_ca()

    async def scenario():
        store, eng, sender, _hist = _engine(tmp_path)
        server = await AsyncProxyServer(eng, "127.0.0.1", 0, ca=ca).start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\n\r\n")
            await writer.drain()
            established = await reader.readuntil(b"\r\n\r\n")
            assert b"200" in established
            cctx = ssl.create_default_context(cafile=str(ca.ca_cert_path))
            cctx.check_hostname = False       # chain is verified; SAN is a DNSName(ip)
            await writer.start_tls(cctx, server_hostname="127.0.0.1")
            writer.write(b"GET /secret HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n")
            await writer.drain()
            data = await reader.read(len(RESP))
            writer.close()
            return data, sender
        finally:
            await server.stop()
            store.close()

    data, sender = asyncio.run(scenario())
    assert data == RESP
    host, port, use_tls, fwd = sender.sent[0]
    assert host == "127.0.0.1" and use_tls is True      # forwarded to the TLS upstream
    assert RawMessage.from_bytes(fwd).start_line == b"GET /secret HTTP/1.1"
