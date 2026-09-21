"""Live h2c transport (Phase 9 Part K): the socket send/receive around the raw
HTTP/2 client. A one-shot loopback TCP server plays the h2c server side, so the real
socket path is exercised offline without nginx."""

import socket
import threading

from fuzzlab.proxy import h2frames
from fuzzlab.proxy.h2client import H2RawClient
from fuzzlab.proxy.h2transport import H2Transport


def _one_shot(server_bytes: bytes, record: dict | None = None) -> tuple[str, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def handle() -> None:
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(1.0)
                got = bytearray()
                try:
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        got += chunk
                        if b"\r\n\r\nSM\r\n\r\n" in got:
                            break            # got the client's preface -> respond promptly
                except (socket.timeout, TimeoutError):
                    pass
                if record is not None:
                    record["req"] = bytes(got)
                conn.sendall(server_bytes)
                try:
                    conn.recv(65536)         # e.g. the client's SETTINGS ACK
                except (socket.timeout, TimeoutError):
                    pass
        finally:
            srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return host, port


def test_request_reads_status_and_body_over_a_real_socket():
    sid = 1                                   # H2RawClient starts client streams at 1
    server = (h2frames.settings_frame({})
              + h2frames.headers_frame(sid, b"\x88", end_stream=False)  # :status: 200 (indexed)
              + h2frames.data_frame(sid, b"<html>ok</html>", end_stream=True))
    host, port = _one_shot(server)
    resp = H2Transport(timeout=5).request(host, port, "GET", "/product.php")
    assert resp.got_headers
    assert resp.status == 200                  # static-indexed :status decodes
    assert b"<html>ok</html>" in resp.body     # DATA body reassembled


def test_send_raw_puts_arbitrary_bytes_on_the_wire_byte_exact():
    rec: dict = {}
    host, port = _one_shot(b"pong", record=rec)
    client = H2RawClient()
    # a deliberately length-desync frame (declares 1 byte, carries 4) — the primitive
    raw = client.build_raw([h2frames.encode_frame(h2frames.DATA, 0, 1, b"AAAA", length=1)])
    got = H2Transport(timeout=5).send_raw(host, port, raw, settle=0.3)
    assert got == b"pong"
    assert rec["req"] == raw                    # exact bytes reached the server
    assert raw.startswith(h2frames.PREFACE)


def test_send_raw_carries_crlf_header_value_verbatim():
    """The h2->h1 desync primitive: a header value with CRLF passes through HPACK and
    onto the wire unchanged (a downgrading front-end is what may mis-split it)."""
    rec: dict = {}
    host, port = _one_shot(b"", record=rec)
    client = H2RawClient()
    raw = client.build_request("GET", "/", "127.0.0.1", "http",
                               headers=[(b"x-smuggle", b"a\r\nX-Injected: 1")])
    H2Transport(timeout=5).send_raw(host, port, raw, settle=0.3)
    assert b"a\r\nX-Injected: 1" in rec["req"]   # CRLF-bearing value went on the wire
