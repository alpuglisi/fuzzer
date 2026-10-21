"""The proxy's upstream sender keeps well-framed connections (BUG-0549, FR-PROXY-405;
audit defect 24).

`SocketSender` opened a socket per call, and for TLS built a fresh SSL context and did a
full handshake per call. It now leaves an upstream connection for reuse only when the
exchange on it was exactly one well-framed HTTP/1.1 request and one fully framed
answer, and neither side said ``Connection: close``. A deliberately malformed request (a
desync probe) never rides a pooled connection and its connection is closed after it.
Only an idempotent request takes a pooled connection; one whose peer closed it before a
byte of answer is retried once on a fresh connection, and a timeout never is.

Every test drives the real sender against a loopback keep-alive peer
(`_keepalive_peer`) and reads which connection each request came on there; nothing is
timed (PA-0135).
"""

from __future__ import annotations

import gc
import ssl
import threading

import pytest

from fuzzlab.proxy.socketsender import SocketSender
from tests._keepalive_peer import KeepAlivePeer, echo, ok


def _get(path: str, *extra: str, method: str = "GET", body: bytes = b"") -> bytes:
    head = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", *extra]
    if body:
        head.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


def _send(sender: SocketSender, peer: KeepAlivePeer, raw: bytes) -> bytes:
    return sender("127.0.0.1", peer.port, False, raw)


CHUNKED = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"


def test_well_framed_keep_alive_exchanges_reuse_one_upstream_connection():
    """Defect 24: five exchanges came on five connections. Wanted: one, over
    Content-Length and chunked answers alike, each answer its own request's."""
    def reply(conn, k, req):
        return CHUNKED if req.path.startswith("/chunked") else echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        sender = SocketSender(timeout=5)
        try:
            for path in ("/a", "/b", "/chunked1", "/chunked2", "/c"):
                got = _send(sender, peer, _get(path))
                assert got == (CHUNKED if path.startswith("/chunked") else ok(path.encode()))
            assert peer.connections == 1 and len(peer.seen) == 5
        finally:
            sender.close()


NOT_FRAMED = [
    # (case, the request, the answer, rides the pooled connection)
    ("answer says Connection: close", _get("/case"),
     ok(b"x", "Connection: close"), True),
    ("close-delimited answer", _get("/case"),
     (b"HTTP/1.1 200 OK\r\n\r\nuntil-close",), True),
    ("bytes past the answer's Content-Length", _get("/case"),
     b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA", True),
    ("two Content-Length headers in the answer", _get("/case"),
     b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok", True),
    ("an HTTP/1.0 answer", _get("/case"),
     b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", True),
    ("a chunked answer whose chunk size is not hex", _get("/case"),
     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nok\r\n0\r\n\r\n", True),
    ("an answer with chunked and Content-Length", _get("/case"),
     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n"
     b"2\r\nok\r\n0\r\n\r\n", True),
    ("an answer asking for connection-bound auth", _get("/case"),
     ok(b"x", "WWW-Authenticate: Negotiate"), True),
    ("a request with two Content-Length headers (a desync probe)",
     b"GET /case HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n"
     b"Content-Length: 0\r\n\r\n", ok(), False),
    ("a chunked request",
     b"POST /case HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
     b"2\r\nok\r\n0\r\n\r\n", ok(), False),
    ("a request saying Connection: close", _get("/case", "Connection: close"), ok(),
     False),
    ("a pipelined second request", _get("/case") + _get("/case2"), ok(), False),
    ("a HEAD request", _get("/case", method="HEAD"),
     b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", False),
    ("a request with connection-bound auth", _get("/case", "Authorization: NTLM TlRM"),
     ok(), False),
]


@pytest.mark.parametrize("case,request_,answer,rides_pool", NOT_FRAMED,
                         ids=[c[0] for c in NOT_FRAMED])
def test_an_exchange_that_is_not_exactly_framed_never_leaves_its_connection(
        case, request_, answer, rides_pool):
    """Two well-framed exchanges share a connection; then the case's exchange. A
    malformed or ambiguous request never takes the pooled connection; whatever went
    wrong, the case's connection is closed by the sender and never used again."""
    def reply(conn, k, req):
        return answer if req.path == "/case" else echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        sender = SocketSender(timeout=1.0)
        try:
            _send(sender, peer, _get("/p1"))
            _send(sender, peer, _get("/p2"))
            pooled = peer.conn_of("/p1")
            assert peer.conn_of("/p2") == pooled and len(pooled) == 1
            _send(sender, peer, request_)
            case_conn = peer.conn_of("/case")[0]
            assert (case_conn == pooled[0]) is rides_pool, case
            assert peer.wait(lambda p: case_conn in p.closed), case
            assert _send(sender, peer, _get("/after")) == ok(b"/after")
            assert peer.conn_of("/after")[0] != case_conn
        finally:
            sender.close()


def test_a_stale_pooled_connection_is_retried_once_and_a_timeout_never():
    """The peer closes a connection when its second request arrives, with no answer
    (an idle close racing a reuse): the GET is retried once on a fresh connection. A
    POST never takes a pooled connection. An answer that times out on a reused
    connection is never resent."""
    hold = threading.Event()

    def reply(conn, k, req):
        if req.path == "/silent":
            hold.wait(10)
            return None
        return None if k == 1 and req.path == "/2" else echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        sender = SocketSender(timeout=1.0)
        try:
            assert _send(sender, peer, _get("/1")) == ok(b"/1")
            assert _send(sender, peer, _get("/2")) == ok(b"/2")
            first, retried = peer.conn_of("/2")
            assert first == peer.conn_of("/1")[0] and retried != first
            assert _send(sender, peer, _get("/3", method="POST", body=b"x=1")) == ok(b"/3")
            post = peer.conn_of("/3")[0]
            assert post not in (first, retried)
            assert _send(sender, peer, _get("/silent")) == b""
            assert peer.conn_of("/silent") in ([post], [retried])
            assert [s.path for s in peer.seen] == ["/1", "/2", "/2", "/3", "/silent"]
        finally:
            hold.set()
            sender.close()


def test_tls_upstream_connections_are_reused_and_the_context_built_once(
        tmp_path, monkeypatch):
    """Defect 24: every TLS call built a new SSL context and did a full handshake.
    Wanted: one context per sender and one handshake for three exchanges (verified
    against the test's own CA; verification stays on)."""
    pytest.importorskip("cryptography")
    from fuzzlab.proxy.ca import LocalCA
    ca = LocalCA(tmp_path / "ca")
    cert, key = ca.leaf_cert_files("127.0.0.1")
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(cert), str(key))
    real = ssl.create_default_context
    built: list[int] = []

    def trusting(*a, **k):
        built.append(1)
        return real(cafile=str(ca.ca_cert_path))
    monkeypatch.setattr(ssl, "create_default_context", trusting)

    with KeepAlivePeer(tls=server) as peer:
        sender = SocketSender(timeout=5)
        try:
            for path in ("/x", "/y", "/z"):
                assert sender("127.0.0.1", peer.port, True, _get(path)) == ok(path.encode())
            assert (peer.connections, peer.handshakes, len(built)) == (1, 1, 1)
        finally:
            sender.close()


def test_concurrent_exchanges_each_get_their_own_answer_on_reused_connections():
    """Eight threads, five exchanges each: every answer is its own request's, and at
    most one connection per thread is opened (a pooled connection is used by one call
    at a time)."""
    with KeepAlivePeer() as peer:
        sender = SocketSender(timeout=5)
        answers: dict[str, bytes] = {}

        def worker(t: int) -> None:
            for i in range(5):
                path = f"/t{t}-{i}"
                answers[path] = _send(sender, peer, _get(path))

        try:
            threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(30)
            assert len(answers) == 40
            assert all(got == ok(p.encode()) for p, got in answers.items())
            assert peer.connections <= 8
        finally:
            sender.close()


def test_closing_the_sender_closes_its_idle_upstream_connections():
    """`close` closes the idle connections (a later call still works, on a connection
    closed after it); a sender dropped without `close` closes them when collected."""
    with KeepAlivePeer() as peer:
        sender = SocketSender(timeout=5)
        _send(sender, peer, _get("/a"))
        a = peer.conn_of("/a")[0]
        assert a not in peer.closed
        sender.close()
        assert peer.wait(lambda p: a in p.closed)
        assert _send(sender, peer, _get("/after")) == ok(b"/after")
        after = peer.conn_of("/after")[0]
        assert peer.wait(lambda p: after in p.closed)

        dropped = SocketSender(timeout=5)
        _send(dropped, peer, _get("/b"))
        b = peer.conn_of("/b")[0]
        del dropped
        gc.collect()
        assert peer.wait(lambda p: b in p.closed)
