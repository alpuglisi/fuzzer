"""The proxy's upstream sender keeps well-framed connections (BUG-0549, FR-PROXY-405;
audit defect 24).

`SocketSender` opened a socket per call, and for TLS built a fresh SSL context and did a
full handshake per call. It now leaves an upstream connection for reuse only when the
exchange on it was exactly one well-framed, bodiless HTTP/1.1 request and one fully
framed answer, and neither side said ``Connection: close``. A desync probe (a malformed
request, or a well-formed one with a body an upstream may leave unread: CL.0) never
rides a pooled connection and its connection is closed after it. Only an idempotent
request takes a pooled connection; one whose peer closed it before any byte of answer
is retried once on a fresh connection, and one that got part of an answer, or timed
out, never is (review round 1). Where an answer ends is SP-63's decision
(BUG-0543): an answer it cannot frame raises, a stalled one raises `UpstreamIncomplete`,
and bytes after a framed answer, read with it or still on the socket, close the
connection (merge integration of AU-PROXY and POOL24).

Every test drives the real sender against a loopback keep-alive peer
(`_keepalive_peer`) and reads which connection each request came on there; nothing is
timed (PA-0135).
"""

from __future__ import annotations

import gc
import ssl
import threading

import pytest

from fuzzlab.proxy import socketsender
from fuzzlab.proxy.socketsender import (SocketSender, UpstreamFramingError,
                                        UpstreamIncomplete)
from tests._keepalive_peer import KeepAlivePeer, Reset, echo, ok


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
    # review round 1: whether the upstream read a body cannot be observed (CL.0)
    ("a GET with a body", _get("/case", body=b"x=1"), ok(), False),
    ("a framing header spelled with an underscore",
     _get("/case", "Transfer_Encoding: chunked"), ok(), False),
]


#: Answers SP-63 cannot frame (PA-0543): the call raises `UpstreamFramingError`, a 502 at
#: the engine, and the connection is closed all the same (merge integration: POOL24's
#: cases expected bytes back, from the reader before SP-63).
UNFRAMEABLE = {"a chunked answer whose chunk size is not hex",
               "an answer with chunked and Content-Length"}


@pytest.mark.parametrize("case,request_,answer,rides_pool", NOT_FRAMED,
                         ids=[c[0] for c in NOT_FRAMED])
def test_an_exchange_that_is_not_exactly_framed_never_leaves_its_connection(
        case, request_, answer, rides_pool):
    """Two well-framed exchanges share a connection; then the case's exchange. A
    malformed or ambiguous request never takes the pooled connection; whatever went
    wrong, the case's connection is closed by the sender and never used again, an
    answer SP-63 refuses included (the kept connection's ``except`` path closes it)."""
    def reply(conn, k, req):
        return answer if req.path == "/case" else echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        sender = SocketSender(timeout=1.0)
        try:
            _send(sender, peer, _get("/p1"))
            _send(sender, peer, _get("/p2"))
            pooled = peer.conn_of("/p1")
            assert peer.conn_of("/p2") == pooled and len(pooled) == 1
            if case in UNFRAMEABLE:
                with pytest.raises(UpstreamFramingError):
                    _send(sender, peer, request_)
            else:
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
    POST never takes a pooled connection, and one with a body never leaves its own
    either (review round 1). An answer that stalls on a reused connection raises
    `UpstreamIncomplete` ("idle", SP-63; it returned ``b""`` before SP-63), is never
    resent, and its connection is never kept."""
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
            assert peer.wait(lambda p: post in p.closed)     # a body: never kept
            with pytest.raises(UpstreamIncomplete) as stalled:
                _send(sender, peer, _get("/silent"))
            assert stalled.value.reason == "idle"
            assert peer.conn_of("/silent") == [retried]
            assert [s.path for s in peer.seen] == ["/1", "/2", "/2", "/3", "/silent"]
            assert _send(sender, peer, _get("/4")) == ok(b"/4")
            assert peer.conn_of("/4")[0] not in (first, retried, post)
        finally:
            hold.set()
            sender.close()


def test_a_body_the_upstream_leaves_unread_never_reaches_the_next_request():
    """Review round 1 (CL.0): the upstream answers ``POST /static`` without reading its
    body, which is a request prefix. The POST's connection was kept and the next request,
    another identity's, completed the smuggled one: its request line and ``Cookie`` were
    absorbed and it got the smuggled answer. Wanted: a request with a body is never kept
    (whether the upstream read the body cannot be observed), so the next request arrives
    on a new connection, intact, and gets its own answer."""
    smuggled = b"GET /smuggled HTTP/1.1\r\nX-Ignore: x"
    with KeepAlivePeer(unread_body=lambda req: req.path == "/static") as peer:
        sender = SocketSender(timeout=5)
        try:
            probe = _get("/static", "Cookie: sid=attacker", method="POST", body=smuggled)
            assert _send(sender, peer, probe) == ok(b"/static")
            victim = _get("/me", "Cookie: sid=victim")
            assert _send(sender, peer, victim) == ok(b"/me")
            post = peer.conn_of("/static")[0]
            (me,) = [s for s in peer.seen if s.path == "/me"]
            assert me.conn != post and me.method == "GET"
            assert me.headers.get("cookie") == "sid=victim" and "x-ignore" not in me.headers
            assert "/smuggled" not in [s.path for s in peer.seen]
            assert peer.wait(lambda p: post in p.closed)
        finally:
            sender.close()


def test_a_kept_connection_reset_after_part_of_its_answer_is_never_resent():
    """Review round 1: the stale-connection rule resends only when no byte of answer
    came. The upstream writes part of a status line for the second request on a kept
    connection and resets: the call raises, the upstream saw that request once, and the
    connection is not used again. A reset before any byte is still resent once. A clean
    close after part of an answer is SP-63's `UpstreamIncomplete` ("eof"), never resent
    either (merge integration)."""
    def reply(conn, k, req):
        if req.path == "/partial" and k == 1:
            return Reset(b"HTTP/1.1 500 Internal Server Er")
        if req.path == "/none" and k == 1:
            return Reset()
        if req.path == "/cut" and k == 1:
            return (b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\npar",)
        return echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        sender = SocketSender(timeout=5)
        try:
            assert _send(sender, peer, _get("/1")) == ok(b"/1")
            kept = peer.conn_of("/1")[0]
            with pytest.raises(ConnectionResetError):
                _send(sender, peer, _get("/partial"))
            assert peer.conn_of("/partial") == [kept]
            assert _send(sender, peer, _get("/2")) == ok(b"/2")
            fresh = peer.conn_of("/2")[0]
            assert fresh != kept
            assert _send(sender, peer, _get("/none")) == ok(b"/none")
            assert peer.conn_of("/none")[0] == fresh and len(peer.conn_of("/none")) == 2
            kept = peer.conn_of("/none")[1]
            with pytest.raises(UpstreamIncomplete) as cut:
                _send(sender, peer, _get("/cut"))
            assert cut.value.reason == "eof" and peer.conn_of("/cut") == [kept]
        finally:
            sender.close()


@pytest.mark.parametrize("read_size", [None, len(ok(b"/case"))],
                         ids=["read with the answer", "left on the socket"])
def test_bytes_after_a_framed_answer_never_leave_its_connection_kept(read_size,
                                                                     monkeypatch):
    """Merge integration (AU-PROXY with POOL24, BUG-0549): the upstream answers one
    request with two responses in one segment, as a desynchronised upstream does. SP-63
    returns the first, framed one; the second was read past its end (the reader's
    leftover) or, when the receive stopped at that end, waits on the socket. On d83876f
    the connection was kept, the stray answer dropped unseen or, arriving later, read
    as the next request's answer. Wanted: the call returns the first answer, the sender
    closes the connection at once (never kept), and the next request gets its own
    answer on another connection."""
    if read_size is not None:
        monkeypatch.setattr(socketsender, "READ_SIZE", read_size)

    def reply(conn, k, req):
        if req.path == "/case":
            return ok(b"/case") + ok(b"stray")
        return echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        sender = SocketSender(timeout=5)
        try:
            assert _send(sender, peer, _get("/p1")) == ok(b"/p1")
            assert _send(sender, peer, _get("/case")) == ok(b"/case")
            case_conn = peer.conn_of("/case")[0]
            assert case_conn == peer.conn_of("/p1")[0]       # it rode the kept one
            assert peer.wait(lambda p: case_conn in p.closed)
            assert _send(sender, peer, _get("/after")) == ok(b"/after")
            assert peer.conn_of("/after")[0] != case_conn
        finally:
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
