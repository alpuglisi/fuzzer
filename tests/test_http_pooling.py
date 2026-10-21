"""The core seam keeps its connections (BUG-0549, FR-CORE-509; audit defect 24).

`HttpClient`'s default transport sent every request through a fresh
``bodyread.bound(requests.Session())`` and closed it, so every send paid a TCP (and TLS)
setup. It now keeps one pooled, bounded session per (origin, identity, session
generation): never a connection or a cookie jar shared across identities or
generations, the pool of a replaced generation dropped once its last send is done, every
pool dropped at `HttpClient.close` (or when the client is collected). Review round 1: the
transport never re-sends (each try is the sender's to make and record, FR-FUZZ-61), and
a send with a body never leaves or takes a pooled connection (CL.0).

Every test drives the real seam against a loopback keep-alive peer (`_keepalive_peer`)
and reads which connection each request came on there; nothing is timed (PA-0135).
"""

from __future__ import annotations

import gc
import select
import socket
import ssl
import threading

import pytest
import requests

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient, Request
from tests._keepalive_peer import KeepAlivePeer, echo, ok


class _Generations:
    """A session addon applying a generation per identity, as `SessionManager.prepare`
    does (``session_generation`` and the session's own ``Cookie`` header)."""

    def __init__(self, **gens: int):
        self.gen = dict(gens)

    def prepare(self, request, identity):
        g = self.gen.get(identity)
        if g is not None:
            request.headers = {**request.headers, "Cookie": f"sid={identity}{g}"}
            request.session_generation = g

    def observe(self, request, response, identity):
        pass

    def authorize(self, request, identity, prepared_host=None):
        pass


def _client(session=None) -> HttpClient:
    return HttpClient(RequestBudget(10_000), ["127.0.0.1"], session=session, timeout=5)


def _get(client: HttpClient, peer: KeepAlivePeer, path: str, identity="anonymous",
         method="GET", body=None):
    return client.send(Request(method, peer.url + path, identity=identity, body=body))


def test_sends_of_one_identity_share_a_connection_sequentially_and_concurrently():
    """Defect 24: five sequential sends came on five connections. Wanted: one, and
    twenty sends from four threads on at most one connection per thread, each answer
    its own request's."""
    with KeepAlivePeer() as peer:
        client = _client()
        try:
            for i in range(5):
                assert _get(client, peer, f"/s{i}").body == f"/s{i}".encode()
            assert peer.connections == 1

            answers: dict[str, bytes] = {}

            def worker(t: int) -> None:
                for i in range(5):
                    path = f"/t{t}-{i}"
                    answers[path] = _get(client, peer, path).body

            threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(30)
            assert answers == {p: p.encode() for p in answers} and len(answers) == 20
            assert len(peer.seen) == 25
            assert peer.connections <= 1 + 4
        finally:
            client.close()


def test_identities_and_generations_never_share_a_connection_or_a_cookie_jar():
    """Each (identity, generation) has its own connection; a cookie the peer sets is
    never sent back by the transport (the seam sets ``Cookie`` itself); a new generation
    gets a new connection and the old generation's is closed; a late send prepared on the
    old generation goes on a connection of its own, closed after it, and never displaces
    the new generation's pool."""
    def reply(conn, k, req):
        return ok(req.path.encode(), "Set-Cookie: planted=1; Path=/")

    with KeepAlivePeer(reply) as peer:
        addon = _Generations(alice=1, bob=1)
        client = _client(addon)
        try:
            for who in ("alice", "bob", "anonymous"):
                for i in range(2):
                    assert _get(client, peer, f"/{who}{i}", who).status == 200
            alice, bob, anon = (peer.conn_of(f"/{w}0") + peer.conn_of(f"/{w}1")
                                for w in ("alice", "bob", "anonymous"))
            assert alice[0] == alice[1] and bob[0] == bob[1] and anon[0] == anon[1]
            assert len({alice[0], bob[0], anon[0]}) == 3
            cookies = {s.path: s.headers.get("cookie") for s in peer.seen}
            assert cookies == {"/alice0": "sid=alice1", "/alice1": "sid=alice1",
                               "/bob0": "sid=bob1", "/bob1": "sid=bob1",
                               "/anonymous0": None, "/anonymous1": None}

            addon.gen["alice"] = 2                       # a re-login: generation 2
            _get(client, peer, "/alice-g2a", "alice")
            _get(client, peer, "/alice-g2b", "alice")
            g2 = peer.conn_of("/alice-g2a") + peer.conn_of("/alice-g2b")
            assert g2[0] == g2[1] and g2[0] not in (alice[0], bob[0], anon[0])
            assert peer.wait(lambda p: alice[0] in p.closed)
            assert bob[0] not in peer.closed and anon[0] not in peer.closed

            addon.gen["alice"] = 1                       # a send prepared before it
            _get(client, peer, "/alice-late", "alice")
            late = peer.conn_of("/alice-late")[0]
            assert late not in (alice[0], g2[0])
            assert peer.wait(lambda p: late in p.closed)
            addon.gen["alice"] = 2
            _get(client, peer, "/alice-g2c", "alice")
            assert peer.conn_of("/alice-g2c") == [g2[0]]
        finally:
            client.close()


def test_a_generation_change_never_closes_a_send_still_in_flight():
    """The old generation's pool is retired, not closed under a send that still uses
    it: that send gets its whole answer, and its connection is closed after it."""
    release = threading.Event()

    def reply(conn, k, req):
        if req.path == "/slow":
            release.wait(10)
        return echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        addon = _Generations(alice=1)
        client = _client(addon)
        try:
            out: dict[str, bytes] = {}
            t = threading.Thread(
                target=lambda: out.update(slow=_get(client, peer, "/slow", "alice").body))
            t.start()
            assert peer.wait(lambda p: p.conn_of("/slow"))
            addon.gen["alice"] = 2
            assert _get(client, peer, "/fast1", "alice").body == b"/fast1"
            assert _get(client, peer, "/fast2", "alice").body == b"/fast2"
            slow = peer.conn_of("/slow")[0]
            assert peer.conn_of("/fast1") == peer.conn_of("/fast2") != [slow]
            assert slow not in peer.closed
            release.set()
            t.join(10)
            assert out == {"slow": b"/slow"}
            assert peer.wait(lambda p: slow in p.closed)
        finally:
            release.set()
            client.close()


def test_a_reused_connection_closed_before_any_answer_is_never_resent_by_the_transport():
    """Review round 1 (FR-FUZZ-61, PA-0510): the transport resent a GET whose reused
    connection the peer closed unanswered, below the sender that records each try, so
    the target got two requests for one recorded try. Wanted: one try per send. The
    failure raises as any transport failure (SP-34); the next send goes on a new
    connection."""
    def reply(conn, k, req):
        return None if k == 1 else echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        client = _client()
        try:
            assert _get(client, peer, "/1").body == b"/1"
            with pytest.raises(requests.exceptions.ConnectionError):
                _get(client, peer, "/2")
            assert [s.path for s in peer.seen] == ["/1", "/2"]
            assert peer.conn_of("/2") == peer.conn_of("/1")
            assert _get(client, peer, "/3").body == b"/3"
            assert peer.conn_of("/3")[0] != peer.conn_of("/1")[0]
            assert [s.path for s in peer.seen] == ["/1", "/2", "/3"]
        finally:
            client.close()


def test_a_send_with_a_body_never_leaves_or_takes_a_pooled_connection():
    """Review round 1 (CL.0; the PA-0002 sweep of the proxy sender's defect): a target
    that answers without reading a request's body leaves it at the head of the next
    request on that connection, so the next send of that identity completes a smuggled
    request and gets its answer. Whether a target read a body cannot be observed.
    Wanted: a send with a body goes on a connection of its own, closed after it; the
    pooled connection of bodiless sends is untouched."""
    smuggled = b"GET /smuggled HTTP/1.1\r\nX-Ignore: x"
    with KeepAlivePeer(unread_body=lambda req: req.path == "/static") as peer:
        client = _client()
        try:
            assert _get(client, peer, "/warm").body == b"/warm"
            warm = peer.conn_of("/warm")[0]
            assert _get(client, peer, "/static", method="POST",
                        body=smuggled).body == b"/static"
            post = peer.conn_of("/static")[0]
            assert post != warm
            assert _get(client, peer, "/next").body == b"/next"
            assert peer.conn_of("/next") == [warm]
            assert "/smuggled" not in [s.path for s in peer.seen]
            assert peer.wait(lambda p: post in p.closed) and warm not in peer.closed
        finally:
            client.close()


def test_closing_the_client_closes_its_pooled_connections():
    """`HttpClient.close` drops every pool (a later send still works, on a connection
    of its own that is closed after it); a client dropped without `close` closes its
    pools when it is collected."""
    with KeepAlivePeer() as peer:
        client = _client(_Generations(alice=1))
        _get(client, peer, "/a", "alice")
        _get(client, peer, "/b")
        held = set(peer.conn_of("/a") + peer.conn_of("/b"))
        assert len(held) == 2 and not held & peer.closed
        client.close()
        assert peer.wait(lambda p: held <= p.closed)
        assert _get(client, peer, "/after").status == 200
        after = peer.conn_of("/after")[0]
        assert peer.wait(lambda p: after in p.closed)

        dropped = _client()
        _get(dropped, peer, "/c")
        c = peer.conn_of("/c")[0]
        del dropped
        gc.collect()
        assert peer.wait(lambda p: c in p.closed)


#: Answers to ``/case`` followed by bytes past their framed end, in one segment, each
#: measured on urllib3 2.8.0 to leave the connection kept with the bytes dropped
#: (`scratchpad/lanes/INTEG/measure_seam_r2.py`): (the answer, what it carries).
STRAYS = {
    "a second answer": (ok(b"/case") + ok(b"stray"), b"/case"),
    "a chunked answer, then another": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n/case\r\n0\r\n\r\n"
        + ok(b"stray"), b"/case"),
    "an empty answer, then another": (ok(b"") + ok(b"stray"), b""),
    "a 204, then bytes": (b"HTTP/1.1 204 No Content\r\n\r\n" + ok(b"stray"), b""),
    "a lone CRLF after the answer": (ok(b"/case") + b"\r\n", b"/case"),
}


def _stray_reply(answer: bytes):
    """``/case`` gets ``answer``; were the next request sent on that connection, a
    second stray answer would reach the client before the real one (the checker's late
    stray: written after the first while the next answer is held), so a kept
    connection shows as the next send getting ``stray2``."""
    case: list[int] = []

    def reply(conn, k, req):
        if req.path == "/case":
            case.append(conn)
            return answer
        if req.path == "/after" and conn in case:
            return ok(b"stray2") + ok(b"/after")
        return echo(conn, k, req)
    return reply


@pytest.mark.parametrize("answer,body", STRAYS.values(), ids=STRAYS.keys())
def test_an_answer_followed_by_another_never_leaves_its_pooled_connection(answer, body):
    """Review round 2 (P2-1, a security regression of this bug's pooling): the target
    answers ``/case`` and sends more bytes past that answer's framed end in the same
    segment (a desynchronised upstream). urllib3 read them into the first response's
    buffer, http.client dropped them with its reader at the framed end, and the
    connection was kept: the next send rode it, and a stray answer arriving later was
    read as that send's answer (measured: ``after=b'stray2'``). Wanted: the send gets
    its own answer, the connection is closed at once and never reused, and the next send
    gets its own answer on another connection."""
    with KeepAlivePeer(_stray_reply(answer)) as peer:
        client = _client()
        try:
            assert _get(client, peer, "/p1").body == b"/p1"
            assert _get(client, peer, "/case").body == body
            case_conn = peer.conn_of("/case")[0]
            assert case_conn == peer.conn_of("/p1")[0]          # it rode the kept one
            assert peer.wait(lambda p: case_conn in p.closed)
            assert _get(client, peer, "/after").body == b"/after"
            assert peer.conn_of("/after") != [case_conn]
            assert _get(client, peer, "/next").body == b"/next"   # and that one is kept
            assert peer.conn_of("/next") == peer.conn_of("/after")
            assert [s.path for s in peer.seen] == ["/p1", "/case", "/after", "/next"]
        finally:
            client.close()


class _TlsTunnel:
    """A loopback HTTPS proxy: TLS to the client, ``CONNECT``, then a byte relay to the
    target, so the client's TLS to the target runs inside the proxy's (urllib3's
    ``SSLTransport``). Counts the tunnels it opened."""

    def __init__(self, ctx):
        self._ctx = ctx
        self.tunnels = 0
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.url = f"https://127.0.0.1:{self._srv.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                raw, _ = self._srv.accept()
            except OSError:
                return                                   # closed
            threading.Thread(target=self._relay, args=(raw,), daemon=True).start()

    def _relay(self, raw) -> None:
        conn = up = None
        try:
            conn = self._ctx.wrap_socket(raw, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            host, port = head.split(b" ")[1].decode().rsplit(":", 1)
            up = socket.create_connection((host, int(port)))
            self.tunnels += 1
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            while True:
                ready = [conn] if conn.pending() else \
                    select.select([conn, up], [], [], 5)[0]
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is conn else conn).sendall(data)
        except (OSError, ValueError):
            return
        finally:
            for s in (conn, up, raw):
                if s is not None:
                    s.close()

    def close(self) -> None:
        self._srv.close()


@pytest.mark.parametrize("tunnel", [False, True], ids=["direct", "inside a proxy's TLS"])
@pytest.mark.parametrize("size", [5, 10_000], ids=["in the reader", "in the TLS layer"])
def test_a_stray_answer_held_by_tls_never_leaves_its_pooled_connection(
        size, tunnel, tmp_path, monkeypatch):
    """Review round 2 (P2-1) over TLS: a stray answer in the same TLS record as the
    answer is buffered by the response's reader (a small answer), or stays in the TLS
    layer when the reader asked for exactly the answer's last bytes (a 10000-byte
    answer: measured 43 bytes pending in the SSL object, the socket not readable). On
    4e0c2c6 the connection was kept and, for the second, the next send was answered
    with the stray. Through an HTTPS proxy the bytes wait in urllib3's ``SSLTransport``.
    Wanted: closed at once, the next send's own answer on another connection; clean
    exchanges keep one connection (one handshake, one tunnel) as before. Verification
    stays on, against the test's own CA."""
    pytest.importorskip("cryptography")
    from fuzzlab.proxy.ca import LocalCA
    ca = LocalCA(tmp_path / "ca")
    cert, key = ca.leaf_cert_files("127.0.0.1")
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(cert), str(key))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca.ca_cert_path))
    proxy = _TlsTunnel(server) if tunnel else None
    for name in ("no_proxy", "NO_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy",
                 "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    if proxy is not None:
        monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    answer = ok(b"x" * size)
    try:
        with KeepAlivePeer(_stray_reply(answer + ok(b"stray")), tls=server) as peer:
            client = _client()
            try:
                https = f"https://127.0.0.1:{peer.port}"
                for path in ("/p1", "/p2"):
                    assert client.send(Request("GET", https + path)).body == path.encode()
                assert (peer.connections, peer.handshakes) == (1, 1)
                assert proxy is None or proxy.tunnels == 1
                assert client.send(Request("GET", https + "/case")).body == b"x" * size
                case_conn = peer.conn_of("/case")[0]
                assert case_conn == peer.conn_of("/p1")[0]
                assert peer.wait(lambda p: case_conn in p.closed)
                assert client.send(Request("GET", https + "/after")).body == b"/after"
                assert peer.conn_of("/after") != [case_conn]
            finally:
                client.close()
    finally:
        if proxy is not None:
            proxy.close()
