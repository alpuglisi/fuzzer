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


@pytest.mark.xfail(strict=True, reason=(
    "Merge-integration sweep of BUG-0549's I2 (a connection is kept only when nothing "
    "follows its framed answer), known and not fixed in this change: the seam's pooled "
    "session (requests over urllib3) reads a second answer that came in the same segment "
    "into the first response's buffer, drops it unseen and keeps the connection; one "
    "arriving after urllib3's checkout check would be read as the next send's answer. "
    "Measured on 18cdf9f: the next GET rode the same connection. Owner: CORE "
    "(`core/http.py::PooledTransport`; every `requests` session shares the mechanism)."))
def test_an_answer_followed_by_another_never_leaves_its_pooled_connection():
    """The target answers ``/case`` twice in one segment (a desynchronised upstream).
    Wanted: the send gets the first answer and the next send another connection."""
    def reply(conn, k, req):
        if req.path == "/case":
            return ok(b"/case") + ok(b"stray")
        return echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        client = _client()
        try:
            assert _get(client, peer, "/p1").body == b"/p1"
            assert _get(client, peer, "/case").body == b"/case"
            case_conn = peer.conn_of("/case")[0]
            assert _get(client, peer, "/after").body == b"/after"
            assert peer.conn_of("/after")[0] != case_conn
        finally:
            client.close()
