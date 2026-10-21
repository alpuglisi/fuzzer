"""The native proxy's HTTP/1 framing and its inbound bounds, over real loopback sockets
(audit defects 18-20; BUG-0543, FR-PROXY-401..403, SP-63).

A real client talks to the real `AsyncProxyServer`, which forwards through the real
`SocketSender` to a real upstream socket (`_Upstream`). Nothing is faked but the
upstream's script.

- Defect 18: a chunked request is read whole (trailer included), de-chunked and sent
  with a ``Content-Length``; an unframeable or over-limit request is answered 400 / 413
  and never forwarded.
- Defect 19: a response ends where its framing says: never at payload bytes that look
  like the last chunk, never at an idle receive or a close before its framed end (that is
  `UpstreamIncomplete`, a 502, recorded as no response), never later than its end for a
  trailer, HEAD, 204, 304 or an interim response.
- Defect 20: the head, the body and the time to receive one request are bounded while
  reading (431 / 413 / 408), connections over the cap are answered 503, every refusal is
  counted, and every bound is configurable.
"""

from __future__ import annotations

import ast
import asyncio
import re
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest

from fuzzlab.proxy import socketsender
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.server import AsyncProxyServer, ProxyEngine
from fuzzlab.proxy.socketsender import SocketSender

ROOT = Path(__file__).resolve().parents[1]
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class _Upstream:
    """A loopback upstream on a real socket. For each connection it reads one request
    (its head, then a ``Content-Length`` body, else whatever arrives within 0.5 s), keeps
    the bytes in ``requests``, then sends ``parts`` in order (a float is a pause in
    seconds) and closes, or, with ``hold``, keeps the connection open until `close`.
    ``then`` gives the parts for each later connection instead (its last repeats)."""

    def __init__(self, parts=(OK,), *, hold=False, then=()):
        self.parts, self.hold, self.then = list(parts), hold, list(then)
        self.requests: list[bytes] = []
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _read(self, conn) -> bytes:
        conn.settimeout(0.5)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return data
                data += chunk
            head = data.split(b"\r\n\r\n", 1)[0]
            m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
            if not m and b"chunked" not in head.lower():
                return data
            while True:
                if m and len(data) - len(head) - 4 >= int(m.group(1)):
                    return data
                chunk = conn.recv(65536)
                if not chunk:
                    return data
                data += chunk
        except (socket.timeout, TimeoutError):
            return data

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            with conn:
                self.requests.append(self._read(conn))
                n = len(self.requests) - 2
                parts = self.parts if n < 0 or not self.then else \
                    self.then[min(n, len(self.then) - 1)]
                for part in parts:
                    if isinstance(part, float):
                        time.sleep(part)
                    else:
                        conn.sendall(part)
                if self.hold:
                    self._stop.wait(30)

    def close(self) -> None:
        self._stop.set()
        self._srv.close()


@pytest.fixture
def upstream():
    made = []

    def make(*parts, hold=False, then=()):
        up = _Upstream(parts or (OK,), hold=hold, then=then)
        made.append(up)
        return up
    yield make
    for up in made:
        up.close()


class _Hist:
    def __init__(self):
        self.recs = []

    def record(self, rec):
        self.recs.append(rec)


def _server(**kw):
    hist = _Hist()
    engine = ProxyEngine(scope=Scope().include("127.0.0.1"),
                         sender=SocketSender(timeout=kw.pop("timeout", 5.0)),
                         history=hist)
    return AsyncProxyServer(engine, "127.0.0.1", 0, **kw), hist


async def _exchange(port, *pieces, wait=5.0) -> bytes:
    """Send ``pieces`` (a float is a pause) while reading what the proxy answers, until
    it closes (or ``wait`` passes); stop sending once it has answered and closed."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    got = bytearray()

    async def read():
        try:
            while chunk := await reader.read(65536):
                got.extend(chunk)
        except ConnectionError:
            pass
    reading = asyncio.create_task(read())
    try:
        for piece in pieces:
            if reading.done():
                break
            if isinstance(piece, float):
                await asyncio.sleep(piece)
            else:
                writer.write(piece)
                await writer.drain()
    except ConnectionError:
        pass
    try:
        await asyncio.wait_for(reading, wait)
    except asyncio.TimeoutError:
        pass
    writer.close()
    return bytes(got)


def _through(server, *pieces, wait=5.0) -> bytes:
    async def main():
        await server.start()
        try:
            return await _exchange(server.port, *pieces, wait=wait)
        finally:
            await server.stop()
    return asyncio.run(main())


def _post(port, headers: bytes, body: bytes = b"") -> bytes:
    return (b"POST http://127.0.0.1:%d/up HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
            % (port, port) + headers + b"\r\n" + body)


# --- defect 18: request framing --------------------------------------------------------

def test_a_chunked_request_reaches_the_upstream_whole_and_de_chunked(upstream):
    """Pre-fix, the listener returned at the head: the upstream got a chunked head with
    no body, and the chunk bytes were left to be read as the next request."""
    up = upstream(OK)
    server, hist = _server()
    head = _post(up.port, b"Transfer-Encoding: chunked\r\n")
    got = _through(server, head, 0.05, b"3;ext=1\r\nab", 0.05, b"c\r\nA\r\n0123456789\r",
                   0.05, b"\n0\r\nX-Checksum: 9\r\n\r\n")
    assert got == OK
    (fwd,) = up.requests
    assert b"Transfer-Encoding" not in fwd and b"X-Checksum" not in fwd
    assert b"\r\nContent-Length: 13\r\n" in fwd
    assert fwd.endswith(b"\r\n\r\nabc0123456789")
    assert hist.recs[0].raw_request.endswith(b"\r\n\r\nabc0123456789")


@pytest.mark.parametrize("headers,body", [
    (b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
    (b"Transfer-Encoding: chunked\r\n", b"zz\r\nhello\r\n0\r\n\r\n"),
    (b"Transfer-Encoding: chunked\r\n", b"5\r\nhelloXX0\r\n\r\n"),
    (b"Transfer-Encoding: gzip, chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
    (b"Content-Length: 5\r\nContent-Length: 6\r\n", b"hello"),
    (b"Content-Length: -5\r\n", b"hello"),
    # malformed field syntax (review round 1, B1): each was framed and forwarded
    (b"X: y\n\nGET /smuggled HTTP/1.1\r\nHost: h\r\n", b""),
    (b"Transfer-Encoding\t: chunked\r\n", b"3\r\nabc\r\n0\r\n\r\n"),
    (b"Content-Length: 5\r\nTransfer-Encoding : chunked\r\n", b"hello"),
    (b"Content-Length: 5\r\nX: a\r\n Transfer-Encoding: chunked\r\n", b"hello"),
    (b"X: a\rContent-Length: 5\r\n", b"hello"),
], ids=["cl-and-te", "bad-chunk-size", "no-crlf-after-data", "not-chunked-alone",
        "conflicting-cl", "invalid-cl", "bare-lf-pipeline", "ws-in-te-name",
        "ws-before-colon", "obs-folded-te", "bare-cr"])
def test_a_request_that_cannot_be_framed_is_answered_400_and_never_forwarded(
        upstream, headers, body):
    """Never forwarded: the upstream gets no connection at all."""
    up = upstream(OK)
    server, hist = _server()
    got = _through(server, _post(up.port, headers, body))
    assert got.startswith(b"HTTP/1.1 400 ") and b"Connection: close" in got
    assert up.requests == [] and hist.recs == []
    assert server.counts["malformed"] == 1


@pytest.mark.parametrize("headers,body", [
    (b"Content-Length: 1000000000000\r\n", b""),
    (b"Transfer-Encoding: chunked\r\n", b"ffffffffff\r\n"),
], ids=["content-length", "chunk-size"])
def test_an_over_limit_request_body_is_answered_413_before_it_is_read(upstream, headers,
                                                                      body):
    """Pre-fix, ``readexactly(Content-Length)`` waited for a terabyte, unbounded."""
    up = upstream(OK)
    server, _hist = _server()
    got = _through(server, _post(up.port, headers, body))
    assert got.startswith(b"HTTP/1.1 413 ")
    assert up.requests == [] and server.counts["oversized"] == 1


def test_raw_framing_forwards_conflicting_lengths_by_the_first_and_nothing_else(upstream):
    """The explicit raw mode (D4) keeps the conflicting Content-Length study; a request
    with both Transfer-Encoding and Content-Length is still refused."""
    up = upstream(OK)
    server, _hist = _server(raw_framing=True)
    req = _post(up.port, b"Content-Length: 5\r\nContent-Length: 6\r\n", b"hello")
    assert _through(server, req) == OK
    assert up.requests[0].endswith(b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello")
    server2, _ = _server(raw_framing=True)
    both = _post(up.port, b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n", b"hello")
    assert _through(server2, both).startswith(b"HTTP/1.1 400 ")
    assert len(up.requests) == 1


def test_the_bytes_after_a_chunked_request_are_the_next_request():
    """In a keep-alive (TLS) connection, the bytes after one request's last chunk are the
    next request, never the remains of the first."""
    from fuzzlab.proxy.framing import FrameLimits, MessageReader
    limits = FrameLimits(1024, 1024)
    first = MessageReader("request", limits, dechunk=True)
    first.feed(b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"
               b"\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n")
    assert first.done and first.message().endswith(b"Content-Length: 3\r\n\r\nabc")
    second = MessageReader("request", limits, dechunk=True)
    second.feed(first.leftover)
    assert second.done and second.message() == b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n"


# --- defect 19: response framing -------------------------------------------------------

def _send(up, request=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", **kw) -> bytes:
    return SocketSender(**kw)("127.0.0.1", up.port, False, request)


def test_a_chunk_whose_data_looks_like_the_last_chunk_is_not_the_end(upstream):
    """Pre-fix, ``endswith(b"0\\r\\n\\r\\n")`` ended the response inside a chunk's data."""
    first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nabc0\r\n\r\n"
    rest = b"\r\n0\r\n\r\n"
    up = upstream(first, 0.3, rest)
    assert _send(up, timeout=5) == first + rest


@pytest.mark.parametrize("parts", [
    (b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",),
    (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nabc0\r\n\r\n",),
    (b"HTTP/1.1 200 OK\r\nContent-Ty",),
], ids=["short-content-length", "unterminated-chunks", "cut-head"])
def test_a_response_cut_before_its_framed_end_is_incomplete_never_returned(upstream,
                                                                            parts):
    up = upstream(*parts)
    with pytest.raises(socketsender.UpstreamResponseError) as err:
        _send(up, timeout=5)
    assert type(err.value).__name__ == "UpstreamIncomplete" and err.value.reason == "eof"


@pytest.mark.parametrize("request_line,parts,want", [
    (b"GET", (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"
              b"X-Trailer: v\r\n\r\n",), None),
    (b"HEAD", (b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n",), None),
    (b"GET", (b"HTTP/1.1 204 No Content\r\n\r\n",), None),
    (b"GET", (b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",), None),
    (b"GET", (b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n", 0.1, OK), OK),
], ids=["trailer", "head", "204", "304", "interim-103"])
def test_a_framed_response_ends_at_its_end_not_at_the_idle_timeout(upstream,
                                                                   request_line, parts,
                                                                   want):
    """The upstream keeps its connection open. Pre-fix, each of these waited for the
    20 s idle timeout (a trailer, a body-less response with no framing header or a HEAD
    with a length), and the 103's head was taken for the whole response's."""
    up = upstream(*parts, hold=True)
    started = time.monotonic()
    got = _send(up, request_line + b" / HTTP/1.1\r\nHost: x\r\n\r\n", timeout=20)
    assert time.monotonic() - started < 10              # a smoke bound; the step is ms
    assert got == (want or b"".join(p for p in parts if isinstance(p, bytes)))


@pytest.mark.parametrize("head", [
    b"HTTP/1.1 200 OK\r\nX: a\nContent-Length: 2\r\n\r\nok",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX: a\r\n Transfer-Encoding: chunked\r\n"
    b"\r\nok",
    b"HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\nok",
], ids=["bare-lf", "obs-fold", "ws-before-colon"])
def test_a_response_head_that_does_not_parse_strictly_is_never_relayed(upstream, head):
    """RFC 9112 §5.1/§5.2: a response field line that is not ``token: value`` on CRLF is
    a framing error (502), never a response framed by the fields a loose split found."""
    up = upstream(head)
    with pytest.raises(socketsender.UpstreamResponseError) as err:
        _send(up, timeout=5)
    assert type(err.value).__name__ == "UpstreamFramingError"


def test_an_incomplete_upstream_response_is_a_502_recorded_as_no_response(upstream):
    """Pre-fix, the client got the cut bytes as a response and history recorded a 200."""
    up = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
    server, hist = _server()
    got = _through(server, b"GET http://127.0.0.1:%d/x HTTP/1.1\r\nHost: h\r\n\r\n"
                   % up.port)
    assert got.startswith(b"HTTP/1.1 502 ")
    (rec,) = hist.recs
    assert rec.raw_response == b"" and rec.status is None
    assert rec.error == "UpstreamIncomplete"


# --- the CONNECT/TLS keep-alive tunnel ---------------------------------------------------

def _tls_or_skip():
    try:
        from cryptography.fernet import Fernet
        Fernet(Fernet.generate_key()).encrypt(b"probe")   # force the rust bindings
    except BaseException as exc:  # noqa: BLE001 - a broken native build panics
        pytest.skip(f"cryptography unavailable/broken: {exc}")


async def _tunnel(server, ca, port):
    """A client's TLS tunnel through the proxy to ``127.0.0.1:port``, verifying the
    proxy's CA-minted leaf."""
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    writer.write(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                 % (port, port))
    await writer.drain()
    assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
    ctx = ssl.create_default_context(cafile=str(ca.ca_cert_path))
    await writer.start_tls(ctx, server_hostname="127.0.0.1")
    return reader, writer


def test_the_bytes_after_a_chunked_request_in_a_tunnel_are_the_next_request(tmp_path):
    """Defect 18's keep-alive case at the listener (review round 1, B3): a chunked POST
    and a GET in one write through the TLS tunnel are exactly two requests. On 08e3eaa
    the upstream got three: the POST's head, its chunk bytes, and the GET."""
    _tls_or_skip()
    from fuzzlab.proxy.ca import LocalCA
    ca = LocalCA(tmp_path / "ca")
    ca.ensure_ca()
    sent = []

    def sender(host, port, use_tls, raw):
        sent.append(raw)
        return OK
    engine = ProxyEngine(scope=Scope().include("127.0.0.1"), sender=sender)
    server = AsyncProxyServer(engine, "127.0.0.1", 0, ca=ca)

    async def main():
        await server.start()
        try:
            reader, writer = await _tunnel(server, ca, 8443)
            writer.write(b"POST /a HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                         b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                         b"GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await writer.drain()
            got = await asyncio.wait_for(reader.readexactly(2 * len(OK)), 5)
            await asyncio.sleep(0.2)            # room for a third request, if one came
            writer.close()
            return got
        finally:
            await server.stop()
    assert asyncio.run(main()) == OK + OK
    assert sent == [b"POST /a HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\n\r\nabc",
                    b"GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"]


def test_a_cut_response_in_a_tunnel_is_a_502_never_an_empty_close(upstream, tmp_path):
    """Review round 1 (AU-PROXY-1): an upstream failure inside the TLS tunnel escaped the
    loop and closed it with nothing written, which a browser retries on a reused
    connection (a POST sent twice). Now the client gets a 502 in the tunnel, and each
    request reached the upstream once."""
    _tls_or_skip()
    from fuzzlab.proxy.ca import LocalCA
    ca = LocalCA(tmp_path / "ca")
    ca.ensure_ca()
    up = upstream(OK, then=[(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",)])

    def sender(host, port, use_tls, raw):        # the real sender, to the plain upstream
        return SocketSender(timeout=5)(host, port, False, raw)
    engine = ProxyEngine(scope=Scope().include("127.0.0.1"), sender=sender)
    server = AsyncProxyServer(engine, "127.0.0.1", 0, ca=ca)

    async def main():
        await server.start()
        try:
            reader, writer = await _tunnel(server, ca, up.port)
            writer.write(b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await writer.drain()
            first = await asyncio.wait_for(reader.readexactly(len(OK)), 5)
            writer.write(b"POST /b HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1"
                         b"\r\n\r\nx")
            await writer.drain()
            rest = bytearray()
            try:
                while chunk := await asyncio.wait_for(reader.read(65536), 5):
                    rest += chunk
            except (ConnectionError, ssl.SSLError):
                pass
            writer.close()
            return first, bytes(rest)
        finally:
            await server.stop()
    first, rest = asyncio.run(main())
    assert first == OK
    assert rest.startswith(b"HTTP/1.1 502 ") and b"Connection: close" in rest
    assert len(up.requests) == 2 and up.requests[1].startswith(b"POST /b ")
    assert any("UpstreamIncomplete" in e for e in server.errors)


# --- defect 20: inbound bounds ---------------------------------------------------------

def test_a_dripped_request_is_answered_408_at_its_deadline_and_never_forwarded(upstream):
    from fuzzlab.proxy.server import InboundLimits
    up = upstream(OK)
    server, _hist = _server(limits=InboundLimits(request_deadline=0.5))
    drip = [p for _ in range(40) for p in (0.1, b"x")]
    started = time.monotonic()
    got = _through(server, _post(up.port, b"Content-Length: 40\r\n"), *drip, wait=8)
    assert got.startswith(b"HTTP/1.1 408 ") and up.requests == []
    assert time.monotonic() - started < 3.5              # cut at 0.5 s, not at 4 s
    assert server.counts["timed_out"] == 1


def test_a_head_over_its_bound_is_answered_431_while_it_arrives(upstream):
    """Pre-fix, the stream reader's limit dropped the connection with no answer."""
    up = upstream(OK)
    server, _hist = _server()
    pad = b"".join(b"X-Pad-%d: %s\r\n" % (i, b"a" * 1000) for i in range(100))
    got = _through(server, b"GET http://127.0.0.1:%d/ HTTP/1.1\r\n" % up.port + pad)
    assert got.startswith(b"HTTP/1.1 431 ") and up.requests == []
    assert server.counts["oversized"] == 1


def test_connections_over_the_cap_are_answered_503_and_counted(upstream):
    from fuzzlab.proxy.server import InboundLimits
    up = upstream(OK)
    server, _hist = _server(limits=InboundLimits(max_connections=2))

    async def main():
        await server.start()
        held = [await asyncio.open_connection("127.0.0.1", server.port) for _ in range(2)]
        for _r, w in held:
            w.write(b"GET http://127.0.0.1:%d/ HTTP/1.1\r\n" % up.port)   # never ends
            await w.drain()
        for _ in range(200):
            if len(server._conns) == 2:
                break
            await asyncio.sleep(0.01)
        refused = await _exchange(server.port)          # refused before it is read
        for _r, w in held:
            w.close()
        for _ in range(200):
            if not server._conns:
                break
            await asyncio.sleep(0.01)
        admitted = await _exchange(server.port, b"GET http://127.0.0.1:%d/ HTTP/1.1\r\n"
                                   b"Host: h\r\n\r\n" % up.port)
        await server.stop()
        return refused, admitted
    refused, admitted = asyncio.run(main())
    assert refused.startswith(b"HTTP/1.1 503 ") and b"Connection: close" in refused
    assert server.counts["refused"] == 1
    assert admitted == OK                               # the cap frees with its connections


def test_every_listener_bound_is_configurable_from_the_cli(monkeypatch, tmp_path):
    import fuzzlab.proxy.cli as cli
    seen = {}

    class Started(Exception):
        pass

    async def fake_start(self):
        seen.update(limits=self.limits, raw=self.raw_framing)
        raise Started
    monkeypatch.setattr(cli.AsyncProxyServer, "start", fake_start)
    with pytest.raises(Started):
        cli.main(["--authorized", "--port", "0", "--no-tls", "--ca-dir", str(tmp_path),
                  "--max-connections", "3",
                  "--max-request-bytes", "1000", "--max-header-bytes", "2000",
                  "--request-deadline", "1.5", "--raw-framing"])
    lim = seen["limits"]
    assert (lim.max_connections, lim.max_body_bytes, lim.max_header_bytes,
            lim.request_deadline, seen["raw"]) == (3, 1000, 2000, 1.5, True)
    with pytest.raises(SystemExit):
        cli.main(["--authorized", "--port", "0", "--no-tls", "--ca-dir", str(tmp_path),
                  "--max-connections", "0"])


# --- SP-63: one framing owner (guard) --------------------------------------------------

_OWNER = "fuzzlab/proxy/framing.py"
_DRIVERS = ("fuzzlab/proxy/server.py", "fuzzlab/proxy/socketsender.py")


def framing_offences(tree: ast.AST) -> list[int]:
    """Lines that frame HTTP/1 by hand: an asyncio stream read to a delimiter or a
    length (``readuntil`` / ``readexactly``), or a guessed last chunk (a bytes literal
    that starts with the zero-size chunk line ``0\\r\\n``)."""
    hits = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("readuntil", "readexactly")):
            hits.append(node.lineno)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, bytes)
              and node.value.startswith(b"0\r\n")):
            hits.append(node.lineno)
    return hits


def test_every_proxy_http1_read_goes_through_the_framing_owner():
    offenders = []
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel == _OWNER:
            continue
        offenders += [f"{rel}:{n}" for n in framing_offences(
            ast.parse(path.read_text(encoding="utf-8")))]
    assert offenders == []
    for rel in _DRIVERS:
        assert "framing.MessageReader(" in (ROOT / rel).read_text(encoding="utf-8"), rel


def test_the_framing_guard_catches_synthetic_offenders():
    pre_fix = ("async def read(reader):\n"
               "    head = await reader.readuntil(b'\\r\\n\\r\\n')\n"
               "    return head + await reader.readexactly(5)\n"
               "def done(body):\n"
               "    return body.endswith(b'0\\r\\n\\r\\n')\n")
    assert sorted(framing_offences(ast.parse(pre_fix))) == [2, 3, 5]
    clean = ("PREFACE = b'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n'\n"
             "def read(sock, reader):\n"
             "    reader.feed(sock.recv(65536))\n"
             "    return reader.done and b'\\r\\n\\r\\n'\n")
    assert framing_offences(ast.parse(clean)) == []
