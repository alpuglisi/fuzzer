"""Live upstream `Sender`: the socket I/O the proxy engine delegates to (Phase 6).

The `ProxyEngine`/`Repeater` are sans-I/O; they forward through an injected
``Sender`` — a callable ``(host, port, use_tls, raw_request_bytes) -> raw_response_bytes``
(`fuzzlab/proxy/repeater.py`). Offline tests use a fake; this is the on-host real
socket implementation: TCP-connect to the upstream (TLS-wrap when ``use_tls``), send
the request **byte-exact**, and read the whole HTTP/1 response back byte-exact.

Byte-exactness is the point of the proxy's raw path — this sender never reserializes;
it sends exactly what it is given and returns exactly what it receives, so a
deliberately malformed request (e.g. a duplicate ``Content-Length``) goes on the wire
verbatim. Lab-only, loopback by default.
"""

from __future__ import annotations

import re
import selectors
import socket
import ssl
import threading
import time
import weakref

from fuzzlab.proxy.message import RawMessage

_CHUNK = 65536
#: Bounds on one upstream response (BUG-0101, FR-PROXY-12): a peer that never stops
#: sending, or drips bytes forever, cannot hold the proxy or exhaust memory.
MAX_HEAD_BYTES = 64 * 1024
MAX_BODY_BYTES = 64 * 1024 * 1024
DEADLINE_FACTOR = 4                      # overall deadline = idle timeout × this


class UpstreamResponseError(OSError):
    """An upstream response exceeded the header / body cap or the overall deadline."""


def _body_complete(head: RawMessage, body) -> bool | None:
    """Return True/False if body completeness is known from the head, else None.

    ``None`` means "no framing header" (read until the peer closes). ``body`` may be a
    ``bytearray``: only ``len`` / ``endswith`` are used, so nothing is copied
    (BUG-0101: the whole body was once copied per received chunk — quadratic).
    """
    te = head.get("Transfer-Encoding")
    if te and b"chunked" in te.lower():
        # Terminating chunk is "0\r\n\r\n" (optionally with trailers before the final
        # CRLF). Good enough for lab traffic; the raw bytes are preserved regardless.
        return body.endswith(b"0\r\n\r\n") or body.endswith(b"0\r\n\r\n\r\n")
    cl = head.get("Content-Length")
    if cl is not None and cl.isdigit():
        return len(body) >= int(cl)
    return None


def recv_http_response(sock: socket.socket, timeout: float, *,
                       max_head: int = MAX_HEAD_BYTES, max_body: int = MAX_BODY_BYTES,
                       deadline: float | None = None) -> bytes:
    """Read one full HTTP/1 response from ``sock`` and return the exact bytes.

    ``timeout`` bounds each idle read; ``deadline`` (seconds, default ``timeout ×
    DEADLINE_FACTOR``) bounds the whole read, so a peer dripping bytes cannot hold it.
    Headers past ``max_head`` or a body past ``max_body`` raise
    `UpstreamResponseError`. Bytes accumulate in one ``bytearray``, never re-copied."""
    sock.settimeout(timeout)
    end = time.monotonic() + (deadline if deadline is not None
                              else timeout * DEADLINE_FACTOR)

    def _recv() -> bytes | None:
        if time.monotonic() > end:
            raise UpstreamResponseError("upstream response exceeded the overall deadline")
        try:
            return sock.recv(_CHUNK)
        except (socket.timeout, TimeoutError):
            return None

    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = _recv()
        if not chunk:
            return bytes(buf)                      # closed / idle before headers completed
        buf += chunk
        if len(buf) > max_head and b"\r\n\r\n" not in buf[:max_head + 4]:
            raise UpstreamResponseError(f"upstream response headers exceed {max_head} bytes")

    split = buf.index(b"\r\n\r\n") + 4
    head = RawMessage.from_bytes(bytes(buf[:split]))
    body = buf[split:]
    if len(body) > max_body:
        raise UpstreamResponseError(f"upstream response body exceeds {max_body} bytes")
    if _body_complete(head, body) is True:
        return bytes(buf[:split]) + bytes(body)
    while True:
        chunk = _recv()
        if not chunk:
            break
        body += chunk
        if len(body) > max_body:
            raise UpstreamResponseError(f"upstream response body exceeds {max_body} bytes")
        if _body_complete(head, body) is True:
            break
    return bytes(buf[:split]) + bytes(body)


class SocketSender:
    """A real upstream `Sender` (drop-in for the engine's injected sender seam).

    ``__call__(host, port, use_tls, raw) -> bytes``. Set ``verify_tls=False`` only for a
    lab origin with a self-signed cert; it defaults to full verification so MITM'd
    upstreams are validated normally. ``max_body`` / ``deadline`` bound one response
    (FR-PROXY-12): they cut off long-lived streams and very large downloads, by design.
    The engine runs it in a worker thread (`asyncio.to_thread`, the default executor: at
    most min(32, CPUs + 4) concurrent upstream calls); it is thread-safe.

    **Kept connections** (FR-PROXY-405, BUG-0549). One SSL context per sender. An
    upstream connection is left for reuse, per (host, port, TLS), only when the exchange
    on it was exactly one well-framed HTTP/1.1 request and one fully framed HTTP/1.1
    answer, and neither said ``Connection: close`` (`reusable_request`,
    `reusable_response`); anything else is closed after its exchange, as before. Only a
    request that is itself reusable and idempotent takes a kept connection, so a
    deliberately malformed request (a desync probe) always goes on a fresh socket. A
    kept connection is checked before use (no byte or close waiting on it, idle at most
    ``idle_seconds``); when its peer closed it before a byte of answer, the request is
    sent once more on a fresh connection; a timeout is never resent. At most
    ``max_idle`` idle connections per upstream and `MAX_IDLE_TOTAL` in all are kept.
    `close` (or collecting the sender) closes the idle ones. ``keep_alive=False``: one
    socket per call.
    """

    def __init__(self, timeout: float = 15.0, verify_tls: bool = True, *,
                 max_body: int = MAX_BODY_BYTES, deadline: float | None = None,
                 keep_alive: bool = True, idle_seconds: float | None = None,
                 max_idle: int | None = None):
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._max_body = max_body
        self._deadline = deadline            # None: timeout × DEADLINE_FACTOR
        self._keep_alive = keep_alive
        self._ctx: ssl.SSLContext | None = None
        self._ctx_lock = threading.Lock()
        self._pool = _IdlePool(IDLE_SECONDS if idle_seconds is None else idle_seconds,
                               MAX_IDLE_PER_UPSTREAM if max_idle is None else max_idle)
        self._finalizer = weakref.finalize(self, self._pool.close)

    def close(self) -> None:
        """Close the idle upstream connections (idempotent; a later call still works,
        on a connection closed after it)."""
        self._finalizer()

    def __call__(self, host: str, port: int, use_tls: bool, raw: bytes) -> bytes:
        key = (host, int(port), bool(use_tls))
        keep = self._keep_alive and reusable_request(raw)
        if keep and _method(raw) in _IDEMPOTENT:
            sock = self._pool.take(key)
            if sock is not None:
                started = time.monotonic()
                try:
                    resp = self._exchange(sock, raw)
                except _PEER_CLOSED:
                    _close(sock)                 # closed under us: resend on a fresh one
                except BaseException:
                    _close(sock)
                    raise
                else:
                    if resp or time.monotonic() - started >= self._timeout:
                        return self._finish(key, sock, resp, keep)
                    _close(sock)                 # the peer closed it before a byte
        sock = self._connect(host, port, use_tls)
        try:
            resp = self._exchange(sock, raw)
        except BaseException:
            _close(sock)
            raise
        return self._finish(key, sock, resp, keep)

    def _context(self) -> ssl.SSLContext:
        with self._ctx_lock:
            if self._ctx is None:
                ctx = ssl.create_default_context()
                if not self._verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                self._ctx = ctx
            return self._ctx

    def _connect(self, host: str, port: int, use_tls: bool) -> socket.socket:
        sock = socket.create_connection((host, port), timeout=self._timeout)
        if use_tls:
            try:
                sock = self._context().wrap_socket(sock, server_hostname=host)
            except BaseException:
                _close(sock)
                raise
        return sock

    def _exchange(self, sock: socket.socket, raw: bytes) -> bytes:
        sock.sendall(raw)
        return recv_http_response(sock, self._timeout, max_body=self._max_body,
                                  deadline=self._deadline)

    def _finish(self, key, sock: socket.socket, resp: bytes, keep: bool) -> bytes:
        if keep and reusable_response(resp):
            self._pool.put(key, sock)
        else:
            _close(sock)
        return resp


# --- kept upstream connections (FR-PROXY-405, BUG-0549) -----------------------------------
#: An idle kept connection older than this is closed, not reused: below the 5 s idle
#: keep-alive timeout Node's http server and Apache httpd default to.
IDLE_SECONDS = 4.0
#: At most this many idle connections per upstream (host, port, TLS) ...
MAX_IDLE_PER_UPSTREAM = 8
#: ... and in all, per sender.
MAX_IDLE_TOTAL = 64

#: A request that may take a kept connection (RFC 9110 §9.2.2 idempotent; HEAD is never
#: kept: its answer's framing depends on the request, which the reader does not see).
_IDEMPOTENT = frozenset({b"GET", b"OPTIONS", b"TRACE", b"PUT", b"DELETE"})
#: The peer closed or reset a kept connection under a send.
_PEER_CLOSED = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                ssl.SSLEOFError, ssl.SSLZeroReturnError)
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HEX = re.compile(rb"[0-9A-Fa-f]{1,16}")
#: Authentication schemes that authenticate the connection, not the request.
_CONNECTION_AUTH = (b"ntlm", b"negotiate")


def _close(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _quiet(sock) -> bool:
    """Nothing waits on an idle connection: no buffered TLS byte, and the socket is not
    readable (a readable idle socket holds a close, a reset or a stray byte)."""
    try:
        if isinstance(sock, ssl.SSLSocket) and sock.pending():
            return False
        with selectors.DefaultSelector() as sel:
            sel.register(sock, selectors.EVENT_READ)
            return not sel.select(0)
    except (OSError, ValueError):
        return False


class _IdlePool:
    """Idle kept connections per (host, port, TLS), the most recent out first; one
    lock, never held over a socket call but a close."""

    def __init__(self, idle_seconds: float, max_idle: int):
        self._idle_seconds = idle_seconds
        self._max_idle = max(0, max_idle)
        self._lock = threading.Lock()
        self._idle: dict[tuple, list[tuple[socket.socket, float]]] = {}
        self._closed = False

    def take(self, key):
        while True:
            with self._lock:
                stack = self._idle.get(key)
                if not stack:
                    return None
                sock, since = stack.pop()
                if not stack:
                    del self._idle[key]
            if time.monotonic() - since <= self._idle_seconds and _quiet(sock):
                return sock
            _close(sock)

    def put(self, key, sock) -> None:
        now = time.monotonic()
        doomed = []
        with self._lock:
            if self._closed or self._max_idle == 0:
                doomed.append(sock)
            else:
                self._idle.setdefault(key, []).append((sock, now))
                for k in list(self._idle):            # the expired, then the oldest
                    fresh = [(s, t) for s, t in self._idle[k]
                             if now - t <= self._idle_seconds]
                    doomed.extend(s for s, t in self._idle[k]
                                  if now - t > self._idle_seconds)
                    while len(fresh) > self._max_idle:
                        doomed.append(fresh.pop(0)[0])
                    if fresh:
                        self._idle[k] = fresh
                    else:
                        del self._idle[k]
                while sum(len(v) for v in self._idle.values()) > MAX_IDLE_TOTAL:
                    oldest = min(self._idle, key=lambda k: self._idle[k][0][1])
                    doomed.append(self._idle[oldest].pop(0)[0])
                    if not self._idle[oldest]:
                        del self._idle[oldest]
        for s in doomed:
            _close(s)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            doomed = [s for stack in self._idle.values() for s, _t in stack]
            self._idle.clear()
        for s in doomed:
            _close(s)


def _strict(data: bytes):
    """``(start line, {lower-case name: [values]}, body)`` of ``data`` when its head is
    strictly well-formed (CRLF lines, token names, no obs-fold, no bare CR / LF / NUL),
    else None."""
    end = data.find(b"\r\n\r\n")
    if end < 0:
        return None
    lines = data[:end].split(b"\r\n")
    if any(c in lines[0] for c in (b"\r", b"\n", b"\x00")):
        return None
    fields: dict[bytes, list[bytes]] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not _TOKEN.fullmatch(name) or \
                any(c in value for c in (b"\r", b"\n", b"\x00")):
            return None
        fields.setdefault(name.lower(), []).append(value.strip(b" \t"))
    return lines[0], fields, data[end + 4:]


def _method(raw: bytes) -> bytes:
    return raw.split(b" ", 1)[0]


def _keeps_alive(fields) -> bool:
    tokens = {t.strip().lower() for v in fields.get(b"connection", ())
              for t in v.split(b",")}
    return b"close" not in tokens and b"upgrade" not in tokens and \
        b"upgrade" not in fields


def _connection_auth(values) -> bool:
    return any(v.split(b" ", 1)[0].lower() in _CONNECTION_AUTH for v in values)


def _length_is(fields, body: bytes) -> bool:
    lengths = fields.get(b"content-length")
    if lengths is None:
        return not body
    return (len(lengths) == 1 and lengths[0].isdigit() and len(lengths[0]) <= 18
            and int(lengths[0]) == len(body))


def _chunked_exact(body: bytes) -> bool:
    """``body`` is exactly one complete chunked body: hex sizes, each chunk's data and
    CRLF, the last chunk, token trailer fields and the final CRLF, and nothing after."""
    i, n = 0, len(body)
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            return False
        size = body[i:j].split(b";", 1)[0]
        if not _HEX.fullmatch(size):
            return False
        size_n = int(size, 16)
        i = j + 2
        if size_n == 0:
            break
        if body[i + size_n:i + size_n + 2] != b"\r\n":
            return False
        i += size_n + 2
    while True:                                           # trailer fields, then CRLF
        j = body.find(b"\r\n", i)
        if j < 0:
            return False
        if j == i:
            return j + 2 == n
        name, colon, _value = body[i:j].partition(b":")
        if not colon or not _TOKEN.fullmatch(name):
            return False
        i = j + 2


def reusable_request(raw: bytes) -> bool:
    """May the connection that carries ``raw`` be kept after its answer? Only for
    exactly one well-formed HTTP/1.1 request: a token method other than HEAD or
    CONNECT, no ``Transfer-Encoding``, ``Expect`` or ``Upgrade``, no ``Connection:
    close``, no connection-bound authentication (NTLM, Negotiate), and a body exactly
    its one ``Content-Length`` (none: no body). A desync probe is none of these."""
    msg = _strict(raw)
    if msg is None:
        return False
    start, fields, body = msg
    parts = start.split(b" ")
    if len(parts) != 3 or parts[2] != b"HTTP/1.1" or not _TOKEN.fullmatch(parts[0]) \
            or not parts[1] or parts[0] in (b"HEAD", b"CONNECT"):
        return False
    if not _keeps_alive(fields) or any(h in fields for h in (
            b"transfer-encoding", b"expect", b"upgrade")):
        return False
    if _connection_auth(fields.get(b"authorization", []) +
                        fields.get(b"proxy-authorization", [])):
        return False
    return _length_is(fields, body)


def reusable_response(resp: bytes) -> bool:
    """Is ``resp`` exactly one fully framed HTTP/1.1 answer that keeps its connection?
    A final status (not 1xx), no ``Connection: close`` or upgrade, no connection-bound
    authentication asked for, and framed by exactly one ``Content-Length`` the body
    matches, or a ``Transfer-Encoding: chunked`` alone whose body is exactly one
    complete chunked body; a 204 or 304 has no body and no transfer coding. A
    close-delimited, over-long, short or doubly framed answer is never kept."""
    msg = _strict(resp)
    if msg is None:
        return False
    start, fields, body = msg
    parts = start.split(b" ", 2)
    if len(parts) < 2 or parts[0] != b"HTTP/1.1" or len(parts[1]) != 3 \
            or not parts[1].isdigit():
        return False
    status = int(parts[1])
    if status < 200 or not _keeps_alive(fields):
        return False
    if _connection_auth(fields.get(b"www-authenticate", []) +
                        fields.get(b"proxy-authenticate", [])):
        return False
    te = fields.get(b"transfer-encoding")
    if status in (204, 304):
        return te is None and not body
    if te is not None:
        return (b"content-length" not in fields and len(te) == 1
                and te[0].lower() == b"chunked" and _chunked_exact(body))
    return b"content-length" in fields and _length_is(fields, body)
