"""Live upstream `Sender`: the socket I/O the proxy engine delegates to (Phase 6).

The `ProxyEngine`/`Repeater` are sans-I/O; they forward through an injected
``Sender`` — a callable ``(host, port, use_tls, raw_request_bytes) -> raw_response_bytes``
(`fuzzlab/proxy/repeater.py`). Offline tests use a fake; this is the on-host real
socket implementation: TCP-connect to the upstream (TLS-wrap when ``use_tls``), send
the request **byte-exact**, and read one whole HTTP/1 response back byte-exact, framed
by the protocol (SP-63, FR-PROXY-402), never by its payload bytes or a quiet socket.

Byte-exactness is the point of the proxy's raw path — this sender never reserializes;
it sends exactly what it is given and returns the response's exact bytes, so a
deliberately malformed request (e.g. a duplicate ``Content-Length``) goes on the wire
verbatim. A response that did not arrive whole raises `UpstreamIncomplete`; one that
cannot be framed raises `UpstreamFramingError`. Lab-only, loopback by default.
"""

from __future__ import annotations

import socket
import ssl
import time

from fuzzlab.core.bodyread import DEADLINE_TIMEOUTS, READ_SIZE
from fuzzlab.proxy import framing
from fuzzlab.proxy.message import RawMessage

#: Bounds on one upstream response (BUG-0101, FR-PROXY-12): a peer that never stops
#: sending, or drips bytes forever, cannot hold the proxy or exhaust memory. The receive
#: size and the deadline factor are SP-60's (`core.bodyread`); the body ceiling stays the
#: proxy's own (a browser's downloads are relayed byte-exact, never content-decoded).
MAX_HEAD_BYTES = 64 * 1024
MAX_BODY_BYTES = 64 * 1024 * 1024
DEADLINE_FACTOR = DEADLINE_TIMEOUTS      # overall deadline = idle timeout x this


class UpstreamResponseError(OSError):
    """An upstream response that is not a complete, framed response (FR-PROXY-12/402)."""


class UpstreamIncomplete(UpstreamResponseError):
    """The response stopped before its framed end (``reason``): ``head`` / ``wire`` (a
    cap), ``deadline``, ``idle`` (a receive timed out) or ``eof`` (the peer closed).
    Never a short response: nothing of it is returned or recorded as one."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class UpstreamFramingError(UpstreamResponseError):
    """The response cannot be framed (SP-63): answered 502, never relayed."""


def recv_http_response(sock: socket.socket, timeout: float, *,
                       max_head: int = MAX_HEAD_BYTES, max_body: int = MAX_BODY_BYTES,
                       deadline: float | None = None, method: bytes = b"GET") -> bytes:
    """Read one whole HTTP/1 response to a ``method`` request from ``sock``; return its
    exact bytes (the final response: interim 1xx ones are read and passed over).

    Framing is SP-63's (`framing.MessageReader`): status line, headers, then a
    ``Content-Length``, chunked (sizes, extensions, trailers parsed) or close-delimited
    body, and none for HEAD / 1xx / 204 / 304. ``timeout`` bounds each idle receive;
    ``deadline`` (seconds, default ``timeout x DEADLINE_FACTOR``) bounds the whole read.
    Headers past ``max_head``, a body past ``max_body``, the deadline, an idle receive
    or a close before the framed end raise `UpstreamIncomplete`; an unframeable response
    raises `UpstreamFramingError`. A peer that closes before sending anything returns
    ``b""`` (no response). Bytes accumulate in the reader's buffers, never re-copied."""
    end = time.monotonic() + (deadline if deadline is not None
                              else timeout * DEADLINE_FACTOR)
    reader = framing.MessageReader("response", framing.FrameLimits(max_head, max_body),
                                   method=method)
    try:
        while not reader.done:
            left = end - time.monotonic()
            if left <= 0:
                raise UpstreamIncomplete(
                    "deadline", "upstream response exceeded the overall deadline")
            sock.settimeout(min(timeout, left))
            try:
                chunk = sock.recv(READ_SIZE)
            except (socket.timeout, TimeoutError):
                if time.monotonic() >= end:
                    raise UpstreamIncomplete(
                        "deadline", "upstream response exceeded the overall deadline")
                raise UpstreamIncomplete(
                    "idle", f"upstream response stalled for {timeout}s before its end")
            if not chunk:
                if not reader.received:
                    return b""                         # closed without a response
                reader.eof()                           # ends a close-delimited body
                break
            reader.feed(chunk)
    except framing.OverLimit as exc:
        raise UpstreamIncomplete("head" if exc.part == "head" else "wire",
                                 f"upstream response {exc}") from exc
    except framing.Incomplete as exc:
        raise UpstreamIncomplete("eof", f"upstream response cut short: {exc}") from exc
    except framing.FramingError as exc:
        raise UpstreamFramingError(f"upstream response cannot be framed: {exc}") from exc
    return reader.head + bytes(reader.body)


class SocketSender:
    """A real upstream `Sender` (drop-in for the engine's injected sender seam).

    ``__call__(host, port, use_tls, raw) -> bytes``. Set ``verify_tls=False`` only for a
    lab origin with a self-signed cert; it defaults to full verification so MITM'd
    upstreams are validated normally. ``max_body`` / ``deadline`` bound one response
    (FR-PROXY-12): they cut off long-lived streams and very large downloads, by design.
    Stateless between calls (one socket per call), so the engine runs it in a worker
    thread (`asyncio.to_thread`, the default executor: at most min(32, CPUs + 4)
    concurrent upstream calls).
    """

    def __init__(self, timeout: float = 15.0, verify_tls: bool = True, *,
                 max_body: int = MAX_BODY_BYTES, deadline: float | None = None):
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._max_body = max_body
        self._deadline = deadline            # None: timeout × DEADLINE_FACTOR

    def __call__(self, host: str, port: int, use_tls: bool, raw: bytes) -> bytes:
        sock = socket.create_connection((host, port), timeout=self._timeout)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                if not self._verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(raw)
            return recv_http_response(sock, self._timeout, max_body=self._max_body,
                                      deadline=self._deadline,
                                      method=RawMessage.from_bytes(raw).method)
        finally:
            try:
                sock.close()
            except OSError:
                pass
