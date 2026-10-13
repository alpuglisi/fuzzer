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

import socket
import ssl
import time

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
                                      deadline=self._deadline)
        finally:
            try:
                sock.close()
            except OSError:
                pass
