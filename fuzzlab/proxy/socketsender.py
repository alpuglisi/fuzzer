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

from fuzzlab.proxy.message import RawMessage

_CHUNK = 65536


def _body_complete(head: RawMessage, body: bytes) -> bool | None:
    """Return True/False if body completeness is known from the head, else None.

    ``None`` means "no framing header" (read until the peer closes).
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


def recv_http_response(sock: socket.socket, timeout: float) -> bytes:
    """Read one full HTTP/1 response from ``sock`` and return the exact bytes."""
    sock.settimeout(timeout)
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(_CHUNK)
        except (socket.timeout, TimeoutError):
            return bytes(buf)
        if not chunk:
            return bytes(buf)                      # closed before headers completed
        buf += chunk

    head_bytes, sep, rest = bytes(buf).partition(b"\r\n\r\n")
    head = RawMessage.from_bytes(head_bytes + sep)
    body = bytearray(rest)
    known = _body_complete(head, bytes(body))
    if known is True:
        return head_bytes + sep + bytes(body)
    while True:
        try:
            chunk = sock.recv(_CHUNK)
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        body += chunk
        if _body_complete(head, bytes(body)) is True:
            break
    return head_bytes + sep + bytes(body)


class SocketSender:
    """A real upstream `Sender` (drop-in for the engine's injected sender seam).

    ``__call__(host, port, use_tls, raw) -> bytes``. Set ``verify_tls=False`` only for a
    lab origin with a self-signed cert; it defaults to full verification so MITM'd
    upstreams are validated normally.
    """

    def __init__(self, timeout: float = 15.0, verify_tls: bool = True):
        self._timeout = timeout
        self._verify_tls = verify_tls

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
            return recv_http_response(sock, self._timeout)
        finally:
            try:
                sock.close()
            except OSError:
                pass
