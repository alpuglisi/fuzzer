"""Live h2c socket transport for the raw HTTP/2 client (Phase 9 on-host, Part K).

`H2RawClient`/`h2frames`/`hpack` build and parse HTTP/2 bytes; this is the missing
last mile — an actual TCP socket that writes those bytes to an **h2c (cleartext,
prior-knowledge)** endpoint like the lab's nginx h2→h1 downgrade front-end and reads
the response frames back. No TLS/ALPN and no HTTP/1.1 Upgrade dance: nginx `http2 on;`
accepts the HTTP/2 preface straight on a plaintext socket.

Two modes:
- ``send_raw(host, port, raw)`` — write **exactly** the given bytes (e.g. a malformed /
  length-desync / CRLF-in-header frame from ``build_raw``) and return whatever comes
  back. This is the byte-exact desync primitive.
- ``request(host, port, ...)`` — a well-behaved exchange: send preface+SETTINGS+HEADERS,
  ACK the server's SETTINGS, read to END_STREAM, and return a decoded response view.

Lab-only, loopback. The desync front-end is opt-in (compose ``desync`` profile).
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

from fuzzlab.proxy import h2frames
from fuzzlab.proxy.h2client import H2RawClient
from fuzzlab.proxy.hpack import decode_headers

_CHUNK = 65536


@dataclass
class H2Response:
    """A decoded view of an h2 response (best-effort; body is never HPACK-compressed)."""
    frames: list = field(default_factory=list)      # all frames decoded off the wire
    headers: list = field(default_factory=list)     # (name, value) from HEADERS on our stream
    body: bytes = b""                               # concatenated DATA on our stream
    raw: bytes = b""                                # every byte read from the socket

    @property
    def status(self) -> int | None:
        """The `:status`, when decodable (a static-indexed `:status: 200` decodes even
        though our minimal HPACK cannot read Huffman-coded literal headers)."""
        for name, value in self.headers:
            if name == b":status":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None

    @property
    def got_headers(self) -> bool:
        return any(f.type == h2frames.HEADERS for f in self.frames)


def _decode_headers_lenient(payload: bytes) -> list[tuple[bytes, bytes]]:
    """Decode what we can; nginx Huffman-codes most literals, which our minimal HPACK
    does not read — but a static-indexed `:status` at the front still decodes."""
    try:
        return decode_headers(payload)
    except Exception:  # noqa: BLE001 - Huffman/dynamic-table fields we don't decode
        return []


def _drain(sock, stream_id: int, timeout: float, settle: float) -> bytes:
    """Read frames until END_STREAM on ``stream_id`` (ACKing the server SETTINGS once),
    or until a ``settle``-length silence / the overall ``timeout``. Returns raw bytes."""
    sock.settimeout(settle)
    buf = bytearray()
    acked = False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(_CHUNK)
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        buf += chunk
        frames, _ = h2frames.decode_frames(bytes(buf))
        done = False
        for f in frames:
            if (f.type == h2frames.SETTINGS and not (f.flags & h2frames.FLAG_ACK)
                    and not acked):
                try:
                    sock.sendall(h2frames.settings_frame(ack=True))
                except OSError:
                    pass
                acked = True
            if f.stream_id == stream_id and (f.flags & h2frames.FLAG_END_STREAM):
                done = True
        if done:
            break
    return bytes(buf)


class H2Transport:
    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout

    def send_raw(self, host: str, port: int, raw: bytes, *, settle: float = 0.5) -> bytes:
        """Write ``raw`` byte-exact and return whatever the server sends back."""
        with socket.create_connection((host, port), timeout=self._timeout) as s:
            s.sendall(raw)
            s.settimeout(settle)
            buf = bytearray()
            deadline = time.monotonic() + self._timeout
            while time.monotonic() < deadline:
                try:
                    chunk = s.recv(_CHUNK)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                buf += chunk
            return bytes(buf)

    def request(self, host: str, port: int, method: str = "GET", path: str = "/", *,
                headers=None, body: bytes | None = None, authority: str | None = None,
                settle: float = 0.5) -> H2Response:
        """A well-behaved h2c request over prior-knowledge cleartext."""
        authority = authority or f"{host}:{port}"
        client = H2RawClient()
        sid = client.next_stream_id()
        req = client.build_request(method, path, authority, "http", headers=headers,
                                   body=body, stream_id=sid, include_preface=True)
        with socket.create_connection((host, port), timeout=self._timeout) as s:
            s.sendall(req)
            raw = _drain(s, sid, self._timeout, settle)
        frames, _ = h2frames.decode_frames(raw)
        hdrs: list[tuple[bytes, bytes]] = []
        body_out = bytearray()
        for f in frames:
            if f.type == h2frames.HEADERS and f.stream_id == sid:
                hdrs += _decode_headers_lenient(f.payload)
            elif f.type == h2frames.DATA and f.stream_id == sid:
                body_out += f.payload
        return H2Response(frames=frames, headers=hdrs, body=bytes(body_out), raw=raw)
