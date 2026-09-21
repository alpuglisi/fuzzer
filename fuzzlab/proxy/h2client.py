"""HTTP/2 raw-frame client (Phase 9 T9.3, protocol depth).

Assembles an HTTP/2 request from frames — preface → SETTINGS → HEADERS (HPACK) → optional
DATA — and, crucially, lets the caller emit **arbitrary or malformed** frames and header
bytes for desync/smuggling research against a **self-owned lab** target (e.g. the opt-in
h2→h1 downgrade front-end, T9.5). The frame assembly here is byte-exact and offline; the
socket, TLS, and ALPN override are the on-host last mile.

Lab-only: this is an authorized-research tool for infrastructure we run ourselves, under
the same scope-enforced, loopback, no-third-parties posture as the rest of the toolkit.
"""

from __future__ import annotations

from fuzzlab.proxy import h2frames
from fuzzlab.proxy.hpack import encode_headers


def _b(v) -> bytes:
    return v if isinstance(v, bytes) else str(v).encode("latin-1")


class H2RawClient:
    """Builds request byte streams from frames; client streams use odd ids."""

    def __init__(self, start_stream_id: int = 1):
        if start_stream_id % 2 == 0:
            raise ValueError("client-initiated stream ids must be odd")
        self._next = start_stream_id

    def next_stream_id(self) -> int:
        sid = self._next
        self._next += 2
        return sid

    def header_list(self, method: str, path: str, authority: str, scheme: str,
                    headers) -> list[tuple[bytes, bytes]]:
        """Pseudo-headers first (HTTP/2 requires it), then regular headers."""
        out = [(b":method", _b(method)), (b":path", _b(path)),
               (b":scheme", _b(scheme)), (b":authority", _b(authority))]
        out += [(_b(n), _b(v)) for n, v in (headers or [])]
        return out

    def build_request(self, method: str = "GET", path: str = "/",
                      authority: str = "localhost", scheme: str = "https", *,
                      headers=None, body: bytes | None = None,
                      stream_id: int | None = None, include_preface: bool = True,
                      settings: dict[int, int] | None = None) -> bytes:
        """Full request bytes. Arbitrary header name/value bytes pass through HPACK
        unchanged (the desync primitive); a body adds a DATA frame with END_STREAM."""
        sid = stream_id if stream_id is not None else self.next_stream_id()
        block = encode_headers(self.header_list(method, path, authority, scheme, headers))
        out = bytearray()
        if include_preface:
            out += h2frames.PREFACE
            out += h2frames.settings_frame(settings or {})
        has_body = body is not None
        out += h2frames.headers_frame(sid, block, end_stream=not has_body)
        if has_body:
            out += h2frames.data_frame(sid, _b(body), end_stream=True)
        return bytes(out)

    def build_raw(self, frames: list[bytes], *, include_preface: bool = True) -> bytes:
        """Concatenate already-built (possibly malformed) frames, for full control."""
        out = bytearray()
        if include_preface:
            out += h2frames.PREFACE
        for f in frames:
            out += f
        return bytes(out)
