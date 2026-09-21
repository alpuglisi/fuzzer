"""Byte-exact HTTP/1.1 message container — the raw path (D4, NFR-PROXY-byte-exact).

``RawMessage`` is the source of truth for what goes on the wire. It holds the exact
bytes of a request or response and **never reserializes** them: round-tripping a
received message returns identical bytes, and every edit is byte surgery on the head
that leaves untouched lines verbatim. This is what lets the proxy forward a
hand-edited request with, say, a duplicate ``Content-Length`` exactly as typed —
something the parsed (``h11``) path would reject or normalize.

The parsed path (``parser.py``) is a separate, convenience view over these bytes; it
validates and normalizes. The two paths are deliberately independent (the hybrid of
decision D4): the parsed path for normal traffic, the raw path for byte-exact study.

Header views preserve **order and duplicates** and do not decode the body. Names are
compared case-insensitively (per RFC 7230) but their original casing is preserved on
the wire.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

CRLF = b"\r\n"
_HEAD_SEPS = (b"\r\n\r\n", b"\n\n")


def _split_head_body(raw: bytes) -> tuple[bytes, bytes, bytes]:
    """Return ``(head, sep, body)`` where ``head + sep + body == raw``.

    ``head`` is the start line plus header block up to (not including) the blank-line
    separator; ``sep`` is the exact separator seen (``\\r\\n\\r\\n`` or, for malformed
    traffic, ``\\n\\n``); ``body`` is everything after. A message with no separator
    yet (head still arriving) has an empty ``sep`` and ``body``.
    """
    best = None
    for cand in _HEAD_SEPS:
        idx = raw.find(cand)
        if idx != -1 and (best is None or idx < best[0]):
            best = (idx, cand)
    if best is None:
        return raw, b"", b""
    idx, sep = best
    return raw[:idx], sep, raw[idx + len(sep):]


@dataclass(frozen=True)
class RawMessage:
    """An HTTP message as exact bytes, with a duplicate-preserving parsed view.

    Immutable: edit methods return a new ``RawMessage``. ``raw`` always equals the
    bytes that would be sent.
    """

    raw: bytes

    # --- construction --------------------------------------------------------
    @classmethod
    def from_bytes(cls, data: bytes) -> "RawMessage":
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("RawMessage requires bytes")
        return cls(bytes(data))

    # --- head / body split (byte-exact) --------------------------------------
    @property
    def _parts(self) -> tuple[bytes, bytes, bytes]:
        return _split_head_body(self.raw)

    @property
    def head(self) -> bytes:
        """Start line + header block, without the blank-line separator."""
        return self._parts[0]

    @property
    def separator(self) -> bytes:
        """The exact head/body separator seen (may be ``b''`` if not yet complete)."""
        return self._parts[1]

    @property
    def body(self) -> bytes:
        return self._parts[2]

    @property
    def complete_head(self) -> bool:
        return self._parts[1] != b""

    # --- line views (order + duplicates preserved) ---------------------------
    def _head_lines(self) -> list[bytes]:
        head = self.head
        if not head:
            return []
        # Split on CRLF, tolerating bare LF for malformed-traffic study.
        return head.replace(b"\r\n", b"\n").split(b"\n")

    @property
    def start_line(self) -> bytes:
        lines = self._head_lines()
        return lines[0] if lines else b""

    def header_lines(self) -> list[bytes]:
        """Raw header lines (after the start line), each without its terminator."""
        return self._head_lines()[1:]

    def headers(self) -> list[tuple[bytes, bytes]]:
        """Ordered ``(name, value)`` pairs, duplicates preserved, values lstripped.

        A line with no colon is skipped (obs-fold/garbage stays only in ``raw``).
        """
        out: list[tuple[bytes, bytes]] = []
        for line in self.header_lines():
            if not line:
                continue
            i = line.find(b":")
            if i == -1:
                continue
            out.append((line[:i], line[i + 1:].lstrip(b" \t")))
        return out

    def get_all(self, name: str | bytes) -> list[bytes]:
        """All values for ``name`` (case-insensitive), in order, duplicates kept."""
        key = _as_bytes(name).lower()
        return [v for (n, v) in self.headers() if n.lower() == key]

    def get(self, name: str | bytes) -> bytes | None:
        vals = self.get_all(name)
        return vals[0] if vals else None

    def has_duplicate(self, name: str | bytes) -> bool:
        return len(self.get_all(name)) > 1

    # --- edits (byte surgery; untouched lines stay verbatim) -----------------
    def _rebuild(self, start_line: bytes, header_lines: Iterable[bytes],
                 body: bytes) -> "RawMessage":
        head = start_line + CRLF + b"".join(l + CRLF for l in header_lines)
        return RawMessage(head + CRLF + body)

    def with_appended_header(self, name: str | bytes, value: str | bytes) -> "RawMessage":
        """Append a header line *without* removing any existing one.

        This is how a duplicate ``Content-Length`` is introduced: the original stays
        and the new line is inserted just before the blank-line separator, so every
        other byte is preserved exactly.
        """
        line = _as_bytes(name) + b": " + _as_bytes(value)
        head, sep, body = self._parts
        if sep == b"":                       # head not yet terminated; just append
            return RawMessage(self.raw + CRLF + line)
        return RawMessage(head + CRLF + line + sep + body)

    def with_header(self, name: str | bytes, value: str | bytes) -> "RawMessage":
        """Set ``name`` to a single ``value`` (replace all existing, else append)."""
        key = _as_bytes(name).lower()
        kept, replaced = [], False
        for line in self.header_lines():
            i = line.find(b":")
            if i != -1 and line[:i].lower() == key:
                if not replaced:             # replace the first, drop the rest
                    kept.append(_as_bytes(name) + b": " + _as_bytes(value))
                    replaced = True
                continue
            kept.append(line)
        if not replaced:
            kept.append(_as_bytes(name) + b": " + _as_bytes(value))
        return self._rebuild(self.start_line, kept, self.body)

    def without_header(self, name: str | bytes) -> "RawMessage":
        key = _as_bytes(name).lower()
        kept = [l for l in self.header_lines()
                if not (l.find(b":") != -1 and l[:l.find(b":")].lower() == key)]
        return self._rebuild(self.start_line, kept, self.body)

    def with_request_line(self, line: str | bytes) -> "RawMessage":
        return self._rebuild(_as_bytes(line), self.header_lines(), self.body)

    # request line == status line at the byte level; alias for readability.
    with_start_line = with_request_line

    def with_body(self, body: str | bytes) -> "RawMessage":
        """Replace the body, leaving the head verbatim.

        Deliberately does **not** fix ``Content-Length`` — desyncing the declared and
        actual body length is exactly the kind of malformed traffic the raw path
        exists to study.
        """
        head, sep, _ = self._parts
        sep = sep or (CRLF + CRLF)
        return RawMessage(head + sep + _as_bytes(body))

    # --- request-line helpers (best-effort; raw stays authoritative) ---------
    @property
    def method(self) -> bytes:
        parts = self.start_line.split(b" ")
        return parts[0] if parts and parts[0] else b""

    @property
    def target(self) -> bytes:
        parts = self.start_line.split(b" ")
        return parts[1] if len(parts) >= 2 else b""

    def __len__(self) -> int:
        return len(self.raw)


def _as_bytes(v: str | bytes) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, bytearray):
        return bytes(v)
    return v.encode("latin-1")
