"""Secret redaction for persisted proxy data (NFR-PROXY-safe, FR-PROXY-11).

The proxy forwards **byte-exact** bytes on the wire (the raw path), but what it
*persists* — flow history (its rows, stored bodies and full-text index) — must not
carry credentials or tokens in cleartext. Before anything is written, this module
redacts:

- **headers:** the values of sensitive headers (`SENSITIVE_HEADERS`, plus any header
  whose name `core.redaction.is_sensitive_name` flags);
- **URL query parameters:** sensitively named ones, in the request target and in
  ``Location`` / ``Content-Location`` / ``Refresh`` response headers;
- **bodies:** sensitively named fields of form-urlencoded, JSON (any depth) and
  multipart (non-file) bodies, in requests and responses alike. A sensitive JSON key's
  **whole value** is replaced, whatever its type (list, object, scalar; BUG-0090).

Sensitivity is by name **token** (`core.redaction`, BUG-0084), so benign fields such as
``author`` stay readable. Body redaction is the shared, fail-closed storage boundary in
`core.redaction` (BUG-0099/0100): unparseable or oversized bodies that may hold a secret
are replaced by an omission marker, and untyped / ``text/plain`` bodies are sniffed. A
chunked or ``Content-Encoding``-compressed body is decoded (bounded, gzip / deflate) and
checked: a clean one is stored byte-exact, one carrying a secret (or undecodable with a
redactable type) is replaced by the marker with ``Transfer-Encoding`` /
``Content-Encoding`` dropped and ``Content-Length`` set — closing the former residual.
A JSON body is re-serialised only when it holds a sensitive key, so every other body
stays byte-identical. ``Content-Length`` is recomputed when a redacted body changes length,
if it was consistent before.

Trade-off: a Repeater tab seeded from history carries the placeholders, so replaying a
JWT / session / CSRF flow needs a fresh capture or ``HistoryWriter(redact_secrets=
False)`` (lab-local opt-out).
"""

from __future__ import annotations

import re
import zlib

from fuzzlab.core.redaction import (MAX_REDACT_BYTES, OMIT_UNSAFE, PLACEHOLDER, body_kind,
                                    is_sensitive_name, mentions_sensitive_name,
                                    redact_body, redact_url)
from fuzzlab.core.redaction import redact_query  # noqa: F401  (re-exported: one boundary)
from fuzzlab.proxy.message import RawMessage

REDACTED = PLACEHOLDER.encode()

# Header names whose values are secrets. Compared case-insensitively.
SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)
_URL_HEADERS = ("location", "content-location", "refresh")


def _dechunk(body: bytes, limit: int) -> bytes | None:
    """The payload of a chunked body (trailers ignored), or ``None`` if malformed or
    longer than ``limit``."""
    out, i = bytearray(), 0
    while True:
        j = body.find(b"\r\n", i)
        if j == -1:
            return None
        try:
            size = int(body[i:j].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return None
        if size == 0:
            return bytes(out)
        if len(out) + size > limit or j + 2 + size > len(body):
            return None
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2


def _decompress(data: bytes, encoding: str, limit: int) -> bytes | None:
    """``data`` decoded per ``Content-Encoding`` (gzip / x-gzip / deflate), bounded to
    ``limit`` bytes of output; ``None`` if unknown, malformed or too large."""
    enc = encoding.strip().lower()
    if enc in ("", "identity"):
        return data
    modes = {"gzip": (16 + zlib.MAX_WBITS,), "x-gzip": (16 + zlib.MAX_WBITS,),
             "deflate": (zlib.MAX_WBITS, -zlib.MAX_WBITS)}.get(enc)
    if modes is None:
        return None                                       # br, zstd, chains: not decoded
    for wbits in modes:
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, limit + 1)
        except zlib.error:
            continue
        if len(out) > limit or d.unconsumed_tail:
            return None                                   # a decompression bomb
        return out
    return None


def _framed_payload(msg: RawMessage, body: bytes) -> bytes | None:
    """``body`` with its transfer and content codings removed (bounded), or ``None``."""
    data = body
    if (te := _header(msg, "Transfer-Encoding")) and "chunked" in te.lower():
        data = _dechunk(data, MAX_REDACT_BYTES)
        if data is None:
            return None
    return _decompress(data, _header(msg, "Content-Encoding"), MAX_REDACT_BYTES)


def _framed_body_unsafe(msg: RawMessage, body: bytes) -> bool:
    """For a chunked / compressed body: True when it must not be stored as received —
    its decoded payload carries a secret, or it cannot be decoded while its type is
    redactable (fail closed, BUG-0100). A clean one is kept byte-exact."""
    ct = _header(msg, "Content-Type")
    payload = _framed_payload(msg, body)
    if payload is None:
        return body_kind(b"", ct) is not None or mentions_sensitive_name(body)
    return redact_body(payload, ct) != payload


def _original_name(msg: RawMessage, name: str) -> bytes:
    """The header's name as the message spells it (keep the persisted copy faithful)."""
    for line in msg.header_lines():
        i = line.find(b":")
        if i != -1 and line[:i].lower() == name.encode():
            return line[:i]
    return name.encode()


def _header(msg: RawMessage, name: str) -> str:
    v = msg.get(name)
    return v.decode("latin-1", "replace") if v is not None else ""


def redact(raw: bytes, extra_headers: tuple[str, ...] = ()) -> bytes:
    """Return ``raw`` with its secrets replaced by a placeholder (see the module
    docstring). Benign headers, parameters and fields are left untouched."""
    msg = RawMessage.from_bytes(raw)
    names = set(SENSITIVE_HEADERS) | {h.lower() for h in extra_headers}
    for line in msg.header_lines():
        i = line.find(b":")
        if i != -1 and is_sensitive_name(line[:i].decode("latin-1", "replace")):
            names.add(line[:i].decode("latin-1", "replace").lower())
    for name in names:
        if msg.get(name) is not None:
            # Replace every occurrence (duplicates included) with the placeholder.
            n = len(msg.get_all(name))
            msg = msg.without_header(name)
            for _ in range(n):
                msg = msg.with_appended_header(name, REDACTED)
    # the request target's query (a response's start line has none)
    target = msg.target.decode("latin-1", "replace")
    if not msg.start_line.startswith(b"HTTP/") and "?" in target:
        new_target = redact_url(target)
        if new_target != target:
            parts = msg.start_line.split(b" ")
            parts[1] = new_target.encode("latin-1")
            msg = msg.with_request_line(b" ".join(parts))
    for name in _URL_HEADERS:
        value = _header(msg, name)
        if "?" in value:
            new = redact_url(value) if name != "refresh" else re.sub(
                r"(url=)(\S+)", lambda m: m.group(1) + redact_url(m.group(2)), value,
                flags=re.I)
            if new != value:
                msg = msg.with_header(_original_name(msg, name), new)
    # bodies. Chunked / compressed: decoded (bounded) and checked; a body that is not
    # provably clean is replaced by the marker with framing made consistent (B-S3),
    # a clean one is kept byte-exact.
    if msg.body and (msg.get("Transfer-Encoding") is not None
                     or msg.get("Content-Encoding") is not None):
        if _framed_body_unsafe(msg, msg.body):
            msg = msg.without_header("Transfer-Encoding").without_header(
                "Content-Encoding").with_body(OMIT_UNSAFE)
            msg = msg.with_header("Content-Length", str(len(OMIT_UNSAFE)))
    elif msg.body:
        old = msg.body
        new = redact_body(old, _header(msg, "Content-Type"))
        if new != old:
            msg = msg.with_body(new)
            declared = _header(msg, "Content-Length").strip()
            if declared.isdigit() and int(declared) == len(old):
                msg = msg.with_header("Content-Length", str(len(new)))
    return msg.raw


def redact_body_for(raw: bytes, body: bytes) -> bytes:
    """``body`` (stored apart from its message) redacted by the content type and framing
    of the message ``raw`` it belongs to (FR-PROXY-11)."""
    if not body:
        return body
    msg = RawMessage.from_bytes(raw or b"")
    if msg.get("Transfer-Encoding") is not None or msg.get("Content-Encoding") is not None:
        return OMIT_UNSAFE if _framed_body_unsafe(msg, body) else body
    return redact_body(body, _header(msg, "Content-Type"))
