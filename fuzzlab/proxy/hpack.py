"""Minimal HPACK for the raw HTTP/2 client (Phase 9 T9.2, RFC 7541).

Just enough to emit and read **arbitrary header bytes**: the integer/string primitives,
the static table, and the literal representations. Encoding always uses *literal without
indexing, new name* — the simplest representation, which carries any name/value bytes
verbatim (the point for desync research) and is accepted by real servers. Decoding
handles indexed (static), literal (with/without/never indexing), and dynamic-table-size
updates (skipped). Huffman strings are not produced here; decoding one raises (the parsed
path via the `hpack`/`h2` libraries handles Huffman live).

No dynamic-table indexing/eviction — not needed to send arbitrary headers, and its
absence keeps the code small and predictable (Phase 9 scope, decision 2).
"""

from __future__ import annotations


class HpackError(ValueError):
    pass


# RFC 7541 Appendix A — the static table (index 1..61).
STATIC_TABLE: tuple[tuple[bytes, bytes], ...] = (
    (b":authority", b""), (b":method", b"GET"), (b":method", b"POST"),
    (b":path", b"/"), (b":path", b"/index.html"), (b":scheme", b"http"),
    (b":scheme", b"https"), (b":status", b"200"), (b":status", b"204"),
    (b":status", b"206"), (b":status", b"304"), (b":status", b"400"),
    (b":status", b"404"), (b":status", b"500"), (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"), (b"accept-language", b""),
    (b"accept-ranges", b""), (b"accept", b""), (b"access-control-allow-origin", b""),
    (b"age", b""), (b"allow", b""), (b"authorization", b""), (b"cache-control", b""),
    (b"content-disposition", b""), (b"content-encoding", b""),
    (b"content-language", b""), (b"content-length", b""), (b"content-location", b""),
    (b"content-range", b""), (b"content-type", b""), (b"cookie", b""), (b"date", b""),
    (b"etag", b""), (b"expect", b""), (b"expires", b""), (b"from", b""), (b"host", b""),
    (b"if-match", b""), (b"if-modified-since", b""), (b"if-none-match", b""),
    (b"if-range", b""), (b"if-unmodified-since", b""), (b"last-modified", b""),
    (b"link", b""), (b"location", b""), (b"max-forwards", b""),
    (b"proxy-authenticate", b""), (b"proxy-authorization", b""), (b"range", b""),
    (b"referer", b""), (b"refresh", b""), (b"retry-after", b""), (b"server", b""),
    (b"set-cookie", b""), (b"strict-transport-security", b""),
    (b"transfer-encoding", b""), (b"user-agent", b""), (b"vary", b""), (b"via", b""),
    (b"www-authenticate", b""),
)


def encode_integer(value: int, prefix_bits: int, flags: int = 0) -> bytes:
    """RFC 7541 §5.1 integer with an N-bit prefix; ``flags`` are the high bits."""
    if value < 0:
        raise HpackError("negative integer")
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([flags | value])
    out = bytearray([flags | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_integer(data: bytes, offset: int, prefix_bits: int) -> tuple[int, int]:
    """RFC 7541 §5.1 integer decode; returns ``(value, new_offset)``."""
    max_prefix = (1 << prefix_bits) - 1
    if offset >= len(data):
        raise HpackError("integer: out of data")
    value = data[offset] & max_prefix
    offset += 1
    if value < max_prefix:
        return value, offset
    shift = 0
    while True:
        if offset >= len(data):
            raise HpackError("integer: truncated continuation")
        b = data[offset]
        offset += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return value, offset


def encode_string(s: bytes) -> bytes:
    """RFC 7541 §5.2 string, no Huffman (H=0) — carries any bytes verbatim."""
    return encode_integer(len(s), 7, flags=0) + s


def decode_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(data):
        raise HpackError("string: out of data")
    huffman = bool(data[offset] & 0x80)
    length, offset = decode_integer(data, offset, 7)
    if offset + length > len(data):
        raise HpackError("string: truncated")
    raw = data[offset:offset + length]
    offset += length
    if huffman:
        raise HpackError("Huffman-coded string not supported (use the parsed path)")
    return raw, offset


def _as_bytes(v) -> bytes:
    return v if isinstance(v, bytes) else str(v).encode("latin-1")


def encode_headers(headers) -> bytes:
    """Encode ``(name, value)`` pairs as literal-without-indexing, new-name.

    Passes arbitrary name/value bytes through unchanged — the raw client's whole point.
    """
    out = bytearray()
    for name, value in headers:
        out += b"\x00"                       # 0000 0000: literal w/o indexing, index 0
        out += encode_string(_as_bytes(name))
        out += encode_string(_as_bytes(value))
    return bytes(out)


def _static(index: int) -> tuple[bytes, bytes]:
    if 1 <= index <= len(STATIC_TABLE):
        return STATIC_TABLE[index - 1]
    raise HpackError(f"index {index} not in the static table (dynamic table unsupported)")


def decode_headers(block: bytes) -> list[tuple[bytes, bytes]]:
    """Decode a header block (static-indexed + literal reps; dynamic updates skipped)."""
    out: list[tuple[bytes, bytes]] = []
    offset = 0
    n = len(block)
    while offset < n:
        b = block[offset]
        if b & 0x80:                          # 1xxxxxxx indexed header field
            index, offset = decode_integer(block, offset, 7)
            out.append(_static(index))
        elif b & 0x40:                        # 01xxxxxx literal, incremental indexing
            index, offset = decode_integer(block, offset, 6)
            name, offset = (_static(index)[0], offset) if index else decode_string(block, offset)
            value, offset = decode_string(block, offset)
            out.append((name, value))
        elif b & 0x20:                        # 001xxxxx dynamic table size update
            _size, offset = decode_integer(block, offset, 5)
        else:                                 # 0000/0001 literal without / never indexed
            index, offset = decode_integer(block, offset, 4)
            name, offset = (_static(index)[0], offset) if index else decode_string(block, offset)
            value, offset = decode_string(block, offset)
            out.append((name, value))
    return out
