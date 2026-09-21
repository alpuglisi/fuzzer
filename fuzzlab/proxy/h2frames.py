"""HTTP/2 frame layer, from scratch (Phase 9 T9.2, RFC 7540).

Byte-exact encode/decode of the HTTP/2 framing so the raw client can put arbitrary —
including malformed — frames on the wire (the point for desync research). A frame is a
9-byte header (24-bit length, 8-bit type, 8-bit flags, 1 reserved bit + 31-bit stream id)
followed by the payload. ``encode_frame`` lets the caller override the declared length
independently of the actual payload, so a length-desync primitive is one call away. The
parsed convenience path (`h2`) is declared separately and skip-guarded.
"""

from __future__ import annotations

from dataclasses import dataclass

# The client connection preface (RFC 7540 §3.5).
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types (§6).
DATA = 0x0
HEADERS = 0x1
PRIORITY = 0x2
RST_STREAM = 0x3
SETTINGS = 0x4
PUSH_PROMISE = 0x5
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0x9

# Flags.
FLAG_END_STREAM = 0x1        # DATA, HEADERS
FLAG_ACK = 0x1               # SETTINGS, PING
FLAG_END_HEADERS = 0x4       # HEADERS, CONTINUATION, PUSH_PROMISE
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20         # HEADERS

# Common SETTINGS identifiers (§6.5.2).
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6


class H2FrameError(ValueError):
    pass


@dataclass
class Frame:
    type: int
    flags: int
    stream_id: int
    payload: bytes = b""
    declared_length: int | None = None      # as read from the wire (may != len(payload))


def encode_frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"",
                 *, length: int | None = None, reserved_bit: int = 0) -> bytes:
    """Serialize one frame. ``length`` overrides the declared 24-bit length (default
    ``len(payload)``) so a length-desync frame can be built deliberately."""
    declared = len(payload) if length is None else length
    if not (0 <= declared < (1 << 24)):
        raise H2FrameError("length must fit in 24 bits")
    sid = (reserved_bit & 1) << 31 | (stream_id & 0x7FFFFFFF)
    header = declared.to_bytes(3, "big") + bytes([ftype & 0xFF, flags & 0xFF]) \
        + sid.to_bytes(4, "big")
    return header + payload


def decode_frame(data: bytes) -> tuple[Frame, int]:
    """Decode one frame; return ``(frame, bytes_consumed)``. The frame's ``payload`` is
    read using the declared length; ``declared_length`` preserves what the wire said."""
    if len(data) < 9:
        raise H2FrameError("need 9 bytes for a frame header")
    declared = int.from_bytes(data[0:3], "big")
    ftype = data[3]
    flags = data[4]
    stream_id = int.from_bytes(data[5:9], "big") & 0x7FFFFFFF
    end = 9 + declared
    if len(data) < end:
        raise H2FrameError("truncated frame payload")
    return Frame(ftype, flags, stream_id, data[9:end], declared_length=declared), end


def decode_frames(data: bytes) -> tuple[list[Frame], int]:
    frames: list[Frame] = []
    off = 0
    while off < len(data):
        try:
            frame, used = decode_frame(data[off:])
        except H2FrameError:
            break
        frames.append(frame)
        off += used
    return frames, off


# --- convenience builders ----------------------------------------------------
def settings_frame(settings: dict[int, int] | None = None, *, ack: bool = False) -> bytes:
    if ack:
        return encode_frame(SETTINGS, FLAG_ACK, 0, b"")
    payload = b"".join(sid.to_bytes(2, "big") + val.to_bytes(4, "big")
                       for sid, val in (settings or {}).items())
    return encode_frame(SETTINGS, 0, 0, payload)


def headers_frame(stream_id: int, header_block: bytes, *, end_stream: bool = False,
                  end_headers: bool = True, flags: int | None = None,
                  length: int | None = None) -> bytes:
    if flags is None:
        flags = (FLAG_END_HEADERS if end_headers else 0) \
            | (FLAG_END_STREAM if end_stream else 0)
    return encode_frame(HEADERS, flags, stream_id, header_block, length=length)


def data_frame(stream_id: int, data: bytes, *, end_stream: bool = True,
               length: int | None = None) -> bytes:
    return encode_frame(DATA, FLAG_END_STREAM if end_stream else 0, stream_id, data,
                        length=length)


def window_update_frame(stream_id: int, increment: int) -> bytes:
    return encode_frame(WINDOW_UPDATE, 0, stream_id,
                        (increment & 0x7FFFFFFF).to_bytes(4, "big"))


def ping_frame(opaque: bytes = b"\x00" * 8, *, ack: bool = False) -> bytes:
    return encode_frame(PING, FLAG_ACK if ack else 0, 0, opaque[:8].ljust(8, b"\x00"))


def rst_stream_frame(stream_id: int, error_code: int = 0) -> bytes:
    return encode_frame(RST_STREAM, 0, stream_id, error_code.to_bytes(4, "big"))


def goaway_frame(last_stream_id: int = 0, error_code: int = 0, debug: bytes = b"") -> bytes:
    payload = (last_stream_id & 0x7FFFFFFF).to_bytes(4, "big") \
        + error_code.to_bytes(4, "big") + debug
    return encode_frame(GOAWAY, 0, 0, payload)
