"""WebSocket framing, from scratch (Phase 9 T9.1, FR-PROXY-1 / protocol depth).

A byte-exact RFC 6455 frame codec — the raw path for WebSocket, so the proxy can
inspect, edit, and replay frames (including malformed/masked ones) without a library
normalizing them. Dependency-light (stdlib only); the parsed convenience path via
`wsproto` is declared separately and skip-guarded.

Frame layout: FIN + RSV1-3 + opcode (1 byte); MASK + 7-bit length (1 byte), with a
16- or 64-bit extended length; a 4-byte masking key when MASK is set; then the payload
(XOR-masked with the key). Client→server frames are masked; server→client are not.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

# Opcodes (RFC 6455 §5.2)
OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

_CONTROL = {OP_CLOSE, OP_PING, OP_PONG}
# Magic GUID for the Sec-WebSocket-Accept handshake (RFC 6455 §4.2.2).
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WSProtocolError(ValueError):
    """A frame violated the WebSocket framing rules."""


def apply_mask(payload: bytes, mask: bytes) -> bytes:
    """XOR ``payload`` with the 4-byte ``mask`` (masking is its own inverse)."""
    if len(mask) != 4:
        raise WSProtocolError("mask must be 4 bytes")
    return bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


@dataclass
class WSFrame:
    opcode: int
    payload: bytes = b""
    fin: bool = True
    masked: bool = False
    mask: bytes = b""
    rsv1: bool = False
    rsv2: bool = False
    rsv3: bool = False

    @property
    def is_control(self) -> bool:
        return self.opcode in _CONTROL


def encode_frame(opcode: int, payload: bytes = b"", *, fin: bool = True,
                 mask: bytes | None = None, rsv: tuple[int, int, int] = (0, 0, 0)) -> bytes:
    """Serialize one frame to exact bytes. Pass ``mask`` (4 bytes) to mask the payload
    (client frames); omit it for an unmasked frame (server frames)."""
    b0 = (0x80 if fin else 0) | (rsv[0] and 0x40) | (rsv[1] and 0x20) | (rsv[2] and 0x10)
    b0 |= opcode & 0x0F
    out = bytearray([b0])
    length = len(payload)
    mask_bit = 0x80 if mask is not None else 0
    if length < 126:
        out.append(mask_bit | length)
    elif length < 65536:
        out.append(mask_bit | 126)
        out += length.to_bytes(2, "big")
    else:
        out.append(mask_bit | 127)
        out += length.to_bytes(8, "big")
    if mask is not None:
        if len(mask) != 4:
            raise WSProtocolError("mask must be 4 bytes")
        out += mask
        out += apply_mask(payload, mask)
    else:
        out += payload
    return bytes(out)


def decode_frame(data: bytes) -> tuple[WSFrame, int]:
    """Decode one frame from the front of ``data``; return ``(frame, bytes_consumed)``.

    Raises ``WSProtocolError`` if ``data`` does not yet hold a complete frame (the caller
    should read more bytes). The frame's ``payload`` is unmasked.
    """
    if len(data) < 2:
        raise WSProtocolError("need at least 2 bytes for a frame header")
    b0, b1 = data[0], data[1]
    fin = bool(b0 & 0x80)
    rsv1, rsv2, rsv3 = bool(b0 & 0x40), bool(b0 & 0x20), bool(b0 & 0x10)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    off = 2
    if length == 126:
        if len(data) < off + 2:
            raise WSProtocolError("truncated 16-bit length")
        length = int.from_bytes(data[off:off + 2], "big")
        off += 2
    elif length == 127:
        if len(data) < off + 8:
            raise WSProtocolError("truncated 64-bit length")
        length = int.from_bytes(data[off:off + 8], "big")
        off += 8
    mask = b""
    if masked:
        if len(data) < off + 4:
            raise WSProtocolError("truncated masking key")
        mask = data[off:off + 4]
        off += 4
    if len(data) < off + length:
        raise WSProtocolError("truncated payload")
    raw_payload = data[off:off + length]
    payload = apply_mask(raw_payload, mask) if masked else raw_payload
    frame = WSFrame(opcode=opcode, payload=payload, fin=fin, masked=masked, mask=mask,
                    rsv1=rsv1, rsv2=rsv2, rsv3=rsv3)
    return frame, off + length


def decode_frames(data: bytes) -> tuple[list[WSFrame], int]:
    """Decode all complete frames from ``data``; return ``(frames, bytes_consumed)``."""
    frames: list[WSFrame] = []
    off = 0
    while off < len(data):
        try:
            frame, used = decode_frame(data[off:])
        except WSProtocolError:
            break                            # incomplete tail; stop
        frames.append(frame)
        off += used
    return frames, off


@dataclass
class WSMessage:
    opcode: int                              # OP_TEXT or OP_BINARY
    data: bytes

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", "replace")


def reassemble(frames: list[WSFrame]) -> list[WSMessage]:
    """Reassemble fragmented data frames into messages (control frames excluded)."""
    messages: list[WSMessage] = []
    cur_op: int | None = None
    buf = bytearray()
    for f in frames:
        if f.is_control:
            continue
        if f.opcode != OP_CONTINUATION:
            cur_op = f.opcode
            buf = bytearray(f.payload)
        else:
            buf += f.payload
        if f.fin and cur_op is not None:
            messages.append(WSMessage(cur_op, bytes(buf)))
            cur_op, buf = None, bytearray()
    return messages


def new_mask(seed: int | None = None) -> bytes:
    """A 4-byte masking key (deterministic when a seed is given, else random)."""
    if seed is not None:
        import random
        return random.Random(seed).randbytes(4)
    return os.urandom(4)


# --- handshake (reuses the HTTP/1.1 machinery) -------------------------------
def accept_key(sec_websocket_key: str) -> str:
    """Compute Sec-WebSocket-Accept from the client's Sec-WebSocket-Key (RFC 6455)."""
    digest = hashlib.sha1((sec_websocket_key + _GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def is_upgrade_request(raw: bytes) -> bool:
    """True if the request is a WebSocket Upgrade (Upgrade+Connection headers)."""
    from fuzzlab.proxy.message import RawMessage
    msg = RawMessage.from_bytes(raw)
    up = (msg.get("Upgrade") or b"").lower()
    conn = (msg.get("Connection") or b"").lower()
    return b"websocket" in up and b"upgrade" in conn


def is_upgrade_response(raw: bytes) -> bool:
    """True if the response accepts a WebSocket upgrade (101 + Sec-WebSocket-Accept)."""
    from fuzzlab.proxy.message import RawMessage
    msg = RawMessage.from_bytes(raw)
    return msg.start_line.split(b" ")[1:2] == [b"101"] and \
        msg.get("Sec-WebSocket-Accept") is not None
