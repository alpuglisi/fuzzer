"""Phase 9 T9.1: WebSocket frame codec, handshake, and flow.protocol (migration 9)."""

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.ws import (OP_BINARY, OP_CLOSE, OP_CONTINUATION, OP_PING, OP_TEXT,
                              WSProtocolError, accept_key, apply_mask, decode_frame,
                              decode_frames, encode_frame, is_upgrade_request,
                              is_upgrade_response, new_mask, reassemble)


# --- migration 9 -------------------------------------------------------------
def test_migration_9_adds_flow_protocol(tmp_path):
    with Store(tmp_path / "u.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 9
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(flow)")}
        assert "protocol" in cols


# --- handshake ---------------------------------------------------------------
def test_accept_key_rfc_vector():
    # RFC 6455 §1.3 worked example
    assert accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_upgrade_detection():
    req = (b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n"
           b"Connection: Upgrade\r\nSec-WebSocket-Key: x\r\n\r\n")
    assert is_upgrade_request(req)
    assert not is_upgrade_request(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    resp = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
    assert is_upgrade_response(resp)
    assert not is_upgrade_response(b"HTTP/1.1 200 OK\r\n\r\n")


# --- framing (byte-exact) ----------------------------------------------------
def test_unmasked_text_frame_is_byte_exact():
    assert encode_frame(OP_TEXT, b"Hello") == b"\x81\x05Hello"   # FIN|TEXT, len 5
    frame, n = decode_frame(b"\x81\x05Hello")
    assert frame.opcode == OP_TEXT and frame.payload == b"Hello"
    assert frame.fin and not frame.masked and n == 7


def test_masking_hides_payload_and_roundtrips():
    mask = new_mask(seed=1)
    wire = encode_frame(OP_TEXT, b"secret", mask=mask)
    assert wire[1] & 0x80                                     # MASK bit set
    assert b"secret" not in wire                              # masked on the wire
    frame, _ = decode_frame(wire)
    assert frame.masked and frame.payload == b"secret"        # decoded back
    assert apply_mask(apply_mask(b"secret", mask), mask) == b"secret"  # self-inverse


def test_extended_lengths():
    for size in (200, 70000):                                 # 16-bit and 64-bit paths
        payload = b"z" * size
        frame, n = decode_frame(encode_frame(OP_BINARY, payload))
        assert frame.payload == payload and n == len(encode_frame(OP_BINARY, payload))


def test_control_frames():
    for op in (OP_PING, OP_CLOSE):
        frame, _ = decode_frame(encode_frame(op, b"\x03\xe8"))
        assert frame.opcode == op and frame.is_control


def test_fragmented_message_reassembles():
    frames = [
        decode_frame(encode_frame(OP_TEXT, b"Hel", fin=False))[0],
        decode_frame(encode_frame(OP_CONTINUATION, b"lo", fin=True))[0],
    ]
    msgs = reassemble(frames)
    assert len(msgs) == 1 and msgs[0].opcode == OP_TEXT and msgs[0].text == "Hello"


def test_decode_frames_handles_multiple_and_partial_tail():
    data = encode_frame(OP_TEXT, b"a") + encode_frame(OP_TEXT, b"b")
    frames, used = decode_frames(data)
    assert [f.payload for f in frames] == [b"a", b"b"] and used == len(data)
    # a trailing incomplete frame is left unconsumed
    frames2, used2 = decode_frames(data + b"\x81\x05Hel")
    assert len(frames2) == 2 and used2 == len(data)


def test_decode_incomplete_raises():
    with pytest.raises(WSProtocolError):
        decode_frame(b"\x81")                                 # header truncated
    with pytest.raises(WSProtocolError):
        decode_frame(b"\x81\x05Hel")                          # payload truncated


# --- history integration -----------------------------------------------------
def test_history_records_protocol(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("proxy", "h")
        w = HistoryWriter(store, run_id)
        w.record(FlowRecord("GET", "ws://h/ws", "h", protocol="ws",
                            raw_request=b"data"))
        w.record(FlowRecord("GET", "http://h/", "h", raw_request=b"x"))  # default proto
        w.flush()
        protos = {r["url"]: r["protocol"] for r in
                  store.conn.execute("SELECT url, protocol FROM flow")}
        assert protos["ws://h/ws"] == "ws"
        assert protos["http://h/"] == "http/1.1"
