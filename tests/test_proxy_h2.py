"""Phase 9 T9.2/T9.3: HTTP/2 frames, minimal HPACK, and the raw-frame client."""

import pytest

from fuzzlab.proxy import h2frames as h2
from fuzzlab.proxy import hpack
from fuzzlab.proxy.h2client import H2RawClient


# --- HPACK -------------------------------------------------------------------
def test_hpack_integer_rfc_vectors():
    assert hpack.encode_integer(10, 5) == b"\x0a"
    assert hpack.encode_integer(1337, 5) == b"\x1f\x9a\x0a"
    v, off = hpack.decode_integer(b"\x1f\x9a\x0a", 0, 5)
    assert v == 1337 and off == 3


def test_hpack_headers_roundtrip_including_arbitrary_bytes():
    hdrs = [(b":method", b"GET"), (b":path", b"/"), (b":authority", b"lab"),
            (b"x-smuggle", b"a\r\nInjected: 1")]     # arbitrary CRLF in a value
    block = hpack.encode_headers(hdrs)
    assert hpack.decode_headers(block) == hdrs        # exact round-trip
    assert hpack.decode_headers(block)[-1][1] == b"a\r\nInjected: 1"


def test_hpack_static_indexed_decode():
    assert hpack.decode_headers(b"\x82") == [(b":method", b"GET")]   # index 2
    assert hpack.decode_headers(b"\x87") == [(b":scheme", b"https")]  # index 7


def test_hpack_huffman_decode_raises():
    # H bit set on a string length → Huffman, which we do not decode offline
    block = b"\x00" + b"\x81\x00" + b"\x00"           # name: H=1,len=1 → error
    with pytest.raises(hpack.HpackError):
        hpack.decode_headers(block)


# --- frame layer -------------------------------------------------------------
def test_frame_roundtrip_and_flags():
    block = hpack.encode_headers([(b":method", b"GET")])
    frame = h2.headers_frame(1, block, end_stream=True)
    fr, n = h2.decode_frame(frame)
    assert fr.type == h2.HEADERS and fr.stream_id == 1 and fr.payload == block
    assert n == len(frame)
    assert fr.flags == (h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM)


def test_length_override_is_a_desync_primitive():
    # declare length 1 but carry 4 payload bytes → the wire framing believes length 1
    frame = h2.encode_frame(h2.DATA, 0, 1, b"AAAA", length=1)
    fr, consumed = h2.decode_frame(frame)
    assert fr.declared_length == 1 and len(fr.payload) == 1 and consumed == 10


def test_builders_decode_correctly():
    s, _ = h2.decode_frame(h2.settings_frame({h2.SETTINGS_MAX_FRAME_SIZE: 16384}))
    assert s.type == h2.SETTINGS and s.stream_id == 0
    assert h2.decode_frame(h2.settings_frame(ack=True))[0].flags == h2.FLAG_ACK
    wu, _ = h2.decode_frame(h2.window_update_frame(1, 65535))
    assert wu.type == h2.WINDOW_UPDATE and int.from_bytes(wu.payload, "big") == 65535
    rst, _ = h2.decode_frame(h2.rst_stream_frame(3, 8))
    assert rst.type == h2.RST_STREAM and rst.stream_id == 3
    ping, _ = h2.decode_frame(h2.ping_frame(b"12345678"))
    assert ping.type == h2.PING and ping.payload == b"12345678"


def test_decode_frames_multiple_and_partial_tail():
    data = h2.ping_frame(b"a" * 8) + h2.ping_frame(b"b" * 8)
    frames, used = h2.decode_frames(data)
    assert len(frames) == 2 and used == len(data)
    frames2, used2 = h2.decode_frames(data + b"\x00\x00\x08\x06\x00")  # partial header/body
    assert len(frames2) == 2 and used2 == len(data)


def test_decode_truncated_raises():
    with pytest.raises(h2.H2FrameError):
        h2.decode_frame(b"\x00\x00\x08\x06\x00\x00\x00\x00")          # header short
    with pytest.raises(h2.H2FrameError):
        h2.decode_frame(h2.ping_frame()[:-2])                        # payload truncated


# --- raw client --------------------------------------------------------------
def test_client_build_request_structure():
    c = H2RawClient()
    raw = c.build_request("GET", "/product.php", "127.0.0.1:8080", "http")
    assert raw.startswith(h2.PREFACE)
    frames, _ = h2.decode_frames(raw[len(h2.PREFACE):])
    assert frames[0].type == h2.SETTINGS
    headers = frames[1]
    assert headers.type == h2.HEADERS and headers.flags & h2.FLAG_END_STREAM
    decoded = hpack.decode_headers(headers.payload)
    assert (b":method", b"GET") in decoded and (b":path", b"/product.php") in decoded
    assert (b":authority", b"127.0.0.1:8080") in decoded


def test_client_body_adds_data_frame_and_stream_ids_increment():
    c = H2RawClient()
    raw = c.build_request("POST", "/login", "h", body=b"user=x", stream_id=1)
    frames, _ = h2.decode_frames(raw[len(h2.PREFACE):])
    hdr = next(f for f in frames if f.type == h2.HEADERS)
    data = next(f for f in frames if f.type == h2.DATA)
    assert not (hdr.flags & h2.FLAG_END_STREAM)        # stream stays open for the body
    assert data.payload == b"user=x" and data.flags & h2.FLAG_END_STREAM
    assert c.next_stream_id() == 1 and c.next_stream_id() == 3   # odd, incrementing


def test_client_passes_arbitrary_header_bytes():
    c = H2RawClient()
    raw = c.build_request("GET", "/", "h", headers=[(b"x", b"v\r\nSmuggled: 1")],
                          include_preface=False)
    frames, _ = h2.decode_frames(raw)
    decoded = hpack.decode_headers(frames[0].payload)
    assert (b"x", b"v\r\nSmuggled: 1") in decoded       # arbitrary bytes survive
    assert not raw.startswith(h2.PREFACE)               # preface omitted


def test_client_build_raw_arbitrary_frame_sequence():
    c = H2RawClient()
    lied = h2.encode_frame(h2.DATA, 0, 1, b"AAAA", length=1)   # malformed on purpose
    raw = c.build_raw([h2.settings_frame({}), lied])
    assert raw.startswith(h2.PREFACE)
    frames, _ = h2.decode_frames(raw[len(h2.PREFACE):])
    assert frames[0].type == h2.SETTINGS and frames[1].declared_length == 1
