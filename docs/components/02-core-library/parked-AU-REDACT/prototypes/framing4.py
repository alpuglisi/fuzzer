"""Revision 4 framing (S1 + B2): a framed body is stored byte-exact when every plausible
reading of it is clean, else a typed omission. No decoded copy is ever stored.

Readings: as chunked (when a TE value contains ``chunked`` and the body parses as chunked)
and as identity (always); each then undoes the TE compression codings and the single CE
value's codings, in reverse. A reading that does not decode is not plausible; caps and
secrets fail closed whatever the reading. Framing bytes kept byte-exact (chunk
extensions, trailers and the suffix after the last chunk, gzip header fields) are judged
by the text pass (B2), never the name scan."""
from __future__ import annotations

import io
import os
import re
import zlib

import proto3
from fuzzlab.core.redaction import MAX_REDACT_BYTES

REVERT = os.environ.get("REVERT", "")
MEMBER_CAP = 1024
CHUNK_CAP = 65_536
FRAME_OPS_CAP = 200_000
FIRST_PIECE = 256
PIECE_MAX = 64 * 1024
ZSTD_WINDOW_MAX = 8 * 1024 * 1024
_CODING = re.compile(r"[a-z0-9-]{1,32}")
_ZSTD_SKIP = re.compile(rb"[\x50-\x5f]\x2a\x4d\x18")
CAP_SOURCE = None


def cap_now() -> int:
    return getattr(CAP_SOURCE, "MAX_REDACT_BYTES", MAX_REDACT_BYTES)


class Omit(Exception):
    """Fail closed whatever the reading: a cap, or a secret."""


class Undecodable(Exception):
    """This reading does not decode (not plausible)."""


class Stats:
    def __init__(self):
        self.ops = self.members = self.chunks = self.fed = self.produced = 0
        self.max_out_call = 0
        self.readings = 0

    def step(self):
        self.ops += 1
        if self.ops > FRAME_OPS_CAP:
            raise Omit("framing operations budget")


def coding_label(tokens):
    return "+".join(t if _CODING.fullmatch(t) else "other" for t in tokens) or "other"


def marker(tokens, why: str) -> bytes:
    return f"__BODY_OMITTED__ (framed {coding_label(tokens)} body: {why})".encode()


def dechunk(body: bytes, cap: int, st: Stats, extras: list):
    out, i, n = bytearray(), 0, len(body)
    while True:
        st.step()
        st.chunks += 1
        if st.chunks > CHUNK_CAP:
            raise Omit("over the chunk cap")
        j = body.find(b"\r\n", i, i + 4096)
        if j == -1:
            raise Undecodable("malformed chunk")
        size_s, _, ext = body[i:j].partition(b";")
        if ext:
            extras.append(("a chunk extension holds a secret", b";" + ext))
        try:
            size = int(size_s.strip(), 16)
        except ValueError:
            raise Undecodable("malformed chunk") from None
        if size == 0:
            suffix = body[j + 2:]
            if suffix != b"\r\n":
                extras.append(("a trailer or suffix holds a secret", suffix))
            return bytes(out)
        if len(out) + size > cap:                     # ADOPT: the decoded cap, not 1 << 62
            raise Omit("decoded body over the cap")
        if j + 2 + size + 2 > n or body[j + 2 + size:j + 4 + size] != b"\r\n":
            raise Undecodable("malformed chunk")
        out += body[j + 2:j + 2 + size]
        i = j + 4 + size


def _gzip_header_fields(mv, off: int) -> bytes:
    b = bytes(mv[off:off + 10])
    if len(b) < 10 or b[:2] != b"\x1f\x8b":
        raise Undecodable("not a gzip member")
    flg, p, fields = b[3], off + 10, b""
    if flg & 4:
        xlen = int.from_bytes(bytes(mv[p:p + 2]), "little")
        fields += bytes(mv[p + 2:p + 2 + xlen])
        p += 2 + xlen
    for bit in (8, 16):
        if flg & bit:
            e = bytes(mv[p:p + 65536]).find(b"\0")
            if e == -1:
                raise Undecodable("gzip header field unterminated")
            fields += b" " + bytes(mv[p:p + e])
            p += e + 1
    return fields


def _inflate(mv, off, wbits, cap, total, out, st):
    d = zlib.decompressobj(wbits)
    piece, n = FIRST_PIECE, len(mv)
    while not d.eof:
        if off >= n:
            raise Undecodable("truncated stream")
        st.step()
        data = mv[off:] if REVERT == "recopy" else mv[off:off + piece]
        st.fed += len(data)
        try:
            chunk = d.decompress(data, (cap - total) if REVERT == "maxlen0"
                                 else max(1, cap - total + 1))
        except zlib.error:
            raise Undecodable("undecodable") from None
        st.max_out_call = max(st.max_out_call, len(chunk))
        st.produced += len(chunk)
        total += len(chunk)
        out.append(chunk)
        if total > cap:
            raise Omit("decoded body over the cap")
        off += len(data) - len(d.unused_data) - len(d.unconsumed_tail)
        piece = min(PIECE_MAX, piece * 2)
    return off, total


def gunzip(data, cap, st, extras):
    mv, off, total, out, members = memoryview(data), 0, 0, [], 0
    while off < len(data):
        members += 1
        st.members += 1
        if members > MEMBER_CAP:
            raise Omit("over the member cap")
        fields = _gzip_header_fields(mv, off)
        if fields:
            extras.append(("a gzip header field holds a secret", fields))
        off, total = _inflate(mv, off, 16 + zlib.MAX_WBITS, cap, total, out, st)
    if members == 0:
        raise Undecodable("empty")
    return b"".join(out)


def inflate(data, cap, st, extras):
    mv = memoryview(data)
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        out = []
        try:
            off, _total = _inflate(mv, 0, wbits, cap, 0, out, st)
        except Undecodable:
            continue
        if off != len(data):
            raise Undecodable("trailing bytes after the stream")
        return b"".join(out)
    raise Undecodable("undecodable")


def unbrotli(data, cap, st, extras):
    try:
        import brotli
    except ImportError:
        raise Undecodable("coding not supported here") from None
    d = brotli.Decompressor()
    st.step()
    st.fed += len(data)
    try:
        out = [d.process(data, output_buffer_limit=cap + 1)]
        total = len(out[0])
        while total <= cap and not d.is_finished() and not d.can_accept_more_data():
            st.step()
            more = d.process(b"", output_buffer_limit=cap + 1 - total)
            if not more:
                break
            out.append(more)
            total += len(more)
    except TypeError:                           # ADOPT: an older API is unsupported, not a crash
        raise Undecodable("coding not supported here") from None
    except brotli.error:
        raise Undecodable("undecodable") from None
    st.max_out_call = max(st.max_out_call, max(len(c) for c in out))
    st.produced += total
    if total > cap:
        raise Omit("decoded body over the cap")
    if not d.is_finished():
        raise Undecodable("truncated stream")
    return b"".join(out)


def unzstd(data, cap, st, extras):
    try:
        import zstandard
    except ImportError:
        raise Undecodable("coding not supported here") from None
    if _ZSTD_SKIP.search(data):
        raise Omit("a skippable frame may hold content")
    st.step()
    try:
        r = zstandard.ZstdDecompressor(max_window_size=ZSTD_WINDOW_MAX).stream_reader(
            io.BytesIO(data), read_across_frames=True)
        out = r.read(cap + 1)
        more = r.read(1) if len(out) <= cap else b""
    except TypeError:
        raise Undecodable("coding not supported here") from None
    except zstandard.ZstdError:
        raise Undecodable("undecodable") from None
    st.fed += len(data)
    st.produced += len(out)
    if len(out) > cap or more:
        raise Omit("decoded body over the cap")
    if not out and data:
        raise Undecodable("undecodable")
    return out


_DECODERS = {"gzip": gunzip, "x-gzip": gunzip, "deflate": inflate, "br": unbrotli,
             "zstd": unzstd}


def _clean(b: bytes) -> bool:
    """B2: framing bytes are judged by the text pass (a binding or a credential shape),
    never by the name scan (``auth.js``, ``GET /api/keys`` are clean)."""
    return proto3.new_redact_body(b, "message/http") == b


def _secret_reason(why: str) -> bool:
    return why.startswith(("redaction would change", "a chunk extension", "a trailer",
                           "a gzip header", "a skippable frame"))


def judge(te_values, ce_values, ctype: str, body: bytes, stats: Stats | None = None) -> bytes:
    st = stats or Stats()
    tokens = [v.strip().lower() for v in te_values] + [c.strip().lower() for c in ce_values]
    cap = cap_now()
    try:
        if len(ce_values) > 1:
            raise Omit("duplicate Content-Encoding headers")
        ce = [t.strip().lower() for t in (ce_values[0].split(",") if ce_values else [])]
        ce = [t for t in ce if t and t != "identity"]
        if any(t not in _DECODERS for t in ce):
            raise Omit("coding not supported here")
        te = [t.strip().lower() for v in te_values for t in v.split(",") if t.strip()]
        te_codings = [t for t in te if t in _DECODERS]
        readings = []
        if any("chunked" in t for t in te):
            extras: list = []
            try:
                readings.append((dechunk(body, cap, st, extras), extras))
            except Undecodable:
                pass                                   # not a plausible chunked reading
        readings.append((body, []))
        decoded, why = [], "undecodable"
        for data, extras in readings:
            st.readings += 1
            ex = list(extras)
            try:
                for t in reversed(te_codings):
                    data = _DECODERS[t](data, cap, st, ex)
                for t in reversed(ce):
                    data = _DECODERS[t](data, cap, st, ex)
            except Undecodable as e:
                why = str(e)
                continue
            if len(data) > cap:
                raise Omit("decoded body over the cap")
            decoded.append((data, ex))
        if not decoded:
            raise Omit(why)
        for data, ex in decoded:
            for reason, b in ex:
                if not _clean(b):
                    raise Omit(reason)
            if proto3.new_redact_body(data, ctype) != data:
                raise Omit("redaction would change it")
        return body
    except Omit as e:
        if not proto3.redactable_type(ctype) and not _secret_reason(str(e)):
            return body                       # declared binary (R4): as received, as today
        return marker(tokens, str(e))
