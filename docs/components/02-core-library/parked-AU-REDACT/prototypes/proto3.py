"""PROTOTYPE rev 3 (scratchpad only): the redactor drafted in DRAFT-CC-CORE-0067 rev 3.

Changes from rev 2, keyed to the coordinator's merged review (S/M numbers):
- M1  a value never opens with the quote that closes the name's own string; a name in URL
      query context (``?``, ``&``, ``&amp;``, ``;``, ``#``, ``%3F``, ``%26``) takes the
      URL value grammar, which never opens a string.
- M2  a sniffed body that parses as JSON is redacted leaf by leaf and re-serialised
      (valid JSON, nothing dropped); one that does not parse takes the text pass.
- M3  markup rules run in every grammar when the body holds ``<input``/``<meta``/
      ``<textarea``/``<param``, with ``\\"``-escaped attribute quotes; every ``*html*``
      type is html; XML name/key -> value pairing; markup inside JSON leaves.
- M4  unbound credential shapes everywhere: JWT, PEM private key, URL userinfo (the
      existing ``_URL_USERINFO``, PA-0003), URL queries inside any string.
- M5  fail closed: an exhausted tag search, wide encodings (BOM, charset, NUL sniff),
      declared form/multipart that do not match their shape, YAML block scalars and
      ``.properties`` continuations.
- M6  one operations budget charged for every Python step and every C-level span.
- M7  a one-token grammar for stored page text (``words``).
"""
from __future__ import annotations

import bisect
import codecs
import html as _html
import json
import os
import re

REVERT = os.environ.get("REVERT", "")

from fuzzlab.core.redaction import (_FORM_SHAPE, _URL_USERINFO, MAX_JSON_DEPTH,
                                    MAX_REDACT_BYTES, OMIT_FAILED, OMIT_TOO_LARGE, OMIT_UNSAFE,
                                    PLACEHOLDER, USERINFO_PLACEHOLDER, _depth_ok,
                                    is_sensitive_name, looks_like_identifier,
                                    mentions_sensitive_name, redact_query)

VALUE_MAX = 8 * 1024 * 1024    # M6: a quoted value, container, element or block is bounded by the body and the budget
UNQUOTED_MAX = 4096
NAME_MAX = 128
TAG_MAX = 8 * 1024 * 1024      # M6: a tag (a large __VIEWSTATE) is bounded by the body and the budget
TAG_TRIES = 32
MAX_HITS = 20_000            # 4x the largest real body measured (4,998)
OPS_CAP = 500_000            # the one budget (16x the most a real body used: 31,541)
SPAN_UNIT = 256
SKELETON_MAX = 16 * 1024
CACHE_MAX = 4096            # tag summaries kept for locality; cleared when full (memory bound)

OMIT_UNPROVABLE = "__BODY_OMITTED__ (unprovable {kind} body: {why})"


class Unprovable(Exception):
    pass


class Budget:
    def __init__(self):
        self.ops = 0
        self.hits = 0

    def step(self, k: int = 1) -> None:
        self.ops += k
        if self.ops > OPS_CAP and REVERT != "nocap":
            raise Unprovable("operations budget")

    def span(self, chars: int) -> None:
        self.step(1 + max(0, chars) // SPAN_UNIT)


# --- grammar selection -----------------------------------------------------------------

_HTML_SNIFF = (b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<iframe",
               b"<h1", b"<div", b"<font", b"<table", b"<a ", b"<style", b"<title", b"<b>",
               b"<br", b"<p>", b"<p ", b"<!--", b"<form", b"<input", b"<meta", b"<section",
               b"<label", b"<template", b"<turbo-stream", b"<span", b"<ul", b"<li")
_XML_TYPES = ("application/xml", "text/xml")
_JS_TYPES = ("application/javascript", "text/javascript", "application/x-javascript",
             "application/ecmascript", "text/ecmascript")
_BINARY_PREFIX = ("image/", "audio/", "video/", "font/")
_BINARY_TYPES = {"application/pdf", "application/zip", "application/gzip", "application/wasm",
                 "application/x-protobuf", "application/grpc", "application/vnd.ms-fontobject"}
_MARKUP = re.compile(r"<(?:input|meta|textarea|param)\b", re.I)


def media_of(ctype: str) -> str:
    return (ctype or "").split(";", 1)[0].strip().lower()


def grammar_of(text_head: str, ctype: str) -> str | None:
    media = media_of(ctype)
    head = text_head[:1024].removeprefix("\xef\xbb\xbf").lstrip("\ufeff \t\r\n").lower()
    if "html" in media or head.startswith(tuple(h.decode() for h in _HTML_SNIFF)):
        return "html"
    if media in _XML_TYPES or media.endswith("+xml") or head.startswith("<?xml"):
        return "xml"
    if media in _JS_TYPES:
        return "js"
    if media == "text/css":
        return "data"
    if media.startswith(_BINARY_PREFIX) or media in _BINARY_TYPES:
        return None
    return "text"


def redactable_type(ctype: str) -> bool:
    media = media_of(ctype)
    return not (media.startswith(_BINARY_PREFIX) and not media.endswith("+xml")) \
        and media not in _BINARY_TYPES


# --- wide encodings (M5b) ----------------------------------------------------------------

_PRINTABLE = frozenset(b"\t\n\r" + bytes(range(0x20, 0x7f)))
_BOMS = [(codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be"),
         (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be")]


def wide_encoding(body: bytes, ctype: str) -> str | None:
    """The wide encoding the body is in (``utf-16``, ``utf-16-le``, ...), or None."""
    for bom, enc in _BOMS:
        if body.startswith(bom):
            return enc
    m = re.search(r"charset\s*=\s*\"?([A-Za-z0-9_-]+)", ctype or "", re.I)
    if m and m.group(1).lower().replace("_", "-") in (
            "utf-16", "utf-16le", "utf-16be", "utf-32", "utf-32le", "utf-32be"):
        cs = m.group(1).lower().replace("_", "-")
        exact = {"utf-16le": "utf-16-le", "utf-16be": "utf-16-be",
                 "utf-32le": "utf-32-le", "utf-32be": "utf-32-be"}.get(cs)
        if exact:
            return exact
        head = body[:1024]                        # no BOM: the NUL parity decides the order
        if cs == "utf-16":
            return "utf-16-le" if head[1::2].count(0) >= head[0::2].count(0) else "utf-16-be"
        return "utf-32-le" if head[3::4].count(0) >= head[0::4].count(0) else "utf-32-be"
    head = body[:1024]
    if len(head) >= 8 and head.count(0) * 10 >= len(head) * 3:      # >= 30% NUL bytes
        for zeros, chars, enc in ((head[1::2], head[0::2], "utf-16-le"),
                                  (head[0::2], head[1::2], "utf-16-be")):
            if zeros.count(0) * 10 >= len(zeros) * 9 and \
                    sum(1 for c in chars if c in _PRINTABLE) * 10 >= len(chars) * 9:
                return enc                       # a strong UTF-16 pattern
    return None


# --- the text pass -----------------------------------------------------------------------

def _trie(words):
    t: dict = {}
    for w in words:
        d = t
        for ch in w:
            d = d.setdefault(ch, {})
        d[""] = {}

    def emit(d):
        if list(d) == [""]:
            return ""
        alts = [re.escape(ch) + emit(d[ch]) for ch in sorted(k for k in d if k)]
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return f"(?:{body})?" if "" in d else body
    return emit(t)


_WORDS = ["pass", "pw", "secret", "token", "jwt", "cookie", "credential", "sess", "sid",
          "key", "auth", "otp", "csrf", "xsrf", "bearer", "sig", "pin", "nonce", "cvv", "cvc",
          "cvn", "csc", "code", "answer", "&#"]
_CAND = re.compile(_trie(_WORDS))
_TYPE = re.compile(r"""type\s*=\s*\\?["']?(?:password|hidden)\b""")   # literal prefix
_LASTDELIM = re.compile(r".*[^A-Za-z0-9_$.\-@]", re.S)
_RIGHT = re.compile(r"[A-Za-z0-9_$.\-@]{0,128}")
_OP = re.compile(r"""(\\["']|["'])?\]?[ \t\r\n\f]{0,16}(=>|:=|=(?!=)|:(?!:))[ \t\r\n\f]{0,16}""")
_PCT_OP = re.compile(r"%3[Dd]")
_RAWTEXT = re.compile(r"<(?:script|style)\b[^>]*>(.*?)</(?:script|style)\s*>", re.I | re.S)
_LAST_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_JS_KEYWORDS = frozenset("var let const return yield await typeof void delete new in of case "
                         "else do export static async get set throw instanceof default".split())
_PROSE = re.compile(r"""[^"'`\r\n\\]{1,4096}""")
_ATTR_EQ = re.compile(r"[ \t\r\n\f]*=")
_PCT_LEAD = re.compile(r"[0-9A-Fa-f]{2}")
_DQ = re.compile(r'(?:[^"\\]|\\.)*+"', re.S)
_SQ = re.compile(r"(?:[^'\\]|\\.)*+'", re.S)
_BQ = re.compile(r"(?:[^`\\]|\\.)*+`", re.S)
_UNQ = re.compile(r"""[^\s"'<>&;,(){}\[\]`#\\]{1,4096}""")
_WORD = re.compile(r"\S{1,4096}")
_EOL = re.compile(r"(?:[^\r\n&]|&(?![^=&\s]{1,128}=)){1,65536}+")
_URLV = re.compile(r"""[^&#;?"'\s<>`\\]{0,4096}""")          # ADOPT: stops at '?'
_URLV_PCT = re.compile(r"""(?:[^&#?"'\s<>`\\%]|%(?!2[6Ff3]|23)[0-9A-Fa-f]{2}){0,4096}""")
_BRACKETS = re.compile(r"""[\[\]{}"'\\]""")
_NUMBER = re.compile(r"[-+]?(?:0[xXoObB][0-9a-fA-F_]+|[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?)n?")
_TAGNAME = re.compile(r"<([A-Za-z][^\s/>\\]{0,63})")
_ATTR = re.compile(r"""[\s/]*((?:=|[^\s/>"'=\\])[^\s/>"'=\\]*)"""
                   r"""(?:\s*=\s*(?:\\"((?:[^\\]|\\(?!"))*)\\"|\\'((?:[^\\]|\\(?!'))*)\\'"""
                   r"""|"([^"]*)"|'([^']*)'|([^\s>\\]*)))?""")
_ATTR_NAME = re.compile(r"""[\s/]*((?:=|[^\s/>"'=\\])[^\s/>"'=\\]*)([ \t\r\n\f]*=[ \t\r\n\f]*)?""")
_UNQ_ATTR = re.compile(r"""[^\s>"'\\][^\s>\\]{0,4095}""")
_BIND_ATTRS = {"name", "id", "http-equiv", "property", "itemprop", "key"}
_VALUE_ATTRS = {"value", "content"}
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*){1,3}")  # rev 3 (REVERT)
_JWT_HEAD = re.compile(r"eyJ[A-Za-z0-9_-]*")         # B1: greedy, never fails once started
_B64SEG = re.compile(r"[A-Za-z0-9_-]*")
_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]{0,40}(?:PRIVATE KEY(?: BLOCK)?|SECRET[A-Z0-9 ]{0,20}))-----")
_PPK = re.compile(r"PuTTY-User-Key-File-[0-9]{1,2}:")
_PPK_PRIV = re.compile(r"Private-Lines: *([0-9]{1,4})\r?\n")
_BEARER = re.compile(r"Bearer[ \t]+([A-Za-z0-9\-._~+/]{8,4096}=*)")   # B4, unbound; literal-led
_AUTH_SCHEMES = frozenset("bearer basic digest token negotiate ntlm apikey bot hoba mutual "
                          "aws4-hmac-sha256".split())
#: ADOPT: a scheme-less DSN, ``root:pw@tcp(db)/app`` -- the owner's _BARE_USERINFO shape,
#: with a left boundary of ``=``, ``:``, a quote or whitespace; URI schemes that carry an
#: address, not a credential, are excluded (``mailto:alice@x``).
_BARE_DSN = re.compile(r"""(?:^|(?<=[\s="'`]))([A-Za-z0-9._~%+-]{1,64}):([^\s/?#"'`<>@{};]{1,256})@(?=[A-Za-z0-9(\[])""")  # REVERT
_AT = re.compile(r"@(?=[A-Za-z0-9(\[])")             # literal-led: the DSN's '@'
_DSN_TAIL = re.compile(r"""(?:^|[\s="'`])([A-Za-z0-9._~%+-]{1,64}):([^\s/?#"'`<>@{};]{1,256})\Z""")
_ADDRESS_SCHEMES = frozenset("mailto tel sms sip sips xmpp im mid cid news urn geo".split())
_RAW_TAG = re.compile(r"<(/?)(script|style)\b", re.I)  # B1: linear opener/closer scan
SKELETON_SCAN = 1 << 20      # B1: the skeleton reads at most this much of the body
_QCTX = re.compile(r"(?:[?&#]|&amp;|%3[Ff]|%26|%23|(?<=[A-Za-z0-9_.~%/-]);)\Z", re.I)
_YAML_BLOCK = re.compile(r"[|>][-+0-9]{0,3}[ \t]*(?:#.*)?")
_ID_RUN = re.compile(r"[A-Za-z0-9_\-+/=.]{8,}")
_ATTR_QSTART = re.compile(r".*[\"'=<>]", re.S)
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


class _Pass:
    def __init__(self, s: str, grammar: str, budget: Budget, markup: bool | None = None,
                 leaf: bool = False):
        self.s, self.g, self.n, self.b = s, grammar, len(s), budget
        self.markup = grammar in ("html", "xml") if markup is None else markup
        self.spans: list[tuple[int, int, str]] = []
        self.cover_end = 0
        self.binds = 0
        self._tag_cache: dict[int, object] = {}
        self._typed: set = set()
        self._enc_cache: dict[int, object] = {}
        self._raw = None
        self.leaf = leaf
        self.shape_spans = 0
        self._raw_starts: list[int] = []

    # -- values ---------------------------------------------------------------------
    def _quoted_end(self, q: str, j: int) -> int:
        pat = _DQ if q == '"' else _SQ if q == "'" else _BQ
        m = pat.match(self.s, j, min(self.n, j + VALUE_MAX))
        self.b.span((m.end() if m else min(self.n, j + VALUE_MAX)) - j)
        if not m:
            if self.leaf:
                return self.n
            raise Unprovable("unterminated string")
        return m.end() - 1

    def _container_end(self, j: int) -> int:
        s, depth, quote, pos = self.s, 0, None, j
        end = min(self.n, j + VALUE_MAX)
        while True:
            m = _BRACKETS.search(s, pos, end)
            self.b.step()
            if m is None:
                if self.leaf:
                    self.b.span(self.n - j)
                    return self.n
                raise Unprovable("unbalanced container")
            c, pos = m.group(), m.end()
            if c == "\\":
                pos += 1
                continue
            if quote:
                if c == quote:
                    quote = None
                continue
            if c in "\"'":
                quote = c
            elif c in "[{":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    self.b.span(pos - j)
                    return pos

    def _bounded(self, pat, j: int, cap: int):
        m = pat.match(self.s, j)
        if not m:
            return None
        self.b.span(m.end() - j)
        if m.end() - j >= cap and pat.match(self.s, m.end()) and \
                pat.match(self.s, m.end()).end() > m.end():
            raise Unprovable("value longer than the bound")
        return m

    def _value(self, j: int, esc: bool, in_string: str | None):
        s = self.s
        if j >= self.n:
            return None
        c = s[j]
        if in_string == "prose":
            if c in "\"'`":
                return None               # M1: the quote closes the string the prose is in
            m = _PROSE.match(s, j)
            self.b.span(m.end() - j if m else 0)
            return (j, m.end(), PLACEHOLDER) if m and m.end() > j else None
        if in_string is not None:
            if c == in_string:
                return None               # M1: the quote closes the name's own string
            pat = {'"': _DQ, "'": _SQ, "`": _BQ}[in_string]
            m = pat.match(s, j, min(self.n, j + VALUE_MAX))
            self.b.span((m.end() if m else min(self.n, j + VALUE_MAX)) - j)
            if not m:
                if self.leaf:
                    return (j, self.n, PLACEHOLDER) if self.n > j else None
                raise Unprovable("unterminated string")
            return (j, m.end() - 1, PLACEHOLDER) if m.end() - 1 > j else None
        if c == "\\" and s[j + 1:j + 2] in ('"', "'"):
            close = "\\" + s[j + 1]
            k = s.find(close, j + 2, min(self.n, j + 2 + VALUE_MAX))
            self.b.span((k if k != -1 else min(self.n, j + 2 + VALUE_MAX)) - j)
            if k == -1:
                raise Unprovable("unterminated escaped string")
            return j + 2, k, PLACEHOLDER
        if c in "\"'`":
            return j + 1, self._quoted_end(c, j + 1), PLACEHOLDER
        if c in "[{":
            return j, self._container_end(j), f'"{PLACEHOLDER}"'
        if self.g == "text":
            m = self._bounded(_EOL, j, 65536)
            if not m:
                return None
            v = m.group().rstrip()
            block = self._continuation(j, v)
            if block is not None:
                return block
            return (j, j + len(v), PLACEHOLDER) if v else None
        m = self._bounded(_WORD if self.g == "words" else _UNQ, j, UNQUOTED_MAX)
        if not m:
            return None
        v = m.group()
        if v.lower() in _AUTH_SCHEMES and REVERT != "schemeword":       # B4
            k = j + len(v)
            while k < self.n and k - j - len(v) < 16 and s[k] in " \t":
                k += 1
            m2 = (_WORD if self.g == "words" else _UNQ).match(s, k) if k > j + len(v) else None
            if m2:
                self.b.span(m2.end() - j)
                return j, m2.end(), PLACEHOLDER
        if (self.g == "js" or (self.g == "html" and not self._markup_proper(j))) \
                and not _NUMBER.fullmatch(v) and REVERT != "anyunquoted":
            return None                   # decision 4: a script identifier is code (inline too)
        return j, j + len(v), PLACEHOLDER

    def _indented_block(self, lo: int, j: int):
        """A YAML key whose value is the more-indented block on the following lines
        (``tokens:\n  - a\n  - b``): the block is the value; bounded, else unprovable."""
        s = self.s
        ls = s.rfind("\n", 0, lo) + 1
        key_indent = len(s[ls:lo]) - len(s[ls:lo].lstrip(" \t"))
        line_start = s.rfind("\n", 0, j) + 1
        first = s[line_start:j]
        if len(first) - len(first.lstrip(" \t")) <= key_indent:
            return None                        # same or less indent: no value (.env, YAML null)
        start = end = line_start
        limit = min(self.n, start + VALUE_MAX)
        while end < self.n:
            nl = s.find("\n", end, limit + 1)
            line_end = nl if nl != -1 else self.n
            line = s[end:line_end]
            self.b.span(len(line))
            if line.strip() and (len(line) - len(line.lstrip(" \t"))) <= key_indent:
                break
            end = line_end + 1 if nl != -1 else self.n
            if end > limit:
                raise Unprovable("block value longer than the bound")
        end = max(start, end - 1) if end <= self.n and s[end - 1:end] == "\n" else end
        body = s[start:end]
        lead = len(body) - len(body.lstrip(" \t"))
        return (start + lead, end, PLACEHOLDER) if end > start + lead else None

    def _continuation(self, j: int, v: str):
        """M5(d): a YAML block scalar (``|``/``>``) or a ``.properties`` ``\\`` line
        continuation extends the value; bounded, else unprovable."""
        s = self.s
        if _YAML_BLOCK.fullmatch(v):
            line_start = s.rfind("\n", 0, j) + 1
            indent = len(s[line_start:j]) - len(s[line_start:j].lstrip(" "))
            pos = s.find("\n", j)
            if pos == -1:
                return None
            start = end = pos + 1
            limit = min(self.n, start + VALUE_MAX)
            while end < self.n:
                nl = s.find("\n", end, limit + 1)
                line_end = nl if nl != -1 else self.n
                line = s[end:line_end]
                self.b.span(len(line))
                if line.strip() and (len(line) - len(line.lstrip(" "))) <= indent:
                    break
                end = line_end + 1 if nl != -1 else self.n
                if end > limit:
                    raise Unprovable("block scalar longer than the bound")
            return (start, max(start, end - 1), PLACEHOLDER) if end > start else None
        n_bs = len(v) - len(v.rstrip("\\"))
        if n_bs % 2 == 1:                       # a properties continuation
            end = j + len(v)
            while True:
                nl = s.find("\n", end)
                if nl == -1:
                    return j, self.n, PLACEHOLDER
                nxt = s.find("\n", nl + 1)
                line_end = nxt if nxt != -1 else self.n
                self.b.span(line_end - nl)
                if line_end - j > VALUE_MAX:
                    raise Unprovable("continued value longer than the bound")
                line = s[nl + 1:line_end].rstrip("\r")
                end = line_end
                if (len(line) - len(line.rstrip("\\"))) % 2 == 0:
                    return j, end, PLACEHOLDER
        return None

    # -- bindings -------------------------------------------------------------------
    def _bind_after(self, lo: int, hi: int) -> bool:
        s = self.s
        in_string = None
        heuristic = False
        if lo > 0 and s[lo - 1] in "\"'`" and s[hi:hi + 1] != s[lo - 1]:
            in_string = s[lo - 1]              # the name starts a string, not a quoted key
        elif self.g == "js" or (self.g == "html" and not self._markup_proper(lo)):
            k = lo                             # in code: a name after a word is prose
            while k > 0 and lo - k < 16 and s[k - 1] in " \t":
                k -= 1
            if k > 0 and (s[k - 1].isalnum() or s[k - 1] in "_$") and k < lo:
                w = _LAST_WORD.search(s, max(0, k - 16), k)
                escaped_break = w and w.start() > 0 and s[w.start() - 1] == "\\"
                if not (w and (w.group() in _JS_KEYWORDS or escaped_break)):
                    in_string, heuristic = "prose", True
        qctx = _QCTX.search(s, max(0, lo - 5), lo)
        if qctx and qctx.group() == ";" and self.g == "js":
            qctx = None                        # in code, ';' ends a statement
        self.b.step()
        if qctx and qctx.group() == "#" and REVERT != "privatefield" and \
                (self.g == "js" or (self.g == "html" and not self._markup_proper(lo))):
            h = lo - 1                         # B5: a private field (`#x = v`, `this.#x`),
            if h == 0 or s[h - 1] in ".{};,( \t\r\n":     # not a URL fragment (`/cb#x=`)
                qctx = None
        if qctx:                               # M1/M4: URL query context
            pct = qctx.group().startswith("%")
            if s.startswith("=", hi):
                k = hi + 1
            else:
                m = _PCT_OP.match(s, hi) if pct else None
                if not m:
                    return False
                k = m.end()
            m = (_URLV_PCT if pct else _URLV).match(s, k)
            self.b.span(m.end() - k)
            if m.end() - k >= 4096:
                raise Unprovable("value longer than the bound")
            if m.end() > k:
                self.spans.append((k, m.end(), PLACEHOLDER))
                self.binds += 1
                self.cover_end = max(self.cover_end, m.end())
            return True
        m = _OP.match(s, hi)
        if not m:
            return False
        esc = bool(m.group(1)) and m.group(1)[0] == "\\"
        if m.group(1):
            in_string = None                   # the name was a quoted key
        if "\n" in s[m.start(2):m.end()] and s[m.end():m.end() + 1] not in ("\"", "'", "`", "[", "{") \
                and self.g != "data":
            if self.g != "text":
                return False                   # prose: "Example code:\n<next line>"
            v = self._indented_block(lo, m.end())
            if v:
                self.spans.append(v)
                self.binds += 1
                self.cover_end = max(self.cover_end, v[1])
                return True
            return False
        try:
            v = self._value(m.end(), esc, in_string)
        except Unprovable:
            if not heuristic:
                raise
            v = None                           # a parity guess never omits the body
        if v:
            self.spans.append(v)
            self.binds += 1
            self.cover_end = max(self.cover_end, v[1])
            return True
        return False

    def _in_bind_attr(self, lo: int) -> bool:
        """``lo`` lies in the value of a ``name=``-like attribute: quoted (spaces allowed,
        ``\\"`` too) or unquoted."""
        s = self.s
        start = max(0, lo - 128)
        self.b.span(lo - start)
        m = _ATTR_QSTART.match(s, start, lo)           # the last quote, '=', '<' or '>'
        if not m:
            return False
        k = m.end() - 1
        c = s[k]
        if c in "\"'":
            if k > 0 and s[k - 1] == "\\":
                k -= 1
        elif c == "=":
            if not self._markup_proper(lo):
                return False        # in code or text, embedded markup quotes its values
            j = k + 1
            while j < lo and s[j] in " \t\r\n\f":
                j += 1
            if j != lo:
                return False        # an unquoted value is one token that starts at the hit
            k += 1
        else:
            return False
        while k > 0 and s[k - 1] in " \t\r\n\f":
            k -= 1
        if k == 0 or s[k - 1] != "=":
            return c == "=" and self._attr_name_before(k) in _BIND_ATTRS
        k -= 1
        return self._attr_name_before(k) in _BIND_ATTRS

    def _markup_proper(self, p: int) -> bool:
        """``p`` is in an html body outside its ``<script>``/``<style>`` raw text."""
        if self.g != "html":
            return False
        if self._raw is None:
            self._raw = _raw_blocks(self.s, self.b) if REVERT != "rawtext_regex" else []
            if REVERT == "rawtext_regex":
                for m in _RAWTEXT.finditer(self.s):
                    self.b.span(m.end() - m.start())
                    self._raw.append((m.start(1), m.end(1)))
            self._raw_starts = [a for a, _b in self._raw]
        i = bisect.bisect_right(self._raw_starts, p) - 1
        return not (i >= 0 and self._raw[i][0] <= p < self._raw[i][1])

    def _attr_name_before(self, k: int) -> str:
        s = self.s
        while k > 0 and s[k - 1] in " \t\r\n\f":
            k -= 1
        a = k
        while a > 0 and k - a < 16 and s[a - 1] not in " \t\r\n\f<>\"'/=\\":
            a -= 1
        return s[a:k].lower()

    def _lex_tag(self, t: int):
        """A summary of the tag at ``t`` (lexed once, charged per attribute): name, end,
        self-closing, its ``type``, its value/content spans, its name=-like spans."""
        if t in self._tag_cache:
            self.b.step()
            return self._tag_cache[t]
        if len(self._tag_cache) >= CACHE_MAX:
            self._tag_cache.clear()
        s = self.s
        m = _TAGNAME.match(s, t)
        if not m:
            self._tag_cache[t] = None
            return None
        name, pos = m.group(1).lower(), m.end()
        typ, values, binds = "", [], []
        end = min(self.n, t + TAG_MAX)
        result = None
        while pos < end:
            self.b.step()
            if s[pos] == ">":
                result = (name, pos + 1, s[pos - 1] == "/", typ, values, binds)
                break
            if s.startswith("\\>", pos):
                pos += 1
                continue
            if REVERT == "attr_regex":
                a = _ATTR.match(s, pos, end)
                if not a or a.end() == pos:
                    pos += 1
                    continue
                for g in (2, 3, 4, 5, 6):
                    if a.group(g) is not None:
                        an, a0, a1 = a.group(1).lower(), a.start(g), a.end(g)
                        if an == "type":
                            typ = s[a0:a1][:16].lower()
                        elif an in _VALUE_ATTRS:
                            values.append((a0, a1))
                        elif an in _BIND_ATTRS:
                            binds.append((a0, a1))
                        break
                self.b.span(a.end() - pos)
                pos = a.end()
                continue
            a = _ATTR_NAME.match(s, pos, end)
            if not a or a.end() == pos:
                pos += 1
                continue
            self.b.span(a.end() - pos)
            if a.group(2) is None:                     # an attribute with no value
                pos = a.end()
                continue
            k = a.end()
            q = s[k:k + 2] if s.startswith(('\\"', "\\'"), k) else s[k:k + 1]
            if q in ('"', "'", '\\"', "\\'"):
                close = s.find(q, k + len(q), end)     # B1: one charged scan
                self.b.span((close if close != -1 else end) - k)
                if close == -1:
                    break                              # unterminated: the tag never closes
                a0, a1, pos = k + len(q), close, close + len(q)
            else:
                u = _UNQ_ATTR.match(s, k, end)
                self.b.span(u.end() - k)
                a0, a1, pos = k, u.end(), max(u.end(), k + 1)
            an = a.group(1).lower()
            if an == "type":
                typ = s[a0:a1][:16].lower()
            elif an in _VALUE_ATTRS:
                values.append((a0, a1))
            elif an in _BIND_ATTRS:
                binds.append((a0, a1))
        if result is None:
            self.b.span(end - t)
        self._tag_cache[t] = result
        return result

    def _enclosing(self, t0: int):
        """The start of the tag that encloses the ``<`` at ``t0`` (a ``<`` inside an
        attribute value), ``"open"`` (a tag that never closes), ``"exhausted"`` (the tries
        ran out) or None. Walked once per ``<``: tags do not nest, so every hit in the
        same gap shares the answer."""
        if t0 in self._enc_cache:
            self.b.step()
            return self._enc_cache[t0]
        if len(self._enc_cache) >= CACHE_MAX:
            self._enc_cache.clear()
        s, cur, ans = self.s, t0, "exhausted"
        lo = max(0, t0 - TAG_MAX)
        for _ in range(TAG_TRIES):
            t = s.rfind("<", lo, cur)
            self.b.span(cur - (t if t != -1 else lo))
            if t == -1:
                ans = None
                break
            tag = self._lex_tag(t)
            if tag is None:
                if _TAGNAME.match(s, t):
                    ans = "open"
                    break
            elif tag[1] > t0:
                ans = t
                break
            cur = t
        self._enc_cache[t0] = ans
        return ans

    def _tags_around(self, p: int):
        """``([tag], exhausted, open_tag)``: the tag enclosing ``p``, if any."""
        s = self.s
        lo = max(0, p - TAG_MAX)
        t0 = s.rfind("<", lo, p)
        self.b.span(p - (t0 if t0 != -1 else lo))
        if t0 == -1:
            return [], False, False
        tag = self._lex_tag(t0)
        if tag is not None and tag[1] > p:
            return [tag], False, False
        if tag is None and _TAGNAME.match(s, t0):
            return [], False, True
        e = self._enclosing(t0)
        if e == "open":
            return [], False, True
        if e == "exhausted":
            return [], True, False
        if e is not None:
            outer = self._lex_tag(e)
            if outer is not None and outer[1] > p:
                return [outer], False, False
        return [], False, False

    def _bind_in_tag(self, lo: int, hi: int) -> None:
        if not self._in_bind_attr(lo):
            return
        tags, exhausted, open_tag = self._tags_around(lo)
        if not tags:
            if (exhausted or open_tag) and REVERT != "bindnothing":
                raise Unprovable("tag not delimited")     # M5(a)
            return
        name, tend, selfclose, _typ, values, binds = tags[0]
        self.b.step(1 + len(binds) + len(values))
        if not any(a0 <= lo and hi <= a1 for a0, a1 in binds):
            return
        for a0, a1 in values:
            if a1 > a0:
                self.spans.append((a0, a1, PLACEHOLDER))
                self.binds += 1
        if name == "textarea" or (self.g == "xml" and not selfclose):
            close = re.compile(r"</" + re.escape(name), re.I).search(
                self.s, tend, min(self.n, tend + VALUE_MAX))
            self.b.span((close.start() if close else min(self.n, tend + VALUE_MAX)) - tend)
            if close is None:
                raise Unprovable("element without its end tag")
            if close.start() > tend:
                self.spans.append((tend, close.start(), PLACEHOLDER))

    def _type_hit(self, p: int) -> None:
        tags, exhausted, open_tag = self._tags_around(p)
        if not tags:
            if exhausted or open_tag:
                raise Unprovable("tag not delimited")
            return
        _name, _tend, _sc, typ, values, _binds = tags[0]
        self.b.step(1 + len(values))
        if typ not in ("password", "hidden") or (p, typ) in self._typed:
            return
        self._typed.add((p, typ))
        for a0, a1 in values:
            if a1 > a0:
                v = self.s[a0:a1]
                self.b.span(len(v))
                if typ == "password" or looks_like_identifier(_html.unescape(v)):
                    self.spans.append((a0, a1, PLACEHOLDER))
                    self.binds += 1

    def _element(self, lo: int, hi: int) -> bool:
        s = self.s
        k = lo
        while k > 0 and k > lo - 64 and (s[k - 1].isalnum() or s[k - 1] in "_.-:"):
            k -= 1
        if k == 0 or s[k - 1] != "<":
            return False
        qname = s[k:hi]
        gt = s.find(">", hi, min(self.n, hi + TAG_MAX))
        if gt == -1:
            raise Unprovable("unterminated element tag")
        if s[gt - 1] == "/":
            return True
        close = s.find("</" + qname, gt, min(self.n, gt + VALUE_MAX))
        self.b.span((close if close != -1 else min(self.n, gt + VALUE_MAX)) - gt)
        if close == -1:
            raise Unprovable("element without its end tag")
        if close > gt + 1:
            self.spans.append((gt + 1, close, PLACEHOLDER))
            self.binds += 1
        return True

    def _entity_hit(self, p: int) -> None:
        if not self._in_bind_attr(p):
            return
        tags, exhausted, open_tag = self._tags_around(p)
        if not tags:
            if exhausted or open_tag:
                raise Unprovable("tag not delimited")
            return
        _n, _te, _sc, _typ, values, binds = tags[0]
        self.b.step(1 + len(binds) + len(values))
        for a0, a1 in binds:
            if a0 <= p < a1 and is_sensitive_name(_html.unescape(self.s[a0:a1])):
                for v0, v1 in values:
                    if v1 > v0:
                        self.spans.append((v0, v1, PLACEHOLDER))
                return

    # -- unbound shapes (M4) ---------------------------------------------------------
    def _shape_span(self, span) -> None:
        """A credential-shape replacement; their number is capped like hits (memory: a
        crafted body of 8 MiB of ``Bearer`` tokens would otherwise hold 500k spans)."""
        self.spans.append(span)
        self.shape_spans += 1
        if self.shape_spans > MAX_HITS:
            raise Unprovable("too many credential shapes")

    def _shapes(self) -> None:
        s = self.s
        if REVERT == "jwt_regex":
            for m in _JWT.finditer(s):
                self.b.span(m.end() - m.start())
                self._shape_span((m.start(), m.end(), PLACEHOLDER))
        else:
            self._jwts()
        for m in _BEARER.finditer(s):
            self.b.span(m.end() - m.start())
            if m.start() == 0 or not (s[m.start() - 1].isalnum() or s[m.start() - 1] == "_"):
                self._shape_span((m.start(1), m.end(1), PLACEHOLDER))
        for m in _PPK.finditer(s):
            pl = _PPK_PRIV.search(s, m.end(), min(self.n, m.end() + 65536))
            self.b.span((pl.end() if pl else min(self.n, m.end() + 65536)) - m.end())
            if not pl:
                raise Unprovable("PuTTY key without its private lines")
            k, lines = pl.end(), int(pl.group(1))
            for _ in range(lines):
                nl = s.find("\n", k)
                self.b.step()
                k = self.n if nl == -1 else nl + 1
            self._shape_span((pl.end(), k, PLACEHOLDER + "\n"))
        if REVERT == "dsn_regex":
            for m in _BARE_DSN.finditer(s):
                self.b.span(m.end() - m.start())
                if m.group(1).lower() not in _ADDRESS_SCHEMES:
                    self._shape_span((m.start(1), m.end(), USERINFO_PLACEHOLDER))
        else:
            ats = 0
            for a in _AT.finditer(s):                     # B1: one bounded look back per '@'
                at = a.start()
                lo = max(0, at - 322)
                ats += 1
                if ats > MAX_HITS:                        # the hit cap bounds the look backs
                    raise Unprovable("too many '@' candidates")
                self.b.span(at - lo)
                if s.rfind(":", lo, at) == -1:
                    continue
                m = _DSN_TAIL.search(s, lo, at)
                if m and m.group(1).lower() not in _ADDRESS_SCHEMES:
                    self._shape_span((m.start(1), at + 1, USERINFO_PLACEHOLDER))
        for m in _PEM.finditer(s):
            end_marker = "-----END " + m.group(1) + "-----"
            k = s.find(end_marker, m.end(), min(self.n, m.end() + VALUE_MAX))
            self.b.span((k if k != -1 else min(self.n, m.end() + VALUE_MAX)) - m.end())
            if k == -1:
                raise Unprovable("private key block without its end")
            self._shape_span((m.end(), k, PLACEHOLDER))
        for m in _USERINFO_FAST.finditer(s):
            self.b.span(m.end() - m.start())
            self._shape_span((m.end(1), m.end(), USERINFO_PLACEHOLDER))

    def _jwts(self) -> None:
        """B1: every ``eyJ`` run is read once (greedy, no backtracking); a run of at least
        8 characters followed by 2-4 more ``.``-joined base64url segments (the second at
        least 5 long) is a JWT/JWS/JWE."""
        s, n, last = self.s, self.n, -1
        for m in _JWT_HEAD.finditer(s):
            self.b.span(m.end() - m.start())
            if m.start() < last or m.end() - m.start() < 8:
                continue
            e, segs = m.end(), 1
            while e < n and s[e] == "." and segs < 5:
                m2 = _B64SEG.match(s, e + 1)
                self.b.span(m2.end() - e)
                if segs == 1 and m2.end() - (e + 1) < 5:
                    break
                e, segs = m2.end(), segs + 1
            if segs >= 3:
                self._shape_span((m.start(), e, PLACEHOLDER))
                last = e

    # -- the pass ---------------------------------------------------------------------
    def run(self) -> str:
        s = self.s
        low = s.lower() if s.isascii() else s.translate(_ASCII_LOWER)
        self.b.span(self.n)
        self._shapes()
        memo: dict[str, bool] = {}
        seen: set[int] = set()
        markup = self.markup or bool(_MARKUP.search(low))
        for m in _CAND.finditer(low):
            if m.start() < self.cover_end:
                continue
            self.b.hits += 1
            self.b.step()
            if self.b.hits > MAX_HITS:
                raise Unprovable("too many candidate names")
            if m.group() == "&#":
                if markup:
                    self._entity_hit(m.start())
                continue
            w = max(0, m.start() - NAME_MAX)
            dm = _LASTDELIM.match(s, w, m.start())
            lo = dm.end() if dm else w
            pm = _PCT_LEAD.match(s, lo, m.start())
            if pm and lo > 0 and s[lo - 1] == "%":
                lo = pm.end()                          # "%3Ftoken": %3F is a delimiter
            hi = _RIGHT.match(s, m.end()).end()
            self.b.span(hi - lo)
            if lo in seen:
                continue
            seen.add(lo)
            name = s[lo:hi].strip(".-")
            sens = memo.get(name)
            if sens is None:
                cut = (m.start() - lo >= NAME_MAX) or (hi - m.end() >= NAME_MAX)
                sens = memo[name] = bool(name) and (cut or is_sensitive_name(name))
            if not sens:
                continue
            if markup and name.lower() in _BIND_ATTRS and _ATTR_EQ.match(s, hi):
                continue                     # name="..." / key="...": its value is a name
            if self.g == "xml" and self._element(lo, hi):
                continue
            if self._bind_after(lo, hi):
                continue
            if markup:
                self._bind_in_tag(lo, hi)
        if markup:
            for m in _TYPE.finditer(low):
                if m.start() > 0 and (low[m.start() - 1].isalnum() or low[m.start() - 1] == "_"):
                    continue
                self.b.hits += 1
                self.b.step()
                if self.b.hits > MAX_HITS:
                    raise Unprovable("too many candidate names")
                self._type_hit(m.start())
        return self._splice()

    def _splice(self) -> str:
        if not self.spans:
            return self.s
        out, last = [], 0
        for a, b, rep in sorted(self.spans):
            if a < last:
                continue
            if self.s[a:b] in (rep, PLACEHOLDER):
                out.append(self.s[last:b])
            else:
                out.append(self.s[last:a])
                out.append(rep)
            last = b
        out.append(self.s[last:])
        return "".join(out)


def _raw_blocks(s: str, budget) -> list:
    """B1: ``<script>``/``<style>`` raw-text spans by one linear scan of openers and
    closers; an opener whose ``>`` or closer never comes runs to the end of the body."""
    blocks, n, open_name, start = [], len(s), None, 0
    for m in _RAW_TAG.finditer(s):
        budget.step()
        if m.start() < start:
            continue
        if open_name is None:
            if m.group(1):
                continue                                # a stray closer
            gt = s.find(">", m.end())
            budget.span((gt if gt != -1 else n) - m.end())
            if gt == -1:
                blocks.append((m.end(), n))
                return blocks
            open_name, start = m.group(2).lower(), gt + 1
        elif m.group(1) and m.group(2).lower() == open_name:
            blocks.append((start, m.start()))
            open_name = None
    if open_name is not None:
        blocks.append((start, n))
    return blocks


def skeleton(s: str, stats: dict | None = None) -> str:
    """The element-name skeleton of an omitted html/xml body: B1, it reads at most
    `SKELETON_SCAN` characters and emits at most `SKELETON_MAX`; counted."""
    out, size, ops = [], 0, 0
    end = len(s) if REVERT == "skeleton_unbounded" else min(len(s), SKELETON_SCAN)
    for m in re.compile(r"</?([A-Za-z][A-Za-z0-9:_-]{0,31})").finditer(s, 0, end):
        ops += 1
        name = m.group(1)
        if looks_like_identifier(name):
            continue
        piece = ("</" if m.group().startswith("</") else "<") + name + ">"
        size += len(piece)
        if size > SKELETON_MAX:
            break
        out.append(piece)
    if stats is not None:
        stats["skeleton_ops"] = ops + end // SPAN_UNIT
        stats["skeleton_scanned"] = end
    return "".join(out)


def text_pass(s: str, grammar: str, budget: Budget, markup=None) -> str:
    return _Pass(s, grammar, budget, markup).run()


# --- JSON leaves (M2, M3) ------------------------------------------------------------------

_LEAF_HINT = re.compile(_trie(_WORDS[:-1]) + r"|eyj|-----begin|//|<(?:input|meta|textarea|param)",
                        re.I)


def _redact_leaves(doc, budget: Budget, *, all_leaves: bool):
    """Sensitive keys' whole values replaced (the JSON rule); every string leaf (sniffed
    JSON) or every leaf with markup (declared JSON) through the text pass."""
    def leaf(v: str) -> str:
        budget.step()
        low = v.lower()
        if not all_leaves and not _MARKUP.search(low) and "eyj" not in low \
                and "-----begin" not in low and "@" not in v:
            return v
        if not _LEAF_HINT.search(low) and "@" not in v:
            return v
        g = "html" if _MARKUP.search(low) else "data"
        return _Pass(v, g, budget, leaf=True).run()

    stack = []

    def walk(v, depth=0):
        if isinstance(v, _Obj):
            return _Obj((k, PLACEHOLDER if is_sensitive_name(str(k)) else walk(x, depth + 1))
                        for k, x in v)
        if isinstance(v, dict):
            return {k: (PLACEHOLDER if is_sensitive_name(str(k)) else walk(x, depth + 1))
                    for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x, depth + 1) for x in v]
        if isinstance(v, str):
            return leaf(v)
        return v
    del stack
    return walk(doc)


class _Num(str):
    """A JSON number or constant as written (``1e400`` stays ``1e400``)."""


class _Obj(list):
    """A JSON object as its ordered pairs: repeated keys and their order survive (T18)."""


def _depth_ok_pairs(doc) -> bool:
    """`_depth_ok` for a tree whose objects are `_Obj` pair lists."""
    stack = [(doc, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            return False
        kids = (x for _k, x in node) if isinstance(node, _Obj) else node
        stack.extend((c, depth + 1) for c in kids if isinstance(c, list))
    return True


def _dump(v, budget: Budget) -> str:
    budget.step()
    if isinstance(v, _Obj):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _dump(x, budget)
                              for k, x in v) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_dump(x, budget) for x in v) + "]"
    if isinstance(v, _Num):
        return str(v)
    return json.dumps(v, ensure_ascii=False)


def _json_tree(text: str, budget: Budget, *, all_leaves: bool):
    """(redacted text, True) when ``text`` parses as a JSON object/array, else (None, False).
    Objects are kept as ordered pairs, so nothing is dropped, merged or reordered."""
    try:                                   # the text pass reads bytes as latin-1
        u, conv = text.encode("latin-1").decode("utf-8"), True
    except (UnicodeEncodeError, UnicodeDecodeError):
        u, conv = text, False
    try:
        doc = json.loads(u, object_pairs_hook=_Obj, parse_float=_Num, parse_int=_Num,
                         parse_constant=_Num)
    except (ValueError, RecursionError):
        return None, False
    if not isinstance(doc, (dict, list)):
        return None, False
    if not _depth_ok_pairs(doc) or len(text) > MAX_REDACT_BYTES:
        raise Unprovable("JSON deeper than the bound")
    budget.span(len(text))
    new = _redact_leaves(doc, budget, all_leaves=all_leaves)
    if new == doc:
        return text, True
    out = _dump(new, budget)
    return (out.encode("utf-8").decode("latin-1") if conv else out), True


# --- multipart (M5c) -------------------------------------------------------------------------

def _multipart(s: str, ctype: str, budget: Budget) -> str | None:
    m = re.search(r'boundary="?([^";]+)"?', ctype, re.I)
    if not m:
        return None
    delim = "--" + m.group(1)
    parts = s.split(delim)
    if len(parts) < 3:
        return None
    for i, part in enumerate(parts):
        budget.step()
        head, sep, data = part.partition("\r\n\r\n")
        if not sep:
            continue
        name = re.search(r'\bname="([^"]*)"', head)
        trail = "\r\n" if data.endswith("\r\n") else ""
        payload = data[:-2] if trail else data
        if name and "filename=" not in head and is_sensitive_name(name.group(1)):
            parts[i] = head + sep + PLACEHOLDER + trail
            continue
        pct = re.search(r"(?im)^content-type:\s*([^\r\n]+)", head)
        part_ct = pct.group(1).strip() if pct else "text/plain"
        new = _redact_str(payload, part_ct, budget)
        parts[i] = head + sep + new + trail
    return delim.join(parts)


# --- the dispatch ---------------------------------------------------------------------------

#: the form shape without backtracking (possessive; today's _FORM_SHAPE backtracks:
#: 0.2-0.5 s and 189 MiB on an 8 MiB near-form body)
_FORM_SHAPE_S = re.compile(r"[^=&\s]+=[^&\s]*+(?:&[^=&\s]+=[^&\s]*+)*+\s*\Z")
#: _URL_USERINFO re-expressed: output-identical (its replacement re-emits group 1) and
#: about 37x faster (the optional scheme group defeated the literal-prefix search)
_USERINFO_FAST = re.compile(r"""(//)[^/?#\s"'`<>\\]{0,256}@""")
_DECLARED_JSON = re.compile(r"^(?:application/json|[a-z0-9.+-]+/[a-z0-9.+-]*\+json)$")


def _redact_str(s: str, ctype: str, budget: Budget) -> str:
    media = media_of(ctype)
    if not s:
        return s
    if _DECLARED_JSON.match(media):
        out, ok = _json_tree(s, budget, all_leaves=False)
        if ok:
            return out
        if REVERT == "jsonomit":
            if mentions_sensitive_name(s.encode("latin-1", "replace")):
                raise Unprovable("unparseable JSON with a sensitive name")
            return s
        return text_pass(s, "data", budget)                       # B3
    if media.startswith("multipart/form-data"):
        out = _multipart(s, ctype, budget)
        if out is not None:
            return out
        return text_pass(s, "data", budget)
    if media == "application/x-www-form-urlencoded":
        red = redact_query(s)
        if _FORM_SHAPE_S.match(s):
            return red
        return text_pass(red, "data", budget)                     # M5(c)
    head = s[:1024].lstrip()
    if head[:1] in ("{", "["):
        out, ok = _json_tree(s, budget, all_leaves=True) if REVERT != "jsontext" \
            else (None, False)
        if ok:
            return out
        g = grammar_of(s, ctype)
        return text_pass(s, "data" if g in ("text", None) else g, budget)
    if len(s) <= MAX_REDACT_BYTES and _FORM_SHAPE_S.match(s):
        return text_pass(redact_query(s), "data", budget)
    g = grammar_of(s, ctype)
    if g is None:
        return s
    return text_pass(s, g, budget)


_TEXT_DECLARED = ("text/", "application/json", "application/xml", "application/javascript",
                  "application/x-www-form-urlencoded", "multipart/", "message/")


def new_redact_body(body: bytes, ctype: str, stats: dict | None = None) -> bytes:
    if not body:
        return body
    if len(body) > MAX_REDACT_BYTES:
        return OMIT_TOO_LARGE
    budget = Budget()
    media = media_of(ctype)
    try:
        wide = wide_encoding(body, ctype)
        if wide is not None:                                     # M5(b)
            bom = next((b for b, e in _BOMS if body.startswith(b)), b"")
            try:
                s = body[len(bom):].decode(wide)
            except UnicodeDecodeError:
                raise Unprovable("undecodable wide text") from None
            out = _redact_str(s, ctype, budget)
            return body if out == s else bom + out.encode(wide)   # ADOPT: the BOM as received
        if media and not redactable_type(ctype):
            return body                                          # declared binary (R4)
        if b"\x00" in body[:4096]:
            if media.startswith(_TEXT_DECLARED) or "+json" in media or "+xml" in media \
                    or "html" in media:
                raise Unprovable("NUL bytes in a declared text body")
            return body                                          # untyped binary (R4)
        s = body.decode("latin-1")          # M6: one byte per char, lossless; JSON re-decodes
        out = _redact_str(s, ctype, budget)
        return body if out == s else out.encode("latin-1")
    except Unprovable as e:
        kind = media if re.fullmatch(r"[a-z0-9.+/-]{1,64}", media or "") else "other"
        marker = OMIT_UNPROVABLE.format(kind=kind or "untyped", why=str(e))
        if "html" in media or "xml" in media:
            marker += "\n" + skeleton(body.decode("latin-1"), stats)
        return marker.encode("latin-1", "replace")
    except Exception:                                            # total (PA-0096)
        return OMIT_FAILED
    finally:
        if stats is not None:
            stats.update(ops=budget.ops, hits=budget.hits)


def redact_page_text(text: str) -> str:
    """M7: stored page text (one line from get_text): the one-token grammar."""
    try:
        return text_pass(text, "words", Budget())
    except Unprovable:
        return ""


def redact_record_text(text: str) -> str:
    """M8: auditor html_context: the html pass, then identifier-like runs blanked."""
    try:
        out = text_pass(text, "html", Budget(), markup=True)
    except Unprovable:
        return "__REDACTED__"
    return _ID_RUN.sub(lambda m: PLACEHOLDER if m.group() != PLACEHOLDER
                       and looks_like_identifier(m.group()) else m.group(), out)
