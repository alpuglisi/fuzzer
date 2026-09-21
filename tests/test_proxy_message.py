"""Phase 6 T6.1/T6.2: dual-path message model, parsers, scope, match-and-replace."""

import pytest

from fuzzlab.proxy import parser
from fuzzlab.proxy.matchreplace import MatchReplaceEngine, MatchReplaceRule
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.scope import Scope, ScopeRule

REQ = (b"POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
       b"Content-Type: application/x-www-form-urlencoded\r\n"
       b"Content-Length: 9\r\n\r\nuser=abcd")


# --- byte-exactness (NFR-PROXY-byte-exact) -----------------------------------
def test_roundtrip_is_byte_exact():
    assert RawMessage.from_bytes(REQ).raw == REQ


def test_head_body_split_reconstructs_exactly():
    m = RawMessage.from_bytes(REQ)
    assert m.head + m.separator + m.body == REQ
    assert m.separator == b"\r\n\r\n"
    assert m.body == b"user=abcd"


def test_lf_only_head_is_preserved():
    raw = b"GET / HTTP/1.1\nHost: x\n\nbody"          # malformed: bare LF
    m = RawMessage.from_bytes(raw)
    assert m.raw == raw and m.separator == b"\n\n"
    assert m.start_line == b"GET / HTTP/1.1"


# --- duplicate-preserving header views ---------------------------------------
def test_headers_preserve_order_and_duplicates():
    m = RawMessage.from_bytes(REQ).with_appended_header("X-Tag", "a") \
                                  .with_appended_header("X-Tag", "b")
    assert m.get_all("X-Tag") == [b"a", b"b"]
    names = [n.lower() for n, _ in m.headers()]
    assert names == [b"host", b"content-type", b"content-length", b"x-tag", b"x-tag"]


def test_header_lookup_is_case_insensitive():
    m = RawMessage.from_bytes(REQ)
    assert m.get("content-length") == b"9"
    assert m.get("CONTENT-LENGTH") == b"9"


# --- the exit criterion, in miniature ----------------------------------------
def test_duplicate_content_length_raw_exact_but_parsed_rejects():
    """Hand-edit a duplicate, conflicting Content-Length: the raw path forwards it
    byte-for-byte; the parsed (h11) path rejects the ambiguous framing."""
    edited = RawMessage.from_bytes(REQ).with_appended_header("Content-Length", "44")
    # raw path: both headers present, every other byte identical
    assert edited.get_all("Content-Length") == [b"9", b"44"]
    assert edited.has_duplicate("Content-Length")
    assert b"Content-Length: 9\r\nContent-Length: 44\r\n\r\n" in edited.raw
    assert edited.raw.startswith(b"POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080")
    # parsed path: valid before the edit, rejected after
    assert parser.is_valid_request(REQ) is True
    assert parser.is_valid_request(edited.raw) is False
    with pytest.raises(parser.ParseError):
        parser.parse_request(edited.raw)


def test_append_only_touches_the_new_line():
    edited = RawMessage.from_bytes(REQ).with_appended_header("X-A", "1")
    # everything up to the blank line is the original head plus exactly one new line
    assert edited.raw == REQ.replace(b"\r\n\r\n", b"\r\nX-A: 1\r\n\r\n")


# --- byte-surgery edits ------------------------------------------------------
def test_with_header_replaces_all_duplicates():
    m = RawMessage.from_bytes(REQ).with_appended_header("Content-Length", "44")
    fixed = m.with_header("Content-Length", "9")
    assert fixed.get_all("Content-Length") == [b"9"]


def test_without_header_removes_it():
    m = RawMessage.from_bytes(REQ).without_header("Content-Type")
    assert m.get("Content-Type") is None
    assert m.get("Host") == b"127.0.0.1:8080"


def test_with_request_line_and_method_target():
    m = RawMessage.from_bytes(REQ)
    assert m.method == b"POST" and m.target == b"/login"
    m2 = m.with_request_line(b"GET /admin HTTP/1.1")
    assert m2.method == b"GET" and m2.target == b"/admin"
    assert m2.body == b"user=abcd"                     # body untouched


def test_with_body_does_not_fix_content_length():
    m = RawMessage.from_bytes(REQ).with_body(b"x")
    assert m.body == b"x"
    assert m.get("Content-Length") == b"9"             # deliberately left stale


# --- parsed path happy cases -------------------------------------------------
def test_parse_request_happy():
    pr = parser.parse_request(REQ)
    assert pr.method == b"POST" and pr.target == b"/login"
    assert pr.header("content-length") == b"9"
    assert pr.body == b"user=abcd"


def test_parse_response_happy():
    raw = (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
           b"Content-Type: text/plain\r\n\r\nhello")
    rs = parser.parse_response(raw, request_method=b"GET")
    assert rs.status_code == 200 and rs.body == b"hello"


# --- scope engine (default-deny) ---------------------------------------------
def test_scope_default_deny():
    assert Scope().in_scope("127.0.0.1:8080") is False


def test_scope_include_exclude_and_portless():
    s = Scope().include("127.0.0.1")                    # port-less → any port
    assert s.in_scope("127.0.0.1:8080") is True
    assert s.in_scope("127.0.0.1:9999") is True
    assert s.in_scope("10.0.0.1:8080") is False


def test_scope_exclude_overrides_include():
    s = Scope().include("*").exclude("secret.local")
    assert s.in_scope("lab.local") is True
    assert s.in_scope("secret.local") is False


def test_scope_subdomain_suffix_and_path():
    s = Scope([ScopeRule(host=".lab.local", path_regex=r"^/api/")])
    assert s.in_scope("a.lab.local", "/api/x") is True
    assert s.in_scope("lab.local", "/api/x") is True
    assert s.in_scope("a.lab.local", "/web") is False   # path out of scope
    assert s.in_scope("evil.com", "/api/x") is False


def test_scope_for_host_helper():
    s = Scope.for_host("127.0.0.1:8080")
    assert s.in_scope("127.0.0.1:8080") is True
    assert s.in_scope("example.com") is False


# --- match-and-replace -------------------------------------------------------
def test_match_replace_request_line_and_header_and_body():
    eng = MatchReplaceEngine([
        MatchReplaceRule("request_line", b"/login", b"/admin"),
        MatchReplaceRule("header", b"127.0.0.1:8080", b"attacker.example",
                         header_name="Host"),
        MatchReplaceRule("body", b"abcd", b"ZZZZ"),
    ])
    out = eng.apply(RawMessage.from_bytes(REQ))
    assert out.target == b"/admin"
    assert out.get("Host") == b"attacker.example"
    assert out.body == b"user=ZZZZ"
    # untouched headers preserved
    assert out.get("Content-Type") == b"application/x-www-form-urlencoded"


def test_match_replace_regex_and_disabled():
    eng = MatchReplaceEngine([
        MatchReplaceRule("header", rb"\d+", b"0", header_name="Content-Length",
                         is_regex=True),
        MatchReplaceRule("body", b"user", b"nope", enabled=False),
    ])
    out = eng.apply(RawMessage.from_bytes(REQ))
    assert out.get("Content-Length") == b"0"
    assert out.body == b"user=abcd"                     # disabled rule skipped


def test_match_replace_can_inject_malformed_duplicate():
    """A match-replace rule can add a conflicting header the parsed path rejects."""
    m = RawMessage.from_bytes(REQ).with_appended_header("Transfer-Encoding", "chunked")
    assert parser.is_valid_request(m.raw) is False      # CL + TE smuggling primitive
    assert m.get("Transfer-Encoding") == b"chunked"
