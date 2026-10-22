"""Every sender places a query value through one owner (FR-FUZZ-64, BUG-0531, PA-0531;
SP-42, FR-CORE-501).

Audit defect 14: each sender placed a query payload its own way. The anonymous senders
appended a second pair; the authenticated seam rebuilt the query through a ``dict``
(a duplicate sibling lost, ``%20`` turned into ``+``, empty parts dropped, ``%E9`` turned
into ``%EF%BF%BD``); the M6 browser appended. Now:

- a **standalone** URL (no entries) gets the payload in the first part of its own query
  named the parameter, in place; every other part keeps its text
  (`core.urls.place_query_param`);
- **bound** entries (a link set, a form) replace every occurrence of the name -- the
  oracle binder's rule (`core.urls.bind_query`); per-occurrence binding is AU-REQID8's
  stated residual (BUG-0530), pinned below.

Every sender sends to a loopback echo server started here (`require_loopback`,
PA-0130), which records the exact request target it received. How a wire is judged
(measured, `test_platform_clients_rewrite_only_escapes_they_disagree_on`):
- every HTTP sender goes through requests, so it is compared **byte for byte** with what
  requests itself prepares from the contract's query (`_prepared`);
- real Chromium is compared with the contract under `canonical_pairs`: bytes, with only
  the escapes the two clients were measured to treat differently decoded.

Known instances this item does not fix are pinned with a strict xfail naming their owner
(PA-0054(3), PA-0115(3)); the AST guard at the end keeps every other query builder out.
"""

from __future__ import annotations

import ast
import json
import re
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, quote_plus, unquote_to_bytes, urlencode, urlsplit, \
    urlunsplit

import pytest

from fuzzlab.core.net import require_loopback

MARK = "zqmark"
#: A payload carrying every character a placement can get wrong.
HARD = "'\"<>&=#+% é/~"


def _pin(owner: str, what: str):
    """A known instance not fixed here, pinned until its owner fixes it (PA-0054(3))."""
    return pytest.mark.xfail(strict=True, reason=f"{what}: owned by {owner} (BUG-0531's "
                             "sweep, PA-0531)")


# --- the equivalence the measured clients preserve -------------------------------------
#: The bytes whose escape the two measured clients were seen to disagree on (or to move):
#: the unreserved set, ``' " < > [ \\ ] ^`` and backtick, ``{ | }``, and any byte >= 0x80.
#: An escape of any other byte (``& = + ; / ? # % ,`` ...) is kept, hex upper-cased.
_MOVABLE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
                     b"'\"<>[\\]^`{|}")


def _canonical(text: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(text):
        m = re.match(r"%([0-9A-Fa-f]{2})", text[i:])
        if m:
            raw = unquote_to_bytes(m.group(0))
            out += raw if raw[0] in _MOVABLE or raw[0] >= 0x80 \
                else ("%" + m.group(1).upper()).encode()
            i += 3
            continue
        out += text[i].encode("utf-8")
        i += 1
    return bytes(out)


def canonical_pairs(raw_query: str) -> list[tuple[bytes, bool, bytes]]:
    """A raw query as the measured clients and a server agree on it: each ``&``-part in
    order (empty parts kept), its name, whether it has ``=``, and its value, as bytes,
    with only the `_MOVABLE` escapes decoded."""
    out = []
    for part in raw_query.split("&"):
        name, eq, value = part.partition("=")
        out.append((_canonical(name), bool(eq), _canonical(value)))
    return out


def test_the_equivalence_still_tells_apart_what_a_server_reads_apart():
    """PA-0034(2): every rewriting a measured client makes compares equal; a duplicate, a
    lost sibling, ``flag`` vs ``flag=``, ``+`` vs ``%2B``, ``&`` vs ``%26``, ``;`` vs
    ``%3B``, an invalid byte vs its replacement character, and order all differ."""
    same = [("a=%7E", "a=~"), ("q='", "q=%27"), ("k=a|b", "k=a%7Cb"), ("s2=%2b", "s2=%2B"),
            ("v=é", "v=%C3%A9"), ("g=%e9", "g=%E9"), ("m=a\\b", "m=a%5Cb"),
            ("u=a[b]", "u=a%5Bb%5D"), ("y=<x>", "y=%3Cx%3E"), ("o=a`b", "o=a%60b")]
    differ = [("id=1&id=x", "id=x"), ("tag=a&tag=b", "tag=b"), ("flag", "flag="),
              ("s=a+b", "s=a%2Bb"), ("x=a%26b", "x=a&b"), ("a=1&b=2", "b=2&a=1"),
              ("o=a%3Db", "o=a=b"), ("g=%E9", "g=%EF%BF%BD"), ("i=a;b", "i=a%3Bb"),
              ("k=a/b", "k=a%2Fb"), ("t=x%20y", "t=x+y"), ("a=1&&b=2", "a=1&b=2")]
    assert all(canonical_pairs(a) == canonical_pairs(b) for a, b in same)
    assert all(canonical_pairs(a) != canonical_pairs(b) for a, b in differ)


class _Echo:
    """A loopback HTTP server that records each request's raw target (path and query
    exactly as received) to ``/p`` (and below it), and whether the request carried
    `MARK` anywhere (target, body or a header value: ``carried``), and answers a small
    HTML page. With ``redirect`` set, a request carrying `MARK` is answered
    ``302 Location: <redirect>``; with ``redirect_limit`` set too, only that many are
    (the rest get the page, as an app's own resource answers its GET)."""

    def __init__(self):
        require_loopback("127.0.0.1")                      # PA-0130
        self.targets: list[str] = []
        self.carried: list[bool] = []
        self.redirect: str | None = None
        self.redirect_limit: int | None = None
        self.redirected = 0
        echo = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                carries = MARK in self.path or MARK.encode() in body or any(
                    MARK in value for value in self.headers.values())
                path = urlsplit(self.path).path
                if path == "/p" or path.startswith("/p/"):
                    echo.targets.append(self.path)
                    echo.carried.append(carries)
                if echo.redirect is not None and carries and (
                        echo.redirect_limit is None
                        or echo.redirected < echo.redirect_limit):
                    echo.redirected += 1
                    self.send_response(302)
                    self.send_header("Location", echo.redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"<html><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _answer                     # noqa: N815 - http.server API

            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def query(self) -> str:
        """The raw query of the one request to ``/p`` this test made."""
        assert len(self.targets) == 1, self.targets
        return urlsplit(self.targets[0]).query

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def echo():
    server = _Echo()
    try:
        yield server
    finally:
        server.close()


def _prepared(query: str) -> str:
    """The query requests itself puts on the wire for ``query`` given verbatim."""
    import requests
    return urlsplit(requests.Request("GET", "http://127.0.0.1:9/p?" + query)
                    .prepare().url).query


# --- the platform fact the equivalence rests on (MULTI_AGENT_ORCHESTRATION §7) --------
#: A raw query given verbatim -> what each client put on the wire. Measured 2026-10-19:
#: requests 2.34.2, Chromium 141.0.7390.37 (Playwright build 1194).
_CLIENT_FACTS = {
    "a=%7E&b=%7e": {"requests": "a=~&b=~", "chromium": "a=%7E&b=%7e"},
    "flag&x=1": {"requests": "flag&x=1", "chromium": "flag&x=1"},
    "s=x+y&t=x%20y": {"requests": "s=x+y&t=x%20y", "chromium": "s=x+y&t=x%20y"},
    "q='&r=%27": {"requests": "q='&r=%27", "chromium": "q=%27&r=%27"},
    "k=a|b&l={}": {"requests": "k=a%7Cb&l=%7B%7D", "chromium": "k=a|b&l={}"},
    "w=a%2Bb&x=a%26b&o=a%3Db&p=a=b": {"requests": "w=a%2Bb&x=a%26b&o=a%3Db&p=a=b",
                                      "chromium": "w=a%2Bb&x=a%26b&o=a%3Db&p=a=b"},
    "q2=%25&r2=%23x&s2=%2b": {"requests": "q2=%25&r2=%23x&s2=%2B",
                              "chromium": "q2=%25&r2=%23x&s2=%2b"},
    "&&a=1&": {"requests": "&&a=1&", "chromium": "&&a=1&"},
    'a=<b>&c="d"': {"requests": "a=%3Cb%3E&c=%22d%22", "chromium": "a=%3Cb%3E&c=%22d%22"},
    "e=é&f=%C3%A9": {"requests": "e=%C3%A9&f=%C3%A9", "chromium": "e=%C3%A9&f=%C3%A9"},
    "g=%E9&h=%e9": {"requests": "g=%E9&h=%E9", "chromium": "g=%E9&h=%e9"},
    "i=a;b&j=a%3Bb": {"requests": "i=a;b&j=a%3Bb", "chromium": "i=a;b&j=a%3Bb"},
    "k=a/b&l=a%2Fb": {"requests": "k=a/b&l=a%2Fb", "chromium": "k=a/b&l=a%2Fb"},
    "m=a\\b&n=a^b&o=a`b": {"requests": "m=a%5Cb&n=a%5Eb&o=a%60b",
                           "chromium": "m=a\\b&n=a^b&o=a`b"},
    "p=a%3Fb&q=a?b": {"requests": "p=a%3Fb&q=a?b", "chromium": "p=a%3Fb&q=a?b"},
    "r=a%40b&s=a%2Cb&t=a%21b": {"requests": "r=a%40b&s=a%2Cb&t=a%21b",
                                "chromium": "r=a%40b&s=a%2Cb&t=a%21b"},
    "u=a%5Bb%5D&v=a[b]": {"requests": "u=a%5Bb%5D&v=a%5Bb%5D", "chromium": "u=a%5Bb%5D&v=a[b]"},
    "w=%7C&x=%22&y=%3C": {"requests": "w=%7C&x=%22&y=%3C", "chromium": "w=%7C&x=%22&y=%3C"},
}


def test_platform_clients_rewrite_only_escapes_they_disagree_on(echo, monkeypatch):
    """requests and real Chromium (FUZZLAB_REQUIRE_BROWSER=1: fails, never skips) send a
    verbatim query with their own escaping rewrites only: never a pair boundary, an
    ``=``, an empty part, or the escape of a byte outside `_MOVABLE`. A client upgrade
    that changes this fails here first."""
    import requests

    from tests._browser import launch_browser_or_skip
    from tests.test_navigation_aborts import _chromium_or_skip
    got: dict[str, dict[str, str]] = {}
    for raw in _CLIENT_FACTS:
        echo.targets.clear()
        requests.get(f"{echo.base}/p?{raw}", timeout=5, allow_redirects=False)
        got[raw] = {"requests": echo.query()}
    _chromium_or_skip(monkeypatch)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = launch_browser_or_skip(pw)
        try:
            page = browser.new_page()
            for raw in _CLIENT_FACTS:
                echo.targets.clear()
                page.goto(f"{echo.base}/p?{raw}")
                got[raw]["chromium"] = echo.query()
        finally:
            browser.close()
    assert got == _CLIENT_FACTS
    for raw, sent in got.items():
        assert canonical_pairs(sent["requests"]) == canonical_pairs(sent["chromium"]) \
            == canonical_pairs(raw)
        assert sent["requests"] == _prepared(raw)          # what `_prepared` models


# --- the owner (core.urls; SP-42, FR-CORE-501) ------------------------------------------
@pytest.mark.parametrize("url,name,want", [
    ("http://h/p?id=1&tag=a&tag=b", "id", f"http://h/p?id={MARK}&tag=a&tag=b"),
    ("http://h/p?tag=a&id=1&tag=b", "tag", f"http://h/p?tag={MARK}&id=1&tag=b"),
    ("http://h/p?a=%7E&flag&id=1&b=x+y&t=x%20y", "id",
     f"http://h/p?a=%7E&flag&id={MARK}&b=x+y&t=x%20y"),
    ("http://h/p?a=1&&id=1&", "id", f"http://h/p?a=1&&id={MARK}&"),
    ("http://h/p?id=1&e=%E9", "id", f"http://h/p?id={MARK}&e=%E9"),
    ("http://h/p?a%5B%5D=1&a%5B%5D=2", "a[]", f"http://h/p?a%5B%5D={MARK}&a%5B%5D=2"),
    ("http://h/p?a+b=1", "a b", f"http://h/p?a+b={MARK}"),
    ("http://h/p?i=a;b&id=1", "id", f"http://h/p?i=a;b&id={MARK}"),
    ("http://h/p;m=1?id=1", "id", f"http://h/p;m=1?id={MARK}"),
    ("http://h/p", "id", f"http://h/p?id={MARK}"),
    ("http://h/p?", "id", f"http://h/p?id={MARK}"),           # an empty query: no parts
    ("http://h/p#", "id", f"http://h/p?id={MARK}"),           # an empty `#` is dropped
    ("http://h/p?x=1#frag", "id", f"http://h/p?x=1&id={MARK}#frag"),
    ("http://h/p?id=", "id", f"http://h/p?id={MARK}"),
    ("http://h/p?id", "id", f"http://h/p?id={MARK}"),
])
def test_the_owner_places_the_first_occurrence_and_keeps_raw_text(url, name, want):
    """The standalone rule: every untouched part keeps its text exactly (a missing ``=``,
    an empty part, ``%20`` vs ``+``, an invalid escape, ``;`` as data, `urlsplit`'s path
    parameters); an absent name is appended once."""
    from fuzzlab.core.urls import place_query_param
    assert place_query_param(url, name, MARK) == want


def test_the_owner_encodes_a_payload_as_quote_plus():
    from fuzzlab.core.urls import place_query_param
    assert place_query_param("http://h/p?a=1", "id", HARD) == \
        "http://h/p?a=1&id=" + quote_plus(HARD, safe="")


def test_name_matching_never_merges_an_invalid_escape_with_its_replacement():
    """A part's name is decoded with ``surrogateescape`` for matching: ``n%E9`` is not
    ``n\\ufffd`` (``errors="replace"`` would make it so and place into the wrong part)."""
    from fuzzlab.core.urls import place_query_param
    url = "http://h/p?n%E9=1&n%EF%BF%BD=2"
    assert place_query_param(url, "n�", MARK) == f"http://h/p?n%E9=1&n%EF%BF%BD={MARK}"
    assert place_query_param(url, "né", MARK) == url + f"&n%C3%A9={MARK}"


def test_bind_query_follows_the_binders_rule_and_adds_nothing_to_bound_entries():
    """The bound rule (BUG-0530 residual R1): every entry called the name gets the value; on
    entries the binder already bound it changes nothing; an absent name is appended."""
    from fuzzlab.core.urls import bind_query
    entries = [("id", "1"), ("tag", "a"), ("tag", "b")]
    assert bind_query("http://h/p", entries, "tag", MARK) == \
        f"http://h/p?id=1&tag={MARK}&tag={MARK}"
    bound = [("id", "1"), ("tag", MARK)]
    assert bind_query("http://h/p", bound, "tag", MARK) == f"http://h/p?id=1&tag={MARK}"
    assert bind_query("http://h/p?x=9", [("id", "1")], "q", MARK) == \
        f"http://h/p?id=1&q={MARK}"


# --- one function per sender: send ``value`` at ``param`` of ``url`` (a GET query point) -
def _anonymous(url, param, value=MARK):
    from fuzzlab.tools.probesender import RequestsProbeSender
    RequestsProbeSender(timeout=5).send(url, param, value)


def _seam_sender(identity=None):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.probesender import SeamProbeSender
    if identity is None:
        return SeamProbeSender(HttpClient(RequestBudget(10), ["127.0.0.1"], timeout=5))
    client = HttpClient(RequestBudget(10), ["127.0.0.1"], session=_PassThroughSession(),
                        timeout=5)
    return SeamProbeSender(client, identity=identity)


def _seam(url, param, value=MARK):
    _seam_sender().send(url, param, value)


class _PassThroughSession:
    """A session addon that applies nothing: the identity-bearing path of the seam,
    whose URL is built by the same `_send_on` (only `prepare`/`observe` are called)."""

    def prepare(self, request, identity):
        return None

    def observe(self, request, response, identity):
        return None


def _seam_with_identity(url, param, value=MARK):
    _seam_sender("lab-user").send(url, param, value)


def _greybox(url, param, value=MARK):
    from fuzzlab.greybox.run import RequestsCorrelatingSender
    RequestsCorrelatingSender(timeout=5, id_factory=lambda: "c").send_correlated(
        url, param, value)


def _blind_requests(url, param, value=MARK):
    import requests

    from fuzzlab.tools.blind_sqli_fuzzer import RequestsSender
    RequestsSender(requests.Session()).get(url, param, value, 5)


def _blind_seam(url, param, value=MARK):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.blind_sqli_fuzzer import SeamSender
    SeamSender(HttpClient(RequestBudget(10), ["127.0.0.1"], timeout=5), "anonymous").get(
        url, param, value, 5)


SENDERS = {"probe-anonymous": _anonymous, "probe-seam": _seam,
           "probe-seam-identity": _seam_with_identity, "greybox": _greybox,
           "blind-sqli-anonymous": _blind_requests, "blind-sqli-seam": _blind_seam}

#: (case id, query before, parameter, the query the contract requires). A standalone point
#: addresses the first occurrence. On 8100959 the anonymous family appended in every case
#: and the seam family failed all but ``blank`` (BUG-0531).
CASES = [
    ("audit", "id=1&tag=a&tag=b", "id", f"id={MARK}&tag=a&tag=b"),
    ("dup-sibling", "tag=a&id=1&tag=b", "tag", f"tag={MARK}&id=1&tag=b"),
    ("raw-text", "a=%7E&flag&id=1&b=x+y", "id", f"a=%7E&flag&id={MARK}&b=x+y"),
    ("blank", "id=&x=1", "id", f"id={MARK}&x=1"),
    ("encoded-name", "a%5B%5D=1&a%5B%5D=2", "a[]", f"a%5B%5D={MARK}&a%5B%5D=2"),
    ("pct20-sibling", "id=1&t=x%20y", "id", f"id={MARK}&t=x%20y"),
    ("empty-parts", "a=1&&id=1&", "id", f"a=1&&id={MARK}&"),
    ("pctE9-sibling", "id=1&e=%E9", "id", f"id={MARK}&e=%E9"),
]


@pytest.mark.parametrize("sender", sorted(SENDERS))
@pytest.mark.parametrize("before,param,want", [pytest.param(*c[1:], id=c[0])
                                               for c in CASES])
def test_every_sender_replaces_the_addressed_occurrence_in_place(echo, sender, before,
                                                                 param, want):
    """Byte for byte against requests' own preparation of the contract (F1)."""
    SENDERS[sender](f"{echo.base}/p?{before}", param)
    assert echo.query() == _prepared(want)


def test_control_a_query_less_url_gets_the_pair(echo):
    """The echo server sees each sender's send, and a URL without a query gets
    ``param=MARK`` from every sender (today's bytes)."""
    for name in sorted(SENDERS):
        echo.targets.clear()
        SENDERS[name](f"{echo.base}/p", "id")
        assert echo.query() == f"id={MARK}", name


@pytest.mark.parametrize("sender", sorted(SENDERS))
def test_a_hard_payload_on_a_query_less_url_is_quote_plus_encoded(echo, sender):
    """Today's bytes for a query-less URL (every ground-truth point): the payload is
    ``quote_plus(value, safe="")``, exactly."""
    SENDERS[sender](f"{echo.base}/p", "id", HARD)
    assert echo.query() == "id=" + quote_plus(HARD, safe="")


def test_the_cases_catch_the_decode_all_reencode_fix(echo):
    """PA-0034(2): a plausible wrong fix -- parse the query (decoding, dropping empty
    parts), replace the first occurrence, re-encode -- fails the cases that guard raw
    text (``%20``, ``flag``), empty parts and an invalid escape."""
    import requests

    def wrong_fix(url, param, value=MARK):
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        i = next(k for k, (n, _v) in enumerate(pairs) if n == param)
        pairs[i] = (param, value)
        requests.get(urlunsplit(parts._replace(query=urlencode(pairs))), timeout=5)
    failed = set()
    for case_id, before, param, want in CASES:
        echo.targets.clear()
        wrong_fix(f"{echo.base}/p?{before}", param)
        if echo.query() != _prepared(want):
            failed.add(case_id)
    assert {"raw-text", "pct20-sibling", "empty-parts", "pctE9-sibling"} <= failed


def test_the_anonymous_and_authenticated_senders_send_the_same_query(echo):
    """The defect's own statement: the result depended on the sender, not the target.
    Both go through requests, so the bytes are equal (F1)."""
    got = {}
    for name in ("probe-anonymous", "probe-seam"):
        echo.targets.clear()
        SENDERS[name](f"{echo.base}/p?id=1&tag=a&tag=b", "id")
        got[name] = echo.query()
    assert got["probe-anonymous"] == got["probe-seam"]


# --- the bound path: a link set's siblings, bound by the oracle (`_FormBoundSender`) -----
@pytest.mark.parametrize("inner", ["anonymous", "seam"])
def test_a_bound_entry_list_is_sent_by_the_binders_rule(echo, inner):
    """The binder's rule, through `bind_query` in each sender: every ``tag`` gets the
    value (``id=1&tag=M&tag=M``) -- the documented rule (BUG-0530 residual R1)."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.tools.probesender import RequestsProbeSender
    url = f"{echo.base}/p"
    candidate = Candidate(url=url, param="tag",
                          base_entries=(("id", "1"), ("tag", "a"), ("tag", "b")))
    sender = RequestsProbeSender(timeout=5) if inner == "anonymous" else _seam_sender()
    _FormBoundSender(sender, candidate).send(url, "tag", MARK)
    assert echo.query() == _prepared(f"id=1&tag={MARK}&tag={MARK}")


@_pin("a follow-up of AU-REQID8 (BUG-0530 residual R1: per-occurrence points)",
      "the binder replaces every occurrence of a repeated name")
def test_a_bound_duplicate_name_changes_one_occurrence_only(echo):
    """``tag=a&tag=b``'s point ``tag``: `FormEntries.replace` sets every entry called
    ``tag``. Its follow-up makes the occurrence part of a point and changes
    `bind_query`; AU-REQID8's identity records the every-occurrence placement."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.tools.probesender import RequestsProbeSender
    url = f"{echo.base}/p"
    candidate = Candidate(url=url, param="tag",
                          base_entries=(("id", "1"), ("tag", "a"), ("tag", "b")))
    _FormBoundSender(RequestsProbeSender(timeout=5), candidate).send(url, "tag", MARK)
    assert echo.query() == _prepared(f"id=1&tag={MARK}&tag=b")


# --- PRG: the follow-up never carries the payload (FR-FUZZ-49) --------------------------
def _prg_send(sender_name, echo, bound):
    from fuzzlab.tools.probesender import RequestsProbeSender
    sender = RequestsProbeSender(timeout=5) if sender_name == "anonymous" \
        else _seam_sender()
    if bound:
        sender.send(f"{echo.base}/p", "id", MARK, entries=[("id", MARK), ("tag", "a")],
                    prg=True)
    else:
        sender.send(f"{echo.base}/p?id=1&tag=a", "id", MARK, prg=True)


@pytest.mark.parametrize("sender_name", ["anonymous", "seam"])
@pytest.mark.parametrize("bound", [False, True], ids=["standalone", "bound"])
def test_a_fragment_only_location_is_followed_without_the_payload(echo, sender_name,
                                                                   bound):
    """A ``302 Location: #top`` resolves to the URL the follow-up is given: the probe's
    own URL, never the placed one (`PRG_RULES['no-body-no-payload']`). On 8100959 the
    anonymous sender's bound branch handed `_follow` the placed URL."""
    echo.redirect = "#top"
    _prg_send(sender_name, echo, bound)
    assert len(echo.targets) == 2 and MARK in echo.targets[0]
    assert MARK not in echo.targets[1], echo.targets


@pytest.mark.parametrize("sender_name", ["anonymous", "seam"])
def test_an_empty_location_is_not_followed(echo, sender_name):
    """No ``Location``: no follow-up (``PRG_RULES['no-location-no-redirect']``)."""
    echo.redirect = ""
    _prg_send(sender_name, echo, bound=False)
    assert len(echo.targets) == 1


# --- PRG of a path point (FR-FUZZ-69, BUG-0542): resolved against its own template -----
#: A path point's ``Location`` -> the follow-up's raw target, or None when nothing may
#: follow. ``{base}`` is the echo server's origin. The point's own URL is its template
#: (``/p/{id}/view``), as a query point's is its URL without the payload (FR-FUZZ-64).
#: Resolved against it, a target that still holds ``{id}`` names the resource the
#: payload is in, so a browser would fetch the payload again there (``#top`` ->
#: ``/p/zqmark/view``, ``edit`` -> ``/p/zqmark/edit``): never fetched. So is an
#: absolute path or URL the server wrote with the payload in it (``/p/zqmark/edit``,
#: the same browser request as ``edit``). A target that leaves the segment is exactly
#: where a browser goes.
PATH_PRG = [
    ("fragment", "#top", None),
    ("relative", "edit", None),
    ("relative-query", "?tab=2", None),
    ("relative-same-dir", "./", None),
    ("leaves-the-segment", "../list", "/p/list"),
    ("absolute-path", "/p/list", "/p/list"),
    ("absolute-url", "{base}/p/list", "/p/list"),
    ("absolute-path-with-the-payload", "/p/" + MARK + "/edit", None),
    ("absolute-url-with-the-payload", "{base}/p/" + MARK + "/edit", None),
]
#: `Probe.prg` for a refused follow-up that would re-send the payload (nothing is sent).
RESENDS = "skipped: the follow-up would re-send the payload"


def _path_prg_send(echo, sender_name, method, location):
    from fuzzlab.tools.probesender import RequestsProbeSender
    echo.redirect = location.format(base=echo.base)
    sender = RequestsProbeSender(timeout=5) if sender_name == "anonymous" \
        else _seam_sender()
    return sender.send(f"{echo.base}/p/{{id}}/view", "id", MARK, method=method,
                       location="path", prg=True)


@pytest.mark.parametrize("sender_name", ["anonymous", "seam"])
@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("location,want", [pytest.param(*c[1:], id=c[0])
                                           for c in PATH_PRG])
def test_a_path_points_prg_follow_up_never_carries_the_payload(echo, sender_name,
                                                               method, location, want):
    """On c483dc1 both senders resolved a path probe's ``Location`` against the placed
    URL, so ``#top`` and ``edit`` re-requested the payload (``/p/zqmark/edit``), and the
    oracle read that request as the page the probe led to (AU-PRGPATH). Now a target
    that keeps the point's segment is refused before any send (`Probe.prg` says why;
    no follow-up is counted), and any other target is fetched where a browser goes."""
    from fuzzlab.oracle.probe import PRG_OBSERVED
    probe = _path_prg_send(echo, sender_name, method, location)
    assert echo.targets[0] == f"/p/{MARK}/view"
    assert all(MARK not in t for t in echo.targets[1:]), echo.targets
    if want is None:
        assert echo.targets == [f"/p/{MARK}/view"]
        assert probe.prg == RESENDS
        assert probe.followed is None and probe.prg_sent is None
        assert probe.follow_up_sends == 0
    else:
        assert echo.targets[1:] == [want]
        assert probe.prg == PRG_OBSERVED and probe.followed.url == echo.base + want
        assert probe.prg_sent["url"] == echo.base + want and probe.follow_up_sends == 1


#: Every location a probe sender places (`test_sender_conformance.PLACEABLE`, a bound
#: query and the path segment): (own URL under ``/p/``, method, entries). The echo
#: redirects any request that carries `MARK`, wherever it is.
PRG_EVERY_LOCATION = {
    "query": ("/p/x?id=1", "GET", None),
    "query-bound": ("/p/x", "GET", [("id", MARK), ("tag", "a")]),
    "body": ("/p/x", "POST", None),
    "header": ("/p/x", "GET", None),
    "json": ("/p/x", "POST", None),
    "path": ("/p/{id}/view", "POST", None),
}


def test_the_prg_location_table_covers_every_placeable_location():
    from tests.test_sender_conformance import PLACEABLE
    assert {k.split("-")[0] for k in PRG_EVERY_LOCATION} == set(PLACEABLE) | {"path"}


@pytest.mark.parametrize("sender_name", ["anonymous", "seam"])
@pytest.mark.parametrize("redirect", ["#top", "edit"])
@pytest.mark.parametrize("key", sorted(PRG_EVERY_LOCATION))
def test_no_prg_follow_up_carries_the_payload_at_any_location(echo, sender_name,
                                                               redirect, key):
    """PA-0542: the follow-up's resolution base is the probe's own URL at **every**
    location, never the request that carried the payload. The PRG fixtures before
    BUG-0542 were body points, where the two URLs are the same. Every location but the
    path is followed (its own URL is payload-free); the path's ``#top``/``edit`` keep its
    segment and are refused before any send."""
    from fuzzlab.oracle.probe import PRG_OBSERVED
    from fuzzlab.tools.probesender import RequestsProbeSender
    own, method, entries = PRG_EVERY_LOCATION[key]
    location = key.split("-")[0]
    param = "X-Probe" if location == "header" else "id"
    echo.redirect = redirect
    sender = RequestsProbeSender(timeout=5) if sender_name == "anonymous" \
        else _seam_sender()
    probe = sender.send(echo.base + own, param, MARK, method=method, location=location,
                        entries=entries, prg=True)
    assert echo.carried[0] is True and not any(echo.carried[1:]), echo.targets
    if location == "path":
        assert len(echo.targets) == 1 and probe.prg == RESENDS
    else:
        assert len(echo.targets) == 2 and probe.prg == PRG_OBSERVED, echo.targets


@pytest.mark.parametrize("sender_name", ["anonymous", "seam"])
@pytest.mark.parametrize("location", ["/p/" + MARK + "/edit", "{base}/p/" + MARK + "/edit"],
                         ids=["absolute-path", "absolute-url"])
def test_a_location_the_server_wrote_with_the_payload_is_refused(echo, sender_name,
                                                                 location):
    """FR-FUZZ-69 (BUG-0542 review): an absolute ``Location`` the server wrote with the
    payload in it (``/p/zqmark/edit``, as an app redirecting to the resource it was
    posted builds it from the request) is the same browser request as ``edit``: it
    re-sends the payload, and its answer is never the page the POST led to. On 9d0e819
    it was fetched as written and, answered with a page, attached as the PRG
    observation. Here the echo answers only the probe with a redirect, so a sent
    follow-up would be observed: it is refused before any send, as ``edit`` is."""
    echo.redirect_limit = 1
    probe = _path_prg_send(echo, sender_name, "POST", location)
    assert echo.targets == [f"/p/{MARK}/view"], echo.targets
    assert probe.prg == RESENDS
    assert probe.followed is None and probe.prg_sent is None
    assert probe.follow_up_sends == 0


# --- the M6 browser executor: what Chromium itself sends -------------------------------
def _executor(monkeypatch):
    from tests.test_navigation_aborts import _chromium_or_skip
    _chromium_or_skip(monkeypatch)
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    executor.SETTLE_MS = 200
    return executor


@pytest.mark.parametrize("before,param,want", [pytest.param(*c[1:], id=c[0])
                                               for c in CASES])
def test_the_browser_executor_replaces_the_addressed_occurrence_in_place(echo, monkeypatch,
                                                                         before, param,
                                                                         want):
    """Real Chromium (FUZZLAB_REQUIRE_BROWSER=1 fails rather than skips): the observe
    navigation of a standalone query DOM point, recorded at the server; judged under the
    measured equivalence (Chromium is not requests)."""
    from fuzzlab.oracle.browser import ExecRequest
    _executor(monkeypatch).run(ExecRequest(url=f"{echo.base}/p?{before}", param=param,
                                           value=MARK, location="query"), "tok")
    assert canonical_pairs(echo.query()) == canonical_pairs(want)


def test_the_browser_sends_a_hard_payload_on_a_query_less_url_as_quote_plus(echo,
                                                                          monkeypatch):
    """Today's bytes, kept: Chromium keeps the escapes it is given."""
    from fuzzlab.oracle.browser import ExecRequest
    _executor(monkeypatch).run(ExecRequest(url=f"{echo.base}/p", param="id", value=HARD,
                                           location="query"), "tok")
    assert echo.query() == "id=" + quote_plus(HARD, safe="")


def test_the_browser_get_store_step_replaces_the_addressed_occurrence_in_place(
        echo, monkeypatch):
    """The stored-XSS plant through a GET: a `StoreStep` carries no query siblings (its
    `entries` are a JSON store body's leaves), so the store URL's own query takes the
    standalone rule."""
    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    _executor(monkeypatch).run(ExecRequest(url=f"{echo.base}/o", store=StoreStep(
        url=f"{echo.base}/p?id=1&tag=a&tag=b", param="id", value=MARK, method="GET",
        location="query")), "tok")
    assert canonical_pairs(echo.query()) == canonical_pairs(f"id={MARK}&tag=a&tag=b")


def test_a_dom_query_point_is_loaded_with_its_siblings(echo, monkeypatch):
    """A crawled DOM query point with a link set (``op=search&q=1``): the browser loads
    it with its siblings, bound by the binder's rule, as the HTTP senders send it. On
    8100959 every load was ``/p?q=<payload>`` alone (pinned until CC-FUZZ-0106 part 2:
    `ExecRequest.entries`)."""
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import DomXssStrategy
    url = f"{echo.base}/p"
    candidate = Candidate(url=url, param="q", method="GET", location="query",
                          category="xss", base_entries=(("op", "search"), ("q", "1")))
    DomXssStrategy(_executor(monkeypatch)).confirm(candidate, None)
    assert echo.targets
    for target in echo.targets:
        pairs = canonical_pairs(urlsplit(target).query)
        assert [n for n, _eq, _v in pairs] == [b"op", b"q"], target
        assert pairs[0][2] == b"search" and pairs[1][2] != b"1", target


class _Recording:
    """An executor that records each `ExecRequest` and observes nothing (offline)."""

    def __init__(self):
        from fuzzlab.oracle.browser import ExecObservation
        self.requests, self._obs = [], ExecObservation(False)

    def run(self, request, token):
        self.requests.append(request)
        return self._obs


@pytest.mark.parametrize("location,entries,want", [
    ("query", (("op", "search"), ("q", "1")), (("op", "search"), ("q", "1"))),
    ("query", None, None),
    ("query", (), None),                       # no link set: the binder binds nothing
    ("fragment", (("op", "search"),), None),   # a fragment is placed in the route
])
def test_dom_xss_hands_the_executor_a_query_points_link_set(location, entries, want):
    """`DomXssStrategy._observe` passes a query point's ``base_entries`` (the link set the
    oracle binds for the HTTP senders when it is non-empty) as `ExecRequest.entries`, and
    nothing for a fragment point or a point without one."""
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import DomXssStrategy
    executor = _Recording()
    candidate = Candidate(url="http://127.0.0.1:9/p", param="q", method="GET",
                          location=location, category="xss", base_entries=entries)
    DomXssStrategy(executor).confirm(candidate, None)
    assert executor.requests and {r.entries for r in executor.requests} == {want}


def test_the_browser_and_the_bound_http_sender_place_a_duplicate_name_alike(echo,
                                                                            monkeypatch):
    """One bound point with a repeated name (``tag=a&tag=b``, point ``tag``), sent by the
    oracle's binder over `RequestsProbeSender` and loaded by the M6 executor with the same
    entries: both go through `core.urls.bind_query`, so the two wires are equal under the
    measured relation (FR-FUZZ-64; the binder's every-occurrence rule, BUG-0530 R1)."""
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.tools.probesender import RequestsProbeSender
    url = f"{echo.base}/p"
    entries = (("id", "1"), ("tag", "a"), ("tag", "b"))
    candidate = Candidate(url=url, param="tag", base_entries=entries)
    _FormBoundSender(RequestsProbeSender(timeout=5), candidate).send(url, "tag", MARK)
    http = echo.query()
    echo.targets.clear()
    _executor(monkeypatch).run(ExecRequest(url=url, param="tag", value=MARK,
                                           location="query", entries=entries), "tok")
    assert canonical_pairs(echo.query()) == canonical_pairs(http) == \
        canonical_pairs(f"id=1&tag={MARK}&tag={MARK}")


# --- known instances in other items' code (PA-0054(3), PA-0115(3)): pinned, offline -----
def test_the_contract_runner_places_a_query_value_in_place():
    """Was pinned for AU-OUTCOME (the runner appended ``&q=``); fixed there through the
    standalone rule (`core.urls.place_query_param`, CC-FUZZ-0105). A new name is still
    appended, encoded as before."""
    from tests.test_disco_contract import contract_doc, runner
    doc = contract_doc()
    doc["endpoints"].append({"id": "ep_q", "method": "GET",
                             "path": "/api/search?op=list&q=1", "auth": "none"})
    r, _session = runner(doc)
    assert urlsplit(r.prepare("ep_q", query={"q": MARK}).url).query == f"op=list&q={MARK}"
    assert urlsplit(r.prepare("ep_q", query={"q": "a b", "n": "&"}).url).query == \
        "op=list&q=a+b&n=%26"


@pytest.mark.parametrize("route_url,pairs,want", [
    # hash mode: the route's own query; a name already there is replaced in place
    ("http://h/#/s?q=1&p=2", [("q", "x y")], "http://h/#/s?q=x%20y&p=2"),
    ("http://h/#/s", [("q", "fuzzlab"), ("p", "fzqaa")], "http://h/#/s?q=fuzzlab&p=fzqaa"),
    ("http://h/#!/s?page=2", [("q", "v")], "http://h/#!/s?page=2&q=v"),
    # history mode: the URL's own query; a space is %20 there too (never +)
    ("http://h/s?q=1&p=2", [("q", "v")], "http://h/s?q=v&p=2"),
    ("http://h/s?q=1", [("q", "x y")], "http://h/s?q=x%20y"),
    ("http://h/app/search", [("q", "fuzzlab")], "http://h/app/search?q=fuzzlab"),
    # a redirect-type name's same-origin path stays `/` in both modes (CC-CRAWL-0053,
    # FR-CRAWL-17: `%2F` would rest on an unmeasured router decoding)
    ("http://h/#/login?redirectUrl=/x", [("redirectUrl", "/"), ("q", "fuzzlab")],
     "http://h/#/login?redirectUrl=/&q=fuzzlab"),
    ("http://h/login?next=/x", [("next", "/")], "http://h/login?next=/"),
])
def test_the_spa_seed_builder_places_its_route_query_in_place(route_url, pairs, want):
    """Was pinned for CRAWL (the seed builder appended a second, unencoded pair); fixed
    through the one owner (`core.urls.place_route_query_pairs`, CC-CRAWL-0053)."""
    from fuzzlab.tools.spa import query_url
    assert query_url(route_url, pairs) == want


@pytest.mark.parametrize("route_url,names,want", [
    ("http://h/#/login?redirectUrl=/x", ["redirectUrl", "q"],
     "http://h/#/login?redirectUrl=/&q=fuzzlab"),
    ("http://h/login?next=/x&q=1", ["next", "q"], "http://h/login?next=/&q=fuzzlab"),
])
def test_a_seeds_redirect_type_value_stays_a_same_origin_path_in_both_modes(route_url,
                                                                            names, want):
    """`spa.seed_url` gives a redirect-type name ``/`` (never ``%2F``) in hash and in
    history mode, in place of the value the route already had (CC-CRAWL-0053)."""
    from fuzzlab.tools.spa import seed_url
    assert seed_url(route_url, names) == want


@pytest.mark.parametrize("url,pairs,want", [
    ("http://h/#/r?a=1&&b=x+y&a=2", [("a", "<v w>")], "http://h/#/r?a=%3Cv%20w%3E&&b=x+y&a=2"),
    ("http://h/r?a=1&flag", [("b", "/")], "http://h/r?a=1&flag&b=%2F"),
    ("http://h/r#/x", [("a", "1"), ("a", "2")], "http://h/r#/x?a=2"),
])
def test_the_route_query_owner_places_each_pair_by_the_standalone_rule(url, pairs, want):
    """`core.urls.place_route_query_pairs`: each pair in order, the first occurrence in
    place, every other part's text kept; the default encoder is `encode_route_value`."""
    from fuzzlab.core.urls import place_route_query_pairs
    assert place_route_query_pairs(url, pairs) == want


@_pin("a follow-up of AU-REQID8 (BUG-0530 residual R2: a stored link set's raw text)",
      "store_adapter.query_pairs drops empty parts and a missing '='")
def test_a_stored_link_set_round_trips_its_crawled_query():
    """A crawled link query, stored as a link set and sent back by the bound rule, keeps
    ``flag`` (no ``=``), its empty parts and ``%20``."""
    from fuzzlab.core.urls import with_query
    from fuzzlab.tools.store_adapter import query_pairs
    raw = "flag&&a=1&t=x%20y"
    sent = urlsplit(with_query("http://h/p", [(n, v) for n, _r, v in query_pairs(raw)]))
    assert canonical_pairs(sent.query) == canonical_pairs(raw)


def test_a_disco_form_body_keeps_a_repeated_name_in_order(tmp_path):
    """Fixed by AU-REQID8 (FR-AUD-31, BUG-0530): the capture's ordered pairs are kept."""
    from fuzzlab.core.store import Store
    from fuzzlab.tools import store_adapter
    from tests.test_disco_import import _rec, _run_dir
    run_dir = _run_dir(tmp_path, [_rec("POST", "/api/tags", body="tag=a&tag=b&q=1",
                                       ctype=store_adapter.FORM_URLENCODED)])
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        store_adapter.import_disco(run_dir, store, run)
        (entries,) = [json.loads(r[0]) for r in store.conn.execute(
            "SELECT entries FROM form WHERE run_id=? AND enctype=?",
            (run, store_adapter.FORM_URLENCODED))]
    assert [n for n, _v in entries] == ["tag", "tag", "q"]


@_pin("LAB", "the labgen tool wrapper re-encodes untouched pairs")
def test_the_labgen_tool_wrapper_keeps_untouched_pairs_as_written():
    """Only the untouched pairs are pinned (``flag`` stays ``flag``, ``%20`` stays
    ``%20``); marking every occurrence of the marked name may be right for a tool's
    injection marker."""
    from fuzzlab.labgen.oracle_wrapper import _mark_query_param
    out = _mark_query_param("http://h/p?id=1&flag&s=x%20y&tag=a", "tag", "*")
    untouched = [p for p in canonical_pairs(urlsplit(out).query) if p[0] != b"tag"]
    assert untouched == canonical_pairs("id=1&flag&s=x%20y")


# --- the guard: every query builder goes through the one owner (PA-0531(1)) -------------
_PKG = Path(__file__).resolve().parent.parent / "fuzzlab"
_OWNER = "fuzzlab/core/urls.py"
_SENDS = frozenset({"request", "get", "post", "put", "patch", "delete", "head", "options",
                    "fetch", "Request"})
_QUOTERS = frozenset({"urlencode", "quote", "quote_plus"})
_PAIR = re.compile(r"[?&][A-Za-z_][\w\[\]%.-]*=")
_SPLIT_RESULTS = frozenset({"SplitResult", "ParseResult", "SplitResultBytes",
                            "ParseResultBytes"})


def _name(node) -> str:
    return node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")


def _walk_no_keywords(node):
    """``ast.walk`` that skips keyword arguments (``quote(s, safe="&")`` is no query)."""
    todo = [node]
    while todo:
        cur = todo.pop()
        yield cur
        todo.extend(c for c in ast.iter_child_nodes(cur) if not isinstance(c, ast.keyword))


def _str_consts(node):
    return [x.value for x in _walk_no_keywords(node)
            if isinstance(x, ast.Constant) and isinstance(x.value, str)]


def _sep_join(node) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
        node.func.attr == "join" and isinstance(node.func.value, ast.Constant) and \
        node.func.value.value in ("&", "?")


def _material(node, qnames) -> bool:
    """Query material: a quoter call, a ``.query``, a ``"&".join``, or a local name the
    function assigned from one of those (B1)."""
    for x in ast.walk(node):
        if (isinstance(x, ast.Call) and _name(x.func) in _QUOTERS) or _sep_join(x) \
                or (isinstance(x, ast.Attribute) and x.attr == "query") \
                or (isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)
                    and x.id in qnames):
            return True
    return False


def _has_params_key(node) -> bool:
    return (isinstance(node, ast.Dict) and any(
        isinstance(k, ast.Constant) and k.value == "params" for k in node.keys)) or (
        isinstance(node, ast.Call) and _name(node.func) == "dict"
        and any(k.arg == "params" for k in node.keywords))


def _scope_nodes(scope):
    """Every node of ``scope``'s own body, nested functions and classes excluded."""
    todo = list(scope.body) if hasattr(scope, "body") else []
    while todo:
        cur = todo.pop()
        yield cur
        todo.extend(c for c in ast.iter_child_nodes(cur)
                    if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef,
                                          ast.ClassDef)))


class _Scan:
    """The shapes of one scope (a function, or the module's own statements)."""

    def __init__(self, scope):
        self.scope = scope
        nodes = list(_scope_nodes(scope))
        self.qnames = {t.id for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign))
                       and n.value is not None and _material(n.value, frozenset())
                       for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
                       if isinstance(t, ast.Name)}
        self.starred = {k.value.id for n in nodes if isinstance(n, ast.Call)
                        and _name(n.func) in _SENDS for k in n.keywords
                        if k.arg is None and isinstance(k.value, ast.Name)}
        self.found: list[str] = []
        for stmt in getattr(scope, "body", []):
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._visit(stmt, in_build=False)

    def _visit(self, node, in_build):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        build = isinstance(node, ast.JoinedStr) or (
            isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))) or (
            isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add)) or (
            isinstance(node, ast.Call) and _name(node.func) == "format")
        if build and not in_build:
            consts = _str_consts(node.value if isinstance(node, ast.AugAssign) else node)
            if any("?" in c or "&" in c for c in consts) and _material(node, self.qnames):
                self.found.append("S4 string built onto a query")
                in_build = True
            elif any(_PAIR.search(c) for c in consts):
                self.found.append("S4b a ?name= literal")
                in_build = True
        shape = self._shape(node)
        if shape:
            self.found.append(shape)
        for child in ast.iter_child_nodes(node):
            self._visit(child, in_build)

    def _shape(self, n) -> str | None:
        if isinstance(n, ast.Call):
            callee = _name(n.func)
            receiver = _name(n.func.value) if isinstance(n.func, ast.Attribute) else ""
            if callee in _SENDS:
                if any(k.arg == "params" for k in n.keywords):
                    return "S1 params= on a send"
                if (callee == "get" and receiver == "requests" and len(n.args) >= 2) or \
                        (callee == "request" and len(n.args) >= 3) or \
                        (callee == "Request" and len(n.args) >= 6):
                    return "S1 a positional params on a send"
                if any(k.arg is None and _has_params_key(k.value) for k in n.keywords):
                    return "S2 params in a **dict"
            if callee in ("update", "setdefault") and receiver in self.starred and (
                    any(k.arg == "params" for k in n.keywords)
                    or (n.args and (_has_params_key(n.args[0]) or (
                        isinstance(n.args[0], ast.Constant) and n.args[0].value == "params")))):
                return "S2 params added to a **dict"
            if callee == "dict" and n.args and isinstance(n.args[0], ast.Call) \
                    and _name(n.args[0].func) in ("parse_qsl", "parse_qs"):
                return "S3 dict(parse_qsl/parse_qs)"
            if callee == "parse_qs":
                return "S3 parse_qs"
            if _sep_join(n):
                return 'S5 "&".join'
            if callee == "_replace" and any(k.arg in ("query", "fragment")
                                            for k in n.keywords):
                return "S6 _replace(query/fragment=)"
            if callee in _SPLIT_RESULTS:
                return "S6 SplitResult/ParseResult(...)"
            if callee in ("urlunsplit", "urlunparse") and n.args \
                    and isinstance(n.args[0], (ast.Tuple, ast.List)):
                elts = n.args[0].elts
                q, f = (3, 4) if callee == "urlunsplit" else (4, 5)

                def same(node, attr):
                    return (isinstance(node, ast.Constant) and node.value == "") or \
                        (isinstance(node, ast.Attribute) and node.attr == attr)
                if len(elts) > f and not (same(elts[q], "query")
                                          and same(elts[f], "fragment")):
                    return "S7 urlunsplit/urlunparse tuple rebuilding a query or fragment"
        if isinstance(n, (ast.Assign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Subscript) and any(
                        isinstance(x, ast.Constant) and x.value == "params"
                        for x in ast.walk(t.slice)):
                    return 'S2 kwargs["params"] store'
                if isinstance(n, ast.Assign) and isinstance(t, ast.Name) \
                        and t.id in self.starred and _has_params_key(n.value):
                    return "S2 params in a **dict"
        return None


def _qualname_scopes(tree):
    """``(qualname, scope)`` for the module and every function, nested ones included."""
    out = [("<module>", tree)]

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                if not isinstance(child, ast.ClassDef):
                    out.append((name, child))
                visit(child, name)
    visit(tree, "")
    return out


def query_builders(source: str) -> Counter:
    """``{(function, shape): count}`` of every query-builder shape in ``source``."""
    found: Counter = Counter()
    for qualname, scope in _qualname_scopes(ast.parse(source)):
        for shape in _Scan(scope).found:
            found[(qualname, shape)] += 1
    return found


def scan(pkg: Path = _PKG) -> Counter:
    """``{(module, function, shape): count}`` over ``fuzzlab/``, the owner excluded."""
    found: Counter = Counter()
    for path in sorted(pkg.rglob("*.py")):
        rel = path.relative_to(pkg.parent).as_posix()
        if rel == _OWNER:
            continue
        for (func, shape), n in query_builders(path.read_text(encoding="utf-8")).items():
            found[(rel, func, shape)] += n
    return found


_CONF = "labgen/conformance/"
_HARNESS = "a harness client of generated cells, on query-less paths: no query to keep"
#: Every query builder outside the owner, with its count and its reason (B1, PA-0531(1)).
#: The scan must equal this exactly: a new builder (or a second one in a listed function)
#: and a stale entry both fail.
ALLOWED: dict[tuple[str, str, str], tuple[int, str]] = {
    ("fuzzlab/core/store.py", "_no_create_uri", "S4b a ?name= literal"):
        (1, "a SQLite file: URI (?mode=rw), not HTTP"),
    ("fuzzlab/core/store.py", "_read_only_uri", "S4b a ?name= literal"):
        (1, "a SQLite file: URI (?mode=ro|rw&cache=private), not HTTP: the one read-only "
            "opener's (FR-CORE-508, CC-CORE-0071)"),
    ("fuzzlab/core/redaction.py", "redact_query", 'S5 "&".join'):
        (1, "storage redaction of a recorded URL, never sent (AU-REDACT's file)"),
    # the pushed tree's redactors frozen at 7393c90, the floor every URL redaction
    # consumer runs first (BUG-0556 r6): 7393c90's own entries above, moved with them
    ("fuzzlab/core/redaction_floor.py", "redact_query", 'S5 "&".join'):
        (1, "storage redaction of a recorded URL, never sent (the frozen floor)"),
    ("fuzzlab/core/redaction_floor.py", "_redact_query_identifiers", 'S5 "&".join'):
        (1, "storage redaction of a recorded URL, never sent (the frozen floor)"),
    ("fuzzlab/core/redaction_floor.py", "redact_url", "S6 _replace(query/fragment=)"):
        (1, "storage redaction of a recorded URL, never sent (the frozen floor)"),
    ("fuzzlab/core/redaction_floor.py", "redact_url_identifiers",
     "S6 _replace(query/fragment=)"):
        (1, "storage redaction of a recorded URL, never sent (the frozen floor)"),
    ("fuzzlab/core/redaction_floor.py", "_blank_identifiers", 'S5 "&".join'):
        (1, "trace redaction, never sent (the frozen floor)"),
    ("fuzzlab/core/trace.py", "_blank_identifiers", 'S5 "&".join'):
        (1, "trace redaction, never sent"),
    ("fuzzlab/disco/fingerprint.py", "normalise_route", "S4 string built onto a query"):
        (2, "a route key of parameter names, never sent"),
    ("fuzzlab/disco/fingerprint.py", "normalise_route", 'S5 "&".join'):
        (2, "a route key of parameter names, never sent"),
    ("fuzzlab/disco/synth.py", "parse_body", "S3 dict(parse_qsl/parse_qs)"):
        (1, "defect 9's item: a schema from captured bodies, never sent"),
    ("fuzzlab/lab_fixtures/external.py", "_bwapp_install", "S1 params= on a send"):
        (1, "lab provisioning with constant parameters, not probing"),
    ("fuzzlab/lab_fixtures/external.py", "_ecommerce_login", "S1 params= on a send"):
        (1, "lab provisioning with constant parameters, not probing"),
    (f"fuzzlab/{_CONF}django_live_boot.py", "DjangoLiveBootHarness.get",
     "S1 params= on a send"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}django_live_boot.py", "DjangoLiveBootHarness.request",
     "S4 string built onto a query"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}live_boot.py", "LiveBootHarness.fetch", "S1 params= on a send"):
        (1, _HARNESS),
    (f"fuzzlab/{_CONF}live_boot.py", "LiveBootHarness.get", "S1 params= on a send"):
        (1, _HARNESS),
    (f"fuzzlab/{_CONF}live_boot.py", "LiveBootHarness.request",
     "S4 string built onto a query"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}live_boot_spring_boot.py", "SpringBootLiveBootHarness.get",
     "S1 params= on a send"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}live_boot_spring_boot.py", "SpringBootLiveBootHarness.request",
     "S4 string built onto a query"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}rails_live_boot.py", "RailsLiveBootHarness.fetch",
     "S1 params= on a send"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}rails_live_boot.py", "RailsLiveBootHarness.get",
     "S1 params= on a send"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}rails_live_boot.py", "RailsLiveBootHarness.request",
     "S4 string built onto a query"): (1, _HARNESS),
    (f"fuzzlab/{_CONF}tier2.py", "LiveBootTier2Oracle._fetch", "S1 params= on a send"):
        (1, _HARNESS),
    ("fuzzlab/labgen/identifier_sqli_oracle.py", "_build_url",
     "S4 string built onto a query"):
        (1, "its input is a mapping: a duplicate cannot be expressed; generated cells "
            "declare none"),
    ("fuzzlab/labgen/oracle_wrapper.py", "_mark_query_param",
     "S6 _replace(query/fragment=)"):
        (1, "LAB hand-off: re-encodes untouched pairs; pinned by "
            "test_the_labgen_tool_wrapper_keeps_untouched_pairs_as_written"),
    ("fuzzlab/oracle/strategies.py", "OpenRedirectStrategy.confirm", "S4b a ?name= literal"):
        (1, "an open-redirect canary URL: the payload value itself, placed by the "
            "owner like any value"),
    ("fuzzlab/proxy/server.py", "target_from_request", "S4 string built onto a query"):
        (1, "the proxy forwards the client's own query verbatim"),
    ("fuzzlab/report/diagram.py", "finding_deep_link", "S4b a ?name= literal"):
        (1, "an in-app link (/diagrams?run=&finding=, integer ids), not traffic to a "
            "target"),
    ("fuzzlab/tools/spa.py", "visit_key", "S4 string built onto a query"):
        (1, "the crawler's dedup key, never sent"),
    ("fuzzlab/tools/spa.py", "visit_key", "S6 _replace(query/fragment=)"):
        (1, "the crawler's dedup key drops the fragment of an origin-less URL; never "
            "sent"),
    ("fuzzlab/tools/spider.py", "LocalSpider._isolated_submit",
     "S4 string built onto a query"):
        (1, "a GET form submission replaces the action's query by its entries, as a "
            "browser does (PA-0111)"),
    ("fuzzlab/tools/spider.py", "LocalSpider._isolated_submit", "S1 params= on a send"):
        (1, "a GET form submission replaces the action's query by its entries, as a "
            "browser does (PA-0111)"),
    ("fuzzlab/tools/store_adapter.py", "_import_forms", "S4 string built onto a query"):
        (1, "a stored endpoint key keeps the POST action's query verbatim"),
    ("fuzzlab/tools/store_adapter.py", "_store_request", "S4 string built onto a query"):
        (1, "a stored endpoint key keeps the request's query verbatim"),
    ("fuzzlab/web/app.py", "create_app.repeater_from_finding_prg",
     "S3 dict(parse_qsl/parse_qs)"):
        (1, "the operator's own UI form post, not traffic to a target"),
    ("fuzzlab/web/app.py", "create_app.repeater_from_finding_prg", "S4b a ?name= literal"):
        (1, "an in-app redirect (/proxy?repeater_tab=<id>), not traffic to a target"),
    ("fuzzlab/web/app.py", "create_app.repeater_from_flow_prg",
     "S3 dict(parse_qsl/parse_qs)"):
        (1, "the operator's own UI form post, not traffic to a target"),
    ("fuzzlab/web/app.py", "create_app.repeater_from_flow_prg", "S4b a ?name= literal"):
        (1, "an in-app redirect (/proxy?repeater_tab=<id>), not traffic to a target"),
    ("fuzzlab/web/projectroutes.py", "_form", "S3 dict(parse_qsl/parse_qs)"):
        (1, "the operator's own UI form post, not traffic to a target"),
}


def test_every_query_builder_goes_through_the_one_owner():
    """No query builder outside `core.urls` but the listed ones, each no more often than
    listed (a second builder in a listed function fails too)."""
    found = scan()
    extra = {k: n for k, n in found.items() if n > ALLOWED.get(k, (0, ""))[0]}
    assert extra == {}


def test_the_query_builder_allow_list_has_no_stale_entry():
    """Every listed builder is still there, exactly as often as listed."""
    found = scan()
    stale = {k: (n, found.get(k, 0)) for k, (n, _why) in ALLOWED.items()
             if found.get(k, 0) != n}
    assert stale == {}


#: One synthetic offender per shape the guard claims (PA-0034(2)), each a whole module.
OFFENDERS = {
    "params kw": "def f(s, u, p):\n    return s.get(u, params=p)\n",
    "params kw put": "def f(s, u, p):\n    return s.put(u, params=p)\n",
    "params kw patch": "def f(s, u, p):\n    return s.patch(u, params=p)\n",
    "params kw delete": "def f(s, u, p):\n    return s.delete(u, params=p)\n",
    "params kw head": "def f(s, u, p):\n    return s.head(u, params=p)\n",
    "params kw options": "def f(s, u, p):\n    return s.options(u, params=p)\n",
    "requests.Request kw": "def f(u, p):\n    return requests.Request('GET', u, params=p)\n",
    "playwright fetch": "def f(c, u, p):\n    return c.request.fetch(u, params=p)\n",
    "playwright get": "def f(c, u, p):\n    return c.request.get(u, params=p)\n",
    "positional requests.get": "def f(u, p):\n    return requests.get(u, p)\n",
    "positional request": "def f(s, u, p):\n    return s.request('GET', u, p)\n",
    "positional Request": "def f(u, p):\n    return requests.Request('GET', u, None, None, "
                          "None, p)\n",
    "subscript": "def f(kw, p, v):\n    kw['params'] = {p: v}\n",
    "subscript ifexp": "def f(kw, loc, e):\n    kw['data' if loc == 'body' else 'params'] "
                       "= list(e)\n",
    "** literal": "def f(s, u, p):\n    return s.get(u, **{'params': p})\n",
    "** dict()": "def f(s, u, p):\n    return s.get(u, **dict(params=p))\n",
    "** local literal": "def f(s, u, p):\n    kw = {'params': p}\n    return s.get(u, **kw)\n",
    "** local dict()": "def f(s, u, p):\n    kw = dict(params=p)\n    return s.get(u, **kw)\n",
    "** update kw": "def f(s, u, p):\n    kw = {}\n    kw.update(params=p)\n"
                    "    return s.get(u, **kw)\n",
    "** update dict": "def f(s, u, p):\n    kw = {}\n    kw.update({'params': p})\n"
                      "    return s.get(u, **kw)\n",
    "** setdefault": "def f(s, u, p):\n    kw = {}\n    kw.setdefault('params', p)\n"
                     "    return s.get(u, **kw)\n",
    "dict(parse_qsl)": "def f(x):\n    return dict(parse_qsl(x))\n",
    "parse_qs": "def f(x):\n    return parse_qs(x)\n",
    "concat quoter": "def f(u, q):\n    return u + '?' + urlencode(q)\n",
    "concat .query": "def f(u, p):\n    return u + '&' + p.query\n",
    "ifexp operand": "def f(u, q):\n    u += ('&' if '?' in u else '?') + urlencode(q)\n"
                     "    return u\n",
    "f-string quoter": "def f(u, q):\n    return f'{u}?{urlencode(q)}'\n",
    "format quoter": "def f(u, q):\n    return '{}?{}'.format(u, urlencode(q))\n",
    "percent quoter": "def f(u, q):\n    return '%s?%s' % (u, urlencode(q))\n",
    "local quoter concat": "def f(u, d):\n    q = urlencode(d)\n    return u + '?' + q\n",
    "local .query concat": "def f(u, p):\n    q = p.query\n    return u + '?' + q\n",
    "local join concat": "def f(u, pairs):\n    q = '&'.join(pairs)\n    return u + '?' + q\n",
    "local f-string": "def f(u, d):\n    q = urlencode(d)\n    return f'{u}?{q}'\n",
    "local format": "def f(u, d):\n    q = urlencode(d)\n    return '{}&{}'.format(u, q)\n",
    "local percent": "def f(u, d):\n    q = quote(d)\n    return '%s?x=%s' % (u, q)\n",
    "local +=": "def f(u, d):\n    q = urlencode(d)\n    u += '&' + q\n    return u\n",
    "?name= concat": "def f(u, v):\n    return u + '?id=' + v\n",
    "&name= concat": "def f(u, n):\n    return u + '&page=' + str(n)\n",
    "?name= f-string": "def f(u, v):\n    return f'{u}?id={v}'\n",
    "?name= format": "def f(u, v):\n    return '{}?id={}'.format(u, v)\n",
    '"&".join': "def f(pairs):\n    return '&'.join(pairs)\n",
    '"?".join': "def f(a, b):\n    return '?'.join([a, b])\n",
    "_replace query": "def f(p, q):\n    return p._replace(query=q)\n",
    "_replace fragment": "def f(p, fr):\n    return p._replace(fragment=fr)\n",
    "SplitResult": "def f(s, n, p, q, fr):\n    return SplitResult(s, n, p, q, fr)\n",
    "ParseResult": "def f(s, n, p, a, q, fr):\n    return ParseResult(s, n, p, a, q, fr)\n",
    "urlunsplit query": "def f(p, q):\n    return urlunsplit((p.scheme, p.netloc, p.path, "
                        "q, p.fragment))\n",
    "urlunsplit fragment": "def f(p, fr):\n    return urlunsplit((p.scheme, p.netloc, "
                           "p.path, p.query, fr))\n",
    "urlunparse query": "def f(p, q):\n    return urlunparse((p.scheme, p.netloc, p.path, "
                        "p.params, q, p.fragment))\n",
    "module level": "q = urlencode({'a': 1})\nURL = 'http://h/p?' + q\n",
}
#: Shapes that look close and are not query builders: none may be flagged.
NEAR_MISSES = {
    "strip": "def f(p):\n    return urlunsplit((p.scheme, p.netloc, p.path, '', ''))\n",
    "keep": "def f(p):\n    return urlunsplit((p.scheme, p.netloc, p.path, p.query, "
            "p.fragment))\n",
    "safe-amp": "def f(s):\n    return '/' + quote(s, safe='&=')\n",
    "model params": "def f(w):\n    return {'params': w}\n",
    "dict get": "def f(d, k):\n    return d.get(k, None)\n",
    "get params key": "def f(d):\n    return d.get('params')\n",
    "update elsewhere": "def f(d, p):\n    d.update(params=p)\n    return d\n",
    "docstring": "def f(u):\n    '''See /p?id=1.'''\n    return u\n",
    "separator test": "def f(u, q):\n    q = urlencode(q)\n    return '?' in u\n",
    "plain url": "def f():\n    return 'http://h/p'\n",
}


def test_the_query_builder_guard_catches_synthetic_offenders():
    """PA-0034(2): every shape the guard claims is flagged on its own synthetic offender,
    and none of the near-misses is."""
    missed = sorted(k for k, src in OFFENDERS.items() if not query_builders(src))
    flagged = sorted(k for k, src in NEAR_MISSES.items() if query_builders(src))
    assert (missed, flagged) == ([], [])
