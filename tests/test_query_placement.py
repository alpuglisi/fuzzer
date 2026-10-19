"""AU-REQID14 measurement, audit defect 14 (BUG-0531): a query payload is placed
differently by each sender.

Every sender sends to a loopback echo server started here (`require_loopback`,
PA-0130), which records the exact request target it received, byte for byte. The
contract the draft (docs/components/07-fuzzing-harness-and-oracle/DRAFT-AU-REQID14.md)
states: for a standalone URL, the payload replaces the value of the first occurrence of
the parameter, in place; every other part keeps its position, its ``=`` (or its absence)
and its text. Until AU-REQID8, bound entries (a link set, a form) replace every
occurrence of the name (the binder's rule), for the HTTP senders and the M6 browser alike.

How a wire is judged (measured, `test_platform_clients_rewrite_only_escapes_they_disagree_on`):
- every HTTP sender goes through requests, so it is compared **byte for byte** with what
  requests itself prepares from the contract's query (`_prepared`);
- real Chromium is compared with the contract under `canonical_pairs`: bytes, with only
  the escapes the two clients were measured to treat differently decoded.

Tests that fail on 8100959 are pinned with a strict xfail until CC-FUZZ-0106 (AU-REQID14)
lands, or until AU-REQID8 for the binder's rule (PA-0054(3)); the combinations that
already hold are not pinned.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote_plus, unquote_to_bytes, urlencode, urlsplit, \
    urlunsplit

import pytest

from fuzzlab.core.net import require_loopback

pin14 = pytest.mark.xfail(strict=True, reason="BUG-0531 (audit defect 14), measured on "
                          "8100959; fixed by CC-FUZZ-0106 (AU-REQID14)")
pin8 = pytest.mark.xfail(strict=True, reason="audit defect 14, the binder's rule: bound "
                         "entries replace every occurrence of a name until AU-REQID8 "
                         "makes the occurrence part of a point (measured on 8100959)")

MARK = "zqmark"
#: A payload carrying every character a placement can get wrong.
HARD = "'\"<>&=#+% é/~"


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
    exactly as received) to ``/p`` and answers a small HTML page. With ``redirect`` set,
    a request whose target carries `MARK` is answered ``302 Location: <redirect>``."""

    def __init__(self):
        require_loopback("127.0.0.1")                      # PA-0130
        self.targets: list[str] = []
        self.redirect: str | None = None
        echo = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if urlsplit(self.path).path == "/p":
                    echo.targets.append(self.path)
                if echo.redirect is not None and MARK in self.path:
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
#: Senders that append a requests ``params=`` pair (the anonymous family) and senders
#: that rebuild the query through ``dict(parse_qsl(...))`` (`with_query_param`).
_APPENDING = ("probe-anonymous", "greybox", "blind-sqli-anonymous")
_DICT = ("probe-seam", "probe-seam-identity", "blind-sqli-seam")
_ALL = _APPENDING + _DICT

#: (case id, query before, parameter, the query the contract requires, the senders that
#: fail it on 8100959). A standalone point addresses the first occurrence.
CASES = [
    ("audit", "id=1&tag=a&tag=b", "id", f"id={MARK}&tag=a&tag=b", _ALL),
    ("dup-sibling", "tag=a&id=1&tag=b", "tag", f"tag={MARK}&id=1&tag=b", _ALL),
    ("raw-text", "a=%7E&flag&id=1&b=x+y", "id", f"a=%7E&flag&id={MARK}&b=x+y", _ALL),
    ("blank", "id=&x=1", "id", f"id={MARK}&x=1", _APPENDING),
    ("encoded-name", "a%5B%5D=1&a%5B%5D=2", "a[]", f"a%5B%5D={MARK}&a%5B%5D=2", _ALL),
    ("pct20-sibling", "id=1&t=x%20y", "id", f"id={MARK}&t=x%20y", _ALL),
    ("empty-parts", "a=1&&id=1&", "id", f"a=1&&id={MARK}&", _ALL),
    ("pctE9-sibling", "id=1&e=%E9", "id", f"id={MARK}&e=%E9", _ALL),
]


def _cases():
    for case_id, before, param, want, failing in CASES:
        for sender in sorted(SENDERS):
            yield pytest.param(sender, before, param, want,
                               marks=[pin14] if sender in failing else [],
                               id=f"{sender}-{case_id}")


@pytest.mark.parametrize("sender,before,param,want", list(_cases()))
def test_every_sender_replaces_the_addressed_occurrence_in_place(echo, sender, before,
                                                                 param, want):
    """Byte for byte against requests' own preparation of the contract (F1)."""
    SENDERS[sender](f"{echo.base}/p?{before}", param)
    assert echo.query() == _prepared(want)


def test_control_a_query_less_url_gets_the_pair(echo):
    """Non-vacuity control (passes on 8100959): the echo server sees each sender's
    send, and a URL without a query gets ``param=MARK`` from every sender."""
    for name in sorted(SENDERS):
        echo.targets.clear()
        SENDERS[name](f"{echo.base}/p", "id")
        assert echo.query() == f"id={MARK}", name


@pytest.mark.parametrize("sender", sorted(SENDERS))
def test_a_hard_payload_on_a_query_less_url_is_quote_plus_encoded(echo, sender):
    """Today's bytes for a query-less URL (every ground-truth point): the payload is
    ``quote_plus(value, safe="")``, exactly. Passes on 8100959; the fix must keep it."""
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
    for case_id, before, param, want, _failing in CASES:
        echo.targets.clear()
        wrong_fix(f"{echo.base}/p?{before}", param)
        if echo.query() != _prepared(want):
            failed.add(case_id)
    assert {"raw-text", "pct20-sibling", "empty-parts", "pctE9-sibling"} <= failed


@pin14
def test_the_anonymous_and_authenticated_senders_send_the_same_query(echo):
    """The defect's own statement: the result depends on the sender, not the target.
    Both go through requests, so the bytes must be equal (F1)."""
    got = {}
    for name in ("probe-anonymous", "probe-seam"):
        echo.targets.clear()
        SENDERS[name](f"{echo.base}/p?id=1&tag=a&tag=b", "id")
        got[name] = echo.query()
    assert got["probe-anonymous"] == got["probe-seam"]


# --- the bound path: a link set's siblings, bound by the oracle (`_FormBoundSender`) -----
@pin8
def test_a_bound_duplicate_name_changes_one_occurrence_only(echo):
    """``tag=a&tag=b``'s point ``tag``: `FormEntries.replace` sets every entry called
    ``tag`` (``tag=MARK&tag=MARK``). The binder keeps that rule until AU-REQID8."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.tools.probesender import RequestsProbeSender
    url = f"{echo.base}/p"
    candidate = Candidate(url=url, param="tag",
                          base_entries=(("id", "1"), ("tag", "a"), ("tag", "b")))
    _FormBoundSender(RequestsProbeSender(timeout=5), candidate).send(url, "tag", MARK)
    assert echo.query() == _prepared(f"id=1&tag={MARK}&tag=b")


# --- PRG: the follow-up never carries the payload (M6) ----------------------------------
def _prg_send(sender_name, echo, bound):
    from fuzzlab.tools.probesender import RequestsProbeSender
    sender = RequestsProbeSender(timeout=5) if sender_name == "anonymous" \
        else _seam_sender()
    if bound:
        sender.send(f"{echo.base}/p", "id", MARK, entries=[("id", MARK), ("tag", "a")],
                    prg=True)
    else:
        sender.send(f"{echo.base}/p?id=1&tag=a", "id", MARK, prg=True)


@pytest.mark.parametrize("sender_name,bound", [
    pytest.param("anonymous", False, id="anonymous-standalone"),
    pytest.param("anonymous", True, id="anonymous-bound", marks=pin14),
    pytest.param("seam", False, id="seam-standalone"),
    pytest.param("seam", True, id="seam-bound")])
def test_a_fragment_only_location_is_followed_without_the_payload(echo, sender_name,
                                                                   bound):
    """A ``302 Location: #top`` resolves to the URL the follow-up is given: the probe's
    own URL, never the placed one (`PRG_RULES['no-body-no-payload']`). On 8100959 the
    anonymous sender's bound branch hands `_follow` the placed URL and re-sends the
    payload; its standalone branch and the seam keep the original URL."""
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


# --- the M6 browser executor: what Chromium itself sends -------------------------------
def _executor(monkeypatch):
    from tests.test_navigation_aborts import _chromium_or_skip
    _chromium_or_skip(monkeypatch)
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    executor.SETTLE_MS = 200
    return executor


def _m6_cases():
    for case_id, before, param, want, _failing in CASES:
        yield pytest.param(before, param, want, marks=[pin14], id=case_id)


@pytest.mark.parametrize("before,param,want", list(_m6_cases()))
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
    """Today's bytes, kept (passes on 8100959): Chromium keeps the escapes it is given."""
    from fuzzlab.oracle.browser import ExecRequest
    _executor(monkeypatch).run(ExecRequest(url=f"{echo.base}/p", param="id", value=HARD,
                                           location="query"), "tok")
    assert echo.query() == "id=" + quote_plus(HARD, safe="")


@pin14
def test_the_browser_get_store_step_replaces_the_addressed_occurrence_in_place(
        echo, monkeypatch):
    """The stored-XSS plant through a GET (`browserexec.py:539`): the store URL's own
    query, placed like any other."""
    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    _executor(monkeypatch).run(ExecRequest(url=f"{echo.base}/o", store=StoreStep(
        url=f"{echo.base}/p?id=1&tag=a&tag=b", param="id", value=MARK, method="GET",
        location="query")), "tok")
    assert canonical_pairs(echo.query()) == canonical_pairs(f"id={MARK}&tag=a&tag=b")


@pin14
def test_a_dom_query_point_is_loaded_with_its_siblings(echo, monkeypatch):
    """A crawled DOM query point with a link set (``op=search&q=1``): the browser loads
    it with its siblings, bound by the binder's rule, as the HTTP senders send it. On
    8100959 `DomXssStrategy` hands the executor no entries, so every load is
    ``/p?q=<payload>`` alone."""
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
