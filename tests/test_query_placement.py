"""AU-REQID measurement, audit defect 14 (BUG-0531): a query payload is placed
differently by each sender.

Every sender sends to a loopback echo server started here (`require_loopback`,
PA-0130), which records the exact request target it received, byte for byte. The
contract the draft (docs/components/07-fuzzing-harness-and-oracle/DRAFT-AU-REQID.md)
states: the payload replaces the value of exactly the addressed occurrence of the
parameter, in place; every other pair keeps its position, its ``=`` (or its absence)
and its bytes, up to the rewriting the HTTP clients themselves apply, measured by
`test_platform_clients_rewrite_only_escapes_without_query_meaning` (requests decodes
``%7E``; Chromium encodes a raw ``'``). `canonical_pairs` is that equivalence.

Tests that fail on 8100959 are pinned with a strict xfail until CC-FUZZ-0106 lands
(PA-0054(3)); the parameter combinations that already hold are not pinned.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import pytest

from fuzzlab.core.net import require_loopback

pin14 = pytest.mark.xfail(strict=True, reason="BUG-0531 (audit defect 14), measured on "
                          "8100959; fixed by CC-FUZZ-0106 (AU-REQID)")

MARK = "zqmark"


# --- the equivalence the measured clients preserve -------------------------------------
#: Escapes a query parser reads differently from their raw character (``& = + % #``):
#: kept escaped (hex upper-cased); every other escape is decoded.
_MEANINGFUL = re.compile(r"%(26|3[dD]|2[bB]|25|23)")


def _canonical(text: str) -> str:
    out, i = [], 0
    for m in _MEANINGFUL.finditer(text):
        out += [unquote(text[i:m.start()]), m.group(0).upper()]
        i = m.end()
    return "".join(out + [unquote(text[i:])])


def canonical_pairs(raw_query: str) -> list[tuple[str, bool, str]]:
    """A raw query as the measured clients and a server agree on it: each ``&``-part in
    order (empty parts kept), its name, whether it has ``=``, and its value, with every
    escape decoded except those of ``& = + % #``."""
    out = []
    for part in raw_query.split("&"):
        name, eq, value = part.partition("=")
        out.append((_canonical(name), bool(eq), _canonical(value)))
    return out


def test_the_equivalence_still_tells_apart_what_a_server_reads_apart():
    """PA-0034(2): the relation is not vacuous -- a duplicate, a lost sibling, ``flag``
    vs ``flag=``, ``+`` vs ``%2B``, ``&`` vs ``%26`` and order all differ under it, while
    each rewriting a measured client makes compares equal."""
    same = [("a=%7E", "a=~"), ("q='", "q=%27"), ("k=a|b", "k=a%7Cb"),
            ("s2=%2b", "s2=%2B"), ("v=é", "v=%C3%A9")]
    differ = [("id=1&id=x", "id=x"), ("tag=a&tag=b", "tag=b"), ("flag", "flag="),
              ("s=a+b", "s=a%2Bb"), ("x=a%26b", "x=a&b"), ("a=1&b=2", "b=2&a=1"),
              ("o=a%3Db", "o=a=b")]
    assert all(canonical_pairs(a) == canonical_pairs(b) for a, b in same)
    assert all(canonical_pairs(a) != canonical_pairs(b) for a, b in differ)


class _Echo:
    """A loopback HTTP server that records each request's raw target (path and query
    exactly as received) and answers a small HTML page."""

    def __init__(self):
        require_loopback("127.0.0.1")                      # PA-0130
        self.targets: list[str] = []
        echo = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if urlsplit(self.path).path == "/p":
                    echo.targets.append(self.path)
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


# --- the platform fact the equivalence rests on (MULTI_AGENT_ORCHESTRATION §7) --------
#: A raw query given verbatim -> what each client put on the wire (measured 2026-10-19,
#: requests 2.34.2, Chromium 1194).
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
}


def test_platform_clients_rewrite_only_escapes_without_query_meaning(echo, monkeypatch):
    """requests and real Chromium (FUZZLAB_REQUIRE_BROWSER=1: fails, never skips) send a
    verbatim query with their own escaping rewrites only: never a pair boundary, an
    ``=``, an empty part, or an escape of ``& = + % #`` (up to hex case). A client
    upgrade that changes this fails here first."""
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


# --- one function per sender: send MARK at ``param`` of ``url`` (a GET query point) ---
def _anonymous(url, param):
    from fuzzlab.tools.probesender import RequestsProbeSender
    RequestsProbeSender(timeout=5).send(url, param, MARK)


def _seam(url, param):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.probesender import SeamProbeSender
    SeamProbeSender(HttpClient(RequestBudget(10), ["127.0.0.1"], timeout=5)).send(
        url, param, MARK)


class _PassThroughSession:
    """A session addon that applies nothing: the identity-bearing path of the seam,
    whose URL is built by the same `_send_on` (only `prepare`/`observe` are called)."""

    def prepare(self, request, identity):
        return None

    def observe(self, request, response, identity):
        return None


def _seam_with_identity(url, param):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.probesender import SeamProbeSender
    client = HttpClient(RequestBudget(10), ["127.0.0.1"], session=_PassThroughSession(),
                        timeout=5)
    SeamProbeSender(client, identity="lab-user").send(url, param, MARK)


def _greybox(url, param):
    from fuzzlab.greybox.run import RequestsCorrelatingSender
    RequestsCorrelatingSender(timeout=5, id_factory=lambda: "c").send_correlated(
        url, param, MARK)


def _blind_requests(url, param):
    import requests

    from fuzzlab.tools.blind_sqli_fuzzer import RequestsSender
    RequestsSender(requests.Session()).get(url, param, MARK, 5)


def _blind_seam(url, param):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.blind_sqli_fuzzer import SeamSender
    SeamSender(HttpClient(RequestBudget(10), ["127.0.0.1"], timeout=5), "anonymous").get(
        url, param, MARK, 5)


SENDERS = {"probe-anonymous": _anonymous, "probe-seam": _seam,
           "probe-seam-identity": _seam_with_identity, "greybox": _greybox,
           "blind-sqli-anonymous": _blind_requests, "blind-sqli-seam": _blind_seam}
#: Senders that append a requests ``params=`` pair (the anonymous family) and senders
#: that rebuild the query through ``dict(parse_qsl(...))`` (`with_query_param`).
_APPENDING = ("probe-anonymous", "greybox", "blind-sqli-anonymous")
_DICT = ("probe-seam", "probe-seam-identity", "blind-sqli-seam")

#: (query before, parameter, query the contract requires, families failing on 8100959).
#: The first occurrence of the parameter is the addressed one: what a standalone point
#: names today.
CASES = [
    ("id=1&tag=a&tag=b", "id", f"id={MARK}&tag=a&tag=b", _APPENDING + _DICT),  # audit
    ("tag=a&id=1&tag=b", "tag", f"tag={MARK}&id=1&tag=b", _APPENDING + _DICT),
    ("a=%7E&flag&id=1&b=x+y", "id", f"a=%7E&flag&id={MARK}&b=x+y", _APPENDING + _DICT),
    ("id=&x=1", "id", f"id={MARK}&x=1", _APPENDING),                 # a blank value
    ("a%5B%5D=1&a%5B%5D=2", "a[]", f"a%5B%5D={MARK}&a%5B%5D=2", _APPENDING + _DICT),
]


def _cases():
    for before, param, want, failing in CASES:
        for sender in sorted(SENDERS):
            yield pytest.param(sender, before, param, want,
                               marks=[pin14] if sender in failing else [],
                               id=f"{sender}-{before}")


@pytest.mark.parametrize("sender,before,param,want", list(_cases()))
def test_every_sender_replaces_the_addressed_occurrence_in_place(echo, sender, before,
                                                                 param, want):
    SENDERS[sender](f"{echo.base}/p?{before}", param)
    assert canonical_pairs(echo.query()) == canonical_pairs(want)


def test_control_a_query_less_url_gets_the_pair(echo):
    """Non-vacuity control (passes on 8100959): the echo server sees each sender's
    send, and a URL without a query gets ``param=MARK`` from every sender."""
    for name in sorted(SENDERS):
        echo.targets.clear()
        SENDERS[name](f"{echo.base}/p", "id")
        assert echo.query() == f"id={MARK}", name


@pin14
def test_the_anonymous_and_authenticated_senders_send_the_same_query(echo):
    """The defect's own statement: the result depends on the sender, not the target."""
    got = {}
    for name in ("probe-anonymous", "probe-seam"):
        echo.targets.clear()
        SENDERS[name](f"{echo.base}/p?id=1&tag=a&tag=b", "id")
        got[name] = echo.query()
    assert canonical_pairs(got["probe-anonymous"]) == canonical_pairs(got["probe-seam"])


# --- the bound path: a link set's siblings, bound by the oracle (`_FormBoundSender`) -----
@pin14
def test_a_bound_duplicate_name_changes_one_occurrence_only(echo):
    """``tag=a&tag=b``'s point ``tag``: `FormEntries.replace` sets every entry called
    ``tag``, so the server receives ``tag=MARK&tag=MARK`` -- neither the first-value nor
    the array reading of the original request."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.tools.probesender import RequestsProbeSender
    url = f"{echo.base}/p"
    candidate = Candidate(url=url, param="tag",
                          base_entries=(("id", "1"), ("tag", "a"), ("tag", "b")))
    _FormBoundSender(RequestsProbeSender(timeout=5), candidate).send(url, "tag", MARK)
    assert canonical_pairs(echo.query()) == canonical_pairs(f"id=1&tag={MARK}&tag=b")


# --- the M6 browser executor: what Chromium itself sends -------------------------------
@pin14
def test_the_browser_executor_replaces_the_addressed_occurrence_in_place(echo,
                                                                         monkeypatch):
    """Real Chromium (FUZZLAB_REQUIRE_BROWSER=1 fails rather than skips): the observe
    navigation of a query DOM point, recorded at the server."""
    from tests.test_navigation_aborts import _chromium_or_skip
    _chromium_or_skip(monkeypatch)
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    executor.SETTLE_MS = 200
    executor.run(ExecRequest(url=f"{echo.base}/p?id=1&tag=a&tag=b", param="id",
                             value=MARK, location="query"), "tok")
    assert canonical_pairs(echo.query()) == canonical_pairs(f"id={MARK}&tag=a&tag=b")
