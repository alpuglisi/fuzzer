"""Proxy rules are validated when created; one connection's failure is contained; scope
is decided once, on the authority, IPv6 included (BUG-0085, BUG-0086; PA-0086/0087).
"""

from __future__ import annotations

import asyncio

import pytest

from fuzzlab.proxy.matchreplace import MatchReplaceRule
from fuzzlab.proxy.scope import Scope, ScopeRule
from fuzzlab.proxy.server import (AsyncProxyServer, ProxyEngine, parse_connect,
                                  target_from_request)

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class _Hist:
    def __init__(self):
        self.recs = []

    def record(self, r):
        self.recs.append(r)


# --- BUG-0085: validated at creation -------------------------------------------

@pytest.mark.parametrize("kw", [
    dict(target="body", match="café€", replace="x"),               # not latin-1
    dict(target="body", match="ok", replace="€"),
    dict(target="body", match="(unclosed", is_regex=True),
])
def test_bad_match_replace_rules_are_refused_when_created(kw):
    with pytest.raises(ValueError):
        MatchReplaceRule(**kw)


def test_a_bad_scope_regex_is_refused_when_created():
    with pytest.raises(ValueError):
        ScopeRule(host="127.0.0.1", path_regex="(unclosed")
    with pytest.raises(ValueError):
        Scope().include("127.0.0.1", "(unclosed")


def test_the_web_api_answers_400_for_bad_rules():
    pytest.importorskip("fastapi")
    from fuzzlab.core.config import load_config
    from fuzzlab.web.app import create_app
    from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController
    from tests._webclient import web_client
    ctl = ProxyController(ProxyConfig(port=0)).build()
    client = web_client(create_app(load_config(), proxy=ctl))
    r = client.post("/api/proxy/scope", json={"host": "127.0.0.1", "path_regex": "(x"})
    assert r.status_code == 400 and "regex" in r.json()["error"]
    r = client.post("/api/proxy/matchreplace",
                    json={"target": "body", "match": "café€", "replace": "x"})
    assert r.status_code == 400


# --- BUG-0085: per-connection containment --------------------------------------

def test_an_engine_failure_answers_502_and_the_proxy_keeps_serving():
    calls = {"n": 0}

    def flaky(host, port, tls, raw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("upstream exploded")
        return OK
    errors = []

    async def main():
        asyncio.get_running_loop().set_exception_handler(
            lambda loop, ctx: errors.append(ctx.get("exception")))
        eng = ProxyEngine(scope=Scope.for_host("127.0.0.1:8080"), sender=flaky)
        srv = await AsyncProxyServer(eng, "127.0.0.1", 0).start()
        out = []
        try:
            for _ in range(2):
                r, w = await asyncio.open_connection("127.0.0.1", srv.port)
                w.write(b"GET http://127.0.0.1:8080/x HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
                await w.drain()
                out.append(await r.read())
                w.close()
        finally:
            await srv.stop()
        return out, srv.errors
    (first, second), contained = asyncio.run(main())
    assert first.startswith(b"HTTP/1.1 502") and second == OK
    assert contained and "upstream exploded" in contained[0] and errors == []


# --- BUG-0086: one scope decision; IPv6 authorities -----------------------------

def test_a_port_specific_exclude_is_not_bypassed_by_a_host_wide_include():
    hist, sent = _Hist(), []

    def sender(h, p, tls, raw):
        sent.append(raw)
        return OK
    scope = Scope().include("127.0.0.1").exclude("127.0.0.1:9000")
    eng = ProxyEngine(scope=scope, sender=sender, history=hist)
    asyncio.run(eng.handle_request(b"GET /secret HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n",
                                   "127.0.0.1", 9000))
    asyncio.run(eng.handle_request(b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
                                   "127.0.0.1", 8080))
    assert len(sent) == 2                                  # forwarded transparently
    assert [r.url for r in hist.recs] == ["http://127.0.0.1:8080/ok"]   # 9000 unrecorded


@pytest.mark.parametrize("rule,authority,hit", [
    ("127.0.0.1", "127.0.0.1:8080", True),                 # port-less: any port
    ("127.0.0.1:8080", "127.0.0.1:8080", True),
    ("127.0.0.1:8080", "127.0.0.1:9090", False),
    ("::1", "[::1]:8443", True),
    ("[::1]", "[::1]:8443", True),
    ("[::1]:8443", "[::1]:8443", True),
    ("[::1]:8443", "[::1]:9443", False),
    (".lab.local", "a.lab.local:80", True),
    (".lab.local", "evil-lab.local:80", False),
])
def test_scope_matches_authorities(rule, authority, hit):
    assert Scope().include(rule).in_scope(authority) is hit


def test_ipv6_connect_and_host_headers_parse():
    assert parse_connect(b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n") == (
        "::1", 8443)
    t = target_from_request(b"GET /x HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n", use_tls=True)
    assert (t.host, t.port) == ("::1", 8443)
    t = target_from_request(b"GET http://[::1]:8080/a?b=1 HTTP/1.1\r\n\r\n")
    assert (t.host, t.port, t.request.split(b" ")[1]) == ("::1", 8080, b"/a?b=1")


def test_an_ipv6_flow_is_recorded_with_a_bracketed_authority():
    hist = _Hist()
    eng = ProxyEngine(scope=Scope().include("::1"), sender=lambda *a: OK, history=hist)
    asyncio.run(eng.handle_request(b"GET /a HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n",
                                   "::1", 8443))
    assert hist.recs[0].url == "http://[::1]:8443/a" and hist.recs[0].host == "[::1]:8443"
