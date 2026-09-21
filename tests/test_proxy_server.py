"""Phase 6 T6.6: CONNECT/target parsing, local-CA leaf cache, and the flow engine."""

import asyncio

import pytest

from fuzzlab.core.store import Store
from fuzzlab.proxy.ca import LocalCA
from fuzzlab.proxy.history import HistoryWriter
from fuzzlab.proxy.intercept import Interceptor
from fuzzlab.proxy.matchreplace import MatchReplaceEngine, MatchReplaceRule
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.server import (AsyncProxyServer, ProxyEngine, parse_connect,
                                  target_from_request)

RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


# --- CONNECT / target parsing ------------------------------------------------
def test_parse_connect():
    assert parse_connect(b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\n\r\n") == ("127.0.0.1", 8443)
    assert parse_connect(b"CONNECT example.com HTTP/1.1\r\n\r\n") == ("example.com", 443)
    assert parse_connect(b"GET / HTTP/1.1\r\n\r\n") is None


def test_target_absolute_form_rewrites_to_origin():
    raw = b"GET http://127.0.0.1:8080/p?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
    t = target_from_request(raw)
    assert (t.host, t.port, t.use_tls) == ("127.0.0.1", 8080, False)
    assert RawMessage.from_bytes(t.request).start_line == b"GET /p?id=1 HTTP/1.1"


def test_target_origin_form_uses_host_header():
    raw = b"POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
    t = target_from_request(raw)
    assert (t.host, t.port) == ("127.0.0.1", 8080)
    assert t.request == raw                            # unchanged (already origin-form)


def test_target_https_absolute_sets_tls():
    raw = b"GET https://svc.local/api HTTP/1.1\r\nHost: svc.local\r\n\r\n"
    t = target_from_request(raw)
    assert t.use_tls is True and t.port == 443


# --- local CA leaf cache (offline via injected minter) -----------------------
def test_leaf_cert_cache_mints_once_per_host(tmp_path):
    calls = []

    def fake_minter(host):
        calls.append(host)
        return (b"cert-" + host.encode(), b"key-" + host.encode())

    ca = LocalCA(tmp_path / "ca", minter=fake_minter)
    a1 = ca.leaf_cert("127.0.0.1:8080")
    a2 = ca.leaf_cert("127.0.0.1:9999")               # same host, different port
    b1 = ca.leaf_cert("other.local")
    assert a1 == a2                                    # cached by hostname, not port
    assert calls == ["127.0.0.1", "other.local"]      # minted once per hostname
    assert ca.cached_hosts() == ["127.0.0.1", "other.local"]
    assert a1[0] == b"cert-127.0.0.1"


def test_real_ca_mints_signed_leaf(tmp_path):
    """On-host: exercise the real X.509 minting when cryptography works."""
    try:
        from cryptography import x509  # noqa: F401
        from cryptography.fernet import Fernet
        Fernet(Fernet.generate_key()).encrypt(b"probe")   # force the rust bindings
    except BaseException as exc:  # noqa: BLE001 - broken native build panics
        pytest.skip(f"cryptography unavailable/broken: {exc}")
    ca = LocalCA(tmp_path / "ca")
    cert_pem, key_pem = ca.leaf_cert("127.0.0.1")
    assert b"BEGIN CERTIFICATE" in cert_pem and b"PRIVATE KEY" in key_pem
    assert ca.ca_cert_path.exists() and (ca.ca_key_path.stat().st_mode & 0o777) == 0o600


# --- ProxyEngine pipeline (sans-I/O) -----------------------------------------
class _FakeSender:
    def __init__(self, response=RESP):
        self.response = response
        self.sent = []

    def __call__(self, host, port, use_tls, raw):
        self.sent.append((host, port, use_tls, raw))
        return self.response


def _engine(tmp_path, **kw):
    store = Store(tmp_path / "u.db")
    run_id = store.start_run("proxy", "127.0.0.1:8080")
    hist = HistoryWriter(store, run_id)
    sender = _FakeSender()
    scope = kw.pop("scope", Scope().include("127.0.0.1"))
    eng = ProxyEngine(scope=scope, sender=sender, history=hist, **kw)
    return store, eng, sender, hist


def test_engine_forwards_in_scope_and_records(tmp_path):
    store, eng, sender, hist = _engine(tmp_path)
    raw = b"GET /product.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
    resp = asyncio.run(eng.handle_request(raw, "127.0.0.1", 8080))
    assert resp == RESP
    assert sender.sent[0][3] == raw                    # byte-exact forward
    assert len(hist.search("product.php")) == 1        # recorded
    store.close()


def test_engine_bypasses_out_of_scope_untouched(tmp_path):
    store, eng, sender, hist = _engine(tmp_path)
    raw = b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    resp = asyncio.run(eng.handle_request(raw, "evil.example", 80))
    assert resp == RESP and sender.sent[0][3] == raw   # forwarded transparently
    assert hist.search("evil.example") == []           # NOT recorded (out of scope)
    store.close()


def test_engine_applies_match_replace_before_forward(tmp_path):
    mr = MatchReplaceEngine([MatchReplaceRule("request_line", b"/a", b"/b")])
    store, eng, sender, hist = _engine(tmp_path, matchreplace=mr)
    asyncio.run(eng.handle_request(
        b"GET /a HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n", "127.0.0.1", 8080))
    assert RawMessage.from_bytes(sender.sent[0][3]).target == b"/b"
    store.close()


def test_engine_interceptor_drop_and_edit(tmp_path):
    interceptor = Interceptor(enabled=True)
    store, eng, sender, hist = _engine(tmp_path, interceptor=interceptor)

    async def scenario(action):
        task = asyncio.create_task(eng.handle_request(
            b"GET /a HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n", "127.0.0.1", 8080))
        for _ in range(100):
            if interceptor.pending():
                break
            await asyncio.sleep(0)
        pend = interceptor.pending()[0]
        if action == "drop":
            interceptor.drop(pend.id)
        else:
            interceptor.forward(pend.id, pend.message.with_request_line(b"GET /z HTTP/1.1"))
        return await task

    assert asyncio.run(scenario("drop")) is None
    assert sender.sent == []                            # dropped: nothing forwarded
    assert asyncio.run(scenario("edit")) == RESP
    assert RawMessage.from_bytes(sender.sent[0][3]).target == b"/z"
    store.close()


# --- async server (plain-HTTP path over loopback) ----------------------------
def test_async_server_plain_http_roundtrip(tmp_path):
    async def scenario():
        store, eng, sender, hist = _engine(tmp_path)
        server = await AsyncProxyServer(eng, "127.0.0.1", 0).start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"GET http://127.0.0.1:8080/p?id=1 HTTP/1.1\r\n"
                         b"Host: 127.0.0.1:8080\r\n\r\n")
            await writer.drain()
            data = await reader.read(len(RESP))
            writer.close()
            return data, sender
        finally:
            await server.stop()
            store.close()

    data, sender = asyncio.run(scenario())
    assert data == RESP
    # the upstream saw an origin-form request rewritten from absolute-form
    assert RawMessage.from_bytes(sender.sent[0][3]).start_line == b"GET /p?id=1 HTTP/1.1"


def test_async_server_connect_is_501_offline(tmp_path):
    async def scenario():
        store, eng, sender, hist = _engine(tmp_path)
        server = await AsyncProxyServer(eng, "127.0.0.1", 0).start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\n\r\n")
            await writer.drain()
            data = await reader.read(100)
            writer.close()
            return data
        finally:
            await server.stop()
            store.close()

    assert b"501" in asyncio.run(scenario())
