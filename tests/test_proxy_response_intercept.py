"""Engine-level intercept tests incl. the Phase 2.2 response hook."""

from __future__ import annotations

import asyncio

from fuzzlab.proxy.intercept import Interceptor
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.server import ProxyEngine

REQ = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"


def _scope():
    return Scope().include("h")


async def _wait_pending(icp, direction, tries=200):
    for _ in range(tries):
        await asyncio.sleep(0)
        hit = [f for f in icp.pending() if f.direction == direction]
        if hit:
            return hit[0]
    raise AssertionError(f"no pending {direction}")


def test_request_edit_and_forward():
    async def go():
        seen = {}

        def sender(host, port, tls, raw):
            seen["req"] = raw
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

        icp = Interceptor(enabled=True)
        eng = ProxyEngine(scope=_scope(), sender=sender, interceptor=icp)
        task = asyncio.create_task(eng.handle_request(REQ, "h", 80))
        flow = await _wait_pending(icp, "request")
        icp.forward(flow.id, RawMessage.from_bytes(b"GET /edited HTTP/1.1\r\nHost: h\r\n\r\n"))
        resp = await task
        assert b"/edited" in seen["req"]
        assert resp.startswith(b"HTTP/1.1 200")
    asyncio.run(go())


def test_request_drop_sends_nothing():
    async def go():
        def sender(*a):
            raise AssertionError("a dropped request must not be forwarded")

        icp = Interceptor(enabled=True)
        eng = ProxyEngine(scope=_scope(), sender=sender, interceptor=icp)
        task = asyncio.create_task(eng.handle_request(REQ, "h", 80))
        flow = await _wait_pending(icp, "request")
        icp.drop(flow.id)
        assert await task is None
    asyncio.run(go())


def test_response_not_held_by_default():
    async def go():
        def sender(*a):
            return b"HTTP/1.1 200 OK\r\n\r\n"

        icp = Interceptor(enabled=True)           # responses off by default
        eng = ProxyEngine(scope=_scope(), sender=sender, interceptor=icp)
        task = asyncio.create_task(eng.handle_request(REQ, "h", 80))
        req = await _wait_pending(icp, "request")
        icp.forward(req.id)
        resp = await task                          # no second pause; passthrough byte-exact
        assert resp == b"HTTP/1.1 200 OK\r\n\r\n"
        assert icp.pending() == []
    asyncio.run(go())


def test_response_edit_when_enabled():
    async def go():
        def sender(*a):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

        icp = Interceptor(enabled=True, intercept_responses=True)
        eng = ProxyEngine(scope=_scope(), sender=sender, interceptor=icp)
        task = asyncio.create_task(eng.handle_request(REQ, "h", 80))
        icp.forward((await _wait_pending(icp, "request")).id)
        resp_flow = await _wait_pending(icp, "response")
        icp.forward(resp_flow.id,
                    RawMessage.from_bytes(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
        resp = await task
        assert resp.startswith(b"HTTP/1.1 403")
    asyncio.run(go())


def test_response_drop_when_enabled():
    async def go():
        def sender(*a):
            return b"HTTP/1.1 200 OK\r\n\r\n"

        icp = Interceptor(enabled=True, intercept_responses=True)
        eng = ProxyEngine(scope=_scope(), sender=sender, interceptor=icp)
        task = asyncio.create_task(eng.handle_request(REQ, "h", 80))
        icp.forward((await _wait_pending(icp, "request")).id)
        icp.drop((await _wait_pending(icp, "response")).id)
        assert await task is None
    asyncio.run(go())
