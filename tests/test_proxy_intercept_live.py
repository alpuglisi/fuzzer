"""Over-the-socket intercept integration (Phase 2.2): a real request through the
in-process AsyncProxyServer is paused, edited, forwarded, and reaches a fake
upstream with the edit — no browser, loopback only.
"""

from __future__ import annotations

import asyncio
import socket
import threading

from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController


def _start_threaded_upstream():
    """A blocking HTTP upstream in its own thread — echoes the request-target.

    It must be off the proxy's event loop: the proxy forwards through the *synchronous*
    SocketSender, which blocks that loop for the upstream round-trip, so an upstream on
    the same loop would deadlock (real upstreams are separate processes).
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            target = data.split(b" ")[1] if b" " in data else b"/"
            body = b"target=" + target
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%b"
                         % (len(body), body))
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


async def _run():
    up, up_port = _start_threaded_upstream()

    ctrl = ProxyController(ProxyConfig(host="127.0.0.1", port=0,
                                       scope_hosts=("127.0.0.1",), intercept=True))
    await ctrl.start()
    proxy_port = ctrl.server.port

    # Client → proxy: absolute-form request (as a proxy-configured client sends).
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(f"GET http://127.0.0.1:{up_port}/orig HTTP/1.1\r\n"
                 f"Host: 127.0.0.1:{up_port}\r\n\r\n".encode())
    await writer.drain()

    # The request is held; edit /orig → /edited and forward it.
    flow = None
    for _ in range(300):
        await asyncio.sleep(0.01)
        pv = ctrl.pending_view()
        if pv:
            flow = pv[0]
            break
    assert flow is not None and flow["direction"] == "request"
    edited = flow["raw"].replace("/orig", "/edited")
    assert ctrl.forward(flow["id"], edited) is True

    resp = await asyncio.wait_for(reader.read(4096), timeout=5)
    writer.close()
    await ctrl.stop()
    up.close()
    return resp


def test_live_intercept_edit_forward_reaches_upstream():
    resp = asyncio.run(_run())
    assert b"200 OK" in resp
    assert b"target=/edited" in resp        # upstream saw the edited request
    assert b"/orig" not in resp
