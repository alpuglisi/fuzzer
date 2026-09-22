"""Real-browser regression for the rebuilt Intercept panel (U3: proxy workbench
rebuild). Drives a real request through the in-process `AsyncProxyServer`, holds it,
edits the raw bytes through the shared `<message-editor>`'s Raw <textarea> (the same
component Repeater uses), and Forwards it — asserting the edit reaches a real upstream
byte-exact. This is the at-risk path the U3 plan calls out explicitly: a <textarea>
normalizes newlines to LF, so the edited request only survives if `toWire` (js/http.js)
restores CRLF before the forward POST, exactly as it did before the front-end rebuild.
Skipped without a browser.
"""

from __future__ import annotations

import glob
import json
import socket
import threading
import time
import urllib.request

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController  # noqa: E402


def _threaded_upstream():
    """A blocking HTTP upstream that echoes the request-target it received."""
    srv = socket.socket()
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


class _Server:
    def __init__(self, app, port):
        import uvicorn
        self._s = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                                log_level="error"))
        self._t = threading.Thread(target=self._s.run, daemon=True)

    def start(self):
        self._t.start()
        for _ in range(100):
            if getattr(self._s, "started", False):
                return
            time.sleep(0.05)
        raise RuntimeError("uvicorn did not start")

    def stop(self):
        self._s.should_exit = True
        self._t.join(timeout=5)


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def _get_json(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def test_intercept_edit_and_forward_in_browser(tmp_path):
    up, up_port = _threaded_upstream()
    web_port = _free_port()
    cfg = load_config(overrides={"target_base_url": "http://127.0.0.1",
                                 "store_path": str(tmp_path / "s.db")}, environ={})
    ctrl = ProxyController(ProxyConfig(host="127.0.0.1", port=0,
                                       scope_hosts=("127.0.0.1",), intercept=True))
    ctrl.build()   # engine + interceptor; the app's lifespan starts the listener
    server = _Server(create_app(cfg, proxy=ctrl), web_port)
    server.start()
    try:
        status = _get_json(f"http://127.0.0.1:{web_port}/api/proxy/status")
        assert status["running"] is True
        proxy_port = status["port"]

        captured = {}

        def send_through_proxy():
            s = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
            s.sendall(f"GET http://127.0.0.1:{up_port}/orig HTTP/1.1\r\n"
                      f"Host: 127.0.0.1:{up_port}\r\n\r\n".encode())
            captured["resp"] = s.recv(4096)
            s.close()

        client_thread = threading.Thread(target=send_through_proxy, daemon=True)
        client_thread.start()

        with sync_playwright() as pw:
            found = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
            kw = {"headless": True}
            if found:
                kw["executable_path"] = found[-1]
            try:
                browser = pw.chromium.launch(**kw)
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"chromium unavailable: {exc}")
            pg = browser.new_page()
            pg.set_default_timeout(15000)
            pg.goto(f"http://127.0.0.1:{web_port}/proxy")
            pg.click("#subtab-intercept")
            pg.locator("#panel-intercept").wait_for(state="visible")
            pg.check("#intercept-on")
            # wait for the held request to appear
            pg.locator("#pending-table tbody tr").first.wait_for(state="visible", timeout=10000)
            pg.locator("#pending-table tbody tr").first.click()
            pg.locator("#pending-detail").wait_for(state="visible")
            edit = pg.locator("#pending-editor textarea.me-raw-edit")
            current = edit.input_value()
            assert "/orig" in current            # byte-exact from the wire, unmodified
            edit.fill(current.replace("/orig", "/edited"))
            pg.click("#pending-forward")
            browser.close()

        client_thread.join(timeout=10)
        assert b"target=/edited" in captured.get("resp", b"")
    finally:
        server.stop()
        up.close()
