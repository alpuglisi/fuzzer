"""Real-browser regression for the Repeater CRLF fix (Phase 2.3).

Drives the Repeater UI (create a tab, edit the raw request in a <textarea>, Send) and
asserts the response streamed back from a threaded upstream — which only works if the
client restores CRLF that the textarea normalized to LF. Skipped without a browser.
"""

from __future__ import annotations

import glob
import socket
import threading
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402


def _threaded_upstream():
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
            body = b"echo=" + target
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%b" % (len(body), body))
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


def test_repeater_create_and_send_in_browser(tmp_path):
    up, up_port = _threaded_upstream()
    web_port = _free_port()
    cfg = load_config(overrides={"authorized": True, "target_base_url": "http://127.0.0.1",
                                 "store_path": str(tmp_path / "s.db")}, environ={})
    server = _Server(create_app(cfg), web_port)
    server.start()
    try:
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
            pg.goto(f"http://127.0.0.1:{web_port}/")
            pg.click('nav.tabs a[data-tab="proxy"]')
            pg.click("#repeater-card details summary")
            pg.fill("#rep-new-host", "127.0.0.1")
            pg.fill("#rep-new-port", str(up_port))
            pg.fill("#rep-new-raw",
                    f"GET /orig HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n\r\n")
            pg.click("#rep-create")
            pg.locator("#rep-editor").wait_for(state="visible")
            # edit the target in the textarea (which normalizes newlines to LF)
            pg.fill("#rep-raw", f"GET /edited HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n\r\n")
            pg.click("#rep-send")
            resp = pg.locator("#rep-resp")
            pg.wait_for_function("el => el.textContent.includes('echo=')",
                                 arg=resp.element_handle(), timeout=20000)
            assert "echo=/edited" in resp.inner_text()
            browser.close()
    finally:
        server.stop()
        up.close()
