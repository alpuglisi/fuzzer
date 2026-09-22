"""Real-browser regression for the rebuilt History panel (U3: proxy workbench
rebuild): a secret header is redacted at write time (`fuzzlab.proxy.redact`, unchanged
by this lane) and must still never reach the page even through the new shared
`<message-editor>` — and everything the editor puts in the DOM must land there via
`textContent`/property assignment, never `innerHTML`, so an HTML-special value in the
(unredacted) request line can't be interpreted as markup. Skipped without a browser.
"""

from __future__ import annotations

import glob
import threading
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.proxy.history import FlowRecord, HistoryWriter  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402

SECRET = "sk-live-topsecret-do-not-leak-0123456789"


def _seed(path):
    with Store(path) as store:
        run_id = store.start_run("proxy", "127.0.0.1")
        hw = HistoryWriter(store, run_id, batch_size=1)
        hw.record(FlowRecord(
            method="GET", url="http://127.0.0.1:8080/<b>x</b>?id=1", host="127.0.0.1",
            status=200, elapsed_ms=12.5, protocol="http/1.1",
            raw_request=("GET /<b>x</b>?id=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        f"Authorization: Bearer {SECRET}\r\n\r\n").encode("latin-1"),
            raw_response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
        hw.flush()


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
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def test_history_detail_redacts_secret_and_escapes_markup(tmp_path):
    path = tmp_path / "p.db"
    _seed(path)
    web_port = _free_port()
    cfg = load_config(overrides={"target_base_url": "http://127.0.0.1",
                                 "store_path": str(path)}, environ={})
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
            pg.goto(f"http://127.0.0.1:{web_port}/proxy")
            pg.locator("#flow-table tbody tr").first.wait_for(state="visible")
            pg.locator("#flow-table tbody tr").first.click()
            pg.locator("#flow-detail").wait_for(state="visible")
            req_pane = pg.locator("#flow-req-editor")
            req_pane.locator("pre.me-raw-view").wait_for(state="visible")
            body_text = pg.locator("body").inner_text()
            # the secret was never persisted, so it can never render
            assert SECRET not in body_text
            assert "__REDACTED__" in req_pane.inner_text()
            # markup in the (unredacted) request line must render as literal text,
            # not be parsed as an element — proof the editor never used innerHTML
            assert pg.locator("#flow-req-editor b").count() == 0
            assert "<b>x</b>" in req_pane.inner_text()
            browser.close()
    finally:
        server.stop()
