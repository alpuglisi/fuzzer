"""End-to-end browser smoke for the Phase 1 launcher (real Chromium + uvicorn).

This is the one test that exercises the launcher's client JS — collecting form
values, the dry-run preview, and a real Run whose output streams over SSE (SSE
works against a real server, unlike the TestClient). Skipped when Playwright or a
Chromium build isn't available, and it tears the server down unconditionally.
"""

from __future__ import annotations

import socket
import threading
import time

from tests._browser import launch_browser_or_skip, require_modules

require_modules()   # skip — or fail under FUZZLAB_REQUIRE_BROWSER=1 (PA-0065)
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Server:
    def __init__(self, app, port):
        import uvicorn
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self):
        self._thread.start()
        for _ in range(100):
            if getattr(self._server, "started", False):
                return
            time.sleep(0.05)
        raise RuntimeError("uvicorn did not start")

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=5)


def _seed_flow(path):
    from fuzzlab.core.store import Store
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    with Store(path) as store:
        rid = store.start_run("proxy", "127.0.0.1")
        hw = HistoryWriter(store, rid, batch_size=1)
        hw.record(FlowRecord(
            method="GET", url="http://127.0.0.1:8080/product.php?id=1", host="127.0.0.1",
            status=200, elapsed_ms=9.0,
            raw_request=b"GET /product.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
        hw.flush()


def test_launcher_dry_run_and_run_in_browser(tmp_path):
    port = _free_port()
    store = tmp_path / "s.db"
    _seed_flow(store)                       # a recorded flow for the Proxy History tab
    cfg = load_config(overrides={"authorized": True,
                                 "target_base_url": "http://127.0.0.1",
                                 "store_path": str(store),
                                 # U6's Host allow-list is derived from web_host/web_port
                                 # (CC-UI-0026); must match the real bind port below.
                                 "web_port": port}, environ={})
    server = _Server(create_app(cfg), port)
    server.start()
    # Launcher moved off "/" to "/launcher" (U1/CC-UI-0028): "/" now renders the
    # Overview dashboard.
    base = f"http://127.0.0.1:{port}/launcher"
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            page = browser.new_page()
            page.set_default_timeout(15000)
            page.goto(base)

            report = 'form.launch-form[data-command="report"]'
            # Launch is a master-detail view: pick the activity to reveal its form.
            page.click('.actlist .act[data-for="report"]')
            page.locator(f"{report} [data-dest='store']").wait_for(state="visible")
            # Dry-run: preview shows the exact command, sends nothing. A typed --store is
            # overridden by the open project (FR-UI-456, CC-UI-0450): the job is pinned.
            page.fill(f"{report} [data-dest='store']", "x.db")
            page.click(f"{report} [data-action='dry-run']")
            preview = page.locator(f"{report} .launch-preview")
            preview.wait_for(state="visible")
            assert f"fuzzlab report --store {store}" in preview.inner_text()
            assert "x.db" not in preview.inner_text()

            # Run: report reads the (pinned) project and exits; its output must still
            # stream to completion over SSE.
            page.fill(f"{report} [data-dest='store']", "")
            page.click(f"{report} [data-action='run']")
            output = page.locator(f"{report} .launch-output")
            output.wait_for(state="visible")
            page.wait_for_function(
                "el => el.textContent.includes('[exit')",
                arg=output.element_handle(), timeout=20000)
            assert "[exit" in output.inner_text()

            # Proxy section (U0/CC-UI-0025): real navigation to /proxy, see the
            # seeded flow, open its detail.
            page.click('nav.tabs a[data-section="proxy"]')
            page.wait_for_url("**/proxy")
            row = page.locator("#flow-table tbody tr").first
            row.wait_for(state="visible")
            assert "/product.php" in row.inner_text()
            row.click()
            detail = page.locator("#flow-req")
            detail.wait_for(state="visible")
            assert "GET /product.php?id=1" in detail.inner_text()
            browser.close()
    finally:
        server.stop()
