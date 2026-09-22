"""Real-browser smoke for the Diagnostics charts (U5, R-09 layer C).

Asserts chart content through the shipped `window.__charts` hook (post-
downsample/smoothing arrays per chart id, per the R-12 registry contract) and
the offscreen `<table>` fallback -- never canvas pixels. Skipped when
Playwright or a Chromium build isn't available, and tears the server down
unconditionally, mirroring test_web_nav_browser.py's pattern.
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
from fuzzlab.core.store import Store, log_scalar  # noqa: E402
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


def _seed(store_path):
    with Store(store_path) as store:
        run_id = store.start_run("gbt", "cfg-1")
        for step in range(40):
            log_scalar(store, run_id, "gbt", "train/loss", step, 1.0 / (step + 1))


def test_charts_expose_window_charts_and_offscreen_table(tmp_path):
    store_path = str(tmp_path / "s.db")
    _seed(store_path)
    port = _free_port()
    cfg = load_config(overrides={"target_base_url": "http://127.0.0.1",
                                 "store_path": store_path}, environ={})
    server = _Server(create_app(cfg), port)
    server.start()
    try:
        with sync_playwright() as pw:
            found = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
            launch_kw = {"headless": True}
            if found:
                launch_kw["executable_path"] = found[-1]
            try:
                browser = pw.chromium.launch(**launch_kw)
            except Exception as exc:  # noqa: BLE001 - no usable browser build here
                pytest.skip(f"chromium unavailable: {exc}")
            page = browser.new_page()
            page.set_default_timeout(15000)
            page.goto(f"http://127.0.0.1:{port}/diagnostics")

            # window.__charts is populated once the chart wrapper has run
            expect_charts = page.wait_for_function(
                "() => window.__charts && window.__charts.size > 0")
            assert expect_charts

            chart_ids = page.evaluate("() => Array.from(window.__charts.keys())")
            assert "chart-0" in chart_ids

            data = page.evaluate(
                "(id) => window.__charts.get(id).getData()", "chart-0")
            assert data["mode"] == "line"
            assert len(data["series"][0]["y"]) == 40

            # the offscreen fallback table for the same chart is populated too
            rows = page.locator("#table-chart-0 tbody tr")
            assert rows.count() > 0

            # the uPlot canvas root is hidden from the accessibility tree; the
            # chart wrapper's role="img" element is the a11y-facing surface
            chart_el = page.locator("#el-chart-0")
            assert chart_el.get_attribute("role") == "img"

            browser.close()
    finally:
        server.stop()
