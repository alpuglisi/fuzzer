"""Real-browser chart smoke for the ML tab (U4; R-09 layer C).

Asserts uPlot-backed chart content through the shipped `window.__charts` hook (post-
downsample arrays) and the offscreen `<table class="chart-fallback">` a11y fallback —
never canvas pixels, per the R-09 test strategy. Skipped when Playwright or a Chromium
build isn't available, and tears the server down unconditionally, mirroring
test_web_launcher_browser.py / test_web_nav_browser.py's pattern.
"""

from __future__ import annotations

import glob
import json
import socket
import threading
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import MetricLogger, Store  # noqa: E402
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


def _seed(path) -> None:
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "sql-injection", 1, "error-signature", "{}",
             "/product.php", "GET", "id"))
        store.conn.execute(
            "INSERT INTO candidate (run_id, evidence, score) VALUES (?,?,?)",
            (run_id, json.dumps({"url": "/product.php", "param": "id",
                                 "category": "sql-injection"}), 0.91))
        store.conn.execute(
            "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
            (run_id, "ml_pr_auc", 0.8))
        store.conn.execute(
            "INSERT INTO model (name, version, feature_version, calibration) "
            "VALUES (?,?,?,?)",
            ("logistic", 1, 1, json.dumps({"alpha": 0.1, "t_lo": 0.2, "t_hi": 0.8})))
        store.conn.execute(
            "INSERT INTO bandit_posteriors (context, arm, alpha, beta, cost_sum, "
            "cost_n) VALUES (?,?,?,?,?,?)",
            ("sql-injection:query", "error-signature", 6.0, 2.0, 12.0, 4))
        store.conn.commit()
        with MetricLogger(store, run_id, "logreg") as ml:
            for step, loss in enumerate((0.9, 0.6, 0.4, 0.35), start=1):
                ml.log("train/loss", step, loss)


def test_ml_charts_render_and_expose_window_charts_hook(tmp_path):
    path = tmp_path / "s.db"
    _seed(path)
    port = _free_port()
    cfg = load_config(overrides={"target_base_url": "http://127.0.0.1",
                                 "store_path": str(path)}, environ={})
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
            page.goto(f"http://127.0.0.1:{port}/ml")

            # the training-loss chart is guaranteed to mount from this seed
            page.wait_for_function(
                "() => window.__charts && window.__charts.has('classifier-loss')")
            data = page.evaluate(
                "() => window.__charts.get('classifier-loss').getData()")
            assert data[0] == [1, 2, 3, 4]          # steps, post-LTTB (well under 1000pt)
            assert data[1] == [0.9, 0.6, 0.4, 0.35]  # values, unchanged (no downsampling)

            # the offscreen a11y table fallback carries the same content, never relying
            # on canvas pixels — present but not visible (R-09/R-11)
            table = page.locator(
                "#chart-classifier-loss table.chart-fallback")
            table.wait_for(state="attached")
            assert not table.is_visible()
            cell = table.locator("tbody tr").first.locator("td").nth(1)
            assert cell.inner_text() == "0.9"

            # bandit posterior density also mounted (multiple Beta-pdf line series)
            page.wait_for_function(
                "() => window.__charts && window.__charts.has('bandit-density')")
            bandit_data = page.evaluate(
                "() => window.__charts.get('bandit-density').getData()")
            assert len(bandit_data) == 2   # [xs, one arm's density] for this single-arm seed
            browser.close()
    finally:
        server.stop()
