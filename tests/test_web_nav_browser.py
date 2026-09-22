"""Real-browser nav smoke for the U0 MPA routes (real Chromium + uvicorn).

Minimal per the R-09 test strategy (docs/UI_IMPLEMENTATION_PLAN.md §7): assert
deep-link navigation to every section works and the sidebar's active-nav DOM state
(`aria-current="page"`) follows the current route — the one thing a route/no-JS
pytest layer (test_web_frontend.py) can't exercise directly. Skipped when
Playwright or a Chromium build isn't available, and tears the server down
unconditionally, mirroring test_web_launcher_browser.py's pattern.
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
from fuzzlab.web.app import NAV, create_app  # noqa: E402


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


# Derived from app.py's NAV (PA-0001) rather than a hand-maintained duplicate list.
SECTIONS = [(item["href"].lstrip("/"), item["id"]) for item in NAV]


def test_deep_link_and_active_nav_in_browser(tmp_path):
    port = _free_port()
    cfg = load_config(overrides={"target_base_url": "http://127.0.0.1",
                                 "store_path": str(tmp_path / "s.db")}, environ={})
    server = _Server(create_app(cfg), port)
    server.start()
    base = f"http://127.0.0.1:{port}/"
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

            for path, section_id in SECTIONS:
                # Deep-link straight to the section's URL (no client-side router
                # to prime first — this is the MPA payoff: every section is a
                # real, independently-loadable page).
                page.goto(base + path)
                current = page.locator('nav.tabs a[aria-current="page"]')
                current.wait_for(state="visible")
                assert current.get_attribute("data-section") == section_id
                # exactly one nav link is marked current
                assert page.locator('nav.tabs a[aria-current="page"]').count() == 1
                main = page.locator("main#main")
                assert main.get_attribute("data-section") == section_id

            # Following a real sidebar link (not a full reload) lands on the right
            # section too, with the nav updating to match.
            page.goto(base)
            page.click('nav.tabs a[data-section="results"]')
            page.wait_for_url(base + "results")
            assert page.locator('nav.tabs a[aria-current="page"]') \
                .get_attribute("data-section") == "results"

            browser.close()
    finally:
        server.stop()
