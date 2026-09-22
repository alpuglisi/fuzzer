"""Real-browser smoke for the Findings workbench (U2): facet filtering,
quick-filter, and the DOM-safety requirement (R-03) that untrusted url/param
values never execute as markup. Skipped without Playwright/Chromium, mirroring
tests/test_web_nav_browser.py's pattern.
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
from fuzzlab.core.store import Store  # noqa: E402
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


def _seed(path):
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        rows = [
            ("sqli", "error-signature", "/product.php", "GET", "id"),
            ("xss-reflected", "reflected-marker", "/search.php", "GET", "q"),
            # A hostile payload: if this were ever rendered via innerHTML
            # instead of textContent, the alert would fire when the browser
            # loads the page — the test below asserts it does not.
            ("xss-stored", "dom-marker",
             "/comments.php\"><img src=x onerror=window.__xss_fired=true>",
             "POST", "body"),
        ]
        for vuln_class, mechanism, url, method, param in rows:
            store.conn.execute(
                "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, vuln_class, 1, mechanism, json.dumps({}), url, method, param))
        store.conn.commit()


def _launch_chromium(pw):
    found = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    launch_kw = {"headless": True}
    if found:
        launch_kw["executable_path"] = found[-1]
    try:
        return pw.chromium.launch(**launch_kw)
    except Exception as exc:  # noqa: BLE001 - no usable browser build here
        pytest.skip(f"chromium unavailable: {exc}")


def test_findings_workbench_facets_and_dom_safety(tmp_path):
    port = _free_port()
    db_path = tmp_path / "s.db"
    _seed(db_path)
    cfg = load_config(overrides={"target_base_url": "http://127.0.0.1",
                                 "store_path": str(db_path)}, environ={})
    server = _Server(create_app(cfg), port)
    server.start()
    base = f"http://127.0.0.1:{port}"
    try:
        with sync_playwright() as pw:
            browser = _launch_chromium(pw)
            page = browser.new_page()
            page.set_default_timeout(15000)
            page.goto(base + "/findings")

            # All three rows render.
            page.locator(".dt-row").first.wait_for(state="visible")
            assert page.locator(".dt-row").count() == 3

            # DOM safety: the hostile payload never executed as markup, and its
            # literal (unsafe) text is present as plain text, not live HTML.
            fired = page.evaluate("() => window.__xss_fired === true")
            assert fired is False
            assert "onerror=window.__xss_fired" in page.content()
            assert page.locator("script:has-text('onerror')").count() == 0

            # Quick-filter (debounced substring) narrows to one row.
            page.fill("#findings-quickfilter", "sqli")
            page.wait_for_timeout(350)  # clear the 200ms debounce
            page.wait_for_function(
                "document.querySelectorAll('.dt-row').length === 1")
            assert page.locator(".dt-row").count() == 1
            page.fill("#findings-quickfilter", "")
            page.wait_for_timeout(350)
            page.wait_for_function(
                "document.querySelectorAll('.dt-row').length === 3")

            # Facet sidebar: selecting a severity checkbox filters the table
            # and adds a chip; "Clear all" restores every row.
            severity_group = page.locator(".facet-group", has=page.locator(
                "summary:has-text('Severity')"))
            severity_group.locator("input[type=checkbox]").first.check()
            page.wait_for_function(
                "document.querySelectorAll('.dt-row').length < 3")
            assert page.locator("#filter-chips .filter-chip").count() >= 1
            page.click("#filter-chips button:has-text('Clear all')")
            page.wait_for_function(
                "document.querySelectorAll('.dt-row').length === 3")

            # Clicking a row navigates to its detail page (real MPA route).
            page.click(".dt-row")
            page.wait_for_url(lambda url: "/findings/" in url and url != base + "/findings")
            assert page.locator("h1").inner_text().startswith("Finding #")

            browser.close()
    finally:
        server.stop()


def test_saved_view_round_trips_through_the_ui(tmp_path):
    port = _free_port()
    db_path = tmp_path / "s.db"
    _seed(db_path)
    cfg = load_config(overrides={"target_base_url": "http://127.0.0.1",
                                 "store_path": str(db_path)}, environ={})
    server = _Server(create_app(cfg), port)
    server.start()
    base = f"http://127.0.0.1:{port}"
    try:
        with sync_playwright() as pw:
            browser = _launch_chromium(pw)
            page = browser.new_page()
            page.set_default_timeout(15000)
            page.on("dialog", lambda d: d.accept("my view"))
            page.goto(base + "/findings")
            page.locator(".dt-row").first.wait_for(state="visible")

            page.fill("#findings-quickfilter", "sqli")
            page.wait_for_timeout(350)
            page.click("#view-save")
            page.wait_for_function(
                "document.querySelectorAll('#views-chips .view-chip').length === 1")

            page.reload()
            page.locator(".dt-row").first.wait_for(state="visible")
            assert page.locator(".dt-row").count() == 3  # a fresh load has no filter
            page.click("#views-chips .view-chip button")
            page.wait_for_function(
                "document.querySelectorAll('.dt-row').length === 1")
            assert page.input_value("#findings-quickfilter") == "sqli"

            browser.close()
    finally:
        server.stop()
