"""Shared real-browser harness for the web control panel's browser tests.

The panel's client JS and templates can only be verified in a real browser: no
`TestClient` test executes JS, applies the app's CSP, or renders a chart. Those tests
used to `importorskip("playwright")` at module level and skip when Chromium could not
launch — which is how every chart on the ML/Diagnostics tabs (BUG-0063) and every
CSP-blocked template construct (BUG-0064) shipped unseen: the browser tests were skipped
where the verifying run happened, and covered two pages only.

So (PA-0065):
* skips happen only when the real operation fails — Playwright not importable, the web
  extra missing, or an actual ``chromium.launch()`` failing (PA-0035), never on a proxy
  check;
* with ``FUZZLAB_REQUIRE_BROWSER=1`` every such skip is a **failure** instead. Set it
  whenever a run is meant to verify UI behavior (a change touching templates or static
  JS/CSS), so a missing browser cannot pass silently.
"""

from __future__ import annotations

import glob
import os
import socket
import threading
import time

import pytest

REQUIRE_ENV = "FUZZLAB_REQUIRE_BROWSER"


def browser_required() -> bool:
    return os.environ.get(REQUIRE_ENV, "") == "1"


def skip_or_fail(reason: str, *, module_level: bool = False):
    """Skip — or, under ``FUZZLAB_REQUIRE_BROWSER=1``, fail — with ``reason``."""
    if browser_required():
        pytest.fail(f"{REQUIRE_ENV}=1 but the browser test cannot run: {reason}",
                    pytrace=False)
    pytest.skip(reason, allow_module_level=module_level)


def require_modules(*, module_level: bool = True):
    """Import the web extra and Playwright, or skip/fail. Call at module top (before
    importing them), replacing ``pytest.importorskip``."""
    for mod in ("fastapi", "uvicorn", "playwright.sync_api"):
        try:
            __import__(mod)
        except ImportError as exc:
            skip_or_fail(f"{mod} unavailable: {exc}", module_level=module_level)


def launch_browser_or_skip(pw):
    """Launch real headless Chromium — the operator's ``PLAYWRIGHT_CHROMIUM_EXECUTABLE``
    if set, else Playwright's own default (the binary the product launches; BUG-0671:
    a path glob here once picked another binary, and stopped matching unnoticed) — and
    skip/fail only if no build actually launches (PA-0035: probe the real operation)."""
    candidates = [os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE") or None]
    errors = []
    for exe in candidates:
        kw = {"headless": True}
        if exe:
            kw["executable_path"] = exe
        try:
            return pw.chromium.launch(**kw)
        except Exception as exc:  # noqa: BLE001 - try the next build
            errors.append(f"{exe or 'bundled'}: {str(exc).splitlines()[0]}")
    skip_or_fail("chromium unavailable: " + "; ".join(errors))


#: The Chromium binaries a browser fact SP-01 relies on is measured on (BUG-0670,
#: PA-0670): Playwright's default headless launch -- the headless shell, the product's
#: binary unless the operator names one -- and the full Chromium of the same Playwright
#: build (``channel="chromium"``). They differ (measured: an empty-bodied 404 is a page
#: on the shell 157.0.8103.78, an error page on the full 153.0.8010.12).
CHROMIUM_BINARIES = {"shell": {}, "full": {"channel": "chromium"}}


def chromium_binary_kwargs(binary: str, kwargs: dict) -> dict:
    """``kwargs`` (from ``navguard.chromium_launch_kwargs``) launching ``binary`` of
    `CHROMIUM_BINARIES`: the operator's executable is dropped, so each binary is the one
    named."""
    out = {k: v for k, v in kwargs.items() if k != "executable_path"}
    out.update(CHROMIUM_BINARIES[binary])
    return out


def guarded_chromium(pw, binary: str, base: str):
    """``(browser, context, page)``: ``binary`` launched as the product launches it,
    one context guarded to ``base`` (``navguard.guard_page``); skip/fail when it does
    not launch. The caller releases the context and closes the browser."""
    from fuzzlab.tools import navguard
    kwargs = chromium_binary_kwargs(binary, navguard.chromium_launch_kwargs(
        navguard.browser_launch_args([base])))
    try:
        browser = pw.chromium.launch(**kwargs)
    except Exception as exc:  # noqa: BLE001 - a launch failure is no verdict
        skip_or_fail(f"chromium {binary} could not launch: {str(exc).splitlines()[0]}")
    ctx = browser.new_context()
    navguard.guard_page(ctx, in_scope=lambda u: u.startswith(base))
    return browser, ctx, ctx.new_page()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    """uvicorn in a daemon thread, stopped unconditionally by the caller."""

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
