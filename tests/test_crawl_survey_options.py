"""The crawler survey options the owner chose (docs/CRAWLER_SURVEY_2026-10-16.md):
option 2 (CC-CRAWL-0035), option 3 (CC-CRAWL-0036), option 5 (CC-CRAWL-0037) and
option 6 (CC-CRAWL-0038). Option 1's tests sit with the write baseline's in
`tests/test_spa_query.py`. Every server here is a loopback test server."""

from __future__ import annotations

import time

from tests._spa_fixture import _Lab, chromium_or_skip


# =====================================================================================
# Option 2: a settle does not wait for realtime transports (CC-CRAWL-0035)
# =====================================================================================
def _hang(seconds, ctype):
    def answer(handler):
        handler.send_response(200)
        handler.send_header("Content-Type", ctype)
        handler.end_headers()
        handler.wfile.flush()
        time.sleep(seconds)                     # held open, as a long-poll or a stream
        try:
            handler.wfile.write(b"data: x\n\n" if "event-stream" in ctype else b"ok")
        except OSError:
            pass
    return answer


def _slow(handler):
    time.sleep(0.8)
    handler._send(200, "application/json", b'{"ok":true}')


class _LongPollLab(_Lab):
    """A page whose ``go()`` opens what never settles -- an engine.io long-poll (GET),
    a socket.io polling GET on another transport query, an event stream -- and one slow
    app request a settle must wait for."""
    index = ("<!doctype html><html><head><title>lp</title></head><body><script>"
             "window.done = false;"
             "window.go = () => {"
             " fetch('/socket.io/?EIO=4&transport=polling&t=1').catch(() => {});"
             " fetch('/rt/?EIO=3&transport=polling').catch(() => {});"
             " new EventSource('/stream');"
             " fetch('/api/slow').then(r => r.json()).then(() => { window.done = true; });"
             "};</script></body></html>")
    responders = {"/socket.io/": _hang(6, "text/plain"), "/rt/": _hang(6, "text/plain"),
                  "/stream": _hang(6, "text/event-stream"), "/api/slow": _slow}


def test_a_settle_waits_for_the_apps_request_but_not_for_a_long_poll_or_a_stream(
        monkeypatch, tmp_path):
    """Real Chromium: the request counter `_track` keeps leaves out socket.io /
    engine.io polling and an event stream, so `_settle` returns once the app's own slow
    request has finished (it is still waited for), not at its 5 s budget."""
    from playwright.sync_api import sync_playwright

    from fuzzlab.tools.navguard import browser_launch_args, chromium_launch_kwargs
    from fuzzlab.tools.spider import LocalSpider
    from tests._browser import skip_or_fail
    chromium_or_skip(monkeypatch)
    lab = _LongPollLab()
    sp = LocalSpider(lab.base, db_name=str(tmp_path / "s.db"), engine="requests",
                     timeout_ms=10000)
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(
                    **chromium_launch_kwargs(browser_launch_args([lab.base])))
            except Exception as exc:  # noqa: BLE001 - a launch failure is a skip
                skip_or_fail(f"chromium could not launch: {exc}")
            try:
                page = browser.new_page()
                sp._track(page)
                page.goto(lab.base, wait_until="load")
                page.evaluate("() => window.go()")
                start = time.monotonic()
                sp._settle(page)
                took = time.monotonic() - start
                assert page.evaluate("() => window.done") is True   # the app's request
                assert took < 3.0, took                             # not the budget
                assert sp._inflight[id(page)] == 0
                assert lab.seen("GET", "/socket.io/") and lab.seen("GET", "/stream")
            finally:
                browser.close()
    finally:
        sp.storage.close()
        lab.close()


def test_what_a_settle_does_not_wait_for():
    """Unit: the predicate, by URL and request type; an unreadable request is waited
    for (fail towards waiting)."""
    from fuzzlab.tools.spider import _background_request

    def req(url, rtype="fetch"):
        return type("R", (), {"url": url, "resource_type": rtype})()

    class Broken:
        @property
        def url(self):
            raise RuntimeError("gone")
    assert _background_request(req("http://h/socket.io/?EIO=4&transport=polling"))
    assert _background_request(req("http://h/x/engine.io/"))
    assert _background_request(req("http://h/rt?EIO=3&transport=polling"))
    assert _background_request(req("http://h/stream", "eventsource"))
    assert _background_request(req("ws://h/live", "websocket"))
    assert not _background_request(req("http://h/api/socket"))
    assert not _background_request(req("http://h/rest/products?transport=car"))
    assert not _background_request(req("http://h/main.js", "script"))
    assert not _background_request(Broken())
