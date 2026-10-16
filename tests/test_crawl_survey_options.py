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


# =====================================================================================
# Option 3: a write the window refused is recorded, never sent (CC-CRAWL-0036)
# =====================================================================================
def test_the_route_tells_the_hook_what_the_window_refused_and_still_aborts():
    """`make_route_handler(on_window_refused=)` is told each refused request (before
    any fetch); an allowed one is not; a failing hook never changes the abort."""
    from fuzzlab.tools import spa
    from fuzzlab.tools.navguard import make_route_handler
    from tests.test_forms_phase4 import _Route
    told = []
    handler = make_route_handler(in_scope=lambda u: True,
                                 window=spa.window_request_refusal,
                                 on_window_refused=told.append)
    post, get = _Route("http://h/api/x", method="POST"), _Route("http://h/rest/x")
    handler(post)
    handler(get)
    assert told == [post.request]
    assert (post.outcome, post.fetched, get.outcome) == ("abort", [], "fulfill")

    def boom(_req):
        raise RuntimeError("hook failed")
    handler = make_route_handler(in_scope=lambda u: True,
                                 window=spa.window_request_refusal, on_window_refused=boom)
    post = _Route("http://h/api/x", method="POST")
    handler(post)
    assert (post.outcome, post.fetched) == ("abort", [])


def _req(url, method="POST", body=b'{"q":"x"}', ctype="application/json"):
    return type("R", (), {"url": url, "method": method, "post_data_buffer": body,
                          "headers": {"content-type": ctype}})()


def test_what_a_blocked_write_records(tmp_path):
    """`_note_window_blocked`: a JSON or form write is recorded with source
    ``blocked`` through the capture boundary (a password blanked, a probe marker
    scrubbed); a read, a transport, a body-less write and a probe load's refusals are
    not."""
    import json

    from fuzzlab.tools import spa
    from fuzzlab.tools.spider import BLOCKED_SOURCE, LocalSpider
    sp = LocalSpider("http://127.0.0.1:9/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    marker = spa.mint_markers(1)[0]
    try:
        sp._current_url = "http://127.0.0.1:9/#/search"
        sp._note_window_blocked(_req("http://127.0.0.1:9/api/search",
                                     body=json.dumps({"q": marker, "page": {"n": 1},
                                                      "password": "s3cret"}).encode()))
        sp._note_window_blocked(_req("http://127.0.0.1:9/api/revealpost", body=b"v=1",
                                     ctype="application/x-www-form-urlencoded"))
        sp._note_window_blocked(_req("http://127.0.0.1:9/api/x", method="GET"))
        sp._note_window_blocked(_req("http://127.0.0.1:9/socket.io/?EIO=4&t=1"))
        sp._note_window_blocked(_req("http://127.0.0.1:9/api/empty", body=None))
        sp._probe = {"blocked": set(), "requests": []}
        sp._note_window_blocked(_req("http://127.0.0.1:9/api/probe"))
        sp._probe = None
        rows = sp.storage.cursor.execute(
            "SELECT method, url, content_type, body_json, source FROM discovered_requests "
            "ORDER BY id").fetchall()
    finally:
        sp.storage.close()
    assert [(m, u, s) for m, u, _c, _b, s in rows] == [
        ("POST", "http://127.0.0.1:9/api/search", BLOCKED_SOURCE),
        ("POST", "http://127.0.0.1:9/api/revealpost", BLOCKED_SOURCE)]
    body = json.loads(rows[0][3])
    assert body["password"] == "" and body["page"] == {"n": 1}
    assert marker not in rows[0][3]
    assert json.loads(rows[1][3]) == {"v": "1"} and rows[1][2] == \
        "application/x-www-form-urlencoded"
    assert sp.spa_counts["requests_blocked_recorded"] == 2


def test_a_reveals_blocked_writes_are_recorded_never_sent_and_imported(monkeypatch,
                                                                        tmp_path):
    """Real Chromium, `PostRevealSpa` (a reveal click that auto-submits a POST form: a
    POST navigation the window refuses) and `RevealSpa` (a menu click that POSTs JSON):
    neither write reaches the server; both are recorded as ``blocked`` requests; the
    form one is imported as a body point under the import's usual rules."""
    import json

    from tests._spa_fixture import PostRevealSpa, RevealSpa, db_rows
    from tests.test_forms_phase4 import _crawl
    from tests.test_spa_query import _import, _params
    chromium_or_skip(monkeypatch)
    for lab_cls, path in ((PostRevealSpa, "/api/revealpost"),
                          (RevealSpa, "/api/reveal-post")):
        lab = lab_cls()
        tmp = tmp_path / lab_cls.__name__
        tmp.mkdir()
        try:
            sp, db, _logs = _crawl(lab, tmp)
        finally:
            lab.close()
        assert not [r for r in lab.requests if r[1].startswith(path)], path   # unsent
        rows = db_rows(db, "SELECT method, url, body_json, source FROM "
                           "discovered_requests WHERE url LIKE '%" + path + "'")
        assert rows and rows[0][0] == "POST" and rows[0][3] == "blocked", path
        assert sp.spa_counts["requests_blocked_recorded"] >= 1
        if lab_cls is PostRevealSpa:
            assert json.loads(rows[0][2]) == {"v": "1"}
            store, run, counts = _import(db, tmp / "u.db")
            try:
                assert ("/api/revealpost", "v", "body") in _params(store, run)
                assert counts["request_blocked"] >= 1
            finally:
                store.close()
        else:
            assert json.loads(rows[0][2]) == {"opened": True}


# =====================================================================================
# Option 5: the signature sees a nested body's shape; non-secret headers kept
# (CC-CRAWL-0037)
# =====================================================================================
def test_two_bodies_of_different_nested_shapes_are_two_requests(tmp_path):
    """The signature is the body's leaf paths: same top-level keys with different
    nested shapes are two rows; the same shape with other values, or a longer array, is
    a duplicate; a form body still dedups on its names."""
    from fuzzlab.tools.spider import StorageManager, _leaf_paths
    st = StorageManager(str(tmp_path / "s.db"))
    url, ct, rec = "http://h/api/order", "application/json", st.record_request
    try:
        assert rec("http://h/", "POST", url, ct, b'{"a":{"b":1}}', "passive") is None
        assert rec("http://h/", "POST", url, ct, b'{"a":{"c":1}}', "passive") is None
        assert rec("http://h/", "POST", url, ct, b'{"a":{"b":2}}', "passive") == "duplicate"
        assert rec("http://h/", "POST", url, ct, b'{"l":[{"x":1}]}', "passive") is None
        assert rec("http://h/", "POST", url, ct, b'{"l":[{"x":1},{"x":2}]}',
                   "passive") == "duplicate"
        form = "application/x-www-form-urlencoded"
        assert rec("http://h/", "POST", url, form, b"q=1&n=2", "passive") is None
        assert rec("http://h/", "POST", url, form, b"n=5&q=9", "passive") == "duplicate"
    finally:
        st.close()
    assert _leaf_paths({"a": {"b": 1, "c": []}, "d": [1, {"e": "x"}]}) == [
        ["a", "b"], ["a", "c"], ["d", "[]"], ["d", "[]", "e"]]
    assert _leaf_paths({}) == [] and _leaf_paths([]) == []


def test_only_allowlisted_non_secret_headers_are_kept():
    """`core.redaction.redact_captured_headers`: Content-Type (media type and
    charset), Accept, X-Requested-With and non-sensitive ``x-`` headers are kept; a
    cookie, an Authorization, a sensitively named header (``x-csrf-token``,
    ``x-api-key``) or an identifier-like value is withheld by name; the browser's own
    headers are not recorded; anything unreadable keeps nothing."""
    from fuzzlab.core.redaction import redact_captured_headers as redact
    out = redact({"Content-Type": "application/json; charset=UTF-8",
                  "Accept": "application/json", "X-Requested-With": "XMLHttpRequest",
                  "X-Api-Version": "2", "Cookie": "token=eyJhbGciOi.x.y",
                  "Authorization": "Bearer eyJhbGciOi.x.y", "X-CSRF-Token": "abc",
                  "X-Api-Key": "k", "X-User-Id": "4716190207394368",
                  "User-Agent": "Mozilla/5.0", "Referer": "http://h/#/basket?id=7"})
    assert out == {"kept": {"accept": "application/json",
                            "content-type": "application/json; charset=utf-8",
                            "x-api-version": "2", "x-requested-with": "XMLHttpRequest"},
                   "withheld": ["authorization", "cookie", "x-api-key", "x-csrf-token",
                                "x-user-id"]}
    assert redact({"content-type": "multipart/form-data; boundary=----WebKitFormBoundary"
                                   "7MA4YWxkTrZu0gW"})["kept"] == \
        {"content-type": "multipart/form-data"}
    assert redact({"content-type": "<b>"}) == {"kept": {}, "withheld": ["content-type"]}
    assert redact({"x-long": "a" * 201}) == {"kept": {}, "withheld": ["x-long"]}
    for junk in (None, 5, "text", {"x-a": 1}):
        assert redact(junk)["kept"] == {}


def test_a_captured_requests_headers_are_stored_redacted_and_an_old_db_gains_the_column(
        tmp_path):
    """The row's ``headers_json`` holds what `redact_captured_headers` keeps, never a
    credential value; a spider DB from before CC-CRAWL-0037 gains the column."""
    import json
    import sqlite3

    from fuzzlab.tools.spider import StorageManager
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE discovered_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "page_url TEXT, method TEXT, url TEXT, content_type TEXT, body_json TEXT, "
                "source TEXT, signature TEXT UNIQUE)")
    con.commit()
    con.close()
    st = StorageManager(db)
    try:
        assert st.record_request("http://h/", "POST", "http://h/api/x", "application/json",
                                 b'{"q":"a"}', "passive",
                                 headers={"authorization": "Bearer s3cr3tT0kenValue123",
                                          "x-app": "web"}) is None
        (raw,) = st.cursor.execute("SELECT headers_json FROM discovered_requests").fetchone()
    finally:
        st.close()
    assert json.loads(raw) == {"kept": {"x-app": "web"}, "withheld": ["authorization"]}
    assert "s3cr3t" not in raw
