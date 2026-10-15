"""Capture-and-abort egress (DISC-CAPTURE §2, FR-CRAWL-18, NFR-CRAWL-safe): under a crawl
with capture on, **zero non-GET requests** reach a real loopback server from any egress
shape a page can use. The server counts every request it receives by method.

Real Chromium (`run_crawl`): every skip is a failure under ``FUZZLAB_REQUIRE_BROWSER=1``
(PA-0065). The shapes are synthetic, technology-generic pages (no lab's routes, names or
code). Measured in Chromium 1194 / Playwright 1.63 before this was designed
(MULTI_AGENT_ORCHESTRATION §7): without the init script, a ``sendBeacon`` and a
``keepalive`` fetch made on ``pagehide`` and ``fetchLater`` reach the server without
passing the context route; a **SharedWorker**'s fetch is never routed at all (pinned
below as a strict xfail: that shape is not closed).
"""

from __future__ import annotations

import pytest

from tests._spa_fixture import _Lab, chromium_or_skip, db_rows, run_crawl

#: Every shape page links to /next, so the crawl navigates away (``pagehide`` fires).
_NEXT = "<a href='/next'>next</a>"
_POST = "fetch('/sink/{n}', {{method: 'POST', body: 'x=1'}}).catch(() => {{}});"

#: shape -> (page HTML, the sink path the crawl must have recorded, or None)
SHAPES = {
    "fetch": ("<script>" + _POST.format(n="fetch") + "</script>", "/sink/fetch"),
    "xhr": ("<script>var x = new XMLHttpRequest(); x.open('POST', '/sink/xhr');"
            "x.send('a=1');</script>", "/sink/xhr"),
    "form-post": ("<form id=f method=post action='/sink/form'><input name=a value=1>"
                  "</form><script>f.submit()</script>", "/sink/form"),
    "form-post-blank": ("<form id=f method=post target=_blank action='/sink/blank'>"
                        "<input name=a value=1></form><script>f.submit()</script>",
                        "/sink/blank"),
    "form-post-iframe": ("<iframe name=t></iframe><form id=f method=post target=t "
                         "action='/sink/frame'><input name=a value=1></form>"
                         "<script>f.submit()</script>", "/sink/frame"),
    "beacon-pagehide": ("<script>navigator.sendBeacon('/sink/beacon-load', 'b=1');"
                        "addEventListener('pagehide', () => {"
                        "navigator.sendBeacon('/sink/beacon-hide', 'b=2');"
                        "fetch('/sink/keepalive', {method: 'POST', body: 'k=1', "
                        "keepalive: true}); });</script>", "/sink/beacon-load"),
    "keepalive-request": ("<script>addEventListener('pagehide', () => fetch(new Request("
                          "'/sink/keepalive-req', {method: 'POST', body: 'k=2', "
                          "keepalive: true})));</script>", None),
    "fetch-later": ("<script>try { fetchLater('/sink/later', {method: 'POST', "
                    "body: 'f=1', activateAfter: 0}); } catch (e) {}</script>", None),
    "websocket": ("<script>var w = new WebSocket('ws://' + location.host + '/ws');"
                  "w.onopen = () => w.send('hello-capture');</script>", None),
    "worker": ("<script>new Worker('/worker.js');</script>", "/sink/worker"),
    "event-source": ("<script>new EventSource('/events');</script>", None),
    "redirect-307": ("<script>fetch('/r307', {method: 'POST', body: 'r=1'})"
                     ".catch(() => {});</script>", "/r307"),
    "graphql-mutation": ("<script>fetch('/graphql', {method: 'POST', headers: "
                         "{'Content-Type': 'application/json'}, body: JSON.stringify("
                         "{query: 'mutation M { add(x: 1) { id } }'})}).catch(() => {});"
                         "</script>", "/graphql"),
    "stream-body": ("<script>try { fetch('/sink/stream', {method: 'POST', duplex: 'half', "
                    "body: new ReadableStream({start(c) { c.enqueue(new TextEncoder()"
                    ".encode('s=1')); c.close(); }})}).catch(() => {}); } catch (e) {}"
                    "</script>", "/sink/stream"),
    "multipart-file": ("<script>var fd = new FormData(); fd.append('note', 'v');"
                       "fd.append('doc', new File(['data'], 'a.txt', {type: 'text/plain'}));"
                       "fetch('/sink/upload', {method: 'POST', body: fd})"
                       ".catch(() => {});</script>", "/sink/upload"),
}
SHARED_WORKER = ("<script>var s = new SharedWorker('/shared.js'); s.port.start();</script>",
                 None)


class EgressLab(_Lab):
    """A loopback server that records every request (``requests``: method, path, ...)
    and every WebSocket text frame (``ws_messages``)."""

    def __init__(self, shape_html: str):
        self.pages = {"/": "<!doctype html><title>s</title>" + shape_html + _NEXT,
                      "/next": "<!doctype html><title>n</title><p>next</p>"}
        self.responders = {
            "/worker.js": lambda h: h._send(200, "application/javascript",
                                            _POST.format(n="worker").encode()),
            "/shared.js": lambda h: h._send(200, "application/javascript",
                                            (_POST.format(n="shared")
                                             + "onconnect = e => {};").encode()),
            "/events": lambda h: h._send(200, "text/event-stream", b"data: hi\n\n"),
            "/r307": self._redirect,
        }
        super().__init__()

    @staticmethod
    def _redirect(h):
        h.send_response(307)
        h.send_header("Location", "/sink/after-307")
        h.send_header("Content-Length", "0")
        h.end_headers()

    def writes(self) -> list:
        return [(m, p) for m, p, *_rest in self.requests if m not in ("GET", "HEAD")]


def _crawl_shape(monkeypatch, tmp_path, html):
    from fuzzlab.tools.spider import LocalSpider
    chromium_or_skip(monkeypatch)
    lab = EgressLab(html)
    db = str(tmp_path / "s.db")
    try:
        sp = LocalSpider(lab.base, max_depth=1, db_name=db, engine="playwright",
                         timeout_ms=5000)
        run_crawl(sp)
        return lab, sp, db
    finally:
        lab.close()


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_no_write_reaches_the_server_from_any_egress_shape(shape, monkeypatch, tmp_path):
    html, recorded = SHAPES[shape]
    lab, sp, db = _crawl_shape(monkeypatch, tmp_path, html)
    assert lab.writes() == [], (shape, lab.writes())
    assert lab.ws_messages == []                       # a page-to-server frame: held
    gets = [p for m, p, *_r in lab.requests if m == "GET"]
    assert "/next" in gets                              # the crawl left the page
    if recorded is not None:                            # not vacuous: the shape fired
        urls = [u for (u,) in db_rows(db, "SELECT url FROM discovered_requests")]
        assert any(u.endswith(recorded) for u in urls), (shape, urls)
    if shape == "websocket":
        assert ("hello-capture",) in db_rows(db, "SELECT head FROM ws_dropped")
    if shape == "beacon-pagehide":
        assert sp.spa_counts["beacons_recorded"] >= 1
    if shape == "stream-body":
        assert sp.spa_counts["body_unavailable"] >= 1   # post_data_buffer None: aborted
    if shape == "multipart-file":
        (body,) = db_rows(db, "SELECT body_json FROM discovered_requests WHERE url "
                              "LIKE '%/sink/upload'")[0]
        assert "data" not in body and "a.txt" not in body   # names and types only
        assert '"note"' in body and '"doc"' in body


@pytest.mark.xfail(strict=True, reason=(
    "measured (Chromium 1194, Playwright 1.63): a SharedWorker's fetch is never routed "
    "by the context route and the init script does not run in workers, so its POST "
    "reaches the server; this egress shape is NOT closed by capture-and-abort "
    "(reported, DISC-CAPTURE §2)"))
def test_a_shared_workers_write_never_reaches_the_server(monkeypatch, tmp_path):
    lab, _sp, _db = _crawl_shape(monkeypatch, tmp_path, SHARED_WORKER[0])
    assert lab.writes() == []


def test_the_shared_worker_page_is_measured_to_send(monkeypatch, tmp_path):
    """Non-vacuity for the xfail above: the write the shared worker makes is what reaches
    the server (and the only one)."""
    lab, _sp, _db = _crawl_shape(monkeypatch, tmp_path, SHARED_WORKER[0])
    assert lab.writes() == [("POST", "/sink/shared")]


# =====================================================================================
# Admission through crawl, import and auto (FR-FUZZ-52, D67), on a real server
# =====================================================================================
_APP = ("<script>fetch('/api/notes', {method: 'POST', headers: {'Content-Type': "
        "'application/json'}, body: JSON.stringify({title: 'hello'})}).catch(() => {});"
        "</script>")


@pytest.mark.parametrize("opt_out", [False, True])
def test_a_captured_write_is_probed_by_default_and_never_with_the_opt_out(
        opt_out, monkeypatch, tmp_path):
    """D67: the crawl sends no write (both cases); ``auto`` then probes the recorded
    write by default through its send gates, and with ``--no-probe-captured-writes``
    sends it nothing and reports it skipped."""
    import contextlib

    import requests

    from fuzzlab.core.store import Store
    from fuzzlab.harness.auto import CAPTURED_WRITE_OPT_OUT, run_auto
    from fuzzlab.tools import store_adapter
    from fuzzlab.tools.probesender import RequestsProbeSender
    from fuzzlab.tools.spider import LocalSpider
    chromium_or_skip(monkeypatch)
    lab = EgressLab(_APP)
    try:
        sp = LocalSpider(lab.base, max_depth=1, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=5000)
        run_crawl(sp)
        assert lab.writes() == []                                  # the crawl: none
        with Store(str(tmp_path / "u.db")) as store, \
                contextlib.closing(requests.Session()) as session:
            run = store.start_run("crawler", "h")
            store_adapter.import_spider(str(tmp_path / "s.db"), store, run)
            assert store.conn.execute(
                "SELECT source FROM endpoint WHERE url = '/api/notes'").fetchone()[0] \
                == "captured-aborted"
            result = run_auto(base_url=lab.base, store=store, run_id=run,
                              sender=RequestsProbeSender(session=session), mode="manual",
                              selected_categories=["sql-injection"],
                              points_source="crawl", probe_captured_writes=not opt_out)
        posts = [w for w in lab.writes() if w == ("POST", "/api/notes")]
    finally:
        lab.close()
    skipped = result.metrics["skipped_points"]
    funnel = _funnel_row(tmp_path / "u.db", opt_out)
    if opt_out:
        assert posts == []
        assert ("/api/notes", "POST", "title", CAPTURED_WRITE_OPT_OUT) in skipped
        assert funnel["refused"] == CAPTURED_WRITE_OPT_OUT and not funnel["buildable"]
    else:
        assert posts                                   # probed (D67)
        assert not [s for s in skipped if s[0] == "/api/notes"]
        # BUG-0151 / PA-0157: the funnel reads the store this real run produced; the
        # oracle ran the candidate (auto writes no attempt rows), so it is probed
        assert funnel["discovered"] and funnel["buildable"]
        assert funnel["stage"] in ("probed", "confirmed"), funnel


def _funnel_row(store_path, opt_out):
    """`scripts/funnel_report.py`'s row for the captured write, read from a store a real
    crawl, import and `auto` run produced (PA-0157)."""
    import importlib.util
    from pathlib import Path

    from fuzzlab.labels.contract import Case
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("funnel_report",
                                                  root / "scripts" / "funnel_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    case = Case(case_id="C1", url="/api/notes", method="POST", param="title",
                location="json", vuln_class="sqli", sink_context="sql",
                expected_vulnerable=True, rendering="server")
    (row,) = mod.funnel(str(store_path), None, cases=[case],
                        probe_captured_writes=not opt_out)
    return row
