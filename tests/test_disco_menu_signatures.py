"""A menu of one element shape is explored past the same-signature cap once its entries
lead to different pages (FR-CRAWL-676, CC-CRAWL-0675, SP-130).

The explorer acts on the first `max_same_signature` occurrences of one element
signature: a long list of one shape is usually records of one template. An SPA menu
whose entries are href-less ``div``s shares one signature too, so a measured lab
(CC-LAB-0411: 23 menu entries, 3 opened) was mostly never reached. Now the outcomes
decide: once two occurrences led to states of different structures, the group is a menu
and its occurrences up to `max_menu_signature` are acted on; records whose clicks show
one template stay capped. An invented app; real Chromium and the capture proxy."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests._browser import skip_or_fail

SECTIONS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
RECORDS = list(range(1, 7))

PAGE = """<!doctype html><html><body>
<nav>%s</nav><ul>%s</ul><main id=m></main>
<script>
function panel(n){fetch('/api/panel/'+n).then(r=>r.text()).then(t=>{
  document.getElementById('m').innerHTML=t;});}
function rec(n){fetch('/api/record/'+n).then(r=>r.text()).then(t=>{
  document.getElementById('m').innerHTML=t;});}
</script></body></html>"""


class _App(BaseHTTPRequestHandler):
    hits: list = []

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html"):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        type(self).hits.append(self.path)
        if self.path == "/":
            nav = "".join(f"<div class=item onclick=\"panel('{s}')\">{s}</div>"
                          for s in SECTIONS)
            recs = "".join(f"<li class=rec onclick='rec({n})'>record {n}</li>"
                           for n in RECORDS)
            return self._send(PAGE % (nav, recs))
        if self.path.startswith("/api/panel/"):
            name = self.path.rsplit("/", 1)[1]
            # each section its own tool: a differently shaped panel
            return self._send(f"<h2>{name}</h2>" + "".join(
                f"<label>{name}{k}<input name={name}_{k}></label>"
                for k in range(SECTIONS.index(name) + 1)))
        if self.path.startswith("/api/record/"):
            n = self.path.rsplit("/", 1)[1]
            return self._send(f"<article><h3>Record {n}</h3><p>text {n}</p></article>")
        self.send_response(404)
        self.end_headers()


def test_a_menu_is_explored_past_the_cap_and_records_stay_capped(tmp_path):
    for mod in ("playwright.sync_api", "mitmproxy"):
        try:
            __import__(mod)
        except ImportError as exc:
            skip_or_fail(f"{mod} unavailable: {exc}")
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.disco.explore import Explorer, ExploreOptions
    from fuzzlab.disco.proxyproc import CaptureProxy
    _App.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        with CaptureProxy([url], out=tmp_path / "capture.jsonl", profile="anon") as proxy:
            try:
                report = Explorer(url, scope_urls=[url], proxy=proxy.endpoint,
                                  options=ExploreOptions(max_actions=60, deadline_s=240,
                                                         max_harvest=0),
                                  actions_log=tmp_path / "actions.jsonl").run()
            except PlaywrightError as exc:
                if "Executable doesn't exist" in str(exc) or "launch" in str(exc).lower():
                    skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
                raise
    finally:
        server.shutdown()
    panels = {h.rsplit("/", 1)[1] for h in _App.hits if h.startswith("/api/panel/")}
    records = {h.rsplit("/", 1)[1] for h in _App.hits if h.startswith("/api/record/")}
    assert panels == set(SECTIONS), panels             # past the cap of 2
    assert report.menu_signatures >= 1
    assert len(records) <= 2, records                  # one template: still capped
