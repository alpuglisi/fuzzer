"""PUT and PATCH (FR-FUZZ-56): a ground truth may enumerate them (never DELETE); `auto`
probes them only with `--fuzz-json-writes`, the opt-in crawled PUT/PATCH requests already
need; a stored-XSS case plants through the store request its ground truth enumerates
(method and JSON body), checked on a real browser against an app whose chat accepts
only a JSON PUT."""

from __future__ import annotations

import glob
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.labels import contract

API = "http://localhost:8080"


def _write(tmp_path, cases, points):
    (tmp_path / "labels.json").write_text(json.dumps(
        {"version": 1, "target": "t", "cases": cases}))
    (tmp_path / "injection-points.json").write_text(json.dumps(
        {"version": 1, "target": "t", "points": points}))
    rows = ["case_id,url,method,param,location,category,expected_vulnerable,"
            "primary_endpoint,primary_role,related_endpoints,flow_variant"]
    rows += [f"{c['case_id']},{c['url']},{c['method']},{c['param']},{c['location']},"
             f"{c['vuln_class']},{str(c['expected_vulnerable']).lower()},{c['url']},"
             f"sink,,direct" for c in cases]
    (tmp_path / "expectedresults.csv").write_text("\n".join(rows) + "\n")


def _stored(**kw):
    return {"case_id": "TC-0001", "url": "/play/streamer", "method": "GET",
            "param": "content", "location": "body", "vuln_class": "xss-stored",
            "sink_context": "html", "expected_vulnerable": True, "rendering": "js",
            "source_url": API + "/live/1/messages", **kw}


def _negative(url="/live", method="GET"):
    return {"case_id": "TC-0002", "url": url, "method": method, "param": "q",
            "location": "query", "vuln_class": "sqli", "sink_context": "sql",
            "expected_vulnerable": False, "rendering": "server-json", "origin": API}


def _put_point(method="PUT", **kw):
    return {"url": "/live/1/messages", "origin": API, "method": method,
            "param": "content", "location": "body", "rendering": "server-json",
            "json_body": {"username": "fuzzlab", "content": "hello"}, **kw}


def test_a_ground_truth_admits_put_and_patch_and_refuses_delete(tmp_path):
    _write(tmp_path, [_stored(), _negative("/live/1/messages", "PATCH")],
           [_put_point(), _put_point("PATCH", param="username")])
    gt = contract.load(tmp_path)
    assert {p.method for p in gt.points} == {"PUT", "PATCH"}
    _write(tmp_path, [_stored(), _negative("/live/1/messages", "DELETE")], [_put_point()])
    with pytest.raises(contract.ContractError):
        contract.load(tmp_path)


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
def test_a_put_or_patch_point_is_probed_only_with_writes(tmp_path, method):
    from fuzzlab.harness.auto import points_from_ground_truth
    _write(tmp_path, [_stored(), _negative()], [_put_point(method)])
    gt = contract.load(tmp_path)
    points, skipped = points_from_ground_truth(gt, "http://127.0.0.1:10007/")
    assert points == []
    assert (("/live/1/messages", method, "content",
             f"{method} probed only with --fuzz-json-writes")) in skipped
    (p,), _skipped = points_from_ground_truth(gt, "http://127.0.0.1:10007/", writes=True)
    assert (p.url, p.method, p.location) == (API + "/live/1/messages", method, "json")
    assert dict(p.base_entries) == {("username",): "fuzzlab", ("content",): "hello"}


def test_a_dom_point_with_another_method_is_skipped_never_rewritten_into_a_get(tmp_path):
    """BUG-0115: a DOM point is a GET page; another method is not relocated."""
    from fuzzlab.harness.auto import points_from_ground_truth
    _write(tmp_path, [_negative()], [_put_point(rendering="js")])
    gt = contract.load(tmp_path)
    points, skipped = points_from_ground_truth(gt, "http://h/", browser_available=True,
                                               writes=True)
    assert points == [] and skipped[0][3] == "a DOM point is a GET page, not PUT"


def test_a_stored_case_plants_through_the_store_request_its_ground_truth_enumerates(
        tmp_path):
    from fuzzlab.harness.auto import points_from_ground_truth
    _write(tmp_path, [_stored(), _negative()], [_put_point()])
    gt = contract.load(tmp_path)
    stored, skipped = points_from_ground_truth(gt, "http://127.0.0.1:10007/",
                                               browser_available=True)
    assert stored == [] and any("--fuzz-json-writes" in s[3] for s in skipped)
    points, _ = points_from_ground_truth(gt, "http://127.0.0.1:10007/",
                                         browser_available=True, writes=True)
    (sp,) = [p for p in points if p.store_url]
    assert sp.url == "http://127.0.0.1:10007/play/streamer"
    assert (sp.store_url, sp.store_method, sp.store_location) == \
        (API + "/live/1/messages", "PUT", "json")
    assert dict(sp.store_entries) == {("username",): "fuzzlab", ("content",): "hello"}


def test_a_stored_case_without_an_enumerated_store_point_stays_a_form_post(tmp_path):
    from fuzzlab.harness.auto import points_from_ground_truth
    _write(tmp_path, [_stored(source_url="/edit"), _negative()], [_put_point()])
    points, _ = points_from_ground_truth(contract.load(tmp_path), "http://h/",
                                         browser_available=True, writes=True)
    (sp,) = [p for p in points if p.store_url]
    assert (sp.store_method, sp.store_location, sp.store_entries) == ("POST", "body", None)


def test_the_store_request_reaches_the_candidate(tmp_path):
    """The auditor's evidence carries the store request to the oracle's candidate."""
    from fuzzlab.audit import InjectionPoint
    from fuzzlab.audit.engine import evaluate
    from fuzzlab.audit.rules import load_rules
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import _candidate_of
    point = InjectionPoint(url="http://h/play/s", param="content", method="GET",
                           location="body", store_url=API + "/live/1/messages",
                           store_param="content", store_method="PUT", store_location="json",
                           store_entries=((("username",), "u"), (("content",), "hi")),
                           origin="ground-truth")
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        evaluate([point], store, run, load_rules())
        evs = [json.loads(r["evidence"]) for r in store.conn.execute(
            "SELECT evidence FROM candidate WHERE run_id = ?", (run,))]
    (ev,) = [e for e in evs if e["category"] == "xss"]
    cand = _candidate_of(ev)
    assert (cand.store_method, cand.store_location) == ("PUT", "json")
    assert [(tuple(p), v) for p, v in cand.store_entries] == \
        [(("username",), "u"), (("content",), "hi")]


@pytest.mark.parametrize("store", [
    dict(method="DELETE", location="body"),           # never a store method
    dict(method="PUT", location="query"),             # a query store is a GET
    dict(method="PUT", location="json", entries=((("username",), "u"),)),  # no leaf
])
def test_the_executor_refuses_an_unplaceable_store_request_before_any_browser(store):
    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    obs = PlaywrightBrowserExecutor().run(ExecRequest(url="http://h/a", store=StoreStep(
        url="http://h/s", param="content", value="v", **store)), "t")
    assert not obs.executed and "unplaceable store" in obs.detail


# --- real browser: a chat that only takes a JSON PUT ----------------------------------
class _Chat(BaseHTTPRequestHandler):
    """``PUT /api/messages`` (JSON ``{username, content}``; anything else is refused);
    ``/page`` renders every stored message's content through ``innerHTML``."""
    messages: list = []
    methods: list = []

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", ctype="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        type(self).methods.append("PUT")
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path != "/api/messages" or \
                self.headers.get("Content-Type") != "application/json":
            return self._send(415)
        msg = json.loads(body)
        if set(msg) != {"username", "content"}:
            return self._send(400)
        type(self).messages.append(msg)
        self._send(200, body, "application/json")

    def do_POST(self):
        type(self).methods.append("POST")
        self._send(405)

    def do_GET(self):
        if self.path == "/api/messages":
            return self._send(200, json.dumps(type(self).messages).encode(),
                              "application/json")
        if self.path == "/page":
            return self._send(200, b"<div id=m></div><script>fetch('/api/messages')"
                                   b".then(r => r.json()).then(ms => ms.forEach(x => {"
                                   b"const p = document.createElement('p');"
                                   b"p.innerHTML = x.content;"
                                   b"document.getElementById('m').appendChild(p);}))"
                                   b"</script>")
        self._send(404)


def test_stored_xss_through_a_json_put_is_confirmed_on_a_real_browser(monkeypatch):
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import StoredXssStrategy
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _Chat.messages, _Chat.methods = [], []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Chat)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    entries = ((("username",), "fuzzlab"), (("content",), "hello"))
    try:
        cand = Candidate(url=base + "/page", param="content", category="xss",
                         store_url=base + "/api/messages", store_param="content",
                         store_method="PUT", store_location="json", store_entries=entries)
        verdict = StoredXssStrategy(PlaywrightBrowserExecutor()).confirm(cand, None)
        form = Candidate(url=base + "/page", param="content", category="xss",
                         store_url=base + "/api/messages", store_param="content")
        missed = StoredXssStrategy(PlaywrightBrowserExecutor()).confirm(form, None)
    finally:
        server.shutdown()
    if verdict is None and not _Chat.messages:
        skip_or_fail("chromium could not run the store step")
    assert verdict is not None and verdict.confirmed and verdict.vuln_class == "xss-stored"
    assert all(m["username"] == "fuzzlab" for m in _Chat.messages)   # siblings kept
    # the old form POST never reaches this store: no verdict, not a false one
    assert missed is None and "POST" in _Chat.methods



def _write_method_literals(root):
    """``path:line`` of every set/tuple/list literal naming PUT and PATCH but not
    DELETE under ``root``, outside the owner (SP-41)."""
    import ast
    from pathlib import Path
    out = []
    for path in sorted(Path(root).rglob("*.py")):
        if path.as_posix().endswith("fuzzlab/tools/store_adapter.py"):
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
                names = {getattr(e, "value", None) for e in node.elts}
                if {"PUT", "PATCH"} <= names and "DELETE" not in names:
                    out.append(f"{path.name}:{node.lineno}")
    return out


def test_the_write_opt_in_methods_are_defined_once():
    """SP-41: the methods `--fuzz-json-writes` gates are `store_adapter.WRITE_METHODS`,
    read by the importer, the ground-truth point builder and the M6 store step."""
    assert _write_method_literals("fuzzlab") == []


def test_the_write_methods_guard_catches_a_synthetic_offender(tmp_path):
    (tmp_path / "rogue.py").write_text('M = frozenset({"POST", "PUT", "PATCH"})\n'
                                       'W = {"POST", "PUT", "PATCH", "DELETE"}\n')
    assert _write_method_literals(tmp_path) == ["rogue.py:1"]
