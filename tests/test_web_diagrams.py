"""The diagrams page and API (FR-UI-510): read-only routes over a run's trace model, the
exports with their download headers, the text-only rendering of captured labels in a
real browser, evidence navigation, and the page updating while a scan writes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzlab.core import trace
from fuzzlab.core.config import load_config
from fuzzlab.core.store import Store
from fuzzlab.web.app import create_app
from tests._webclient import web_client

O = "http://127.0.0.1:9002"
XSS = '<img src=x onerror="window.__xss=1">'
STATIC = Path(__file__).resolve().parents[1] / "fuzzlab" / "web" / "static" / "js"


def _seed(path) -> int:
    with Store(path) as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run)
        rec.emit("run.start", {"origins": [O], "identity": "anonymous"}, key="run.start")
        rec.emit("observe.exchange", {"src": "capture", "ref": "record 0", "method": "GET",
                                      "url": O + "/a/" + XSS, "origin": O, "status": 200,
                                      "params": [["q", "query"]], "action": "act-1"},
                 key="c0", scope="workflow:act-1", t=1.0)
        rec.emit("test.start", {"test": "t1", "url": O + "/a/" + XSS, "origin": O,
                                "method": "GET", "param": "q", "location": "query",
                                "category": "xss"}, key="test.start:t1", scope="test:t1")
        x = rec.emit("exchange", {"test": "t1", "strategy": "xss:" + XSS,
                                  "role": "mutation", "method": "GET",
                                  "url": O + "/a/" + XSS, "origin": O, "param": "q",
                                  "value_preview": XSS, "outcome": "response",
                                  "status": 200}, scope="test:t1")
        rec.emit("test.strategy", {"test": "t1", "strategy": "xss:" + XSS,
                                   "outcome": "not_confirmed", "exchanges": [x]},
                 scope="test:t1")
        rec.emit("run.end", {"status": "complete"}, key="run.end")
        rec.close()
    return run


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "s.db"
    run = _seed(path)
    app = create_app(load_config(overrides={"store_path": str(path)}, environ={}))
    return web_client(app), run, path


def test_the_api_serves_the_model_scopes_sequences_and_evidence(client):
    c, run, _path = client
    assert c.get("/diagrams").status_code == 200
    runs = c.get("/api/diagram/runs").json()["runs"]
    assert runs[0]["id"] == run and runs[0]["state"] == "complete"
    model = c.get(f"/api/diagram/{run}/dataflow").json()
    assert {n["kind"] for n in model["nodes"]} >= {"actor", "origin", "interface"}
    assert all(f["view"] == "app" for f in model["flows"])
    overlay = c.get(f"/api/diagram/{run}/dataflow?overlay=true").json()
    assert any(f["view"] == "test" for f in overlay["flows"])
    scopes = [s["scope"] for s in c.get(f"/api/diagram/{run}/scopes").json()["scopes"]]
    assert "test:t1" in scopes and "workflow:act-1" in scopes
    seq = c.get(f"/api/diagram/{run}/sequence", params={"scope": "test:t1"}).json()
    key = next(s["evidence"][0] for s in seq["steps"] if s.get("kind") == "request")
    ev = c.get(f"/api/diagram/{run}/evidence", params={"ref": key}).json()
    assert ev["items"][0]["kind"] == "exchange"
    iface = next(n["id"] for n in model["nodes"] if n["kind"] == "interface")
    ev = c.get(f"/api/diagram/{run}/evidence", params={"ref": iface}).json()
    assert {i["kind"] for i in ev["items"]} == {"observe.exchange", "exchange"}


def test_exports_download_and_bad_requests_are_refused(client):
    c, run, _path = client
    r = c.get(f"/api/diagram/{run}/export.json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    doc = json.loads(r.text)
    assert doc["schema"] == "fuzzlab.diagram/1" and doc["nodes"][0]["evidence"]
    r = c.get(f"/api/diagram/{run}/export/flow.mmd")
    assert r.text.startswith("flowchart LR") and "<img" not in r.text
    r = c.get(f"/api/diagram/{run}/export/sequence.mmd", params={"scope": "test:t1"})
    assert r.text.startswith("sequenceDiagram") and "<img" not in r.text
    assert c.get(f"/api/diagram/{run}/sequence").status_code == 400
    assert c.get(f"/api/diagram/{run}/dataflow?knowledge=bogus").status_code == 400
    assert c.get(f"/api/diagram/{run}/finding/99").status_code == 404


def test_the_page_scripts_never_parse_html_strings():
    from tests.test_web_sitetree_browser import _offenders, _page_scripts
    template = (Path(__file__).resolve().parents[1] / "fuzzlab" / "web" / "templates"
                / "sections" / "diagrams.html").read_text()
    names = _page_scripts(template, lambda n: (STATIC / n).read_text())
    assert "diagrams.js" in names
    assert _offenders(names, lambda n: (STATIC / n).read_text()) == []


def test_the_page_renders_labels_as_text_navigates_evidence_and_updates_live(tmp_path):
    from playwright.sync_api import sync_playwright

    from tests._browser import Server, free_port, launch_browser_or_skip
    path = tmp_path / "s.db"
    run = _seed(path)
    port = free_port()
    cfg = load_config(overrides={"store_path": str(path), "web_port": port,
                                 "diagram_poll_ms": 400}, environ={})
    server = Server(create_app(cfg), port)
    server.start()
    errors: list[str] = []
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            page = browser.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{port}/diagrams")
            page.wait_for_selector("#dg-flow svg", state="attached")
            page.wait_for_selector("#dg-seq svg", state="attached")
            flow_text = page.text_content("#dg-flow")
            assert "<img" in flow_text                       # shown, as text
            assert page.locator("#diagrams-root img").count() == 0
            assert page.evaluate("window.__xss") is None
            assert "complete" in page.text_content("#dg-status-text")
            page.click("#dg-ifaces tbody tr")
            page.wait_for_selector("#dg-ev-list li")
            assert "observe.exchange" in page.text_content("#dg-ev-list")
            # a scan writes more while the page is open: it shows up without a reload
            with Store(path) as store:
                rec = trace.TraceRecorder(store, run)
                rec.emit("observe.exchange", {"src": "capture", "ref": "record 9",
                                              "method": "POST", "url": O + "/late",
                                              "origin": O, "status": 201}, t=2.0)
                rec.close()
            page.locator("#dg-ifaces").get_by_text("POST /late").wait_for(timeout=10000)
            browser.close()
    finally:
        server.stop()
    assert errors == []
    assert run == 1
