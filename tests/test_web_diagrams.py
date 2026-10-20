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
from fuzzlab.report import diagram
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
    for bad in ("finding:abc", "nosuch:1"):                 # never a 500
        assert c.get(f"/api/diagram/{run}/sequence?scope={bad}").status_code == 400
        assert c.get(f"/api/diagram/{run}/export/sequence.mmd?scope={bad}"
                     ).status_code == 400
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
            # the application box opens its own evidence (BUG-0518)
            page.locator("#dg-flow text.head", has_text="Target application").click()
            page.locator("#dg-ev-list").get_by_text("run.start").first.wait_for(
                timeout=10000)
            # an origin found later is listed; choosing one keeps every origin listed
            other = "http://127.0.0.1:9003"
            with Store(path) as store:
                rec = trace.TraceRecorder(store, run)
                rec.emit("observe.exchange", {"src": "capture", "ref": "record 10",
                                              "method": "GET", "url": other + "/x",
                                              "origin": other, "status": 200}, t=3.0)
                rec.close()
            page.locator(f"#dg-origin option[value='{other}']").wait_for(
                state="attached", timeout=10000)
            polls = _dg_count(page, "polls")
            page.select_option("#dg-origin", O)
            _dg_reach(page, "polls", polls + 2)               # two polls (D8: no sleep)
            values = page.eval_on_selector_all("#dg-origin option",
                                               "els => els.map(e => e.value)")
            assert values == ["", O, other]
            browser.close()
    finally:
        server.stop()
    assert errors == []
    assert run == 1


# --- a finding's deep link (FR-UI-513) ---------------------------------------------------
def _bad_link(param: str) -> str:
    return (f"bad diagram link: {param} must be given once, as a whole number from 1 to "
            f"{diagram.MAX_LINK_ID}\n")


def test_a_deep_link_is_validated_and_never_reflected(tmp_path):
    """The oracle for the link's validation: a malformed or incomplete link is a 400 whose
    body is the fixed message (so no value can be reflected); a well-formed link that
    does not hold applies nothing and says why, in fixed text; a valid link carries
    exactly the run, the finding and its scope to the page script."""
    from tests._finding_runs import pipeline_runs, recorded_finding
    path = tmp_path / "s.db"
    (run, fid), (untraced, ufid) = pipeline_runs(path, tmp_path, traced=(True, False))
    with Store(path) as store:
        lost_run, lost_fid = recorded_finding(store, event=False)
    c = web_client(create_app(load_config(overrides={"store_path": str(path)},
                                          environ={})))
    bad_values = ["abc", "0", "01", "-1", "+1", "1.0", "", " 1", "1 ", "1e3", "١",
                  str(diagram.MAX_LINK_ID + 1), "9" * 40, XSS]
    cases = [([("run", str(run))], "finding"), ([("finding", str(fid))], "run"),
             ([("run", str(run)), ("run", str(run)), ("finding", str(fid))], "run"),
             ([("run", str(run)), ("finding", str(fid)), ("finding", str(fid))],
              "finding")]
    cases += [([("run", v), ("finding", str(fid))], "run") for v in bad_values]
    cases += [([("run", str(run)), ("finding", v)], "finding") for v in bad_values]
    for params, param in cases:
        r = c.get("/diagrams", params=params)
        assert r.status_code == 400 and r.text == _bad_link(param), (params, r.text)
        assert r.headers["content-type"].startswith("text/plain")
    foreign = {(untraced, fid): f"finding #{fid} belongs to another run",
               (run, 10 ** 9): "no such finding in the open project",
               (untraced, ufid): "its run has no trace (recorded before diagrams, or "
                                 "with --no-trace)",
               (lost_run, lost_fid): "its trace event was not recorded"}
    for (r_id, f_id), why in foreign.items():
        page = c.get("/diagrams", params={"run": r_id, "finding": f_id})
        assert page.status_code == 200
        assert (f"The link to run #{r_id}, finding #{f_id} was not applied: {why}."
                in page.text)
        assert "data-link-" not in page.text
    page = c.get("/diagrams", params={"run": run, "finding": fid})
    assert page.status_code == 200 and 'id="dg-link-notice"' not in page.text
    assert (f'data-link-run="{run}" data-link-finding="{fid}"\n  '
            f'data-link-scope="finding:{fid}"') in page.text
    plain = c.get("/diagrams").text                     # no link: nothing applied
    assert "data-link-" not in plain and 'id="dg-link-notice"' not in plain


def test_the_deep_link_builder_and_parser_agree():
    for r, f in ((1, 7), (7, 1), (diagram.MAX_LINK_ID, diagram.MAX_LINK_ID)):
        link = diagram.finding_deep_link(r, f)
        assert link == f"/diagrams?run={r}&finding={f}"
        query = [tuple(p.split("=")) for p in link.split("?", 1)[1].split("&")]
        assert diagram.parse_deep_link(query) == (r, f)
    for r, f in ((0, 1), (1, 0), (diagram.MAX_LINK_ID + 1, 1), (True, 1), ("1", 1)):
        with pytest.raises(ValueError):
            diagram.finding_deep_link(r, f)
    assert diagram.parse_deep_link([("other", "x")]) is None


def test_a_finding_link_opens_exactly_its_run_sequence_and_data_flow(tmp_path):
    """From the Findings page, a finding with a trace opens exactly its run (one the run
    list's 200 newest leave out), its sequence and its filtered data flow; a finding
    without one says so and has no link. The run and the finding stay through a reload
    the store's writes cause, until the operator chooses another run."""
    from urllib.parse import quote

    from playwright.sync_api import sync_playwright

    from tests._browser import Server, free_port, launch_browser_or_skip
    from tests._finding_runs import pipeline_runs
    path = tmp_path / "s.db"
    (run_a, fid), (run_c, fid_c) = pipeline_runs(path, tmp_path, traced=(True, False))

    def traced_run(**event) -> int:
        with Store(path) as store:
            rid = store.start_run("auto", "h")
            rec = trace.TraceRecorder(store, rid)
            rec.emit("run.start", {"origins": [O]}, key="run.start")
            if event:
                rec.emit("observe.exchange", event, t=1.0)
            rec.close()
        return rid

    for _ in range(200):                     # run A is beyond the run list's 200 newest
        traced_run()
    (run_b, _fid_b), = pipeline_runs(path, tmp_path, traced=(True,))
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
            base = f"http://127.0.0.1:{port}"
            # 1. the Findings page: a link for A's finding only
            page.goto(base + "/findings")
            row_a = page.locator(f'#findings-table tr[data-row-id="{fid}"]')
            row_c = page.locator(f'#findings-table tr[data-row-id="{fid_c}"]')
            row_c.wait_for()
            assert "No diagram: run #%d has no trace" % run_c in row_c.inner_text()
            assert row_c.locator('a[href^="/diagrams"]').count() == 0
            link = row_a.locator('a[href^="/diagrams"]')
            assert link.count() == 1
            assert link.get_attribute("href") == f"/diagrams?run={run_a}&finding={fid}"
            # 2. it opens exactly that run, the finding's sequence and its data flow
            link.click()
            page.wait_for_url(f"**/diagrams?run={run_a}&finding={fid}")
            page.locator("#dg-seq text", has_text=f"finding {fid} created").first.wait_for(
                timeout=10000)
            assert page.input_value("#dg-run") == str(run_a)
            assert page.input_value("#dg-scope") == f"finding:{fid}"
            assert page.input_value("#dg-finding") == str(fid)
            assert page.is_checked("#dg-overlay")
            assert page.locator("#dg-flow path.dg-flow").count() >= 1
            # 3. a write reloads the runs: the linked run stays, though not listed
            new = traced_run()
            page.locator(f"#dg-run option[value='{new}']").wait_for(state="attached",
                                                                    timeout=10000)
            assert page.input_value("#dg-run") == str(run_a)
            assert page.input_value("#dg-scope") == f"finding:{fid}"
            # 4. the operator chooses another run: the link is released, and a later
            # write's reload shows that run's whole data flow, not the linked finding's
            page.select_option("#dg-run", str(run_b))
            page.locator("#dg-status-text", has_text=f"Run {run_b}:").wait_for(
                timeout=10000)
            with Store(path) as store:
                b_origin = store.conn.execute(
                    "SELECT label FROM dg_entity WHERE run_id=? AND kind='origin'",
                    (run_b,)).fetchone()["label"]
                rec = trace.TraceRecorder(store, run_b)
                rec.emit("observe.exchange", {"src": "capture", "ref": "record 99",
                                              "method": "GET", "url": b_origin + "/late-b",
                                              "origin": b_origin, "status": 200}, t=2.0)
                rec.close()
            page.locator("#dg-ifaces").get_by_text("GET /late-b").wait_for(timeout=10000)
            assert page.input_value("#dg-run") == str(run_b)
            assert page.input_value("#dg-finding") == ""
            # 5. smoke check only (the 400 matrix of the test above is the oracle): a
            # hostile run is refused, a foreign pair is named, and nothing runs
            resp = page.goto(f"{base}/diagrams?run={quote(XSS)}&finding={fid}")
            assert resp.status == 400 and "<img" not in resp.text()
            page.goto(f"{base}/diagrams?run={run_a}&finding={fid_c}")
            page.locator("#dg-link-notice").wait_for()
            assert "belongs to another run" in page.text_content("#dg-link-notice")
            assert page.evaluate("window.__xss") is None
            assert page.locator("#diagrams-root img").count() == 0
            browser.close()
    finally:
        server.stop()
    assert errors == []


def _capped_reads(text: str) -> list[str]:
    """Reads of a model attribute's length in page script: the attributes keep at most
    `MAX_ATTR_VALUES` values, so a count must come from the coverage (BUG-0519 sweep)."""
    import re
    return re.findall(r"attrs\.\w+(?:\s*\|\|\s*\[\])?\)?\.length", text)


def test_the_page_never_counts_a_capped_attribute():
    assert _capped_reads((STATIC / "diagrams.js").read_text()) == []
    assert _capped_reads("const finds = (k.attrs.finding || []).length;") != []



# --- a live refresh keeps the user's place (FR-UI-514, CC-UI-0068, BUG-0534) ------------
# Synchronised by the page's counters (`#diagrams-root` data-baseline, -polls, -refreshes:
# D8), never by sleeping; each test asserts its refresh happened.

@pytest.fixture(scope="module")
def live(tmp_path_factory):
    from playwright.sync_api import sync_playwright

    from tests._browser import Server, free_port, launch_browser_or_skip
    path = tmp_path_factory.mktemp("dglive") / "s.db"
    run = _seed(path)
    port = free_port()
    cfg = load_config(overrides={"store_path": str(path), "web_port": port,
                                 "diagram_poll_ms": 400}, environ={})
    server = Server(create_app(cfg), port)
    server.start()
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            yield {"base": f"http://127.0.0.1:{port}", "browser": browser, "path": path,
                   "run": run, "n": [0]}
            browser.close()
    finally:
        server.stop()


def _dg_count(page, name: str) -> int:
    return page.eval_on_selector("#diagrams-root",
                                 f"r => parseInt(r.dataset.{name} || '0', 10)")


def _dg_reach(page, name: str, n: int) -> None:
    page.wait_for_function(
        "([k, n]) => parseInt(document.querySelector('#diagrams-root').dataset[k] || '0', "
        "10) >= n", arg=[name, n], timeout=15000)


def _dg_page(live):
    ctx = live["browser"].new_context()
    page = ctx.new_page()
    page.set_default_timeout(15000)
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(live["base"] + "/diagrams")
    page.wait_for_function("() => document.querySelector('#diagrams-root')"
                           ".dataset.baseline === '1'")
    page.select_option("#dg-scope", "workflow:act-1")   # a capture: request, forward,
    page.locator("#dg-seq g.dg-step").nth(3).wait_for()  # two responses on one key
    page.wait_for_selector("#dg-flow svg", state="attached")
    return ctx, page, errors


def _dg_write(live, before: bool = False) -> str:
    """A capture record in the run (another connection of the server's process); its
    interface's label. ``before``: on a new origin, at a path and in act-1 at a time that
    sort before everything already there (entity ids sort by origin, then method and
    path; ``http://127.0.0.1:9000`` < ``:9001``... as text) -- a new origin group,
    interface row and first step, ahead of whatever is focused."""
    live["n"][0] += 1
    n = live["n"][0]
    with Store(live["path"]) as store:
        rec = trace.TraceRecorder(store, live["run"])
        if before:
            early = f"http://127.0.0.1:{9001 - n}"
            rec.emit("observe.exchange", {"src": "capture", "ref": f"record {100 + n}",
                                          "method": "GET", "url": early + f"/0early{n}",
                                          "origin": early, "status": 200,
                                          "action": "act-1"},
                     key=f"early{n}", scope="workflow:act-1", t=0.5 - n / 1000)
        else:
            rec.emit("observe.exchange", {"src": "capture", "ref": f"record {100 + n}",
                                          "method": "POST", "url": O + f"/late{n}",
                                          "origin": O, "status": 201}, t=5.0 + n)
        rec.close()
    return f"GET /0early{n}" if before else f"POST /late{n}"


#: the focused control's identity: its focus key and what it shows (a row's first cell,
#: a box's or step's title, a link's text, a select's id), never its position
_DG_IDENTITY = """() => { const a = document.activeElement;
  const title = a.querySelector && a.querySelector('title');
  const label = a.tagName === 'SELECT' ? a.id : a.tagName === 'TR' ? a.cells[0].textContent
    : title ? title.textContent.split('\\n')[0] : a.textContent;
  return [a.tagName, a.getAttribute('data-focus-key') || a.id, label]; }"""


_DG_TARGETS = {
    "interface row": "#dg-ifaces tbody tr[tabindex]",
    "origin group": "#dg-flow g[role=button]",
    "response step": "#dg-seq g.dg-step >> nth=2",
    "export link": "#dg-exports a >> nth=0",
    "run select": "#dg-run",
    "scope select": "#dg-scope",
}


@pytest.mark.parametrize("where", ["after", "before"])
@pytest.mark.parametrize("kind", list(_DG_TARGETS))
def test_a_live_refresh_keeps_focus_on_every_kind_of_control(live, kind, where):
    """E6: the Diagrams page's refresh re-renders its regions; focus fell from 4 of 6
    control kinds to <body> (the selects kept it). Each kind keeps focus on the same
    control. The write sorts after the focused control, or before it -- a new origin
    group, interface row and first step ahead of the focused one (blocker 3): the
    control is matched by identity (its key and what it shows), never by position."""
    ctx, page, errors = _dg_page(live)
    try:
        target = page.locator(_DG_TARGETS[kind]).first
        target.focus()
        before = page.evaluate(_DG_IDENTITY)
        r0 = _dg_count(page, "refreshes")
        label = _dg_write(live, before=(where == "before"))
        _dg_reach(page, "refreshes", r0 + 1)
        page.locator("#dg-ifaces").get_by_text(label).wait_for()
        after = page.evaluate(_DG_IDENTITY)
        assert after[0] != "BODY" and after == before, (before, after)
        if where == "before" and kind in ("interface row", "origin group", "response step"):
            assert page.locator(_DG_TARGETS[kind]).first.evaluate(
                "e => e !== document.activeElement"), "nothing was inserted before it"
    finally:
        ctx.close()
    assert errors == []


def test_every_focusable_control_in_the_diagrams_live_regions_has_a_focus_key(live):
    """FR-UI-514 (D5): every focusable control the refresh re-renders carries a focus key,
    unique in its region; the request, forward and response steps of one capture record
    share their evidence key, so a step's key is derived from more than its evidence."""
    ctx, page, errors = _dg_page(live)
    try:
        found = page.evaluate("""() => {
          const sel = 'a[href], button, input, select, textarea, [tabindex]';
          const out = [];
          for (const r of ['#dg-flow', '#dg-ifaces', '#dg-seq', '#dg-exports']) {
            for (const e of document.querySelector(r).querySelectorAll(sel)) {
              if (e.closest('[hidden]') || e.getAttribute('tabindex') === '-1') continue;
              out.push({region: r, tag: e.tagName, key: e.getAttribute('data-focus-key')});
            }
          }
          return out;
        }""")
        regions = {f["region"] for f in found}
        assert regions == {"#dg-flow", "#dg-ifaces", "#dg-seq", "#dg-exports"}
        assert [f for f in found if not f["key"]] == []
        keys = [(f["region"], f["key"]) for f in found]
        assert len(keys) == len(set(keys))
    finally:
        ctx.close()
    assert errors == []
