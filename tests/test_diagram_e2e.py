"""The diagrams end to end (FR-CORE-505, FR-FUZZ-60, FR-AUD-28, FR-UI-511): a crawl's
discovered interfaces, the real pipeline against a loopback app (real HTTP: SQL errors, a
redirect, a connection reset, a timeout), the persisted model, its data flow and
sequences, the evidence links from a finding back to its exchanges, the exports -- and
what must never happen: a secret in any of them, captured text becoming diagram syntax,
a missing response drawn as a reply, a replay that duplicates."""

from __future__ import annotations

import json
import re
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import pytest

from fuzzlab.core import trace
from fuzzlab.core.store import Store
from fuzzlab.report import diagram
from fuzzlab.tools import store_adapter

SECRETS = ("SECRETPW1", "SECRETTOKEN123456abcdef")
EVIL = '"]-->x<script>alert(1)</script>;%0Aflowchart'


class _App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body=b"ok", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/product/"):
            if "'" in unquote(path):
                return self._send(500, b"You have an error in your SQL syntax near '''")
            return self._send(200, b"<html>a product</html>")
        if path == "/go":
            return self._send(302, b"", [("Location", "/landing")])
        if path == "/hangup":
            self.connection.shutdown(socket.SHUT_RDWR)   # no response at all
            return None
        if path == "/slow":
            time.sleep(1.2)
            return self._send(200, b"slow")
        return self._send(200, b"<html>page</html>")


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    from fuzzlab.harness.auto import run_auto
    from fuzzlab.tools.probesender import RequestsProbeSender
    tmp = tmp_path_factory.mktemp("dg")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    db = tmp / "spider.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE discovered_pages (url TEXT, status_code INT, source TEXT)")
    con.executemany("INSERT INTO discovered_pages VALUES (?,200,?)", [
        (base + "/product/1", "link"), (base + "/product/2", "link"),
        (base + "/go?to=x", "link"), (base + "/hangup?x=1", "link"),
        (base + "/slow?s=1", "link"), (base + "/x/" + EVIL, "link"),
        (base + f"/login?token={SECRETS[1]}", "link")])
    # a load that failed: the spider stores status 0 (BUG-0515: never a reply)
    con.execute("INSERT INTO discovered_pages VALUES (?,0,'link')", (base + "/gone",))
    con.execute("CREATE TABLE discovered_requests (id INTEGER PRIMARY KEY, page_url TEXT, "
                "method TEXT, url TEXT, content_type TEXT, body_json TEXT, source TEXT, "
                "signature TEXT)")
    con.execute("INSERT INTO discovered_requests (page_url, method, url, content_type, "
                "body_json, source) VALUES (?,?,?,?,?,?)",
                (base + "/login", "POST", base + "/api/login", "application/json",
                 json.dumps({"email": "a@b.example", "password": SECRETS[0]}),
                 "dry-submit"))
    con.commit()
    con.close()
    store = Store(tmp / "s.db")
    run_id = store.start_run("auto", "h")
    rec = trace.TraceRecorder(store, run_id)
    try:
        with trace.recording(rec):
            store_adapter.import_spider(db, store, run_id)
            run_auto(base_url=base + "/", store=store, run_id=run_id,
                     sender=RequestsProbeSender(timeout=0.4), mode="manual",
                     selected_categories=["sql-injection", "open-redirect"],
                     points_source="crawl")
    finally:
        rec.close()
        server.shutdown()
    yield {"store": store, "run": run_id, "base": base, "db": db}
    store.close()


def _exchanges(conn, run_id, **match):
    out = []
    for r in conn.execute("SELECT key, body FROM trace_event WHERE run_id=? AND "
                          "kind='exchange' ORDER BY seq", (run_id,)):
        b = json.loads(r["body"])
        if all(b.get(k) == v for k, v in match.items()):
            out.append((r["key"], b))
    return out


def test_the_run_is_complete_and_nothing_was_dropped(run):
    st = diagram.status(run["store"].conn, run["run"])
    assert st["state"] == "complete", st
    assert st["recorder"]["dropped"] == 0 and st["recorder"]["written"] == st["events"]


def test_the_data_flow_shows_the_application_and_keeps_testing_separate(run):
    conn, base = run["store"].conn, run["base"]
    origin = base.replace("localhost", "127.0.0.1")
    app = diagram.dataflow(conn, run["run"])
    kinds = {n["kind"] for n in app["nodes"]}
    assert kinds <= {"actor", "tool", "application", "origin", "interface", "page",
                     "external"}                     # nothing server-side is invented
    assert all(f["view"] == "app" for f in app["flows"])
    (orig,) = [n for n in app["nodes"] if n["kind"] == "origin"]
    assert orig["label"] == origin and orig["attrs"]["internals"][0].startswith("unknown")
    product = f"iface:{origin}|GET|/product/{{id}}"
    flow = next(f for f in app["flows"] if f["dst"] == product)
    # the spider's own page loads are the crawler's, not a browser's (BUG-0515)
    assert flow["src"] == trace.SPIDER and flow["observations"] == 2
    ids = {n["id"]: n for n in app["nodes"]}
    assert ids[product]["knowledge"] == "inferred"           # a grouping, not a request
    # a write the browser made and the spider blocked was never sent: drawn refused,
    # apart from any traffic that was sent (BUG-0515)
    blocked = next(f for f in app["flows"] if f["dst"].endswith("|POST|/api/login"))
    assert blocked["src"] == trace.BROWSER and blocked["protocol"] == "blocked"
    assert blocked["attrs"]["refused"][0].startswith("blocked")
    assert blocked["attrs"]["data"] == ["credential:json", "data:json"]
    assert "-.->|\"blocked" in diagram.mermaid_flow(app)
    with_tests = diagram.dataflow(conn, run["run"], overlay=True)
    tool = [f for f in with_tests["flows"] if f["view"] == "test"]
    assert tool and all(f["src"] == trace.TOOL for f in tool)
    cov = {n["id"]: n.get("coverage") for n in with_tests["nodes"]}
    assert cov[product]["discovered"] == 2 and cov[product]["scheduled"] >= 1
    assert cov[product]["executed"] >= 2 and cov[product]["evaluated"] >= 1
    assert cov[product]["finding"] == 1
    # tested, no finding: what was done is shown, not "secure"
    go = cov[f"iface:{origin}|GET|/go"]
    assert go["executed"] >= 1 and go["finding"] == 0


def test_a_finding_links_to_exactly_its_exchanges_and_its_sequence(run):
    conn, run_id = run["store"].conn, run["run"]
    (fid,) = [r[0] for r in conn.execute("SELECT id FROM finding WHERE run_id=?",
                                         (run_id,))]
    links = diagram.finding_links(conn, run_id, fid)
    assert links["vuln_class"] == "sqli" and links["exchanges"]
    own = {k for k, b in _exchanges(conn, run_id, test=links["test"],
                                    strategy=links["strategy"])}
    assert set(links["exchanges"]) == own
    for key in links["exchanges"]:
        assert diagram.evidence(conn, run_id, key)["items"][0]["kind"] == "exchange"
    seq = diagram.sequence(conn, run_id, f"finding:{fid}")
    kinds = [(s["type"], s.get("kind")) for s in seq["steps"]]
    assert ("message", "request") in kinds and ("message", "response") in kinds
    roles = {s.get("role") for s in seq["steps"] if s.get("kind") == "request"}
    assert {"mutation", "control"} <= roles
    finding = [s for s in seq["steps"] if s.get("kind") == "finding"]
    assert len(finding) == 1 and finding[0]["type"] == "note"   # never a target reply
    assert set(links["exchanges"]) <= set(finding[0]["evidence"])
    tool = {p["id"] for p in seq["participants"] if p["kind"] != "target"}
    for s in seq["steps"]:
        if s.get("kind") == "response":
            assert s["src"] not in tool and s["dst"] in tool


def test_missing_responses_and_timeouts_are_never_drawn_as_replies(run):
    conn, run_id = run["store"].conn, run["run"]
    reset = _exchanges(conn, run_id, outcome="unobserved")
    timeout = _exchanges(conn, run_id, outcome="timeout")
    assert reset and all("/hangup" in b["url"] for _k, b in reset)
    assert timeout and all("/slow" in b["url"] for _k, b in timeout)
    assert all(b.get("status") is None for _k, b in reset + timeout)
    for key, b in reset[:1] + timeout[:1]:
        seq = diagram.sequence(conn, run_id, f"test:{b['test']}")
        cited = [s for s in seq["steps"] if key in s.get("evidence", [])]
        assert not [s for s in cited if s.get("kind") == "response"]   # never a reply
        lost = [s for s in seq["steps"] if s["type"] == "lost"]
        assert lost and all(b["outcome"] in s["label"] or "unobserved" in s["label"]
                            or "timeout" in s["label"] for s in lost)
        assert "-x" in diagram.mermaid_sequence(seq)


def test_a_failed_spider_load_is_drawn_lost_never_as_a_reply(run):
    conn, run_id = run["store"].conn, run["run"]
    seq = diagram.sequence(conn, run_id, "spider")
    i = next(i for i, s in enumerate(seq["steps"]) if "/gone" in s.get("label", ""))
    after = seq["steps"][i + 1]
    assert after["type"] == "lost" and "no response" in after["label"]
    assert not any(s["kind"] == "response" and s["label"] == "0" for s in seq["steps"])
    gone = next(f for f in diagram.dataflow(conn, run_id)["flows"]
                if f["dst"].endswith("|GET|/gone"))
    assert "status" not in gone["attrs"]


def test_a_redirect_is_shown_with_its_target(run):
    conn, run_id = run["store"].conn, run["run"]
    redirects = _exchanges(conn, run_id, status=302)
    assert redirects and all(b["redirect"].endswith("/landing") for _k, b in redirects)
    # the response's target never replaces where the value was injected (BUG-0517)
    assert all(b["location"] in ("query", "body", "header", "path", "cookie")
               for _k, b in redirects if b.get("param"))


def test_no_secret_reaches_events_model_or_exports(run):
    conn, run_id = run["store"].conn, run["run"]
    texts = [r[0] for r in conn.execute("SELECT body FROM trace_event WHERE run_id=?",
                                        (run_id,))]
    texts += [r[0] for r in conn.execute("SELECT attrs FROM dg_entity WHERE run_id=? "
                                         "UNION ALL SELECT label FROM dg_entity WHERE "
                                         "run_id=? UNION ALL SELECT attrs FROM dg_flow "
                                         "WHERE run_id=?", (run_id, run_id, run_id))]
    texts.append(json.dumps(diagram.export_json(conn, run_id)))
    texts.append(diagram.mermaid_flow(diagram.dataflow(conn, run_id, overlay=True)))
    for scope in diagram.scopes(conn, run_id):
        texts.append(diagram.mermaid_sequence(diagram.sequence(conn, run_id,
                                                               scope["scope"])))
    blob = "\n".join(texts)
    for secret in SECRETS:
        assert secret not in blob, secret


def test_captured_text_never_becomes_diagram_syntax(run):
    conn, run_id = run["store"].conn, run["run"]
    flow = diagram.mermaid_flow(diagram.dataflow(conn, run_id, overlay=True))
    seqs = [diagram.mermaid_sequence(diagram.sequence(conn, run_id, s["scope"]))
            for s in diagram.scopes(conn, run_id)]
    for text in [flow] + seqs:
        assert "<script" not in text and "-->x" not in text
        for line in text.splitlines():
            # every quoted label holds the safe alphabet and entities only
            for label in re.findall(r'"([^"]*)"', line):
                assert re.fullmatch(r"[A-Za-z0-9 ./_\-{}()?=,+@#;…]*", label), line
    assert "#60;script#62;" in flow                     # shown, as text


def test_replay_and_reimport_add_nothing(run):
    conn, run_id = run["store"].conn, run["run"]

    def snap():
        return (sorted(tuple(r) for r in conn.execute(
            "SELECT eid, knowledge, first_seen, last_seen, attrs FROM dg_entity WHERE "
            "run_id=?", (run_id,))),
                sorted(tuple(r) for r in conn.execute(
                    "SELECT fid, attrs FROM dg_flow WHERE run_id=?", (run_id,))),
                conn.execute("SELECT COUNT(*) FROM dg_evidence WHERE run_id=?",
                             (run_id,)).fetchone()[0])
    events = conn.execute("SELECT COUNT(*) FROM trace_event WHERE run_id=?",
                          (run_id,)).fetchone()[0]
    before = snap()
    trace.rebuild(conn, run_id)
    assert snap() == before
    rec = trace.TraceRecorder(run["store"], run_id)
    with trace.recording(rec):
        from fuzzlab.tools.observe import observe_spider
        observe_spider(run["db"])
    stats = rec.close()
    assert stats["written"] == 0 and stats["duplicates"] > 0
    assert conn.execute("SELECT COUNT(*) FROM trace_event WHERE run_id=?",
                        (run_id,)).fetchone()[0] == events
    assert snap() == before


# --- a disco capture through the production importer ------------------------------------
def test_a_capture_gives_origins_auth_contexts_workflows_and_external_refs(tmp_path):
    from fuzzlab.disco.capture import append_record, make_record
    page, api = "http://127.0.0.1:3101", "http://127.0.0.1:3102"
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    def rec(t, method, url, *, status=200, action="act-1", profile="anon", body=None,
            ctype=None, res_headers=None, error=None, kind="http", ws=None, referer=None):
        headers = {"Content-Type": ctype} if ctype else {}
        if referer:
            headers["Referer"] = referer
        headers["Authorization"] = f"Bearer {SECRETS[1]}"
        append_record(run_dir / "capture.jsonl", make_record(
            kind=kind, t=t, action_id=action, method=method, url=url,
            req_headers=headers, req_body=body.encode() if body else None, status=status,
            res_headers=res_headers or {"Content-Type": "text/html"},
            res_body=b"<html></html>", error=error, ws_direction=ws, profile=profile))
    rec(1.0, "GET", page + "/")
    rec(2.0, "GET", api + "/api/items?id=3", referer=page + "/", profile="user_a")
    rec(3.0, "POST", api + "/api/login", ctype="application/json",
        body=json.dumps({"email": "x@y.example", "password": SECRETS[0]}))
    rec(4.0, "GET", page + "/old", status=302,
        res_headers={"Location": page + "/new"})
    rec(5.0, "GET", api + "/api/slow", status=None, error="ConnectionResetError")
    rec(6.0, "WS", api.replace("http", "ws") + "/socket", kind="ws", ws="client",
        status=101, body="hello")
    rec(7.0, "GET", page + "/beacon", action=None)
    rec(8.0, "GET", page + "/about", action="nav-2")
    rec(9.0, "GET", page + "/#/route", action="harvest-3")
    (run_dir / "actions.jsonl").write_text("\n".join(json.dumps(d) for d in (
        {"seq": 1, "kind": "click", "label": '<img src=x onerror=alert(1)>',
         "route": page + "/", "url": page + "/", "state": "s"},
        # a link click logged before ``action_id`` existed: its id is the records'
        {"seq": 2, "kind": "click", "label": "About", "route": page + "/",
         "url": page + "/about", "state": "s"},
        {"seq": 3, "action_id": "harvest-3", "kind": "load", "label": "",
         "route": page + "/#/route", "url": page + "/#/route", "state": None})) + "\n")
    (run_dir / "capture.jsonl.stats.json").write_text(json.dumps(
        {"blocked": {"evil.example.com": 3}, "recorded": 7}))
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("crawl", "h")
        recorder = trace.TraceRecorder(store, run_id)
        with trace.recording(recorder):
            store_adapter.import_disco(run_dir, store, run_id, base_url=page)
        recorder.close()
        conn = store.conn
        model = diagram.dataflow(conn, run_id)
        nodes = {n["id"]: n for n in model["nodes"]}
        assert {f"origin:{page}", f"origin:{api}"} <= set(nodes)
        assert nodes["ext:evil.example.com"]["kind"] == "external"
        refused = next(f for f in model["flows"] if f["dst"] == "ext:evil.example.com")
        assert refused["attrs"]["refused"] == [3]
        auth = {a for f in model["flows"] for a in f["attrs"].get("auth", [])}
        assert auth == {"anon", "user_a"}                # both contexts, by name only
        items = next(f for f in model["flows"] if f["dst"].endswith("|GET|/api/items"))
        assert items["attrs"]["initiator"] == ["/"]
        old = next(f for f in model["flows"] if f["dst"].endswith("|GET|/old"))
        assert old["attrs"]["redirect"][0].endswith("/new")
        seq = diagram.sequence(conn, run_id, "workflow:act-1")
        parts = {p["id"]: p["kind"] for p in seq["participants"]}
        assert parts["explorer"] == "tool" and parts["proxy"] == "tool"
        kinds = [s["kind"] for s in seq["steps"]]
        assert kinds[0] == "action" and "forward" in kinds and "ws" in kinds
        lost = [s for s in seq["steps"] if s["type"] == "lost"]
        assert len(lost) == 1 and "ConnectionResetError" in lost[0]["label"]
        # BUG-0512: an action and the requests it caused share one workflow, whatever
        # its id's prefix; no workflow holds an action alone
        for action, path in (("nav-2", "/about"), ("harvest-3", "/")):
            wf = diagram.sequence(conn, run_id, f"workflow:{action}")
            assert wf["steps"][0]["kind"] == "action"
            assert any(path in s["label"] for s in wf["steps"] if s["kind"] == "request")
        workflows = {s["scope"] for s in diagram.scopes(conn, run_id)
                     if s["kind"] == "workflow"}
        assert workflows == {"workflow:act-1", "workflow:nav-2", "workflow:harvest-3"}
        # stable keys: importing the same run again adds nothing
        again = trace.TraceRecorder(store, run_id)
        with trace.recording(again):
            store_adapter.import_disco(run_dir, store, run_id, base_url=page)
        assert again.close()["written"] == 0
        unc = diagram.sequence(conn, run_id, "capture")
        assert "uncorrelated" in unc["notes"][0]
        blob = json.dumps(diagram.export_json(conn, run_id)) + "".join(
            r[0] for r in conn.execute("SELECT body FROM trace_event"))
        for secret in SECRETS:
            assert secret not in blob
        mm = diagram.mermaid_sequence(seq)
        assert "<img" not in mm and "#60;img" in mm
