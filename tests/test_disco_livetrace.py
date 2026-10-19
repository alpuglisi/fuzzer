"""The live trace of a disco capture (FR-CRAWL-30, FR-AUD-29; BUG-0524).

The live readers are judged by themselves first: after two live passes, and before the
final pass (which is the import itself and would fill in anything they missed), the
run's rows must already equal a fresh import's. The files are cut near every line
boundary and inside every multi-byte character, U+2028, U+0085 and a raw ``\\r``.
Then the final pass: every event and the model equal the import's.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from fuzzlab.core import trace
from fuzzlab.core.store import Store
from fuzzlab.disco import capture as capmod
from fuzzlab.disco.capture import make_record, read_capture
from fuzzlab.disco.livetrace import LiveTrace
from fuzzlab.report import diagram
from fuzzlab.tools import observe

O = "http://127.0.0.1:3201"
SECRETS = ("hunter2-Sup3rSecret!", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl")
#: The cap T1 runs with: every fixture record is under it but one.
CAP = 6000


def _rec(t, method, url, *, action, status=200, body=None, ctype=None, res=None,
         error=None, kind="http", ws=None, referer=None):
    headers = {"Authorization": f"Bearer {SECRETS[1]}"}
    if ctype:
        headers["Content-Type"] = ctype
    if referer:
        headers["Referer"] = referer
    return make_record(kind=kind, t=t, action_id=action, method=method, url=url,
                       req_headers=headers, req_body=body, status=status,
                       res_headers=res or {"Content-Type": "text/plain"},
                       res_body="ok   \u0085 é€\U0001F600".encode(),
                       error=error, ws_direction=ws, profile="anon")


def _capture_lines() -> tuple[list[bytes], list[str]]:
    """The capture's lines and, in order, the path of each record a reader must keep."""
    note = {"note": "a b\u0085c é€\U0001F600", "password": SECRETS[0]}
    recs = [
        ("/", _rec(1.0, "GET", O + "/", action="act-1")),
        ("/api/items", _rec(2.0, "POST", O + "/api/items?id=3", action="nav-2",
                            ctype="application/json",
                            body=json.dumps(note, ensure_ascii=False).encode(),
                            referer=O + "/")),
        ("/old", _rec(3.0, "GET", O + "/old", action="nav-3", status=302,
                      res={"Location": O + "/new"})),
        ("/slow", _rec(4.0, "GET", O + "/slow", action=None, status=None,
                       error="ConnectionResetError")),
        ("/socket", _rec(5.0, "WS", O.replace("http", "ws") + "/socket", action="harvest-4",
                         kind="ws", ws="client", status=101,
                         body="hi   \U0001F600".encode())),
    ]
    big = _rec(6.0, "GET", O + "/big", action="act-1", body=("x" * (CAP + 10)).encode(),
               ctype="text/plain")
    good = [r.to_json().encode() + b"\n" for _p, r in recs]
    lines = [good[0], good[1], b"{not json\n", b"\n", good[2],
             big.to_json().encode() + b"\n", good[3], good[4]]
    return lines, [p for p, _r in recs]


def _action_lines() -> list[bytes]:
    def line(doc, ascii_only=True):
        return (json.dumps(doc, ensure_ascii=ascii_only) + "\n").encode()
    return [
        line({"seq": 1, "action_id": "act-1", "kind": "click", "label": "Go",
              "route": O + "/", "url": O + "/"}),
        b"{oops\n",
        b"\n",
        # a log from before ``action_id``: its id is the records' (final pass only)
        line({"seq": 2, "kind": "submit", "label": "Send", "route": O + "/",
              "url": O + "/", "fields": [["email", "email"]]}),
        # a raw CR (JSON whitespace) and raw U+2028 / multi-byte characters: one line
        (b'{"seq": 3,\r "action_id": "nav-3", "kind": "click", "label": '
         + "\"A B é\U0001F600\"".encode() + b', "route": "/", "url": "/"}\n'),
        line({"seq": 4, "action_id": "harvest-4", "kind": "load", "label": "",
              "route": O + "/#/r", "url": O + "/#/r"}),
    ]


#: What the import must give, written down independently of the code under test.
ACTION_SCOPES = {1: "workflow:act-1", 4: "workflow:nav-2", 5: "workflow:nav-3",
                 6: "workflow:harvest-4"}
LIVE_ACTION_LINES = {1, 5, 6}           # the lines carrying an ``action_id``


def _cuts(data: bytes) -> list[int]:
    """Offsets near every line boundary and at every byte of each multi-byte character
    (U+2028, U+0085 included) and around each raw ``\\r``."""
    cuts = set()
    for i, b in enumerate(data):
        if b == 0x0A:
            cuts.update(range(i - 1, i + 3))
        if b >= 0x80 or b == 0x0D:
            cuts.update((i, i + 1))
    return sorted(c for c in cuts if 0 < c < len(data))


def _events(conn, run, keys=None) -> dict:
    rows = conn.execute("SELECT key, kind, scope, t, body FROM trace_event WHERE run_id=? "
                        "AND key != 'run.end'", (run,)).fetchall()
    return {r[0]: (r[1], r[2], r[3], r[4]) for r in rows if keys is None or r[0] in keys}


def _model(conn, run) -> tuple:
    ents = conn.execute("SELECT eid, kind, parent, label, knowledge, first_seen, last_seen, "
                        "attrs FROM dg_entity WHERE run_id=? ORDER BY eid", (run,)).fetchall()
    flows = conn.execute("SELECT fid, src, dst, view, protocol, knowledge, first_seen, "
                         "last_seen, attrs FROM dg_flow WHERE run_id=? ORDER BY fid",
                         (run,)).fetchall()
    return [tuple(r) for r in ents], [tuple(r) for r in flows]


def _import(store, run_dir) -> int:
    run = store.start_run("auto", "h")
    rec = trace.TraceRecorder(store, run)
    with trace.recording(rec):
        observe.observe_disco(run_dir, read_capture(run_dir / "capture.jsonl").records)
    rec.close()
    return run


def _write(run_dir: Path, cap: bytes, act: bytes) -> None:
    (run_dir / "capture.jsonl").write_bytes(cap)
    (run_dir / "actions.jsonl").write_bytes(act)


def test_the_live_trace_equals_the_import_wherever_the_files_are_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(capmod, "MAX_LINE_BYTES", CAP)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cap_lines, paths = _capture_lines()
    cap, act = b"".join(cap_lines), b"".join(_action_lines())
    for marker in (" ", "\u0085", "€", "\U0001F600"):
        assert marker.encode() in cap                    # the fixture holds them raw
    assert b"\r" in act and " ".encode() in act
    (run_dir / "capture.jsonl.stats.json").write_text(json.dumps({"blocked": {"x.test": 2}}))
    (run_dir / "explore.json").write_text(json.dumps({"explore": {"out_of_scope":
                                                                  {"y.test": 5}}}))
    db = tmp_path / "s.db"
    _write(run_dir, cap, act)
    tag = observe.disco_tag(run_dir)
    with Store(db) as store:
        ref_run = _import(store, run_dir)
        expected = _events(store.conn, ref_run)
        expected_model = _model(store.conn, ref_run)
    # the import itself, against what was written (independent of the readers)
    recs = {k: json.loads(v[3]) for k, v in expected.items() if ":rec:" in k}
    assert sorted(recs) == sorted(f"{tag}:rec:{i}" for i in range(len(paths)))
    for i, path in enumerate(paths):
        assert recs[f"{tag}:rec:{i}"]["url"].split("?")[0].endswith(path)
    scopes = {int(k.rsplit("line", 1)[1]): v[1] for k, v in expected.items()
              if ":action:" in k}
    assert scopes == ACTION_SCOPES
    assert {k for k in expected if ":external:" in k or ":guard:" in k} == \
        {f"{tag}:external:x.test", f"{tag}:guard:y.test"}
    live_keys = set(recs) | {f"{tag}:action:line{n}" for n in LIVE_ACTION_LINES}
    expected_live = {k: v for k, v in expected.items() if k in live_keys}
    blob = json.dumps(expected)
    assert all(s not in blob for s in SECRETS)

    cases = [("capture", k) for k in _cuts(cap)] + [("actions", k) for k in _cuts(act)]
    assert len(cases) > 100
    for which, k in cases:
        first = (cap[:k], act) if which == "capture" else (cap, act[:k])
        _write(run_dir, *first)
        with Store(db) as store:
            run = store.start_run("disco", "h")
        live = LiveTrace(run_dir, db, run)
        live.open()
        try:
            live.poll()
            _write(run_dir, cap, act)
            live.poll()
            with Store(db) as store:
                got = _events(store.conn, run)
            # the live readers alone, before the final import could fill anything in
            assert got == expected_live, (which, k)
            live.finish("complete")
        finally:
            live.store.close()
        with Store(db) as store:
            assert _events(store.conn, run) == expected, (which, k)
            assert _model(store.conn, run) == expected_model, (which, k)
            end = store.conn.execute("SELECT body FROM trace_event WHERE run_id=? AND "
                                     "key='run.end'", (run,)).fetchone()[0]
            assert json.loads(end) == {"status": "complete"}


def test_a_dropped_batch_is_healed_by_the_final_import(tmp_path, monkeypatch):
    """A batch the store would not take is counted and written by the final pass; the
    run keeps reading partial (the count stays)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cap_lines, _paths = _capture_lines()
    monkeypatch.setattr(capmod, "MAX_LINE_BYTES", CAP)
    _write(run_dir, b"".join(cap_lines), b"".join(_action_lines()))
    db = tmp_path / "s.db"
    with Store(db) as store:
        run = store.start_run("disco", "h")
    real, calls = trace.reduce, []

    def once(conn, run_id, events):
        calls.append(len(events))
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return real(conn, run_id, events)
    monkeypatch.setattr(trace, "reduce", once)
    live = LiveTrace(run_dir, db, run)
    live.open()
    try:
        live.poll()
        assert live.recorder.stats["dropped"] > 0
        live.finish("complete")
    finally:
        live.store.close()
    monkeypatch.setattr(trace, "reduce", real)
    with Store(db) as store:
        ref = _import(store, run_dir)
        assert _events(store.conn, run) == _events(store.conn, ref)
        assert _model(store.conn, run) == _model(store.conn, ref)
        st = diagram.status(store.conn, run)
        assert st["state"] == "partial" and st["recorder"]["dropped"] > 0


def test_both_refusal_layers_are_traced_under_their_own_keys(tmp_path):
    """BUG-0524: the browser guard's refusals (explore.json) are traced beside the
    capture proxy's; one host refused by both is two events, both counts kept."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    capmod.append_record(run_dir / "capture.jsonl", _rec(1.0, "GET", O + "/", action=None))
    (run_dir / "capture.jsonl.stats.json").write_text(
        json.dumps({"blocked": {"evil.example": 3}}))
    (run_dir / "explore.json").write_text(json.dumps(
        {"explore": {"out_of_scope": {"evil.example": 22, "cdn.example": 4}}}))
    with Store(tmp_path / "s.db") as store:
        run = _import(store, run_dir)
        tag = observe.disco_tag(run_dir)
        ev = _events(store.conn, run)
        assert json.loads(ev[f"{tag}:guard:cdn.example"][3]) == \
            {"src": "browser-guard", "host": "cdn.example", "count": 4}
        assert f"{tag}:external:evil.example" in ev and f"{tag}:guard:evil.example" in ev
        flows = {f["dst"]: f for f in diagram.dataflow(store.conn, run)["flows"]}
        assert flows["ext:evil.example"]["attrs"]["refused"] == [3, 22]
        assert flows["ext:cdn.example"]["attrs"]["refused"] == [4]
        again = trace.TraceRecorder(store, run)
        with trace.recording(again):
            observe.observe_disco(run_dir, read_capture(run_dir / "capture.jsonl").records)
        assert again.close()["written"] == 0


# --- through the command, with the proxy and the explorer faked -------------------------
def _fake_capture(monkeypatch, *, explore=None, stop=None):
    from fuzzlab.disco import explore as ex
    from fuzzlab.disco import proxyproc

    def start(self):
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.touch()
        self.endpoint = "127.0.0.1:9"
        return self
    monkeypatch.setattr(proxyproc.CaptureProxy, "start", start)
    monkeypatch.setattr(proxyproc.CaptureProxy, "stop", stop or (lambda self: None))
    monkeypatch.setattr(proxyproc.CaptureProxy, "stats",
                        lambda self: {"recorded": 1, "blocked": {}})

    class FakeExplorer:
        def __init__(self, start, *, scope_urls, proxy, options, storage_state,
                     actions_log):
            self.log = Path(actions_log)

        def run(self):
            capmod.append_record(self.log.parent / "capture.jsonl",
                                 _rec(1.0, "GET", O + "/", action="act-1"))
            self.log.write_text(json.dumps({"seq": 1, "action_id": "act-1",
                                            "kind": "click", "label": "Go", "route": "/",
                                            "url": "/"}) + "\n")
            if explore:
                explore()
            return ex.ExploreReport(out_of_scope={"elsewhere.example": 2})
    monkeypatch.setattr(ex, "Explorer", FakeExplorer)


def _argv(tmp_path):
    return ["capture", "--start", O + "/", "--out", str(tmp_path / "run"), "--store",
            str(tmp_path / "s.db"), "--authorized"]


def _run_end(db) -> tuple[dict, str | None]:
    with Store(db) as store:
        row = store.conn.execute("SELECT e.body, r.notes FROM trace_event e JOIN run r "
                                 "ON r.id = e.run_id WHERE e.key='run.end'").fetchone()
    return (json.loads(row[0]), row[1]) if row else ({}, None)


def test_a_capture_with_a_store_records_its_trace_and_its_end(tmp_path, monkeypatch, capsys):
    from fuzzlab.disco import cli
    _fake_capture(monkeypatch)
    assert cli.main(_argv(tmp_path)) == 0
    end, notes = _run_end(tmp_path / "s.db")
    assert end == {"status": "complete"} and notes is None
    with Store(tmp_path / "s.db") as store:
        kinds = {r[0] for r in store.conn.execute("SELECT kind FROM trace_event")}
        tool = store.conn.execute("SELECT tool FROM run").fetchone()[0]
    assert tool == "disco"
    assert {"observe.exchange", "observe.action", "observe.external", "run.end"} <= kinds
    assert "trace: run 1" in capsys.readouterr().out


def test_a_failed_live_trace_leaves_the_capture_and_marks_the_run(tmp_path, monkeypatch,
                                                                 capsys):
    from fuzzlab.disco import cli

    def boom(self, final=False):
        raise RuntimeError("boom")
    _fake_capture(monkeypatch)
    monkeypatch.setattr(capmod.CaptureTail, "read", boom)
    assert cli.main(_argv(tmp_path)) == 0                     # the exit code is unchanged
    assert (tmp_path / "run" / "explore.json").exists()
    err = capsys.readouterr().err
    assert "the live trace stopped (RuntimeError: boom)" in err       # when it happened
    assert "live trace: RuntimeError: boom" in err                    # and at the end
    end, notes = _run_end(tmp_path / "s.db")
    assert end == {"status": "aborted: trace RuntimeError"}
    assert notes.startswith("aborted: LiveTraceFailed: trace RuntimeError")


def test_a_proxy_that_cannot_stop_still_ends_the_trace(tmp_path, monkeypatch):
    from fuzzlab import procutil
    from fuzzlab.disco import cli

    def lost(self):
        raise procutil.ServerLost("the capture proxy was gone")
    _fake_capture(monkeypatch, stop=lost)
    with pytest.raises(procutil.ServerLost):
        cli.main(_argv(tmp_path))
    end, notes = _run_end(tmp_path / "s.db")
    assert end == {"status": "aborted: ServerLost"}
    assert notes.startswith("aborted: ServerLost")
    with Store(tmp_path / "s.db") as store:          # what was captured is still traced
        assert store.conn.execute("SELECT COUNT(*) FROM trace_event WHERE "
                                  "kind='observe.exchange'").fetchone()[0] == 1


def test_a_failed_explorer_marks_the_run_aborted(tmp_path, monkeypatch):
    from fuzzlab.disco import cli

    def fail():
        raise RuntimeError("explorer crashed")
    _fake_capture(monkeypatch, explore=fail)
    with pytest.raises(RuntimeError, match="explorer crashed"):
        cli.main(_argv(tmp_path))
    end, notes = _run_end(tmp_path / "s.db")
    assert end == {"status": "aborted: RuntimeError"}
    assert notes.startswith("aborted: RuntimeError")


def test_a_trace_that_does_not_finish_is_reported_and_exits_1(tmp_path, monkeypatch, capsys):
    from fuzzlab.disco import cli, livetrace
    release = threading.Event()
    real = observe.observe_disco

    def slow(*a, **kw):
        release.wait(30)
        return real(*a, **kw)
    _fake_capture(monkeypatch)
    monkeypatch.setattr(livetrace, "join_bound", lambda events: 0.3)
    monkeypatch.setattr(observe, "observe_disco", slow)
    try:
        assert cli.main(_argv(tmp_path)) == 1
        assert "live trace: timeout" in capsys.readouterr().err
    finally:
        release.set()
    deadline = time.monotonic() + 15                 # the thread still ends the run
    while time.monotonic() < deadline and not _run_end(tmp_path / "s.db")[0]:
        time.sleep(0.05)
    assert _run_end(tmp_path / "s.db")[0] == {"status": "complete"}


def test_the_join_bound_grows_with_the_flushes_the_final_pass_needs():
    from fuzzlab.disco.livetrace import FLUSH_STALL_S, JOIN_TIMEOUT_S, join_bound
    assert join_bound(0) == join_bound(trace.MAX_BUFFER - 1) == JOIN_TIMEOUT_S
    assert join_bound(5 * trace.MAX_BUFFER) == FLUSH_STALL_S * (6 + 1) + FLUSH_STALL_S


# --- the real thing ----------------------------------------------------------------------
def _require_real():
    from tests._browser import skip_or_fail
    for mod in ("playwright.sync_api", "mitmproxy"):
        try:
            __import__(mod)
        except ImportError as exc:
            skip_or_fail(f"{mod} unavailable: {exc}")


def _ro(db):
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def test_a_host_the_proxy_refuses_reaches_the_trace_with_its_final_count(tmp_path):
    """mitmdump for real (no browser): an in-scope exchange is in the store while the
    proxy runs; two refused requests are one event with the final count, at the end."""
    try:
        __import__("mitmproxy")
    except ImportError as exc:
        from tests._browser import skip_or_fail
        skip_or_fail(f"mitmproxy unavailable: {exc}")
    import requests

    from fuzzlab.disco.proxyproc import CaptureProxy
    from tests._disco_app import DiscoApp
    out, db = tmp_path / "run", tmp_path / "s.db"
    with Store(db) as store:
        run = store.start_run("disco", "h")
    with DiscoApp() as app:
        with CaptureProxy([app.url], out=out / "capture.jsonl") as proxy:
            live = LiveTrace(out, db, run, poll_s=0.05).start()
            http = requests.Session()
            http.trust_env = False
            via = {"http": f"http://{proxy.endpoint}"}
            http.get(app.url + "/", proxies=via, timeout=10)
            for _ in range(2):
                with pytest.raises(requests.RequestException):
                    http.get("http://127.0.0.2:9/x", proxies=via, timeout=10)
            seen, deadline = 0, time.monotonic() + 15
            while not seen and time.monotonic() < deadline:
                with _ro(db) as conn:
                    seen = conn.execute("SELECT COUNT(*) FROM trace_event WHERE run_id=? "
                                        "AND kind='observe.exchange'", (run,)).fetchone()[0]
                time.sleep(0.05)
            assert seen == 1                            # live, before the proxy stopped
        assert live.stop("complete") is None
    stats = json.loads((out / "capture.jsonl.stats.json").read_text())
    assert stats["blocked"] == {"127.0.0.2": 2}
    with Store(db) as store:
        tag = observe.disco_tag(out)
        body = store.conn.execute("SELECT body FROM trace_event WHERE key=?",
                                  (f"{tag}:external:127.0.0.2",)).fetchone()[0]
    assert json.loads(body)["count"] == 2


def test_a_real_capture_is_in_the_store_while_it_runs_and_unchanged(tmp_path, monkeypatch):
    """A guarded Chromium through mitmdump, `fuzzlab disco capture --store`: an
    independent reader sees exchanges and actions while the capture runs (at least 5 s
    before the proxy stops, by the capture's own clock), and afterwards every count
    agrees with an independent one and the run equals an import of the directory."""
    _require_real()
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.disco import cli, proxyproc
    from tests._browser import skip_or_fail
    from tests._disco_app import DiscoApp
    out, db = tmp_path / "run", tmp_path / "s.db"
    stopped: list[float] = []
    real_stop = proxyproc.CaptureProxy.stop

    def stamped(self):
        stopped.append(time.time())
        return real_stop(self)
    monkeypatch.setattr(proxyproc.CaptureProxy, "stop", stamped)
    samples: list[tuple[float, int, int, str]] = []
    done = threading.Event()

    def reader():
        while not done.is_set():
            try:
                with _ro(db) as conn:
                    run = conn.execute("SELECT id FROM run WHERE tool='disco'").fetchone()
                    if run:
                        n = dict(conn.execute(
                            "SELECT kind, COUNT(*) FROM trace_event WHERE run_id=? "
                            "GROUP BY kind", (run[0],)).fetchall())
                        samples.append((time.time(), n.get("observe.exchange", 0),
                                        n.get("observe.action", 0),
                                        diagram.status(conn, run[0])["state"]))
            except sqlite3.Error:
                pass
            time.sleep(0.1)
    with DiscoApp() as other, DiscoApp(other=other.url) as app:
        watch = threading.Thread(target=reader, daemon=True)
        watch.start()
        try:
            rc = cli.main(["capture", "--start", app.url, "--out", str(out), "--store",
                           str(db), "--max-actions", "80", "--deadline", "240",
                           "--workers", "2", "--authorized"])
        except PlaywrightError as exc:
            if "Executable doesn't exist" in str(exc) or "launch" in str(exc).lower():
                skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
            raise
        finally:
            done.set()
            watch.join(5)
        hits, posts = len(app.hits), app.paths("POST")
    assert rc == 0 and stopped
    live = [s for s in samples if s[0] <= stopped[0] - 5 and s[1] and s[2]]
    assert live and all(s[3] == "partial" for s in live), samples[:5]
    records = read_capture(out / "capture.jsonl").records
    stats = json.loads((out / "explore.json").read_text())
    guard = stats["explore"]["out_of_scope"]
    assert guard                                       # the fixture's refused origin
    assert hits == stats["proxy"]["recorded"] == len(records)
    assert "/api/projects/101/tasks" in posts
    tag = observe.disco_tag(out)
    with Store(db) as store:
        run = store.conn.execute("SELECT id FROM run WHERE tool='disco'").fetchone()[0]
        st = diagram.status(store.conn, run)
        assert st["state"] == "complete" and st["run_end"] == "complete"
        assert st["by_kind"]["observe.exchange"] == len(records)
        for host, count in guard.items():               # BUG-0524
            body = store.conn.execute("SELECT body FROM trace_event WHERE run_id=? AND "
                                      "key=?", (run, f"{tag}:guard:{host}")).fetchone()[0]
            assert json.loads(body)["count"] == count
        again = trace.TraceRecorder(store, run)
        with trace.recording(again):
            observe.observe_disco(out, records)
        assert again.close()["written"] == 0
        ref = _import(store, out)
        assert _events(store.conn, run) == _events(store.conn, ref)
        assert _model(store.conn, run) == _model(store.conn, ref)
