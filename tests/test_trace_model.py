"""The trace model's guarantees (FR-CORE-505, `core.trace`): events are append-only and
idempotent per key; the diagram model derived from them is order-independent, equal to
a full replay, never double-counted, and honest about what it does not know."""

from __future__ import annotations

import json
import random
import sqlite3
import threading

import pytest

from fuzzlab.core import trace
from fuzzlab.core.store import Store

O = "http://127.0.0.1:9001"


def _obs(i, path, t, *, status=200, profile="anon", method="GET"):
    return ("observe.exchange", {"src": "capture", "ref": f"record {i}", "method": method,
                                 "url": O + path, "origin": O, "status": status,
                                 "profile": profile, "params": [["q", "query"]]},
            f"k{i}", t)


EVENTS = [_obs(1, "/api/items/12", 10.0), _obs(2, "/api/items/13", 5.0, status=404),
          _obs(3, "/api/items/new", 7.0, profile="user_a"), _obs(4, "/api/items", 8.0,
                                                                  method="POST")]


def _snapshot(conn, run):
    ents = {r["eid"]: (r["knowledge"], r["first_seen"], r["last_seen"],
                       json.loads(r["attrs"])) for r in conn.execute(
        "SELECT * FROM dg_entity WHERE run_id=?", (run,))}
    flows = {r["fid"]: (r["knowledge"], r["first_seen"], r["last_seen"],
                        json.loads(r["attrs"])) for r in conn.execute(
        "SELECT * FROM dg_flow WHERE run_id=?", (run,))}
    ev = sorted(tuple(r) for r in conn.execute(
        "SELECT ref, event_key FROM dg_evidence WHERE run_id=?", (run,)))
    return ents, flows, ev


def _record(store, run, events, **kw):
    rec = trace.TraceRecorder(store, run, **kw)
    for kind, body, key, t in events:
        rec.emit(kind, body, key=key, t=t)
    return rec.close()


def test_duplicates_out_of_order_and_replay_give_one_model(tmp_path):
    with Store(tmp_path / "s.db") as store:
        a = store.start_run("auto", "h")
        b = store.start_run("auto", "h")
        _record(store, a, EVENTS)
        shuffled = EVENTS[:]
        random.Random(7).shuffle(shuffled)
        stats = _record(store, b, shuffled + shuffled[:2])          # delivered twice
        assert stats["duplicates"] == 2 and stats["written"] == len(EVENTS)
        assert _snapshot(store.conn, a)[0] == _snapshot(store.conn, b)[0]
        assert _snapshot(store.conn, a)[1] == _snapshot(store.conn, b)[1]
        before = _snapshot(store.conn, a)
        assert trace.rebuild(store.conn, a) == len(EVENTS)
        assert _snapshot(store.conn, a) == before                  # replay == incremental
        assert trace.rebuild(store.conn, a) == len(EVENTS)
        assert _snapshot(store.conn, a) == before                  # and repeatable
        n = store.conn.execute("SELECT COUNT(*) FROM trace_event WHERE run_id=?",
                               (a,)).fetchone()[0]
        assert n == len(EVENTS)


def test_first_and_last_seen_conflicts_and_grouping_are_kept(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        _record(store, run, EVENTS)
        rows = {r["eid"]: r for r in store.conn.execute(
            "SELECT * FROM dg_entity WHERE run_id=?", (run,))}
        ids = rows[f"iface:{O}|GET|/api/items/{{id}}"]
        assert (ids["first_seen"], ids["last_seen"]) == (5.0, 10.0)
        attrs = json.loads(ids["attrs"])
        assert attrs["status"] == [200, 404]                       # both, not the last
        assert attrs["grouping"] == ["inferred: id-shaped path segments grouped"]
        # a word is never merged with an id; a method is its own interface
        assert f"iface:{O}|GET|/api/items/new" in rows
        assert f"iface:{O}|POST|/api/items" in rows
        flow = store.conn.execute(
            "SELECT attrs FROM dg_flow WHERE run_id=? AND dst=?",
            (run, f"iface:{O}|GET|/api/items/{{id}}")).fetchone()
        assert json.loads(flow["attrs"])["data"] == ["data:query"]


def test_a_restarted_recorder_continues_and_reimport_adds_nothing(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        _record(store, run, EVENTS[:2])
        _record(store, run, EVENTS)                                # restart + replay
        seqs = [r[0] for r in store.conn.execute(
            "SELECT seq FROM trace_event WHERE run_id=? ORDER BY id", (run,))]
        assert len(seqs) == 4 and seqs == sorted(seqs) and len(set(seqs)) == 4
        evidence = store.conn.execute(
            "SELECT COUNT(*) FROM dg_evidence WHERE run_id=? AND ref=?",
            (run, f"iface:{O}|GET|/api/items/{{id}}")).fetchone()[0]
        assert evidence == 2                                       # never double-counted


def test_unknown_time_stays_unknown(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run)
        rec.emit("observe.page", {"src": "spider", "url": O + "/a", "origin": O},
                 key="p", t=None)
        rec.emit("run.start", {"origins": [O]}, key="r")           # now
        rec.close()
        t = dict(store.conn.execute("SELECT key, t FROM trace_event").fetchall())
        assert t["p"] is None and t["r"] is not None
        row = store.conn.execute("SELECT first_seen FROM dg_entity WHERE eid=?",
                                 (f"iface:{O}|GET|/a",)).fetchone()
        assert row["first_seen"] is None


def test_backpressure_flushes_and_a_failed_batch_is_counted_never_silent(tmp_path, caplog):
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        stats = _record(store, run, EVENTS, max_buffer=2)
        assert stats["forced_flushes"] == 2 and stats["buffer_peak"] == 2

        class _Broken:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *a):
                if sql.startswith("INSERT OR IGNORE INTO trace_event"):
                    raise sqlite3.OperationalError("database is locked")
                return self._conn.execute(sql, *a)

            def __getattr__(self, name):
                return getattr(self._conn, name)

        class _Store:
            conn = _Broken(store.conn)

        rec = trace.TraceRecorder(_Store(), run)
        rec.emit("run.end", {"status": "complete"}, key="lost")
        stats = rec.close()
        assert stats["dropped"] == 1 and stats["written"] == 0
        metrics = dict(store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=? AND key='trace_dropped'",
            (run,)).fetchall())
        assert metrics["trace_dropped"] == 1.0
        from fuzzlab.report.diagram import status
        assert status(store.conn, run)["state"] == "partial"


def test_concurrent_runs_on_their_own_threads_never_mix(tmp_path):
    path = tmp_path / "s.db"
    with Store(path) as store:
        runs = [store.start_run("auto", "h") for _ in range(4)]
    errors = []

    def work(run):
        try:
            with Store(path) as store:
                rec = trace.TraceRecorder(store, run, max_buffer=7)
                with trace.recording(rec):
                    for i in range(60):
                        trace.emit("exchange", {"origin": O, "url": O + f"/r{run}",
                                                "method": "GET", "outcome": "response",
                                                "status": 200, "role": "probe"},
                                   key=f"x{i}")
                rec.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(r,)) for r in runs]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    with Store(path) as store:
        for run in runs:
            urls = {json.loads(r[0])["url"] for r in store.conn.execute(
                "SELECT body FROM trace_event WHERE run_id=?", (run,))}
            assert urls == {O + f"/r{run}"}
            assert store.conn.execute("SELECT COUNT(*) FROM trace_event WHERE run_id=?",
                                      (run,)).fetchone()[0] == 60


@pytest.mark.parametrize("url,expected,grouped", [
    ("http://h/a/12/b", "/a/{id}/b", True),
    ("http://h/a/680f1206-1ab0-40bc-8690-b13c5a44bcc2", "/a/{id}", True),
    ("http://h/rest/track-order/undefined", "/rest/track-order/{id}", True),
    ("http://h/product/{id}", "/product/{id}", False),             # already a template
    ("http://h/v2/users?id=7#x", "/v2/users", False),              # never the query
    ("http://h/api/Products", "/api/Products", False),
])
def test_interface_paths_group_ids_only(url, expected, grouped):
    assert trace.interface_path(url) == (expected, grouped)


def test_no_recorder_no_events_and_no_cost():
    assert trace.active() is None
    assert trace.emit("run.start", {}) is None


# --- SP-48: one writer of the trace and the diagram model --------------------------------
import re as _re  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_WRITE = _re.compile(r"\b(INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM)\s+"
                     r"(trace_event|dg_entity|dg_flow|dg_evidence)\b", _re.I)


def writers(sources: dict[str, str]) -> list[str]:
    return sorted(f"{name}: {m.group(2)}" for name, text in sources.items()
                  for m in _WRITE.finditer(text))


def test_only_core_trace_writes_the_trace_and_the_model():
    root = _Path(__file__).resolve().parents[1] / "fuzzlab"
    found = writers({str(p.relative_to(root)): p.read_text()
                     for p in root.rglob("*.py")
                     if p.name not in ("trace.py", "migrations.py")})
    assert found == []
    own = writers({"trace.py": (root / "core" / "trace.py").read_text()})
    assert own                                      # not vacuous: the owner does write


def test_the_writer_guard_catches_a_synthetic_offender():
    assert writers({"x.py": 'conn.execute("INSERT INTO dg_flow (fid) VALUES (?)")',
                    "y.py": 'c.execute("DELETE FROM trace_event WHERE run_id=?")',
                    "z.py": 'c.execute("SELECT * FROM dg_flow")'}) == \
        ["x.py: dg_flow", "y.py: trace_event"]


def test_a_unit_of_work_closing_is_written_at_once(tmp_path):
    """Measured on Juice Shop: events buffered before a quiet phase (a browser
    confirmation sends nothing through the sender) waited 38.7 s for the next event.
    A test's or strategy's end flushes, whatever the clock says."""
    clock = [0.0]
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run, flush_seconds=3600, clock=lambda: clock[0])
        rec.emit("exchange", {"origin": O, "url": O + "/a", "method": "GET"}, key="x1")
        assert store.conn.execute("SELECT COUNT(*) FROM trace_event").fetchone()[0] == 0
        clock[0] = 40.0                                     # a quiet phase
        rec.emit("test.strategy", {"test": "t1", "outcome": "not_confirmed"}, key="s1")
        assert store.conn.execute("SELECT COUNT(*) FROM trace_event").fetchone()[0] == 2
        rec.close()


def test_executed_counts_a_tests_own_sends_on_its_interface(tmp_path):
    """BUG-0515: *executed* is a test's own sends, answered or not, on the test's
    interface; its follow-up, restore or retry never counts, on any interface."""
    from fuzzlab.report.diagram import interface_coverage
    ex = {"origin": O, "method": "GET", "test": "t1"}
    events = [
        ("test.start", {"test": "t1", "url": O + "/a", "origin": O, "method": "GET"},
         "ts", 1.0),
        ("exchange", ex | {"url": O + "/a?q=1", "role": "probe", "outcome": "response",
                           "status": 200}, "x1", 2.0),
        ("exchange", ex | {"url": O + "/a?q=2", "role": "mutation", "outcome": "timeout"},
         "x2", 3.0),
        ("exchange", ex | {"url": O + "/b", "role": "follow-up", "outcome": "response",
                           "status": 200, "parent": "x1"}, "x3", 4.0),
        ("exchange", ex | {"url": O + "/a?q=3", "role": "retry", "outcome": "unobserved",
                           "parent": "x2"}, "x4", 5.0),
        ("exchange", ex | {"url": O + "/c", "role": "restore", "outcome": "response",
                           "status": 200}, "x5", 6.0),
        ("exchange", {"origin": O, "method": "GET", "url": O + "/d", "role": "baseline",
                      "outcome": "response", "status": 200}, "x6", 7.0)]
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        _record(store, run, events)
        cov = interface_coverage(store.conn, run)
    assert cov[f"iface:{O}|GET|/a"]["executed"] == 2
    for other in ("/b", "/c", "/d"):
        assert cov.get(f"iface:{O}|GET|{other}", {}).get("executed", 0) == 0


def test_kind_and_capped_attributes_do_not_depend_on_order(tmp_path):
    """BUG-0516: an entity's kind and a capped attribute set are the same whatever the
    order and batching of the events, and equal to a rebuild."""
    many = [("observe.exchange", {"src": "capture", "ref": f"r{i}", "method": "GET",
                                  "url": O + "/p", "origin": O, "status": 100 + i},
             f"s{i}", float(i)) for i in range(trace.MAX_ATTR_VALUES + 5)]
    page = [("observe.page", {"src": "spider", "url": O + "/p", "origin": O,
                              "ref": "discovered_pages row 1"}, "pg", None)]
    snaps = []
    with Store(tmp_path / "s.db") as store:
        for order, batch in ((page + many, 3), (many[::-1] + page, 1000),
                             (many[7:] + page + many[:7], 2)):
            run = store.start_run("auto", "h")
            _record(store, run, order, max_buffer=batch)
            snap = _snapshot(store.conn, run)
            trace.rebuild(store.conn, run)
            assert _snapshot(store.conn, run) == snap            # rebuild == incremental
            snaps.append(snap)
        assert snaps[0] == snaps[1] == snaps[2]
        ents = snaps[0][0]
        iface = ents[f"iface:{O}|GET|/p"]
        assert iface[3]["status"] == list(range(100, 100 + trace.MAX_ATTR_VALUES))
        assert iface[3]["status_more"] is True
        kind = store.conn.execute("SELECT kind FROM dg_entity WHERE eid=?",
                                  (f"iface:{O}|GET|/p",)).fetchall()
        assert {r[0] for r in kind} == {"interface"}             # the stronger kind


def test_the_counters_are_written_while_the_run_is_live(tmp_path):
    """BUG-0516: dropped events and lag reach ``run_metrics`` during the run, not only
    at close."""
    clock = [0.0]
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run, clock=lambda: clock[0])
        rec.emit("run.start", {"origins": [O]}, key="r")
        metrics = dict(store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run,)).fetchall())
        assert metrics["trace_written"] == 1.0                   # before any close
        clock[0] = trace.METRICS_SECONDS + 0.1
        rec.emit("test.start", {"test": "t1"}, key="t")
        metrics = dict(store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run,)).fetchall())
        assert metrics["trace_written"] == 2.0
        rec.close()


JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")


@pytest.mark.parametrize("url,secret", [
    ("http://admin:hunter2@h/x", "hunter2"),                      # userinfo
    ("http://h/a;jsessionid=0123456789ABCDEFabcdef/b", "0123456789ABCDEFabcdef"),
    (f"http://h/cb#access_token={JWT}&state=1", JWT),             # an implicit grant
    (f"http://h/cb#code=Zq8vLm3NpR7sTw2X", "Zq8vLm3NpR7sTw2X"),
    (f"http://h/reset/{JWT}", JWT),                               # a token in the path
    ("/r?token=plain", "plain"),                                  # relative
    # a URL embedded in a payload: the token ends where the text does (BUG-0521)
    ("$(curl http://127.0.0.1:8123/cb/0123456789abcdef0123456789abcdef)",
     "0123456789abcdef0123456789abcdef"),
    ("`curl http://127.0.0.1:8123/cb/0123456789abcdef0123456789abcdef`",
     "0123456789abcdef0123456789abcdef"),
])
def test_safe_ref_withholds_every_token_shape(url, secret):
    """BUG-0514: what `safe_ref` returns never holds the secret, and a path token is
    grouped like any id."""
    assert secret not in trace.safe_ref(url)
    path, _grouped = trace.interface_path(trace.safe_ref(url))
    assert secret not in path and ";" not in path


def test_a_payload_preview_never_keeps_its_canary_token():
    """BUG-0521: an out-of-band payload's preview keeps no canary token, whatever
    character follows it."""
    tok = "0123456789abcdef0123456789abcdef"
    for template in ("$(curl {u})", "`curl {u}`", ";curl {u}", "|wget -q {u}&"):
        value = template.format(u=f"http://127.0.0.1:8123/cb/{tok}")
        body = trace.scrub_event({"value_preview": trace.value_preview("cmd", value)})
        assert tok[:16] not in body["value_preview"]


def test_scrub_event_passes_relative_urls_under_url_keys():
    body = trace.scrub_event({"url": "/r?token=x9", "redirect": f"/cb#access_token={JWT}",
                              "location": "query", "identity": "alice"})
    assert "x9" not in body["url"] and JWT not in body["redirect"]
    assert body["location"] == "query" and body["identity"] == "alice"


# --- FR-FUZZ-62 (CC-CORE-0065): the M6 browser's steps -------------------------------
def _m6(step, **body):
    return {"test": "t1", "strategy": "xss-dom:browser-execution", "visit": "v1",
            "step": step, "method": "GET", "origin": O} | body


def test_executed_counts_an_m6_visits_store_and_observe_loads(tmp_path):
    """FR-FUZZ-62: an M6 visit's store and observe loads are the test's own sends
    (a ``no_status`` one was made too); a refused placement and the page counts are
    not."""
    from fuzzlab.report.diagram import interface_coverage
    events = [
        ("test.start", {"test": "t1", "url": O + "/a", "origin": O, "method": "GET"},
         "ts", 1.0),
        ("browser.step", _m6("navigate", url=O + "/a", outcome="response", status=200),
         "b1", 2.0),
        ("browser.step", _m6("store", url=O + "/s", method="POST", outcome="response",
                             status=200), "b2", 3.0),
        ("browser.step", _m6("store", url=O + "/s", method="POST", outcome="no_status"),
         "b3", 4.0),
        ("browser.step", _m6("navigate", url=O + "/a", outcome="not_sent"), "b4", 5.0),
        ("browser.step", _m6("page", answered=7, failed=1, refused=2,
                             outcome="counted"), "b5", 6.0),
        ("browser.step", _m6("end", outcome="executed"), "b6", 7.0)]
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        _record(store, run, events)
        cov = interface_coverage(store.conn, run)
    assert cov[f"iface:{O}|GET|/a"]["executed"] == 3
    assert cov.get(f"iface:{O}|POST|/s", {}).get("executed", 0) == 0


def test_the_m6_browsers_overlay_flow_is_keyed_apart_from_the_tools_exchanges(tmp_path):
    """FR-FUZZ-62 (PA-0515(1)): the tool's exchange and the M6 browser's load of one
    interface are two flows, each with its own evidence; a refused placement is
    none."""
    events = [
        ("exchange", {"test": "t1", "origin": O, "method": "GET", "url": O + "/a?q=1",
                      "role": "probe", "outcome": "response", "status": 200}, "x1", 1.0),
        ("browser.step", _m6("navigate", url=O + "/a", outcome="response", status=200),
         "b1", 2.0),
        ("browser.step", _m6("navigate", url=O + "/a", outcome="timeout"), "b2", 3.0),
        ("browser.step", _m6("navigate", url=O + "/c", outcome="not_sent"), "b3", 4.0)]
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        _record(store, run, events)
        ents, flows, ev = _snapshot(store.conn, run)
    iface = f"iface:{O}|GET|/a"
    tool = f"flow:test:{trace.TOOL}->{iface}:http"
    m6 = f"flow:test:{trace.M6_BROWSER}->{iface}:http"
    assert {tool, m6} <= set(flows)
    assert [k for r, k in ev if r == tool] == ["x1"]
    assert sorted(k for r, k in ev if r == m6) == ["b1", "b2"]
    assert ents[trace.M6_BROWSER][0] == "observed"
    assert f"iface:{O}|GET|/c" not in ents                  # never sent: no interface


def test_browser_steps_reduce_independently_of_order(tmp_path):
    """FR-FUZZ-62 (PA-0516): the M6 branch is order- and batching-independent and equal
    to a rebuild."""
    steps = [("browser.step", _m6("navigate", url=O + f"/p{i % 3}", outcome="response",
                                  status=200 + i), f"b{i}", float(i)) for i in range(9)]
    steps += [("exchange", {"test": "t1", "origin": O, "method": "GET",
                            "url": O + "/p1", "role": "probe", "outcome": "response",
                            "status": 200}, "x", 4.5),
              ("browser.step", _m6("store", url=O + "/s", method="POST",
                                   outcome="error", error="Error"), "bs", 0.5)]
    snaps = []
    with Store(tmp_path / "s.db") as store:
        for order, batch in ((steps, 2), (steps[::-1], 1000),
                             (steps[4:] + steps[:4], 3)):
            run = store.start_run("auto", "h")
            _record(store, run, order, max_buffer=batch)
            snap = _snapshot(store.conn, run)
            trace.rebuild(store.conn, run)
            assert _snapshot(store.conn, run) == snap
            snaps.append(snap)
    assert snaps[0] == snaps[1] == snaps[2]
    flows = snaps[0][1]
    assert flows[f"flow:test:{trace.M6_BROWSER}->iface:{O}|POST|/s:http"][3]["outcome"] \
        == ["error"]


def test_a_run_that_does_not_decide_its_candidate_is_not_evaluated(tmp_path):
    """CC-UI-0066 (BUG-0523): *evaluated* counts the runs that reached a verdict on the
    test's candidate. A stored-XSS interface whose only candidate is inconclusive
    (its store unplaceable) shows no evaluation from the non-deciding reflected run; a
    confirmation counts whoever made it (recorded ``decides`` true); an older event
    without ``decides`` counts as before."""
    from fuzzlab.report.diagram import interface_coverage

    def strategy(test, name, outcome, key, **extra):
        return ("test.strategy", {"test": test, "strategy": name, "outcome": outcome}
                | extra, key, 2.0)
    events = [
        ("test.start", {"test": "t1", "url": O + "/board", "origin": O, "method": "POST"},
         "s1", 1.0),
        strategy("t1", "xss-reflected:reflected-context", "not_confirmed", "a",
                 decides=False),
        strategy("t1", "xss-stored:browser-execution", "unplaceable", "b", decides=True),
        ("test.start", {"test": "t2", "url": O + "/c", "origin": O, "method": "GET"},
         "s2", 1.0),
        strategy("t2", "xss-reflected:reflected-context", "confirmed", "c", decides=True),
        strategy("t2", "sqli:error-signature", "not_confirmed", "d"),        # older event
        ("test.start", {"test": "t3", "url": O + "/d", "origin": O, "method": "GET"},
         "s3", 1.0),
        strategy("t3", "xss-stored:browser-execution", "not_confirmed", "e",
                 decides=True)]
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        _record(store, run, events)
        cov = interface_coverage(store.conn, run)
    assert cov[f"iface:{O}|POST|/board"]["evaluated"] == 0
    assert cov[f"iface:{O}|GET|/c"]["evaluated"] == 2
    assert cov[f"iface:{O}|GET|/d"]["evaluated"] == 1
