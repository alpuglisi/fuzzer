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
