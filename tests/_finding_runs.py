"""Runs with findings, for the finding → diagram link (FR-UI-513) tests: the real pipeline
(`run_auto`) against a loopback app, traced or not (as ``--no-trace``), and the shapes
production writes when a finding's event is missing or incomplete, written through the
one trace writer."""

from __future__ import annotations

import sqlite3
import threading
from http.server import ThreadingHTTPServer

from fuzzlab.core import trace
from fuzzlab.core.store import Store


def pipeline_runs(path, tmp, *, traced=(True,)) -> list[tuple[int, int]]:
    """One real ``run_auto`` per entry of ``traced`` (True: recorded, with the spider's
    import; False: ``trace_events=False``, as ``--no-trace``) against the loopback app
    of `tests.test_diagram_e2e`, each confirming one SQL injection. Returns
    ``[(run_id, finding_id)]`` in order."""
    from fuzzlab.harness.auto import run_auto
    from fuzzlab.tools import store_adapter
    from fuzzlab.tools.probesender import RequestsProbeSender
    from tests.test_diagram_e2e import _App

    server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    db = tmp / "spider.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE IF NOT EXISTS discovered_pages "
                "(url TEXT, status_code INT, source TEXT)")
    con.executemany("INSERT INTO discovered_pages VALUES (?,200,'link')",
                    [(base + "/product/1",), (base + "/product/2",)])
    con.commit()
    con.close()
    out = []
    try:
        with Store(path) as store:
            for on in traced:
                run_id = store.start_run("auto", "h")
                kw = dict(base_url=base + "/", store=store, run_id=run_id,
                          sender=RequestsProbeSender(timeout=0.4), mode="manual",
                          selected_categories=["sql-injection"], points_source="crawl")
                if on:
                    rec = trace.TraceRecorder(store, run_id)
                    try:
                        with trace.recording(rec):
                            store_adapter.import_spider(db, store, run_id)
                            run_auto(**kw)
                    finally:
                        rec.close()
                else:
                    store_adapter.import_spider(db, store, run_id)
                    run_auto(**kw, trace_events=False)
                (fid,) = [r[0] for r in store.conn.execute(
                    "SELECT id FROM finding WHERE run_id=?", (run_id,))]
                out.append((run_id, fid))
    finally:
        server.shutdown()
        server.server_close()
    return out


def recorded_finding(store, *, event: bool = True, test: str | None = "t1",
                     origin: str | None = "http://127.0.0.1:9008") -> tuple[int, int]:
    """A traced run with one finding whose event is missing (``event=False``: its batch
    was dropped) or names no test / no origin (the oracle writes ``test`` None outside a
    test, and no origin for a candidate URL with none)."""
    run_id = store.start_run("auto", "h")
    fid = store.conn.execute(
        "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, url, "
        "method, param) VALUES (?,?,?,?,?,?,?,?)",
        (run_id, "sqli", 1, "error-signature", "{}", "/x", "GET", "q")).lastrowid
    store.conn.commit()
    rec = trace.TraceRecorder(store, run_id)
    rec.emit("run.start", {"origins": [origin] if origin else []}, key="run.start")
    if event:
        rec.emit("finding", {"finding_id": fid, "test": test, "strategy": "s",
                             "mechanism": "error-signature", "vuln_class": "sqli",
                             "url": (origin or "") + "/x", "method": "GET", "param": "q",
                             "location": "query", "origin": origin, "exchanges": []},
                 key=f"finding:{fid}", scope=f"test:{test}" if test else "run")
    rec.emit("run.end", {"status": "complete"}, key="run.end")
    rec.close()
    return run_id, fid
