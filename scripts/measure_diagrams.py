#!/usr/bin/env python3
"""Measure the diagram trace's cost (FR-CORE-505, NFR-CORE-trace-overhead).

Two documented workloads, both local and offline (loopback only; no lab needed):

1. **Overhead on the real pipeline.** A loopback app (SQL error on a quote in
   ``/item/<n>``, a reflected ``q`` on ``/search``, a redirect on ``/go``) with ``--points``
   query and path points from a synthetic spider DB; `run_auto` (sql-injection,
   open-redirect, xss categories, the unauthenticated sender) runs ``--repeat`` times
   with the trace on and off, alternating. Reported: wall time per run (median, min,
   max), requests sent, the recorder's own time (``flush_ms``) and events.
2. **A large trace.** ``--events`` synthetic events (discovery observations over
   ``--interfaces`` interfaces, and tests of ``--per-test`` exchanges each) written
   through the recorder; then the time of each view and export over them, and the
   store's size.

Usage: ``python scripts/measure_diagrams.py [--repeat 5] [--points 40] [--events 50000]``.
Prints one JSON document. Nothing is asserted: the numbers are the result.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzzlab.core import trace  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402


class _App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path.startswith("/item/") and "'" in unquote(parts.path):
            status, body = 500, b"You have an error in your SQL syntax"
        elif parts.path == "/go":
            self.send_response(302)
            self.send_header("Location", "/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif parts.path.startswith("/search"):
            q = parse_qs(parts.query).get("q", [""])[0]
            status, body = 200, f"<html><p>{q[:40]}</p></html>".encode()
        else:
            status, body = 200, b"<html>page</html>"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _spider_db(path: Path, base: str, points: int) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE discovered_pages (url TEXT, status_code INT, source TEXT)")
    rows = []
    for i in range(points):
        kind = i % 4
        if kind == 0:
            rows.append((f"{base}/item/{i}", 200, "link"))
        elif kind == 1:
            rows.append((f"{base}/search{i}?q=a", 200, "link"))
        elif kind == 2:
            rows.append((f"{base}/go?to=x{i}", 200, "link"))
        else:
            rows.append((f"{base}/page{i}?id={i}", 200, "link"))
    con.executemany("INSERT INTO discovered_pages VALUES (?,?,?)", rows)
    con.commit()
    con.close()


def overhead(repeat: int, points: int) -> dict:
    from fuzzlab.harness.auto import run_auto
    from fuzzlab.tools import store_adapter
    from fuzzlab.tools.probesender import RequestsProbeSender
    server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    out = {"on": [], "off": []}
    try:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "spider.db"
            _spider_db(db, base, points)
            for i in range(repeat * 2):
                mode = "on" if i % 2 == 0 else "off"
                with Store(Path(tmp) / f"s{i}.db") as store:
                    run = store.start_run("auto", "h")
                    rec = trace.TraceRecorder(store, run) if mode == "on" else None
                    started = time.perf_counter()
                    with trace.recording(rec):
                        store_adapter.import_spider(db, store, run)
                        result = run_auto(base_url=base + "/", store=store, run_id=run,
                                          sender=RequestsProbeSender(), mode="manual",
                                          selected_categories=["sql-injection",
                                                               "open-redirect", "xss"],
                                          points_source="crawl",
                                          trace_events=mode == "on")
                    stats = rec.close() if rec else {}
                    out[mode].append({"seconds": time.perf_counter() - started,
                                      "requests": result.metrics.get("requests"),
                                      "events": stats.get("written"),
                                      "recorder_ms": stats.get("flush_ms"),
                                      "max_lag_ms": stats.get("max_lag_ms"),
                                      "dropped": stats.get("dropped")})
    finally:
        server.shutdown()

    def summary(rows):
        secs = [r["seconds"] for r in rows]
        return {"runs": len(rows), "median_s": round(statistics.median(secs), 3),
                "min_s": round(min(secs), 3), "max_s": round(max(secs), 3),
                "requests": sorted({r["requests"] for r in rows}), "detail": rows}
    on, off = summary(out["on"]), summary(out["off"])
    rec_ms = statistics.median([r["recorder_ms"] for r in out["on"]])
    reqs = out["on"][0]["requests"] or 1
    return {"workload": {"points": points, "repeat": repeat,
                         "categories": ["sql-injection", "open-redirect", "xss"]},
            "trace_on": on, "trace_off": off,
            "median_overhead_s": round(on["median_s"] - off["median_s"], 3),
            "median_overhead_pct": round(100 * (on["median_s"] - off["median_s"])
                                         / off["median_s"], 2),
            "recorder_ms_median": round(rec_ms, 2),
            "recorder_ms_per_request": round(rec_ms / reqs, 4)}


def large(events: int, interfaces: int, per_test: int) -> dict:
    from fuzzlab.report import diagram
    origin = "http://127.0.0.1:9100"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "big.db"
        with Store(path) as store:
            run = store.start_run("auto", "h")
            rec = trace.TraceRecorder(store, run)
            started = time.perf_counter()
            rec.emit("run.start", {"origins": [origin]}, key="run.start")
            n, test = 1, 0
            obs = events // 3
            for i in range(obs):
                rec.emit("observe.exchange", {
                    "src": "capture", "ref": f"record {i}", "method": "GET",
                    "url": f"{origin}/api/r{i % interfaces}/{i}", "origin": origin,
                    "status": 200, "params": [["q", "query"]],
                    "action": f"act-{i // 20}"}, key=f"o{i}",
                    scope=f"workflow:act-{i // 20}", t=1000.0 + i)
                n += 1
            while n < events - 2:
                test += 1
                tid = f"t{test}"
                rec.emit("test.start", {"test": tid, "url": f"{origin}/api/r{test}/{{id}}",
                                        "origin": origin, "method": "GET", "param": "q",
                                        "location": "query", "category": "sql-injection"},
                         key=f"test.start:{tid}", scope=f"test:{tid}")
                n += 1
                keys = []
                for j in range(per_test):
                    keys.append(rec.emit("exchange", {
                        "test": tid, "strategy": f"s{j % 3}",
                        "role": ("baseline", "mutation", "control")[j % 3],
                        "method": "GET", "url": f"{origin}/api/r{test}/{{id}}",
                        "origin": origin, "param": "q", "value_preview": f"v{j}",
                        "outcome": "response", "status": 200, "elapsed_ms": 1.0},
                        scope=f"test:{tid}"))
                    n += 1
                rec.emit("test.strategy", {"test": tid, "strategy": "s0",
                                           "outcome": "not_confirmed",
                                           "exchanges": keys[:10]}, scope=f"test:{tid}")
                rec.emit("test.end", {"test": tid, "outcome": "not_confirmed"},
                         key=f"test.end:{tid}", scope=f"test:{tid}")
                n += 2
            rec.emit("run.end", {"status": "complete"}, key="run.end")
            stats = rec.close()
            write_s = time.perf_counter() - started
            conn = store.conn
            timings = {}

            def timed(name, fn):
                t0 = time.perf_counter()
                value = fn()
                timings[name] = round((time.perf_counter() - t0) * 1000, 1)
                return value
            model = timed("dataflow_ms", lambda: diagram.dataflow(conn, run))
            timed("dataflow_overlay_ms", lambda: diagram.dataflow(conn, run, overlay=True))
            scopes = timed("scopes_ms", lambda: diagram.scopes(conn, run))
            timed("sequence_test_ms", lambda: diagram.sequence(conn, run, "test:t1"))
            timed("sequence_workflow_ms", lambda: diagram.sequence(conn, run,
                                                                   "workflow:act-1"))
            timed("evidence_page_ms", lambda: diagram.evidence(
                conn, run, model["nodes"][-1]["id"]))
            timed("export_json_ms", lambda: diagram.export_json(conn, run))
            timed("mermaid_flow_ms", lambda: diagram.mermaid_flow(model))
            timed("rebuild_ms", lambda: trace.rebuild(conn, run))
        size = os.path.getsize(path)
    return {"workload": {"events": stats["written"], "interfaces": interfaces,
                         "exchanges_per_test": per_test, "tests": test,
                         "scopes": len(scopes)},
            "write": {"seconds": round(write_s, 2),
                      "events_per_s": round(stats["written"] / write_s),
                      "recorder_ms": round(stats["flush_ms"], 1),
                      "flushes": stats["flushes"],
                      "forced_flushes": stats["forced_flushes"],
                      "max_lag_ms": round(stats["max_lag_ms"], 1),
                      "dropped": stats["dropped"]},
            "views": timings, "store_bytes": size}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repeat", type=int, default=5)
    p.add_argument("--points", type=int, default=40)
    p.add_argument("--events", type=int, default=50000)
    p.add_argument("--interfaces", type=int, default=2000)
    p.add_argument("--per-test", type=int, default=150)
    args = p.parse_args(argv)
    doc = {"overhead": overhead(args.repeat, args.points),
           "large_trace": large(args.events, args.interfaces, args.per_test),
           "python": sys.version.split()[0], "cpus": os.cpu_count()}
    for row in doc["overhead"]["trace_on"]["detail"] + doc["overhead"]["trace_off"]["detail"]:
        for k, v in list(row.items()):
            if isinstance(v, float):
                row[k] = round(v, 3)
    print(json.dumps(doc, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
