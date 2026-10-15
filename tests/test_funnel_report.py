"""`scripts/funnel_report.py`: where each answer-key case is lost (goal metric, BUG-0141
recurrence of 2026-10-15). Offline, on a synthetic store."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from fuzzlab.core.store import Store

ROOT = Path(__file__).resolve().parent.parent
GT = ROOT / "lab" / "ground-truth-juice-shop"


def _funnel():
    spec = importlib.util.spec_from_file_location("funnel_report",
                                                  ROOT / "scripts" / "funnel_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.funnel


def test_each_case_reports_the_furthest_stage_and_confirmation_is_class_aware(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        c = store.conn
        ep = c.execute("INSERT INTO endpoint (run_id, url, method, source) VALUES (?,?,?,?)",
                       (run, "http://127.0.0.1:3000/profile", "POST", "crawl")).lastrowid
        c.execute("INSERT INTO parameter (run_id, endpoint_id, name, location) "
                  "VALUES (?,?,?,?)", (run, ep, "username", "body"))
        c.execute("INSERT INTO candidate (run_id, rule, evidence) VALUES (?,?,?)",
                  (run, "SSTI", json.dumps({"url": "http://127.0.0.1:3000/profile",
                                            "param": "username",
                                            "category": "server-side-template-injection"})))
        c.execute("INSERT INTO finding (run_id, vuln_class, label, url, method, param) "
                  "VALUES (?,?,?,?,?,?)", (run, "ssti", 1, "/profile", "POST", "username"))
        c.commit()
    rows = {r["case"]: r["stage"] for r in _funnel()(str(tmp_path / "u.db"), str(GT))}
    assert rows["JUICE-0006"] == "confirmed"          # ssti on /profile username
    assert rows["JUICE-0008"] == "reached"            # same input, stored XSS: not confirmed
    assert rows["JUICE-0009"] == "not reached"
