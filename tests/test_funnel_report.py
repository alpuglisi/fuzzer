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
    full = {r["case"]: r for r in _funnel()(str(tmp_path / "u.db"), str(GT))}
    rows = {k: r["stage"] for k, r in full.items()}
    assert rows["JUICE-0006"] == "confirmed"          # ssti on /profile username
    assert rows["JUICE-0008"] == "reached"            # same input, stored XSS: not confirmed
    assert rows["JUICE-0009"] == "not reached"
    # DISC-CAPTURE §9: the existing columns hold, and every row also carries the
    # discovery and admission stages (method-aware; see tests/test_capture.py)
    assert {"case", "class", "path", "param", "stage", "method", "discovered",
            "buildable", "refused"} <= set(full["JUICE-0006"])
    assert full["JUICE-0006"]["discovered"] is (full["JUICE-0006"]["method"] == "POST")
    assert full["JUICE-0009"]["discovered"] is False


def test_the_text_report_keeps_its_stage_lines_and_adds_the_new_ones(tmp_path, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location("funnel_report",
                                                  ROOT / "scripts" / "funnel_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with Store(tmp_path / "u.db") as store:
        store.start_run("auto", "h")
    assert mod.main(["--store", str(tmp_path / "u.db"), "--ground-truth", str(GT)]) == 0
    out = capsys.readouterr().out
    for stage in ("discovered", "buildable", "refused", "reached", "candidate", "probed",
                  "confirmed"):
        assert f"{stage:>10}: " in out, stage


def test_a_checked_candidate_with_no_attempt_row_reads_probed(tmp_path):
    """`auto` writes `candidate.oracle_status`, never attempt rows: a candidate the
    oracle checked is probed; one it never ran is refused with the oracle's status."""
    from fuzzlab.core import oracle_status
    from fuzzlab.labels.contract import Case

    def case(cid, param):
        return Case(case_id=cid, url="/api/items", method="POST", param=param,
                    location="body", vuln_class="sqli", sink_context="sql",
                    expected_vulnerable=True, rendering="server")
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        for param, st in (("q", oracle_status.CHECKED), ("r", oracle_status.SKIPPED_BUDGET)):
            store.conn.execute(
                "INSERT INTO candidate (run_id, rule, evidence, oracle_status) "
                "VALUES (?,?,?,?)", (run, "R-SQLI-PARAM", json.dumps(
                    {"url": "http://h/api/items", "param": param,
                     "category": "sql-injection"}), st))
        store.conn.commit()
    rows = {r["case"]: r for r in _funnel()(str(tmp_path / "u.db"), None,
                                             cases=[case("A", "q"), case("B", "r")])}
    assert rows["A"]["stage"] == "probed"
    assert rows["B"]["stage"] == "candidate"
    assert rows["B"]["refused"] == f"oracle: {oracle_status.SKIPPED_BUDGET}"
