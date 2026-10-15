#!/usr/bin/env python3
"""Where each answer-key case is lost: a per-stage funnel for one run.

For every positive case of a ground-truth contract, report the furthest stage the run
reached for its input (same path, method-insensitive, same parameter name):

    reached    the input exists in the run's points (endpoint + parameter)
    candidate  an audit rule made it a candidate of the case's category
    probed     the oracle sent at least one attempt for such a candidate
    confirmed  a finding exists for the input

A change is judged by which stage count it moves (discovery reach first). Offline:
reads the store only.

    python3 scripts/funnel_report.py --store run.db --ground-truth lab/ground-truth-juice-shop
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

STAGES = ("reached", "candidate", "probed", "confirmed")

#: answer-key category -> the categories the audit rules use for it
CATEGORY = {
    "sqli": {"sql-injection"}, "xss-dom": {"xss"}, "xss-reflected": {"xss"},
    "xss-stored": {"xss"}, "ssti": {"server-side-template-injection"},
    "ssrf": {"ssrf"}, "open_redirect": {"open-redirect"}, "xxe": {"xxe"},
    "path_traversal": {"path-traversal", "file-inclusion"},
    "insecure_deserialization": {"insecure-deserialization"},
}


def _key(url: str) -> str:
    """A path key: the path, or the hash route for an SPA fragment URL."""
    parts = urlsplit(url or "")
    if parts.fragment.startswith("/"):
        return "/#" + parts.fragment.split("?", 1)[0]
    return parts.path or "/"


def funnel(store: str, gt_dir: str, run_id: int | None = None) -> list[dict]:
    from fuzzlab.labels import contract
    db = sqlite3.connect(store)
    db.row_factory = sqlite3.Row
    if run_id is None:
        run_id = db.execute("SELECT max(id) FROM run").fetchone()[0]
    points = {(_key(r["url"]), r["name"]) for r in db.execute(
        "SELECT e.url, p.name FROM parameter p JOIN endpoint e ON p.endpoint_id = e.id "
        "WHERE p.run_id = ?", (run_id,))}
    cands: dict[tuple, set] = {}
    probed: set[tuple] = set()
    for r in db.execute("SELECT c.id, c.evidence, (SELECT count(*) FROM attempt a "
                        "WHERE a.candidate_id = c.id) n FROM candidate c "
                        "WHERE c.run_id = ?", (run_id,)):
        e = json.loads(r["evidence"] or "{}")
        k = (_key(e.get("url", "")), e.get("param"))
        cands.setdefault(k, set()).add(e.get("category"))
        points.add(k)                       # a candidate's point was reached
        if r["n"]:
            probed.add((k, e.get("category")))
    found = {(_key(r["url"]), r["param"], r["vuln_class"]) for r in db.execute(
        "SELECT url, param, vuln_class FROM finding WHERE run_id = ?", (run_id,))}
    rows = []
    for case in contract.load(gt_dir).positives():
        k = (_key(case.url), case.param)
        want = CATEGORY.get(case.vuln_class, {case.vuln_class})
        stage = None
        if k in points:
            stage = "reached"
        if cands.get(k, set()) & want:
            stage = "candidate"
        if any((k, c) in probed for c in want):
            stage = "probed"
        if (k[0], k[1], case.vuln_class) in found:     # the case's own class only
            stage = "confirmed"
        rows.append({"case": case.case_id, "class": case.vuln_class, "path": k[0],
                     "param": k[1], "stage": stage or "not reached"})
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--store", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--run", type=int)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rows = funnel(args.store, args.ground_truth, args.run)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        print(f"{r['case']:<11} {r['class']:<26} {r['path']:<24} {r['param']:<16} {r['stage']}")
    n = len(rows)
    order = ("not reached",) + STAGES
    for i, stage in enumerate(STAGES):
        at_least = sum(1 for r in rows if order.index(r["stage"]) >= i + 1)
        print(f"{stage:>10}: {at_least}/{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
