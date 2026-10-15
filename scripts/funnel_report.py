#!/usr/bin/env python3
"""Where each answer-key case is lost: a per-stage funnel for one run.

For every positive case of a ground-truth contract, report the furthest stage the run
reached for its input (same path, method-insensitive, same parameter name):

    reached    the input exists in the run's points (endpoint + parameter)
    candidate  an audit rule made it a candidate of the case's category
    probed     the oracle sent at least one attempt for such a candidate
    confirmed  a finding exists for the input

and, beside it (DISC-CAPTURE §9, FR-FUZZ-52), the discovery and admission stages:

    discovered  an endpoint of **any** source (a link, a form, an observed request, a
                request the crawl recorded and never sent) has the input, method-aware
                (path key + method), and op-key-aware when the case names an op key
    buildable   `harness.auto`'s point builder makes a non-skipped point for it
    refused     the builder skipped it, with the builder's reason (a policy: a
                destructive URL, a credential, a login form without isolation, a
                captured write opted out with --no-probe-captured-writes, ...)

A change is judged by which stage count it moves (discovery reach first). Offline:
reads the store only.

    python3 scripts/funnel_report.py --store run.db --ground-truth lab/ground-truth-<app>
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


#: The base URL the point builder joins stored paths to here (only paths are compared).
_BASE = "http://funnel.invalid"


def _admission(db, run_id: int, probe_captured_writes: bool, browser: bool):
    """``(buildable, refused)``: the point keys ``(path key, METHOD, param)`` the run's
    point builder (`harness.auto.injection_points_from_store`, the one builder) makes,
    and ``{key: reason}`` for those it skips."""
    from types import SimpleNamespace

    from fuzzlab.harness.auto import injection_points_from_store
    skipped: list = []
    points = injection_points_from_store(
        SimpleNamespace(conn=db), run_id, _BASE, skipped=skipped, isolated=set(),
        browser_available=browser, probe_captured_writes=probe_captured_writes)
    built = {(_key(p.url), p.method.upper(), p.param) for p in points}
    refused: dict = {}
    for path, method, param, reason in skipped:
        refused.setdefault((_key(path), (method or "GET").upper(), param), reason)
    return built, refused


def funnel(store: str, gt_dir: str | None, run_id: int | None = None, *,
           cases=None, probe_captured_writes: bool = True,
           browser: bool = False) -> list[dict]:
    """One row per positive case (``cases``, or the contract at ``gt_dir``)."""
    db = sqlite3.connect(store)
    db.row_factory = sqlite3.Row
    if run_id is None:
        run_id = db.execute("SELECT max(id) FROM run").fetchone()[0]
    if cases is None:
        from fuzzlab.labels import contract
        cases = contract.load(gt_dir).positives()
    endpoints = [(_key(r["url"]), (r["method"] or "GET").upper(), r["op_key"] or "",
                  r["name"]) for r in db.execute(
        "SELECT e.url, e.method, e.op_key, p.name FROM parameter p "
        "JOIN endpoint e ON p.endpoint_id = e.id WHERE p.run_id = ?", (run_id,))]
    discovered = {(k, m, n) for k, m, _o, n in endpoints}
    discovered_op = {(k, m, o, n) for k, m, o, n in endpoints}
    built, refused = _admission(db, run_id, probe_captured_writes, browser)
    points = {(k, n) for k, _m, _o, n in endpoints}
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
    findings = {(_key(r["url"]), r["param"], r["vuln_class"]) for r in db.execute(
        "SELECT url, param, vuln_class FROM finding WHERE run_id = ?", (run_id,))}
    rows = []
    for case in cases:
        k = (_key(case.url), case.param)
        method = (case.method or "GET").upper()
        op = getattr(case, "op_key", None)
        found = ((k[0], method, op, k[1]) in discovered_op if op
                 else (k[0], method, k[1]) in discovered)
        want = CATEGORY.get(case.vuln_class, {case.vuln_class})
        stage = None
        if k in points:
            stage = "reached"
        if cands.get(k, set()) & want:
            stage = "candidate"
        if any((k, c) in probed for c in want):
            stage = "probed"
        if (k[0], k[1], case.vuln_class) in findings:  # the case's own class only
            stage = "confirmed"
        pkey = (k[0], method, k[1])
        rows.append({"case": case.case_id, "class": case.vuln_class, "path": k[0],
                     "param": k[1], "stage": stage or "not reached",
                     "method": method, "discovered": found,
                     "buildable": pkey in built,
                     "refused": None if pkey in built else refused.get(pkey)})
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--store", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--run", type=int)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-probe-captured-writes", action="store_true",
                    help="judge admission as a run with this flag did (D67)")
    ap.add_argument("--browser", action="store_true",
                    help="judge admission as a run with --browser did (fragment points)")
    args = ap.parse_args(argv)
    rows = funnel(args.store, args.ground_truth, args.run,
                  probe_captured_writes=not args.no_probe_captured_writes,
                  browser=args.browser)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        admission = ("buildable" if r["buildable"] else
                     f"refused: {r['refused']}" if r["refused"] else "-")
        print(f"{r['case']:<11} {r['class']:<26} {r['path']:<24} {r['param']:<16} "
              f"{r['stage']:<11} {'discovered' if r['discovered'] else '-':<10} "
              f"{admission}")
    n = len(rows)
    order = ("not reached",) + STAGES
    print(f"{'discovered':>10}: {sum(1 for r in rows if r['discovered'])}/{n}")
    print(f"{'buildable':>10}: {sum(1 for r in rows if r['buildable'])}/{n}")
    why: dict = {}
    for r in rows:
        if r["refused"]:
            why[r["refused"]] = why.get(r["refused"], 0) + 1
    print(f"{'refused':>10}: {sum(why.values())}/{n}"
          + (" (" + ", ".join(f"{k} x{v}" for k, v in sorted(why.items())) + ")"
             if why else ""))
    for i, stage in enumerate(STAGES):
        at_least = sum(1 for r in rows if order.index(r["stage"]) >= i + 1)
        print(f"{stage:>10}: {at_least}/{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
