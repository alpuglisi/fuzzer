#!/usr/bin/env python3
"""Where each answer-key case is lost: a per-stage funnel for one run.

For every positive case of a ground-truth contract, report the furthest stage the run
reached for its input. An input is the same path, HTTP method, location family (query,
body -- a JSON body included --, fragment, header, cookie) and parameter name: a GET
point never reaches a POST case, a query field never a body field. A record that does
not say its method or location still matches on what it does say, and the row's
``attribution`` is then ``partial`` instead of ``exact``, so an ambiguous match is
visible rather than counted silently (lean QC review; the funnel was method-insensitive
before 2026-10-16).

Stages:

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
    # a trailing slash names the same route (Express, Django with APPEND_SLASH...): the
    # app's own `/api/Feedbacks/` is the answer key's `/api/Feedbacks` (2026-10-17)
    return (parts.path or "/").rstrip("/") or "/"


#: a store location -> the answer key's location family
LOCATION_FAMILY = {"json": "body", "form": "body", "multipart": "body"}


def _loc(location: str | None) -> str | None:
    if not location:
        return None
    location = location.lower()
    return LOCATION_FAMILY.get(location, location)


def _method(method: str | None) -> str | None:
    return method.upper() if method else None


def _match(case_id: tuple, rec: tuple) -> str | None:
    """``"exact"`` / ``"partial"`` when record ``rec`` = (path, method, loc, param) is the
    case's input, else None. A known method or location must agree; an unknown one
    makes the match partial."""
    if rec[0] != case_id[0] or rec[3] != case_id[3]:
        return None
    for i in (1, 2):
        if rec[i] is not None and case_id[i] is not None and rec[i] != case_id[i]:
            return None
    return "exact" if rec[1] is not None and rec[2] is not None else "partial"


def _best(case_id: tuple, recs) -> str | None:
    hits = {_match(case_id, r) for r in recs} - {None}
    return "exact" if "exact" in hits else ("partial" if hits else None)


def funnel(store: str, gt_dir: str, run_id: int | None = None) -> list[dict]:
    from fuzzlab.labels import contract
    db = sqlite3.connect(store)
    db.row_factory = sqlite3.Row
    if run_id is None:
        run_id = db.execute("SELECT max(id) FROM run").fetchone()[0]
    points = {(_key(r["url"]), _method(r["method"]), _loc(r["location"]), r["name"])
              for r in db.execute(
                  "SELECT e.url, e.method, p.name, p.location FROM parameter p "
                  "JOIN endpoint e ON p.endpoint_id = e.id WHERE p.run_id = ?", (run_id,))}
    cands: dict[tuple, set] = {}            # identity -> categories
    probed: dict[tuple, set] = {}           # identity -> categories with an attempt
    for r in db.execute(
            "SELECT c.evidence, e.url AS purl, e.method AS pmethod, p.name AS pname, "
            "p.location AS ploc, (SELECT count(*) FROM attempt a "
            "WHERE a.candidate_id = c.id) n FROM candidate c "
            "LEFT JOIN parameter p ON c.parameter_id = p.id "
            "LEFT JOIN endpoint e ON p.endpoint_id = e.id WHERE c.run_id = ?", (run_id,)):
        e = json.loads(r["evidence"] or "{}")
        ident = (_key(e.get("url") or r["purl"] or ""),
                 _method(e.get("method") or r["pmethod"]),
                 _loc(e.get("location") or r["ploc"]),
                 e.get("param") or r["pname"] or e.get("target_identifier"))
        cands.setdefault(ident, set()).add(e.get("category"))
        points.add(ident)                   # a candidate's point was reached
        if r["n"]:
            probed.setdefault(ident, set()).add(e.get("category"))
    # A finding has no location column. Take it from the candidate its attempt probed,
    # else from the one location the run's candidates of that class give the same input.
    found = []
    for r in db.execute(
            "SELECT f.url, f.method, f.param, f.vuln_class, c.evidence FROM finding f "
            "LEFT JOIN attempt a ON f.attempt_id = a.id "
            "LEFT JOIN candidate c ON a.candidate_id = c.id WHERE f.run_id = ?", (run_id,)):
        e = json.loads(r["evidence"] or "{}")
        path, method = _key(r["url"]), _method(r["method"] or e.get("method"))
        loc = _loc(e.get("location"))
        if loc is None:
            want = CATEGORY.get(r["vuln_class"], {r["vuln_class"]})
            locs = {k[2] for k, cats in cands.items()
                    if k[0] == path and k[3] == r["param"] and k[1] in (method, None)
                    and k[2] is not None and cats & want}
            loc = locs.pop() if len(locs) == 1 else None
        found.append(((path, method, loc, r["param"]), r["vuln_class"]))
    rows = []
    for case in contract.load(gt_dir).positives():
        ident = (_key(case.url), _method(case.method), _loc(case.location), case.param)
        want = CATEGORY.get(case.vuln_class, {case.vuln_class})
        stage, how = None, None
        for name, recs in (
                ("reached", points),
                ("candidate", [k for k, cats in cands.items() if cats & want]),
                ("probed", [k for k, cats in probed.items() if cats & want]),
                ("confirmed", [k for k, cls in found if cls == case.vuln_class])):
            hit = _best(ident, recs)
            if hit:
                stage, how = name, hit
        rows.append({"case": case.case_id, "class": case.vuln_class, "path": ident[0],
                     "method": ident[1], "location": ident[2], "param": ident[3],
                     "stage": stage or "not reached", "attribution": how})
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
        mark = " (partial)" if r["attribution"] == "partial" else ""
        print(f"{r['case']:<11} {r['class']:<24} {r['method'] or '?':<5} "
              f"{r['location'] or '?':<8} {r['path']:<24} {r['param']:<16} {r['stage']}{mark}")
    n = len(rows)
    order = ("not reached",) + STAGES
    for i, stage in enumerate(STAGES):
        at_least = sum(1 for r in rows if order.index(r["stage"]) >= i + 1)
        print(f"{stage:>10}: {at_least}/{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
