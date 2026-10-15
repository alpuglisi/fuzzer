"""`fuzzlab flow-anomaly` — the anomaly tripwire over a run's recorded flows (CC-FUZZ-0054).

Reads the local store and **writes** `flow.anomaly_score` / `anomaly_flag` for the run
(FR-ML-23); sends no traffic, so it needs no ``--authorized``. Reached through
`fuzzlab.plugins.optional.import_ml`: without the ML package it exits 2 with a clear
message. Advisory only — "most unusual per host", never "malicious".

``--store`` is optional (`core.storepath`, FR-CORE-400); a missing store is refused,
never created, and the resolved store is named in the summary.
"""

from __future__ import annotations

import argparse
import sys

from fuzzlab.core import storepath
from fuzzlab.core.store import Store
from fuzzlab.plugins.optional import ML_UNAVAILABLE, import_ml


def build_parser(prog: str = "fuzzlab flow-anomaly") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="Score a run's in-scope flows per host with an anomaly detector and "
                    "store flow.anomaly_score / anomaly_flag (writes the store; no traffic).")
    p.add_argument("--store", default=None,
                   help="Unified store (SQLite) to read and write (default: $FUZZLAB_STORE, "
                        "$FUZZLAB_STORE_PATH, else ./fuzzlab.db)")
    p.add_argument("--run", type=int, required=True, help="Run id whose flows to score")
    p.add_argument("--method", choices=["ecod", "iforest"], default="ecod",
                   help="Detector: ecod (parameter-free, default) or iforest (seeded)")
    p.add_argument("--contamination", type=float, default=0.1, metavar="F",
                   help="Flag up to this fraction of EVERY scored host's flows (forced: "
                        "even a clean host gets its most unusual flagged), whole tie "
                        "groups only, in (0, 0.5] (default 0.1)")
    p.add_argument("--seed", type=int, default=0, help="Seed for --method iforest")
    return p


def main(argv: list[str], *, prog: str = "fuzzlab flow-anomaly") -> int:
    p = build_parser(prog)
    args = p.parse_args(argv)
    if not 0 < args.contamination <= 0.5:
        p.error("--contamination must be in (0, 0.5]")
    try:
        resolved = storepath.resolve(args.store)
        storepath.check_readable(resolved)
    except storepath.StorePathError as exc:
        p.error(str(exc))
    flow = import_ml("fuzzlab.ml.flow_anomaly")
    if flow is None:
        print(f"{prog}: {ML_UNAVAILABLE} (fuzzlab.ml)", file=sys.stderr)
        return 2
    with Store(resolved.path) as store:
        r = flow.detect_flow_anomalies(store, args.run, method=args.method,
                                       contamination=args.contamination, seed=args.seed)
    print(f"flow anomalies, run #{r['run_id']} ({r['method']}; up to {r['contamination']} "
          f"of every scored host's flows is flagged — most unusual, not malicious):")
    print(f"  in-scope flows: {r['flows']} (out of scope, ignored: {r['out_of_scope']}); "
          f"scored {r['scored']}; flagged {r['flagged']}")
    if r["skipped_hosts"]:
        print(f"  not scored (fewer than 3 flows): {', '.join(r['skipped_hosts'])}")
    for host, h in r["hosts"].items():
        print(f"  {host}: {h['flagged']} of {h['flows']} flagged")
    for t in r["top"]:
        print(f"    - {t['method']} {t['url']} [{t['status']}]  score {t['score']}")
    print("  (advisory — written to flow.anomaly_score / anomaly_flag; never labels)")
    print(f"  {storepath.describe(resolved)}")
    return 0
