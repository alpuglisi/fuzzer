"""`fuzzlab reveal-holdout` — read a run's sealed blind-holdout metrics (CC-FUZZ-0053).

The holdout's numbers are sealed away from every summary surface (`fuzzlab.core.sealed`);
this command is the one deliberate way to read them, and every use is counted per
holdout membership version: deciding anything from these numbers (a threshold, a
feature, a model kind) uses the holdout up — bump ``fuzzlab.ml.holdout.HOLDOUT_VERSION``
to draw a fresh one. Sends no traffic and needs no ML package.
"""

from __future__ import annotations

import argparse
import os

from fuzzlab.core.sealed import reveal
from fuzzlab.core.store import Store


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fuzzlab reveal-holdout",
        description="Print a run's sealed holdout metrics and count the reveal.")
    p.add_argument("--store", required=True, help="Unified store (SQLite) to read")
    p.add_argument("--run", type=int, required=True, help="Run id")
    return p


def main(argv: list[str]) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    if not os.path.exists(args.store):
        p.error(f"no such store: {args.store}")
    with Store(args.store) as store:
        out = reveal(store, args.run)
    if not out["metrics"]:
        print(f"run #{args.run}: nothing to reveal (no sealed holdout metrics; train with "
              f"`fuzzlab auto --holdout`)")
        return 0
    print(f"run #{args.run}: sealed holdout metrics — reveal #{out['reveals']} of "
          f"holdout version {out['version']} (store-wide). Tuning on these numbers uses "
          f"the holdout up; bump HOLDOUT_VERSION to draw a fresh one.")
    for (model_id, version), metrics in sorted(out["metrics"].items()):
        print(f"  model #{model_id} (holdout v{version}):")
        for key, value in sorted(metrics.items()):
            shown = int(value) if key in ("holdout_rows", "holdout_positives") else \
                round(value, 6)
            print(f"    {key} = {shown}")
    return 0
