"""`fuzzlab reveal-holdout` — read a run's sealed blind-holdout metrics (CC-FUZZ-0053).

The holdout's numbers are sealed away from every summary surface (`fuzzlab.core.sealed`);
this command is the one deliberate way to read them, and every use is counted per
holdout membership version: deciding anything from these numbers (a threshold, a
feature, a model kind) uses the holdout up — bump ``fuzzlab.ml.holdout.HOLDOUT_VERSION``
to draw a fresh one. Sends no traffic and needs no ML package.

``--store`` is optional (`core.storepath`, FR-CORE-400). Because a reveal is counted, the
resolved store is named on stderr *before* anything is revealed, and the header names
the run (tool, host, start time), so a reveal of the wrong store's run is obvious. A
missing store is refused, never created.
"""

from __future__ import annotations

import argparse
import sys

from fuzzlab.core import storepath
from fuzzlab.core.sealed import reveal
from fuzzlab.core.store import Store


def build_parser(prog: str = "fuzzlab reveal-holdout") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="Print a run's sealed holdout metrics and count the reveal.")
    p.add_argument("--store", default=None,
                   help="Unified store (SQLite) to read (default: $FUZZLAB_STORE, "
                        "$FUZZLAB_STORE_PATH, else ./fuzzlab.db)")
    p.add_argument("--run", type=int, required=True, help="Run id")
    return p


def main(argv: list[str], *, prog: str = "fuzzlab reveal-holdout") -> int:
    p = build_parser(prog)
    args = p.parse_args(argv)
    try:
        resolved = storepath.resolve(args.store)
        storepath.check_readable(resolved)
    except storepath.StorePathError as exc:
        p.error(str(exc))
    # named before the reveal is counted (design §4.3)
    print(storepath.describe(resolved), file=sys.stderr)
    with Store(resolved.path) as store:
        row = store.conn.execute("SELECT tool, config_hash, started_at FROM run WHERE id=?",
                                 (args.run,)).fetchone()
        out = reveal(store, args.run)
    if not out["metrics"]:
        print(f"run #{args.run}: nothing to reveal (no sealed holdout metrics; train with "
              f"`fuzzlab auto --holdout`)")
        return 0
    print(f"run #{args.run}: sealed holdout metrics — reveal #{out['reveals']} of "
          f"holdout version {out['version']} (store-wide). Tuning on these numbers uses "
          f"the holdout up; bump HOLDOUT_VERSION to draw a fresh one.")
    if row is not None:
        print(f"  run: {row['tool']} on {row['config_hash']}, started {row['started_at']}; "
              f"store {resolved.path}")
    for (model_id, version), metrics in sorted(out["metrics"].items()):
        print(f"  model #{model_id} (holdout v{version}):")
        for key, value in sorted(metrics.items()):
            shown = int(value) if key in ("holdout_rows", "holdout_positives") else \
                round(value, 6)
            print(f"    {key} = {shown}")
    return 0
