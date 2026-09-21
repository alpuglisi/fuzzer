"""``fuzzlab report`` — print a reproducible evaluation report for a stored run.

Read-only and offline (no traffic). Defaults to the latest run; ``--json`` emits the
canonical JSON artifact for diffing/reproducibility.
"""

from __future__ import annotations

import argparse

from fuzzlab.core.store import Store
from fuzzlab.report.report import build_report, format_json, format_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fuzzlab report")
    p.add_argument("--store", required=True, help="Unified store (SQLite) to read")
    p.add_argument("--run", default="latest",
                   help="Run id to report on, or 'latest' (default)")
    p.add_argument("--json", action="store_true", help="Emit canonical JSON")
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)

    with Store(args.store) as store:
        run_id = None if args.run == "latest" else int(args.run)
        report = build_report(store, run_id)
        print(format_json(report) if args.json else format_text(report))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
