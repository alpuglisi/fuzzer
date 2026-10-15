"""``fuzzlab report`` — print a reproducible evaluation report for a stored run.

Read-only and offline (no traffic). Defaults to the latest run; ``--json`` emits the
canonical JSON artifact for diffing/reproducibility. ``--store`` is optional: the store
is resolved by `core.storepath` (FR-CORE-400) and named on stderr, so stdout stays the
report. A missing store is refused, never created (FR-UI-401).
"""

from __future__ import annotations

import argparse
import sys

from fuzzlab.core import storepath
from fuzzlab.core.store import Store
from fuzzlab.report.report import build_report, format_json, format_text


def build_parser(prog: str = "fuzzlab report") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog)
    p.add_argument("--store", default=None,
                   help="Unified store (SQLite) to read (default: $FUZZLAB_STORE, "
                        "$FUZZLAB_STORE_PATH, else ./fuzzlab.db)")
    p.add_argument("--run", default="latest",
                   help="Run id to report on, or 'latest' (default)")
    p.add_argument("--json", action="store_true", help="Emit canonical JSON")
    return p


def main(argv: list[str], *, prog: str = "fuzzlab report") -> int:
    p = build_parser(prog)
    args = p.parse_args(argv)
    try:
        resolved = storepath.resolve(args.store)
        storepath.check_readable(resolved)
    except storepath.StorePathError as exc:
        p.error(str(exc))
    print(storepath.describe(resolved), file=sys.stderr)

    with Store(resolved.path) as store:
        run_id = None if args.run == "latest" else int(args.run)
        report = build_report(store, run_id)
        print(format_json(report) if args.json else format_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
