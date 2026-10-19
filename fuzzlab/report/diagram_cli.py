"""``fuzzlab diagram`` -- export a run's data-flow and sequence diagrams (FR-UI-511).

Read-only and offline (no traffic): reads the run's trace model (`core.trace`) from the
store and prints it as JSON (the full model with evidence keys) or Mermaid (a data-flow
``flowchart``, or one sequence scope). ``--rebuild`` first replays the run's events into
the materialized model (the only write; the events themselves are never changed).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fuzzlab.core import storepath, trace
from fuzzlab.core.store import Store
from fuzzlab.report import diagram

FORMATS = ("json", "mermaid-flow", "mermaid-seq", "status", "scopes")


def build_parser(prog: str = "fuzzlab diagram") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog, description=__doc__.split("\n\n")[0])
    p.add_argument("--store", default=None,
                   help=storepath.store_help("Unified store (SQLite) to read"))
    p.add_argument("--run", default="latest", help="Run id, or 'latest' (default)")
    p.add_argument("--format", choices=FORMATS, default="json",
                   help="json (default): the full model; mermaid-flow: the data flow; "
                        "mermaid-seq: one sequence (--scope); status: completeness; "
                        "scopes: the run's sequence scopes")
    p.add_argument("--scope", default=None,
                   help="Sequence scope for mermaid-seq: test:<id>, workflow:act-<n>, "
                        "capture, spider, finding:<id>, or an exchange key")
    p.add_argument("--overlay", action="store_true",
                   help="mermaid-flow: add the testing overlay (the tool's own traffic)")
    p.add_argument("--out", default=None, help="Write to this file instead of stdout")
    p.add_argument("--rebuild", action="store_true",
                   help="Replay the run's events into the diagram model first")
    return p


def main(argv: list[str], *, prog: str = "fuzzlab diagram") -> int:
    p = build_parser(prog)
    args = p.parse_args(argv)
    try:
        resolved = storepath.resolve(args.store)
        storepath.check_readable(resolved)
    except storepath.StorePathError as exc:
        p.error(str(exc))
    print(storepath.describe(resolved), file=sys.stderr)
    if args.format == "mermaid-seq" and not args.scope:
        p.error("--format mermaid-seq needs --scope (see --format scopes)")
    with Store(resolved.path) as store:
        conn = store.conn
        if args.run == "latest":
            row = conn.execute("SELECT MAX(id) m FROM run").fetchone()
            if row["m"] is None:
                p.error("the store has no runs")
            run_id = int(row["m"])
        else:
            run_id = int(args.run)
        if args.rebuild:
            n = trace.rebuild(conn, run_id)
            print(f"rebuilt the diagram model of run {run_id} from {n} event(s)",
                  file=sys.stderr)
        if args.format == "json":
            text = json.dumps(diagram.export_json(conn, run_id), indent=1,
                              sort_keys=True, ensure_ascii=True)
        elif args.format == "status":
            text = json.dumps(diagram.status(conn, run_id), indent=1, sort_keys=True)
        elif args.format == "scopes":
            text = json.dumps(diagram.scopes(conn, run_id), indent=1, ensure_ascii=True)
        elif args.format == "mermaid-flow":
            text = diagram.mermaid_flow(diagram.dataflow(conn, run_id,
                                                         overlay=args.overlay))
        else:
            text = diagram.mermaid_sequence(diagram.sequence(conn, run_id, args.scope))
    if args.out:
        Path(args.out).write_text(text if text.endswith("\n") else text + "\n",
                                  encoding="utf-8")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return 0
