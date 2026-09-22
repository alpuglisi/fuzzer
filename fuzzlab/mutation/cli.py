"""`fuzzlab mutate-run` — learn + evade the live lab WAF, record variants (Phase 8).

Sends a base payload at a WAF-protected parameter, searches for a semantics-preserving
variant that the live filter lets through, and records bypasses to `payload_variant`.
With `--cov-dir` (the Part E side channel) it also measures the coverage the variant
reaches. Lab-only: requires `--authorized`.
"""

from __future__ import annotations

import argparse
from urllib.parse import urlparse

from fuzzlab.core.store import Store
from fuzzlab.mutation import run as mrun
from fuzzlab.tools.probesender import make_probe_sender


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fuzzlab mutate-run")
    p.add_argument("--url", required=True,
                   help="Full endpoint URL, e.g. http://127.0.0.1:8080/search.php")
    p.add_argument("--param", required=True, help="Parameter to inject into")
    p.add_argument("--store", required=True, help="Store (SQLite) to record variants in")
    p.add_argument("--vuln-class", default="sql-injection",
                   choices=["sql-injection", "xss"])
    p.add_argument("--method", default="GET")
    p.add_argument("--location", default="query", choices=["query", "body"])
    p.add_argument("--base", action="append",
                   help="Base payload (repeatable; sensible default per class)")
    p.add_argument("--identity", default=None, help="Authenticated identity (optional)")
    p.add_argument("--cov-dir", default=None,
                   help="Part E side-channel dir; measures the variant's coverage gain")
    p.add_argument("--app-root", default="/var/www/html")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--budget", type=int, default=40)
    p.add_argument("--allow-destructive", action="store_true",
                   help="Permit recording destructive variants (default: refused)")
    p.add_argument("--confirm-oracle", action="store_true",
                   help="Independently re-check each recorded bypass with the oracle's "
                        "own confirmation strategies for --vuln-class at the same "
                        "endpoint (advisory; the oracle stays the sole finding-writer)")
    p.add_argument("--authorized", action="store_true",
                   help="Required: confirm you are authorized to test this lab target")
    return p


def main(argv: list[str]) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if not args.authorized:
        p.error("refusing to send payloads without --authorized (lab-only)")

    bases = args.base or mrun.DEFAULT_BASES.get(args.vuln_class, [])
    if not bases:
        p.error(f"no base payloads for {args.vuln_class}; pass --base")

    sender = make_probe_sender(args.url, args.identity)
    coverage_fn = None
    if args.cov_dir:
        coverage_fn = mrun.make_coverage_fn(
            args.url, args.param, cov_dir=args.cov_dir, app_root=args.app_root,
            method=args.method, location=args.location)

    with Store(args.store) as store:
        run_id = store.start_run("mutate", urlparse(args.url).hostname or args.url)
        oracle = None
        if args.confirm_oracle:
            # store/run_id attached so a genuine confirmation actually writes the
            # `finding` row -- an Oracle with neither is a pure dry-run that never
            # persists (see Oracle._write_finding's guard), which would silently
            # defeat the point of --confirm-oracle.
            from fuzzlab.oracle import Oracle
            oracle = Oracle(store=store, run_id=run_id)
        summary = mrun.run_mutation(
            url=args.url, param=args.param, store=store, run_id=run_id, sender=sender,
            bases=bases, vuln_class=args.vuln_class, method=args.method,
            location=args.location, coverage_fn=coverage_fn, seed=args.seed,
            budget=args.budget, allow_destructive=args.allow_destructive, oracle=oracle)
        _print_summary(args, summary, run_id)
    return 0


def _print_summary(args, summary, run_id) -> None:
    print(f"\nmutate-run ({args.vuln_class}; {args.url} [{args.param}]; run_id={run_id})")
    print(f"  bases: {summary['bases']}   blocked by WAF: {summary['blocked']}   "
          f"bypasses found: {summary['bypasses']}   recorded: {summary['recorded']}"
          + (f"   oracle-confirmed: {summary['oracle_confirmed']}"
             if args.confirm_oracle else ""))
    for r in summary["results"]:
        tag = "BYPASS" if (r["evaded"] and r["semantics_ok"] and r["base_blocked"]) else "-"
        cov = f"  +{r['novel_lines']} new line(s)" if r["novel_lines"] else ""
        oracle_note = ""
        if args.confirm_oracle and r["recorded_id"] is not None:
            oracle_note = ("  [oracle: CONFIRMED, finding written]"
                           if r["oracle_confirmed"] else "  [oracle: not confirmed]")
        print(f"    [{tag}] base={r['base']!r}")
        print(f"           variant={r['variant']!r} via {r['operators']}"
              f"  evaded={r['evaded']} semantics_ok={r['semantics_ok']}{cov}{oracle_note}")
    if summary["recorded"]:
        print(f'\n  recorded variants:  sqlite3 {args.store} "SELECT base_payload, variant, '
              f'operators, bypassed_rule, coverage_gain FROM payload_variant '
              f'WHERE run_id={run_id};"')


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
