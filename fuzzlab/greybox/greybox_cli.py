"""`fuzzlab greybox-run` — the live Phase 3 grey-box pass (T3.2–T3.7).

Sends correlated probes at the instrumented lab, reads the pcov / DB-fault side
channel back per request, writes shaped-reward ``attempt`` rows, and (optionally)
resets the DB between stateful iterations. Lab-only: requires ``--authorized``.

Prereqs on the host (see docs/ON_HOST_RUNBOOK.md Part E): the coverage shim
(``includes/cov.php``) is installed and the side-channel dir is bind-mounted; for
``--reset``, ``labctl.sh`` has ``snapshot``/``restore`` subcommands.
"""

from __future__ import annotations

import argparse
import os
from urllib.parse import urlparse

from fuzzlab.core.store import Store
from fuzzlab.greybox import run as gbrun
from fuzzlab.greybox.coverage import FileCoverageSource
from fuzzlab.greybox.dbfault import FileDbFaultSource
from fuzzlab.greybox.reset import ScriptLabControl
from fuzzlab.labels import contract
from fuzzlab.tools.store_adapter import import_spider


def _cookie_for(host: str, identity: str, base_url: str, auth_origins=()):
    """``(Cookie header value or None, secure_only, is_auth_endpoint, origins)`` for an
    authenticated surface (fail loud). ``secure_only``: the session was established over
    https, so the sender must never put the cookie on a plain-http request (BUG-0098).
    ``is_auth_endpoint``: the session's login endpoints, probed without the cookie
    (BUG-0112). ``origins``: the session's canonical origins; the sender attaches the
    cookie only to a probe on one of them (FR-SESS-20, BUG-0134)."""
    from fuzzlab.core.config import load_config
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.session.manager import SessionManager

    cfg = load_config()
    store = CredentialStore.open(cfg)
    scope = list(cfg.get("scope_hosts", []))
    if host not in scope:
        scope.append(host)
    mgr = SessionManager(store, scope_hosts=scope, auth_origins=list(auth_origins))
    header = mgr.session_header(host, identity, base_url,     # SessionAuthError if wrong
                                operator=True)
    state = mgr.ensure(host, identity, base_url, operator=True)
    secure_only, origins = bool(state.secure_only), frozenset(state.origins)
    if header.startswith("Cookie: "):
        return header[len("Cookie: "):], secure_only, mgr.is_auth_endpoint, origins
    return None, secure_only, mgr.is_auth_endpoint, origins


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fuzzlab greybox-run")
    p.add_argument("--base-url", required=True, help="Target base URL (lab, loopback)")
    p.add_argument("--store", required=True, help="Unified store (SQLite) to write to")
    p.add_argument("--spider-db", default="spider_results.db",
                   help="Crawl DB to import points from (crawl/auto sourcing)")
    p.add_argument("--ground-truth", default=None,
                   help="Ground-truth dir; enables ground-truth point sourcing + M10 class")
    p.add_argument("--points", choices=["auto", "crawl", "ground-truth"], default="auto",
                   help="auto: ground-truth if present else crawl")
    p.add_argument("--cov-dir", default="/tmp/fzl-cov",
                   help="Side-channel dir the cov.php shim writes (default /tmp/fzl-cov)")
    p.add_argument("--app-root", default=gbrun.DEFAULT_APP_ROOT,
                   help="Document root inside the container (coverage prefix filter)")
    p.add_argument("--labctl", default=None,
                   help="Path to labctl.sh; enables DB snapshot/restore for --reset")
    p.add_argument("--reset", action="store_true",
                   help="Restore the DB baseline between stateful (non-GET) points")
    p.add_argument("--identity", default=None,
                   help="Probe an authenticated surface as this identity (optional)")
    from fuzzlab.session.manager import AUTH_ORIGIN_HELP
    p.add_argument("--auth-origin", action="append", default=[], metavar="ORIGIN",
                   help=AUTH_ORIGIN_HELP)
    p.add_argument("--settle", type=float, default=0.0,
                   help="Seconds to wait after each request for the shim to flush")
    p.add_argument("--mutation-variants", action="store_true",
                   help="Also probe sqli/xss attacks with mutation-engine variants "
                        "(T8.5 wiring); off by default (extra live traffic)")
    p.add_argument("--max-mutation-variants", type=int, default=2,
                   help="Cap on mutation variants tried per attack probe (default 2)")
    p.add_argument("--allow-destructive", action="store_true",
                   help="Permit recording destructive-looking mutation variants "
                        "(default: refused, matches `mutate-run`)")
    p.add_argument("--authorized", action="store_true",
                   help="Required: confirm you are authorized to test this lab target")
    from fuzzlab.cli_dryrun import add_dry_run_flag
    add_dry_run_flag(p)
    return p


def main(argv: list[str]) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if args.dry_run:
        from fuzzlab.cli_dryrun import report
        report("greybox-run", args)
        return 0

    if not args.authorized:
        p.error("refusing to send probes without --authorized (lab-only)")

    try:
        ground_truth = contract.load(args.ground_truth) if args.ground_truth else None
    except contract.ContractError as exc:
        p.error(str(exc))

    source = args.points
    if source == "auto":
        source = "ground-truth" if ground_truth is not None else "crawl"
    if source == "ground-truth" and ground_truth is None:
        p.error("--points ground-truth requires --ground-truth")

    host = urlparse(args.base_url).hostname or args.base_url
    auth_origins = []
    if args.auth_origin:                 # a usage error before any side effect (R5)
        from fuzzlab.session.manager import parse_auth_origins
        from fuzzlab.tools.authhttp import scope_hosts_for
        try:
            auth_origins = parse_auth_origins(args.auth_origin,
                                              scope_hosts_for(args.base_url))
        except ValueError as exc:
            p.error(str(exc))
    cookie, cookie_secure_only, is_auth_endpoint, cookie_origins = None, False, None, None
    if args.identity:
        from fuzzlab.session.manager import SessionAuthError
        try:
            cookie, cookie_secure_only, is_auth_endpoint, cookie_origins = _cookie_for(
                host, args.identity, args.base_url, auth_origins)
        except SessionAuthError as exc:
            p.error(f"authentication failed for {args.identity}@{host}: {exc}")

    # ground-truth points are pure: an empty set is a usage error before any side effect
    # (BUG-0078 sweep, PA-0079); crawl points need the store, so a run that then fails is
    # marked aborted rather than left looking like an empty finished run
    if source == "ground-truth":
        points, skipped = gbrun.points_with_classes(ground_truth, args.base_url)
        if not points:
            p.error("no injection points to probe (crawl first, or pass --ground-truth)")

    with Store(args.store) as store:
        run_id = store.start_run("greybox", host)
        try:
            counts = {}
            if source != "ground-truth":
                if os.path.exists(args.spider_db):
                    counts = import_spider(args.spider_db, store, run_id,
                                           base_url=args.base_url)
                skipped = []
                points = gbrun.points_from_store(store, run_id, args.base_url,
                                                 skipped=skipped)

            if not points:
                p.error("no injection points to probe (crawl first, or pass --ground-truth)")

            sender = gbrun.RequestsCorrelatingSender(cookie=cookie,
                                                     cookie_secure_only=cookie_secure_only,
                                                     cookie_origins=cookie_origins,
                                                     is_auth_endpoint=is_auth_endpoint)
            if source == "ground-truth":                 # explicit points (BUG-0112)
                sender.allow_explicit(p.url for p in points)
            coverage_source = FileCoverageSource(args.cov_dir)
            dbfault_source = FileDbFaultSource(args.cov_dir)
            lab_control = ScriptLabControl(args.labctl) if args.labctl else None

            summary = gbrun.run_greybox(
                base_url=args.base_url, store=store, run_id=run_id, points=points,
                sender=sender, coverage_source=coverage_source,
                dbfault_source=dbfault_source, lab_control=lab_control,
                reset_between=args.reset, app_root=args.app_root, settle=args.settle,
                mutation_variants=args.mutation_variants,
                max_mutation_variants=args.max_mutation_variants,
                allow_destructive=args.allow_destructive)

            _print_summary(args, source, counts, points, skipped, summary, run_id)
        except BaseException as exc:
            store.mark_aborted(run_id, exc)
            raise
    return 0


def _print_summary(args, source, counts, points, skipped, summary, run_id) -> None:
    print(f"\ngreybox run (source={source}; run_id={run_id})")
    if counts:
        print(f"  crawl imported: {counts.get('endpoint', 0)} endpoint(s), "
              f"{counts.get('parameter', 0)} parameter(s)")
    print(f"  points probed: {summary['points']}   attempts: {summary['attempts']}")
    print(f"  novel app lines (frontier growth): {summary['novel_lines']}")
    print(f"  db_fault attempts: {summary['db_faults']}")
    print(f"  M10 would-confirm (advisory; oracle stays sole writer): "
          f"{summary['m10_would_confirm']}")
    print(f"  reward — baseline max: {summary['baseline_reward']:.3f}   "
          f"new-code (payload vs its baseline) max: {summary['newcode_reward']:.3f}   "
          f"overall max: {summary['max_reward']:.3f}")
    print(f"  app coverage lines seen: {summary.get('coverage_lines_seen', 0)}")
    if args.mutation_variants:
        print(f"  mutation variants probed: {summary.get('mutation_variants_probed', 0)}   "
              f"recorded (accepted): {summary.get('mutation_variants_recorded', 0)}")
    if summary.get("session_out_of_origin"):
        print(f"  probes sent without the session (another origin, FR-SESS-20): "
              f"{summary['session_out_of_origin']}")
    if summary.get("destructive_refused"):
        print(f"  destructive payloads refused (never sent): "
              f"{summary['destructive_refused']} — pass --allow-destructive (lab-only)")
    if summary.get("coverage_lines_seen", 0) == 0:
        print("  NOTE: no application coverage was captured — is the cov.php shim "
              "installed and is --cov-dir the bind-mounted side channel?")
    if skipped:
        print(f"  skipped (need a browser, M6): {len(skipped)} point(s)")
    print("\n  exit check (T3.7):")
    print(f'    sqlite3 {args.store} "SELECT id, payload_family, round(reward,3) AS reward, '
          f'db_fault FROM attempt WHERE run_id={run_id} ORDER BY reward DESC LIMIT 10;"')


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
