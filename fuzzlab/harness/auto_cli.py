"""`fuzzlab auto` — run an automatic-mode pass over a crawl (Phase 2 T2.8).

Consolidates an existing crawl (`spider_results.db` from `fuzzlab crawl`) into the
store, then runs the deterministic pipeline: scoped rules evaluation with negatives,
oracle confirmation (sole finding-writer), target fingerprint, and — when a
ground-truth contract is given — TP/FP scoring. Sends confirmation probes, so it
requires ``--authorized`` (lab-only).

Category selection follows the run mode (D14/D15): automatic + ground truth derives
the categories and scores; automatic + no ground truth needs ``--categories`` or
fails loudly (unscored); manual selects, defaulting to all known categories.
"""

from __future__ import annotations

import argparse
import os
from urllib.parse import urlparse

from fuzzlab.core.runmode import RunModeError
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import run_auto
from fuzzlab.labels import contract
from fuzzlab.tools.probesender import make_probe_sender
from fuzzlab.tools.store_adapter import import_spider


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="fuzzlab auto")
    p.add_argument("--base-url", required=True,
                   help="Target origin, e.g. http://127.0.0.1:8080")
    p.add_argument("--spider-db", default="spider_results.db",
                   help="Crawl results to consolidate (from `fuzzlab crawl`)")
    p.add_argument("--store", required=True, help="Unified store (SQLite) to write to")
    p.add_argument("--ground-truth", default=None,
                   help="Ground-truth dir (enables D14 categories + scoring)")
    p.add_argument("--mode", choices=["automatic", "manual"], default="automatic")
    p.add_argument("--points", choices=["auto", "crawl", "ground-truth"], default="auto",
                   help="Where injection points come from: ground-truth (detection "
                        "benchmark), crawl (discovery run), or auto (default: "
                        "ground-truth if --ground-truth is given, else crawl)")
    p.add_argument("--categories", default=None,
                   help="Comma-separated categories (manual, or D15 fail-safe)")
    p.add_argument("--identity", default=None,
                   help="Authenticated run as this identity (else anonymous)")
    p.add_argument("--browser", action="store_true",
                   help="Enable M6 browser execution (stored/DOM XSS) via Playwright")
    p.add_argument("--bandit", action="store_true",
                   help="Order oracle mechanisms with the Thompson bandit (Phase 4); "
                        "posteriors persist in the store across runs")
    p.add_argument("--authorized", action="store_true",
                   help="Required: confirm you are authorized to test this lab target")
    args = p.parse_args(argv)

    if not args.authorized:
        p.error("refusing to send probes without --authorized (lab-only)")

    selected = [c.strip() for c in args.categories.split(",")] if args.categories else None
    ground_truth = contract.load(args.ground_truth) if args.ground_truth else None
    host = urlparse(args.base_url).netloc or args.base_url

    with Store(args.store) as store:
        run_id = store.start_run("auto", host)
        counts = import_spider(args.spider_db, store, run_id) if \
            os.path.exists(args.spider_db) else {}
        sender = make_probe_sender(args.base_url, args.identity)
        browser = None
        if args.browser:
            from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
            browser = PlaywrightBrowserExecutor()
        scheduler = None
        if args.bandit:
            from fuzzlab.oracle.strategies import default_strategies
            from fuzzlab.scheduler import ThompsonBandit, arm_priors
            scheduler = ThompsonBandit(priors=arm_priors(default_strategies()),
                                       cost_normalized=True, backoff=True)
            scheduler.load(store)                # resume posteriors + costs from prior runs
        try:
            result = run_auto(base_url=args.base_url, store=store, run_id=run_id,
                              sender=sender, mode=args.mode, ground_truth=ground_truth,
                              selected_categories=selected, points_source=args.points,
                              browser=browser, scheduler=scheduler)
        except RunModeError as exc:
            p.error(str(exc))            # D15 fail-safe: loud, non-zero exit

        if scheduler is not None:
            scheduler.save(store)                # persist what this run learned
        _print_summary(args, counts, result)
    return 0


def _print_summary(args, counts, result) -> None:
    plan = result.plan
    m = result.metrics
    print(f"\nauto run ({plan.mode}, {'scored' if plan.scored else 'unscored'}; "
          f"categories={plan.categories}; source={plan.source})")
    print(f"  points from: {m.get('points_source', 'crawl')}")
    if counts:
        print(f"  crawl imported: {counts.get('endpoint', 0)} endpoint(s), "
              f"{counts.get('parameter', 0)} parameter(s)")
    print(f"  points audited: {result.points_audited}   "
          f"candidates: {result.candidates}   negatives: {result.negatives}")
    print(f"  findings (oracle-confirmed): {result.findings}")
    if result.report is not None:
        r = result.report
        print(f"  score vs ground truth: tp={r.tp} fp={r.fp} fn={r.fn} tn={r.tn}")
    else:
        print("  unscored (no ground truth / D15 fail-safe)")
    if m.get("requests") is not None:
        rpf = m.get("requests_per_finding")
        print(f"  requests: {m['requests']}"
              + (f"   requests/finding: {rpf}" if rpf is not None else ""))
    skipped = m.get("skipped_points") or []
    if skipped:
        print(f"  not audited ({len(skipped)} enumerated point(s) — scoped as future "
              f"capability; they score as false negatives):")
        for path, method, param, reason in skipped:
            print(f"    - {method} {path} [{param}]: {reason}")
