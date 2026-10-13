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


def build_parser() -> argparse.ArgumentParser:
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
    p.add_argument("--oob", action="store_true",
                   help="Enable M8 out-of-band callback confirmation (blind command "
                        "injection) via a local, loopback-only listener. Default off; "
                        "the listener never binds to anything but 127.0.0.1 and is torn "
                        "down at the end of the run.")
    p.add_argument("--greybox-coverage-file", default=None,
                   help="Enable M10 grey-box confirmation (sql-injection/xss) with a "
                        "FileCoverageSource reading the lab shim's per-request pcov "
                        "side channel from this directory. Default off (no-op); needs "
                        "a correlating probe sender to do anything (on-host last mile).")
    p.add_argument("--greybox-dbfault-file", default=None,
                   help="Enable M10's DB-fault corroboration with a FileDbFaultSource "
                        "reading the lab shim's per-request side channel from this "
                        "directory. Default off (no-op). May be combined with "
                        "--greybox-coverage-file, or used alone (xss needs coverage "
                        "only; sqli needs both).")
    p.add_argument("--bandit", action="store_true",
                   help="Order oracle mechanisms with the Thompson bandit (Phase 4); "
                        "posteriors persist in the store across runs")
    p.add_argument("--score", action="store_true",
                   help="After the run, train the detection classifier and write advisory "
                        "candidate scores (Phase 5; never labels)")
    p.add_argument("--rank", action="store_true",
                   help="After the run, train the candidate ranker and write advisory "
                        "rank scores + NDCG@k/Precision@k vs random (Phase 7; never labels)")
    p.add_argument("--train-on", choices=["run", "earlier"], default="run",
                   help="What --score/--rank train on: run = this run's own labels "
                        "(in-sample deploy fit); earlier = earlier runs against the same "
                        "target, never this run's labels (refuses when there are none)")
    p.add_argument("--confirm-budget", type=int, default=None, metavar="N",
                   help="Send at most N distinct candidates to the oracle, chosen by a "
                        "model trained on EARLIER runs against the same target (active "
                        "learning, Phase 7). The rest are recorded as skipped, not "
                        "rejected. With no usable earlier labels every candidate is "
                        "confirmed (the summary says so). Default: confirm all.")
    p.add_argument("--budget-method", default="score",
                   choices=["score", "uncertainty", "committee", "random"],
                   help="Order for --confirm-budget: score = most likely vulnerable first "
                        "(most findings per request); uncertainty / committee = least sure "
                        "first (best for improving the model); random = seeded control")
    p.add_argument("--budget-seed", type=int, default=0,
                   help="Seed for --budget-method random / committee (default 0)")
    p.add_argument("--anomaly", action="store_true",
                   help="After the run, score every candidate with the ECOD anomaly "
                        "tripwire and store anomaly_score/anomaly_flag (Phase 10; "
                        "unusual != vulnerable; never labels)")
    p.add_argument("--anomaly-contamination", type=float, default=0.1, metavar="F",
                   help="Fraction of candidates --anomaly flags, in (0, 0.5] (default 0.1)")
    p.add_argument("--plugins", action="store_true",
                   help="Discover and attach entry-point plugins (Phase 10); the active "
                        "set is recorded on the run. Default off (runs with no plugins).")
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
        report("auto", args)
        return 0

    if not args.authorized:
        p.error("refusing to send probes without --authorized (lab-only)")
    if args.confirm_budget is not None and args.confirm_budget < 1:
        p.error("--confirm-budget must be at least 1")
    if not 0 < args.anomaly_contamination <= 0.5:
        p.error("--anomaly-contamination must be in (0, 0.5]")
    if args.train_on != "run" and not (args.score or args.rank):
        p.error("--train-on needs --score and/or --rank")

    selected = [c.strip() for c in args.categories.split(",")] if args.categories else None
    try:
        ground_truth = contract.load(args.ground_truth) if args.ground_truth else None
    except contract.ContractError as exc:
        p.error(str(exc))            # clean message, non-zero exit (no traceback)
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
        oob = None
        if args.oob:
            from fuzzlab.oracle.oob import OobListener
            oob = OobListener()          # loopback-only; refuses any other host
            oob.start()
        coverage = None
        if args.greybox_coverage_file:
            from fuzzlab.greybox.coverage import FileCoverageSource
            coverage = FileCoverageSource(args.greybox_coverage_file)
        dbfault = None
        if args.greybox_dbfault_file:
            from fuzzlab.greybox.dbfault import FileDbFaultSource
            dbfault = FileDbFaultSource(args.greybox_dbfault_file)
        scheduler = None
        if args.bandit:
            from fuzzlab.oracle.strategies import default_strategies
            from fuzzlab.scheduler import ThompsonBandit, arm_priors
            scheduler = ThompsonBandit(priors=arm_priors(default_strategies()),
                                       cost_normalized=True, backoff=True)
            scheduler.load(store)                # resume posteriors + costs from prior runs
            from fuzzlab.core.store import MetricLogger
            scheduler.attach_metrics(MetricLogger(store, run_id, source="bandit"))
        plugins = None
        if args.plugins:
            from fuzzlab.plugins import PluginManager
            plugins = PluginManager.from_entry_points()   # entry-point discovery (Phase 10)
        prioritizer = None
        if args.confirm_budget is not None:
            from functools import partial
            from fuzzlab.ml.active import prioritize
            prioritizer = partial(prioritize, method=args.budget_method,
                                  seed=args.budget_seed)
        try:
            result = run_auto(base_url=args.base_url, store=store, run_id=run_id,
                              sender=sender, mode=args.mode, ground_truth=ground_truth,
                              selected_categories=selected, points_source=args.points,
                              browser=browser, oob=oob, coverage=coverage, dbfault=dbfault,
                              scheduler=scheduler, plugins=plugins,
                              confirm_budget=args.confirm_budget, prioritizer=prioritizer)
        except RunModeError as exc:
            p.error(str(exc))            # D15 fail-safe: loud, non-zero exit
        finally:
            if oob is not None:
                oob.stop()                # tear down the loopback listener every run

        if scheduler is not None:
            scheduler.flush_metrics()            # commit any buffered per-pull metrics
            scheduler.save(store)                # persist what this run learned
        ml = None
        if args.score:
            from fuzzlab.ml.train import train_and_score
            # advisory scores + model (best of logistic/GBT by out-of-fold PR-AUC);
            # never labels.
            ml = train_and_score(store, run_id, model_kind="auto", train_on=args.train_on)
        rank = None
        if args.rank:
            from fuzzlab.ml.rank_train import train_and_rank
            # advisory rank scores + NDCG@k/Precision@k vs random; never labels.
            rank = train_and_rank(store, run_id, train_on=args.train_on)
        anomaly = None
        if args.anomaly:
            from fuzzlab.ml.anomaly import detect_anomalies
            # advisory per-candidate anomaly score/flag (persisted); never labels.
            anomaly = detect_anomalies(store, run_id, contamination=args.anomaly_contamination)
            anomaly["top"] = _top_flagged(store, anomaly)
        _print_summary(args, counts, result, ml, rank, anomaly)
    return 0


def _top_flagged(store, anomaly: dict, limit: int = 5) -> list[dict]:
    """The most anomalous flagged candidates (path, param, category, score)."""
    import json
    from fuzzlab.core.urls import to_path
    flagged = sorted(((s, cid) for cid, s, f in zip(anomaly["ids"], anomaly["scores"],
                                                     anomaly["flags"]) if f), reverse=True)
    out = []
    for score, cid in flagged[:limit]:
        row = store.conn.execute("SELECT evidence FROM candidate WHERE id=?", (cid,)).fetchone()
        try:
            ev = json.loads(row["evidence"] or "{}") if row else {}
        except (ValueError, TypeError):
            ev = {}
        out.append({"path": to_path(ev.get("url", "")), "param": ev.get("param", ""),
                    "category": ev.get("category", ""), "score": round(score, 3)})
    return out


def _print_budget(m: dict) -> None:
    if "confirm_budget" not in m:
        return
    confirmable = m.get("confirmable_keys", 0)
    if m.get("confirm_budget_fallback"):
        print(f"  oracle budget NOT applied: no usable earlier labels for this target — "
              f"confirmed all {confirmable} confirmable candidate(s)")
        return
    if m.get("budget_method") == "random":
        how = "random order — the control for T7.4"
    else:
        sha = m.get("budget_model_sha256")
        how = (f"ordered by {m.get('budget_method')}, trained on "
               f"{m.get('budget_training_rows', 0)} earlier labelled candidate(s) "
               f"from this target" + (f"; model {sha[:12]}" if sha else ""))
    print(f"  oracle budget: checked {m.get('oracle_checked_keys', 0)} of {confirmable} "
          f"confirmable candidate(s); {confirmable - m.get('oracle_checked_keys', 0)} "
          f"skipped ({how})")
    if m.get("scored") and m.get("oracle_skipped"):
        print("    skipped candidates count as misses in the score")


def _print_earlier(label: str, verb: str, r: dict, metric: str, key: str,
                   baseline: str, baseline_key: str) -> None:
    """Summary line for a model trained on earlier runs (CC-FUZZ-0049): what it was
    trained on, how much of this run it had seen, and the forward evaluation."""
    if r.get("refused"):
        print(f"  {label}: NOT {verb} — {r.get('reason')} (use --train-on run to train "
              f"on this run's labels)")
        return
    runs = ", ".join(str(x) for x in r.get("train_run_ids") or [])
    line = (f"  {label} ({r['model']}): {verb} {r.get(verb, 0)} candidate(s); trained on "
            f"{r.get('train_rows', 0)} earlier labelled candidate(s) from this target "
            f"(runs {runs}), not on this run's labels; "
            f"{round(100 * (r.get('seen_fraction') or 0.0))}% of this run's candidates "
            f"were seen in training; ")
    if f"{key}_forward" in r:
        line += (f"forward {metric}={r[f'{key}_forward']} "
                 f"({baseline} {r.get(baseline_key)})")
    else:
        line += f"no forward {metric} ({r.get('forward_skipped_reason')})"
    print(line + "  (advisory — never labels)")


def _print_summary(args, counts, result, ml=None, rank=None, anomaly=None) -> None:
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
    _print_budget(m)
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
    if ml is not None and ml.get("train_on") == "earlier":
        _print_earlier("ml", "scored", ml, "PR-AUC", "pr_auc", "prevalence",
                       "baseline_prevalence_forward")
    elif ml is not None:
        line = f"  ml ({ml['model']}): scored {ml.get('scored', 0)} candidate(s)"
        if not ml.get("fallback"):
            line += (f"; PR-AUC={ml.get('pr_auc')} vs prevalence "
                     f"{ml.get('baseline_prevalence')} / sigma {ml.get('baseline_sigma')}")
        print(line + "  (advisory — never labels)")
    if rank is not None and rank.get("train_on") == "earlier":
        _print_earlier("ranker", "ranked", rank, f"NDCG@{rank.get('at_k')}", "ndcg",
                       "random", "baseline_ndcg_forward")
    elif rank is not None:
        line = f"  ranker ({rank['model']}): ranked {rank.get('ranked', 0)} candidate(s)"
        if not rank.get("fallback"):
            line += (f"; NDCG@{rank.get('at_k')}={rank.get('ndcg')} "
                     f"(random {rank.get('baseline_ndcg')}), "
                     f"P@{rank.get('at_k')}={rank.get('precision')} "
                     f"(random {rank.get('baseline_precision')})")
        print(line + "  (advisory — never labels)")
    if anomaly is not None:
        print(f"  anomaly: flagged {anomaly.get('flagged', 0)} of {anomaly.get('rows', 0)} "
              f"candidate(s)  (advisory — unusual is not vulnerable)")
        for t in anomaly.get("top", []):
            print(f"    - {t['path']} [{t['param']}] {t['category']}  score {t['score']}")
