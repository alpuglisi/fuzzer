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
from fuzzlab.harness.auto import plan_run, run_auto
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
    p.add_argument("--rank-objective", choices=["pointwise", "pairwise", "auto"],
                   default="pointwise",
                   help="With --rank (not --train-on saved): pointwise (default), pairwise "
                        "learning-to-rank over (vulnerable, not) pairs run-wide, or auto "
                        "(the better run-wide out-of-fold NDCG)")
    p.add_argument("--train-on", choices=["run", "earlier", "saved"], default="run",
                   help="What --score/--rank train on: run = this run's own labels "
                        "(labelled rows also get out-of-fold scores); earlier = earlier "
                        "runs against the same target, never this run's labels; saved = "
                        "no training, apply the newest saved model from an earlier run "
                        "(refuses when there is none)")
    p.add_argument("--model-id", type=int, default=None, metavar="ID",
                   help="With --score --train-on saved: the saved classifier model row to "
                        "apply (default: the newest qualifying one)")
    p.add_argument("--ranker-model-id", type=int, default=None, metavar="ID",
                   help="With --rank --train-on saved: the saved ranker model row to apply")
    p.add_argument("--calibrate", choices=["none", "platt"], default="none",
                   help="With --score (not --train-on saved): Platt-scale the classifier's "
                        "probabilities on cross-fitted out-of-fold scores; the evidence "
                        "(Brier / ECE before and after) is recorded (default none)")
    p.add_argument("--holdout", action="store_true",
                   help="With --score/--rank/--confirm-budget: keep the fixed blind holdout "
                        "(20%% of each target's endpoints) out of training, and seal its "
                        "metrics — read them with `fuzzlab reveal-holdout`")
    p.add_argument("--hybrid", action="store_true",
                   help="With --score: add the ECOD anomaly score as a classifier feature "
                        "(XGBOD-style; label-free)")
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
                   help="At most this fraction of candidates is flagged by --anomaly, "
                        "whole tie groups only, in (0, 0.5] (default 0.1)")
    p.add_argument("--anomaly-method", choices=["ecod", "iforest"], default="ecod",
                   help="With --anomaly: the detector — ecod (parameter-free, default) or "
                        "iforest (Isolation Forest, seeded)")
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
    if args.anomaly_method != "ecod" and not args.anomaly:
        p.error("--anomaly-method needs --anomaly")
    if args.rank_objective != "pointwise" and not args.rank:
        p.error("--rank-objective needs --rank")
    if args.rank_objective != "pointwise" and args.train_on == "saved":
        p.error("--rank-objective does not apply to --train-on saved (a saved ranker keeps "
                "its own)")
    if args.train_on != "run" and not (args.score or args.rank):
        p.error("--train-on needs --score and/or --rank")
    if args.hybrid and not args.score:
        p.error("--hybrid needs --score")
    if args.calibrate != "none" and not args.score:
        p.error("--calibrate needs --score")
    if args.calibrate != "none" and args.train_on == "saved":
        p.error("--calibrate does not apply to --train-on saved (a saved model keeps its "
                "own calibrator)")
    if args.holdout and not (args.score or args.rank or args.confirm_budget is not None):
        p.error("--holdout needs --score, --rank or --confirm-budget")
    if args.hybrid and args.train_on == "saved":
        p.error("--hybrid does not apply to --train-on saved (a saved model keeps its own)")
    if args.model_id is not None and not (args.score and args.train_on == "saved"):
        p.error("--model-id needs --score and --train-on saved")
    if args.ranker_model_id is not None and not (args.rank and args.train_on == "saved"):
        p.error("--ranker-model-id needs --rank and --train-on saved")

    # Plugins (the ML stages included, FR-ML-6) are settled before the store is opened,
    # so a missing ML package or a prioritizer conflict leaves no run row behind.
    plugins = _build_plugins(p, args)

    selected = [c.strip() for c in args.categories.split(",")] if args.categories else None
    try:
        ground_truth = contract.load(args.ground_truth) if args.ground_truth else None
    except contract.ContractError as exc:
        p.error(str(exc))            # clean message, non-zero exit (no traceback)
    host = urlparse(args.base_url).netloc or args.base_url
    # Every usage-level check runs before any side effect (BUG-0078, PA-0079): the run
    # plan by the same function `run_auto` uses (D15 fail-safe, a ground-truth source
    # without a contract), then the environment the flags need.
    try:
        plan_run(mode=args.mode, ground_truth=ground_truth, selected_categories=selected,
                 points_source=args.points)
    except RunModeError as exc:
        p.error(str(exc))
    _precheck_environment(p, args)

    with Store(args.store) as store:
        run_id = store.start_run("auto", host)
        try:
            return _run(p, args, store, run_id, plugins, selected, ground_truth)
        except BaseException as exc:
            # a failure only the run itself can hit (an OOB bind, a crash): the run row
            # says so instead of reading as an empty finished run; then re-raise, so a
            # usage error still exits 2 and a real bug keeps its traceback
            store.mark_aborted(run_id, exc)
            raise


def _precheck_environment(p, args) -> None:
    """Refuse, before the store is opened, a flag whose environment is missing."""
    import importlib.util
    if args.browser and importlib.util.find_spec("playwright") is None:
        p.error("--browser needs Playwright (pip install playwright; "
                "playwright install chromium)")
    for flag, path in (("--greybox-coverage-file", args.greybox_coverage_file),
                       ("--greybox-dbfault-file", args.greybox_dbfault_file)):
        if path and not os.path.exists(path):
            p.error(f"{flag}: {path} does not exist (is the lab's side channel mounted?)")


def _run(p, args, store, run_id: int, plugins, selected, ground_truth) -> int:
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
    try:
        result = run_auto(base_url=args.base_url, store=store, run_id=run_id,
                          sender=sender, mode=args.mode, ground_truth=ground_truth,
                          selected_categories=selected, points_source=args.points,
                          browser=browser, oob=oob, coverage=coverage, dbfault=dbfault,
                          scheduler=scheduler, plugins=plugins,
                          confirm_budget=args.confirm_budget)
    except RunModeError as exc:
        p.error(str(exc))            # D15 fail-safe: loud, non-zero exit
    finally:
        if oob is not None:
            oob.stop()                # tear down the loopback listener every run

    if scheduler is not None:
        scheduler.flush_metrics()            # commit any buffered per-pull metrics
        scheduler.save(store)                # persist what this run learned
    # the ML stages ran inside `run_auto` as `after_run` plugins (CC-FUZZ-0050)
    args.run_id = run_id
    return _print_summary(args, counts, result, plugins)


def _build_plugins(p, args):
    """The run's `PluginManager`: the ML stages the flags ask for (registered first)
    plus any `--plugins` entry points — or ``None`` when neither is asked for, exactly
    as before. Every error here is a usage error raised before any traffic."""
    from fuzzlab.plugins.optional import ML_UNAVAILABLE, import_ml
    stages: list = []
    ml_absent = False
    if args.score or args.rank or args.anomaly or args.confirm_budget is not None:
        ml_plugins = import_ml("fuzzlab.ml.plugins")
        if ml_plugins is None:
            ml_absent = True
            if args.score or args.rank or args.anomaly:
                p.error(f"{ML_UNAVAILABLE}: --score/--rank/--anomaly need fuzzlab.ml")
        else:
            stages = ml_plugins.stage_plugins(
                score=args.score, rank=args.rank, anomaly=args.anomaly,
                contamination=args.anomaly_contamination, train_on=args.train_on,
                hybrid=args.hybrid, model_id=args.model_id,
                ranker_model_id=args.ranker_model_id,
                confirm_budget=args.confirm_budget, budget_method=args.budget_method,
                budget_seed=args.budget_seed, calibrate=args.calibrate,
                holdout=args.holdout, anomaly_method=args.anomaly_method,
                rank_objective=args.rank_objective)
    args.stage_names = {st.flag: st.name for st in stages}
    if not stages and not args.plugins:
        if args.confirm_budget is not None:
            p.error(f"{ML_UNAVAILABLE}: --confirm-budget needs fuzzlab.ml or a "
                    f"--plugins plugin that contributes a prioritizer")
        return None
    from fuzzlab.plugins import PluginManager
    plugins = (PluginManager.from_entry_points(extra=stages) if args.plugins
               else PluginManager(plugins=stages))   # entry-point discovery (Phase 10)
    if args.confirm_budget is not None:
        try:
            found = plugins.guarded_prioritizer()
        except ValueError as exc:                    # PluginConflict
            p.error(str(exc))
        if found is None:
            p.error(f"{ML_UNAVAILABLE}: --confirm-budget needs fuzzlab.ml or a "
                    f"--plugins plugin that contributes a prioritizer" if ml_absent else
                    "--confirm-budget: no plugin could provide the budget order "
                    f"({plugins.errors() or 'none contributed one'})")
    return plugins


def _print_budget(m: dict) -> None:
    if "confirm_budget" not in m:
        return
    confirmable = m.get("confirmable_keys", 0)
    if m.get("confirm_budget_error"):
        print(f"  oracle budget: {m.get('budget_plugin', 'prioritizer')} FAILED — "
              f"{m.get('budget_error')}; confirmed the first "
              f"{m.get('oracle_checked_keys', 0)} of {confirmable} confirmable "
              f"candidate(s) in row order")
        return
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


def _print_ml_extras(r: dict, run_id) -> None:
    """Calibration and holdout lines under a classifier / ranker line (CC-FUZZ-0053).
    The holdout line prints only label-free facts — how many endpoints are held out and
    whether sealed metrics were written — never a holdout number."""
    if r.get("objective"):                           # CC-FUZZ-0054 (ranker)
        how = r["objective"] if r["objective"] != "auto" else \
            f"auto → {r.get('objective_used')} (selection-biased)"
        print(f"    objective: {how}; run-wide per-fold NDCG@k {r.get('ndcg_global')}, "
              f"P@k {r.get('precision_global')}"
              + ("" if r.get("objective_used") == r["objective"] or r["objective"] == "auto"
                 else f" (fit fell back to {r.get('objective_used')}: no pair)"))
    cal = r.get("calibration")
    if cal and cal.get("calibrator") == "platt":
        print(f"    calibration: platt — out-of-fold ECE {round(cal['ece_oof_raw'], 4)} raw "
              f"→ {round(cal['ece_oof_calibrated'], 4)} cross-fitted; Brier "
              f"{round(cal['brier_oof_raw'], 4)} → {round(cal['brier_oof_calibrated'], 4)}")
    elif cal:
        print(f"    calibration: {cal.get('calibrator')} — scores left uncalibrated")
    if r.get("quarantined_rows"):                    # BUG-0107 (FR-ML-24)
        print(f"    {r['quarantined_rows']} candidate(s) with unreadable evidence skipped")
    h = r.get("holdout")
    if h is not None:
        held = h.get("endpoints")
        where = f"{held} endpoint(s) of this run held out" if held is not None else \
            "holdout"
        if h.get("implied"):                         # BUG-0091: the target is sealed
            where += " (implied: target sealed)"
        if h.get("sealed"):
            print(f"    holdout: {where}; metrics sealed — read with `fuzzlab "
                  f"reveal-holdout --run {run_id if run_id is not None else 'N'}` "
                  f"(each read is counted)")
        else:
            print(f"    holdout: {where}; no sealed metrics ({h.get('skipped_reason')})")


def _print_earlier(label: str, verb: str, r: dict, metric: str, key: str,
                   baseline: str, baseline_key: str) -> None:
    """Summary line for a model trained on earlier runs (CC-FUZZ-0049): what it was
    trained on, how much of this run it had seen, and the forward evaluation."""
    if r.get("refused"):
        print(f"  {label}: NOT {verb} — {r.get('reason')} (use --train-on run to train "
              f"on this run's labels)")
        return
    runs = ", ".join(str(x) for x in r.get("train_run_ids") or [])
    if r.get("train_on") == "saved":            # CC-FUZZ-0051: applied, not trained
        how = (f"with saved model #{r.get('source_model_id')} (trained on runs {runs}), "
               f"not trained on this run")
    else:
        how = (f"trained on {r.get('train_rows', 0)} earlier labelled candidate(s) from "
               f"this target (runs {runs}), not on this run's labels")
    line = (f"  {label} ({r['model']}): {verb} {r.get(verb, 0)} candidate(s); {how}; "
            f"{round(100 * (r.get('seen_fraction') or 0.0))}% of this run's candidates "
            f"were seen in training; ")
    if f"{key}_forward" in r:
        line += (f"forward {metric}={r[f'{key}_forward']} "
                 f"({baseline} {r.get(baseline_key)})")
    else:
        line += f"no forward {metric} ({r.get('forward_skipped_reason')})"
    print(line + "  (advisory — never labels)")


def _print_summary(args, counts, result, plugins=None) -> int:
    """Print the run summary; returns the exit code (1 when a post-run stage or the
    budget prioritizer failed, or a requested ML stage did not run)."""
    stage_names = getattr(args, "stage_names", {})        # flag -> plugin name
    outcomes = {o.info.name: o for o in getattr(result, "plugin_outcomes", [])}
    failed = False
    reported: set[str] = set()

    def stage(flag: str):
        """A requested stage's result, or None after printing why it has none."""
        nonlocal failed
        name = stage_names.get(flag, flag)
        reported.add(name)
        outcome = outcomes.get(name)
        if outcome is not None and outcome.ok:
            return outcome.result
        failed = True
        why = outcome.error if outcome is not None else (
            (plugins.errors().get(name) if plugins is not None else None) or "not run")
        print(f"  {name}: FAILED — {why}")
        return None

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
    if skipped and m.get("points_source") == "crawl":
        print(f"  not fuzzed ({len(skipped)} crawl point(s) on a destructive URL, "
              f"NFR-FUZZ-safe):")
        for path, method, param, reason in skipped:
            print(f"    - {method} {path} [{param}]: {reason}")
    elif skipped:
        print(f"  not audited ({len(skipped)} enumerated point(s) — scoped as future "
              f"capability; they score as false negatives):")
        for path, method, param, reason in skipped:
            print(f"    - {method} {path} [{param}]: {reason}")
    if m.get("auth_endpoint_anonymous_sends"):
        print(f"  auth-endpoint probes sent without the session: "
              f"{m['auth_endpoint_anonymous_sends']} (NFR-FUZZ-safe)")
    ml = stage("score") if args.score else None
    rank = stage("rank") if args.rank else None
    anomaly = stage("anomaly") if args.anomaly else None
    if ml is not None and ml.get("train_on") in ("earlier", "saved"):
        _print_earlier("ml", "scored", ml, "PR-AUC", "pr_auc", "prevalence",
                       "baseline_prevalence_forward")
    elif ml is not None:
        line = f"  ml ({ml['model']}): scored {ml.get('scored', 0)} candidate(s)"
        if not ml.get("fallback"):
            line += (f"; PR-AUC={ml.get('pr_auc')} vs prevalence "
                     f"{ml.get('baseline_prevalence')} / sigma {ml.get('baseline_sigma')}")
        print(line + "  (advisory — never labels)")
    if ml is not None:
        _print_ml_extras(ml, getattr(args, "run_id", None))
    if rank is not None and rank.get("train_on") in ("earlier", "saved"):
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
    if rank is not None:
        _print_ml_extras(rank, getattr(args, "run_id", None))
    if anomaly is not None:
        method = anomaly.get("method", "ecod")
        label = "anomaly" if method == "ecod" else f"anomaly ({method})"
        print(f"  {label}: flagged {anomaly.get('flagged', 0)} of {anomaly.get('rows', 0)} "
              f"candidate(s)  (advisory — unusual is not vulnerable)")
        if anomaly.get("flag_reason"):               # ties are never split (BUG-0070)
            print(f"    note: {anomaly['flag_reason']}")
        for t in anomaly.get("top", []):
            print(f"    - {t['path']} [{t['param']}] {t['category']}  score {t['score']}")
    for name, outcome in outcomes.items():          # third-party post-run plugins
        if name in reported:
            continue
        reported.add(name)
        if outcome.ok:
            print(f"  plugin {name}: after_run done")
        else:
            failed = True
            print(f"  plugin {name}: FAILED — {outcome.error}")
    if m.get("confirm_budget_error"):
        failed = True
        reported.add(m.get("budget_plugin"))
    if plugins is not None:
        errors = plugins.errors()
        others = sorted(n for n in plugins.disabled() if n not in reported)
        if others:
            print("  plugins disabled after an error:")
            for name in others:
                print(f"    - {name}: {errors.get(name)}")
        for info, why in plugins.rejections():
            print(f"  plugin refused ({why}): {info.name}")
    return 1 if failed else 0
