#!/usr/bin/env python3
"""Profile one `fuzzlab auto` run against a running external lab (lane PERF, FR-LAB-370).

Runs ``fuzzlab auto`` **in this process** (the real CLI entry point, the real sender,
browser and oracle) against one lab of ``lab/external/`` that ``lab/labctl.sh up <lab>
--authorized`` already started, then prints one JSON document:

- ``score``: tp / fp / fn / tn against the lab's answer key (the scorer the live tests
  use, ``harness.scoring.score`` over ``integration.detections_from_store``);
- ``metrics``: the run's own ``run_metrics`` rows (``pipeline_requests``,
  ``pipeline_requests_per_finding``, ...);
- ``wall_s``: the run's wall time;
- ``phases``: wall-clock time and call count per phase, measured by timers wrapped
  around the named functions for the length of the run (outermost call only, so a
  re-entered phase is not counted twice): the fingerprint baseline, the audit, each
  confirmation strategy, the browser executor (driver start / browser session /
  driver stop), the session login, the HTTP sends and ``time.sleep`` (waits and
  backoff). Wall time, not CPU: the waits are the point;
- ``profile`` (``--cprofile``): the top functions by own time from cProfile. cProfile
  misattributes time across Playwright's greenlets (measured: the dispatcher fiber's
  whole browser session lands under the driver stop), so ``phases`` is the
  authoritative breakdown and ``profile`` only locates CPU hot spots.

Lab only: it sends traffic only to the lab's loopback origin, and only with
``--authorized`` (D11), which it passes on to ``fuzzlab auto``. The keyring is the
environment's (``FUZZLAB_KEYRING_PATH`` / ``FUZZLAB_KEYRING_PASSPHRASE``), as for
``labctl.sh``. Nothing is asserted: the numbers are the result.

Examples::

    python scripts/measure_scan_perf.py --lab juice-shop --points ground-truth \\
        --store /tmp/js.db --authorized -- --browser --oob
    python scripts/measure_scan_perf.py --lab bwapp --points crawl \\
        --spider-db /tmp/bw_spider.db --store /tmp/bw.db --authorized -- --browser
"""

from __future__ import annotations

import argparse
import cProfile
import functools
import importlib
import io
import json
import os
import pstats
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

#: (module, attribute path, phase name): the functions timed for the run.
PHASES = (
    ("fuzzlab.harness.pipeline", "_baseline", "fingerprint_baseline"),
    ("fuzzlab.harness.pipeline", "evaluate", "audit"),
    ("fuzzlab.oracle.oracle", "Oracle._confirm_outcome", "oracle_confirm"),
    ("fuzzlab.tools.browserexec", "PlaywrightBrowserExecutor.run", "browser_total"),
    # FR-FUZZ-720: a wave of concurrent visits (absent on a tree before it: skipped)
    ("fuzzlab.tools.browserexec", "PlaywrightBrowserExecutor.run_many", "browser_batch"),
    ("fuzzlab.tools.browserexec", "PlaywrightBrowserExecutor._in_browser",
     "browser_session"),
    ("fuzzlab.tools.browserexec", "PlaywrightBrowserExecutor._stop_driver",
     "browser_driver_stop"),
    ("fuzzlab.session.manager", "SessionManager._login", "session_login"),
    ("fuzzlab.core.http", "HttpClient.send", "http_send"),
    ("time", "sleep", "sleep"),
)


class Timers:
    """Wall-clock time and calls per phase; only the outermost call of a phase on a
    thread is timed (a phase that re-enters itself is not counted twice)."""

    def __init__(self) -> None:
        self.total: dict[str, float] = {}
        self.calls: dict[str, int] = {}
        self._lock = threading.Lock()
        self._depth = threading.local()
        self._undo: list = []

    def wrap(self, module: str, attr: str, phase: str) -> None:
        mod = importlib.import_module(module)
        owner, name = mod, attr
        if "." in attr:
            cls, name = attr.split(".", 1)
            owner = getattr(mod, cls)
        original = getattr(owner, name, None)
        if original is None:                 # a phase this tree does not have
            return
        timers = self

        @functools.wraps(original)
        def timed(*a, **kw):
            depth = getattr(timers._depth, phase, 0)
            setattr(timers._depth, phase, depth + 1)
            start = time.perf_counter()
            try:
                return original(*a, **kw)
            finally:
                setattr(timers._depth, phase, depth)
                if depth == 0:
                    spent = time.perf_counter() - start
                    with timers._lock:
                        timers.total[phase] = timers.total.get(phase, 0.0) + spent
                        timers.calls[phase] = timers.calls.get(phase, 0) + 1

        setattr(owner, name, timed)
        self._undo.append((owner, name, original))

    def wrap_strategies(self) -> None:
        """Each confirmation strategy's ``confirm``, as ``strategy:<Class>``."""
        from fuzzlab.oracle import strategies
        for strategy in strategies.default_strategies():
            cls = type(strategy)
            if "confirm" in vars(cls):
                self.wrap(cls.__module__, f"{cls.__name__}.confirm",
                          f"strategy:{cls.__name__}")

    def undo(self) -> None:
        for owner, name, original in reversed(self._undo):
            setattr(owner, name, original)
        self._undo.clear()

    def report(self) -> dict:
        out = {k: {"s": round(v, 3), "calls": self.calls[k]}
               for k, v in sorted(self.total.items(), key=lambda kv: -kv[1])}
        stop = self.total.get("browser_driver_stop", 0.0)
        session = self.total.get("browser_session", 0.0)
        total = self.total.get("browser_total")
        if total is not None:
            out["browser_driver_start_and_other"] = {
                "s": round(total - stop - session, 3),
                "calls": self.calls.get("browser_total", 0)}
        return out


#: Measurement only (``--browser-timeline``): logs each timer a document schedules and
#: fires, so a settle design can see what ran after ``load``. Never used by a scan.
TIMER_LOG_JS = """(() => {
  const log = []; const st = window.setTimeout, si = window.setInterval;
  const live = new Set();
  window.__fl_timer_log = () => ({log, live: live.size});
  window.setTimeout = function (fn, ms, ...rest) {
    const at = Date.now(); const d = Number(ms) || 0; let id;
    const wrapped = function () { live.delete(id); log.push(["fire", at, d, Date.now()]);
      return typeof fn === "function" ? fn.apply(this, arguments) : undefined; };
    id = st.call(this, wrapped, ms, ...rest); live.add(id); log.push(["set", at, d]);
    return id;
  };
  window.setInterval = function (fn, ms, ...rest) {
    log.push(["interval", Date.now(), Number(ms) || 0]); return si.call(this, fn, ms, ...rest);
  };
})();"""


class BrowserTimeline:
    """Per M6 observation: when ``load`` fired, when the sentinel hit, the last start or
    end of a request a settle would wait for (SP-40's rule), the WebSockets opened,
    and the document's timers -- all relative to the wait's start (seconds)."""

    def __init__(self) -> None:
        self.records: list[dict] = []
        self._cur: dict | None = None
        self._undo: list = []

    def _patch(self, owner, name, make):
        original = getattr(owner, name)
        setattr(owner, name, make(original))
        self._undo.append((owner, name, original))

    def install(self) -> None:
        import playwright.sync_api._generated as gen

        from fuzzlab.tools import browserexec, navguard
        from fuzzlab.tools.netquiet import LONG_LIVED_MS, STREAMING_TYPES
        tl = self

        def binding(original):
            def expose_binding(ctx, name, callback):
                def recorded(source, t):
                    if tl._cur is not None and "hit" not in tl._cur:
                        tl._cur["hit"] = time.time()
                    return callback(source, t)
                return original(ctx, name, recorded)
            return expose_binding

        def guard(original):
            def guard_page(target, *a, **kw):
                out = original(target, *a, **kw)
                pages = getattr(target, "pages", None)
                if pages and tl._cur is not None:
                    page, rec = pages[-1], tl._cur
                    rec.update(open={}, net=[], ws=0)
                    long_s = LONG_LIVED_MS / 1000

                    def started(r):
                        if r.resource_type not in STREAMING_TYPES:
                            rec["open"][id(r)] = time.time()
                            rec["net"].append(time.time())

                    def ended(r):
                        began = rec["open"].pop(id(r), None)
                        if began is not None and time.time() - began < long_s:
                            rec["net"].append(time.time())

                    page.on("request", started)
                    page.on("requestfinished", ended)
                    page.on("requestfailed", ended)
                    page.on("websocket", lambda _ws: rec.__setitem__("ws", rec["ws"] + 1))
                    page.on("load", lambda *_: rec.setdefault("load", time.time()))
                    target.add_init_script(TIMER_LOG_JS)
                return out
            return guard_page

        def in_browser(original):
            def _in_browser(self, pw, request, token, *a, **kw):
                tl._cur = {"t0": time.time(), "url": request.url.split("?")[0][-60:],
                           "store": request.store is not None}
                try:
                    return original(self, pw, request, token, *a, **kw)
                finally:
                    tl.records.append(tl._finish(tl._cur))
                    tl._cur = None
            return _in_browser

        def wait(original):
            def _wait_for_token(self, page, *a, **kw):
                if tl._cur is not None:
                    tl._cur["wait0"] = time.time()
                try:
                    return original(self, page, *a, **kw)
                finally:
                    if tl._cur is not None:
                        tl._cur["wait1"] = time.time()
                        try:
                            tl._cur["timers"] = page.evaluate(
                                "window.__fl_timer_log ? window.__fl_timer_log() : null")
                        except Exception as exc:  # noqa: BLE001 - measurement only
                            tl._cur["timers_error"] = type(exc).__name__
            return _wait_for_token

        self._patch(gen.BrowserContext, "expose_binding", binding)
        self._patch(navguard, "guard_page", guard)
        self._patch(browserexec.PlaywrightBrowserExecutor, "_in_browser", in_browser)
        self._patch(browserexec.PlaywrightBrowserExecutor, "_wait_for_token", wait)

    @staticmethod
    def _finish(rec: dict) -> dict:
        w0 = rec.get("wait0")
        if w0 is None:
            return {"url": rec["url"], "observed": False,
                    "total_s": round(time.time() - rec["t0"], 3)}

        def rel(t):
            return None if t is None else round(t - w0, 3)
        timers = rec.get("timers") or {}
        fires = [e[3] / 1000 for e in timers.get("log", []) if e[0] == "fire"]
        intervals = [e for e in timers.get("log", []) if e[0] == "interval"]
        return {"url": rec["url"], "store": rec["store"], "observed": True,
                "total_s": round(time.time() - rec["t0"], 3),
                "pre_wait_s": round(w0 - rec["t0"], 3),
                "wait_s": rel(rec.get("wait1")), "load": rel(rec.get("load")),
                "hit": rel(rec.get("hit")),
                "last_net": rel(max(rec.get("net") or [None], key=lambda x: x or 0)),
                "open_at_end": len(rec.get("open") or {}), "ws": rec.get("ws", 0),
                "last_timer_fire": rel(max(fires) if fires else None),
                "timers_pending_at_end": timers.get("live"),
                "intervals": len(intervals),
                "max_timer_delay_ms": max([e[2] for e in timers.get("log", [])
                                           if e[0] == "set"] or [0])}

    def undo(self) -> None:
        for owner, name, original in reversed(self._undo):
            setattr(owner, name, original)
        self._undo.clear()


def score_store(store_path: str, gt_dir: Path) -> dict:
    from fuzzlab.core.store import Store
    from fuzzlab.harness.integration import detections_from_store
    from fuzzlab.harness.scoring import score
    from fuzzlab.labels import contract
    gt = contract.load(gt_dir)
    with Store(store_path) as s:
        run = s.conn.execute("SELECT MAX(id) m FROM run").fetchone()["m"]
        report = score(detections_from_store(s, run), gt)
        metrics = {r["key"]: r["value"] for r in s.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id = ?", (run,))}
    out = {"tp": report.tp, "fp": report.fp, "fn": report.fn, "tn": report.tn,
           "matched": sorted(report.matched), "missed": sorted(report.missed),
           "false_alarms": sorted(report.false_alarms)}
    return {"run_id": run, "score": out, "metrics": metrics}


def build_argv(args, meta, gt_dir: Path, extra: list[str]) -> list[str]:
    from fuzzlab.lab_fixtures.external import base_url
    base = args.base_url or base_url(meta).rstrip("/")
    argv = ["--base-url", base, "--store", args.store, "--ground-truth", str(gt_dir),
            "--points", args.points, "--authorized"]
    if args.spider_db:
        argv += ["--spider-db", args.spider_db]
    if meta.identity and not args.anonymous:
        argv += ["--identity", meta.identity]
    return argv + extra


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in argv:
        cut = argv.index("--")
        argv, extra = argv[:cut], argv[cut + 1:]
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--lab", required=True, help="a lab of lab/external/ (LAB_META)")
    p.add_argument("--points", choices=("ground-truth", "crawl"), required=True)
    p.add_argument("--store", required=True, help="a fresh store path for this run")
    p.add_argument("--spider-db", help="crawl results (`fuzzlab crawl --db`)")
    p.add_argument("--base-url", help="override the lab's base URL (bWAPP: /bWAPP/)")
    p.add_argument("--anonymous", action="store_true", help="no --identity")
    p.add_argument("--browser-timeline", action="store_true",
                   help="record each M6 observation's load / hit / network / timer "
                        "times (adds a timer-logging init script: measurement only)")
    p.add_argument("--cprofile", metavar="OUT", help="also write a cProfile to OUT")
    p.add_argument("--authorized", action="store_true",
                   help="required: the lab is yours and running on loopback (D11)")
    args = p.parse_args(argv)
    if not args.authorized:
        p.error("refusing to send traffic without --authorized (lab-only)")
    if os.path.exists(args.store):
        p.error(f"{args.store} exists: give a fresh store per run")
    from fuzzlab.harness import auto_cli
    from fuzzlab.lab_fixtures.external import REPO_ROOT, lab_meta
    meta = lab_meta(args.lab)
    gt_dir = REPO_ROOT / "lab" / f"ground-truth-{args.lab}"
    auto_argv = build_argv(args, meta, gt_dir, extra)

    timers = Timers()
    for module, attr, phase in PHASES:
        timers.wrap(module, attr, phase)
    timers.wrap_strategies()
    timeline = BrowserTimeline() if args.browser_timeline else None
    if timeline is not None:
        timeline.install()
    prof = cProfile.Profile() if args.cprofile else None
    out = io.StringIO()
    start = time.perf_counter()
    try:
        real_stdout, sys.stdout = sys.stdout, out
        if prof is not None:
            prof.enable()
        rc = auto_cli.main(auto_argv)
    finally:
        if prof is not None:
            prof.disable()
        sys.stdout = real_stdout
        wall = time.perf_counter() - start
        if timeline is not None:          # patched over the timers: undone first
            timeline.undo()
        timers.undo()
    result = {"lab": args.lab, "points": args.points, "argv": auto_argv, "rc": rc,
              "wall_s": round(wall, 3), "phases": timers.report(),
              "summary": out.getvalue().strip().splitlines()[-12:]}
    if timeline is not None:
        result["browser_timeline"] = timeline.records
    result.update(score_store(args.store, gt_dir))
    if prof is not None:
        prof.dump_stats(args.cprofile)
        buf = io.StringIO()
        pstats.Stats(prof, stream=buf).sort_stats("tottime").print_stats(15)
        result["profile"] = buf.getvalue().splitlines()[-22:]
    print(json.dumps(result, indent=2, default=str))
    return rc


if __name__ == "__main__":
    sys.exit(main())
