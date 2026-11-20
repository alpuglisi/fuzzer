#!/usr/bin/env python3
"""The held-out black-box benchmark (lab/HOLDOUT.md; FR-LAB-424, FR-CORE-680).

For each held-out lab (``lab/HOLDOUT.md``'s table, or ``--lab``), fresh:

1. ``lab/labctl.sh reset <lab>`` -- start from nothing -- then, for a lab whose
   accounts are its own seed, ``seed-credentials`` (the passwords the app publishes), and
   ``lab/labctl.sh bootstrap <lab> --authorized``: the fixture's own bootstrap creates /
   verifies the lab identities into a keyring private to this run;
2. discovery only -- ``fuzzlab crawl`` (Playwright, from the app's start page, as the
   lab's identity when it has one) and ``fuzzlab disco capture`` (anonymous);
3. ``fuzzlab auto --points crawl --score --authorized`` over both, with the answer key
   given only for scoring (``--ground-truth``: categories and the confusion matrix) and
   the lab's identity / peer identity when it has them;
4. the confusion matrix from the run's own findings (``finding`` rows, the oracle's
   only output), per lab: tp / fp / fn / tn, requests, wall time, and every fn with its
   point, class, reach tag and how far the pipeline got with it (no candidate /
   candidate not checked / checked, not confirmed);
5. ``lab/labctl.sh down <lab>``.

No ground-truth-point run is ever made: the answer key never supplies a point. The
crawl configuration is the same for every lab and is derived only from the fixture's
metadata (start page, identities, the app's fixed second origins): nothing per lab is
tuned. Writes one JSON and one markdown table.

Sends traffic to the loopback labs only, and only with ``--authorized`` (D11).

    python3 scripts/holdout_score.py --authorized [--lab vampi ...] \
        [--out docs/components/01-target-lab/holdout-scores.json] [--md PATH]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import secrets
import shutil
import socket
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LABCTL = ROOT / "lab" / "labctl.sh"
DEFAULT_OUT = ROOT / "docs" / "components" / "01-target-lab" / "holdout-scores.json"
#: Detection code (lab/HOLDOUT.md rule 1): the table records whether it is identical to
#: ``--detection-base``, so a score is attributable to a known detection tree.
DETECTION_PATHS = ("fuzzlab/audit", "fuzzlab/oracle", "fuzzlab/session", "fuzzlab/tools",
                   "fuzzlab/harness", "fuzzlab/core/runmode.py", "fuzzlab/core/urls.py",
                   "fuzzlab/disco", "fuzzlab/mutation")
FIELDS = ("lab", "status", "tp", "fp", "fn", "tn", "precision", "recall", "requests",
          "wall_seconds", "crawl_auth", "auto_auth")


# --- pure parts (unit-tested offline) -------------------------------------------------

def reach_tag(notes: str) -> str:
    """A case's ``[reach: ...]`` tag, or ``?`` if it has none."""
    if notes.startswith("[reach: "):
        return notes[len("[reach: "):].split("]", 1)[0]
    return "?"


def candidate_progress(rows: list[tuple[str, str, str, str, str]], case) -> str:
    """How far the run got with ``case`` (from its candidates' ``(path, method, param,
    category, oracle_status)``): ``no candidate`` (the point was never discovered or no
    rule selected it for the class), ``candidate not checked`` (budget-skipped,
    inconclusive ...), ``checked, not confirmed``."""
    from fuzzlab.core.oracle_status import CHECKED
    from fuzzlab.core.runmode import to_category
    want = (case.url, case.method.upper(), case.param, to_category(case.vuln_class))
    statuses = {r[4] for r in rows if r[:4] == want}
    if not statuses:
        same_point = any(r[:3] == want[:3] for r in rows)
        return "no candidate for the class" if same_point else "no candidate"
    return "checked, not confirmed" if CHECKED in statuses else (
        "candidate not checked (" + ",".join(sorted(s or "-" for s in statuses)) + ")")


def lab_row(lab: str, gt, report, candidates, requests: int | None, wall: float,
            status: str = "ok", error: str = "", extra: dict | None = None) -> dict:
    by_id = {c.case_id: c for c in gt.cases}
    fns = []
    for cid in sorted(report.missed):
        c = by_id[cid]
        fns.append({"case_id": cid, "url": c.url, "method": c.method, "param": c.param,
                    "location": c.location, "vuln_class": c.vuln_class,
                    "reach": reach_tag(c.notes or ""),
                    "progress": candidate_progress(candidates, c)})
    row = {"lab": lab, "status": status, "tp": report.tp, "fp": report.fp,
           "fn": report.fn, "tn": report.tn, "precision": round(report.precision, 4),
           "recall": round(report.recall, 4), "requests": requests,
           "wall_seconds": round(wall, 1), "positives": len(gt.positives()),
           "negatives": len(gt.negatives()), "fns": fns,
           "fps": sorted(str(k) for k in report.false_alarms)}
    if error:
        row["error"] = error
    row.update(extra or {})
    return row


def error_row(lab: str, wall: float, error: str, extra: dict | None = None) -> dict:
    row = {"lab": lab, "status": "error", "tp": None, "fp": None, "fn": None, "tn": None,
           "precision": None, "recall": None, "requests": None,
           "wall_seconds": round(wall, 1), "fns": [], "fps": [], "error": error}
    row.update(extra or {})
    return row


def render_markdown(table: dict) -> str:
    out = ["# Held-out benchmark (crawl runs only)", "",
           f"fuzzlab commit `{table['fuzzlab_commit']}`"
           + (f"; detection code identical to `{table['detection_base']}`: "
              f"{table['detection_identical']}" if table.get("detection_base") else "")
           + f"; generated {table['generated']}.", "",
           "| " + " | ".join(FIELDS) + " |", "|" + " --- |" * len(FIELDS)]
    for r in table["labs"]:
        out.append("| " + " | ".join("" if r.get(f) is None else str(r.get(f))
                                     for f in FIELDS) + " |")
    for r in table["labs"]:
        out += ["", f"## {r['lab']}", ""]
        if r.get("error"):
            out.append(f"error: {r['error']}")
        if r["fns"]:
            out += ["| fn | point | class | reach | progress |", "| --- | --- | --- | --- | --- |"]
            out += [f"| {f['case_id']} | {f['method']} {f['url']} [{f['param']}] "
                    f"({f['location']}) | {f['vuln_class']} | {f['reach']} | {f['progress']} |"
                    for f in r["fns"]]
        if r["fps"]:
            out += ["", "false alarms: " + "; ".join(r["fps"])]
    return "\n".join(out) + "\n"


# --- the run --------------------------------------------------------------------------

def _free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _git(*args: str) -> str:
    from fuzzlab.procutil import run_bounded
    res = run_bounded(["git", *args], timeout=60, cwd=str(ROOT))
    return res.stdout.strip() if res.returncode == 0 else ""


def detection_identical(base: str) -> bool | None:
    from fuzzlab.procutil import run_bounded
    if not _git("rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"):
        return None
    res = run_bounded(["git", "diff", "--quiet", base, "--", *DETECTION_PATHS],
                      timeout=120, cwd=str(ROOT))
    dirty = run_bounded(["git", "diff", "--quiet", "HEAD", "--", *DETECTION_PATHS],
                        timeout=120, cwd=str(ROOT))
    return res.returncode == 0 and dirty.returncode == 0


def _candidates(store) -> list[tuple[str, str, str, str, str]]:
    from fuzzlab.core.urls import to_path, to_route_path
    run = store.conn.execute("SELECT MAX(id) m FROM run").fetchone()["m"]
    out = []
    for row in store.conn.execute(
            "SELECT evidence, oracle_status FROM candidate WHERE run_id = ?", (run,)):
        ev = json.loads(row["evidence"] or "{}")
        url = ev.get("url") or ""
        path = to_route_path(url) if ev.get("location") == "fragment" else to_path(url)
        out.append((path, (ev.get("method") or "GET").upper(), ev.get("param") or "",
                    ev.get("category") or "", row["oracle_status"] or ""))
    return out


def score_store(store_path: Path, gt_dir: Path):
    """``(gt, report, candidates, requests)`` of the store's newest run."""
    from fuzzlab.core.store import Store
    from fuzzlab.harness.integration import detections_from_store
    from fuzzlab.harness.scoring import score
    from fuzzlab.labels import contract
    gt = contract.load(gt_dir)
    with Store(str(store_path)) as s:
        run = s.conn.execute("SELECT MAX(id) m FROM run").fetchone()["m"]
        report = score(detections_from_store(s, run), gt)
        used = s.conn.execute("SELECT SUM(used) u FROM request_budget WHERE run_id = ?",
                              (run,)).fetchone()["u"]
        cands = _candidates(s)
    return gt, report, cands, (int(used) if used is not None else None)


def crawl_requests(spider_db: Path) -> int | None:
    """Pages and requests the legacy crawl recorded (a lower bound on what it sent)."""
    try:
        with closing(sqlite3.connect(str(spider_db))) as c:
            n = 0
            for table in ("discovered_pages", "discovered_requests"):
                try:
                    n += c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except sqlite3.Error:
                    pass
            return n
    except sqlite3.Error:
        return None


def disco_requests(run_dir: Path) -> int | None:
    f = run_dir / "capture.jsonl"
    if not f.is_file():
        return None
    with f.open(encoding="utf-8", errors="replace") as fh:
        return sum(1 for line in fh if line.strip())


class Runner:
    """One lab's benchmark run in a private temp dir with a private keyring."""

    def __init__(self, lab: str, tmp: Path, *, budget_total: int, timeout: float,
                 disco_deadline: float, log: Callable[[str], None]):
        from fuzzlab.lab_fixtures.external import LAB_META
        self.lab, self.tmp, self.timeout, self.log = lab, tmp, timeout, log
        self.disco_deadline = disco_deadline
        self.meta = LAB_META[lab]
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.env = {**os.environ,
                    "PYTHONPATH": str(ROOT),
                    "FUZZLAB_PYTHON": sys.executable,
                    "FUZZLAB_EXT_PROJECT_SUFFIX": "-holdout",
                    self.meta.port_env: str(self.port),
                    "FUZZLAB_KEYRING_PATH": str(tmp / "keyring.enc"),
                    "FUZZLAB_KEYRING_PASSPHRASE": secrets.token_hex(16),
                    "FUZZLAB_BUDGET_TOTAL": str(budget_total)}

    def _run(self, argv: list[str], *, timeout: float | None = None, cwd: Path | None = None):
        from fuzzlab.procutil import run_bounded
        self.log(f"[{self.lab}] $ {' '.join(argv[:6])} ...")
        res = run_bounded(argv, timeout=timeout or self.timeout, env=self.env,
                          cwd=str(cwd or self.tmp))
        (self.tmp / "log.txt").open("a", encoding="utf-8").write(
            f"$ {' '.join(argv)}\n--- rc={res.returncode}\n{res.stdout[-20000:]}\n"
            f"--- stderr\n{res.stderr[-20000:]}\n")
        return res

    def labctl(self, *args: str, timeout: float = 1800):
        return self._run([str(LABCTL), *args], timeout=timeout, cwd=LABCTL.parent)

    def fuzzlab(self, *args: str):
        return self._run([sys.executable, "-m", "fuzzlab.cli", *args])

    def auth_origins(self) -> list[str]:
        out = []
        for host, _container in self.meta.fixed_ports:
            out += ["--auth-origin", f"http://127.0.0.1:{host}"]
        return out

    def run(self) -> dict:
        gt_dir = ROOT / "lab" / f"ground-truth-{self.lab}"
        start = time.monotonic()
        try:
            res = self.labctl("reset", self.lab)          # fresh, no traffic yet
            if res.returncode != 0:
                return error_row(self.lab, time.monotonic() - start,
                                 f"labctl reset rc={res.returncode}: {res.stderr[-400:]}")
            from fuzzlab.lab_fixtures.external import _PUBLISHED_CREDENTIALS
            if self.lab in _PUBLISHED_CREDENTIALS:          # seeded accounts (FR-LAB-425)
                sc = self._run([sys.executable, "-m", "fuzzlab.lab_fixtures.external",
                                "seed-credentials", self.lab, "--authorized"], cwd=ROOT)
                if sc.returncode != 0:
                    return error_row(self.lab, time.monotonic() - start,
                                     f"seed-credentials rc={sc.returncode}: {sc.stderr[-400:]}")
            if self.meta.identity:
                bs = self.labctl("bootstrap", self.lab, "--authorized")
                if bs.returncode != 0:
                    return error_row(self.lab, time.monotonic() - start,
                                     f"labctl bootstrap rc={bs.returncode}: {bs.stderr[-400:]}")
            st = self.labctl("status", self.lab, timeout=300)
            if st.returncode != 0:
                return error_row(self.lab, time.monotonic() - start,
                                 f"labctl status rc={st.returncode} (not loopback-only?)")
            ident = ["--identity", self.meta.identity] if self.meta.identity else []
            peer = (["--peer-identity", self.meta.extra_identities[0][0]]
                    if self.meta.identity and self.meta.extra_identities else [])
            start_url = self.base + self.meta.app_path
            spider = self.tmp / "spider.db"
            c = self.fuzzlab("crawl", "--start", start_url, "--engine", "playwright",
                             "--db", str(spider), *ident, *self.auth_origins())
            crawl_auth = "identity" if ident else "anonymous"
            if c.returncode != 0 and ident:
                # a black-box tester whose login fails still crawls: anonymously, and the
                # table says so (the failed login is a finding, recorded, not fixed)
                crawl_auth = "anonymous (the logged-in crawl failed)"
                c = self.fuzzlab("crawl", "--start", start_url, "--engine", "playwright",
                                 "--db", str(spider), *self.auth_origins())
            disco = self.tmp / "disco"
            d = self.fuzzlab("disco", "capture", "--start", start_url, "--out", str(disco),
                             "--deadline", str(self.disco_deadline), "--authorized",
                             *sum((["--scope", f"http://127.0.0.1:{h}"]
                                   for h, _ in self.meta.fixed_ports), []))
            discovery = []
            if c.returncode == 0:
                discovery += ["--spider-db", str(spider)]
            if d.returncode == 0 and (disco / "capture.jsonl").is_file():
                discovery += ["--disco-run", str(disco)]
            extra = {"crawl_rc": c.returncode, "disco_rc": d.returncode,
                     "crawl_auth": crawl_auth,
                     "crawl_recorded": crawl_requests(spider) if c.returncode == 0 else None,
                     "disco_exchanges": disco_requests(disco) if d.returncode == 0 else None}
            if not discovery:
                return error_row(self.lab, time.monotonic() - start,
                                 "both discovery runs failed", extra)
            store = self.tmp / "store.db"

            def auto(*accounts: str):
                if store.exists():
                    store.unlink()                  # a fresh store: one run, one score
                return self.fuzzlab("auto", "--base-url", self.base + self.meta.app_path,
                                    *discovery, "--store", str(store), "--ground-truth",
                                    str(gt_dir), "--points", "crawl", *accounts,
                                    *self.auth_origins(), "--browser", "--oob", "--score",
                                    "--authorized")
            a = auto(*ident, *peer)
            extra["auto_auth"] = "identity" if ident else "anonymous"
            if a.returncode != 0 and ident:
                extra["auto_auth"] = "anonymous (the logged-in run failed)"
                extra["auto_identity_rc"] = a.returncode
                a = auto()
            extra["auto_rc"] = a.returncode
            if not store.is_file():
                return error_row(self.lab, time.monotonic() - start,
                                 f"auto rc={a.returncode}, no store: {a.stderr[-400:]}", extra)
            gt, report, cands, used = score_store(store, gt_dir)
            requests = sum(n for n in (used, extra["crawl_recorded"],
                                       extra["disco_exchanges"]) if n)
            extra["probe_requests"] = used
            status = "ok" if a.returncode == 0 else f"auto rc={a.returncode}"
            return lab_row(self.lab, gt, report, cands, requests, time.monotonic() - start,
                           status=status, error="" if a.returncode == 0
                           else a.stderr[-400:], extra=extra)
        except Exception as exc:  # noqa: BLE001 - one lab's failure is a row, not a crash
            return error_row(self.lab, time.monotonic() - start, f"{type(exc).__name__}: {exc}")
        finally:
            try:
                self.labctl("down", self.lab, timeout=600)
            except Exception as exc:  # noqa: BLE001
                self.log(f"[{self.lab}] labctl down failed: {exc!r}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--lab", action="append", default=[],
                   help="a held-out lab to run (repeatable; default: every one listed)")
    p.add_argument("--out", default=str(DEFAULT_OUT), help="the JSON table to write")
    p.add_argument("--md", default=None, help="the markdown table (default: --out's .md)")
    p.add_argument("--detection-base", default="e14c925",
                   help="the ref whose detection code the table says it matches")
    p.add_argument("--budget-total", type=int, default=30000,
                   help="FUZZLAB_BUDGET_TOTAL for each auto run (default 30000)")
    p.add_argument("--timeout", type=float, default=5400, help="seconds per step")
    p.add_argument("--disco-deadline", type=float, default=600,
                   help="seconds for each disco capture (default 600)")
    p.add_argument("--keep-tmp", action="store_true", help="keep each lab's run directory")
    p.add_argument("--authorized", action="store_true",
                   help="confirm the labs are yours (required: sends traffic to loopback)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from fuzzlab.lab_fixtures.heldout import held_out_labs
    listed = [lab.name for lab in held_out_labs()]
    unknown = sorted(set(args.lab) - set(listed))
    if unknown:
        print(f"not held-out labs (lab/HOLDOUT.md): {', '.join(unknown)}", file=sys.stderr)
        return 2
    if not args.authorized:
        print("the benchmark sends traffic to the loopback labs: pass --authorized",
              file=sys.stderr)
        return 2
    labs = args.lab or listed
    rows = []
    for lab in labs:
        tmp = Path(tempfile.mkdtemp(prefix=f"holdout-{lab}-"))
        runner = Runner(lab, tmp, budget_total=args.budget_total, timeout=args.timeout,
                        disco_deadline=args.disco_deadline,
                        log=lambda m: print(m, file=sys.stderr, flush=True))
        row = runner.run()
        row["run_dir"] = str(tmp) if args.keep_tmp else None
        if not args.keep_tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        rows.append(row)
        print(json.dumps({k: row.get(k) for k in FIELDS}), flush=True)
    table = {"benchmark": "held-out, crawl runs only (lab/HOLDOUT.md)",
             "fuzzlab_commit": _git("rev-parse", "HEAD"),
             "detection_base": args.detection_base,
             "detection_identical": detection_identical(args.detection_base),
             "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "labs": rows}
    out = Path(args.out)
    out.write_text(json.dumps(table, indent=1) + "\n", encoding="utf-8")
    md = Path(args.md) if args.md else out.with_suffix(".md")
    md.write_text(render_markdown(table), encoding="utf-8")
    print(f"wrote {out} and {md}")
    return 0 if all(r["status"] == "ok" for r in rows) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
