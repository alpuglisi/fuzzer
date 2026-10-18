#!/usr/bin/env python3
"""Score a discovery run against Google's Security Crawl Maze (CC-LAB-0302).

The maze links each test resource one way (an HTML tag or attribute, a header, CSS,
JavaScript, a framework route, a known file); every resource a crawler should reach
ends in ``.found``, and the lab serves the expected set itself
(``/fetch-expected-results``; the same list ships in the source,
``blueprints/utils/resources/expected-results.json``, read by default). A resource
counts as **found** when the run
requested it:

* a disco run (``--disco-run DIR``): any HTTP exchange in its ``capture.jsonl`` -- the
  browser's own subresource loads included, since they are requests the run made;
* a legacy crawl (``--spider-db FILE``): a page the crawl visited or queued
  (``discovered_pages``) or a request it captured (``discovered_requests``).

Prints found/total, a per-category breakdown and the missed paths. The maze is a public
development lab (not held out), so per-case output is fine here.

    python3 scripts/crawl_maze_score.py --disco-run RUN [--expected URL_OR_FILE]
    python3 scripts/crawl_maze_score.py --spider-db spider.db
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

#: The expected set at the pinned commit, from the fixture's source checkout (the lab's
#: own endpoint refuses ``path=/``: it strips the slash and wants a non-empty prefix).
DEFAULT_EXPECTED = str(ROOT / "lab/external/security-crawl-maze/.cache/src/blueprints/"
                           "utils/resources/expected-results.json")


def load_expected(source: str) -> list[str]:
    """The expected paths, from the lab's endpoint (a URL) or a JSON list file."""
    if source.startswith(("http://", "https://")):
        import requests
        s = requests.Session()
        s.trust_env = False                 # a loopback lab: never through a proxy
        resp = s.get(source, timeout=10)
        resp.raise_for_status()
        return list(resp.json())
    return list(json.loads(Path(source).read_text(encoding="utf-8")))


def requested_disco(run_dir: Path) -> set[str]:
    from fuzzlab.disco.capture import read_capture
    return {urlsplit(r.url).path for r in read_capture(run_dir / "capture.jsonl").records
            if r.kind == "http"}


def requested_spider(db: Path) -> set[str]:
    conn = sqlite3.connect(str(db))
    out: set[str] = set()
    try:
        for table in ("discovered_pages", "discovered_requests"):
            try:
                out |= {urlsplit(u).path for (u,) in conn.execute(f"SELECT url FROM {table}")}
            except sqlite3.Error:
                pass                        # an older spider DB
    finally:
        conn.close()
    return out


def category(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    if parts and parts[0] == "test":
        parts = parts[1:]
    return "/".join(parts[:2]) if len(parts) > 2 else (parts[0] if parts else "/")


def score(expected: list[str], requested: set[str]) -> dict:
    found = [p for p in expected if p in requested]
    missed = [p for p in expected if p not in requested]
    total, hit = Counter(map(category, expected)), Counter(map(category, found))
    return {"found": len(found), "total": len(expected), "missed": missed,
            "by_category": {c: (hit[c], n) for c, n in sorted(total.items())}}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--disco-run", type=Path)
    src.add_argument("--spider-db", type=Path)
    p.add_argument("--expected", default=DEFAULT_EXPECTED,
                   help="the lab's expected-results URL, or a JSON list file")
    p.add_argument("--exclude-prefix", action="append", default=[], metavar="PATH",
                   help="leave expected paths under PATH out (a case the lab does not "
                        "serve, e.g. /javascript/frameworks when they are not built)")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    args = p.parse_args(argv)
    requested = requested_disco(args.disco_run) if args.disco_run else \
        requested_spider(args.spider_db)
    expected = [e for e in load_expected(args.expected)
                if not any(e.startswith(x) for x in args.exclude_prefix)]
    result = score(expected, requested)
    if args.json:
        print(json.dumps(result, indent=1))
        return 0
    print(f"found {result['found']}/{result['total']}")
    for cat, (hit, n) in result["by_category"].items():
        print(f"  {cat:32s} {hit}/{n}")
    for path in result["missed"]:
        print(f"  missed {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
