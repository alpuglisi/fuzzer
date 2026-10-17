"""Run ``mitmdump`` with the disco recorder in *this* interpreter.

``python -m fuzzlab.disco.mitm --listen-host 127.0.0.1 --port N --scope URL[,URL]
--out capture.jsonl --stats stats.json --confdir DIR [--keep-tag] [--upstream-insecure]``

Started by `fuzzlab.disco.proxyproc` through `procutil` (SP-22/SP-31), never by hand
from another module. Running mitmproxy's own entry point here (rather than a
``mitmdump`` binary found on ``PATH``) guarantees the addon imports this same
``fuzzlab``. The listener is loopback only (`core.net.require_loopback`, PA-0081), and
mitmproxy's CA lives in ``--confdir``, a directory of the run, not ``~/.mitmproxy``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fuzzlab.core.net import require_loopback


def mitmdump_args(ns: argparse.Namespace) -> list[str]:
    """mitmdump's argv for the parsed options (pure; tested)."""
    recorder = Path(__file__).with_name("recorder.py")
    args = ["--listen-host", require_loopback(ns.listen_host, "capture proxy"),
            "--listen-port", str(ns.port), "--quiet",
            "-s", str(recorder),
            "--set", f"confdir={ns.confdir}",
            "--set", "connection_strategy=lazy",       # no upstream connect before scope
            "--set", f"disco_scope={ns.scope}",
            "--set", f"disco_out={ns.out}",
            "--set", f"disco_stats={ns.stats}",
            "--set", f"disco_keep_tag={'true' if ns.keep_tag else 'false'}",
            "--set", f"disco_profile={ns.profile}"]
    if ns.upstream_insecure:
        args += ["--set", "ssl_insecure=true"]
    return args


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m fuzzlab.disco.mitm")
    p.add_argument("--listen-host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--stats", required=True)
    p.add_argument("--confdir", required=True)
    p.add_argument("--profile", default="")
    p.add_argument("--keep-tag", action="store_true")
    p.add_argument("--upstream-insecure", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    from mitmproxy.tools.main import mitmdump
    return mitmdump(mitmdump_args(ns)) or 0


if __name__ == "__main__":
    sys.exit(main())
