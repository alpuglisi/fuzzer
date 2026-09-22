"""Single command-line entry point: ``fuzzlab <command>``.

Dispatches to the local web launcher and to the individual tools. Every tool
also stays runnable directly as ``python -m fuzzlab.tools.<name>`` (the headless
path kept per D11). This entry point sends no traffic on its own.
"""

from __future__ import annotations

import runpy
import sys

from fuzzlab import __version__

_TOOL_MODULES = {
    "crawl": "fuzzlab.tools.spider",
    "audit": "fuzzlab.tools.fetcher",
    "fuzz": "fuzzlab.tools.blind_sqli_fuzzer",
    "build-db": "fuzzlab.tools.build_sql_db",
}

_USAGE = """usage: fuzzlab <command> [args]

commands:
  web [--with-proxy]  open the local control panel / launcher (loopback only;
                      --with-proxy runs the intercepting proxy in-process, needs --authorized)
  session <sub>       manage per-host credentials / print a session header
  crawl [args]        run the crawler        (python -m fuzzlab.tools.spider)
  audit [args]        run the auditor        (python -m fuzzlab.tools.fetcher)
  fuzz  [args]        run the blind SQLi fuzzer (requires --authorized)
  auto  [args]        run an automatic pipeline pass over a crawl (requires --authorized)
  greybox-run [args]  live grey-box pass: coverage/DB-fault reward (requires --authorized)
  proxy [args]        run the intercepting proxy / export its CA (requires --authorized)
  mutate-run [args]   learn + evade the live lab WAF, record variants (requires --authorized)
  report [args]       print a reproducible evaluation report for a stored run (read-only)
  lab-generate [args] render a lab manifest to source files via an emitter (read-only; --check runs build gates)
  build-db [args]     rebuild the indicator database
  version             print the version

Lab-only. Nothing runs against a target until you ask it to (no auto-run).
"""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_USAGE)
        return 0

    command, rest = argv[0], argv[1:]

    if command == "version":
        print(f"fuzzlab {__version__}")
        return 0

    # Every branch below (and each subcommand's own `main()`) is independently
    # runnable as `python -m fuzzlab.<module>` too (D11), so this try/except is a
    # defense-in-depth backstop, not the primary fix for any one command — it exists
    # so a command whose own module doesn't (yet) guard a particular failure path
    # still gets a clean message here instead of a raw traceback. `SystemExit` (every
    # `sys.exit(...)`/`argparse` `.error()` call already used throughout these
    # commands) is a `BaseException`, not caught by `except Exception` below, so this
    # never interferes with an existing clean-exit path.
    try:
        if command == "web":
            from fuzzlab.web.app import web_main
            return web_main(rest)

        if command == "session":
            from fuzzlab.session import cli as session_cli
            return session_cli.main(rest)

        if command == "auto":
            from fuzzlab.harness import auto_cli
            return auto_cli.main(rest)

        if command == "greybox-run":
            from fuzzlab.greybox import greybox_cli
            return greybox_cli.main(rest)

        if command == "proxy":
            from fuzzlab.proxy import cli as proxy_cli
            return proxy_cli.main(rest)

        if command == "mutate-run":
            from fuzzlab.mutation import cli as mutation_cli
            return mutation_cli.main(rest)

        if command == "report":
            from fuzzlab.report import cli as report_cli
            return report_cli.main(rest)

        if command == "lab-generate":
            from fuzzlab.labgen import cli as labgen_cli
            return labgen_cli.main(rest)

        module = _TOOL_MODULES.get(command)
        if module is None:
            print(f"unknown command: {command}\n\n{_USAGE}", file=sys.stderr)
            return 2

        # Delegate to the tool's module main, preserving its own argument parsing.
        sys.argv = [module, *rest]
        runpy.run_module(module, run_name="__main__")
        return 0
    except KeyboardInterrupt:
        # Matches the exit code every other command in this toolkit already uses on
        # a clean interrupt (proxy/cli.py, mutate-run, auto), not the POSIX 128+SIGINT
        # convention, for consistency across `fuzzlab <command>` as a whole.
        print("\n[-] Interrupted by user.", file=sys.stderr)
        return 0
    except Exception as exc:             # noqa: BLE001 - clean top-level backstop
        print(f"[!] fuzzlab {command} failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
