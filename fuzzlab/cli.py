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
  web                 open the local control panel / launcher (loopback only)
  session <sub>       manage per-host credentials / print a session header
  crawl [args]        run the crawler        (python -m fuzzlab.tools.spider)
  audit [args]        run the auditor        (python -m fuzzlab.tools.fetcher)
  fuzz  [args]        run the blind SQLi fuzzer (requires --authorized)
  auto  [args]        run an automatic pipeline pass over a crawl (requires --authorized)
  report [args]       print a reproducible evaluation report for a stored run (read-only)
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

    if command == "web":
        from fuzzlab.web.app import serve
        serve()
        return 0

    if command == "session":
        from fuzzlab.session import cli as session_cli
        return session_cli.main(rest)

    if command == "auto":
        from fuzzlab.harness import auto_cli
        return auto_cli.main(rest)

    if command == "report":
        from fuzzlab.report import cli as report_cli
        return report_cli.main(rest)

    module = _TOOL_MODULES.get(command)
    if module is None:
        print(f"unknown command: {command}\n\n{_USAGE}", file=sys.stderr)
        return 2

    # Delegate to the tool's module main, preserving its own argument parsing.
    sys.argv = [module, *rest]
    runpy.run_module(module, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
