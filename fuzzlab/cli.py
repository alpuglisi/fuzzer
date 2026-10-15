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


def _usage() -> str:
    """Grouped help — working runs, training/benchmark, lab — from the one table
    (`cli_taxonomy.COMMANDS`, FR-UI-400)."""
    from fuzzlab.cli_taxonomy import render_help
    return render_help()


def _old_name_note(command: str) -> None:
    """One stderr line for an older name; stdout is the command's own (design D-6)."""
    from fuzzlab.cli_taxonomy import OLD_NAMES
    new = OLD_NAMES.get(command)
    if new:
        print(f"fuzzlab: '{command}' is now 'fuzzlab {new}' (the old name still works)",
              file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage())
        return 0

    command, rest = argv[0], argv[1:]

    # D71: the send rules a run turns off come only from that command's own flags
    # (`core.sendpolicy.apply`); start every command from the defaults.
    from fuzzlab.core import sendpolicy
    sendpolicy.set_disabled(())

    if command == "version":
        print(f"fuzzlab {__version__}")
        return 0

    if command == "web":
        from fuzzlab.web.app import web_main
        return web_main(rest)

    if command == "session":
        from fuzzlab.session import cli as session_cli
        return session_cli.main(rest)

    if command == "train":
        from fuzzlab import train_cli
        return train_cli.main(rest)

    _old_name_note(command)

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

    if command == "flow-anomaly":
        from fuzzlab.harness import flow_anomaly_cli
        return flow_anomaly_cli.main(rest)

    if command == "reveal-holdout":
        from fuzzlab.harness import reveal_cli
        return reveal_cli.main(rest)

    if command == "lab-generate":
        from fuzzlab.labgen import cli as labgen_cli
        return labgen_cli.main(rest)

    module = _TOOL_MODULES.get(command)
    if module is None:
        print(f"unknown command: {command}\n\n{_usage()}", file=sys.stderr)
        return 2

    # Delegate to the tool's module main, preserving its own argument parsing.
    sys.argv = [module, *rest]
    runpy.run_module(module, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
