"""Shared ``--dry-run`` plan/report logic for the plain CLI entry points.

The web launcher already ships a dry-run preview (``POST /api/launch/dry-run``
in ``fuzzlab/web/app.py``, backed by the pure functions in
``fuzzlab/web/commandspec.py`` and ``fuzzlab/web/runner.py`` — CC-UI-0013/
CC-UI-0015): it plans and reports the exact argv/display for an activity and
sends nothing. This module reuses that same plan/report logic for headless
use outside the web UI, rather than reimplementing it: it adapts a parsed
``argparse.Namespace`` into the ``values`` dict those pure functions expect
and prints the result instead of returning it as JSON.

Every plain CLI entry point except ``fuzzlab/greybox/greybox_cli.py`` (owned
by a separate lane, D0b) calls :func:`report` from its own ``--dry-run``
branch: ``crawl``, ``audit``, ``fuzz``, ``auto``, ``mutate-run``, ``proxy``.

Pure and offline: importing/calling this module sends no traffic.
"""

from __future__ import annotations

import argparse

from fuzzlab.web.commandspec import spec as _spec
from fuzzlab.web.runner import build_argv, display_command


def add_dry_run_flag(parser: argparse.ArgumentParser) -> None:
    """Add the shared ``--dry-run`` flag to a tool's parser."""
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Plan and print the exact command that would run; send nothing.",
    )


def report(command_name: str, args: argparse.Namespace) -> None:
    """Print the dry-run plan for ``command_name`` given its parsed ``args``.

    Mirrors the fields the web launcher's ``/api/launch/dry-run`` route
    returns (argv, display command, sends_traffic, needs_authorized,
    would_execute), printed as text for headless/CLI use instead of JSON.
    """
    command_spec = _spec(command_name)
    # Exclude dry_run itself from the reported argv/display: it is not part of
    # the real action being planned (the same flag also happens to show up as
    # an ordinary --dry-run option in the web launcher's introspected form,
    # since build_parser() is shared — see commandspec.introspect()).
    values = {k: v for k, v in vars(args).items() if k != "dry_run"}
    argv = build_argv(command_spec, values)
    display = display_command(command_spec, values)
    would_execute = not (command_spec.sends_traffic and not values.get("authorized"))

    print(f"DRY RUN — {command_name}: plans the action, sends nothing.")
    print(f"  command: {display}")
    print(f"  argv: {argv}")
    print(f"  sends_traffic: {command_spec.sends_traffic}")
    print(f"  needs_authorized: {command_spec.needs_authorized}")
    print(f"  would_execute: {would_execute}")
