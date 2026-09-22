"""Command-spec registry — introspect each launchable activity's ``argparse``
parser into a machine-readable form schema.

The web launcher renders a control for every flag of every tool. Rather than
hand-mirror the flags into HTML (which rots the moment a tool grows a flag, and
duplicates a source of truth — see PA-0001/PA-0003), we read the flags straight
from each tool's own ``argparse`` parser. Every tool exposes a ``build_parser()``
that returns its parser *without* parsing; this module introspects
``parser._actions`` into :class:`OptionSpec`/:class:`CommandSpec`, so a new flag
shows up in the UI automatically with no change here.

Pure and offline: importing this module sends no traffic and runs no tool. Each
parser is imported lazily (only when its spec is built) so an optional dependency
missing on one tool never breaks the whole registry.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any, Callable


# --- schema ----------------------------------------------------------------

@dataclass(frozen=True)
class OptionSpec:
    """One command-line option, as a UI form field."""

    name: str                       # canonical flag, e.g. "--base-url"
    dest: str                       # argparse dest, e.g. "base_url"
    type: str                       # one of: bool | int | float | str | choice
    required: bool
    default: Any
    help: str
    choices: list[str] | None = None
    multiple: bool = False          # action="append" → a repeatable field

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "dest": self.dest, "type": self.type,
            "required": self.required, "default": self.default, "help": self.help,
            "choices": self.choices, "multiple": self.multiple,
        }


@dataclass(frozen=True)
class CommandSpec:
    """A launchable activity and its options (plus any subcommands)."""

    name: str                       # UI/CLI name, e.g. "auto"
    prog: str                       # argparse prog, e.g. "fuzzlab auto"
    summary: str
    sends_traffic: bool             # does invoking it reach the target?
    needs_authorized: bool          # has an --authorized gate
    destructive_gate: bool          # has an --allow-destructive gate
    group: str | None = None        # launcher grouping label; None → default name-map
    options: list[OptionSpec] = field(default_factory=list)
    subcommands: dict[str, list[OptionSpec]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "prog": self.prog, "summary": self.summary,
            "sends_traffic": self.sends_traffic,
            "needs_authorized": self.needs_authorized,
            "destructive_gate": self.destructive_gate,
            "group": self.group,
            "options": [o.to_dict() for o in self.options],
            "subcommands": {
                k: [o.to_dict() for o in v] for k, v in self.subcommands.items()
            },
        }


# --- introspection ---------------------------------------------------------

def _option_type(action: argparse.Action) -> tuple[str, list[str] | None]:
    """Map an argparse action to a form field type (+ choices)."""
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
        return "bool", None
    if action.choices is not None:
        return "choice", [str(c) for c in action.choices]
    if action.type is int:
        return "int", None
    if action.type is float:
        return "float", None
    return "str", None


def introspect(parser: argparse.ArgumentParser) -> tuple[list[OptionSpec], dict[str, list[OptionSpec]]]:
    """Read a parser's optional args into (options, subcommand-options).

    Skips the auto-added ``-h/--help`` action and any positionals (our tools use
    only optional flags). Subparsers are recursed into one level.
    """
    options: list[OptionSpec] = []
    subcommands: dict[str, list[OptionSpec]] = {}
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if isinstance(action, argparse._SubParsersAction):
            for sub_name, sub in action.choices.items():
                sub_opts, _ = introspect(sub)
                subcommands[sub_name] = sub_opts
            continue
        if not action.option_strings:
            continue  # positional — none expected in the launchable tools
        name = next((o for o in action.option_strings if o.startswith("--")),
                    action.option_strings[0])
        typ, choices = _option_type(action)
        options.append(OptionSpec(
            name=name,
            dest=action.dest,
            type=typ,
            required=bool(action.required),
            default=action.default,
            help=action.help or "",
            choices=choices,
            multiple=isinstance(action, argparse._AppendAction),
        ))
    return options, subcommands


# --- registry --------------------------------------------------------------

@dataclass(frozen=True)
class _Entry:
    name: str
    summary: str
    sends_traffic: bool
    loader: Callable[[], argparse.ArgumentParser] | None  # None → no flags
    group: str | None = None        # launcher grouping label (None → default name-map)


def _load_crawl() -> argparse.ArgumentParser:
    from fuzzlab.tools.spider import build_parser
    return build_parser()


def _load_audit() -> argparse.ArgumentParser:
    from fuzzlab.tools.fetcher import build_parser
    return build_parser()


def _load_fuzz() -> argparse.ArgumentParser:
    from fuzzlab.tools.blind_sqli_fuzzer import build_parser
    return build_parser()


def _load_auto() -> argparse.ArgumentParser:
    from fuzzlab.harness.auto_cli import build_parser
    return build_parser()


def _load_greybox() -> argparse.ArgumentParser:
    from fuzzlab.greybox.greybox_cli import build_parser
    return build_parser()


def _load_proxy() -> argparse.ArgumentParser:
    from fuzzlab.proxy.cli import build_parser
    return build_parser()


def _load_mutate() -> argparse.ArgumentParser:
    from fuzzlab.mutation.cli import build_parser
    return build_parser()


def _load_report() -> argparse.ArgumentParser:
    from fuzzlab.report.cli import build_parser
    return build_parser()


def _load_session() -> argparse.ArgumentParser:
    from fuzzlab.session.cli import build_parser
    return build_parser()


def _load_labgen() -> argparse.ArgumentParser:
    from fuzzlab.labgen.cli import build_parser
    return build_parser()


# Ordered: discovery → attack → analysis. `sends_traffic` is a fact about the
# activity, not something argparse knows, so it is declared here; the authorized
# and destructive gates ARE read from the parser (presence of the flags).
_REGISTRY: list[_Entry] = [
    _Entry("crawl", "Crawl the target and record pages/endpoints.", True, _load_crawl),
    _Entry("audit", "Audit crawled pages for injection points.", True, _load_audit),
    _Entry("fuzz", "Time-based blind-SQLi fuzzer.", True, _load_fuzz),
    _Entry("auto", "Automatic discovery → oracle-confirm pipeline.", True, _load_auto),
    _Entry("greybox-run", "Live grey-box pass (coverage / DB-fault reward).", True, _load_greybox),
    _Entry("proxy", "Intercepting proxy / CA export.", True, _load_proxy),
    _Entry("mutate-run", "Learn + evade the live WAF; record bypass variants.", True, _load_mutate),
    _Entry("report", "Reproducible evaluation report for a stored run.", False, _load_report),
    _Entry("session", "Provision per-host credentials; print a session header.", True, _load_session),
    _Entry("build-db", "Rebuild the packaged indicator database (no traffic).", False, None),
    # Lab authoring: render a manifest to source files. Read-only (writes files;
    # `--check` runs build gates) — sends no traffic, so no authorized gate.
    _Entry("lab-generate",
           "Render a lab manifest to source files via an emitter (read-only; "
           "--check runs build gates).",
           False, _load_labgen, group="Lab / authoring"),
]


def _build(entry: _Entry) -> CommandSpec:
    if entry.loader is None:
        return CommandSpec(
            name=entry.name, prog=f"fuzzlab {entry.name}", summary=entry.summary,
            sends_traffic=entry.sends_traffic, needs_authorized=False,
            destructive_gate=False, group=entry.group, options=[], subcommands={},
        )
    parser = entry.loader()
    options, subcommands = introspect(parser)
    dests = {o.dest for o in options}
    for opts in subcommands.values():
        dests.update(o.dest for o in opts)
    return CommandSpec(
        name=entry.name,
        prog=parser.prog,
        summary=entry.summary,
        sends_traffic=entry.sends_traffic,
        needs_authorized="authorized" in dests,
        destructive_gate="allow_destructive" in dests,
        group=entry.group,
        options=options,
        subcommands=subcommands,
    )


def command_names() -> list[str]:
    """Names of every registered launchable activity, in display order."""
    return [e.name for e in _REGISTRY]


def spec(name: str) -> CommandSpec:
    """Build the :class:`CommandSpec` for one activity by name."""
    for entry in _REGISTRY:
        if entry.name == name:
            return _build(entry)
    raise KeyError(name)


def all_specs() -> list[CommandSpec]:
    """Build every activity's spec (skips any whose parser import fails)."""
    out: list[CommandSpec] = []
    for entry in _REGISTRY:
        try:
            out.append(_build(entry))
        except Exception:  # noqa: BLE001 — an optional-dep import must not sink the registry
            continue
    return out
