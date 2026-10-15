"""The command taxonomy: working runs vs training/benchmark runs vs the lab (FR-FUZZ-401).

Pure and offline: no traffic, no store. One table drives three things
(`docs/CLI_WORKING_VS_TRAINING_DESIGN.md`):

* :data:`COMMANDS` — every dispatchable command, its group and one-line summary. It
  prints ``fuzzlab --help`` (:func:`render_help`) and names the older aliases.
* :data:`FLAG_CLASSES` — every flag of every command's parser, classified:

  - ``B`` both: same meaning in working and training runs;
  - ``T`` training: ground truth, training data, fit choices and modulators, holdouts,
    experiment controls. Refused in a working command, naming ``fuzzlab train run``;
  - ``W*`` narrowed in a working command (:data:`WORKING_RESTRICT`);
  - ``L`` needs our instrumented lab. Refused in a working command.

  ``tests/test_cli_taxonomy.py`` fails on an unclassified dest, a stale entry, or a
  :data:`PENDING` dest that has arrived.
* :func:`copy_parser` — a parser for a new command built from an existing command's own
  parser (its actions are *copied*, never re-typed: PA-0001/PA-0003), with the target URL
  as a positional and the flags a working command must refuse turned into refusing
  options (design D-8).
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

# --- commands ---------------------------------------------------------------------

WORKING = "Working runs (lab-only): use fuzzlab as a tool against a lab target you are " \
          "authorized to test"
TRAINING = "Training and benchmark: ground truth, scored runs, model training, " \
           "holdouts, models"
LAB = "Lab"
OTHER = "Other"
GROUPS = (WORKING, TRAINING, LAB, OTHER)


@dataclass(frozen=True)
class Command:
    name: str                  # as typed after `fuzzlab`, e.g. "crawl", "train run"
    group: str
    usage: str                 # the left column of the help, e.g. "train run <url> [args]"
    summary: str
    flags: str | None = None   # key into FLAG_CLASSES / PARSERS (None: no parser)
    store_default: bool = False  # --store optional, resolved by core.storepath
    old_name: str | None = None  # the older top-level name that still works


COMMANDS: tuple[Command, ...] = (
    Command("auto", WORKING, "auto [args]",
            "crawl results -> audit -> oracle-confirm pipeline (requires --authorized; "
            "ground-truth and training flags: use `train run`)", flags="auto"),
    Command("crawl", WORKING, "crawl [args]",
            "run the crawler (python -m fuzzlab.tools.spider)", flags="crawl"),
    Command("audit", WORKING, "audit [args]",
            "run the auditor (python -m fuzzlab.tools.fetcher)", flags="audit"),
    Command("fuzz", WORKING, "fuzz [args]",
            "run the blind SQLi fuzzer (requires --authorized)", flags="fuzz"),
    Command("session", WORKING, "session <sub>",
            "manage per-host credentials / print a session header", flags="session"),
    Command("proxy", WORKING, "proxy [args]",
            "run the intercepting proxy / export its CA (requires --authorized; "
            "--record keeps flow history)", flags="proxy"),
    Command("report", WORKING, "report [args]",
            "print a reproducible evaluation report for a stored run (read-only)",
            flags="report", store_default=True),
    Command("web", WORKING, "web [--with-proxy]",
            "open the local control panel / launcher (loopback only; --with-proxy runs "
            "the intercepting proxy in-process, needs --authorized)"),
    Command("train run", TRAINING, "train run <url> [args]",
            "a run scored against ground truth and/or that trains models "
            "(requires --authorized)", flags="auto"),
    Command("train models", TRAINING, "train models [args]",
            "list saved models (the model registry; read-only)", flags="train models",
            store_default=True),
    Command("train reveal-holdout", TRAINING, "train reveal-holdout [args]",
            "print a run's sealed holdout metrics (counts the reveal)",
            flags="reveal-holdout", store_default=True, old_name="reveal-holdout"),
    Command("train flow-anomaly", TRAINING, "train flow-anomaly [args]",
            "flag each host's most unusual recorded flows (writes the store; no traffic)",
            flags="flow-anomaly", store_default=True, old_name="flow-anomaly"),
    Command("train mutate", TRAINING, "train mutate [args]",
            "learn + evade the live lab WAF, record variants (requires --authorized)",
            flags="mutate-run", store_default=True, old_name="mutate-run"),
    Command("lab-generate", LAB, "lab-generate [args]",
            "render a lab manifest to source files via an emitter (read-only; --check "
            "runs build gates)", flags="lab-generate"),
    Command("build-db", LAB, "build-db [args]", "rebuild the indicator database"),
    Command("greybox-run", LAB, "greybox-run [args]",
            "live grey-box pass on the instrumented lab: coverage/DB-fault reward "
            "(requires --authorized)", flags="greybox-run"),
    Command("version", OTHER, "version", "print the version"),
)

#: Older top-level names that still work, and the command each now is.
OLD_NAMES: dict[str, str] = {c.old_name: c.name for c in COMMANDS if c.old_name}


def command(name: str) -> Command:
    for c in COMMANDS:
        if c.name == name:
            return c
    raise KeyError(name)


_HELP_COLUMNS = 100


def render_help() -> str:
    """``fuzzlab --help``: every command once, in its group, from :data:`COMMANDS`."""
    import textwrap
    width = max(len(c.usage) for c in COMMANDS) + 2
    lines = ["usage: fuzzlab <command> [args]      "
             "(fuzzlab <command> --help for its options)"]
    for group in GROUPS:
        lines += ["", group]
        for c in COMMANDS:
            if c.group == group:
                body = textwrap.wrap(c.summary, _HELP_COLUMNS - 2 - width) or [""]
                lines.append(f"  {c.usage.ljust(width)}{body[0]}")
                lines += [" " * (2 + width) + more for more in body[1:]]
    lines += [""] + textwrap.wrap("Older names (still work): " + ", ".join(
        f"{old} (= {new})" for old, new in OLD_NAMES.items()), _HELP_COLUMNS)
    lines += ["",
              "Store: --store PATH, else $FUZZLAB_STORE, else $FUZZLAB_STORE_PATH, else "
              "./fuzzlab.db in the",
              "       current directory (the web UI uses the same rule). auto and "
              "greybox-run still need --store.",
              "Lab-only. Nothing runs against a target until you ask it to (no auto-run)."]
    return "\n".join(lines) + "\n"


# --- parsers ----------------------------------------------------------------------

def _load(module: str, name: str = "build_parser") -> Callable[[], argparse.ArgumentParser]:
    def loader() -> argparse.ArgumentParser:
        import importlib
        return getattr(importlib.import_module(module), name)()
    return loader


#: Each classified parser, by FLAG_CLASSES key (imported lazily; importing sends nothing).
PARSERS: dict[str, Callable[[], argparse.ArgumentParser]] = {
    "auto": _load("fuzzlab.harness.auto_cli"),
    "crawl": _load("fuzzlab.tools.spider"),
    "audit": _load("fuzzlab.tools.fetcher"),
    "fuzz": _load("fuzzlab.tools.blind_sqli_fuzzer"),
    "session": _load("fuzzlab.session.cli"),
    "proxy": _load("fuzzlab.proxy.cli"),
    "report": _load("fuzzlab.report.cli"),
    "reveal-holdout": _load("fuzzlab.harness.reveal_cli"),
    "flow-anomaly": _load("fuzzlab.harness.flow_anomaly_cli"),
    "mutate-run": _load("fuzzlab.mutation.cli"),
    "greybox-run": _load("fuzzlab.greybox.greybox_cli"),
    "lab-generate": _load("fuzzlab.labgen.cli"),
    "train models": _load("fuzzlab.train_cli", "build_models_parser"),
}

#: Commands with no classified parser, and why.
UNCLASSIFIED = {
    "web": "its parser lives inside web_main and is not exposed as build_parser(); "
           "its flags are UI-server options",
    "build-db": "no argparse parser",
    "version": "no parser",
}


def _all(cls: str, dests: Iterable[str]) -> dict[str, str]:
    return {d: cls for d in dests}


FLAG_CLASSES: dict[str, dict[str, str]] = {
    "auto": {
        "base_url": "B", "spider_db": "B", "store": "B",
        "ground_truth": "T", "mode": "T", "points": "T",
        "categories": "B", "identity": "B", "browser": "B", "oob": "B",
        "greybox_coverage_file": "L", "greybox_dbfault_file": "L",
        "bandit": "B", "score": "W*", "rank": "W*",
        "rank_objective": "T", "train_on": "T",
        "model_id": "B", "ranker_model_id": "B",
        "calibrate": "T", "holdout": "T", "hybrid": "T",
        "confirm_budget": "B", "budget_method": "W*", "budget_seed": "T",
        "anomaly": "B", "anomaly_contamination": "B", "anomaly_method": "B",
        "plugins": "B", "header_points": "B", "fuzz_json_writes": "B",
        "authorized": "B", "dry_run": "B",
    },
    "crawl": _all("B", ["start", "max_depth", "db", "engine", "timeout", "resume", "store",
                        "identity", "follow_selector_forms", "no_spa_routes",
                        "submit_spa_forms", "no_reveal", "dry_run"]),
    "audit": _all("B", ["spider_db", "indicator_db", "out", "engine", "timeout", "append",
                        "quiet", "store", "identity", "base_url", "dry_run"]),
    "fuzz": _all("B", ["url", "param", "output", "baseline_iterations", "repeats", "sigma",
                       "min_delay", "pause", "timeout", "authorized", "store", "identity",
                       "dry_run"]),
    "session": _all("B", ["set-credential:host", "set-credential:identity",
                          "set-credential:username", "print:host", "print:identity",
                          "print:base_url"]),
    "proxy": _all("B", ["host", "port", "scope", "ca_dir", "store", "record", "identity",
                        "max_response_bytes", "response_deadline", "no_verify_tls",
                        "export_ca", "no_tls", "authorized", "dry_run"]),
    "report": _all("B", ["store", "run", "json"]),
    "reveal-holdout": _all("T", ["store", "run"]),
    "flow-anomaly": _all("T", ["store", "run", "method", "contamination", "seed"]),
    "mutate-run": _all("T", ["url", "param", "store", "vuln_class", "method", "location",
                             "base", "identity", "cov_dir", "app_root", "seed", "budget",
                             "allow_destructive", "authorized", "dry_run"]),
    "greybox-run": {
        **_all("B", ["base_url", "store", "spider_db", "identity", "mutation_variants",
                     "max_mutation_variants", "allow_destructive", "authorized",
                     "dry_run"]),
        "ground_truth": "T", "points": "T",
        **_all("L", ["cov_dir", "app_root", "labctl", "reset", "settle"]),
    },
    "lab-generate": _all("L", ["manifest", "out", "emitter", "check", "corpus_report"]),
    "train models": _all("T", ["store"]),
}

#: Dests another lane is adding (BUG-0138, `ccr-27885270-9ahcdd`): their class is decided
#: here so the merge stays classified. The guard fails once one exists in its parser
#: while still listed here — move it into FLAG_CLASSES then.
PENDING: dict[str, dict[str, str]] = {
    "auto": {"auth_origin": "B"},
    "crawl": {"auth_origin": "B", "no_spa_query": "B"},
    "greybox-run": {"auth_origin": "B"},
}

#: W* flags: the values a working command allows.
WORKING_RESTRICT: dict[str, dict[str, tuple[str, ...]]] = {
    "auto": {"budget_method": ("score",)},
}


def parser_dests(parser: argparse.ArgumentParser) -> list[str]:
    """Every option dest of ``parser``; a subcommand's as ``"<sub>:<dest>"``."""
    out: list[str] = []
    for a in parser._actions:
        if isinstance(a, argparse._HelpAction):
            continue
        if isinstance(a, argparse._SubParsersAction):
            for sub, sp in a.choices.items():
                out += [f"{sub}:{d}" for d in parser_dests(sp)]
            continue
        out.append(a.dest)
    return out


def refused_dests(key: str) -> set[str]:
    """Dests a working command built on parser ``key`` refuses (classes T and L)."""
    return {d for d, c in FLAG_CLASSES[key].items() if c in ("T", "L")}


# --- copying a parser ---------------------------------------------------------------

def _message(prog_target: str, flag: str, cls: str) -> str:
    if flag == "--ground-truth":
        return (f"{flag} is a benchmark option and never part of a working run; "
                f"use `{prog_target}`")
    if cls == "L":
        return (f"{flag} needs the instrumented lab; use `{prog_target}` "
                f"(or `fuzzlab greybox-run`)")
    return f"{flag} is a training option; use `{prog_target}` (see `{prog_target} --help`)"


class _Refuse(argparse.Action):
    """A flag a working command refuses: consumed (so the message names the flag, never
    its value) and turned into a usage error."""

    def __init__(self, option_strings, dest, *, message, **kwargs):
        self.message = message
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.error(self.message)


class _Restrict(argparse.Action):
    """A W* flag: only the listed values pass."""

    def __init__(self, option_strings, dest, *, allowed, target, **kwargs):
        self.allowed = allowed
        self.target = target
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values not in self.allowed:
            parser.error(f"{option_string} {values} is a training choice (a working run "
                         f"allows {', '.join(self.allowed)}); use `{self.target}`")
        setattr(namespace, self.dest, values)


#: Marks "not given on the command line" (presence, never a comparison with a default).
ABSENT = argparse.SUPPRESS


def copy_parser(source: argparse.ArgumentParser, *, prog: str,
                url_positional: bool = False,
                refuse: Mapping[str, str] | None = None,
                restrict: Mapping[str, tuple[str, ...]] | None = None,
                refuse_to: str = "fuzzlab train run",
                presence: Iterable[str] | None = None,
                description: str | None = None) -> argparse.ArgumentParser:
    """A new parser carrying a *copy* of each of ``source``'s actions (never re-typed,
    and ``source`` is never mutated).

    ``--store`` becomes optional. With ``url_positional`` the target is a positional
    ``url`` and ``--base-url`` a hidden alias. ``refuse`` maps dest -> class (T/L): each
    becomes a hidden option that consumes its value and exits 2 naming ``refuse_to``.
    ``restrict`` maps dest -> allowed values. ``presence`` dests default to
    :data:`ABSENT`, so ``hasattr(ns, dest)`` says whether the flag was given.
    """
    refuse = dict(refuse or {})
    restrict = dict(restrict or {})
    presence = set(presence or ())
    new = argparse.ArgumentParser(prog=prog,
                                  description=description or source.description,
                                  formatter_class=source.formatter_class)
    for action in source._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if action.dest in refuse:
            flag = next((o for o in action.option_strings if o.startswith("--")),
                        action.option_strings[0])
            new._add_action(_Refuse(
                action.option_strings, action.dest, nargs=action.nargs,
                default=ABSENT, help=argparse.SUPPRESS,
                message=_message(refuse_to, flag, refuse[action.dest])))
            continue
        if action.dest in restrict:
            new._add_action(_Restrict(
                action.option_strings, action.dest, nargs=action.nargs,
                default=action.default, choices=action.choices, help=action.help,
                metavar=action.metavar, allowed=restrict[action.dest], target=refuse_to))
            continue
        a = copy.copy(action)
        if a.dest == "store":
            a.required = False
            a.default = None
        if url_positional and a.dest == "base_url":
            a.required = False
            a.help = argparse.SUPPRESS
        if a.dest in presence:
            a.default = ABSENT
        new._add_action(a)
    if url_positional:
        new.add_argument("url", nargs="?", default=None,
                         help="Target base URL, e.g. http://127.0.0.1:8080 (first argument)")
    return new


def working_parser(key: str, *, prog: str) -> argparse.ArgumentParser:
    """The working view of parser ``key``: T and L flags refused, W* flags restricted,
    the URL positional — the parser `fuzzlab scan` (Phase 2) is built from."""
    return copy_parser(PARSERS[key](), prog=prog, url_positional=True,
                       refuse={d: FLAG_CLASSES[key][d] for d in refused_dests(key)},
                       restrict=WORKING_RESTRICT.get(key))
