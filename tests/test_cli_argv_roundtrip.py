"""BUG-0400 / PA-0400: an argv built from a parser's values must parse back to the same values.

`web/runner.build_flags` (used by the web launcher's real launch argv and by every CLI's
``--dry-run`` display through `cli_dryrun`) serialises a values dict keyed by argparse
dest back into flags. It handles three action shapes (bool, append, single value) and
mis-serialises the others the project's parsers use. The working shapes are asserted
here; each broken shape is pinned with a strict xfail naming BUG-0400, so the UI lane's
fix turns it into an XPASS that must be converted into a plain test (PA-0054(3),
MULTI_AGENT_ORCHESTRATION §6). This lane may not edit `fuzzlab/web/`.
"""

from __future__ import annotations

import pytest

from fuzzlab.web import commandspec
from fuzzlab.web.runner import build_flags


def _round_trip(name: str, argv: list[str]) -> tuple[dict, dict]:
    """(values parsed from ``argv``, values parsed from build_flags(values))."""
    loader = {e.name: e.loader for e in commandspec._REGISTRY}[name]
    parser = loader()
    first = vars(parser.parse_args(argv))
    spec = commandspec.spec(name)
    rebuilt = build_flags(spec, {k: v for k, v in first.items() if k != "dry_run"})
    second = vars(loader().parse_args(rebuilt))
    return first, second


@pytest.mark.parametrize("name, argv", [
    ("auto", ["--base-url", "http://127.0.0.1:8080", "--store", "x.db", "--score",
              "--categories", "sql-injection,xss"]),
    ("crawl", ["--start", "http://127.0.0.1:8080", "--max-depth", "2", "--no-reveal"]),
    ("mutate-run", ["--url", "http://127.0.0.1/x", "--param", "id", "--store", "x.db",
                    "--base", "1 OR 1=1", "--base", "' OR ''='"]),
])
def test_bool_append_and_single_value_shapes_round_trip(name, argv):
    first, second = _round_trip(name, argv)
    assert first == second


@pytest.mark.xfail(strict=True, reason="BUG-0400: nargs='*' with no items is emitted as "
                   "the literal value '[]' (owned by the UI lane: fuzzlab/web/runner.py)")
def test_nargs_star_with_no_items_round_trips():
    first, second = _round_trip("crawl", ["--submit-spa-forms"])
    assert first == second


@pytest.mark.xfail(strict=True, reason="BUG-0400: an option whose const is '' "
                   "(--follow-selector-forms alone) is dropped (UI lane)")
def test_optional_value_with_empty_const_round_trips():
    first, second = _round_trip("crawl", ["--follow-selector-forms"])
    assert first == second


@pytest.mark.xfail(strict=True, reason="BUG-0400: a value starting with '-' is emitted "
                   "space-separated and no longer parses (UI lane)")
def test_dash_leading_value_round_trips():
    first, second = _round_trip("auto", ["--base-url", "http://127.0.0.1:8080",
                                         "--store", "x.db", "--identity=-bob"])
    assert first == second


# --- discovery: every action of every registered parser (PA-0400(1)) -------------------

import argparse  # noqa: E402

_URL = "http://127.0.0.1:8080"


def _sample(action) -> str:
    if action.choices:
        return str(list(action.choices)[-1])
    if action.type in (int, float):
        return "3"
    return _URL if "url" in action.dest or action.dest == "start" else "v"


def _required_argv(parser, skip) -> list[str]:
    out: list[str] = []
    for a in parser._actions:
        if a.required and a.option_strings and a is not skip:
            out += [a.option_strings[-1], _sample(a)]
    return out


def _cases():
    """(spec name, dest, argv, broken-shape reason or None) for every option of every
    registered parser that has no subcommands (`session`'s subcommands are not built
    by `build_flags` at all — a stated scope of the launcher, not this bug)."""
    out = []
    for entry in commandspec._REGISTRY:
        if entry.loader is None:
            continue
        parser = entry.loader()
        if any(isinstance(a, argparse._SubParsersAction) for a in parser._actions):
            continue
        for a in parser._actions:
            if not a.option_strings or isinstance(a, argparse._HelpAction) \
                    or a.dest == "dry_run":
                continue
            flag = a.option_strings[-1]
            base = _required_argv(parser, a)
            if a.nargs == 0:
                variants = [([flag], None)]
            elif isinstance(a, argparse._AppendAction):
                variants = [([flag, _sample(a), flag, _sample(a)], None)]
            elif a.nargs == "?":
                variants = [([flag, _sample(a)], None),
                            ([flag], "BUG-0400: bare optional-value flag (const)"
                             if a.const == "" else None)]
            elif a.nargs in ("*", "+"):
                variants = [([flag, "a", "b"],
                              "BUG-0400: a list value is emitted as its Python repr")]
                if a.nargs == "*":
                    variants.append(([flag], "BUG-0400: nargs='*' with no items"))
            else:
                variants = [([flag, _sample(a)], None)]
            for extra, broken in variants:
                out.append((entry.name, a.dest, base + extra, broken))
    return out


_CASES = _cases()


@pytest.mark.parametrize(
    "name, dest, argv",
    [pytest.param(n, d, v, marks=[pytest.mark.xfail(strict=True, reason=r)] if r else [],
                  id=f"{n}:{d}:{len(v)}") for n, d, v, r in _CASES])
def test_every_action_of_every_registered_parser_round_trips(name, dest, argv):
    first, second = _round_trip(name, argv)
    assert first == second


def test_discovery_reaches_every_registered_parser_and_the_broken_shapes():
    names = {n for n, *_ in _CASES}
    assert {"auto", "crawl", "mutate-run", "report", "proxy", "flow-anomaly"} <= names
    assert any(r for *_, r in _CASES), "the known BUG-0400 shapes must be enumerated"
