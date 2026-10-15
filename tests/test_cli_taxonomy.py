"""FR-FUZZ-401, FR-UI-400: the command taxonomy, its flag classes and the working view.

Every flag of every command is classified (an unclassified, stale or arrived-but-pending
dest fails here), the grouped help lists every command once, a copied parser never
mutates or diverges from its source, and a working command refuses every training,
benchmark and lab-only flag by name (design D-8) — before anything is imported that
could send.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from pathlib import Path

import pytest

from fuzzlab import cli_taxonomy as tx

ROOT = Path(__file__).resolve().parents[1]
CLASSES = {"B", "T", "W*", "L"}


# --- classification coverage (two directions + pending) -----------------------------

@pytest.mark.parametrize("key", sorted(tx.PARSERS))
def test_every_dest_of_every_parser_is_classified_and_no_entry_is_stale(key):
    assert tx.classification_problems(key, tx.PARSERS[key]()) == []


def test_every_command_with_flags_has_a_parser_and_every_other_says_why():
    for c in tx.COMMANDS:
        if c.flags is None:
            assert c.name in tx.UNCLASSIFIED, c.name
        else:
            assert c.flags in tx.PARSERS and c.flags in tx.FLAG_CLASSES, c.name
    assert set(tx.PARSERS) == set(tx.FLAG_CLASSES)


def test_the_guard_catches_an_unclassified_a_stale_and_an_arrived_pending_dest():
    """PA-0034(2): the guard itself is proven on synthetic offenders."""
    p = argparse.ArgumentParser()
    p.add_argument("--store")
    p.add_argument("--run")
    p.add_argument("--new-flag")                       # unclassified; `json` is stale
    problems = tx.classification_problems("report", p)
    assert "unclassified: new_flag" in problems and "stale: json" in problems
    crawl = tx.PARSERS["crawl"]()
    crawl.add_argument("--auth-origin")                # BUG-0138's dest arrives
    assert "pending but present: auth_origin" in tx.classification_problems("crawl", crawl)


def test_session_subcommands_are_walked():
    assert any(":" in d for d in tx.parser_dests(tx.PARSERS["session"]()))


def test_the_working_ml_flags_follow_the_owner_split():
    auto = tx.FLAG_CLASSES["auto"]
    for d in ("ground_truth", "mode", "points", "train_on", "rank_objective", "calibrate",
              "holdout", "hybrid", "budget_seed"):
        assert auto[d] == "T", d
    for d in ("bandit", "confirm_budget", "anomaly", "model_id", "ranker_model_id",
              "categories", "identity", "browser", "oob", "plugins", "header_points",
              "authorized"):
        assert auto[d] == "B", d
    assert auto["score"] == auto["rank"] == auto["budget_method"] == "W*"
    assert auto["greybox_coverage_file"] == auto["greybox_dbfault_file"] == "L"


# --- the grouped help ---------------------------------------------------------------

def _dispatchable() -> set[str]:
    """Top-level names `fuzzlab/cli.py` dispatches, read from its source (AST)."""
    tree = ast.parse((ROOT / "fuzzlab" / "cli.py").read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) \
                and node.left.id == "command":
            for comp in node.comparators:
                if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                    names.add(comp.value)
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_TOOL_MODULES" for t in node.targets):
            names |= {k.value for k in node.value.keys}
    return names


def test_every_dispatchable_name_is_listed_once_in_exactly_one_place():
    from fuzzlab.cli import _usage
    text = _usage()
    tops = {c.name.split()[0] for c in tx.COMMANDS}
    assert _dispatchable() == tops | set(tx.OLD_NAMES), \
        "a command is dispatched but not in COMMANDS (or the reverse)"
    for c in tx.COMMANDS:
        rows = [ln for ln in text.splitlines() if ln.startswith("  " + c.usage + " ")
                or ln.strip() == c.usage]
        assert len(rows) == 1, (c.name, rows)
    tail = text[text.index("Older names"):]
    older = " ".join(tail[:tail.index("\n\n")].split())
    for old in tx.OLD_NAMES:
        assert old in older
        assert not any(ln.startswith(f"  {old} ") for ln in text.splitlines())


def test_help_is_grouped_working_training_lab_and_wrapped():
    from fuzzlab.cli import main
    out = subprocess.run([sys.executable, "-m", "fuzzlab.cli", "--help"],
                         capture_output=True, text=True, check=True).stdout
    order = [out.index(g) for g in tx.GROUPS]
    assert order == sorted(order)
    assert out.index("train run <url>") > out.index(tx.TRAINING) > out.index("  report ")
    assert all(len(ln) <= 100 for ln in out.splitlines())
    for c in tx.COMMANDS:                     # never a command name split across lines
        assert c.name in out, c.name
    block = out[out.index("Older names"):]
    block = block[:block.index("\n\n")]
    for old, new in tx.OLD_NAMES.items():      # the raw text: a wrap must not split it
        assert f"{old} (= {new})" in block, (old, block)
    from fuzzlab.core.storepath import DEFAULT_RULE
    assert "Lab-only" in out and DEFAULT_RULE.split(", else ")[-1] in out
    assert "scan" not in out.split()          # Phase 2: never advertise an unbuilt command
    assert main(["help"]) == 0


def test_an_unknown_command_still_exits_2_with_the_help(capsys):
    from fuzzlab.cli import main
    assert main(["nope"]) == 2
    assert "Training and benchmark" in capsys.readouterr().err


# --- copy_parser ----------------------------------------------------------------------

def action_variants(parser, *, skip=()):
    """``(action, argv)`` samples for every option of ``parser``: each nargs shape, a
    ``--flag=value`` form, and a dash-leading value where one can be given (PA-0400(1)).
    Required options are filled in. Shared with `tests/test_train_cli.py`."""
    def sample(a):
        if a.choices:
            return str(list(a.choices)[-1])
        return "7" if a.type in (int, float) else "v"

    def required(but):
        out = []
        for a in parser._actions:
            if a.required and a.option_strings and a is not but and a.dest not in skip:
                out += [a.option_strings[-1], sample(a)]
        return out

    for a in parser._actions:
        if (not a.option_strings or isinstance(a, argparse._HelpAction)
                or a.dest in skip):
            continue
        flag, base = a.option_strings[-1], required(a)
        if a.nargs == 0:
            shapes = [[flag]]
        elif isinstance(a, argparse._AppendAction):
            shapes = [[flag, sample(a), flag, sample(a)], [f"{flag}=-x"]]
        elif a.nargs == "?":
            shapes = [[flag], [flag, sample(a)], [f"{flag}=-x"]]
        elif a.nargs in ("*", "+"):
            shapes = [[flag, "a", "b"]] + ([[flag]] if a.nargs == "*" else [])
        else:
            shapes = [[flag, sample(a)]]
            if not a.choices and a.type not in (int, float):
                shapes.append([f"{flag}=-x"])
        for extra in shapes:
            yield a, base + extra


@pytest.mark.parametrize("key", sorted(k for k in tx.PARSERS if k != "session"))
def test_a_copy_parses_every_action_exactly_like_its_source(key):
    """PA-0400(1): copy vs source, over every action of every parser (discovered)."""
    src = tx.PARSERS[key]()
    copy = tx.copy_parser(tx.PARSERS[key](), prog="x")
    n = 0
    for action, argv in action_variants(src):
        assert vars(copy.parse_args(argv)) == vars(src.parse_args(argv)), (action.dest,
                                                                           argv)
        n += 1
    assert n >= len([a for a in src._actions if a.option_strings]) - 1


@pytest.mark.parametrize("make, problem", [
    (lambda p: p.add_mutually_exclusive_group().add_argument("--a"), "mutually exclusive"),
    (lambda p: p.set_defaults(x=1), "set_defaults"),
    (lambda p: p.add_subparsers().add_parser("s"), "subcommands"),
])
def test_a_shape_copy_parser_cannot_carry_is_refused(make, problem):
    """PA-0400(2): fail closed, never a parser that parses differently."""
    p = argparse.ArgumentParser(prog="src")
    make(p)
    with pytest.raises(tx.CopyError, match=problem):
        tx.copy_parser(p, prog="x")
    for kwargs, problem in (({"allow_abbrev": False}, "allow_abbrev"),
                            ({"prefix_chars": "+"}, "prefix_chars"),
                            ({"fromfile_prefix_chars": "@"}, "fromfile"),
                            ({"argument_default": 0}, "argument_default")):
        with pytest.raises(tx.CopyError, match=problem):
            tx.copy_parser(argparse.ArgumentParser(**kwargs), prog="x")


def test_only_a_single_value_option_can_be_restricted():
    p = argparse.ArgumentParser()
    p.add_argument("--opt", nargs="?", const="c")
    with pytest.raises(tx.CopyError, match="single-value"):
        tx.copy_parser(p, prog="x", restrict={"opt": ("c",)})
    q = argparse.ArgumentParser()
    q.add_argument("--n", type=int, default=1)
    r = tx.copy_parser(q, prog="x", restrict={"n": (2,)})
    assert r.parse_args(["--n", "2"]).n == 2          # the source's `type` is kept

def _auto():
    return tx.PARSERS["auto"]()


def test_a_copy_carries_every_dest_and_never_mutates_its_source():
    src = _auto()
    before = [(a.dest, a.required, a.default, a.help, a.option_strings)
              for a in src._actions]
    new = tx.copy_parser(src, prog="x", url_positional=True,
                         refuse={"calibrate": "T"}, restrict={"budget_method": ("score",)},
                         presence=("score",))
    after = [(a.dest, a.required, a.default, a.help, a.option_strings)
             for a in src._actions]
    assert before == after
    src_ids = {id(a) for a in src._actions}
    assert not any(id(a) in src_ids for a in new._actions)
    assert set(tx.parser_dests(src)) | {"url"} == set(tx.parser_dests(new))


def test_a_copy_makes_store_optional_and_the_url_positional():
    new = tx.copy_parser(_auto(), prog="x", url_positional=True)
    ns = new.parse_args(["http://127.0.0.1:8080"])
    assert ns.url == "http://127.0.0.1:8080" and ns.store is None and ns.base_url is None
    assert "--base-url" not in new.format_help()          # the alias is hidden


def test_presence_dests_are_absent_unless_given():
    new = tx.copy_parser(_auto(), prog="x", presence=("mode", "score"))
    ns = new.parse_args(["--base-url", "u"])
    assert not hasattr(ns, "mode") and not hasattr(ns, "score")
    ns = new.parse_args(["--base-url", "u", "--mode", "automatic", "--score"])
    assert ns.mode == "automatic" and ns.score is True


# --- the working view: refusal by name (D-8) ------------------------------------------

def _refused_cases():
    p = tx.PARSERS["auto"]()
    by_dest = {a.dest: a for a in p._actions}
    for dest in sorted(tx.refused_dests("auto")):
        a = by_dest[dest]
        flag = next(o for o in a.option_strings if o.startswith("--"))
        value = [] if a.nargs == 0 else [list(a.choices)[0] if a.choices else "/some/path"]
        yield pytest.param(dest, flag, value, id=dest)


@pytest.mark.parametrize("dest, flag, value", list(_refused_cases()))
def test_the_working_view_refuses_every_training_and_lab_flag_by_name(dest, flag, value,
                                                                     capsys):
    p = tx.working_parser("auto", prog="fuzzlab scan")
    with pytest.raises(SystemExit) as exc:
        p.parse_args(["http://127.0.0.1:8080", flag, *value, "--authorized"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert f"error: {flag} " in err and "fuzzlab train run" in err
    assert "/some/path" not in err                       # the flag is named, not its value


def test_ground_truth_is_refused_as_never_a_working_option(capsys):
    p = tx.working_parser("auto", prog="fuzzlab scan")
    with pytest.raises(SystemExit):
        p.parse_args(["http://x", "--ground-truth", "lab/ground-truth"])
    assert "never part of a working run" in capsys.readouterr().err


@pytest.mark.parametrize("method", ["uncertainty", "committee", "random"])
def test_the_working_view_allows_only_the_score_budget_order(method, capsys):
    p = tx.working_parser("auto", prog="fuzzlab scan")
    with pytest.raises(SystemExit):
        p.parse_args(["http://x", "--confirm-budget", "5", "--budget-method", method])
    assert f"--budget-method {method} is a training choice" in capsys.readouterr().err
    ns = p.parse_args(["http://x", "--confirm-budget", "5", "--budget-method", "score"])
    assert ns.budget_method == "score" and ns.confirm_budget == 5


def _engine_validates(ns, monkeypatch, tmp_path) -> bool:
    """Run the engine's own usage rules (`auto_cli.main`) on a completed working
    namespace; True when they all pass (the run then reaches the store, stubbed here)."""
    from fuzzlab.harness import auto_cli

    class Reached(Exception):
        pass

    def stop(*a, **k):
        raise Reached
    monkeypatch.setattr(auto_cli.Store, "__init__", stop)
    monkeypatch.setattr(auto_cli, "_build_plugins", lambda p, args: None)
    argv = ["--base-url", ns.url, "--store", str(tmp_path / "s.db"), "--authorized",
            "--categories", ns.categories, "--train-on", ns.train_on]
    argv += [f for f, on in (("--score", ns.score), ("--rank", ns.rank),
                             ("--anomaly", ns.anomaly)) if on]
    if ns.confirm_budget is not None:
        argv += ["--confirm-budget", str(ns.confirm_budget)]
    if ns.model_id is not None:
        argv += ["--model-id", str(ns.model_id)]
    try:
        auto_cli.main(argv)
    except Reached:
        return True
    except SystemExit:
        return False
    return False


@pytest.mark.parametrize("extra, train_on", [
    ([], "run"), (["--anomaly"], "run"), (["--confirm-budget", "3"], "run"),
    (["--score"], "saved"), (["--rank"], "saved"),
    (["--score", "--model-id", "3"], "saved"),
])
def test_a_completed_working_namespace_passes_the_engines_rules(extra, train_on,
                                                                monkeypatch, tmp_path):
    """FR-FUZZ-401 (reviews A4, then round 2): --score/--rank apply a saved model, and a
    plain working run keeps the engine's own `run` -- so every working namespace passes
    the engine's validation (`--train-on` other than run needs --score/--rank)."""
    from fuzzlab.harness.auto_cli import build_parser
    p = tx.working_parser("auto", prog="fuzzlab scan")
    ns = tx.working_namespace("auto", p.parse_args(["http://127.0.0.1:9", "--categories",
                                                    "xss", *extra]))
    assert ns.train_on == train_on
    assert _engine_validates(ns, monkeypatch, tmp_path)
    assert build_parser().get_default("train_on") == "run"     # the source is untouched


def test_store_default_matches_each_commands_parser():
    """A command flagged `store_default` has an optional --store resolved by storepath;
    a command whose parser requires --store is never flagged (review A5)."""
    from fuzzlab.train_cli import build_run_parser
    effective = {"train run": build_run_parser}
    for c in tx.COMMANDS:
        if c.flags is None:
            continue
        parser = effective.get(c.name, tx.PARSERS[c.flags])()
        store = next((a for a in parser._actions if a.dest == "store"), None)
        if c.store_default:
            assert store is not None and not store.required, c.name
        if store is not None and store.required:
            assert not c.store_default, c.name
    assert tx.command("train run").store_default


def test_the_working_view_keeps_every_working_flag():
    p = tx.working_parser("auto", prog="fuzzlab scan")
    ns = p.parse_args(["http://127.0.0.1:8080", "--categories", "xss", "--identity", "bob",
                       "--browser", "--oob", "--bandit", "--score", "--rank",
                       "--model-id", "3", "--confirm-budget", "4", "--anomaly",
                       "--plugins", "--header-points", "--fuzz-json-writes",
                       "--authorized"])
    assert ns.url and ns.score and ns.rank and ns.model_id == 3 and ns.authorized


def test_a_working_view_refusal_opens_no_socket(monkeypatch):
    """Refusal is decided at parse time: nothing connects anywhere. (Importing `auto`'s
    parser imports its sender module today -- `auto_cli` is locked this phase; Phase 2
    makes that import lazy. Importing is not sending; this test pins the sending.)"""
    import socket
    calls = []
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: calls.append(a))
    p = tx.working_parser("auto", prog="s")
    for flag in (["--calibrate", "platt"], ["--ground-truth", "x"], ["--holdout"]):
        with pytest.raises(SystemExit):
            p.parse_args(["http://127.0.0.1:8080", *flag, "--authorized"])
    assert calls == []
