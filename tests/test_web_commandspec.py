"""Tests for the command-spec registry (`fuzzlab/web/commandspec.py`).

The registry derives the launcher's form schema from each tool's own argparse
parser (single source of truth). These tests cover the introspection mapping in
isolation and assert the real tools' specs match their parsers (never
hand-mirrored constants — PA-0001).
"""

from __future__ import annotations

import argparse
import json

import pytest

from fuzzlab.web import commandspec as cs


# --- introspection mapping (isolated, deterministic) -----------------------

def _sample_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sample")
    p.add_argument("--name", required=True, help="a required string")
    p.add_argument("--count", type=int, default=3, help="an int")
    p.add_argument("--ratio", type=float, default=1.5, help="a float")
    p.add_argument("--mode", choices=["a", "b"], default="a", help="a choice")
    p.add_argument("--flag", action="store_true", help="a bool")
    p.add_argument("--tag", action="append", help="repeatable")
    return p


def test_introspect_maps_every_option_type():
    options, subs = cs.introspect(_sample_parser())
    by_name = {o.name: o for o in options}
    assert subs == {}
    # -h/--help is skipped
    assert "--help" not in by_name and "-h" not in by_name
    assert by_name["--name"].type == "str" and by_name["--name"].required is True
    assert by_name["--count"].type == "int" and by_name["--count"].default == 3
    assert by_name["--ratio"].type == "float" and by_name["--ratio"].default == 1.5
    assert by_name["--mode"].type == "choice" and by_name["--mode"].choices == ["a", "b"]
    assert by_name["--flag"].type == "bool" and by_name["--flag"].required is False
    assert by_name["--tag"].multiple is True


def test_introspect_recurses_subparsers():
    p = argparse.ArgumentParser(prog="s")
    sub = p.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("one")
    one.add_argument("--x", required=True)
    options, subs = cs.introspect(p)
    assert options == []  # only the subparsers action, which is not an option
    assert "one" in subs
    assert subs["one"][0].name == "--x" and subs["one"][0].required is True


def test_dest_uses_long_flag_name():
    p = argparse.ArgumentParser()
    p.add_argument("-u", "--base-url")
    options, _ = cs.introspect(p)
    assert options[0].name == "--base-url"
    assert options[0].dest == "base_url"


# --- the real registry -----------------------------------------------------

def test_registry_lists_expected_activities():
    names = set(cs.command_names())
    expected = {"crawl", "audit", "fuzz", "auto", "greybox-run",
                "proxy", "mutate-run", "report", "session", "build-db",
                "lab-generate"}
    assert expected <= names


def test_lab_generate_registered_grouped_and_untraffic():
    # X0: lab-generate is a launchable authoring activity in its own group. It
    # renders files (writes locally, `--check` runs gates) and sends NO traffic,
    # so it carries no authorized/destructive gate.
    s = cs.spec("lab-generate")
    assert s.group == "Lab / authoring"
    assert s.sends_traffic is False
    assert s.needs_authorized is False and s.destructive_gate is False
    # fields come from the tool's own parser (PA-0001), incl. the required ones
    dests = {o.dest: o for o in s.options}
    assert dests["manifest"].required is True and dests["out"].required is True
    assert dests["emitter"].type == "choice"
    assert "group" in s.to_dict()  # the field is exposed to the UI


def test_group_defaults_to_none_for_ungrouped_activities():
    assert cs.spec("auto").group is None
    assert cs.spec("auto").to_dict()["group"] is None


def test_all_specs_build_and_are_json_serializable():
    specs = cs.all_specs()
    assert len(specs) == len(cs.command_names())  # none failed to build
    for s in specs:
        # to_dict() must round-trip through JSON (the launcher sends it to the UI)
        json.dumps(s.to_dict())
        assert s.name and s.prog.startswith("fuzzlab ")


@pytest.mark.parametrize("name,authorized,destructive,traffic", [
    ("auto", True, False, True),
    ("fuzz", True, False, True),
    # greybox-run gained its own --allow-destructive gate (CC-FUZZ-0019): its
    # opt-in mutation-variant write-back goes through the same destructive gate
    # as mutate-run, so the auto-derived commandspec now reports it too.
    ("greybox-run", True, True, True),
    ("proxy", True, False, True),
    ("mutate-run", True, True, True),
    ("crawl", False, False, True),
    ("audit", False, False, True),
    ("report", False, False, False),
    ("build-db", False, False, False),
])
def test_gates_and_traffic_flags(name, authorized, destructive, traffic):
    s = cs.spec(name)
    assert s.needs_authorized is authorized
    assert s.destructive_gate is destructive
    assert s.sends_traffic is traffic


def test_authorized_gate_is_derived_from_the_parser():
    # every command whose spec claims an authorized gate must actually expose the flag
    for s in cs.all_specs():
        dests = {o.dest for o in s.options}
        for opts in s.subcommands.values():
            dests.update(o.dest for o in opts)
        assert s.needs_authorized == ("authorized" in dests)
        assert s.destructive_gate == ("allow_destructive" in dests)


def test_option_defaults_match_the_parser_not_a_constant():
    # PA-0001: the spec must READ defaults from the tool's parser, not restate them.
    from fuzzlab.proxy.cli import build_parser
    parser = build_parser()
    spec_defaults = {o.dest: o.default for o in cs.spec("proxy").options}
    for dest, default in spec_defaults.items():
        assert default == parser.get_default(dest)


def test_unknown_command_raises():
    with pytest.raises(KeyError):
        cs.spec("does-not-exist")
