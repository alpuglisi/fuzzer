"""Tests for the CLI-level ``--dry-run`` flag (D0a).

Every plain CLI entry point except ``fuzzlab/greybox/greybox_cli.py`` (owned by
a separate lane, D0b) now accepts ``--dry-run``: it plans and reports the exact
command it would run and sends nothing, reusing the same plan/report logic the
web launcher's ``/api/launch/dry-run`` route already ships (CC-UI-0013/0015),
via the shared ``fuzzlab.cli_dryrun`` module.

Covers: ``crawl``, ``audit``, ``fuzz``, ``auto``, ``mutate-run``, ``proxy``.
"""

from __future__ import annotations

import runpy
import sys

import pytest


def _explode(*_a, **_kw):
    raise AssertionError("dry-run must not perform the real action")


# --- crawl (fuzzlab/tools/spider.py — no main(), dispatched via __main__) --

def test_crawl_has_dry_run_flag():
    from fuzzlab.tools.spider import build_parser
    args = build_parser().parse_args(["--start", "http://localhost", "--dry-run"])
    assert args.dry_run is True


def test_crawl_dry_run_reports_plan_and_sends_nothing(monkeypatch, capsys):
    from fuzzlab.tools import spider
    monkeypatch.setattr(spider.LocalSpider, "crawl", _explode)
    monkeypatch.setattr(spider.LocalSpider, "__init__", _explode)
    monkeypatch.setattr(sys, "argv",
                        ["spider.py", "--start", "http://localhost", "--dry-run"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("fuzzlab.tools.spider", run_name="__main__")
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "crawl" in out
    assert "fuzzlab crawl" in out
    assert "--dry-run" not in out.split("\n")[1]  # not echoed in the planned argv


# --- audit (fuzzlab/tools/fetcher.py — no main(), dispatched via __main__) --

def test_audit_has_dry_run_flag():
    from fuzzlab.tools.fetcher import build_parser
    args = build_parser().parse_args(["--dry-run"])
    assert args.dry_run is True


def test_audit_dry_run_reports_plan_and_sends_nothing(monkeypatch, capsys):
    from fuzzlab.tools import fetcher
    monkeypatch.setattr(fetcher, "load_urls", _explode)
    monkeypatch.setattr(fetcher, "load_indicators", _explode)
    monkeypatch.setattr(sys, "argv", ["fetcher.py", "--dry-run"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("fuzzlab.tools.fetcher", run_name="__main__")
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "audit" in out
    assert "fuzzlab audit" in out


# --- fuzz (fuzzlab/tools/blind_sqli_fuzzer.py — has main()) -----------------

def test_fuzz_has_dry_run_flag():
    from fuzzlab.tools.blind_sqli_fuzzer import build_parser
    args = build_parser().parse_args(["--url", "http://localhost/x", "--dry-run"])
    assert args.dry_run is True


def test_fuzz_dry_run_reports_plan_and_sends_nothing(monkeypatch, capsys):
    from fuzzlab.tools import blind_sqli_fuzzer as fuzzmod
    monkeypatch.setattr(fuzzmod, "establish_baseline", _explode)
    monkeypatch.setattr(fuzzmod, "run_fuzzing_cycle", _explode)
    rc = fuzzmod.main(["--url", "http://localhost/x", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "fuzz" in out
    assert "--url http://localhost/x" in out
    # No --authorized was passed, and dry-run must not enforce/require it.
    assert "would_execute: False" in out


# --- auto (fuzzlab/harness/auto_cli.py — has main()) -------------------------

def test_auto_has_dry_run_flag():
    from fuzzlab.harness.auto_cli import build_parser
    args = build_parser().parse_args(
        ["--base-url", "http://localhost", "--store", "x.db", "--dry-run"])
    assert args.dry_run is True


def test_auto_dry_run_reports_plan_and_sends_nothing(monkeypatch, capsys):
    from fuzzlab.harness import auto_cli
    monkeypatch.setattr(auto_cli, "run_auto", _explode)
    monkeypatch.setattr(auto_cli.Store, "__init__", _explode)
    rc = auto_cli.main(
        ["--base-url", "http://localhost", "--store", "x.db", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "auto" in out


# --- mutate-run (fuzzlab/mutation/cli.py — has main()) -----------------------

def test_mutate_run_has_dry_run_flag():
    from fuzzlab.mutation.cli import build_parser
    args = build_parser().parse_args(
        ["--url", "http://localhost/x", "--param", "id", "--store", "x.db",
         "--dry-run"])
    assert args.dry_run is True


def test_mutate_run_dry_run_reports_plan_and_sends_nothing(monkeypatch, capsys):
    from fuzzlab.mutation import cli as mutation_cli
    monkeypatch.setattr(mutation_cli.mrun, "run_mutation", _explode)
    monkeypatch.setattr(mutation_cli.Store, "__init__", _explode)
    monkeypatch.setattr(mutation_cli, "make_probe_sender", _explode)
    rc = mutation_cli.main(
        ["--url", "http://localhost/x", "--param", "id", "--store", "x.db",
         "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "mutate-run" in out


# --- proxy (fuzzlab/proxy/cli.py — has main()) --------------------------------

def test_proxy_has_dry_run_flag():
    from fuzzlab.proxy.cli import build_parser
    args = build_parser().parse_args(["--dry-run"])
    assert args.dry_run is True


def test_proxy_dry_run_reports_plan_and_sends_nothing(monkeypatch, capsys):
    from fuzzlab.proxy import cli as proxy_cli
    monkeypatch.setattr(proxy_cli, "LocalCA", _explode)
    monkeypatch.setattr(proxy_cli, "SocketSender", _explode)
    monkeypatch.setattr(proxy_cli.asyncio, "run", _explode)
    rc = proxy_cli.main(["--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "proxy" in out


# --- shared helper module -----------------------------------------------------

def test_greybox_cli_untouched_by_this_lane():
    """D0a explicitly excludes greybox_cli.py (owned by lane D0b)."""
    from fuzzlab.greybox.greybox_cli import build_parser
    dests = {a.dest for a in build_parser()._actions}
    assert "dry_run" not in dests


@pytest.mark.parametrize("name", ["crawl", "audit", "fuzz", "auto", "mutate-run", "proxy"])
def test_dry_run_report_uses_shared_web_commandspec(name):
    """cli_dryrun.report reuses the same CommandSpec registry the web
    launcher's dry-run preview uses (no reimplemented plan/report logic)."""
    from fuzzlab.web import commandspec
    assert name in commandspec.command_names()
