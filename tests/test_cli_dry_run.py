"""Tests for the CLI-level ``--dry-run`` flag (D0a + D0b).

Every plain CLI entry point now accepts ``--dry-run``: it plans and reports the
exact command it would run and sends nothing, reusing the same plan/report
logic the web launcher's ``/api/launch/dry-run`` route already ships
(CC-UI-0013/0015), via the shared ``fuzzlab.cli_dryrun`` module.

Covers: ``crawl``, ``audit``, ``fuzz``, ``auto``, ``mutate-run``, ``proxy``
(D0a, ``CC-FUZZ-0020``/others) and ``greybox-run`` (D0b, ``CC-FUZZ-0022``).
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


# --- greybox-run (fuzzlab/greybox/greybox_cli.py — has main(); D0b) ---------

def test_greybox_run_has_dry_run_flag():
    from fuzzlab.greybox.greybox_cli import build_parser
    args = build_parser().parse_args(
        ["--base-url", "http://localhost", "--store", "x.db", "--dry-run"])
    assert args.dry_run is True


def test_greybox_run_dry_run_reflects_mutation_variant_flags():
    """The C1-added --mutation-variants/--max-mutation-variants/
    --allow-destructive flags are ordinary parser options, so they show up in
    the planned argv/display like any other flag."""
    from fuzzlab.greybox.greybox_cli import build_parser
    args = build_parser().parse_args(
        ["--base-url", "http://localhost", "--store", "x.db",
         "--mutation-variants", "--max-mutation-variants", "5",
         "--allow-destructive", "--dry-run"])
    assert args.dry_run is True
    assert args.mutation_variants is True
    assert args.max_mutation_variants == 5
    assert args.allow_destructive is True


def test_greybox_run_dry_run_reports_plan_and_sends_nothing(monkeypatch, capsys):
    from fuzzlab.greybox import greybox_cli
    monkeypatch.setattr(greybox_cli.gbrun, "run_greybox", _explode)
    monkeypatch.setattr(greybox_cli.gbrun, "points_from_store", _explode)
    monkeypatch.setattr(greybox_cli.gbrun, "RequestsCorrelatingSender", _explode)
    monkeypatch.setattr(greybox_cli.Store, "__init__", _explode)
    monkeypatch.setattr(greybox_cli, "import_spider", _explode)
    rc = greybox_cli.main(
        ["--base-url", "http://localhost", "--store", "x.db", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "greybox-run" in out
    assert "fuzzlab greybox-run" in out
    assert "--base-url http://localhost" in out
    # No --authorized was passed, and dry-run must not enforce/require it.
    assert "would_execute: False" in out


def test_greybox_run_dry_run_includes_mutation_variant_flags_in_plan(capsys):
    """The planned argv/display reflects the C1-added flags, not just the
    pre-existing ones (the exact requirement D0b's task called out)."""
    from fuzzlab.greybox import greybox_cli
    rc = greybox_cli.main(
        ["--base-url", "http://localhost", "--store", "x.db",
         "--mutation-variants", "--max-mutation-variants", "7",
         "--allow-destructive", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "--mutation-variants" in out
    assert "--max-mutation-variants 7" in out
    assert "--allow-destructive" in out


# --- shared helper module -----------------------------------------------------

@pytest.mark.parametrize(
    "name", ["crawl", "audit", "fuzz", "auto", "mutate-run", "proxy", "greybox-run"])
def test_dry_run_report_uses_shared_web_commandspec(name):
    """cli_dryrun.report reuses the same CommandSpec registry the web
    launcher's dry-run preview uses (no reimplemented plan/report logic)."""
    from fuzzlab.web import commandspec
    assert name in commandspec.command_names()
