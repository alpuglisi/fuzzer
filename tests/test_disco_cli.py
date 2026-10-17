"""``fuzzlab disco`` (D70): usage failures exit 2 having written nothing (PA-0079), an
earlier run's output is never reused (PA-0450), ``--dry-run`` sends nothing, and the
legacy ``crawl`` says it is deprecated."""

from __future__ import annotations

import json

import pytest
import yaml

from fuzzlab import cli as top
from fuzzlab.disco import cli
from fuzzlab.disco.capture import append_record

from tests.test_disco_synth import U1, rec


@pytest.fixture()
def capture_file(tmp_path):
    p = tmp_path / "run" / "capture.jsonl"
    p.parent.mkdir()
    for r in (rec("GET", "/api/projects", res=[{"id": 101}], t=1),
              rec("POST", "/api/projects/101/tasks", body={"title": "a"}, res={"id": U1},
                  status=201, t=2)):
        append_record(p, r)
    return p


def test_capture_without_authorized_exits_2_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr("fuzzlab.disco.proxyproc.CaptureProxy.start",
                        lambda self: pytest.fail("a proxy was started"))
    out = tmp_path / "new"
    assert cli.main(["capture", "--start", "http://127.0.0.1:9/", "--out", str(out)]) == 2
    assert not out.exists()


def test_capture_refuses_a_directory_holding_an_earlier_capture(capture_file):
    assert cli.main(["capture", "--start", "http://127.0.0.1:9/", "--out",
                     str(capture_file.parent), "--authorized"]) == 2


def test_capture_dry_run_plans_and_sends_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("fuzzlab.disco.proxyproc.CaptureProxy.start",
                        lambda self: pytest.fail("a proxy was started"))
    assert cli.main(["capture", "--start", "http://127.0.0.1:9/", "--out", str(tmp_path / "x"),
                     "--dry-run"]) == 0
    assert "sends nothing" in capsys.readouterr().out and not (tmp_path / "x").exists()


def test_synth_then_generate_without_llm_sends_nothing_and_makes_a_valid_contract(capture_file, tmp_path,
                                                                    monkeypatch):
    monkeypatch.setattr("fuzzlab.disco.generate.AnthropicProvider.__init__",
                        lambda *a, **k: pytest.fail("an LLM client was built"))
    inv = tmp_path / "inventory.json"
    assert cli.main(["synth", "--capture", str(capture_file), "--out", str(inv)]) == 0
    assert json.loads(inv.read_text())["x-disco"]["endpoints"] == 2
    assert cli.main(["synth", "--capture", str(capture_file), "--out", str(inv)]) == 2
    contract = tmp_path / "contract.yaml"
    assert cli.main(["generate", "--inventory", str(inv), "--out", str(contract),
                     "--auth-profile", "user_a:bearer:env:TOKEN_A",
                     "--auth-profile", "anon:none"]) == 0
    doc = yaml.safe_load(contract.read_text())
    assert [p["id"] for p in doc["auth_profiles"]] == ["user_a", "anon"]
    assert doc["test_cases"] == [] and len(doc["endpoints"]) == 2


@pytest.mark.parametrize("spec", ["user_a", "user_a:root", ":none"])
def test_a_malformed_auth_profile_exits_2_before_any_call(capture_file, tmp_path, spec):
    inv = tmp_path / "inventory.json"
    cli.main(["synth", "--capture", str(capture_file), "--out", str(inv)])
    out = tmp_path / "c.yaml"
    assert cli.main(["generate", "--inventory", str(inv), "--out", str(out),
                     "--auth-profile", spec]) == 2
    assert not out.exists()


def _contract(tmp_path, capture_file) -> str:
    inv = tmp_path / "inventory.json"
    cli.main(["synth", "--capture", str(capture_file), "--out", str(inv)])
    out = tmp_path / "contract.yaml"
    cli.main(["generate", "--inventory", str(inv), "--out", str(out)])
    return str(out)


def test_run_usage_failures_write_no_results(tmp_path, capture_file):
    contract = _contract(tmp_path, capture_file)
    results = tmp_path / "results.jsonl"
    assert cli.main(["run", "--contract", contract, "--results", str(results)]) == 2
    assert not results.exists()
    bad = tmp_path / "bad.yaml"
    bad.write_text("contract_version: '9'\n")
    assert cli.main(["run", "--contract", str(bad), "--results", str(results),
                     "--authorized"]) == 2
    assert not results.exists()
    results.write_text("earlier\n")
    assert cli.main(["run", "--contract", contract, "--results", str(results),
                     "--authorized"]) == 2
    assert results.read_text() == "earlier\n"


def test_run_dry_run_plans_and_sends_nothing(tmp_path, capture_file, capsys):
    contract = _contract(tmp_path, capture_file)
    results = tmp_path / "results.jsonl"
    assert cli.main(["run", "--contract", contract, "--results", str(results),
                     "--dry-run"]) == 0
    assert "would_execute: False" in capsys.readouterr().out and not results.exists()


def test_the_legacy_crawl_says_it_is_deprecated(capsys):
    with pytest.raises(SystemExit):
        top.main(["crawl", "--help"])
    assert "deprecated (D70)" in capsys.readouterr().err
