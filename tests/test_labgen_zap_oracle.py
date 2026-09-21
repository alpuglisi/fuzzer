"""Offline tests for `fuzzlab.labgen.zap_oracle` (the OWASP ZAP whole-app
safety-net oracle wrapper -- see docs/LAB_SEED_AUTHORING_PLAYBOOK.md and
docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md).

Every branch is exercised with an injected fake runner that simulates what
the real `zap.sh -cmd -autorun <plan>` invocation does: it reads the
generated plan's `report` job to find where a report should land, and
optionally writes one there (or not, to simulate a crash) before returning.
No real subprocess or the ~234MB ZAP binary is needed here (see
test_labgen_zap_oracle_integration.py for the skip-guarded real-binary test,
per PA-0005).
"""

import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from fuzzlab.labgen.oracle_wrapper import OracleRunResult, OracleSafetyError, ToolNotFoundError, Verdict
from fuzzlab.labgen.zap_oracle import ZapWholeAppScanRequest, run_zap_whole_app_scan


def _alert(name, risk="High", confidence="Medium", url="http://127.0.0.1:8089/?user=x", param="user"):
    return {
        "name": name,
        "riskdesc": f"{risk} ({confidence})",
        "instances": [{"uri": url, "param": param}],
    }


class FakeZapRunner:
    """Reads the generated plan's `report` job to learn where to write a
    fake ZAP JSON report (or writes none, to simulate a crash/timeout), then
    returns the next scripted `OracleRunResult`. Records every argv/plan."""

    def __init__(self, script):
        # script: list of (alerts_or_None, run_kwargs) consumed in order.
        self._script = list(script)
        self.calls = []
        self.plans = []

    def __call__(self, argv, timeout_s):
        self.calls.append((list(argv), timeout_s))
        plan_path = argv[argv.index("-autorun") + 1]
        plan = yaml.safe_load(Path(plan_path).read_text())
        self.plans.append(plan)
        report_job = next(j for j in plan["jobs"] if j["type"] == "report")
        report_dir = report_job["parameters"]["reportDir"]
        report_file = report_job["parameters"]["reportFile"]

        if not self._script:
            raise AssertionError("FakeZapRunner called more times than scripted")
        alerts, run_kwargs = self._script.pop(0)
        if alerts is not None:
            Path(report_dir, f"{report_file}.json").write_text(
                json.dumps({"site": [{"alerts": alerts}]})
            )
        defaults = dict(returncode=0, stdout="", stderr="", timed_out=False, duration_s=0.01)
        defaults.update(run_kwargs)
        return OracleRunResult(argv=list(argv), **defaults)


def _req(**kwargs):
    kwargs.setdefault("target_url", "http://127.0.0.1:8089/?user=test")
    kwargs.setdefault("tool_path", "/opt/zap/zap.sh")
    return ZapWholeAppScanRequest(**kwargs)


@pytest.fixture(autouse=True)
def _zap_sh_resolves(monkeypatch):
    # Every test passes an explicit tool_path for a zap.sh that doesn't
    # really exist on disk -- resolve it as if `locate_tool` found it there,
    # exactly like a real install would, without touching the real PATH.
    monkeypatch.setattr(shutil, "which", lambda candidate: candidate)


# --- loopback safety / tool location -----------------------------------------

def test_refuses_non_loopback_target_without_invoking_runner():
    request = _req(target_url="http://example.com/?user=test")
    runner = FakeZapRunner([])
    with pytest.raises(OracleSafetyError):
        run_zap_whole_app_scan(request, runner=runner)
    assert runner.calls == []


def test_missing_binary_raises_tool_not_found(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    request = _req(tool_path=None)
    with pytest.raises(ToolNotFoundError):
        run_zap_whole_app_scan(request, runner=FakeZapRunner([]))


# --- plan construction --------------------------------------------------------

def test_plan_seeds_spider_with_the_full_target_url_including_query():
    request = _req(alert_name_pattern=re.compile("SSTI"))
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    plan = runner.plans[0]
    spider_job = next(j for j in plan["jobs"] if j["type"] == "spider")
    assert spider_job["parameters"]["url"] == "http://127.0.0.1:8089/?user=test"


def test_plan_context_url_and_include_paths_strip_the_query_string():
    request = _req()
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    plan = runner.plans[0]
    ctx = plan["env"]["contexts"][0]
    assert ctx["urls"] == ["http://127.0.0.1:8089/"]
    assert any(p.startswith("http://127.0.0.1:8089/") for p in ctx["includePaths"])


def test_plan_extra_include_paths_are_appended():
    request = _req(include_paths=["http://127.0.0.1:8089/admin/.*"])
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    plan = runner.plans[0]
    assert "http://127.0.0.1:8089/admin/.*" in plan["env"]["contexts"][0]["includePaths"]


def test_plan_never_includes_an_exitstatus_job():
    # The wrapper must never rely on ZAP's own opaque, unscoped exit code
    # (Spike 005 finding) -- it always classifies from the parsed report.
    request = _req()
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    plan = runner.plans[0]
    assert not any(j["type"] == "exitStatus" for j in plan["jobs"])


def test_plan_uses_traditional_json_plus_report_template():
    request = _req()
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    plan = runner.plans[0]
    report_job = next(j for j in plan["jobs"] if j["type"] == "report")
    assert report_job["parameters"]["template"] == "traditional-json-plus"


def test_argv_passes_dir_flag_for_an_isolated_zap_home(tmp_path):
    request = _req(zap_home_dir=str(tmp_path / "zap-home"))
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("-dir") + 1] == str(tmp_path / "zap-home")


# --- verdict classification: scoped (alert_name_pattern) ---------------------

def test_matching_alert_at_or_above_threshold_is_confirmed_vulnerable():
    request = _req(alert_name_pattern=re.compile("Server Side Template Injection"))
    runner = FakeZapRunner([([_alert("Server Side Template Injection", risk="High")], {})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_VULNERABLE
    assert verdict.confirmed_vulnerable is True
    assert len(verdict.matching_alerts) == 1


def test_non_matching_alerts_yield_confirmed_secure_even_with_other_noise():
    request = _req(alert_name_pattern=re.compile("Server Side Template Injection"))
    runner = FakeZapRunner([([
        _alert("Content Security Policy (CSP) Header Not Set", risk="Medium"),
        _alert("Missing Anti-clickjacking Header", risk="Medium"),
    ], {})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE
    assert verdict.matching_alerts == ()
    assert len(verdict.all_alerts) == 2  # still surfaced for debugging


def test_matching_alert_below_risk_threshold_does_not_count():
    request = _req(alert_name_pattern=re.compile("XSS"), risk_threshold="High")
    runner = FakeZapRunner([([_alert("Cross Site Scripting (Reflected)", risk="Medium")], {})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE


def test_risk_threshold_is_case_insensitive():
    request = _req(alert_name_pattern=re.compile("XSS"), risk_threshold="medium")
    runner = FakeZapRunner([([_alert("Reflected XSS", risk="High")], {})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_VULNERABLE


# --- verdict classification: unscoped whole-app safety-net mode -------------

def test_unscoped_mode_treats_any_alert_at_or_above_threshold_as_vulnerable():
    request = _req(alert_name_pattern=None, risk_threshold="Medium")
    runner = FakeZapRunner([([_alert("Missing Anti-clickjacking Header", risk="Medium")], {})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_VULNERABLE
    assert "whole-app safety-net" in verdict.checked_for


def test_unscoped_mode_is_secure_when_everything_is_below_threshold():
    request = _req(alert_name_pattern=None, risk_threshold="High")
    runner = FakeZapRunner([([_alert("Missing Anti-clickjacking Header", risk="Medium")], {})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE


# --- fail-closed: timeout, crash, malformed/missing/stale report -----------

def test_timeout_is_inconclusive_never_secure():
    request = _req(max_attempts=1)
    runner = FakeZapRunner([(None, {"timed_out": True, "returncode": None})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE


def test_bounded_retry_stops_after_max_attempts_all_timing_out():
    request = _req(max_attempts=3, timeout_s=1.0)
    runner = FakeZapRunner([
        (None, {"timed_out": True, "returncode": None}),
        (None, {"timed_out": True, "returncode": None}),
        (None, {"timed_out": True, "returncode": None}),
    ])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE
    assert len(runner.calls) == 3


def test_bounded_retry_stops_as_soon_as_an_attempt_does_not_time_out():
    request = _req(max_attempts=5, alert_name_pattern=re.compile("SSTI"))
    runner = FakeZapRunner([
        (None, {"timed_out": True, "returncode": None}),
        ([], {}),
    ])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE
    assert len(runner.calls) == 2


def test_crash_with_no_report_file_is_inconclusive_never_secure():
    # Simulates a real crash (e.g. BindException, OOM): the process returns
    # non-zero and never writes a report at all.
    request = _req()
    runner = FakeZapRunner([(None, {"returncode": 1})])
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE
    assert verdict.outcome is not Verdict.CONFIRMED_SECURE


def test_malformed_report_json_is_inconclusive(tmp_path):
    request = _req(report_dir=str(tmp_path))
    inner = FakeZapRunner([([], {})])

    # After the (well-formed) fake report is written, corrupt it before the
    # wrapper reads it back, simulating a truncated/corrupted real report.
    # (A plain function, not an instance-attribute override, because Python
    # looks up `__call__` on the type for `runner(...)`, not the instance.)
    def corrupting_runner(argv, timeout_s):
        result = inner(argv, timeout_s)
        Path(tmp_path, "report.json").write_text("{not valid json")
        return result

    verdict = run_zap_whole_app_scan(request, runner=corrupting_runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE


def test_a_stale_report_from_a_previous_attempt_is_never_classified(tmp_path):
    # Pre-seed a report directory with a "vulnerable" report as if left over
    # from an earlier, unrelated run, then have the runner simulate a crash
    # (no new report written) on the only attempt. The wrapper must delete
    # the stale report before invoking the tool and must not fall back to
    # classifying stale data -- a crash is inconclusive, not "vulnerable
    # because an old report file happens to still be sitting there."
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    (report_dir / "report.json").write_text(
        json.dumps({"site": [{"alerts": [_alert("Server Side Template Injection", risk="High")]}]})
    )
    request = _req(report_dir=str(report_dir), alert_name_pattern=re.compile("SSTI"))
    runner = FakeZapRunner([(None, {"returncode": 1})])  # crash: no new report written
    verdict = run_zap_whole_app_scan(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE


# --- temp-dir ownership/cleanup ----------------------------------------------

def test_wrapper_created_zap_home_and_report_dir_are_cleaned_up_afterwards():
    request = _req()
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    argv, _ = runner.calls[0]
    zap_home = argv[argv.index("-dir") + 1]
    report_dir = runner.plans[0]["jobs"][-1]["parameters"]["reportDir"]
    assert not Path(zap_home).exists()
    assert not Path(report_dir).exists()


def test_caller_supplied_zap_home_and_report_dir_are_not_deleted(tmp_path):
    zap_home = tmp_path / "my-zap-home"
    zap_home.mkdir()
    report_dir = tmp_path / "my-reports"
    report_dir.mkdir()
    request = _req(zap_home_dir=str(zap_home), report_dir=str(report_dir))
    runner = FakeZapRunner([([], {})])
    run_zap_whole_app_scan(request, runner=runner)
    assert zap_home.exists()
    assert report_dir.exists()
