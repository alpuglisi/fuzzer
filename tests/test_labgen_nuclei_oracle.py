"""Offline tests for `fuzzlab.labgen.nuclei_oracle` (generator-build-time
tool-oracle wrapper around Nuclei -- see docs/LAB_SEED_AUTHORING_PLAYBOOK.md
and docs/spikes/SPIKE-004-nuclei-vs-dvwa.md).

Every branch is exercised with an injected fake runner; no real `nuclei`
binary is needed here (see test_labgen_nuclei_oracle_integration.py for the
one skip-guarded real-binary test, per PA-0005).
"""

import json
import shutil

import pytest

from fuzzlab.labgen.nuclei_oracle import (
    NucleiRunResult,
    NucleiVerdict,
    PathTraversalOracleRequest,
    TraversalVulnClass,
    run_path_traversal_oracle,
)
from fuzzlab.labgen.oracle_wrapper import OracleSafetyError, ToolNotFoundError


def _ok_run(argv, stdout="", stderr="", returncode=0):
    return NucleiRunResult(argv=argv, returncode=returncode, stdout=stdout, stderr=stderr,
                            timed_out=False, duration_s=0.01)


def _timeout_run(argv):
    return NucleiRunResult(argv=argv, returncode=None, stdout="", stderr="",
                            timed_out=True, duration_s=999.0)


def _match_line(matched_at="http://127.0.0.1:8091/vulnerabilities/fi/index.php?page=../../../../etc/passwd"):
    return json.dumps({"template-id": "fuzzlab-path-traversal-etc-passwd", "matched-at": matched_at})


class FakeRunner:
    """A scripted, dependency-injected runner: returns queued results in
    order, and records every argv it was called with."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def __call__(self, argv, timeout_s):
        self.calls.append((list(argv), timeout_s))
        if not self._results:
            raise AssertionError("FakeRunner called more times than results were queued")
        return self._results.pop(0)


@pytest.fixture(autouse=True)
def _fake_nuclei_on_path(monkeypatch):
    """Every test in this file uses tool_path="/fake/nuclei" (or a custom
    explicit path) purely as an argv value -- no real binary is invoked
    (the runner is always a FakeRunner). Mirrors
    test_labgen_oracle_wrapper.py's `monkeypatch.setattr(shutil, "which", ...)`
    pattern so `locate_tool` resolves without touching the real filesystem/PATH.
    """
    monkeypatch.setattr(shutil, "which", lambda name: name if name.startswith("/") else None)


def _request(**overrides):
    defaults = dict(
        target_base_url="http://127.0.0.1:8091",
        endpoint_path="/vulnerabilities/fi/index.php",
        param_name="page",
        tool_path="/fake/nuclei",
    )
    defaults.update(overrides)
    return PathTraversalOracleRequest(**defaults)


# --- loopback safety (reused from oracle_wrapper, but must actually be wired in) --

@pytest.mark.parametrize("url", [
    "http://example.com",
    "http://10.0.0.5",
    "https://evil.test",
])
def test_run_path_traversal_oracle_refuses_non_loopback_target_without_invoking_runner(url):
    runner = FakeRunner([])
    with pytest.raises(OracleSafetyError):
        run_path_traversal_oracle(_request(target_base_url=url), runner=runner)
    assert runner.calls == []


# --- tool-not-found -----------------------------------------------------------

def test_run_path_traversal_oracle_raises_tool_not_found_for_missing_binary(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    runner = FakeRunner([])
    request = _request(tool_path="/definitely/does/not/exist/nuclei")
    with pytest.raises(ToolNotFoundError):
        run_path_traversal_oracle(request, runner=runner)
    assert runner.calls == []


# --- classification: the three outcomes ---------------------------------------

def test_confirmed_vulnerable_when_jsonl_output_has_a_match():
    runner = FakeRunner([_ok_run([], stdout=_match_line() + "\n")])
    verdict = run_path_traversal_oracle(_request(), runner=runner)
    assert verdict.outcome is NucleiVerdict.CONFIRMED_VULNERABLE
    assert verdict.vuln_class is TraversalVulnClass.PATH_TRAVERSAL
    assert "matched" in verdict.reason


def test_confirmed_secure_on_clean_scan_with_zero_matches_and_exit_zero():
    runner = FakeRunner([_ok_run([], stdout="", stderr="[INF] Scan completed in 5ms. No results found.\n")])
    verdict = run_path_traversal_oracle(_request(), runner=runner)
    assert verdict.outcome is NucleiVerdict.CONFIRMED_SECURE


def test_timeout_is_inconclusive_never_secure():
    runner = FakeRunner([_timeout_run([])])
    verdict = run_path_traversal_oracle(_request(), runner=runner)
    assert verdict.outcome is NucleiVerdict.INCONCLUSIVE
    assert "timeout" in verdict.reason


@pytest.mark.parametrize("stderr_line", [
    "[INF] Skipped 127.0.0.1:9999 from target list as found unresponsive permanently: ...",
    "dial tcp 127.0.0.1:9999: connect: connection refused",
    "context deadline exceeded",
    "no such host",
    "no address associated with hostname",
])
def test_host_unreachable_signal_is_inconclusive_never_secure(stderr_line):
    """BUG-0023: nuclei exits 0 with zero matches both for a clean scan AND
    for a target it never reached -- the wrapper must not conflate them."""
    runner = FakeRunner([_ok_run([], stdout="", stderr=stderr_line + "\n")])
    verdict = run_path_traversal_oracle(_request(), runner=runner)
    assert verdict.outcome is NucleiVerdict.INCONCLUSIVE
    assert "unreachable" in verdict.reason


def test_host_unreachable_signal_wins_even_if_a_match_somehow_also_appears():
    """Defense in depth: the unreachable check runs before the match check,
    so a contradictory run (which should never happen in practice) still
    fails closed rather than being reported as vulnerable."""
    runner = FakeRunner([_ok_run(
        [],
        stdout=_match_line() + "\n",
        stderr="found unresponsive permanently\n",
    )])
    verdict = run_path_traversal_oracle(_request(), runner=runner)
    assert verdict.outcome is NucleiVerdict.INCONCLUSIVE


def test_nonzero_exit_with_no_match_and_no_unreachable_signal_is_inconclusive():
    runner = FakeRunner([_ok_run([], stdout="", stderr="", returncode=1)])
    verdict = run_path_traversal_oracle(_request(), runner=runner)
    assert verdict.outcome is NucleiVerdict.INCONCLUSIVE
    assert "exited with status" in verdict.reason


def test_jsonl_parsing_ignores_non_json_noise_lines():
    stdout = "\n".join([
        "some banner line that is not json",
        "",
        _match_line(),
        "trailing garbage {not valid json",
    ])
    runner = FakeRunner([_ok_run([], stdout=stdout)])
    verdict = run_path_traversal_oracle(_request(), runner=runner)
    assert verdict.outcome is NucleiVerdict.CONFIRMED_VULNERABLE


# --- argv construction: scoping + the "never -silent" rule ---------------------

def test_argv_includes_declared_endpoint_and_param_as_template_variables():
    runner = FakeRunner([_ok_run([], stdout="")])
    run_path_traversal_oracle(_request(), runner=runner)
    (argv, timeout_s), = runner.calls
    assert "-var" in argv
    assert "endpoint_path=/vulnerabilities/fi/index.php" in argv
    assert "param_name=page" in argv


def test_argv_never_passes_silent():
    """BUG-0023's fix depends on nuclei's stderr diagnostics, which -silent
    suppresses -- this must never regress."""
    runner = FakeRunner([_ok_run([], stdout="")])
    run_path_traversal_oracle(_request(), runner=runner)
    (argv, _), = runner.calls
    assert "-silent" not in argv


def test_argv_includes_cookie_and_headers():
    runner = FakeRunner([_ok_run([], stdout="")])
    request = _request(cookie="security=low; PHPSESSID=abc", headers={"X-Test": "1"})
    run_path_traversal_oracle(request, runner=runner)
    (argv, _), = runner.calls
    assert "Cookie: security=low; PHPSESSID=abc" in argv
    assert "X-Test: 1" in argv


def test_argv_includes_extra_args():
    runner = FakeRunner([_ok_run([], stdout="")])
    request = _request(extra_args=["-rate-limit", "10"])
    run_path_traversal_oracle(request, runner=runner)
    (argv, _), = runner.calls
    assert argv[-2:] == ["-rate-limit", "10"]


def test_custom_template_path_is_passed_through():
    runner = FakeRunner([_ok_run([], stdout="")])
    request = _request(template_path="/custom/template.yaml")
    run_path_traversal_oracle(request, runner=runner)
    (argv, _), = runner.calls
    idx = argv.index("-t")
    assert argv[idx + 1] == "/custom/template.yaml"


# --- session refresh / bounded retry (same contract as oracle_wrapper) --------

def test_refresh_session_called_once_per_attempt_and_cookie_is_split_out():
    calls = {"n": 0}

    def refresh():
        calls["n"] += 1
        return {"Cookie": f"security=low; sid={calls['n']}"}

    runner = FakeRunner([_timeout_run([]), _ok_run([], stdout="")])
    request = _request(refresh_session=refresh, max_attempts=2, cookie="stale")
    verdict = run_path_traversal_oracle(request, runner=runner)
    assert verdict.outcome is NucleiVerdict.CONFIRMED_SECURE
    assert calls["n"] == 2
    (first_argv, _), (second_argv, _) = runner.calls
    assert "Cookie: security=low; sid=1" in first_argv
    assert "Cookie: security=low; sid=2" in second_argv


def test_max_attempts_bounds_total_calls_and_stops_on_first_non_timeout():
    runner = FakeRunner([_ok_run([], stdout="")])
    request = _request(max_attempts=5)
    run_path_traversal_oracle(request, runner=runner)
    assert len(runner.calls) == 1


def test_max_attempts_exhausted_all_timeouts_is_inconclusive():
    runner = FakeRunner([_timeout_run([]), _timeout_run([])])
    request = _request(max_attempts=2)
    verdict = run_path_traversal_oracle(request, runner=runner)
    assert verdict.outcome is NucleiVerdict.INCONCLUSIVE
    assert len(runner.calls) == 2


def test_max_attempts_less_than_one_is_clamped_to_one():
    runner = FakeRunner([_ok_run([], stdout="")])
    request = _request(max_attempts=0)
    run_path_traversal_oracle(request, runner=runner)
    assert len(runner.calls) == 1


# --- default template path -----------------------------------------------------

def test_default_template_path_points_at_the_bundled_template():
    from fuzzlab.labgen.nuclei_oracle import DEFAULT_PATH_TRAVERSAL_TEMPLATE
    assert str(DEFAULT_PATH_TRAVERSAL_TEMPLATE) == "lab/nuclei-templates/path-traversal-etc-passwd.yaml"


def test_bundled_template_file_exists_and_is_valid_yaml():
    import yaml
    from fuzzlab.labgen.nuclei_oracle import DEFAULT_PATH_TRAVERSAL_TEMPLATE
    with open(DEFAULT_PATH_TRAVERSAL_TEMPLATE) as fh:
        doc = yaml.safe_load(fh)
    assert doc["id"] == "fuzzlab-path-traversal-etc-passwd"
    assert doc["http"][0]["matchers-condition"] == "and"
