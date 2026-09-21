"""Offline tests for `fuzzlab.labgen.identifier_sqli_oracle` (generator-
build-time custom differential-response prober for identifier/alias/
connector-position SQL injection -- see docs/LAB_IMPLEMENTATION_PLAN.md
sec 2.2 and the module's own docstring for the sqlmap spot-check findings
that motivated it).

Every classification branch is exercised with an injected fake HTTP runner;
no real network call or target is needed here (mirrors
tests/test_labgen_nuclei_oracle.py's FakeRunner convention).
"""

import pytest

from fuzzlab.labgen.identifier_sqli_oracle import (
    DialectNotImplementedError,
    DifferentialMode,
    HttpProbeResult,
    IdentifierSqliOracleRequest,
    IdentifierSqliVerdict,
    SqlDialect,
    run_identifier_sqli_oracle,
)
from fuzzlab.labgen.oracle_wrapper import OracleSafetyError


def _ok(url, body="", status_code=200, elapsed_s=0.01):
    return HttpProbeResult(url=url, status_code=status_code, body=body, timed_out=False, elapsed_s=elapsed_s)


def _error(url, status_code=500, body="DB ERROR", elapsed_s=0.01):
    return HttpProbeResult(url=url, status_code=status_code, body=body, timed_out=False, elapsed_s=elapsed_s)


def _timeout(url, elapsed_s=999.0):
    return HttpProbeResult(url=url, status_code=None, body="", timed_out=True, elapsed_s=elapsed_s)


class FakeHttpRunner:
    """A scripted, dependency-injected runner: returns queued results in
    order (one per `_fire` call: baseline, TRUE, FALSE, ...), and records
    every (url, headers, cookie, timeout_s) it was called with."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def __call__(self, url, headers, cookie, timeout_s):
        self.calls.append((url, dict(headers), cookie, timeout_s))
        if not self._results:
            raise AssertionError("FakeHttpRunner called more times than results were queued")
        result = self._results.pop(0)
        if callable(result):
            return result(url)
        return result


def _request(**overrides):
    defaults = dict(
        target_base_url="http://127.0.0.1:8199",
        endpoint_path="/order_by_vuln.php",
        param_name="sort",
        column_a="id",
        column_b="name",
    )
    defaults.update(overrides)
    return IdentifierSqliOracleRequest(**defaults)


# --- loopback safety (reused from oracle_wrapper) ---------------------------

@pytest.mark.parametrize("url", [
    "http://example.com",
    "http://10.0.0.5",
    "https://evil.test",
])
def test_run_identifier_sqli_oracle_refuses_non_loopback_target_without_invoking_runner(url):
    runner = FakeHttpRunner([])
    with pytest.raises(OracleSafetyError):
        run_identifier_sqli_oracle(_request(target_base_url=url), runner=runner)
    assert runner.calls == []


# --- dialect registry ---------------------------------------------------------

def test_unimplemented_dialect_raises_before_any_probe_is_fired():
    runner = FakeHttpRunner([])
    request = _request(dialect=SqlDialect.POSTGRESQL)
    with pytest.raises(DialectNotImplementedError):
        run_identifier_sqli_oracle(request, runner=runner)
    assert runner.calls == []


def test_sqlite_dialect_also_raises_not_implemented():
    runner = FakeHttpRunner([])
    request = _request(dialect=SqlDialect.SQLITE)
    with pytest.raises(DialectNotImplementedError):
        run_identifier_sqli_oracle(request, runner=runner)
    assert runner.calls == []


# --- response_diff mode: the three outcomes ---------------------------------

def test_confirmed_vulnerable_when_true_and_false_bodies_differ():
    """Synthetic data modeling the manually-confirmed vulnerable case from
    the spot-check: the CASE-WHEN substitution changes row order."""
    runner = FakeHttpRunner([
        _ok("baseline", body="1:charlie\n2:alpha\n3:bravo\n"),
        _ok("true", body="1:charlie\n2:alpha\n3:bravo\n"),   # TRUE -> id order
        _ok("false", body="2:alpha\n3:bravo\n1:charlie\n"),  # FALSE -> name order
    ])
    verdict = run_identifier_sqli_oracle(_request(), runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.CONFIRMED_VULNERABLE
    assert verdict.dialect is SqlDialect.MYSQL
    assert verdict.mode is DifferentialMode.RESPONSE_DIFF
    assert "different response bodies" in verdict.reason


def test_confirmed_secure_when_true_and_false_bodies_are_identical():
    """Synthetic data modeling a parameterized/allowlisted endpoint: the
    substitution reaches the endpoint (2xx) but never changes the query."""
    runner = FakeHttpRunner([
        _ok("baseline", body="1:charlie\n2:alpha\n3:bravo\n"),
        _ok("true", body="1:charlie\n2:alpha\n3:bravo\n"),
        _ok("false", body="1:charlie\n2:alpha\n3:bravo\n"),
    ])
    verdict = run_identifier_sqli_oracle(_request(), runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.CONFIRMED_SECURE
    assert "identical" in verdict.reason


def test_inconclusive_when_baseline_is_unhealthy():
    runner = FakeHttpRunner([
        _error("baseline", status_code=500),
        _ok("true", body="x"),
        _ok("false", body="x"),
    ])
    verdict = run_identifier_sqli_oracle(_request(), runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert "baseline" in verdict.reason


def test_inconclusive_when_both_true_and_false_probes_error_identically():
    """PA-0025: two identical-looking failures must never be read as
    'secure' -- this is the allowlist-rejection case from the spot-check
    (both probes get HTTP 400/500 from a strict identifier filter)."""
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _error("true", status_code=400, body="BAD COLUMN"),
        _error("false", status_code=400, body="BAD COLUMN"),
    ])
    verdict = run_identifier_sqli_oracle(_request(), runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert "unhealthy" in verdict.reason


def test_inconclusive_when_true_and_false_probes_disagree_on_health():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _ok("true", body="x"),
        _error("false", status_code=500),
    ])
    verdict = run_identifier_sqli_oracle(_request(), runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert "disagree" in verdict.reason


def test_timeout_on_a_differential_probe_is_inconclusive_never_secure():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _timeout("true"),
        _ok("false", body="x"),
    ])
    verdict = run_identifier_sqli_oracle(_request(), runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert "timed out" in verdict.reason


# --- timing_blind mode: the three outcomes ----------------------------------

def test_timing_blind_confirmed_vulnerable_when_true_sleeps_and_false_does_not():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok", elapsed_s=0.02),
        _ok("true", body="ok", elapsed_s=3.1),
        _ok("false", body="ok", elapsed_s=0.03),
    ])
    request = _request(mode=DifferentialMode.TIMING_BLIND, sleep_seconds=3.0, timing_threshold_s=2.5)
    verdict = run_identifier_sqli_oracle(request, runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.CONFIRMED_VULNERABLE
    assert verdict.mode is DifferentialMode.TIMING_BLIND
    assert "blind timing side channel" in verdict.reason


def test_timing_blind_confirmed_secure_when_neither_probe_sleeps():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok", elapsed_s=0.02),
        _ok("true", body="ok", elapsed_s=0.03),
        _ok("false", body="ok", elapsed_s=0.03),
    ])
    request = _request(mode=DifferentialMode.TIMING_BLIND, sleep_seconds=3.0, timing_threshold_s=2.5)
    verdict = run_identifier_sqli_oracle(request, runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.CONFIRMED_SECURE


def test_timing_blind_inconclusive_when_both_probes_sleep():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok", elapsed_s=0.02),
        _ok("true", body="ok", elapsed_s=3.2),
        _ok("false", body="ok", elapsed_s=3.1),
    ])
    request = _request(mode=DifferentialMode.TIMING_BLIND, sleep_seconds=3.0, timing_threshold_s=2.5)
    verdict = run_identifier_sqli_oracle(request, runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert "inconsistent" in verdict.reason


def test_timing_blind_inconclusive_on_client_side_timeout():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok", elapsed_s=0.02),
        _timeout("true"),
        _ok("false", body="ok", elapsed_s=0.03),
    ])
    request = _request(mode=DifferentialMode.TIMING_BLIND, sleep_seconds=3.0, timing_threshold_s=2.5)
    verdict = run_identifier_sqli_oracle(request, runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert "client timeout" in verdict.reason


def test_timing_blind_inconclusive_when_baseline_is_unhealthy():
    runner = FakeHttpRunner([
        _error("baseline", status_code=500),
        _ok("true", body="ok", elapsed_s=3.1),
        _ok("false", body="ok", elapsed_s=0.03),
    ])
    request = _request(mode=DifferentialMode.TIMING_BLIND, sleep_seconds=3.0, timing_threshold_s=2.5)
    verdict = run_identifier_sqli_oracle(request, runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert "baseline" in verdict.reason


# --- argv/url construction ----------------------------------------------------

def test_response_diff_url_contains_case_when_substitution():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _ok("true", body="a"),
        _ok("false", body="b"),
    ])
    run_identifier_sqli_oracle(_request(), runner=runner)
    baseline_call, true_call, false_call = runner.calls
    assert "sort=id" in baseline_call[0]
    assert "CASE" in true_call[0]
    assert "CASE" in false_call[0]


def test_timing_blind_url_contains_sleep_call():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _ok("true", body="a", elapsed_s=3.1),
        _ok("false", body="b", elapsed_s=0.01),
    ])
    request = _request(mode=DifferentialMode.TIMING_BLIND)
    run_identifier_sqli_oracle(request, runner=runner)
    _, true_call, false_call = runner.calls
    assert "SLEEP" in true_call[0]
    assert "SLEEP" in false_call[0]


def test_base_query_params_are_preserved_alongside_the_injected_param():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _ok("true", body="a"),
        _ok("false", body="b"),
    ])
    request = _request(base_query_params={"page": "2"})
    run_identifier_sqli_oracle(request, runner=runner)
    baseline_call, _, _ = runner.calls
    assert "page=2" in baseline_call[0]


def test_headers_and_cookie_are_passed_through():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _ok("true", body="a"),
        _ok("false", body="b"),
    ])
    request = _request(cookie="security=low", headers={"X-Test": "1"})
    run_identifier_sqli_oracle(request, runner=runner)
    baseline_call, _, _ = runner.calls
    _, headers, cookie, _ = baseline_call
    assert cookie == "security=low"
    assert headers["X-Test"] == "1"


# --- session refresh / bounded retry (same contract as oracle_wrapper) -----

def test_refresh_session_called_once_per_attempt_and_cookie_is_split_out():
    calls = {"n": 0}

    def refresh():
        calls["n"] += 1
        return {"Cookie": f"security=low; sid={calls['n']}"}

    runner = FakeHttpRunner([
        _timeout("baseline1"),
        _timeout("true1"),
        _timeout("false1"),
        _ok("baseline2", body="ok"),
        _ok("true2", body="a"),
        _ok("false2", body="a"),
    ])
    request = _request(refresh_session=refresh, max_attempts=2, cookie="stale")
    verdict = run_identifier_sqli_oracle(request, runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.CONFIRMED_SECURE
    assert calls["n"] == 2
    first_cookie = runner.calls[0][2]
    last_cookie = runner.calls[-1][2]
    assert first_cookie == "security=low; sid=1"
    assert last_cookie == "security=low; sid=2"


def test_max_attempts_bounds_total_calls_and_stops_on_first_non_timeout():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _ok("true", body="a"),
        _ok("false", body="a"),
    ])
    request = _request(max_attempts=5)
    run_identifier_sqli_oracle(request, runner=runner)
    assert len(runner.calls) == 3


def test_max_attempts_exhausted_all_timeouts_is_inconclusive():
    runner = FakeHttpRunner([
        _timeout("b1"), _timeout("t1"), _timeout("f1"),
        _timeout("b2"), _timeout("t2"), _timeout("f2"),
    ])
    request = _request(max_attempts=2)
    verdict = run_identifier_sqli_oracle(request, runner=runner)
    assert verdict.outcome is IdentifierSqliVerdict.INCONCLUSIVE
    assert len(runner.calls) == 6


def test_max_attempts_less_than_one_is_clamped_to_one():
    runner = FakeHttpRunner([
        _ok("baseline", body="ok"),
        _ok("true", body="a"),
        _ok("false", body="a"),
    ])
    request = _request(max_attempts=0)
    run_identifier_sqli_oracle(request, runner=runner)
    assert len(runner.calls) == 3
