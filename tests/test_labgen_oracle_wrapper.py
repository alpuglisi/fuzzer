"""Offline tests for `fuzzlab.labgen.oracle_wrapper` (generator-build-time
tool-oracle wrapper around sqlmap/commix/SSTImap -- see
docs/LAB_SEED_AUTHORING_PLAYBOOK.md and docs/spikes/SPIKE-001-sqlmap-vs-vapi.md /
SPIKE-002-commix-vs-dvwa.md / SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md).

Every branch is exercised with an injected fake runner; no real subprocess or
binary is needed here (see test_labgen_oracle_wrapper_integration.py for the
skip-guarded real-binary tests, per PA-0005).
"""

import shutil

import pytest

from fuzzlab.labgen.oracle_wrapper import (
    CommandInjectionOracleRequest,
    OracleRunResult,
    OracleSafetyError,
    ParamLocation,
    ServerSideTemplateInjectionOracleRequest,
    SqlInjectionOracleRequest,
    ToolNotFoundError,
    Verdict,
    VulnClass,
    assert_loopback,
    locate_tool,
    run_command_injection_oracle,
    run_oracle,
    run_server_side_template_injection_oracle,
    run_sql_injection_oracle,
)


def _ok_run(argv, stdout="", stderr="", returncode=0):
    return OracleRunResult(argv=argv, returncode=returncode, stdout=stdout, stderr=stderr,
                            timed_out=False, duration_s=0.01)


def _timeout_run(argv):
    return OracleRunResult(argv=argv, returncode=None, stdout="", stderr="",
                            timed_out=True, duration_s=999.0)


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


# --- loopback safety ---------------------------------------------------------

def test_assert_loopback_accepts_localhost_and_127_0_0_1_and_ipv6():
    assert_loopback("http://127.0.0.1:8080/login")
    assert_loopback("http://localhost/login")
    assert_loopback("http://[::1]:8080/login")


@pytest.mark.parametrize("url", [
    "http://example.com/login",
    "http://10.0.0.5/login",
    "https://evil.test/login",
    "http://127.0.0.1.evil.test/login",
])
def test_assert_loopback_rejects_non_loopback(url):
    with pytest.raises(OracleSafetyError):
        assert_loopback(url)


def test_assert_loopback_rejects_url_with_no_scheme_or_host():
    with pytest.raises(OracleSafetyError):
        assert_loopback("127.0.0.1/login")


def test_run_sql_injection_oracle_refuses_non_loopback_target_without_invoking_runner():
    request = SqlInjectionOracleRequest(target_url="http://example.com/login", param_name="username")
    runner = FakeRunner([])
    with pytest.raises(OracleSafetyError):
        run_sql_injection_oracle(request, runner=runner)
    assert runner.calls == []


def test_run_command_injection_oracle_refuses_non_loopback_target():
    request = CommandInjectionOracleRequest(target_url="http://example.com/ping", param_name="ip")
    runner = FakeRunner([])
    with pytest.raises(OracleSafetyError):
        run_command_injection_oracle(request, runner=runner)
    assert runner.calls == []


# --- tool location (BUG-0007-class: never a raw FileNotFoundError) ----------

def test_locate_tool_found_on_path(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name if name == "sqlmap" else None)
    assert locate_tool("sqlmap") == "/usr/bin/sqlmap"


def test_locate_tool_not_found_raises_actionable_error_not_file_not_found(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(ToolNotFoundError) as exc_info:
        locate_tool("sqlmap")
    assert "sqlmap" in str(exc_info.value)
    assert "PATH" in str(exc_info.value)


def test_locate_tool_uses_explicit_path(monkeypatch, tmp_path):
    fake = tmp_path / "sqlmap.py"
    fake.write_text("# not a real binary\n")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert locate_tool("sqlmap", explicit_path=str(fake)) == str(fake.resolve())


def test_run_sql_injection_oracle_missing_binary_raises_tool_not_found(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    with pytest.raises(ToolNotFoundError):
        run_sql_injection_oracle(request, runner=FakeRunner([]))


# --- --ignore-code construction (Spike 001) ---------------------------------

def test_sqlmap_ignore_code_added_when_secure_status_codes_given(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(
        target_url="http://127.0.0.1/login", param_name="username",
        secure_status_codes=[401, 403],
    )
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    run_sql_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert "--ignore-code" in argv
    assert argv[argv.index("--ignore-code") + 1] == "401,403"


def test_sqlmap_no_ignore_code_flag_when_no_secure_status_codes_given(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    run_sql_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert "--ignore-code" not in argv


# --- parameter scoping (Spike 002) ------------------------------------------

def test_sqlmap_argv_scopes_to_declared_parameter(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    run_sql_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("-p") + 1] == "username"


def test_commix_argv_scopes_to_declared_parameter_only(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/commix")
    request = CommandInjectionOracleRequest(target_url="http://127.0.0.1/ping", param_name="ip")
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    run_command_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("-p") + 1] == "ip"
    # never a blind sweep -- no other parameter name/flag sneaks in
    assert "--crawl" not in argv
    assert "--forms" not in argv


def test_commix_method_and_data_and_cookie_passed_through(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/commix")
    request = CommandInjectionOracleRequest(
        target_url="http://127.0.0.1/ping", param_name="ip", method="POST",
        data="ip=127.0.0.1&Submit=submit", cookie="PHPSESSID=abc123",
    )
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    run_command_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("--data") + 1] == "ip=127.0.0.1&Submit=submit"
    assert argv[argv.index("--cookie") + 1] == "PHPSESSID=abc123"


# --- session/token refresh + bounded retry (Spike 002, part 2) -------------

def test_refresh_session_called_and_cookie_split_out_of_headers(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/commix")
    calls = {"n": 0}

    def refresh():
        calls["n"] += 1
        return {"Cookie": f"session={calls['n']}", "X-Csrf-Token": f"tok{calls['n']}"}

    request = CommandInjectionOracleRequest(
        target_url="http://127.0.0.1/ping", param_name="ip", refresh_session=refresh,
    )
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    run_command_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert calls["n"] == 1
    assert argv[argv.index("--cookie") + 1] == "session=1"
    headers_value = argv[argv.index("--headers") + 1]
    assert "X-Csrf-Token: tok1" in headers_value
    assert "Cookie:" not in headers_value  # cookie goes through --cookie, not --headers


def test_bounded_retry_refreshes_session_each_attempt_and_stops_at_max_attempts(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/commix")
    calls = {"n": 0}

    def refresh():
        calls["n"] += 1
        return {"Cookie": f"session={calls['n']}"}

    request = CommandInjectionOracleRequest(
        target_url="http://127.0.0.1/ping", param_name="ip",
        refresh_session=refresh, max_attempts=3, timeout_s=1.0,
    )
    # All three attempts hang -- the wrapper must give up after exactly
    # max_attempts, never loop forever.
    runner = FakeRunner([_timeout_run([]), _timeout_run([]), _timeout_run([])])
    verdict = run_command_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE
    assert calls["n"] == 3
    assert len(runner.calls) == 3
    # every call used the same bounded per-attempt timeout
    assert all(timeout == 1.0 for _, timeout in runner.calls)


def test_bounded_retry_stops_as_soon_as_an_attempt_does_not_time_out(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/commix")
    request = CommandInjectionOracleRequest(
        target_url="http://127.0.0.1/ping", param_name="ip", max_attempts=5,
    )
    runner = FakeRunner([_timeout_run([]), _ok_run([], stdout="does not seem to be injectable")])
    verdict = run_command_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE
    assert len(runner.calls) == 2  # stopped after the second, non-timing-out attempt


# --- verdict classification: fail-closed on ambiguity -----------------------

def test_timeout_is_inconclusive_never_secure(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_timeout_run([])])
    verdict = run_sql_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE
    assert verdict.run.timed_out is True


def test_nonzero_exit_is_inconclusive(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run([], returncode=1, stderr="traceback etc")])
    verdict = run_sql_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE


def test_crash_reports_inconclusive_never_guessed_as_secure(monkeypatch):
    # A crash is just a nonzero exit with unrelated stderr -- must never be
    # silently treated as "secure" (fail-closed).
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run([], returncode=1, stderr="Traceback (most recent call last): ...")])
    verdict = run_sql_injection_oracle(request, runner=runner)
    assert verdict.outcome is not Verdict.CONFIRMED_SECURE
    assert verdict.outcome is Verdict.INCONCLUSIVE


def test_vulnerable_marker_yields_confirmed_vulnerable(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run([], stdout="sqlmap identified the following injection point(s)")])
    verdict = run_sql_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_VULNERABLE
    assert verdict.vuln_class is VulnClass.SQL_INJECTION
    assert verdict.confirmed_vulnerable is True


def test_secure_marker_yields_confirmed_secure(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/commix")
    request = CommandInjectionOracleRequest(target_url="http://127.0.0.1/ping", param_name="ip")
    runner = FakeRunner([_ok_run([], stdout="POST parameter 'ip' does not seem to be injectable")])
    verdict = run_command_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE
    assert verdict.confirmed_secure is True


def test_neither_marker_present_is_inconclusive(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run([], stdout="usage: sqlmap [options]")])
    verdict = run_sql_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE


def test_both_markers_present_is_inconclusive_not_a_guess(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run(
        [], stdout="identified the following injection point(s) ... does not seem to be injectable"
    )])
    verdict = run_sql_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE


# --- run_oracle() dispatch ----------------------------------------------------

def test_run_oracle_dispatches_sql_injection_request(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(target_url="http://127.0.0.1/login", param_name="username")
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    verdict = run_oracle(request, runner=runner)
    assert verdict.vuln_class is VulnClass.SQL_INJECTION


def test_run_oracle_dispatches_command_injection_request(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/commix")
    request = CommandInjectionOracleRequest(target_url="http://127.0.0.1/ping", param_name="ip")
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    verdict = run_oracle(request, runner=runner)
    assert verdict.vuln_class is VulnClass.COMMAND_INJECTION


def test_run_oracle_rejects_unknown_request_type():
    with pytest.raises(TypeError):
        run_oracle(object())


# --- param_location is accepted for all three values (query/body/header) ---

@pytest.mark.parametrize("location", [ParamLocation.QUERY, ParamLocation.BODY, ParamLocation.HEADER])
def test_param_location_accepted_without_error(monkeypatch, location):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sqlmap")
    request = SqlInjectionOracleRequest(
        target_url="http://127.0.0.1/login", param_name="username", param_location=location,
    )
    runner = FakeRunner([_ok_run([], stdout="does not seem to be injectable")])
    verdict = run_sql_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE


# --- SSTImap (Spike 003) -----------------------------------------------------

def test_run_ssti_oracle_refuses_non_loopback_target_without_invoking_runner():
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://example.com/", param_name="user",
    )
    runner = FakeRunner([])
    with pytest.raises(OracleSafetyError):
        run_server_side_template_injection_oracle(request, runner=runner)
    assert runner.calls == []


def test_sstimap_missing_binary_raises_tool_not_found(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test", param_name="user",
    )
    with pytest.raises(ToolNotFoundError):
        run_server_side_template_injection_oracle(request, runner=FakeRunner([]))


def test_sstimap_argv_marks_the_declared_query_parameter_and_scopes_to_query(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test&submit=Login", param_name="user",
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    # SSTImap has no -p flag: scoping is the marker embedded in the URL at
    # exactly the declared parameter's value, plus -P restricted to Query.
    marked_url = argv[argv.index("-u") + 1]
    assert "user=%2A" in marked_url or "user=*" in marked_url
    assert "submit=Login" in marked_url  # untouched -- never swept
    assert argv[argv.index("-P") + 1] == "Q"
    assert "-M" not in argv  # default marker '*' -- no need to pass -M


def test_sstimap_argv_scopes_to_body_when_param_location_is_body(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/", param_name="user",
        param_location=ParamLocation.BODY, method="POST", data="user=test&submit=Login",
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("-P") + 1] == "B"
    marked_data = argv[argv.index("-d") + 1]
    assert "user=%2A" in marked_data or "user=*" in marked_data
    assert "submit=Login" in marked_data
    assert argv[argv.index("-m") + 1] == "POST"


def test_sstimap_argv_scopes_to_header_when_param_location_is_header(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/", param_name="X-Custom",
        param_location=ParamLocation.HEADER, headers={"X-Custom": "test", "X-Other": "keep"},
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("-P") + 1] == "H"
    header_flags = [argv[i + 1] for i, a in enumerate(argv) if a == "-H"]
    assert "X-Custom: *" in header_flags
    assert "X-Other: keep" in header_flags  # untouched -- never swept


def test_sstimap_custom_marker_is_passed_via_dash_m(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test", param_name="user", marker="INJECT_HERE",
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("-M") + 1] == "INJECT_HERE"
    assert "user=INJECT_HERE" in argv[argv.index("-u") + 1]


def test_sstimap_cookie_is_split_into_stackable_dash_c_flags(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test", param_name="user",
        cookie="a=1; b=2",
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    cookie_flags = [argv[i + 1] for i, a in enumerate(argv) if a == "-C"]
    assert cookie_flags == ["a=1", "b=2"]


def test_sstimap_has_no_ignore_code_equivalent_field():
    # Spike 003: verified by reading SSTImap's source that it has no
    # sqlmap-style auth-status special-casing, so its request type carries no
    # secure_status_codes field at all (unlike SqlInjectionOracleRequest).
    assert not hasattr(ServerSideTemplateInjectionOracleRequest, "secure_status_codes")


def test_sstimap_vulnerable_marker_yields_confirmed_vulnerable(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test", param_name="user",
    )
    runner = FakeRunner([_ok_run(
        [], stdout="SSTImap identified the following injection point:\n\n  Query parameter: user"
    )])
    verdict = run_server_side_template_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_VULNERABLE
    assert verdict.vuln_class is VulnClass.SERVER_SIDE_TEMPLATE_INJECTION


def test_sstimap_secure_marker_yields_confirmed_secure(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test", param_name="user",
    )
    runner = FakeRunner([_ok_run([], stdout="Tested parameters appear to be not injectable.")])
    verdict = run_server_side_template_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.CONFIRMED_SECURE


def test_sstimap_timeout_is_inconclusive_never_secure(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test", param_name="user",
        max_attempts=2, timeout_s=1.0,
    )
    runner = FakeRunner([_timeout_run([]), _timeout_run([])])
    verdict = run_server_side_template_injection_oracle(request, runner=runner)
    assert verdict.outcome is Verdict.INCONCLUSIVE
    assert len(runner.calls) == 2  # bounded -- never more than max_attempts


def test_run_oracle_dispatches_ssti_request(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/?user=test", param_name="user",
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    verdict = run_oracle(request, runner=runner)
    assert verdict.vuln_class is VulnClass.SERVER_SIDE_TEMPLATE_INJECTION
