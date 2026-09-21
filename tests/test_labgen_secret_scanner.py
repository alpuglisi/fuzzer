"""Tests for the secret-scanner build gate (T-LAB0.6), the Gitleaks-based
counterpart to ``tests/test_labgen_gates.py``'s name-leak scanner tests.

Two groups, mirroring the plan's own split:

1. A **positive/negative fixture corpus** run against the real ``gitleaks``
   binary (skip-guarded to when it's actually on PATH -- PA-0005: a real code
   path that test doubles bypass everywhere must still have at least one test
   exercising the real implementation, skippable when it needs an environment
   feature). This is what actually establishes the no-silent-false-negative
   property the plan calls for -- code review of the wrapper is not enough.
2. **Fail-closed / crash-handling** tests using an injected fake ``Runner``
   (mirrors ``fuzzlab.labgen.oracle_wrapper``'s test convention), which need
   no real binary at all: a scanner crash must raise, never be silently
   treated as "clean".
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from fuzzlab.labgen.secret_scanner import (
    SecretScanError,
    SecretScanRunResult,
    ToolNotFoundError,
    default_runner,
    locate_gitleaks,
    scan_tree_for_secrets,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"

GITLEAKS_AVAILABLE = shutil.which("gitleaks") is not None

requires_gitleaks = pytest.mark.skipif(
    not GITLEAKS_AVAILABLE,
    reason="gitleaks binary not found on PATH -- real-binary tests are skip-guarded per PA-0005",
)


# --- Positive/negative fixture corpus (real gitleaks binary) ---------------
# Per docs/LAB_PHASE_0_PLAN.md T-LAB0.6: "a scanner with silent false
# negatives is worse than no scanner, and that property is only established
# by testing it against known-leaky inputs, not by code review."

# The should-flag fixtures below must be real-shaped enough to trigger
# Gitleaks' own detection rules (that's the whole point -- proving the gate
# catches an unmarked real-shaped secret) without ever containing the full
# matching string as one literal in this source file, which GitHub's own
# push-protection secret scanning would otherwise (correctly) flag on push,
# exactly like it flagged an earlier version of this fixture (see
# ERROR_LOG.md). Each secret is assembled at test-run time from fragments;
# Gitleaks scans the fully-assembled bytes written to a temp file, so its
# own detection is unaffected -- only the source text avoids the literal.
_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
_STRIPE_KEY = "sk_" + "live_" + "51H8xJ2eZvKYlo2CvAbCdEfGh1234567890ab"

SHOULD_FLAG = {
    # A real-shaped AWS access key with no fake/example marker anywhere.
    "should_flag/aws_key.php": f'<?php\n$aws_key = "{_AWS_KEY}";\n'.encode(),
    # A real-shaped Stripe live secret key, unmarked.
    "should_flag/stripe_key.py": f'STRIPE_SECRET = "{_STRIPE_KEY}"\n'.encode(),
    # A PEM private key block (Gitleaks' generic private-key rule).
    "should_flag/id_rsa": b"-----BEGIN RSA PRIVATE KEY-----\n"
    b"MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL\n"
    b"-----END RSA PRIVATE KEY-----\n",
}

SHOULD_NOT_FLAG = {
    # Seeded fake DB password the generator might legitimately emit as
    # vulnerable-code content (CWE-798 hardcoded-credential demonstration) --
    # marked FAKE per .gitleaks.toml's allowlist convention.
    "should_not_flag/config.php": b'<?php\n$db_password = "FAKE_hunter2_not_a_real_secret";\n',
    # AWS's own documented example access key -- ends in EXAMPLE, so it is
    # covered by the same allowlist without a vendor-specific carve-out.
    "should_not_flag/aws_docs_example.md": b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    # An explicitly-marked placeholder API key.
    "should_not_flag/settings.py": b'API_KEY = "PLACEHOLDER_do_not_use_in_prod"\n',
    # Ordinary application code with no secret-shaped content at all.
    "should_not_flag/handler.php": b"<?php\nfunction add($a, $b) { return $a + $b; }\n",
    # The out-of-band ground-truth file itself -- must never be flagged.
    "should_not_flag/labels.json": b'{"cases": []}\n',
    # An empty file.
    "should_not_flag/empty.txt": b"",
}


@requires_gitleaks
@pytest.mark.parametrize("path", sorted(SHOULD_FLAG))
def test_scanner_flags_known_leaky_secrets(path):
    result = scan_tree_for_secrets({path: SHOULD_FLAG[path]}, config_path=GITLEAKS_CONFIG)
    assert not result.passed, f"expected a leak in {path!r} but scan passed clean"
    assert result.leaks, f"expected at least one SecretLeak entry for {path!r}"


@requires_gitleaks
@pytest.mark.parametrize("path", sorted(SHOULD_NOT_FLAG))
def test_scanner_does_not_flag_known_clean_or_fake_content(path):
    result = scan_tree_for_secrets({path: SHOULD_NOT_FLAG[path]}, config_path=GITLEAKS_CONFIG)
    assert result.passed, f"unexpected leak(s) in {path!r}: {result.leaks}"
    assert list(result.leaks) == []


@requires_gitleaks
def test_scanner_reports_rule_id_and_file_for_a_real_hit():
    result = scan_tree_for_secrets(
        {"aws_key.php": SHOULD_FLAG["should_flag/aws_key.php"]}, config_path=GITLEAKS_CONFIG
    )
    assert not result.passed
    assert any(leak.rule_id == "aws-access-token" and leak.file.endswith("aws_key.php") for leak in result.leaks)


@requires_gitleaks
def test_scanner_clean_tree_passes():
    tree = {path: content for path, content in SHOULD_NOT_FLAG.items()}
    result = scan_tree_for_secrets(tree, config_path=GITLEAKS_CONFIG)
    assert result.passed
    assert bool(result) is True


@requires_gitleaks
def test_real_gitleaks_binary_is_locatable():
    """The one PA-0005-required test exercising the real, non-mocked path."""
    resolved = locate_gitleaks()
    assert resolved
    assert Path(resolved).name == "gitleaks" or "gitleaks" in resolved


# --- Fail-closed / crash-handling (injected fake runner, no real binary) ---


def _fake_runner_factory(returncode, report_content=None, write_report=True):
    """Build a fake Runner that mimics gitleaks' argv/report-file contract
    without shelling out to anything real."""

    def fake_runner(argv):
        argv = list(argv)
        report_path = Path(argv[argv.index("--report-path") + 1])
        if write_report:
            if report_content is None:
                report_path.write_text("[]" if returncode == 0 else "")
            else:
                report_path.write_text(report_content)
        return SecretScanRunResult(argv=argv, returncode=returncode, stdout="", stderr="", duration_s=0.0)

    return fake_runner


def test_tool_not_found_raises_typed_error_not_raw_filenotfound():
    with pytest.raises(ToolNotFoundError):
        scan_tree_for_secrets(
            {"x.php": b"<?php\n"},
            config_path=GITLEAKS_CONFIG,
            tool_path="/definitely/not/a/real/gitleaks/binary",
        )


def test_unexpected_exit_code_raises_secret_scan_error_not_treated_as_clean():
    fake = _fake_runner_factory(returncode=2)
    with pytest.raises(SecretScanError):
        scan_tree_for_secrets(
            {"x.php": b"<?php\n"},
            config_path=GITLEAKS_CONFIG,
            tool_path="/bin/true",
            runner=fake,
        )


def test_exit_1_with_empty_report_is_treated_as_a_crash_not_a_clean_pass():
    """A scanner malfunction that reports 'leaks found' but produces no
    findings must not silently pass the build."""
    fake = _fake_runner_factory(returncode=1, report_content="[]")
    with pytest.raises(SecretScanError):
        scan_tree_for_secrets(
            {"x.php": b"<?php\n"},
            config_path=GITLEAKS_CONFIG,
            tool_path="/bin/true",
            runner=fake,
        )


def test_malformed_report_json_raises_secret_scan_error():
    fake = _fake_runner_factory(returncode=1, report_content="{not valid json")
    with pytest.raises(SecretScanError):
        scan_tree_for_secrets(
            {"x.php": b"<?php\n"},
            config_path=GITLEAKS_CONFIG,
            tool_path="/bin/true",
            runner=fake,
        )


def test_report_missing_expected_field_raises_secret_scan_error():
    bad_report = json.dumps([{"RuleID": "aws-access-token"}])  # missing File/StartLine/Match/Description
    fake = _fake_runner_factory(returncode=1, report_content=bad_report)
    with pytest.raises(SecretScanError):
        scan_tree_for_secrets(
            {"x.php": b"<?php\n"},
            config_path=GITLEAKS_CONFIG,
            tool_path="/bin/true",
            runner=fake,
        )


def test_missing_config_raises_secret_scan_error():
    with pytest.raises(SecretScanError):
        scan_tree_for_secrets(
            {"x.php": b"<?php\n"},
            config_path="/no/such/.gitleaks.toml",
            tool_path="/bin/true",
            runner=_fake_runner_factory(returncode=0),
        )


def test_clean_exit_with_injected_runner_passes():
    fake = _fake_runner_factory(returncode=0)
    result = scan_tree_for_secrets(
        {"x.php": b"<?php\n"},
        config_path=GITLEAKS_CONFIG,
        tool_path="/bin/true",
        runner=fake,
    )
    assert result.passed
    assert list(result.leaks) == []


def test_leaky_exit_with_injected_runner_parses_reported_leak():
    report = json.dumps(
        [
            {
                "RuleID": "aws-access-token",
                "Description": "AWS",
                "File": "x.php",
                "StartLine": 3,
                "Match": _AWS_KEY,
            }
        ]
    )
    fake = _fake_runner_factory(returncode=1, report_content=report)
    result = scan_tree_for_secrets(
        {"x.php": b"<?php\n"},
        config_path=GITLEAKS_CONFIG,
        tool_path="/bin/true",
        runner=fake,
    )
    assert not result.passed
    assert len(result.leaks) == 1
    leak = result.leaks[0]
    assert leak.rule_id == "aws-access-token"
    assert leak.start_line == 3
    assert leak.match == _AWS_KEY


def test_locate_gitleaks_raises_typed_error_when_absent_from_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolNotFoundError):
        locate_gitleaks()


# --- Config sanity ----------------------------------------------------------


def test_gitleaks_config_file_exists_and_extends_default():
    assert GITLEAKS_CONFIG.is_file()
    text = GITLEAKS_CONFIG.read_text("utf-8")
    assert "useDefault = true" in text
    assert "[allowlist]" in text


@requires_gitleaks
def test_default_runner_is_wired_to_real_subprocess():
    """Smoke-check that `default_runner` really shells out (distinct from
    the injected-fake-runner tests above)."""
    result = scan_tree_for_secrets(
        {"clean.txt": b"nothing interesting here\n"},
        config_path=GITLEAKS_CONFIG,
        runner=default_runner,
    )
    assert result.passed
