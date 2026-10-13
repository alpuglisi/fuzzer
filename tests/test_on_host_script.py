"""The on-host script and runbook exercise the shipped CLI, not the ML package
(CC-FUZZ-0055): any `fuzzlab.ml` reference — import, `python -c`, heredoc — would test a
path users never run. Plus the script's syntax, its asserting read-back, and the opt-in
holdout reveal."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "on_host_full_run.sh"
RUNBOOK = REPO / "docs" / "ON_HOST_RUNBOOK.md"


def test_no_direct_ml_package_use():
    for path in (SCRIPT, RUNBOOK):
        assert not re.search(r"fuzzlab\.ml\b", path.read_text()), path.name


def test_script_parses():
    if shutil.which("bash") is None:
        pytest.skip("no bash")
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_the_holdout_reveal_is_opt_in_and_the_budget_check_asserts():
    text = SCRIPT.read_text()
    guard = text.index('if [ -n "${REVEAL_HOLDOUT:-}" ]; then')
    block = text[guard:text.index("\nfi\n", guard)]
    assert text.count("fuzzlab reveal-holdout") == 1 and "fuzzlab reveal-holdout" in block
    assert "_check_sql auto.db \"$Q_BUDGET_APPLIED\" 1" in text
    assert "MIN(5, (SELECT value" in text


def test_check_sql_fails_on_a_mismatch(tmp_path):
    """The asserting read-back really fails on a mismatch — with a stand-in `sqlite3`
    that answers 1 (the on-host check needs only its exit status and comparison)."""
    if shutil.which("bash") is None:
        pytest.skip("no bash")
    body = SCRIPT.read_text()
    func = body[body.index("_check_sql() {"):body.index("}", body.index("_check_sql() {")) + 1]
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "sqlite3").write_text("#!/bin/sh\necho 1\n")
    (fake / "sqlite3").chmod(0o755)
    env = {"PATH": f"{fake}:/usr/bin:/bin"}
    ok = subprocess.run(["bash", "-c", f'{func}\n_check_sql x.db "SELECT 1;" 1'], env=env)
    bad = subprocess.run(["bash", "-c", f'{func}\n_check_sql x.db "SELECT 1;" 0'], env=env)
    assert ok.returncode == 0 and bad.returncode != 0
