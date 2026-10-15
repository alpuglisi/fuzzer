"""The Stop hooks check what a change declares, not the words it uses (BUG-0157).

``.claude/hooks/check_bookkeeping.py`` replaced a keyword scan that blocked a README
line saying "The timeout setting is 15 seconds." and was satisfied by any touch of
``ERROR_LOG.md``. It now requires ``Change-Type:`` and ``Risk:`` trailers on unpushed
commits, an ``ERROR_LOG.md`` entry for a declared defect, and one for a changed bug or
spike record. ``.claude/hooks/check-corpus-cwe-coverage.sh`` no longer imposes the
two-unique-CWE quota (PA-0033 replaced): independent examples may share a CWE; an entry
needs a well-formed mapping, and the owner's five-pairs-per-class floor stays.

Each hook runs for real against a throwaway git repository with a bare ``origin``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# The hooks live outside the package and tests, so no import selects this file: it is
# declared a guard and always runs.
pytestmark = pytest.mark.package_guard
BOOKKEEPING = ROOT / ".claude" / "hooks" / "check_bookkeeping.py"
CWE_HOOK = ROOT / ".claude" / "hooks" / "check-corpus-cwe-coverage.sh"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


@pytest.fixture
def repo(tmp_path):
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    _git(work, "config", "user.email", "t@t")
    _git(work, "config", "user.name", "t")
    _git(work, "checkout", "-q", "-b", "main")
    (work / "ERROR_LOG.md").write_text("# Error log\n")
    (work / "README.md").write_text("# r\n")
    _git(work, "add", ".")
    _git(work, "commit", "-qm", "base\n\nChange-Type: docs\nRisk: low")
    _git(work, "push", "-q", "origin", "main")
    return work


def commit(repo: Path, files: dict[str, str], message: str) -> None:
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", message)


def run_hook(cmd: list[str], repo: Path, payload: dict | None = None) -> tuple[int, str]:
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(cmd, cwd=repo, input=json.dumps(payload or {}), capture_output=True,
                          text=True, env=env, timeout=60)
    return proc.returncode, proc.stderr


def bookkeeping(repo: Path, payload: dict | None = None) -> tuple[int, str]:
    return run_hook([sys.executable, str(BOOKKEEPING)], repo, payload)


# ------------------------------------------------------------------ bookkeeping


def test_a_benign_sentence_with_an_incident_word_is_not_an_incident(repo):
    """The proposal's negative control: the old hook blocked this with exit 2."""
    commit(repo, {"README.md": "The timeout setting is 15 seconds.\n"},
           "docs: timeout\n\nChange-Type: docs\nRisk: low")
    assert bookkeeping(repo) == (0, "")


def test_a_commit_without_its_declared_type_and_risk_is_asked_for_them(repo):
    commit(repo, {"a.py": "x = 1\n"}, "add a")
    code, err = bookkeeping(repo)
    assert code == 2 and "Change-Type:" in err and "Risk:" in err
    commit(repo, {"b.py": "y = 1\n"}, "add b\n\nChange-Type: guess\nRisk: low")
    code, err = bookkeeping(repo)
    assert code == 2 and "got guess" in err


def test_trailers_outside_the_final_paragraph_do_not_count(repo):
    commit(repo, {"a.py": "x = 1\n"},
           "add a\n\nChange-Type: feature\nRisk: low\n\nCo-Authored-By: x <x@x>")
    code, err = bookkeeping(repo)
    assert code == 2 and "final paragraph" in err


def test_a_declared_defect_needs_its_error_log_entry(repo):
    commit(repo, {"a.py": "x = 2\n"}, "fix a\n\nChange-Type: defect\nRisk: medium")
    code, err = bookkeeping(repo)
    assert code == 2 and "Change-Type: defect" in err
    commit(repo, {"ERROR_LOG.md": "# Error log\n- a.py: x was 1\n"},
           "log\n\nChange-Type: docs\nRisk: low")
    assert bookkeeping(repo) == (0, "")


def test_a_bug_record_needs_its_error_log_entry_even_uncommitted(repo):
    (repo / "docs" / "bugs").mkdir(parents=True)
    (repo / "docs" / "bugs" / "BUG-0001-x.md").write_text("# BUG-0001\n")
    code, err = bookkeeping(repo)
    assert code == 2 and "BUG-0001-x.md" in err
    (repo / "ERROR_LOG.md").write_text("# Error log\n- BUG-0001\n")
    assert bookkeeping(repo) == (0, "")


def test_pushed_history_is_not_rechecked_and_the_hook_never_loops(repo):
    commit(repo, {"a.py": "x = 1\n"}, "no trailers")
    assert bookkeeping(repo, {"stop_hook_active": True}) == (0, "")
    _git(repo, "push", "-q", "origin", "main")
    assert bookkeeping(repo) == (0, "")


def test_outside_a_checkout_the_hook_does_nothing(tmp_path):
    assert bookkeeping(tmp_path) == (0, "")


# ------------------------------------------------------------------ CWE corpus


def _entry(name: str, role: str, unique: list[str], shared: list[str] | None = None) -> str:
    lines = [f"- file: {name}", f"  role: {role}", f"  cwe_unique: {json.dumps(unique)}"]
    if shared is not None:
        lines.append(f"  cwe_shared: {json.dumps(shared)}")
    return "\n".join(lines)


def _manifest(entries: list[str]) -> str:
    return "\n".join(entries) + "\n"


def _cell(n_vuln: int = 5, n_idio: int = 5, unique=("CWE-89",)) -> str:
    entries = [_entry(f"vulnerable-{i}.php", "vulnerable", list(unique), ["CWE-20"])
               for i in range(n_vuln)]
    entries += [_entry(f"idiomatic-{i}.php", "idiomatic", list(unique)) for i in range(n_idio)]
    return _manifest(entries)


MANIFEST = "docs/research/corpus-examples/sqli/php/manifest.yaml"


def cwe_hook(repo: Path) -> tuple[int, str]:
    pytest.importorskip("yaml")
    return run_hook(["bash", str(CWE_HOOK)], repo)


def test_examples_may_share_one_accurate_cwe(repo):
    """Under the replaced PA-0033 quota, ten entries sharing CWE-89 were all rejected."""
    commit(repo, {MANIFEST: _cell()}, "corpus\n\nChange-Type: feature\nRisk: low")
    assert cwe_hook(repo) == (0, "")


@pytest.mark.parametrize("unique,needle", [
    ([], "has no CWE mapping"),
    (["SQLi"], "malformed CWE id"),
    (["CWE-89", "CWE-89"], "twice"),
])
def test_a_missing_or_malformed_mapping_is_flagged(repo, unique, needle):
    entries = [_entry("bad.php", "vulnerable", unique)]
    entries += [_entry(f"v{i}.php", "vulnerable", ["CWE-89"]) for i in range(5)]
    entries += [_entry(f"i{i}.php", "idiomatic", ["CWE-89"]) for i in range(5)]
    commit(repo, {MANIFEST: _manifest(entries)}, "corpus\n\nChange-Type: feature\nRisk: low")
    code, err = cwe_hook(repo)
    assert code == 2 and needle in err


def test_the_owner_requested_pairs_floor_stays(repo):
    commit(repo, {MANIFEST: _cell(n_vuln=5, n_idio=4)}, "corpus\n\nChange-Type: feature\nRisk: low")
    code, err = cwe_hook(repo)
    assert code == 2 and ">= 5 of EACH" in err


# ------------------------------------------------------------------------ wiring


def test_the_repository_stop_hooks_are_the_declared_ones():
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
    commands = [h["command"] for block in settings["hooks"]["Stop"] for h in block["hooks"]]
    assert any("check_bookkeeping.py" in c for c in commands)
    assert any("check-corpus-cwe-coverage.sh" in c for c in commands)
    assert not any("check-error-log-bookkeeping.sh" in c for c in commands)
    assert not (ROOT / ".claude" / "hooks" / "check-error-log-bookkeeping.sh").exists()
