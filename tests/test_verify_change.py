"""The verification harness (`scripts/verify_change.py`) selects tests mechanically.

Its selection logic is exercised on synthetic repositories: a module change selects
exactly the tests that import it (directly, through a helper, from a function body, or
by a string module name), every whole-package guard is always added, changed tests and
helpers are added, a changed conftest selects everything, and files split into the
parallel and serial passes by the maintained list. A mixed guard file contributes only
its guard tests (PA-0403 corrected). One small end-to-end run proves the harness refuses
a dirty tree, verifies the committed HEAD in a detached worktree, counts outcomes,
writes per-file evidence in ``manifest.json`` and reuses it only for an identical key
(PA-0038 corrected), and removes its own worktree. The whole suite is never run here.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.package_guard


def _load():
    spec = importlib.util.spec_from_file_location("verify_change", ROOT / "scripts" / "verify_change.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_change"] = mod
    spec.loader.exec_module(mod)
    return mod


vc = _load()


def _write(root: Path, rel: str, body: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body))


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def synth(tmp_path):
    """A small repository shaped like this one."""
    r = tmp_path / "repo"
    _write(r, "fuzzlab/__init__.py")
    _write(r, "fuzzlab/a.py", "X = 1\n")
    _write(r, "fuzzlab/user_of_a.py", "from fuzzlab import a\n")
    _write(r, "fuzzlab/b/__init__.py")
    _write(r, "fuzzlab/b/c.py", "from . import d\n")
    _write(r, "fuzzlab/b/d.py", "Y = 2\n")
    _write(r, "fuzzlab/b/templates/page.j2", "hi\n")
    _write(r, "tests/__init__.py")
    _write(r, "tests/conftest.py")
    _write(r, "tests/_helper.py", "from fuzzlab.a import X\n")
    _write(r, "tests/test_direct.py", "import fuzzlab.a\ndef test_x():\n    assert fuzzlab.a.X\n")
    _write(r, "tests/test_from_pkg.py", "from fuzzlab.b import c\ndef test_c():\n    assert c\n")
    _write(r, "tests/test_via_helper.py", "from tests._helper import X\ndef test_h():\n    assert X\n")
    _write(r, "tests/test_relative_helper.py", "from ._helper import X\ndef test_r():\n    assert X\n")
    _write(r, "tests/test_lazy.py", "def test_lazy():\n    from fuzzlab.b.d import Y\n    assert Y\n")
    _write(r, "tests/test_string_ref.py",
           "import importlib\ndef test_s():\n    importlib.import_module('fuzzlab.b.d')\n")
    _write(r, "tests/test_path_ref.py", "P = 'fuzzlab/a.py'\ndef test_p():\n    assert P\n")
    _write(r, "tests/test_user_of_a.py", "from fuzzlab.user_of_a import a\ndef test_u():\n    assert a\n")
    _write(r, "tests/test_unrelated.py", "def test_nothing():\n    assert True\n")
    _write(r, "tests/test_ast_guard.py",
           "import ast\nfrom pathlib import Path\n"
           "def test_g():\n    for p in Path('fuzzlab').rglob('*.py'):\n        ast.parse(p.read_text())\n")
    _write(r, "tests/test_marked_guard.py",
           "import pytest\npytestmark = pytest.mark.package_guard\ndef test_m():\n    assert True\n")
    _write(r, "tests/test_mixed_guard.py", MIXED_GUARD)
    _write(r, "tests/test_live_boot_thing.py", "def test_lb():\n    assert True\n")
    return r


# A guard file that also holds behavioural tests. Its guard tests reach the
# source-reading call directly, through a helper, a module constant, a fixture and a
# class sibling; the behavioural ones do not, and fail if they are ever run as a guard.
MIXED_GUARD = """\
import ast
from pathlib import Path

import pytest

SOURCES = sorted(Path("fuzzlab").rglob("*.py"))


def _trees():
    return [ast.parse(p.read_text()) for p in SOURCES]


@pytest.fixture
def parsed():
    return [ast.parse(p.read_text()) for p in Path("fuzzlab").glob("*.py")]


def test_direct():
    assert ast.parse("x = 1")


def test_through_a_helper():
    assert isinstance(_trees(), list)


def test_through_a_constant():
    assert isinstance(SOURCES, list)


def test_through_a_fixture(parsed):
    assert isinstance(parsed, list)


def test_behaviour():
    assert False, "a behavioural test ran as a guard"


class TestGuards:
    def _helper(self):
        return ast.parse("y = 2")

    def test_through_a_sibling(self):
        assert self._helper()

    def test_plain(self):
        assert False, "a behavioural method ran as a guard"
"""
MIXED_NODES = ["test_direct", "test_through_a_helper", "test_through_a_constant",
               "test_through_a_fixture", "TestGuards::test_through_a_sibling"]


def _sel(root, pkg=(), tst=(), **kw):
    return vc.select_tests(root, list(pkg), list(tst), **kw)


GUARDS = {"tests/test_ast_guard.py", "tests/test_marked_guard.py", "tests/test_mixed_guard.py"}


def test_module_for_path(synth):
    assert vc.module_for_path(synth, "fuzzlab/a.py") == "fuzzlab.a"
    assert vc.module_for_path(synth, "fuzzlab/b/__init__.py") == "fuzzlab.b"
    # a data file belongs to its nearest enclosing package (the code that loads it)
    assert vc.module_for_path(synth, "fuzzlab/b/templates/page.j2") == "fuzzlab.b"
    # a deleted module still maps by shape
    assert vc.module_for_path(synth, "fuzzlab/b/gone.py") == "fuzzlab.b.gone"
    assert vc.module_for_path(synth, "docs/x.md") is None


def test_file_refs_resolves_every_import_form(synth):
    refs = vc.file_refs(synth / "tests/test_relative_helper.py", "tests/test_relative_helper.py", synth)
    assert "tests._helper" in refs.imports
    refs = vc.file_refs(synth / "tests/test_lazy.py", "tests/test_lazy.py", synth)
    assert "fuzzlab.b.d" in refs.imports
    refs = vc.file_refs(synth / "tests/test_from_pkg.py", "tests/test_from_pkg.py", synth)
    assert {"fuzzlab.b", "fuzzlab.b.c"} <= refs.imports
    refs = vc.file_refs(synth / "tests/test_string_ref.py", "tests/test_string_ref.py", synth)
    assert "fuzzlab.b.d" in refs.strings
    refs = vc.file_refs(synth / "tests/test_path_ref.py", "tests/test_path_ref.py", synth)
    assert "fuzzlab.a" in refs.strings


def test_a_module_change_selects_its_importers_and_every_guard(synth):
    sel = _sel(synth, ["fuzzlab/a.py"])
    assert set(sel.files) == {
        "tests/test_direct.py",
        "tests/test_via_helper.py",
        "tests/test_relative_helper.py",
        "tests/test_path_ref.py",
        *GUARDS,
    }
    # an import of a module that merely imports the changed one is not direct
    assert "tests/test_user_of_a.py" not in sel.files
    assert "tests/test_unrelated.py" not in sel.files


def test_transitive_mode_follows_package_importers(synth):
    sel = _sel(synth, ["fuzzlab/a.py"], transitive=True)
    assert "tests/test_user_of_a.py" in sel.files


def test_a_submodule_change_is_found_through_from_imports_and_strings(synth):
    sel = _sel(synth, ["fuzzlab/b/d.py"])
    assert set(sel.files) == {"tests/test_lazy.py", "tests/test_string_ref.py", *GUARDS}


def test_a_package_init_or_data_change_selects_everything_below_it(synth):
    for changed in ("fuzzlab/b/__init__.py", "fuzzlab/b/templates/page.j2"):
        sel = _sel(synth, [changed])
        assert {"tests/test_from_pkg.py", "tests/test_lazy.py", "tests/test_string_ref.py"} <= set(sel.files)
        assert "tests/test_direct.py" not in sel.files


def test_guards_are_always_selected_even_for_no_package_change(synth):
    assert set(_sel(synth).files) == GUARDS


def test_a_mixed_guard_file_contributes_only_its_guard_tests(synth):
    sel = _sel(synth, ["fuzzlab/a.py"])
    assert sel.nodes == {"tests/test_mixed_guard.py": MIXED_NODES}
    assert "tests/test_mixed_guard.py::test_behaviour" not in sel.targets(sel.files)
    # a single-purpose guard file and a marked guard still run whole
    assert "tests/test_ast_guard.py" in sel.targets(sel.files)
    assert "tests/test_marked_guard.py" in sel.targets(sel.files)
    # a changed guard file runs whole, and the opt-out restores whole files
    assert "tests/test_mixed_guard.py" not in _sel(synth, tst=["tests/test_mixed_guard.py"]).nodes
    assert _sel(synth, ["fuzzlab/a.py"], whole_guard_files=True).nodes == {}


def test_a_listed_guard_file_is_never_split(synth, monkeypatch):
    monkeypatch.setattr(vc, "EXPLICIT_GUARDS", ("tests/test_mixed_guard.py",))
    assert _sel(synth, ["fuzzlab/a.py"]).nodes == {}


def test_guard_nodes_falls_back_to_the_whole_file_when_unsure(tmp_path):
    p = tmp_path / "test_g.py"
    p.write_text("import ast\nfor x in [1]:\n    ast.parse('x')\n"
                 "def test_a():\n    pass\ndef test_b():\n    ast.parse('y')\n")
    assert vc.guard_nodes(p) is None  # module-level code reads source
    p.write_text("import ast\ndef test_a():\n    ast.parse('x')\n")
    assert vc.guard_nodes(p) is None  # every test is a guard
    p.write_text("def test_a(:\n")
    assert vc.guard_nodes(p) is None  # unparseable


def test_changed_tests_and_helpers_are_selected(synth):
    sel = _sel(synth, tst=["tests/test_unrelated.py"])
    assert "tests/test_unrelated.py" in sel.files
    sel = _sel(synth, tst=["tests/_helper.py"])
    assert {"tests/test_via_helper.py", "tests/test_relative_helper.py"} <= set(sel.files)
    # a deleted test file is not selected
    assert "tests/test_gone.py" not in _sel(synth, tst=["tests/test_gone.py"]).files


def test_a_conftest_change_selects_the_whole_suite(synth):
    sel = _sel(synth, tst=["tests/conftest.py"])
    assert sel.full
    assert set(sel.files) == set(vc.all_test_files(synth))


def test_guard_detection_kinds(synth, tmp_path):
    assert vc.guard_kind(synth / "tests/test_ast_guard.py") in ("ast.parse", "glob *.py")
    p0 = tmp_path / "test_parse_only.py"
    p0.write_text("import ast\nT = ast.parse('x = 1')\n")
    assert vc.guard_kind(p0) == "ast.parse"
    assert vc.guard_kind(synth / "tests/test_marked_guard.py") == "marker"
    assert vc.guard_kind(synth / "tests/test_direct.py") is None
    p = tmp_path / "test_flakes.py"
    p.write_text("from pyflakes.api import checkPath\n")
    assert vc.guard_kind(p) == "pyflakes"
    p.write_text("from pathlib import Path\nFILES = list(Path('x').glob('*.py'))\n")
    assert vc.guard_kind(p) == "glob *.py"
    p.write_text("from pathlib import Path\nFILES = list(Path('x').glob('*.json'))\n")
    assert vc.guard_kind(p) is None


def test_split_uses_the_maintained_list_and_the_name_rule(monkeypatch):
    files = ["tests/test_procutil.py", "tests/test_x_live_boot.py", "tests/test_lint.py"]
    monkeypatch.setattr(vc, "SERIAL_FILES", {"tests/test_procutil.py": "a measured reason"})
    monkeypatch.setattr(vc, "SERIAL_NAME_PARTS", ("live_boot",))
    parallel, serial = vc.split_passes(files)
    assert parallel == ["tests/test_lint.py"]
    assert serial == files[:2]


def test_everything_runs_in_parallel_unless_a_reason_is_recorded():
    """BUG-0142/0143: the former serial files were measured passing in parallel (two runs,
    0 failures). A file returns to the serial pass only with a stated reason."""
    files = ["tests/test_procutil.py", "tests/test_x_live_boot.py", "tests/test_y_multitarget.py"]
    assert vc.split_passes(files) == (files, [])
    for rel, reason in vc.SERIAL_FILES.items():
        assert len(reason.strip()) >= 20, f"{rel}: a serial file needs its measured reason"


def test_the_maintained_lists_name_real_files():
    for rel in list(vc.SERIAL_FILES) + list(vc.EXPLICIT_GUARDS):
        assert (ROOT / rel).is_file(), f"{rel} is listed in scripts/verify_change.py but does not exist"


def test_the_real_repository_guards_are_detected():
    guards = vc.package_guards(ROOT)
    for rel in ("tests/test_lint.py", "tests/test_requirements_traceability.py",
                "tests/test_pa_enforcement.py", "tests/test_shared_primitives.py",
                "tests/test_procutil_guard.py"):
        assert rel in guards


def test_parse_junit_counts_each_outcome(tmp_path):
    xml = tmp_path / "r.xml"
    xml.write_text(
        '<testsuites><testsuite>'
        '<testcase classname="a" name="p"/>'
        '<testcase classname="a" name="f"><failure message="x"/></testcase>'
        '<testcase classname="a" name="e"><error message="x"/></testcase>'
        '<testcase classname="a" name="s"><skipped type="pytest.skip" message="x"/></testcase>'
        '<testcase classname="a" name="x"><skipped type="pytest.xfail" message="x"/></testcase>'
        '</testsuite></testsuites>'
    )
    c = vc.parse_junit(xml)
    assert (c.passed, c.failed, c.errors, c.skipped, c.xfailed) == (1, 1, 1, 1, 1)
    assert not c.ok


def _commit_repo(root: Path) -> str:
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.invalid")
    _git(root, "config", "user.name", "t")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return _git(root, "rev-parse", "HEAD").strip()


def test_end_to_end_on_a_synthetic_repo(synth, tmp_path, capsys):
    (synth / "tests/conftest.py").write_text("")
    base = _commit_repo(synth)
    _write(synth, "fuzzlab/a.py", "X = 2\n")
    _write(synth, "tests/test_direct.py",
           "import fuzzlab.a\ndef test_x():\n    assert fuzzlab.a.X == 2\n"
           "def test_fails():\n    assert fuzzlab.a.X == 3\n")
    _git(synth, "commit", "-qam", "change a")

    # a dirty tracked file is refused before anything is created
    _write(synth, "fuzzlab/a.py", "X = 99\n")
    out = tmp_path / "out-dirty"
    assert vc.main(["--repo", str(synth), "--base", base, "--out", str(out), "--allow-concurrent"]) == 2
    assert not (out / "worktree").exists()
    _git(synth, "checkout", "-q", "--", "fuzzlab/a.py")

    # an uncommitted edit never reaches the verified tree: only the commit is tested
    _write(synth, "tests/test_untracked_new.py", "def test_u():\n    assert False\n")
    out = tmp_path / "out"
    rc = vc.main(["--repo", str(synth), "--base", base, "--out", str(out), "--allow-concurrent",
                  "--workers", "1", "--wait-other", "0"])
    printed = capsys.readouterr().out
    assert rc == 1, printed  # test_fails fails
    summary = json.loads((out / "summary.json").read_text())
    sel = json.loads((out / "selection.json").read_text())
    assert "tests/test_untracked_new.py" not in sel["parallel"] + sel["serial"]
    assert set(sel["parallel"] + sel["serial"]) == {
        "tests/test_direct.py", "tests/test_via_helper.py", "tests/test_relative_helper.py",
        "tests/test_path_ref.py", *GUARDS,
    }
    assert summary["files"] == 7
    assert summary["total"]["failed"] == 1  # the mixed file's behavioural tests did not run
    assert summary["total"]["passed"] == 11
    assert "TOTAL 7 file(s)" in printed
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["result"] == "fail"
    assert manifest["per_file"]["tests/test_direct.py"]["failed"] == 1
    assert manifest["per_file"]["tests/test_mixed_guard.py"]["passed"] == 5
    assert set(manifest["key"]) >= {"tree", "dependency_files", "python", "installed",
                                    "flags", "targets"}
    # its own worktree is gone, and git no longer lists it
    assert not (out / "worktree").exists()
    assert str(out / "worktree") not in _git(synth, "worktree", "list")
    # every pid it started was recorded
    assert (out / "pids.txt").read_text().split()


def test_passing_evidence_is_reused_only_for_an_identical_key(synth, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FUZZLAB_VERIFY_CACHE", str(tmp_path / "cache"))
    base = _commit_repo(synth)
    _write(synth, "fuzzlab/a.py", "X = 2\n")
    _git(synth, "commit", "-qam", "change a")
    argv = ["--repo", str(synth), "--base", base, "--allow-concurrent", "--workers", "1",
            "--wait-other", "0"]
    assert vc.main(argv + ["--out", str(tmp_path / "o1")]) == 0
    first = json.loads((tmp_path / "o1" / "manifest.json").read_text())
    assert first["result"] == "pass"
    capsys.readouterr()
    # same tree, same environment: the recorded evidence is reported, nothing re-runs
    assert vc.main(argv + ["--out", str(tmp_path / "o2"), "--reuse"]) == 0
    assert "reused qualified evidence" in capsys.readouterr().out
    assert not (tmp_path / "o2" / "parallel.xml").exists()
    # any change to the key (here a flag in the environment) runs again
    monkeypatch.setenv("FUZZLAB_EXTRA_FLAG", "1")
    assert vc.main(argv + ["--out", str(tmp_path / "o3"), "--reuse"]) == 0
    assert "reused" not in capsys.readouterr().out
    assert (tmp_path / "o3" / "parallel.xml").exists()
    # a failure is never cached for reuse
    _write(synth, "tests/test_direct.py", "def test_f():\n    assert False\n")
    _git(synth, "commit", "-qam", "break")
    assert vc.main(argv + ["--out", str(tmp_path / "o4"), "--reuse"]) == 1
    assert vc.main(argv + ["--out", str(tmp_path / "o5"), "--reuse"]) == 1


def test_junit_results_are_attributed_to_their_files(tmp_path):
    xml = tmp_path / "j.xml"
    xml.write_text(
        '<testsuites><testsuite>'
        '<testcase classname="tests.test_a" name="t1"/>'
        '<testcase classname="tests.test_a.TestK" name="t2"><failure/></testcase>'
        '<testcase classname="tests.test_ab" name="t3"><skipped/></testcase>'
        '<testcase classname="other" name="t4"/>'
        '</testsuite></testsuites>')
    got = {k: (c.passed, c.failed, c.skipped) for k, c in
           vc.junit_by_file(xml, ["tests/test_a.py", "tests/test_ab.py"]).items()}
    assert got == {"tests/test_a.py": (1, 1, 0), "tests/test_ab.py": (0, 0, 1), "?": (1, 0, 0)}


def _alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return state not in ("Z", "X")


def test_the_runner_stops_what_its_pytest_left_behind_in_its_own_group(tmp_path):
    runner = vc.Runner(tmp_path)
    pidfile = tmp_path / "bg.pid"
    # the leader exits at once and leaves a background child in its group
    rc = runner.run(["sh", "-c", f"sleep 60 & echo $! > {pidfile}; exit 0"], tmp_path,
                    dict(), tmp_path / "log", timeout=30)
    assert rc == 0
    bg = int(pidfile.read_text())
    assert not _alive(bg)
    assert vc.group_members(runner.children[0].pid) == []
    assert (tmp_path / "pids.txt").read_text().split() == [str(runner.children[0].pid)]


def test_the_runner_times_out_and_stops_only_its_own_group(tmp_path):
    runner = vc.Runner(tmp_path)
    rc = runner.run(["sleep", "60"], tmp_path, dict(), tmp_path / "log", timeout=1)
    assert rc == 124
    proc = runner.children[0]
    assert proc.returncode is not None  # reaped, after its group was swept
    assert not _alive(proc.pid)
