"""The built package ships every tracked file, and nothing it must not (BUG-0068,
FR-CORE-22, PA-0070).

Development runs from an editable install, which reads files straight from the source
tree — so a package-data rule that misses files is invisible until someone installs a
real build. These tests build the package for real (setuptools `build_py`, `sdist`, and
the wheel where this environment can build one) from a copy of the **tracked** tree and
compare the built file set with the source.

The wheel: Debian's patched setuptools raises ``AttributeError: install_layout`` for
``bdist_wheel`` (an environment bug, ERROR_LOG); that test then skips with the reason,
and ``FUZZLAB_REQUIRE_WHEEL=1`` turns the skip into a failure (PA-0065(2)).
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PYPROJECT = REPO / "pyproject.toml"
SECRETISH = (".env", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "*id_rsa*",
             "*.db", "*.sqlite*")
#: Tracked files that legitimately match a secret-ish pattern (reason required).
SECRETISH_ALLOWED = {
    "fuzzlab/tools/data/php_indicators.db": "the packaged indicator database (build-db)",
}
EXECUTABLES = ("bin/rails", "artisan")


def _tracked() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "fuzzlab"], cwd=REPO, capture_output=True,
                             text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [p for p in out.splitlines() if "__pycache__" not in p]


def _deny() -> list[str]:
    cfg = tomllib.loads(PYPROJECT.read_text())
    return cfg["tool"]["setuptools"]["exclude-package-data"]["*"]


def _denied(rel_in_pkg: str, patterns) -> bool:
    return any(fnmatch.fnmatch(rel_in_pkg, p) or fnmatch.fnmatch(Path(rel_in_pkg).name, p)
               for p in patterns)


def _copy(tmp: Path, files, pyproject_text: str | None = None) -> Path:
    src = tmp / "src"
    for rel in files:
        dst = src / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst)
    (src / "pyproject.toml").write_text(pyproject_text or PYPROJECT.read_text())
    shutil.copy2(REPO / "README.md", src / "README.md")
    return src


def _setup(src: Path, *args: str) -> subprocess.CompletedProcess:
    code = ("import sys, setuptools; sys.argv = ['setup.py', '-q', *sys.argv[1:]]; "
            "setuptools.setup()")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-c", code, *args], cwd=src, env=env,
                          capture_output=True, text=True, timeout=600)


def build_py(src: Path) -> Path:
    out = src / "out"
    proc = _setup(src, "build_py", "--build-lib", str(out))
    assert proc.returncode == 0, proc.stderr[-2000:]
    return out


def _files(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


@pytest.fixture(scope="module")
def tracked():
    return _tracked()


@pytest.fixture(scope="module")
def built(tmp_path_factory, tracked):
    src = _copy(tmp_path_factory.mktemp("pkg"), tracked)
    return build_py(src)


def test_the_built_package_ships_every_tracked_file(built, tracked):
    files = {f for f in _files(built) if f.startswith("fuzzlab/")}
    assert files == set(tracked)
    non_py = [f for f in tracked if not f.endswith(".py")]
    assert len(non_py) >= 485                     # BUG-0068: 87 of 485 shipped before
    for must in ("fuzzlab/web/templates/sections/ml.html", "fuzzlab/web/static/js/ml.js",
                 "fuzzlab/tools/data/php_indicators.db"):
        assert must in files
    assert any(Path(f).name.startswith(".") for f in files)       # dotfiles ship too


def test_executable_bits_survive_the_build(built, tracked):
    for rel in (f for f in tracked if f.endswith(EXECUTABLES)):
        if os.access(REPO / rel, os.X_OK):
            assert os.access(built / rel, os.X_OK), rel


def test_the_deny_list_matches_no_tracked_file(tracked):
    """The converse: an over-broad exclusion would silently stop shipping a needed file
    while the equality test above still passed (it would then fail — but say why)."""
    deny = _deny()
    hits = [f for f in tracked if _denied(f[len("fuzzlab/"):], deny)]
    assert hits == []


def test_planted_secrets_and_junk_are_never_shipped(tmp_path, tracked):
    src = _copy(tmp_path, tracked)
    static = src / "fuzzlab" / "web" / "static"
    planted = [".env", "x.pem", "k.key", "s.sqlite", ".DS_Store", "a.swp", "b~",
               ".env.local", ".env.staging", "id_rsa", "c.p12"]
    for name in planted + [".env.example"]:
        (static / name).write_text("planted")
    (src / "fuzzlab" / ".env").write_text("planted")             # at a package root too
    files = _files(build_py(src))
    for name in planted:
        assert f"fuzzlab/web/static/{name}" not in files, name
    assert "fuzzlab/.env" not in files
    assert "fuzzlab/web/static/.env.example" in files            # not over-broad


def test_no_untracked_store_or_secret_under_the_package(tracked):
    """A working-tree build packages whatever sits under `fuzzlab/` — ignored files
    included — and `*.db` / every `.env` variant cannot all be denied by setuptools. So
    no untracked store or secret-ish file may be there (release builds come from a clean
    checkout; this catches the development case)."""
    known = set(tracked)
    stray = []
    for root, dirs, names in os.walk(REPO / "fuzzlab"):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in names:
            rel = str((Path(root) / name).relative_to(REPO))
            if rel in known or rel in SECRETISH_ALLOWED:
                continue
            if name.endswith((".example", ".sample")):
                continue
            if any(fnmatch.fnmatch(name, p) for p in SECRETISH) or name.startswith(".env"):
                stray.append(rel)
    assert stray == []


def test_sdist_ships_every_tracked_file_with_modes(tmp_path, tracked):
    src = _copy(tmp_path, tracked)
    proc = _setup(src, "sdist", "-d", str(src / "dist"), "--formats=gztar")
    assert proc.returncode == 0, proc.stderr[-2000:]
    (archive,) = (src / "dist").glob("*.tar.gz")
    with tarfile.open(archive) as tar:
        members = {m.name.split("/", 1)[1]: m for m in tar.getmembers() if "/" in m.name}
    assert set(tracked) <= set(members)
    for rel in (f for f in tracked if f.endswith(EXECUTABLES)):
        if os.access(REPO / rel, os.X_OK):
            assert members[rel].mode & 0o111, rel


def test_the_wheel_ships_every_tracked_file(tmp_path, tracked):
    src = _copy(tmp_path, tracked)
    proc = _setup(src, "bdist_wheel", "-d", str(src / "dist"))
    if proc.returncode != 0:
        reason = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "failed"
        if "install_layout" in proc.stderr and not os.environ.get("FUZZLAB_REQUIRE_WHEEL"):
            pytest.skip(f"bdist_wheel unavailable here (Debian setuptools bug): {reason}")
        pytest.fail(f"bdist_wheel failed: {reason}")
    (wheel,) = (src / "dist").glob("*.whl")
    with zipfile.ZipFile(wheel) as zf:
        names = {n for n in zf.namelist() if n.startswith("fuzzlab/")}
        assert names == set(tracked)
        for rel in (f for f in tracked if f.endswith(EXECUTABLES)):
            if os.access(REPO / rel, os.X_OK):
                assert (zf.getinfo(rel).external_attr >> 16) & 0o111, rel


def no_ml_pyproject() -> str:
    """The FR-ML-6 no-ML switch, both lines (the recursive data rule would otherwise
    ship `fuzzlab/ml/*.py` as data of the parent package)."""
    text = PYPROJECT.read_text()
    text = text.replace('include = ["fuzzlab*"]',
                        'include = ["fuzzlab*"]\nexclude = ["fuzzlab.ml*"]', 1)
    return text.replace('[tool.setuptools.exclude-package-data]\n',
                        '[tool.setuptools.exclude-package-data]\n"fuzzlab" = ["ml/*"]\n', 1)


def build_no_ml(tmp: Path, tracked) -> Path:
    out = build_py(_copy(tmp, tracked, no_ml_pyproject()))
    built = _files(out)
    assert not [f for f in built if f.startswith("fuzzlab/ml/")]      # non-vacuous
    assert "fuzzlab/plugins/optional.py" in built and "fuzzlab/web/app.py" in built
    return out


def test_the_no_ml_switch_removes_ml_and_only_ml(tmp_path, tracked):
    out = build_no_ml(tmp_path, tracked)
    expected = {f for f in tracked if not f.startswith("fuzzlab/ml/")}
    assert {f for f in _files(out) if f.startswith("fuzzlab/")} == expected
