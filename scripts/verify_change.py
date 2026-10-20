#!/usr/bin/env python3
"""Verify a committed change the way this project has learned it must be verified.

Usage::

    scripts/verify_change.py --base <ref>          # tests selected for base..HEAD
    scripts/verify_change.py --full                # the whole suite, split the same way
    scripts/verify_change.py --base <ref> --list-only   # print the selection, run nothing

What it does (see ``docs/MULTI_AGENT_ORCHESTRATION.md`` section 2 and ``CLAUDE.md``):

1. Refuses a dirty tree (tracked changes), then checks the **committed** ``HEAD`` out
   into a fresh detached ``git worktree``. A tree caught mid-edit has produced false
   "flaky" failures here before; untracked files are reported, never verified.
2. Builds the test list mechanically, never by hand:

   a. every ``fuzzlab`` module in ``git diff --name-only <base>..HEAD -- fuzzlab``,
      and every test file that imports one of them -- found by AST import analysis
      (absolute and relative imports, imports inside functions, imports reached
      through ``tests/_*.py`` helpers, and module names or paths written as string
      constants, e.g. ``importlib.import_module`` or ``python -m``);
   b. every whole-package guard (lint, traceability, AST scans). They import nothing
      they check, so an import-based list misses them. Detected by the
      ``package_guard`` marker, by an AST scan for ``ast.parse`` / ``pyflakes`` /
      globbing ``*.py`` files, and by the maintained ``EXPLICIT_GUARDS`` list;
   c. every changed test file; a changed helper adds the tests that import it, and a
      changed ``conftest.py`` selects the whole suite.

3. Splits the list into a parallel pass (``pytest -n <workers> --dist loadfile``) and a
   serial pass (only files listed in ``SERIAL_FILES`` with a measured reason; empty
   since BUG-0142/BUG-0143, when every file was shown to pass in parallel).
4. Runs the passes one pytest process at a time, with ``FUZZLAB_REQUIRE_BROWSER``,
   ``FUZZLAB_REQUIRE_LINT`` and ``FUZZLAB_REQUIRE_NETNS`` set, after waiting for any
   other pytest on the host to finish (concurrent load has produced false failures).
   Each pass's pytest controller also takes the host pytest lock that every session of
   the test tree takes (``tests/_pytest_lock.py``, BUG-0532; its xdist workers do not),
   waiting for it as long as ``--wait-other``. This script never holds that lock itself,
   so it cannot deadlock against its child.
5. Prints the file count and passed / failed / skipped / xfailed per pass and in total;
   exits non-zero on any failure.
6. Never kills by name or pattern: it records the pid of every pytest it starts (each
   in its own session), stops only those process groups, and removes only its own
   worktree.

Standard library only. Lab-only project: this runs the offline test suite; it sends
no traffic anywhere.
"""

from __future__ import annotations

import argparse
import ast
import fcntl
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE = "fuzzlab"
TESTS_DIR = "tests"

# Whole-package guards that the AST detector below would not recognise on its own
# (they read docs or files without ``ast.parse`` / pyflakes / a ``*.py`` glob).
# Keep this list current: a new guard either carries the ``package_guard`` marker or
# is listed here.
EXPLICIT_GUARDS: tuple[str, ...] = (
    "tests/test_lint.py",
    "tests/test_requirements_traceability.py",
    "tests/test_pa_enforcement.py",
    "tests/test_shared_primitives.py",
    "tests/test_verify_change.py",
    "tests/test_procutil_guard.py",
    "tests/test_no_wall_clock_ratio.py",
    "tests/test_loopback_listeners.py",
    "tests/test_browser_scope.py",
    "tests/test_guarded_navigation.py",
    "tests/test_navigation_aborts.py",
    "tests/test_session_origin_scope.py",
    "tests/test_sender_conformance.py",
    "tests/test_ml_import_guard.py",
    "tests/test_no_ml.py",
    "tests/test_packaging.py",
)

# Files that must run in the serial pass, each with its reason (BUG-0142/BUG-0143).
# Empty by measurement: the 105 files once kept serial (live boots, multitarget labs,
# procutil, browser suites) passed in parallel (-n 3 --dist loadfile) on 6e44a3f, in
# two consecutive runs: 1716 passed, 0 failed, about 14 min 20 s each (38 min 45 s
# serially). Two concurrency defects found on the way are fixed: a live boot could run
# against another test's server (BUG-0143), and a test's exact count raced the
# supervisor (BUG-0144). The last intermittent failure under full parallel load,
# test_multitarget_category4's connection reset, was reproduced deterministically and
# fixed in the code, not by a serial pass (BUG-0147).
#
# A file goes back on this list only with its reason, and only after a reproduced
# failure under parallel load that cannot be fixed in the test or the code
# (PA-0149(2)). "It failed once under load" is not a reason.
SERIAL_FILES: dict[str, str] = {}
SERIAL_NAME_PARTS: tuple[str, ...] = ()

REQUIRE_FLAGS = {
    "FUZZLAB_REQUIRE_BROWSER": "1",
    "FUZZLAB_REQUIRE_LINT": "1",
    "FUZZLAB_REQUIRE_NETNS": "1",
}
#: How long a child pytest waits for the host pytest lock (tests/_pytest_lock.py).
PYTEST_LOCK_WAIT = "FUZZLAB_PYTEST_LOCK_WAIT"
GUARD_MARKER = "package_guard"
CONFTEST_NAMES = ("conftest.py",)


# --------------------------------------------------------------------------- git


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def dirty_tracked(repo: Path) -> list[str]:
    """Tracked files with uncommitted changes (staged or not)."""
    out = git(repo, "status", "--porcelain", "--untracked-files=no")
    return [line[3:] for line in out.splitlines() if line.strip()]


def untracked(repo: Path) -> list[str]:
    out = git(repo, "status", "--porcelain", "--untracked-files=normal")
    return [line[3:] for line in out.splitlines() if line.startswith("??")]


def changed_paths(repo: Path, base: str, head: str, *pathspec: str) -> list[str]:
    out = git(repo, "diff", "--name-only", f"{base}..{head}", "--", *pathspec)
    return [p for p in out.splitlines() if p.strip()]


# ------------------------------------------------------------ module resolution


def module_for_path(root: Path, rel: str) -> str | None:
    """Dotted module for a repo-relative path under the package.

    ``fuzzlab/a/b.py`` -> ``fuzzlab.a.b``; ``fuzzlab/a/__init__.py`` -> ``fuzzlab.a``;
    a data file (template, YAML, static asset) maps to its nearest enclosing package,
    which is the code that loads it. Works for deleted paths too (by shape).
    """
    parts = Path(rel).parts
    if not parts or parts[0] != PACKAGE:
        return None
    if rel.endswith(".py"):
        mod = list(parts[:-1]) + [Path(parts[-1]).stem]
        if mod[-1] == "__init__":
            mod = mod[:-1]
        return ".".join(mod)
    # data file: walk up to the nearest directory that is a package
    d = Path(*parts[:-1])
    while len(d.parts) > 1 and not (root / d / "__init__.py").exists():
        d = d.parent
    return ".".join(d.parts)


def is_package_module(root: Path, module: str) -> bool:
    return (root / Path(*module.split(".")) / "__init__.py").exists()


def _resolve_relative(current: str, is_pkg: bool, level: int, module: str | None) -> str:
    base = current.split(".")
    if not is_pkg:
        base = base[:-1]
    if level > 1:
        base = base[: len(base) - (level - 1)]
    if module:
        base = base + module.split(".")
    return ".".join(base)


def module_name_of_test_file(rel: str) -> str:
    p = Path(rel)
    parts = list(p.parts[:-1]) + [p.stem]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


@dataclass
class FileRefs:
    """What one Python file under ``tests/`` refers to."""

    imports: set[str] = field(default_factory=set)  # dotted names, best resolution
    strings: set[str] = field(default_factory=set)  # dotted names found in string constants


def _dotted_from_string(s: str) -> str | None:
    s = s.strip()
    if not s or len(s) > 200 or " " in s:
        return None
    if s.startswith(PACKAGE + "/") and s.endswith(".py"):
        s = s[:-3].replace("/", ".")
        if s.endswith(".__init__"):
            s = s[: -len(".__init__")]
        return s
    if s == PACKAGE or s.startswith(PACKAGE + "."):
        if all(part.isidentifier() for part in s.split(".")):
            return s
    return None


def file_refs(path: Path, rel: str, root: Path) -> FileRefs:
    """AST-scan one file: every import (anywhere, relative resolved) and every string
    constant naming a package module or path."""
    refs = FileRefs()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return refs
    current = module_name_of_test_file(rel)
    is_pkg = path.name == "__init__.py"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                refs.imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                mod = _resolve_relative(current, is_pkg, node.level, node.module)
            else:
                mod = node.module or ""
            if mod:
                refs.imports.add(mod)
            for alias in node.names:
                if alias.name != "*" and mod:
                    # ``from pkg import sub`` imports pkg.sub when sub is a module
                    refs.imports.add(f"{mod}.{alias.name}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            dotted = _dotted_from_string(node.value)
            if dotted:
                refs.strings.add(dotted)
    return refs


def _real_module(root: Path, dotted: str) -> bool:
    p = root / Path(*dotted.split("."))
    return p.with_suffix(".py").exists() or (p / "__init__.py").exists()


def package_names(root: Path, names: set[str]) -> set[str]:
    """The package-module subset of ``names`` (dropping ``from m import func`` noise
    that does not name a module)."""
    out = set()
    for n in names:
        if n == PACKAGE or n.startswith(PACKAGE + "."):
            # keep the longest prefix that is a real module (handles pkg.mod.func)
            parts = n.split(".")
            while parts and not _real_module(root, ".".join(parts)):
                parts.pop()
            out.add(n)  # by shape too: a deleted module still matches its importers
            if parts:
                out.add(".".join(parts))
    return out


def module_matches(imported: str, changed: str, changed_is_pkg: bool) -> bool:
    """Does importing ``imported`` load ``changed``?

    Importing ``a.b.c`` executes ``a/__init__``, ``a/b/__init__`` and ``a/b/c``; so a
    changed package ``__init__`` (or a data file owned by a package) is loaded by any
    import at or below it, and a changed plain module only by importing it (or a
    name inside it).
    """
    if imported == changed:
        return True
    if changed_is_pkg and imported.startswith(changed + "."):
        return True
    return False


# ------------------------------------------------------------------- selection


@dataclass
class Selection:
    files: list[str]
    reasons: dict[str, set[str]]
    full: bool = False
    notes: list[str] = field(default_factory=list)

    def add(self, rel: str, reason: str) -> None:
        self.reasons.setdefault(rel, set()).add(reason)


def all_test_files(root: Path) -> list[str]:
    return sorted(
        str(p.relative_to(root))
        for p in (root / TESTS_DIR).rglob("test_*.py")
        if "__pycache__" not in p.parts
    )


def helper_files(root: Path) -> list[str]:
    return sorted(
        str(p.relative_to(root))
        for p in (root / TESTS_DIR).rglob("*.py")
        if "__pycache__" not in p.parts and not p.name.startswith("test_")
    )


def effective_package_imports(root: Path) -> dict[str, set[str]]:
    """Per test file: the package modules it imports, directly or through the
    ``tests`` helper modules it imports (transitively), plus string references."""
    refs: dict[str, FileRefs] = {}
    for rel in all_test_files(root) + helper_files(root):
        refs[rel] = file_refs(root / rel, rel, root)
    by_module = {module_name_of_test_file(rel): rel for rel in refs}

    def helper_deps(rel: str) -> set[str]:
        out = set()
        for name in refs[rel].imports:
            parts = name.split(".")
            while parts:
                cand = ".".join(parts)
                if cand in by_module and by_module[cand] != rel:
                    out.add(by_module[cand])
                    break
                parts.pop()
        return out

    closure: dict[str, set[str]] = {}

    def own(rel: str) -> set[str]:
        return package_names(root, refs[rel].imports | refs[rel].strings)

    for rel in all_test_files(root):
        seen = {rel}
        stack = [rel]
        mods: set[str] = set()
        while stack:
            cur = stack.pop()
            mods |= own(cur)
            for dep in helper_deps(cur):
                if dep not in seen:
                    seen.add(dep)
                    stack.append(dep)
        closure[rel] = mods
    return closure


def helper_users(root: Path, helper_rel: str) -> set[str]:
    """Test files importing ``helper_rel`` (a ``tests/_*.py``), transitively."""
    refs = {rel: file_refs(root / rel, rel, root) for rel in all_test_files(root) + helper_files(root)}
    target = module_name_of_test_file(helper_rel)
    users: set[str] = set()
    frontier = {target}
    seen_helpers = {target}
    while frontier:
        nxt: set[str] = set()
        for rel, r in refs.items():
            if any(i == t or i.startswith(t + ".") for i in r.imports for t in frontier):
                if Path(rel).name.startswith("test_"):
                    users.add(rel)
                else:
                    m = module_name_of_test_file(rel)
                    if m not in seen_helpers:
                        seen_helpers.add(m)
                        nxt.add(m)
        frontier = nxt
    return users


def reverse_closure(root: Path, changed: set[str]) -> set[str]:
    """``--transitive``: every package module that imports a changed one, directly or
    indirectly."""
    graph: dict[str, set[str]] = {}
    for p in (root / PACKAGE).rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        rel = str(p.relative_to(root))
        mod = module_for_path(root, rel)
        r = file_refs(p, rel, root)
        # relative imports in the package resolve against the module itself
        graph[mod] = package_names(root, r.imports)
    out = set(changed)
    grew = True
    while grew:
        grew = False
        for mod, deps in graph.items():
            if mod in out:
                continue
            if any(module_matches(d, c, is_package_module(root, c)) for d in deps for c in out):
                out.add(mod)
                grew = True
    return out


def _has_guard_marker(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
        ):
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Attribute) and sub.attr == GUARD_MARKER:
                    return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                for sub in ast.walk(dec):
                    if isinstance(sub, ast.Attribute) and sub.attr == GUARD_MARKER:
                        return True
    return False


def guard_kind(path: Path) -> str | None:
    """Why ``path`` is a whole-package guard, or None.

    A guard reads the package as source rather than importing what it checks: it
    carries the ``package_guard`` marker, imports pyflakes, calls ``ast.parse``, or
    globs / walks for ``*.py`` files.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return None
    if _has_guard_marker(tree):
        return "marker"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "pyflakes" for a in node.names):
            return "pyflakes"
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "pyflakes":
            return "pyflakes"
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "parse" and isinstance(f.value, ast.Name) and f.value.id == "ast":
                return "ast.parse"
            if isinstance(f, ast.Attribute) and f.attr in ("glob", "rglob", "iglob"):
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.endswith(".py"):
                        return "glob *.py"
            if isinstance(f, ast.Attribute) and f.attr == "walk" and isinstance(f.value, ast.Name) and f.value.id == "os":
                return "os.walk"
    return None


def package_guards(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel in all_test_files(root):
        kind = guard_kind(root / rel)
        if kind:
            out[rel] = kind
    for rel in EXPLICIT_GUARDS:
        if (root / rel).exists():
            out.setdefault(rel, "explicit list")
    return out


def select_tests(
    root: Path,
    changed_pkg_paths: list[str],
    changed_test_paths: list[str],
    *,
    transitive: bool = False,
) -> Selection:
    """The test files a change must run (relative paths, existing at ``root``)."""
    sel = Selection(files=[], reasons={})
    existing = set(all_test_files(root))

    for rel in changed_test_paths:
        name = Path(rel).name
        if name in CONFTEST_NAMES or rel in {f"{TESTS_DIR}/_leak_guard.py"}:
            sel.full = True
            sel.notes.append(f"{rel} changed: every test is affected, selecting the whole suite")
    if sel.full:
        for rel in sorted(existing):
            sel.add(rel, "suite-wide fixture changed")
        sel.files = sorted(sel.reasons)
        return sel

    changed_mods = {m for m in (module_for_path(root, p) for p in changed_pkg_paths) if m}
    target_mods = reverse_closure(root, changed_mods) if transitive else changed_mods
    pkg_flags = {m: is_package_module(root, m) for m in target_mods}

    if target_mods:
        imports = effective_package_imports(root)
        for rel, mods in imports.items():
            hits = sorted(
                c for c in target_mods if any(module_matches(i, c, pkg_flags[c]) for i in mods)
            )
            if hits:
                sel.add(rel, "imports " + ", ".join(hits[:3]) + (" ..." if len(hits) > 3 else ""))

    for rel, kind in package_guards(root).items():
        sel.add(rel, f"package guard ({kind})")

    for rel in changed_test_paths:
        if rel in existing:
            sel.add(rel, "changed test file")
        elif Path(rel).name.startswith("_") and (root / rel).exists():
            for user in helper_users(root, rel):
                sel.add(user, f"imports changed helper {rel}")

    sel.files = sorted(r for r in sel.reasons if r in existing)
    return sel


def is_serial(rel: str) -> bool:
    return rel in SERIAL_FILES or any(part in Path(rel).name for part in SERIAL_NAME_PARTS)


def split_passes(files: list[str]) -> tuple[list[str], list[str]]:
    parallel = [f for f in files if not is_serial(f)]
    serial = [f for f in files if is_serial(f)]
    return parallel, serial


# ------------------------------------------------------------------ counting


@dataclass
class Counts:
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    xfailed: int = 0

    def __add__(self, o: "Counts") -> "Counts":
        return Counts(
            self.passed + o.passed,
            self.failed + o.failed,
            self.errors + o.errors,
            self.skipped + o.skipped,
            self.xfailed + o.xfailed,
        )

    def line(self) -> str:
        return (
            f"{self.passed} passed, {self.failed} failed, {self.errors} errors, "
            f"{self.skipped} skipped, {self.xfailed} xfailed"
        )

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.errors == 0


def parse_junit(xml_path: Path) -> Counts:
    c = Counts()
    root = ET.parse(xml_path).getroot()
    for case in root.iter("testcase"):
        kids = {child.tag: child for child in case}
        if "failure" in kids:
            c.failed += 1
        elif "error" in kids:
            c.errors += 1
        elif "skipped" in kids:
            if (kids["skipped"].get("type") or "") == "pytest.xfail":
                c.xfailed += 1
            else:
                c.skipped += 1
        else:
            c.passed += 1
    return c


# ------------------------------------------------------------------ processes


def _ancestors() -> set[int]:
    out, pid = set(), os.getpid()
    while pid > 1:
        out.add(pid)
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            break
        pid = int(stat.rsplit(")", 1)[1].split()[1])  # field 4: ppid
    return out


def other_pytest_pids(own: set[int]) -> list[tuple[int, str]]:
    """Read-only scan of /proc for pytest processes not started by this harness
    (and not its own ancestors, e.g. a pytest that invoked it)."""
    found = []
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    skip = _ancestors() | set(own)
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in skip:
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        args = [a.decode(errors="replace") for a in argv if a]
        if not args:
            continue
        is_pytest = Path(args[0]).name in ("pytest", "py.test") or (
            len(args) >= 3 and args[1] == "-m" and args[2] == "pytest"
        )
        if is_pytest:
            found.append((pid, " ".join(args)[:160]))
    return found


def group_members(pgid: int) -> list[int]:
    """Live (non-zombie) processes in process group ``pgid``, read from /proc."""
    out = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        state, pgrp = fields[0], int(fields[2])
        if pgrp == pgid and state not in ("Z", "X"):
            out.append(int(entry.name))
    return out


class Runner:
    """Starts pytest processes one at a time; stops only what it started.

    Each pytest runs as the leader of its own session and process group. The leader is
    never reaped before its group has been swept: its exit is observed with
    ``WNOWAIT``, so its pid -- and therefore the group id -- stays held (a zombie)
    while anything left in the group is signalled. Only then is it reaped (PA-0125(5):
    an id is trusted only while its leader pid is held). Nothing is ever found or
    killed by name or pattern.
    """

    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.pidfile = out_dir / "pids.txt"
        self.children: list[subprocess.Popen] = []

    @staticmethod
    def _exited(proc: subprocess.Popen, timeout: float | None) -> bool:
        """Wait for the leader to exit WITHOUT reaping it."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                info = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            except ChildProcessError:
                return True  # already reaped elsewhere
            if info is not None:
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.2)

    def _signal_group(self, proc: subprocess.Popen, sig: int) -> None:
        try:
            os.killpg(proc.pid, sig)  # held leader: the group id is still ours
        except ProcessLookupError:
            pass

    def _sweep(self, proc: subprocess.Popen) -> None:
        """With the leader held, stop whatever is still live in its group."""
        if not group_members(proc.pid):
            return
        print(f"  pid {proc.pid}'s process group outlived it; stopping that group only")
        for sig, grace in ((signal.SIGTERM, 10.0), (signal.SIGKILL, 5.0)):
            self._signal_group(proc, sig)
            deadline = time.monotonic() + grace
            while group_members(proc.pid) and time.monotonic() < deadline:
                time.sleep(0.2)
            if not group_members(proc.pid):
                return

    def _finish(self, proc: subprocess.Popen, timeout: float | None) -> bool:
        """Bring one child to a reaped end; True if it exited within ``timeout``."""
        in_time = self._exited(proc, timeout)
        if not in_time:
            self._signal_group(proc, signal.SIGTERM)
            if not self._exited(proc, 30):
                self._signal_group(proc, signal.SIGKILL)
                self._exited(proc, None)
        self._sweep(proc)
        proc.wait()  # reap last
        return in_time

    def run(self, cmd: list[str], cwd: Path, env: dict, log: Path, timeout: float) -> int:
        with open(log, "w") as fh:
            proc = subprocess.Popen(
                cmd, cwd=cwd, env=env, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True
            )
        self.children.append(proc)
        with open(self.pidfile, "a") as pf:
            pf.write(f"{proc.pid}\n")
        if not self._finish(proc, timeout):
            print(f"  timed out after {timeout:.0f}s; stopped pid {proc.pid}'s process group")
            return 124
        return proc.returncode

    def cleanup(self) -> None:
        """On any exit path: end every child this run started and has not reaped."""
        for proc in self.children:
            if proc.returncode is None:
                self._signal_group(proc, signal.SIGTERM)
                self._finish(proc, 30)


# ------------------------------------------------------------------ main flow


def chromium_executable() -> str | None:
    cands = sorted(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux/chrome"))
    return str(cands[-1]) if cands else None


def have_xdist() -> bool:
    import importlib.util

    return importlib.util.find_spec("xdist") is not None


def pytest_cmd(files: list[str], junit: Path, *, parallel: bool, workers: int) -> list[str]:
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rfEs",
           f"--junitxml={junit}"]
    if parallel:
        cmd += ["-n", str(workers), "--dist", "loadfile"]
    else:
        cmd += ["-o", "faulthandler_timeout=600", "--durations=15"]
    return cmd + files


def pytest_env(wait_other: float) -> dict[str, str]:
    """The environment of every pytest this run starts: the require-flags, and the host
    pytest lock's wait set to this run's ``--wait-other`` unless the caller set it
    (BUG-0532: the child's controller takes that lock, and another session can take it
    between the quiet-host check and the child's start)."""
    env = dict(os.environ, **REQUIRE_FLAGS)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    env.setdefault(PYTEST_LOCK_WAIT, f"{wait_other:g}")
    chrome = chromium_executable()
    if chrome and "PLAYWRIGHT_CHROMIUM_EXECUTABLE" not in env:
        env["PLAYWRIGHT_CHROMIUM_EXECUTABLE"] = chrome
    return env


def acquire_host_lock(wait: float):
    lock_path = Path(tempfile.gettempdir()) / "fuzzlab-verify-change.lock"
    fh = open(lock_path, "w")
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except BlockingIOError:
            if time.monotonic() >= deadline:
                fh.close()
                return None
            time.sleep(5)


def wait_for_quiet_host(wait: float, own: set[int]) -> bool:
    deadline = time.monotonic() + wait
    announced = False
    while True:
        others = other_pytest_pids(own)
        if not others:
            return True
        if not announced:
            print("waiting for other pytest processes to finish (one pytest at a time):")
            for pid, args in others:
                print(f"  pid {pid}: {args}")
            announced = True
        if time.monotonic() >= deadline:
            return False
        time.sleep(10)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", help="base ref; tests are selected for <base>..HEAD")
    ap.add_argument("--head", default="HEAD", help="commit to verify (default HEAD)")
    ap.add_argument("--full", action="store_true", help="run the whole suite, split the same way")
    ap.add_argument("--repo", default=".", help="repository (default: current directory)")
    ap.add_argument("--transitive", action="store_true",
                    help="also select tests importing any package module that imports a changed one")
    ap.add_argument("--list-only", action="store_true", help="print the selection and run nothing")
    ap.add_argument("--workers", type=int, default=3, help="xdist workers for the parallel pass")
    ap.add_argument("--timeout", type=float, default=5400, help="seconds per pass")
    ap.add_argument("--wait-other", type=float, default=1800,
                    help="seconds to wait for other pytest processes / harness runs (default 1800)")
    ap.add_argument("--out", help="directory for logs and the summary (default: a new temp dir)")
    ap.add_argument("--keep-worktree", action="store_true", help="leave the detached worktree in place")
    ap.add_argument("--allow-concurrent", action="store_true",
                    help="skip the host lock and the wait for other pytest processes (only for "
                         "this script's own tests; never for a verification you report). A child "
                         "pytest of this repository's test tree still takes the host pytest lock")
    args = ap.parse_args(argv)

    if not args.full and not args.base:
        ap.error("give --base <ref> (or --full)")

    repo = Path(git(Path(args.repo), "rev-parse", "--show-toplevel").strip())
    dirty = dirty_tracked(repo)
    if dirty:
        print("refusing: the tree has uncommitted tracked changes; commit them first:")
        for p in dirty[:20]:
            print(f"  {p}")
        return 2
    loose = untracked(repo)
    if loose:
        print(f"note: {len(loose)} untracked path(s) are NOT part of the verified commit, e.g. {loose[:5]}")

    sha = git(repo, "rev-parse", args.head).strip()
    base_sha = git(repo, "rev-parse", args.base).strip() if args.base else None

    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix=f"fuzzlab-verify-{sha[:8]}-"))
    out.mkdir(parents=True, exist_ok=True)
    wt = out / "worktree"
    runner = Runner(out)

    def _on_signal(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, _on_signal)

    lock = None
    created = False
    try:
        git(repo, "worktree", "add", "--detach", str(wt), sha)
        created = True
        print(f"verifying {sha[:12]} in detached worktree {wt}")

        if args.full:
            sel = Selection(files=all_test_files(wt), reasons={}, full=True)
            print("mode: --full (every test file)")
        else:
            pkg = changed_paths(repo, base_sha, sha, PACKAGE)
            tst = changed_paths(repo, base_sha, sha, TESTS_DIR)
            other = [p for p in changed_paths(repo, base_sha, sha)
                     if not p.startswith((PACKAGE + "/", TESTS_DIR + "/", "docs/"))
                     and not p.endswith(".md")]
            sel = select_tests(wt, pkg, tst, transitive=args.transitive)
            print(f"base {base_sha[:12]}: {len(pkg)} changed package file(s), {len(tst)} changed test file(s)")
            for p in pkg:
                print(f"  changed: {p} -> {module_for_path(wt, p)}")
            if other:
                print(f"note: {len(other)} changed file(s) outside {PACKAGE}/ and {TESTS_DIR}/ "
                      f"(consider --full): {other[:8]}")
            for n in sel.notes:
                print(f"note: {n}")

        parallel, serial = split_passes(sel.files)
        print(f"selected {len(sel.files)} test file(s): {len(parallel)} parallel, {len(serial)} serial")
        (out / "selection.json").write_text(json.dumps(
            {"head": sha, "base": base_sha, "full": sel.full, "parallel": parallel, "serial": serial,
             "reasons": {k: sorted(v) for k, v in sel.reasons.items()}}, indent=1))
        if args.list_only:
            for f in sel.files:
                why = "; ".join(sorted(sel.reasons.get(f, ()))) or "full suite"
                print(f"  {'S' if is_serial(f) else 'P'} {f}  [{why}]")
            return 0
        if not sel.files:
            print("nothing to run")
            return 0

        # sanity: the package under test must be the worktree's own copy
        probe = subprocess.run([sys.executable, "-c", f"import {PACKAGE}; print({PACKAGE}.__file__)"],
                               cwd=wt, capture_output=True, text=True)
        loaded = probe.stdout.strip()
        if not loaded or not Path(loaded).resolve().is_relative_to(wt.resolve()):
            print(f"refusing: `import {PACKAGE}` in the worktree loads {loaded or probe.stderr.strip()!r}, "
                  "not the worktree's copy")
            return 2

        if not args.allow_concurrent:
            lock = acquire_host_lock(args.wait_other)
            if lock is None:
                print("refusing: another verify_change run holds the host lock")
                return 3
            if not wait_for_quiet_host(args.wait_other, {p.pid for p in runner.children}):
                print("refusing: other pytest processes are still running (one pytest at a time)")
                return 3

        env = pytest_env(args.wait_other)
        use_xdist = have_xdist()
        if parallel and not use_xdist:
            print("note: pytest-xdist is not installed; the parallel pass runs without -n")

        total = Counts()
        results = {}
        for name, files, par in (("parallel", parallel, use_xdist), ("serial", serial, False)):
            if not files:
                continue
            junit = out / f"{name}.xml"
            log = out / f"{name}.log"
            cmd = pytest_cmd(files, junit, parallel=par, workers=args.workers)
            print(f"[{name}] {len(files)} file(s) ... (log: {log})", flush=True)
            t0 = time.monotonic()
            rc = runner.run(cmd, wt, env, log, args.timeout)
            dt = time.monotonic() - t0
            counts = parse_junit(junit) if junit.exists() else Counts(errors=1)
            if rc not in (0, 1, 5) and counts.ok:
                counts.errors += 1  # interrupted / internal error with nothing recorded
            tail = log.read_text(errors="replace").strip().splitlines()[-1:] if log.exists() else []
            print(f"[{name}] rc={rc} {dt:.0f}s: {counts.line()}  ({tail[0] if tail else ''})")
            if not counts.ok:
                lines = log.read_text(errors="replace").splitlines()
                summary = [ln for ln in lines if ln.startswith(("FAILED", "ERROR"))]
                for ln in summary[:40]:
                    print(f"  {ln}")
            results[name] = {"files": len(files), "rc": rc, "seconds": round(dt), **counts.__dict__}
            total = total + counts

        print(f"TOTAL {len(sel.files)} file(s): {total.line()}")
        (out / "summary.json").write_text(json.dumps(
            {"head": sha, "base": base_sha, "full": sel.full, "files": len(sel.files),
             "passes": results, "total": total.__dict__}, indent=1))
        print(f"logs and summary: {out}")
        return 0 if total.ok else 1
    except KeyboardInterrupt as exc:
        print(f"interrupted ({exc}); stopping this run's own processes")
        return 130
    finally:
        runner.cleanup()
        if created and not args.keep_worktree:
            try:
                git(repo, "worktree", "remove", "--force", str(wt))
            except subprocess.CalledProcessError as exc:
                print(f"warning: could not remove worktree {wt}: {exc.stderr.strip()}")
        if lock is not None:
            lock.close()


if __name__ == "__main__":
    sys.exit(main())
