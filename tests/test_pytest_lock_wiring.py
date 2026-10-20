"""The root conftest takes the host pytest lock first, in every session (BUG-0532, PA-0532).

A whole-tree guard, light enough to run with every change (``scripts/verify_change.py``
selects it as a package guard): the AST check is proven on synthetic offenders
(PA-0034(2)), and this very session is checked to have run the hook and to hold the
host lock (directly, through its xdist controller, or as a nested session). The lock's
behaviour is proven in ``tests/test_pytest_lock.py``.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from tests import _pytest_lock as lock

REPO = Path(__file__).resolve().parent.parent
RAN_THE_HOOK = {"acquired", "worker", "nested", "nested-in-process"}
pytestmark = pytest.mark.package_guard



def conftest_problems(source: str) -> list[str]:
    """Why a root conftest would not take the lock first in every session."""
    tree = ast.parse(source)
    problems = []
    imports_module = any(isinstance(n, ast.ImportFrom) and n.module == "tests"
                         and any(a.name == "_pytest_lock" for a in n.names) for n in tree.body)
    configure = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
                      and n.name == "pytest_configure"), None)
    body = [] if configure is None else [
        s for s in configure.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
    first = body[0] if body else None
    takes_first = (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
                   and isinstance(first.value.func, ast.Attribute)
                   and first.value.func.attr == "pytest_configure"
                   and isinstance(first.value.func.value, ast.Name)
                   and first.value.func.value.id == "_pytest_lock")
    if not (imports_module and takes_first):
        problems.append("pytest_configure does not call _pytest_lock.pytest_configure first")
    releases = any(isinstance(n, ast.ImportFrom) and n.module == "tests._pytest_lock"
                   and any(a.name == "pytest_unconfigure" and a.asname is None for a in n.names)
                   for n in tree.body)
    if not releases:
        problems.append("pytest_unconfigure is not tests._pytest_lock's")
    return problems


def test_the_root_conftest_takes_the_lock_first():
    assert conftest_problems((REPO / "tests" / "conftest.py").read_text()) == []


def test_the_wiring_guard_catches_each_synthetic_offender():
    good = (REPO / "tests" / "conftest.py").read_text()
    offenders = {
        "the hook removed": good.replace("    _pytest_lock.pytest_configure(config)\n", ""),
        "the hook second": good.replace(
            "    _pytest_lock.pytest_configure(config)\n    _clear_store_env(config)\n",
            "    _clear_store_env(config)\n    _pytest_lock.pytest_configure(config)\n"),
        "no release": good.replace(
            "from tests._pytest_lock import pytest_unconfigure  # noqa: F401\n", ""),
        "the pre-BUG-0532 conftest": textwrap.dedent("""
            from tests._store_guard import pytest_configure  # noqa: F401
        """),
    }
    for name, source in offenders.items():
        assert source != good, name
        assert conftest_problems(source), name


def test_this_session_ran_the_hook(request):
    assert lock.decision(request.config) in RAN_THE_HOOK
    if lock.fcntl is not None:
        assert lock.host_lock_held_by_ancestor(), (
            "this session runs without the host pytest lock held by it or an ancestor")
