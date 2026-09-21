"""Tier 0 -- lint + minimal-pair diff (T-LAB0.7).

The fast tier: seconds, no container, no live app. Two independent checks:

1. A real syntax check of one emitted file's content -- :func:`lint_php`
   (``php -l``) or :func:`lint_python` (``python -m py_compile``), each
   skip-guarded when its interpreter/CLI isn't on the build host
   (:func:`php_available`/:func:`python_available`, matching this project's
   PA-0005 pattern).
2. Minimal-pair diff -- checks that a vulnerable/secure twin's
   ``EmittedFiles`` differ only in the transform region. The real checker
   is ``fuzzlab.labgen.minimal_pair`` (owned by a sibling lane) -- **PHP-
   oriented only**, by that module's own documented scope (it parses a
   ``// Module composition: ...`` line and PHP ``$var``/``function NAME(``
   identifiers): :func:`get_minimal_pair_checker` prefers it whenever it can
   import, which is correct for ``php_current``/``php_laravel`` but not yet
   meaningful for a non-PHP emitter's output (a documented, not-yet-attempted
   extension point per that module's own docstring). A non-PHP emitter's own
   Tier-0 tests should therefore call :func:`_naive_minimal_pair_check`
   directly rather than through :func:`get_minimal_pair_checker`, until a
   future cross-cutting task extends the real checker's comment-syntax/
   identifier-pattern detection per language (see
   ``fuzzlab.labgen.emitters.python_fastapi``'s own Tier-0 tests for the
   worked example).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from fuzzlab.labgen.emitter import EmittedFiles


@dataclass(frozen=True)
class LintResult:
    path: str
    ok: bool
    detail: str


def php_available() -> bool:
    """Whether the ``php`` CLI is on this build host. Callers should guard
    :func:`lint_php` with this (or an equivalent ``pytest.mark.skipif``),
    per this project's PA-0005 pattern -- never silently report a pass when
    the tool that would have found a failure isn't even present."""
    return shutil.which("php") is not None


def lint_php(path: str, content: bytes, *, timeout: float = 10.0) -> LintResult:
    """Syntax-check one PHP file's content with ``php -l``.

    Raises :class:`RuntimeError` if the ``php`` CLI isn't available --
    callers must guard with :func:`php_available` first rather than
    silently reporting a false pass.
    """
    if not php_available():
        raise RuntimeError("php CLI not available on this host -- guard with php_available() first")
    with tempfile.TemporaryDirectory() as tmpdir:
        php_path = Path(tmpdir) / "cell.php"
        php_path.write_bytes(content)
        result = subprocess.run(
            ["php", "-l", str(php_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return LintResult(path=path, ok=result.returncode == 0, detail=result.stdout + result.stderr)


def lint_emitted_files(files: EmittedFiles) -> list[LintResult]:
    """Lint every file an emitter produced for one cell."""
    return [lint_php(f.path, f.content) for f in files]


def python_available() -> bool:
    """Whether a ``python`` (or ``python3``) interpreter capable of running
    ``-m py_compile`` is on this build host. Always true in this project's
    own CI/dev environment (it runs on Python), but callers still guard with
    this per PA-0005's own convention -- mirrors :func:`php_available`
    exactly, for the same "never silently report a pass when the tool that
    would have found a failure isn't even present" reason, and so a future
    host that only ships a Python this interpreter can't shell out to still
    fails loud rather than false-passing."""
    return shutil.which(sys.executable) is not None or shutil.which("python3") is not None


def lint_python(path: str, content: bytes, *, timeout: float = 10.0) -> LintResult:
    """Syntax-check one Python file's content with ``python -m py_compile``.

    Raises :class:`RuntimeError` if no usable interpreter is available --
    callers must guard with :func:`python_available` first, mirroring
    :func:`lint_php`'s own contract exactly.
    """
    if not python_available():
        raise RuntimeError("python interpreter not available on this host -- guard with python_available() first")
    with tempfile.TemporaryDirectory() as tmpdir:
        py_path = Path(tmpdir) / "cell.py"
        py_path.write_bytes(content)
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(py_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return LintResult(path=path, ok=result.returncode == 0, detail=result.stdout + result.stderr)


def lint_python_emitted_files(files: EmittedFiles) -> list[LintResult]:
    """Lint every ``.py`` file an emitter produced for one cell (non-``.py``
    scaffold outputs like ``requirements.txt``/``Dockerfile`` are not
    Python source and are skipped, not silently reported as passing)."""
    return [lint_python(f.path, f.content) for f in files if f.path.endswith(".py")]


@dataclass(frozen=True)
class MinimalPairResult:
    is_minimal_pair: bool
    differing_paths: tuple[str, ...]
    notes: str


MinimalPairChecker = Callable[[EmittedFiles, EmittedFiles], MinimalPairResult]


def _naive_minimal_pair_check(vulnerable: EmittedFiles, secure: EmittedFiles) -> MinimalPairResult:
    """Conservative fallback used until ``fuzzlab.labgen.minimal_pair``
    lands.

    Compares the two renders **positionally** (index 0 with index 0, and so
    on), not by matching file path: ``php_current`` names its one output
    file per *cell* (derived from ``cell_id``), not per *page*, so a
    vulnerable cell and its secure twin are two different cell IDs and
    therefore two different paths by construction -- a future routed,
    multi-file emitter (Addendum D) that instead writes one shared
    controller/view pair per *page*, toggled by a build profile, would make
    matching by path meaningful again, so this function does not hard-code
    either assumption: it requires equal *file count* (structural parity)
    and reports each index's own path(s) whether or not they match.

    This is a structural sanity check, **not** a semantic "the diff is
    confined to the transform region" proof -- that stronger property needs
    the real, emitter-region-aware checker the sibling lane is building;
    this fallback is deliberately conservative and says so in ``notes``.
    """
    if len(vulnerable) != len(secure):
        return MinimalPairResult(
            is_minimal_pair=False,
            differing_paths=(),
            notes=f"file count differs: {len(vulnerable)} (vulnerable) vs {len(secure)} (secure)",
        )
    differing: list[str] = []
    for vuln_file, secure_file in zip(vulnerable, secure):
        if vuln_file.content == secure_file.content:
            continue
        label = vuln_file.path if vuln_file.path == secure_file.path else f"{vuln_file.path} <-> {secure_file.path}"
        differing.append(label)
    if not differing:
        return MinimalPairResult(
            is_minimal_pair=False,
            differing_paths=(),
            notes="twins are byte-identical at every position -- not a pair at all",
        )
    return MinimalPairResult(
        is_minimal_pair=True,
        differing_paths=tuple(differing),
        notes=(
            "naive fallback check (fuzzlab.labgen.minimal_pair not available): confirmed the twins "
            "have the same file count and differ in at least one positional file pair; does NOT "
            "confirm the diff is confined to the transform region -- that stronger property needs "
            "the real checker"
        ),
    )


def get_minimal_pair_checker() -> MinimalPairChecker:
    """Prefer the real, sibling-owned checker (``fuzzlab.labgen.minimal_pair
    .check_minimal_pair``) if it has landed; otherwise fall back to the
    naive structural check above. No caller of this function needs to
    change once that sibling lane merges."""
    try:
        from fuzzlab.labgen import minimal_pair as _minimal_pair_module
    except ImportError:
        return _naive_minimal_pair_check
    checker = getattr(_minimal_pair_module, "check_minimal_pair", None)
    if checker is None:  # pragma: no cover - defensive; exercised once the module lands with a different name
        return _naive_minimal_pair_check
    return checker
