"""Tier 0 -- lint + minimal-pair diff (T-LAB0.7).

The fast tier: seconds, no container, no live app. Two independent checks:

1. :func:`lint_php` -- a real syntax check (``php -l``) of one emitted
   file's content. Skip-guarded when the ``php`` CLI isn't on the build
   host (:func:`php_available`, matching this project's PA-0005 pattern).
2. Minimal-pair diff -- checks that a vulnerable/secure twin's
   ``EmittedFiles`` differ only in the transform region. The real checker
   is ``fuzzlab.labgen.minimal_pair`` (owned by a concurrently-developed
   sibling lane and not yet landed as of this module's authoring);
   :func:`get_minimal_pair_checker` imports it if present and falls back to
   :func:`_naive_minimal_pair_check` otherwise, so this module works today
   and upgrades automatically once that sibling lane merges -- no further
   change needed here.
"""

from __future__ import annotations

import shutil
import subprocess
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
