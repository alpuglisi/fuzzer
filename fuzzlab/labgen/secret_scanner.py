"""Secret-scanner build gate (T-LAB0.6), separate from and complementary to
the vulnerability-class name-leak scanner in ``fuzzlab.labgen.gates``.

Runs **Gitleaks** (MIT license) headlessly, in ``--no-git`` mode, against a
generated lab output tree written to disk, using the project's
``.gitleaks.toml`` (repo root) which extends Gitleaks' default ruleset with
one allowlist for seeded fake/example credentials (see that file's
comments). Not TruffleHog: per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.6,
TruffleHog's differentiator is live credential verification, which is pure
noise against seeded fake credentials and an unwanted outbound call from a
loopback-only project's build.

Mirrors ``fuzzlab.labgen.oracle_wrapper``'s established pattern for wrapping
an independent, external CLI tool (PA-0005): a dependency-injected
``Runner`` so tests never need the real ``gitleaks`` binary, a typed
``ToolNotFoundError`` instead of a raw ``FileNotFoundError``, and a
structured result type. It deliberately does **not** import from or extend
``fuzzlab.labgen.gates``/``fuzzlab.labgen.denylist`` (the name-leak scanner)
-- these are two independent build gates per the plan ("Two separate
gates."), not one extended into the other.

Fail-closed contract (the plan's own rule): a scanner **crash** fails the
build exactly like a real hit does -- a scanner that silently no-ops on a
crash is worse than no scanner. Concretely: a missing ``gitleaks`` binary
raises ``ToolNotFoundError``; a subprocess that produces exit code 1 (leaks
found) yields ``SecretScanResult(passed=False, ...)`` with the parsed leaks;
any other unexpected condition -- a nonzero/non-1 exit code, or output that
does not parse as the expected JSON report -- raises ``SecretScanError``
rather than being interpreted as "no leaks found".
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

__all__ = [
    "SecretLeak",
    "SecretScanRunResult",
    "SecretScanResult",
    "SecretScanError",
    "ToolNotFoundError",
    "Runner",
    "default_runner",
    "locate_gitleaks",
    "scan_tree_for_secrets",
]


class ToolNotFoundError(RuntimeError):
    """Raised instead of letting a raw ``FileNotFoundError`` propagate when
    the ``gitleaks`` executable cannot be located (same convention as
    ``fuzzlab.labgen.oracle_wrapper.ToolNotFoundError`` / BUG-0007 / PA-0021:
    a validation boundary that raises a typed error for some failure modes
    must raise it for every foreseeable one, including a missing
    executable)."""


class SecretScanError(RuntimeError):
    """Raised on a scanner **crash** -- an exit code other than 0 (clean) or
    1 (leaks found), or a report file that fails to parse as the expected
    JSON shape. Per T-LAB0.6: fails the build on a crash, not just a hit; a
    scanner that silently no-ops on a crash is worse than no scanner."""


@dataclasses.dataclass(frozen=True)
class SecretLeak:
    """One Gitleaks finding, narrowed to the fields this gate reports on."""

    rule_id: str
    description: str
    file: str
    start_line: int
    match: str


@dataclasses.dataclass(frozen=True)
class SecretScanRunResult:
    """The raw subprocess outcome, kept for debugging regardless of how it
    was classified (mirrors ``OracleRunResult``)."""

    argv: Sequence[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    duration_s: float


@dataclasses.dataclass(frozen=True)
class SecretScanResult:
    """The structured pass/fail result every caller gets back."""

    passed: bool
    leaks: Sequence[SecretLeak]
    run: SecretScanRunResult

    def __bool__(self) -> bool:  # convenience: `if scan_tree_for_secrets(...):`
        return self.passed


# A runner is dependency-injected so tests never need to touch the real
# `subprocess` module or a real `gitleaks` binary (mirrors
# `fuzzlab.labgen.oracle_wrapper.Runner`) -- the one exception being a
# skip-guarded real-binary integration test.
Runner = Callable[[Sequence[str]], SecretScanRunResult]


def default_runner(argv: Sequence[str]) -> SecretScanRunResult:
    """The real runner: shells out to `gitleaks` via `subprocess.run`.

    No timeout is imposed here deliberately -- unlike the oracle-wrapper
    tools (sqlmap/commix/SSTImap), Gitleaks scans a static, already-rendered
    file tree with no network I/O and no target to hang against, so there is
    no "hung tool" failure mode to bound against (callers that still want a
    hard ceiling can inject their own ``Runner`` wrapping this one).
    """
    start = time.monotonic()
    proc = subprocess.run(list(argv), capture_output=True, text=True)
    return SecretScanRunResult(
        argv=list(argv),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_s=time.monotonic() - start,
    )


def locate_gitleaks(explicit_path: Optional[str] = None) -> str:
    """Find the `gitleaks` executable, never raising a raw
    `FileNotFoundError` (mirrors `oracle_wrapper.locate_tool`).

    Resolution order: an explicit path/command (if given) -> PATH lookup of
    `gitleaks`. Raises `ToolNotFoundError` with an actionable message
    otherwise.
    """
    candidate = explicit_path or "gitleaks"
    resolved = shutil.which(candidate)
    if resolved:
        return resolved
    if explicit_path and Path(explicit_path).is_file():
        return str(Path(explicit_path).resolve())
    raise ToolNotFoundError(
        f"'gitleaks' executable not found "
        + (f"at explicit path {explicit_path!r} or " if explicit_path else "")
        + "on PATH. Install it (e.g. `apt-get install gitleaks`, or see "
        "https://github.com/gitleaks/gitleaks for other install methods) or "
        "pass an explicit path via the `tool_path` parameter."
    )


def _write_tree(root: Path, tree: Mapping[str, bytes]) -> None:
    for rel_path, content in tree.items():
        dest = root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)


def _parse_report(report_path: Path) -> list[SecretLeak]:
    if not report_path.exists():
        # Gitleaks does not write a report file when it finds zero leaks in
        # some versions/configs; treat "no report" as "no findings", not a
        # crash -- the exit-code check in `scan_tree_for_secrets` is what
        # actually distinguishes clean/leaky/crashed.
        return []
    raw = report_path.read_text("utf-8")
    if not raw.strip():
        return []
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SecretScanError(
            f"gitleaks report at {report_path} did not parse as JSON: {exc}"
        ) from exc
    if not isinstance(findings, list):
        raise SecretScanError(
            f"gitleaks report at {report_path} was not a JSON array (got {type(findings).__name__})"
        )
    leaks: list[SecretLeak] = []
    for entry in findings:
        if not isinstance(entry, dict):
            raise SecretScanError(f"gitleaks report at {report_path} contained a non-object finding: {entry!r}")
        try:
            leaks.append(
                SecretLeak(
                    rule_id=str(entry["RuleID"]),
                    description=str(entry["Description"]),
                    file=str(entry["File"]),
                    start_line=int(entry["StartLine"]),
                    match=str(entry["Match"]),
                )
            )
        except KeyError as exc:
            raise SecretScanError(
                f"gitleaks report at {report_path} finding missing expected field {exc}: {entry!r}"
            ) from exc
    return leaks


def scan_tree_for_secrets(
    tree: Mapping[str, bytes],
    *,
    config_path: str | Path = ".gitleaks.toml",
    tool_path: Optional[str] = None,
    runner: Runner = default_runner,
) -> SecretScanResult:
    """Write ``tree`` (a ``{relative_path: content}`` mapping, the same shape
    ``fuzzlab.labgen.gates.generate_source_tree`` returns) to a temporary
    directory and run Gitleaks against it headlessly, using ``config_path``
    (the project's ``.gitleaks.toml`` by default).

    Returns a :class:`SecretScanResult` with ``passed=False`` and the parsed
    :class:`SecretLeak` list when Gitleaks finds one or more real secrets.
    Raises :class:`ToolNotFoundError` if the ``gitleaks`` binary cannot be
    located, and :class:`SecretScanError` on any other crash condition (an
    exit code other than 0/1, or a report that does not parse as expected)
    -- both are build-breaking failures, never silently treated as "clean"
    (the plan's fail-on-crash rule for this gate).
    """
    resolved_tool = locate_gitleaks(tool_path)
    resolved_config = Path(config_path).resolve()
    if not resolved_config.is_file():
        raise SecretScanError(f"gitleaks config not found at {resolved_config}")

    with tempfile.TemporaryDirectory(prefix="fuzzlab-secret-scan-") as tmp:
        tmp_root = Path(tmp)
        _write_tree(tmp_root, tree)
        report_path = tmp_root.parent / f"{tmp_root.name}-report.json"
        argv = [
            resolved_tool,
            "detect",
            "--no-git",
            "--source", str(tmp_root),
            "--config", str(resolved_config),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--exit-code", "1",
        ]
        run = runner(argv)
        try:
            if run.returncode == 0:
                leaks: list[SecretLeak] = []
            elif run.returncode == 1:
                leaks = _parse_report(report_path)
                if not leaks:
                    # Exit 1 is gitleaks' own "leaks found" signal; an empty
                    # report alongside it is a crash-shaped inconsistency,
                    # not a clean pass -- fail loud rather than guess.
                    raise SecretScanError(
                        f"gitleaks exited 1 (leaks found) but its report at {report_path} "
                        f"contained no findings -- treating as a scanner malfunction, not a clean pass "
                        f"(stdout={run.stdout!r}, stderr={run.stderr!r})"
                    )
            else:
                raise SecretScanError(
                    f"gitleaks exited with unexpected status {run.returncode!r} "
                    f"(argv={list(run.argv)!r}, stdout={run.stdout!r}, stderr={run.stderr!r})"
                )
        finally:
            report_path.unlink(missing_ok=True)

    return SecretScanResult(passed=not leaks, leaks=leaks, run=run)
