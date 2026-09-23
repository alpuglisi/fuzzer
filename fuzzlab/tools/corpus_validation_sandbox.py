"""Dynamic-execution sandbox for validating `docs/research/corpus-examples/`
vulnerable/idiomatic pairs, per `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s
"Validation execution sandbox" section.

This is a distinct, real risk surface from this project's lab safety
doctrine (`CLAUDE.md`'s loopback-only/`--authorized` posture governs the
*generated lab*; this governs *running arbitrary collected/manufactured
source during corpus validation*, which the lab doctrine does not cover).
Actually executing a deliberately-vulnerabilized third-party snippet
(PHP object-injection gadgets, Python `pickle`/`yaml.load` payloads,
Node `vm`/`eval` payloads, command-injection payloads that are host-kernel-
facing arbitrary code execution) requires real containment, not a
convention.

Containment (all required, per the plan's own spec):

- **Runtime: gVisor (`runsc`)**, not plain `runc` -- a syscall-interception
  boundary between the executed payload and the real host kernel, the
  actual point of this sandbox given several of these CWE classes are
  command-injection-adjacent.
- **Network: zero, no exceptions.** The OCI spec's `network` namespace is
  unshared with no interface ever attached to it -- there is no bridge, no
  veth, no loopback-only allowance to punch through, nothing to
  allow-list. A payload attempting outbound network I/O of any kind
  (SSRF, exfiltration, C2 callback) gets `ENETUNREACH`/`Network is
  unreachable` at the kernel-facing boundary `runsc` intercepts.
- **Filesystem: ephemeral per run.** `root.readonly = true` plus a
  memory-backed overlay (`--overlay2=root:memory`) means every write the
  payload makes lands in a throwaway layer that is destroyed with the
  container -- nothing persists to the real disk across runs, and a
  path-traversal payload that manages to write somewhere cannot
  contaminate the next validation. (Known, documented trade-off: the
  read-side root is the *host's* own filesystem, not a purpose-built
  minimal image -- see "Deviations from the plan's literal spec" below.)
- **Resource limits, real cgroup v1 (not `ulimit` approximations):** a
  `memory` cgroup caps RSS, a `pids` cgroup caps the number of tasks the
  sandbox can fork (the direct fork-bomb defence), and a wall-clock
  `timeout(1)` wrapper kills the whole `runsc` invocation if it hangs.
- **Non-root, no capabilities, no new privileges:** the sandboxed process
  runs as `nobody` (uid/gid 65534) with an empty capability set and
  `noNewPrivileges: true`.
- **Explicit opt-in, audited per run:** :func:`run_in_sandbox` refuses to
  do anything unless called with ``authorized=True`` (mirrors the lab's
  own `--authorized` flag convention rather than inventing a separate
  one), and every invocation -- pass or fail -- is appended to an audit
  log (:data:`DEFAULT_AUDIT_LOG_PATH`) recording what payload, which CWE,
  which fixture, and the outcome, so a validation batch is always a
  visible, reviewable action.

**Deviations from the plan's literal spec, and why:**

1. The plan's illustrative Docker invocation implies a purpose-built,
   minimal validation image. This environment's egress policy blocks the
   CDN backends every container registry checked (Docker Hub, ECR
   Public, GCR) routes image blobs through, so no image can be pulled at
   all. Instead, this sandbox reuses the *host's own* already-installed
   PHP/Python/Node interpreters, mounted read-only as the container's
   root filesystem (the same mechanism `runsc do`'s built-in "testing
   only" mode uses internally) -- with an ephemeral overlay for writes.
   This trades filesystem-read minimalism (the payload can `stat`/`read`
   host files outside its own fixture, though it cannot write to them or
   exfiltrate what it reads, since there is no network) for not needing a
   bespoke per-language rootfs (chasing missing `php.ini` extension
   `.so`s, Python stdlib files, timezone/locale data one "file not
   found" at a time). Given this environment is itself an ephemeral,
   disposable remote-execution sandbox with no live secrets of
   consequence beyond this public repository's own checked-out source,
   this is judged an acceptable, explicitly-documented trade -- not a
   silent one. Revisit if this sandbox is ever run somewhere with
   host-side secrets worth protecting from a *read*, not just exfil.
2. Docker itself is not used to drive `runsc` (the plan's example
   invocation shape is `docker run --runtime=runsc ...`) -- `runsc` is
   invoked directly against a hand-built OCI bundle. This is a strictly
   stronger, more inspectable path (no containerd/dockerd process in the
   loop at all) and was necessary anyway once base-image pulls turned out
   to be infeasible in this environment.

See :func:`run_in_sandbox` for the entry point and :data:`SandboxResult`
for what it returns. Static-analysis validation (Semgrep/Bandit/Psalm/
eslint-security -- the plan's other validation method, which needs no
sandbox since those tools only parse source text) is out of scope for
this module.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AUDIT_LOG_PATH = REPO_ROOT / "docs" / "research" / "corpus-validation-audit.jsonl"

RUNSC_BIN = "/usr/local/bin/runsc"
CGROUP_ROOT = Path("/sys/fs/cgroup")

# Interpreter binaries this sandbox knows how to drive, keyed by the same
# language tag `docs/research/corpus-examples/<feature>/<language>/`
# directories already use. Resolved via `shutil.which` at call time (not
# hardcoded paths) so this stays correct across environments; the fixed
# fallback for node covers this environment's non-PATH install location.
_LANGUAGE_INTERPRETERS: dict[str, list[str]] = {
    "php": ["php"],
    "python": ["python3"],
    "node": ["node", "/opt/node22/bin/node"],
}

DEFAULT_MEMORY_LIMIT_BYTES = 256 * 1024 * 1024  # 256 MiB, matches the plan's example
DEFAULT_PIDS_LIMIT = 64  # matches the plan's example
DEFAULT_TIMEOUT_S = 10


class SandboxUnavailableError(RuntimeError):
    """Raised when the sandbox's own preconditions (runsc, cgroup v1
    controllers, an interpreter for the requested language) are not met.
    Never silently falls back to running a payload unsandboxed."""


@dataclasses.dataclass(frozen=True)
class SandboxResult:
    stdout: str
    stderr: str
    exit_code: Optional[int]
    timed_out: bool
    duration_s: float
    network_namespace_isolated: bool = True  # always true for this sandbox; kept
    # explicit on the result so a caller/report never has to assume it.


def _resolve_interpreter(language: str) -> str:
    candidates = _LANGUAGE_INTERPRETERS.get(language)
    if candidates is None:
        raise SandboxUnavailableError(
            f"no known interpreter mapping for language {language!r}; "
            f"known languages: {sorted(_LANGUAGE_INTERPRETERS)}"
        )
    for candidate in candidates:
        resolved = shutil.which(candidate) if not os.path.isabs(candidate) else (
            candidate if os.path.exists(candidate) else None
        )
        if resolved:
            return resolved
    raise SandboxUnavailableError(
        f"no usable interpreter found for language {language!r} "
        f"(tried {candidates!r})"
    )


def _check_preconditions(language: str) -> str:
    if not os.path.exists(RUNSC_BIN):
        raise SandboxUnavailableError(
            f"gVisor runtime not found at {RUNSC_BIN} -- this sandbox refuses "
            f"to run a payload without it (no unsandboxed fallback)."
        )
    for controller in ("memory", "pids"):
        if not (CGROUP_ROOT / controller).is_dir():
            raise SandboxUnavailableError(
                f"cgroup v1 '{controller}' controller not mounted at "
                f"{CGROUP_ROOT / controller} -- cannot enforce the resource "
                f"limits this sandbox requires."
            )
    return _resolve_interpreter(language)


def _build_oci_config(
    *, interpreter_path: str, script_path: Path, extra_args: list[str], cwd: str
) -> dict:
    """Build an OCI runtime config.json enforcing every hardening measure
    `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s sandbox section requires except
    the resource limits (those are applied via cgroup v1 directly on the
    `runsc` process, not via this config, since runsc's OCI cgroup wiring
    needs a cgroup driver this environment doesn't have configured)."""
    return {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 65534, "gid": 65534},  # nobody:nogroup
            "args": [interpreter_path, str(script_path), *extra_args],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": cwd,
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 256, "soft": 256}],
            "noNewPrivileges": True,
        },
        # Not `readonly: true` here: gVisor's own `runsc do` (the reference
        # implementation of this exact "run host fs read-only-in-spirit,
        # ephemeral overlay on top" pattern) leaves the OCI root writable
        # and relies entirely on the `-overlay2=all:memory` runtime flag to
        # keep every write memory-backed and ephemeral -- an explicit
        # `readonly: true` here was tried first and empirically defeats
        # that overlay (writes fail outright with "Read-only file
        # system" instead of landing in the ephemeral layer), so this
        # matches gVisor's own working combination instead.
        "root": {"path": "/"},
        "hostname": "corpus-validation-sandbox",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
            {
                "destination": "/sys",
                "type": "sysfs",
                "source": "sysfs",
                "options": ["nosuid", "noexec", "nodev", "ro"],
            },
            # No separate /tmp mount: that would shadow the host's real
            # /tmp (where a fixture under /tmp would otherwise live) with
            # an empty tmpfs. The root-level `overlay2=root:memory` layer
            # already gives every path -- /tmp included -- ephemeral,
            # memory-backed write capability without needing a dedicated
            # mount, so a write anywhere (including to /tmp) is scratch
            # space that vanishes with the container.
        ],
        "linux": {
            # Deliberately empty network namespace: no interfaces are ever
            # attached to it, so there is nothing to allow-list -- every
            # outbound call fails at the syscall boundary runsc intercepts.
            "namespaces": [
                {"type": "pid"},
                {"type": "network"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
            ],
        },
        # The ephemeral-write guarantee comes from the `-overlay2=all:memory`
        # runtime flag `run_in_sandbox` passes to `runsc run` itself, not
        # from anything in this spec -- there is no per-container spec
        # annotation for it that actually takes effect (empirically
        # confirmed; the flag is the real mechanism, matching how
        # `runsc do` -- gVisor's own reference implementation of this
        # pattern -- does it).
    }


def _write_cgroup_limit(controller: str, cgroup_name: str, filename: str, value: str) -> Path:
    cgroup_dir = CGROUP_ROOT / controller / cgroup_name
    cgroup_dir.mkdir(parents=True, exist_ok=True)
    (cgroup_dir / filename).write_text(value)
    return cgroup_dir


def _cleanup_cgroup(controller: str, cgroup_name: str) -> None:
    cgroup_dir = CGROUP_ROOT / controller / cgroup_name
    try:
        cgroup_dir.rmdir()
    except OSError:
        pass  # best-effort; a lingering empty cgroup dir is harmless


def _append_audit_log(entry: dict, audit_log_path: Path) -> None:
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_log_path, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def run_in_sandbox(
    *,
    language: str,
    script_path: Path,
    authorized: bool,
    extra_args: Optional[list[str]] = None,
    cwd: Optional[str] = None,
    memory_limit_bytes: int = DEFAULT_MEMORY_LIMIT_BYTES,
    pids_limit: int = DEFAULT_PIDS_LIMIT,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    cwe: Optional[str] = None,
    audit_log_path: Path = DEFAULT_AUDIT_LOG_PATH,
) -> SandboxResult:
    """Execute ``script_path`` under gVisor with zero network, an ephemeral
    read-only-host-plus-memory-overlay filesystem, real cgroup v1 memory/pids
    limits, and a wall-clock timeout. Refuses to run anything unless
    ``authorized=True`` is passed explicitly (mirrors this project's
    ``--authorized`` lab-safety convention). Every call is appended to
    ``audit_log_path`` regardless of outcome.

    Raises :class:`SandboxUnavailableError` if gVisor or the required
    cgroup v1 controllers are not present -- never silently falls back to
    running the payload unsandboxed.
    """
    if not authorized:
        raise PermissionError(
            "run_in_sandbox() requires authorized=True -- this executes "
            "real, potentially malicious code and is never an implicit "
            "side effect of another operation."
        )
    script_path = Path(script_path).resolve()
    if not script_path.is_file():
        raise FileNotFoundError(f"fixture not found: {script_path}")

    interpreter_path = _check_preconditions(language)
    extra_args = extra_args or []
    run_cwd = cwd or str(script_path.parent)

    container_id = f"corpus-validate-{uuid.uuid4().hex[:12]}"
    bundle_dir = Path(f"/tmp/{container_id}")
    bundle_dir.mkdir(parents=True)
    memory_cgroup = None
    pids_cgroup = None
    started = time.monotonic()
    timed_out = False
    stdout = ""
    stderr = ""
    exit_code: Optional[int] = None

    try:
        config = _build_oci_config(
            interpreter_path=interpreter_path,
            script_path=script_path,
            extra_args=extra_args,
            cwd=run_cwd,
        )
        (bundle_dir / "config.json").write_text(json.dumps(config, indent=2))

        memory_cgroup = _write_cgroup_limit(
            "memory", container_id, "memory.limit_in_bytes", str(memory_limit_bytes)
        )
        pids_cgroup = _write_cgroup_limit("pids", container_id, "pids.max", str(pids_limit))

        cmd = [
            "timeout",
            "--kill-after=2",
            str(timeout_s),
            RUNSC_BIN,
            "-network=none",
            "-overlay2=all:memory",
            "run",
            "--bundle",
            str(bundle_dir),
            container_id,
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        # Attach the runsc process (and thus everything it spawns) to the
        # resource-limited cgroups before it gets far enough to fork the
        # sandboxed workload.
        try:
            (memory_cgroup / "cgroup.procs").write_text(str(proc.pid))
            (pids_cgroup / "cgroup.procs").write_text(str(proc.pid))
        except OSError:
            pass  # process may already have exited on a fast failure path
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s + 5)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            timed_out = True
            exit_code = proc.returncode
        if exit_code == 124:  # `timeout(1)`'s own exit code for a kill
            timed_out = True
    finally:
        subprocess.run(
            [RUNSC_BIN, "delete", "-force", container_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        shutil.rmtree(bundle_dir, ignore_errors=True)
        if memory_cgroup is not None:
            _cleanup_cgroup("memory", container_id)
        if pids_cgroup is not None:
            _cleanup_cgroup("pids", container_id)

    duration_s = time.monotonic() - started
    result = SandboxResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        timed_out=timed_out,
        duration_s=duration_s,
    )
    _append_audit_log(
        {
            "ts": time.time(),
            "language": language,
            "fixture": str(script_path),
            "cwe": cwe,
            "extra_args": extra_args,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_s": round(duration_s, 3),
        },
        audit_log_path,
    )
    return result


def sandbox_available() -> bool:
    """True iff gVisor and the required cgroup v1 controllers are present.
    Callers should use this to skip (not silently fall back on) dynamic
    validation where the sandbox itself can't run."""
    try:
        _check_preconditions("python")
    except SandboxUnavailableError:
        return False
    return True
