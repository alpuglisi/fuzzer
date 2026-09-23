"""Real, end-to-end tests for `fuzzlab.tools.corpus_validation_sandbox` --
the dynamic-execution sandbox `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s
"Validation execution sandbox" section requires before any collected/
manufactured vulnerable-vs-idiomatic pair can be dynamically validated.

Every test here spins up a real gVisor (`runsc`) container -- no mocking of
the containment boundary, since a mock would prove nothing about whether
the actual protection holds. Skip-guarded on the module's own
`sandbox_available()` capability probe (same convention as this suite's
`slow` marker's `live_boot_available()` guard) so this degrades to a clean
skip, never a failure, wherever `runsc` or the cgroup v1 `memory`/`pids`
controllers are absent.
"""

from __future__ import annotations

import json
import shutil
import stat
import uuid
from pathlib import Path

import pytest

from fuzzlab.tools.corpus_validation_sandbox import (
    SandboxUnavailableError,
    run_in_sandbox,
    sandbox_available,
)

pytestmark = [
    pytest.mark.slow,
    pytest.mark.sandbox,
    pytest.mark.skipif(
        not sandbox_available(),
        reason="gVisor (runsc) or cgroup v1 memory/pids controllers not available in this environment",
    ),
]


@pytest.fixture()
def fixtures_dir():
    """A scratch directory the sandbox's non-root (uid 65534) process can
    actually traverse into as its working directory. pytest's own
    `tmp_path` lives under `/tmp/pytest-of-<user>/pytest-<n>/...`, whose
    intermediate directories are created root-only (0700) -- fine for the
    test process itself, but the sandboxed process running as `nobody`
    gets `permission denied` just trying to `chdir` into it, independent
    of anything this sandbox is supposed to contain. A dedicated,
    world-traversable directory sidesteps that pytest-fixture-specific
    permission quirk without loosening anything the sandbox itself
    enforces."""
    path = Path(f"/tmp/corpus-sandbox-test-{uuid.uuid4().hex[:12]}")
    path.mkdir(mode=0o755)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _write(fixtures_dir: Path, name: str, content: str) -> Path:
    path = fixtures_dir / name
    path.write_text(content)
    return path


def test_authorized_false_refuses_without_running_anything(fixtures_dir: Path) -> None:
    script = _write(fixtures_dir, "noop.php", "<?php echo 'should never run';")
    with pytest.raises(PermissionError):
        run_in_sandbox(language="php", script_path=script, authorized=False)


def test_missing_fixture_raises_file_not_found(fixtures_dir: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run_in_sandbox(
            language="php",
            script_path=fixtures_dir / "does-not-exist.php",
            authorized=True,
        )


def test_unknown_language_raises_sandbox_unavailable(fixtures_dir: Path) -> None:
    script = _write(fixtures_dir, "x.rb", "puts 'hi'")
    with pytest.raises(SandboxUnavailableError):
        run_in_sandbox(language="ruby-nonexistent", script_path=script, authorized=True)


def test_php_executes_and_reports_a_non_root_uid(fixtures_dir: Path) -> None:
    script = _write(
        fixtures_dir,
        "whoami.php",
        "<?php echo 'uid=' . posix_getuid() . PHP_EOL;",
    )
    result = run_in_sandbox(language="php", script_path=script, authorized=True, cwe="TEST-BASIC")
    assert result.exit_code == 0
    assert not result.timed_out
    # 65534 is nobody:nogroup -- proves the sandboxed process is not root.
    assert "uid=65534" in result.stdout


def test_python_executes(fixtures_dir: Path) -> None:
    script = _write(fixtures_dir, "hello.py", "print('hello-from-python-sandbox')")
    result = run_in_sandbox(language="python", script_path=script, authorized=True)
    assert result.exit_code == 0
    assert "hello-from-python-sandbox" in result.stdout


def test_node_executes(fixtures_dir: Path) -> None:
    script = _write(fixtures_dir, "hello.js", "console.log('hello-from-node-sandbox');")
    result = run_in_sandbox(language="node", script_path=script, authorized=True)
    assert result.exit_code == 0
    assert "hello-from-node-sandbox" in result.stdout


def test_network_is_genuinely_unreachable(fixtures_dir: Path) -> None:
    """The core containment claim for SSRF-shaped payloads: an outbound
    connection attempt must fail at the kernel-facing boundary, not merely
    time out slowly or succeed against an unexpected local target."""
    script = _write(
        fixtures_dir,
        "ssrf_probe.php",
        """<?php
$ctx = stream_context_create(['http' => ['timeout' => 3]]);
$result = @file_get_contents('http://8.8.8.8/', false, $ctx);
echo $result === false ? 'NETWORK_BLOCKED' : 'NETWORK_REACHED';
""",
    )
    result = run_in_sandbox(
        language="php", script_path=script, authorized=True, timeout_s=8, cwe="TEST-SSRF"
    )
    assert not result.timed_out
    assert "NETWORK_BLOCKED" in result.stdout
    assert "NETWORK_REACHED" not in result.stdout


def test_filesystem_writes_never_reach_the_real_host(fixtures_dir: Path) -> None:
    """The ephemeral-overlay containment claim: a write the sandboxed
    process makes must not survive past the container's own lifetime.
    Targets a path under /tmp itself (mode 1777, world-writable) rather
    than `fixtures_dir` (root-owned 0755) -- the sandboxed process runs as
    `nobody` and, correctly, has no write bit on a root-owned 0755
    directory at all, same as it would outside the sandbox; that's an
    ordinary POSIX permission check, not something this test is about.
    /tmp mirrors the realistic case a path-traversal payload targets: a
    world-writable location outside the fixture's own directory."""
    marker_path = Path(f"/tmp/should-never-persist-{fixtures_dir.name}.txt")
    assert not marker_path.exists()
    script = _write(
        fixtures_dir,
        "path_traversal_write.php",
        f"<?php file_put_contents({json.dumps(str(marker_path))}, 'written-by-sandbox');"
        f" echo file_exists({json.dumps(str(marker_path))}) ? 'WROTE_OK' : 'WRITE_FAILED';",
    )
    result = run_in_sandbox(language="php", script_path=script, authorized=True)
    # The write must succeed *inside* the sandbox (proves the overlay is
    # actually writable, not that writes are simply rejected outright)...
    assert "WROTE_OK" in result.stdout
    # ...but must never land on the real host filesystem once the
    # container is torn down.
    assert not marker_path.exists()


def test_memory_limit_is_enforced(fixtures_dir: Path) -> None:
    script = _write(
        fixtures_dir,
        "memory_hog.php",
        """<?php
$blocks = [];
for ($i = 0; $i < 200; $i++) {
    $blocks[] = str_repeat('A', 10 * 1024 * 1024);
}
echo 'SHOULD_NOT_REACH_HERE';
""",
    )
    result = run_in_sandbox(
        language="php",
        script_path=script,
        authorized=True,
        memory_limit_bytes=64 * 1024 * 1024,
        timeout_s=10,
        cwe="TEST-MEMORY",
    )
    assert "SHOULD_NOT_REACH_HERE" not in result.stdout
    # 137 = 128 + SIGKILL(9): the memory cgroup OOM-killed the process.
    assert result.exit_code == 137


def test_pids_limit_bounds_a_fork_bomb(fixtures_dir: Path) -> None:
    script = _write(
        fixtures_dir,
        "fork_bomb.py",
        """
import os
count = 0
try:
    while True:
        os.fork()
        count += 1
except OSError:
    pass
""",
    )
    result = run_in_sandbox(
        language="python",
        script_path=script,
        authorized=True,
        pids_limit=64,
        timeout_s=10,
        cwe="TEST-FORKBOMB",
    )
    # The specific exit code a bounded fork loop ends on isn't the
    # contract here (it can legitimately vary) -- what matters is that it
    # terminates well inside the wall-clock timeout instead of running
    # away, proving the pids cgroup actually capped it rather than the
    # sandbox being generously fast.
    assert not result.timed_out
    assert result.duration_s < 8


def test_wall_clock_timeout_kills_a_hanging_process(fixtures_dir: Path) -> None:
    script = _write(fixtures_dir, "hang.php", "<?php while (true) {}")
    result = run_in_sandbox(language="php", script_path=script, authorized=True, timeout_s=3)
    assert result.timed_out
    # Generous upper bound: must die close to the requested timeout, not
    # merely "eventually" (proves the kill actually fires, not that the
    # test happened to finish before some much longer real deadline).
    assert result.duration_s < 8


def test_audit_log_records_every_call(fixtures_dir: Path, tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    script = _write(fixtures_dir, "audited.php", "<?php echo 'ok';")
    run_in_sandbox(
        language="php",
        script_path=script,
        authorized=True,
        cwe="CWE-999-TEST",
        audit_log_path=audit_log,
    )
    assert audit_log.exists()
    lines = audit_log.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["cwe"] == "CWE-999-TEST"
    assert entry["language"] == "php"
    assert entry["exit_code"] == 0
    assert entry["timed_out"] is False
