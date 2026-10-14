"""NFR-LAB-cleanup (BUG-0125): a live-boot harness's ``close()`` -- and a build that
fails after the server started -- leaves no process behind: the port refuses
connections and nothing remains in the server's process group or its supervisor's
session.

Real processes, run **offline**: composer with ``COMPOSER_DISABLE_NETWORK=1`` (and
git limited to ``file://``) installs from the local composer cache, and ``go build``
with ``GOPROXY=off`` (the emitted app is stdlib-only). If the local cache cannot
satisfy the install, the test skips naming that -- it never reaches the network.
Every server binds 127.0.0.1 and receives one local request at most.
"""

from __future__ import annotations

import shutil
import socket

import pytest

from fuzzlab import procutil
from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootError, GoLiveBootHarness
from fuzzlab.labgen.conformance.live_boot import LiveBootError, LiveBootHarness
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("COMPOSER_DISABLE_NETWORK", "1")
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
    monkeypatch.setenv("GOPROXY", "off")


def _cmdline(pid: int) -> list[str]:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return [a.decode() for a in fh.read().split(b"\0") if a]
    except (FileNotFoundError, ProcessLookupError):
        return []


def _assert_nothing_left(server: procutil.ServerHandle, port: int) -> None:
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", port), timeout=2.0).close()
    assert procutil.group_members(server.child_pid, server.child_start_time) == []
    assert procutil.session_members(server.pid, server.start_time) == []
    assert server.proc.returncode is not None  # the supervisor was reaped
    assert server not in procutil.registered()


def _laravel_cells():
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_auth.yaml")
    return [c for c in manifest.cells if c.cell_id == "LABGEN-PLA-0001"]


def _build_or_skip_offline(harness, error_type, step: str) -> None:
    try:
        harness.build()
    except error_type as exc:
        harness.close()
        if step in str(exc):
            pytest.skip(f"offline {step} not satisfiable from the local cache: {str(exc)[:300]}")
        raise


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("php") is None or shutil.which("composer") is None,
                    reason="php + composer required")
def test_laravel_harness_close_leaves_no_process_and_frees_the_port(offline) -> None:
    cells = _laravel_cells()
    harness = LiveBootHarness(LaravelEmitter(), cells)
    _build_or_skip_offline(harness, LiveBootError, "composer install")
    try:
        server, port = harness._server, harness._port
        argv = _cmdline(server.child_pid)
        # the server is PHP's built-in server itself, the supervisor's direct child --
        # never an `artisan serve` parent whose `php -S` child outlives it
        assert argv[:2] == ["php", "-S"] and "artisan" not in " ".join(argv), argv
        assert harness.get(served_url_for(cells[0])).status < 600  # it really serves
        assert procutil.group_members(server.child_pid, server.child_start_time)
    finally:
        harness.close()
    _assert_nothing_left(server, port)


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain required")
def test_go_harness_close_leaves_no_process_and_frees_the_port(offline) -> None:
    manifest = load_manifest("lab/manifests/webhook_signature_go_sample.yaml")
    harness = GoLiveBootHarness(GoEmitter(), manifest.cells)
    _build_or_skip_offline(harness, GoLiveBootError, "go build")
    try:
        server, port = harness._server, harness._port
        assert procutil.group_members(server.child_pid, server.child_start_time)
    finally:
        harness.close()
    _assert_nothing_left(server, port)
    harness.close()  # idempotent


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain required")
def test_a_build_that_fails_after_the_server_started_leaves_nothing(offline, monkeypatch) -> None:
    """``__exit__`` never runs when ``__enter__`` raises: the harness's ``__enter__``
    must close what ``build()`` had already started (a second leak path BUG-0125's
    sweep found in all five harnesses)."""
    seen: dict = {}

    def boot_then_fail(self) -> None:
        seen["server"], seen["port"] = self._server, self._port
        raise GoLiveBootError("simulated boot failure after the server started")

    monkeypatch.setattr(GoLiveBootHarness, "_wait_for_boot", boot_then_fail)
    manifest = load_manifest("lab/manifests/webhook_signature_go_sample.yaml")
    with pytest.raises(GoLiveBootError, match="simulated"):
        with GoLiveBootHarness(GoEmitter(), manifest.cells):
            pass
    server = seen["server"]
    assert procutil.group_members(server.child_pid, server.child_start_time) == []
    assert procutil.session_members(server.pid, server.start_time) == []
    assert server not in procutil.registered()


@pytest.mark.parametrize("module, cls", [
    ("live_boot", "LiveBootHarness"),
    ("go_live_boot", "GoLiveBootHarness"),
    ("rails_live_boot", "RailsLiveBootHarness"),
    ("live_boot_spring_boot", "SpringBootLiveBootHarness"),
    ("django_live_boot", "DjangoLiveBootHarness"),
])
def test_every_harness_starts_through_procutil_and_closes_on_a_failed_enter(module, cls) -> None:
    """All five harnesses, checked without a boot: the server is started by
    ``procutil.start_server``, ``close()`` stops it with ``procutil.stop_server``,
    and ``__enter__`` closes on failure. (The real-process proof is the Laravel and
    Go tests above; Rails, Spring Boot and Django need network installs.)"""
    import importlib
    import inspect

    harness = getattr(importlib.import_module(f"fuzzlab.labgen.conformance.{module}"), cls)
    assert "procutil.start_server(" in inspect.getsource(harness.build)
    assert "procutil.stop_server(" in inspect.getsource(harness.close)
    enter = inspect.getsource(harness.__enter__)
    assert "except BaseException" in enter and "self.close()" in enter
