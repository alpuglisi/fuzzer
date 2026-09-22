"""Regression coverage for `BUG-0033`/`PA-0035`: `live_boot.live_boot_available()`'s
capability probe must exercise the real, actual operation path (a bounded
composer-driven Packagist round trip) rather than a raw-socket proxy for it,
and every later real subprocess step in the live-boot pipeline (`_run`) must
enforce its own bounded timeout independently of the probe.

Deliberately **not** skip-guarded on `live_boot_available()` itself (unlike
every other `test_labgen_conformance_live_boot*` module) -- these tests
exercise the probe's and `_run`'s own failure-handling code paths via
monkeypatched `subprocess.run`, so they must run everywhere, including a host
with no composer/php/network at all: that is exactly the case this bug was
about (a bounded, honest answer, never a hang), and it must be tested without
itself depending on the thing it is testing the absence of.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance import live_boot


def test_composer_network_probe_returns_false_on_timeout_never_raises(monkeypatch) -> None:
    """A hung `composer show` (the real op the probe exercises) must report
    `False` -- never propagate `subprocess.TimeoutExpired`, and never hang
    the caller. Direct regression for `BUG-0033`'s failure mode."""
    monkeypatch.setattr(live_boot.shutil, "which", lambda name: "/usr/local/bin/composer")

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 20.0))

    monkeypatch.setattr(live_boot.subprocess, "run", _raise_timeout)
    assert live_boot._composer_network_probe(timeout=1.0) is False


def test_composer_network_probe_returns_false_when_composer_missing(monkeypatch) -> None:
    monkeypatch.setattr(live_boot.shutil, "which", lambda name: None)
    assert live_boot._composer_network_probe() is False


def test_composer_network_probe_returns_false_on_nonzero_exit(monkeypatch) -> None:
    """A real composer invocation that runs to completion but fails (e.g. the
    proxy rejects it, DNS fails, Packagist 5xxs) must report unavailable --
    the probe's job is "will the real op succeed", not merely "did something
    run"."""
    monkeypatch.setattr(live_boot.shutil, "which", lambda name: "/usr/local/bin/composer")
    monkeypatch.setattr(
        live_boot.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(args=a[0], returncode=1, stdout="", stderr="boom"),
    )
    assert live_boot._composer_network_probe() is False


def test_composer_network_probe_returns_true_on_success(monkeypatch) -> None:
    monkeypatch.setattr(live_boot.shutil, "which", lambda name: "/usr/local/bin/composer")
    monkeypatch.setattr(
        live_boot.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(args=a[0], returncode=0, stdout="ok", stderr=""),
    )
    assert live_boot._composer_network_probe() is True


def test_composer_network_probe_enforces_a_bounded_timeout(monkeypatch) -> None:
    """The probe must actually pass a `timeout=` through to `subprocess.run`
    -- never rely on composer's own internal timeouts, which is exactly the
    "assume the later real operation is bounded because the probe passed"
    gap `PA-0035` closes."""
    monkeypatch.setattr(live_boot.shutil, "which", lambda name: "/usr/local/bin/composer")
    captured: dict = {}

    def _capture(*args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(live_boot.subprocess, "run", _capture)
    live_boot._composer_network_probe(timeout=3.5)
    assert captured.get("timeout") == 3.5


def test_run_wraps_subprocess_timeout_in_live_boot_error_not_a_hang(monkeypatch) -> None:
    """`_run` (every real subprocess step of the live-boot pipeline --
    `composer install`, `artisan key:generate`, ...) must turn a real
    `subprocess.TimeoutExpired` into an immediate, clearly-worded
    `LiveBootError` -- never let it propagate uncaught and never hang.
    Direct regression for `PA-0035`'s "every later real operation must also
    be independently bounded" requirement."""

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout"), output="partial-out", stderr="partial-err")

    monkeypatch.setattr(live_boot.subprocess, "run", _raise_timeout)
    with pytest.raises(live_boot.LiveBootError, match="did not complete within"):
        live_boot._run(["composer", "install"], cwd=Path("/tmp"), timeout=5.0)


def test_run_passes_through_a_normal_completed_process(monkeypatch) -> None:
    monkeypatch.setattr(
        live_boot.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(args=a[0], returncode=0, stdout="ok", stderr=""),
    )
    result = live_boot._run(["php", "-v"], cwd=Path("/tmp"), timeout=5.0)
    assert result.returncode == 0
    assert result.stdout == "ok"
