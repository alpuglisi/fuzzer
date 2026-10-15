"""The Laravel live-boot dependency cache and the cached toolchain probes (BUG-0142).

Every Laravel live boot used to run its own ``composer install`` of the same locked
409 MB ``vendor/`` (27-52 s each), and every live-boot test module re-ran a network
probe at import (121 s to collect the Laravel files). These tests pin the replacement
without touching the network: ``composer`` is replaced by a fake that writes a small
``vendor/``.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance import (
    django_live_boot,
    go_live_boot,
    live_boot,
    live_boot_spring_boot,
    rails_live_boot,
)


@pytest.fixture
def fake_skeleton(tmp_path, monkeypatch):
    skel = tmp_path / "skeleton"
    (skel / "app").mkdir(parents=True)
    (skel / "composer.json").write_text('{"name": "x"}')
    (skel / "composer.lock").write_text('{"packages": ["a/b 1.0"]}')
    monkeypatch.setattr(live_boot, "SKELETON_DIR", skel)
    monkeypatch.setattr(live_boot, "_toolchain_versions", lambda: "php 8.3\ncomposer 2")
    monkeypatch.setenv(live_boot.VENDOR_CACHE_ENV, str(tmp_path / "cache"))
    installs: list[Path] = []

    def fake_run(cmd, *, cwd, timeout, env=None):
        assert cmd[:2] == ["composer", "install"] and "--no-scripts" in cmd
        installs.append(Path(cwd))
        vendor = Path(cwd) / "vendor"
        (vendor / "laravel" / "framework").mkdir(parents=True)
        (vendor / "laravel" / "framework" / "Kernel.php").write_text("<?php // package")
        (vendor / "composer").mkdir()
        (vendor / "composer" / "autoload_classmap.php").write_text("<?php // skeleton map")
        (vendor / "autoload.php").write_text("<?php // loader")
        (vendor / "bin").mkdir()
        os.symlink("../laravel/framework/Kernel.php", vendor / "bin" / "kernel")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(live_boot, "_run", fake_run)
    return installs


def test_the_locked_dependencies_are_installed_once_per_host(fake_skeleton):
    first = live_boot.cached_vendor(60.0)
    second = live_boot.cached_vendor(60.0)
    assert first == second and (first / "laravel" / "framework" / "Kernel.php").is_file()
    assert len(fake_skeleton) == 1
    assert (first.parent / "complete").is_file()


def test_an_interrupted_build_is_rebuilt_not_trusted(fake_skeleton):
    vendor = live_boot.cached_vendor(60.0)
    (vendor.parent / "complete").unlink()  # as if the process died before publishing
    live_boot.cached_vendor(60.0)
    assert len(fake_skeleton) == 2


def test_a_failed_install_publishes_nothing(fake_skeleton, monkeypatch):
    monkeypatch.setattr(live_boot, "_run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "out", "boom"))
    with pytest.raises(live_boot.LiveBootError, match="composer install failed"):
        live_boot.cached_vendor(60.0)
    root = live_boot._vendor_cache_root()
    assert not (root / live_boot.vendor_cache_key()).exists()
    assert not [p for p in root.iterdir() if ".build-" in p.name]


def test_the_cache_key_follows_the_lock_file(fake_skeleton):
    before = live_boot.vendor_cache_key()
    (live_boot.SKELETON_DIR / "composer.lock").write_text('{"packages": ["a/b 2.0"]}')
    assert live_boot.vendor_cache_key() != before


def test_each_app_gets_its_own_autoloader_and_shared_package_files(fake_skeleton, tmp_path):
    cached = live_boot.cached_vendor(60.0)
    app_vendor = tmp_path / "app" / "vendor"
    live_boot.materialize_vendor(cached, app_vendor)
    package = "laravel/framework/Kernel.php"
    assert os.stat(app_vendor / package).st_ino == os.stat(cached / package).st_ino
    for own in ("composer/autoload_classmap.php", "autoload.php"):
        assert os.stat(app_vendor / own).st_ino != os.stat(cached / own).st_ino
    assert os.readlink(app_vendor / "bin" / "kernel") == "../laravel/framework/Kernel.php"
    # What dump-autoload does to the app's copy never reaches the shared cache.
    (app_vendor / "composer" / "autoload_classmap.php").write_text("<?php // app map")
    (app_vendor / "autoload.php").write_text("<?php // app loader")
    assert (cached / "composer" / "autoload_classmap.php").read_text() == "<?php // skeleton map"
    assert (cached / "autoload.php").read_text() == "<?php // loader"


def test_the_harness_never_runs_a_per_boot_install():
    """The per-app step is dump-autoload; composer install appears only in the cache build."""
    import inspect
    build = inspect.getsource(live_boot.LiveBootHarness.build)
    assert '"install"' not in build and "cached_vendor(" in build and '"dump-autoload"' in build


@pytest.mark.parametrize("module, available, probe", [
    (live_boot, "live_boot_available", "_composer_network_probe"),
    (live_boot_spring_boot, "spring_boot_boot_available", "_maven_network_probe"),
    (rails_live_boot, "rails_boot_available", "_bundle_network_probe"),
    (django_live_boot, "django_boot_available", "_pip_network_probe"),
    (go_live_boot, "go_boot_available", "_go_module_proxy_probe"),
])
def test_each_toolchain_check_runs_once_per_process_and_its_probe_stays_testable(
        module, available, probe):
    assert hasattr(getattr(module, available), "cache_info"), f"{available} is not cached"
    # The probe's own tests patch its environment and call it repeatedly (BUG-0142's
    # first attempt cached the probe and broke them).
    assert not hasattr(getattr(module, probe), "cache_info"), f"{probe} must not be cached"


# ---------------------------------------------------------------- Django venv cache


@pytest.fixture
def fake_pip(tmp_path, monkeypatch):
    monkeypatch.setenv(django_live_boot.VENV_CACHE_ENV, str(tmp_path / "venvs"))
    calls: list[list[str]] = []

    def fake_run(cmd, *, cwd, timeout, env=None):
        calls.append(cmd)
        if cmd[1:3] == ["-m", "venv"]:
            (Path(cmd[3]) / "bin").mkdir(parents=True)
            (Path(cmd[3]) / "bin" / "python").write_text("#!/bin/sh\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(django_live_boot, "_run", fake_run)
    return calls


def test_the_pinned_django_environment_is_built_once_per_host(fake_pip):
    first = django_live_boot.cached_venv(60.0)
    assert django_live_boot.cached_venv(60.0) == first
    assert [c[1:3] if c[1:3] == ["-m", "venv"] else c[1:2] for c in fake_pip] == [
        ["-m", "venv"], ["install"]]
    assert django_live_boot.DJANGO_PIN in fake_pip[1]
    assert (first.parent / "complete").is_file()


def test_a_failed_django_install_leaves_nothing_to_reuse(fake_pip, monkeypatch):
    def failing(cmd, *, cwd, timeout, env=None):
        if cmd[1:3] == ["-m", "venv"]:
            (Path(cmd[3]) / "bin").mkdir(parents=True)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 1, "", "no network")

    monkeypatch.setattr(django_live_boot, "_run", failing)
    with pytest.raises(django_live_boot.LiveBootError, match="pip install"):
        django_live_boot.cached_venv(60.0)
    assert not (django_live_boot._venv_cache_root() / django_live_boot.venv_cache_key()).exists()


def test_the_django_harness_never_builds_a_per_boot_environment():
    import inspect
    build = inspect.getsource(django_live_boot.DjangoLiveBootHarness.build)
    assert '"venv"' not in build and '"install"' not in build and "cached_venv(" in build
