"""Hermetic tests of the external labs' shell side (CC-LAB-0300, FR-LAB-301): the
dispatch block in ``lab/labctl.sh`` and ``lab/external/extctl.sh``.

Nothing real is reachable: the scripts run with a ``PATH`` holding only stub
``docker``/``podman`` and a stub Python (``FUZZLAB_PYTHON``) that record every call,
plus the few coreutils the scripts use. The dispatch block is extracted by its sentinel
comments and run in a temp directory against a fake ``external/`` tree, so a
not-dispatched subcommand (``snapshot``, ``start``) never runs the real lab's path.
Exit codes are checked on both branches of each option (PA-0016).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from fuzzlab.procutil import run_bounded

REPO = Path(__file__).resolve().parent.parent
LABCTL = REPO / "lab" / "labctl.sh"
EXTCTL = REPO / "lab" / "external" / "extctl.sh"

_TOOLS = ("bash", "sed", "head", "tr", "grep", "dirname", "basename", "cat", "awk", "env", "sh",
          "touch", "rm", "mkdir")

_ENGINE_STUB = r"""#!/bin/bash
# Records argv; answers from state files in $STUB_DIR. A *-compose binary behaves as
# `<engine> compose`.
echo "$(basename "$0") $*" >> "$STUB_DIR/calls"
case "$(basename "$0")" in *-compose) set -- compose "$@" ;; esac
case "$1 $2" in
  "compose version") exit 0 ;;
esac
if [ "$1" = compose ]; then
  for a in "$@"; do
    case "$a" in
      config) cat "$STUB_DIR/config.json"; exit 0 ;;
      up) if [ -f "$STUB_DIR/up_fails" ]; then rm -f "$STUB_DIR/up_fails"; exit 1; fi; exit 0 ;;
      down|ps) exit 0 ;;
    esac
  done
  exit 0
fi
case "$1" in
  ps) if [ -f "$STUB_DIR/ps_fails" ]; then exit 1; fi
      if [ -f "$STUB_DIR/ps_ids" ]; then cat "$STUB_DIR/ps_ids"; fi; exit 0 ;;
  rm) if [ ! -f "$STUB_DIR/sticky" ]; then rm -f "$STUB_DIR/ps_ids"; fi; exit 0 ;;
  network|volume|pod) if [ "$2" = ls ]; then echo "res-$1"; fi; exit 0 ;;
esac
exit 0
"""

_PY_STUB = r"""#!/bin/bash
echo "py $*" >> "$STUB_DIR/calls"
sub="$3"
if [ -f "$STUB_DIR/py_fail_$sub" ]; then exit "$(cat "$STUB_DIR/py_fail_$sub")"; fi
if [ "$sub" = info ]; then echo "fuzzlab-x 8092 http://127.0.0.1:8092/bWAPP/"; fi
exit 0
"""


@pytest.fixture
def stubs(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in _TOOLS:
        real = shutil.which(tool)
        assert real, tool
        (bindir / tool).symlink_to(real)
    for name in ("docker", "podman", "podman-compose"):
        (bindir / name).write_text(_ENGINE_STUB)
        (bindir / name).chmod(0o755)
    py = tmp_path / "py"
    py.write_text(_PY_STUB)
    py.chmod(0o755)
    (tmp_path / "config.json").write_text('{"services": {}}')
    return tmp_path


def _env(stubs: Path, **extra: str) -> dict[str, str]:
    env = {"PATH": str(stubs / "bin"), "STUB_DIR": str(stubs),
           "FUZZLAB_PYTHON": str(stubs / "py"), "HOME": str(stubs)}
    env.update(extra)
    return env


def _calls(stubs: Path) -> list[str]:
    f = stubs / "calls"
    return f.read_text().splitlines() if f.exists() else []


def _ext(stubs, *args, compose="docker compose", **env):
    e = _env(stubs, **env)
    if compose is not None:
        e["LABCTL_COMPOSE"] = compose
    return run_bounded([str(EXTCTL), *args], timeout=60, env=e)


# --- the dispatch block (lab/labctl.sh) ----------------------------------------------------

def _dispatch_block() -> str:
    text = LABCTL.read_text(encoding="utf-8")
    begin = text.index("# EXTERNAL_DISPATCH_BLOCK_BEGIN")
    end = text.index("# EXTERNAL_DISPATCH_BLOCK_END")
    return text[begin:end]


@pytest.fixture
def fake_lab(tmp_path, stubs):
    lab = tmp_path / "lab"
    (lab / "external" / "bwapp").mkdir(parents=True)
    (lab / "external" / "bwapp" / "compose.yaml").write_text("name: x\n")
    ext = lab / "external" / "extctl.sh"
    ext.write_text('#!/bin/bash\necho "DISPATCHED $* [$LABCTL_COMPOSE]"\n')
    ext.chmod(0o755)
    return lab


def _run_dispatch(fake_lab, stubs, *args):
    script = ("set -euo pipefail\nCOMPOSE=(docker compose)\n" + _dispatch_block()
              + '\necho "NOT_DISPATCHED $*"\n')
    return run_bounded(["bash", "-c", script, "labctl.sh", *args], timeout=30,
                       cwd=str(fake_lab), env=_env(stubs))


@pytest.mark.parametrize("args", [["up", "bwapp"], ["down", "bwapp"], ["status", "bwapp"],
                                  ["reset", "bwapp"], ["bootstrap", "bwapp", "--authorized"],
                                  ["up", "bwapp", "--authorized"]])
def test_external_lifecycle_commands_are_dispatched(fake_lab, stubs, args):
    res = _run_dispatch(fake_lab, stubs, *args)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == f"DISPATCHED {' '.join(args)} [docker compose]"


@pytest.mark.parametrize("args", [
    ["snapshot", "bwapp"], ["restore", "bwapp"], ["start", "bwapp"], ["stop", "bwapp"],
    ["up", "--authorized"], ["up"], ["down"], ["up", "nosuchlab"], ["up", "../bwapp"],
    ["up", "Bwapp"], ["up", "bwapp/../bwapp"], ["logs", "bwapp"], ["exec", "bwapp"],
])
def test_other_commands_keep_their_meaning(fake_lab, stubs, args):
    res = _run_dispatch(fake_lab, stubs, *args)
    assert res.returncode == 0, res.stderr
    assert res.stdout.startswith("NOT_DISPATCHED"), res.stdout


def test_the_dispatch_block_sits_before_the_main_case():
    text = LABCTL.read_text(encoding="utf-8")
    assert text.index("# EXTERNAL_DISPATCH_BLOCK_END") < text.index('case "${1:-}" in\n  up)')
    assert text.index("# PROFILE_ARGS_BLOCK_END") < text.index("# EXTERNAL_DISPATCH_BLOCK_BEGIN")


# --- extctl.sh ------------------------------------------------------------------------

def test_both_scripts_parse():
    for path in (LABCTL, EXTCTL):
        assert run_bounded(["bash", "-n", str(path)], timeout=30).returncode == 0, path


def test_extctl_refuses_to_run_without_labctl(stubs):
    res = _ext(stubs, "up", "bwapp", compose=None)
    assert res.returncode == 2 and "labctl.sh" in res.stderr
    assert _calls(stubs) == []


@pytest.mark.parametrize("args,extra", [
    (["up", "nosuchlab"], {}), (["up", "../bwapp"], {}), (["up", ""], {}),
    (["up", "bwapp", "--bogus"], {}),
    (["up", "bwapp"], {"FUZZLAB_EXT_PROJECT_SUFFIX": "-A;rm"}),
])
def test_extctl_refuses_bad_input_before_any_call(stubs, args, extra):
    res = _ext(stubs, *args, **extra)
    assert res.returncode == 2
    assert _calls(stubs) == []


def test_bootstrap_without_authorized_sends_nothing(stubs):
    res = _ext(stubs, "bootstrap", "bwapp")
    assert res.returncode == 2 and "--authorized" in res.stderr
    assert not any(c.startswith("py ") for c in _calls(stubs))


_BOOT = ("py -m fuzzlab.lab_fixtures.external bootstrap bwapp --authorized --engine docker "
         "--project fuzzlab-bwapp")


def test_bootstrap_with_authorized_targets_the_running_project(stubs):
    res = _ext(stubs, "bootstrap", "bwapp", "--authorized")
    assert res.returncode == 0, res.stderr
    assert _calls(stubs) == [_BOOT]


def _dc(project="fuzzlab-bwapp", lab="bwapp"):
    return f"docker compose -p {project} -f {lab}/compose.yaml"


def test_the_preflight_never_dies_of_sigpipe_when_its_checker_stops_reading(stubs):
    """The resolved config used to be piped into the checker (`printf | _py check-config`)
    under ``set -o pipefail``. A checker that exits without reading all of it (here the
    stub, which reads nothing; in production any early exit, e.g. an argument error)
    kills the writer with SIGPIPE: ``up`` exits 141 with no message. That happened once,
    under parallel load, on the 2026-10-15 integration run. A config larger than a pipe
    buffer makes it deterministic."""
    (stubs / "config.json").write_text('{"services": {}, "pad": "' + "x" * 300_000 + '"}')
    res = _ext(stubs, "up", "bwapp")
    assert res.returncode != 141, "SIGPIPE: the preflight still pipes into its checker"
    assert res.returncode == 0, res.stderr

@pytest.mark.parametrize("authorized", [False, True])
def test_up_preflights_starts_checks_exposure_and_bootstraps_only_when_authorized(stubs,
                                                                                    authorized):
    res = _ext(stubs, "up", "bwapp", *(["--authorized"] if authorized else []))
    assert res.returncode == 0, res.stderr
    py = "py -m fuzzlab.lab_fixtures.external"
    expected = [f"{py} info bwapp", f"{py} fetch bwapp", f"{_dc()} config --format json",
                f"{py} check-config bwapp", f"{_dc()} up -d --build",
                f"{py} check-exposure bwapp --engine docker --project fuzzlab-bwapp"]
    if authorized:
        expected.append(_BOOT)
    assert _calls(stubs) == expected
    assert "http://127.0.0.1:8092/bWAPP/" in res.stdout


def test_up_refuses_a_config_that_fails_the_preflight(stubs):
    (stubs / "py_fail_check-config").write_text("1")
    res = _ext(stubs, "up", "bwapp")
    assert res.returncode != 0
    assert not any(" up -d" in c for c in _calls(stubs))


def test_up_tears_down_an_exposed_stack_and_exits_3(stubs):
    (stubs / "py_fail_check-exposure").write_text("3")
    (stubs / "ps_ids").write_text("c1\nc2\n")
    res = _ext(stubs, "up", "bwapp", "--authorized")
    calls = _calls(stubs)
    assert res.returncode == 3
    assert f"{_dc()} down -v --remove-orphans" in calls
    assert "docker rm -f c1 c2" in calls                      # force-clean by listed ids
    assert any(c.startswith("docker volume rm -f") for c in calls)
    assert not any("bootstrap" in c for c in calls)


def test_up_retries_once_through_the_force_clean(stubs):
    (stubs / "up_fails").write_text("")
    (stubs / "ps_ids").write_text("c1\n")
    res = _ext(stubs, "up", "juice-shop")
    calls = _calls(stubs)
    assert res.returncode == 0, res.stderr
    assert calls.count(f"{_dc('fuzzlab-juice-shop', 'juice-shop')} up -d --build") == 2
    assert "docker rm -f c1" in calls
    assert ("docker ps -a -q --filter label=com.docker.compose.project=fuzzlab-juice-shop"
            in calls)


def test_down_checks_exposure_first_and_force_cleans_leftovers(stubs):
    (stubs / "ps_ids").write_text("c1\n")
    res = _ext(stubs, "down", "bwapp")
    calls = _calls(stubs)
    assert res.returncode == 0, res.stderr
    exposure = next(i for i, c in enumerate(calls) if "check-exposure" in c)
    assert exposure < calls.index(f"{_dc()} down --remove-orphans")
    assert "docker rm -f c1" in calls
    assert not any("volume rm" in c for c in calls)            # down keeps data volumes


def test_an_exposed_stack_that_cannot_be_removed_is_reported_loudly(stubs):
    (stubs / "py_fail_check-exposure").write_text("3")
    (stubs / "ps_ids").write_text("c1\n")
    (stubs / "sticky").write_text("")
    res = _ext(stubs, "up", "bwapp")
    assert res.returncode == 3 and "EXPOSED STACK STILL RUNNING" in res.stderr


def test_down_on_an_engine_error_never_reports_success(stubs):
    (stubs / "ps_fails").write_text("")
    res = _ext(stubs, "down", "bwapp")
    assert res.returncode == 1 and "remain" in res.stderr


def test_status_on_an_engine_error_is_its_own_failure(stubs):
    (stubs / "ps_fails").write_text("")
    assert _ext(stubs, "status", "bwapp").returncode == 2


def test_down_of_a_stopped_lab_does_not_warn(stubs):
    res = _ext(stubs, "down", "bwapp")
    assert res.returncode == 0 and "warning" not in res.stderr
    assert not any("check-exposure" in c for c in _calls(stubs))


def test_down_fails_when_containers_survive_the_force_clean(stubs):
    (stubs / "ps_ids").write_text("c1\n")
    (stubs / "sticky").write_text("")
    res = _ext(stubs, "down", "bwapp")
    assert res.returncode == 1 and "remain" in res.stderr


def test_a_failed_exposure_check_never_aborts_down(stubs):
    (stubs / "py_fail_check-exposure").write_text("3")
    (stubs / "ps_ids").write_text("c1\n")
    res = _ext(stubs, "down", "bwapp")
    assert res.returncode == 0 and "warning" in res.stderr
    assert f"{_dc()} down --remove-orphans" in _calls(stubs)


def test_reset_drops_volumes_then_runs_up(stubs):
    res = _ext(stubs, "reset", "bwapp")
    calls = _calls(stubs)
    assert res.returncode == 0, res.stderr
    assert calls[0] == f"{_dc()} down -v --remove-orphans"
    assert "docker volume ls -q --filter label=com.docker.compose.project=fuzzlab-bwapp" in calls
    assert "docker volume rm -f res-volume" in calls
    assert calls.index("docker volume rm -f res-volume") < calls.index(f"{_dc()} up -d --build")


@pytest.mark.parametrize("ids,exposure_rc,want", [("", None, 1), ("c1\n", None, 0),
                                                  ("c1\n", "3", 3)])
def test_status_exit_codes(stubs, ids, exposure_rc, want):
    if ids:
        (stubs / "ps_ids").write_text(ids)
    if exposure_rc:
        (stubs / "py_fail_check-exposure").write_text(exposure_rc)
    assert _ext(stubs, "status", "bwapp").returncode == want


def test_a_project_suffix_isolates_every_call(stubs):
    res = _ext(stubs, "down", "bwapp", FUZZLAB_EXT_PROJECT_SUFFIX="-pytest-1")
    assert res.returncode == 0, res.stderr
    for c in _calls(stubs):
        if "fuzzlab-bwapp" in c:
            assert "fuzzlab-bwapp-pytest-1" in c, c


@pytest.mark.parametrize("compose,dc", [
    ("podman-compose", "podman-compose -p fuzzlab-bwapp -f bwapp/compose.yaml down --remove-orphans"),
    ("podman compose", "podman compose -p fuzzlab-bwapp -f bwapp/compose.yaml down --remove-orphans"),
])
def test_the_podman_provider_uses_the_podman_engine_and_removes_its_pod(stubs, compose, dc):
    (stubs / "ps_ids").write_text("c1\n")
    res = _ext(stubs, "down", "bwapp", compose=compose)
    calls = _calls(stubs)
    assert res.returncode == 0, res.stderr
    assert dc in calls
    assert "podman rm -f c1" in calls
    assert "podman pod rm -f res-pod" in calls
    assert any("--engine podman" in c for c in calls)
    assert not any(c.startswith("docker ") for c in calls)


def test_an_unknown_provider_is_refused(stubs):
    assert _ext(stubs, "status", "bwapp", compose="nerdctl compose").returncode == 2


def test_no_lifecycle_op_removes_anything_by_name_pattern():
    text = EXTCTL.read_text(encoding="utf-8")
    assert "pkill" not in text and "killall" not in text
    for line in text.splitlines():
        if " rm " in line and "ENGINE" in line:
            assert '"${ids[@]}"' in line, line
    assert os.access(EXTCTL, os.X_OK)
