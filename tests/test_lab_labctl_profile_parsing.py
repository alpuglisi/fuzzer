"""CC-LAB-0247 (Lane 7, Gate E, S5): offline test of `lab/labctl.sh`'s
`PFF_PROFILE` -> `PROFILE_ARGS` splitting logic, without needing a real
compose provider or a live `./labctl.sh up`.

Extracts the exact block between labctl.sh's own
`# PROFILE_ARGS_BLOCK_BEGIN`/`# PROFILE_ARGS_BLOCK_END` sentinel comments
and executes it in a real bash subshell for each `PFF_PROFILE` value,
inspecting the resulting `PROFILE_ARGS` array -- this exercises labctl.sh's
own real logic (PA-0027), not a second, hand-reimplemented copy of it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

LABCTL_PATH = Path("lab/labctl.sh")


def _extract_profile_args_block() -> str:
    text = LABCTL_PATH.read_text(encoding="utf-8")
    begin = text.index("# PROFILE_ARGS_BLOCK_BEGIN")
    end = text.index("# PROFILE_ARGS_BLOCK_END") + len("# PROFILE_ARGS_BLOCK_END")
    return text[begin:end]


def _profile_args_for(pff_profile: str | None) -> list[str]:
    block = _extract_profile_args_block()
    script = block + '\nfor a in "${PROFILE_ARGS[@]}"; do printf "%s\\n" "$a"; done\n'
    env = {}
    if pff_profile is not None:
        env["PFF_PROFILE"] = pff_profile
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=10, env=env,
    )
    assert result.returncode == 0, f"block failed: {result.stderr}"
    return [line for line in result.stdout.split("\n") if line]


def test_block_is_present_and_matches_the_committed_source() -> None:
    # A basic sanity check that the sentinel markers still exist -- if this
    # ever fails, labctl.sh's own logic moved/was renamed and this test's
    # extraction needs updating alongside it.
    block = _extract_profile_args_block()
    assert "PROFILE_ARGS=()" in block
    assert "IFS=','" in block


def test_no_profile_set_yields_empty_profile_args() -> None:
    assert _profile_args_for(None) == []


def test_single_value_unchanged_from_before_this_change() -> None:
    # The pre-existing, single-value case (`PFF_PROFILE=desync`) must be
    # byte-for-byte unchanged.
    assert _profile_args_for("desync") == ["--profile", "desync"]


def test_comma_separated_values_each_get_their_own_profile_flag() -> None:
    assert _profile_args_for("apps,desync") == ["--profile", "apps", "--profile", "desync"]


def test_three_comma_separated_values() -> None:
    assert _profile_args_for("a,b,c") == ["--profile", "a", "--profile", "b", "--profile", "c"]
