"""Runs the shared DataTable's pure-JS unit tests (node:test) under pytest.

No node:test precedent existed in this repo before U2 (checked: no *.test.js/
*.test.mjs, no package.json at the project root) — this is the first, and
follows the R-09 test-strategy note (docs/UI_IMPLEMENTATION_PLAN.md) of using
node's own built-in test runner rather than adding a JS test framework
dependency (no build step / no bundler invariant, §2). Skipped when `node`
isn't on PATH rather than failing the suite.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_JS_TEST = Path(__file__).resolve().parent.parent / "fuzzlab/web/static/js/datatable.test.mjs"


def test_datatable_pure_logic_node_test():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not on PATH")
    result = subprocess.run(
        [node, "--test", str(_JS_TEST)],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, (
        f"datatable.test.mjs failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    assert "# fail 0" in result.stdout
