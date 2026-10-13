"""`fuzzlab/` stays pyflakes-clean (CC-FUZZ-0055 et al.): unused imports, f-strings with
no placeholder, shadowed redefinitions (a dead duplicate `overview_summary` hid behind
one) and undefined names.

A finding on a line marked ``# noqa`` is a deliberate exception (e.g. a re-exported
vocabulary). pyflakes is a dev dependency (`pip install -e .[dev]`); without it the test
skips — and ``FUZZLAB_REQUIRE_LINT=1`` turns that skip into a failure (PA-0065(2)).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "fuzzlab"


def test_fuzzlab_is_pyflakes_clean():
    try:
        from pyflakes.api import checkPath
        from pyflakes.reporter import Reporter
    except ImportError:
        if os.environ.get("FUZZLAB_REQUIRE_LINT"):
            pytest.fail("pyflakes is required (FUZZLAB_REQUIRE_LINT=1) but not installed")
        pytest.skip("pyflakes not installed (pip install -e .[dev])")

    class _Collect(Reporter):
        def __init__(self):
            self.found: list[str] = []

        def flake(self, message):
            line = Path(message.filename).read_text().splitlines()[message.lineno - 1]
            if "noqa" not in line:
                self.found.append(str(message))

        def unexpectedError(self, filename, msg):
            self.found.append(f"{filename}: {msg}")

        def syntaxError(self, filename, msg, lineno, offset, text):
            self.found.append(f"{filename}:{lineno}: {msg}")

    rep = _Collect()
    for path in sorted(ROOT.rglob("*.py")):
        if "__pycache__" not in path.parts and "skeleton" not in path.parts:
            checkPath(str(path), rep)
    assert rep.found == []
