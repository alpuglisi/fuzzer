"""BUG-0671 / PA-0671: no test, script or module chooses a browser binary by its install
path.

`scripts/verify_change.py` and eleven test helpers each globbed
``/opt/pw-browsers/chromium-*/chrome-linux/chrome`` and, when it matched, set
``PLAYWRIGHT_CHROMIUM_EXECUTABLE``: the suite ran the **full** Chromium, while the
product -- with no operator setting -- launches Playwright's default, the **headless
shell**. When Playwright's layout became ``chrome-linux64/`` the globs matched nothing
and every browser test moved to the headless shell without a word, which is how
BUG-0670 (an empty 404 is a page on the shell, an error page on the full browser)
surfaced as five "DID NOT RAISE" failures instead of as a measured browser difference.

Now a test launches the product's binary (the operator's
``PLAYWRIGHT_CHROMIUM_EXECUTABLE``, else Playwright's default), and a fact that differs
between binaries is measured on each by name (`tests/_browser.py::CHROMIUM_BINARIES`:
Playwright's own ``channel``, never a path). This guard flags a browser install path
in any Python file of ``fuzzlab/``, ``scripts/`` or ``tests/``.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
#: a browser install location or a binary path inside one
_INSTALL_PATH = re.compile(r"pw-browsers|ms-playwright|chrome-linux(?:64)?/|"
                           r"chrome-headless-shell-linux|chromium[-_]\d{3,}|headless_shell-\d")


def install_path_sites(files: dict[str, str]) -> list[str]:
    """``rel:line`` of every line naming a browser install path."""
    return [f"{rel}:{n}" for rel, text in sorted(files.items())
            for n, line in enumerate(text.splitlines(), 1) if _INSTALL_PATH.search(line)]


def _python_files() -> dict[str, str]:
    me = Path(__file__).resolve()
    return {str(p.relative_to(ROOT)): p.read_text(encoding="utf-8", errors="replace")
            for d in ("fuzzlab", "scripts", "tests") for p in (ROOT / d).rglob("*.py")
            if p.resolve() != me and "__pycache__" not in p.parts}


def test_no_python_file_chooses_a_browser_binary_by_its_install_path():
    assert install_path_sites(_python_files()) == []


def test_the_install_path_guard_catches_synthetic_offenders():
    files = {
        "tests/a.py": 'exe = glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")',
        "scripts/b.py": 'p = Path.home() / ".cache/ms-playwright"',
        "fuzzlab/c.py": 'x = "/x/chrome-linux64/chrome"',
        "tests/d.py": 'y = "chromium_headless_shell-1243"',
        "tests/fine.py": 'kw = {"channel": "chromium"}\nos.environ.get("PLAYWRIGHT_X")',
    }
    assert install_path_sites(files) == ["fuzzlab/c.py:1", "scripts/b.py:1", "tests/a.py:1",
                                         "tests/d.py:1"]
