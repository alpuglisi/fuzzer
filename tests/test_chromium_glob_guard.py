"""PA-0651: a pre-installed Chromium is looked up under both layouts Playwright installs
(`chrome-linux/` up to its 2025 builds, `chrome-linux64/` since), never under one
spelled out (BUG-0651: every lookup named `chrome-linux/chrome`, matched nothing on a
`chrome-linux64` image, and silently fell back to Playwright's own lookup)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_ONE_LAYOUT = re.compile(r"chrome-linux/chrome")


def one_layout_offenders(sources: dict[str, str]) -> list[str]:
    """``file:line`` of every lookup that names only the old `chrome-linux/` layout."""
    return [f"{rel}:{n}" for rel, src in sources.items()
            for n, line in enumerate(src.splitlines(), 1) if _ONE_LAYOUT.search(line)]


def _sources() -> dict[str, str]:
    out = {}
    for top in ("fuzzlab", "tests", "scripts"):
        for p in (ROOT / top).rglob("*.py"):
            if "__pycache__" in p.parts or p.name == Path(__file__).name:
                continue
            out[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
    return out


def test_no_chromium_lookup_names_one_layout_only():
    assert one_layout_offenders(_sources()) == []


def test_the_guard_catches_a_synthetic_offender():
    bad = {"tests/x.py": 'exe = glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")\n'}
    assert one_layout_offenders(bad) == ["tests/x.py:1"]
    ok = {"tests/y.py": 'glob.glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome")\n'}
    assert one_layout_offenders(ok) == []


def test_the_pattern_matches_both_layouts(tmp_path):
    for layout in ("chrome-linux", "chrome-linux64"):
        exe = tmp_path / f"chromium-1{layout[-2:]}" / layout / "chrome"
        exe.parent.mkdir(parents=True)
        exe.write_text("")
    found = sorted(p.parent.name for p in tmp_path.glob("chromium-*/chrome-linux*/chrome"))
    assert found == ["chrome-linux", "chrome-linux64"]
