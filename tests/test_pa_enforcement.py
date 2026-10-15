"""Every preventive action names what enforces it.

Every ``PA-NNNN`` entry in ``docs/PREVENTIVE_ACTIONS.md`` ends with exactly one line:

* ``- Enforced by: tests/<file>.py::<test>[, tests/<file>.py::<test> ...]``, or
* ``- Enforced by: none — <reason>``.

A named test must exist: its file, and a test function (or ``Class::method``) of that
name, resolved by AST -- nothing is imported. The share of PAs enforced by ``none`` is
reported as a warning, not a failure: the retrospective of BUG-0110..BUG-0139 found
that every one of those bugs happened while a prose PA already applied, so the count is
kept visible. The checker itself is proven on synthetic offenders (PA-0034(2)).
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PA_DOC = ROOT / "docs" / "PREVENTIVE_ACTIONS.md"
pytestmark = pytest.mark.package_guard

ENTRY_START = re.compile(r"^- \*\*(PA-\d{4})\b")
ENFORCED = re.compile(r"^\s*- Enforced by: (.*)$")
TEST_REF = re.compile(r"^(tests/[\w/]+\.py)::(\w+(?:::\w+)?)$")
NONE_PREFIX = "none — "


@dataclass
class Entry:
    pa: str
    lines: list[str]


def parse_entries(text: str) -> list[Entry]:
    """Split the register into PA entries. An entry runs from its ``- **PA-NNNN**``
    bullet to the next one, the next heading, or the end of the file."""
    entries: list[Entry] = []
    cur: Entry | None = None
    for line in text.splitlines():
        m = ENTRY_START.match(line)
        if m:
            cur = Entry(m.group(1), [line])
            entries.append(cur)
        elif line.startswith("#"):
            cur = None
        elif cur is not None:
            cur.lines.append(line)
    return entries


def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(f"{node.name}::{sub.name}")
    return names


def check_entry(entry: Entry, root: Path, cache: dict | None = None) -> tuple[list[str], str | None]:
    """Problems with one entry, and its enforcement kind ("tests" / "none")."""
    cache = {} if cache is None else cache
    problems: list[str] = []
    body = [ln for ln in entry.lines if ln.strip()]
    hits = [i for i, ln in enumerate(body) if ENFORCED.match(ln)]
    if not hits:
        return [f"{entry.pa}: no '- Enforced by:' line"], None
    if len(hits) > 1:
        problems.append(f"{entry.pa}: {len(hits)} '- Enforced by:' lines (exactly one allowed)")
    if hits[-1] != len(body) - 1:
        problems.append(f"{entry.pa}: the '- Enforced by:' line is not the entry's last line")
    value = ENFORCED.match(body[hits[-1]]).group(1).strip()
    if value.startswith("none"):
        if not value.startswith(NONE_PREFIX) or not value[len(NONE_PREFIX):].strip():
            problems.append(f"{entry.pa}: 'none' needs the form 'none — <reason>'")
        return problems, "none"
    refs = [r.strip() for r in value.split(",")]
    for ref in refs:
        m = TEST_REF.match(ref)
        if not m:
            problems.append(f"{entry.pa}: {ref!r} is not tests/<file>.py::<test>")
            continue
        rel, name = m.groups()
        path = root / rel
        if not path.is_file():
            problems.append(f"{entry.pa}: {rel} does not exist")
            continue
        if rel not in cache:
            cache[rel] = _test_names(path)
        if name not in cache[rel]:
            problems.append(f"{entry.pa}: {rel} defines no test {name}")
    return problems, "tests"


def check_register(text: str, root: Path) -> tuple[list[str], dict[str, str]]:
    entries = parse_entries(text)
    problems: list[str] = []
    kinds: dict[str, str] = {}
    seen: set[str] = set()
    cache: dict = {}
    for e in entries:
        if e.pa in seen:
            problems.append(f"{e.pa}: appears twice")
        seen.add(e.pa)
        p, kind = check_entry(e, root, cache)
        problems += p
        if kind:
            kinds[e.pa] = kind
    return problems, kinds


def test_every_pa_names_its_enforcement_and_every_named_test_exists():
    problems, kinds = check_register(PA_DOC.read_text(encoding="utf-8"), ROOT)
    assert kinds, "no PA entries were parsed"
    assert problems == []


def test_the_unenforced_share_is_reported():
    _, kinds = check_register(PA_DOC.read_text(encoding="utf-8"), ROOT)
    none = sorted(pa for pa, k in kinds.items() if k == "none")
    share = f"{len(none)}/{len(kinds)} PAs are not enforced by a test ({100 * len(none) // len(kinds)}%)"
    print(share)
    if none:
        warnings.warn(share, UserWarning, stacklevel=1)


# ---------------------------------------------------------------- synthetic offenders

GOOD = (
    "- **PA-0001** — a rule.\n"
    "  1. **part** text.\n"
    "  - Enforced by: tests/test_x.py::test_a, tests/test_x.py::TestK::test_b\n"
    "\n"
    "- **PA-0002** — another rule.\n"
    "  - Enforced by: none — a process rule\n"
)


@pytest.fixture
def fake_root(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(
        "def test_a():\n    pass\n\nclass TestK:\n    def test_b(self):\n        pass\n"
    )
    return tmp_path


def test_the_checker_passes_a_well_formed_register(fake_root):
    problems, kinds = check_register(GOOD, fake_root)
    assert problems == []
    assert kinds == {"PA-0001": "tests", "PA-0002": "none"}


@pytest.mark.parametrize("text,needle", [
    ("- **PA-0003** — no line at all.\n", "no '- Enforced by:' line"),
    ("- **PA-0003** — r.\n  - Enforced by: none — a\n  - Enforced by: none — b\n", "exactly one"),
    ("- **PA-0003** — r.\n  - Enforced by: none — a\n  trailing text\n", "not the entry's last line"),
    ("- **PA-0003** — r.\n  - Enforced by: none\n", "none — <reason>"),
    ("- **PA-0003** — r.\n  - Enforced by: none — \n", "none — <reason>"),
    ("- **PA-0003** — r.\n  - Enforced by: tests/test_gone.py::test_a\n", "does not exist"),
    ("- **PA-0003** — r.\n  - Enforced by: tests/test_x.py::test_missing\n", "defines no test"),
    ("- **PA-0003** — r.\n  - Enforced by: tests/test_x.py::TestK::test_zzz\n", "defines no test"),
    ("- **PA-0003** — r.\n  - Enforced by: the lint\n", "is not tests/<file>.py::<test>"),
    ("- **PA-0001** — r.\n  - Enforced by: none — x\n" + GOOD, "appears twice"),
])
def test_the_checker_flags_each_kind_of_offender(fake_root, text, needle):
    problems, _ = check_register(text, fake_root)
    assert any(needle in p for p in problems), problems


def test_a_heading_ends_an_entry(fake_root):
    text = "- **PA-0001** — r.\n  - Enforced by: none — x\n\n## Appendix\n\n- Enforced by: stray\n"
    problems, kinds = check_register(text, fake_root)
    assert problems == [] and kinds == {"PA-0001": "none"}
