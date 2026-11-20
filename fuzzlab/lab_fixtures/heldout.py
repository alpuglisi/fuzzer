"""The held-out labs (lab/HOLDOUT.md, FR-LAB-420..423): read from the one table.

``lab/HOLDOUT.md`` is the single source of the list. The benchmark
(``scripts/holdout_score.py``) runs exactly these labs, and the guard
(``tests/test_holdout_benchmark.py``) refuses any other test file that names one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOLDOUT_MD = REPO_ROOT / "lab" / "HOLDOUT.md"
SECTION = "## Held-out labs"
_LAB = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{2,}$")


class HoldoutTableError(ValueError):
    """lab/HOLDOUT.md's table is missing or malformed (fail closed: an unreadable list
    must never read as "nothing is held out")."""


@dataclass(frozen=True)
class HeldOutLab:
    name: str
    upstream: str
    stack: str
    #: lower-case names a test file may not contain (the directory's first word included)
    names: tuple[str, ...]


def parse_holdout_table(text: str) -> list[HeldOutLab]:
    """The rows of the ``## Held-out labs`` table. Raises on a missing section, an
    empty table or a malformed row."""
    if SECTION not in text:
        raise HoldoutTableError(f"no {SECTION!r} section")
    body = text.split(SECTION, 1)[1]
    body = re.split(r"^## ", body, maxsplit=1, flags=re.MULTILINE)[0]
    rows = [ln.strip() for ln in body.splitlines() if ln.strip().startswith("|")]
    if len(rows) < 3:
        raise HoldoutTableError("the held-out table has no rows")
    out: list[HeldOutLab] = []
    for ln in rows[2:]:                       # skip the header and the --- rule
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) != 4:
            raise HoldoutTableError(f"row has {len(cells)} cells, want 4: {ln!r}")
        name, upstream, stack, names = cells
        aliases = tuple(sorted({n.strip().lower() for n in names.split(",") if n.strip()}))
        if not _LAB.match(name) or not aliases or not all(_NAME.match(a) for a in aliases):
            raise HoldoutTableError(f"malformed row: {ln!r}")
        out.append(HeldOutLab(name, upstream, stack, aliases))
    if len({lab.name for lab in out}) != len(out):
        raise HoldoutTableError("a lab is listed twice")
    return out


def held_out_labs(path: Path = HOLDOUT_MD) -> list[HeldOutLab]:
    return parse_holdout_table(path.read_text(encoding="utf-8"))


def name_pattern(labs: list[HeldOutLab]) -> re.Pattern[str]:
    """Any held-out name as a token: not inside a longer alphanumeric word."""
    alts = sorted({n for lab in labs for n in lab.names}, key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(map(re.escape, alts)) + r")(?![a-z0-9])",
                      re.IGNORECASE)
