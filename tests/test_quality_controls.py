"""Every preventive action maps to one control family, and the generated index is current.

``docs/QUALITY_POLICY.md`` organises the controls in twelve families (L01..L12);
``docs/quality/pa_control_map.tsv`` maps each historical PA in
``docs/PREVENTIVE_ACTIONS.md`` to one of them, with its status and enforcement
mechanism; ``scripts/quality_index.py`` renders ``docs/quality/CONTROL_INDEX.md`` from
both. A new PA without a mapping, a PA mapped twice, an unknown family, or a stale
index fails here. The checker is proven on synthetic offenders.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.package_guard


def _load():
    spec = importlib.util.spec_from_file_location("quality_index", ROOT / "scripts" / "quality_index.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["quality_index"] = mod
    spec.loader.exec_module(mod)
    return mod


qi = _load()


def _texts():
    return (qi.MAP.read_text(encoding="utf-8"), qi.REGISTER.read_text(encoding="utf-8"),
            qi.POLICY.read_text(encoding="utf-8"))


def test_every_register_pa_is_mapped_once_to_a_known_family():
    map_text, register_text, policy_text = _texts()
    assert qi.check(map_text, register_text, policy_text) == []
    rows, _ = qi.load_map(map_text)
    assert {r["pa"] for r in rows} == set(qi.register_entries(register_text))


def test_the_generated_index_is_current():
    map_text, register_text, _ = _texts()
    assert qi.INDEX.read_text(encoding="utf-8") == qi.render(map_text, register_text), (
        "run scripts/quality_index.py")


def test_the_policy_states_the_three_revision_3_requirements():
    policy = qi.POLICY.read_text(encoding="utf-8")
    for heading in ("R1 — Systemic-diagnosis trigger", "R2 — Evidence for design-critical "
                    "assumptions", "R3 — Capability-transfer acceptance"):
        assert heading in policy


# ---------------------------------------------------------------- synthetic offenders

HEADER = "\t".join(qi.COLUMNS)
REGISTER = ("- **PA-0001** — a.\n  - Enforced by: tests/test_x.py::test_a\n\n"
            "- **PA-0002** — b.\n  - Enforced by: none — a process rule\n")


def _row(pa="PA-0001", family="L10", disposition="retain", status="active", mechanism="test",
         control="implemented", topic="t", correction="c"):
    return "\t".join([pa, family, disposition, status, mechanism, control, topic, correction, "", "s"])


GOOD = "\n".join(["# comment", HEADER, _row(), _row("PA-0002", mechanism="review", control="designed")])


def test_the_checker_passes_a_good_map():
    assert qi.check(GOOD, REGISTER) == []


@pytest.mark.parametrize("map_text,needle", [
    ("\n".join([HEADER, _row()]), "PA-0002: in the register but not mapped"),
    (GOOD + "\n" + _row(), "PA-0001: mapped twice"),
    (GOOD + "\n" + _row("PA-0009"), "PA-0009: mapped but not in the register"),
    ("\n".join([HEADER, _row(family="L13"), _row("PA-0002", mechanism="review")]), "unknown family"),
    ("\n".join([HEADER, _row(status="archived"), _row("PA-0002", mechanism="review")]),
     "does not match disposition"),
    ("\n".join([HEADER, _row(mechanism="review"), _row("PA-0002", mechanism="review")]),
     "disagrees with the register"),
    ("\n".join([HEADER, _row(control="proven"), _row("PA-0002", mechanism="review")]),
     "unknown control_status"),
    ("\n".join([HEADER, _row(correction=" "), _row("PA-0002", mechanism="review")]),
     "topic and correction are required"),
    ("pa\tfamily\n" + _row(), "map header"),
])
def test_the_checker_flags_each_offender(map_text, needle):
    problems = qi.check(map_text, REGISTER)
    assert any(needle in p for p in problems), problems


def test_a_policy_missing_a_family_section_is_flagged():
    policy = "\n".join(f"### {code} — x" for code in qi.FAMILIES if code != "L07")
    problems = qi.check(GOOD, REGISTER, policy)
    assert problems == ["L07: no section in docs/QUALITY_POLICY.md"]
