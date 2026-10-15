#!/usr/bin/env python3
"""Map every preventive action to its control family, and render the current view.

``docs/PREVENTIVE_ACTIONS.md`` is the immutable history of preventive actions (PA IDs
never change). ``docs/QUALITY_POLICY.md`` is the short operating policy, organised in
twelve control families (L01..L12). ``docs/quality/pa_control_map.tsv`` joins the two:
one row per PA, with its family, its disposition from the 2026-10-15 lean quality
review, its status, the mechanism that enforces it and that mechanism's state.

This script renders ``docs/quality/CONTROL_INDEX.md`` from the map and the register,
so a contributor reads one family's current controls instead of the whole register::

    scripts/quality_index.py            # rewrite docs/quality/CONTROL_INDEX.md
    scripts/quality_index.py --check    # exit 1 if the map or the index is out of date

``tests/test_quality_controls.py`` runs the same checks. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "docs" / "PREVENTIVE_ACTIONS.md"
POLICY = ROOT / "docs" / "QUALITY_POLICY.md"
MAP = ROOT / "docs" / "quality" / "pa_control_map.tsv"
INDEX = ROOT / "docs" / "quality" / "CONTROL_INDEX.md"

FAMILIES = {
    "L01": "Change and CAPA triage",
    "L02": "Shared contracts",
    "L03": "Input and persistence boundaries",
    "L04": "Network and secret containment",
    "L05": "Resource and storage lifecycle",
    "L06": "Oracle and evaluation integrity",
    "L07": "Generated lab and environment compatibility",
    "L08": "Provenance and identity",
    "L09": "Verification and release",
    "L10": "Test and guard quality",
    "L11": "Delivery flow and escalation",
    "L12": "Performance and reuse",
}
# disposition (the review's recommendation) -> status (how a reader treats the entry)
STATUS_OF = {
    "retain": "active",
    "consolidate": "consolidated",
    "rewrite": "rewritten",
    "archive": "archived",
    "replace": "replaced",
}
MECHANISMS = ("test", "hook", "fixture", "harness", "on-host", "review", "gap", "superseded")
CONTROL_STATES = ("designed", "implemented", "qualified", "operating-effective", "archived")
COLUMNS = ["pa", "family", "disposition", "status", "mechanism", "control_status",
           "topic", "correction", "note", "source"]

ENTRY_START = re.compile(r"^- \*\*(PA-\d{4})\b")
ENFORCED = re.compile(r"^\s*- Enforced by: (.*)$")


def register_entries(text: str) -> dict[str, str]:
    """PA id -> its enforcement value ('tests' or 'none — <reason>'), in register order."""
    out: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        m = ENTRY_START.match(line)
        if m:
            current = m.group(1)
            out.setdefault(current, "")
            continue
        if line.startswith("#"):
            current = None
            continue
        m = ENFORCED.match(line)
        if m and current:
            value = m.group(1).strip()
            out[current] = value if value.startswith("none") else "tests"
    return out


def load_map(text: str) -> tuple[list[dict], list[str]]:
    """(rows, problems). Lines starting with '#' are comments."""
    body = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))
    reader = csv.DictReader(io.StringIO(body), delimiter="\t")
    problems: list[str] = []
    if reader.fieldnames != COLUMNS:
        return [], [f"map header is {reader.fieldnames}, expected {COLUMNS}"]
    return list(reader), problems


def check(map_text: str, register_text: str, policy_text: str | None = None) -> list[str]:
    """Every problem with the map: missing, extra or duplicate PAs and bad values."""
    rows, problems = load_map(map_text)
    if problems:
        return problems
    reg = register_entries(register_text)
    seen: set[str] = set()
    for r in rows:
        pa = r["pa"]
        if pa in seen:
            problems.append(f"{pa}: mapped twice")
        seen.add(pa)
        if pa not in reg:
            problems.append(f"{pa}: mapped but not in the register")
        if r["family"] not in FAMILIES:
            problems.append(f"{pa}: unknown family {r['family']!r}")
        if r["disposition"] not in STATUS_OF:
            problems.append(f"{pa}: unknown disposition {r['disposition']!r}")
        elif r["status"] != STATUS_OF[r["disposition"]]:
            problems.append(f"{pa}: status {r['status']!r} does not match disposition "
                            f"{r['disposition']!r} (expected {STATUS_OF[r['disposition']]!r})")
        if r["mechanism"] not in MECHANISMS:
            problems.append(f"{pa}: unknown mechanism {r['mechanism']!r}")
        if r["control_status"] not in CONTROL_STATES:
            problems.append(f"{pa}: unknown control_status {r['control_status']!r}")
        if pa in reg and (reg[pa] == "tests") != (r["mechanism"] == "test"):
            problems.append(f"{pa}: mechanism {r['mechanism']!r} disagrees with the register's "
                            f"'Enforced by' ({'tests' if reg[pa] == 'tests' else 'none'})")
        if not r["topic"].strip() or not r["correction"].strip():
            problems.append(f"{pa}: topic and correction are required")
    for pa in reg:
        if pa not in seen:
            problems.append(f"{pa}: in the register but not mapped to a control family")
    if policy_text is not None:
        for code in FAMILIES:
            if not re.search(rf"^#+ {code} ", policy_text, re.M):
                problems.append(f"{code}: no section in docs/QUALITY_POLICY.md")
    return problems


def render(map_text: str, register_text: str) -> str:
    rows, _ = load_map(map_text)
    reg = register_entries(register_text)
    by_family: dict[str, list[dict]] = {code: [] for code in FAMILIES}
    for r in rows:
        by_family.setdefault(r["family"], []).append(r)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    out = [
        "# Control index (generated)",
        "",
        "Generated by `scripts/quality_index.py` from `docs/quality/pa_control_map.tsv` and",
        "`docs/PREVENTIVE_ACTIONS.md`. Do not edit by hand. The policy is",
        "`docs/QUALITY_POLICY.md`; this index tells you which historical PAs sit under each",
        "family and how each is enforced.",
        "",
        "How to read a status: **active** — the PA's own wording is current; **consolidated**",
        "— its invariant is current, read through the family; **rewritten** / **replaced** —",
        "the correction column is current and wins over the PA's original wording;",
        "**archived** — history only, not an instruction. A `test` mechanism means a named",
        "test exists, not that the whole PA is proven (control state `implemented`, not",
        "`qualified`).",
        "",
        f"{len(rows)} PAs: " + ", ".join(f"{counts[k]} {k}" for k in
                                         ("active", "consolidated", "rewritten", "archived",
                                          "replaced") if k in counts) + ".",
        "",
    ]
    for code, name in FAMILIES.items():
        fam = sorted(by_family.get(code, []), key=lambda r: int(r["pa"][3:]))
        out += [f"## {code} — {name} ({len(fam)})", ""]
        if not fam:
            out += ["(no historical PA maps here)", ""]
            continue
        out += ["| PA | Topic | Status | Mechanism / state | Current requirement |",
                "| --- | --- | --- | --- | --- |"]
        for r in fam:
            text = r["correction"] + (f" **Now:** {r['note']}" if r["note"] else "")
            text = text.replace("|", "\\|")
            enforcement = r["mechanism"]
            if reg.get(r["pa"], "").startswith("none"):
                enforcement += " (register: none)"
            out.append(f"| {r['pa']} | {r['topic']} | {r['status']} | "
                       f"{enforcement} / {r['control_status']} | {text} |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="report problems and a stale index; write nothing")
    args = ap.parse_args(argv)
    map_text = MAP.read_text(encoding="utf-8")
    register_text = REGISTER.read_text(encoding="utf-8")
    policy_text = POLICY.read_text(encoding="utf-8") if POLICY.exists() else None
    problems = check(map_text, register_text, policy_text)
    for p in problems:
        print(f"problem: {p}", file=sys.stderr)
    rendered = render(map_text, register_text)
    if args.check:
        current = INDEX.read_text(encoding="utf-8") if INDEX.exists() else ""
        if current != rendered:
            print("docs/quality/CONTROL_INDEX.md is out of date; run scripts/quality_index.py",
                  file=sys.stderr)
            return 1
        return 1 if problems else 0
    if problems:
        return 1
    INDEX.write_text(rendered, encoding="utf-8")
    print(f"wrote {INDEX.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
