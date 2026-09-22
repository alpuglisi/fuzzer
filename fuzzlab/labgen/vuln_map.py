"""Generate the lab's vulnerability map (`L-P3.3c-CUT`, `CC-LAB-0061`/
`FR-LAB-58`, `docs/LAB_IMPLEMENTATION_PLAN.md` S4.3.6.5).

Retires the hand-written `puppy-fort-factory/VULNERABILITIES.md`: that file
could (and, per its own bug history, did) drift out of sync with the ground
truth it claimed to summarize. This module renders the human-readable
vulnerability map straight from `lab/ground-truth/labels.json` (the
authoritative source every scorer/consumer already reads) plus
`lab/ground-truth/migration-exemptions.yaml` (which real cases are not yet
reproduced by the generator, and why) -- so `lab/VULNERABILITIES.md` cannot
say anything `labels.json` does not itself say. Nothing here is a second,
independently-maintained fact about a case: it is prose rendered from facts
`fuzzlab.labels.contract` already loads and validates.
"""

from __future__ import annotations

from pathlib import Path

from fuzzlab.labels import contract
from fuzzlab.labgen.cutover_gate import DEFAULT_EXEMPTIONS_PATH, load_exemptions

__all__ = ["render_vulnerabilities_md", "write_vulnerabilities_md"]

_HEADER = """# Target lab -- vulnerability map (generated)

**Generated file -- do not hand-edit.** Rendered by
`fuzzlab.labgen.vuln_map` from `lab/ground-truth/labels.json` and
`lab/ground-truth/migration-exemptions.yaml` (`L-P3.3c-CUT`). Regenerate
with:

```
python3 -m fuzzlab.labgen.vuln_map --out lab/VULNERABILITIES.md
```

This is the deliberately vulnerable target lab for the toolkit's own
security testing (lab-only, authorized-only -- see the repo's top-level
`README.md` and `CLAUDE.md`). "Vulnerable" / "secure" below refer
specifically to **SQL injection (SQLi)** and **cross-site scripting (XSS)**,
the two classes `lab/ground-truth/labels.json` labels; a page marked
*secure* is free of SQLi/XSS, not a claim it is hardened against every
possible attack.

"""

_CASES_HEADER = """## Labeled cases (`lab/ground-truth/labels.json`)

| Case | URL | Method | Param | Class | Verdict | Notes |
| --- | --- | --- | --- | --- | --- | --- |
"""

_EXEMPT_HEADER = """
## Not yet reproduced by the generator (`lab/ground-truth/migration-exemptions.yaml`)

These labeled cases have no `php_laravel` cell reproducing them yet. Each
entry below is a reviewed, machine-readable exemption -- see
`fuzzlab.labgen.cutover_gate` (the module that enforces this list is
exhaustive: every `PFF-` case in `labels.json` must be either covered or
named here, or the cutover gate fails the build).

| Case | Reason |
| --- | --- |
"""


def render_vulnerabilities_md(
    *,
    labels_dir: str | Path = "lab/ground-truth",
    exemptions_path: str | Path = DEFAULT_EXEMPTIONS_PATH,
) -> str:
    """Render the full generated `VULNERABILITIES.md` content as a string."""
    cases = contract.load_labels(labels_dir)
    exemptions = load_exemptions(exemptions_path)

    lines = [_HEADER, _CASES_HEADER]
    for case in sorted(cases, key=lambda c: c.case_id):
        verdict = "VULNERABLE" if case.expected_vulnerable else "secure"
        notes = (case.notes or "").replace("|", "\\|")
        lines.append(
            f"| {case.case_id} | `{case.url}` | {case.method} | `{case.param}` | "
            f"{case.vuln_class} | {verdict} | {notes} |\n"
        )

    if exemptions:
        lines.append(_EXEMPT_HEADER)
        for case_id, reason in sorted(exemptions.items()):
            lines.append(f"| {case_id} | {reason.replace('|', chr(92) + '|')} |\n")

    return "".join(lines)


def write_vulnerabilities_md(out_path: str | Path, **kwargs: object) -> None:
    Path(out_path).write_text(render_vulnerabilities_md(**kwargs), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="fuzzlab.labgen.vuln_map")
    parser.add_argument("--out", default="lab/VULNERABILITIES.md")
    args = parser.parse_args(argv)
    write_vulnerabilities_md(args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
