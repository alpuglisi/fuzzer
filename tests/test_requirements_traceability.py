"""PA-0112: every safety NFR is traced to the test that fails without it.

BUG-0111/0112: NFR-CRAWL-safe and NFR-FUZZ-safe were written into the specs and never
built; nothing failed. Now every NFR in a ``requirements.md`` is classified here as
SAFETY or NOT_SAFETY (an unclassified NFR fails), and every SAFETY NFR carries
``Enforced by:`` lines naming ``tests/<file>.py::<test_function>`` (checked to exist,
by AST) and/or ``Not yet enforced:`` lines that say so plainly.
"""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Safety and integrity guarantees: each must be traced.
SAFETY = {
    "NFR-LAB-safety", "NFR-LAB-no-secret-leak", "NFR-CORE-no-bypass", "NFR-CORE-secrets",
    "NFR-SESS-redaction", "NFR-CRAWL-safe", "NFR-CRAWL-dry-run", "NFR-AUD-safe",
    "NFR-AUD-dry-run", "NFR-IND-safe", "NFR-FUZZ-safe", "NFR-FUZZ-dry-run",
    "NFR-MUT-safe", "NFR-MUT-offline", "NFR-MUT-dry-run", "NFR-ML-advisory",
    "NFR-PROXY-safe", "NFR-PROXY-dry-run", "NFR-PLUG-safe", "NFR-UI-localhost",
    "NFR-UI-read-only", "NFR-UI-redacted", "NFR-UI-no-auto-run",
    "NFR-UI-control-plane-hardened",
    "NFR-LAB-cleanup",  # BUG-0125: leaked lab servers OOM-killed the host
}
#: Everything else, with the reason it is not a safety guarantee.
NOT_SAFETY = {
    "NFR-AUD-explainable": "traceability of output",
    "NFR-AUD-idempotent": "result stability",
    "NFR-AUD-no-leak": "benchmark integrity (D9), not operator safety",
    "NFR-CORE-central-connection": "connection configuration",
    "NFR-CORE-deterministic": "reproducibility",
    "NFR-CORE-single-writer": "concurrency (WAL, one writer path)",
    "NFR-CRAWL-bounded": "crawl termination",
    "NFR-CRAWL-reproducible": "reproducibility",
    "NFR-FUZZ-deterministic": "reproducibility",
    "NFR-FUZZ-labeled-output": "output format",
    "NFR-FUZZ-precision": "detection quality",
    "NFR-FUZZ-response-fidelity": "detection quality",
    "NFR-IND-no-leak": "benchmark integrity (D9)",
    "NFR-IND-static": "catalog lifecycle",
    "NFR-IND-versioned": "catalog lifecycle",
    "NFR-LAB-label-accuracy": "benchmark integrity",
    "NFR-LAB-no-leak": "benchmark integrity (D9)",
    "NFR-LAB-reproducible": "reproducibility",
    "NFR-ML-calibrated": "model quality",
    "NFR-ML-no-leak": "benchmark integrity (D9)",
    "NFR-ML-reproducible": "reproducibility",
    "NFR-MUT-bounded": "search termination",
    "NFR-MUT-semantics": "mutation correctness",
    "NFR-PLUG-optional": "packaging",
    "NFR-PLUG-reproducible": "reproducibility",
    "NFR-PROXY-byte-exact": "fidelity",
    "NFR-PROXY-nonblocking": "performance",
    "NFR-PROXY-optional": "packaging",
    "NFR-SCHED-degrade": "graceful degradation",
    "NFR-SCHED-observable": "observability",
    "NFR-SCHED-reproducible": "reproducibility",
    "NFR-SESS-portable": "portability",
    "NFR-SESS-single-flight": "concurrency",
    "NFR-SESS-zero-config": "usability",
    "NFR-SESS-zero-request": "efficiency",
    "NFR-UI-browser-verified": "test practice",
    "NFR-UI-live": "freshness",
}

_NFR = re.compile(r"^- \*\*(NFR-[A-Za-z0-9-]+)\*\*")
_TEST_REF = re.compile(r"(tests/[\w/]+\.py)::(test_\w+)")


def nfr_blocks(text: str) -> dict[str, str]:
    """``{NFR id: its bullet text, continuation and sub-bullets included}``."""
    blocks, current, lines = {}, None, []
    for line in text.splitlines():
        m = _NFR.match(line)
        if m or line.startswith("- ") or line.startswith("#"):
            if current:
                blocks[current] = "\n".join(lines)
            current, lines = (m.group(1), [line]) if m else (None, [])
            continue
        if current:
            lines.append(line)
    if current:
        blocks[current] = "\n".join(lines)
    return blocks


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}


def problems(spec_paths, root: Path = ROOT) -> list[str]:
    out, seen = [], set()
    for spec in spec_paths:
        for nfr, block in nfr_blocks(Path(spec).read_text()).items():
            seen.add(nfr)
            if nfr not in SAFETY and nfr not in NOT_SAFETY:
                out.append(f"{nfr}: unclassified (add it to SAFETY or NOT_SAFETY)")
                continue
            if nfr not in SAFETY:
                continue
            enforced = [ln for ln in block.splitlines() if "Enforced by:" in ln]
            pending = [ln for ln in block.splitlines() if "Not yet enforced:" in ln]
            if not enforced and not pending:
                out.append(f"{nfr}: no 'Enforced by:' or 'Not yet enforced:' line")
            refs = [r for ln in enforced for r in _TEST_REF.findall(ln)]
            if enforced and not refs:
                out.append(f"{nfr}: 'Enforced by:' names no tests/<file>.py::<test>")
            for path, fn in refs:
                p = root / path
                if not p.exists():
                    out.append(f"{nfr}: {path} does not exist")
                elif fn not in _test_functions(p):
                    out.append(f"{nfr}: {path}::{fn} does not exist")
    return out


def _specs():
    return sorted((ROOT / "docs" / "components").glob("*/requirements.md"))


def test_every_safety_nfr_is_traced_to_real_tests():
    assert problems(_specs()) == []


def test_every_classified_nfr_still_exists():
    present = set()
    for spec in _specs():
        present |= set(nfr_blocks(spec.read_text()))
    assert (SAFETY | set(NOT_SAFETY)) - present == set()


def test_the_guard_catches_each_kind_of_offender(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_real():\n    pass\n")
    spec = tmp_path / "requirements.md"
    spec.write_text(
        "## 4. Non-functional requirements\n"
        "- **NFR-CRAWL-safe** No line at all.\n"
        "- **NFR-FUZZ-safe** A bad reference.\n"
        "  - Enforced by: `x` — `tests/test_x.py::test_missing`\n"
        "- **NFR-MUT-safe** A good one.\n"
        "  - Enforced by: `x` — `tests/test_x.py::test_real`\n"
        "- **NFR-NEW-thing** Unclassified.\n"
        "- **NFR-UI-redacted** Honest.\n"
        "  - Not yet enforced: the repeater shows raw traffic.\n")
    assert problems([spec], root=tmp_path) == [
        "NFR-CRAWL-safe: no 'Enforced by:' or 'Not yet enforced:' line",
        "NFR-FUZZ-safe: tests/test_x.py::test_missing does not exist",
        "NFR-NEW-thing: unclassified (add it to SAFETY or NOT_SAFETY)",
    ]
