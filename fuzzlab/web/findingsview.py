"""Read-only, store-backed findings for the Findings workbench (U2, CC-UI-0029).

Mirrors `web/results.py` / `web/proxyview.py`: pure functions over the shared
store, no writes, and the store file is never created. `finding.confidence` is
the oracle's *confirmation mechanism* (e.g. "error-signature"), not a severity
level -- the store schema (`docs/ARCHITECTURE.md`, "the store as the
contract") has no severity column, so `severity` here is a UI-only, advisory
categorization derived from `vuln_class` (never a stored or scored fact),
purely to drive the facet sidebar / badge coloring R-03 asks for. It is never
written back to the store.
"""

from __future__ import annotations

import json
from typing import Any

from fuzzlab.core.store import Store

# Advisory only (not part of the store contract): a coarse, best-effort severity
# band per vuln_class family, checked as a substring match (vuln_class spellings
# are informal across tools/tests -- "sqli" vs "sql-injection"). Used only for
# facet grouping / badge color in the Findings workbench; extend as new vuln
# classes appear. Unmatched classes fall back to "info" rather than guessing high.
_SEVERITY_RULES: tuple[tuple[str, str], ...] = (
    ("sql", "critical"), ("command", "critical"), ("template", "critical"),
    ("xxe", "critical"), ("deserial", "critical"),
    ("xss", "high"), ("ssrf", "high"), ("traversal", "high"), ("inclusion", "high"),
    ("idor", "high"), ("auth-bypass", "high"),
    ("csrf", "medium"), ("redirect", "medium"), ("header", "medium"), ("cors", "medium"),
)

SEVERITIES = ("critical", "high", "medium", "low", "info")


def derive_severity(vuln_class: str | None) -> str:
    """Best-effort severity band for `vuln_class`, for facet/badge display only."""
    v = (vuln_class or "").lower()
    for needle, sev in _SEVERITY_RULES:
        if needle in v:
            return sev
    return "info"


_FINDING_COLS = ("id", "run_id", "attempt_id", "case_id", "vuln_class", "label",
                  "confidence", "url", "method", "param", "created_at")

# Ground-truth fields a confirmation strategy or upstream tooling MAY attach to
# `verdict.evidence` (CR-LAB-0001 Addendum B / `fuzzlab.labels.contract.Case`).
# The oracle (the sole finding-writer, see `fuzzlab/oracle/oracle.py`) never
# reads ground truth itself (D9/D10: it must not know the answer), so these
# keys are additive/optional on every finding -- present only when a plugin or
# future harness integration chose to carry them through, never required.
_GROUND_TRUTH_KEYS = ("primary_endpoint", "primary_role", "related_endpoints",
                      "flow_variant")


def _parse_evidence(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"raw": parsed}
    except (ValueError, TypeError):
        return {"raw": raw}


def _ground_truth_fields(evidence: dict[str, Any]) -> dict[str, Any] | None:
    found = {k: evidence[k] for k in _GROUND_TRUTH_KEYS if k in evidence}
    return found or None


def list_findings(store: Store, *, limit: int = 5000) -> list[dict[str, Any]]:
    """Every confirmed finding, newest first, with a derived `severity` band.

    Bounded (`limit`) rather than paginated server-side: the Findings workbench
    fetches this once and does facet/quick-filter/sort entirely client-side
    (D4, R-03 "no virtualization -- a few thousand rows are fine").
    """
    rows = store.conn.execute(
        f"SELECT {', '.join(_FINDING_COLS)} FROM finding ORDER BY id DESC LIMIT ?",
        (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["severity"] = derive_severity(d.get("vuln_class"))
        out.append(d)
    return out


def finding_detail(store: Store, finding_id: int) -> dict[str, Any] | None:
    """One finding's full record: evidence, derived severity, any ground-truth
    fields carried in its evidence, and the attempt it confirmed (if any)."""
    row = store.conn.execute(
        f"SELECT {', '.join(_FINDING_COLS)}, evidence FROM finding WHERE id=?",
        (finding_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    evidence = _parse_evidence(d.get("evidence"))
    d["evidence"] = evidence
    d["severity"] = derive_severity(d.get("vuln_class"))
    d["ground_truth"] = _ground_truth_fields(evidence)

    attempt = None
    if d.get("attempt_id") is not None:
        arow = store.conn.execute(
            "SELECT id, payload_family, reward, score, uncertainty, created_at "
            "FROM attempt WHERE id=?", (d["attempt_id"],)).fetchone()
        attempt = dict(arow) if arow else None
    d["attempt"] = attempt
    return d
