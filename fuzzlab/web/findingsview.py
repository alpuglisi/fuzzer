"""Read oracle findings from the store for the Findings workbench (U2, D11).

Read-only, pure and dependency-light like ``results.py``/``proxyview.py`` — the
Findings workbench filters/sorts/facets entirely client-side (R-03: in-memory
filter -> sort -> fragment-render, no per-filter round trip), so this module's
job is just to hand back every finding (capped) plus enough shape for the
facet sidebar and detail view. ``finding``/``attempt`` are tool-written only;
nothing here writes to them (the panel's write surface for this section is
limited to ``saved_views``, see ``savedviews.py``).
"""

from __future__ import annotations

import json
from typing import Any

# Severity is UI-only presentation sugar for the facet sidebar/badges — it is
# NOT part of the store schema (`finding` has no severity column; see
# fuzzlab/core/migrations.py) and is never treated as a security verdict. The
# oracle's confirmed `label=1` is the actual finding; this just buckets
# `vuln_class` into the five ZAP/CVSS-convention bands the plan's color tokens
# (--crit/--high/--med/--low/--info in tokens.css) are keyed to, so an unknown
# or future vuln_class degrades to "Info" rather than erroring.
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")

_SEVERITY_BY_VULN_CLASS: dict[str, str] = {
    "sqli": "Critical",
    "command-injection": "Critical",
    "ssti": "Critical",
    "file-inclusion": "High",
    "xss-stored": "High",
    "xss-reflected": "Medium",
    "xss-dom": "Medium",
    "open-redirect": "Low",
}


def severity_for(vuln_class: str | None) -> str:
    """Map a finding's ``vuln_class`` to a display severity band (default Info)."""
    return _SEVERITY_BY_VULN_CLASS.get((vuln_class or "").lower(), "Info")


def _row(row) -> dict[str, Any]:
    try:
        evidence = json.loads(row["evidence"]) if row["evidence"] else {}
    except (ValueError, TypeError):
        evidence = {"raw": row["evidence"]}
    vuln_class = row["vuln_class"]
    return {
        "id": row["id"],
        "run_id": row["run_id"],
        "attempt_id": row["attempt_id"],
        "case_id": row["case_id"],
        "vuln_class": vuln_class,
        "severity": severity_for(vuln_class),
        "label": row["label"],
        # `finding.confidence` stores the oracle's confirmation *mechanism*
        # (e.g. "error-signature", "boolean-blind" — see fuzzlab/oracle/
        # strategies.py); this doubles as the plan's "confidence/mechanism"
        # facet group, matching the store as written, not a separate field.
        "confidence": row["confidence"],
        "evidence": evidence,
        "url": row["url"],
        "method": row["method"],
        "param": row["param"],
        "created_at": row["created_at"],
        "run_tool": row["run_tool"],
    }


_LIST_SQL = (
    "SELECT f.id, f.run_id, f.attempt_id, f.case_id, f.vuln_class, f.label, "
    "f.confidence, f.evidence, f.url, f.method, f.param, f.created_at, "
    "r.tool AS run_tool "
    "FROM finding f LEFT JOIN run r ON r.id = f.run_id "
)


def list_findings(store, limit: int = 5000) -> list[dict[str, Any]]:
    """Every finding, newest first, capped at ``limit`` (the DataTable's own
    escalation lever per R-03 — no virtualization, no server-side paging)."""
    rows = store.conn.execute(_LIST_SQL + "ORDER BY f.id DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r) for r in rows]


def finding_detail(store, finding_id: int) -> dict[str, Any] | None:
    """One finding plus its attempt (if any). Ground-truth multi-artifact
    fields (``primary_endpoint``/``primary_role``/``related_endpoints``/
    ``flow_variant``) live on the out-of-band ground-truth ``Case``
    (fuzzlab.labels.contract.Case), keyed by the opaque ``case_id`` the scoring
    harness matches against (D9/D10) — they are not columns on `finding`/
    `attempt` (see fuzzlab/core/migrations.py) and this lane does not add them
    (no schema change of its own). ``ground_truth_fields_available`` is always
    False today so the detail template can render the gap instead of
    fabricating blank fields."""
    row = store.conn.execute(_LIST_SQL + "WHERE f.id=?", (finding_id,)).fetchone()
    if row is None:
        return None
    out = _row(row)
    attempt = None
    if row["attempt_id"] is not None:
        a = store.conn.execute(
            "SELECT id, payload_family, score, uncertainty, reward, coverage, "
            "created_at FROM attempt WHERE id=?", (row["attempt_id"],)).fetchone()
        if a is not None:
            attempt = dict(a)
    out["attempt"] = attempt
    out["ground_truth_fields_available"] = False
    return out
