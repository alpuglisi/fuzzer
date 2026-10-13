"""The one reader of a run's stored anomaly flags (CC-UI-0043, PA-0003).

`detect_anomalies` (ML) writes `candidate.anomaly_score` / `anomaly_flag`; the CLI
summary (via the ML anomaly stage) and the run page both list the top flagged candidates
through this function. It is a plain store read, so the run page works without the ML
package (FR-ML-6). The flags are the last fit's values for the run (a store-wide fit
would overwrite them), so readers show them beside the run's own `anomaly_flagged`.
"""

from __future__ import annotations

from fuzzlab.core.evidence import display_evidence

from fuzzlab.core.urls import to_path


def top_flagged(store, run_id: int, limit: int = 5) -> list[dict]:
    """The run's most anomalous flagged candidates — score, then id, descending (the
    order the CLI has always printed) — as ``{path, param, category, score}``."""
    out = []
    for row in store.conn.execute(
            "SELECT evidence, anomaly_score FROM candidate WHERE run_id=? AND "
            "anomaly_flag=1 AND anomaly_score IS NOT NULL "
            "ORDER BY anomaly_score DESC, id DESC LIMIT ?", (run_id, limit)).fetchall():
        ev = display_evidence(row["evidence"])          # display only (BUG-0107)
        out.append({"path": to_path(ev.get("url", "")), "param": ev.get("param", ""),
                    "category": ev.get("category", ""), "score": round(row["anomaly_score"], 3)})
    return out


#: The rule `detect_anomalies` records as ``run_metrics.anomaly_flag_rule`` since
#: CC-ML-0019 (`fuzzlab.ml.anomaly.FLAG_RULE`; a plain number here so this core
#: reader needs no ML import).
FLAG_RULE_TIES_NOT_SPLIT = 2.0


def flag_note(store, run_id: int, metrics: dict) -> str | None:
    """What a reader must say beside a run's stored flags (CC-ML-0019, BUG-0070):

    - flags written before the tie rule (flags stored, no ``anomaly_flag_rule``) may
      exceed the contamination fraction — said so;
    - under the tie rule, fewer flags than the budget means a tie group at the cut was
      not split."""
    flagged_rows = store.conn.execute(
        "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND anomaly_flag=1",
        (run_id,)).fetchone()["c"]
    if metrics.get("anomaly_flag_rule") != FLAG_RULE_TIES_NOT_SPLIT:
        return ("flags from the pre-BUG-0070 rule (tie groups may exceed the fraction)"
                if flagged_rows else None)
    flagged, budget = metrics.get("anomaly_flagged"), metrics.get("anomaly_flag_budget")
    if flagged is not None and budget is not None and flagged < budget:
        return (f"flagged {int(flagged)} of at most {int(budget)}: a tie group at the cut "
                "is never split (identical scores are equally unusual)")
    return None
