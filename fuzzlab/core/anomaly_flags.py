"""The one reader of a run's stored anomaly flags (CC-UI-0043, PA-0003).

`detect_anomalies` (ML) writes `candidate.anomaly_score` / `anomaly_flag`; the CLI
summary (via the ML anomaly stage) and the run page both list the top flagged candidates
through this function. It is a plain store read, so the run page works without the ML
package (FR-ML-6). The flags are the last fit's values for the run (a store-wide fit
would overwrite them), so readers show them beside the run's own `anomaly_flagged`.
"""

from __future__ import annotations

import json

from fuzzlab.core.urls import to_path


def top_flagged(store, run_id: int, limit: int = 5) -> list[dict]:
    """The run's most anomalous flagged candidates — score, then id, descending (the
    order the CLI has always printed) — as ``{path, param, category, score}``."""
    out = []
    for row in store.conn.execute(
            "SELECT evidence, anomaly_score FROM candidate WHERE run_id=? AND "
            "anomaly_flag=1 AND anomaly_score IS NOT NULL "
            "ORDER BY anomaly_score DESC, id DESC LIMIT ?", (run_id, limit)).fetchall():
        try:
            ev = json.loads(row["evidence"] or "{}")
        except (ValueError, TypeError):
            ev = {}
        out.append({"path": to_path(ev.get("url", "")), "param": ev.get("param", ""),
                    "category": ev.get("category", ""), "score": round(row["anomaly_score"], 3)})
    return out
