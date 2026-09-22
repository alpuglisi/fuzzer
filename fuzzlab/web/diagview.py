"""Read-only, store-backed diagnostics data for the Diagnostics tab (U5).

Mirrors `web/results.py` / `web/proxyview.py`: pure functions over the shared
store, no writes ever, the store file is never created. Metric points are
written elsewhere (B0's `core.store.log_scalar` / `MetricLogger`, called from
the GBT/logistic trainers, the bandit-backed oracle, the greybox coverage
loop, and `MutationSearch`); this module only reads `metric_series` back and
prepares it for the shared `createChart` wrapper (`static/js/charts.js`):
one JSON payload per chart, already downsampled server-side (R-05's resolved
render order) via `web.downsample`.
"""

from __future__ import annotations

from typing import Any

from fuzzlab.web import downsample

# Sources whose charts read better as a min/max envelope band than a single
# line (R-08: "offer a min/max-per-bucket envelope mode for the bandit CI
# band") — the bandit posterior/regret series jump step to step in a way an
# average would smear out. Everything else defaults to a plain LTTB line.
_ENVELOPE_SOURCES = {"bandit"}

_MAX_POINTS = 1000


def list_series(store) -> list[dict[str, Any]]:
    """Every populated (source, key) combination, with the run ids and point
    count backing it, and the suggested chart mode (line | envelope) — the
    Diagnostics page's chart-group list is built from this, one panel per row,
    so a chart is never rendered for a series with zero points."""
    rows = store.conn.execute(
        "SELECT source, key, COUNT(*) AS n, COUNT(DISTINCT run_id) AS n_runs, "
        "GROUP_CONCAT(DISTINCT run_id) AS run_ids "
        "FROM metric_series GROUP BY source, key ORDER BY source, key"
    ).fetchall()
    out = []
    for r in rows:
        run_ids = sorted({int(x) for x in (r["run_ids"] or "").split(",") if x})
        out.append({
            "source": r["source"],
            "key": r["key"],
            "points": r["n"],
            "runs": run_ids,
            "mode": "envelope" if r["source"] in _ENVELOPE_SOURCES else "line",
        })
    return out


def series_data(store, source: str, key: str, run_ids: list[int] | None = None,
                 max_points: int = _MAX_POINTS) -> dict[str, Any]:
    """One chart's data: one downsampled series per run, in uPlot's columnar
    shape. ``run_ids`` narrows to specific runs (cross-run overlay); omitted
    means every run that has this (source, key).

    Non-finite values never reach here (`log_scalar`/`MetricLogger` drop them
    at emit time, PA-0003's single write path), so there is no NaN filtering
    on the read side either.
    """
    mode = "envelope" if source in _ENVELOPE_SOURCES else "line"
    if run_ids:
        placeholders = ",".join("?" for _ in run_ids)
        rows = store.conn.execute(
            f"SELECT run_id, step, value FROM metric_series "
            f"WHERE source=? AND key=? AND run_id IN ({placeholders}) "
            f"ORDER BY run_id, step",
            (source, key, *run_ids),
        ).fetchall()
    else:
        rows = store.conn.execute(
            "SELECT run_id, step, value FROM metric_series "
            "WHERE source=? AND key=? ORDER BY run_id, step",
            (source, key),
        ).fetchall()

    by_run: dict[int, list[tuple[int, float]]] = {}
    for r in rows:
        by_run.setdefault(r["run_id"], []).append((r["step"], r["value"]))

    series: list[dict[str, Any]] = []
    for rid, pts in sorted(by_run.items()):
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        if mode == "envelope":
            oxs, mins, maxs = downsample.envelope(xs, ys, max_points)
            series.append({"run_id": rid, "x": oxs, "min": mins, "max": maxs})
        else:
            oxs, oys = downsample.lttb(xs, ys, max_points)
            series.append({"run_id": rid, "x": oxs, "y": oys})

    return {"source": source, "key": key, "mode": mode, "series": series}
