"""Read-only, store-backed diagnostics + store-explorer data for the Diagnostics
tab (U5 / CC-UI-0032; `docs/UI_IMPLEMENTATION_PLAN.md` §3, R-02/R-05/R-12).

Mirrors `web/results.py` / `web/proxyview.py`: pure functions over the shared
store, no writes, never creates the store file. Two families of data:

- **Diagnostics** (TensorBoard-like): cross-run scalar trends over
  `run_metrics`, intra-run step series over `metric_series` (LTTB-downsampled
  server-side per R-05), candidate-score distributions, bandit arm posteriors,
  and the model-registry timeline.
- **Store explorer** (FR-UI-2, Datasette-style): read-only browsing of any
  table in the store, with the table name always validated against
  `sqlite_master` before it is ever interpolated into SQL (SQLite has no
  parameter placeholder for identifiers) — never taken from the caller
  unchecked. Row values are handed back as plain JSON; the client renders them
  via `textContent` only (never innerHTML), so this module's job is just to
  never execute untrusted SQL, not to sanitize for HTML.
"""

from __future__ import annotations

from typing import Any

# --- LTTB downsampling (R-05: "read-side downsampling = LTTB, ~1000 pts/series,
# preserves loss spikes / regret jumps that bucket-averaging erases", ~30 lines
# pure Python). Largest-Triangle-Three-Buckets: keeps the first/last point, and
# from each of the remaining evenly-spaced buckets keeps the point that forms
# the largest triangle with the previous kept point and the *next* bucket's
# average point (its "effective area") — this is what preserves spikes that a
# naive stride/average would smooth away.


def lttb(xs: list[float], ys: list[float], threshold: int) -> tuple[list[float], list[float]]:
    """Downsample ``(xs, ys)`` to at most ``threshold`` points. ``xs`` must be
    sorted ascending. A no-op when there are already <= threshold points, or
    threshold is too small to bucket (<3, since first+last are always kept)."""
    n = len(xs)
    if threshold >= n or threshold < 3 or n == 0:
        return xs, ys

    sampled_x = [xs[0]]
    sampled_y = [ys[0]]
    # Bucket size for the *middle* points only (first/last are fixed).
    bucket_size = (n - 2) / (threshold - 2)
    a = 0  # index of the last kept point
    for i in range(threshold - 2):
        bucket_start = int((i + 0) * bucket_size) + 1
        bucket_end = int((i + 1) * bucket_size) + 1
        bucket_end = min(bucket_end, n - 1)
        if bucket_end <= bucket_start:
            bucket_end = bucket_start + 1

        # Average point of the *next* bucket (its "effective" point).
        next_start = bucket_end
        next_end = int((i + 2) * bucket_size) + 1
        next_end = min(next_end, n)
        next_end = max(next_end, next_start + 1)
        avg_x = sum(xs[next_start:next_end]) / (next_end - next_start)
        avg_y = sum(ys[next_start:next_end]) / (next_end - next_start)

        point_ax, point_ay = xs[a], ys[a]
        best_area = -1.0
        best_idx = bucket_start
        for j in range(bucket_start, bucket_end):
            area = abs(
                (point_ax - avg_x) * (ys[j] - point_ay)
                - (point_ax - xs[j]) * (avg_y - point_ay)
            )
            if area > best_area:
                best_area = area
                best_idx = j

        sampled_x.append(xs[best_idx])
        sampled_y.append(ys[best_idx])
        a = best_idx

    sampled_x.append(xs[-1])
    sampled_y.append(ys[-1])
    return sampled_x, sampled_y


# --- diagnostics: run list for the multi-select -----------------------------

def list_runs_brief(store) -> list[dict[str, Any]]:
    rows = store.conn.execute(
        "SELECT id, tool, started_at FROM run ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return [{"id": r["id"], "tool": r["tool"], "started_at": r["started_at"]} for r in rows]


# --- diagnostics: metric picker (grouped by source) --------------------------

def metric_keys(store) -> dict[str, Any]:
    """Every known metric key, split into the two sources a chart can draw
    from: single-value-per-run ``run_metrics`` (cross-run trend), and stepped
    ``metric_series`` grouped by its own ``source`` column (intra-run /
    cross-run overlay), for the R-05 "metric picker grouped by source
    (collapsible)" control."""
    run_metric_keys = [
        r["key"] for r in store.conn.execute(
            "SELECT DISTINCT key FROM run_metrics ORDER BY key").fetchall()
    ]
    series_rows = store.conn.execute(
        "SELECT DISTINCT source, key FROM metric_series ORDER BY source, key"
    ).fetchall()
    grouped: dict[str, list[str]] = {}
    for r in series_rows:
        grouped.setdefault(r["source"], []).append(r["key"])
    return {"run_metrics": run_metric_keys, "series": grouped}


# --- diagnostics: cross-run trend over run_metrics ---------------------------

def run_metrics_trend(store, run_ids: list[int], keys: list[str]) -> dict[str, Any]:
    """One point per (run, key) — a trend line across the selected runs for
    each selected `run_metrics` key. Small (one row per run per key already),
    so no downsampling needed here."""
    if not run_ids or not keys:
        return {"runs": [], "series": {}}
    placeholders_r = ",".join("?" * len(run_ids))
    placeholders_k = ",".join("?" * len(keys))
    rows = store.conn.execute(
        f"SELECT run_id, key, value FROM run_metrics "
        f"WHERE run_id IN ({placeholders_r}) AND key IN ({placeholders_k})",
        (*run_ids, *keys),
    ).fetchall()
    runs = store.conn.execute(
        f"SELECT id, started_at FROM run WHERE id IN ({placeholders_r}) ORDER BY id",
        run_ids,
    ).fetchall()
    run_order = [r["id"] for r in runs]
    started = {r["id"]: r["started_at"] for r in runs}
    by_key: dict[str, dict[int, float]] = {k: {} for k in keys}
    for r in rows:
        if r["key"] in by_key:
            by_key[r["key"]][r["run_id"]] = r["value"]
    series = {
        k: [by_key[k].get(rid) for rid in run_order]
        for k in keys
    }
    return {
        "runs": [{"id": rid, "started_at": started.get(rid)} for rid in run_order],
        "series": series,
    }


# --- diagnostics: intra-run / cross-run overlay step series ------------------

def metric_series_data(
    store, run_ids: list[int], source: str, key: str, max_points: int = 1000,
) -> dict[str, Any]:
    """Per-run step series for one ``(source, key)``, LTTB-downsampled to at
    most ``max_points`` per run (R-05: downsample server-side, then send)."""
    if not run_ids:
        return {"source": source, "key": key, "series": {}}
    placeholders = ",".join("?" * len(run_ids))
    rows = store.conn.execute(
        f"SELECT run_id, step, ts, value FROM metric_series "
        f"WHERE run_id IN ({placeholders}) AND source=? AND key=? "
        f"ORDER BY run_id, step",
        (*run_ids, source, key),
    ).fetchall()
    by_run: dict[int, tuple[list[float], list[float]]] = {}
    for r in rows:
        xs, ys = by_run.setdefault(r["run_id"], ([], []))
        xs.append(float(r["step"]))
        ys.append(float(r["value"]))
    series = {}
    for run_id, (xs, ys) in by_run.items():
        dxs, dys = lttb(xs, ys, max_points)
        series[str(run_id)] = {"steps": dxs, "values": dys}
    return {"source": source, "key": key, "series": series}


# --- diagnostics: candidate score distribution (pre-binned) ------------------

def candidate_score_histogram(store, run_id: int, bins: int = 20) -> dict[str, Any]:
    """A pre-binned histogram of this run's advisory candidate scores (never
    raw per-candidate rows — R-05's "distributions stored/served pre-binned")."""
    rows = store.conn.execute(
        "SELECT score FROM candidate WHERE run_id=? AND score IS NOT NULL", (run_id,)
    ).fetchall()
    scores = [r["score"] for r in rows]
    if not scores:
        return {"run_id": run_id, "edges": [], "counts": [], "n": 0}
    lo, hi = min(scores), max(scores)
    if lo == hi:
        return {"run_id": run_id, "edges": [lo, hi], "counts": [len(scores)], "n": len(scores)}
    width = (hi - lo) / bins
    counts = [0] * bins
    for s in scores:
        idx = min(int((s - lo) / width), bins - 1)
        counts[idx] += 1
    edges = [lo + i * width for i in range(bins + 1)]
    return {"run_id": run_id, "edges": edges, "counts": counts, "n": len(scores)}


# --- diagnostics: bandit arm state -------------------------------------------

def bandit_arms(store) -> list[dict[str, Any]]:
    """Current Beta posteriors per (context, arm), plus the posterior mean, for
    the "bandit arm state" snapshot panel."""
    rows = store.conn.execute(
        "SELECT context, arm, alpha, beta, updated_at FROM bandit_posteriors "
        "ORDER BY context, arm"
    ).fetchall()
    out = []
    for r in rows:
        a, b = r["alpha"], r["beta"]
        mean = a / (a + b) if (a + b) else None
        out.append({"context": r["context"], "arm": r["arm"], "alpha": a, "beta": b,
                    "mean": mean, "updated_at": r["updated_at"]})
    return out


# --- diagnostics: model registry timeline ------------------------------------

def model_registry_timeline(store) -> list[dict[str, Any]]:
    rows = store.conn.execute(
        "SELECT name, version, feature_version, calibration, created_at FROM model "
        "ORDER BY created_at, id"
    ).fetchall()
    return [
        {"name": r["name"], "version": r["version"], "feature_version": r["feature_version"],
         "calibration": r["calibration"], "created_at": r["created_at"]}
        for r in rows
    ]


# --- store explorer (FR-UI-2, read-only, injection-safe) ---------------------
#
# Table names cannot be bound as SQL parameters, so every route below resolves
# the caller-supplied name against `sqlite_master` FIRST and only ever
# interpolates a name that query itself returned — never the raw request
# value directly. This makes the identifier "injection-safe" by construction
# (an attacker-controlled string can only ever select among real table names,
# never smuggle SQL), independent of the strict-identifier regex below, which
# exists as defense-in-depth / a fast reject.

import re as _re

_IDENT_RE = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def list_tables(store) -> list[str]:
    """Every ordinary user table in the store (never sqlite's own
    `sqlite_%`-prefixed internal tables)."""
    rows = store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r["name"] for r in rows]


def _resolve_table(store, name: str) -> str | None:
    """Validate ``name`` against the live table list; returns the exact name
    to interpolate, or None if it does not name a real table (rejects both
    malformed identifiers and anything not actually in `sqlite_master`,
    including views/virtual tables this explorer does not expose)."""
    if not name or not _IDENT_RE.match(name):
        return None
    row = store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row["name"] if row else None


def table_columns(store, name: str) -> list[str] | None:
    table = _resolve_table(store, name)
    if table is None:
        return None
    # `table` was just re-read from sqlite_master above, not the raw caller
    # value — see the module docstring.
    rows = store.conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    return [r["name"] for r in rows]


def browse_table(
    store, name: str, *, limit: int = 100, offset: int = 0,
) -> dict[str, Any] | None:
    """Read-only page of ``name``. Returns ``None`` if ``name`` is not a real
    table. ``limit``/``offset`` are always cast to ``int`` and clamped so a
    caller cannot smuggle SQL through them either (they are bound as
    parameters regardless, but the clamp also bounds response size)."""
    table = _resolve_table(store, name)
    if table is None:
        return None
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    cols = table_columns(store, table) or []
    total = store.conn.execute(f'SELECT COUNT(*) c FROM "{table}"').fetchone()["c"]
    rows = store.conn.execute(
        f'SELECT * FROM "{table}" LIMIT ? OFFSET ?', (limit, offset)
    ).fetchall()
    return {
        "table": table,
        "columns": cols,
        "rows": [[_jsonable(r[c]) for c in cols] for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def _jsonable(value: Any) -> Any:
    """`body.data` (and any future BLOB column) is bytes — never send raw
    bytes into a JSON response; summarize instead so the explorer stays
    read-only/display-only for binary columns."""
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    return value
