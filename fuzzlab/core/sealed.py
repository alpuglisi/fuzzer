"""The sealed blind-holdout record (migration 17, CC-CORE-0030, FR-ML-19).

The holdout's metrics are **sealed against the toolkit's summary surfaces**: they are
written to `holdout_metric`, never to `run_metrics`, so the report, the run page, the
diagnostics trends and the ML tab — which all read `run_metrics` — never show them, and
the store browser does not list the two tables (`SEALED_TABLES`). The one reader is
`reveal`, behind ``fuzzlab auto --reveal-holdout``, and every reveal is counted
(`holdout_reveal`), per membership version: looking at the holdout to tune a model uses
it up, and bumping ``fuzzlab.ml.holdout.HOLDOUT_VERSION`` (a new salt) refreshes it.

Sealed is not secret: the run page still lists each candidate's stored scores, and the
SQLite file can be opened directly. The seal keeps the toolkit itself from showing the
numbers casually; it is not access control.

A plain store module (no ML import), so ``--reveal-holdout`` works without the ML
package.
"""

from __future__ import annotations

#: Tables no generic store view may list or browse.
SEALED_TABLES = ("holdout_metric", "holdout_reveal")


def write_metrics(store, run_id: int, model_id: int, holdout_version: int,
                  metrics: dict) -> None:
    """Record one model's holdout metrics for a run (no commit)."""
    for key, value in sorted(metrics.items()):
        store.conn.execute(
            "INSERT INTO holdout_metric (run_id, model_id, holdout_version, key, value) "
            "VALUES (?,?,?,?,?)", (run_id, model_id, holdout_version, key, float(value)))


def reveal(store, run_id: int) -> dict:
    """Read a run's sealed holdout metrics and count the reveal.

    Returns ``{"metrics": {(model_id, version): {key: value}}, "reveals": n}`` where
    ``n`` is the store-wide number of reveals for the newest version among this run's
    metrics, this one included. A run with no holdout metrics records no reveal and
    returns ``{"metrics": {}, "reveals": 0}`` ("nothing to reveal")."""
    rows = store.conn.execute(
        "SELECT model_id, holdout_version, key, value FROM holdout_metric "
        "WHERE run_id=? ORDER BY model_id, key", (run_id,)).fetchall()
    if not rows:
        return {"metrics": {}, "reveals": 0}
    metrics: dict = {}
    for r in rows:
        metrics.setdefault((r["model_id"], r["holdout_version"]), {})[r["key"]] = r["value"]
    version = max(r["holdout_version"] for r in rows)
    store.conn.execute("INSERT INTO holdout_reveal (run_id, holdout_version) VALUES (?,?)",
                       (run_id, version))
    store.conn.commit()
    count = store.conn.execute(
        "SELECT COUNT(*) c FROM holdout_reveal WHERE holdout_version=?",
        (version,)).fetchone()["c"]
    return {"metrics": metrics, "reveals": count, "version": version}
