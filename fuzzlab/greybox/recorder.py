"""Persist grey-box signals onto an existing `attempt` row.

The fuzzer writes the `attempt` first (payload family, screening features); grey-box
then **enriches** that row with the coverage blob, the DB-fault flag, and the
recomputed shaped reward. Fills the columns migration 1 already reserved
(`attempt.coverage`, `attempt.db_fault`) — rows, not schema (no migration).
"""

from __future__ import annotations


def record_attempt_signals(store, attempt_id: int, *,
                           coverage: str | None = None,
                           db_fault: bool | None = None,
                           reward: float | None = None) -> None:
    """Update the given attempt's grey-box columns. Only provided fields are set."""
    sets: list[str] = []
    params: list[object] = []
    if coverage is not None:
        sets.append("coverage=?")
        params.append(coverage)
    if db_fault is not None:
        sets.append("db_fault=?")
        params.append(1 if db_fault else 0)
    if reward is not None:
        sets.append("reward=?")
        params.append(float(reward))
    if not sets:
        return
    params.append(int(attempt_id))
    store.conn.execute(
        f"UPDATE attempt SET {', '.join(sets)} WHERE id=?", params)
    store.conn.commit()
