"""Saved views: UI-owned filter/sort/column presets over a DataTable-backed
section (U2 findings first; the ``table`` key makes this reusable by any
other section, e.g. a future recent-runs or store-explorer view).

Persisted in the project store's ``saved_views`` table (migration 12,
fuzzlab/core/migrations.py). This is a UI-view-preference table, not a result
table — the invariant in docs/UI_IMPLEMENTATION_PLAN.md §2 ("UI writes no
result tables") is about `finding`/`attempt`/etc., which stay tool-written;
the control panel is the sole writer of `saved_views`, the same footing as
`repeater_tab`. Kept pure/dependency-light like ``results.py`` so the route
layer (``app.py``) stays a thin translation to/from JSON.
"""

from __future__ import annotations

import json
from typing import Any


def _row(row) -> dict[str, Any]:
    try:
        spec = json.loads(row["spec_json"]) if row["spec_json"] else {}
    except (ValueError, TypeError):
        spec = {}
    return {
        "id": row["id"],
        "table": row["table_key"],
        "name": row["name"],
        "spec": spec,
        "pinned": bool(row["is_pinned"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_views(store, table: str) -> list[dict[str, Any]]:
    """Every saved view for ``table``, pinned first, newest first."""
    rows = store.conn.execute(
        "SELECT id, table_key, name, spec_json, is_pinned, created_at, updated_at "
        "FROM saved_views WHERE table_key=? ORDER BY is_pinned DESC, id DESC",
        (table,)).fetchall()
    return [_row(r) for r in rows]


def get_view(store, view_id: int) -> dict[str, Any] | None:
    row = store.conn.execute(
        "SELECT id, table_key, name, spec_json, is_pinned, created_at, updated_at "
        "FROM saved_views WHERE id=?", (view_id,)).fetchone()
    return _row(row) if row else None


def create_view(store, table: str, name: str, spec: dict[str, Any],
                pinned: bool = False) -> dict[str, Any]:
    cur = store.conn.execute(
        "INSERT INTO saved_views (table_key, name, spec_json, is_pinned) "
        "VALUES (?,?,?,?)",
        (table, name, json.dumps(spec), int(bool(pinned))))
    store.conn.commit()
    return get_view(store, int(cur.lastrowid))


def update_view(store, view_id: int, *, name: str | None = None,
                spec: dict[str, Any] | None = None,
                pinned: bool | None = None) -> dict[str, Any] | None:
    """Partial update; a field left as ``None`` keeps its current value."""
    existing = get_view(store, view_id)
    if existing is None:
        return None
    new_name = existing["name"] if name is None else name
    new_spec = existing["spec"] if spec is None else spec
    new_pinned = existing["pinned"] if pinned is None else bool(pinned)
    store.conn.execute(
        "UPDATE saved_views SET name=?, spec_json=?, is_pinned=?, "
        "updated_at=datetime('now') WHERE id=?",
        (new_name, json.dumps(new_spec), int(bool(new_pinned)), view_id))
    store.conn.commit()
    return get_view(store, view_id)


def delete_view(store, view_id: int) -> bool:
    cur = store.conn.execute("DELETE FROM saved_views WHERE id=?", (view_id,))
    store.conn.commit()
    return cur.rowcount > 0
