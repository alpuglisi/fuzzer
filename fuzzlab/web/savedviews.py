"""Server-side saved views for faceted workbenches (U2, CC-UI-0029, R-03).

`saved_views` persists a named filter/sort/column spec per logical dataset
(`table_key`, e.g. `"finding"`) -- durable and readable back by anyone opening
the panel, unlike `localStorage` (per-viewer only; the Findings workbench uses
that instead for throwaway state such as the last-selected view id or a draft
filter string). A spec is `{version, name, pinned, filter: {text, facets,
predicates}, sort, columns}` (R-03); this module treats `spec` as an opaque
dict and only reads/writes the envelope columns around it.

`saved_views` is itself not a `finding`/`attempt`/`candidate`/flow result
table (NFR-UI-read-only: "the UI writes no result tables") -- it holds view
*definitions* a person authored in the panel, not tool output, so this is the
one deliberate write path the Findings (and later, other workbench) sections
get.
"""

from __future__ import annotations

import json
from typing import Any

from fuzzlab.core.store import Store


def _row(r) -> dict[str, Any]:
    d = dict(r)
    try:
        spec = json.loads(d.pop("spec_json") or "{}")
    except (ValueError, TypeError):
        spec = {}
    d["spec"] = spec if isinstance(spec, dict) else {}
    d["is_pinned"] = bool(d["is_pinned"])
    return d


def list_views(store: Store, table_key: str) -> list[dict[str, Any]]:
    rows = store.conn.execute(
        "SELECT id, table_key, name, spec_json, is_pinned, created_at, updated_at "
        "FROM saved_views WHERE table_key=? ORDER BY is_pinned DESC, id",
        (table_key,)).fetchall()
    return [_row(r) for r in rows]


def get_view(store: Store, view_id: int) -> dict[str, Any] | None:
    row = store.conn.execute(
        "SELECT id, table_key, name, spec_json, is_pinned, created_at, updated_at "
        "FROM saved_views WHERE id=?", (view_id,)).fetchone()
    return _row(row) if row else None


def create_view(store: Store, table_key: str, name: str, spec: dict[str, Any],
                pinned: bool = False) -> dict[str, Any]:
    cur = store.conn.execute(
        "INSERT INTO saved_views (table_key, name, spec_json, is_pinned) "
        "VALUES (?,?,?,?)",
        (table_key, name, json.dumps(spec), int(bool(pinned))))
    store.conn.commit()
    return get_view(store, cur.lastrowid)


def update_view(store: Store, view_id: int, *, name: str | None = None,
                spec: dict[str, Any] | None = None,
                pinned: bool | None = None) -> dict[str, Any] | None:
    if get_view(store, view_id) is None:
        return None
    sets: list[str] = []
    params: list[Any] = []
    if name is not None:
        sets.append("name=?")
        params.append(name)
    if spec is not None:
        sets.append("spec_json=?")
        params.append(json.dumps(spec))
    if pinned is not None:
        sets.append("is_pinned=?")
        params.append(int(bool(pinned)))
    sets.append("updated_at=datetime('now')")
    params.append(view_id)
    store.conn.execute(f"UPDATE saved_views SET {', '.join(sets)} WHERE id=?", params)
    store.conn.commit()
    return get_view(store, view_id)


def delete_view(store: Store, view_id: int) -> bool:
    cur = store.conn.execute("DELETE FROM saved_views WHERE id=?", (view_id,))
    store.conn.commit()
    return cur.rowcount > 0
