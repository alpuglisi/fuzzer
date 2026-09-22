"""Read-only, generic store-table browsing for the Diagnostics tab's store
explorer (U5, FR-UI-17) — a small Datasette-style "pick a table, see rows"
view over the same SQLite store every other read-only panel uses.

Safety (non-negotiable per CLAUDE.md / the invariants this lane must hold):
this module never writes, and it never renders a raw secret. Two independent
redaction rules apply at render time, before a row ever reaches the template
or the JSON API — reusing the SAME substring convention `core.config._redact`
/ `core.obs._redact` already use elsewhere in this codebase, for one
consistent security policy rather than a second bespoke one:

  1. **Column-name redaction.** Any column whose name contains one of
     ``_REDACT_TOKENS`` (password/secret/token/credential/cookie/authorization)
     is masked, regardless of table. This is deliberately over-inclusive: e.g.
     ``session_state.token_exp`` is a plain float expiry timestamp, not a
     secret, but it is masked anyway because erring safe on a generic,
     ad-hoc browser over the whole store is worth more than showing one
     expiry column. `session_state` itself stores only non-secret metadata
     by design (migration 3) — this is defense in depth, not a sign it holds
     credentials.
  2. **BLOB redaction.** Every BLOB-affinity column (`body.data`,
     `repeater_tab.raw_request`, `flow.req_raw_sha`/`resp_raw_sha` point at
     redacted-on-write bytes, but the underlying `body` blobs a crawl or
     candidate might reference are NOT guaranteed redacted) is NEVER decoded
     or rendered — only its byte length, as ``<blob: N bytes>``. A generic
     table browser has no way to know a given blob is safe to show raw, so it
     never tries.

FTS5 shadow tables (`<name>_fts_*`) and the internal `schema_version` table
are excluded from the table list — they are storage implementation detail,
not data a user is browsing.
"""

from __future__ import annotations

from typing import Any

# Same substring convention as fuzzlab.core.config._REDACT_KEYS and
# fuzzlab.core.obs._REDACT — one policy, applied here at the column-name
# level instead of a JSON-dict-value level.
_REDACT_TOKENS = ("password", "secret", "token", "credential", "cookie", "authorization")

_REDACTED = "***redacted***"
_MAX_CELL_LEN = 500  # generic browser: truncate pathologically long text, never binary


def _is_redacted_column(name: str) -> bool:
    lname = name.lower()
    return any(tok in lname for tok in _REDACT_TOKENS)


def list_tables(store) -> list[dict[str, Any]]:
    """Every user table in the store (name + column names), excluding FTS5
    shadow tables and sqlite/schema-version internals."""
    rows = store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' AND name != 'schema_version' "
        "AND name NOT LIKE '%_fts_%' AND name NOT LIKE '%_fts' "
        "ORDER BY name"
    ).fetchall()
    out = []
    for r in rows:
        cols = store.conn.execute(f"PRAGMA table_info({r['name']})").fetchall()
        out.append({
            "name": r["name"],
            "columns": [{"name": c["name"], "type": c["type"],
                        "redacted": _is_redacted_column(c["name"])}
                       for c in cols],
        })
    return out


def table_exists(store, table: str) -> bool:
    return any(t["name"] == table for t in list_tables(store))


def _render_cell(value: Any, col_type: str, redacted: bool) -> Any:
    if redacted:
        return _REDACTED if value is not None else None
    if isinstance(value, bytes) or (col_type or "").upper() == "BLOB":
        n = len(value) if isinstance(value, (bytes, bytearray)) else 0
        return f"<blob: {n} bytes>"
    if isinstance(value, str) and len(value) > _MAX_CELL_LEN:
        return value[:_MAX_CELL_LEN] + "…"
    return value


def table_rows(store, table: str, *, limit: int = 100, offset: int = 0) -> dict[str, Any] | None:
    """A page of one table's rows, redacted at render time. ``None`` if
    ``table`` isn't a real, allow-listed table (never trusts a raw path
    param into SQL — the name is re-validated against ``list_tables`` here,
    not just quoted)."""
    tables = {t["name"]: t for t in list_tables(store)}
    meta = tables.get(table)
    if meta is None:
        return None
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    col_types = {c["name"]: c["type"] for c in meta["columns"]}
    redacted_cols = {c["name"] for c in meta["columns"] if c["redacted"]}

    total = store.conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
    # `table` is validated against list_tables()'s sqlite_master-derived allow-list
    # above, never taken raw from the request, so this is not string-built SQLi.
    rows = store.conn.execute(
        f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()

    out_rows = []
    for row in rows:
        d = dict(row)
        out_rows.append({
            k: _render_cell(v, col_types.get(k, ""), k in redacted_cols)
            for k, v in d.items()
        })

    return {
        "table": table,
        "columns": meta["columns"],
        "rows": out_rows,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
