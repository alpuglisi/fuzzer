# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 4 of 10). Derived from
# vulnerable-3-altered.py's real psycopg2 structure. Minimal-pair discipline:
# identical function signature, identical query shape and column list. The
# ONLY mechanism difference: `search` is bound via psycopg2's own `%s`
# placeholder substitution (a value position, which psycopg2 can safely
# parameterize), and `sort_by` -- a SQL identifier, which no driver-level
# parameter placeholder can bind -- is checked against SORTABLE_COLUMNS
# before being placed in the query text at all.
import psycopg2

SORTABLE_COLUMNS = {"id", "customer_name", "total", "created_at"}


def export_orders(conn, search: str, sort_by: str) -> list:
    cursor = conn.cursor()
    # IDIOMATIC: the LIKE value is bound through psycopg2's own %s
    # placeholder (the driver sends it as a separate parameter, never as
    # part of the SQL text); the ORDER BY column -- which %s cannot bind,
    # since it's an identifier rather than a value -- is validated against
    # an explicit allowlist of the table's real column names first.
    column = sort_by if sort_by in SORTABLE_COLUMNS else "id"
    query = f"""
        SELECT id, customer_name, total, created_at FROM orders
        WHERE customer_name LIKE %s
        ORDER BY {column}
    """
    cursor.execute(query, (f"%{search}%",))
    return cursor.fetchall()
