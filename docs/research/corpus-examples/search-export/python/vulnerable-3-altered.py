# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 4 of 10). Genuinely distinct third
# variant from vulnerable-1.py/idiomatic-1.py's Django-ORM-escape-hatch shape
# (QuerySet.extra(where=...) vs .filter(Q(...))): a raw psycopg2 driver-level
# order/export endpoint, with no ORM involved at all -- f-string
# interpolation directly into the SQL text passed to cursor.execute().
import psycopg2


def export_orders(conn, search: str, sort_by: str) -> list:
    cursor = conn.cursor()
    # VULNERABLE: both `search` and `sort_by` are interpolated directly into
    # the SQL text via an f-string before it ever reaches cursor.execute() --
    # psycopg2's own documentation is explicit that this bypasses its driver-
    # level parameter substitution entirely, and is not equivalent to using
    # `%s` placeholders even though the connection/cursor objects are
    # identical in both files.
    query = f"""
        SELECT id, customer_name, total, created_at FROM orders
        WHERE customer_name LIKE '%{search}%'
        ORDER BY {sort_by}
    """
    cursor.execute(query)
    return cursor.fetchall()
