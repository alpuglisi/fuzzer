# vulnerable-6-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" -- derived from idiomatic-6-altered.py's own real structure,
# altered ONLY in how the response headers are written: instead of
# Flask's Headers API, the handler builds the raw status+header block as
# a plain WSGI header list and writes booking_id straight into it via
# start_response(), bypassing werkzeug's own CRLF rejection entirely.
from urllib.parse import parse_qs


def download_receipt_app(environ, start_response):
    query = parse_qs(environ.get("QUERY_STRING", ""))
    booking_id = query.get("booking_id", [""])[0]

    body = render_receipt(booking_id)
    headers = [
        ("Content-Type", "application/pdf"),
        # Business-logic-adjacent CRLF injection: booking_id is
        # interpolated directly into a raw header value with no CRLF
        # stripping, and passed straight to start_response(), which
        # (unlike werkzeug's Headers class) performs no validation of
        # its own.
        ("X-Booking-Reference", booking_id),
        ("Content-Disposition", f"attachment; filename=receipt-{booking_id}.pdf"),
    ]
    start_response("200 OK", headers)
    return [body]


def render_receipt(booking_id):
    return b"%PDF-1.4 ..."
