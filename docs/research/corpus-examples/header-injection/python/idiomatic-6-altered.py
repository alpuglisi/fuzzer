# idiomatic-6-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics". HTTP response header variant of this cell's CRLF-injection
# class -- distinct from idiomatic-emailmessage-structured-3.py's
# SMTP/email headers: sets the response header through Flask's own
# Headers API, which rejects embedded CR/LF at the werkzeug layer,
# rather than building the raw header line as a string.
from flask import Flask, make_response

app = Flask(__name__)


@app.route("/bookings/<booking_id>/receipt")
def download_receipt(booking_id):
    resp = make_response(render_receipt(booking_id))
    # Headers.__setitem__ raises ValueError if the value contains a
    # newline -- the framework itself is the enforcement point, not a
    # manual check here.
    resp.headers["X-Booking-Reference"] = booking_id
    resp.headers["Content-Disposition"] = f"attachment; filename=receipt-{booking_id}.pdf"
    return resp


def render_receipt(booking_id):
    return b"%PDF-1.4 ..."
