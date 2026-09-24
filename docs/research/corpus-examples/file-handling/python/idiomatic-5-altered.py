# idiomatic-5-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" -- derived from vulnerable-5-altered.py's own real
# structure. Same pathlib-based download route, hardened: the requested
# path is resolved and confirmed to be relative to REPORTS_DIR using
# Path.is_relative_to() (Python 3.9+) -- a different confinement
# technique from idiomatic-2.py's manual normpath()+startswith(os.sep)
# check, using the stdlib's own purpose-built path-containment API
# instead of a hand-rolled string comparison.
from pathlib import Path

from flask import Flask, abort, request, send_file

app = Flask(__name__)
REPORTS_DIR = Path("/srv/app/reports").resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename", "")
    candidate = (REPORTS_DIR / filename).resolve()

    if not candidate.is_relative_to(REPORTS_DIR):
        abort(403)

    return send_file(candidate)
