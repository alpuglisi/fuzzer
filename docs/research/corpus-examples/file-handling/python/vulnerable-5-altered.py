# vulnerable-5-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics". A distinct download idiom from this file's
# send_from_directory-misuse pair (vulnerable-2.py/idiomatic-2.py):
# pathlib-based path construction. Path traversal: the client-supplied
# filename is joined onto the reports directory with no confinement
# check of any kind before the file is opened and streamed back.
from pathlib import Path

from flask import Flask, request, send_file

app = Flask(__name__)
REPORTS_DIR = Path("/srv/app/reports")


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename", "")
    target = REPORTS_DIR / filename
    return send_file(target)
