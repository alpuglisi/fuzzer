# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics". Missing idiomatic counterpart for vulnerable-1.py's CWE-639/
# CWE-862/CWE-915 IDOR shape (this cell's own manifest.yaml entry for
# vulnerable-1.py). See manifest.yaml's own entry for this file for the
# deliberate design-choice note: vulnerable-1.py is unusually a
# documentation/prompt-library file (an LLM code-reviewer's own IDOR
# detection prompt, embedding several vulnerable/safe Flask snippets
# inline as illustrative text) rather than live route code, so this
# counterpart is written as an actual, standalone, runnable Flask route
# module instead of mirroring that odd prompt-library format -- drawing
# the general shape from the exact pattern vulnerable-1.py itself
# documents (`Invoice.query.filter_by(id=x, user_id=current_user.id)`),
# so the corpus gains one real IDOR-fixed route rather than another prompt
# document. Minimal-pair discipline: this file and a hypothetical
# vulnerable twin of it would differ *only* in the presence of the
# `user_id=current_user.id` filter (i.e. the ownership check) -- same
# imports, same route, same model, same response shape.

from flask import Blueprint, jsonify
from flask_login import login_required, current_user

from models import Invoice

invoices_bp = Blueprint("invoices", __name__)


@invoices_bp.route("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    # SAFE: the primary-key lookup is scoped to the caller's own rows via
    # an explicit `user_id=current_user.id` filter, so a caller can never
    # fetch another user's invoice by guessing/incrementing invoice_id
    # (CWE-639/CWE-862/CWE-915's IDOR shape). `first_or_404()` returns the
    # same 404 for "doesn't exist" and "exists but isn't yours", so the
    # response also doesn't leak which case occurred.
    invoice = Invoice.query.filter_by(
        id=invoice_id, user_id=current_user.id
    ).first_or_404()
    return jsonify(invoice.to_dict())
