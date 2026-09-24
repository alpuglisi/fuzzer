# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 9 of 10). Genuinely distinct third
# variant from vulnerable-1.py's template-side `| safe` filter and
# idiomatic-1.py/idiomatic-2.py's bleach.clean()-on-ingest idiom: this
# file's flaw is entirely on the PYTHON side, not in a template -- wrapping
# a stored comment in Flask/Jinja2's own Markup() class before it's ever
# passed to render_template(), which has the exact same effect as a
# template-side `| safe` filter but is a distinct real-world anti-pattern
# (a view function or serializer marking a string "already safe" instead of
# a template author choosing to disable autoescaping for one value).
from flask import Blueprint, render_template, request, session
from markupsafe import Markup

from ..models.database import get_db_connection

reviews_bp = Blueprint('reviews', __name__)


@reviews_bp.route('/product/<int:product_id>/reviews')
def list_reviews(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, body, author FROM reviews WHERE product_id = ? ORDER BY created_at DESC',
        (product_id,),
    )
    rows = cursor.fetchall()
    conn.close()

    # VULNERABLE: Markup() marks a value as "already-safe HTML" -- exactly
    # what Jinja2's `| safe` filter does at the template layer, but done
    # here in the view function itself, over every stored review body,
    # before the template ever sees it. render_template()'s own autoescaping
    # is bypassed for this value regardless of what the template does with
    # it, since Markup instances are never re-escaped.
    reviews = [{"id": r[0], "body": Markup(r[1]), "author": r[2]} for r in rows]
    return render_template('reviews/list.html', reviews=reviews)

# Corresponding template fragment (templates/reviews/list.html):
#
#   {% for review in reviews %}
#     <div class="review">{{ review.body }}</div>
#   {% endfor %}
#
# Note: {{ review.body }} has NO |safe filter here -- it doesn't need one,
# because `review.body` is already a Markup instance by the time the
# template renders it, which Jinja2 treats as pre-escaped regardless of the
# template's own autoescape setting.
