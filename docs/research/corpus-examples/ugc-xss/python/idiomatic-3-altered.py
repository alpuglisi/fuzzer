# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 9 of 10). Derived from
# vulnerable-3-altered.py's real reviews-listing structure. Minimal-pair
# discipline: identical route, identical query, identical template.
# The ONLY mechanism difference: the review body is passed to
# render_template() as a plain `str`, not wrapped in Markup() -- so Jinja2's
# normal autoescaping (on by default for .html templates) applies to it
# exactly like every other value in this same dict.
from flask import Blueprint, render_template

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

    # IDIOMATIC: review bodies stay plain `str` values -- nothing marks
    # them "already safe" -- so Jinja2's own default autoescaping (on for
    # .html templates) HTML-escapes them exactly like any other value when
    # the template interpolates them.
    reviews = [{"id": r[0], "body": r[1], "author": r[2]} for r in rows]
    return render_template('reviews/list.html', reviews=reviews)

# Corresponding template fragment (templates/reviews/list.html) is
# byte-identical to vulnerable-3-altered.py's -- the safety comes entirely
# from `review.body` reaching the template as a plain string rather than a
# Markup instance:
#
#   {% for review in reviews %}
#     <div class="review">{{ review.body }}</div>
#   {% endfor %}
