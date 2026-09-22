"""
Source: jwilliamsresearch/os3-security-studio, app/routes/xss.py (insecure()
route) + templates/xss/insecure.html.
License: MIT (dual-licensed repo; software code is MIT per repository
LICENSE.md — see manifest.yaml)
Copyright (c) 2025 James Williams

Pattern: a real Flask teaching app deliberately ships a matched
vulnerable/secure pair of comment routes for the same feature (see
idiomatic-1.py for the secure() sibling in the same file). The insecure route
takes a posted comment, inserts it into the `comments` table completely
unsanitized, and the paired template renders every stored comment with
Jinja2's `| safe` filter:

    <div class="mt-2">{{ comment[0] | safe }}</div>

`| safe` disables Jinja2's autoescaping for that value, so any HTML/script an
attacker stored in `comment` is rendered as live markup for every later
visitor viewing this page — a real stored-XSS comment pipeline, not just a
reflected-parameter case.
"""

from flask import Blueprint, render_template, request, session, flash
from ..models.database import get_db_connection

xss_bp = Blueprint('xss', __name__)


@xss_bp.route('/insecure', methods=['GET', 'POST'])
def insecure():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        user_id = session.get('user_id', 1)  # Default to user 1 if not logged in

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO comments (user_id, content) VALUES (?, ?)', (user_id, comment))
        conn.commit()
        conn.close()

        flash('Comment added!', 'success')

    # Get all comments
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.content, u.username, c.created_at
        FROM comments c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
    ''')
    comments = cursor.fetchall()
    conn.close()

    return render_template('xss/insecure.html', comments=comments)

# Corresponding template fragment (templates/xss/insecure.html):
#
#   {% for comment in comments %}
#     <strong>{{ comment[1] }}</strong>
#     <small class="text-muted">{{ comment[2] }}</small>
#     <div class="mt-2">{{ comment[0] | safe }}</div>
#   {% endfor %}
