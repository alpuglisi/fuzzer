"""
Source: jwilliamsresearch/os3-security-studio, app/routes/xss.py (secure()
route) + templates/xss/secure.html.
License: MIT (dual-licensed repo; software code is MIT per repository
LICENSE.md — see manifest.yaml)
Copyright (c) 2025 James Williams

Pattern: the idiomatic/safe sibling of vulnerable-1.py, in the same file and
using the same `| safe`-rendering template shape (see idiomatic-1.py's
counterpart template note below) -- but here the comment is run through
`bleach.clean()` (a real, actively-maintained allowlist HTML sanitizer)
*before* being stored, so the value that later reaches the `| safe` template
filter has already had disallowed tags/attributes stripped. This is the
"sanitize on the way in, trust it on the way out" idiom that real apps use
alongside (or instead of) escaping on the way out.
"""

import bleach
from flask import Blueprint, render_template, request, session, flash
from ..models.database import get_db_connection

xss_bp = Blueprint('xss', __name__)


@xss_bp.route('/secure', methods=['GET', 'POST'])
def secure():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        # SECURE: Sanitize input
        comment = bleach.clean(comment, tags=['b', 'i', 'em', 'strong'], strip=True)
        user_id = session.get('user_id', 1)

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

    return render_template('xss/secure.html', comments=comments)

# Corresponding template fragment (templates/xss/secure.html) is identical in
# shape to insecure.html's -- the safety comes entirely from bleach.clean()
# having already stripped disallowed markup before storage:
#
#   <div class="mt-2">{{ comment[0] | safe }}</div>
