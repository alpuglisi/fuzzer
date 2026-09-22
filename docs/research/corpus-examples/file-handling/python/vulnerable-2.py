"""
Excerpt from mugenkyou/College_daddy, app.py: the `/api/download` route.
`path.lstrip('/')` only strips leading slashes -- it does not neutralize
`../` traversal segments -- and the resulting directory is passed
straight to `send_from_directory()` as its *base* directory argument
(werkzeug's traversal protection there only guards the filename argument,
not an attacker-controlled base directory). See manifest.yaml for
repo/commit/license provenance. Trimmed to the one route; unrelated
admin-upload/quiz/chat routes omitted (`os` and `send_from_directory`
are imported earlier in the source file).
"""

@app.route('/api/download')
def download():
    path = request.args.get('path')
    if not path or not os.path.isfile(path.lstrip('/')):
        return 'File not found', 404
    dir_name = os.path.dirname(path.lstrip('/'))
    file_name = os.path.basename(path)
    return send_from_directory(dir_name, file_name, as_attachment=True)
