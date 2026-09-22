"""
Excerpt from xuchengli/ai-answerer, app.py: `/upload` and `/uploads/<name>`
routes. Uses werkzeug's `secure_filename()` before `file.save()`, and
`send_from_directory()` (which itself confines the served path to
`UPLOAD_FOLDER`) for the matching download side. See manifest.yaml for
repo/commit/license provenance. Trimmed to the file-handling routes only;
unrelated TTS/LLM-answer routes and config (including a hardcoded demo
Redis URL/password in the source's `app.config` block) are omitted.
"""

import os
from flask import Flask, render_template, request, url_for, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'


@app.post('/upload')
def upload():
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return url_for('download_file', name=filename)

@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)
