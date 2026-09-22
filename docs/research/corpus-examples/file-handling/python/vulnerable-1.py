"""
Excerpt from kaushikjadhav01/COVID-19-Detection-Flask-App-based-on-Chest-X-
rays-and-CT-Scans, app.py: the `/uploaded_chest` upload route. An
`ALLOWED_EXTENSIONS` allowlist is defined at module scope but never
actually checked here, and the `secure_filename()` call is commented out
-- any uploaded file is accepted and written to disk regardless of
extension/content. See manifest.yaml for repo/commit/license provenance.
Trimmed to the module-level config and the one route; the sibling
`/uploaded_ct` route repeats the identical pattern.
"""

from flask import Flask, render_template, request, session, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './flask_app/assets/images'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__, static_url_path='/assets',
            static_folder='./flask_app/assets',
            template_folder='./flask_app')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/uploaded_chest', methods=['POST', 'GET'])
def uploaded_chest():
   if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            # filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'upload_chest.jpg'))
