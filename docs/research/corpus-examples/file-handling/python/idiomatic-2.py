"""
Excerpt from laurentftech/Podcast_generator, app.py: the
`/demos/<demo_id>/<path:filename>` route. Resolves the requested demo
directory with `os.path.normpath(os.path.abspath(...))` and rejects the
request unless the resolved path is confined under `DEMOS_DIR` (checked
with a trailing `os.sep` to avoid a sibling-directory prefix bypass,
e.g. `demos_evil` matching a `demos_base` startswith check with no
separator). See manifest.yaml for repo/commit/license provenance.
Trimmed to the one route; unrelated generation/settings routes omitted
(`os` and `send_from_directory` are imported earlier in the source
file).
"""

@app.route('/demos/<demo_id>/<path:filename>')
def serve_demo_file(demo_id, filename):
    demo_dir = os.path.join(app.config['DEMOS_DIR'], demo_id)
    # Validate demo_dir is inside DEMOS_DIR
    normalized_demo_dir = os.path.normpath(os.path.abspath(demo_dir))
    demos_base = os.path.abspath(app.config['DEMOS_DIR'])
    if not normalized_demo_dir.startswith(demos_base + os.sep):
        return "Invalid demo ID", 400
    return send_from_directory(normalized_demo_dir, filename)
