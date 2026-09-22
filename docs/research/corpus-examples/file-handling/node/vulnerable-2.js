/*
 * Excerpt from Tzahi12345/YoutubeDL-Material, backend/app.js: the
 * `/api/thumbnail/:path` route. `req.params.path` is decoded and used
 * directly -- `path.isAbsolute(file_path)` lets an attacker supply an
 * absolute path (or a `../`-relative one joined under `__dirname`) with
 * no canonicalization/confinement check before `res.sendFile()`.
 * See manifest.yaml for repo/commit/license provenance. Trimmed to the
 * one route; unrelated routes/config omitted (`fs` and `path` are
 * required earlier in the source file).
 */

app.get('/api/thumbnail/:path', optionalJwt, async (req, res) => {
    let file_path = decodeURIComponent(req.params.path);
    if (fs.existsSync(file_path)) path.isAbsolute(file_path) ? res.sendFile(file_path) : res.sendFile(path.join(__dirname, file_path));
    else res.sendStatus(404);
});
