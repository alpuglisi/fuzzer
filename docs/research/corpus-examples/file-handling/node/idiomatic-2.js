/*
 * Excerpt from Aman9690/clash-config-editor, backend/server.js: the
 * `isValidFilename` allowlist check plus a `fs.realpath()` confinement
 * check (belt-and-suspenders: the filename itself is restricted to a
 * safe character set with no path separators, and the resolved real
 * path is also verified to stay under `configDir`) on the
 * `/api/files/read/:filename` route. See manifest.yaml for repo/commit/
 * license provenance. Trimmed to the relevant helper + route; unrelated
 * auth/upload/save routes omitted (`fs/promises` and `path` are
 * imported earlier in the source file).
 */

const isValidFilename = (filename) => {
  if (!filename || typeof filename !== 'string') {
    return false;
  }

  const normalized = path.normalize(filename);

  if (normalized.includes('..') ||
      normalized.includes('/') ||
      normalized.includes('\\') ||
      path.isAbsolute(normalized)) {
    return false;
  }

  if (!/^[a-zA-Z0-9_\-\.]+$/.test(filename)) {
    return false;
  }

  return true;
};

app.get('/api/files/read/:filename', authMiddleware, async (req, res) => {
  try {
    const filename = req.params.filename;

    if (!isValidFilename(filename)) {
      return res.status(400).json({ success: false, error: 'Invalid filename' });
    }

    const filePath = path.join(configDir, filename);
    const realPath = await fs.realpath(filePath).catch(() => null);

    if (!realPath || !realPath.startsWith(await fs.realpath(configDir))) {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }

    const stats = await fs.stat(realPath);
    if (!stats.isFile()) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    const content = await fs.readFile(realPath, 'utf8');
    const config = yaml.load(content);

    res.json({
      success: true,
      filename,
      content,
      config
    });
  } catch (error) {
    if (error.code === 'ENOENT') {
      res.status(404).json({ success: false, error: 'File not found' });
    } else {
      res.status(400).json({ success: false, error: 'Failed to read file' });
    }
  }
});
