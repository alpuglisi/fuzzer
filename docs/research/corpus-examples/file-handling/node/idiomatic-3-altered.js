// idiomatic-3-altered.js
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" -- derived from vulnerable-3-altered.js's own real
// structure. Same busboy-based handler, hardened: the declared MIME type
// is checked against an explicit allowlist, the destination filename is
// generated server-side (never derived from the client-supplied original
// name), and the extension used is taken only from the allowlisted MIME
// type -- never from the client-supplied filename at all.
const express = require('express');
const Busboy = require('busboy');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const UPLOAD_DIR = path.join(__dirname, '..', 'public', 'uploads');

const ALLOWED_MIME_EXT = {
  'application/pdf': '.pdf',
  'image/png': '.png',
  'image/jpeg': '.jpg',
};

router.post('/upload/document', (req, res) => {
  const busboy = Busboy({ headers: req.headers });
  let rejected = false;

  busboy.on('file', (fieldname, file, info) => {
    const ext = ALLOWED_MIME_EXT[info.mimeType];
    if (!ext) {
      rejected = true;
      file.resume(); // drain and discard the stream
      return;
    }
    const safeName = crypto.randomBytes(16).toString('hex') + ext;
    const savePath = path.join(UPLOAD_DIR, safeName);
    file.pipe(fs.createWriteStream(savePath));
  });

  busboy.on('finish', () => {
    if (rejected) return res.status(415).json({ error: 'unsupported file type' });
    res.json({ status: 'uploaded' });
  });
  req.pipe(busboy);
});

module.exports = router;
