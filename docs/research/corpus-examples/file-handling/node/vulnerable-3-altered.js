// vulnerable-3-altered.js
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". A distinct upload-handler idiom from this file's multer-
// based pair (vulnerable-1.js/idiomatic-1.js) and the peertube-upload
// pair: a hand-rolled busboy handler (no multer at all). Unrestricted
// upload: the upload's declared MIME type and original filename are both
// trusted outright, with no allowlist and no sanitization of either.
const express = require('express');
const Busboy = require('busboy');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const UPLOAD_DIR = path.join(__dirname, '..', 'public', 'uploads');

router.post('/upload/document', (req, res) => {
  const busboy = Busboy({ headers: req.headers });

  busboy.on('file', (fieldname, file, info) => {
    // No mimetype allowlist, no extension check, no filename
    // sanitization: the client-declared original filename is used
    // verbatim as the destination path under the web-served uploads
    // directory.
    const savePath = path.join(UPLOAD_DIR, info.filename);
    file.pipe(fs.createWriteStream(savePath));
  });

  busboy.on('finish', () => res.json({ status: 'uploaded' }));
  req.pipe(busboy);
});

module.exports = router;
