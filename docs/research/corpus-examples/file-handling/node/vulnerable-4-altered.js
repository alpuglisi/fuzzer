// vulnerable-4-altered.js
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". A distinct download-sub-shape variant, standalone CWE-22,
// from this file's vulnerable-2.js/idiomatic-2.js pair: a plain
// res.download() call where the client-supplied `name` query parameter
// is joined directly onto the attachments directory with no confinement
// check of any kind.
const express = require('express');
const path = require('path');

const router = express.Router();
const ATTACH_DIR = path.join(__dirname, '..', 'storage', 'attachments');

router.get('/attachments/download', (req, res) => {
  const filePath = path.join(ATTACH_DIR, req.query.name);
  res.download(filePath, req.query.name);
});

module.exports = router;
