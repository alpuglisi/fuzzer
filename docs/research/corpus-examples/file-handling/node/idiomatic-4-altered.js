// idiomatic-4-altered.js
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" -- a distinct mitigation technique from idiomatic-2.js's
// realpath-confinement approach: confined download via indirect
// reference. The client never supplies a path or filename at all. It
// supplies an opaque attachment id, which is looked up in the database
// for the real on-disk path -- there is no user-controlled string that
// ever reaches the filesystem layer, so there is nothing to traverse.
const express = require('express');
const Attachment = require('../models/Attachment');

const router = express.Router();

router.get('/attachments/:id/download', async (req, res) => {
  const attachment = await Attachment.findById(req.params.id);
  if (!attachment) return res.status(404).json({ error: 'not found' });

  // attachment.storagePath is a server-generated path recorded at upload
  // time (never derived from a client-supplied name), so no traversal
  // sequence in a request can influence which file gets served.
  res.download(attachment.storagePath, attachment.originalName);
});

module.exports = router;
