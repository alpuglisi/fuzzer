// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". Missing idiomatic counterpart for
// vulnerable-peertube-upload-1.ts's combined CWE-20/CWE-22/CWE-434 shape
// (this cell's own manifest.yaml entry: a manufactured simplified upload
// handler that both skips a mimetype allowlist check AND builds its
// destination path from the client-supplied `file.originalname` with no
// sanitization, so it is vulnerable to unrestricted upload AND path
// traversal at once -- distinct from idiomatic-peertube-upload-1.ts,
// which is a verbatim PeerTube excerpt covering only the mimetype-check
// half of that combined shape).
//
// Minimal-pair discipline: identical function signature, identical
// overall shape (destructure the uploaded file, validate, move it, return
// its path), same imports as the vulnerable twin plus the two additions
// the fix requires (a mimetype allowlist and `basename`). The ONLY
// mechanism differences are (1) an explicit mimetype allowlist check
// before anything is moved, mirroring the real isVideoFileMimeTypeValid()
// gate idiomatic-peertube-upload-1.ts documents, and (2) deriving the
// destination filename from `basename(file.originalname)` stripped to a
// safe character set, so a filename like `../../etc/cron.d/x` can no
// longer escape CONFIG.STORAGE.VIDEOS_DIR.
// License note: like its vulnerable twin, this is a manufactured handler
// derived from AGPL-3.0-or-later PeerTube source (see
// idiomatic-peertube-upload-1.ts's own license note) -- the same caution
// applies here.

import { basename, join } from 'path'

const ALLOWED_VIDEO_MIME_TYPES = new Set([
  'video/mp4',
  'video/webm',
  'video/ogg',
  'video/quicktime'
])

export async function acceptVideoUpload (req: express.Request, res: express.Response) {
  const file = req.files['videofile'][0]

  // SAFE: an explicit mimetype allowlist check (contrast: vulnerable
  // twin's total absence of any content-type check) -- mirrors the real
  // isVideoFileMimeTypeValid(files) gate idiomatic-peertube-upload-1.ts
  // shows in commonVideoFileChecks().
  if (!ALLOWED_VIDEO_MIME_TYPES.has(file.mimetype)) {
    res.status(415).json({ error: 'unsupported video mimetype' })
    return
  }

  // SAFE: the stored filename is derived from basename() (strips any
  // directory component, defeating '../' traversal) and then reduced to
  // a safe character set, so the destination can never resolve outside
  // CONFIG.STORAGE.VIDEOS_DIR regardless of what file.originalname
  // contains (contrast: vulnerable twin's unsanitized
  // join(VIDEOS_DIR, file.originalname)).
  const safeName = basename(file.originalname).replace(/[^a-zA-Z0-9_.-]/g, '_')
  const destination = join(CONFIG.STORAGE.VIDEOS_DIR, safeName)
  await moveFile(file.path, destination)

  res.json({ path: destination })
}
