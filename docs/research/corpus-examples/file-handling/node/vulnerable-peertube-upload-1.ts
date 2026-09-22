// Manufactured vulnerable variant, derived from
// idiomatic-peertube-upload-1.ts (PeerTube, AGPL-3.0-or-later). Illustrates
// a common real-world anti-pattern: a custom/simplified upload handler that
// accepts the file straight from multipart form data and moves it into the
// public media directory without calling an equivalent of
// isVideoFileMimeTypeValid() -- trusting the client-supplied filename
// extension/Content-Type outright (CWE-434: Unrestricted Upload of File
// with Dangerous Type).
// License note: derived from AGPL-3.0 code -- see the idiomatic entry's
// license note; the same caution applies here.

export async function acceptVideoUpload (req: express.Request, res: express.Response) {
  const file = req.files['videofile'][0]

  // No mimetype/extension allowlist check (contrast: idiomatic side's
  // isVideoFileMimeTypeValid(files)) -- the upload is trusted purely on
  // the client-declared originalname/mimetype fields.
  const destination = join(CONFIG.STORAGE.VIDEOS_DIR, file.originalname)
  await moveFile(file.path, destination)

  res.json({ path: destination })
}
