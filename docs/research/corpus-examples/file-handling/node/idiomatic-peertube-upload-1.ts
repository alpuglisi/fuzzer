// Excerpt of PeerTube, server/core/middlewares/validators/videos/shared/
// video-validators.ts (AGPL-3.0-or-later). Source: repo Chocobozzz/PeerTube,
// commit faa76bad2c1969a088ef1df38dc666dfe7259b5c.
// License note: AGPL-3.0 (copyleft) -- kept to the single illustrative
// function per this corpus's copyleft-handling rule.

export async function commonVideoFileChecks (options: {
  req: express.Request
  res: express.Response
  channelUser: MUserId
  videoFileSize: number
  files: express.UploadFilesForCheck
}): Promise<boolean> {
  const { req, res, channelUser, videoFileSize, files } = options

  if (!isVideoFileMimeTypeValid(files)) {
    res.fail({
      status: HttpStatusCode.UNSUPPORTED_MEDIA_TYPE_415,
      message: req.t(
        'This file is not supported. Please, make sure it is of the following type: {types}',
        { types: CONSTRAINTS_FIELDS.VIDEOS.EXTNAME.join(', ') }
      )
    })
    return false
  }

  if (!isVideoFileSizeValid(videoFileSize.toString())) {
    res.fail({
      status: HttpStatusCode.PAYLOAD_TOO_LARGE_413,
      message: req.t('This file is too large. It exceeds the maximum file size authorized'),
      type: ServerErrorCode.MAX_FILE_SIZE_REACHED
    })
    return false
  }

  if (await checkUserQuota({ channelUser, uploadSize: videoFileSize, req, res }) === false) return false

  return true
}
