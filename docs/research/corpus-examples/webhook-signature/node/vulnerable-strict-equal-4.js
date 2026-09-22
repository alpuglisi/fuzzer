// Manufactured vulnerable variant, derived from
// idiomatic-timingsafe-equal-4.js. Naive `===` comparison instead of
// crypto.timingSafeEqual() -- the same timing-side-channel class as this
// cell's Python entry, expressed here via JavaScript's own short-
// circuiting string equality.
const crypto = require('crypto');

function verifyGithubWebhook(payload, signatureHeader, webhookSecret) {
  const expected = 'sha256=' + crypto.createHmac('sha256', webhookSecret).update(payload).digest('hex');
  return expected === signatureHeader;
}
