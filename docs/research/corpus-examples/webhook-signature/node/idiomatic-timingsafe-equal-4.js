// Manufactured, representative of the well-documented real pattern for
// GitHub-style webhook verification: crypto.timingSafeEqual() for a
// constant-time comparison, with a length check first since
// timingSafeEqual() throws on mismatched buffer lengths (a documented
// Node API constraint, not incidental).
const crypto = require('crypto');

function verifyGithubWebhook(payload, signatureHeader, webhookSecret) {
  const expected = 'sha256=' + crypto.createHmac('sha256', webhookSecret).update(payload).digest('hex');
  const expectedBuf = Buffer.from(expected);
  const actualBuf = Buffer.from(signatureHeader);

  if (expectedBuf.length !== actualBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}
