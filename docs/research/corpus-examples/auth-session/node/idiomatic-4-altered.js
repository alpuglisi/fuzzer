// Idiomatic counterpart to vulnerable-4-altered.js (auth-session/node,
// CWE-330/CWE-338). Differs only in the token-generation mechanism: a
// CSPRNG (`crypto.randomBytes`) replaces the Date.now()+Math.random()
// construction, with no dependency on a timestamp or a non-cryptographic
// PRNG.
'use strict';

const crypto = require('crypto');

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { generateResetToken };
