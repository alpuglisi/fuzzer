// Manufactured third variant for auth-session/node CWE-330/CWE-338 (Use
// of Insufficiently Random Values / Cryptographically Weak PRNG) --
// distinct from this cell's natural pair (vulnerable-2.js/idiomatic-2.js,
// which is about the express-session HMAC *secret*). This one targets a
// different token purpose entirely: a password-reset token generator, a
// common Express/Koa-style route handler idiom.
'use strict';

// BUG: builds the reset token out of Date.now() (a coarse, often-logged/
// guessable timestamp) and Math.random() (a non-cryptographic PRNG whose
// internal state is recoverable from a handful of observed outputs) --
// neither component is suitable as a security-sensitive secret.
function generateResetToken() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

module.exports = { generateResetToken };
