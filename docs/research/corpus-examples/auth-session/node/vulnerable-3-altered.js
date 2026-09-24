// Manufactured third variant for auth-session/node CWE-347 (Improper
// Verification of Cryptographic Signature) -- a distinct mechanism from
// this cell's natural pair (vulnerable-1.js/idiomatic-1.js, which is
// node-jsonwebtoken's real alg:none-by-default history). This one is a
// hand-rolled JWT verifier that trusts the *token's own* header `alg`
// field to decide HOW to verify, instead of the caller pinning one
// expected algorithm ahead of time -- the classic RS256/HS256 "algorithm
// confusion" bug: when a token claims `alg: HS256`, the verifier reuses
// the RSA *public* key (not secret -- it is handed out to every relying
// party) as the HMAC *secret*, so anyone who knows the public key (by
// definition, everyone) can forge a token this verifier accepts.
//
// Manufactured per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's
// "Per-pair mechanics". Self-contained (Node stdlib `crypto` only) so it
// can be exercised without any external JWT package.
'use strict';

const crypto = require('crypto');

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signHS256(signingInput, secret) {
  return crypto.createHmac('sha256', secret).update(signingInput).digest();
}

function signRS256(signingInput, rsaPrivateKeyPem) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  return signer.sign(rsaPrivateKeyPem);
}

function makeToken(payload, alg, key) {
  const header = { alg, typ: 'JWT' };
  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = alg === 'HS256' ? signHS256(signingInput, key) : signRS256(signingInput, key);
  return `${signingInput}.${b64url(sig)}`;
}

// BUG: dispatches verification based on the token's own claimed `alg`
// instead of a caller-pinned expectation. `rsaPublicKeyPem` is meant only
// to verify RS256 signatures, but the HS256 branch below reuses it as an
// HMAC secret whenever a token merely *claims* alg=HS256.
function verifyToken(token, rsaPublicKeyPem) {
  const [headerB64, payloadB64, sigB64] = token.split('.');
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = Buffer.from(sigB64, 'base64url');

  if (header.alg === 'HS256') {
    const expected = signHS256(signingInput, rsaPublicKeyPem);
    if (!crypto.timingSafeEqual(expected, signature)) {
      throw new Error('invalid signature');
    }
  } else if (header.alg === 'RS256') {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signingInput);
    if (!verifier.verify(rsaPublicKeyPem, signature)) {
      throw new Error('invalid signature');
    }
  } else {
    throw new Error(`unsupported alg ${header.alg}`);
  }
  return JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
}

module.exports = { makeToken, verifyToken };
