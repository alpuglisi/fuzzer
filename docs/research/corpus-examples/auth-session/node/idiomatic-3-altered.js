// Idiomatic counterpart to vulnerable-3-altered.js (auth-session/node,
// CWE-347). Differs *only* in the verification mechanism: the caller
// pins the one algorithm this verifier will ever accept (RS256) before
// looking at the token at all, so the token's own `alg` claim can never
// steer which key material or algorithm family gets used to check it --
// closing the RS256-public-key-as-HMAC-secret confusion in
// vulnerable-3-altered.js.
'use strict';

const crypto = require('crypto');

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
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
  const sig = signRS256(signingInput, key);
  return `${signingInput}.${b64url(sig)}`;
}

const EXPECTED_ALG = 'RS256'; // pinned by the caller, not read from the token

function verifyToken(token, rsaPublicKeyPem) {
  const [headerB64, payloadB64, sigB64] = token.split('.');
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
  if (header.alg !== EXPECTED_ALG) {
    throw new Error(`rejected: expected alg ${EXPECTED_ALG}, token claims ${header.alg}`);
  }
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = Buffer.from(sigB64, 'base64url');
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(signingInput);
  if (!verifier.verify(rsaPublicKeyPem, signature)) {
    throw new Error('invalid signature');
  }
  return JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
}

module.exports = { makeToken, verifyToken };
