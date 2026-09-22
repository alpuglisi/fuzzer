// Source: HubSpot/oauth-quickstart-nodejs, index.js, commit 01d1b9a8c6e8144bc51edc6af0bcf2155831bda2.
// License: MIT (package.json "license": "MIT"; no separate LICENSE file in the repo).
//
// Excerpt: the express-session setup only, trimmed from the file's full OAuth quickstart
// flow (token exchange, HubSpot API calls, etc. omitted as unrelated to the session secret).
//
// Vulnerability (CWE-330 use of insufficiently random values): the express-session `secret`
// -- the HMAC key used to sign the session-ID cookie -- is derived from Math.random(), a
// non-cryptographic PRNG never intended for security-sensitive values (its internal state
// can be inferred from a handful of observed outputs, e.g. via V8 xorshift128+ state-
// recovery techniques). An attacker who can predict or recover this secret can forge a
// validly-signed `connect.sid` cookie for any session ID and hijack any session, including
// one they were never issued.

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const app = express();

const PORT = 3000;

// ... CLIENT_ID / CLIENT_SECRET / SCOPES setup omitted ...

// Use a session to keep track of client ID
app.use(session({
  secret: Math.random().toString(36).substring(2),
  resave: false,
  saveUninitialized: true
}));

// ... OAuth authorize/callback routes and HubSpot API calls omitted ...
