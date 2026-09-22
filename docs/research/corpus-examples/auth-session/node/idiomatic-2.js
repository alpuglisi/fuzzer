// Source: auth0-blog/oidc-webapp, src/server.js, commit d15aacb4a25bbfc1c3ac59c1e06bf4f80d36db70.
// License: MIT (LICENSE file present).
//
// Excerpt: the express-session and cookie-parser setup only, trimmed from the file's full
// OIDC login flow (Auth0 authorization-code exchange, JWKS verification, etc. omitted as
// unrelated to the session-secret generation shown here).
//
// Contrast with node/vulnerable-2.js: the session secret (and the cookie-parser signing
// secret) is drawn from crypto.randomBytes(), Node's CSPRNG, instead of Math.random(). The
// resulting secret is not predictable from observed outputs and isn't part of any
// documented PRNG-state-recovery attack the way Math.random()'s xorshift128+ state is.

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.use(
  session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false
  })
);

// ... OIDC provider discovery, /login, /callback routes omitted ...
