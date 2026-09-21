# BUG-0010 — Proxy CONNECT/TLS leaf cert rejected: missing Authority Key Identifier

- Date: 2026-09-21
- Status: fixed
- Severity: high (HTTPS interception unusable on-host — the Part I core feature)

## Description
`LocalCA` minted CA and leaf certificates without the Subject Key Identifier (SKI) and
Authority Key Identifier (AKI) extensions (and without KeyUsage / serverAuth EKU, and with
a `DNSName` SAN even for IP hosts). Modern OpenSSL (Fedora, Python 3.13) enforces RFC 5280
strictly and rejects a chain whose leaf has no AKI:

```
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
Missing Authority Key Identifier
```

So CONNECT/TLS interception fails the handshake, and a real browser (also strict) would
reject the intercepted leaf too.

## Where encountered
On the host: `pytest tests/test_proxy_live.py::test_connect_tls_tunnel_forwards_byte_exact`
failed at the client-side TLS handshake with the error above. The sandbox skips this test
(no working `cryptography`), so it was never exercised there.

## What it caused to fail
The Part I exit (HTTPS interception through the proxy) could not work on-host: every leaf
the CA minted was unverifiable, so `writer.start_tls`/the browser handshake failed.

## What the bug was identified to be
`_mint_ca` added only `BasicConstraints(ca=True)`; `_mint_leaf` added only the SAN and
`BasicConstraints(ca=False)`. No SKI on the CA, no AKI on the leaf. Strict verifiers
require the leaf's AKI to reference the issuer's SKI to build/validate the chain; without
it, verification aborts before the signature is even checked. Also `datetime.utcnow()` was
deprecated on 3.13, and an IP host got a `DNSName` SAN (unverifiable by IP).

## Root cause analysis
Five Whys:
1. Why did the handshake fail? OpenSSL rejected the leaf: "Missing Authority Key Identifier".
2. Why was the AKI missing? `_mint_leaf` never added it (nor the CA an SKI).
3. Why weren't they added? The minting code produced a "minimal" cert (SAN + basic
   constraints) that older/looser verifiers accepted, so the gap was invisible.
4. Why invisible in tests? The only cert-verifying test is skip-guarded on a working
   `cryptography`, which the sandbox lacks — so it never ran until the host.
5. Why not caught by design review? Certificate-chain requirements (SKI/AKI/EKU) are easy
   to omit and only strict verifiers enforce them; there was no assertion on the minted
   cert's extensions.

**Root cause:** the CA/leaf minting omitted the SKI/AKI (and EKU/KeyUsage) extensions that
strict X.509 verifiers require, and the one test that would have caught it only runs where
`cryptography` works — which was never the sandbox.

## Corrective action
- `_mint_ca` now adds a `SubjectKeyIdentifier` and a CA `KeyUsage` (keyCertSign, cRLSign).
- `_mint_leaf` now adds a `SubjectKeyIdentifier`, an `AuthorityKeyIdentifier` derived from
  the CA public key (matches the CA's SKI), a serverAuth `ExtendedKeyUsage`, a leaf
  `KeyUsage`, and an `IPAddress` SAN for IP hosts (else `DNSName`).
- Replaced deprecated `datetime.utcnow()` with a naive-UTC helper (`_utcnow`).
- Added a skip-guarded unit test asserting the leaf's AKI matches the CA's SKI and that the
  serverAuth EKU + IP SAN are present (`tests/test_proxy_live.py::
  test_leaf_cert_chains_to_ca_with_aki_ski`), alongside the existing tunnel test that now
  passes on-host.

## Preventive action
PA-0011 (see `docs/PREVENTIVE_ACTIONS.md`): X.509 certs generated for TLS must carry the
extensions strict verifiers require — a CA with SKI + keyCertSign KeyUsage, and a leaf with
SKI, an AKI referencing the issuer, serverAuth EKU, and a SAN of the correct type
(IPAddress for IP hosts). Verify a generated cert against a real chain check (and assert its
extensions) in a test, even if that test is skip-guarded to the environment that has a
working crypto backend.
