# BUG-0079 — The proxy CA wrote leaf files outside its directory, named by a CONNECT host

- Date: 2026-10-13
- Status: fixed (CC-PROXY-0019, CC-CORE-0034)
- Severity: high. Any client of the proxy chose a write path on the host. Keys were
  briefly world-readable.

## Description
`LocalCA.leaf_cert_files(host)` built `<ca_dir>/leaves/<host>.crt|.key` from the raw
CONNECT authority. `CONNECT ../../outside/evil:443` therefore wrote `outside/evil.crt` and
`outside/evil.key` **outside** the CA directory. Every key, the CA key included, was
written with the process umask and `chmod 0600`'d afterwards, so it was world-readable
for an instant, and `leaves/` and the CA directory were created with default modes.

## Where encountered
The error-review phase (review 7). Reproduced with real `cryptography` minting
(`scratchpad/review7/r3_ca_traversal.py`).

## What it caused to fail
NFR-PROXY-safe: the local CA's material is meant to stay private and in its own place.
A proxy client could create files anywhere the operator can write, and a co-tenant
could read a key during its write window.

## What the bug was identified to be
A network-supplied string was used as a filesystem path fragment without validation.
Secrets were made private after being written, not at creation.

## Root cause analysis
Five Whys:
1. *Why outside the directory?* The CONNECT host went straight into the filename.
2. *Why unvalidated?* The leaf cache was written for real hostnames; its input was
   assumed to be one.
3. *Why that assumption?* The minting is on-host and was tested only with friendly
   hosts through an injected minter.
4. *Why briefly readable?* `write_bytes` then `chmod`, the common idiom, which is wrong
   for secrets.
5. *Why no rule?* No PA covered paths built from network input, or secret-file
   creation.

**Root cause:** untrusted input crossed into a filesystem path, and secret files were
not created private.

## Corrective action
In CC-PROXY-0019:
- **Host validation.** `ca.leaf_host` accepts only an IP literal (IPv6 with or without
  brackets) or an IDNA-encoded, lower-cased hostname of `[a-z0-9_-]` labels, at most 253
  characters. `_` is allowed for Docker service names. Anything else raises
  `ValueError`; the CONNECT handler already contains minting failures.
- **Safe filenames.** IPv6 leaf files are `ip6-<hex>`, so they collide with no hostname.
- **A backstop:** the resolved leaf path must sit directly in `leaves/`.
- **Keys** are created by `core.secretfile.write_secret` (shared, CC-CORE-0034): `O_CREAT|O_NOFOLLOW`, mode 0600, `fchmod`
  before truncating and writing, so a planted symlink is refused.
- **Directories:** `leaves/` and the CA directory are `0700`.
- **Tests** (`tests/test_proxy_ca_hardening.py`):
  - 12 hostile hosts write nothing;
  - valid hosts include IPv6, IDNA and an underscore;
  - keys are 0600 under umask 0, even with `chmod` disabled;
  - an existing key is re-moded, and a symlink is refused;
  - the cache refuses before minting;
  - the backstop holds if validation were bypassed;
  - the real CA key is 0600.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- No prior bug built a path from network input.
- PA-0046 (redirect handling) is about where traffic goes, not files.

**Result:** a new root cause, with no prior PA to analyse for failure.

## Preventive action
**PA-0080** (in `docs/PREVENTIVE_ACTIONS.md`):
1. A value from the network that becomes part of a filesystem path is validated
   against a whitelist grammar, and the resolved path is asserted inside its root.
2. Secret files are created with restrictive modes (`os.open(..., 0o600)` plus
   `O_NOFOLLOW`), never chmodded after the write.

**Sweep (PA-0002):** every write whose path includes a variable:
- **CA leaves and CA key:** fixed.
- **History bodies:** named by sha256, not input-derived.
- **greybox coverage ids:** `sanitize_cid` already maps ids to a safe name.
- **labgen output:** operator-supplied paths, not network input.
- **`web/runner` logs:** server-generated names.
- **The encrypted-file credential backend** (`core/credentials.py`) — **an instance,
  fixed.** It wrote its temp file with the umask and then chmodded it 0600. It now uses
  the same shared `core.secretfile.write_secret` (PA-0003), and its directory is
  `0700`. Test: `tests/test_credentials.py::test_the_encrypted_keyring_file_is_private_from_creation`.
