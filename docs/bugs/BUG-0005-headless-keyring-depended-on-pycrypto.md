# BUG-0005 — Headless credential backend depended on PyCrypto, crashed on a fresh host

- Date: 2026-09-21
- Status: fixed
- Severity: high

## Description
The headless/CI encrypted-file credential backend (D12 fallback) was built on
`keyrings.alt.file.EncryptedKeyring`, whose AES implementation requires
**PyCrypto/pycryptodome** (the `Crypto` / `Cryptodome` module). That package was not
a declared dependency and is not installed by `pip install -e .`. The module's own
comment wrongly claimed the backend was "validated on a host with a working
`cryptography` build" — but `cryptography` is a *different* library and does not
provide `Crypto`.

## Where encountered
On the Fedora host, first real use of the headless path:
`fuzzlab session set-credential ...` with `FUZZLAB_KEYRING_PATH` /
`FUZZLAB_KEYRING_PASSPHRASE` set.

## What it caused to fail
The command crashed instead of storing credentials:
`ModuleNotFoundError: No module named 'Crypto'` (after first trying `Cryptodome`),
raised from `keyrings.alt.file._get_crypto_impl` when `EncryptedKeyring` was
constructed. This blocked every authenticated (`--identity`) run on a headless host —
the exact environment the encrypted-file fallback exists to serve.

## What the bug was identified to be
A dependency the code relied on at runtime (PyCrypto, via a third-party keyring
backend) was neither declared nor present, and the intended library (`cryptography`,
already installed transitively via the OS-keyring stack) was never actually wired up.
Because the credential-store tests inject an in-memory fake backend, the real backend
path was never exercised, so the missing dependency was invisible until first use.

## Root cause analysis
Five Whys:
1. Why did it crash? `EncryptedKeyring` imported `Crypto`, which is not installed.
2. Why isn't it installed? PyCrypto/pycryptodome was never declared as a dependency.
3. Why was it assumed present? The author believed the already-present `cryptography`
   package satisfied the encrypted backend — but `keyrings.alt` uses PyCrypto, a
   different library; one does not satisfy the other.
4. Why wasn't it caught before the host? The offline test suite injects a fake
   backend (good for testing the store's logic), so the real backend — the only place
   the dependency is used — was never constructed in a test.
5. Why does that hide it? A code path exercised only by real dependencies, and
   bypassed by test doubles everywhere else, has no automated signal; it fails on
   first real use.

**Root cause:** a runtime dependency (PyCrypto) pulled in by a chosen third-party
backend was undeclared and unverified, and the only tests that would have used it
substituted a fake — so a fresh-install/first-use failure shipped.

## Corrective action
- Reimplemented the encrypted-file backend as `_CryptographyFileBackend` in
  `fuzzlab/core/credentials.py`: a single AES-Fernet-encrypted JSON file with the key
  derived from `FUZZLAB_KEYRING_PASSPHRASE` via PBKDF2-HMAC-SHA256 over a random
  per-file salt. It uses **`cryptography`** only (the intended library, already
  present), with `0600` file perms and atomic writes; a wrong passphrase fails loudly.
- Declared `cryptography>=42,<51` as a direct dependency in `pyproject.toml`; dropped
  the reliance on `keyrings.alt`'s PyCrypto-based `EncryptedKeyring`.
- Added real round-trip tests (`tests/test_credentials.py`) that exercise the actual
  backend (set/get/delete, persistence across instances, ciphertext-on-disk, wrong
  passphrase). They **skip** (not fail) when `cryptography` can't be used — e.g. the
  sandbox's broken build, whose rust bindings raise a pyo3 `PanicException` (a
  `BaseException`) — so the suite stays green where the native lib is broken and runs
  the checks where it works. Suite 126 passed / 2 skipped.

## Preventive action
PA-0005 (see `docs/PREVENTIVE_ACTIONS.md`): every library imported at runtime — including
by a third-party backend the code instantiates — must be a **declared** dependency;
never assume one installed library satisfies another's requirement. And a real
(non-fake) code path that test doubles bypass everywhere must still have at least one
test that exercises the real implementation (skippable when it needs an environment
feature), or a documented on-host smoke check — so first-use/fresh-install failures
are caught before a user hits them.
