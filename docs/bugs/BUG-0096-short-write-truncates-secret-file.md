# BUG-0096 — A short write left a truncated secret file and reported success

- Date: 2026-10-13
- Status: fixed (CC-CORE-0035, CC-PROXY-0020)
- Severity: medium. A full disk or a file-size limit could silently truncate the
  encrypted keyring or a TLS key. The keyring would then rename the truncated temp file
  over the good keyring, losing every stored credential.

## Description
`core.secretfile.write_secret` called `os.write` once and returned. Under a **real**
kernel short write (`RLIMIT_FSIZE`=4, `SIGXFSZ` ignored),
`write_secret(p, b"SECRET_DATA")` returned normally with `b'SECR'` (4 of 11 bytes) on
disk. Other gaps:
- nothing called `fsync`;
- the keyring wrote a fixed `.tmp` name, then `os.replace`d it unconditionally;
- the CA key and leaf files were written in place.

## Where encountered
A third-party review of head `5eb4be9` (finding #7). Reproduced with
`scratchpad/ext/f7_shortwrite.py`.

## What it caused to fail
- FR-CORE-25 (credentials are kept safely in the credential store);
- the proxy CA's integrity (FR-PROXY-2 / FR-PROXY-10);
- PA-0080's helper contract.

## What the bug was identified to be
The helper assumed `os.write` writes everything. POSIX allows fewer bytes, and
`os.write` returns the count. Replacement was not atomic and not durable.

## Root cause analysis
1. *Why truncated?* One `os.write` call; the return value was ignored.
2. *Why did the keyring lose data?* It renamed a temp file it never verified was
   complete.
3. *Why was the helper written so?* BUG-0079's fix was about **who can read** a secret
   file (mode 0600 from creation, `O_NOFOLLOW`), and the write itself was kept minimal.
4. *Why not caught?* PA-0080 and its tests covered modes and symlinks, not completeness
   or atomicity.

**Root cause:** the secret-file contract covered confidentiality but not integrity
(complete and atomic writes).

## Corrective action
- **CC-CORE-0035 (`core/secretfile.py`):**
  - **`write_secret`** loops `os.write` over a `memoryview` until complete, raises
    `OSError` on no progress, and `fsync`s.
  - **`create_secret`** uses `O_CREAT|O_EXCL|O_NOFOLLOW` 0600, refuses an existing
    file, and removes a partial file on failure.
  - **`replace_secret`** writes a unique temp file in the same directory (via
    `create_secret`), then `os.replace` and a guarded directory `fsync` (a no-op where
    unsupported). On any error the temp file is removed and the original is untouched.
  - The keyring backend uses `replace_secret` instead of its fixed `.tmp` name.
- **CC-PROXY-0020 (`proxy/ca.py`):**
  - **The CA key** is created with `create_secret` (`O_EXCL`), so an existing trust
    root is never silently replaced. It is written key first, then the cert, the cert
    atomically.
  - **On load**, the CA key must match its certificate (SPKI comparison), and a half
    CA (one file without the other) is refused. Both raise `CAError`, naming the fix:
    remove both files, then re-trust.
  - **Leaf key and cert** use `replace_secret`, key first.
- **Leaf "pair check on load", deviation stated:** the agreed draft said a mismatched
  leaf pair is re-minted on load. Leaves are never loaded from disk: they are rewritten
  from the in-memory pair on every use, and `ssl.load_cert_chain` itself refuses a
  mismatch. So the check reduces to that, rather than being built as dead code.
  - **Reviewed:** taken back to both reviewers under PA-0093(2), and AGREED 3/3.
  - **Cross-process residual (both reviewers' nit).** Two proxies sharing one `ca_dir`
    (the web panel's in-process proxy and `fuzzlab proxy`) each mint their own leaf
    for a host. The two files are replaced one at a time, so one process can load
    the other's key. `load_cert_chain` then raises, and per-connection containment
    closes that connection: a handshake failure, never a wrong certificate. A
    re-mint would not fix it; per-process leaf names would, if it ever matters.
  - **Pinned by** `test_a_corrupted_leaf_on_disk_heals_on_the_next_use`.
- **Tests** (`tests/test_secretfile.py`):
  - a real `RLIMIT_FSIZE` short write in a child process makes `write_secret` raise;
  - `replace_secret` under the same limit leaves the original intact and no temp file;
  - short writes are looped until complete;
  - zero progress raises;
  - `fsync` is called;
  - a replace is atomic, 0600, and leaves no temp file;
  - a failed rename removes the temp file;
  - `create_secret` never replaces, and cleans up after itself;
  - a symlink is never followed;
  - a failed keyring save keeps the previous keyring readable;
  - a failed leaf write leaves no partial PEM;
  - the CA key is never silently replaced (a half CA and a mismatched pair raise).

  The test module needs the new helpers, so it cannot import on `5eb4be9`. Its
  real-short-write harness pointed at the pre-fix tree reproduces the finding: the
  child prints `RETURNED` with `b'SECR'` on disk, against `RAISED 27` (`EFBIG`) after
  the fix.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0079 / PA-0080:** created `write_secret`. The same helper and the same
  promise ("secret files are written safely"). A **recurrence** of an incomplete fix.
- **BUG-0087 / PA-0088:** atomic transitions on shared storage. The same principle,
  applied to SQLite there and not extended to files.

## Prior-preventive-action failure analysis
**PA-0080 was too narrow.** It defined a safe secret file as private from creation and
not following symlinks: confidentiality only. Completeness and atomicity were outside
the rule. PA-0088 ("an all-or-nothing transition is tested by injecting a mid-way
failure") was written for the store and not generalised to files, so the file layer
had no such test.

## Preventive action
- **PA-0097** (strengthens PA-0080 and extends PA-0088 to files):
  1. **A file write is complete or raises:** loop on short writes, raise on no
     progress, `fsync` before returning.
  2. **Replacing a file is atomic:** unique temp file, fsync, rename, directory fsync;
     on failure the temp is removed and the original intact.
  3. **A file that must never be replaced silently (a trust root) is created with
     `O_EXCL`.**
  4. **Each is tested with an injected mid-write failure**, including a real kernel
     short write where the platform allows it.

**Sweep (PA-0002):** every `os.write`, and every `.tmp` + `replace`, in `fuzzlab/`:
- **`os.write`:** only `secretfile` (fixed).
- **`.tmp` + `replace`:** only the keyring (moved to `replace_secret`).
- **`write_text` / `write_bytes`** (labgen output, corpus sourcing reports, the
  sandbox's cgroup and config files): Python's buffered `write` writes everything or
  raises, so it cannot truncate silently. They are regenerable artefacts, not secrets
  or trust state. Non-atomic by design; noted.
