# BUG-0105 — Directory-fsync failures were swallowed after a secret replacement

- Date: 2026-10-13
- Status: fixed (CC-CORE-0036)
- Severity: low-medium. The audit rated it Medium. A caller was told a durable write
  succeeded when it had not been made durable.

## Description
`secretfile._fsync_dir` ignored every `OSError` from opening or fsyncing the directory,
EIO included, so `replace_secret` returned normally. Its docstring claimed that on any
error the original stays untouched, which is impossible after the rename.

## Where encountered
A third-party audit (finding #9), reproduced with `scratchpad/ext2/f09_dirsync.py`. I
wrote this code in `1619932`.

## What it caused to fail
FR-CORE-25's durability claim (PA-0097(2)).

## What the bug was identified to be
The agreed nit allowed "a no-op where directory fsync is unsupported". I implemented it
as "a no-op on any error".

## Root cause analysis
1. *Why swallowed?* A bare `except OSError: pass` / `return`.
2. *Why bare?* The "unsupported" condition was never named.
3. *Why not caught?* No test injected a real failure on the directory fsync.

**Root cause:** an agreed, narrow exception was widened in implementation without the
reviewers. This is PA-0093(2)'s failure mode again.

## Corrective action
- `_fsync_dir` skips only when there is no `O_DIRECTORY`, or on `EINVAL` / `ENOTSUP` /
  `EOPNOTSUPP` (`UNSUPPORTED_ERRNOS`). `EBADF` is not on the list: it is a programming
  error (A8).
- Any other error after the rename raises `DurabilityUnknown(OSError)`: "replacement
  visible…; crash durability not established; retrying is safe".
- The docstring now distinguishes errors before the rename from errors after it. The
  keyring wraps the error in a `CredentialError` that says a retry is safe.
- **Tests:**
  - EIO → `DurabilityUnknown`, with the new content visible;
  - EINVAL / ENOTSUP / EOPNOTSUPP → skipped;
  - EBADF → raised;
  - no `O_DIRECTORY` → skipped;
  - the keyring message;
  - an AST guard against bare swallows in `secretfile`, with a synthetic offender.

## Recurrence review
- **BUG-0096 / PA-0097:** my own code.
- **BUG-0092 / PA-0093(2):** an agreed constraint changed in implementation.

## Prior-preventive-action failure analysis
**PA-0093(2) was not followed.** It said an agreed constraint is never changed in
implementation without going back to the reviewers. Here a narrowly agreed exception
was widened.

## Preventive action
- **PA-0106:** an error is swallowed only by an explicit, named list of conditions,
  never by a bare `except OSError` / `except Exception`. A swallow list is tested with
  one swallowed and one propagated error, and guarded against bare swallows.

**Sweep:**
- `_unlink_quietly` (the stated cleanup swallow);
- `credentials.delete` (BUG-0109);
- `ca.py` (no swallows).
