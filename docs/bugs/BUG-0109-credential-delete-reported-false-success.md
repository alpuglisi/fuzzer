# BUG-0109 — Credential deletion reported success on a backend failure

- Date: 2026-10-13
- Status: fixed (CC-CORE-0036)
- Severity: low-medium. The audit rated it Medium. An operator believed a credential
  was removed while it stayed usable.

## Description
`CredentialStore.delete` wrapped the backend call in `except Exception: pass`. A
`PermissionError("locked keyring")` returned normally, and `get` still returned the
credential. The comment shows only "deleting a missing entry" was meant to be ignored.

## Where encountered
A third-party audit (finding #13), reproduced with `scratchpad/ext2/f12_13_keyring.py`.

## What it caused to fail
FR-CORE-25; the operator's expectation that a delete deletes.

## What the bug was identified to be
A blanket swallow standing in for one specific benign condition.

## Root cause analysis
1. *Why silent?* `except Exception: pass`.
2. *Why blanket?* Backends signal "missing" differently (`keyring`'s
   `PasswordDeleteError`, or nothing at all), and the code took the shortcut.
3. *Why not caught?* No test with a failing backend.

**Root cause:** success was reported without verifying the effect.

## Corrective action
- `delete` **verifies**: after `delete_password` (whether it raised or not),
  `get_password` must return `None`. Then the entry was missing or is deleted, and that
  is success.
- Otherwise it raises `CredentialError` with the backend's exception as the cause and
  no secret in the message. If the verification itself fails, that raises
  `CredentialError` too.
- **Tests:** a locked backend → `CredentialError` (with its cause, no secret); a
  missing entry with a "not found" error → fine; a missing entry with no error → fine.

## Recurrence review
- The swallow class, together with **BUG-0105** in this batch.

## Prior-preventive-action failure analysis
No prior PA addressed reporting success. This is new.

## Preventive action
- **PA-0110:** an operation reports success only when its effect is verified, or when
  the swallowed failure is exactly the documented no-op case.

**Sweep:** `set` (an exception propagates); `session/cli` delete (now raises loudly);
`_unlink_quietly` (cleanup of our own temp file, stated).
