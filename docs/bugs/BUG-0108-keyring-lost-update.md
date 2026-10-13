# BUG-0108 — Concurrent keyring updates lost one

- Date: 2026-10-13
- Status: fixed (CC-CORE-0036)
- Severity: low. The audit rated it Medium. It needs two writers at the same moment.

## Description
`_CryptographyFileBackend.set_password` / `delete_password` each loaded the whole
encrypted map, changed it and replaced the file. Two writers that loaded the same map
both succeeded, and the later replace discarded the other's change. A save racing a
delete could bring a deleted credential back. Atomic replace (BUG-0096) prevents torn
files, not lost updates.

## Where encountered
A third-party audit (finding #12), reproduced with `scratchpad/ext2/f12_13_keyring.py`.
Three processes × 6 writes kept 6 of 18 on `1619932`.

## What it caused to fail
FR-CORE-25 (the credential store).

## What the bug was identified to be
A read-modify-write on shared file state with no lock.

## Root cause analysis
1. *Why lost?* There was no serialisation between load and save.
2. *Why none?* PA-0088(2)'s lock-across-check rule was written for SQLite.
3. *Why not caught?* No two-writer test.

**Root cause:** the check-then-act rule was not applied to file-based stores.

## Corrective action
- `set_password` / `delete_password` run under a `threading.Lock` plus an exclusive
  `fcntl.flock`, held across load → mutate → save, on a stable `<keyring>.lock` file
  (0600, `O_NOFOLLOW`, never the keyring inode, which each save replaces).
- **Stated:** without `fcntl` (non-POSIX) only threads are serialised, and `flock` is
  advisory and unreliable on NFS (B-N5).
- **Tests:**
  - three processes × 5 writes → all kept;
  - the lock file is 0600;
  - 8 threads never overlap a load (with an injected overlap detector).

  On `1619932` the three-process run kept 6 of 18.

## Recurrence review
- **BUG-0087 / PA-0088(2)** and **BUG-0096 / PA-0097.**

## Prior-preventive-action failure analysis
**PA-0088(2) was too narrow in scope.** It covered SQLite only. PA-0097 addressed
completeness and atomicity, not serialisation.

## Preventive action
- **PA-0109:** PA-0088(2) applies to every shared store, files included. A
  read-modify-write holds an interprocess lock across the read, and has a two-writer
  test.

**Sweep:**
- the CA key: create-once with `O_EXCL`;
- leaves: per-process, rewritten from memory (residual stated in BUG-0096);
- labgen and corpus files: single-writer tools.
