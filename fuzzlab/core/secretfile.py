"""Secret files: private from the first byte, complete or an error, replaced atomically
(BUG-0079 / PA-0080; BUG-0096 / PA-0097; PA-0003).

``write_bytes`` then ``chmod`` leaves a window in which the file has the umask's mode,
often world-readable. Every function here opens with mode 0600 and ``O_NOFOLLOW`` (a
planted symlink is refused).

A single ``os.write`` may write **fewer** bytes than asked (a full disk, a file-size
limit, a signal) and still return normally, which once left a truncated secret file
behind a successful return (BUG-0096). Every write here loops until the data is written
in full, raises on no progress, and ``fsync``\\ s before returning.

- `write_secret` writes ``path`` in place (re-moding and truncating an existing file).
- `create_secret` creates ``path`` and refuses if it already exists (``O_EXCL``): for a
  file that must never be silently replaced, such as the proxy's CA key.
- `replace_secret` writes a unique temporary file in the same directory, fsyncs it,
  renames it over ``path`` and fsyncs the directory: readers see the old file or the
  new one, never a partial one. On an error **before** the rename the temporary file is
  removed and the original is untouched. If the directory fsync fails **after** the
  rename, `DurabilityUnknown` is raised: the new content is already visible, but its
  crash durability is not established — a retry is idempotent (BUG-0105).

The directory fsync is skipped only where the platform cannot do it — no
``O_DIRECTORY``, or ``EINVAL`` / ``ENOTSUP`` / ``EOPNOTSUPP`` (`UNSUPPORTED_ERRNOS`) —
never on any other error (PA-0106: an explicit swallow list).
"""

from __future__ import annotations

import errno
import os
import secrets
from pathlib import Path

_MODE = 0o600
#: The only errors that mean "this platform/filesystem cannot fsync a directory".
UNSUPPORTED_ERRNOS = frozenset(e for e in (getattr(errno, n, None) for n in
                                           ("EINVAL", "ENOTSUP", "EOPNOTSUPP")) if e)


class DurabilityUnknown(OSError):
    """The replacement is visible at its path, but the directory fsync failed, so its
    crash durability is not established. Retrying the same write is idempotent."""


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte of ``data`` to ``fd`` (looping on short writes), then fsync."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:                                  # no progress: never return early
            raise OSError(f"short write: {len(view)} bytes left unwritten")
        view = view[n:]
    os.fsync(fd)


def write_secret(path: str | Path, data: bytes) -> None:
    """Write ``data`` to ``path`` (0600 from creation, no symlink), complete or raise."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, _MODE)
    try:
        os.fchmod(fd, _MODE)
        os.ftruncate(fd, 0)
        _write_all(fd, data)
    finally:
        os.close(fd)


def create_secret(path: str | Path, data: bytes) -> None:
    """Create ``path`` with ``data`` (0600); ``FileExistsError`` if it already exists. A
    failed write removes the partial file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _MODE)
    try:
        try:
            os.fchmod(fd, _MODE)
            _write_all(fd, data)
        finally:
            os.close(fd)
    except BaseException:
        _unlink_quietly(path)
        raise


def replace_secret(path: str | Path, data: bytes) -> None:
    """Atomically replace ``path`` with ``data`` (0600): temp, fsync, rename, dir fsync."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    create_secret(tmp, data)
    try:
        os.replace(tmp, path)
    except BaseException:
        _unlink_quietly(tmp)
        raise
    try:
        _fsync_dir(path.parent)
    except OSError as exc:
        raise DurabilityUnknown(
            exc.errno, f"replacement visible at {path}; crash durability not established "
                       f"({exc.strerror or exc}) — retrying the write is safe") from exc


def _unlink_quietly(path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _fsync_dir(directory: Path) -> None:
    """Make a rename durable. Skipped only where the platform cannot fsync a directory
    (no ``O_DIRECTORY``, or an `UNSUPPORTED_ERRNOS` error); any other error raises."""
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        if exc.errno in UNSUPPORTED_ERRNOS:
            return
        raise
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in UNSUPPORTED_ERRNOS:
            raise
    finally:
        os.close(fd)
