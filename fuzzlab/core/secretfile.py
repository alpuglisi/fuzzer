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
  new one, never a partial one. On any error the temporary file is removed and the
  original is untouched.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

_MODE = 0o600


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
    _fsync_dir(path.parent)


def _unlink_quietly(path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _fsync_dir(directory: Path) -> None:
    """Make a rename durable. A no-op where a directory cannot be opened or fsynced."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
