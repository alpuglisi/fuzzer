"""Create secret files private from the first byte (BUG-0079, PA-0080, PA-0003).

``write_bytes`` then ``chmod`` leaves a window in which the file has the umask's mode,
often world-readable. `write_secret` opens with mode 0600 and ``O_NOFOLLOW`` (a planted
symlink is refused), re-modes an existing file before truncating it, then writes.
"""

from __future__ import annotations

import os
from pathlib import Path


def write_secret(path: str | Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        os.write(fd, data)
    finally:
        os.close(fd)
