"""Secret files are complete or an error, and replaced atomically (BUG-0096, PA-0097,
FR-CORE-25).

`write_secret` once called ``os.write`` once: a short write (a full disk, a file-size
limit) returned normally with a truncated secret on disk, and the keyring then renamed
that truncated temp file over the good keyring.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from fuzzlab.core import secretfile
from fuzzlab.core.secretfile import create_secret, replace_secret, write_secret

REPO = Path(__file__).resolve().parent.parent

_LIMITED = textwrap.dedent("""
    import os, resource, signal, sys
    sys.path.insert(0, {repo!r})
    from fuzzlab.core.secretfile import {fn}
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)     # the limit becomes a short write
    resource.setrlimit(resource.RLIMIT_FSIZE, (4, resource.RLIM_INFINITY))
    try:
        {fn}({path!r}, b"SECRET_DATA")
        print("RETURNED")
    except OSError as exc:
        print("RAISED", exc.errno)
""")


def _under_a_4_byte_limit(fn: str, path: Path) -> str:
    """Run ``fn(path, b"SECRET_DATA")`` in a child whose file-size limit is 4 bytes: a
    real kernel short write, then EFBIG."""
    code = _LIMITED.format(repo=str(REPO), fn=fn, path=str(path))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


@pytest.mark.skipif(not hasattr(os, "fork") or sys.platform != "linux",
                    reason="RLIMIT_FSIZE short writes are exercised on Linux")
def test_a_real_short_write_raises_instead_of_returning(tmp_path):
    """The finding: 4 of 11 bytes on disk and a normal return."""
    path = tmp_path / "secret"
    assert _under_a_4_byte_limit("write_secret", path).startswith("RAISED")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux RLIMIT_FSIZE")
def test_a_failed_replace_leaves_the_original_intact_and_no_temp(tmp_path):
    path = tmp_path / "keyring.cfg"
    path.write_bytes(b"ORIGINAL")
    assert _under_a_4_byte_limit("replace_secret", path).startswith("RAISED")
    assert path.read_bytes() == b"ORIGINAL"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keyring.cfg"]


def test_short_writes_are_looped_until_complete(tmp_path, monkeypatch):
    real = os.write
    calls = []
    monkeypatch.setattr(secretfile.os, "write",
                        lambda fd, b: calls.append(1) or real(fd, bytes(b[:3])))
    write_secret(tmp_path / "s", b"SECRET_DATA")
    assert (tmp_path / "s").read_bytes() == b"SECRET_DATA" and len(calls) == 4


def test_zero_progress_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(secretfile.os, "write", lambda fd, b: 0)
    with pytest.raises(OSError, match="short write"):
        write_secret(tmp_path / "s", b"SECRET_DATA")


def test_every_write_is_fsynced(tmp_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(secretfile.os, "fsync", lambda fd: synced.append(fd) or real(fd))
    write_secret(tmp_path / "a", b"x")
    replace_secret(tmp_path / "b", b"y")
    assert len(synced) >= 3                       # a; b's temp; b's directory


def test_replace_is_atomic_private_and_leaves_no_temp(tmp_path):
    path = tmp_path / "k"
    old = os.umask(0)
    try:
        replace_secret(path, b"one")
        replace_secret(path, b"two")
    finally:
        os.umask(old)
    assert path.read_bytes() == b"two"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["k"]


def test_a_failed_rename_removes_the_temp(tmp_path, monkeypatch):
    path = tmp_path / "k"
    path.write_bytes(b"ORIGINAL")

    def fail(*a):
        raise OSError("rename failed")
    monkeypatch.setattr(secretfile.os, "replace", fail)
    with pytest.raises(OSError, match="rename failed"):
        replace_secret(path, b"NEW")
    assert path.read_bytes() == b"ORIGINAL" and [p.name for p in tmp_path.iterdir()] == ["k"]


def test_create_never_replaces_and_a_failed_create_leaves_nothing(tmp_path, monkeypatch):
    path = tmp_path / "ca.key"
    create_secret(path, b"KEY")
    with pytest.raises(FileExistsError):
        create_secret(path, b"OTHER")
    assert path.read_bytes() == b"KEY"
    monkeypatch.setattr(secretfile.os, "write", lambda fd, b: 0)
    with pytest.raises(OSError):
        create_secret(tmp_path / "new.key", b"KEY")
    assert not (tmp_path / "new.key").exists()


def test_a_planted_symlink_is_not_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    link = tmp_path / "s"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        write_secret(link, b"x")
    with pytest.raises(OSError):
        create_secret(link, b"x")
    replace_secret(link, b"x")                    # replaces the link itself, not its target
    assert victim.read_text() == "keep" and not link.is_symlink()


# --- the users: keyring and CA ------------------------------------------------------

def test_a_failed_keyring_save_keeps_the_previous_keyring(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    from fuzzlab.core.credentials import CredentialStore, _encrypted_file_backend
    path = tmp_path / "keyring.cfg"
    env = {"FUZZLAB_KEYRING_PASSPHRASE": "lab-pass"}
    CredentialStore(backend=_encrypted_file_backend(str(path), env)).set(
        "h", "admin", "u", "pw1")
    before = path.read_bytes()
    real = os.write
    monkeypatch.setattr(secretfile.os, "write", lambda fd, b: real(fd, bytes(b[:4])) and 0)
    with pytest.raises(OSError):
        CredentialStore(backend=_encrypted_file_backend(str(path), env)).set(
            "h", "admin", "u", "pw2")
    monkeypatch.undo()
    assert path.read_bytes() == before
    # no temp file left; the stable lock file (BUG-0108) is expected beside it
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keyring.cfg", "keyring.cfg.lock"]
    again = CredentialStore(backend=_encrypted_file_backend(str(path), env))
    assert again.get("h", "admin").password == "pw1"


def _fake(host):
    return (f"CERT {host}".encode(), f"KEY {host}".encode())


def test_a_failed_leaf_write_raises_and_leaves_no_partial_pem(tmp_path, monkeypatch):
    from fuzzlab.proxy.ca import LocalCA
    ca = LocalCA(tmp_path / "ca", minter=_fake)
    monkeypatch.setattr(secretfile.os, "write", lambda fd, b: 0)
    with pytest.raises(OSError):
        ca.leaf_cert_files("lab.local")
    leaves = tmp_path / "ca" / "leaves"
    assert [p for p in leaves.iterdir()] == []


def test_the_ca_key_is_never_silently_replaced(tmp_path):
    pytest.importorskip("cryptography")
    from fuzzlab.proxy.ca import CAError, LocalCA
    ca = LocalCA(tmp_path / "ca")
    cert, key = ca.ensure_ca()
    # reloaded: the pair is checked and matches
    assert LocalCA(tmp_path / "ca").ensure_ca() == (cert, key)
    # half a CA (the cert lost) is refused, the key kept
    ca.ca_cert_path.unlink()
    with pytest.raises(CAError, match="incomplete CA"):
        LocalCA(tmp_path / "ca").ensure_ca()
    assert ca.ca_key_path.read_bytes() == key
    # a key that is not the certificate's is refused, never re-minted
    other = LocalCA(tmp_path / "other")
    other_cert, _ = other.ensure_ca()
    ca.ca_cert_path.write_bytes(other_cert)
    with pytest.raises(CAError, match="does not match"):
        LocalCA(tmp_path / "ca").ensure_ca()
    assert ca.ca_key_path.read_bytes() == key


def test_a_corrupted_leaf_on_disk_heals_on_the_next_use(tmp_path):
    """The evidence for not re-minting leaves on load (reviewed deviation, BUG-0096):
    leaves are rewritten from the in-memory pair on every use, so a key swapped on disk
    is replaced by the matching pair and `load_cert_chain` succeeds. If leaves are ever
    read back from disk, this fails."""
    pytest.importorskip("cryptography")
    import ssl

    from fuzzlab.proxy.ca import LocalCA
    ca = LocalCA(tmp_path / "ca")
    cert, key = ca.leaf_cert_files("lab.local")
    good = (cert.read_bytes(), key.read_bytes())
    other_key = LocalCA(tmp_path / "other").leaf_cert_files("lab.local")[1].read_bytes()
    key.write_bytes(other_key)                         # the pair on disk now mismatches
    cert2, key2 = ca.leaf_cert_files("lab.local")
    assert (cert2.read_bytes(), key2.read_bytes()) == good
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(cert2), str(key2))


# --- BUG-0105 / PA-0106: directory-sync errors are swallowed only when unsupported --

def _dir_fsync_fails(monkeypatch, err):
    real_open, real_fsync, dirs = os.open, os.fsync, set()

    def op(path, flags, *a):
        fd = real_open(path, flags, *a)
        if os.path.isdir(path):
            dirs.add(fd)
        return fd

    def fs(fd):
        if fd in dirs:
            raise OSError(err, os.strerror(err))
        return real_fsync(fd)
    monkeypatch.setattr(secretfile.os, "open", op)
    monkeypatch.setattr(secretfile.os, "fsync", fs)


def test_a_real_directory_fsync_error_raises_durability_unknown(tmp_path, monkeypatch):
    import errno
    from fuzzlab.core.secretfile import DurabilityUnknown
    path = tmp_path / "k"
    path.write_bytes(b"OLD")
    _dir_fsync_fails(monkeypatch, errno.EIO)
    with pytest.raises(DurabilityUnknown, match="durability not established"):
        replace_secret(path, b"NEW")
    assert path.read_bytes() == b"NEW"           # visible, as the error says


@pytest.mark.parametrize("name", ["EINVAL", "ENOTSUP", "EOPNOTSUPP"])
def test_an_unsupported_directory_fsync_is_skipped(tmp_path, monkeypatch, name):
    import errno
    _dir_fsync_fails(monkeypatch, getattr(errno, name))
    replace_secret(tmp_path / "k", b"NEW")
    assert (tmp_path / "k").read_bytes() == b"NEW"


def test_ebadf_is_not_swallowed(tmp_path, monkeypatch):
    """A8: EBADF is a programming error, not "unsupported"."""
    import errno
    from fuzzlab.core.secretfile import DurabilityUnknown
    _dir_fsync_fails(monkeypatch, errno.EBADF)
    with pytest.raises(DurabilityUnknown):
        replace_secret(tmp_path / "k", b"NEW")


def test_no_o_directory_is_skipped(tmp_path, monkeypatch):
    monkeypatch.delattr(secretfile.os, "O_DIRECTORY", raising=False)
    replace_secret(tmp_path / "k", b"NEW")
    assert (tmp_path / "k").read_bytes() == b"NEW"


def test_the_keyring_reports_unknown_durability(tmp_path, monkeypatch):
    import errno
    pytest.importorskip("cryptography")
    from fuzzlab.core.credentials import (CredentialError, CredentialStore,
                                          _encrypted_file_backend)
    env = {"FUZZLAB_KEYRING_PASSPHRASE": "lab-pass"}
    store = CredentialStore(backend=_encrypted_file_backend(str(tmp_path / "k.cfg"), env))
    _dir_fsync_fails(monkeypatch, errno.EIO)
    with pytest.raises(CredentialError, match="retrying is safe"):
        store.set("h", "u", "user", "pw")


def test_swallow_lists_are_explicit():
    """PA-0106 guard: no bare `except OSError: pass` / `return` in secretfile."""
    import ast
    src = (REPO / "fuzzlab" / "core" / "secretfile.py").read_text()
    offenders = [h.lineno for h in ast.walk(ast.parse(src))
                 if isinstance(h, ast.ExceptHandler) and isinstance(h.type, ast.Name)
                 and h.type.id in ("OSError", "Exception")
                 and len(h.body) == 1 and isinstance(h.body[0], (ast.Pass, ast.Return))
                 and not _in_unlink(src, h.lineno)]
    assert offenders == []


def _in_unlink(src, line):
    """`_unlink_quietly` is the one stated swallow (cleanup of our own temp file)."""
    lines = src.splitlines()[:line]
    for prev in reversed(lines):
        if prev.startswith("def "):
            return prev.startswith("def _unlink_quietly")
    return False


def test_the_swallow_guard_catches_an_offender():
    import ast
    bad = "def f():\n    try:\n        g()\n    except OSError:\n        pass\n"
    handlers = [h for h in ast.walk(ast.parse(bad)) if isinstance(h, ast.ExceptHandler)]
    assert handlers and isinstance(handlers[0].body[0], ast.Pass)
    assert not _in_unlink(bad, handlers[0].lineno)


# --- BUG-0108 / PA-0109: keyring updates are serialised; BUG-0109: deletes verified --

def _bulk_set(path, who, n):
    from fuzzlab.core.credentials import CredentialStore, _encrypted_file_backend
    env = {"FUZZLAB_KEYRING_PASSPHRASE": "lab-pass"}
    for i in range(n):
        CredentialStore(backend=_encrypted_file_backend(path, env)).set("h", f"{who}{i}",
                                                                        "u", "p")


def test_concurrent_processes_lose_no_update(tmp_path):
    """The audit's lost update: two writers loaded the same map; one change vanished."""
    pytest.importorskip("cryptography")
    import multiprocessing as mp
    from fuzzlab.core.credentials import CredentialStore, _encrypted_file_backend
    path = str(tmp_path / "keyring.cfg")
    ctx = mp.get_context("fork")
    procs = [ctx.Process(target=_bulk_set, args=(path, w, 5)) for w in "abc"]
    [p.start() for p in procs]
    [p.join(60) for p in procs]
    s = CredentialStore(backend=_encrypted_file_backend(
        path, {"FUZZLAB_KEYRING_PASSPHRASE": "lab-pass"}))
    assert all(s.get("h", f"{w}{i}") for w in "abc" for i in range(5))
    lock = tmp_path / "keyring.cfg.lock"
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


@pytest.mark.parametrize("with_fcntl", [True, False])
def test_two_threads_never_interleave_a_load_and_save(tmp_path, monkeypatch, with_fcntl):
    """Without fcntl (non-POSIX) the thread lock alone must still serialise."""
    pytest.importorskip("cryptography")
    if not with_fcntl:
        import fuzzlab.core.credentials as creds
        monkeypatch.setattr(creds, "fcntl", None)
    import threading
    from fuzzlab.core.credentials import _encrypted_file_backend
    env = {"FUZZLAB_KEYRING_PASSPHRASE": "lab-pass"}
    be = _encrypted_file_backend(str(tmp_path / "k.cfg"), env)
    inside, overlap = [0], []
    real = be._load

    def load():
        inside[0] += 1
        overlap.append(inside[0])
        try:
            time.sleep(0.01)                     # widen the window an overlap needs
            return real()
        finally:
            inside[0] -= 1
    be._load = load
    ts = [threading.Thread(target=lambda i=i: be.set_password("fuzzlab", f"a{i}", "p"))
          for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert max(overlap) == 1


def test_a_failed_delete_is_reported_and_a_missing_one_is_not():
    from fuzzlab.core.credentials import CredentialError, CredentialStore

    class Backend:
        def __init__(self, fail_with=None):
            self.data, self.fail_with = {}, fail_with

        def get_password(self, s, a):
            return self.data.get((s, a))

        def set_password(self, s, a, p):
            self.data[(s, a)] = p

        def delete_password(self, s, a):
            if self.fail_with is not None:
                raise self.fail_with
            self.data.pop((s, a), None)

    s = CredentialStore(backend=Backend(PermissionError("locked keyring")))
    s.set("h", "admin", "u", "pw")
    with pytest.raises(CredentialError, match="could not delete") as info:
        s.delete("h", "admin")
    assert isinstance(info.value.__cause__, PermissionError) and "pw" not in str(info.value)
    # deleting a missing entry: the backend's "not found" error is verified away
    CredentialStore(backend=Backend(KeyError("missing"))).delete("h", "nobody")
    CredentialStore(backend=Backend()).delete("h", "nobody")
