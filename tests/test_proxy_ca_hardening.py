"""Leaf certificates are minted only for a valid host, inside the CA directory, with keys
0600 from creation (BUG-0079, FR-PROXY-10, PA-0080).

A CONNECT authority such as `../../outside/evil:443` used to become a leaf filename,
writing a cert and a key outside `<ca_dir>/leaves/`. Keys were written with the default
umask and chmodded afterwards.
"""

from __future__ import annotations

import os
import stat

import pytest

from fuzzlab.proxy.ca import LocalCA, leaf_host


def _fake(host):
    return (f"CERT {host}".encode(), f"KEY {host}".encode())


@pytest.mark.parametrize("host", ["../../outside/evil", "a/b", "..", "", "a\x00b",
                                  "x" * 64 + ".lab", "a..b", "-a.lab", "a b", "a\\b",
                                  "[::1", "évil/.."])
def test_hostile_hosts_are_refused_and_nothing_is_written(tmp_path, host):
    ca = LocalCA(tmp_path / "ca", minter=_fake)
    with pytest.raises(ValueError):
        ca.leaf_cert_files(host)
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written == []


@pytest.mark.parametrize("host,expect,fname", [
    ("Lab.Local", "lab.local", "lab.local"),
    ("web_1", "web_1", "web_1"),                       # Docker service names
    ("127.0.0.1:8443", "127.0.0.1", "127.0.0.1"),
    ("[::1]:8443", "::1", "ip6-" + "00" * 15 + "01"),
    ("::1", "::1", "ip6-" + "00" * 15 + "01"),
    ("bücher.example", "xn--bcher-kva.example", "xn--bcher-kva.example"),
])
def test_valid_hosts_get_leaves_inside_the_ca_dir(tmp_path, host, expect, fname):
    assert leaf_host(host) == expect
    ca = LocalCA(tmp_path / "ca", minter=_fake)
    cert, key = ca.leaf_cert_files(host)
    leaves = (tmp_path / "ca" / "leaves").resolve()
    assert cert.resolve().parent == leaves and key.name == f"{fname}.key"


def test_keys_are_0600_from_creation_whatever_the_umask(tmp_path):
    old = os.umask(0)
    try:
        ca = LocalCA(tmp_path / "ca", minter=_fake)
        _cert, key = ca.leaf_cert_files("lab.local")
    finally:
        os.umask(old)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "ca" / "leaves").stat().st_mode) == 0o700


def test_an_existing_key_is_re_moded_and_a_planted_symlink_is_not_followed(tmp_path):
    ca = LocalCA(tmp_path / "ca", minter=_fake)
    _cert, key = ca.leaf_cert_files("lab.local")
    key.chmod(0o644)
    ca.clear_cache()
    ca.leaf_cert_files("lab.local")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    target = tmp_path / "victim"
    target.write_text("keep")
    key.unlink()
    key.symlink_to(target)
    with pytest.raises((OSError, ValueError)):     # the path backstop or O_NOFOLLOW
        ca.leaf_cert_files("lab.local")
    assert target.read_text() == "keep"


def test_the_real_ca_key_is_0600_from_creation(tmp_path):
    pytest.importorskip("cryptography")
    old = os.umask(0)
    try:
        ca = LocalCA(tmp_path / "ca")
        ca.ensure_ca()
    finally:
        os.umask(old)
    assert stat.S_IMODE(ca.ca_key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "ca").stat().st_mode) == 0o700


def test_the_leaf_cache_itself_refuses_a_hostile_host(tmp_path):
    minted = []
    ca = LocalCA(tmp_path / "ca", minter=lambda h: minted.append(h) or _fake(h))
    with pytest.raises(ValueError):
        ca.leaf_cert("../../outside/evil:443")
    assert minted == [] and ca.cached_hosts() == []


def test_a_key_is_never_world_readable_even_between_write_and_chmod(tmp_path, monkeypatch):
    """0600 from creation: with chmod disabled and a permissive umask, the key is still
    0600 (it used to be written with the umask, then chmodded)."""
    import pathlib
    monkeypatch.setattr(pathlib.Path, "chmod", lambda self, mode: None)
    old = os.umask(0)
    try:
        _cert, key = LocalCA(tmp_path / "ca", minter=_fake).leaf_cert_files("lab.local")
    finally:
        os.umask(old)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


def test_the_path_backstop_holds_if_validation_were_bypassed(tmp_path, monkeypatch):
    import fuzzlab.proxy.ca as ca_mod
    monkeypatch.setattr(ca_mod, "leaf_host", lambda h: h)
    monkeypatch.setattr(ca_mod, "_leaf_filename", lambda h: h)
    ca = LocalCA(tmp_path / "ca", minter=_fake)
    with pytest.raises(ValueError, match="escapes"):
        ca.leaf_cert_files("../../outside/evil")
    assert not (tmp_path / "outside").exists()
