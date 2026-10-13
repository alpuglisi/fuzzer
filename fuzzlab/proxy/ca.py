"""Local CA and cached leaf certificates for TLS interception (FR-PROXY-2).

To intercept HTTPS the proxy terminates TLS with a certificate the browser trusts: a
**local CA** (generated once, kept on the host, 0600) mints a per-host **leaf cert** on
first CONNECT, signed by the CA, and caches it so repeat visits are cheap
(NFR-PROXY-safe: the CA never leaves the host).

The cryptography-backed minting is imported lazily and runs **on-host** (the sandbox has
no working `cryptography` build). The part that is pure and testable here — the
per-host **leaf cache** and its key logic — is separated behind an injectable
``minter`` seam, so the caching behavior is unit-tested offline with a fake minter and
the real X.509 work is exercised on the host.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from pathlib import Path

from typing import Callable

from fuzzlab.core.secretfile import create_secret, replace_secret


def _utcnow() -> datetime.datetime:
    """Naive UTC now (compatible with all `cryptography` versions; no `utcnow()`)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

# minter: host -> (cert_pem, key_pem)
Minter = Callable[[str], "tuple[bytes, bytes]"]

_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def leaf_host(host: str) -> str:
    """The validated, canonical host a leaf is minted for (BUG-0079, FR-PROXY-10).

    ``host`` arrives from the network (a CONNECT authority), so it is a whitelist
    grammar, never a filename fragment: an IP literal (IPv6 with or without brackets,
    port stripped by `split_authority`), or a hostname of ``[a-z0-9_-]`` labels (``_``
    allowed: Docker service names) separated by single dots, IDNA-encoded and
    lower-cased, at most 253 characters. Anything else raises ``ValueError``."""
    from fuzzlab.proxy.authority import split_authority
    name, _port = split_authority(host or "")
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        pass
    try:
        name = name.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"not a valid leaf hostname: {host!r}") from exc
    name = name.rstrip(".")
    if not name or len(name) > 253 or not all(_LABEL.match(lb) for lb in name.split(".")):
        raise ValueError(f"not a valid leaf hostname: {host!r}")
    return name


def _leaf_filename(host: str) -> str:
    """A filename for a validated host: IPv6 as ``ip6-<hex>`` (no ':' in a filename,
    and no collision with a hostname)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"ip6-{ip.packed.hex()}" if ip.version == 6 else host


class CAError(RuntimeError):
    """The on-disk CA is incomplete or its key does not match its certificate."""


class LocalCA:
    """A local CA that mints and caches per-host leaf certs.

    ``minter`` is injectable for tests; when absent, leaves are minted with
    ``cryptography`` (lazy import, on-host).
    """

    def __init__(self, ca_dir: str | Path, minter: Minter | None = None,
                 valid_days: int = 825):
        self._dir = Path(ca_dir)
        self._minter = minter
        self._valid_days = valid_days
        self._leaf_cache: dict[str, tuple[bytes, bytes]] = {}
        self._ca_cert_pem: bytes | None = None
        self._ca_key_pem: bytes | None = None

    @property
    def ca_cert_path(self) -> Path:
        return self._dir / "fuzzlab-ca.crt"

    @property
    def ca_key_path(self) -> Path:
        return self._dir / "fuzzlab-ca.key"

    # --- leaf cache (pure; testable offline) --------------------------------
    def leaf_cert(self, host: str) -> tuple[bytes, bytes]:
        """Return ``(cert_pem, key_pem)`` for ``host``, minting+caching on first use."""
        host = leaf_host(host)                         # cache per hostname, not port
        cached = self._leaf_cache.get(host)
        if cached is not None:
            return cached
        leaf = (self._minter or self._mint_leaf)(host)
        self._leaf_cache[host] = leaf
        return leaf

    def leaf_cert_files(self, host: str) -> tuple[Path, Path]:
        """Materialize ``host``'s leaf cert+key to files and return their paths.

        ``ssl.SSLContext.load_cert_chain`` needs file paths, so the cached PEMs are
        written under ``<ca_dir>/leaves/`` (both 0600), key first, then cert, each
        replaced atomically and in full (BUG-0096): a failed write raises and never
        leaves a partial PEM. The files are always rewritten from the in-memory pair, so
        what is on disk is that pair; ``load_cert_chain`` itself refuses a mismatch.
        On-host (needs a real leaf).
        """
        cert_pem, key_pem = self.leaf_cert(host)
        safe = _leaf_filename(leaf_host(host))
        d = self._dir / "leaves"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        cert_path = d / f"{safe}.crt"
        key_path = d / f"{safe}.key"
        root = d.resolve()
        for p in (cert_path, key_path):               # backstop: never outside leaves/
            if p.resolve().parent != root:
                raise ValueError(f"leaf path escapes {root}: {p}")
        replace_secret(key_path, key_pem)
        replace_secret(cert_path, cert_pem)
        return cert_path, key_path

    def cached_hosts(self) -> list[str]:
        return sorted(self._leaf_cache)

    def clear_cache(self) -> None:
        self._leaf_cache.clear()

    # --- on-host: real CA + leaf minting (lazy cryptography) ----------------
    def ensure_ca(self) -> tuple[bytes, bytes]:
        """Load the CA from disk, or create and persist it. On-host.

        The trust root is never replaced silently (BUG-0096): the key is created with
        ``O_EXCL`` (0600 from creation, BUG-0079), then the certificate is written
        atomically. On load the key must match the certificate, and a half-written CA
        (one file without the other) is refused, each with `CAError` naming the fix."""
        if self._ca_cert_pem is not None:
            return self._ca_cert_pem, self._ca_key_pem
        have_cert, have_key = self.ca_cert_path.exists(), self.ca_key_path.exists()
        if have_cert and have_key:
            cert_pem = self.ca_cert_path.read_bytes()
            key_pem = self.ca_key_path.read_bytes()
            if not self._pair_matches(cert_pem, key_pem):
                raise CAError(f"the CA key {self.ca_key_path} does not match its "
                              f"certificate {self.ca_cert_path}; remove both to create a "
                              f"new CA (and re-trust it)")
            self._ca_cert_pem, self._ca_key_pem = cert_pem, key_pem
            return cert_pem, key_pem
        if have_cert or have_key:
            present = self.ca_cert_path if have_cert else self.ca_key_path
            raise CAError(f"incomplete CA: {present} exists without its pair; remove it "
                          f"to create a new CA (and re-trust it)")
        cert_pem, key_pem = self._mint_ca()
        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        create_secret(self.ca_key_path, key_pem)     # never replaces an existing key
        replace_secret(self.ca_cert_path, cert_pem)
        self.ca_cert_path.chmod(0o644)               # the certificate is public
        self._ca_cert_pem, self._ca_key_pem = cert_pem, key_pem
        return cert_pem, key_pem

    def _pair_matches(self, cert_pem: bytes, key_pem: bytes) -> bool:
        """Whether ``key_pem`` is the private key of ``cert_pem`` (False if unparsable)."""
        x509, _hashes, serialization, _rsa, _oid = self._crypto()
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            key = serialization.load_pem_private_key(key_pem, password=None)
        except (ValueError, TypeError):
            return False
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        return (cert.public_key().public_bytes(serialization.Encoding.DER, spki)
                == key.public_key().public_bytes(serialization.Encoding.DER, spki))

    def _crypto(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        return x509, hashes, serialization, rsa, NameOID

    def _mint_ca(self) -> tuple[bytes, bytes]:
        x509, hashes, serialization, rsa, NameOID = self._crypto()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fuzzlab local CA")])
        now = _utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                # KeyUsage + SubjectKeyIdentifier: modern OpenSSL verifiers require a
                # proper CA (keyCertSign) and an SKI the leaf's AKI can chain to.
                .add_extension(x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .sign(key, hashes.SHA256()))
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        return cert.public_bytes(serialization.Encoding.PEM), key_pem

    def _mint_leaf(self, host: str) -> tuple[bytes, bytes]:
        x509, hashes, serialization, rsa, NameOID = self._crypto()
        from cryptography.x509.oid import ExtendedKeyUsageOID
        ca_cert_pem, ca_key_pem = self.ensure_ca()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = _utcnow()
        # An IP literal needs an IPAddress SAN (not DNSName) to verify by hostname.
        try:
            san_entry = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san_entry = x509.DNSName(host)
        san = x509.SubjectAlternativeName([san_entry])
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=self._valid_days))
                .add_extension(san, critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                # SKI + AKI so the leaf chains to the CA under strict verifiers (the
                # "Missing Authority Key Identifier" failure), + serverAuth EKU for
                # browsers, + a leaf KeyUsage.
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        ca_cert.public_key()), False)
                .add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False), critical=False)
                .sign(ca_key, hashes.SHA256()))
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        return cert.public_bytes(serialization.Encoding.PEM), key_pem
