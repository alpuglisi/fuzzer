"""URL normalization used wherever a result URL is stored for cross-referencing.

Result URLs (findings, pages, endpoints, parameters) are stored in **path form**
so they line up with the ground-truth contract (which is written in paths) and can
be matched by the harness. This is the single place that convention lives — writers
must not store URLs verbatim ad hoc (see PA-0003 / BUG-0003).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlparse


def to_path(url: str) -> str:
    """Return a URL's path with a leading slash (``/product.php``); ``/`` if empty."""
    path = urlparse(url).path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


#: Hostnames that all mean "this machine" — one lab target, however it was typed.
_LOOPBACK_NAMES = {"localhost"}
_DEFAULT_PORT = {"http": 80, "https": 443}


def _canonical_host(host: str) -> str:
    host = host.lower().rstrip(".")
    if host in _LOOPBACK_NAMES:
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host                                   # a hostname: kept as written
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip == ipaddress.ip_address("::1"):
        return "127.0.0.1"
    return ip.compressed                              # other 127/8 hosts stay distinct


def canonical_origin(url: str | None) -> str | None:
    """``scheme://host:port`` of a target URL, canonical for matching (CC-CORE-0029), or
    ``None`` when it has no usable host or port — ``None`` never matches anything.

    Scheme and host are lower-cased (a trailing dot dropped), ``localhost`` / ``::1`` (in
    any spelling, IPv4-mapped included) become ``127.0.0.1``, the default port is made
    explicit, and userinfo, path, query and fragment are dropped. A URL without a scheme
    is read as ``http``. Other hosts — including other 127/8 addresses, which can be
    distinct services — are kept. Use it to *compare* targets; stored values stay as
    written.
    """
    text = (url or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    scheme = (parts.scheme or "http").lower()
    if not parts.hostname:
        return None
    host = _canonical_host(parts.hostname)
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:                   # non-numeric or out-of-range port
        return None
    if port is None:
        port = _DEFAULT_PORT.get(scheme)
    shown = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown}" + (f":{port}" if port is not None else "")
