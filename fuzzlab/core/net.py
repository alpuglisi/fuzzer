"""The one loopback gate for every listener the toolkit opens (BUG-0080, D11, PA-0081).

A listener (the proxy, the web panel, the in-process proxy, the OOB callback server)
must bind loopback only. That check existed in three copies with different host sets,
and the `fuzzlab proxy` CLI had none, so `--host 0.0.0.0` bound every interface.
"""

from __future__ import annotations

import ipaddress


def is_loopback_host(host: str) -> bool:
    """True for ``localhost``, any 127/8 address, ``::1`` (bracketed or not) and the
    IPv4-mapped loopback forms. Any other name, ``0.0.0.0`` / ``::`` and every routable
    address are not loopback."""
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool((mapped or ip).is_loopback)


def require_loopback(host: str, what: str = "listener") -> str:
    """Return ``host`` if it is loopback, else raise ``ValueError`` naming ``what``."""
    if not is_loopback_host(host):
        raise ValueError(f"refusing to bind {what} to non-loopback host {host!r} "
                         f"(lab-only: loopback only, D11)")
    return host
