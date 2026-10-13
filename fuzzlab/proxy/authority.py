"""One parser for ``host[:port]`` authorities (BUG-0086, PA-0003).

Every proxy site that split an authority did ``partition(":")``, which breaks on IPv6:
``[::1]:8443`` became host ``"["``. Brackets are part of the authority syntax, not of
the host, so `split_authority` strips them and `join_authority` puts them back.
"""

from __future__ import annotations


def split_authority(text: str, default_port: int | None = None) -> tuple[str, int | None]:
    """``(host, port)`` from ``host``, ``host:port``, ``[v6]`` or ``[v6]:port``. A bare
    IPv6 literal without brackets (``::1``) is read as a host with no port. The port is
    ``default_port`` when absent or not a number; the host is lower-cased."""
    text = (text or "").strip()
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            host, rest = text[1:end], text[end + 1:]
            port = rest[1:] if rest.startswith(":") else ""
            return host.lower(), int(port) if port.isdigit() else default_port
    if text.count(":") > 1:                      # unbracketed IPv6 literal: no port
        return text.lower(), default_port
    host, _, port = text.partition(":")
    return host.lower(), int(port) if port.isdigit() else default_port


def join_authority(host: str, port: int | None) -> str:
    """``host:port`` (IPv6 hosts bracketed); just the host when ``port`` is None."""
    h = f"[{host}]" if ":" in host else host
    return h if port is None else f"{h}:{port}"
