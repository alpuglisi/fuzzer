"""URL normalization used wherever a result URL is stored for cross-referencing.

Result URLs (findings, pages, endpoints, parameters) are stored in **path form**
so they line up with the ground-truth contract (which is written in paths) and can
be matched by the harness. This is the single place that convention lives — writers
must not store URLs verbatim ad hoc (see PA-0003 / BUG-0003).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote_plus, urlparse, urlsplit


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


# --- destructive URLs (NFR-CRAWL-safe / NFR-FUZZ-safe; BUG-0111/0112) ---------------
#: Words that name a destructive or session-ending action. Matched as whole tokens of
#: the decoded path and query, so ``model``, ``dropdown`` or ``clearance`` never match.
#: ``format`` is deliberately absent: ``?format=csv`` is the common export selector.
DESTRUCTIVE_TOKENS = frozenset({
    "logout", "logoff", "signout", "reset", "delete", "del", "remove", "destroy",
    "drop", "purge", "wipe", "truncate", "erase", "install", "uninstall", "deactivate",
    "unsubscribe", "clear", "flush", "empty", "trash", "kill", "terminate", "revoke",
    "cancel", "disable", "ban", "shutdown", "restart", "reboot", "exit", "setup",
    "rebuild", "migrate", "seed",
})
#: Two adjacent tokens that together name such an action (``sign-out``, ``set_up``).
DESTRUCTIVE_PAIRS = frozenset({
    ("log", "out"), ("log", "off"), ("sign", "out"), ("sign", "off"), ("set", "up"),
    ("end", "session"),
})
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_TOKEN = re.compile(r"[a-z]+|[0-9]+")


def _url_tokens(url: str) -> list[str]:
    parts = urlsplit(url or "")
    text = f"{parts.path}?{parts.query}"
    for _ in range(3):                               # %2572 -> %72 -> r, then stable
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return _TOKEN.findall(_CAMEL.sub(r"\1 \2", text).lower())


def destructive_reason(url: str) -> str | None:
    """The token (or pair) that marks ``url`` as a destructive action, or None.

    The one rule every crawl, audit and probe gate uses (PA-0003). It inspects only the
    URL's path and query, decoded and tokenised; it is deliberately conservative, since
    skipping a harmless page costs only coverage.
    """
    tokens = _url_tokens(url)
    for tok in tokens:
        if tok in DESTRUCTIVE_TOKENS:
            return tok
    for pair in zip(tokens, tokens[1:]):
        if pair in DESTRUCTIVE_PAIRS:
            return " ".join(pair)
    return None


def url_key(url: str) -> str:
    """``canonical_origin`` plus path: how an explicit allowance names a URL."""
    return f"{canonical_origin(url) or ''}{urlsplit(url or '').path or '/'}"


class DestructiveUrlRefused(ValueError):
    """A send to a destructive URL the operator did not explicitly enumerate."""


def check_send_url(url: str, explicit: frozenset[str] = frozenset()) -> None:
    """Refuse a probe to a destructive URL unless it is explicitly allowed.

    Every probe sender calls this first (NFR-FUZZ-safe, CC-FUZZ-0060). ``explicit``
    holds :func:`url_key` values of operator-enumerated (ground-truth) points.
    """
    reason = destructive_reason(url)
    if reason is not None and url_key(url) not in explicit:
        raise DestructiveUrlRefused(
            f"refusing to send to {url.split('?', 1)[0]}: it looks destructive "
            f"({reason!r}) and was not explicitly enumerated (ground truth)")
