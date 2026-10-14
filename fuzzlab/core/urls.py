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


def to_route_path(url: str) -> str:
    """`to_path`, plus ``#`` and the path of a single-page app's hash route when the URL
    has one (``http://h/#/search?q=x`` -> ``/#/search``): how a ``fragment`` point's
    endpoint is stored, so a browser can load the route (forms phase 3, FR-CORE-36). The
    route's query is not kept. Any other URL is exactly `to_path`."""
    route = spa_route(url)
    return to_path(url) + ("#" + route[0] if route is not None else "")


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
    # BUG-0114: bWAPP's insecure_crypt_storage_2.php?insert= appends to a password
    # file. (`update` is a pair below: as a bare word it is a REST route's name, e.g.
    # ForgeCart's /admin/customers/update, which the crawl must reach.)
    "insert", "updatedb", "dbupdate", "upgradedb", "dbupgrade",
})
#: Two adjacent tokens that together name such an action (``sign-out``, ``set_up``).
DESTRUCTIVE_PAIRS = frozenset({
    ("log", "out"), ("log", "off"), ("sign", "out"), ("sign", "off"), ("set", "up"),
    ("end", "session"),
    # BUG-0114: `update`/`upgrade` as a script name (bWAPP's update.php rebuilds its
    # database on a GET; WordPress's upgrade.php upgrades it), as a query verb
    # (`?action=update`), or next to a database word (`update_db.php`) -- never a REST
    # route segment merely named `update` (reviewers A/B)
    *{(verb, ext) for verb in ("update", "upgrade")
      for ext in ("php", "php5", "asp", "aspx", "jsp", "cgi", "pl", "py")},
    *{(slot, verb) for verb in ("update", "upgrade")
      for slot in ("action", "op", "do", "cmd", "task", "mode", "method", "func")},
    *{pair for verb in ("update", "upgrade") for db in ("db", "database", "schema")
      for pair in ((verb, db), (db, verb))},
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
    skipping a harmless page costs only coverage. A **text** (a button label, a control
    name, an entry value, an option) is judged with `text_destructive_reason`, never by
    embedding it in a URL: a ``#`` in it would start a fragment this rule never reads
    (BUG-0131).
    """
    return _destructive_tokens(_url_tokens(url))


def _text_tokens(text: str | None) -> list[str]:
    """``text`` decoded as `_url_tokens` decodes a URL (``%xx`` and ``+``, at most three
    rounds) and tokenised the same way, with every character kept: no URL parsing, so
    no ``#`` or ``?`` can hide what follows it (BUG-0131)."""
    text = text or ""
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return _TOKEN.findall(_CAMEL.sub(r"\1 \2", text).lower())


def text_destructive_reason(text: str | None) -> str | None:
    """`destructive_reason`'s tokens and pairs over a whole **text** -- a button label,
    a control name, an entry value, an option -- or None (BUG-0131, PA-0131: the one
    rule for texts, PA-0003). Unlike ``destructive_reason("/?x=" + text)``, a ``#``
    in the text hides nothing."""
    return _destructive_tokens(_text_tokens(text))


def _destructive_tokens(tokens: list[str]) -> str | None:
    for tok in tokens:
        if tok in DESTRUCTIVE_TOKENS:
            return tok
    for pair in zip(tokens, tokens[1:]):
        if pair in DESTRUCTIVE_PAIRS:
            return " ".join(pair)
    return None


#: Parameter names that control the next location: the auditor's redirect rule
#: (`tools.fetcher.rule_redirect_parameters`, exact names) and the crawler's seeds and
#: probes (`tools.spa.redirect_name`, whole tokens) read this one set (CC-CORE-0053,
#: PA-0003). Moved unchanged from `tools/fetcher.py`. The rules-data
#: ``R-OPEN-REDIRECT`` ``name_regex`` is a separate, regex-shaped list (a stated
#: PA-0003 tension, FR-CRAWL-17).
REDIRECT_PARAMS = frozenset({
    'redirect', 'redirect_url', 'redirect_uri', 'redir', 'next', 'next_url',
    'return', 'returnurl', 'return_url', 'returnto', 'return_to', 'goto',
    'continue', 'dest', 'destination', 'url', 'u', 'r', 'back', 'forward',
    'out', 'success_url', 'cancel_url', 'checkout_url', 'location',
})

#: Words that name a transaction: submitting it spends, buys, moves or subscribes
#: (forms phase 3). Separate from DESTRUCTIVE_TOKENS: such a page may be *visited*, but
#: its form is never submitted and a captured request to it is never fuzzed.
TRANSACTION_TOKENS = frozenset({
    "checkout", "purchase", "pay", "payment", "order", "transfer", "redeem", "wallet",
    "membership", "subscribe", "subscription", "buy", "donate", "donation", "deposit",
    "withdraw", "withdrawal", "topup",
})
#: Two adjacent tokens that together name one (``top-up``, ``check out``).
TRANSACTION_PAIRS = frozenset({("top", "up"), ("check", "out")})


def transaction_reason(text: str | None) -> str | None:
    """The token (or pair) that marks ``text`` -- a URL, a route path or a button label
    -- as a transaction, or None (CC-CORE-0045). Tokenised like `destructive_reason`
    (decoded, camelCase split); a trailing plural ``s`` is folded (``orders``,
    ``payments``)."""
    if text and ("://" in text or text.startswith("/")):
        tokens = _url_tokens(text) + _url_tokens(urlsplit(text).fragment)   # SPA route
    else:
        tokens = _TOKEN.findall(_CAMEL.sub(r"\1 \2", text or "").lower())
    for tok in tokens:
        stem = tok[:-1] if len(tok) > 3 and tok.endswith("s") else tok
        if tok in TRANSACTION_TOKENS or stem in TRANSACTION_TOKENS:
            return stem if stem in TRANSACTION_TOKENS else tok
    for pair in zip(tokens, tokens[1:]):
        if pair in TRANSACTION_PAIRS:
            return " ".join(pair)
    return None


def origin_scope(*urls: str | None) -> frozenset[str]:
    """The canonical origins (scheme, host, port) of ``urls`` -- what a browser may
    reach (BUG-0123). Loopback aliases on the same port are one origin, by
    `canonical_origin`."""
    return frozenset(o for o in (canonical_origin(u) for u in urls if u) if o is not None)


def in_origin_scope(url: str, origins: frozenset[str]) -> bool:
    """Whether ``url``'s canonical origin is one of ``origins``: the one browser-scope
    predicate (PA-0003, PA-0123). ``ws``/``wss`` compare as ``http``/``https``."""
    text = url or ""
    low = text[:6].lower()
    if low.startswith("ws://"):
        text = "http://" + text[5:]
    elif low.startswith("wss://"):
        text = "https://" + text[6:]
    if "://" not in text:
        return False                                  # no network origin at all
    origin = canonical_origin(text)
    return origin is not None and origin in origins


def url_key(url: str) -> str:
    """``canonical_origin`` plus path: how an explicit allowance names a URL."""
    return f"{canonical_origin(url) or ''}{urlsplit(url or '').path or '/'}"


#: A URL fragment starting with one of these names a single-page app's route (``#/x``,
#: hashbang ``#!/x``): the one definition (forms phase 3 merge, PA-0003).
SPA_ROUTE_PREFIXES = ("/", "!/")


def is_spa_route_fragment(fragment: str | None) -> bool:
    """Is ``fragment`` (without its ``#``) a single-page app's route?"""
    return bool(fragment) and fragment.startswith(SPA_ROUTE_PREFIXES)


def spa_route(url: str | None) -> tuple[str, str] | None:
    """``(route path, route query)`` of a URL whose fragment is a single-page app's hash
    route (``/#/search?q=x`` -> ``("/search", "q=x")``; ``#!/x`` too), or None for any
    other fragment or none (forms phase 3, FR-CORE-36). A route's query is read by the
    app in the browser and never reaches the server."""
    fragment = urlsplit(url or "").fragment
    if not is_spa_route_fragment(fragment):
        return None
    path, _sep, query = fragment.partition("?")
    return path, query


#: Methods a probe never sends unless its URL was explicitly enumerated (forms phase 3,
#: FR-FUZZ-47): a crawl-captured DELETE is never imported, and refused again at the send.
REFUSED_SEND_METHODS = frozenset({"DELETE"})


class DestructiveUrlRefused(ValueError):
    """A send to a destructive URL the operator did not explicitly enumerate."""


def check_send_url(url: str, explicit: frozenset[str] = frozenset(),
                   method: str | None = None) -> None:
    """Refuse a probe to a destructive URL, or with a refused method (``DELETE``),
    unless the URL is explicitly allowed.

    Every probe sender calls this first (NFR-FUZZ-safe, CC-FUZZ-0060), passing its
    send's ``method``. ``explicit`` holds :func:`url_key` values of operator-enumerated
    (ground-truth) points.
    """
    reason = destructive_reason(url)
    if reason is None and (method or "").upper() in REFUSED_SEND_METHODS:
        reason = f"{method.upper()} method"
    if reason is not None and url_key(url) not in explicit:
        raise DestructiveUrlRefused(
            f"refusing to send to {url.split('?', 1)[0]}: it looks destructive "
            f"({reason!r}) and was not explicitly enumerated (ground truth)")
