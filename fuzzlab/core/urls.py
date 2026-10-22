"""URL normalization used wherever a result URL is stored for cross-referencing.

Result URLs (findings, pages, endpoints, parameters) are stored in **path form**
so they line up with the ground-truth contract (which is written in paths) and can
be matched by the harness. This is the single place that convention lives — writers
must not store URLs verbatim ad hoc (see PA-0003 / BUG-0003).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote_plus, urlparse, urlsplit, urlunsplit


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


def store_url(url: str, main_origin: str | None, *, route: bool = False,
              keep_query: bool = False) -> str:
    """How an importer stores a crawled URL (FR-CORE-504): its path (`to_route_path`
    with ``route``) when it is on the run's main origin, or when either origin is
    unknown; otherwise its canonical origin followed by that path, so a page's API on
    another origin keeps it. ``main_origin`` is a `canonical_origin`. ``keep_query``
    keeps the URL's own query text after the path (a page a fresh form value is fetched
    from, FR-FUZZ-67, is that exact page). A ``;`` path parameter that holds a secret
    (``/a;jsessionid=…/b``) is never stored: `core.redaction.strip_secret_path_params`
    drops it, as `to_path` drops the last segment's (BUG-0556)."""
    from fuzzlab.core.redaction import strip_secret_path_params   # the one rule (SP-17)
    path = strip_secret_path_params(to_route_path(url) if route else to_path(url))
    origin = canonical_origin(url)
    stored = path if main_origin is None or origin is None or origin == main_origin \
        else origin + path
    query = urlsplit(url or "").query if keep_query else ""
    return urlunsplit(("", "", stored, query, "")) if query else stored


def stored_absolute(stored: str, base_origin: str) -> str:
    """The URL a stored page or endpoint names (FR-CORE-504): an absolute stored URL as
    it is, a path under ``base_origin`` (the run's origin, never its path: BUG-0113). A
    stored path always starts with ``/``, so a path holding ``://`` stays a path."""
    if stored.startswith(("http://", "https://")):
        return stored
    return base_origin + (stored if stored.startswith("/") else "/" + stored)


def is_loopback_origin(origin: str | None) -> bool:
    """True for an origin on this machine (127.0.0.0/8, ``localhost``, ``::1``): where a
    lab may live (D11)."""
    host = urlsplit(origin or "").hostname
    if host is None:
        return False
    try:
        return ipaddress.ip_address(_canonical_host(host)).is_loopback
    except ValueError:
        return False


class PathPlacementError(ValueError):
    """A ``path`` point's value cannot be placed in its URL."""


def path_placeholder(param: str) -> str:
    """How a URL template names a path segment parameter: ``/ticket/{id}``."""
    return "{" + param + "}"


def place_path_param(url: str, param: str, value: str) -> str:
    """A ``path`` point's URL with its one placeholder segment (``{param}``, a whole
    segment of the path) replaced by ``value``, percent-encoded as one segment (a ``/``
    in the value stays inside it). The one placement every sender uses (FR-FUZZ-57).
    Raises `PathPlacementError` when the path does not hold the placeholder exactly
    once as a whole segment: refused, never sent elsewhere (PA-0115)."""
    from urllib.parse import quote
    parts = urlsplit(url or "")
    segments = parts.path.split("/")
    hits = [i for i, seg in enumerate(segments) if seg == path_placeholder(param)]
    if len(hits) != 1:
        raise PathPlacementError(f"{path_placeholder(param)!r} is not exactly one segment "
                                 f"of {parts.path!r}")
    segments[hits[0]] = quote(str(value), safe="")
    return urlunsplit(parts._replace(path="/".join(segments)))


# --- query placement (SP-42 extended, FR-CORE-501; CC-CORE-0068, BUG-0531) -----------
def encode_query_value(text) -> str:
    """The one encoder of a query name or value a sender writes: `quote_plus` with
    ``safe=""``, what `urlencode` writes. A query-less URL therefore gets exactly the
    bytes it got before this owner existed (FR-FUZZ-64)."""
    from urllib.parse import quote_plus
    return quote_plus(str(text), safe="")


class QueryEntries:
    """A URL query as the ordered list of its raw ``&``-parts (FR-CORE-501).

    Split on ``&`` only: both measured clients keep ``;`` as data. Every part keeps its
    text exactly: its order, a repeated name, an empty part (``&&``, a trailing ``&``)
    and a missing ``=`` (``flag``). An empty query has no parts. A part's name is decoded
    as a server reads it (form decoding) for matching only, with an invalid escape kept
    as a surrogate, so ``n%E9`` never matches ``n%EF%BF%BD`` (``n\\ufffd``)."""

    __slots__ = ("parts",)

    def __init__(self, parts=()):
        self.parts: tuple[str, ...] = tuple(parts)

    @classmethod
    def parse(cls, raw_query: str | None) -> "QueryEntries":
        return cls(raw_query.split("&") if raw_query else ())

    @staticmethod
    def name_of(part: str) -> str:
        return unquote_plus(part.partition("=")[0], errors="surrogateescape")

    def replace_first(self, name: str, value, encode=encode_query_value) -> "QueryEntries":
        """The first part named ``name`` with ``value`` (``encode``-d) in place, its raw
        name kept; one ``name=value`` part appended when there is none."""
        parts = list(self.parts)
        for i, part in enumerate(parts):
            if self.name_of(part) == name:
                parts[i] = f"{part.partition('=')[0]}={encode(value)}"
                return QueryEntries(parts)
        parts.append(f"{encode(name)}={encode(value)}")
        return QueryEntries(parts)

    def to_query(self) -> str:
        return "&".join(self.parts)


def place_query_param(url: str, name: str, value) -> str:
    """The standalone rule (FR-FUZZ-64): ``url`` with ``value`` in the first part of its
    own query named ``name``, in place, appended once when there is none. Every other
    part, and the rest of the URL, keeps its text (`urlsplit`; an empty ``?`` or ``#`` is
    dropped). The one placement of a value into a URL's own query (SP-42)."""
    parts = urlsplit(url or "")
    query = QueryEntries.parse(parts.query).replace_first(name, value).to_query()
    return urlunsplit(parts._replace(query=query))


def with_query(url: str, entries) -> str:
    """``url`` with its query replaced by ``entries`` (an ordered list of decoded
    ``(name, value)`` pairs, duplicates kept), urlencoded as a browser serialises a form
    (PA-0111). Moved here from ``tools/authhttp`` unchanged in its bytes."""
    from urllib.parse import urlencode
    parts = urlsplit(url or "")
    return urlunsplit(parts._replace(query=urlencode(list(entries))))


def bind_query(url: str, entries, name: str, value) -> str:
    """The bound rule (FR-FUZZ-64): ``url`` with its query set to ``entries`` bound by the
    oracle binder's rule (`core.forms.FormEntries.replace`: every entry called ``name``
    set to ``value``, appended when there is none). Entries the binder has already bound
    come back unchanged. The one bind-then-place of the HTTP senders' bound query branch
    and of the M6 executor; AU-REQID8 changes the rule here, for both."""
    from fuzzlab.core.forms import FormEntries
    bound = FormEntries(tuple(e) for e in entries).replace(name, value)
    return with_query(url, bound)


def encode_route_value(text) -> str:
    """A name or value in a single-page app's route query, as its router reads it:
    `quote` with ``safe=""`` (a space is ``%20``, never ``+``)."""
    from urllib.parse import quote
    return quote(str(text), safe="")


def place_route_query_pairs(url: str, pairs, encode=encode_route_value) -> str:
    """``url`` with each ``(name, value)`` of ``pairs`` placed, in order, by the standalone
    rule (`QueryEntries.replace_first`: the first occurrence in place, appended once when
    absent) into its *route's* query: a URL with a fragment keeps its route and the pairs
    go into the fragment's own query (``/#/search?q=``, hash mode); a URL without one is
    history mode and the pairs go into its own query. Every other part keeps its text.
    ``encode`` encodes the placed names and values (CC-CRAWL-0053: the SPA seed builder
    passes its own, which keeps ``/``)."""
    parts = urlsplit(url or "")
    if parts.fragment:
        route, _sep, raw = parts.fragment.partition("?")
    else:
        route, raw = None, parts.query
    entries = QueryEntries.parse(raw)
    for name, value in pairs:
        entries = entries.replace_first(name, value, encode=encode)
    query = entries.to_query()
    if route is None:
        return urlunsplit(parts._replace(query=query))
    return urlunsplit(parts._replace(fragment=f"{route}?{query}" if query else route))


def place_route_query_param(url: str, name: str, value) -> str:
    """A fragment point's URL (the M6 browser): inside a single-page app's hash route
    (``/#/search?q=``, `spa_route`), the standalone rule over the route's own query
    (`place_route_query_pairs`, names and values `encode_route_value`-d); any other
    fragment is replaced by the pair, form-encoded, as before."""
    if spa_route(url) is not None:
        return place_route_query_pairs(url, [(name, value)])
    parts = urlsplit(url or "")
    fragment = f"{encode_query_value(name)}={encode_query_value(value)}"
    return urlunsplit(parts._replace(fragment=fragment))


def url_key(url: str) -> str:
    """``canonical_origin`` plus path: how an explicit allowance names a URL."""
    return f"{canonical_origin(url) or ''}{urlsplit(url or '').path or '/'}"


def document_key(url: str) -> str:
    """Which document a URL loads: ``canonical_origin``, path and query -- never only the
    path (`url_key`: ``/p?a=1`` and ``/p?a=2`` are two documents). The fragment is
    dropped: it is never sent. The one definition for the reveal window's own reload
    and for the browser guard's "is this still the document I loaded" (BUG-0138
    review, PA-0003)."""
    parts = urlsplit(url or "")
    return (canonical_origin(url) or "") + (parts.path or "/") + \
        (f"?{parts.query}" if parts.query else "")


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
