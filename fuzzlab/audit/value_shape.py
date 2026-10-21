"""What an injection point's example value looks like (forms phase 2, FR-AUD-20).

Some candidate rules key on the **value** an app put in a field, not on its name: a
field whose default is a host name (``www.example.org``) is a command-injection
candidate whatever it is called, and one whose default is a file name
(``lang_en.php``) a file-inclusion candidate. :func:`value_shape` is the one
classifier (PA-0003); the rules reference its closed set of shapes, :data:`SHAPES`
(PA-0058(2)).

It is total — a non-string, an empty or an over-long value is ``None`` and it never
raises (PA-0096) — and linear in the value's length: it splits and tests characters
against sets, with no regular expression (a nested quantifier backtracked in review;
PA-0095).

:func:`neutral_value` is what the fuzzer sends in place of such a default (a sibling's,
or a command-injection point's base value), so it never sends a host name taken from
the app's own defaults: loopback instead.
"""

from __future__ import annotations

import ipaddress
import string

#: Every shape a rule may name (``value_shape_in``).
SHAPES = ("ip", "hostname", "filename", "path", "url")
#: The categories each shape implies (PA-0124): the default rules carry exactly one
#: ``R-*-VALUE`` rule per pair, and a test keeps every shape in this table.
SHAPE_CATEGORIES = {
    "ip": ("command-injection",),
    "hostname": ("command-injection",),
    "filename": ("file-inclusion",),
    "path": ("file-inclusion",),
    "url": ("open-redirect", "ssrf"),
}
#: Pairs deliberately left out, with the reason (PA-0124: the table is never silent).
SHAPE_EXCLUSIONS = {
    ("url", "file-inclusion"): "remote file inclusion from a crawled URL value would "
                               "send the app a third-party URL to load (forms phase 2, "
                               "lane A, Q5)",
}
#: Longer values are not classified (and not scanned).
MAX_LEN = 2048
#: A file name ends in one of these. A closed set: a dotted word with any other last
#: part is not a file name (``john.doe``). It wins over a host name with the same last
#: label (``readme.md``, ``build.sh``, ``index.pl``).
FILE_EXTENSIONS = frozenset({
    "php", "php3", "php4", "php5", "php7", "phtml", "inc", "html", "htm", "shtml",
    "xhtml", "txt", "text", "log", "md", "xml", "json", "yml", "yaml", "ini", "conf",
    "cfg", "config", "properties", "env", "csv", "tsv", "js", "css", "tpl", "tmpl",
    "twig", "jsp", "jspx", "asp", "aspx", "ascx", "cgi", "pl", "py", "rb", "sh", "sql",
    "db", "bak", "old", "orig", "swp", "lang", "pdf", "doc", "docx", "xls", "xlsx",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "bmp", "webp", "zip", "tar", "gz", "tgz",
})
#: A host name's last label is a two-letter (country-code shaped) label or one of these.
#: Accepted false positive: a dotted name ending in two letters (``user.id``,
#: ``order.by``) is a host name.
GENERIC_TLDS = frozenset({
    "com", "net", "org", "gov", "edu", "mil", "int", "io", "info", "biz", "co", "app",
    "dev", "cloud", "online", "site", "xyz", "local", "localdomain", "internal", "lan",
    "home", "test", "example", "invalid", "arpa",
})
_URL_SCHEMES = frozenset({"http", "https", "ftp", "file"})
_LDH = frozenset(string.ascii_lowercase + string.digits + "-")
_NAME_CHARS = frozenset(string.ascii_letters + string.digits + "_.~-")
_SPACE = frozenset(string.whitespace)
_ALPHA = frozenset(string.ascii_lowercase)

#: Sent in place of an ip-, host- or url-shaped default.
SAFE_HOST = "127.0.0.1"
SAFE_URL = "http://127.0.0.1/"


def _is_url(value: str) -> bool:
    scheme, sep, rest = value.partition("://")
    return (bool(sep) and scheme.lower() in _URL_SCHEMES and bool(rest)
            and not any(ch in _SPACE for ch in value))


def _is_ip(value: str) -> bool:
    text = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_filename(value: str) -> bool:
    if len(value) > 128 or not all(ch in _NAME_CHARS for ch in value):
        return False
    base, dot, ext = value.rpartition(".")
    return bool(dot) and bool(base.strip(".")) and ext.lower() in FILE_EXTENSIONS


def _is_path(value: str) -> bool:
    if not ("/" in value or "\\" in value):
        return False
    segments = value.replace("\\", "/").split("/")
    first, last = segments[0], segments[-1]
    drive = len(first) == 2 and first[0].isalpha() and first[1] == ":"
    if not all(ch in _NAME_CHARS for seg in segments[1:] for ch in seg):
        return False
    if not drive and not all(ch in _NAME_CHARS for ch in first):
        return False
    anchored = (value.startswith(("/", "\\", "./", "../", "~/")) or drive)
    return anchored or _is_filename(last)


def _is_hostname(value: str) -> bool:
    text = value.lower()
    if text == "localhost":
        return True
    if text.endswith("."):
        text = text[:-1]
    if len(text) > 253:
        return False
    labels = text.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not 1 <= len(label) <= 63 or label[0] == "-" or label[-1] == "-":
            return False
        if not all(ch in _LDH for ch in label):
            return False
    tld = labels[-1]
    return all(ch in _ALPHA for ch in tld) and (len(tld) == 2 or tld in GENERIC_TLDS)


def value_shape(value) -> str | None:
    """The shape of an example value — one of :data:`SHAPES` — or ``None``.

    Tried in order: ``url`` (a known scheme and ``://``), ``ip`` (an IPv4/IPv6
    literal), ``filename`` (one segment ending in a :data:`FILE_EXTENSIONS` extension),
    ``path`` (segments of file-name characters, anchored at ``/``, ``./``, ``../``,
    ``~/`` or a drive, or ending in a file name), ``hostname`` (RFC 1123 labels, at
    least two, the last a two-letter or :data:`GENERIC_TLDS` label; or ``localhost``).
    """
    try:
        if not isinstance(value, str) or not value or len(value) > MAX_LEN:
            return None
        for shape, test in (("url", _is_url), ("ip", _is_ip), ("filename", _is_filename),
                            ("path", _is_path), ("hostname", _is_hostname)):
            if test(value):
                return shape
        return None
    except Exception:                        # total (PA-0096): never raises
        return None


def _host_prefix(value: str) -> tuple[str, str]:
    """``(prefix, rest)`` split at the first ``/`` or ``:`` (an IPv6 literal in
    brackets is kept whole)."""
    if value.startswith("[") and "]" in value:
        end = value.index("]") + 1
        return value[:end], value[end:]
    cuts = [i for i in (value.find("/"), value.find(":")) if i > 0]
    if not cuts:
        return value, ""
    return value[:min(cuts)], value[min(cuts):]


def redirect_seed(value):
    """What an open-redirect probe may embed for an allowlist that checks containment
    (BUG-0124; the stated FR-AUD-20 exception, FR-AUD-21): an ``http``/``https`` example
    sliced from the original text -- its case, explicit port and trailing slash exactly
    as the app wrote them -- up to its query or fragment, with any userinfo cut out.
    ``None`` for anything else, and for a host or path with an identifier-like piece (a
    capability subdomain or a path token never leaves; BUG-0120 class)."""
    from urllib.parse import unquote, urlsplit

    from fuzzlab.core.redaction import looks_like_identifier
    if not isinstance(value, str) or value_shape(value) != "url":
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    if looks_like_identifier(parts.hostname) or any(
            piece and looks_like_identifier(unquote(piece)) for piece in parts.path.split("/")):
        return None                                  # a token in the host or the path
    cuts = [i for i in (value.find("?"), value.find("#")) if i >= 0]
    seed = value[:min(cuts)] if cuts else value
    scheme_end = seed.index("://") + 3
    authority_end = seed.find("/", scheme_end)
    authority_end = len(seed) if authority_end < 0 else authority_end
    authority = seed[scheme_end:authority_end]
    if "@" in authority:
        seed = seed[:scheme_end] + authority.rsplit("@", 1)[1] + seed[authority_end:]
    return seed


def names_outside_lab(value) -> bool:
    """True when ``value`` names a network location that is not loopback: a value
    `neutral_value` would replace whose host is not 127.0.0.0/8, ``localhost`` or
    ``::1`` (`core.urls.is_loopback_origin`, D11). Such a value is never sent (FR-AUD-20)
    and never replaced by a stand-in either (FR-FUZZ-67, BUG-0544): a request that needs
    it cannot be rebuilt. A value naming loopback names the lab itself and is sent as
    the app gave it. Total: a non-string is False.

    Fails closed (BUG-0544 review B3): a value is the lab only when `_names_only_lab`
    proves it; anything else `neutral_value` would change is outside the lab."""
    if not isinstance(value, str) or neutral_value(value) == value:
        return False
    return not _names_only_lab(value)


#: What a host, a port, a scheme or an IPv6 literal is spelled with. A value's path,
#: query and fragment are cut at every other character, so each run a reader could take
#: for a host is looked at whole (BUG-0544 review R2-1: a fixed separator list missed
#: ``evil.example:8080`` and ``https:evil.example``).
_HOSTISH = frozenset(string.ascii_letters + string.digits + "-.:[]")
_SCHEME_CHARS = frozenset(string.ascii_letters + string.digits + "+-.")
_HOST_PORT_CHARS = frozenset(string.ascii_letters + string.digits + "-.")


def _tail_tokens(tail: str):
    """The maximal runs of `_HOSTISH` characters in ``tail``, in order (linear, no
    regular expression; PA-0095)."""
    run: list[str] = []
    for ch in tail:
        if ch in _HOSTISH:
            run.append(ch)
        elif run:
            yield "".join(run)
            run = []
    if run:
        yield "".join(run)


def _ipv4_like(text: str) -> bool:
    """Four dot-separated numbers in any radix WHATWG's IPv4 parser reads (decimal,
    ``0x`` hex, leading-``0`` octal): ``0x8.8.8.8`` and ``010.8.8.8`` are 8.8.8.8 to a
    reader that puts ``http://`` before them, as the canonical quad is (measured in
    node 22)."""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        digits, base = ((part[2:], string.hexdigits) if part[:2].lower() == "0x"
                        else (part, string.digits))
        if not digits or not all(ch in base for ch in digits):
            return False
    return True


def _reads_as_host(token: str) -> bool:
    """Whether one run of a value's path, query or fragment (`_tail_tokens`) names a
    host to some reader (FR-AUD-20, fail closed; BUG-0544 review R2-1), loopback
    included -- a value is the lab only when its tail names no host at all:

    * `value_shape` reads it (one trailing dot off) as a URL, an IP or a host name, or
      it is a dotted quad in another radix (`_ipv4_like`);
    * it starts with a scheme and ``:``, with or without ``//`` (``https:evil.example``,
      which WHATWG resolves against the page to ``https://evil.example/``;
      ``evil.example:8080``, a scheme to WHATWG and a host to the next reader);
    * it is a host and a port: a dotted, numeric or bracketed label, ``:`` and digits or
      nothing (``8.8.8.8:53``, ``[::ffff:8.8.8.8]:53``), which a reader that puts
      ``http://`` before it reads as one. Accepted false positive: a time (``10:30``,
      host 0.0.0.10 to that reader) or a ``word:`` (``Help:Contents``) is a host here."""
    text = token[:-1] if token.endswith(".") else token
    if not text:
        return False
    if value_shape(text) in ("url", "ip", "hostname") or _ipv4_like(text):
        return True
    if text.startswith("[") and "]" in text:
        return text[text.index("]") + 1:].startswith(":")
    head, colon, port = text.partition(":")
    if not colon or not head:
        return False
    if head[0] in string.ascii_letters and all(ch in _SCHEME_CHARS for ch in head):
        return True
    return all(ch in _HOST_PORT_CHARS for ch in head) and (not port or port.isdigit())


def _loopback_authority(authority: str) -> bool:
    """An authority that is a loopback host with at most a numeric port: no userinfo,
    no other punctuation (``127.0.0.1:80@evil.example`` is not one)."""
    from fuzzlab.core.urls import is_loopback_origin
    if not authority or "@" in authority:
        return False
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return False
        host, rest = authority[:end + 1], authority[end + 1:]
    else:
        host, colon, port = authority.partition(":")
        rest = colon + port
    if rest and not (rest.startswith(":") and rest[1:].isdigit()):
        return False
    try:
        return is_loopback_origin("http://" + host)
    except ValueError:
        return False


def _names_only_lab(value: str) -> bool:
    """Whether ``value`` provably names loopback and nothing else (FR-AUD-20 as amended
    by FR-FUZZ-67): no ``@``, ``\\``, ``%``, control or non-ASCII character anywhere
    (WHATWG and other consumers read those differently from `urlsplit`; a reader that
    maps a fullwidth ``evil`` and an ideographic full stop before ``example`` reads
    evil.example, measured in node 22); only ``http``/``https`` when a scheme is given;
    the whole authority a loopback host with a numeric port, as `_loopback_authority`
    splits it **and** as `urlsplit` reads it; and no part of the path, query or fragment
    naming a host or URL to any reader
    (`_reads_as_host`: ``?next=http://evil.example/``, ``?next=evil.example:8080``,
    ``?next=https:evil.example`` and ``#8.8.8.8:53`` are outside; review R2-1)."""
    from urllib.parse import urlsplit

    from fuzzlab.core.urls import is_loopback_origin
    if any(ch in value for ch in "@\\%") or any(ord(ch) < 33 or ord(ch) >= 127
                                                  for ch in value):
        return False
    if "://" in value:
        scheme, rest = value.split("://", 1)
        if scheme.lower() not in ("http", "https"):
            return False
    elif value.startswith("//"):
        rest = value[2:]
    else:
        rest = value
    cut = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if not _loopback_authority(authority):
        return False
    try:
        parsed = urlsplit("http://" + rest)
        host = parsed.hostname
        parsed.port                           # raises on a non-numeric port
    except ValueError:
        return False
    if host is None or not is_loopback_origin("http://" + (f"[{host}]" if ":" in host
                                                            else host)):
        return False
    if "//" in tail:
        return False
    return not any(_reads_as_host(token) for token in _tail_tokens(tail))


def neutral_value(value):
    """``value``, or loopback in its place when it names a network location: what the
    fuzzer sends instead of a default the app supplied (FR-AUD-20). It errs toward
    loopback (reviewer B, R3):

    * anything with ``://`` (any scheme, any length) or starting with ``//`` →
      :data:`SAFE_URL`;
    * an ip or host name → :data:`SAFE_HOST`, also with a port (``host:8080``); with a
      path after it (``host/page``, ``host:8080/x``) → :data:`SAFE_URL`.

    A caller exempts its own fillers first (``store_adapter.is_filler``: they never
    resolve at all). Stated residual: an e-mail default (``user@mail.example.com``) is
    sent as is and may trigger mail."""
    if not isinstance(value, str):
        return value
    if "://" in value or value.startswith("//"):
        return SAFE_URL
    if value_shape(value) in ("ip", "hostname"):     # a url-shaped value has '://' above
        return SAFE_HOST
    prefix, rest = _host_prefix(value)
    if rest and value_shape(prefix) in ("ip", "hostname"):
        return SAFE_URL if "/" in rest else SAFE_HOST
    return value
