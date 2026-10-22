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
    """True when ``value`` may name a network location outside the lab (FR-AUD-20, SP-73,
    D11). Such a value is never sent (FR-AUD-20) and never replaced by a stand-in either
    (FR-FUZZ-67, BUG-0544): a request that needs it cannot be rebuilt. A value naming
    only loopback names the lab itself and is sent as the app gave it. Total: a
    non-string is False.

    An allow-list (PA-0544(7), PA-0555; BUG-0544 residual N-R3-1, BUG-0555), decided on
    every text a reader parses (`_reader_texts`): a value of a URL or authority shape
    (`_authority_shaped`: a scheme and ``:``, a leading ``//`` or ``\\``, or a leading
    token, or the host a reader that puts ``http://`` before the value takes, that is a
    `_host_token`) is the lab only when `_names_only_lab` proves it -- its authority one
    of the explicit loopback spellings of `_lab_authority` and its path, query and
    fragment in `_tail_in_grammar`. Anything else names no host but a single-label one
    to any reader (a pure word, a small number, free text with a space, a reference to
    the page's own path) and is the lab.

    Nothing here asks whether `neutral_value` or `value_shape` would change the value:
    no recogniser of a host admits one (BUG-0555). Stated residual: a value that names no
    host of its own but whose path, query or fragment does (``/?next=evil.top``,
    ``intranet/?next=evil.top``) is the lab -- holding every such value to the tail
    grammar would put 99.9% of ASP.NET view states (``/wE...``) and 21.5% of standard
    base64 tokens outside (measured, BUG-0555)."""
    if not isinstance(value, str):
        return False
    texts = _reader_texts(value)
    return any(_authority_shaped(text) for text in texts) and not _names_only_lab(value)


#: Where a reader ends a value's leading token (BUG-0555): the authority's own ends
#: ('/', '?', '#', and '\\' for the special schemes), a port or scheme (':'), userinfo
#: ('@') and a path parameter (';', which some readers cut at).
_LEAD_DELIMITERS = "/?#:@;\\"
#: Where WHATWG ends an authority after ``http://`` (the special-scheme rule).
_AUTHORITY_ENDS = "/?#\\"
#: The IDNA label separators UTS #46 maps to '.' (after NFKC: U+FF0E is already '.',
#: U+FF61 is U+3002).
_IDNA_DOTS = ("\u3002",)
#: WHATWG's "C0 control or space", trimmed from both ends of a URL.
_C0_OR_SPACE = "".join(chr(i) for i in range(0x21))


def _reader_texts(value: str) -> tuple[str, ...]:
    """The texts URL readers parse from ``value`` (BUG-0555), so a padded or NUL-cut
    ``evil.top`` is read as ``evil.top`` (fail closed: each proof itself reads the raw
    value, which holds no control or space): `_reader_text` of the whole value, and of
    the part before its first NUL (a C reader stops there)."""
    texts = (_reader_text(value),)
    if "\x00" in value:
        texts += (_reader_text(value.partition("\x00")[0]),)
    return texts


def _reader_text(value: str) -> str:
    """``value`` as WHATWG parses it: every ASCII tab and newline removed, C0 controls
    and spaces trimmed at both ends; and as an application that trims Unicode
    whitespace first (Python's and JavaScript's ``strip``/``trim``). Linear."""
    text = value.replace("\t", "").replace("\n", "").replace("\r", "")
    while True:
        trimmed = text.strip(_C0_OR_SPACE).strip()
        if trimmed == text:
            return text
        text = trimmed


def _scheme_shaped(text: str) -> bool:
    """Whether ``text`` starts with a URL scheme and ``:`` (WHATWG's scheme state: an
    ASCII letter, then ASCII letters, digits, ``+``, ``-`` or ``.``)."""
    scheme, colon, _rest = text.partition(":")
    return (bool(colon) and scheme[:1].isascii() and scheme[:1].isalpha()
            and scheme.isascii()
            and scheme.replace("+", "").replace("-", "").replace(".", "").isalnum())


def _leading_token(text: str) -> str:
    """``text`` up to its first `_LEAD_DELIMITERS` character (a bracketed literal kept
    whole)."""
    if text.startswith("["):
        end = text.find("]")
        return text if end < 0 else text[:end + 1]
    cut = min((i for i in (text.find(c) for c in _LEAD_DELIMITERS) if i >= 0),
              default=len(text))
    return text[:cut]


def _reader_host(text: str) -> str:
    """The host a reader that puts ``http://`` before ``text`` takes (WHATWG, measured
    in node 22): leading ``/`` and ``\\`` are skipped (``/evil.top`` is evil.top), the
    authority ends at the next `_AUTHORITY_ENDS` character, userinfo at its last ``@``,
    and the port starts at the first ``:`` outside brackets (``user@evil.example`` ->
    ``evil.example``, ``a;b.top:8080`` -> ``a;b.top``)."""
    text = text.lstrip("/\\")
    cut = min((i for i in (text.find(c) for c in _AUTHORITY_ENDS) if i >= 0),
              default=len(text))
    host = text[:cut].rpartition("@")[2]
    if host.startswith("["):
        end = host.find("]")
        return host if end < 0 else host[:end + 1]
    return host.partition(":")[0]


def _host_text(token: str) -> str | None:
    """The domain WHATWG's host parser reads from ``token`` (`new URL("http://" +
    token)`), approximated so that it never hides a dot or a digit: percent-decoded
    (UTF-8, an invalid byte replaced), NFKC-normalised and case-folded (UTS #46 maps
    fullwidth letters and digits and U+FF0E to ASCII), every format character and
    variation selector dropped (UTS #46 ignores them: ``evil\\u200b.top`` is evil.top), and
    the ideographic full stop read as ``.``. ``None`` when WHATWG cannot read a host at
    all: a space or control character is left (a forbidden domain code point). Bounded:
    a token longer than :data:`MAX_LEN` with no space is read as a dotted host."""
    import unicodedata
    from urllib.parse import unquote
    if _has_space_or_control(token):
        return None
    if len(token) > MAX_LEN:
        return "."                  # too long to map within the bound: a host (fail closed)
    text = unquote(token, errors="replace")
    text = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", text).casefold())
    text = "".join(ch for ch in text
                   if unicodedata.category(ch) != "Cf"
                   and not ("\ufe00" <= ch <= "\ufe0f" or "\U000e0100" <= ch <= "\U000e01ef"
                            or ch in "\u034f\u180b\u180c\u180d\u180f"))
    for dot in _IDNA_DOTS:
        text = text.replace(dot, ".")
    if not text or _has_space_or_control(text):
        return None
    return text


def _has_space_or_control(text: str) -> bool:
    """Whether ``text`` holds whitespace or a control character (C-level fast path: a
    printable string holds neither but the space)."""
    if text.isprintable():
        return " " in text
    return any(ch.isspace() or ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0 for ch in text)


def _ipv4_number(part: str) -> int | None:
    """WHATWG's IPv4 number parser: ``0x``/``0X`` hex, a leading ``0`` octal, else
    decimal (ASCII digits only); ``None`` when ``part`` is not one."""
    if not part:
        return None
    if part[:2] in ("0x", "0X"):
        digits, base, allowed = part[2:], 16, "0123456789abcdefABCDEF"
    elif len(part) > 1 and part[0] == "0":
        digits, base, allowed = part[1:], 8, "01234567"
    else:
        digits, base, allowed = part, 10, "0123456789"
    if not digits:
        return 0
    if not all(ch in allowed for ch in digits):
        return None
    if base == 10 and len(digits) > 10:
        return 1 << 40              # past 2**32: never an address (and int() stays bounded)
    return int(digits, base)


#: A dotless number below this is an address in 0.0.0.0/8 to WHATWG and inet_aton
#: ("this network": RFC 6890 marks it no destination and not forwardable). From here to
#: 2**32 - 1 it is a routable address (``134744072`` is 8.8.8.8). Measured on the test
#: host (Linux 6.18, a UDP connect, nothing sent): 0.0.0.0 is routed to 127.0.0.1, every
#: other 0/8 address to the default route (Linux treats 0/8 as unicast since 5.3).
_SMALL_NUMBER_LIMIT = 1 << 24


def _small_number(text: str) -> bool:
    """A dotless number (`_host_text`, `_ipv4_number`) below `_SMALL_NUMBER_LIMIT`."""
    host = _host_text(text)
    number = None if host is None or "." in host else _ipv4_number(host)
    return number is not None and number < _SMALL_NUMBER_LIMIT


def _host_token(token: str) -> bool:
    """Whether a reader that puts ``http://`` before ``token`` reads a host that is not
    only a search-list name: WHATWG can read one (`_host_text`: no space or control) and
    it holds a dot (``.`` or an IDNA full stop, after WHATWG's mapping: ``evil%2Etop``,
    a fullwidth full stop, ``evil\\u200b.top``, ``1.2.3``, ``v1.2``), is a bracketed
    literal, is ``localhost``, or is a dotless number that WHATWG reads as 0.0.0.0 (this
    host: the kernel routes it to loopback) or as an address of at least
    `_SMALL_NUMBER_LIMIT` (``0x8080808``, ``134744072``). A pure word (``intranet``),
    another small number (``42``) and a number of 2**32 or more (no reader takes it for
    an address) are single-label names, a host only to a resolver that completes them
    from a search list or a hosts file (the stated residual of FR-AUD-20)."""
    if token.startswith("["):
        return True
    text = _host_text(token)
    if text is None:
        return False
    if "." in text or text == "localhost":
        return True
    number = _ipv4_number(text)
    return number is not None and (number == 0 or _SMALL_NUMBER_LIMIT <= number < 1 << 32)


def _authority_shaped(text: str) -> bool:
    """Whether a reader may take a host from ``text`` (`_reader_texts`): it starts with a
    scheme and ``:`` (any scheme: ``https:evil.example``, ``mailto:``, ``sort:asc``), a
    ``//`` or a ``\\`` (a network-path reference: WHATWG reads ``\\`` as ``/`` and
    ``/\\`` as ``//``), or its leading token, or the host a reader that puts
    ``http://`` before it takes, is a `_host_token`."""
    if not text:
        return False
    if text.startswith(("\\", "//", "/\\")) or _scheme_shaped(text):
        return True
    lead = _leading_token(text)
    if lead == text and _small_number(text):
        return False            # a bare small number, 0 included: nothing after the host
    return _host_token(lead) or _host_token(_reader_host(text))


def _plain_ascii(value: str) -> bool:
    """Printable ASCII with no space: no control, space or non-ASCII character."""
    return value.isascii() and value.isprintable() and " " not in value


#: The safe tail grammar (FR-AUD-20 as the owner decided it, 2026-10-21; BUG-0544 review
#: R3-1). An allow-list of how a loopback value's path, query and fragment may be spelled,
#: never a recogniser of hosts: a recogniser asks which tokens read as a host and misses
#: every spelling its lists do not hold (a gTLD outside `GENERIC_TLDS`, a one- to
#: three-part or integer IPv4 address); this asks only whether every token is in the
#: grammar. A separator between words:
_TAIL_SEPARATORS = frozenset("/?#&=")
#: The characters of a word.
_TAIL_WORD = frozenset(string.ascii_letters + string.digits + "_-~")


def _tail_in_grammar(tail: str) -> bool:
    """Whether a loopback value's path, query and fragment (``tail``, from the first
    ``/``, ``?`` or ``#`` after the authority) are all in the safe grammar::

        tail      := ( separator | word )*
        separator := "/" | "?" | "#" | "&" | "="      -- never "/" twice in a row
        word      := a maximal run of ASCII letters, digits, "_", "-", "~"
                     whose first character is not a digit

    So no token holds a ``.`` or a ``:`` (or any other character: ``%``, ``@``,
    ``\\``, ``[``, ``+``, ``;``, ``,``, non-ASCII), and none is a number in any radix
    or of any length (a digit-led token: ``2``, ``134744072``, ``0x8080808``, ``010``).
    Anything else is outside the lab, and `neutral_value` stands in for it. Linear, no
    regular expression (PA-0095).

    Accepted false positives (the owner's decision): a loopback value whose tail holds
    a number, a dotted or colon-separated token or any character outside the grammar
    (``?page=2``, ``/app.js?v=1.2.3``, ``?at=10:30``, ``?q=a+b``, ``/2fa``) is outside.
    Stated residual: a dotless word (``?next=intranet``) is in the grammar; only a
    resolver that completes it from a search list reads it as a host."""
    after_slash = False
    word_start = True
    for ch in tail:
        if ch in _TAIL_SEPARATORS:
            if ch == "/" and after_slash:
                return False                   # '//': a network-path reference
            after_slash = ch == "/"
            word_start = True
        elif ch in _TAIL_WORD:
            if word_start and ch in string.digits:
                return False                   # a number in some radix
            after_slash = word_start = False
        else:
            return False                       # not in the grammar
    return True


#: The loopback hosts a value may name and still be the lab (FR-AUD-20, BUG-0555): an
#: explicit set of spellings that every reader (WHATWG, `urlsplit`, `ipaddress`,
#: inet_aton, a resolver) reads as the same loopback host -- ``localhost`` (in any case:
#: every reader folds it), ``[::1]``, and ``127.a.b.c`` in canonical dotted decimal
#: (`_lab_ipv4`). Not admitted, so outside: ``localhost.`` (WHATWG keeps it as another
#: host, and a resolver may send a rooted name to DNS: RFC 6761 6.3 only asks it to
#: answer locally), every other spelling of a loopback address (``127.1``,
#: ``2130706433``, ``0x7f000001``, ``0177.0.0.1``, ``127.0.0.1.``,
#: ``[0:0:0:0:0:0:0:1]``, ``[::ffff:127.0.0.1]``: readers disagree on them).
_LAB_NAMES = frozenset({"localhost", "[::1]"})


def _lab_ipv4(host: str) -> bool:
    """``127.a.b.c`` in canonical dotted decimal: four ASCII decimal parts, each 0..255
    with no leading zero. Every reader reads that spelling as the same address, and
    127.0.0.0/8 never leaves the host (RFC 1122 3.2.1.3); the lab's own multi-origin
    setups bind 127.0.0.2 and 127.0.0.3."""
    parts = host.split(".")
    return (len(parts) == 4 and parts[0] == "127"
            and all(p.isascii() and p.isdigit() and len(p) <= 3
                    and (p == "0" or p[0] != "0") and int(p) <= 255 for p in parts))


def _lab_authority(authority: str) -> tuple[str, int | None] | None:
    """``(host, port)`` when ``authority`` is a `_LAB_NAMES` or `_lab_ipv4` host with at
    most a port of one to five ASCII digits (up to 65535); ``None`` for anything else
    (userinfo, an empty port, any other character)."""
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host, rest = authority[:end + 1], authority[end + 1:]
    else:
        host, colon, port = authority.partition(":")
        rest = colon + port
    port = None
    if rest:
        digits = rest[1:]
        if not (rest[0] == ":" and 1 <= len(digits) <= 5 and digits.isascii()
                and digits.isdigit() and int(digits) <= 65535):
            return None
        port = int(digits)
    host = host.lower()
    if host in _LAB_NAMES or _lab_ipv4(host):
        return host, port
    return None


def _names_only_lab(value: str) -> bool:
    """Whether a value of a URL or authority shape provably names loopback and nothing
    else (FR-AUD-20 as amended by FR-FUZZ-67; BUG-0544 reviews R2-1, R3-1, N-R3-1;
    BUG-0555): no ``@``, ``\\``, ``%``, control, space or non-ASCII character anywhere
    (WHATWG and other readers read those differently from `urlsplit`; a reader that maps
    a fullwidth ``evil`` and an ideographic full stop before ``example`` reads
    evil.example, measured in node 22); ``http://``, ``https://``, ``//`` or nothing
    before the authority; the authority, up to the first ``/``, ``?`` or ``#``, one of
    `_lab_authority`'s spellings, and `urlsplit` reading the same host and port; and the
    path, query and fragment wholly in the safe tail grammar (`_tail_in_grammar`, an
    allow-list: ``?next=evil.top``, ``?next=134744072``, ``?next=https:evil.example``
    and ``#8.8.8.8:53`` are outside)."""
    from urllib.parse import urlsplit
    if any(ch in value for ch in "@\\%") or not _plain_ascii(value):
        return False
    head = value[:8].lower()
    if head.startswith("http://"):
        rest = value[7:]
    elif head.startswith("https://"):
        rest = value[8:]
    elif value.startswith("//"):
        rest = value[2:]
    else:
        rest = value
    cut = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    lab = _lab_authority(authority)
    if lab is None:
        return False
    host, port = lab
    try:
        parsed = urlsplit("http://" + rest)
        if parsed.hostname != host.strip("[]") or parsed.port != port:
            return False
    except ValueError:
        return False
    return _tail_in_grammar(tail)


def neutral_value(value):
    """``value``, or loopback in its place when it names a network location: what the
    fuzzer sends instead of a default the app supplied (FR-AUD-20). It errs toward
    loopback (reviewer B, R3):

    * anything with ``://`` (any scheme, any length) or starting with ``//`` →
      :data:`SAFE_URL`;
    * an ip or host name → :data:`SAFE_HOST`, also with a port (``host:8080``); with a
      path after it (``host/page``, ``host:8080/x``) → :data:`SAFE_URL`;
    * any other value `names_outside_lab` puts outside the lab (BUG-0555) → loopback
      too: :data:`SAFE_URL` when it has a scheme, a path, a query or a fragment, else
      :data:`SAFE_HOST`.

    A caller exempts its own fillers first (``store_adapter.is_filler``: they never
    resolve at all)."""
    if not isinstance(value, str):
        return value
    if "://" in value or value.startswith("//"):
        return SAFE_URL
    if value_shape(value) in ("ip", "hostname"):     # a url-shaped value has '://' above
        return SAFE_HOST
    prefix, rest = _host_prefix(value)
    if rest and value_shape(prefix) in ("ip", "hostname"):
        return SAFE_URL if "/" in rest else SAFE_HOST
    if names_outside_lab(value):
        text = _reader_text(value)
        return (SAFE_URL if _scheme_shaped(text) or any(ch in text for ch in "/\\?#")
                else SAFE_HOST)
    return value
