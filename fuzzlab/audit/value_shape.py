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


def neutral_value(value):
    """``value``, or loopback in its place when it is ip-, host- or url-shaped: what the
    fuzzer sends instead of a default the app supplied (FR-AUD-20). A caller exempts
    its own fillers first (``store_adapter.is_filler``: they never resolve at all)."""
    shape = value_shape(value)
    if shape in ("ip", "hostname"):
        return SAFE_HOST
    if shape == "url":
        return SAFE_URL
    return value
