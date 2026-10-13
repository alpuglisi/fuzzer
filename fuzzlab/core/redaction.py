"""Which field names hold secrets — one predicate for logs and persisted traffic
(BUG-0084, PA-0003, PA-0085).

Names are matched by **token**, not by substring. A name is split on ``_ - . [ ]``,
whitespace, camelCase and letter/digit boundaries, then lower-cased, and each token is
compared with the set. Substring matching redacted ``author`` (``auth``), ``sidebar``
(``sid``) and ``tokenizer``. A name that merely contains a sensitive word inside a
longer token is not redacted, so benign fields stay readable. A sensitive token anywhere
in the name redacts it, so ``session_count`` is redacted: harmless, and stated.

**The storage boundary (BUG-0099, BUG-0100, PA-0100, PA-0101).** Every producer of
persisted traffic — proxy history and the core HTTP client's recorder — redacts through
`redact_url` and `redact_body` here: one boundary, in `core` so `core` never imports the
proxy. It **fails closed**: a body it cannot prove clean is replaced by an omission
marker, never stored as received —

- larger than `MAX_REDACT_BYTES` (a redactable or sniffed type): omitted;
- JSON that does not parse (bad syntax, an integer past Python's digit limit, deeper
  than the parser) or nests deeper than `MAX_JSON_DEPTH`: kept only when a scan of
  **every** identifier-like token and quoted string finds no sensitive name, else
  omitted;
- a body with no or a non-redactable content type (``text/plain``, none) is **sniffed**
  (bounded): JSON if it parses to an object or array, form if it has the urlencoded
  shape — then redacted by the same rules.

**Plurals (BUG-0090).** A token ending in ``s`` is also compared with that ``s`` folded
off, but only when the folded form is itself sensitive: ``passwords``, ``secrets``,
``sessions``, ``jwts`` and ``apiKeys`` are secrets, while ``passes`` (→ ``passe``) and
``passage`` stay readable. ``keys`` follows ``key``'s rule (whole name, or qualified), so
``hotkeys`` and ``monkeys`` stay readable. Accepted harmless false redactions: the whole
names ``codes`` / ``pins``, and ``session_count``.
"""

from __future__ import annotations

import json
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

#: Whole tokens that mark a secret on their own.
SENSITIVE_TOKENS = frozenset({
    "password", "passwd", "pwd", "pw", "pass", "passcode", "passphrase", "secret",
    "token", "tokens", "jwt", "cookie", "cookies", "credential", "credentials",
    "session", "sessid", "sessionid", "sid", "apikey", "auth", "authorization",
    "otp", "csrf", "xsrf", "csrftoken", "xsrftoken", "accesstoken", "refreshtoken",
    "authtoken", "bearer", "signature", "sig", "pin",
})
#: ``key`` is a secret with one of these beside it (``api_key``, ``privateKey``), or alone.
_KEY_QUALIFIERS = frozenset({"api", "private", "secret", "access", "signing", "client",
                             "auth", "encryption", "master"})

_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
                    r"|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")


def name_tokens(name: str) -> list[str]:
    """``name`` split into lower-case tokens (see the module docstring)."""
    return [t.lower() for t in _SPLIT.split(name or "") if t]


def _fold(token: str) -> str:
    """``token`` with a trailing plural ``s`` removed, when that leaves a sensitive word."""
    if len(token) > 2 and token.endswith("s"):
        stem = token[:-1]
        if stem in SENSITIVE_TOKENS or stem in ("key", "code") \
                or stem.endswith(("sessid", "sessionid")):
            return stem
    return token


def is_sensitive_name(name: str) -> bool:
    """True when the field or parameter ``name`` holds a secret."""
    tokens = [_fold(t) for t in name_tokens(name)]
    if not tokens:
        return False
    if any(t in SENSITIVE_TOKENS or t.endswith(("sessid", "sessionid")) for t in tokens):
        return True                               # incl. PHPSESSID / JSESSIONID
    if "key" in tokens:
        return len(tokens) == 1 or any(t in _KEY_QUALIFIERS for t in tokens)
    return tokens == ["code"]                     # an OAuth code, only as the whole name


# --- the storage boundary (BUG-0099 / BUG-0100) ------------------------------------

PLACEHOLDER = "__REDACTED__"
MAX_REDACT_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64
OMIT_TOO_LARGE = b"__BODY_OMITTED__ (too large to redact)"
OMIT_UNSAFE = b"__BODY_OMITTED__ (unparseable body with a sensitive field)"
OMIT_FAILED = b"__BODY_OMITTED__ (redaction failed)"

_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.\-]*")
_DQ = re.compile(r'"(?:[^"\\]|\\.)*"')
_SQ = re.compile(r"'(?:[^'\\]|\\.)*'")
_FORM_SHAPE = re.compile(rb"^[^=&\s]+=[^&\s]*(?:&[^=&\s]+=[^&\s]*)*\s*$")


def redact_query(query: str) -> str:
    """``query`` with each sensitively named parameter's value replaced."""
    if not query:
        return query
    out = []
    for part in query.split("&"):
        name, eq, _value = part.partition("=")
        out.append(f"{name}={PLACEHOLDER}" if eq and is_sensitive_name(unquote_plus(name))
                   else part)
    return "&".join(out)


def redact_url(url: str) -> str:
    """``url`` (absolute or origin-form) with sensitive query values replaced."""
    if "?" not in (url or ""):
        return url
    parts = urlsplit(url)
    new = redact_query(parts.query)
    return url if new == parts.query else urlunsplit(parts._replace(query=new))


def _redact_json(value):
    # A sensitive key's whole value is the secret, whatever its shape (BUG-0090).
    # Only ever called on a tree already checked to be at most MAX_JSON_DEPTH deep.
    if isinstance(value, dict):
        return {k: (PLACEHOLDER if is_sensitive_name(str(k)) else _redact_json(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json(v) for v in value]
    return value


def _depth_ok(doc) -> bool:
    """Iteratively: ``doc`` nests at most `MAX_JSON_DEPTH` containers deep."""
    stack = [(doc, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > MAX_JSON_DEPTH:
                return False
            children = node.values() if isinstance(node, dict) else node
            stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
    return True


def mentions_sensitive_name(body: bytes) -> bool:
    """Whether **any** identifier-like word or quoted string in ``body`` is a sensitive
    name — the fail-closed scan for a body that cannot be parsed (A1/B-S1: unquoted,
    single-quoted, form-in-JSON and unterminated shapes all reach it)."""
    text = body.decode("utf-8", "replace")
    for m in _DQ.finditer(text):
        try:
            name = json.loads(m.group(0))
        except ValueError:
            return True                                 # undecodable key: assume it is
        if is_sensitive_name(name):
            return True
    if any(is_sensitive_name(m.group(0)[1:-1]) for m in _SQ.finditer(text)):
        return True
    return any(is_sensitive_name(m.group(0)) for m in _WORD.finditer(text))


def _unsafe(body: bytes) -> bytes:
    return OMIT_UNSAFE if mentions_sensitive_name(body) else body


def redact_json_body(body: bytes) -> bytes:
    """A JSON body with every sensitive key's value replaced — fail closed."""
    if len(body) > MAX_REDACT_BYTES:
        return OMIT_TOO_LARGE
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return _unsafe(body)
    if not _depth_ok(doc):
        return _unsafe(body)
    new = _redact_json(doc)
    if new == doc:
        return body                                     # byte-identical when clean
    return json.dumps(new, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def redact_form_body(body: bytes) -> bytes:
    if len(body) > MAX_REDACT_BYTES:
        return OMIT_TOO_LARGE
    text = body.decode("latin-1")
    new = redact_query(text)
    return body if new == text else new.encode("latin-1")


def redact_multipart_body(body: bytes, content_type: str) -> bytes:
    if len(body) > MAX_REDACT_BYTES:
        return OMIT_TOO_LARGE
    m = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not m:
        return _unsafe(body)
    delim = b"--" + m.group(1).encode("latin-1")
    parts = body.split(delim)
    for i, part in enumerate(parts):
        head, sep, data = part.partition(b"\r\n\r\n")
        name = re.search(rb'\bname="([^"]*)"', head)
        if sep and name and b"filename=" not in head \
                and is_sensitive_name(name.group(1).decode("latin-1")):
            parts[i] = head + sep + PLACEHOLDER.encode() + \
                (b"\r\n" if data.endswith(b"\r\n") else b"")
    return delim.join(parts)


def body_kind(body: bytes, content_type: str) -> str | None:
    """``json`` / ``form`` / ``multipart`` from the declared type, else sniffed (bounded:
    the first bytes and the urlencoded shape), else ``None``."""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct == "application/x-www-form-urlencoded":
        return "form"
    if ct == "application/json" or ct.endswith("+json"):
        return "json"
    if ct.startswith("multipart/form-data"):
        return "multipart"
    head = body[:1024].lstrip()
    if head[:1] in (b"{", b"["):
        return "json?"                                  # JSON only if it parses
    if len(body) <= MAX_REDACT_BYTES and _FORM_SHAPE.match(body):
        return "form"
    return None


def redact_body(body: bytes, content_type: str) -> bytes:
    """``body`` with sensitively named fields replaced, per its content type (or what
    it sniffs as) — the one storage boundary (BUG-0099/0100), fail closed."""
    if not body:
        return body
    kind = body_kind(body, content_type)
    if kind == "form":
        return redact_form_body(body)
    if kind == "json":
        return redact_json_body(body)
    if kind == "multipart":
        return redact_multipart_body(body, content_type or "")
    if kind == "json?":                                 # sniffed: redact if it parses
        if len(body) > MAX_REDACT_BYTES:
            return OMIT_TOO_LARGE
        try:
            doc = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return body                                 # not JSON after all
        if not isinstance(doc, (dict, list)):
            return body
        return redact_json_body(body)
    return body
