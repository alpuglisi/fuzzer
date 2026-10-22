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
import math
import re
from urllib.parse import quote, unquote, unquote_plus

#: Whole tokens that mark a secret on their own.
SENSITIVE_TOKENS = frozenset({
    "password", "passwd", "pwd", "pw", "pass", "passcode", "passphrase", "secret",
    "token", "tokens", "jwt", "cookie", "cookies", "credential", "credentials",
    "session", "sessid", "sessionid", "sid", "apikey", "auth", "authorization",
    "otp", "csrf", "xsrf", "csrftoken", "xsrftoken", "accesstoken", "refreshtoken",
    "authtoken", "bearer", "signature", "sig", "pin",
    # anti-CSRF names that tokenise as one word (forms phase 1, reviewer B-M5)
    "nonce", "wpnonce", "csrfmiddlewaretoken",
    # a payment card's security code (forms phase 4, FR-CRAWL-15 G1b): never filled,
    # stored or fuzzed
    "cvv", "cvc", "cvn", "csc",
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


#: A crawl- or form-sourced parameter, or a link's query, with one of these name tokens
#: carries a credential: never fuzzed, and a link set holding one is never bound (it
#: could change or re-bind the operator's identity). Moved here from `harness.auto`
#: (forms phase 2, CC-CORE-0042) so the importer and the point builder share it.
CREDENTIAL_TOKENS = frozenset({"password", "passwd", "pwd", "pass", "secret"})


def is_credential_name(name: str) -> bool:
    """True when the parameter ``name`` has a credential token (``password_new``)."""
    return bool(set(name_tokens(name)) & CREDENTIAL_TOKENS)


#: Adjacent tokens that together name a secret (``securityAnswer``,
#: ``recovery_answers``): an account-recovery answer is a credential (forms phase 3,
#: lane S review). ``answer`` alone is deliberately not one: it names ordinary quiz and
#: survey fields.
SENSITIVE_PAIRS = frozenset({("security", "answer"), ("secret", "answer"),
                             ("recovery", "answer")})


def is_sensitive_name(name: str) -> bool:
    """True when the field or parameter ``name`` holds a secret."""
    tokens = [_fold(t) for t in name_tokens(name)]
    if not tokens:
        return False
    if any(t in SENSITIVE_TOKENS or t.endswith(("sessid", "sessionid")) for t in tokens):
        return True                               # incl. PHPSESSID / JSESSIONID
    for first, second in zip(tokens, tokens[1:]):  # whole adjacent tokens, plural folded
        if (first, second[:-1] if second.endswith("s") else second) in SENSITIVE_PAIRS:
            return True
    if "key" in tokens:
        return len(tokens) == 1 or any(t in _KEY_QUALIFIERS for t in tokens)
    return tokens == ["code"]                     # an OAuth code, only as the whole name


# --- identifier-like values (forms phase 2; reviewers A/B, PA-0003) ----------------

#: Pieces of a value are separated by these (hosts, schemes, e-mail, JWT dots, words).
_PIECE_SPLIT = re.compile(r"[.:@\s]")
#: ... and of a URL or absolute path, by ``/`` too. Elsewhere ``/`` stays in the
#: alphabet: standard base64 uses it (reviewer B).
_URL_PIECE_SPLIT = re.compile(r"[.:@/\s]")
_ID_ALPHABET = re.compile(r"[A-Za-z0-9_\-+/=]+")
#: A piece this long from the identifier alphabet is identifier-like (rule R1).
ID_MIN_LEN = 16
#: A shorter piece needs this length and Shannon estimate (rule R2).
ID_SHORT_MIN_LEN = 8
ID_SHORT_MIN_BITS = 32.0
#: One ``_``/``-``/``/``/``+`` part of a word-shaped piece: a word (lower, Capitalised,
#: ALLCAPS or CamelCase) with at most four trailing digits, or one to four digits
#: alone. Written without nested quantifiers over the same characters, so matching is
#: linear (PA-0095; ``(?:[A-Z]?[a-z]+)+`` backtracked exponentially, reviewer B).
_WORD_PART = re.compile(r"(?:[A-Z]+|[a-z]*(?:[A-Z][a-z]+)*)[0-9]{0,4}|[0-9]{1,4}")
#: A date or date-and-hour piece (``2026-10-14T10`` once a timestamp is split on ``:``).
_DATE_PIECE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2})?")


def _shannon_bits(piece: str) -> float:
    """Per-character Shannon entropy of ``piece`` times its length."""
    n = len(piece)
    counts: dict[str, int] = {}
    for ch in piece:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values()) * n


def _word_shaped(piece: str) -> bool:
    """Names such as ``directory_traversal_1``, ``owasp_top10_2017_a1``,
    ``ProductDetailsPage`` and the raw query text ``hello+world+2024``: every
    ``_``/``-``/``/``/``+`` part is a word or a short number."""
    parts = [x for x in re.split(r"[_\-/+]", piece) if x]
    return bool(parts) and all(_WORD_PART.fullmatch(x) for x in parts)


def _identifier_piece(piece: str) -> bool:
    if len(piece) < ID_SHORT_MIN_LEN or not _ID_ALPHABET.fullmatch(piece):
        return False
    if _word_shaped(piece) or _DATE_PIECE.fullmatch(piece):
        return False
    digit = any(ch.isdigit() for ch in piece)
    if len(piece) >= ID_MIN_LEN:                  # R1: hex, UUID, base64(url), JWT part
        return digit or (any(ch.islower() for ch in piece)
                         and any(ch.isupper() for ch in piece))
    letter = any(ch.isalpha() for ch in piece)    # R2: a short random token
    return digit and letter and _shannon_bits(piece) >= ID_SHORT_MIN_BITS


def looks_like_identifier(value) -> bool:
    """True when ``value`` looks like a secret identifier: a session id, a one-time or
    capability token, an API key — whatever its parameter is called.

    The value is split on ``. : @`` and whitespace, and also on ``/`` when it is a URL
    or an absolute path (it contains ``://`` or starts with ``/``); elsewhere ``/``
    belongs to standard base64. It is identifier-like when any piece, drawn only from
    ``[A-Za-z0-9_-+/=]``, is

    * **R1** at least 16 characters with a digit, or with both upper and lower case
      (hex ids, UUIDs, base64/base64url secrets, JWT segments); or
    * **R2** 8–15 characters with a letter and a digit and a Shannon estimate of at
      least 32 bits (a short random token).

    and the piece is not **word-shaped** (every ``_``/``-``/``/``/``+`` part a word —
    lower, Capitalised, ALLCAPS or CamelCase — with at most four trailing digits, or
    one to four digits) nor a date (``2026-10-14`` / ``2026-10-14T10``).

    Ordinary words (raw ``hello+world+2024`` too), names such as
    ``directory_traversal_1``, host names, file names, paths, e-mail addresses,
    timestamps and the importer's fillers are not. Accepted misses: a short or
    low-entropy token; an all-one-case base64 token with no digit; a random token that
    happens to be word-shaped (about 0.3% of random 8–32 character hex, base32 and
    base64 tokens; 0.6% of 16-character standard base64). Accepted false positive
    (fails closed): a long alphanumeric code that is not word-shaped. Total: a
    non-string is False, and it never raises; linear in the value's length.

    Callers pass the **raw** value: percent-decoded, not form-decoded. Form decoding
    turns base64's ``+`` into a space, which splits the token into short pieces.
    """
    try:
        if not isinstance(value, str):
            return False
        url = value.startswith("/") or "://" in value
        split = _URL_PIECE_SPLIT if url else _PIECE_SPLIT
        return any(_identifier_piece(p) for p in split.split(value))
    except Exception:                             # total (PA-0096): never raises
        return False


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
    """``url`` (absolute or origin-form) with every sensitively named value replaced by
    `PLACEHOLDER`, wherever it sits (FR-CORE-537, BUG-0556): a query pair (``&`` or
    ``;`` separated), a ``;name=value`` path parameter, a query-shaped fragment, and a
    URL, query string or ``;`` pair nested in any of those values (raw or
    percent-encoded, walked by `_UrlWalk`). Byte-identical when it holds none; a value
    past the walk's bounds is replaced whole. Total: a non-string is returned as is."""
    return _walk_url(url, identifiers=False)


# --- URL values, at any depth (BUG-0556, FR-CORE-537) --------------------------------

#: A value is walked at most this many levels deep: a nested URL, a query string, a
#: ``;`` pair list and a percent-encoding layer are a level each ...
MAX_VALUE_DEPTH = 12
#: ... and at most this many characters long. A value past either bound, or one with a
#: percent-encoding layer still undecoded at the last level, is redacted whole: it
#: cannot be proven clean (fail closed, PA-0101).
MAX_VALUE_CHARS = 64 * 1024
#: The pair separators of a query, a fragment's query and a nested value (``;`` too:
#: servlet containers and many frameworks split on it, BUG-0556).
_PAIR_SEP = re.compile(r"([&;])")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


class _Whole(Exception):
    """A value the walk cannot prove clean: its top-level pair redacts it whole."""


class _UrlWalk:
    """One pass over a URL or one of its values (BUG-0556). The rule, at every level:

    - a pair or path parameter whose name `is_sensitive_name` flags: its value is
      `PLACEHOLDER`;
    - with ``identifiers``, a value that `looks_like_identifier` (judged percent-decoded
      once, the callers' contract): ``""`` at the top level (a URL's own query or
      fragment pair, as before), `PLACEHOLDER` when nested inside another value;
    - a value with structure of its own is walked: a nested URL (``://``, a leading
      ``/``, a ``?`` or a ``#``: its path parameters, query and fragment; with
      ``identifiers``, a token in its host or path redacts the whole outer value) or a
      query string (``=``, ``&`` or ``;``: its pairs);
    - a value with neither is percent-decoded one layer and walked again; when that
      changes it, the result is percent-encoded again (``safe=""``), so the URL stays a
      URL and the value stays one value;
    - a value past `MAX_VALUE_DEPTH` levels or `MAX_VALUE_CHARS` characters (a layer
      left undecoded included), or one the walk fails on, raises `_Whole`: its
      top-level pair or path parameter is redacted whole, never kept raw.

    Unchanged text is returned byte-identical: only a value that held a secret is
    re-encoded. Linear in the value's length per level (PA-0095)."""

    def __init__(self, identifiers: bool):
        self.identifiers = identifiers

    def url(self, url: str) -> str:
        base, hashmark, frag = url.partition("#")
        head, qmark, query = base.partition("?")
        head = self.path(head, 1)
        if qmark:
            query = self.pairs(query, 1, top=True)
        if hashmark:
            frag = self.fragment(frag, 1, top=True)
        return head + qmark + query + hashmark + frag

    def path(self, head: str, depth: int) -> str:
        """``head``'s ``;`` path parameters walked (the authority is left alone)."""
        if ";" not in head:
            return head
        start = 0
        if "://" in head:
            start = head.find("/", head.index("://") + 3)
            if start < 0:
                return head
        out = []
        for seg in head[start:].split("/"):
            if ";" in seg:
                first, *params = seg.split(";")
                seg = ";".join([first] + [self.param(p, depth) for p in params])
            out.append(seg)
        return head[:start] + "/".join(out)

    def param(self, part: str, depth: int) -> str:
        """One path parameter (``name=value`` or bare): its own top level."""
        name, eq, raw = part.partition("=")
        if eq and is_sensitive_name(unquote_plus(name)):
            return f"{name}={PLACEHOLDER}"
        text = raw if eq else part
        try:
            new = self.value(text, depth + 1, top=False)
        except Exception:                         # _Whole, or a failure: fail closed
            new = PLACEHOLDER
        if new == text:
            return part
        return f"{name}={new}" if eq else new

    def pairs(self, text: str, depth: int, top: bool) -> str:
        parts = _PAIR_SEP.split(text)
        for i in range(0, len(parts), 2):
            parts[i] = self.pair(parts[i], depth, top)
        return "".join(parts)

    def pair(self, part: str, depth: int, top: bool) -> str:
        if not part:
            return part
        name, eq, raw = part.partition("=")
        if eq and is_sensitive_name(unquote_plus(name)):
            return f"{name}={PLACEHOLDER}"
        text = raw if eq else part
        try:
            new = self.value(text, depth + 1, top)
        except Exception:
            if not top:
                raise                               # the top-level pair redacts it whole
            new = "" if self.identifiers else PLACEHOLDER
        if new == text:
            return part
        return f"{name}={new}" if eq else new

    def fragment(self, frag: str, depth: int, top: bool) -> str:
        if "?" in frag:                             # a route's query (``#/x?token=…``)
            route, q, query = frag.partition("?")
            return route + q + self.pairs(query, depth, top)
        if "=" in frag:                             # ``#access_token=…&state=…``
            return self.pairs(frag, depth, top)
        if top:
            return frag                             # ``#top``, ``#/item/7``: no value
        return self.value(frag, depth + 1, top=False)

    def value(self, text: str, depth: int, top: bool) -> str:
        if depth > MAX_VALUE_DEPTH or len(text) > MAX_VALUE_CHARS:
            raise _Whole
        if self.identifiers and looks_like_identifier(unquote(text)):
            return "" if top else PLACEHOLDER
        if "://" in text or text.startswith("/") or "?" in text or "#" in text:
            return self.nested_url(text, depth)
        if "=" in text or "&" in text or ";" in text:
            return self.pairs(text, depth, top=False)
        if _PCT.search(text):
            inner = unquote(text, errors="surrogateescape")
            new = self.value(inner, depth + 1, top=False)
            if new == inner:
                return text
            return quote(new, safe="", errors="surrogateescape")
        return text

    def nested_url(self, text: str, depth: int) -> str:
        base, hashmark, frag = text.partition("#")
        head, qmark, query = base.partition("?")
        if self.identifiers and looks_like_identifier(
                unquote("/".join(seg.split(";", 1)[0] for seg in head.split("/")))):
            raise _Whole                            # a token in its host or path
        head = self.path(head, depth)
        if qmark:
            query = self.pairs(query, depth, top=False)
        if hashmark:
            frag = self.fragment(frag, depth, top=False)
        return head + qmark + query + hashmark + frag


def _walk_url(url, identifiers: bool):
    """`_UrlWalk` over a whole URL; total. A URL with no ``?``, ``;`` or ``#`` holds no
    value and is returned as it is."""
    if not isinstance(url, str) or not any(c in url for c in "?;#"):
        return url
    try:
        return _UrlWalk(identifiers).url(url)
    except Exception:                               # unreachable by construction; closed
        return re.split(r"[;?#]", url, maxsplit=1)[0] + "?" + PLACEHOLDER


def value_holds_secret(raw_value) -> bool:
    """True when ``raw_value`` -- one query, fragment or path value, percent-decoded once
    (the contract `looks_like_identifier` states) -- holds a secret anywhere: it looks
    like an identifier, or a URL, query string or ``;`` pair nested in it (raw or
    percent-encoded, at any depth) has a sensitively named or identifier-like value, or
    it is past the walk's bounds (`_UrlWalk`; BUG-0556). Total: a non-string is False."""
    if not isinstance(raw_value, str):
        return False
    try:
        return (looks_like_identifier(raw_value)
                or _UrlWalk(True).value(raw_value, 1, top=True) != raw_value)
    except Exception:                               # _Whole: it cannot be proven clean
        return True


def stored_value(name, raw_value, value):
    """A crawled query, fragment or path value as it may be stored -- a link set's entry
    (`tools.store_adapter.redact_sibling`) or a parameter's example: ``""`` when
    ``name`` `is_sensitive_name` or ``raw_value`` (percent-decoded once) holds a secret
    anywhere (`value_holds_secret`), else ``value`` as given. The one rule for every
    stored sibling value and example (PA-0003, PA-0100; BUG-0556)."""
    if (isinstance(name, str) and is_sensitive_name(name)) or value_holds_secret(raw_value):
        return ""
    return value


def strip_secret_path_params(path):
    """``path`` without each ``;name=value`` (or bare ``;value``) path parameter that
    holds a secret -- a sensitive name, or a value `value_holds_secret` holds for -- in
    any segment: how a stored page or endpoint path keeps no session id
    (``/a;jsessionid=…/b`` -> ``/a/b``; `core.urls.to_path` already drops the last
    segment's parameters). A parameter that holds none is kept. Total (BUG-0556)."""
    if not isinstance(path, str) or ";" not in path:
        return path
    from urllib.parse import unquote as _unquote

    def secret(part: str) -> bool:
        name, eq, raw = part.partition("=")
        if eq and is_sensitive_name(unquote_plus(name)):
            return True
        return value_holds_secret(_unquote(raw if eq else part))
    out = []
    for seg in path.split("/"):
        if ";" in seg:
            first, *params = seg.split(";")
            seg = ";".join([first] + [p for p in params if not secret(p)])
        out.append(seg)
    return "/".join(out)


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


# --- the crawler's captured requests (forms phase 3, FR-CRAWL-13, CC-CORE-0047) ------

#: A captured request body larger than this is not recorded.
CAPTURE_MAX_BYTES = 64 * 1024
#: ... nor one whose JSON nests deeper than this many containers.
CAPTURE_MAX_DEPTH = 8


def redact_spa_fragment(url: str) -> str:
    """``url`` with the query of a SPA-route fragment (``#/reset?token=...``,
    ``#!/x?id=...``) redacted like a URL query (`_UrlWalk`): sensitive names replaced,
    identifier-like values blanked, nested URLs and ``;`` pairs walked. A fragment that
    is not a route (``#top``) is left alone. The crawler keeps such fragments as pages
    (FR-CRAWL-12), so they pass this boundary."""
    head, sep, frag = (url or "").partition("#")
    from fuzzlab.core.urls import is_spa_route_fragment    # the one definition (PA-0003)
    if not sep or not is_spa_route_fragment(frag) or "?" not in frag:
        return url
    route, _q, query = frag.partition("?")
    new = _UrlWalk(True).pairs(query, 1, top=True)
    return url if new == query else f"{head}#{route}?{new}"


def page_url_is_clean(url: str) -> bool:
    """Whether a page URL may be stored and fetched as it is (FR-FUZZ-67, BUG-0544): the
    strongest URL redactor (`redact_url_identifiers`, which walks nested URLs, query
    strings and ``;`` pairs and path parameters, BUG-0556) leaves it unchanged, it
    carries no redaction placeholder at any depth (a crawl's ``found_from`` was redacted
    once already, and a placeholder survives a second pass; a nested one is redacted as
    `PLACEHOLDER`, never as a blank), and no query value (``&`` or ``;`` separated) is
    empty (a value blanked upstream looks exactly like that). Fails closed: any doubt
    keeps the page out."""
    if not isinstance(url, str) or redact_url_identifiers(url) != url:
        return False
    if PLACEHOLDER in url or "__REDACTED_KEY_" in url or USERINFO_PLACEHOLDER in url:
        return False
    head = url.split("#", 1)[0]
    query = head.split("?", 1)[1] if "?" in head else ""
    return not any(part.endswith("=") for part in _PAIR_SEP.split(query)[::2])


def redact_url_identifiers(url: str) -> str:
    """The strongest URL redactor (`_UrlWalk` with identifiers; FR-CORE-537): every
    sensitively named value replaced (`redact_url`'s rule) and every identifier-like
    value redacted, wherever it sits -- a query pair (``&`` or ``;``), a path parameter,
    a query-shaped or SPA-route fragment, and a URL, query string or ``;`` pair nested
    in any of those, raw or percent-encoded at any depth. A URL's own query or fragment
    value that is identifier-like (or past the walk's bounds) is blanked to ``name=``; a
    nested one, and a path parameter's, becomes `PLACEHOLDER`, re-encoded so the URL
    stays a URL. How the crawler stores an XHR URL and a captured request's URLs
    (FR-CRAWL-12/13) and what `page_url_is_clean` compares against. Total; a URL holding
    no secret is returned byte-identical."""
    return _walk_url(url, identifiers=True)


def _blank(value):
    """A blanked value keeps its declared type: ``""`` for a string, ``null`` for a
    number or a boolean, an empty container for a container (its whole subtree goes,
    PA-0091(2))."""
    if isinstance(value, str):
        return ""
    if isinstance(value, dict):
        return {}
    if isinstance(value, list):
        return []
    return None


#: An identifier-like key (a card number, a session id used as a map key) is replaced by
#: this, numbered per body, and its value blanked (lane S review, reviewer B must-fix 1).
REDACTED_KEY = "__REDACTED_KEY_{n}__"


class _KeyNamer:
    """Replaces identifier-like keys of one body; the same key gets the same name."""

    def __init__(self):
        self.names: dict[str, str] = {}

    def __call__(self, key: str) -> str | None:
        """The placeholder for ``key`` when it looks like an identifier, else None."""
        if not looks_like_identifier(key):
            return None
        if key not in self.names:
            self.names[key] = REDACTED_KEY.format(n=len(self.names))
        return self.names[key]


def _identifier_number(value) -> bool:
    """A JSON number whose digits look like an identifier (a card number, a 19-digit
    id): judged as its text, so a body's encoding never decides (reviewer B)."""
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and looks_like_identifier(str(value)))


def is_identifier_value(value) -> bool:
    """A leaf value that looks like an identifier: a string by `looks_like_identifier`,
    a non-bool number by its text (`_identifier_number`). The one value rule for stored
    request leaves (forms phase 3 merge, reviewer A J1, PA-0003)."""
    if isinstance(value, str):
        return looks_like_identifier(value)
    return _identifier_number(value)


def redact_leaf(segments, value):
    """A request body leaf as it may be stored and replayed: blanked by type (`_blank`)
    when any key segment of its path is sensitive or its value `is_identifier_value`,
    else ``value``. The one leaf rule: the crawler's capture (`_blank_tree`) and the
    importer's JSON producer (`store_adapter`) both use it (PA-0003)."""
    if any(isinstance(s, str) and is_sensitive_name(s) for s in segments) \
            or is_identifier_value(value):
        return _blank(value)
    return value


def _blank_tree(value, namer: _KeyNamer):
    """``value`` with every sensitively named key's value, every identifier-like string
    or number blanked, and every identifier-like key replaced (its value blanked)
    (called on a tree at most `CAPTURE_MAX_DEPTH` deep)."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = str(k)
            placeholder = namer(key)
            if placeholder is not None:
                out[placeholder] = _blank(v)
            elif is_sensitive_name(key):
                out[k] = _blank(v)
            else:
                out[k] = _blank_tree(v, namer)
        return out
    if isinstance(value, list):
        return [_blank_tree(v, namer) for v in value]
    return redact_leaf((), value)               # the one leaf rule (sensitive keys above)


def _container_depth_ok(doc, limit: int) -> bool:
    stack = [(doc, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > limit:
                return False
            children = node.values() if isinstance(node, dict) else node
            stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
    return True


def _reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name}")


def redact_captured_body(body: bytes, content_type: str):
    """A request body the crawler captured, as the JSON value it may store, or why not:
    ``(value, None)`` or ``(None, reason)`` (FR-CRAWL-13, the one boundary for it).

    Only a JSON object or array, or a form-encoded body (an object of name -> value,
    the last value of a repeated name winning), is recorded, at most
    `CAPTURE_MAX_BYTES` and `CAPTURE_MAX_DEPTH` deep. It first passes `redact_body` (the
    storage boundary, fail closed): a body that boundary would omit is not recorded.
    Then every sensitively named key's value (`is_sensitive_name`; passwords, tokens,
    sessions) is blanked whatever its shape, and every identifier-like value is blanked
    -- a string (a form value judged on its raw, percent-decoded form) or a number
    judged as its text, so ``4716190207394368`` is blanked as a JSON number exactly as
    it is in a form: a string becomes ``""``, a number or boolean ``null``, a container
    empty. An identifier-like **key** (or form name) is replaced by `REDACTED_KEY`
    (numbered per body) and its value blanked. The result never depends on whether the
    body was JSON or form-encoded (lane S review). Total: it never raises."""
    from urllib.parse import unquote
    try:
        if not body:
            return None, "empty body"
        if len(body) > CAPTURE_MAX_BYTES:
            return None, "body too large"
        kind = body_kind(body, content_type)
        if kind not in ("json", "json?", "form"):
            return None, "not a JSON or form-encoded body"
        if redact_body(body, content_type).startswith(b"__BODY_OMITTED__"):
            return None, "body the storage boundary omits"
        namer = _KeyNamer()
        if kind == "form":
            doc = {}
            for part in body.decode("latin-1").split("&"):
                if not part:
                    continue
                name, _eq, raw = part.partition("=")
                key = unquote_plus(name)
                placeholder = namer(unquote(name))
                if placeholder is not None:
                    doc[placeholder] = ""
                elif is_sensitive_name(key) or looks_like_identifier(unquote(raw)):
                    doc[key] = ""
                else:
                    doc[key] = unquote_plus(raw)
            return (doc, None) if doc else (None, "empty body")
        try:
            doc = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None, "unparseable JSON"
        if not isinstance(doc, (dict, list)):
            return None, "a JSON body that is not an object or array"
        if not _container_depth_ok(doc, CAPTURE_MAX_DEPTH):
            return None, "body nested too deep"
        return _blank_tree(doc, namer), None
    except Exception:                       # total (PA-0096): never raises, never stores
        return None, "redaction failed"


# --- the project-record boundary (CC-CORE-0450, FR-UI-456, NFR-UI-project-provenance-redacted)

#: ``scheme://user[:password]@`` or ``//user[:password]@`` — URL userinfo, anywhere in a
#: value, up to the **last** ``@`` of the authority (a password may contain ``@``; URL
#: parsers split at the last one; code review B).
_URL_USERINFO = re.compile(r"(?i)((?:(?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]*:)?//)[^/?#\s]*@")
#: A scheme-less ``user:password@host`` at the start of a value or of a whitespace-
#: separated piece, also up to the authority's last ``@``.
_BARE_USERINFO = re.compile(r"(^|\s)[^\s/@:?#]+:[^\s/?#]*@(?=[^\s@/])")
#: A ``;name=value`` path (matrix) parameter, e.g. ``;jsessionid=…``.
_MATRIX_PARAM = re.compile(r";([^;=/?#\s]+)=([^;/?#\s]*)")
#: What a stripped userinfo becomes.
USERINFO_PLACEHOLDER = "***@"
#: The longest value `redact_for_record` keeps (cut after userinfo is stripped).
MAX_RECORD_CHARS = 4096


def redact_for_record(dest: str, value):
    """The one writer-side redactor for what the web UI records about a job or a project
    (``launch.argv``, ``launch.target``, ``project.targets``; PA-0100: one boundary).

    - a value whose option name (``dest``) `is_sensitive_name` flags → `PLACEHOLDER`;
    - URL userinfo (``http://user:pw@``, ``//user:pw@``) and a scheme-less ``user:pw@``
      → ``***@`` (through the authority's last ``@``);
    - in each whitespace-separated piece, sensitive values of the query, of a query-shaped
      fragment (``#access_token=…``, ``#/route?token=…``) and of ``;name=value`` path
      parameters → `PLACEHOLDER`.

    Non-strings are returned unchanged (counts, booleans). Never raises on a string."""
    if not isinstance(value, str):
        return value
    if dest and is_sensitive_name(dest):
        return PLACEHOLDER
    # Userinfo is stripped from the **whole** value before it is cut (BUG-0455: a cut
    # between a password and its ``@`` left the password unmatched); both patterns are
    # linear. The cut then bounds the per-piece work and the stored size (PA-0095/0096).
    out = _URL_USERINFO.sub(lambda m: m.group(1) + USERINFO_PLACEHOLDER, value)
    out = _BARE_USERINFO.sub(lambda m: m.group(1) + USERINFO_PLACEHOLDER, out)
    if len(out) > MAX_RECORD_CHARS:
        out = out[:MAX_RECORD_CHARS] + " …(truncated)"
    pieces = re.split(r"(\s+)", out)
    return "".join(_redact_piece(p) for p in pieces)


def _redact_piece(piece: str) -> str:
    piece = _MATRIX_PARAM.sub(
        lambda m: f";{m.group(1)}={PLACEHOLDER}" if is_sensitive_name(m.group(1))
        else m.group(0), piece)
    base, hashmark, fragment = piece.partition("#")
    if "?" in base:
        try:
            base = redact_url(base)
        except ValueError:                   # an unparseable authority (e.g. a bad IPv6)
            base = base.split("?", 1)[0] + "?" + redact_query(base.split("?", 1)[1])
    if hashmark:
        route, q, query = fragment.partition("?")
        if q:
            fragment = route + "?" + redact_query(query)
        elif "=" in fragment:
            fragment = redact_query(fragment)
    return base + hashmark + fragment
