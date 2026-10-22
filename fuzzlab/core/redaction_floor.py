"""The redaction floor: the pushed tree's own redactors, frozen at 7393c90 (BUG-0556 r6).

FROZEN AT 7393c90 -- NEVER EDITED. Every definition below is copied verbatim from the
pushed tree (``git show 7393c90:<file>``, the file named above each section). The only
change: a function-local import of a live module names this module instead, so the
frozen code never calls a live (layered) redactor. `tests/test_redaction_floor.py` pins
each definition's text to 7393c90's (a SHA-256 taken from ``git show`` when the guard was
written) and this module's statements to exactly this list, so an edit here fails it. A
redactor is fixed in its live owner, layered on this floor (PA-0556 item 11), never here.

The owner's design for BUG-0556 (audit gap 5, "layer on the pushed redactor"): every URL
redaction consumer first runs its floor here -- the pushed tree's own redaction of what
that consumer redacts -- and then the batch's walk (`core.redaction._UrlWalk`) on the
floor's output only. So nothing the pushed tree redacted reaches the walk, and the walk
can only remove more. Where a floor raises (``urlsplit`` rejecting a URL: ``http://[h/…``,
a bracketed host it does not accept, a netloc that NFKC-normalises to a delimiter), the
consumer raises as the pushed tree did and its caller withholds the value as it did then
(the proxy history writer's ``_prepare_contained``; `core.trace.safe_ref`'s
``(unparseable URL withheld)``). The consumers and their floors (`core.redaction.LAYERED`):

- `core.redaction.redact_url` -> `redact_url`; `redact_url_identifiers` ->
  `redact_url_identifiers` (with ``placeholder``: `redact_url`, which never blanks a
  value); `redact_spa_fragment` -> `redact_spa_fragment`; `page_url_is_clean` ->
  `page_url_is_clean`; `redact_for_record` -> `redact_for_record`; `stored_value` ->
  `redact_sibling` (7393c90's rule for a stored sibling value, from
  ``tools/store_adapter.py``);
- `core.trace.safe_ref` -> `safe_ref`;
- `proxy.redact.redact` -> `redact`: the request line and ``Location``,
  ``Content-Location`` and ``Refresh`` (a duplicate collapsed as 7393c90's
  ``RawMessage.with_header`` collapsed it), the sensitive headers and the bodies.

The proxy's message container and the body boundary are frozen with them (7393c90's
``proxy/message.py`` and the body functions of ``core/redaction.py``): the floor imports
nothing from ``fuzzlab`` at module level, so ``core`` still never imports the proxy, and
nothing the floor runs changes when a live module does.
"""

from __future__ import annotations

import json
import math
import re
import zlib
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import unquote_plus, urlsplit, urlunsplit


# --- fuzzlab/core/redaction.py at 7393c90 (verbatim) ----------------------------------

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


def _redact_query_identifiers(query: str) -> str:
    """`redact_query`, then each value that `looks_like_identifier` (judged on its raw,
    percent-decoded form) blanked to ``name=``."""
    from urllib.parse import unquote
    out = []
    for part in redact_query(query).split("&"):
        name, eq, raw = part.partition("=")
        out.append(f"{name}=" if eq and looks_like_identifier(unquote(raw)) else part)
    return "&".join(out)


def redact_spa_fragment(url: str) -> str:
    """``url`` with the query of a SPA-route fragment (``#/reset?token=...``,
    ``#!/x?id=...``) redacted like a URL query: sensitive names replaced, identifier-like
    values blanked. A fragment that is not a route (``#top``) is left alone. The crawler
    keeps such fragments as pages (FR-CRAWL-12), so they pass this boundary."""
    head, sep, frag = (url or "").partition("#")
    from fuzzlab.core.redaction_floor import is_spa_route_fragment    # the one definition (PA-0003)
    if not sep or not is_spa_route_fragment(frag) or "?" not in frag:
        return url
    route, _q, query = frag.partition("?")
    new = _redact_query_identifiers(query)
    return url if new == query else f"{head}#{route}?{new}"


def page_url_is_clean(url: str) -> bool:
    """Whether a page URL may be stored and fetched as it is (FR-FUZZ-67, BUG-0544): the
    strongest URL redactor (`redact_url_identifiers`) leaves it unchanged, it carries no
    redaction placeholder (a crawl's ``found_from`` was redacted once already, and a
    placeholder survives a second pass), and no query value is empty (a value blanked
    upstream looks exactly like that). Fails closed: any doubt keeps the page out."""
    if not isinstance(url, str) or redact_url_identifiers(url) != url:
        return False
    if PLACEHOLDER in url or "__REDACTED_KEY_" in url or USERINFO_PLACEHOLDER in url:
        return False
    head = url.split("#", 1)[0]
    query = head.split("?", 1)[1] if "?" in head else ""
    return not any(part.endswith("=") for part in query.split("&"))


def redact_url_identifiers(url: str) -> str:
    """`redact_url`, then each query value that `looks_like_identifier` (given its raw,
    percent-decoded value) blanked to ``name=``, and a SPA-route fragment's query
    redacted the same way (`redact_spa_fragment`): how the crawler stores an XHR URL and
    a captured request's URLs (FR-CRAWL-12/13). Total; a URL with neither is returned
    unchanged."""
    url = redact_spa_fragment(redact_url(url))
    if "?" not in (url or "").split("#", 1)[0]:
        return url
    parts = urlsplit(url)
    new = _redact_query_identifiers(parts.query)
    return url if new == parts.query else urlunsplit(parts._replace(query=new))


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


# --- fuzzlab/core/urls.py at 7393c90 (verbatim) ---------------------------------------

#: A URL fragment starting with one of these names a single-page app's route (``#/x``,
#: hashbang ``#!/x``): the one definition (forms phase 3 merge, PA-0003).
SPA_ROUTE_PREFIXES = ("/", "!/")


def is_spa_route_fragment(fragment: str | None) -> bool:
    """Is ``fragment`` (without its ``#``) a single-page app's route?"""
    return bool(fragment) and fragment.startswith(SPA_ROUTE_PREFIXES)


# --- fuzzlab/core/trace.py at 7393c90 (verbatim) --------------------------------------

#: An identifier-like path segment `safe_ref` withheld; grouped as ``{id}``.
REDACTED_SEGMENT = "{redacted}"
#: A run of identifier characters inside a path segment (`safe_ref`, BUG-0521).
_TOKEN_RUN = re.compile(r"[A-Za-z0-9_\-+=]{8,}")


def safe_ref(url: str) -> str:
    """A URL fit for a diagram or an export (BUG-0514):

    - sensitive and identifier-like query values blanked, a SPA route's query too
      (`core.redaction.redact_url_identifiers`);
    - userinfo, sensitive ``;name=value`` path parameters and a query-shaped fragment's
      sensitive values (``#access_token=…``) replaced, by the record boundary
      (`core.redaction.redact_for_record`, PA-0003: one implementation);
    - every other ``;name=value`` and fragment value that looks like an identifier
      blanked;
    - an identifier-like path segment (a JWT, a reset token, a UUID) replaced by
      `REDACTED_SEGMENT`, which an interface groups as ``{id}``.

    Total: a URL it cannot parse is withheld whole."""
    from fuzzlab.core.redaction_floor import redact_for_record, redact_url_identifiers
    try:
        text = redact_for_record("", redact_url_identifiers(url or ""))
        return _blank_identifiers(text)
    except Exception:  # noqa: BLE001 - never let a malformed URL leak through
        return "(unparseable URL withheld)"


def _blank_identifiers(url: str) -> str:
    """`safe_ref`'s last step: identifier-like path segments, matrix values and fragment
    values (the query's are already done)."""
    from urllib.parse import unquote

    from fuzzlab.core.redaction_floor import looks_like_identifier
    head, hashmark, fragment = url.partition("#")
    base, qmark, query = head.partition("?")
    scheme, sep, rest = base.partition("://")
    if not sep:
        scheme, rest = "", base
    authority, slash, path = rest.partition("/") if sep else ("", "", rest)
    segments = []
    for seg in path.split("/"):
        name, semi, params = seg.partition(";")
        if name and looks_like_identifier(unquote(name)):
            name = REDACTED_SEGMENT
        elif name:
            # a token inside a segment, as in a URL embedded in text: ``cb/<tok>)``,
            # ``cb/<tok>`'' (BUG-0521)
            name = _TOKEN_RUN.sub(
                lambda m: REDACTED_SEGMENT if looks_like_identifier(m.group(0))
                else m.group(0), name)
        if semi:
            params = ";".join(
                f"{k}=" if eq and looks_like_identifier(unquote(v)) else part
                for part in params.split(";")
                for k, eq, v in [part.partition("=")])
        segments.append(name + semi + params)
    path = "/".join(segments)
    if hashmark and "=" in fragment:
        route, q, fquery = fragment.rpartition("?") if "?" in fragment \
            else ("", "", fragment)
        fquery = "&".join(
            f"{k}=" if eq and looks_like_identifier(unquote(v)) else part
            for part in fquery.split("&") for k, eq, v in [part.partition("=")])
        fragment = route + q + fquery
    out = (f"{scheme}://{authority}{slash}" if sep else "") + path
    return out + qmark + query + hashmark + fragment


# --- fuzzlab/tools/store_adapter.py at 7393c90 (verbatim) -----------------------------

def redact_sibling(name: str, raw_value: str, value: str) -> str:
    """A crawled link's sibling value as it may be stored and sent: ``""`` when its
    name is sensitive or its raw value looks like an identifier (a token, an id), else
    ``value`` (forms phase 2, FR-FUZZ-43; PA-0100)."""
    from fuzzlab.core.redaction_floor import is_sensitive_name, looks_like_identifier
    if is_sensitive_name(name) or looks_like_identifier(raw_value):
        return ""
    return value


# --- fuzzlab/proxy/message.py at 7393c90 (verbatim) -----------------------------------

CRLF = b"\r\n"
_HEAD_SEPS = (b"\r\n\r\n", b"\n\n")


def _split_head_body(raw: bytes) -> tuple[bytes, bytes, bytes]:
    """Return ``(head, sep, body)`` where ``head + sep + body == raw``.

    ``head`` is the start line plus header block up to (not including) the blank-line
    separator; ``sep`` is the exact separator seen (``\\r\\n\\r\\n`` or, for malformed
    traffic, ``\\n\\n``); ``body`` is everything after. A message with no separator
    yet (head still arriving) has an empty ``sep`` and ``body``.
    """
    best = None
    for cand in _HEAD_SEPS:
        idx = raw.find(cand)
        if idx != -1 and (best is None or idx < best[0]):
            best = (idx, cand)
    if best is None:
        return raw, b"", b""
    idx, sep = best
    return raw[:idx], sep, raw[idx + len(sep):]


@dataclass(frozen=True)
class RawMessage:
    """An HTTP message as exact bytes, with a duplicate-preserving parsed view.

    Immutable: edit methods return a new ``RawMessage``. ``raw`` always equals the
    bytes that would be sent.
    """

    raw: bytes

    # --- construction --------------------------------------------------------
    @classmethod
    def from_bytes(cls, data: bytes) -> "RawMessage":
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("RawMessage requires bytes")
        return cls(bytes(data))

    # --- head / body split (byte-exact) --------------------------------------
    @property
    def _parts(self) -> tuple[bytes, bytes, bytes]:
        return _split_head_body(self.raw)

    @property
    def head(self) -> bytes:
        """Start line + header block, without the blank-line separator."""
        return self._parts[0]

    @property
    def separator(self) -> bytes:
        """The exact head/body separator seen (may be ``b''`` if not yet complete)."""
        return self._parts[1]

    @property
    def body(self) -> bytes:
        return self._parts[2]

    @property
    def complete_head(self) -> bool:
        return self._parts[1] != b""

    # --- line views (order + duplicates preserved) ---------------------------
    def _head_lines(self) -> list[bytes]:
        head = self.head
        if not head:
            return []
        # Split on CRLF, tolerating bare LF for malformed-traffic study.
        return head.replace(b"\r\n", b"\n").split(b"\n")

    @property
    def start_line(self) -> bytes:
        lines = self._head_lines()
        return lines[0] if lines else b""

    def header_lines(self) -> list[bytes]:
        """Raw header lines (after the start line), each without its terminator."""
        return self._head_lines()[1:]

    def headers(self) -> list[tuple[bytes, bytes]]:
        """Ordered ``(name, value)`` pairs, duplicates preserved, values lstripped.

        A line with no colon is skipped (obs-fold/garbage stays only in ``raw``).
        """
        out: list[tuple[bytes, bytes]] = []
        for line in self.header_lines():
            if not line:
                continue
            i = line.find(b":")
            if i == -1:
                continue
            out.append((line[:i], line[i + 1:].lstrip(b" \t")))
        return out

    def get_all(self, name: str | bytes) -> list[bytes]:
        """All values for ``name`` (case-insensitive), in order, duplicates kept."""
        key = _as_bytes(name).lower()
        return [v for (n, v) in self.headers() if n.lower() == key]

    def get(self, name: str | bytes) -> bytes | None:
        vals = self.get_all(name)
        return vals[0] if vals else None

    def has_duplicate(self, name: str | bytes) -> bool:
        return len(self.get_all(name)) > 1

    # --- edits (byte surgery; untouched lines stay verbatim) -----------------
    def _rebuild(self, start_line: bytes, header_lines: Iterable[bytes],
                 body: bytes) -> "RawMessage":
        head = start_line + CRLF + b"".join(l + CRLF for l in header_lines)
        return RawMessage(head + CRLF + body)

    def with_appended_header(self, name: str | bytes, value: str | bytes) -> "RawMessage":
        """Append a header line *without* removing any existing one.

        This is how a duplicate ``Content-Length`` is introduced: the original stays
        and the new line is inserted just before the blank-line separator, so every
        other byte is preserved exactly.
        """
        line = _as_bytes(name) + b": " + _as_bytes(value)
        head, sep, body = self._parts
        if sep == b"":                       # head not yet terminated; just append
            return RawMessage(self.raw + CRLF + line)
        return RawMessage(head + CRLF + line + sep + body)

    def with_header(self, name: str | bytes, value: str | bytes) -> "RawMessage":
        """Set ``name`` to a single ``value`` (replace all existing, else append)."""
        key = _as_bytes(name).lower()
        kept, replaced = [], False
        for line in self.header_lines():
            i = line.find(b":")
            if i != -1 and line[:i].lower() == key:
                if not replaced:             # replace the first, drop the rest
                    kept.append(_as_bytes(name) + b": " + _as_bytes(value))
                    replaced = True
                continue
            kept.append(line)
        if not replaced:
            kept.append(_as_bytes(name) + b": " + _as_bytes(value))
        return self._rebuild(self.start_line, kept, self.body)

    def without_header(self, name: str | bytes) -> "RawMessage":
        key = _as_bytes(name).lower()
        kept = [l for l in self.header_lines()
                if not (l.find(b":") != -1 and l[:l.find(b":")].lower() == key)]
        return self._rebuild(self.start_line, kept, self.body)

    def with_request_line(self, line: str | bytes) -> "RawMessage":
        return self._rebuild(_as_bytes(line), self.header_lines(), self.body)

    # request line == status line at the byte level; alias for readability.
    with_start_line = with_request_line

    def with_body(self, body: str | bytes) -> "RawMessage":
        """Replace the body, leaving the head verbatim.

        Deliberately does **not** fix ``Content-Length`` — desyncing the declared and
        actual body length is exactly the kind of malformed traffic the raw path
        exists to study.
        """
        head, sep, _ = self._parts
        sep = sep or (CRLF + CRLF)
        return RawMessage(head + sep + _as_bytes(body))

    # --- request-line helpers (best-effort; raw stays authoritative) ---------
    @property
    def method(self) -> bytes:
        parts = self.start_line.split(b" ")
        return parts[0] if parts and parts[0] else b""

    @property
    def target(self) -> bytes:
        parts = self.start_line.split(b" ")
        return parts[1] if len(parts) >= 2 else b""

    def __len__(self) -> int:
        return len(self.raw)


def _as_bytes(v: str | bytes) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, bytearray):
        return bytes(v)
    return v.encode("latin-1")


# --- fuzzlab/proxy/redact.py at 7393c90 (verbatim) ------------------------------------

REDACTED = PLACEHOLDER.encode()

# Header names whose values are secrets. Compared case-insensitively.
SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)
_URL_HEADERS = ("location", "content-location", "refresh")


def _dechunk(body: bytes, limit: int) -> bytes | None:
    """The payload of a chunked body (trailers ignored), or ``None`` if malformed or
    longer than ``limit``."""
    out, i = bytearray(), 0
    while True:
        j = body.find(b"\r\n", i)
        if j == -1:
            return None
        try:
            size = int(body[i:j].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return None
        if size == 0:
            return bytes(out)
        if len(out) + size > limit or j + 2 + size > len(body):
            return None
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2


def _decompress(data: bytes, encoding: str, limit: int) -> bytes | None:
    """``data`` decoded per ``Content-Encoding`` (gzip / x-gzip / deflate), bounded to
    ``limit`` bytes of output; ``None`` if unknown, malformed or too large."""
    enc = encoding.strip().lower()
    if enc in ("", "identity"):
        return data
    modes = {"gzip": (16 + zlib.MAX_WBITS,), "x-gzip": (16 + zlib.MAX_WBITS,),
             "deflate": (zlib.MAX_WBITS, -zlib.MAX_WBITS)}.get(enc)
    if modes is None:
        return None                                       # br, zstd, chains: not decoded
    for wbits in modes:
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, limit + 1)
        except zlib.error:
            continue
        if len(out) > limit or d.unconsumed_tail:
            return None                                   # a decompression bomb
        return out
    return None


def _framed_payload(msg: RawMessage, body: bytes) -> bytes | None:
    """``body`` with its transfer and content codings removed (bounded), or ``None``."""
    data = body
    if (te := _header(msg, "Transfer-Encoding")) and "chunked" in te.lower():
        data = _dechunk(data, MAX_REDACT_BYTES)
        if data is None:
            return None
    return _decompress(data, _header(msg, "Content-Encoding"), MAX_REDACT_BYTES)


def _framed_body_unsafe(msg: RawMessage, body: bytes) -> bool:
    """For a chunked / compressed body: True when it must not be stored as received —
    its decoded payload carries a secret, or it cannot be decoded while its type is
    redactable (fail closed, BUG-0100). A clean one is kept byte-exact."""
    ct = _header(msg, "Content-Type")
    payload = _framed_payload(msg, body)
    if payload is None:
        return body_kind(b"", ct) is not None or mentions_sensitive_name(body)
    return redact_body(payload, ct) != payload


def _original_name(msg: RawMessage, name: str) -> bytes:
    """The header's name as the message spells it (keep the persisted copy faithful)."""
    for line in msg.header_lines():
        i = line.find(b":")
        if i != -1 and line[:i].lower() == name.encode():
            return line[:i]
    return name.encode()


def _header(msg: RawMessage, name: str) -> str:
    v = msg.get(name)
    return v.decode("latin-1", "replace") if v is not None else ""


def redact(raw: bytes, extra_headers: tuple[str, ...] = ()) -> bytes:
    """Return ``raw`` with its secrets replaced by a placeholder (see the module
    docstring). Benign headers, parameters and fields are left untouched."""
    msg = RawMessage.from_bytes(raw)
    names = set(SENSITIVE_HEADERS) | {h.lower() for h in extra_headers}
    for line in msg.header_lines():
        i = line.find(b":")
        if i != -1 and is_sensitive_name(line[:i].decode("latin-1", "replace")):
            names.add(line[:i].decode("latin-1", "replace").lower())
    for name in names:
        if msg.get(name) is not None:
            # Replace every occurrence (duplicates included) with the placeholder.
            n = len(msg.get_all(name))
            msg = msg.without_header(name)
            for _ in range(n):
                msg = msg.with_appended_header(name, REDACTED)
    # the request target's query (a response's start line has none)
    target = msg.target.decode("latin-1", "replace")
    if not msg.start_line.startswith(b"HTTP/") and "?" in target:
        new_target = redact_url(target)
        if new_target != target:
            parts = msg.start_line.split(b" ")
            parts[1] = new_target.encode("latin-1")
            msg = msg.with_request_line(b" ".join(parts))
    for name in _URL_HEADERS:
        value = _header(msg, name)
        if "?" in value:
            new = redact_url(value) if name != "refresh" else re.sub(
                r"(url=)(\S+)", lambda m: m.group(1) + redact_url(m.group(2)), value,
                flags=re.I)
            if new != value:
                msg = msg.with_header(_original_name(msg, name), new)
    # bodies. Chunked / compressed: decoded (bounded) and checked; a body that is not
    # provably clean is replaced by the marker with framing made consistent (B-S3),
    # a clean one is kept byte-exact.
    if msg.body and (msg.get("Transfer-Encoding") is not None
                     or msg.get("Content-Encoding") is not None):
        if _framed_body_unsafe(msg, msg.body):
            msg = msg.without_header("Transfer-Encoding").without_header(
                "Content-Encoding").with_body(OMIT_UNSAFE)
            msg = msg.with_header("Content-Length", str(len(OMIT_UNSAFE)))
    elif msg.body:
        old = msg.body
        new = redact_body(old, _header(msg, "Content-Type"))
        if new != old:
            msg = msg.with_body(new)
            declared = _header(msg, "Content-Length").strip()
            if declared.isdigit() and int(declared) == len(old):
                msg = msg.with_header("Content-Length", str(len(new)))
    return msg.raw
