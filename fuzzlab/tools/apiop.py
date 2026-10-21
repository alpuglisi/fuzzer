"""Which captured requests are one API operation, and what each one adds to it
(FR-CRAWL-37, BUG-0546; used by the spider's capture writer,
`tools.spider.StorageManager.record_request`).

**The operation** (`operation_key`). Two captured requests are the same API operation
only when all of these match:

- the method;
- the canonical origin and path (`core.urls.url_key`). An exact path is never coarser
  than its template, which the importer derives over the whole run (SP-45);
- the request's media type;
- every **operation selector** (`operation_selectors`), in the body at any depth or in
  the query:
  - a GraphQL request's operation: its type, its name and its root fields, for the
    operation ``operationName`` selects (`graphql_operations`);
  - the value of a dispatcher field (`SELECTOR_NAMES`): an ``action``/``op``/``cmd``
    field, a JSON-RPC ``method``, an HTTP method override (``_method``), GraphQL's
    ``operationName``.

  A field so named is a selector whenever its value is a non-empty string or an
  integer, never a boolean (`_selector_value`): a multi-word value (a submit button's
  ``value="Add to cart"``) or a long one selects as a short token does. A string is
  keyed with its whitespace runs folded to one space, by its text up to
  `MAX_SELECTOR_CHARS`, else by the digest of its folded text. Misjudging a data field
  as a selector costs a row, never an input: every row is imported (review round 1,
  B1: a value with whitespace, or over 64 characters, was data, and merged two
  operations).

**What a request adds** (`request_shape`, `operation_schema`). A request's shape is its
typed key paths: every position of its body, at every depth (object keys by name, array
elements as one position), with the JSON type found there, and the name of each query
parameter. An operation's schema is the merge of its stored rows' shapes (their union).
Each stored row is one real request the application sent, never a merged body:

- a request whose exact shape a row of its operation already has is a duplicate;
- one whose shape adds a key path or a type, at any depth, to the operation's schema is
  always stored: no input a captured request carried is dropped;
- one that only combines known inputs differently (another context) is stored while
  the operation has fewer than `MAX_CONTEXT_ROWS` rows, then counted as not recorded.

(Bodies are not merged into one row: the importer judges a body as a whole, so a merged
one would be refused for a field another request carried, or for its leaf count.)

Everything here is total on its input and bounded by the capture boundary's own limits
(`core.redaction.CAPTURE_MAX_BYTES`, depth `CAPTURE_MAX_DEPTH`), plus `MAX_DEPTH`,
`MAX_SELECTORS`, `MAX_GRAPHQL_TOKENS`, `MAX_OPERATIONS`, `MAX_ROOT_FIELDS` and
`MAX_CONTEXT_ROWS`. A GraphQL document is read by a linear scanner, never by a
backtracking pattern.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit

from fuzzlab.core.redaction import CAPTURE_MAX_BYTES
from fuzzlab.core.urls import url_key

#: Field names (compared lower-cased) whose value selects the handler of a dispatching
#: endpoint.
SELECTOR_NAMES = frozenset({
    "action", "act", "op", "operation", "operationname", "cmd", "command", "do",
    "task", "func", "function", "method", "_method"})
#: A selector's string value (whitespace runs folded) of at most this many characters is
#: keyed by its text; a longer one by ``"sha256:"`` and the hex digest of its folded
#: text, 71 characters, so never equal to a short one.
MAX_SELECTOR_CHARS = 64
_WHITESPACE_RUN = re.compile(r"\s+")
#: At most this many selectors identify one operation (the first, in sorted order).
MAX_SELECTORS = 64
#: No walk goes deeper than this (the capture boundary stops at 8).
MAX_DEPTH = 16
#: A GraphQL document with more tokens than this is not parsed: it is identified by the
#: digest of its text (whitespace runs folded), so two such documents stay apart.
MAX_GRAPHQL_TOKENS = 20000
#: At most this many root fields are kept per GraphQL operation.
MAX_ROOT_FIELDS = 64
#: Fragment and inline-fragment nesting followed when collecting root fields.
MAX_FRAGMENT_DEPTH = 8
#: At most this many operations of one document are read (the first, in document
#: order), so a document's cost stays linear in its length.
MAX_OPERATIONS = 16
#: Once an operation has this many stored rows, a request that adds no key path or type
#: to its schema (another combination of known inputs) is not stored; one that adds
#: either always is.
MAX_CONTEXT_ROWS = 32

#: The marker of an array element in a shape's path (keys are always strings).
_ELEMENT = 0


# --- the operation ------------------------------------------------------------------

def _query_pairs(url: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(urlsplit(url or "").query, keep_blank_values=True)
    except ValueError:
        return []


def _selector_value(value):
    """How a dispatcher field's value is keyed, or None when it selects nothing: an
    integer as itself; a non-empty string with every whitespace run folded to one space,
    as its text up to `MAX_SELECTOR_CHARS`, else ``"sha256:<hex>"`` of the folded text
    (surrogates passed through, so it is total). A boolean, an empty string, ``None``,
    a float or a container selects nothing."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value:
        return None
    folded = _WHITESPACE_RUN.sub(" ", value)
    if len(folded) <= MAX_SELECTOR_CHARS:
        return folded
    digest = hashlib.sha256(folded.encode("utf-8", "surrogatepass")).hexdigest()
    return "sha256:" + digest


def operation_selectors(doc, query_pairs=()) -> list:
    """The operation selectors of a request whose redacted body is ``doc`` and whose
    query is ``query_pairs``, sorted, at most `MAX_SELECTORS`: ``["field", path,
    value]`` for a dispatcher field (the value as `_selector_value` keys it) and
    ``["graphql", path, operations]`` for a GraphQL document (`graphql_operations`). A
    body path starts with ``"$"``, a query one with ``"?"``; array elements are
    numbered."""
    found: list = []
    op_name = next((v for n, v in query_pairs if n == "operationName"), None)
    for name, value in query_pairs:
        key = _selector_value(value) if name.lower() in SELECTOR_NAMES else None
        if key is not None:
            found.append(["field", ["?", name], key])
        if name == "query":
            ops = graphql_operations(value, op_name)
            if ops is not None:
                found.append(["graphql", ["?", name], ops])
    stack = [(["$"], doc, 0)]
    while stack:
        path, node, depth = stack.pop()
        if depth > MAX_DEPTH:
            continue
        if isinstance(node, dict):
            query = node.get("query")
            if isinstance(query, str):
                name = node.get("operationName")
                ops = graphql_operations(query, name if isinstance(name, str) else None)
                if ops is not None:
                    found.append(["graphql", path + ["query"], ops])
            for key, value in node.items():
                key = str(key)
                selects = _selector_value(value) if key.lower() in SELECTOR_NAMES else None
                if selects is not None:
                    found.append(["field", path + [key], selects])
                if isinstance(value, (dict, list)):
                    stack.append((path + [key], value, depth + 1))
        elif isinstance(node, list):
            for i, value in enumerate(node):
                if isinstance(value, (dict, list)):
                    stack.append((path + [i], value, depth + 1))
    texts = sorted({json.dumps(s, ensure_ascii=False) for s in found})
    return [json.loads(t) for t in texts[:MAX_SELECTORS]]


def operation_key(method: str, url: str, media: str, doc) -> str:
    """The identity of the API operation a captured request calls, as JSON text:
    ``[method, url_key(url), media type, operation selectors]`` (see the module)."""
    return json.dumps([(method or "").upper(), url_key(url), media or "",
                       operation_selectors(doc, _query_pairs(url))], ensure_ascii=False)


def signature_prefix(op_key: str) -> str:
    """The text every stored signature of the operation ``op_key`` starts with."""
    return op_key[:-1] + ", "


def row_signature(op_key: str, shape) -> str:
    """A stored representative's signature: its operation and the digest of its
    shape, ``[method, url_key, media type, selectors, shape digest]``."""
    text = json.dumps(sorted(json.dumps(list(p), ensure_ascii=False) for p in shape),
                      ensure_ascii=False)
    return signature_prefix(op_key) + json.dumps(
        hashlib.sha256(text.encode("utf-8")).hexdigest()) + "]"


# --- what a request adds ------------------------------------------------------------

def _json_type(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def request_shape(doc, url: str = "") -> frozenset:
    """The typed key paths of a captured request: ``("body", *path, type)`` for every
    position of its body at every depth (object keys by name, every array element as
    `_ELEMENT`), and ``("query", name, "string")`` for each query parameter name."""
    out = {("query", name, "string") for name, _v in _query_pairs(url)}
    stack = [(("body",), doc, 0)]
    while stack:
        path, node, depth = stack.pop()
        out.add(path + (_json_type(node),))
        if depth >= MAX_DEPTH:
            continue
        if isinstance(node, dict):
            for key, value in node.items():
                stack.append((path + (str(key),), value, depth + 1))
        elif isinstance(node, list):
            for value in node:
                stack.append((path + (_ELEMENT,), value, depth + 1))
    return frozenset(out)


def operation_schema(rows) -> frozenset:
    """The merged schema of an operation's stored representatives: the union of their
    shapes, from ``(url, body_json)`` rows. A row whose body cannot be read adds
    nothing."""
    out: set = set()
    for url, body_json in rows:
        try:
            doc = json.loads(body_json)
        except (TypeError, ValueError, RecursionError):
            continue
        out |= request_shape(doc, url or "")
    return frozenset(out)


# --- GraphQL ------------------------------------------------------------------------

_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_NUMBER = re.compile(r"-?[0-9][_0-9A-Za-z.+\-]*")
_STRING = re.compile(r'"(?:[^"\\\r\n]|\\.)*"')
_COMMENT = re.compile(r"#[^\r\n]*")
_PUNCTUATORS = frozenset("!$&():=@[]{}|")
_IGNORED = frozenset(" \t\r\n,﻿")
_OPERATION_TYPES = ("query", "mutation", "subscription")
_CLOSERS = {"{": "}", "(": ")", "[": "]"}
#: `_document`'s answer for a document over `MAX_GRAPHQL_TOKENS`.
_OVER = object()


def _tokens(text: str) -> list[str] | None:
    """GraphQL's lexical tokens, a string or number as one placeholder; None when the
    text is not GraphQL. Linear; it stops after `MAX_GRAPHQL_TOKENS` + 1 tokens (the
    caller sees the length)."""
    toks: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if len(toks) > MAX_GRAPHQL_TOKENS:
            return toks
        c = text[i]
        if c in _IGNORED:
            i += 1
        elif c == "#":
            i = _COMMENT.match(text, i).end()
        elif text.startswith('"""', i):
            j = i + 3
            while True:
                k = text.find('"""', j)
                if k < 0:
                    return None
                if text[k - 1] == "\\":          # an escaped \"""
                    j = k + 3
                    continue
                i = k + 3
                break
            toks.append('"')
        elif c == '"':
            m = _STRING.match(text, i)
            if m is None:
                return None
            toks.append('"')
            i = m.end()
        elif text.startswith("...", i):
            toks.append("...")
            i += 3
        elif c in _PUNCTUATORS:
            toks.append(c)
            i += 1
        else:
            m = _NAME.match(text, i)
            if m is not None:
                toks.append(m.group())
            else:
                m = _NUMBER.match(text, i)
                if m is None:
                    return None
                toks.append("0")
            i = m.end()
    return toks


def _is_name(tok: str) -> bool:
    return tok[:1] == "_" or (tok[:1].isascii() and tok[:1].isalpha())


def _close(toks, i, end):
    """The index after the bracket that closes ``toks[i]``, or None (unbalanced)."""
    opener, closer, depth = toks[i], _CLOSERS[toks[i]], 0
    for j in range(i, end):
        if toks[j] == opener:
            depth += 1
        elif toks[j] == closer:
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def _directives(toks, i, end):
    """The index after any directives (``@name(args)``) at ``i``, or None."""
    while i is not None and i < end and toks[i] == "@":
        if i + 1 >= end or not _is_name(toks[i + 1]):
            return None
        i += 2
        if i < end and toks[i] == "(":
            i = _close(toks, i, end)
    return i


def _document(text: str):
    """``(tokens, operations, fragments)`` of an executable GraphQL document, `_OVER`
    for one that starts like a document and passes `MAX_GRAPHQL_TOKENS`, or None.
    An operation is ``(type, name, span)``; a fragment maps its name to its span; a
    span is the ``[start, end)`` of a selection set."""
    toks = _tokens(text)
    if not toks:
        return None
    if len(toks) > MAX_GRAPHQL_TOKENS:
        return _OVER if toks[0] in ("{", "fragment") + _OPERATION_TYPES else None
    n, ops, frags, i = len(toks), [], {}, 0
    while i < n:
        tok = toks[i]
        if tok == "{":
            kind, name = "query", ""
        elif tok in _OPERATION_TYPES:
            kind, name, i = tok, "", i + 1
            if i < n and _is_name(toks[i]):
                name, i = toks[i], i + 1
            if i < n and toks[i] == "(":
                i = _close(toks, i, n)
            i = _directives(toks, i, n)
        elif tok == "fragment":
            if i + 3 >= n or not _is_name(toks[i + 1]) or toks[i + 2] != "on" \
                    or not _is_name(toks[i + 3]):
                return None
            kind, name, i = "fragment", toks[i + 1], _directives(toks, i + 4, n)
        else:
            return None                     # not an executable document
        if i is None or i >= n or toks[i] != "{":
            return None
        end = _close(toks, i, n)
        if end is None:
            return None
        if kind == "fragment":
            frags.setdefault(name, (i, end))
        else:
            ops.append((kind, name, (i, end)))
        i = end
    return (toks, ops, frags) if ops else None


def _root_fields(toks, span, frags, seen, out, depth=0) -> bool:
    """Add the fields selected at the top of ``span`` to ``out`` (aliases resolved,
    fragments expanded once each); False when the selection set is malformed."""
    i, end = span[0] + 1, span[1] - 1
    while i < end:
        tok = toks[i]
        if tok == "...":
            i += 1
            inline = i < end and toks[i] in ("on", "@", "{")
            name = None
            if inline and toks[i] == "on":
                if i + 1 >= end or not _is_name(toks[i + 1]):
                    return False
                i += 2
            elif not inline:
                if i >= end or not _is_name(toks[i]):
                    return False
                name, i = toks[i], i + 1
            i = _directives(toks, i, end)
            if i is None:
                return False
            if inline:
                if i >= end or toks[i] != "{":
                    return False
                inner = (i, _close(toks, i, end))
                if inner[1] is None:
                    return False
                if depth < MAX_FRAGMENT_DEPTH and \
                        not _root_fields(toks, inner, frags, seen, out, depth + 1):
                    return False
                i = inner[1]
            elif name in frags:
                if name not in seen and depth < MAX_FRAGMENT_DEPTH:
                    seen.add(name)
                    if not _root_fields(toks, frags[name], frags, seen, out, depth + 1):
                        return False
            else:
                out.add("..." + name)       # a fragment the document does not define
        elif _is_name(tok):
            field, i = tok, i + 1
            if i < end and toks[i] == ":":
                if i + 1 >= end or not _is_name(toks[i + 1]):
                    return False
                field, i = toks[i + 1], i + 2
            out.add(field)
            if i < end and toks[i] == "(":
                i = _close(toks, i, end)
            i = _directives(toks, i, end)
            if i is not None and i < end and toks[i] == "{":
                i = _close(toks, i, end)
            if i is None:
                return False
        else:
            return False
    return True


def graphql_operations(text, operation_name=None) -> list | None:
    """The operations a GraphQL request runs, ``[[type, name, root fields], ...]``
    sorted: the one ``operation_name`` names, else every operation of the document (at
    most `MAX_OPERATIONS`); ``[["document", "", [digest]]]`` for a document over
    `MAX_GRAPHQL_TOKENS`; None when ``text`` is not an executable GraphQL document."""
    if not isinstance(text, str) or len(text) > CAPTURE_MAX_BYTES:
        return None
    doc = _document(text)
    if doc is None:
        return None
    if doc is _OVER:
        folded = " ".join(text.split())
        return [["document", "", [hashlib.sha256(folded.encode("utf-8")).hexdigest()]]]
    toks, ops, frags = doc
    chosen = [op for op in ops if op[1] == operation_name] or ops
    out = []
    for kind, name, span in chosen[:MAX_OPERATIONS]:
        fields: set = set()
        if not _root_fields(toks, span, frags, set(), fields):
            return None
        out.append([kind, name, sorted(fields)[:MAX_ROOT_FIELDS]])
    return sorted(out)
