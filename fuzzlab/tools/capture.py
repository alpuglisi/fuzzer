"""Capture-and-abort for the crawler (DISC-CAPTURE; FR-CRAWL-18, FR-CRAWL-19).

Discover what the app **does**, observed in the browser at the protocol level, never
what its code says. The crawl's browser lets reads go out and records every other
request it sees, then aborts it: nothing the app would write reaches the server while
the crawl discovers. Pure helpers, testable without a browser; `tools/navguard.py`
calls the predicate in its route handler and `tools/spider.py` records.

* `capture_refusal` -- the crawl-wide predicate: what is aborted (and recorded);
* GraphQL reads over POST -- `graphql_read_only`, by the published grammar
  (`graphql_tokens`, `graphql_operations`); `op_key` names the operation a body carries
  (GraphQL ``operationName`` or a hash of its document, JSON-RPC ``method``);
* long-poll transports -- `transport_protocol`, by published protocol markers;
* `CAPTURE_INIT_JS` -- the init script for egress the route never sees (``sendBeacon``,
  ``keepalive`` fetches, ``fetchLater``; measured in Chromium, DISC-CAPTURE §2).

Nothing here is fitted to one app: every rule is a published standard or a generic word
rule shared with the reveal window (`spa.window_request_refusal`).
"""

from __future__ import annotations

import hashlib
import json
import string
from urllib.parse import urlsplit

#: The methods a request may have; any other is "unrecognised" and aborted (fail closed).
KNOWN_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
#: Methods that write (their capture is "a captured write", FR-FUZZ-52).
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: A body larger than this is never classified as a read: aborted.
BODY_CAP = 64 * 1024

#: The capture reasons' stable prefixes (the spider counts by them, PA-0110).
WHY_FAILED = "capture failed"
WHY_BODY_UNAVAILABLE = "body unavailable"
WHY_GET_RULE = "GET refused by rule"
WHY_METHOD = "unrecognised method"
WHY_OVER_CAP = "body over the cap"
WHY_WRITE = "captured, not sent"
WHY_WINDOW = "reveal window"

#: ``discovered_requests.source`` (FR-CRAWL-18): sent and observed; recorded and aborted;
#: a long-poll transport (kept out of import, FR-CRAWL-19).
SOURCE_OBSERVED = "observed"
SOURCE_CAPTURED = "captured-aborted"
SOURCE_TRANSPORT = "transport"
#: Older spider DBs recorded only what was sent, as ``passive`` or ``submit``.
LEGACY_SOURCES = frozenset({"passive", "submit"})


def capture_refusal(method: str, url: str, navigation: bool, body, *,
                    refresh: frozenset = frozenset()) -> str | None:
    """Why the crawl aborts (and records) a request, or None to let it go out
    (FR-CRAWL-18, DISC-CAPTURE §1 and §3):

    * a GET or HEAD **navigation**: None (the scope and destructive rules judge it, as
      before capture);
    * any other GET or HEAD: the reveal window's GET word rules
      (`spa.window_request_refusal`: destructive, transaction, credential token, account
      action), crawl-wide;
    * any other known method: aborted, unless it is the session's own refresh endpoint
      (``refresh``: ``(METHOD, url_key)`` pairs the session learned at login) or a
      GraphQL read (`graphql_read_only`). A body that is None (a blob or a stream the
      driver cannot show; measured: a ``ReadableStream`` upload) or over `BODY_CAP` is
      aborted;
    * an unrecognised method: aborted.

    The route handler wraps the call: an error aborts too (fail closed)."""
    from fuzzlab.core.urls import url_key
    from fuzzlab.tools.spa import window_request_refusal
    method = (method or "").upper()
    if method not in KNOWN_METHODS:
        return f"{WHY_METHOD} {method[:16]!r}"
    if method in ("GET", "HEAD"):
        if navigation:
            return None
        why = window_request_refusal(method, url, False)
        return f"{WHY_GET_RULE}: {why}" if why else None
    if (method, url_key(url)) in refresh:
        return None
    if body is None:
        return f"{WHY_BODY_UNAVAILABLE} ({method})"
    if len(body) > BODY_CAP:
        return f"{WHY_OVER_CAP} ({method})"
    if method == "POST" and graphql_read_only(body):
        return None
    return f"{WHY_WRITE}: a {method} request"


# --- GraphQL (the published grammar: spec.graphql.org, "Language") ----------------------
_GQL_PUNCT = frozenset("!$&()[]{}:=@|")
_GQL_NAME_START = frozenset(string.ascii_letters + "_")
_GQL_NAME = _GQL_NAME_START | frozenset(string.digits)
_GQL_IGNORED = frozenset(" \t\r\n,﻿")
#: The operation keywords of an executable definition (GraphQL §2.3).
GQL_OPERATIONS = frozenset({"query", "mutation", "subscription"})


def _block_string_end(text: str, i: int) -> int | None:
    """The index just past the ``\"\"\"`` closing a block string opened at ``i``."""
    j = i + 3
    while True:
        end = text.find('"""', j)
        if end < 0:
            return None
        if text[end - 1] == "\\":                  # an escaped \"""
            j = end + 3
            continue
        return end + 3


def graphql_tokens(text: str) -> list[str] | None:
    """The lexical tokens of a GraphQL document (GraphQL §2.1): names, punctuators,
    numbers and strings (block strings included), with the ignored tokens dropped
    (whitespace, commas, the BOM, ``#`` comments). None for anything the grammar does
    not allow (an unterminated string, a stray character) or a document over
    `BODY_CAP`. One linear pass, every branch advancing."""
    if not isinstance(text, str) or len(text) > BODY_CAP:
        return None
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in _GQL_IGNORED:
            i += 1
        elif c == "#":
            while i < n and text[i] not in "\r\n":
                i += 1
        elif text.startswith('"""', i):
            end = _block_string_end(text, i)
            if end is None:
                return None
            out.append(text[i:end])
            i = end
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] in "\r\n":
                    return None
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return None
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("...", i):
            out.append("...")
            i += 3
        elif c in _GQL_PUNCT:
            out.append(c)
            i += 1
        elif c in _GQL_NAME_START:
            j = i + 1
            while j < n and text[j] in _GQL_NAME:
                j += 1
            out.append(text[i:j])
            i = j
        elif c.isascii() and (c.isdigit() or c == "-"):
            j = i + 1
            while j < n and text[j].isascii() and (text[j].isalnum() or text[j] in ".+-"):
                j += 1
            out.append(text[i:j])
            i = j
        else:
            return None
    return out


def graphql_operations(text: str) -> list[str] | None:
    """The kinds of a GraphQL document's top-level definitions, in order: ``query``
    (the ``{`` shorthand included), ``mutation``, ``subscription`` or ``fragment``.
    None when it is not an executable document under the grammar: a type-system
    definition, a definition with no selection set, unbalanced brackets, an empty
    document. A keyword inside a selection set (a field named ``mutation``), a string
    or a comment is never a definition."""
    toks = graphql_tokens(text)
    if not toks:
        return None
    kinds: list[str] = []
    depth, inside = 0, False
    for tok in toks:
        if depth == 0 and not inside:
            if tok == "{":
                kinds.append("query")             # the query shorthand
            elif tok in GQL_OPERATIONS or tok == "fragment":
                kinds.append(tok)
                inside = True
                continue
            else:
                return None
        if tok in ("{", "(", "["):
            if tok == "{" and depth == 0:
                inside = True
            depth += 1
        elif tok in ("}", ")", "]"):
            depth -= 1
            if depth < 0:
                return None
            if depth == 0 and tok == "}":
                inside = False                    # the selection set closed
    if depth != 0 or inside:
        return None
    return kinds


def _json_value(body):
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(body, str):
        return body
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        return None


def graphql_read_only(body) -> bool:
    """Is a POST body a GraphQL **read** (DISC-CAPTURE §3)? A JSON object with a
    ``query`` string, or a non-empty batch of them, where every document has at least
    one ``query`` operation and no ``mutation`` or ``subscription`` under the published
    grammar (`graphql_operations`). A persisted query (no ``query``, only an
    ``extensions`` hash) and anything unparseable is not a read. Total."""
    try:
        doc = _json_value(body)
        items = doc if isinstance(doc, list) and doc else [doc]
        for item in items:
            if not is_graphql_body(item):
                return False
            kinds = graphql_operations(item["query"])
            if not kinds or "query" not in kinds or \
                    {"mutation", "subscription"} & set(kinds):
                return False
        return True
    except Exception:  # noqa: BLE001 - total: anything odd is not a read
        return False


def is_graphql_body(doc) -> bool:
    """A JSON object carrying a GraphQL request (its ``query`` a string)."""
    return isinstance(doc, dict) and isinstance(doc.get("query"), str)


def is_jsonrpc_body(doc) -> bool:
    """A JSON-RPC 2.0 request object (jsonrpc.org, specification §4)."""
    return isinstance(doc, dict) and doc.get("jsonrpc") == "2.0" and \
        isinstance(doc.get("method"), str)


#: An op key's name part keeps only these characters, at most `OP_KEY_LEN` of them.
OP_KEY_LEN = 64
_OP_CHARS = frozenset(string.ascii_letters + string.digits + "_.-/")


def _op_name(name) -> str:
    return "".join(ch for ch in str(name) if ch in _OP_CHARS)[:OP_KEY_LEN]


def op_key(doc) -> str:
    """The operation a JSON body names on its URL, or ``""`` (DISC-CAPTURE §5): a GraphQL
    ``operationName`` (``gql:<name>``), else a short hash of the document's tokens
    (``gql#<12 hex>``; layout and comments do not change it); a JSON-RPC ``method``
    (``rpc:<method>``); a batch joins its members' keys with ``+``. One URL with many
    operations is many endpoints. Total."""
    try:
        if isinstance(doc, list):
            keys = [op_key(d) for d in doc[:8]]
            return "+".join(keys)[:4 * OP_KEY_LEN] if any(keys) else ""
        if is_graphql_body(doc):
            name = _op_name(doc.get("operationName") or "")
            if name:
                return f"gql:{name}"
            toks = graphql_tokens(doc["query"])
            norm = " ".join(toks) if toks is not None else " ".join(doc["query"].split())
            return "gql#" + hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()[:12]
        if is_jsonrpc_body(doc):
            name = _op_name(doc["method"])
            return f"rpc:{name}" if name else ""
    except Exception:  # noqa: BLE001 - total: no op key
        return ""
    return ""


#: Top-level keys of a body kind that are never points (DISC-CAPTURE §5): GraphQL's
#: document, operation name and extensions (only ``variables`` leaves are points), and
#: JSON-RPC's envelope.
GRAPHQL_PINNED = frozenset({"query", "operationName", "extensions"})
JSONRPC_PINNED = frozenset({"jsonrpc", "method", "id"})


def pinned_top_keys(doc) -> frozenset:
    """The top-level keys of a recorded body that are sent as captured and never
    fuzzed: `GRAPHQL_PINNED` for a GraphQL body, `JSONRPC_PINNED` for JSON-RPC."""
    if is_graphql_body(doc):
        return GRAPHQL_PINNED
    if is_jsonrpc_body(doc):
        return JSONRPC_PINNED
    return frozenset()


# --- long-poll transports (DISC-CAPTURE §7, FR-CRAWL-19) ----------------------------------
_SOCKET_IO_SEGMENTS = frozenset({"socket.io", "engine.io"})
_SOCKJS_TRANSPORTS = frozenset({"xhr", "xhr_send", "xhr_streaming"})


def transport_protocol(url: str, protocols=()) -> str | None:
    """The long-poll or socket transport a request belongs to, by its protocol's
    **published** markers, or None (DISC-CAPTURE §7):

    * socket.io / engine.io: a ``socket.io`` or ``engine.io`` path segment, or ``EIO``
      with ``transport`` in the query;
    * SockJS: ``.../<server id digits>/<session>/xhr|xhr_send|xhr_streaming``;
    * SignalR: ``connectionToken`` or ``negotiateVersion``, or a ``negotiate`` segment
      with ``clientProtocol``;
    * Phoenix: a ``longpoll`` segment with ``vsn``;
    * ActionCable: a WebSocket subprotocol ``actioncable-*`` (``protocols``).

    Total."""
    try:
        parts = urlsplit(url or "")
        segs = [s for s in parts.path.split("/") if s]
        names = {p.partition("=")[0] for p in parts.query.split("&") if p}
        if any(s.lower() in _SOCKET_IO_SEGMENTS for s in segs) or \
                {"eio", "transport"} <= {n.lower() for n in names}:
            return "socket.io"
        if len(segs) >= 3 and segs[-1] in _SOCKJS_TRANSPORTS and segs[-3].isdigit():
            return "sockjs"
        if names & {"connectionToken", "negotiateVersion"} or \
                (segs and segs[-1] == "negotiate" and "clientProtocol" in names):
            return "signalr"
        if segs and segs[-1] == "longpoll" and "vsn" in names:
            return "phoenix"
        if any(str(p).lower().startswith("actioncable-") for p in protocols or ()):
            return "actioncable"
    except Exception:  # noqa: BLE001 - total: not a known transport
        return None
    return None


#: Transport rows recorded per (protocol, URL key): the rest of an aborted poller's
#: reconnect churn is counted only (DISC-CAPTURE §7).
MAX_TRANSPORT_ROWS_PER_URL = 1


# --- egress the route never sees (DISC-CAPTURE §2) ----------------------------------------
#: The binding the init script reports a withheld beacon to.
CAPTURE_BINDING = "__fuzzlabCaptured"
#: Added with ``add_init_script`` to every crawl context. Measured in Chromium 1194 with
#: Playwright 1.63 (no init script): a ``sendBeacon`` made on load reaches the route
#: (resource type ``ping``), but a ``sendBeacon`` and a ``keepalive`` fetch made on
#: ``pagehide``, and ``fetchLater``, reach the server **without** passing the context
#: route. So ``sendBeacon`` becomes a recorder that returns true and sends nothing;
#: ``keepalive`` is stripped from ``fetch`` (an init object and a ``Request``), which
#: makes the request an ordinary one the route sees; ``fetchLater`` throws.
CAPTURE_INIT_JS = r"""
(() => {
  const report = (url, body) => {
    try {
      let text = null;
      if (typeof body === 'string') text = body;
      else if (body instanceof URLSearchParams) text = body.toString();
      const fn = window['__fuzzlabCaptured'];
      if (typeof fn === 'function') Promise.resolve(fn(String(url), text)).catch(() => {});
    } catch (e) {}
  };
  try {
    const sendBeacon = function sendBeacon(url, body) { report(url, body); return true; };
    Object.defineProperty(Navigator.prototype, 'sendBeacon',
      {value: sendBeacon, configurable: false, writable: false});
  } catch (e) {}
  try {
    const realFetch = window.fetch;
    const fetch = function fetch(input, init) {
      if (init && typeof init === 'object' && init.keepalive) {
        init = Object.assign({}, init); init.keepalive = false;
      }
      if (typeof Request === 'function' && input instanceof Request && input.keepalive)
        input = new Request(input, {keepalive: false});
      return realFetch.call(this, input, init);
    };
    Object.defineProperty(window, 'fetch',
      {value: fetch, configurable: false, writable: false});
  } catch (e) {}
  try {
    const fetchLater = function fetchLater() {
      throw new DOMException('fetchLater is disabled by the crawler', 'NotAllowedError');
    };
    Object.defineProperty(window, 'fetchLater',
      {value: fetchLater, configurable: false, writable: false});
  } catch (e) {}
})();
"""
