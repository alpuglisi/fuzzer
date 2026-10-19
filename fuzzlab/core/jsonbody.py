"""JSON request bodies as injection points (forms phase 3, FR-CORE-36).

A captured JSON API request (``POST /rest/user/login {"email": …, "password": …}``) is
fuzzed one **leaf** at a time: every probe sends the whole body, as the app sent it,
with exactly one leaf set to the payload (as a string). This module is the one place
the convention lives (PA-0003): how a leaf's path is stored, how it is named, how a
stored entry list is read back (PA-0108), and how a body is rebuilt for a send.

* **Path** -- a tuple of segments: a ``str`` object key or an ``int`` list index
  (``("user", "tags", 0)``). Stored losslessly as a JSON array of segments.
* **Entry** -- ``(path, value)``; ``value`` is the leaf's typed JSON value (string,
  number, bool, null, or an empty object/list, which has no leaves of its own).
* **Name** -- the display and parameter name of a path: object keys joined by ``.``,
  list indexes as ``[n]``; ``\\``, ``.``, ``[`` and ``]`` inside a key are escaped with
  ``\\`` (``a\\.b`` is the key ``a.b``). :func:`parse_name` inverts :func:`display_name`
  exactly, so a name round-trips byte for byte.
* **Location** -- :data:`LOCATION` (``"json"``): a point whose payload goes into one leaf
  of a JSON body sent as ``Content-Type: application/json`` (:data:`ENCTYPE`).

Every function here is total on hostile input (PA-0096): a malformed path, name or
entry list is ``None`` (or `JsonPlacementError` where a send must be refused), never a
crash, and sizes are bounded (:data:`MAX_LEAVES`, :data:`MAX_DEPTH`) before anything is
built.
"""

from __future__ import annotations

import json
import math

#: The ``parameter.location`` of a JSON-leaf point.
LOCATION = "json"
#: The ``form.enctype`` of a captured JSON request's stored body.
ENCTYPE = "application/json"
#: A body with more leaves than this is not imported (no partial body is ever sent).
MAX_LEAVES = 64
#: A body nested deeper than this is not imported.
MAX_DEPTH = 16
#: A list index larger than this is malformed (a stored path never needs one).
MAX_INDEX = 10_000

_ESCAPED = "\\.[]"


class JsonPlacementError(ValueError):
    """A JSON leaf cannot be placed (a malformed name or entry list)."""


def _reject_constant(name):                 # NaN, Infinity: not JSON (RFC 8259)
    raise ValueError(f"non-standard JSON constant {name}")


def loads(text):
    """Strict JSON: NaN/Infinity rejected, as is an over-long integer (``ValueError``)."""
    return json.loads(text, parse_constant=_reject_constant)


def _is_segment(seg) -> bool:
    if isinstance(seg, bool):
        return False
    if isinstance(seg, int):
        return 0 <= seg <= MAX_INDEX
    return isinstance(seg, str)


def _is_scalar(value) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _is_leaf_value(value) -> bool:
    return _is_scalar(value) or value == {} or value == []


def leaves(body) -> list[tuple[tuple, object]] | None:
    """``(path, value)`` for every leaf of a JSON **object** body, in document order, or
    None when ``body`` is not an object, has more than :data:`MAX_LEAVES` leaves, nests
    deeper than :data:`MAX_DEPTH`, or holds a value JSON cannot carry. An empty object or
    list is a leaf (kept, so a rebuilt body has the app's shape); the root object
    itself is never one."""
    if not isinstance(body, dict):
        return None
    out: list[tuple[tuple, object]] = []
    stack = [((), body, 0)]
    while stack:
        path, node, depth = stack.pop()
        if depth > MAX_DEPTH:
            return None
        if isinstance(node, dict) and (node or not path):
            items = [(k, v) for k, v in node.items()]
            if not all(isinstance(k, str) for k, _v in items):
                return None
        elif isinstance(node, list) and node:
            items = list(enumerate(node))
        else:
            if not _is_leaf_value(node):
                return None
            out.append((path, node))
            if len(out) > MAX_LEAVES:
                return None
            continue
        for key, child in reversed(items):       # reversed: pop keeps document order
            stack.append((path + (key,), child, depth + 1))
    return out


def is_point_value(value) -> bool:
    """A leaf that may become a parameter: a string, number or bool (never null or an
    empty container)."""
    return isinstance(value, (str, bool, int)) or (isinstance(value, float)
                                                   and math.isfinite(value))


def _escape(key: str) -> str:
    return "".join("\\" + ch if ch in _ESCAPED else ch for ch in key)


def display_name(path) -> str:
    """The parameter name of ``path``: keys joined by ``.``, indexes as ``[n]``, with
    ``\\ . [ ]`` escaped inside a key. The first segment is always a key (an object
    body's leaf)."""
    out = []
    for i, seg in enumerate(path):
        if isinstance(seg, bool) or not isinstance(seg, (str, int)):
            raise JsonPlacementError(f"not a path segment: {seg!r}")
        if isinstance(seg, int):
            out.append(f"[{seg}]")
        else:
            out.append(("." if i else "") + _escape(seg))
    return "".join(out)


def parse_name(name) -> tuple | None:
    """The path :func:`display_name` gave ``name``, or None when ``name`` is not such a
    name (a dangling or unknown escape, an unclosed, non-numeric or zero-padded index,
    text right after an index). Linear in ``len(name)``."""
    if not isinstance(name, str):
        return None
    path: list = []
    key: list[str] = []
    i, n = 0, len(name)
    in_key = True                       # the first segment is a key, possibly ""
    while i < n:
        ch = name[i]
        if ch == "\\":
            if i + 1 >= n or name[i + 1] not in _ESCAPED or not in_key:
                return None
            key.append(name[i + 1])
            i += 2
        elif ch == ".":
            if in_key:
                path.append("".join(key))
            key, in_key = [], True
            i += 1
        elif ch == "[":
            if in_key:                  # at 0 too: "[0]" is the path ("", 0)
                path.append("".join(key))
                key, in_key = [], False
            end = name.find("]", i)
            digits = name[i + 1:end] if end > 0 else ""
            if not digits.isdigit() or not digits.isascii() or len(digits) > 5 \
                    or (len(digits) > 1 and digits[0] == "0"):
                return None
            index = int(digits)
            if index > MAX_INDEX:
                return None
            path.append(index)
            i = end + 1
            if i < n and name[i] not in ".[":
                return None
        elif ch == "]":
            return None
        else:
            if not in_key:
                return None
            key.append(ch)
            i += 1
    if in_key:
        path.append("".join(key))
    return tuple(path)


def name_segment(path) -> str:
    """The key a name rule matches: the path's last object key (``user.tags[0]`` ->
    ``tags``), so ``email``, ``q`` and ``url`` match however deep they sit."""
    for seg in reversed(tuple(path)):
        if isinstance(seg, str):
            return seg
    return ""


def segments_of(name: str) -> list[str]:
    """Every object key of a JSON point's name (credential and sensitive checks run on
    each, FR-AUD-22); the name itself when it does not parse."""
    path = parse_name(name)
    if path is None:
        return [name or ""]
    return [seg for seg in path if isinstance(seg, str)]


def decode_entries(raw) -> list[tuple[tuple, object]] | None:
    """The one reader of a stored JSON entry list (PA-0108): ``[[path array, value],
    ...]`` as text (or already parsed) -> ``[(path tuple, value)]``; None when the shape
    or a type is wrong, a path repeats or nests inside another leaf, or the list is too
    long. The caller fails closed on None."""
    try:
        data = loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(data, (list, tuple)) or not data or len(data) > MAX_LEAVES:
        return None
    out: list[tuple[tuple, object]] = []
    seen: set[tuple] = set()
    for item in data:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            return None
        path, value = item
        if not isinstance(path, (list, tuple)) or not path or len(path) > MAX_DEPTH + 1:
            return None
        path = tuple(path)
        if not isinstance(path[0], str) or not all(_is_segment(s) for s in path):
            return None
        if not _is_leaf_value(value) or path in seen:
            return None
        seen.add(path)
        out.append((path, value))
    try:
        build(out)                       # a path inside another leaf is malformed
    except JsonPlacementError:
        return None
    return out


def encode_entries(entries) -> str:
    """A JSON entry list as stored in ``form.entries`` (paths as arrays)."""
    return json.dumps([[list(path), value] for path, value in entries],
                      ensure_ascii=False, allow_nan=False)


def _child(container, seg, nxt):
    """The container under ``seg`` (created as nxt's kind when absent)."""
    fresh = [] if isinstance(nxt, int) else {}
    if isinstance(container, dict):
        if not isinstance(seg, str):
            raise JsonPlacementError("an index under an object")
        node = container.setdefault(seg, fresh)
    else:
        if not isinstance(seg, int) or isinstance(seg, bool) or seg > MAX_INDEX:
            raise JsonPlacementError("a key under a list")
        while len(container) <= seg:
            container.append(None)
        if container[seg] is None:
            container[seg] = fresh
        node = container[seg]
    if not isinstance(node, (dict, list)) or type(node) is not type(fresh):
        raise JsonPlacementError("a path runs through a leaf")
    return node


def build(entries) -> dict:
    """The JSON object ``entries`` describe, values with their types. A list index
    beyond the current end pads with null (never happens for a captured body). Raises
    `JsonPlacementError` for paths that conflict."""
    root: dict = {}
    leaf_paths: set[tuple] = set()
    inner: set[tuple] = set()                    # every proper prefix of a leaf path
    for path, value in entries:
        path = tuple(path)
        if not path or not isinstance(path[0], str):
            raise JsonPlacementError(f"bad path {path!r}")
        prefixes = [path[:k] for k in range(1, len(path))]
        if path in leaf_paths or path in inner or any(p in leaf_paths for p in prefixes):
            raise JsonPlacementError("a path repeats or runs through another leaf")
        leaf_paths.add(path)
        inner.update(prefixes)
        if isinstance(value, (dict, list)):
            if value:
                raise JsonPlacementError("a non-empty container is not a leaf value")
            value = type(value)()               # a fresh one: entries never shared
        node = root
        for seg, nxt in zip(path, path[1:]):
            node = _child(node, seg, nxt)
        last = path[-1]
        if isinstance(node, dict):
            if not isinstance(last, str):
                raise JsonPlacementError("an index under an object")
            node[last] = value
        else:
            if not isinstance(last, int) or isinstance(last, bool) or last > MAX_INDEX:
                raise JsonPlacementError("a key under a list")
            while len(node) <= last:
                node.append(None)
            node[last] = value
    return root


def normalize_entries(entries) -> list[tuple[tuple, object]]:
    """``entries`` (as bound on a candidate: paths may be lists after a JSON round trip
    through evidence) checked and with tuple paths. Raises `JsonPlacementError`."""
    out = decode_entries([[list(p) if isinstance(p, (list, tuple)) else p, v]
                          for p, v in entries]) if entries else None
    if out is None:
        raise JsonPlacementError("malformed JSON entry list")
    return out


def replace_leaf(entries, name: str, value) -> list[tuple[tuple, object]]:
    """A copy of ``entries`` with the leaf ``name`` names set to ``value``. Raises
    `JsonPlacementError` for a malformed name, and when ``entries`` is a captured body
    that has no such leaf: a leaf is never added to an app's body, which would send a
    request the app never made (refuse, never relocate: PA-0115). Only an empty entry
    list (no captured body) takes the leaf as the whole body."""
    path = parse_name(name)
    if path is None:
        raise JsonPlacementError(f"not a JSON point name: {name!r}")
    out = [(p, value if p == path else v) for p, v in entries]
    if not any(p == path for p, _v in out):
        if out:
            raise JsonPlacementError(f"the body has no leaf {name!r}")
        out.append((path, value))
    return out


def body_for(param: str, value: str, entries=None) -> bytes:
    """The body a ``json`` send carries: ``entries`` rebuilt (types kept) with leaf
    ``param`` set to ``value`` as a string -- or, with no entries, ``{param: value}``
    nested along the path. UTF-8, compact. Raises `JsonPlacementError` when the leaf
    cannot be placed, including a leaf the entries do not have (the sender then
    refuses, never relocates: PA-0115)."""
    base = normalize_entries(entries) if entries else []
    body = build(replace_leaf(base, param, str(value)))
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def body_with(entries, values) -> bytes:
    """The body ``entries`` describe with each leaf ``values`` names set to its value
    **as a typed JSON value** -- a string, a number, or an object such as a query
    operator (``{"$ne": …}``, the NoSQL operator probe, FR-FUZZ-54) -- where
    :func:`body_for` always sends a string. A name the entries lack is refused, never
    added (PA-0115); so is a value JSON cannot carry. Raises `JsonPlacementError`."""
    base = normalize_entries(entries)
    have = {p for p, _v in base}
    paths = {}
    for name in values:
        path = parse_name(name)
        if path is None or path not in have:
            raise JsonPlacementError(f"the body has no leaf {name!r}")
        paths[name] = path
    body = build(base)
    for name, value in values.items():
        node = body
        *parents, last = paths[name]
        for seg in parents:
            node = node[seg]
        node[last] = value
    try:
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise JsonPlacementError(f"a value JSON cannot carry: {exc}") from None

