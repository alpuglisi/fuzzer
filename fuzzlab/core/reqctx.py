"""The request-context identity (SP-57, FR-FUZZ-66; BUG-0530): which rows are one test.

A *request context* is everything that decides the request a test sends and the
observations it makes, other than the payload: the origin, path, method and location;
the target's own slot (a name, every occurrence of it under the bound rule, its first
under the standalone rule, or a JSON leaf's path); the URL's raw query parts; the
sibling entries, as sent; the body's content type; the setup steps that run before
each send (a stored case's store request, a fresh-binding fetch of a form's page,
FR-FUZZ-67); a sibling the replay refuses to send; and the run's identity scope.

It is versioned (``v``). `context_id` names it; `confirmation_key` is the one key the
pipeline confirms on, the point builder deduplicates on (`point_key`) and the ML label
join compares against a finding's recorded key. Two rows share a test only when their
contexts are equal: the same wire request for every probe and the same observation
steps. The target's own original value is not in the context (a probe replaces it); it
is the *seed* (a digest), in the key only for the categories whose strategies read it
(`SEED_CATEGORIES`).

Everything here is computed from a candidate's evidence (`point_evidence` is that
evidence for a point), so a row written before this identity existed gets its context
on read: nothing is migrated, and nothing a row does not record is invented (its
identity scope reads as unrecorded). Values in the context are the evidence's own,
already redacted (PA-0100); the seed holds only a digest (D12).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from urllib.parse import urlsplit

from fuzzlab.core.urls import QueryEntries, canonical_origin

#: The identity's version: a reader compares contexts only within one version.
CONTEXT_VERSION = 1
#: A context id's prefix names its version.
CONTEXT_PREFIX = f"rc{CONTEXT_VERSION}-"
#: The target's slot in a context (the payload goes there; its original value is the seed).
TARGET = "\x00target"
FORM_URLENCODED = "application/x-www-form-urlencoded"
_JSON = "application/json"

#: Categories whose strategies read the target's own original value, so two contexts
#: that differ only in it are two tests for them (and one for every other category):
#: access-control replays the value the crawl saw (`CrossAccountReplayStrategy`),
#: open-redirect sends its crawled seed, command-injection starts from the base value,
#: nosql-injection reads the leaf's original type. Derived from `oracle/strategies.py`
#: by `tests/test_request_contexts.py::test_the_seed_categories_are_the_strategies_that_read_the_original_value`.
SEED_CATEGORIES = frozenset({"access-control", "open-redirect", "command-injection",
                             "nosql-injection"})

#: Every `oracle.probe.Candidate` field, classified (PA-0530(2)): in the identity (with
#: the context field it becomes) or excluded (with the reason). A new field is in
#: neither until someone decides, and the guard test fails.
CANDIDATE_FIELDS_IN_IDENTITY: dict[str, str] = {
    "url": "origin, path, raw query parts and fragment",
    "param": "target",
    "method": "method",
    "location": "location (and the placement rule)",
    "content_type": "content_type",
    "base_entries": "entries (the target's slot as TARGET; its value is the seed)",
    "store_url": "setup: the store step",
    "store_param": "setup: the store step",
    "store_method": "setup: the store step",
    "store_location": "setup: the store step",
    "store_entries": "setup: the store step",
    "bindings": "setup: the fresh-binding step (FR-FUZZ-67)",
    "replay_refusal": "refused (a sibling the replay never sends)",
    "category": "the confirmation key's second member",
    "base_value": "the seed (command-injection's starting value)",
    "redirect_seed": "the seed (open-redirect's crawled seed)",
}
CANDIDATE_FIELDS_EXCLUDED: dict[str, str] = {
    "vuln_class": "a hint; the category is in the key",
    "sink_context": "an audit label, never on the wire (PA-0048's duplicates stay one test)",
    "decided_by": "which mechanism decides; merged per key (FR-AUD-30)",
    "context_id": "derived from the identity",
    "context_key": "derived from the identity",
}


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()[:32]


def _is_json(location) -> bool:
    from fuzzlab.core.jsonbody import LOCATION
    return location == LOCATION


def _leaf_name(path) -> str | None:
    from fuzzlab.core import jsonbody
    try:
        return jsonbody.display_name(path if isinstance(path, (list, tuple)) else [path])
    except jsonbody.JsonPlacementError:
        return None


def _is_target(name_or_path, param: str, location) -> bool:
    if _is_json(location):
        return _leaf_name(name_or_path) == param
    return name_or_path == param


def _entries(entries, param: str, location):
    """The sibling entries as sent, each occurrence of the target as `TARGET` (the bound
    rule replaces every occurrence, `core.forms.FormEntries.replace`)."""
    out = []
    for entry in entries or ():
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            out.append(["\x00malformed", entry])
            continue
        name, value = entry
        if isinstance(name, tuple):
            name = list(name)
        out.append([name, TARGET if _is_target(name, param, location) else value])
    return out


def _split(url: str):
    """``urlsplit(url)``, or None for a URL it cannot parse (an unclosed IPv6 bracket):
    the identity is total, such a URL is then its own opaque text."""
    try:
        return urlsplit(url)
    except ValueError:
        return None


def _origin(url: str):
    try:
        return canonical_origin(url)
    except ValueError:
        return None


def _query(url: str, param: str, standalone_query: bool) -> list[str]:
    """The URL's raw query parts in order; under the standalone rule
    (`core.urls.place_query_param`) the first part named ``param`` is the target's slot,
    appended once when there is none."""
    split = _split(url)
    parts = list(QueryEntries.parse(split.query).parts) if split is not None else []
    if standalone_query:
        for i, part in enumerate(parts):
            if QueryEntries.name_of(part) == param:
                parts[i] = TARGET
                break
        else:
            parts.append(TARGET)
    return parts


def _setup(ev: Mapping) -> list:
    """The steps that run before each send of the test, in order."""
    steps = []
    bindings = ev.get("bindings")
    if isinstance(bindings, Mapping) and bindings.get("fresh"):
        steps.append({"step": "bind", "page": bindings.get("page"),
                      "fresh": list(bindings.get("fresh") or ())})
    if ev.get("store_url"):
        store_location = ev.get("store_location") or "body"
        store_param = ev.get("store_param") or ev.get("param") or ""
        store_entries = ev.get("store_entries")
        store = str(ev["store_url"])
        split = _split(store)
        steps.append({"step": "store",
                      "origin": _origin(store),
                      "path": (split.path or "/") if split is not None else store,
                      "query": _query(store, "", False),
                      "method": str(ev.get("store_method") or "POST").upper(),
                      "location": store_location, "param": store_param,
                      "entries": (_entries(store_entries, store_param, store_location)
                                  if store_entries is not None else None)})
    return steps


def request_context(ev: Mapping) -> dict:
    """The request context of a candidate's evidence (or of `point_evidence`): a
    canonical, JSON-able dict. Total and deterministic."""
    url = str(ev.get("url") or "")
    parts = _split(url)
    param = str(ev.get("param") or "")
    location = str(ev.get("location") or "query")
    entries = ev.get("entries")
    # a JSON leaf is always placed into a body; query and body points with siblings are
    # bound (every occurrence), without them standalone (the first occurrence)
    bound = (entries is not None and location in ("query", "body")) or _is_json(location)
    content_type = ev.get("body_content_type") or (
        _JSON if _is_json(location) else FORM_URLENCODED if location == "body" else None)
    return {
        "v": CONTEXT_VERSION,
        "origin": _origin(url),
        "path": (parts.path or "/") if parts is not None else url,   # opaque if unparsable
        "query": _query(url, param, location == "query" and not bound),
        "fragment": (parts.fragment or None) if parts is not None else None,
        "method": str(ev.get("method") or "GET").upper(),
        "location": location,
        "target": param.lower() if location == "header" else param,
        "placement": "bound" if bound else "standalone",
        "content_type": content_type,
        "entries": _entries(entries, param, location) if entries is not None else None,
        "setup": _setup(ev),
        "refused": ev.get("replay_refusal") or None,
        "identity": ev.get("identity_scope"),
    }


def context_id(ev: Mapping) -> str:
    """The context's id: the one stamped on the evidence by `stamp`, or, for a row
    written before (or without) it, computed on read from the same fields."""
    stamped = ev.get("context_id")
    if isinstance(stamped, str) and stamped.startswith(CONTEXT_PREFIX):
        return stamped
    return CONTEXT_PREFIX + _digest(request_context(ev))


def seed(ev: Mapping) -> str:
    """A digest of what the target starts from (never the value, D12): its own original
    value in the entries, the command-injection base value, the open-redirect seed."""
    param = str(ev.get("param") or "")
    location = ev.get("location") or "query"
    own = [entry[1] for entry in (ev.get("entries") or ())
           if isinstance(entry, (list, tuple)) and len(entry) == 2
           and _is_target(entry[0], param, location)]
    return "s1-" + _digest([own, ev.get("base_value"), ev.get("redirect_seed")])


def confirmation_key(ev: Mapping) -> tuple[str, ...]:
    """The one key rows are confirmed on (FR-FUZZ-66): the context id and the category,
    plus the seed for a category whose strategies read the original value. Rows share a
    test, a budget slot and a status only when their keys are equal."""
    category = str(ev.get("category") or "")
    key = (context_id(ev), category)
    return key + ((seed(ev),) if category in SEED_CATEGORIES else ())


def point_evidence(point) -> dict:
    """The wire fields of an `audit.engine.InjectionPoint`, as its candidates' evidence
    records them (the engine writes exactly these; the builder keys on them)."""
    ev: dict = {"url": point.url, "param": point.param, "method": point.method,
                "location": point.location}
    if point.store_url:                                  # stored-XSS store endpoint (M6)
        ev["store_url"] = point.store_url
        ev["store_param"] = point.store_param or point.param
        ev["store_method"] = point.store_method
        ev["store_location"] = point.store_location
        if point.store_entries is not None:
            ev["store_entries"] = [list(e) for e in point.store_entries]
    if point.body_content_type:
        ev["body_content_type"] = point.body_content_type
    if point.base_entries is not None:
        ev["entries"] = [list(e) for e in point.base_entries]
    bindings = getattr(point, "bindings", None)
    if bindings:                                         # FR-FUZZ-67: names, a page; no value
        ev["bindings"] = {"page": bindings[0], "fresh": list(bindings[1])}
    refusal = getattr(point, "replay_refusal", None)
    if refusal:
        ev["replay_refusal"] = refusal
    return ev


def point_key(point, identity: str | None = None) -> tuple[str, str]:
    """``(context id, seed)`` of a point: two points are one point only when both are
    equal (the builder's dedup; the seed keeps the categories that read it apart)."""
    ev = point_evidence(point)
    ev["identity_scope"] = identity
    ev["base_value"] = point.base_value
    ev["redirect_seed"] = point.redirect_seed
    return context_id(ev), seed(ev)


def stamp(evidence: dict, identity: str | None) -> dict:
    """Write the run's identity scope and the context id into a candidate's evidence
    (the audit engine, once per fired rule)."""
    evidence["identity_scope"] = identity
    evidence["context_id"] = CONTEXT_PREFIX + _digest(request_context(evidence))
    return evidence
