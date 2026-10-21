"""Automatic-mode entry point: crawl results -> the Phase 2 pipeline (T2.8).

`run_auto` is the live glue over `run_pipeline`: it builds injection points from a
crawl already consolidated into the store (endpoint/parameter rows), resolves the
run plan (D14 categories from ground truth + scored, or D15 fail-safe), wraps the
probe sender in a request counter so the run's request cost is measured, and runs
the pipeline. `fuzzlab auto` (see `auto_cli`) wires this to the CLI.

Injection points use the endpoint's **full** URL (base + stored path) with no query
string, so the probe sender adds `?param=value` cleanly (the stored path is in
path form via `core.urls.to_path`).
"""

from __future__ import annotations

import json

from fuzzlab.audit import InjectionPoint, known_categories
from fuzzlab.audit.value_shape import (SAFE_HOST, names_outside_lab, neutral_value,
                                       redirect_seed, value_shape)
from fuzzlab.core.redaction import is_credential_name
from fuzzlab.core.runmode import (RunModeError, RunPlan, categories_from_vuln_classes,
                                   resolve_run)
from fuzzlab.harness.pipeline import PipelineResult, run_pipeline
from fuzzlab.oracle.strategies import DomXssStrategy, StoredXssStrategy


def _decider(cls) -> tuple[str, str]:
    """``(category, arm)`` of the one strategy that decides a point (FR-AUD-30), taken
    from the strategy's own attributes, never spelled again here (PA-0001)."""
    return cls.category, f"{cls.vuln_class}:{cls.mechanism}"


#: The mechanism that alone decides a stored case's observe point, and a ground-truth
#: DOM point (BUG-0523): the browser executes the payload, or nothing observes it.
STORED_DECIDER = _decider(StoredXssStrategy)
DOM_DECIDER = _decider(DomXssStrategy)
#: Every deciding mechanism a point builder writes (checked against the default arms by
#: `tests/test_unplaceable_confirmation.py`).
DECIDERS = (STORED_DECIDER, DOM_DECIDER)


def points_from_ground_truth(ground_truth, base_url: str, browser_available: bool = False,
                             writes: bool = False, account_values=None):
    """Injection points from the enumerated ground-truth contract (detection benchmark).

    Returns ``(points, skipped)``. Server-rendered **GET query**, **POST body**,
    and **header-carried** (``location="header"``, e.g. a webhook-signature check
    against a header value -- `CC-LAB-0174`'s `TWCH-0001`) params are always
    audited (`CC-FUZZ-0032`/`FR-FUZZ-19` closed the header gap `FR-FUZZ-13`
    originally flagged: `fuzzlab.tools.probesender`'s senders now carry a
    header-injection convention). Client-only/DOM points (fragment,
    ``client_only``, or ``rendering=js``) are audited only when a **browser**
    is available (M6); otherwise they are returned as ``skipped`` (path,
    method, param, reason) so the gap is explicit and they score as false
    negatives until a browser is provided -- the only remaining "skipped"
    reason this function has.

    A **PUT/PATCH** point (FR-FUZZ-56) is probed like a POST one, only with ``writes``
    (`fuzzlab auto --fuzz-json-writes`, the opt-in crawled PUT/PATCH requests need:
    each probe updates what the request targets); without it, it is skipped. A DOM
    point is a GET page; a DOM point with another method is skipped, never rewritten
    into a GET (BUG-0115). DELETE is not in the contract.

    A **path** point (``/ticket/{id}``, FR-FUZZ-57) keeps its template as its URL; the
    senders place each value in that segment. A point naming an ``account_value``
    (FR-LAB-309) carries that value of the run's own account (``account_values``, from
    the credential store) as its own; without it the point is skipped.
    """
    from fuzzlab.tools.store_adapter import WRITE_METHODS   # the one opt-in set
    base = base_url.rstrip("/")
    points: list[InjectionPoint] = []
    skipped: list[tuple[str, str, str, str]] = []
    # The enumerated *points* (`injection-points.json`) carry no `sink_context`
    # at all (`fuzzlab.labels.contract.InjectionPoint` is deliberately slim --
    # just what surface to probe); `sink_context` lives on the scoring
    # `Case` (`labels.json`) instead. A rule keyed on `sink_context_in`
    # (`R-INSECURE-DESERIALIZATION`, `CC-FUZZ-0034`) needs it on the audited
    # point too, so look it up by the same (url, method, param) identity a
    # point and its case share.
    #
    # `BUG-0046`/`PA-0048`: a (url, method, param) key is NOT always
    # one-case-per-point -- `fuzzlab.labels.contract`'s own supported
    # multi-vuln_class-per-endpoint pattern (`Case.key` includes
    # `vuln_class`, e.g. Twitch's `TWCH-0013`/`TWCH-0015`, both at
    # `/generated/labgen-go-0025`/`destination`, `sink_context="header"`
    # vs `"redirect"` respectively) means more than one DISTINCT
    # `sink_context` can legitimately apply to the same point. A plain
    # `{key: sink_context}` dict comprehension here silently kept only
    # whichever case happened to be LAST in `ground_truth.cases`' own
    # iteration order, discarding the other -- a `sink_context_in`-gated
    # rule for the discarded case's own vuln_class then never fired for
    # this point at all, an unconditional false negative for as long as
    # any two cases have shared a (url, method, param) key with different
    # `sink_context` values (found empirically: `CC-FUZZ-0045`'s new
    # `R-HEADER-INJECTION`/`sink_context_in=["header"]` rule never
    # generated a candidate for `TWCH-0013` in a real `run_targets` run,
    # despite `HttpHeaderInjectionCrlfStrategy` confirming the identical
    # candidate directly when hand-built, because this dict's last-write-
    # wins collapse had already overwritten `"header"` with `TWCH-0015`'s
    # own `"redirect"` for that same key). Fixed by keeping every DISTINCT
    # `sink_context` value per key (a `set`, not a scalar) and emitting one
    # audited `InjectionPoint` per distinct value below -- `fuzzlab.harness.
    # scoring.score`'s own `detected_keys` is a `set` keyed on `(url,
    # method, param, vuln_class)` (never `sink_context`), so a duplicate
    # point differing only in `sink_context` costs at most one extra,
    # harmless re-probe of every OTHER (non-`sink_context`-gated) rule for
    # that one point -- never a double-counted TP/FP, verified by
    # `scoring.py`'s own set-based dedup logic before relying on it here.
    sink_contexts_by_point: dict[tuple[str, str, str], set[str | None]] = {}
    for c in ground_truth.cases:
        key = (c.url if c.url.startswith("/") else "/" + c.url, c.method.upper(), c.param)
        sink_contexts_by_point.setdefault(key, set()).add(c.sink_context)
    for gp in ground_truth.points:
        path = gp.url if gp.url.startswith("/") else "/" + gp.url
        is_dom = (gp.client_only or (gp.rendering or "") == "js"
                  or gp.location == "fragment")
        method = gp.method.upper()
        if method in WRITE_METHODS and not writes:
            skipped.append((path, gp.method, gp.param,
                            f"{method} probed only with --fuzz-json-writes"))
            continue
        own = None
        if gp.account_value is not None:
            own = (account_values or {}).get(gp.account_value)
            if not own:
                skipped.append((path, gp.method, gp.param,
                                f"needs the run's own account's {gp.account_value!r} "
                                "(--identity; stored by the lab's bootstrap)"))
                continue
        if not is_dom and method in ("GET", "POST", *WRITE_METHODS) \
                and gp.location in ("query", "body", "header", "path"):
            # A whole-body point (`param="body"`) whose ground truth marks it
            # `rendering="server-json"` declares its real content type, so the
            # sender can send the raw body correctly instead of assuming JSON
            # for every body point (CC-FUZZ-0032/FR-FUZZ-19: some are XML/
            # binary-serialized, e.g. TrackerNest's XXE/insecure-deserialization
            # cases, which stay form-encoded/unaffected -- `body_content_type`
            # is `None` for those, same as before this change).
            body_content_type = (
                "application/json"
                if gp.param == "body" and gp.location == "body" and gp.rendering == "server-json"
                else None
            )
            sink_contexts = sink_contexts_by_point.get(
                (path, gp.method.upper(), gp.param), {None})
            # FR-FUZZ-54: a point with the JSON body its endpoint takes is a JSON-leaf
            # point, its probes carrying the other leaves, as a crawled JSON request is
            location, entries, refusal = gp.location, None, None
            if gp.json_body is not None and gp.location == "body":
                from fuzzlab.core import jsonbody
                location = jsonbody.LOCATION
                leaves = jsonbody.leaves(gp.json_body) or ()
                entries = tuple((p, own if own and jsonbody.display_name(p) == gp.param
                                 else _send_value(v)) for p, v in leaves)
                refusal = _outside_lab(leaves, gp.param)               # FR-FUZZ-67
                body_content_type = None
            elif own:                          # the account's own value (FR-LAB-309)
                entries = ((gp.param, own),)
            for sink_context in sorted(sink_contexts, key=lambda s: s or ""):
                points.append(InjectionPoint(url=(gp.origin or base) + path,
                                             param=gp.param,
                                             method=gp.method.upper(), location=location,
                                             body_content_type=body_content_type,
                                             base_entries=entries,
                                             sink_context=sink_context,
                                             origin="ground-truth",
                                             replay_refusal=refusal))
        elif is_dom and method != "GET":
            skipped.append((path, gp.method, gp.param,
                            f"a DOM point is a GET page, not {method}"))
        elif is_dom and browser_available:
            # BUG-0115 sweep: no ground-truth DOM point has another location today
            # (pinned by tests/test_forms_phase2.py); the rewrite is left as is
            loc = gp.location if gp.location in ("query", "fragment") else "query"
            points.append(InjectionPoint(url=(gp.origin or base) + path, param=gp.param,
                                         method="GET", location=loc,
                                         origin="ground-truth",
                                         decided_by=DOM_DECIDER))    # FR-AUD-30
        else:
            skipped.append((path, gp.method, gp.param,
                            "client-only/DOM (needs browser execution, M6)"))

    # Stored XSS lives in the *cases* (observe url + source_url store endpoint), not the
    # enumerated points. Audit it only with a browser (M6): plant at source_url, observe.
    for case in ground_truth.cases:
        if case.vuln_class != "xss-stored" or not case.source_url:
            continue
        opath = case.url if case.url.startswith("/") else "/" + case.url
        # FR-LAB-308: a store endpoint on another origin of the lab is an absolute URL
        # (loopback, checked at load)
        store_url = case.source_url if "://" in case.source_url else \
            base + (case.source_url if case.source_url.startswith("/")
                    else "/" + case.source_url)
        # FR-FUZZ-56: the store request as the ground truth enumerates it (its point at
        # the store URL: method, JSON body); a form POST when it is not enumerated
        store_method, store_location, store_entries = "POST", "body", None
        refusal = None
        for sp in ground_truth.points:
            spath = sp.url if sp.url.startswith("/") else "/" + sp.url
            if (sp.origin or base) + spath == store_url and sp.param == case.param:
                store_method, store_location = sp.method.upper(), sp.location
                if sp.json_body is not None and sp.location == "body":
                    from fuzzlab.core import jsonbody
                    store_location = jsonbody.LOCATION
                    leaves = jsonbody.leaves(sp.json_body) or ()
                    store_entries = tuple((p, _send_value(v)) for p, v in leaves)
                    refusal = _outside_lab(leaves, case.param)          # FR-FUZZ-67
                break
        if store_method in WRITE_METHODS and not writes:
            skipped.append((opath, case.method, case.param,
                            f"stored XSS through {store_method}: probed only with "
                            "--fuzz-json-writes"))
        elif browser_available:
            points.append(InjectionPoint(
                url=(case.origin or base) + opath, param=case.param, method=case.method,
                location=case.location, store_url=store_url, store_param=case.param,
                store_method=store_method, store_location=store_location,
                store_entries=store_entries, origin="ground-truth",
                decided_by=STORED_DECIDER,                               # FR-AUD-30
                replay_refusal=refusal))
        else:
            skipped.append((opath, case.method, case.param,
                            "stored XSS (needs browser execution, M6)"))
    return points, skipped


#: A crawl- or form-sourced parameter with a credential name token is never fuzzed (the
#: one predicate lives in `core.redaction` since forms phase 2, CC-CORE-0042).
_credential_name = is_credential_name


def _send_value(value):
    """What the fuzzer sends for an app-supplied default: the value as the app gave it
    (the importer's own fillers, a value naming no network location, or one naming
    loopback -- the lab itself, D11), else loopback in place of a value naming a host
    outside the lab (FR-AUD-20). A request that needs such a sibling is never sent with
    the stand-in either: `_outside_lab` names it and the point carries a
    ``replay_refusal`` (FR-FUZZ-67, BUG-0544)."""
    from fuzzlab.tools.store_adapter import is_filler
    return value if is_filler(value) or not names_outside_lab(value) else neutral_value(value)


def _outside_lab(entries, target) -> str | None:
    """Why a request whose sibling ``entries`` (as stored, before `_send_value`) name a
    host outside the lab can never be rebuilt, or None. The target's own entry is the
    payload's slot, never a sibling (a probe replaces it)."""
    from fuzzlab.core import jsonbody
    from fuzzlab.tools.store_adapter import is_filler
    names = []
    for name, value in entries or ():
        own = (jsonbody.display_name(name) if isinstance(name, (list, tuple)) else name)
        if own != target and not is_filler(value) and names_outside_lab(value):
            names.append(own)
    if not names:
        return None
    return (f"sibling {', '.join(dict.fromkeys(names))} names a host outside the lab "
            "(FR-AUD-20): the request cannot be rebuilt without a stand-in")


def _shapes(example) -> frozenset[str]:
    shape = value_shape(example)
    return frozenset() if shape is None else frozenset({shape})


def _password_fields(raw) -> tuple[str, ...] | None:
    """The one reader of `form.password_fields` (PA-0108): a JSON list of strings, or
    None when the stored value is malformed (the caller fails closed)."""
    try:
        value = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return None
    return tuple(value)


def _crawl_url(stored: str, origin: str) -> tuple[str, str | None]:
    """``(url, refusal)`` of a stored page or endpoint (FR-AUD-27): the URL it names
    (`core.urls.stored_absolute`: a path under the run's origin, an absolute URL as
    stored), and why it is never probed: another origin that is not loopback (D11)."""
    from fuzzlab.core.urls import canonical_origin, is_loopback_origin, stored_absolute
    url = stored_absolute(stored, origin)
    other = canonical_origin(url)
    if other != canonical_origin(origin) and not is_loopback_origin(other):
        return url, "another origin, not loopback (D11)"
    return url, None


def _stored_key(stored: str) -> str:
    """A stored URL as reported (a skip row): a path with its leading ``/``, an absolute
    URL as stored."""
    if stored.startswith(("http://", "https://", "/")):
        return stored
    return "/" + stored


def _login_form_paths(store, run_id: int, base_url: str) -> dict[str, frozenset | None]:
    """``{url_key: password-control names}`` of every path with an in-app login form in
    this run (None: a malformed row — the path is isolated and all its points dropped)."""
    from urllib.parse import urlsplit

    from fuzzlab.core.urls import url_key
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    out: dict[str, frozenset | None] = {}
    for r in store.conn.execute(
            "SELECT e.url AS path, f.password_fields AS pw FROM form f "
            "JOIN endpoint e ON e.id = f.endpoint_id WHERE f.run_id = ?", (run_id,)):
        key = url_key(_crawl_url(r["path"], origin)[0])
        names = _password_fields(r["pw"])
        if names is None:
            out[key] = None
        elif names and out.get(key, frozenset()) is not None:
            out[key] = frozenset(out.get(key, frozenset()) | set(names))
    return out


def isolated_paths_from_store(store, run_id: int, base_url: str) -> frozenset[str]:
    """The ``url_key`` (origin + path, no query) of every path with an in-app login form
    in this run: the paths a sender must never send the run's session to (FR-FUZZ-44).
    Path-level, for any method and any point source. The one derivation (PA-0003)."""
    return frozenset(_login_form_paths(store, run_id, base_url))


def _crawl_url_refusal(url: str) -> str | None:
    """Why a crawl point's URL is never fuzzed: a destructive URL, or a destructive
    SPA hash route (``/#/logout``), which `destructive_reason` alone does not read. The
    route's fragment (its path and query) is judged as a whole **text**
    (`core.urls.text_destructive_reason`), never re-joined into a URL, so a second
    ``#`` inside it hides nothing (``/#/a#/logout``; BUG-0131, CC-FUZZ-0077)."""
    from urllib.parse import urlsplit

    from fuzzlab.core.urls import (destructive_reason, is_spa_route_fragment,
                                   text_destructive_reason)
    reason = destructive_reason(url)
    fragment = urlsplit(url or "").fragment
    if reason is None and is_spa_route_fragment(fragment):
        reason = text_destructive_reason(fragment)
    return reason


def injection_points_from_store(store, run_id: int, base_url: str,
                                skipped: list | None = None,
                                isolated: set | None = None,
                                browser_available: bool = False) -> list[InjectionPoint]:
    """Build injection points from the run's endpoint/parameter rows.

    A point on a destructive URL (``core.urls.destructive_reason``: logout, reset,
    delete, ...) is never fuzzed from a crawl (NFR-FUZZ-safe, BUG-0112); it is appended
    to ``skipped`` as ``(path, method, param, reason)`` instead.

    A point on a path with an in-app login form (`isolated_paths_from_store`) needs an
    isolated session (FR-FUZZ-44). By default (``isolated`` None) such points are
    dropped and reported, so a caller that cannot isolate never fuzzes a login form
    with its session. A caller that can passes a set: it receives every such path's
    ``url_key`` and the points. A parameter named like a password control of a form on
    that path is never a point.

    A ``json`` point (a captured request's leaf, forms phase 3) carries its body's
    other leaves as ``base_entries`` (paths and typed values). A ``fragment`` point (an
    SPA hash route's query) is built only with ``browser_available``; without a browser
    it is reported, as ground truth's DOM points are.
    """
    from urllib.parse import urlsplit

    from fuzzlab.core import jsonbody
    from fuzzlab.core.urls import url_key
    # Stored crawl paths are absolute (`to_path`), so they join to the base URL's
    # origin, never its path: `--base-url .../bWAPP/` must not give /bWAPP/bWAPP/
    # (BUG-0113).
    parts = urlsplit(base_url)
    base = f"{parts.scheme}://{parts.netloc}"
    login_paths = _login_form_paths(store, run_id, base_url)
    if isolated is not None:
        isolated.update(login_paths)
    from fuzzlab.core import reqctx
    from fuzzlab.tools.store_adapter import is_filler
    rows = store.conn.execute(
        "SELECT e.url AS path, e.method AS method, p.name AS name, p.location AS location, "
        "p.example AS example, f.entries AS entries, f.source_page AS source_page, "
        "f.fresh AS fresh "
        "FROM parameter p JOIN endpoint e ON p.endpoint_id = e.id "
        "LEFT JOIN form f ON f.id = p.form_id "
        "WHERE p.run_id = ? ORDER BY p.id",
        (run_id,),
    ).fetchall()
    # (c2) a field whose own example says nothing ("" or our filler) takes the shapes
    # its name has elsewhere in the run: one pass over the rows (PA-0095)
    shapes_by_name: dict[str, set[str]] = {}
    for r in rows:
        shapes_by_name.setdefault(r["name"], set()).update(_shapes(r["example"]))
    points: list[InjectionPoint] = []
    # SP-57 (FR-FUZZ-66, BUG-0530): two rows are one point only when their request
    # contexts and seeds are equal -- never by (path, method, name), which merged a
    # name's query and body rows and every sibling set of it
    seen: set[tuple[str, str]] = set()
    for r in rows:
        path = _stored_key(r["path"])
        method = r["method"] or "GET"
        url, elsewhere = _crawl_url(path, base)      # its own origin kept (FR-AUD-27)
        if elsewhere is not None:
            if skipped is not None:
                skipped.append((path, method, r["name"], elsewhere))
            continue
        reason = _crawl_url_refusal(url)
        if reason is not None:
            if skipped is not None:
                skipped.append((path, method, r["name"], f"destructive URL ({reason!r})"))
            continue
        location = r["location"] or "query"
        if location == "fragment" and not browser_available:
            if skipped is not None:
                skipped.append((path, method, r["name"],
                                "client-only/DOM (needs browser execution, M6)"))
            continue
        names = (jsonbody.segments_of(r["name"]) if location == jsonbody.LOCATION
                 else [r["name"]])
        if any(_credential_name(n) for n in names):
            # never fill a credential with payloads (it could change the operator's
            # password); ground-truth points are not affected (reviewers A/B)
            if skipped is not None:
                skipped.append((path, method, r["name"], "credential parameter"))
            continue
        key = url_key(url)
        if key in login_paths:
            names = login_paths[key]
            why = ("malformed form row (password_fields)" if names is None else
                   "password control" if r["name"] in names else
                   None if isolated is not None else
                   "needs an isolated session (login form)")
            if why is not None:
                if skipped is not None:
                    skipped.append((path, method, r["name"], why))
                continue
        raw = None                                   # the stored entries, before sending
        if location == jsonbody.LOCATION:
            raw = jsonbody.decode_entries(r["entries"]) if r["entries"] else None
            if raw is None:
                if skipped is not None:
                    skipped.append((path, method, r["name"],
                                    "malformed form row (JSON entries)"))
                continue
        elif r["entries"]:
            try:
                raw = [(n, v) for n, v in json.loads(r["entries"])]
            except (ValueError, TypeError):
                raw = None
        elif location == "path" and r["example"]:
            # a crawled path segment (FR-AUD-26): its value, as a query link's is
            raw = [(r["name"], r["example"])]
        entries = None if raw is None else tuple((n, _send_value(v)) for n, v in raw)
        bindings = _bindings(r, base, raw, r["name"])
        if bindings is False:
            if skipped is not None:
                skipped.append((path, method, r["name"], "malformed form row (fresh)"))
            continue
        example = r["example"]
        shapes = _shapes(example)
        if example in (None, "") or is_filler(example):
            shapes = frozenset(shapes_by_name.get(r["name"], ()))
        point = InjectionPoint(url=url, param=r["name"],
                               method=method, location=location,
                               base_entries=entries, origin="crawl",
                               value_shapes=shapes,
                               base_value=(SAFE_HOST if shapes & {"ip", "hostname"}
                                           else None),
                               redirect_seed=redirect_seed(example),
                               bindings=bindings,
                               replay_refusal=_outside_lab(raw, r["name"]))
        key = reqctx.point_key(point)
        if key not in seen:
            seen.add(key)
            points.append(point)
    return points


def _bindings(row, origin: str, raw, target: str):
    """The replay recipe of a point's sibling set (FR-FUZZ-67, BUG-0544): ``(the page a
    fresh value is bound from, or None; the names whose stored value is a placeholder)``,
    the target excepted (a probe replaces it). None when no sibling needs one; False when
    the stored list is malformed (the point is dropped, PA-0108). The page is never one
    on another origin that is not loopback (D11)."""
    from fuzzlab.core import jsonbody
    try:
        fresh = json.loads(row["fresh"]) if row["fresh"] else []
    except ValueError:
        return False
    if not isinstance(fresh, list) or not all(isinstance(n, str) for n in fresh):
        return False
    have = {jsonbody.display_name(n) if isinstance(n, (list, tuple)) else n
            for n, _v in raw or ()}
    names = tuple(dict.fromkeys(n for n in fresh if n != target and n in have))
    if not names:
        return None
    page = None
    if row["source_page"]:
        from fuzzlab.core.urls import canonical_origin
        page, _elsewhere = _crawl_url(_stored_key(row["source_page"]), origin)
        point_url, _ = _crawl_url(_stored_key(row["path"]), origin)
        try:
            same = canonical_origin(page) == canonical_origin(point_url)
        except ValueError:
            same = False
        if not same:
            # a value read on another origin is another session's (SP-13; BUG-0544
            # review B6): no page, so the test is inconclusive
            page = None
    return page, names


def _path_of(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).path or "/"


#: Header points' names when ``--header-points`` is given bare.
DEFAULT_HEADER_POINTS = ("User-Agent", "Referer")


def header_point_cost() -> int:
    """A lower bound on the requests one header point costs when nothing is found:
    the sqli and xss confirmers' fixed probes, derived from the strategies themselves
    (PA-0001)."""
    from fuzzlab.oracle.strategies import (_TIMING_TEMPLATES, SqliBooleanStrategy,
                                           SqliErrorStrategy, SqliTimingStrategy)
    return (len(SqliErrorStrategy._probes)
            + 3 * len(SqliBooleanStrategy._FAMILIES)   # every family's screen (FR-FUZZ-45)
            + 1                                        # the SQL evaluation marker's probe
            + SqliTimingStrategy.baseline_samples + len(_TIMING_TEMPLATES)
            + 1)                                   # the reflected-XSS marker


def _header_page(status) -> bool:
    return status is not None and 200 <= int(status) <= 299


def header_points_from_store(store, run_id: int, base_url: str, names,
                             skipped: list | None = None) -> list[InjectionPoint]:
    """One header point per crawled 2xx GET page and header name (forms phase 2,
    FR-FUZZ-43). The URL carries the page's representative query -- the first crawled
    link set for that path (`core.forms.first_link_set`, already redacted), its ip/host/
    url values sent neutral -- so the page runs as on a visit. A destructive page is
    left out and reported. ``names`` are already checked
    (`core.http.header_point_refusal`)."""
    from urllib.parse import urlsplit

    from fuzzlab.core.forms import first_link_set
    from fuzzlab.core.urls import destructive_reason, with_query
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    rows = store.conn.execute(
        "SELECT url, status FROM page WHERE run_id = ? AND method = 'GET' ORDER BY id",
        (run_id,)).fetchall()
    points: list[InjectionPoint] = []
    seen: set[str] = set()
    for r in rows:
        path = _stored_key(r["url"])
        if path in seen or not _header_page(r["status"]):
            continue
        seen.add(path)
        page_url, elsewhere = _crawl_url(path, origin)      # FR-AUD-27
        reason = elsewhere or (None if destructive_reason(page_url) is None else
                               f"destructive URL ({destructive_reason(page_url)!r})")
        if reason is not None:
            if skipped is not None:
                skipped.extend((path, "GET", name, reason) for name in names)
            continue
        # never a set holding a placeholder or a host outside the lab (FR-FUZZ-67)
        query = first_link_set(store.conn, run_id, path,
                               accept=lambda entries: _outside_lab(entries, None) is None)
        # its representative query through the one owner (SP-42), same bytes as before
        url = with_query(page_url, [(n, _send_value(v)) for n, v in query]) if query \
            else page_url
        points.extend(InjectionPoint(url=url, param=name, method="GET", location="header",
                                     origin="crawl") for name in names)
    return points


def header_point_estimate(spider_db, names) -> tuple[int, int]:
    """``(pages, requests)``: how many crawled 2xx GET pages would get header points
    and a lower bound on their request cost. Reads the spider DB read-only, before any
    store is opened (PA-0079)."""
    import sqlite3
    from pathlib import Path

    from fuzzlab.core.store import open_read_only
    from fuzzlab.core.urls import destructive_reason, to_path
    path = Path(spider_db)
    if not path.exists():
        return 0, 0
    # the one read-only opener (FR-CORE-508, CC-FUZZ-0108): never creates or writes it
    conn = open_read_only(path, timeout=5.0)
    try:
        rows = conn.execute("SELECT url, status_code FROM discovered_pages").fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    pages = {to_path(url) for url, status in rows if _header_page(status)}
    pages = {p for p in pages if destructive_reason(p) is None}   # as the builder checks
    return len(pages), len(pages) * len(names) * header_point_cost()


class _CountingSender:
    """Wrap a probe sender to count sends, so the run's request cost is measured.

    Serves as both the pipeline's ``sender`` and its ``budget`` (``used()``).
    """

    def __init__(self, inner):
        self._inner = inner
        self.count = 0

    @property
    def prg_capable(self) -> bool:
        from fuzzlab.oracle.probe import accepts_prg
        return accepts_prg(self._inner)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        from fuzzlab.oracle.probe import Probe, ProbeUnobserved
        self.count += 1
        try:
            if prg:                          # FR-FUZZ-49: only ever asked of a capable inner
                probe = self._inner.send(url, param, value, timing=timing, method=method,
                                         location=location, content_type=content_type,
                                         entries=entries, prg=True)
            elif entries is not None:
                probe = self._inner.send(url, param, value, timing=timing, method=method,
                                         location=location, entries=entries)
            elif method == "GET" and location == "query":
                probe = self._inner.send(url, param, value, timing=timing)
            elif content_type:
                probe = self._inner.send(url, param, value, timing=timing,
                                         method=method, location=location,
                                         content_type=content_type)
            else:
                probe = self._inner.send(url, param, value, timing=timing,
                                         method=method, location=location)
        except ProbeUnobserved as exc:
            self.count += exc.resent        # re-sent before giving up (BUG-0147)
            raise
        if isinstance(probe, Probe):
            # a PRG follow-up or a re-send the sender made for this probe is a request
            # of the run too (FR-FUZZ-49 P8, BUG-0147)
            self.count += probe.follow_up_sends
        return probe

    @property
    def fetch_capable(self) -> bool:
        from fuzzlab.oracle.probe import accepts_fetch
        return accepts_fetch(self._inner)

    def fetch(self, url, *, route_url):
        """The binder's page fetch (FR-FUZZ-67): a request of the run, counted."""
        from fuzzlab.oracle.probe import Probe, ProbeUnobserved
        self.count += 1
        try:
            probe = self._inner.fetch(url, route_url=route_url)
        except ProbeUnobserved as exc:
            self.count += exc.resent
            raise
        if isinstance(probe, Probe):
            self.count += probe.follow_up_sends
        return probe

    def used(self, component: str | None = None) -> int:
        return self.count


class _FragmentGuard:
    """Crawl-sourced runs (forms phase 3): an SPA route's query never reaches the server,
    so an HTTP send at location ``fragment`` is refused (`UnplaceableLocation`) before
    it reaches the sender, whose last branch would put it in the query (BUG-0115
    instance 4, pinned). Only the M6 browser executor places a fragment point; the
    oracle takes a refusal as "no verdict from this mechanism" (PA-0115). Ground-truth
    runs are not wrapped (their pinned behaviour is unchanged)."""

    def __init__(self, inner):
        self._inner = inner

    @property
    def prg_capable(self) -> bool:
        from fuzzlab.oracle.probe import accepts_prg
        return accepts_prg(self._inner)

    @property
    def fetch_capable(self) -> bool:
        from fuzzlab.oracle.probe import accepts_fetch
        return accepts_fetch(self._inner)

    def fetch(self, url, *, route_url):
        return self._inner.fetch(url, route_url=route_url)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        if location == "fragment":
            from fuzzlab.oracle.probe import UnplaceableLocation
            raise UnplaceableLocation("a fragment point is placed by the browser only")
        if prg:                          # FR-FUZZ-49: only ever asked of a capable inner
            return self._inner.send(url, param, value, timing=timing, method=method,
                                    location=location, content_type=content_type,
                                    entries=entries, prg=True)
        if entries is not None:
            return self._inner.send(url, param, value, timing=timing, method=method,
                                    location=location, entries=entries)
        if method == "GET" and location == "query":
            return self._inner.send(url, param, value, timing=timing)
        if content_type:
            return self._inner.send(url, param, value, timing=timing,
                                    method=method, location=location,
                                    content_type=content_type)
        return self._inner.send(url, param, value, timing=timing,
                                method=method, location=location)


def plan_run(*, mode: str, ground_truth, selected_categories,
             points_source: str = "auto",
             header_points: bool = False) -> tuple[str, RunPlan]:
    """``(points source, run plan)`` for a run — pure, no store, no traffic. The one
    usage-level resolution (PA-0003): `run_auto` calls it, and `fuzzlab auto` calls it
    **before opening the store**, so a D15 fail-safe or a ground-truth source without a
    contract exits with no run row behind (BUG-0078, PA-0079). Raises `RunModeError`."""
    source = points_source
    if source == "auto":
        source = "ground-truth" if ground_truth is not None else "crawl"
    if source == "ground-truth" and ground_truth is None:
        raise RunModeError("points_source='ground-truth' requires a ground-truth contract")
    if header_points and source != "crawl":
        raise RunModeError("header points come from a crawl: use them with crawl points "
                           "(--points crawl), not ground truth")
    gt_categories = None
    if ground_truth is not None:
        gt_categories = categories_from_vuln_classes(
            c.vuln_class for c in ground_truth.positives())
    plan = resolve_run(mode, ground_truth_categories=gt_categories,
                       selected_categories=selected_categories,
                       all_categories=known_categories())
    return source, plan


def run_auto(*, base_url: str, store, run_id: int, sender, mode: str = "automatic",
             ground_truth=None, selected_categories=None, points_source: str = "auto",
             pages_html: dict[str, str] | None = None, browser=None, oob=None,
             coverage=None, dbfault=None,
             scheduler=None, plugins=None, confirm_budget: int | None = None,
             prioritizer=None, header_names=None, peer=None,
             writes: bool = False, account_values=None,
             trace_events: bool = True) -> PipelineResult:
    """Resolve the plan (D14/D15) and run the Phase 2 pipeline.

    ``plugins`` (a `PluginManager`) is recorded on the run, may contribute the budget
    prioritizer when ``prioritizer`` is not given (exactly one may; two raise
    `RunModeError`), and has its ``after_run`` stages dispatched once the pipeline is
    done — their outcomes land on ``result.plugin_outcomes`` (CC-FUZZ-0050).

    ``points_source``: ``"ground-truth"`` audits the enumerated contract points (a
    detection benchmark, decoupled from crawl coverage); ``"crawl"`` audits what the
    crawl discovered (a discovery run); ``"auto"`` (default) picks ground-truth when a
    contract is present, else crawl. ``browser`` (a `BrowserExecutor`) enables M6
    stored/DOM XSS confirmation and, for ground-truth sourcing, the DOM points.
    ``oob`` (an already-started `OobListener`) enables M8 out-of-band confirmation
    of blind command injection. ``coverage``/``dbfault`` (a `CoverageSource`/
    `DbFaultSource`) enable M10 grey-box confirmation of sql-injection/xss; both
    default to ``None`` (no-op) same as ``browser``/``oob``. ``writes``
    (``--fuzz-json-writes``) admits the ground truth's PUT/PATCH points (FR-FUZZ-56);
    ``account_values`` are the run's own account's stored values (FR-LAB-309).
    ``trace_events`` (default on): every send, test, strategy outcome and finding is
    recorded as a trace event (FR-FUZZ-60) with the active `core.trace` recorder, or
    one opened for this run.
    """
    source, plan = plan_run(mode=mode, ground_truth=ground_truth,
                            selected_categories=selected_categories,
                            points_source=points_source,
                            header_points=bool(header_names))

    skipped: list[tuple[str, str, str, str]] = []
    isolated: set[str] = set()
    if source == "ground-truth":
        points, skipped = points_from_ground_truth(
            ground_truth, base_url, browser_available=browser is not None, writes=writes,
            account_values=account_values)
        # The operator enumerated these: they may be probed even if they look
        # destructive (NFR-FUZZ-safe's send-time gate, BUG-0112).
        if hasattr(sender, "allow_explicit"):
            sender.allow_explicit([u for p in points for u in (p.url, p.store_url)])
    else:
        points = injection_points_from_store(store, run_id, base_url, skipped=skipped,
                                             isolated=isolated,
                                             browser_available=browser is not None)
        if isolated:
            if hasattr(sender, "isolate"):
                sender.isolate(isolated)       # never the run's session there (FR-FUZZ-44)
            else:
                from fuzzlab.core.urls import url_key
                kept = []
                for p in points:
                    if url_key(p.url) in isolated:
                        why = "needs an isolated session; this sender cannot provide one"
                        skipped.append((_path_of(p.url), p.method, p.param, why))
                    else:
                        kept.append(p)
                points = kept
        if header_names:
            # last, so they are confirmed last and a budget runs out on them first
            points += header_points_from_store(store, run_id, base_url,
                                               list(header_names), skipped=skipped)

    if plugins is not None:
        plugins.record(store, run_id)          # NFR-PLUG-reproducible: pin the active set
        if prioritizer is None and confirm_budget is not None:
            try:                               # a plugin-contributed budget order
                prioritizer = plugins.guarded_prioritizer()
            except ValueError as exc:          # PluginConflict: two would order it
                raise RunModeError(str(exc)) from exc
    from fuzzlab.core import trace
    from fuzzlab.core.urls import canonical_origin
    from fuzzlab.harness.tracing import TracingSender
    recorder = trace.active()
    own = None
    if recorder is None and trace_events:
        own = recorder = trace.TraceRecorder(store, run_id)
    if recorder is not None:
        sender = TracingSender(sender, identity=getattr(sender, "_identity", None))
        if peer is not None:
            # every sender a strategy is given is traced: the peer account's and the
            # unauthenticated replays are the evidence of an access finding (BUG-0513)
            import dataclasses
            peer = dataclasses.replace(
                peer,
                sender=None if peer.sender is None else TracingSender(
                    peer.sender, identity=getattr(peer.sender, "_identity", None)
                    or peer.peer_name or "peer"),
                anonymous=None if peer.anonymous is None else TracingSender(
                    peer.anonymous, identity="anonymous"))
    counting = _CountingSender(sender)
    # crawl points: a fragment is never sent over HTTP (forms phase 3, PA-0115)
    probing = counting if source == "ground-truth" else _FragmentGuard(counting)
    origins = sorted({o for o in [canonical_origin(base_url)]
                      + [canonical_origin(p.url) for p in points] if o})
    status = "aborted"
    # the run's identity scope: part of every request context (SP-57, FR-FUZZ-66)
    identity = getattr(sender, "_identity", None) or "anonymous"
    with trace.recording(recorder):
        trace.emit("run.start", {"base_url": trace.safe_ref(base_url), "origins": origins,
                                 "points": source, "mode": mode, "n_points": len(points),
                                 "identity": identity}, key="run.start", scope="run")
        try:
            result = run_pipeline(points, store, run_id, probing, plan,
                                  ground_truth=ground_truth, pages_html=pages_html,
                                  budget=counting, browser=browser, oob=oob,
                                  coverage=coverage, dbfault=dbfault, scheduler=scheduler,
                                  plugins=plugins, confirm_budget=confirm_budget,
                                  prioritizer=prioritizer, peer=peer, identity=identity)
            status = "complete"
        except BaseException as exc:
            status = f"aborted: {type(exc).__name__}"
            raise
        finally:
            trace.emit("run.end", {"status": status}, key="run.end", scope="run")
            if own is not None:
                own.close()
            elif recorder is not None:
                recorder.flush()
    result.metrics["points_source"] = source
    result.metrics["header_points"] = sum(1 for p in points if p.location == "header"
                                          and p.origin == "crawl")
    skipped += result.metrics.pop("header_breaker_skipped", [])
    result.metrics["skipped_points"] = skipped
    report = getattr(sender, "isolation_report", None)
    if source != "ground-truth" and isolated and callable(report):
        result.metrics["isolated_sessions"] = report()
    anonymous = getattr(sender, "auth_endpoint_anonymous_sends", None)
    if anonymous is not None:
        result.metrics["auth_endpoint_anonymous_sends"] = anonymous
    out_of_origin = getattr(sender, "session_out_of_origin", None)
    if isinstance(out_of_origin, int) and out_of_origin:
        # sends made without the session: another origin (FR-SESS-20, BUG-0134)
        result.metrics["session_out_of_origin"] = out_of_origin
    if plugins is not None:
        # post-run stages (the ML stages, FR-ML-6), each its own guarded unit of work;
        # then close the run's plugin record with each plugin's final status
        result.plugin_outcomes = plugins.after_run(store, run_id)
        plugins.finalize(store, run_id)
    return result
