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
from fuzzlab.audit.value_shape import SAFE_HOST, neutral_value, redirect_seed, value_shape
from fuzzlab.core.redaction import is_credential_name
from fuzzlab.core.runmode import (RunModeError, RunPlan, categories_from_vuln_classes,
                                   resolve_run)
from fuzzlab.harness.pipeline import PipelineResult, run_pipeline


def points_from_ground_truth(ground_truth, base_url: str, browser_available: bool = False):
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
    """
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
        if not is_dom and gp.method.upper() in ("GET", "POST") \
                and gp.location in ("query", "body", "header"):
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
            for sink_context in sorted(sink_contexts, key=lambda s: s or ""):
                points.append(InjectionPoint(url=base + path, param=gp.param,
                                             method=gp.method.upper(), location=gp.location,
                                             body_content_type=body_content_type,
                                             sink_context=sink_context,
                                             origin="ground-truth"))
        elif is_dom and browser_available:
            # BUG-0115 sweep: no ground-truth DOM point has another location today
            # (pinned by tests/test_forms_phase2.py); the rewrite is left as is
            loc = gp.location if gp.location in ("query", "fragment") else "query"
            points.append(InjectionPoint(url=base + path, param=gp.param,
                                         method="GET", location=loc,
                                         origin="ground-truth"))
        else:
            skipped.append((path, gp.method, gp.param,
                            "client-only/DOM (needs browser execution, M6)"))

    # Stored XSS lives in the *cases* (observe url + source_url store endpoint), not the
    # enumerated points. Audit it only with a browser (M6): plant at source_url, observe.
    for case in ground_truth.cases:
        if case.vuln_class != "xss-stored" or not case.source_url:
            continue
        opath = case.url if case.url.startswith("/") else "/" + case.url
        spath = case.source_url if case.source_url.startswith("/") else "/" + case.source_url
        if browser_available:
            points.append(InjectionPoint(
                url=base + opath, param=case.param, method=case.method,
                location=case.location, store_url=base + spath, store_param=case.param,
                origin="ground-truth"))
        else:
            skipped.append((opath, case.method, case.param,
                            "stored XSS (needs browser execution, M6)"))
    return points, skipped


#: A crawl- or form-sourced parameter with a credential name token is never fuzzed (the
#: one predicate lives in `core.redaction` since forms phase 2, CC-CORE-0042).
_credential_name = is_credential_name


def _send_value(value):
    """What the fuzzer sends for an app-supplied default: loopback in place of an ip-,
    host- or url-shaped one (FR-AUD-20), the importer's own fillers as they are."""
    from fuzzlab.tools.store_adapter import is_filler
    return value if is_filler(value) else neutral_value(value)


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
        path = r["path"] if r["path"].startswith("/") else "/" + r["path"]
        key = url_key(origin + path)
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


def _json_base_entries(raw):
    """A JSON point's siblings as sent (forms phase 3, FR-FUZZ-47): the stored leaves
    (`core.jsonbody.decode_entries`, already passed `store_adapter.redact_leaf`), each
    value through `_send_value` (loopback for a host/url-shaped one), types kept. None
    when the stored list is malformed (the point is then dropped, PA-0108)."""
    from fuzzlab.core import jsonbody
    entries = jsonbody.decode_entries(raw) if raw else None
    if entries is None:
        return None
    return tuple((path, _send_value(value)) for path, value in entries)


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
    from fuzzlab.tools.store_adapter import is_filler
    rows = store.conn.execute(
        "SELECT e.url AS path, e.method AS method, p.name AS name, p.location AS location, "
        "p.example AS example, f.entries AS entries "
        "FROM parameter p JOIN endpoint e ON p.endpoint_id = e.id "
        "LEFT JOIN form f ON f.id = p.form_id "
        "WHERE p.run_id = ?",
        (run_id,),
    ).fetchall()
    # (c2) a field whose own example says nothing ("" or our filler) takes the shapes
    # its name has elsewhere in the run: one pass over the rows (PA-0095)
    shapes_by_name: dict[str, set[str]] = {}
    for r in rows:
        shapes_by_name.setdefault(r["name"], set()).update(_shapes(r["example"]))
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str, str]] = set()
    for r in rows:
        path = r["path"] if r["path"].startswith("/") else "/" + r["path"]
        method = r["method"] or "GET"
        key = (path, method, r["name"])
        if key in seen:
            continue
        seen.add(key)
        reason = _crawl_url_refusal(base + path)
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
        key = url_key(base + path)
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
        entries = None
        if location == jsonbody.LOCATION:
            entries = _json_base_entries(r["entries"])
            if entries is None:
                if skipped is not None:
                    skipped.append((path, method, r["name"],
                                    "malformed form row (JSON entries)"))
                continue
        elif r["entries"]:
            try:
                entries = tuple((n, _send_value(v)) for n, v in json.loads(r["entries"]))
            except (ValueError, TypeError):
                entries = None
        example = r["example"]
        shapes = _shapes(example)
        if example in (None, "") or is_filler(example):
            shapes = frozenset(shapes_by_name.get(r["name"], ()))
        points.append(InjectionPoint(url=base + path, param=r["name"],
                                     method=method, location=location,
                                     base_entries=entries, origin="crawl",
                                     value_shapes=shapes,
                                     base_value=(SAFE_HOST if shapes & {"ip", "hostname"}
                                                 else None),
                                     redirect_seed=redirect_seed(example)))
    return points


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
    from urllib.parse import urlencode, urlsplit

    from fuzzlab.core.forms import first_link_set
    from fuzzlab.core.urls import destructive_reason
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    rows = store.conn.execute(
        "SELECT url, status FROM page WHERE run_id = ? AND method = 'GET' ORDER BY id",
        (run_id,)).fetchall()
    points: list[InjectionPoint] = []
    seen: set[str] = set()
    for r in rows:
        path = r["url"] if r["url"].startswith("/") else "/" + r["url"]
        if path in seen or not _header_page(r["status"]):
            continue
        seen.add(path)
        reason = destructive_reason(origin + path)
        if reason is not None:
            if skipped is not None:
                skipped.extend((path, "GET", name, f"destructive URL ({reason!r})")
                               for name in names)
            continue
        query = first_link_set(store.conn, run_id, path)
        url = origin + path
        if query:
            url += "?" + urlencode([(n, _send_value(v)) for n, v in query])
        points.extend(InjectionPoint(url=url, param=name, method="GET", location="header",
                                     origin="crawl") for name in names)
    return points


def header_point_estimate(spider_db, names) -> tuple[int, int]:
    """``(pages, requests)``: how many crawled 2xx GET pages would get header points
    and a lower bound on their request cost. Reads the spider DB read-only, before any
    store is opened (PA-0079)."""
    import sqlite3
    from pathlib import Path
    from urllib.parse import quote

    from fuzzlab.core.urls import destructive_reason, to_path
    path = Path(spider_db)
    if not path.exists():
        return 0, 0
    conn = sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True)
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
        from fuzzlab.oracle.probe import Probe
        self.count += 1
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
        if isinstance(probe, Probe):
            # a PRG follow-up the sender made for this probe is a request of the run
            # too (FR-FUZZ-49, P8)
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
             prioritizer=None, header_names=None) -> PipelineResult:
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
    default to ``None`` (no-op) same as ``browser``/``oob``.
    """
    source, plan = plan_run(mode=mode, ground_truth=ground_truth,
                            selected_categories=selected_categories,
                            points_source=points_source,
                            header_points=bool(header_names))

    skipped: list[tuple[str, str, str, str]] = []
    isolated: set[str] = set()
    if source == "ground-truth":
        points, skipped = points_from_ground_truth(
            ground_truth, base_url, browser_available=browser is not None)
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
    counting = _CountingSender(sender)
    # crawl points: a fragment is never sent over HTTP (forms phase 3, PA-0115)
    probing = counting if source == "ground-truth" else _FragmentGuard(counting)
    result = run_pipeline(points, store, run_id, probing, plan,
                          ground_truth=ground_truth, pages_html=pages_html,
                          budget=counting, browser=browser, oob=oob,
                          coverage=coverage, dbfault=dbfault, scheduler=scheduler,
                          plugins=plugins, confirm_budget=confirm_budget,
                          prioritizer=prioritizer)
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
