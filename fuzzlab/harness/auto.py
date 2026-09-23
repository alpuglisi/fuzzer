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

from fuzzlab.audit import InjectionPoint, known_categories
from fuzzlab.core.runmode import RunModeError, categories_from_vuln_classes, resolve_run
from fuzzlab.harness.pipeline import PipelineResult, run_pipeline


def points_from_ground_truth(ground_truth, base_url: str, browser_available: bool = False):
    """Injection points from the enumerated ground-truth contract (detection benchmark).

    Returns ``(points, skipped)``. Server-rendered **GET query** and **POST body**
    params are always audited. Client-only/DOM points (fragment, ``client_only``, or
    ``rendering=js``) are audited only when a **browser** is available (M6); otherwise
    they are returned as ``skipped`` (path, method, param, reason) so the gap is
    explicit and they score as false negatives until a browser is provided.
    **Header-carried points** (``location="header"``, e.g. a webhook-signature check
    against a header value -- `CC-LAB-0174`'s `TWCH-0001`) are always ``skipped``
    with their own reason: neither this function's point model nor
    ``fuzzlab.tools.probesender``'s senders carry a header-injection convention yet
    (`FR-FUZZ-13`), a real, distinct gap from the DOM/browser one -- never folded
    into that reason string, which would misreport *why* the point can't be audited.
    """
    base = base_url.rstrip("/")
    points: list[InjectionPoint] = []
    skipped: list[tuple[str, str, str, str]] = []
    for gp in ground_truth.points:
        path = gp.url if gp.url.startswith("/") else "/" + gp.url
        is_dom = (gp.client_only or (gp.rendering or "") == "js"
                  or gp.location == "fragment")
        is_header = gp.location == "header"
        if not is_dom and not is_header and gp.method.upper() in ("GET", "POST") \
                and gp.location in ("query", "body"):
            points.append(InjectionPoint(url=base + path, param=gp.param,
                                         method=gp.method.upper(), location=gp.location))
        elif is_dom and browser_available:
            loc = gp.location if gp.location in ("query", "fragment") else "query"
            points.append(InjectionPoint(url=base + path, param=gp.param,
                                         method="GET", location=loc))
        elif is_header:
            skipped.append((path, gp.method, gp.param,
                            "header-carried injection point (no header-capable "
                            "point/sender wiring yet, FR-FUZZ-13)"))
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
                location=case.location, store_url=base + spath, store_param=case.param))
        else:
            skipped.append((opath, case.method, case.param,
                            "stored XSS (needs browser execution, M6)"))
    return points, skipped


def injection_points_from_store(store, run_id: int, base_url: str) -> list[InjectionPoint]:
    """Build injection points from the run's endpoint/parameter rows."""
    base = base_url.rstrip("/")
    rows = store.conn.execute(
        "SELECT e.url AS path, e.method AS method, p.name AS name, p.location AS location "
        "FROM parameter p JOIN endpoint e ON p.endpoint_id = e.id "
        "WHERE p.run_id = ?",
        (run_id,),
    ).fetchall()
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str, str]] = set()
    for r in rows:
        path = r["path"] if r["path"].startswith("/") else "/" + r["path"]
        method = r["method"] or "GET"
        key = (path, method, r["name"])
        if key in seen:
            continue
        seen.add(key)
        points.append(InjectionPoint(url=base + path, param=r["name"],
                                     method=method, location=r["location"] or "query"))
    return points


class _CountingSender:
    """Wrap a probe sender to count sends, so the run's request cost is measured.

    Serves as both the pipeline's ``sender`` and its ``budget`` (``used()``).
    """

    def __init__(self, inner):
        self._inner = inner
        self.count = 0

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query"):
        self.count += 1
        if method == "GET" and location == "query":
            return self._inner.send(url, param, value, timing=timing)
        return self._inner.send(url, param, value, timing=timing,
                                method=method, location=location)

    def used(self, component: str | None = None) -> int:
        return self.count


def run_auto(*, base_url: str, store, run_id: int, sender, mode: str = "automatic",
             ground_truth=None, selected_categories=None, points_source: str = "auto",
             pages_html: dict[str, str] | None = None, browser=None, oob=None,
             coverage=None, dbfault=None,
             scheduler=None, plugins=None) -> PipelineResult:
    """Resolve the plan (D14/D15) and run the Phase 2 pipeline.

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
    source = points_source
    if source == "auto":
        source = "ground-truth" if ground_truth is not None else "crawl"

    skipped: list[tuple[str, str, str, str]] = []
    if source == "ground-truth":
        if ground_truth is None:
            raise RunModeError("points_source='ground-truth' requires a ground-truth contract")
        points, skipped = points_from_ground_truth(
            ground_truth, base_url, browser_available=browser is not None)
    else:
        points = injection_points_from_store(store, run_id, base_url)

    gt_categories = None
    if ground_truth is not None:
        gt_categories = categories_from_vuln_classes(
            c.vuln_class for c in ground_truth.positives())

    plan = resolve_run(mode, ground_truth_categories=gt_categories,
                       selected_categories=selected_categories,
                       all_categories=known_categories())

    if plugins is not None:
        plugins.record(store, run_id)          # NFR-PLUG-reproducible: pin the active set
    counting = _CountingSender(sender)
    result = run_pipeline(points, store, run_id, counting, plan,
                          ground_truth=ground_truth, pages_html=pages_html,
                          budget=counting, browser=browser, oob=oob,
                          coverage=coverage, dbfault=dbfault, scheduler=scheduler,
                          plugins=plugins)
    result.metrics["points_source"] = source
    result.metrics["skipped_points"] = skipped
    return result
