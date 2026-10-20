"""Routes for the site tree (CC-UI-0500, FR-UI-503): one page and a read-only JSON API.

Registered from `web/app.py` in one block (`register`), so the app keeps one line per
section. Every route is a sync ``def`` (store I/O never runs on the event loop,
PA-0102(3)) and a GET: the API reads the store through the app's own accessor
(``with_store``, the same one the diagnostics views use) and never creates the store
file. The store version (`sitetree.store_version`, SP-58) is taken **before** each
request opens its read snapshot (G11), so a cached child list is never older than its
key; the routes pass the ``store_path`` callable itself, which the version reads under
its own lock (a project transition never races it, CC-UI-0068).

- ``GET /sitetree`` -- the page.
- ``GET /api/sitetree/children?node=&after=&limit=`` + filters -- a node's children.
- ``GET /api/sitetree/node?node=&before=&limit=`` + filters -- roll-up and findings.
- ``GET /api/sitetree/facets`` -- filter choices.
- ``GET /api/sitetree/version`` -- the store version the page polls (SQLite's change
  counter on one held, query-only connection; ``null`` with no store or no version now).

Filters: ``run``, ``category``, ``severity``, ``status`` (repeatable) and ``q``.
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from fuzzlab.web import sitetree


def _filters(run, category, severity, status, q) -> sitetree.Filters:
    return sitetree.parse_filters(run=run or [], category=category or [],
                                  severity=severity or [], status=status or [],
                                  q=q or "")


def _error(exc: Exception) -> JSONResponse:
    if isinstance(exc, sitetree.NodeGone):
        return JSONResponse({"error": "gone", "detail": str(exc)}, status_code=404)
    return JSONResponse({"error": "bad request", "detail": str(exc)}, status_code=400)


def register(app: FastAPI, *, templates, shell_context: Callable[[], dict],
             with_store: Callable[[Callable[[Any], Any], Any], Any],
             store_path: Callable[[], str | None], poll_ms: int = 5000) -> None:
    """Add the site tree's routes to ``app``. ``with_store(fn, default)`` is the app's
    store accessor; ``store_path()`` names the same store, for the store version."""

    @app.get("/sitetree", response_class=HTMLResponse)
    def sitetree_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/sitetree.html", {**shell_context(), "poll_ms": poll_ms})

    @app.get("/api/sitetree/version")
    def sitetree_version():
        return {"version": sitetree.store_version(store_path)}

    @app.get("/api/sitetree/facets")
    def sitetree_facets():
        empty = {"runs": [], "categories": [], "severities": list(sitetree.SEVERITIES),
                 "statuses": list(sitetree.STATUSES)}
        return with_store(lambda store: sitetree.facets(store.conn), empty)

    @app.get("/api/sitetree/children")
    def sitetree_children(node: str = "", after: str | None = None,
                          limit: int | None = None, run: list[str] = Query(default=[]),
                          category: list[str] = Query(default=[]),
                          severity: list[str] = Query(default=[]),
                          status: list[str] = Query(default=[]), q: str = ""):
        try:
            key = sitetree.parse_key(node)
            filters = _filters(run, category, severity, status, q)
            version = sitetree.store_version(store_path)       # before the snapshot (G11)
            return with_store(
                lambda store: sitetree.children(store.conn, key, filters, after=after,
                                                limit=limit, version=version),
                {"children": [], "next": None})
        except (sitetree.SiteTreeError, sitetree.NodeGone) as exc:
            return _error(exc)

    @app.get("/api/sitetree/node")
    def sitetree_node(node: str = "", before: int | None = None,
                      limit: int | None = None, run: list[str] = Query(default=[]),
                      category: list[str] = Query(default=[]),
                      severity: list[str] = Query(default=[]),
                      status: list[str] = Query(default=[]), q: str = ""):
        try:
            key = sitetree.parse_key(node)
            filters = _filters(run, category, severity, status, q)
            found = with_store(
                lambda store: sitetree.summary(store.conn, key, filters, before=before,
                                               limit=limit), None)
        except (sitetree.SiteTreeError, sitetree.NodeGone) as exc:
            return _error(exc)
        if found is None:
            return _error(sitetree.NodeGone("no store"))
        return found
