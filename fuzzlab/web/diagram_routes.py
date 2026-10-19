"""Routes for the data-flow and sequence diagrams (FR-UI-510, `report.diagram`).

One page and a read-only JSON/text API over a run's trace model. Every route is a sync
``def`` and a GET that reads the store through the app's own accessor (never creating
the store); nothing here sends a request to a target. The page polls the store's
version fingerprint (`sitetree.store_version`, ``/api/sitetree/version``) and refreshes
while a scan writes.

- ``GET /diagrams`` -- the page.
- ``GET /api/diagram/runs`` -- runs with trace events, and their completeness.
- ``GET /api/diagram/{run}/status`` -- completeness, dropped events, lag, gaps.
- ``GET /api/diagram/{run}/dataflow?overlay=&origin=&knowledge=&finding=``
- ``GET /api/diagram/{run}/scopes`` / ``.../sequence?scope=``
- ``GET /api/diagram/{run}/evidence?ref=&after=`` / ``.../finding/{id}``
- ``GET /api/diagram/{run}/export.json`` / ``export/flow.mmd`` / ``export/sequence.mmd``
"""

from __future__ import annotations

import json
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from fuzzlab.report import diagram

_KNOWLEDGE = ("observed", "inferred", "unknown")


def _runs(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT r.id, r.started_at, r.tool, COUNT(e.id) n FROM run r JOIN trace_event e "
        "ON e.run_id = r.id GROUP BY r.id ORDER BY r.id DESC LIMIT 200").fetchall()
    return [{"id": r["id"], "started_at": r["started_at"], "tool": r["tool"],
             "events": r["n"], "state": diagram.status(conn, r["id"])["state"]}
            for r in rows]


def register(app: FastAPI, *, templates, shell_context: Callable[[], dict],
             with_store: Callable[[Callable[[Any], Any], Any], Any],
             poll_ms: int = 3000) -> None:

    @app.get("/diagrams", response_class=HTMLResponse)
    def diagrams_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/diagrams.html", {**shell_context(), "poll_ms": poll_ms})

    @app.get("/api/diagram/runs")
    def diagram_runs():
        return with_store(lambda store: {"runs": _runs(store.conn)}, {"runs": []})

    def _read(fn, default=None):
        found = with_store(lambda store: fn(store.conn), default)
        if found is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return found

    @app.get("/api/diagram/{run_id}/status")
    def diagram_status(run_id: int):
        return _read(lambda c: diagram.status(c, run_id))

    @app.get("/api/diagram/{run_id}/dataflow")
    def diagram_dataflow(run_id: int, overlay: bool = False, origin: str = "",
                         knowledge: str = "", finding: int | None = None):
        if knowledge and knowledge not in _KNOWLEDGE:
            return JSONResponse({"error": "bad knowledge filter"}, status_code=400)
        return _read(lambda c: diagram.dataflow(c, run_id, overlay=overlay,
                                                origin=origin or None,
                                                knowledge=knowledge or None,
                                                finding=finding))

    @app.get("/api/diagram/{run_id}/scopes")
    def diagram_scopes(run_id: int):
        return _read(lambda c: {"scopes": diagram.scopes(c, run_id)})

    @app.get("/api/diagram/{run_id}/sequence")
    def diagram_sequence(run_id: int, scope: str = ""):
        if not scope or len(scope) > 200:
            return JSONResponse({"error": "scope required"}, status_code=400)
        found = _read(lambda c: diagram.sequence(c, run_id, scope))
        if isinstance(found, dict) and found.get("error"):
            return JSONResponse({"error": found["error"]}, status_code=400)
        return found

    @app.get("/api/diagram/{run_id}/evidence")
    def diagram_evidence(run_id: int, ref: str = "", after: int = 0):
        if not ref or len(ref) > 1000:
            return JSONResponse({"error": "ref required"}, status_code=400)
        return _read(lambda c: diagram.evidence(c, run_id, ref, after=after))

    @app.get("/api/diagram/{run_id}/finding/{finding_id}")
    def diagram_finding(run_id: int, finding_id: int):
        return _read(lambda c: diagram.finding_links(c, run_id, finding_id))

    def _download(text: str, name: str, media: str) -> Response:
        return Response(text, media_type=media, headers={
            "Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/diagram/{run_id}/export.json")
    def diagram_export_json(run_id: int):
        doc = with_store(lambda s: diagram.export_json(s.conn, run_id), None)
        if doc is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return _download(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True),
                         f"fuzzlab-run-{run_id}-diagram.json", "application/json")

    @app.get("/api/diagram/{run_id}/export/flow.mmd")
    def diagram_export_flow(run_id: int, overlay: bool = False):
        text = with_store(lambda s: diagram.mermaid_flow(
            diagram.dataflow(s.conn, run_id, overlay=overlay)), None)
        if text is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return _download(text, f"fuzzlab-run-{run_id}-dataflow.mmd", "text/plain")

    @app.get("/api/diagram/{run_id}/export/sequence.mmd")
    def diagram_export_sequence(run_id: int, scope: str = ""):
        if not scope or len(scope) > 200:
            return JSONResponse({"error": "scope required"}, status_code=400)
        seq = with_store(lambda s: diagram.sequence(s.conn, run_id, scope), None)
        if seq is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        if seq.get("error"):
            return JSONResponse({"error": seq["error"]}, status_code=400)
        text = diagram.mermaid_sequence(seq)
        return _download(text, f"fuzzlab-run-{run_id}-sequence.mmd", "text/plain")
