"""Routes for project files (CC-UI-0450, FR-UI-450..457) — kept out of ``app.py`` so its
diff stays one registration call.

Pages: ``GET /projects`` (open / new / temporary / save as / close, the recent list,
leftover temporaries, a pending migration offer or refusal) and ``GET /project`` (the
open project's metadata and run history). JSON: ``GET /api/projects``,
``GET /api/project/history``. Every action is a plain ``<form method="post">`` answered
with a 303 back to a page (PRG; works without JavaScript) and goes through
``SecurityGateMiddleware``'s same-origin gate like every state-changing request.

A refusal is shown on the next page as a message the server holds (``manager.flash``,
autoescaped like every rendered value): nothing is reflected through the URL. The
message text names the refusal (it may quote the project name the operator typed). This
replaces the design's ``?notice=<code>`` scheme (design-gate F18; a recorded deviation in
CC-UI-0450): one local operator, one message queue, consumed by the next projects page.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any
from urllib.parse import parse_qsl

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from fuzzlab.core.project import ProjectError
from fuzzlab.web.projects import NeedsDiscard, NoProject, ProjectBusy, ProjectManager

#: What a project action may raise that becomes a message on the page (PA-0106: a
#: named list — the manager converts the OS errors it expects into `ProjectError` at
#: their site; ``OperationalError`` is a locked or vanished file; anything else is a
#: server error, loudly).
_ACTION_ERRORS = (ProjectError, ProjectBusy, NeedsDiscard, NoProject,
                  sqlite3.OperationalError)


async def _form(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8", errors="replace")
    return dict(parse_qsl(body, keep_blank_values=True))


def _flag(form: dict[str, str], key: str) -> bool:
    return form.get(key, "") in ("1", "on", "true", "yes")


def register(app, templates, cfg, manager: ProjectManager) -> None:
    """Add the project routes to ``app`` (called once from ``create_app``)."""
    from fuzzlab.web.app import _shell_context

    def _page_state() -> dict[str, Any]:
        return {"files": manager.list_files(), "recent": manager.recent(),
                "leftovers": manager.leftover_temporaries(),
                "projects_dir": str(manager.projects_dir)}

    def _take_flash() -> list[dict[str, str]]:
        taken, manager.flash = manager.flash, []      # one swap: no append is lost
        return [{"level": lvl, "text": text} for lvl, text in taken]

    @app.get("/projects", response_class=HTMLResponse)
    def projects_page(request: Request):
        return templates.TemplateResponse(request, "sections/projects.html", {
            **_shell_context(cfg, active="projects"), **_page_state(),
            "flash": _take_flash()})

    @app.get("/api/projects")
    def projects_api():
        return {"project": manager.state(), **_page_state()}

    @app.get("/project", response_class=HTMLResponse)
    def project_page(request: Request):
        return templates.TemplateResponse(request, "sections/project.html", {
            **_shell_context(cfg, active="project"), "meta": manager.metadata(),
            "history": manager.history(), "flash": _take_flash()})

    @app.get("/api/project/history")
    def project_history_api():
        return {"project": manager.state(), "meta": manager.metadata(),
                "history": manager.history() or []}

    async def _act(request: Request, action, *, ok: str, back: str = "/projects",
                   home_on_switch: bool = False):
        """Run one project action; a refusal becomes a held message, never a 500.

        ``home_on_switch`` (New, Temporary, Open, Use default — the research's "URL →
        results" path): go to ``/`` only when the action made the requested project the
        open one (it returned True) **and** nothing but its ok message is queued; an
        offer, a refusal or a warning (e.g. what a discard left) stays on ``/projects``,
        where messages are shown (layout reviews C/D)."""
        form = await _form(request)
        try:
            result = await action(form)
        except _ACTION_ERRORS as exc:
            manager.flash.append(("error", _refusal_text(exc)))
            return RedirectResponse(url=back, status_code=303)
        if isinstance(result, list) and result:          # a discard left something
            manager.flash.append(("warn", "Discarded, but: " + "; ".join(result)))
        elif ok:
            manager.flash.append(("ok", ok if not isinstance(result, str) else
                                  ok.format(result=result)))
        if home_on_switch and result is True and \
                all(level == "ok" for level, _ in manager.flash):
            manager.flash = []                           # the open project says it all
            return RedirectResponse(url="/", status_code=303)
        return RedirectResponse(url=back, status_code=303)

    def _refusal_text(exc: Exception) -> str:
        if isinstance(exc, NeedsDiscard):
            return ("The open project is temporary: leaving it deletes it. Save it as a "
                    "named project first, or tick the box to discard it.")
        return str(exc)

    def _recent_fields(f: dict[str, str]) -> tuple[int | None, str | None]:
        recent = f.get("recent")
        if recent in (None, ""):
            return None, None
        if not re.fullmatch(r"[0-9]{1,4}", recent):
            raise ProjectError("no such recent project")
        return int(recent), f.get("path") or None

    @app.post("/projects/new")
    async def project_new(request: Request):
        return await _act(request, lambda f: manager.new(
            f.get("name", "").strip(), discard=_flag(f, "discard")), ok="Project created.",
            home_on_switch=True)

    @app.post("/projects/temporary")
    async def project_temporary(request: Request):
        return await _act(request, lambda f: manager.temporary(discard=_flag(f, "discard")),
                          ok="Temporary project started.", home_on_switch=True)

    @app.post("/projects/use-default")
    async def project_use_default(request: Request):
        return await _act(request, lambda f: manager.use_default(discard=_flag(f, "discard")),
                          ok="", home_on_switch=True)

    @app.post("/projects/open")
    async def project_open(request: Request):
        async def go(f):
            recent_id, recent_path = _recent_fields(f)
            return await manager.open(
                file=f.get("file") or None, recent_id=recent_id, recent_path=recent_path,
                temporary=f.get("temporary") or None, discard=_flag(f, "discard"))
        return await _act(request, go, ok="", home_on_switch=True)

    @app.post("/projects/snapshot")
    async def project_snapshot(request: Request):
        return await _act(request, lambda f: manager.snapshot(),
                          ok="Snapshot saved as {result}; this project stays open.")

    @app.post("/projects/forget")
    async def project_forget(request: Request):
        async def go(f):
            recent_id, recent_path = _recent_fields(f)
            if recent_id is None or recent_path is None:
                raise ProjectError("no such recent project")
            await manager.forget(recent_id, recent_path)
        return await _act(request, go, ok="Removed from the recent list (the file is "
                                          "untouched).")

    @app.post("/projects/save-as")
    async def project_save_as(request: Request):
        return await _act(request, lambda f: manager.save_as(f.get("name", "").strip()),
                          ok="Saved; the copy is now the open project.")

    @app.post("/projects/close")
    async def project_close(request: Request):
        return await _act(request, lambda f: manager.close(discard=_flag(f, "discard")),
                          ok="Project closed.")

    @app.post("/projects/migrate")
    async def project_migrate(request: Request):
        return await _act(request, lambda f: manager.migrate_pending(
            discard=_flag(f, "discard")), ok="Migrated; backup written to {result}.")

    @app.post("/projects/dismiss")
    async def project_dismiss(request: Request):
        async def go(_f):
            await manager.dismiss_pending()
        return await _act(request, go, ok="")

    @app.post("/projects/discard-temporary")
    async def project_discard_leftover(request: Request):
        return await _act(request, lambda f: manager.discard_leftover(
            f.get("temporary", ""), confirm=_flag(f, "discard")),
            ok="Temporary project discarded.")

    @app.post("/projects/make-private")
    async def project_make_private(request: Request):
        return await _act(request, lambda f: manager.make_private(),
                          ok="The project file is now readable by you only.")

    @app.post("/project/meta")
    async def project_meta(request: Request):
        async def go(f):
            targets = [t for t in f.get("targets", "").splitlines() if t.strip()]
            await manager.set_meta(f.get("notes", ""), targets)
        return await _act(request, go, ok="Saved.", back="/project")

    @app.exception_handler(NoProject)
    async def _no_project(_request, exc):                # a route that needs a project
        return JSONResponse({"error": str(exc)}, status_code=409)

    @app.exception_handler(ProjectError)
    async def _project_error(_request, exc):             # e.g. a project dir not 0700
        return JSONResponse({"error": str(exc)}, status_code=409)
