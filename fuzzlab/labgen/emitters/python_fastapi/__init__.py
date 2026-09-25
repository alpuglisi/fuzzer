"""``python_fastapi``: the Python/FastAPI emitter, Tier-A depth (L-P3.2).

Implements :class:`fuzzlab.labgen.emitter.Emitter` for FastAPI + SQLAlchemy +
Jinja2 by assembling :mod:`fuzzlab.labgen.emitters.python_fastapi.modules`
fragments per cell -- the same module-composition architecture
``fuzzlab.labgen.emitters.php_current`` uses (``CR-LAB-0001`` Addendum C),
reimplemented independently for this stack rather than extending the shared,
PHP-specific ``fuzzlab.labgen.modules`` package (out of this lane's scope,
per ``docs/LAB_IMPLEMENTATION_PLAN.md`` Phase 3's "no stack's emitter package
imports another's" rule).

**Scope, stated plainly (Tier-A only, per the Phase 3 pacing decision):**
this emitter covers the same three well-documented value-context shapes
``php_current`` already proves -- ``sql_numeric_literal`` SQLi,
``sql_string_literal`` SQLi, and ``html_body`` reflected/stored XSS --
ported to FastAPI/SQLAlchemy/Jinja2 idiom. It deliberately does **not**
cover identifier/alias/connector-position SQLi or escaping-context-mismatch
XSS (those stay deferred to a future full-depth pass on this stack, per the
Addendum C pacing decision). It renders one illustrative sample of three
synthetic routes (``/products``, ``/login``, ``/profile``) -- not a
migration of any real app; unlike ``php_laravel`` (Phase 3's other PHP
lane), Python/FastAPI has no real hand-built app to migrate.

**Multi-file routing, without a `route` accumulator module.** Per
``CR-LAB-0001`` Addendum D's FastAPI-specific research
(``docs/LAB_IMPLEMENTATION_PLAN.md`` Phase 3 §4.2): FastAPI's own documented
multi-file pattern needs one new `import` + `include_router()` line per
router module in a central file, same accumulator shape as Laravel's
``routes/web.php``/Express's ``app.js`` -- but a small, project-owned,
**static discovery scaffold** (`pkgutil.iter_modules()`/`importlib` walking
a `routers/` package at import time) avoids needing one: the scaffold is
rendered once per build (:data:`STACK_ENV`'s ``scaffold_files``) and never
touched per generated cell, so it carries none of the
reshuffling/non-determinism risk an accumulator exists to guard against.
``render()`` therefore returns exactly one per-cell router file; the scaffold
(``app/main.py``, ``app/db.py``, package ``__init__.py`` files,
``requirements.txt``, ``Dockerfile``) is a **separate**, one-time output a
build driver fetches from :data:`STACK_ENV` rather than from any per-cell
``render()`` call -- ``fuzzlab.labgen.emitter.Emitter``'s ABC has no
per-stack-scaffold method yet (a real gap this lane does not attempt to
close by editing ``emitter.py``, out of scope per the task brief), so this
is exposed as an emitter-specific attribute other callers (a future
``lab-generate`` CLI, T-LAB0.10) can read once other Phase-3 lanes have
settled on a shared convention.

**The FastAPI debug-page correctness requirement**
(``docs/LAB_IMPLEMENTATION_PLAN.md`` Phase 3's framework-debug-page
research): ``/docs``, ``/redoc``, and ``/openapi.json`` are served by
FastAPI *by default regardless of any debug flag* and leak the full API
schema -- unlike Laravel/Express, there is no single "production mode" flag
that also covers this. :data:`STACK_ENV`'s ``app/main.py`` scaffold
constructs ``FastAPI(docs_url=None, redoc_url=None, openapi_url=None)``
explicitly; this is asserted by a test, not left as an unverified docstring
claim.

**SBOM.** This build environment does not have ``syft`` installed
(confirmed via ``which syft``) and this task does not install new system
tools to get one -- per the task brief, the intended generation command is
documented here instead of blocking on it: once a real build tree exists on
disk (this stack's own ``requirements.txt`` above, scaffolded per build),
run ``syft dir:<generated-app-root> --output cyclonedx-json=sbom.json`` (or
``syft file:<generated-app-root>/requirements.txt`` for a
dependency-manifest-only scan) to produce a CycloneDX SBOM for the
generated app's own dependency tree. Not yet wired into any build step;
tracked as a follow-up once ``syft`` is available in a build environment
(the same "skip, don't block" convention this task's own brief sets for
this exact tool).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from fuzzlab.labgen.emitter import EmittedFile, EmittedFiles, Emitter
from fuzzlab.labgen.schema import Cell, SinkContext

from .modules import COMPLEXITIES, SCAFFOLD_ENV, SINKS, SOURCES, TRANSFORMS


class _ModuleSet(NamedTuple):
    source: str
    sink: str
    complexity: str


#: (vuln_class, sink_context.family) -> which modules render this shape.
#: Tier-A scope only -- identifier/alias/connector-position SQLi and
#: escaping-context-mismatch XSS are deliberately absent (Addendum C pacing
#: decision); any pair not listed here is declared unsupported via
#: `supports()`.
_MODULE_SET_BY_SHAPE: dict[tuple[str, str], _ModuleSet] = {
    ("sqli", "sql_numeric_literal"): _ModuleSet("get_param", "sql_numeric_lookup", "single_statement"),
    ("sqli", "sql_string_literal"): _ModuleSet("post_param", "sql_string_literal_lookup", "single_statement"),
    ("xss", "html_body"): _ModuleSet("read_stored_field", "html_body_echo", "render_only"),
}

#: Per-route static render context (table/column/param names, or the stored
#: field expression an HTML-sink cell reads), the same "render-only
#: information, not verdict-relevant" split php_current's own
#: `_PAGE_PARAMS` uses -- `fuzzlab.labgen.schema.Cell` deliberately carries
#: only what `verdict()` needs. These are illustrative synthetic routes
#: (this stack has no real hand-built app to migrate, unlike php_laravel).
#:
#: CC-LAB-0246 (FR-LAB-169, Browsable Labs Lane 6; PA-0053/PA-0054/BUG-0056)
#: adds render-only keys, identical on both twins of a route:
#:
#: * ``absent_input`` (required): the declared absent-input behavior, from
#:   the shared cross-emitter vocabulary (Lane 4's S15 spellings), allowed
#:   per source kind by :data:`ABSENT_INPUT_BY_SOURCE` -- ``default_value``
#:   (+ ``default_literal``), ``required_param`` (handled 400 before any
#:   transform/sink) or ``no_input``;
#: * ``nav_label``: the page's link text on the homepage/nav (``site.py``);
#: * ``form_fields`` (POST routes): the fields of the GET form page the
#:   site layer serves at the same path (design contract point 4).
_PAGE_PARAMS: dict[str, dict[str, Any]] = {
    # A plain query-string route, deliberately not `/products/{id}` -- the
    # source module reads `id` via `request.query_params.get(...)`
    # (GetParamSource's own docstring explains why: a `{id}` FastAPI path
    # parameter with no matching typed function argument is a startup-time
    # routing error, and a *typed* one would coerce/reject non-numeric
    # input before the handler body ever ran, closing off this shape).
    # CC-LAB-0246: `default_value` "1" fixes D1/BUG-0056 (a bare GET
    # concatenated `str(None)` into SQL and 500'd on the vulnerable twin).
    "/products": {
        "var_name": "id", "param_name": "id", "table": "products", "column": "id",
        "absent_input": "default_value", "default_literal": "1",
        "nav_label": "Product",
    },
    "/login": {
        "var_name": "username",
        "param_name": "username",
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
        "absent_input": "required_param",
        "nav_label": "Log in",
        "form_fields": ("username", "password"),
    },
    "/profile": {
        "var_name": "bio", "stored_expr": "current_user['bio']", "css_class": "bio",
        "absent_input": "no_input",
        "nav_label": "Profile",
    },
}

#: CC-LAB-0246: which ``absent_input`` values each source module may carry
#: (PA-0054 (1), checked offline by tests/test_labgen_python_fastapi_browsable.py).
ABSENT_INPUT_BY_SOURCE: dict[str, frozenset[str]] = {
    "get_param": frozenset({"default_value", "required_param"}),
    "post_param": frozenset({"default_value", "required_param"}),
    "read_stored_field": frozenset({"no_input"}),
}


def served_path_for(cell: Cell, cells: list[Cell]) -> str:
    """CC-LAB-0246 (F3/R-B7 branch (a)): the path ``cell`` is actually served
    at in a whole-app build of ``cells`` -- the pure-Python mirror of
    ``app/main.py``'s router discovery. Routers are included in sorted
    module-name order; the first to claim a ``(method, path)`` keeps it, and
    any later router claiming a taken pair is included under the prefix
    ``/twin/<cell-id>``, so both twins of a pair are served (the per-cell
    files are unchanged, keeping every minimal pair intact)."""
    taken: set[tuple[str, str]] = set()
    for other in sorted(cells, key=lambda c: _module_name(c.cell_id)):
        key = (other.route.method, other.route.path)
        path = other.route.path if key not in taken else f"/twin/{other.cell_id.lower()}{other.route.path}"
        taken.add((other.route.method, path))
        if other.cell_id == cell.cell_id:
            return path
    raise ValueError(f"{cell.cell_id} is not in the given cell set")


def _module_name(cell_id: str) -> str:
    return cell_id.lower().replace("-", "_")


class PythonFastapiEmitter(Emitter):
    """Renders a :class:`Cell` to one FastAPI router module via module
    composition. Mirrors ``PhpCurrentEmitter``'s fail-loud discipline:
    an unsupported shape or an unknown route/op raises rather than
    guessing at a default.
    """

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return (vuln_class, sink_context.family) in _MODULE_SET_BY_SHAPE

    def render(self, cell: Cell) -> EmittedFiles:
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError(
                f"{cell.cell_id}: unsupported for python_fastapi "
                f"(class={cell.vuln_class!r}, sink_context.family={cell.sink_context.family!r}) "
                "-- callers must check supports() before calling render(), per T-LAB0.4's "
                "declare-unsupported-and-skip rule"
            )
        modules = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)]

        if cell.route.path not in _PAGE_PARAMS:
            raise ValueError(
                f"{cell.cell_id}: python_fastapi has no route profile for {cell.route.path!r} "
                f"-- known routes: {sorted(_PAGE_PARAMS)}"
            )
        ctx: dict[str, Any] = dict(_PAGE_PARAMS[cell.route.path])
        ctx["handler_name"] = f"handle_{cell.cell_id.lower().replace('-', '_')}"

        source_result = SOURCES[modules.source].render(ctx)
        ctx = source_result.context

        applied_ops = list(cell.transform.ops) or ["identity"]
        transform_code_blocks: list[str] = []
        for op in applied_ops:
            if op not in TRANSFORMS:
                raise ValueError(
                    f"{cell.cell_id}: python_fastapi has no transform module for op {op!r} "
                    f"-- known ops: {sorted(TRANSFORMS)}"
                )
            transform_result = TRANSFORMS[op].render(ctx)
            ctx = transform_result.context
            transform_code_blocks.append(transform_result.code)

        sink_result = SINKS[modules.sink].render(ctx)

        body = _indent_block(
            "\n".join((source_result.code, *transform_code_blocks, sink_result.code)),
            "    ",
        )
        complexity_result = COMPLEXITIES[modules.complexity].render({**ctx, "body": body})

        composition = " -> ".join((modules.source, *applied_ops, modules.sink, modules.complexity))
        handler_source = complexity_result.code
        python_source = (
            f"# Generated by fuzzlab.labgen.emitters.python_fastapi for cell {cell.cell_id}\n"
            f"# Route: {cell.route.method} {cell.route.path}\n"
            f"# Module composition: {composition}\n"
            "from __future__ import annotations\n"
            "\n"
            "import hashlib\n"
            "import html\n"
            "\n"
            "import jinja2\n"
            "from fastapi import APIRouter, Depends, Request\n"
            "from fastapi.responses import HTMLResponse, JSONResponse\n"
            "from sqlalchemy import text\n"
            "from sqlalchemy.orm import Session\n"
            "\n"
            "from ..db import get_current_user, get_db\n"
            "from ..site import layout, render_row\n"
            "\n"
            "router = APIRouter()\n"
            "\n"
            "\n"
            f'@router.{cell.route.method.lower()}("{cell.route.path}")\n'
            f"{handler_source}"
        )
        path = f"app/routers/{cell.cell_id.lower().replace('-', '_')}.py"
        return (EmittedFile(path=path, content=python_source.encode("utf-8"), role="controller"),)


def _indent_block(text: str, prefix: str) -> str:
    """Indent every non-blank line of ``text`` by ``prefix``. Deterministic
    and dependency-free, matching ``php_current``'s own helper exactly
    (duplicated rather than imported, per this lane's "no cross-imports
    between stack emitter packages" isolation)."""
    lines = text.split("\n")
    return "\n".join((prefix + line) if line else line for line in lines)


# --- StackEnv (CR-LAB-0001 Addendum D) -------------------------------------
#
# `fuzzlab.labgen.schema` does not yet define a shared `StackEnv` type (no
# Phase-3 stack lane has landed one yet as of this lane's own build; the
# Phase 3 lane map explicitly keeps `schema.py` a "shared read-only file"
# lanes must not edit concurrently without coordinating). This dataclass is
# therefore package-local, matching Addendum D's field list, until a shared
# location is agreed across the Node/Express, Python/FastAPI, and PHP/Laravel
# lanes -- not a permanent design choice, a scoping one.
@dataclass(frozen=True)
class StackEnv:
    language: str
    framework: str
    framework_version: str
    base_image: str
    workdir: str
    entrypoint_cmd: tuple[str, ...]
    is_multi_file: bool
    scaffold_files: EmittedFiles
    accumulators: tuple[str, ...] = ()
    file_roles: dict[str, str] = field(default_factory=dict)


#: FastAPI version this emitter is pinned to -- matches the generated app's
#: own `requirements.txt` lockfile (below) and this environment's installed
#: `fastapi` (confirmed via `python3 -c "import fastapi; print(fastapi.__version__)"`
#: during this task's build), and the current PyPI latest as of 2026-09-21.
FASTAPI_VERSION = "0.141.1"
UVICORN_VERSION = "0.53.0"
SQLALCHEMY_VERSION = "2.0.54"
JINJA2_VERSION = "3.1.6"
PYDANTIC_VERSION = "2.13.5"

#: Digest-pinned per decision D7's convention (`lab/web.Dockerfile`). Fetched
#: live against the Docker Hub registry API (`docker-content-digest` response
#: header for the `python:3.12-slim-bookworm` multi-arch manifest list) on
#: 2026-09-21 -- see `templates/scaffold/Dockerfile.j2`'s own comment for the
#: fetch method; re-confirm at the next scheduled base-image refresh.
_BASE_IMAGE_TAG = "python:3.12-slim-bookworm"
_BASE_IMAGE_DIGEST = "sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e"
BASE_IMAGE = f"{_BASE_IMAGE_TAG}@{_BASE_IMAGE_DIGEST}"

WORKDIR = "/app"
ENTRYPOINT_CMD: tuple[str, ...] = ("uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000")


def render_scaffold_files() -> EmittedFiles:
    """Render this stack's one-time scaffold files (Addendum D's
    ``scaffold_files``). Deterministic across calls (no wall-clock/random
    inputs) -- the CLI (once built, T-LAB0.10) calls this exactly once per
    build, never per cell."""
    main_code = SCAFFOLD_ENV.get_template("main.py.j2").render(app_title="fuzzlab lab (python_fastapi, Tier-A)")
    db_code = SCAFFOLD_ENV.get_template("db.py.j2").render(app_slug="fuzzlab_lab")
    dockerfile = SCAFFOLD_ENV.get_template("Dockerfile.j2").render(
        base_image=BASE_IMAGE,
        base_image_tag=_BASE_IMAGE_TAG,
        workdir=WORKDIR,
        entrypoint_cmd_json=json.dumps(list(ENTRYPOINT_CMD)),
    )
    requirements = SCAFFOLD_ENV.get_template("requirements.txt.j2").render(
        fastapi_version=FASTAPI_VERSION,
        uvicorn_version=UVICORN_VERSION,
        sqlalchemy_version=SQLALCHEMY_VERSION,
        jinja2_version=JINJA2_VERSION,
        pydantic_version=PYDANTIC_VERSION,
    )
    # CC-LAB-0246: the site layer's page table, rendered statically from
    # _PAGE_PARAMS (sorted -> deterministic), never read from app.routes.
    pages = {
        path: {
            "label": profile["nav_label"],
            **({"form_fields": tuple(profile["form_fields"])} if "form_fields" in profile else {}),
        }
        for path, profile in sorted(_PAGE_PARAMS.items())
    }
    site_code = SCAFFOLD_ENV.get_template("site.py.j2").render(
        app_name="fuzzlab FastAPI sample", pages_literal=repr(pages)
    )
    return (
        EmittedFile(path="app/__init__.py", content=b"", role="scaffold"),
        EmittedFile(path="app/main.py", content=main_code.encode("utf-8"), role="scaffold"),
        EmittedFile(path="app/db.py", content=db_code.encode("utf-8"), role="scaffold"),
        EmittedFile(path="app/site.py", content=site_code.encode("utf-8"), role="scaffold"),
        EmittedFile(path="app/routers/__init__.py", content=b"", role="scaffold"),
        EmittedFile(path="requirements.txt", content=requirements.encode("utf-8"), role="scaffold"),
        EmittedFile(path="Dockerfile", content=dockerfile.encode("utf-8"), role="scaffold"),
    )


STACK_ENV = StackEnv(
    language="python",
    framework="fastapi",
    framework_version=FASTAPI_VERSION,
    base_image=BASE_IMAGE,
    workdir=WORKDIR,
    entrypoint_cmd=ENTRYPOINT_CMD,
    is_multi_file=True,
    scaffold_files=render_scaffold_files(),
    accumulators=(),  # static discovery scaffold replaces a `route` accumulator -- see module docstring
    file_roles={"controller": "app/routers/{cell_id_lower}.py"},
)
