"""Browsable Labs checks for the generic `python_fastapi` sample (CC-LAB-0246 /
FR-LAB-169, `docs/LAB_LANE6_NODE_FASTAPI_PLAN.md` §2B/§4B).

No spider crawl, by explicit decision (plan §4B): the sample has no ground
truth, so contract point 6's "100% of ground-truth URLs" is vacuous. The
PA-0053/PA-0054 obligations are enforced in-process instead:

1. PA-0054 (1), offline: every route the sample's manifests produce declares
   an `absent_input` value allowed for its source kind, rendered before the
   transform, identically on both twins;
2. R-B3: the site table (`_PAGE_PARAMS`) covers exactly the manifest routes;
3. `GET /` is 200 HTML in the layout, and every served GET page is
   link-reachable from `/` (a BeautifulSoup BFS, the parser `LocalSpider`'s
   static engine uses);
4. PA-0054 (2): a bare request to every served path (`served_path_for` over
   every cell, twins included, plus the site layer) answers < 500, with the
   declared statuses asserted exactly;
5. R-B2 (found/not-found byte difference), R-B5 (GET form + POST cell on
   one path), R-B7/F3 branch (a) (each twin served at its own URL, with its
   own behavior).

POSTs to `/login` are skip-guarded on `python-multipart` (R-B4 / F4: the
generated app's requirements do not declare it; it is present here only by
accident of this environment).
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from fuzzlab.labgen.emitters.python_fastapi import (
    _MODULE_SET_BY_SHAPE,
    _PAGE_PARAMS,
    ABSENT_INPUT_BY_SOURCE,
    STACK_ENV,
    PythonFastapiEmitter,
    served_path_for,
)
from fuzzlab.labgen.schema import load_manifest

_MANIFEST = "lab/manifests/phase3_python_fastapi_sample.yaml"
_CELLS = list(load_manifest(_MANIFEST).cells)


def _deps() -> bool:
    return all(importlib.util.find_spec(m) is not None for m in ("fastapi", "sqlalchemy", "httpx"))


def _multipart() -> bool:
    return importlib.util.find_spec("multipart") is not None


def _source_of(cell) -> str:
    return _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)].source


# --- offline -----------------------------------------------------------------


def test_every_route_declares_an_allowed_absent_input() -> None:
    routes = {c.route.path for c in _CELLS}
    assert routes == {"/login", "/products", "/profile"}  # hard-coded
    for cell in _CELLS:
        profile = _PAGE_PARAMS[cell.route.path]
        assert profile.get("absent_input") in ABSENT_INPUT_BY_SOURCE[_source_of(cell)], cell.cell_id
        if profile["absent_input"] == "default_value":
            assert profile.get("default_literal"), cell.cell_id


def test_site_table_covers_exactly_the_manifest_routes() -> None:
    """R-B3: the homepage/form table is rendered from _PAGE_PARAMS, so it
    must equal the sample's route set (a new route without a site entry fails)."""
    assert set(_PAGE_PARAMS) == {c.route.path for c in _CELLS}
    assert all(profile.get("nav_label") for profile in _PAGE_PARAMS.values())


def _declaration_lines(cell) -> str:
    source = PythonFastapiEmitter().render(cell)[0].content.decode("utf-8")
    keep = [
        ln.strip() for ln in source.splitlines()
        if "query_params.get(" in ln or "request.form()).get(\"" + str(_PAGE_PARAMS[cell.route.path].get("param_name")) in ln
        or "missing required parameter" in ln
    ]
    return "\n".join(keep)


def test_absent_input_is_rendered_and_identical_on_both_twins() -> None:
    by_route: dict[str, set[str]] = {}
    for cell in _CELLS:
        decl = _PAGE_PARAMS[cell.route.path]["absent_input"]
        lines = _declaration_lines(cell)
        if decl == "default_value":
            assert f'or "{_PAGE_PARAMS[cell.route.path]["default_literal"]}"' in lines, (cell.cell_id, lines)
        if decl == "required_param":
            assert "missing required parameter" in lines, (cell.cell_id, lines)
        by_route.setdefault(cell.route.path, set()).add(lines)
    for route, variants in by_route.items():
        assert len(variants) == 1, (route, variants)


def test_served_path_for_gives_each_twin_its_own_url() -> None:
    paths = {c.cell_id: served_path_for(c, _CELLS) for c in _CELLS}
    assert paths == {
        "LABGEN-PY-0001": "/products",
        "LABGEN-PY-0002": "/twin/labgen-py-0002/products",
        "LABGEN-PY-0003": "/login",
        "LABGEN-PY-0004": "/twin/labgen-py-0004/login",
        "LABGEN-PY-0005": "/profile",
        "LABGEN-PY-0006": "/twin/labgen-py-0006/profile",
    }


# --- in-process (TestClient) --------------------------------------------------


@pytest.fixture(scope="module")
def client() -> Iterator:
    if not _deps():
        pytest.skip("fastapi/sqlalchemy/httpx not installed (optional extra, PA-0005)")
    tmpdir = tempfile.mkdtemp()
    emitter = PythonFastapiEmitter()
    for f in (*STACK_ENV.scaffold_files, *(g for c in _CELLS for g in emitter.render(c))):
        p = Path(tmpdir) / f.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(f.content)
    old_cwd = os.getcwd()
    sys.path.insert(0, tmpdir)
    os.chdir(tmpdir)
    for name in [m for m in list(sys.modules) if m == "app" or m.startswith("app.")]:
        del sys.modules[name]
    try:
        main = importlib.import_module("app.main")
        from fastapi.testclient import TestClient

        yield TestClient(main.app, raise_server_exceptions=False)
    finally:
        os.chdir(old_cwd)
        sys.path.remove(tmpdir)
        for name in [m for m in list(sys.modules) if m == "app" or m.startswith("app.")]:
            del sys.modules[name]


def _served_get_paths() -> set[str]:
    return {served_path_for(c, _CELLS) for c in _CELLS} | {"/"}


def test_homepage_is_html_in_the_layout(client) -> None:
    r = client.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "<header>" in r.text and "<footer>" in r.text and "fuzzlab FastAPI sample" in r.text


def test_every_served_page_is_link_reachable_from_home(client) -> None:
    seen: dict[str, int] = {"/": 0}
    frontier = ["/"]
    while frontier:
        path = frontier.pop(0)
        if seen[path] >= 2:
            continue
        r = client.get(path)
        if "text/html" not in r.headers.get("content-type", ""):
            continue
        for a in BeautifulSoup(r.text, "html.parser").find_all("a", href=True):
            href = a["href"].split("#")[0]
            if href.startswith("/") and href not in seen:
                seen[href] = seen[path] + 1
                frontier.append(href)
    missing = sorted(_served_get_paths() - set(seen))
    assert not missing, (missing, sorted(seen))


def test_pa_0054_bare_request_sweep(client) -> None:
    expected = {
        "/": 200,
        "/products": 200,  # default id 1 (D1 fixed)
        "/twin/labgen-py-0002/products": 200,
        "/login": 200,  # GET form page
        "/twin/labgen-py-0004/login": 200,
        "/profile": 200,
        "/twin/labgen-py-0006/profile": 200,
    }
    assert set(expected) == _served_get_paths()
    statuses = {path: client.get(path).status_code for path in sorted(expected)}
    assert statuses == expected, statuses


@pytest.mark.skipif(not _multipart(), reason="python-multipart not installed (R-B4 / F4)")
def test_bare_post_login_is_a_handled_400_on_both_twins(client) -> None:
    for path in ("/login", "/twin/labgen-py-0004/login"):
        r = client.post(path)
        assert r.status_code == 400 and "missing required parameter" in r.text, (path, r.status_code)


def test_found_and_not_found_views_differ_by_at_least_200_bytes(client) -> None:
    """R-B2: measured 2026-09-25 -- found 1,137 vs not-found 924 bytes (213)."""
    for path in ("/products", "/twin/labgen-py-0002/products"):
        found = client.get(path, params={"id": "1"})
        missing = client.get(path, params={"id": "999"})
        assert found.status_code == missing.status_code == 200
        assert "<td>Puppy Bed</td>" in found.text and "No matching record." in missing.text
        assert len(found.content) - len(missing.content) >= 200, (len(found.content), len(missing.content))


@pytest.mark.skipif(not _multipart(), reason="python-multipart not installed (R-B4 / F4)")
def test_get_form_and_post_cell_share_one_path(client) -> None:
    """R-B5: GET /login renders the form; POST /login still reaches the cell."""
    form = client.get("/login")
    assert form.status_code == 200 and '<form method="post" action="/login">' in form.text
    posted = client.post("/login", data={"username": "ryder", "password": "changeme"})
    assert posted.status_code == 200 and "<td>ryder</td>" in posted.text


def test_each_twin_is_served_with_its_own_behavior(client) -> None:
    """R-B7 / F3 branch (a): the secure twin answers at its /twin/ URL."""
    r = client.get("/twin/labgen-py-0006/profile")
    assert r.status_code == 200 and '<div class="bio">' in r.text
    r = client.get("/twin/labgen-py-0002/products", params={"id": "1"})
    assert r.status_code == 200 and "<td>Puppy Bed</td>" in r.text
    # The secure twin's source differs from the vulnerable one's only in the
    # transform/sink region, and the file itself is unchanged by the prefix.
    secure = PythonFastapiEmitter().render(next(c for c in _CELLS if c.cell_id == "LABGEN-PY-0006"))[0]
    assert '@router.get("/profile")' in secure.content.decode("utf-8")
