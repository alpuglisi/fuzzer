"""Offline checks for PicTrail's browsable site (CC-LAB-0242 / FR-LAB-160,
`docs/LAB_LANE2_DJANGO_PICTRAIL_PLAN.md`).

Everything here runs without Django installed (the real rendering is proven
by the `slow` live-boot modules): the plan's §5 step 1 structural gate (the
shared layout template exists and is well-formed, and every page template
extends it), the R1 twin-URL mechanism (branch (a)), the PA-0053 absent-input
declarations every `get_param` route must carry, and the §2e request-encoding
signal `fuzzlab.harness.auto` still derives from the corrected ground truth.
"""

from __future__ import annotations

import glob
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from fuzzlab.harness.auto import points_from_ground_truth
from fuzzlab.labels.contract import load as load_ground_truth
from fuzzlab.labgen.conformance.django_live_boot import SKELETON_DIR
from fuzzlab.labgen.emitters.django import (
    _COMMENT_TEMPLATE_HTML,
    _MODULE_SET_BY_SHAPE,
    _REAL_PAGE_CELL_IDS,
    _REAL_PAGE_TWIN_CELL_IDS,
    _ROUTE_PARAMS,
    _SITE_ROUTES,
    DjangoEmitter,
    served_url_for,
)
from fuzzlab.labgen.schema import load_manifest

TEMPLATES_DIR = SKELETON_DIR / "fuzlab_django_lab" / "templates"
LAYOUT = TEMPLATES_DIR / "layouts" / "site.html"
_EXTENDS = '{% extends "layouts/site.html" %}'

#: Every template a page renders into; `_COMMENT_TEMPLATE_HTML` is checked
#: separately (it is emitted per cell, not a skeleton file).
_PAGE_TEMPLATES = sorted(
    p for p in TEMPLATES_DIR.rglob("*.html") if p != LAYOUT
)


def _django_cells():
    """Every django cell across every manifest, derived from the emitter's
    own `supports()` predicate (PA-0027), never a hand-kept list."""
    emitter = DjangoEmitter()
    seen = {}
    for path in sorted(glob.glob("lab/manifests/*.yaml")):
        for cell in load_manifest(path).cells:
            if cell.stack_profile == "django" and emitter.supports(cell.vuln_class, cell.sink_context):
                seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


class _TagBalance(HTMLParser):
    _VOID = {"meta", "link", "br", "img", "input", "hr"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in self._VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> (open: {self.stack})")
            return
        self.stack.pop()


def _assert_well_formed(text: str, label: str) -> None:
    """HTML tags balanced, and Django block/if/for tags balanced."""
    parser = _TagBalance()
    parser.feed(text)
    parser.close()
    assert not parser.errors, (label, parser.errors)
    assert not parser.stack, (label, parser.stack)
    for opener, closer in (("block", "endblock"), ("if", "endif"), ("for", "endfor")):
        opens = len(re.findall(r"{%\s*" + opener + r"\b", text))
        closes = len(re.findall(r"{%\s*" + closer + r"\b", text))
        assert opens == closes, (label, opener, opens, closes)


# --- §5 step 1 gate: the shared layout exists and is well-formed ------------


def test_shared_layout_exists_and_is_well_formed() -> None:
    assert LAYOUT.is_file(), LAYOUT
    text = LAYOUT.read_text("utf-8")
    assert text.startswith("<!DOCTYPE html>\n"), text[:80]
    _assert_well_formed(text, str(LAYOUT))
    assert "{% block title %}PicTrail{% endblock %}" in text
    assert "{% block content %}{% endblock %}" in text
    assert "<h1><a href=\"/\">PicTrail</a></h1>" in text
    assert "<style>" in text and "<link" not in text and "<script" not in text, (
        "inline CSS only -- no external assets (the lab stays offline and loopback-only)"
    )
    # Nav: the homepage, every page-classified real page, the api's client
    # page, and the catalog (plan §2a/§2c).
    for href in ("/", "/explore", "/post", "/post/comments", "/upload", "/inbox", "/settings", "/catalog"):
        assert f'<a href="{href}">' in text, href
    # Byte-identical across twins by construction: no per-request/per-cell
    # context variable is ever interpolated into the layout itself.
    assert "{{" not in text, "the layout must not interpolate any context variable"


@pytest.mark.parametrize("path", _PAGE_TEMPLATES, ids=lambda p: str(p.relative_to(TEMPLATES_DIR)))
def test_every_page_template_extends_the_shared_layout(path: Path) -> None:
    text = path.read_text("utf-8")
    assert text.startswith(_EXTENDS + "\n"), (path, text[:120])
    assert "{% block content %}" in text, path
    _assert_well_formed(text, str(path))


def test_comment_template_extends_the_shared_layout() -> None:
    assert _COMMENT_TEMPLATE_HTML.startswith(_EXTENDS + "\n")
    assert '<div class="comment">{{ comment }}</div>' in _COMMENT_TEMPLATE_HTML
    _assert_well_formed(_COMMENT_TEMPLATE_HTML, "_COMMENT_TEMPLATE_HTML")


def test_every_template_a_route_profile_names_exists_in_the_skeleton() -> None:
    named = set()
    for profile in _ROUTE_PARAMS.values():
        for key in ("html_row_template", "page_template", "get_form_template"):
            if key in profile:
                named.add(profile[key])
    assert named == {"pages/post_detail.html", "pages/settings.html", "pages/explore.html", "pages/inbox.html"}
    for name in sorted(named):
        assert (TEMPLATES_DIR / name).is_file(), name
    site_py = (SKELETON_DIR / "fuzlab_django_lab" / "views" / "site.py").read_text("utf-8")
    for _, view, _ in _SITE_ROUTES:
        assert f"def {view}(request):" in site_py, view


def test_explore_page_never_echoes_the_sort_value() -> None:
    """R1b/R6: the explore listing's only body-visible response to `sort` is
    the row order -- the template never interpolates the raw key, so two
    different unrecognized keys cannot produce two different bodies on the
    secure twin (the property `identifier_sqli_oracle.py`'s format-agnostic
    body-diff check relies on)."""
    text = (TEMPLATES_DIR / "pages" / "explore.html").read_text("utf-8")
    assert not re.search(r"{{\s*sort", text), text
    assert not re.search(r"{{\s*request", text), text


# --- R1, branch (a): twin-suffixed URLs --------------------------------------


def test_r1_every_secure_twin_is_served_at_its_real_pages_twin_suffixed_url() -> None:
    cells = {c.cell_id: c for c in _django_cells()}
    real_by_path = {cells[cid].route.path: cid for cid in _REAL_PAGE_CELL_IDS}
    assert len(real_by_path) == len(_REAL_PAGE_CELL_IDS) == 6
    assert len(_REAL_PAGE_TWIN_CELL_IDS) == 6
    for twin_id in sorted(_REAL_PAGE_TWIN_CELL_IDS):
        twin = cells[twin_id]
        # Each twin shares its route (and so its route profile) with exactly
        # one real page's vulnerable cell ...
        assert twin.route.path in real_by_path, twin_id
        real = cells[real_by_path[twin.route.path]]
        assert (twin.vuln_class, twin.sink_context.family) == (real.vuln_class, real.sink_context.family)
        # ... and is served at that page's own URL + `.<cell-id>`.
        assert served_url_for(real) == real.route.path
        assert served_url_for(twin) == f"{real.route.path}.{twin_id.lower()}"
    # Illustrative cells keep the generic pattern.
    for cid, cell in cells.items():
        if cid not in _REAL_PAGE_CELL_IDS | _REAL_PAGE_TWIN_CELL_IDS:
            assert served_url_for(cell) == f"/generated/{cid.lower().replace('-', '_')}/", cid


def test_r1_served_urls_are_unique_and_match_the_route_accumulator() -> None:
    cells = _django_cells()
    urls = [served_url_for(c) for c in cells]
    site_urls = ["/" + url_path for url_path, _, _ in _SITE_ROUTES]
    assert len(set(urls + site_urls)) == len(urls) + len(site_urls), sorted(urls + site_urls)
    body = DjangoEmitter().render_route_accumulator(cells).content.decode("utf-8")
    for cell in cells:
        slug = cell.cell_id.lower().replace("-", "_")
        assert f'    path("{served_url_for(cell).lstrip("/")}", handle_{slug}, name="{slug}"),' in body, cell.cell_id
    for url_path, view, name in _SITE_ROUTES:
        assert f'    path("{url_path}", {view}, name="{name}"),' in body
    assert "from fuzlab_django_lab.views.site import catalog, home, upload_client\n" in body
    # /catalog lists every GET-servable page (the illustrative POST-only
    # login API is not linked -- a GET of it is not a page).
    for cell in cells:
        linkable = cell.route.method == "GET" or cell.route.path in ("/settings", "/inbox")
        assert f'("{served_url_for(cell)}", "{cell.cell_id}", "{cell.route.method}", {linkable}),' in body


# --- PA-0053 / PA-0054: absent-input behavior is declared, not incidental ----


def test_every_get_param_route_declares_its_absent_input_behavior() -> None:
    """Every route whose cells read a named GET parameter (`get_param`
    source) declares a real default (`default_value`) or a handled 4xx
    before the sink (`required_param`) -- PA-0053, enforced here offline
    for the whole emitter, independent of what a crawl happens to reach
    (PA-0054)."""
    routes = {
        c.route.path
        for c in _django_cells()
        if _MODULE_SET_BY_SHAPE[(c.vuln_class, c.sink_context.family)].source == "get_param"
    }
    assert routes == {"/api/products", "/post", "/upload/link-preview", "/explore"}
    for route in sorted(routes):
        profile = _ROUTE_PARAMS[route]
        assert ("default_value" in profile) != ("required_param" in profile), (route, profile)


def test_post_pages_answer_get_with_their_form_before_the_sink() -> None:
    """`/settings` and `/inbox` read the POST body; a GET renders the form
    page first and never reaches the source/transform/sink (plan §2d)."""
    for cell in _django_cells():
        if cell.route.path not in ("/settings", "/inbox"):
            continue
        view = DjangoEmitter().render(cell)[0].content.decode("utf-8")
        handler = view[view.index(f"def handle_{cell.cell_id.lower().replace('-', '_')}(request):"):]
        lines = [ln.strip() for ln in handler.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        assert lines[1] == 'if request.method != "POST":', (cell.cell_id, lines[:4])
        assert lines[2].startswith('return render(request, "pages/'), (cell.cell_id, lines[:4])


def test_absent_input_lines_are_identical_on_both_twins() -> None:
    """The new default/required/GET-form/HTML-tail lines live in the source
    and complexity regions, identical on both twins -- every minimal pair
    still differs only in its transform/sink region (BUG-0027)."""
    by_route: dict[str, list[str]] = {}
    for cell in _django_cells():
        view = DjangoEmitter().render(cell)[0].content.decode("utf-8")
        slug = cell.cell_id.lower().replace("-", "_")
        view = view.replace(f"handle_{slug}", "handle_X")
        keep = [
            ln for ln in view.splitlines()
            if "request.GET.get(" in ln or "request.method" in ln
            or "missing required parameter" in ln or "pages/post_detail.html" in ln
        ]
        by_route.setdefault(cell.route.path, []).append("\n".join(keep))
    for route, variants in by_route.items():
        assert len(set(variants)) == 1, (route, variants)


# --- §2e: the corrected `rendering` field keeps auto.py's encoding signal ----


def test_rendering_field_corrected_and_request_encoding_unchanged() -> None:
    ground_truth = load_ground_truth("lab/ground-truth-picktrail-django")
    rendering = {p.url: p.rendering for p in ground_truth.points}
    assert rendering == {
        "/post": "server",
        "/post/comments": "server",
        "/upload/link-preview": "server-json",  # the one genuine `api`, still JSON
        "/settings": "server",
        "/explore": "server",
        "/inbox": "server",
    }
    assert {c.url: c.rendering for c in ground_truth.cases} == rendering
    # `auto.py` only switches to a JSON request body for a whole-body point
    # (`param == "body"`) marked `server-json`; none of PicTrail's points is
    # whole-body, so every point stays form-encoded / query-string, exactly
    # what Django's `request.POST`/`request.GET` parse -- before and after.
    points, skipped = points_from_ground_truth(ground_truth, "http://127.0.0.1:8085")
    assert not skipped
    assert len(points) == 6
    assert all(p.body_content_type is None for p in points), [(p.url, p.body_content_type) for p in points]
