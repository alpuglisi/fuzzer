"""Offline Browsable Labs checks for ForgeCart, the ``ruby_rails`` app
(CC-LAB-0245 / FR-LAB-166, ``docs/LAB_LANE5_RUBY_RAILS_FORGECART_PLAN.md`` §4
"Offline"). Every check the plan names O1-O7 lives here, each with the
adversarial self-test the plan requires (PA-0034(2)): a check that has only
ever been run against today's clean codebase proves nothing about whether it
can fail.

* O1 / O1-neg -- PA-0054 part 1: every named input every route reads has a
  *declared* absent-input behavior, and the rendered controller implements it.
* O2 -- the shared layout's structure (no per-request token, no external
  asset, sorted nav groups).
* O3 -- every nav target is a served route of the whole-app build; every real
  page profile is a ground-truth URL with the plan §1e classification.
* O4 -- GET page routes are emitted exactly for the profiles that have one.
* O5a / O5b -- CSRF posture of skeleton views; the webhook console's script.
* O6 -- the Rails skeleton's debug posture (BUG-0055/PA-0057).
* O7 / O7-neg -- no test or detection code depends on Rails debug-page
  content (standing check, not a one-time grep).
"""

from __future__ import annotations

import glob
import re
import shutil
from pathlib import Path

import pytest

from fuzzlab.labels.contract import load_injection_points
from fuzzlab.labgen.conformance import tier0
from fuzzlab.labgen.emitters.ruby_rails import (
    _ABSENT_INPUT_BY_SHAPE,
    _REAL_PAGE_PROFILES,
    RailsEmitter,
    ShapeAbsentInput,
    absent_input_violations,
    url_path_for,
)
from fuzzlab.labgen.emitters.ruby_rails.route_accumulator import (
    DuplicateRouteError,
    RouteAccumulator,
    served_routes,
)
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest

REPO = Path(__file__).resolve().parent.parent
SKELETON = REPO / "fuzzlab" / "labgen" / "emitters" / "ruby_rails" / "stack" / "skeleton"
VIEWS = SKELETON / "app" / "views"
LAYOUT = VIEWS / "layouts" / "application.html.erb"
CONSOLE = VIEWS / "webhooks" / "console.html.erb"
GROUND_TRUTH = "lab/ground-truth-forgecart"


def _illustrative_cell() -> Cell:
    # LABGEN-RR-0001, built in tests only (no manifest carries it) -- the same
    # construction the whole-app live test uses.
    return Cell(
        cell_id="LABGEN-RR-0001",
        vuln_class="xss",
        stack_profile="ruby_rails",
        route=Route(method="GET", path=url_path_for("LABGEN-RR-0001")),
        sink_context=SinkContext(family="html_body"),
        transform=Pipeline(),
    )


def _every_ruby_rails_cell() -> list[Cell]:
    """Every ruby_rails cell of every manifest the emitter supports
    (PA-0027: derived from `supports()`, not a literal list), plus the
    test-only illustrative cell."""
    emitter = RailsEmitter()
    seen: dict[str, Cell] = {"LABGEN-RR-0001": _illustrative_cell()}
    for path in sorted(glob.glob(str(REPO / "lab" / "manifests" / "*.yaml"))):
        for cell in load_manifest(path).cells:
            if cell.stack_profile == "ruby_rails" and emitter.supports(cell.vuln_class, cell.sink_context):
                seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


def _whole_app_routes_rb() -> str:
    emitter = RailsEmitter()
    return RouteAccumulator().render_file({c.cell_id: emitter.route_fragment_for(c) for c in _every_ruby_rails_cell()})


def _controller(cell: Cell) -> str:
    return next(f.content.decode("utf-8") for f in RailsEmitter().render(cell) if f.role == "controller")


# --- O1 / O1-neg: absent-input declarations (PA-0054 part 1) ----------------


def test_o1_every_route_declares_and_implements_its_absent_input_behavior() -> None:
    cells = _every_ruby_rails_cell()
    # Non-vacuous: all 12 whole-app cells, all four shapes.
    assert len(cells) >= 12
    assert {(c.vuln_class, c.sink_context.family) for c in cells} == set(_ABSENT_INPUT_BY_SHAPE)
    violations = [v for c in cells for v in absent_input_violations(c)]
    assert violations == []


def test_o1_neg_a_missing_declaration_is_reported() -> None:
    cell = next(c for c in _every_ruby_rails_cell() if c.cell_id == "LABGEN-RR-RP-0005")
    shape = (cell.vuln_class, cell.sink_context.family)
    stripped = {k: v for k, v in _ABSENT_INPUT_BY_SHAPE.items() if k != shape}
    assert absent_input_violations(cell, declarations=stripped)
    # ... and a declaration with no inputs is reported too.
    emptied = {**_ABSENT_INPUT_BY_SHAPE, shape: ShapeAbsentInput(inputs=(), bare_status=400)}
    assert absent_input_violations(cell, declarations=emptied)


def test_o1_neg_a_controller_without_the_declared_construct_is_reported() -> None:
    for cell_id, bare in (("LABGEN-RR-RP-0001", "value = params[:q]"), ("LABGEN-RR-RP-0005", "raw_yaml = params[:yaml_payload]")):
        cell = next(c for c in _every_ruby_rails_cell() if c.cell_id == cell_id)
        source = _controller(cell)
        construct = next(i.construct for i in _ABSENT_INPUT_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)].inputs)
        lhs = bare.split(" = ")[0]
        degraded = source.replace(f"{lhs} = {construct}", bare)
        assert degraded != source
        found = absent_input_violations(cell, controller_source=degraded)
        assert any("not in the rendered controller" in v for v in found), found
        assert any("bare params[" in v for v in found), found


def test_o1_neg_a_source_cannot_render_without_a_declared_behavior() -> None:
    from fuzzlab.labgen.emitters.ruby_rails.modules import SOURCES

    for name in ("get_param", "post_param"):
        with pytest.raises(ValueError, match="absent-input"):
            SOURCES[name].render({"var_name": "v", "param_name": "p", "absent_kind": None, "default_rb": None})


# --- O2: the shared layout -------------------------------------------------


def test_o2_layout_structure() -> None:
    text = LAYOUT.read_text(encoding="utf-8")
    code = re.sub(r"<%#.*?%>", "", text, flags=re.S)  # ERB comments may name what is excluded
    for forbidden in ("csrf_meta_tags", "csp_meta_tag", "stylesheet_link_tag", "javascript_include_tag",
                      'rel="stylesheet"', "src=\"http", "href=\"http", "request.", "params"):
        assert forbidden not in code, forbidden
    assert "<style>" in code and "<nav>" in code and "<header>" in code and "<footer>" in code
    assert "<%= yield %>" in code
    assert '<form action="/search" method="get"' in code
    assert 'name="q"' in code and 'value="' not in code  # the search box never echoes q
    nav = code.split("<nav>", 1)[1].split("</nav>", 1)[0]
    groups = nav.split("<br>")
    assert len(groups) == 2
    for group in groups:
        hrefs = re.findall(r'href="([^"]+)"', group)
        assert hrefs and hrefs == sorted(hrefs), hrefs


# --- O3: nav targets and page profiles --------------------------------------


def _nav_hrefs() -> list[str]:
    nav = LAYOUT.read_text(encoding="utf-8").split("<nav>", 1)[1].split("</nav>", 1)[0]
    return re.findall(r'href="([^"]+)"', nav)


def test_o3_every_nav_target_is_a_get_route_of_the_whole_app_build() -> None:
    get_paths = {path for verb, path, _ in served_routes(_whole_app_routes_rb()) if verb == "GET"}
    missing = [h for h in _nav_hrefs() if h not in get_paths]
    assert missing == []
    # Every served page (not /up, not illustrative /cell/*) is in the nav.
    pages = {p for p in get_paths if p != "/up" and not p.startswith("/cell/")}
    assert pages == set(_nav_hrefs())


def test_o3_profiles_are_ground_truth_urls_with_the_plan_classification() -> None:
    gt_urls = {p.url for p in load_injection_points(GROUND_TRUTH)}
    assert set(_REAL_PAGE_PROFILES) == gt_urls
    # Plan §1e: exactly the two webhook receivers are `api`.
    apis = {url for url, profile in _REAL_PAGE_PROFILES.items() if profile.kind == "api"}
    assert apis == {"/webhooks/orders/create", "/webhooks/customers/update"}
    assert {p.kind for p in _REAL_PAGE_PROFILES.values()} == {"page", "api"}


def test_o3_served_routes_parser_refuses_an_unknown_line() -> None:
    with pytest.raises(ValueError):
        served_routes("Rails.application.routes.draw do\n  resources :things\nend\n")


# --- O4: GET page route emission ---------------------------------------------


def test_o4_get_page_lines_exactly_for_profiles_with_one() -> None:
    routes = served_routes(_whole_app_routes_rb())
    get_page_targets = {path: target for verb, path, target in routes if verb == "GET" and "#" in target
                        and not target.startswith("cell_")}
    for url, profile in _REAL_PAGE_PROFILES.items():
        if profile.get_page:
            assert get_page_targets.get(url) == profile.get_page, url
    # No illustrative cell gets a GET page.
    assert not [p for p in get_page_targets if p.startswith("/cell/")]
    # A GET page never breaks the duplicate-URL defence.
    emitter = RailsEmitter()
    cell = next(c for c in _every_ruby_rails_cell() if c.cell_id == "LABGEN-RR-RP-0004")
    with pytest.raises(DuplicateRouteError):
        RouteAccumulator().render_file({"A": emitter.route_fragment_for(cell), "B": emitter.route_fragment_for(cell)})


# --- O5a / O5b ---------------------------------------------------------------


def test_o5a_no_skeleton_view_adds_forgery_tokens() -> None:
    views = sorted(VIEWS.rglob("*.erb"))
    assert len(views) >= 12
    for view in views:
        code = re.sub(r"<%#.*?%>", "", view.read_text(encoding="utf-8"), flags=re.S)
        for forbidden in ("form_with", "form_tag", "csrf_meta_tags", "authenticity_token"):
            assert forbidden not in code, (view, forbidden)


def test_o5b_webhook_console_script() -> None:
    text = CONSOLE.read_text(encoding="utf-8")
    script = text.split("<script>", 1)[1].split("</script>", 1)[0]
    secret = "whsec_lab_lab_only_not_a_real_secret"
    assert secret not in text  # R6: never embeds the secret
    assert "Accept" not in script  # R2: no Accept override
    assert "window.location.pathname" in script and "fetch(" in script
    assert '"X-Shopify-Hmac-SHA256"' in script
    # R2: JSON.parse only inside a try, with a raw-text fallback.
    assert script.count("JSON.parse") == 1
    assert re.search(r"try\s*\{[^}]*JSON\.parse[^}]*\}\s*catch", script)
    assert "request." not in text and "params" not in text  # reads no request data


# --- O6: Rails skeleton debug posture (BUG-0055/PA-0057) -------------------


def test_o6_development_environment_shows_no_detailed_exceptions_or_view_annotations() -> None:
    from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness

    env = RailsLiveBootHarness(RailsEmitter(), [])._harness_env()["RAILS_ENV"]
    config = (SKELETON / "config" / "environments" / f"{env}.rb").read_text(encoding="utf-8")
    code = "\n".join(line for line in config.splitlines() if not line.strip().startswith("#"))
    assert re.search(r"^\s*config\.consider_all_requests_local\s*=\s*false\s*$", code, re.M)
    assert re.search(r"^\s*config\.action_view\.annotate_rendered_view_with_filenames\s*=\s*false\s*$", code, re.M)
    assert "= true" not in re.findall(r"consider_all_requests_local.*", code)[0]


# --- O7 / O7-neg: no code depends on Rails debug-page content ---------------

#: Strings that only a Rails detailed exception / routing-error page contains.
_DEBUG_PAGE_STRINGS = (
    "Extracted source",
    "Routing Error",
    "Routes match in priority",
    "Full Trace",
    "Application Trace",
    "Framework Trace",
    "ActionController::RoutingError",
    "ActionController::ParameterMissing",
    "ActiveRecord::RecordNotFound",
    "Rails.root",
)

#: Directory prefixes that build/boot the app rather than consume its error
#: pages (matched by exact directory prefix, never substring).
_EXCLUDED_DIRS = ("fuzzlab/labgen/emitters/ruby_rails",)
_EXCLUDED_FILES = ("fuzzlab/labgen/conformance/rails_live_boot.py",)

#: Pinned, literal allowlist: files that name the strings only to assert their
#: ABSENCE. Exactly 2 -- this file (where every O-check lives) and the live
#: navigability test. Adding one is a reviewed code change, never a pattern.
_ALLOWLIST = (
    "tests/test_labgen_ruby_rails_browsable.py",
    "tests/test_labgen_ruby_rails_navigability_live_boot.py",
)


def scan_debug_page_dependencies(root: Path) -> list[tuple[str, int, str]]:
    """Every (relative path, line, string) hit of a Rails debug-page string in
    a `*.py` under `root/tests` or `root/fuzzlab`, minus the exact exclusions
    and the pinned allowlist. Paths compare as POSIX strings relative to
    `root`; exclusions are exact files or exact directory prefixes."""
    hits: list[tuple[str, int, str]] = []
    for top in ("tests", "fuzzlab"):
        base = root / top
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            if "__pycache__" in rel.split("/"):
                continue
            if rel in _EXCLUDED_FILES or rel in _ALLOWLIST:
                continue
            if any(rel.startswith(d + "/") for d in _EXCLUDED_DIRS):
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for needle in _DEBUG_PAGE_STRINGS:
                    if needle in line:
                        hits.append((rel, lineno, needle))
    return hits


def test_o7_no_test_or_detection_code_depends_on_rails_debug_pages() -> None:
    assert scan_debug_page_dependencies(REPO) == []


def test_o7_neg_the_scan_reports_real_hits_and_honours_only_exact_exclusions(tmp_path: Path) -> None:
    planted = {
        # must be reported
        "tests/test_synthetic_scrape.py": "Extracted source",
        "fuzzlab/synthetic_oracle.py": "ActionController::RoutingError",
        # must NOT be reported: inside the exclusion / an allowlisted name
        "fuzzlab/labgen/emitters/ruby_rails/synthetic_module.py": "Routing Error",
        "tests/test_labgen_ruby_rails_browsable.py": "Full Trace",
        # must still be reported: near misses of the exclusion / allowlist
        "fuzzlab/labgen/emitters/ruby_rails_extra/synthetic.py": "Application Trace",
        "tests/test_labgen_ruby_rails_browsable_extra.py": "Rails.root",
    }
    for rel, needle in planted.items():
        dest = tmp_path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f"X = {needle!r}\n", encoding="utf-8")
    reported = {rel for rel, _, _ in scan_debug_page_dependencies(tmp_path)}
    assert reported == {
        "tests/test_synthetic_scrape.py",
        "fuzzlab/synthetic_oracle.py",
        "fuzzlab/labgen/emitters/ruby_rails_extra/synthetic.py",
        "tests/test_labgen_ruby_rails_browsable_extra.py",
    }


# --- R16: whole-collection render stays valid Ruby (PA-0024) ---------------


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby interpreter not available (PA-0005)")
def test_r16_every_ruby_rails_cell_renders_to_valid_ruby() -> None:
    emitter = RailsEmitter()
    cells = _every_ruby_rails_cell()
    assert len(cells) >= 12
    for cell in cells:
        for result in tier0.lint_ruby_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: ruby -c failed: {result.detail}"
