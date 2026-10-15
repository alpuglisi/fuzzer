"""PA-0300: every function that takes an operator base URL has a sub-path test.

BUG-0300: `harness.auto.points_from_ground_truth` joined ground-truth paths to the
whole base URL (`base_url.rstrip("/") + path`), so a base under a sub-path
(`http://127.0.0.1:8092/bWAPP/`) doubled it (`/bWAPP/bWAPP/sqli_1.php`). PA-0113(3)
("every component that takes an operator URL has a test with the app under a
sub-path") already asked for the test that would have caught it, but nothing listed the
components it governs, and BUG-0113's sweep cleared this one "by contract". This file
is that list, made mechanical.

**Discovery rule** (`base_url_functions`): every ``def`` in ``fuzzlab/**.py`` --
functions, methods and nested functions, public or private -- with a parameter that is
an operator base URL:

* (a) **by name:** the parameter's name, split on ``_``, ends in ``url`` and has a
  qualifier from `BASE_QUALIFIERS` before it (``base_url``, ``target_url``,
  ``start_url``, ``target_base_url``, ``auth_base_url``, ``root_url``, ``app_url``);
* (b) **by use:** the parameter is a bare `BARE_BASE_NAMES` name (``base``,
  ``start``, ``root``) and the function uses it as a URL -- inside the first argument
  of one of `URL_FUNCTIONS`, or as the receiver of ``.rstrip("/")`` (BUG-0300's join
  shape). A ``base`` that is a payload, a mapping or a number is not discovered.

Not discovered (stated limits): a request URL (``url``, ``page_url``, ``login_url``)
is not a base; a base read from CLI arguments or config inside a function is covered
where that function passes it on, under one of the names above. An ``origin`` /
``*_origin`` parameter is not discovered: an origin has no path by definition. The one
function that builds request URLs from one (`fuzzlab.lab_fixtures.external._LabClient`)
refuses a URL with a path (tested in ``tests/test_external_labs_static.py``); the others
(e.g. `fuzzlab.ml.holdout`'s ``origin`` / ``run_origin``) use it as a key, not a base.

Each discovered function (``module:Qualified.name``) has exactly one `REGISTRY` entry:

* `Covered` -- a test that calls the function, directly or through the public entry
  point that hands it the base, with a base URL carrying a sub-path. The test must
  exist (AST) and contain a sub-path URL literal (`SUBPATH_URL`) or an app mount
  prefix (`MOUNT_PREFIX`, ``"/app/"``), directly or through a module constant. Each
  pointer was checked when it was written by tracing the test run (sys.monitoring on
  the registered code objects) and reading the base value each call received: every
  pointed test called its function with a base whose path is not ``/``.
* `XFail` -- a strict xfail test (``xfail(strict=True)``) whose reason names the bug.

A new function matching the rule without an entry fails; an entry whose function is
gone fails. Proven on synthetic offenders (PA-0034(2)).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from fuzzlab.labels.contract import Case, GroundTruth, InjectionPoint

ROOT = Path(__file__).resolve().parents[1]

#: (a) a ``*_url`` parameter qualified by one of these tokens is an operator base.
BASE_QUALIFIERS = frozenset({"base", "start", "target", "root", "app", "site", "entry"})
#: (b) a bare parameter of one of these names is a base when used as a URL.
BARE_BASE_NAMES = frozenset({"base", "start", "root"})
URL_FUNCTIONS = frozenset({"urljoin", "urlsplit", "urlparse", "canonical_origin",
                           "to_path"})
#: A URL whose path has a directory after its authority (``http://h/app/``,
#: ``…/bWAPP/x``). An origin-level page (``http://h/login.php``) is not a sub-path base.
SUBPATH_URL = re.compile(r"https?://[^/\s'\"]+/[A-Za-z][\w.-]*/")
#: Or an app mount prefix a fixture serves under (``prefix="/app/"``).
MOUNT_PREFIX = re.compile(r"^/[A-Za-z][\w.-]*/$")


def _is_subpath_literal(text: str) -> bool:
    return bool(SUBPATH_URL.search(text) or MOUNT_PREFIX.match(text))


def _name_rule(name: str) -> bool:
    toks = name.lower().split("_")
    return len(toks) >= 2 and toks[-1] == "url" and any(t in BASE_QUALIFIERS
                                                          for t in toks[:-1])


def _used_as_url(fn: ast.AST, name: str) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        called = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
        if called in URL_FUNCTIONS and node.args and any(
                isinstance(x, ast.Name) and x.id == name for x in ast.walk(node.args[0])):
            return True
        if (isinstance(f, ast.Attribute) and f.attr == "rstrip"
                and isinstance(f.value, ast.Name) and f.value.id == name):
            return True
    return False


def base_url_functions_in(source: str, module: str) -> dict[str, str]:
    """``{"module:Qual.name": parameter}`` for every function in ``source`` taking an
    operator base URL, by the discovery rule in this module's docstring."""
    found: dict[str, str] = {}

    def visit(node, stack):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, stack + [child.name])
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = child.args
                for arg in a.posonlyargs + a.args + a.kwonlyargs:
                    if _name_rule(arg.arg) or (arg.arg in BARE_BASE_NAMES
                                               and _used_as_url(child, arg.arg)):
                        found[f"{module}:{'.'.join(stack + [child.name])}"] = arg.arg
                        break
                visit(child, stack + [child.name])
            else:
                visit(child, stack)
    visit(ast.parse(source), [])
    return found


def base_url_functions() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
        found.update(base_url_functions_in(path.read_text(), module))
    return found


@dataclass(frozen=True)
class Covered:
    """A test that drives the function with a sub-path base."""
    test: str


@dataclass(frozen=True)
class XFail:
    """A strict xfail pinning a known bug in the function under a sub-path."""
    bug: str
    test: str


def _test_function(ref: str) -> ast.FunctionDef | None:
    file, _sep, name = ref.partition("::")
    path = ROOT / file
    if not path.exists() or not name.startswith("test_"):
        return None
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _strict_xfail_reason(fn: ast.FunctionDef) -> str | None:
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call) and getattr(dec.func, "attr", "") == "xfail":
            kw = {k.arg: k.value for k in dec.keywords}
            strict = kw.get("strict")
            if isinstance(strict, ast.Constant) and strict.value is True:
                reason = kw.get("reason")
                text = ast.unparse(reason) if reason is not None else ""
                return text
    return None


def _module_constants(file: str) -> dict[str, str]:
    """Module-level string constants of a test file (a test may name its sub-path base
    through one: ``BASE = "http://h/app/"``)."""
    out = {}
    for node in ast.parse((ROOT / file).read_text()).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = node.value.value
    return out


def _has_subpath_url(ref: str, fn: ast.FunctionDef) -> bool:
    consts = _module_constants(ref.partition("::")[0])
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and _is_subpath_literal(node.value):
            return True
        if isinstance(node, ast.Name) and _is_subpath_literal(consts.get(node.id, "")):
            return True
    return False


def pointer_problems(registry: dict) -> list[str]:
    problems = []
    for qual, entry in registry.items():
        fn = _test_function(entry.test)
        if fn is None:
            problems.append(f"{qual}: no test {entry.test}")
            continue
        if isinstance(entry, XFail):
            reason = _strict_xfail_reason(fn)
            if reason is None:
                problems.append(f"{qual}: {entry.test} is not a strict xfail")
            elif entry.bug not in reason and not _reason_constant_names(entry, reason):
                problems.append(f"{qual}: {entry.test}'s reason does not name {entry.bug}")
        elif not _has_subpath_url(entry.test, fn):
            problems.append(f"{qual}: {entry.test} has no sub-path URL")
    return problems


def _reason_constant_names(entry: XFail, reason: str) -> bool:
    """A reason given as a module constant (``reason=_BUG``) names the bug through it."""
    value = _module_constants(entry.test.partition("::")[0]).get(reason.strip(), "")
    return entry.bug in value


_ME = "tests/test_base_url_subpath_registry.py"
_SUB = "tests/test_subpath_apps.py"
_SUB_LOGIN = f"{_SUB}::test_a_login_that_lands_on_a_page_with_its_own_password_form_succeeds"
_SPA_SUBPATH = "tests/test_session_browser_login.py::test_a_spa_under_a_sub_path_logs_in"
_BW_ISOLATED = ("tests/test_login_form_isolation.py::"
                "test_bwapps_login_shaped_forms_are_imported_and_isolated")
_IDENTIFIER = f"{_ME}::test_identifier_sqli_route_paths_join_the_base_path"
_AUTHHTTP = f"{_ME}::test_auth_builders_scope_the_host_of_a_subpath_target"
_BROWSER_SESSION = f"{_ME}::test_a_browser_session_for_a_subpath_base_scopes_its_whole_origin"

#: Every discovered function -> its sub-path test (each pointer traced when written).
REGISTRY = {
    "fuzzlab.greybox.greybox_cli:_cookie_for":
        Covered(f"{_ME}::test_greybox_cli_logs_in_from_the_operators_subpath_base"),
    "fuzzlab.greybox.run:run_greybox":
        Covered(f"{_ME}::test_greybox_sends_each_point_to_its_own_url_under_a_subpath_base"),
    "fuzzlab.greybox.run:points_with_classes":
        XFail("BUG-0300",
              f"{_ME}::test_greybox_ground_truth_points_join_absolute_paths_to_the_origin"),
    "fuzzlab.greybox.run:points_from_store":
        Covered("tests/test_login_form_isolation.py::test_greybox_never_gets_login_form_points"),
    "fuzzlab.harness.auto:points_from_ground_truth":
        XFail("BUG-0300", f"{_ME}::test_ground_truth_points_join_absolute_paths_to_the_origin"),
    "fuzzlab.harness.auto:_login_form_paths": Covered(_BW_ISOLATED),
    "fuzzlab.harness.auto:isolated_paths_from_store": Covered(_BW_ISOLATED),
    "fuzzlab.harness.auto:injection_points_from_store":
        Covered(f"{_SUB}::test_crawl_points_join_absolute_paths_to_the_origin"),
    "fuzzlab.harness.auto:header_points_from_store":
        Covered("tests/test_forms_phase2.py::test_header_points_turn_on_and_are_observable"),
    "fuzzlab.harness.auto:run_auto":
        Covered("tests/test_forms_phase1.py::"
                "test_a_two_field_form_is_confirmed_only_with_its_siblings"),
    "fuzzlab.labgen.emitters.php_laravel.identifier_sqli:"
    "build_laravel_identifier_sqli_request": Covered(_IDENTIFIER),
    "fuzzlab.labgen.emitters.php_laravel.identifier_sqli:"
    "assert_laravel_identifier_sqli_cell": Covered(_IDENTIFIER),
    "fuzzlab.labgen.identifier_sqli_assertion:build_identifier_sqli_request":
        Covered(_IDENTIFIER),
    "fuzzlab.labgen.identifier_sqli_assertion:IdentifierSqliTier2Oracle.__init__":
        Covered(_IDENTIFIER),
    "fuzzlab.labgen.oracle_wrapper:assert_loopback":
        Covered(f"{_ME}::test_the_oracle_loopback_check_reads_only_the_host_of_a_subpath_url"),
    "fuzzlab.session.browserlogin:LoginGate.__init__": Covered(_SPA_SUBPATH),
    # BUG-0148: `_login_routes` became `_Discovery` (the sub-path SPA's form is behind
    # a route, so that test drives it)
    "fuzzlab.session.browserlogin:_Discovery.__init__": Covered(_SPA_SUBPATH),
    "fuzzlab.session.browserlogin:_pick_form": Covered(_SPA_SUBPATH),
    "fuzzlab.session.browserlogin:_drive": Covered(_SPA_SUBPATH),
    "fuzzlab.session.browserlogin:run": Covered(_SPA_SUBPATH),
    "fuzzlab.session.manager:SessionManager.ensure": Covered(_SUB_LOGIN),
    "fuzzlab.session.manager:SessionManager.session_header":
        Covered(f"{_ME}::test_standalone_session_headers_log_in_from_a_subpath_base"),
    "fuzzlab.session.manager:SessionManager.session_headers":
        Covered(f"{_ME}::test_standalone_session_headers_log_in_from_a_subpath_base"),
    "fuzzlab.session.manager:SessionManager.verify_live":
        Covered("tests/test_json_points.py::"
                "test_a_json_login_sqli_is_confirmed_on_an_isolated_session_only"),
    "fuzzlab.session.manager:SessionManager._login": Covered(_SUB_LOGIN),
    "fuzzlab.session.manager:SessionManager._browser_login_state": Covered(_SPA_SUBPATH),
    "fuzzlab.session.manager:SessionManager._spa_probe": Covered(_SPA_SUBPATH),
    "fuzzlab.session.manager:SessionManager._probe_fetch": Covered(_SPA_SUBPATH),
    "fuzzlab.session.manager:SessionManager._discover_login_form": Covered(_SUB_LOGIN),
    "fuzzlab.session.manager:SessionManager._navigate": Covered(_SUB_LOGIN),
    "fuzzlab.session.manager:SessionManager._navigation_ok": Covered(_SUB_LOGIN),
    "fuzzlab.session.manager:SessionManager._credential_destination_ok": Covered(_SUB_LOGIN),
    "fuzzlab.session.manager:SessionManager._post_credentials": Covered(_SUB_LOGIN),
    "fuzzlab.session.manager:SessionManager._basic_login":
        Covered(f"{_SUB}::test_a_basic_session_never_reads_an_app_page_redirect_as_logout"),
    "fuzzlab.session.manager:SessionManager._verify_authenticated": Covered(_SUB_LOGIN),
    "fuzzlab.tools.authhttp:_build": Covered(_AUTHHTTP),
    "fuzzlab.tools.authhttp:_build_parts": Covered(_AUTHHTTP),
    "fuzzlab.tools.authhttp:make_authenticated_client": Covered(_AUTHHTTP),
    "fuzzlab.tools.authhttp:make_auth": Covered(_AUTHHTTP),
    "fuzzlab.tools.authhttp:make_session_manager": Covered(_AUTHHTTP),
    "fuzzlab.tools.authhttp:make_auth_with_isolation": Covered(_AUTHHTTP),
    "fuzzlab.tools.browserauth:_ensure":
        Covered(f"{_SUB}::test_the_crawler_logs_in_from_its_start_url_not_the_bare_origin"),
    "fuzzlab.tools.browserauth:_cookies_of":
        Covered(f"{_SUB}::test_the_crawler_logs_in_from_its_start_url_not_the_bare_origin"),
    "fuzzlab.tools.browserauth:playwright_auth":
        Covered(f"{_SUB}::test_the_crawler_logs_in_from_its_start_url_not_the_bare_origin"),
    "fuzzlab.tools.browserauth:header_scope_for": Covered(_BROWSER_SESSION),
    "fuzzlab.tools.browserauth:browser_session": Covered(_BROWSER_SESSION),
    "fuzzlab.tools.fetcher:ContentFetcher.__init__":
        Covered("tests/test_browser_scope.py::test_the_static_auditor_refuses_another_origin_too"),
    "fuzzlab.tools.probesender:SeamProbeSender.__init__":
        Covered("tests/test_login_form_isolation.py::"
                "test_isolated_login_uses_the_operators_sub_path_base"),
    "fuzzlab.tools.probesender:make_probe_sender":
        Covered("tests/test_login_form_isolation.py::"
                "test_make_probe_sender_wires_an_isolated_client_on_the_runs_budget"),
    "fuzzlab.tools.spa:route_url":
        Covered("tests/test_spa_routes.py::test_route_urls_for_hash_hashbang_and_history_mode"),
    "fuzzlab.tools.spa:route_of": Covered(_SPA_SUBPATH),
    "fuzzlab.tools.spider:LocalSpider.__init__":
        Covered(f"{_SUB}::test_the_crawler_logs_in_from_its_start_url_not_the_bare_origin"),
    "fuzzlab.web.results:build_finding_raw_request":
        Covered(f"{_ME}::test_a_finding_raw_request_keeps_its_stored_path_under_a_subpath_base"),
    # Merged 2026-10-15 (origin-scoped sessions FR-SESS-20, the run-target reader
    # FR-CORE-500): each reduces a sub-path base to its origin or host; the path never
    # reaches an origin.
    "fuzzlab.core.runtarget:origin_of":
        Covered(f"{_ME}::test_a_subpath_base_reduces_to_its_origin_never_its_path"),
    "fuzzlab.harness.auto_cli:_auth_origins":
        Covered(f"{_ME}::test_auth_origins_are_scoped_by_a_subpath_bases_host"),
    "fuzzlab.session.manager:SessionManager._check_base":
        Covered(f"{_ME}::test_a_subpath_base_is_checked_by_its_origin"),
    "fuzzlab.session.manager:SessionManager._login_anchors":
        Covered(f"{_ME}::test_login_anchors_of_a_subpath_base_are_origins_only"),
    "fuzzlab.session.manager:SessionManager._origins_of":
        Covered(f"{_ME}::test_a_new_sessions_origins_from_a_subpath_base"),
    "fuzzlab.tools.authhttp:scope_hosts_for":
        Covered(f"{_ME}::test_auth_origins_are_scoped_by_a_subpath_bases_host"),
    "fuzzlab.tools.probesender:SeamProbeSender._run_origins":
        Covered(f"{_ME}::test_a_senders_run_origins_from_a_subpath_base"),
}


# --- the guard -------------------------------------------------------------------------
def test_every_base_url_function_is_registered():
    found = base_url_functions()
    assert sorted(set(found) - set(REGISTRY)) == [], "register each with its sub-path test"
    assert sorted(set(REGISTRY) - set(found)) == [], "a registry entry is stale"


def test_every_registry_pointer_is_a_real_subpath_test():
    assert pointer_problems(REGISTRY) == []


def test_the_registry_guard_catches_synthetic_offenders():
    """PA-0034(2): each discovery branch finds a function built to match it, a
    non-URL ``base`` and request URLs are not found, and the pointer check refuses a
    missing test, a non-strict xfail and a test with no sub-path URL."""
    src = '''
from urllib.parse import urljoin, urlsplit
def a(store, base_url): return base_url + "/x"
def b(*, target_base_url=None): pass
class C:
    def __init__(self, auth_base_url): pass
    def m(self, start_url): pass
def d(base): return urljoin(base, "x")
def e(base, path): return base.rstrip("/") + path
def f(root): return urlsplit(root).path
def g(base): return base + 1
def h(url, page_url, login_url, real_url, action_url): pass
def k(base: dict): return {**base}
'''
    found = base_url_functions_in(src, "synthetic")
    assert set(found) == {"synthetic:a", "synthetic:b", "synthetic:C.__init__",
                          "synthetic:C.m", "synthetic:d", "synthetic:e", "synthetic:f"}
    assert sorted(set(found) - set(REGISTRY)) == sorted(found)   # unregistered: flagged
    me = "tests/test_base_url_subpath_registry.py"
    assert pointer_problems({"x": Covered(f"{me}::test_no_such_test")})
    assert pointer_problems({"x": XFail("BUG-0300", f"{me}::test_every_base_url_function_is_registered")})
    assert pointer_problems({"x": Covered(f"{me}::test_every_base_url_function_is_registered")})
    assert pointer_problems({"x": XFail("BUG-9999",
                                        f"{me}::test_ground_truth_points_join_absolute_paths_to_the_origin")})
    assert pointer_problems({"x": Covered(
        f"{me}::test_an_origin_level_page_url_is_not_a_subpath_literal")})
    assert pointer_problems({"x": Covered(
        f"{me}::test_a_finding_raw_request_keeps_its_stored_path_under_a_subpath_base")}) == []


def test_an_origin_level_page_url_is_not_a_subpath_literal():
    """Review L1: a URL with a path but no directory is an origin-level page, so a test
    whose only URLs look like this one does not drive a sub-path base. (This test is
    itself the pointer offender above: keep its only URL origin-level.)"""
    assert not _is_subpath_literal("http://127.0.0.1/login.php")


# --- BUG-0300 (strict xfails; the corrective action is the auto.py lock owner's) -------
_BUG_0300 = ("BUG-0300 (CC-FUZZ-0300): ground-truth points join to the whole base URL; "
             "deferred to the owner of fuzzlab/harness/auto.py and fuzzlab/greybox/run.py")
ORIGIN = "http://127.0.0.1:8092"


def _subpath_ground_truth() -> GroundTruth:
    return GroundTruth(target="bwapp", cases=[
        Case(case_id="BW-0001", url="/bWAPP/sqli_1.php", method="GET", param="title",
             location="query", vuln_class="sqli", sink_context="sql",
             expected_vulnerable=True, rendering="server"),
        Case(case_id="BW-0002", url="/bWAPP/xss_stored_1.php", method="POST",
             param="entry", location="body", vuln_class="xss-stored",
             sink_context="html", expected_vulnerable=True, rendering="server",
             source_url="/bWAPP/xss_stored_1.php"),
    ], points=[
        InjectionPoint(url="/bWAPP/sqli_1.php", method="GET", param="title",
                       location="query", rendering="server"),
        InjectionPoint(url="/bWAPP/dom.php", method="GET", param="q",
                       location="fragment", rendering="js"),
    ])


def _all_urls(points) -> set[str]:
    return {u for p in points for u in (p.url, getattr(p, "store_url", None)) if u}


@pytest.mark.xfail(strict=True, reason=_BUG_0300)
def test_ground_truth_points_join_absolute_paths_to_the_origin():
    from fuzzlab.harness.auto import points_from_ground_truth
    for base in (ORIGIN + "/bWAPP/", ORIGIN + "/bWAPP", ORIGIN + "/app/"):
        points, _skipped = points_from_ground_truth(_subpath_ground_truth(), base,
                                                    browser_available=True)
        assert _all_urls(points) == {ORIGIN + "/bWAPP/sqli_1.php", ORIGIN + "/bWAPP/dom.php",
                                     ORIGIN + "/bWAPP/xss_stored_1.php"}, base


@pytest.mark.xfail(strict=True, reason=_BUG_0300)
def test_greybox_ground_truth_points_join_absolute_paths_to_the_origin():
    from fuzzlab.greybox.run import points_with_classes
    points, _skipped = points_with_classes(_subpath_ground_truth(), ORIGIN + "/bWAPP/")
    sqli = [p for p in points if p.param == "title"]
    assert [(p.url, p.vuln_class) for p in sqli] == [(ORIGIN + "/bWAPP/sqli_1.php", "sqli")]


def test_bug_0300_is_what_the_xfails_claim():
    """Today every branch doubles the sub-path (and the origin base is right), so the
    xfails above fail for the stated reason only."""
    from fuzzlab.greybox.run import points_with_classes
    from fuzzlab.harness.auto import points_from_ground_truth
    gt = _subpath_ground_truth()
    points, _ = points_from_ground_truth(gt, ORIGIN + "/bWAPP/", browser_available=True)
    assert _all_urls(points) == {ORIGIN + "/bWAPP/bWAPP/sqli_1.php",
                                 ORIGIN + "/bWAPP/bWAPP/dom.php",
                                 ORIGIN + "/bWAPP/bWAPP/xss_stored_1.php"}
    points, _ = points_from_ground_truth(gt, ORIGIN, browser_available=True)
    assert _all_urls(points) == {ORIGIN + "/bWAPP/sqli_1.php", ORIGIN + "/bWAPP/dom.php",
                                 ORIGIN + "/bWAPP/xss_stored_1.php"}
    grey, _ = points_with_classes(gt, ORIGIN + "/bWAPP/")
    assert {(p.url, p.vuln_class) for p in grey if p.param == "title"} == \
        {(ORIGIN + "/bWAPP/bWAPP/sqli_1.php", "sqli")}


# --- sub-path tests for registered functions that had none (PA-0300 sweep) ------------
SUBPATH_BASE = "http://127.0.0.1:8092/bWAPP/"


def test_a_finding_raw_request_keeps_its_stored_path_under_a_subpath_base():
    """`web.results.build_finding_raw_request` takes only the host and port from the
    base: a finding's stored path is the full request path and is never re-joined."""
    from fuzzlab.web.results import build_finding_raw_request
    raw, host, port, tls = build_finding_raw_request(
        "/bWAPP/sqli_1.php", "GET", "title", "x'", "http://127.0.0.1:8092/bWAPP/")
    assert raw.startswith("GET /bWAPP/sqli_1.php?title=x%27 HTTP/1.1\r\n")
    assert (host, port, tls) == ("127.0.0.1", 8092, False)


def test_the_oracle_loopback_check_reads_only_the_host_of_a_subpath_url():
    from fuzzlab.labgen.oracle_wrapper import OracleSafetyError, assert_loopback
    assert_loopback("http://127.0.0.1:8092/bWAPP/")
    assert_loopback("http://localhost:8092/app/deep/")
    with pytest.raises(OracleSafetyError):
        assert_loopback("http://example.com/127.0.0.1/")


def test_auth_builders_scope_the_host_of_a_subpath_target(monkeypatch):
    """`tools.authhttp`: every builder scopes the target's host; its path is the
    caller's to use (the session manager keeps the operator base, BUG-0113)."""
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.tools import authhttp
    from tests.test_credentials import FakeBackend
    monkeypatch.setattr(CredentialStore, "open",
                        classmethod(lambda cls, cfg: CredentialStore(backend=FakeBackend())))
    target = "http://127.0.0.1:8092/bWAPP/portal.php"
    manager, client, _budget, scope = authhttp._build_parts(target, 5.0)
    assert "127.0.0.1" in scope and not any("/" in h for h in scope)
    assert "127.0.0.1" in manager._scope and "127.0.0.1" in client._scope
    for built in (authhttp._build(target, 5.0), authhttp.make_auth(target),
                  authhttp.make_auth_with_isolation(target)[:2]):
        assert "127.0.0.1" in built[0]._scope and "127.0.0.1" in built[1]._scope
    assert "127.0.0.1" in authhttp.make_session_manager(target)._scope
    assert "127.0.0.1" in authhttp.make_authenticated_client(target, "user")._scope


class _RecordingRunner:
    def __init__(self, bodies):
        self.bodies, self.urls = list(bodies), []

    def __call__(self, url, headers, cookie, timeout_s):
        from fuzzlab.labgen.identifier_sqli_oracle import HttpProbeResult
        self.urls.append(url)
        body = self.bodies[min(len(self.urls) - 1, len(self.bodies) - 1)]
        return HttpProbeResult(url=url, status_code=200, body=body, timed_out=False,
                               elapsed_s=0.01)


def test_identifier_sqli_route_paths_join_the_base_path():
    """A generated cell's served path is an app route, so it joins the base's path
    (PA-0300(2)): under ``/app/`` every probe goes to ``/app/<route>``, never the
    origin root, and never a doubled path."""
    from fuzzlab.labgen.conformance.tier1 import build_tier1_case
    from fuzzlab.labgen.emitters.php_current import _PAGE_PARAMS
    from fuzzlab.labgen.emitters.php_laravel.identifier_sqli import (
        assert_laravel_identifier_sqli_cell, build_laravel_identifier_sqli_request)
    from fuzzlab.labgen.identifier_sqli_assertion import (
        IdentifierSqliTier2Oracle, assert_identifier_sqli_cell, build_identifier_sqli_request)
    from fuzzlab.labgen.identifier_sqli_oracle import _build_url
    from fuzzlab.labgen.schema import load_manifest
    from fuzzlab.labgen.verdict import load_safety_matrix
    base = "http://127.0.0.1:8080/app/"
    catalog = _PAGE_PARAMS["/catalog.php"]
    hs = {c.cell_id: c for c in load_manifest(
        "lab/manifests/phase1_harder_shapes_sample.yaml").cells}["LABGEN-HS-0001"]
    pl = {c.cell_id: c for c in load_manifest(
        "lab/manifests/phase3_php_laravel_sample.yaml").cells}["LABGEN-PL-0007"]
    matrix = load_safety_matrix()
    kw = dict(param_name=catalog["param_name"], column_a=catalog["column_a"],
              column_b=catalog["column_b"])

    req = build_identifier_sqli_request(hs, target_base_url=base, **kw)
    assert _build_url(req, "x").startswith(base + "catalog.php?")
    req = build_laravel_identifier_sqli_request(pl, target_base_url=base)
    assert _build_url(req, "x").startswith(base + "cell/labgen-pl-0007?")

    runner = _RecordingRunner(["baseline", "true", "false"])
    assert_identifier_sqli_cell(hs, matrix, target_base_url=base, runner=runner, **kw)
    assert runner.urls and all(u.startswith(base + "catalog.php?") for u in runner.urls)
    runner = _RecordingRunner(["baseline", "true", "false"])
    assert_laravel_identifier_sqli_cell(pl, matrix, target_base_url=base, runner=runner)
    assert runner.urls and all(u.startswith(base + "cell/labgen-pl-0007?")
                               for u in runner.urls)

    runner = _RecordingRunner(["baseline", "true", "false"])
    oracle = IdentifierSqliTier2Oracle(target_base_url=base, column_a=catalog["column_a"],
                                       column_b=catalog["column_b"], runner=runner)
    oracle.confirm(build_tier1_case(hs, param_name=catalog["param_name"],
                                    payload="(CASE WHEN (1=1) THEN name ELSE price END)",
                                    evidence_marker="unused", expected_vulnerable=True))
    assert runner.urls and all(u.startswith(base + "catalog.php?") for u in runner.urls)


def test_greybox_sends_each_point_to_its_own_url_under_a_subpath_base(tmp_path):
    """`run_greybox` takes the base for the record only: every probe goes to the
    point's own URL, which keeps the app's path."""
    from fuzzlab.core.store import Store
    from fuzzlab.greybox.run import GreyboxPoint, ProbeSpec, run_greybox
    from fuzzlab.oracle.probe import Probe
    from tests.test_greybox_live import DictCoverage, DictFault, FakeSender
    sender = FakeSender([(Probe(200, "ok"), {}, False)])
    point = GreyboxPoint(SUBPATH_BASE + "sqli_1.php", "title", "GET", "query", "sqli")
    with Store(tmp_path / "g.db") as store:
        rid = store.start_run("greybox", "127.0.0.1")
        run_greybox(base_url=SUBPATH_BASE, store=store, run_id=rid, points=[point],
                    sender=sender, coverage_source=DictCoverage(sender),
                    dbfault_source=DictFault(sender),
                    probes=(ProbeSpec("baseline", "1", "baseline"),))
    assert [s[0] for s in sender.sent] == [SUBPATH_BASE + "sqli_1.php"]


def test_greybox_cli_logs_in_from_the_operators_subpath_base(monkeypatch):
    """`greybox_cli._cookie_for` hands the operator's whole base URL to the session
    manager (never its origin, BUG-0113)."""
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.core.urls import canonical_origin
    from fuzzlab.greybox import greybox_cli
    from fuzzlab.session import manager as manager_mod
    from fuzzlab.session.state import SessionState
    from tests.test_credentials import FakeBackend
    seen = []
    monkeypatch.setattr(CredentialStore, "open",
                        classmethod(lambda cls, cfg: CredentialStore(backend=FakeBackend())))

    def ensure(self, host, identity, base_url, *, operator=False):
        seen.append((base_url, operator))
        # FR-SESS-20: a session established from this base carries its origin.
        return SessionState(host, identity, kind="cookie", cookies={"PHPSESSID": "s"},
                            valid=True, origins=frozenset({canonical_origin(base_url)}))
    monkeypatch.setattr(manager_mod.SessionManager, "ensure", ensure)
    cookie, secure_only, _is_auth, origins = greybox_cli._cookie_for(
        "127.0.0.1", "user", SUBPATH_BASE + "portal.php")
    assert cookie == "PHPSESSID=s" and secure_only is False
    assert origins == frozenset({"http://127.0.0.1:8092"})     # FR-SESS-20: the origin only
    assert seen and all(s == (SUBPATH_BASE + "portal.php", True) for s in seen)


def test_standalone_session_headers_log_in_from_a_subpath_base():
    """`SessionManager.session_header` / `session_headers` (greybox, `session print`)
    log in from the operator's base under its path."""
    from tests.test_subpath_apps import SubpathApp, _mgr
    app = SubpathApp()
    mgr = _mgr(app)
    base = "http://h:8090/app/portal.php"
    assert mgr.session_header("h", "user", base, operator=True) == "Cookie: PHPSESSID=authed"
    assert app.gets[0] == base
    assert mgr.session_headers("h", "user", base, operator=True) == \
        {"Cookie": "PHPSESSID=authed"}


def test_a_browser_session_for_a_subpath_base_scopes_its_whole_origin():
    """`browserauth.browser_session` / `header_scope_for`: the manager gets the whole
    base; cookies go to the origin root and headers to every in-scope page of the
    session's host, sibling paths included (BUG-0113)."""
    from fuzzlab.session.state import SessionState
    from fuzzlab.tools import browserauth
    seen = []

    class Mgr:
        def ensure(self, host, identity, base_url, *, operator=False):
            seen.append((host, base_url, operator))
            return SessionState(host, identity, kind="bearer", cookies={"sid": "abc123def"},
                                headers={"Authorization": "Bearer T"}, valid=True)
    base = SUBPATH_BASE + "portal.php"
    session = browserauth.browser_session(Mgr(), "u", base,
                                          in_scope=lambda u: "127.0.0.1:8092" in u)
    assert seen == [("127.0.0.1", base, True)]
    assert [c["url"] for c in session.cookies] == ["http://127.0.0.1:8092/"]
    assert session.header_scope(SUBPATH_BASE + "sqli_1.php")
    assert session.header_scope("http://127.0.0.1:8092/other/x")
    assert not session.header_scope("http://127.0.0.1:9999/bWAPP/x")
    scope = browserauth.header_scope_for(SessionState("127.0.0.1", "u", valid=True), base,
                                         lambda u: True)
    assert scope(SUBPATH_BASE + "x.php") and not scope("http://evil.example/bWAPP/")


# --- origin and host reducers (merged 2026-10-15): a sub-path base keeps its origin -----

def test_a_subpath_base_reduces_to_its_origin_never_its_path():
    from fuzzlab.core.runtarget import origin_of
    assert origin_of(SUBPATH_BASE) == "http://127.0.0.1:8092"
    assert origin_of(SUBPATH_BASE + "portal.php?x=1") == "http://127.0.0.1:8092"


def test_auth_origins_are_scoped_by_a_subpath_bases_host():
    import argparse

    from fuzzlab.harness import auto_cli
    from fuzzlab.tools.authhttp import scope_hosts_for
    assert "127.0.0.1" in scope_hosts_for(SUBPATH_BASE)
    parser = argparse.ArgumentParser()
    assert auto_cli._auth_origins(parser, ["http://127.0.0.1:9000"], SUBPATH_BASE) == [
        "http://127.0.0.1:9000"]


def _subpath_manager():
    from tests.test_subpath_apps import SubpathApp, _mgr
    return _mgr(SubpathApp())


def test_a_subpath_base_is_checked_by_its_origin():
    from fuzzlab.session.manager import SessionAuthError
    from fuzzlab.session.state import SessionState
    mgr = _subpath_manager()
    mgr._state[("h", "user")] = SessionState("h", "user", origins=frozenset({"http://h:8090"}))
    mgr._check_base("h", "user", "http://h:8090/app/portal.php", operator=True)   # same origin
    with pytest.raises(SessionAuthError):
        mgr._check_base("h", "user", "http://h:9999/app/portal.php", operator=True)


def test_login_anchors_of_a_subpath_base_are_origins_only():
    anchors = _subpath_manager()._login_anchors("http://h:8090/app/portal.php")
    assert "http://h:8090" in anchors and "https://h:8090" in anchors
    assert not any("/app" in a for a in anchors)


def test_a_new_sessions_origins_from_a_subpath_base():
    origins = _subpath_manager()._origins_of("http://h:8090/app/portal.php",
                                             "http://h:8090/app/login.php")
    assert origins == frozenset({"http://h:8090"})


def test_a_senders_run_origins_from_a_subpath_base():
    import types

    from fuzzlab.tools.probesender import SeamProbeSender
    sender = types.SimpleNamespace(_manager=None, _identity="user")
    assert SeamProbeSender._run_origins(sender, SUBPATH_BASE) == frozenset(
        {"http://127.0.0.1:8092"})
