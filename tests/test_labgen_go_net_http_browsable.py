"""Offline checks for LoopCast's browsable site (`CC-LAB-0243` / `FR-LAB-162`,
`docs/LAB_LANE3_GO_NET_HTTP_TWITCH_PLAN.md`).

Everything here runs without booting a real `go` server (the real rendering
is proven by the `slow` live-boot module,
`tests/test_labgen_go_live_boot.py`): the PA-0053/PA-0054 absent-input
declarations every route must carry (`§2d`), R4's layout/page-chrome checks
(no `AccessControlIdorStrategy` denial-marker word, no standalone 3+-digit
token, so the site layer never adds a coincidental oracle signal), and R3's
HTML-escaping of the one echoed value the site layer renders.
"""

from __future__ import annotations

import glob
import re

from fuzzlab.labgen.emitters.go_net_http import (
    _ROUTE_PARAMS,
    ABSENT_INPUT_KINDS,
    GoEmitter,
    served_url_for,
)
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.strategies import AccessControlIdorStrategy

SITE_GO = "fuzzlab/labgen/emitters/go_net_http/stack/skeleton/site.go"

#: A double-quoted Go string literal's contents (no attempt at full Go
#: string-escape parsing beyond `\"`/other backslash escapes, which is
#: enough for this file's own ASCII page chrome).
_GO_STRING_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')

#: Any standalone run of 3+ decimal digits -- the same guard the GoTemplateSsti
#: strategy's own arithmetic-product canary needs the layout to never
#: coincidentally match (R4).
_THREE_PLUS_DIGITS = re.compile(r"\d{3,}")


def _go_cells():
    """Every `go_net_http` cell across every manifest, derived from the
    emitter's own `supports()` predicate (PA-0027), never a hand-kept list."""
    emitter = GoEmitter()
    seen = {}
    for path in sorted(glob.glob("lab/manifests/*.yaml")):
        for cell in load_manifest(path).cells:
            if cell.stack_profile == "go_net_http" and emitter.supports(
                cell.vuln_class, cell.sink_context
            ):
                seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


def _string_literals(text: str) -> list[str]:
    return _GO_STRING_LITERAL.findall(text)


# --- PA-0053 / PA-0054: absent-input behavior is declared, not incidental ----


def test_every_route_declares_its_absent_input_behavior() -> None:
    """Every route in the emitter's own route profile declares exactly one
    of the closed `ABSENT_INPUT_KINDS` values -- PA-0053, enforced here
    offline for the whole emitter, independent of what a crawl happens to
    reach (PA-0054)."""
    cells = _go_cells()
    routes = {c.route.path for c in cells}
    assert routes == set(_ROUTE_PARAMS), (routes, set(_ROUTE_PARAMS))
    for route in sorted(routes):
        profile = _ROUTE_PARAMS[route]
        assert "absent_input" in profile, route
        assert profile["absent_input"] in ABSENT_INPUT_KINDS, (route, profile["absent_input"])


def test_required_and_default_routes_are_the_declared_ones() -> None:
    """`required_param` (CC-LAB-0247: renamed from `required_400` during the
    Lane 7 absent-input vocabulary reconciliation, PA-0058 rule 2 -- same
    meaning, unified spelling) is declared exactly for the 3 routes
    BUG-0053 found (no safe default URL/filename exists for any of them);
    `default_value` (renamed from `default`) is declared exactly for the 2
    redirect routes (R7's decision rule)."""
    required = {p for p, v in _ROUTE_PARAMS.items() if v["absent_input"] == "required_param"}
    default = {p for p, v in _ROUTE_PARAMS.items() if v["absent_input"] == "default_value"}
    assert required == {"/api/clips/thumbnail", "/clips/download", "/clips/export"}
    assert default == {"/channels/redirect", "/auth/login-redirect"}
    for route in default:
        assert "default_value" in _ROUTE_PARAMS[route], route


def test_every_served_url_appears_exactly_once() -> None:
    """R1: `served_url_for` never doubles up two cells onto one `net/http`
    pattern (which would panic at Go's own mux-registration time)."""
    cells = _go_cells()
    served = [served_url_for(c) for c in cells]
    assert len(served) == len(set(served)), served


# --- R4: the site layer adds no coincidental oracle signal --------------


def test_site_layer_has_no_denial_marker_word() -> None:
    """The layout/page chrome must contain none of
    `AccessControlIdorStrategy._DENIAL_MARKERS` -- the object-lookup
    dashboard's own 403 page text is the one exception this test allows,
    since a real denial page is *supposed* to look denied; every other
    string literal in the site layer must stay clean."""
    text = open(SITE_GO, encoding="utf-8").read()
    denial_re = AccessControlIdorStrategy._DENIAL_MARKERS
    hits = [s for s in _string_literals(text) if denial_re.search(s)]
    assert not hits, hits


def test_site_layer_has_no_standalone_three_digit_token() -> None:
    """Guards any future page reuse of the layout by the SSTI cell's own
    3-digit arithmetic-product canary (R4): no site-layer string literal
    contains a 3+-digit run."""
    text = open(SITE_GO, encoding="utf-8").read()
    hits = [s for s in _string_literals(text) if _THREE_PLUS_DIGITS.search(s)]
    assert not hits, hits


# --- R3: the dashboard's echoed channel_id is HTML-escaped -------------


def test_dashboard_sink_escapes_the_echoed_channel_id() -> None:
    sink_src = open(
        "fuzzlab/labgen/emitters/go_net_http/templates/sinks/"
        "object_lookup_authorization_check.go.j2",
        encoding="utf-8",
    ).read()
    assert "html.EscapeString({{ channel_id_var }})" in sink_src
