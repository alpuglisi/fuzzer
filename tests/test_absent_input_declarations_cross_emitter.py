"""PA-0002 sweep (CC-LAB-0244, S15): does each emitter declare, for every
real route it serves, what happens when the request's required input is
absent (`PA-0053`/`PA-0054`, strengthened by `PA-0056`)?

`spring_boot` (this lane) and `django` (`CC-LAB-0242`) already declare this
explicitly, per route, checked offline elsewhere
(`tests/test_labgen_spring_boot_browsable.py`,
`tests/test_labgen_django_browsable.py`) -- this module only re-confirms the
declaration *mechanism* exists for them, so a regression that silently
removes it is caught here too.

`go_net_http`, `ruby_rails`, `node_express`, `python_fastapi` and
`php_current` have **no such mechanism at all** (verified directly: none of
their emitter modules define anything resembling a per-route absent-input
declaration) -- each is `xfail(strict=True)`, naming its owning Browsable
Labs lane, per `PA-0056` rule 3 (a `PA-0002` sweep that defers a fix must
pin the exposure, not just mention it in prose). A lane that adds the
mechanism will XPASS here and must delete its own marker at merge (the same
decision rule `CC-LAB-0244`'s own plan uses elsewhere).

`php_laravel` has a real mechanism (`_DEFAULT_VALUE_KEY`, from `BUG-0051`/
`PA-0053`) but this module only checks that the mechanism itself still
exists, not that every one of its routes uses it -- full per-route coverage
for `php_laravel` is out of this lane's scope (it owns no code there) and is
recorded as an open item, not silently assumed complete.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.filterwarnings("ignore")


def test_spring_boot_declares_absent_input_for_every_route() -> None:
    from fuzzlab.labgen.emitters.spring_boot import ABSENT_INPUT_KINDS, _PAGE_PARAMS

    for route, profile in _PAGE_PARAMS.items():
        assert profile.get("absent_input") in ABSENT_INPUT_KINDS, route


def test_django_declares_absent_input_for_every_get_param_route() -> None:
    from fuzzlab.labgen.emitters.django import _ROUTE_PARAMS

    for route, profile in _ROUTE_PARAMS.items():
        if route == "/api/login":
            continue  # BUG-0052: a bound/unbound lookup of 'None' cleanly 404s, not a crash -- recorded, not declared
        if "stored_expr" in profile:
            continue  # reads previously-stored data, not live request input -- no absent-input key applies
        if "get_form_template" in profile:
            continue  # GET renders the form; the POST-only source never runs on a bare GET (BUG-0052)
        if "var_name" not in profile:
            continue  # not a get_param-sourced route -- no absent-input key applies
        assert "default_value" in profile or profile.get("required_param"), route


def test_php_laravel_declaration_mechanism_still_exists() -> None:
    """`BUG-0051`/`PA-0053`'s `default_value` mechanism is present. This does
    **not** assert full per-route coverage across `php_laravel` (a lane this
    change does not own) -- that remains an open follow-up, not claimed done
    here."""
    from fuzzlab.labgen.emitters.php_laravel import _DEFAULT_VALUE_KEY

    assert _DEFAULT_VALUE_KEY == "default_value"


#: The vocabulary an absent-input declaration actually uses, across the two
#: emitters that have one (`spring_boot`'s `ABSENT_INPUT_KINDS` values,
#: `django`'s/`php_laravel`'s `default_value`/`required_param`). A module
#: merely *having* a route-params-shaped dict (several of the other five
#: emitters do, for unrelated per-route metadata) is not itself a
#: declaration mechanism -- what matters is whether any route's own profile
#: dict uses one of these keys.
_DECLARATION_KEYS = frozenset({
    "absent_input", "default_value", "required_param", "required_header",
    "required_multipart", "empty_body_400", "no_input", "form_when_absent",
})


def _has_absent_input_declaration(mod) -> bool:
    """Whether any dict attribute of ``mod`` contains a route-profile-shaped
    value (itself a dict) using one of `_DECLARATION_KEYS` -- a coarse but
    honest existence check, not a per-route completeness audit."""
    for attr_name in dir(mod):
        attr = getattr(mod, attr_name)
        if not isinstance(attr, dict):
            continue
        for value in attr.values():
            if isinstance(value, dict) and _DECLARATION_KEYS & set(value):
                return True
    return False


@pytest.mark.xfail(strict=True, reason="Browsable Labs Lane 3 (go_net_http) owns adding this -- PA-0056 rule 3")
def test_go_net_http_has_no_absent_input_declaration_mechanism_yet() -> None:
    import fuzzlab.labgen.emitters.go_net_http as mod

    assert _has_absent_input_declaration(mod), (
        "go_net_http gained a route-profile/declaration mechanism -- delete this xfail (S15 decision rule)"
    )


@pytest.mark.xfail(strict=True, reason="Browsable Labs Lane 5 (ruby_rails) owns adding this -- PA-0056 rule 3")
def test_ruby_rails_has_no_absent_input_declaration_mechanism_yet() -> None:
    import fuzzlab.labgen.emitters.ruby_rails as mod

    assert _has_absent_input_declaration(mod), (
        "ruby_rails gained a route-profile/declaration mechanism -- delete this xfail (S15 decision rule)"
    )


@pytest.mark.xfail(strict=True, reason="Browsable Labs Lane 6 (node_express) owns adding this -- PA-0056 rule 3")
def test_node_express_has_no_absent_input_declaration_mechanism_yet() -> None:
    import fuzzlab.labgen.emitters.node_express as mod

    assert _has_absent_input_declaration(mod), (
        "node_express gained a route-profile/declaration mechanism -- delete this xfail (S15 decision rule)"
    )


@pytest.mark.xfail(strict=True, reason="Browsable Labs Lane 6 (python_fastapi) owns adding this -- PA-0056 rule 3")
def test_python_fastapi_has_no_absent_input_declaration_mechanism_yet() -> None:
    import fuzzlab.labgen.emitters.python_fastapi as mod

    assert _has_absent_input_declaration(mod), (
        "python_fastapi gained a route-profile/declaration mechanism -- delete this xfail (S15 decision rule)"
    )


@pytest.mark.xfail(strict=True, reason="No Browsable Labs lane assigned to php_current yet -- follow-up, PA-0056 rule 3")
def test_php_current_has_no_absent_input_declaration_mechanism_yet() -> None:
    import fuzzlab.labgen.emitters.php_current as mod

    assert _has_absent_input_declaration(mod), (
        "php_current gained a route-profile/declaration mechanism -- delete this xfail (S15 decision rule)"
    )
