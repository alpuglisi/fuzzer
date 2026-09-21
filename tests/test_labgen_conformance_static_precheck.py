"""Static-precheck flag mechanism tests (T-LAB0.7)."""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.static_precheck import (
    NoStaticCheckerConfiguredError,
    StaticPrecheckStatus,
    run_static_precheck,
    static_precheck_status,
)


def test_sqli_shapes_are_uninformative() -> None:
    assert static_precheck_status("sqli", "sql_numeric_literal") is StaticPrecheckStatus.UNINFORMATIVE
    assert static_precheck_status("sqli", "sql_string_literal") is StaticPrecheckStatus.UNINFORMATIVE


def test_xss_html_body_shape_is_informative() -> None:
    assert static_precheck_status("xss", "html_body") is StaticPrecheckStatus.INFORMATIVE


def test_harder_shapes_are_uninformative() -> None:
    """L-P1.2b: identifier/alias-position SQLi and escaping-context-mismatch
    XSS are both shapes a taint engine is structurally blind to -- the latter
    notably so, since the escaping it looks for is *present* and only the
    context is wrong (see STATIC_PRECHECK_BY_SHAPE's own comments)."""
    for shape in (
        ("sqli", "sql_identifier"),
        ("sqli", "sql_join_alias"),
        ("xss", "url_javascript_scheme"),
        ("xss", "html_attribute_unquoted"),
    ):
        assert static_precheck_status(*shape) is StaticPrecheckStatus.UNINFORMATIVE


def test_unregistered_shape_fails_loud() -> None:
    # Deliberately a shape no lane has authored a module set for (an LDAP
    # filter sink); the previous stand-in here, (xss, html_attribute_unquoted),
    # became a *registered* shape in L-P1.2b, which is exactly why this test
    # now names something the registry does not cover at all.
    with pytest.raises(KeyError):
        static_precheck_status("ldapi", "ldap_filter")


def test_uninformative_shape_is_skipped_and_checker_is_never_called() -> None:
    calls: list[str] = []

    def checker() -> bool:
        calls.append("called")
        return True

    result = run_static_precheck("sqli", "sql_numeric_literal", checker=checker)
    assert result.ran is False
    assert result.passed is None
    assert calls == []  # the whole point: an uninformative shape's checker is never invoked


def test_uninformative_shape_is_skipped_even_with_no_checker_supplied() -> None:
    result = run_static_precheck("sqli", "sql_string_literal", checker=None)
    assert result.ran is False
    assert result.passed is None


def test_informative_shape_runs_the_supplied_checker() -> None:
    result = run_static_precheck("xss", "html_body", checker=lambda: True)
    assert result.ran is True
    assert result.passed is True


def test_informative_shape_with_no_checker_raises_rather_than_silently_passing() -> None:
    with pytest.raises(NoStaticCheckerConfiguredError):
        run_static_precheck("xss", "html_body", checker=None)


def test_informative_shape_propagates_a_failing_checker_result() -> None:
    result = run_static_precheck("xss", "html_body", checker=lambda: False)
    assert result.ran is True
    assert result.passed is False
