"""Spellings FR-AUD-20's lab predicate still admits after the owner's final round
(BUG-0555, review round 2's fix check): each is pinned by a strict xfail naming its owner
(AUD, `fuzzlab/audit/value_shape.py::names_outside_lab`, SP-73), never left as prose
(PA-0531(4)). Neither is a regression: 7393c90 and d3cb339 admit them too.

- A '+' before a special scheme in a form-encoded value: every form reader decodes it to
  a space and WHATWG trims it, so ``next=+https:evil.top`` reads as https://evil.top/;
  and a JSON ``\\u003a`` escape of the scheme's colon, read after ``JSON.parse``.
- A Unicode spelling of an IPv6 address that getaddrinfo's idna nameprep (NFKC, the
  mapped-to-nothing characters dropped) reads as the ASCII address, as the IPv4 forms
  already are judged.
"""

import pytest

from fuzzlab.audit.value_shape import names_outside_lab

_FULLWIDTH_V6 = "２００１：ｄｂ８：：１"

FORM_DECODED = ["?next=+https:evil.top", "?next=+https:/evil.top", "go=+https:/evil.top/x",
                "/login?next=+https:evil.example/", "?a=1&next=+ws:evil.top",
                "?next=++https:evil.top", "?next=+HTTPS:evil.top", "?next=+wss:evil.top",
                "?next=+ftp:/evil.top", '{"u":"https\\u003aevil.top"}']
UNICODE_V6 = [_FULLWIDTH_V6, "2001：4860：4860：：8888", "2001:db8:​:1",
              "2001:4860:4860:\xad:8888", "2001:4860:4860:️:8888", "2001:db8:⁠:1",
              "dns=" + _FULLWIDTH_V6]


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="BUG-0555 residual (owner AUD, SP-73): a '+' before a special "
                          "scheme, or a JSON-escaped colon, is read past the mark")
@pytest.mark.parametrize("value", FORM_DECODED)
def test_a_special_scheme_behind_a_form_decoded_plus_or_a_json_escape_is_outside(value):
    assert names_outside_lab(value)


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="BUG-0555 residual (owner AUD, SP-73): the IPv6 rule is not run "
                          "on getaddrinfo's nameprep reading (NFKC, ignorables dropped)")
@pytest.mark.parametrize("value", UNICODE_V6)
def test_a_unicode_spelling_of_an_ipv6_address_is_outside(value):
    assert names_outside_lab(value)
