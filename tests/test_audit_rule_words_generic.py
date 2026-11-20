"""BUG-0660: audit rules nominate by black-box-generic words, not by names a lab used.

Each rule below once carried a word taken from a generated lab app (twitch-clone's
``channel_id``, netflix-clone's ``account_id``, expedia-clone's ``sortBy``,
twitch-clone's ``/api/clips/thumbnail``, booking-clone's ``label``) or a word with no
public source (a header named ``jwt``; bWAPP's ``lang_en.php`` extension). These tests
pin the generic replacement on names no lab uses, and that the lab-only word is gone.
"""

import pytest

from fuzzlab.audit import InjectionPoint, load_rules, matches
from fuzzlab.audit.value_shape import FILE_EXTENSIONS, value_shape

RULES = {r.id: r for r in load_rules()}


def _q(param, location="query", method="GET"):
    return InjectionPoint(url="/x", param=param, location=location, method=method)


# R-ACCESS-CONTROL: any object identifier (OWASP API1:2023 BOLA, WSTG-ATHZ-04 IDOR).

@pytest.mark.parametrize("param", ["id", "ID", "uuid", "guid", "invoice_id", "userId",
                                   "orderID", "documentUuid", "order-guid", "doc_uuid",
                                   # the lab names still match, by shape alone
                                   "channel_id", "account_id"])
def test_access_control_nominates_any_object_identifier(param):
    assert matches(RULES["R-ACCESS-CONTROL"], _q(param))


@pytest.mark.parametrize("param", ["paid", "valid", "android", "idea", "ids", "userid",
                                   "hidden", "q", "name"])
def test_access_control_ignores_words_that_only_contain_id(param):
    assert not matches(RULES["R-ACCESS-CONTROL"], _q(param))


def test_access_control_query_and_path_rules_share_one_identifier_shape():
    assert (RULES["R-ACCESS-CONTROL"].when["name_regex"]
            == RULES["R-ACCESS-CONTROL-PATH"].when["name_regex"])
    assert RULES["R-ACCESS-CONTROL"].when["method_in"] == ["GET"]
    assert RULES["R-ACCESS-CONTROL"].when["location_in"] == ["query"]
    assert not matches(RULES["R-ACCESS-CONTROL"], _q("invoice_id", method="POST"))
    assert not matches(RULES["R-ACCESS-CONTROL"], _q("invoice_id", location="body"))


# R-SPEL-INJECTION: location-only, like R-SSTI; the SpEL strategy confirms.

def test_spel_rule_has_no_name_word_and_ssti_locations():
    when = RULES["R-SPEL-INJECTION"].when
    assert "name_regex" not in when
    assert when["location_in"] == RULES["R-SSTI"].when["location_in"]


@pytest.mark.parametrize("location", ["query", "body", "json"])
@pytest.mark.parametrize("param", ["q", "term", "sortBy"])
def test_spel_nominates_any_name_in_a_value_location(param, location):
    assert matches(RULES["R-SPEL-INJECTION"], _q(param, location=location))


@pytest.mark.parametrize("location", ["fragment", "header", "cookie", "path"])
def test_spel_does_not_nominate_outside_value_locations(location):
    assert not matches(RULES["R-SPEL-INJECTION"], _q("sort", location=location))


# R-SSRF: `thumbnail` dropped; `image` (OWASP SSRF Prevention Cheat Sheet) stays.

@pytest.mark.parametrize("param", ["image", "imageUrl", "avatar", "thumbnail_url",
                                   "webhook"])
def test_ssrf_nominates_url_shaped_names(param):
    assert matches(RULES["R-SSRF"], _q(param))


def test_ssrf_no_longer_nominates_a_bare_thumbnail():
    assert "thumbnail" not in RULES["R-SSRF"].when["name_regex"]
    assert not matches(RULES["R-SSRF"], _q("thumbnail"))


# R-CSV-FORMULA-INJECTION: `label` dropped (only booking-clone justified it).

@pytest.mark.parametrize("param", ["name", "comment", "note", "description", "title"])
def test_csv_formula_nominates_free_text_names(param):
    assert matches(RULES["R-CSV-FORMULA-INJECTION"], _q(param))


def test_csv_formula_no_longer_nominates_label():
    assert not matches(RULES["R-CSV-FORMULA-INJECTION"], _q("label"))


# R-JWT-ALG-NONE: the Authorization header (RFC 6750 / RFC 7235) only.

def test_jwt_alg_none_nominates_authorization_not_a_header_named_jwt():
    rule = RULES["R-JWT-ALG-NONE"]
    assert matches(rule, _q("Authorization", location="header"))
    assert not matches(rule, _q("jwt", location="header"))
    assert not matches(rule, _q("X-JWT", location="header"))


# value_shape: `lang` is not a common web file extension (bWAPP's lang_en.php).

def test_lang_is_not_a_file_extension():
    assert "lang" not in FILE_EXTENSIONS
    assert value_shape("en.lang") != "filename"
    assert value_shape("lang_en.php") == "filename"        # a .php file still is
