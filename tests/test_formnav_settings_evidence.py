"""The settings-word gate on shapes from independent public sources (FR-CRAWL-680).

Every fixture below is written from a framework's or vendor's public documentation,
not from a lab: the gate must hold on forms it was never measured on, and a
navigation picker must stay navigable. Sources are named next to each fixture."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from fuzzlab.core.forms import form_record
from fuzzlab.tools import formnav
from fuzzlab.tools.store_adapter import body_refusal, form_skip_reason

ROOT = Path(__file__).resolve().parents[1]
CSRF = "<input type=hidden name=csrfmiddlewaretoken value=T>"


def _rec(html, page="http://h/app/page"):
    return form_record(BeautifulSoup(html, "html.parser").find("form"), page)


def _select(name, values, action="/app/x", method="post", extra=""):
    opts = "".join(f"<option value='{v}'>{v}</option>" for v in values)
    return (f"<form method={method} action='{action}'>{extra}<select name='{name}'>"
            f"{opts}</select><button type=submit>Go</button></form>")


#: Settings pickers, each from a public source (none from a lab).
SETTINGS_PICKERS = {
    # Django docs, "Translation: The set_language redirect view" (POST, `language`)
    "django set_language": _select("language", ["en", "fr", "de"], "/i18n/setlang/",
                                   extra=CSRF + "<input type=hidden name=next value=/>"),
    # Django docs, "Time zones: Selecting the current time zone" (POST, `timezone`)
    "django timezone": _select("timezone", ["Europe/Paris", "America/New_York"],
                               "/set_timezone/", extra=CSRF),
    # Rails guides, "Rails Internationalization (I18n) API" (`locale`)
    "rails locale": _select("locale", ["en", "nl"], "/locale", method="get"),
    # Rails API, ActionView `time_zone_select` (`user[time_zone]`)
    "rails time_zone_select": _select("user[time_zone]", ["Hawaii", "Alaska"], "/users/1"),
    # Spring Framework reference, `ThemeChangeInterceptor` (default parameter `theme`)
    "spring theme": _select("theme", ["light", "dark"], "/prefs", method="get"),
    # Shopify Liquid `localization` form (`country_code`, `return_to`)
    "shopify country": _select("country_code", ["CA", "US"], "/localization",
                               extra="<input type=hidden name=return_to value=/>"),
    # GitHub REST / GitLab Projects API `visibility`
    "repository visibility": _select("visibility", ["public", "private"], "/repo/1"),
    # GitLab Members API `access_level`
    "gitlab access_level": _select("access_level", ["10", "30", "40"], "/members/7"),
}

#: Settings pickers whose names say nothing; their option values, read against a
#: public code list (IANA tz areas, the platform's locale table), show what they pick.
VALUE_ONLY_PICKERS = {
    "tz database names": _select("zone", ["Europe/London", "Asia/Tokyo", "Etc/UTC"]),
    "BCP 47 tags": _select("hl", ["en-US", "pt-BR", "zh-TW"]),
}

#: Navigation pickers and query modifiers that must not be refused.
NAVIGATION_PICKERS = {
    # a menu of pages
    "page menu": _select("page", ["1", "2", "3"], method="get"),
    # Joomla's `view` is a navigation parameter (`option=com_content&view=article`)
    "joomla view": _select("view", ["article", "category", "featured"], "/index.php",
                           method="get"),
    # JSON:API 1.1 "Sorting" / GitHub REST `sort`: a read-only list modifier
    "json:api sort": _select("sort", ["created", "-created", "title"], method="get"),
    # GitHub REST / WordPress REST `per_page`: pagination, read-only
    "per_page": _select("per_page", ["10", "50", "100"], method="get"),
    # option values that merely look short: not a language list
    "order by column": _select("order_by", ["id", "name", "date"], method="get"),
}


@pytest.mark.parametrize("key", sorted(SETTINGS_PICKERS) + sorted(VALUE_ONLY_PICKERS))
def test_settings_pickers_from_public_sources_are_never_submitted(key):
    html = {**SETTINGS_PICKERS, **VALUE_ONLY_PICKERS}[key]
    rec = _rec(html)
    assert rec["selector"], key
    select = rec["options"][0][0]
    # even when the operator names the select, navigation refuses it
    reason = formnav.refusal(rec, frozenset({select}), True, lambda u: True)
    assert reason and "settings" in reason, (key, reason)
    if rec["method"] == "POST":
        assert form_skip_reason(rec), key        # and the importer never fuzzes it


@pytest.mark.parametrize("key", sorted(NAVIGATION_PICKERS))
def test_navigation_pickers_and_list_modifiers_are_not_refused(key):
    rec = _rec(NAVIGATION_PICKERS[key])
    assert formnav.refusal(rec, frozenset(), True, lambda u: True) is None, key
    post = _rec(NAVIGATION_PICKERS[key].replace("method=get", "method=post"))
    assert form_skip_reason(post) is None, key


def test_value_only_rule_needs_every_option_and_two_of_them():
    assert formnav.option_set_setting(["Europe/Paris"]) is None
    assert formnav.option_set_setting(["Europe/Paris", "other"]) is None
    assert formnav.option_set_setting(["en", "fr"]) == "language options"
    assert formnav.option_set_setting(["asc", "desc"]) is None
    assert formnav.option_set_setting(["id", "name", "date"]) is None
    assert formnav.option_set_setting(["1", "2"]) is None
    assert formnav.option_set_setting(["America/Chicago", "Pacific/Auckland"]) \
        == "time zone options"


def test_a_captured_body_with_a_locale_or_time_zone_key_is_refused():
    leaves = [("user.locale", ["user", "locale"], "body", "en"),
              ("q", ["q"], "body", "x")]
    assert "locale" in body_refusal("http://h/api/me", leaves)
    leaves = [("time_zone", ["time_zone"], "body", "UTC")]
    assert "time_zone" in body_refusal("http://h/api/me", leaves)
    leaves = [("sort", ["sort"], "body", "price"), ("per_page", ["per_page"], "body", "10")]
    assert body_refusal("http://h/api/search", leaves) is None


REMOVED = ("sort", "per_page", "perPage", "view", "display", "layout", "skin", "region",
           "mode")


@pytest.mark.parametrize("word", REMOVED)
def test_words_without_an_independent_source_are_gone(word):
    assert formnav.settings_word(word) is None


def _uncited(source: str, name: str = "SETTINGS_WORDS") -> list[str]:
    """The words of the set literal ``name`` in ``source`` with no comment above their
    line inside the literal (walking up over other word lines; reaching the literal's
    opening line first means uncited)."""
    lines = source.splitlines()
    tree = ast.parse(source)
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == name for t in n.targets))
    start = node.lineno - 1
    out = []
    for w in node.value.args[0].elts:
        line = w.lineno - 2
        while line > start and not lines[line].strip().startswith("#"):
            line -= 1
        if line <= start:
            out.append(w.value)
    return out


def test_every_settings_word_sits_under_a_cited_comment():
    """Each word in `SETTINGS_WORDS` is in a line under a comment naming its source
    (PA-0660(2)): a word added above every comment, uncited, fails here."""
    source = (ROOT / "fuzzlab/tools/formnav.py").read_text()
    assert _uncited(source) == []


def test_the_citation_check_catches_an_uncited_word():
    offender = 'SETTINGS_WORDS = frozenset({\n    "uncited",\n    # RFC 1\n    "ok",\n})\n'
    assert _uncited(offender) == ["uncited"]
