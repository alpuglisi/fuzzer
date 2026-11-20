"""Disco never submits a form that configures the application (FR-CRAWL-674,
CC-CRAWL-0673, SP-120).

A settings form -- a control or the submitter named or labelled by a settings word
(`formnav.settings_word`) -- changes how the application answers every later request
(lane CRAWLSAFE measured the explorer submitting a security-level form, after which
every later request ran at that level). The spider's form gates already refuse such a
form; the explorer's `form_refusal` now asks the same owner. Invented forms."""

from __future__ import annotations

import pytest

from fuzzlab.disco.explore import form_refusal


@pytest.mark.parametrize("fields, submitter", [
    ([{"tag": "select", "name": "display_level"}], {"label": "Set"}),
    ([{"tag": "select", "id": "uiTheme"}], {"label": "Apply"}),
    ([{"tag": "input", "type": "text", "name": "q"}], {"name": "form_security"}),
    ([{"tag": "select", "name": "x", "label": "Language"}], {"label": "Save"}),
])
def test_a_settings_form_is_never_submitted(fields, submitter):
    assert (form_refusal(fields, submitter) or "").startswith("settings:")


def test_an_ordinary_form_is_still_submitted():
    fields = [{"tag": "input", "type": "text", "name": "title", "label": "Title"},
              {"tag": "textarea", "name": "body", "label": "Message"}]
    assert form_refusal(fields, {"label": "Post"}) is None


def test_the_explorer_and_the_spider_ask_one_owner():
    """SP-120: the explorer imports `formnav.settings_word`, never a word list of its
    own."""
    import inspect

    from fuzzlab.disco import explore
    src = inspect.getsource(explore.form_refusal)
    assert "settings_word" in src and "SETTINGS_WORDS" not in src
