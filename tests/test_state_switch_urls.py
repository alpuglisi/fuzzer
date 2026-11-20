"""BUG-0680 / PA-0680: the destructive-URL rule (SP-09, `core.urls.destructive_reason`)
also refuses state *switches* -- toggles, enable/activate, an action slot naming a state
verb, a destructive verb fused with its object -- measured against a cited corpus of
state-changing GET links from independent apps, and against benign links.

The corpus (``tests/data/state_change_corpus/``, CC-CORE-0650) cites each entry's
upstream source (repository, commit or branch, line). Entries labelled ``lab`` come from
the labs the bug was found on (Mutillidae, DVGA); the black-box rule (PA-0680(2)) lets
no word rest on them alone.

Every assertion computes the rule's verdict (PA-0001): a positive the rule does not
refuse needs a written residual here, a stale residual fails, and the benign links it
refuses are pinned so that a broadening which costs more coverage is a decision, never
a silent drift.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

import pytest
import yaml

from fuzzlab.core.urls import (
    ACTION_SLOTS,
    COMPOUND_STEMS,
    DESTRUCTIVE_TOKENS,
    SLOT_VERBS,
    _destructive_tokens,
    _url_tokens,
    destructive_reason,
    text_destructive_reason,
)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/data/state_change_corpus"
POSITIVES = json.loads((CORPUS / "positives.json").read_text())
NEGATIVES = json.loads((CORPUS / "negatives.json").read_text())

#: Words BUG-0680 added to the rule.
NEW_TOKENS = ("enable", "activate", "toggle")
#: The rule's words before BUG-0680 (d492b9d), each from a bug report of its own
#: (BUG-0111/0112/0114). Every word added after them must carry corpus evidence.
LEGACY_TOKENS = frozenset({
    "ban", "cancel", "clear", "dbupdate", "dbupgrade", "deactivate", "del", "delete",
    "destroy", "disable", "drop", "empty", "erase", "exit", "flush", "insert", "install",
    "kill", "logoff", "logout", "migrate", "purge", "reboot", "rebuild", "remove",
    "reset", "restart", "revoke", "seed", "setup", "shutdown", "signout", "terminate",
    "trash", "truncate", "uninstall", "unsubscribe", "updatedb", "upgradedb", "wipe",
})
#: Verbs BUG-0680 added to the action slots.
NEW_SLOT_VERBS = ("toggle", "enable", "activate", "resume", "stop", "switch")


def _get_positives(*, lab: bool):
    return [e for e in POSITIVES if (e.get("method") or "GET") == "GET"
            and e.get("kind") != "tool-default" and bool(e.get("lab")) is lab]


#: Cited state-changing GET links the rule does not refuse, each with why it is
#: accepted. Each is revisited the day the rule starts refusing it (stale check).
RESIDUALS = {
    "/dvwa/security.php?phpids=on": "flag value (on/off): a generic flag rule refused "
                                    "58 ordinary test URLs (?q=1); no name-only shape",
    "/dvwa/security.php?phpids=off": "as phpids=on",
    "/bWAPP/smgmt_admin_portal.php?admin=1": "flag value; the page is the lab's demo",
    "/WebGoat/service/debug/labels.mvc?enabled=true": "flag value; one source only",
    "/WebGoat/start.mvc?lang=en": "per-session UI language: no app state, no crawl "
                                  "collapse; ?lang= is on ordinary pages (DVWA help)",
    "/WebGoat/start.mvc?lang=de": "as lang=en",
    "/WebGoat/start.mvc?lang=fr": "as lang=en",
    "/explore/repos?lang=de-DE": "as lang=en",
    "/any/page?locale=fr": "as lang=en",
    "/any/page?theme=dark": "per-session presentation, as lang=en",
    "/rest/user/change-password?current=a&new=b&repeat=b": "BUG-0301 (open, strict "
                                                           "xfail in "
                                                           "test_destructive_routes_"
                                                           "external_labs)",
    "/rest/saveLoginIp": "`save` refuses 8 ordinary test routes; one GET source",
    "/admin/reports/status/run-cron?token=x": "`cron`: one source (Drupal); token-gated",
    "/cron/KEY": "as run-cron",
    "/profile/switch-org/2": "bare `switch` refuses a generated lab's cell "
                             "(/api/profiles/switch); caught only in an action slot",
}

#: The labs' own links (BUG-0680's trigger): refused, or residual with its reason.
LAB_RESIDUALS = {
    "/difficulty/hard": "a setting noun plus value: no GET source outside DVGA, and the "
                        "noun-plus-value shape refused 3 cited benign links "
                        "(wapiti's form.php?level=1); black-box rule (PA-0680(2))",
    "/difficulty/easy": "as /difficulty/hard",
    "/start_over": "`start over`: no second independent source (CC-CORE-0650)",
}

#: Benign links the rule refuses (coverage cost, never a safety cost), pinned.
KNOWN_FALSE_REFUSALS = {
    "/dvwa/setup.php", "/bWAPP/install.php", "/user/password/reset",
    "/user/password/send-reset-email", "/admin/appearance/uninstall",
    "/admin/modules/uninstall", "/wiki/Factory_reset", "/blog/how-to-reset-your-router",
    # BUG-0680's words: a render-only page and documentation pages
    "/user/activate", "/en-US/docs/Web/API/DOMTokenList/toggle", "/wiki/Toggle_switch",
    "/help/enable-javascript", "/kb/how-to-activate-windows",
}


@pytest.mark.parametrize("entry", _get_positives(lab=False), ids=lambda e: e["url"])
def test_every_cited_state_changing_get_is_refused_or_a_stated_residual(entry):
    url = entry["url"]
    if url in RESIDUALS:
        assert destructive_reason(url) is None, f"stale residual: the rule refuses {url}"
    else:
        assert destructive_reason(url) is not None, (url, entry["source"])


def test_residuals_name_corpus_entries():
    urls = {e["url"] for e in POSITIVES}
    assert set(RESIDUALS) <= urls and set(LAB_RESIDUALS) <= urls


def test_the_bugs_lab_toggles_are_refused_and_the_rest_are_stated():
    for entry in _get_positives(lab=True):
        url = entry["url"]
        if url in LAB_RESIDUALS:
            assert destructive_reason(url) is None, f"stale lab residual: {url}"
        else:
            assert destructive_reason(url) is not None, url
    for url in ("/index.php?do=toggle-security&page=home.php",
                "/index.php?do=toggle-enforce-ssl&page=home.php",
                "/index.php?do=toggle-hints&page=home.php"):
        assert destructive_reason(url) is not None


def test_benign_links_refused_are_exactly_the_known_ones():
    refused = {e["url"] for e in NEGATIVES if not e.get("wordlist")
               and destructive_reason(e["url"])}
    assert refused == KNOWN_FALSE_REFUSALS


def _independent_apps(word_check) -> set[str]:
    """Apps (lab entries count; tool-default exclusions do not) whose corpus URL
    satisfies ``word_check(tokens)``."""
    return {e.get("lab") or e["app"] for e in POSITIVES
            if e.get("kind") != "tool-default" and word_check(_url_tokens(e["url"]))}


def words_without_two_sources(tokens, positives_apps) -> list[str]:
    """Rule words (beyond the legacy list) shown on fewer than two independent apps, or
    only on the labs the bug came from."""
    return sorted(w for w in set(tokens) - LEGACY_TOKENS
                  if len(positives_apps(w)) < 2
                  or not positives_apps(w) - {"mutillidae", "dvga"})


def test_every_word_added_to_the_rule_is_shown_on_two_independent_apps():
    """PA-0680(2), the black-box rule: no word rests on one target. Any word added to
    DESTRUCTIVE_TOKENS after the legacy list needs two corpus apps, one not a lab the
    bug came from -- so a future word without evidence fails here."""
    def apps(word):
        return _independent_apps(lambda toks: word in toks)
    assert set(NEW_TOKENS) <= DESTRUCTIVE_TOKENS
    assert words_without_two_sources(DESTRUCTIVE_TOKENS, apps) == []


def test_the_two_source_guard_catches_a_synthetic_offender():
    """PA-0034(2): a word with one source, or with lab-only sources, is reported."""
    def apps(word):
        return {"solo": {"wordpress"}, "labonly": {"mutillidae", "dvga"},
                "ok": {"wordpress", "jenkins"}}.get(word, set())
    assert words_without_two_sources({"solo", "labonly", "ok", "logout"}, apps) == [
        "labonly", "solo"]


def test_the_action_slot_shape_is_shown_on_two_independent_apps_with_get():
    def slot_verb(toks):
        return any(a in ACTION_SLOTS and b in SLOT_VERBS for a, b in zip(toks, toks[1:]))
    apps = {e.get("lab") or e["app"] for e in _get_positives(lab=False)
            if slot_verb(_url_tokens(e["url"]))}
    assert len(apps) >= 2, apps
    assert set(NEW_SLOT_VERBS) <= set(SLOT_VERBS)


def test_the_compound_shape_is_shown_on_two_independent_apps():
    def fused(toks):
        return any(t.startswith(s) and t != s for t in toks for s in COMPOUND_STEMS)
    apps = {e.get("lab") or e["app"] for e in _get_positives(lab=False)
            if fused(_url_tokens(e["url"]))}
    assert len(apps) >= 2, apps


@pytest.mark.parametrize("url,expected", [
    ("/index.php?do=toggle-hints", "toggle"),
    ("/job/x/enable", "enable"),
    ("/wp-admin/plugins.php?action=activate&plugin=a", "activate"),
    ("/wp-admin/plugins.php?action=resume&plugin=a", "action resume"),
    ("/sqli_9.php?action=stop", "action stop"),
    ("/x?op=switch&to=2", "op switch"),
    ("/resetbutton/123", "reset in resetbutton"),
    ("/123/deletesnippet?index=0", "delete in deletesnippet"),
    ("/WebGoat/service/restartlesson.mvc", "restart in restartlesson"),
    ("/%74oggle", "toggle"),
])
def test_state_switches_are_refused(url, expected):
    assert destructive_reason(url) == expected


@pytest.mark.parametrize("url", [
    # inflections are words of their own (a listing of deleted items, a toggles page)
    "/posts/deleted", "/settings/toggles", "/admin/removed", "/resetting-guide",
    # a state verb outside an action slot
    "/api/playback/stop-reasons", "/profiles/switch", "/player?state=resume",
    # BUG-0114's harmless list stays harmless
    "/clearance.php", "/dropdown.php", "/installation.php", "/update_profile.php",
])
def test_inflections_and_free_standing_verbs_are_not_refused(url):
    assert destructive_reason(url) is None


def test_texts_share_the_new_words():
    """SP-10 reads the same tokens (PA-0003): an "Enable" button or a "toggle" control
    is a state switch as a text too."""
    assert text_destructive_reason("Enable debug mode") == "enable"
    assert text_destructive_reason("toggleHints") == "toggle"
    assert text_destructive_reason("Activate") == "activate"


def _crawlable_lab_routes() -> list[str]:
    urls = set()
    for path in sorted(glob.glob(str(ROOT / "lab/manifests/*.yaml"))):
        for cell in (yaml.safe_load(Path(path).read_text()) or {}).get("cells") or []:
            urls.add((cell.get("route") or {}).get("path") or "/")
    for gt in sorted(glob.glob(str(ROOT / "lab/ground-truth*/"))):
        for name, key in (("injection-points.json", "points"), ("labels.json", "cases")):
            f = Path(gt) / name
            if not f.exists():
                continue
            data = json.loads(f.read_text())
            for it in (data.get(key, []) if isinstance(data, dict) else data):
                if isinstance(it, dict) and it.get("url"):
                    urls.add(it["url"])
    return sorted(urls)


def test_no_lab_injection_point_or_cell_is_refused_by_the_new_shapes():
    """The coverage side: every generated cell and ground-truth point stays crawlable
    and fuzzable under the words BUG-0680 added (measured 0 of 505, CC-CORE-0650)."""
    routes = _crawlable_lab_routes()
    assert len(routes) > 100
    old_tokens = DESTRUCTIVE_TOKENS - set(NEW_TOKENS)
    newly = [u for u in routes if destructive_reason(u)
             and not any(t in old_tokens for t in _url_tokens(u))]
    assert newly == []


def test_the_compound_rule_is_proven_on_a_synthetic_offender():
    """PA-0034(2): a token list without the compound rule misses a fused verb."""
    assert _destructive_tokens(["resetbutton"]) == "reset in resetbutton"
    assert "resetbutton" not in DESTRUCTIVE_TOKENS
