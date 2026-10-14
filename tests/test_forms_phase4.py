"""Forms phase 4: the reveal window, constraint-aware filling and reveal navigation
(FR-CRAWL-15, FR-CRAWL-16; CC-CRAWL-0023/0024, CC-AUD-0039, CC-CORE-0052; BUG-0131).

* **The reveal window (W1-W4).** From just before a reveal click or the first G1
  interaction until the close, the reload and a final quiet period, the route aborts
  every write, every navigation (its target is queued instead) and side-effect GETs;
  page-to-server WebSocket messages are dropped. Only a named-route form's vetted final
  click lifts it, for that click. After a reveal in an authenticated crawl the session
  is checked client-side (plus ``verify_live`` when the window aborted anything); a loss
  re-adopts the browser state once, a second one stops reveals.
* **G1 (FR-CRAWL-15).** On a named route, invalid controls get ladder values (all
  fillers, none identifier-like) until the button is enabled; sensitive controls, object
  selectors, identifier options, gated checkboxes and CAPTCHA forms are refused.
* **G2 (FR-CRAWL-16).** Menus, dialogs and drawers are opened (gated labels, cards by
  their own ``el.click()``), what they reveal is queued through the normal gates, and the
  window closes with Escape and a reload.

Every browser test runs a local in-process fake app on 127.0.0.1 port 0.
"""

from __future__ import annotations

import ast
import json
import logging
from pathlib import Path

import pytest

from fuzzlab.tools import spa
from tests._spa_fixture import (
    G1Spa,
    RevealSpa,
    SessionRevealSpa,
    chromium_or_skip,
    db_rows,
    run_crawl,
)


# =====================================================================================
# W2: what the window lets through (pure)
# =====================================================================================
@pytest.mark.parametrize("method,url,navigation,blocked", [
    ("GET", "http://h/rest/products/search?q=apple", False, None),
    ("HEAD", "http://h/assets/i18n/en.json", False, None),
    ("POST", "http://h/rest/products/search", False, "a POST request"),
    ("PUT", "http://other.example/x", False, "a PUT request"),          # any destination
    ("DELETE", "http://h/api/x", False, "a DELETE request"),
    ("GET", "http://h/profile", True, "a navigation"),
    ("GET", "http://h/logout", False, "a destructive GET"),
    ("GET", "http://h/#/delete-account", False, "a destructive GET"),
    ("GET", "http://h/api/order-history", False, "a transaction GET"),
    ("GET", "http://h/rest/wallet/balance", False, "a transaction GET"),
    ("GET", "http://h/rest/user/change-password?new=x", False, "an account endpoint"),
    ("GET", "http://h/api/register", False, "an account endpoint"),
    ("GET", "http://h/api/items?action=create", False, "an account word"),
    ("GET", "http://h/rest/products?password=x", False, "a credential token"),
    ("GET", "http://h/rest/products?pwd=x", False, "a credential token"),
])
def test_the_window_lets_only_safe_gets_through(method, url, navigation, blocked):
    why = spa.window_request_refusal(method, url, navigation)
    assert (why is None) if blocked is None else (blocked in (why or "")), why


class _Route:
    """A fake Playwright route (as in test_browser_scope), recording the abort code."""

    def __init__(self, url, *, method="GET", navigation=False, site=None):
        self.request = type("Req", (), {
            "url": url, "method": method, "headers": {"content-type": "x/y"},
            "post_data_buffer": b"body" if method == "POST" else None,
            "is_navigation_request": lambda _self: navigation})()
        self.site = site or {}
        self.outcome, self.code, self.fetched = None, None, []

    def fetch(self, max_redirects=None, headers=None):
        self.fetched.append(self.request.url)
        return self.site.get(self.request.url, type("R", (), {"status": 200,
                                                                "headers": {}})())

    def abort(self, code=None):
        self.outcome, self.code = "abort", code

    def continue_(self):
        self.outcome = "continue"

    def fulfill(self, response=None, status=None, headers=None):
        self.outcome = "fulfill"


def test_the_route_asks_the_window_before_any_fetch_and_keeps_the_page_on_navigation():
    from fuzzlab.tools.navguard import make_route_handler
    asked = []

    def window(method, url, navigation):
        asked.append((method, url, navigation))
        return spa.window_request_refusal(method, url, navigation)
    handler = make_route_handler(in_scope=lambda u: True, window=window)
    post = _Route("http://h/api/x", method="POST")
    nav = _Route("http://h/profile", navigation=True)
    ok = _Route("http://h/rest/x")
    for route in (post, nav, ok):
        handler(route)
    assert (post.outcome, post.fetched) == ("abort", [])
    # a navigation is aborted as ERR_ABORTED, so no error page is committed
    assert (nav.outcome, nav.code, nav.fetched) == ("abort", "aborted", [])
    assert ok.outcome == "fulfill"
    assert asked == [("POST", "http://h/api/x", False), ("GET", "http://h/profile", True),
                     ("GET", "http://h/rest/x", False)]


def test_the_window_is_asked_again_on_every_redirect_hop():
    from fuzzlab.tools.navguard import make_route_handler
    redirect = type("R", (), {"status": 302, "headers": {"location": "/api/orders"}})()

    class _Api:
        calls = []

        def fetch(self, *a, **kw):
            self.calls.append(a)
            raise AssertionError("a refused hop is never fetched")
    handler = make_route_handler(in_scope=lambda u: True, api=_Api(),
                                 window=spa.window_request_refusal)
    route = _Route("http://h/rest/go", site={"http://h/rest/go": redirect})
    handler(route)
    assert route.outcome == "abort" and _Api.calls == []


class _WS:
    """A fake page-side WebSocketRoute; ``server`` records what is forwarded."""

    def __init__(self, url):
        self.url, self.handler = url, None
        self.server = type("S", (), {"sent": [], "send": lambda s, m: s.sent.append(m)})()

    def connect_to_server(self):
        return self.server

    def on_message(self, handler):
        self.handler = handler


def test_the_websocket_forwarder_drops_page_messages_only_inside_the_window():
    """W3: in-scope sockets go through a forwarding handler; page-to-server messages are
    forwarded only while the window is closed, dropped (and reported) inside it."""
    from fuzzlab.tools.navguard import make_ws_handler
    state, dropped = {"on": False}, []
    handler = make_ws_handler(lambda u: True, hold=lambda: state["on"],
                              on_drop=dropped.append)
    ws = _WS("ws://h/socket")
    handler(ws)
    ws.handler("hello")
    state["on"] = True
    ws.handler("in-window")
    state["on"] = False
    ws.handler("after")
    assert ws.server.sent == ["hello", "after"] and dropped == ["ws://h/socket"]


# =====================================================================================
# The label gate (G2d) and the Juice Shop login button
# =====================================================================================
@pytest.mark.parametrize("labels,refused", [
    (["Account", "Show/hide account menu", "account_circle"], None),
    (["", "Open Sidenav", "menu"], None),
    (["more_vert", "", ""], None),                   # an icon-only toggle: its raw text
    (["Log in", "Login", "exit_to_app"], "destructive icon"),   # no text-first for reveals
    (["Logout", "", ""], "destructive"),
    (["Delete all", "", ""], "destructive"),
    (["Items removed", "", ""], "destructive"),      # inflections folded
    (["Privacy & Security", "", ""], "settings-like"),
    (["Language", "", ""], "settings-like"),
    (["Orders & Payment", "", ""], "transaction"),
    (["Register", "", ""], "account word"),
    (["", "", ""], "no label"),
    (["#1 Delete", "", ""], "destructive"),           # BUG-0131: a '#' hides nothing
])
def test_the_reveal_gate(labels, refused):
    why = spa.reveal_refusal(labels)
    assert (why is None) if refused is None else (refused in (why or "")), why


def _form(button, aria="", icons="", controls=(("email", "text"),
                                               ("password", "password"))):
    return {"controls": [list(c) for c in controls], "button": button,
            "button_aria": aria, "button_icons": icons, "action": None,
            "autocomplete": [""] * len(controls)}


def test_juice_shops_login_button_still_passes_with_exit_to_app_a_destructive_glyph():
    """G2d / lane S's live fix: ``exit_to_app`` is a destructive glyph now, but a form's
    submitter is judged on its text and aria-label first; a glyph-only one is refused.
    (The real-browser IconSpa test -- test_spa_capture.py::
    test_icon_text_never_decides_a_button_label -- and FR-SESS-19's login tests click
    it.)"""
    assert "exit_to_app" in spa.DESTRUCTIVE_GLYPHS
    assert spa.form_refusal(_form("Log in", "Login", "exit_to_app"), "login",
                            named=None) is None
    assert "destructive button icon ('exit_to_app')" in \
        spa.form_refusal(_form("", "", "exit_to_app"), "login", named=None)
    assert "destructive button aria-label" in \
        spa.form_refusal(_form("", "Logout", "exit_to_app"), "x", named=None)
    # the always-refused glyphs keep refusing whatever the text says
    assert "destructive button icon" in spa.form_refusal(_form("Item 3", "", "delete"),
                                                        "x", named=None)
    from fuzzlab.session.browserlogin import login_form_refusal
    login = _form("Log in", "Login", "exit_to_app")
    assert login_form_refusal(login, "login") is None


# =====================================================================================
# BUG-0131: a '#' in a text hid the rest of it from the destructive rule
# =====================================================================================
@pytest.mark.parametrize("text", ["#1 Delete", "Item #4 remove", "x#logout", "#a_drop_table"])
def test_a_hash_in_a_label_name_value_or_option_hides_nothing(text):
    from fuzzlab.core.urls import text_destructive_reason
    from fuzzlab.tools import formnav
    from fuzzlab.tools.store_adapter import entries_refusal
    assert text_destructive_reason(text)
    assert "destructive button" in spa.form_refusal(_form(text, controls=[("q", "text")]),
                                                    "contact", named=None)
    assert "destructive control" in spa.form_refusal(
        _form("Go", controls=[(text, "text")]), "contact", named=None)
    assert entries_refusal([("note", text)]) and entries_refusal([(text, "x")])
    assert formnav.option_refusal("a", text) and formnav.option_refusal(text, "a")


def test_the_text_rule_agrees_with_the_url_rule_on_texts_without_a_hash():
    """The fix changes nothing for texts the old embedding read whole."""
    from fuzzlab.core.urls import (
        DESTRUCTIVE_PAIRS,
        DESTRUCTIVE_TOKENS,
        destructive_reason,
        text_destructive_reason,
    )
    words = sorted(DESTRUCTIVE_TOKENS) + [" ".join(p) for p in sorted(DESTRUCTIVE_PAIRS)]
    texts = words + [f"Please {w} now" for w in words] + [
        "Model", "dropdown", "clearance", "Search", "Update profile", "sign-out",
        "deleteAll", "%64elete", "a+b", "set_up", "Log  out", "update.php"]
    for text in texts:
        old = destructive_reason("/?x=" + text.replace(" ", "+"))
        assert text_destructive_reason(text) == old, text


def test_a_second_hash_in_a_spa_fragment_hides_nothing():
    assert spa.route_destructive_reason("http://h/#/a#/logout") == "logout"
    assert spa.route_destructive_reason("http://h/#/about") is None


# =====================================================================================
# G1 (FR-CRAWL-15): the ladder, the refusals
# =====================================================================================
@pytest.mark.parametrize("info,first", [
    ({"kind": "number", "min": "10", "max": "20"}, "11"),
    ({"kind": "number", "min": "0", "max": "30", "step": "11"}, "0"),
    ({"kind": "number", "min": "1000000", "max": "9999999999"}, "1111111"),
    ({"kind": "range", "min": "0", "max": "5"}, "1"),
    ({"kind": "number", "names": ["mobileNumber"]}, "1111111111"),
    ({"kind": "number", "names": ["zipCode"]}, "12345"),
    ({"kind": "number", "names": ["year"]}, "2000"),
    ({"kind": "text", "names": ["mobile"]}, "5555550100"),
    ({"kind": "text", "minlength": "10"}, "fuzzlabxxx"),
    ({"kind": "text", "maxlength": "4"}, "fuzz"),
    ({"kind": "email"}, "fuzzlab@example.invalid"),
    ({"kind": "date"}, "2020-01-01"),
])
def test_the_ladder_respects_the_constraints(info, first):
    cands = spa.g1_candidates(info)
    assert cands and cands[0] == first, cands
    assert len(cands) <= spa.G1_MAX_ATTEMPTS or info.get("pattern")


def test_a_grid_with_no_ladder_value_has_no_candidate():
    """A stated gap: only ladder values are typed, so [10, 20] step 5 (10, 15, 20) has
    none, and the form is reported still invalid."""
    assert spa.g1_candidates({"kind": "number", "min": "10", "max": "20", "step": "5"}) == []


def test_a_pattern_gets_candidates_of_its_quantifier_lengths():
    assert spa.pattern_lengths("[0-9]{5}-[a-z]{2,4}x{3,}") == [5, 2, 4, 3]
    cands = spa.g1_candidates({"kind": "text", "pattern": "[0-9]{5}"})
    assert "11111" in cands and "12345" in cands


def _ladder_values():
    from fuzzlab.tools.store_adapter import (
        LADDER_CONSTANTS,
        LADDER_MAX_DIGITS,
        LADDER_MAX_TEXT,
        LADDER_TEXT,
        LADDER_TEXT_VARIANTS,
        ladder_digits,
    )
    values = set(LADDER_CONSTANTS) | set(LADDER_TEXT_VARIANTS)
    for n in range(1, LADDER_MAX_DIGITS + 1):
        values |= set(ladder_digits(n))
    for n in range(3, LADDER_MAX_TEXT + 1):
        values.add(spa._fit_length(LADDER_TEXT, n, n))
    probes = [{"kind": k, "min": lo, "max": hi, "minlength": a, "maxlength": b,
               "pattern": p, "names": names}
              for k in ("text", "number", "range", "tel", "email", "url", "textarea")
              for lo, hi in ((None, None), ("10", "20"), ("1000000", "9999999999"))
              for a, b in ((None, None), ("3", "5"), ("12", "40"))
              for p in ("", "[0-9]{5}", "[A-Za-z]+")
              for names in ([], ["phone"], ["zip"], ["qty"], ["year"])]
    for info in probes:
        values |= set(spa.g1_candidates(info))
    return sorted(v for v in values if v is not None)


def test_every_ladder_value_is_a_filler_and_never_identifier_like():
    """B7: every value G1 can type is recognised by `store_adapter.is_filler` (the single
    source) and is never identifier-like (redaction never mistakes it for a secret, and
    it never carries one)."""
    from fuzzlab.core.redaction import looks_like_identifier
    from fuzzlab.tools.store_adapter import is_filler
    values = _ladder_values()
    assert len(values) > 50
    for value in values:
        assert is_filler(value), value
        assert not looks_like_identifier(value), value
    # exact: near misses are not fillers
    for other in ("fuzzlab ", "fuzzlabX", "1234567890123456", "1112", "2001", "fu"):
        assert not is_filler(other), other


@pytest.mark.parametrize("names,options,chosen,refused", [
    (["nationality"], [("", "--"), ("BE", "Belgium"), ("FR", "France")], "Belgium", None),
    (["rating"], [("1", "1 star"), ("5", "5 stars")], "1 star", None),
    (["size"], [("", "Small"), ("", "Large")], "Small", None),
    (["cardId"], [("", "Visa")], "Visa", "object selector"),
    (["user_id"], [("", "alice")], "alice", "object selector"),
    (["id"], [("", "x")], "x", "object selector"),
    (["owner"], [("", "x")], "x", "object selector"),
    (["card"], [("", "Visa •••• 4242")], "Visa •••• 4242", "identifier-like option"),
    (["address"], [("9f8e7d6c5b4a39281706f5e4d3c2b1a0", "Home")], "Home",
     "identifier-like option"),
    (["address"], [("17", "Home")], "Home", "numeric record key"),
    (["plan"], [("", "Delete my data")], "Delete my data", "destructive"),
    (["plan"], [("", "Buy premium")], "Buy premium", "transaction"),
    (["plan"], [("", "Dark theme")], "Dark theme", "settings-like"),
])
def test_select_refusal(names, options, chosen, refused):
    why = spa.select_refusal(names, options, chosen)
    assert (why is None) if refused is None else (refused in (why or "")), why


@pytest.mark.parametrize("label,refused", [
    ("I accept the terms", None),
    ("I have read the privacy notice", "settings-like"),
    ("Subscribe to the newsletter", "subscribe"),
    ("Send me newsletters", "subscription or remember-me"),
    ("Remember me", "subscription or remember-me"),
    ("Make this my default address", "settings-like"),
    ("I understand my account will be deleted", "destructive"),
    ("", "unlabelled"),
])
def test_checkbox_refusal(label, refused):
    why = spa.checkbox_refusal(label)
    assert (why is None) if refused is None else (refused in (why or "")), why


@pytest.mark.parametrize("name,sensitive", [
    ("cvv", True), ("cardCvc", True), ("otp", True), ("pin", True),
    ("securityAnswer", True), ("password", True), ("totpToken", True),
    ("verificationCode", True), ("code", True),
    ("comment", False), ("zipCode", False), ("postcode", False), ("mobileNumber", False),
])
def test_g1_never_fills_a_sensitive_or_credential_control(name, sensitive):
    assert bool(spa.g1_sensitive([name])) is sensitive


@pytest.mark.parametrize("form,refused", [
    ({"controls": [["captchaControl", "text"]], "hints": []}, True),
    ({"controls": [["q", "text"]], "hints": ["g-recaptcha"]}, True),
    ({"controls": [["q", "text"]], "hints": ["https://h/recaptcha/api2/anchor"]}, True),
    ({"controls": [["q", "text"]], "hints": [], "challenge": True}, True),
    ({"controls": [["comment", "textarea"]], "hints": ["capture", "captain"]}, False),
])
def test_captcha_forms_are_refused(form, refused):
    assert bool(spa.captcha_reason(form)) is refused


def test_caps_are_positive_constants():
    """B8: caps as constants (each enforced in a real-browser test below)."""
    for cap in (spa.G1_MAX_ATTEMPTS, spa.MAX_REVEAL_CANDIDATES, spa.MAX_REVEALS_PER_PAGE,
                spa.MAX_REVEALS, spa.MAX_CARDS_PER_SIGNATURE, spa.MAX_MENU_ITEMS,
                spa.MAX_CARD_TEXT, spa.G1_PATTERN_TIMEOUT_MS):
        assert isinstance(cap, int) and cap > 0


def test_the_revealed_forms_table_is_the_contract(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    db = str(tmp_path / "s.db")
    sm = StorageManager(db)
    try:
        assert sm.record_revealed_form("http://h/#/x?token=SECRET", "x", "sig") is True
        assert sm.record_revealed_form("http://h/#/x", "x", "sig") is False
        sm.record_revealed_form("http://h/#/x", "x", "sig", submitted=True)
        assert db_rows(db, "SELECT page_url, route, signature, submitted FROM "
                           "revealed_forms") == [("http://h/#/x?token=__REDACTED__", "x",
                                                  "sig", 1)]
        sm.reset()
        assert db_rows(db, "SELECT * FROM revealed_forms") == []
    finally:
        sm.close()


def test_reveals_are_on_by_default_and_the_cli_turns_them_off(tmp_path):
    from fuzzlab.tools.spider import LocalSpider, build_parser
    assert build_parser().parse_args([]).no_reveal is False
    assert build_parser().parse_args(["--no-reveal"]).no_reveal is True
    sp = LocalSpider("http://127.0.0.1:9/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        assert sp._reveal_on is False                      # never in the static engine
    finally:
        sp.storage.close()


# =====================================================================================
# Real browser: G2 and the window (RevealSpa), one shared crawl
# =====================================================================================
class _Logs(logging.Handler):
    def __init__(self):
        super().__init__(logging.INFO)
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _crawl(lab, tmp_path, **kw):
    from fuzzlab.tools.spider import LocalSpider
    db = str(tmp_path / "s.db")
    sp = LocalSpider(lab.base, max_depth=2, db_name=db, engine="playwright",
                     timeout_ms=10000, **kw)
    logs = _Logs()
    root = logging.getLogger()
    level = root.level
    root.addHandler(logs)
    root.setLevel(logging.INFO)
    try:
        run_crawl(sp)
    finally:
        root.removeHandler(logs)
        root.setLevel(level)
    return sp, db, logs.lines


@pytest.fixture(scope="module")
def revealed(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    lab = RevealSpa()
    try:
        chromium_or_skip(mp)
        sp, db, logs = _crawl(lab, tmp_path_factory.mktemp("reveal"))
        yield lab, sp, db, logs
    finally:
        lab.close()
        mp.undo()


def _paths(lab, method=None):
    return [r[1] for r in lab.requests if method is None or r[0] == method]


def test_w2_a_reveal_can_only_read(revealed):
    """W2: the menu's click POSTs and makes side-effect GETs (transaction, account,
    credential words); none reaches the server. The plain GETs do (the reveal ran)."""
    lab, sp, _db, _logs = revealed
    assert "/rest/marker/menu-opened" in _paths(lab, "GET")
    assert "/rest/marker/plain-get" in _paths(lab, "GET")
    assert _paths(lab, "POST") == []
    for refused in ("/api/order-history", "/rest/user/change-password",
                    "/rest/products"):
        assert not any(p.startswith(refused) for p in _paths(lab)), refused
    assert sp.spa_counts["reveal_writes_blocked"] >= 5


def test_w2_a_menu_items_navigation_is_queued_never_sent_during_the_reveal(revealed):
    """G2b + W2: the profile item navigates by script (Juice Shop's account menu). The
    navigation is aborted inside the window and its target queued: /profile is
    requested exactly once, by the crawl's own visit."""
    lab, sp, db, _logs = revealed
    assert _paths(lab, "GET").count("/profile") == 1
    pages = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    assert pages[lab.base + "profile"] == "reveal"
    assert sp.spa_counts["reveal_navigations_captured"] >= 1
    # its server-rendered form is recorded as any crawled form is
    assert (lab.base + "profile", "POST") in db_rows(
        db, "SELECT action_url, method FROM discovered_forms")


def test_w3_a_websocket_message_in_the_window_is_dropped(revealed):
    lab, sp, _db, _logs = revealed
    assert "hello" in lab.ws_messages                    # forwarded outside the window
    assert "reveal-msg" not in lab.ws_messages
    assert sp.spa_counts["reveal_ws_dropped"] >= 1


def test_w1_a_debounced_post_after_close_never_arrives(revealed):
    """W1 / B2: the dialog POSTs 300 ms after Escape closes it; the window covers the
    close, the reload and the quiet period, so nothing arrives."""
    lab, _sp, _db, _logs = revealed
    assert "/api/after-close" not in _paths(lab)


def test_g2b_a_menu_item_failing_the_gate_is_never_clicked(revealed):
    """Logout, Orders & Payment and Privacy & Security are never clicked; History (a
    passing item) is, after a reload and a re-click of the trigger."""
    lab, sp, _db, _logs = revealed
    gets = _paths(lab, "GET")
    for item in ("item-L", "item-O", "item-P"):
        assert f"/rest/marker/{item}" not in gets, item
    assert "/rest/marker/item-H" in gets
    assert sp.spa_counts["reveals_refused"] >= 3


def test_g2a_cards_are_clicked_on_the_element_capped_and_never_with_descendants(revealed):
    """G2a: interactive cards (role=button) are clicked by ``el.click()``, at most
    `MAX_CARDS_PER_SIGNATURE` per signature; a card with an interactive descendant is
    not one target; a card whose text fails the gate is refused; G2c: the dialog's own
    Close button is never clicked."""
    lab, sp, _db, _logs = revealed
    gets = _paths(lab, "GET")
    clicked = [n for n in range(1, 5) if f"/rest/marker/card-{n}" in gets]
    assert clicked == list(range(1, spa.MAX_CARDS_PER_SIGNATURE + 1))
    assert "/rest/marker/card-bad" not in gets and "/rest/marker/add" not in gets
    assert "/rest/marker/card-del" not in gets
    assert "/rest/marker/dlg-close" not in gets
    assert sp.spa_counts["reveals_over_cap"] >= 1


def test_a_card_is_dispatched_on_the_element_never_by_a_coordinate_click(revealed):
    """B6: a card under a transparent overlay is still reached by its own
    ``el.click()``; the overlay (what a coordinate click would hit) never is."""
    lab, _sp, _db, _logs = revealed
    gets = _paths(lab, "GET")
    assert "/rest/marker/card-covered" in gets and "/rest/marker/veil-hit" not in gets


def test_g2e_a_dialog_form_and_a_menu_link_are_discovered_and_attributed(revealed):
    lab, sp, db, logs = revealed
    rows = db_rows(db, "SELECT route, signature, submitted FROM revealed_forms")
    assert rows == [("cards", json.dumps([[["review", "textarea"]], "Submit"]), 0)]
    # the dialog's real <form> goes through the phase 1/2 record, its own method
    assert (lab.base + "api/reviews", "POST") in db_rows(
        db, "SELECT action_url, method FROM discovered_forms")
    pages = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    assert pages[lab.base + "#/secret-link"] == "reveal"       # an undeclared route
    assert any("Revealed forms are recorded" in ln for ln in sp.spa_summary())
    # not submitted: the route was not named
    assert "/api/review" not in _paths(lab)


def test_the_counts_are_persisted_in_crawl_stats(revealed):
    """PA-0110 / B8: each count is of an effect that happened, stored by the crawl."""
    _lab, sp, db, _logs = revealed
    stats = dict(db_rows(db, "SELECT name, value FROM crawl_stats"))
    for key in ("reveals_clicked", "reveals_refused", "reveal_writes_blocked",
                "reveal_ws_dropped", "reveal_navigations_captured", "revealed_links",
                "revealed_forms", "session_losses_after_reveal", "g1_controls_filled",
                "g1_forms_unsatisfiable", "reveals_stopped"):
        assert key in stats, key
    assert stats["reveals_clicked"] == sp.spa_counts["reveals_clicked"] >= 4
    assert stats["revealed_links"] >= 2 and stats["revealed_forms"] == 1


def test_a_revealed_form_is_submitted_only_on_a_named_route(monkeypatch, tmp_path):
    chromium_or_skip(monkeypatch)
    lab = RevealSpa()
    try:
        sp, db, _logs = _crawl(lab, tmp_path, submit_spa_forms=["cards"])
    finally:
        lab.close()
    assert _paths(lab, "POST").count("/api/review") == 1        # once per signature
    assert db_rows(db, "SELECT route, submitted FROM revealed_forms") == [("cards", 1)]
    assert "/api/after-close" not in _paths(lab)


def test_the_crawl_cap_on_reveals(monkeypatch, tmp_path):
    chromium_or_skip(monkeypatch)
    monkeypatch.setattr(spa, "MAX_REVEALS", 1)
    lab = RevealSpa()
    try:
        sp, _db, _logs = _crawl(lab, tmp_path)
    finally:
        lab.close()
    assert sp.spa_counts["reveals_clicked"] == 1
    assert sp.spa_counts["reveals_over_cap"] >= 1


def test_no_reveal_turns_reveals_off(monkeypatch, tmp_path):
    chromium_or_skip(monkeypatch)
    lab = RevealSpa()
    try:
        sp, _db, _logs = _crawl(lab, tmp_path, reveal=False)
    finally:
        lab.close()
    assert sp.spa_counts["reveals_clicked"] == 0
    assert "/rest/marker/menu-opened" not in _paths(lab)


# =====================================================================================
# Real browser: G1 (G1Spa), one shared crawl
# =====================================================================================
@pytest.fixture(scope="module")
def g1(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    lab = G1Spa()
    try:
        chromium_or_skip(mp)
        sp, db, logs = _crawl(lab, tmp_path_factory.mktemp("g1"), submit_spa_forms=[
            "g1", "g1bad", "g1captcha", "g1card", "g1ack"])
        yield lab, sp, db, logs
    finally:
        lab.close()
        mp.undo()


def test_g1_an_angular_like_form_is_made_valid_and_submitted_once(g1):
    """A number in [10, 20], a pattern [0-9]{5}, a required select, a slider (ng-invalid
    until moved), a required checkbox and a mat-select: every value is a ladder value
    or a filler (`is_filler`)."""
    from fuzzlab.tools.store_adapter import is_filler
    lab, sp, _db, _logs = g1
    posts = [r for r in lab.requests if r[:2] == ("POST", "/api/g1-submit")]
    assert len(posts) == 1
    body = json.loads(posts[0][4])
    assert body == {"qty": "11", "zip": "11111", "nationality": "BE", "rating": "1",
                    "terms": True, "size": "Small"}
    assert all(is_filler(body[k]) for k in ("qty", "zip", "rating"))
    assert sp.spa_counts["g1_controls_filled"] >= 5


def test_g1_a_selection_change_post_is_never_sent_before_the_submission(g1):
    """B5: every G1 interaction runs inside the window; the select's and the
    mat-select's autosave POSTs are aborted."""
    lab, sp, _db, _logs = g1
    assert "/api/autosave" not in _paths(lab)
    assert sp.spa_counts["reveal_writes_blocked"] >= 2


def test_g1_an_unsatisfiable_pattern_is_not_submittable_with_the_reason(g1):
    lab, sp, _db, logs = g1
    assert "/api/sent/g1bad" not in _paths(lab)
    assert any("g1bad not submittable (invalid after" in ln and ": tag" in ln
               for ln in logs), logs
    assert sp.spa_counts["g1_forms_unsatisfiable"] >= 1


def test_g1_a_captcha_form_is_refused(g1):
    lab, _sp, _db, logs = g1
    assert "/api/sent/g1captcha" not in _paths(lab)
    assert any("g1captcha not submitted: CAPTCHA form" in ln for ln in logs)


def test_g1_a_saved_card_picker_is_never_chosen_in(g1):
    """G1c: the mat-select's options are card endings (a numeric id); the form is not
    submittable, while the plain select of the first form (nationality) was filled."""
    lab, _sp, _db, logs = g1
    assert "/api/sent/g1card" not in _paths(lab)
    assert any("g1card not submittable" in ln and "identifier-like option" in ln
               for ln in logs), logs


def test_g1_a_delete_account_checkbox_is_never_checked_and_never_submitted(g1):
    lab, _sp, _db, logs = g1
    assert "/api/sent/g1ack" not in _paths(lab)
    assert any("g1ack not submittable" in ln and "destructive" in ln for ln in logs)


# =====================================================================================
# Real browser: W4 (SessionRevealSpa, authenticated, the session in localStorage)
# =====================================================================================
LS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.c2Vzc2lvbi1mb3ItdGVzdHM.Zm9vYmFyYmF6cXV4MTIzNDU2"


class _LsManager:
    def __init__(self, base):
        origin = base.rstrip("/")
        self.state = type("State", (), {
            "cookies": {}, "headers": {}, "secure_only": False,
            "browser_state": {"cookies": [], "origins": [{
                "origin": origin, "localStorage": [{"name": "token",
                                                    "value": LS_TOKEN}]}]}})()
        self.verified = 0

    def ensure(self, host, identity, base_url, operator=False):
        return self.state

    def verify_live(self, host, identity, base_url):
        self.verified += 1
        return True


def test_w4_a_client_side_logout_is_readopted_then_a_second_loss_stops_reveals(
        monkeypatch, tmp_path):
    """An icon-only toggle clears the localStorage token without any request: the
    client-side check after the reveal sees it, reveals stop on that route, the browser
    state is re-adopted and the crawl goes on (``mid`` is still revealed); the second
    loss (``session2``) stops reveals for the crawl (``late`` is never revealed)."""
    chromium_or_skip(monkeypatch)
    lab = SessionRevealSpa()
    try:
        sp, db, _logs = _crawl(lab, tmp_path, session_manager=_LsManager(lab.base),
                               identity="user")
    finally:
        lab.close()
    gets = _paths(lab, "GET")
    assert "/rest/marker/opened-session1" in gets
    assert "/rest/marker/opened-mid" in gets                    # re-adopted, went on
    assert "/rest/marker/opened-session2" in gets
    assert "/rest/marker/opened-late" not in gets               # stopped
    assert sp.spa_counts["session_losses_after_reveal"] == 2
    assert sp.reveals_stopped and "lost again" in sp.reveals_stopped
    stats = dict(db_rows(db, "SELECT name, value FROM crawl_stats"))
    assert stats["reveals_stopped"] == 1 and stats["session_losses_after_reveal"] == 2
    assert any("Reveals stopped" in ln for ln in sp.spa_summary())


# =====================================================================================
# PA-0131 guard: a text is never judged by embedding it in a URL (BUG-0131)
# =====================================================================================
_URL_RULES = {"destructive_reason", "route_destructive_reason", "_url_tokens"}
#: Calls that build a URL from URL parts on purpose, with the reason.
_ALLOWED_EMBEDDINGS = {
    # a SPA route's own path and query, re-joined (URL parts, not a text); a second
    # '#' inside a fragment is the app's own fragment (Angular, Vue), not the route --
    # BUG-0131's PA-0002 sweep records it as a residual (a FUZZ change, not made here)
    ("fuzzlab/harness/auto.py",
     "destructive_reason(route[0] + ('?' + route[1] if route[1] else ''))"),
}


def _embedded_text_offenders(source: str) -> list[str]:
    """Calls of a URL rule whose argument is built with a ``?`` (a text spliced into a
    query): a ``#`` in the text would hide the rest of it."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else \
            getattr(node.func, "id", None)
        arg = node.args[0]
        if name not in _URL_RULES or not isinstance(arg, (ast.BinOp, ast.JoinedStr)):
            continue
        consts = [n.value for n in ast.walk(arg)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        if any("?" in c for c in consts):
            out.append(ast.unparse(node))
    return out


def test_no_text_is_judged_through_a_url():
    root = Path(__file__).resolve().parent.parent
    found = set()
    for path in sorted((root / "fuzzlab").rglob("*.py")):
        rel = str(path.relative_to(root))
        found |= {(rel, call) for call in _embedded_text_offenders(path.read_text())}
    assert found - _ALLOWED_EMBEDDINGS == set()
    assert _ALLOWED_EMBEDDINGS <= found               # the allowance is not stale


def test_the_text_guard_catches_synthetic_offenders():
    """PA-0034(2): the old spellings are flagged; the text rule and URLs are not."""
    for bad in ('r = destructive_reason("/?x=" + text.replace(" ", "+"))',
                'r = destructive_reason("/?" + "x=" + (t or ""))',
                'r = urls.destructive_reason(f"/?x={label}")',
                'r = route_destructive_reason("/a?" + q)'):
        assert _embedded_text_offenders(bad), bad
    for ok in ('r = text_destructive_reason(label)', 'r = destructive_reason(url)',
               'r = destructive_reason("/" + route)'):
        assert not _embedded_text_offenders(ok), ok
