"""The owner's send-rule decisions (D71): the CAPTCHA rule is gone; three rules stay
on by default, and each can be turned off for one lab run.

`fuzzlab.core.sendpolicy` is the one switch. The destructive, transaction and
credential-change rules stay pure classifiers. Each refusal site passes its reason
through the switch, and these tests drive each rule on and off at those sites:
- the probe send gate and the PRG follow-up;
- the crawler's route, link, form (button, glyph, action, control), label, reveal,
  reveal-window and seed rules;
- the browser route guard;
- the selector-form rules;
- the importer's form, entry, request and body rules;
- crawl points.

The rules are independent. The login flow keeps all three whatever the flags: it uses
them to tell a login form from a password-change form and to stay logged in. The
policy is process state set only by a command's own flags, never read from the
environment.
"""

from __future__ import annotations

import argparse

import pytest
from bs4 import BeautifulSoup

from fuzzlab.core import sendpolicy
from fuzzlab.core.forms import form_record
from fuzzlab.core.urls import DestructiveUrlRefused, check_send_url, in_origin_scope, origin_scope
from fuzzlab.harness import auto
from fuzzlab.oracle.probe import Probe
from fuzzlab.session import browserlogin
from fuzzlab.tools import formnav, navguard, probesender, spa, store_adapter

BASE = "http://127.0.0.1:3000"


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    """Every test starts and ends with every rule enforced (monkeypatch restores the
    module state, so nothing leaks into a later test or file)."""
    monkeypatch.setattr(sendpolicy, "_disabled", frozenset())


def off(*rules):
    sendpolicy.set_disabled(rules)


class _Route:
    """A fake Playwright route (as `tests/test_browser_scope.py`)."""

    def __init__(self, url, method="GET"):
        self.request = type("Req", (), {
            "url": url, "method": method, "headers": {},
            "post_data_buffer": b"x=1" if method != "GET" else None,
            "is_navigation_request": lambda _self: False})()
        self.outcome = None

    def fetch(self, max_redirects=None):
        return type("Resp", (), {"status": 200, "headers": {}})()

    def abort(self, code=None):
        self.outcome = "abort"

    def continue_(self):
        self.outcome = "continue"

    def fulfill(self, response=None, status=None, headers=None):
        self.outcome = "fulfill"


def _guard_aborts(url, method="GET", **kw):
    origins = origin_scope(BASE + "/")
    route = _Route(url, method)
    navguard.make_route_handler(in_scope=lambda u: in_origin_scope(u, origins), **kw)(route)
    return route.outcome == "abort"


# ----------------------------------------------------------------------- the switch


def test_every_rule_is_enforced_by_default():
    assert all(sendpolicy.enforced(r) for r in sendpolicy.RULES)
    assert sendpolicy.destructive("logout") == "logout"
    assert sendpolicy.transaction("checkout") == "checkout"
    assert sendpolicy.credential_change("two passwords") == "two passwords"
    with pytest.raises(ValueError):
        sendpolicy.set_disabled(["captcha"])


def test_no_environment_value_turns_a_rule_off(monkeypatch):
    """Review of CC-CORE-0062: a stray shell value must never relax a rule for a module
    or library caller that does not set the policy."""
    for name in ("FUZZLAB_SEND_POLICY_OFF", "FUZZLAB_ALLOW_DESTRUCTIVE_ROUTES"):
        monkeypatch.setenv(name, "destructive,transactions,credential-changes")
    assert sendpolicy.disabled() == frozenset()
    with pytest.raises(DestructiveUrlRefused):
        check_send_url(BASE + "/rest/user/logout")


def test_a_command_sets_the_policy_from_its_own_flags_only():
    p = argparse.ArgumentParser()
    sendpolicy.add_arguments(p)
    assert sendpolicy.apply(p.parse_args(["--allow-transactions"])) == (sendpolicy.TRANSACTIONS,)
    assert sendpolicy.disabled() == {sendpolicy.TRANSACTIONS}
    assert sendpolicy.apply(p.parse_args([])) == ()
    assert sendpolicy.disabled() == frozenset()


@pytest.mark.parametrize("module", ["fuzzlab.tools.spider", "fuzzlab.tools.fetcher",
                                    "fuzzlab.harness.auto_cli", "fuzzlab.greybox.greybox_cli"])
def test_each_traffic_command_has_the_three_flags(module):
    import importlib
    parser = importlib.import_module(module).build_parser()
    dests = {a.dest for a in parser._actions}
    assert {"allow_destructive_routes", "allow_transactions",
            "allow_credential_changes"} <= dests


def test_the_crawl_and_audit_parse_steps_apply_the_flags(monkeypatch):
    from fuzzlab.tools import fetcher, spider
    spider.parse_args(["--start", BASE + "/", "--allow-destructive-routes"])
    assert sendpolicy.disabled() == {sendpolicy.DESTRUCTIVE}
    monkeypatch.setattr("sys.argv", ["fetcher", "--allow-credential-changes"])
    fetcher.parse_args()
    assert sendpolicy.disabled() == {sendpolicy.CREDENTIAL_CHANGES}


@pytest.mark.parametrize("main", ["fuzzlab.harness.auto_cli", "fuzzlab.greybox.greybox_cli"])
def test_auto_and_greybox_apply_the_flags_before_the_dry_run(main, monkeypatch, capsys):
    import importlib
    mod = importlib.import_module(main)
    parser = mod.build_parser()
    required = [a for a in parser._actions if a.required]
    argv = []
    for a in required:
        argv += [a.option_strings[0], BASE + "/"] if a.option_strings else [BASE + "/"]
    mod.main(argv + ["--allow-transactions", "--dry-run"])
    assert sendpolicy.disabled() == {sendpolicy.TRANSACTIONS}


def test_the_top_level_entry_starts_from_the_defaults(capsys):
    from fuzzlab import cli
    off(sendpolicy.DESTRUCTIVE)
    assert cli.main(["version"]) == 0
    assert sendpolicy.disabled() == frozenset()


# ------------------------------------------------------------- destructive (D71)


def test_destructive_rule_on_and_off_at_its_refusal_sites():
    url = BASE + "/rest/user/logout"
    record = form_record(BeautifulSoup(
        "<form method=post action='/account/delete'><input name=email></form>", "html.parser"
    ).find("form"), BASE + "/")
    selector = {"selector": True, "options": [("bug", "1", "One")], "method": "POST",
                "controls": [("bug", "select")], "action_url": BASE + "/delete.php"}

    def spa_form(**kw):
        form = {"controls": [("q", "text")], "button": "Send", "button_aria": "",
                "action": None, **kw}
        return spa.form_refusal(form, "a", named=None) is None

    def verdicts():
        try:
            check_send_url(url)
            sent = True
        except DestructiveUrlRefused:
            sent = False
        return {
            "probe gate": sent,
            "form button": spa_form(button="Delete all"),
            # a glyph-only button on a named route (D76: on an unnamed one a label-less
            # button is refused whatever the rules)
            "form glyph": spa.form_refusal(
                {"controls": [("q", "text")], "button": "", "button_aria": "",
                 "button_icons": "delete", "action": None}, "a",
                named=frozenset({"a"})) is None,
            "form action": spa_form(action=BASE + "/#/logout"),
            "form control": spa_form(controls=[("deleteAll", "checkbox")]),
            "label": spa.label_refusal("Remove item") is None,
            "browser guard": not _guard_aborts(BASE + "/logout.php", method="POST"),
            "crawl point": auto._crawl_url_refusal(url) is None,
            "import request": store_adapter.request_refusal("POST", url) is None,
            "import form": store_adapter.form_skip_reason(record) is None,
            "import entries": store_adapter.entries_refusal([("action", "delete")]) is None,
            "selector form": formnav.refusal(selector, frozenset({"bug"}), False,
                                             lambda u: True) is None,
            "selector option": formnav.option_refusal("reset", "Reset") is None,
        }

    assert not any(verdicts().values()), verdicts()
    off(sendpolicy.DESTRUCTIVE)
    assert all(verdicts().values()), verdicts()


def test_a_delete_method_stays_refused_with_the_destructive_rule_off():
    off(sendpolicy.DESTRUCTIVE)
    check_send_url(BASE + "/api/Feedbacks/1", method="POST")
    with pytest.raises(DestructiveUrlRefused):
        check_send_url(BASE + "/api/Feedbacks/1", method="DELETE")


# --------------------------------------------------------------- visits (D72)


@pytest.mark.parametrize("disabled", [(), tuple(sendpolicy.RULES)])
def test_a_visit_is_never_refused_for_its_words_whatever_the_flags(disabled):
    """D72 (owner, 2026-10-16): the three rules govern writes only. Every visit site --
    a route, a reveal click, a GET in the window, a seed URL, a GET through the browser
    guard, a GET send, a PRG follow-up -- refuses nothing for its words, with the flags
    or without them."""
    off(*disabled)
    assert spa.classify_route("/logout")[0] == spa.ROUTE_OK
    assert spa.reveal_refusal(["More", "", "delete"]) is None
    assert spa.reveal_refusal(["Register", "", ""]) is None
    for url in ("/rest/user/logout", "/rest/wallet/balance", "/rest/user/change-password"):
        assert spa.window_request_refusal("GET", BASE + url, False) is None, url
    assert spa.query_url_refusal(BASE + "/#/logout?q=1") is None
    assert not _guard_aborts(BASE + "/logout.php")
    check_send_url(BASE + "/rest/user/logout", method="GET")
    for target in ("/logout.php", "/checkout", "/register"):
        assert _prg(target)[1] is None, target
    # the login flow keeps its strict rule whatever the flags
    assert spa.classify_route("/logout", strict=True)[0] == spa.ROUTE_DESTRUCTIVE


# ----------------------------------------------------------------- transactions


def _prg(location):
    return probesender.prg_target(Probe(status=303, text="", headers={"Location": location}),
                                  BASE + "/api/x", "POST")


def test_transaction_rule_on_and_off_at_its_refusal_sites():
    form = {"controls": [("q", "text")], "button": "Buy now", "button_aria": "",
            "action": None}

    def verdicts():
        return {
            "form": spa.form_refusal(form, "basket", named=None) is None,
            "label": spa.label_refusal("Checkout") is None,
            "import request": store_adapter.request_refusal(
                "POST", BASE + "/rest/basket/1/checkout") is None,
        }

    assert not any(verdicts().values()), verdicts()
    off(sendpolicy.TRANSACTIONS)
    assert all(verdicts().values()), verdicts()


# ----------------------------------------------------------- credential changes

CHANGE_PASSWORD = [("currentPassword", "password"), ("newPassword", "password"),
                   ("newPasswordRepeat", "password")]


def test_credential_rule_on_and_off_at_its_refusal_sites():
    form = {"controls": CHANGE_PASSWORD, "button": "Change", "button_aria": "",
            "action": None}
    record = form_record(BeautifulSoup(
        "<form method=post action='/profile'><input type=password name=old>"
        "<input type=password name=new></form>", "html.parser").find("form"), BASE + "/")
    leaves = [("password", ["password"], None, "a"),
              ("passwordRepeat", ["passwordRepeat"], None, "a")]

    def verdicts():
        # D76: a POST to one user (an id) with two passwords is a change; to the
        # collection it is a registration (imported, asserted below)
        body = store_adapter.body_refusal(BASE + "/api/Users/7", leaves) or ""
        return {
            "spa form": spa.form_refusal(form, "change-password", named=None) is None,
            "import form": store_adapter.form_skip_reason(record) is None,
            "import body": not body.startswith("credential-change"),
            "label account word": spa.label_refusal("Register") is None,
        }

    assert not any(verdicts().values()), verdicts()
    assert store_adapter.body_refusal(BASE + "/api/Users", leaves) is None    # D76
    off(sendpolicy.CREDENTIAL_CHANGES)
    assert all(verdicts().values()), verdicts()


# --------------------------------------------------------------------- isolation


def test_turning_one_rule_off_leaves_the_others_on():
    off(sendpolicy.TRANSACTIONS)
    with pytest.raises(DestructiveUrlRefused):                   # a write (D72)
        check_send_url(BASE + "/logout", method="POST")
    form = {"controls": CHANGE_PASSWORD, "button": "Change", "button_aria": "",
            "action": None}
    assert spa.form_refusal(form, "change-password", named=None)
    off(sendpolicy.DESTRUCTIVE, sendpolicy.CREDENTIAL_CHANGES)
    assert spa.label_refusal("Checkout")
    off(sendpolicy.DESTRUCTIVE)
    assert spa.label_refusal("Reset password")       # still an account word


def test_the_login_flow_keeps_every_rule_whatever_the_flags():
    """The rules also tell a login form from a password-change form and keep a login
    off logout pages; the flags never change how a login is found."""
    off(*sendpolicy.RULES)
    login_ish = {"controls": [("email", "text"), ("password", "password")],
                 "button": "Log out", "button_aria": "", "action": None}
    assert browserlogin.login_form_refusal(login_ish, "login")
    assert spa.form_refusal(login_ish, "login", named=None) is None       # a crawl: off
    assert spa.form_refusal(login_ish, "login", named=None, strict=True)  # login: kept
    assert spa.classify_route("/logout", strict=True)[0] == spa.ROUTE_DESTRUCTIVE
    assert _guard_aborts(BASE + "/logout.php", strict=True)               # login window
    assert not _guard_aborts(BASE + "/logout.php")


def test_the_login_window_and_route_choice_pass_strict(monkeypatch):
    """`browserlogin`'s window guard is built with ``strict=True`` (every `guard_page`
    call in the module, checked on the AST), and its login-route choice asks a strict
    `classify_route` (the call is intercepted)."""
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(browserlogin))
    guards = [c for c in ast.walk(tree) if isinstance(c, ast.Call)
              and getattr(c.func, "id", getattr(c.func, "attr", None)) == "guard_page"]
    assert guards
    for call in guards:
        kw = {k.arg: k.value for k in call.keywords}
        assert isinstance(kw.get("strict"), ast.Constant) and kw["strict"].value is True
    calls = []
    monkeypatch.setattr(spa, "classify_route",
                        lambda path, strict=False: calls.append(strict) or (spa.ROUTE_OK, None))
    page = type("Page", (), {"url": BASE + "/#/",
                             "eval_on_selector_all": lambda self, sel, js: []})()
    gate = type("Gate", (), {"routes": ["login", "account/login"],
                             "in_scope": staticmethod(lambda u: True)})()
    off(*sendpolicy.RULES)
    browserlogin._login_routes(page, gate, BASE + "/")
    assert calls and all(calls)


def test_no_captcha_rule_is_left():
    assert not hasattr(spa, "captcha_reason") and not hasattr(spa, "CAPTCHA_TOKENS")
    form = {"controls": [("captchaControl", "text"), ("comment", "textarea")],
            "button": "Submit", "button_aria": "", "action": None, "challenge": True,
            "hints": ["g-recaptcha"]}
    assert spa.form_refusal(form, "contact", named=None) is None
