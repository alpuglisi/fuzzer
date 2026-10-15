"""The owner's send-rule decisions (D71): the CAPTCHA rule is gone; three rules stay
on by default, and each can be turned off for one lab run.

`fuzzlab.core.sendpolicy` is the one switch. The destructive, transaction and
credential-change rules stay pure classifiers. Each refusal site passes its reason
through the switch: the probe send gate, the crawler's route, link, form, label and
reveal-window rules, the browser route guard, the auditor, and the importer's form,
request and body rules. The login flow keeps all three rules whatever the flags,
because it uses them to tell a login form from a password-change form and to stay
logged in. These tests drive each rule on and off at its refusal sites and show the
rules are independent.
"""

from __future__ import annotations

import argparse
import inspect

import pytest
from bs4 import BeautifulSoup

from fuzzlab.core import sendpolicy
from fuzzlab.core.forms import form_record
from fuzzlab.core.urls import DestructiveUrlRefused, check_send_url
from fuzzlab.harness import auto
from fuzzlab.session import browserlogin
from fuzzlab.tools import formnav, spa, store_adapter

BASE = "http://127.0.0.1:3000"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(sendpolicy.ENV, raising=False)


def off(*rules):
    sendpolicy.set_disabled(rules)


# ----------------------------------------------------------------------- the switch


def test_every_rule_is_enforced_by_default():
    assert all(sendpolicy.enforced(r) for r in sendpolicy.RULES)
    assert sendpolicy.destructive("logout") == "logout"
    assert sendpolicy.transaction("checkout") == "checkout"
    assert sendpolicy.credential_change("two passwords") == "two passwords"


def test_unknown_rules_are_refused_and_junk_in_the_environment_is_ignored(monkeypatch):
    with pytest.raises(ValueError):
        sendpolicy.set_disabled(["captcha"])
    monkeypatch.setenv(sendpolicy.ENV, "nonsense, ,destructive")
    assert sendpolicy.disabled() == {sendpolicy.DESTRUCTIVE}


@pytest.mark.parametrize("module", ["fuzzlab.tools.spider", "fuzzlab.tools.fetcher",
                                    "fuzzlab.harness.auto_cli", "fuzzlab.greybox.greybox_cli"])
def test_each_traffic_command_has_the_three_flags(module):
    import importlib
    parser = importlib.import_module(module).build_parser()
    dests = {a.dest for a in parser._actions}
    assert {"allow_destructive_routes", "allow_transactions",
            "allow_credential_changes"} <= dests


def test_a_command_sets_the_policy_from_its_own_flags_only(monkeypatch):
    p = argparse.ArgumentParser()
    sendpolicy.add_arguments(p)
    assert sendpolicy.apply(p.parse_args(["--allow-transactions"])) == (sendpolicy.TRANSACTIONS,)
    assert sendpolicy.disabled() == {sendpolicy.TRANSACTIONS}
    # an inherited value is replaced, never kept
    monkeypatch.setenv(sendpolicy.ENV, "destructive,credential-changes")
    assert sendpolicy.apply(p.parse_args([])) == ()
    assert sendpolicy.disabled() == frozenset()


def test_the_top_level_entry_clears_a_stray_setting(monkeypatch, capsys):
    from fuzzlab import cli
    monkeypatch.setenv(sendpolicy.ENV, "destructive")
    assert cli.main(["version"]) == 0
    assert sendpolicy.ENV not in __import__("os").environ


# ------------------------------------------------------------- destructive (D71)


def test_destructive_rule_on_and_off_at_its_refusal_sites():
    url = BASE + "/rest/user/logout"
    form = {"controls": [("q", "text")], "button": "Delete all", "button_aria": "",
            "action": None}
    record = form_record(BeautifulSoup(
        "<form method=post action='/account/delete'><input name=email></form>", "html.parser"
    ).find("form"), BASE + "/")

    def verdicts():
        try:
            check_send_url(url)
            sent = True
        except DestructiveUrlRefused:
            sent = False
        return {
            "probe gate": sent,
            "route": spa.classify_route("/logout")[0] == spa.ROUTE_OK,
            "form": spa.form_refusal(form, "a", named=None) is None,
            "label": spa.label_refusal("Delete account") is None,
            "window": spa.window_request_refusal("GET", url, False) is None,
            "crawl point": auto._crawl_url_refusal(url) is None,
            "import request": store_adapter.request_refusal("POST", url) is None,
            "import form": store_adapter.form_skip_reason(record) is None,
            "option": formnav.option_refusal("reset", "Reset") is None,
        }

    assert not any(verdicts().values()), verdicts()
    off(sendpolicy.DESTRUCTIVE)
    assert all(verdicts().values()), verdicts()


def test_a_delete_method_stays_refused_with_the_destructive_rule_off():
    off(sendpolicy.DESTRUCTIVE)
    check_send_url(BASE + "/api/Feedbacks/1", method="POST")
    with pytest.raises(DestructiveUrlRefused):
        check_send_url(BASE + "/api/Feedbacks/1", method="DELETE")


# ----------------------------------------------------------------- transactions


def test_transaction_rule_on_and_off_at_its_refusal_sites():
    form = {"controls": [("q", "text")], "button": "Buy now", "button_aria": "",
            "action": None}

    def verdicts():
        return {
            "form": spa.form_refusal(form, "basket", named=None) is None,
            "label": spa.label_refusal("Checkout") is None,
            "window": spa.window_request_refusal("GET", BASE + "/rest/wallet/balance",
                                                 False) is None,
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
    leaves = [("password", ["password"], None, "a"), ("passwordRepeat", ["passwordRepeat"],
                                                       None, "a")]

    def verdicts():
        return {
            "spa form": spa.form_refusal(form, "change-password", named=None) is None,
            "import form": store_adapter.form_skip_reason(record) is None,
            "import body": store_adapter.body_refusal(BASE + "/api/Users", leaves) is None
            or "credential entry" in store_adapter.body_refusal(BASE + "/api/Users", leaves),
            "window": spa.window_request_refusal("GET", BASE + "/rest/user/change-password",
                                                 False) is None,
        }

    assert not any(verdicts().values()), verdicts()
    off(sendpolicy.CREDENTIAL_CHANGES)
    assert all(verdicts().values()), verdicts()


# --------------------------------------------------------------------- isolation


def test_turning_one_rule_off_leaves_the_others_on():
    off(sendpolicy.TRANSACTIONS)
    assert spa.classify_route("/logout")[0] == spa.ROUTE_DESTRUCTIVE
    form = {"controls": CHANGE_PASSWORD, "button": "Change", "button_aria": "",
            "action": None}
    assert spa.form_refusal(form, "change-password", named=None)
    off(sendpolicy.DESTRUCTIVE, sendpolicy.CREDENTIAL_CHANGES)
    assert spa.label_refusal("Checkout")


def test_the_login_flow_keeps_every_rule_whatever_the_flags():
    """The rules also tell a login form from a password-change form and keep a login
    off logout pages; the flags never change how a login is found."""
    off(*sendpolicy.RULES)
    change = {"controls": [("email", "text"), ("password", "password")],
              "button": "Log out", "button_aria": "", "action": None}
    assert browserlogin.login_form_refusal(change, "login")
    assert spa.form_refusal(change, "login", named=None) is None       # a crawl: off
    assert spa.form_refusal(change, "login", named=None, strict=True)  # login: kept
    src = inspect.getsource(browserlogin)
    assert "strict=True)              # D71" in src                      # the login window
    assert "form_refusal(form, route, named=None, strict=True)" in src


def test_no_captcha_rule_is_left():
    assert not hasattr(spa, "captcha_reason") and not hasattr(spa, "CAPTCHA_TOKENS")
    form = {"controls": [("captchaControl", "text"), ("comment", "textarea")],
            "button": "Submit", "button_aria": "", "action": None, "challenge": True,
            "hints": ["g-recaptcha"]}
    assert spa.form_refusal(form, "contact", named=None) is None
