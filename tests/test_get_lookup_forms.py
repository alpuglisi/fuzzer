"""A login-shaped GET lookup form is not a credential change because of a word on its
button (FR-AUD-692, CC-AUD-0692; SP-19's rule unchanged).

A GET form is a safe request (RFC 9110 §9.2.1); a login-shaped one (one password
control, one user field) is probed on an isolated session with the password sent empty
(FR-FUZZ-44). A lookup form labelled ``View Account Details`` was refused as account
management for its button's word, so its fields were never points (measured on
Mutillidae, CC-LAB-0411). Its structure and action path still refuse it: two password
controls, a change word in a password name, an account word in the action path. A POST
form, and every captured request, keeps the whole rule. Invented forms."""

from __future__ import annotations

from fuzzlab.tools.store_adapter import form_skip_reason


def _form(method="GET", action="http://h/app?view=profile", controls=None, entries=None):
    controls = controls or [("username", "text"), ("password", "password"),
                            ("lookup-btn", "submit")]
    entries = entries or [("username", ""), ("password", ""),
                          ("lookup-btn", "View Account Details")]
    return {"action_url": action, "method": method, "enctype": "", "selector": False,
            "options": [], "controls": controls, "entries": entries}


def test_a_get_lookup_form_with_an_account_word_on_its_button_is_imported():
    assert form_skip_reason(_form()) is None


def test_the_same_form_by_post_keeps_the_whole_rule():
    assert "credential-change" in form_skip_reason(_form(method="POST"))


def test_a_get_form_with_a_credential_change_structure_is_still_refused():
    two = _form(controls=[("username", "text"), ("password", "password"),
                          ("password2", "password"), ("b", "submit")],
                entries=[("username", ""), ("password", ""), ("password2", ""),
                         ("b", "Go")])
    assert "credential-change" in form_skip_reason(two)
    new = _form(controls=[("username", "text"), ("new_password", "password"),
                          ("b", "submit")],
                entries=[("username", ""), ("new_password", ""), ("b", "Go")])
    assert "credential-change" in form_skip_reason(new)
    assert "credential-change" in form_skip_reason(_form(action="http://h/account/edit"))


def test_a_get_form_that_is_not_login_shaped_keeps_the_whole_rule():
    extra = _form(controls=[("username", "text"), ("email", "text"),
                            ("password", "password"), ("b", "submit")],
                  entries=[("username", ""), ("email", ""), ("password", ""),
                           ("b", "Update account")])
    assert form_skip_reason(extra) is not None
