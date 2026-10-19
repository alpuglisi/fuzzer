"""Forms phase 3, request capture and SPA form submission (FR-CRAWL-13, CC-CRAWL-0017,
CC-CORE-0047).

* **Passive capture (default on):** the page's own fetch/XHR requests with a JSON or
  form-encoded body go to the spider table ``discovered_requests``, redacted only by
  `core.redaction` (``redact_captured_body``, ``redact_url_identifiers``): sensitive
  names and identifier-like values blanked (a string to ``""``, a number to ``null``),
  64 KiB / depth 8, fail closed. Request headers and cookies are never recorded;
  socket.io / engine.io requests are excluded.
* **``--submit-spa-forms [ROUTE ...]`` (default off):** fill with our fillers and click
  once per form signature, at most `spa.MAX_SUBMISSIONS` per crawl. Never a destructive,
  settings, transaction, credential-change, 2FA-only or file-upload form; never an
  unnamed route when routes are named. A password form only in a fresh unauthenticated
  context; in an authenticated crawl a bare flag submits only there, and the crawl's own
  context only on a named route, re-checking the session after each submission and
  stopping on loss.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.core.redaction import (CAPTURE_MAX_BYTES, CAPTURE_MAX_DEPTH,
                                    redact_captured_body, redact_url_identifiers)
from fuzzlab.core.urls import TRANSACTION_TOKENS
from fuzzlab.tools import spa
from tests._spa_fixture import (IDENT, SECRETS, HashSpa, Recorder, chromium_or_skip,
                                db_rows, db_text, run_crawl)

JSON = "application/json"
FORM = "application/x-www-form-urlencoded"


# =====================================================================================
# The redaction boundary for captured bodies (core.redaction, CC-CORE-0047)
# =====================================================================================
def _doc(body, ct=JSON):
    doc, why = redact_captured_body(body if isinstance(body, bytes) else
                                    json.dumps(body).encode(), ct)
    assert why is None, why
    return doc


def test_a_json_body_keeps_benign_values_and_types():
    body = {"email": "user@example.invalid", "rating": 5, "ok": True, "note": None,
            "tags": ["a", "b"], "address": {"city": "Ghent"}}
    assert _doc(body) == body                                 # nothing over-redacts


@pytest.mark.parametrize("name", ["password", "passwords", "newPassword", "api_key",
                                  "authToken", "tokens", "Authorization", "session_id",
                                  "csrf", "pin", "totp_secret"])
@pytest.mark.parametrize("value,blank", [
    ("SECRETVALUE", ""), (123456, None), (12.5, None), (True, None),
    (["SECRETVALUE"], []), ({"inner": "SECRETVALUE"}, {}),
    ([{"x": "SECRETVALUE"}], []), ({"a": {"b": ["SECRETVALUE"]}}, {}),
])
def test_a_sensitive_name_blanks_its_whole_value_keeping_the_type(name, value, blank):
    """PA-0091: each name form x each value shape; a blanked string is "", a number
    null (A8), a container empty (its whole subtree goes)."""
    doc = _doc({name: value, "keep": "visible"})
    assert doc == {name: blank, "keep": "visible"}
    assert "SECRETVALUE" not in json.dumps(doc)


def test_nested_sensitive_names_and_identifier_values_are_blanked():
    body = {"user": {"email": "a@b.invalid", "password": "SECRETVALUE"},
            "items": [{"id": IDENT, "qty": 2}], "ref": IDENT, "page": "products"}
    assert _doc(body) == {"user": {"email": "a@b.invalid", "password": ""},
                          "items": [{"id": "", "qty": 2}], "ref": "", "page": "products"}


def test_identifier_like_numbers_are_blanked_ordinary_numbers_kept():
    """Lane S review (B must-fix 1): a card number sent as a JSON number was stored
    while its form-encoded twin was blanked."""
    body = {"cardNum": 4716190207394368, "orderRef": 1234567890123456789,
            "expMonth": 12, "expYear": 2031, "quantity": 3, "price": 12.5, "ok": True,
            "nested": [{"pan": 5555555555554444}]}
    assert _doc(body) == {"cardNum": None, "orderRef": None, "expMonth": 12,
                          "expYear": 2031, "quantity": 3, "price": 12.5, "ok": True,
                          "nested": [{"pan": None}]}


def test_identifier_like_keys_are_replaced_and_their_values_blanked():
    from fuzzlab.core.redaction import REDACTED_KEY
    k0, k1 = REDACTED_KEY.format(n=0), REDACTED_KEY.format(n=1)
    body = {IDENT: {"qty": 1, "note": "SECRETVALUE"}, "items": {"4716190207394368": 2},
            "ok": 1}
    doc = _doc(body)
    assert doc == {k0: {}, "items": {k1: None}, "ok": 1}
    assert IDENT not in json.dumps(doc) and "4716190207394368" not in json.dumps(doc)
    form = f"{IDENT}=a&x=1&{IDENT}=b".encode()                  # one name, one placeholder
    assert _doc(form, FORM) == {k0: "", "x": "1"}


def test_json_and_form_bodies_with_the_same_values_are_redacted_alike():
    """The boundary never depends on how a body was encoded (lane S review)."""
    fields = [("cardNum", "4716190207394368"), ("ref", IDENT), (IDENT, "x"),
              ("qty", "3"), ("email", "a@b.invalid"), ("securityAnswer", "Rex"),
              ("api_key", "SECRETVALUE"), ("expMonth", "12")]
    as_json = _doc({k: (int(v) if v.isdigit() else v) for k, v in fields})
    as_form = _doc("&".join(f"{k}={v}" for k, v in fields).encode(), FORM)
    assert list(as_json) == list(as_form)
    for key in as_json:
        blanked_json = as_json[key] in (None, "")
        assert blanked_json == (as_form[key] == ""), key
        if not blanked_json:
            assert str(as_json[key]) == as_form[key], key
    assert {k for k in as_json if as_json[k] in (None, "")} == \
        {"cardNum", "ref", "__REDACTED_KEY_0__", "securityAnswer", "api_key"}


@pytest.mark.parametrize("name,sensitive", [
    ("securityAnswer", True), ("security_answer", True), ("SecurityAnswers", True),
    ("secret_answer", True), ("recoveryAnswer", True), ("recovery-answers", True),
    ("answer", False), ("answers", False), ("quizAnswer", False), ("answer_security", False),
    ("securityQuestion", False),
])
def test_account_recovery_answers_are_secrets_and_a_bare_answer_is_not(name, sensitive):
    from fuzzlab.core.redaction import is_sensitive_name
    assert is_sensitive_name(name) is sensitive


def test_a_security_answer_is_blanked_in_json_and_form_bodies():
    assert _doc({"securityAnswer": "Rex", "answer": "42"}) == \
        {"securityAnswer": "", "answer": "42"}
    assert _doc(b"security_answer=Rex&answer=42", FORM) == \
        {"security_answer": "", "answer": "42"}


def test_crawl_stats_are_stored_replaced_and_cleared(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    db = str(tmp_path / "s.db")
    sm = StorageManager(db)
    try:
        sm.record_stats({"routes_found": 3, "deletes_blocked": 1})
        sm.record_stats({"routes_found": 5})
        assert dict(db_rows(db, "SELECT name, value FROM crawl_stats")) == \
            {"routes_found": 5, "deletes_blocked": 1}
        sm.reset()
        assert db_rows(db, "SELECT * FROM crawl_stats") == []
    finally:
        sm.close()


def test_a_form_body_is_an_object_last_value_wins_with_secrets_blanked():
    b64 = "dGhpc2lzYXNlY3JldHRva2VuMTIz+/AB"            # base64: judged on its raw form
    body = f"name=bob&api_key=SECRETVALUE&ref={IDENT}&blob={b64}&name=alice&q=a+b".encode()
    assert _doc(body, FORM) == {"name": "alice", "api_key": "", "ref": "", "blob": "",
                                "q": "a b"}


@pytest.mark.parametrize("body,ct,why", [
    (b"", JSON, "empty body"),
    (b'{"a":"' + b"x" * CAPTURE_MAX_BYTES + b'"}', JSON, "body too large"),
    (b"[" * (CAPTURE_MAX_DEPTH + 1) + b"]" * (CAPTURE_MAX_DEPTH + 1), JSON,
     "body nested too deep"),
    (b'{"password":"SECRETVALUE",}', JSON, "body the storage boundary omits"),
    (b'{"a": NaN}', JSON, "unparseable JSON"),
    (b'{"n": ' + b"9" * 5000 + b"}", JSON, "unparseable JSON"),
    (b'"just a string"', JSON, "a JSON body that is not an object or array"),
    (b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--",
     "multipart/form-data; boundary=b", "not a JSON or form-encoded body"),
    (b"\x00\x01binary", "application/octet-stream", "not a JSON or form-encoded body"),
])
def test_what_is_not_recorded(body, ct, why):
    assert redact_captured_body(body, ct) == (None, why)


def test_the_depth_bound_is_inclusive_and_mislabelled_json_is_sniffed():
    ok = b"[" * CAPTURE_MAX_DEPTH + b"]" * CAPTURE_MAX_DEPTH
    assert redact_captured_body(ok, JSON)[1] is None
    assert redact_captured_body(b'{"password":"SECRETVALUE"}', "text/plain") == \
        ({"password": ""}, None)


def test_the_capture_redactor_is_total():
    for body in (b"\xff\xfe", b"{" * 100000, "x" * 10):
        doc, why = redact_captured_body(body, JSON)              # never raises
        assert doc is None and why


def test_url_identifiers_are_blanked_and_sensitive_names_replaced():
    assert redact_url_identifiers(f"http://h/a?ref={IDENT}&lang=en&token=abc") == \
        "http://h/a?ref=&lang=en&token=__REDACTED__"
    assert redact_url_identifiers("http://h/a?page=2&q=apple") == "http://h/a?page=2&q=apple"
    assert redact_url_identifiers("http://h/#/a") == "http://h/#/a"


def test_a_spa_fragments_query_passes_the_boundary_too(tmp_path):
    """Found while building this: SPA fragments are now kept as pages, and
    `redact_url` never looks at a fragment, so ``#/cb?access_token=...`` would have been
    stored verbatim."""
    from fuzzlab.core.redaction import redact_spa_fragment
    from fuzzlab.tools.spider import LocalSpider
    url = f"http://h/x?a=1#/cb?access_token=SECRETVALUE&ref={IDENT}&q=apple"
    assert redact_spa_fragment(url) == \
        "http://h/x?a=1#/cb?access_token=__REDACTED__&ref=&q=apple"
    assert redact_url_identifiers(f"http://h/?ref={IDENT}#!/a?token=SECRETVALUE") == \
        "http://h/?ref=#!/a?token=__REDACTED__"
    assert redact_spa_fragment("http://h/#top?token=x") == "http://h/#top?token=x"
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        sp._spa_on = True
        assert sp._crawl_url("http://127.0.0.1:8080/#/cb?token=SECRETVALUE") == \
            "http://127.0.0.1:8080/#/cb?token=__REDACTED__"
    finally:
        sp.storage.close()


# =====================================================================================
# The spider table: contract, write site, dedupe
# =====================================================================================
def test_the_discovered_requests_table_is_exactly_the_contract(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.close()
    cols = [r[1] for r in db_rows(str(tmp_path / "s.db"),
                                  "PRAGMA table_info(discovered_requests)")]
    # FR-CRAWL-29 (CC-CRAWL-0047): `seen_at`, when the request was captured
    assert cols == ["id", "page_url", "method", "url", "content_type", "body_json",
                    "source", "signature", "seen_at"]
    (sql,) = db_rows(str(tmp_path / "s.db"), "SELECT sql FROM sqlite_master WHERE "
                     "name='discovered_requests'")[0]
    assert "signature TEXT UNIQUE" in sql


def test_record_request_redacts_at_the_write_site_and_dedupes_by_signature(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    db = str(tmp_path / "s.db")
    sm = StorageManager(db)
    try:
        assert sm.record_request(f"http://h/#/a?sid={IDENT}", "post",
                                 f"http://localhost/api/x?ref={IDENT}",
                                 "application/json; charset=utf-8",
                                 b'{"password":"SECRETVALUE","b":1}', "passive") is None
        # same method, canonical path and keys: one row (an alias host included)
        assert sm.record_request("http://h/", "POST", "http://127.0.0.1/api/x",
                                 JSON, b'{"b":2,"password":"x"}', "submit") == "duplicate"
        assert sm.record_request("http://h/", "POST", "http://h/api/x", JSON,
                                 b'{"c":1}', "submit") is None
        sm.reset()
        assert db_rows(db, "SELECT * FROM discovered_requests") == []
        sm.record_request("http://h/", "PUT", "http://h/api/y", JSON, b'[1,2]', "passive")
    finally:
        sm.close()
    rows = db_rows(db, "SELECT page_url, method, url, content_type, body_json, source, "
                       "signature FROM discovered_requests")
    assert rows == [("http://h/", "PUT", "http://h/api/y", JSON, "[1, 2]", "passive",
                     '["PUT", "http://h:80/api/y", []]')]


def test_record_request_stores_no_secret_and_no_identifier(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    db = str(tmp_path / "s.db")
    sm = StorageManager(db)
    try:
        sm.record_request(f"http://h/#/a?token=SECRETVALUE&ref={IDENT}", "POST",
                          f"http://h/api/x?api_key=SECRETVALUE&ref={IDENT}", JSON,
                          json.dumps({"password": "SECRETVALUE", "ref": IDENT}).encode(),
                          "passive")
    finally:
        sm.close()
    text = db_text(db)
    assert "SECRETVALUE" not in text and IDENT not in text


class _Req:
    def __init__(self, url, method="POST", rtype="fetch", body=None, headers=None):
        self.url, self.method, self.resource_type = url, method, rtype
        self.post_data_buffer = body
        self.headers = headers or {}


def test_passive_capture_takes_only_bodied_non_transport_requests(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    db = str(tmp_path / "s.db")
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=db, engine="requests")
    try:
        sp._current_url = "http://127.0.0.1:8080/#/contact"
        hdr = {"content-type": JSON, "authorization": "Bearer SECRETBEARER",
               "cookie": "token=SECRETCOOKIE"}
        body = b'{"comment":"hi"}'
        sp._observe(_Req("http://127.0.0.1:8080/api/f", body=body, headers=hdr), None,
                    scripts=True)
        sp._observe(_Req("http://127.0.0.1:8080/api/g", method="GET", body=body,
                         headers=hdr), None, scripts=True)          # a GET: queued instead
        sp._observe(_Req("http://127.0.0.1:8080/api/h", rtype="document", body=body,
                         headers=hdr), None, scripts=True)          # not fetch/XHR
        sp._observe(_Req("http://127.0.0.1:8080/socket.io/?EIO=4&transport=polling",
                         body=b'{"token":"SOCKSECRET"}', headers=hdr), None, scripts=True)
        sp._observe(_Req("http://127.0.0.1:8080/api/i", body=None, headers=hdr), None,
                    scripts=True)                                   # no body
    finally:
        sp.storage.close()
    rows = db_rows(db, "SELECT page_url, url, body_json, source FROM discovered_requests")
    assert rows == [("http://127.0.0.1:8080/#/contact", "http://127.0.0.1:8080/api/f",
                     '{"comment": "hi"}', "passive")]
    assert sp.spa_counts["transport_urls_skipped"] == 1
    text = db_text(db)
    assert not any(s in text for s in ("SECRETBEARER", "SECRETCOOKIE", "SOCKSECRET"))


# =====================================================================================
# The submission gate (spa.form_refusal)
# =====================================================================================
def _form(controls, button="Submit", action=None, autocomplete=None):
    return {"controls": [list(c) for c in controls], "button": button, "action": action,
            "autocomplete": autocomplete or [""] * len(controls)}


LOGIN = _form([("email", "text"), ("password", "password")], "Log in")
CONTACT = _form([("comment", "textarea"), ("rating", "number")], "Submit")


def test_ordinary_forms_pass_the_gate():
    assert spa.form_refusal(LOGIN, "login", named=None) is None
    assert spa.form_refusal(CONTACT, "contact", named=None) is None
    assert spa.form_refusal(CONTACT, "contact", named=frozenset({"contact"})) is None


def test_a_route_not_named_is_refused_when_routes_are_named():
    assert "not named" in spa.form_refusal(CONTACT, "contact", named=frozenset({"login"}))
    # whole-route comparison, never a substring (PA-0122)
    assert spa.form_refusal(CONTACT, "contact-us", named=frozenset({"contact"}))


@pytest.mark.parametrize("word", sorted(TRANSACTION_TOKENS))
def test_each_transaction_word_is_refused_on_the_route_and_on_the_label(word):
    """Reviewer B must-fix 2: one shared list (`core.urls.transaction_reason`)."""
    assert "transaction route" in spa.form_refusal(CONTACT, f"shop/{word}", named=None)
    assert "transaction button" in spa.form_refusal(_form(CONTACT["controls"],
                                                          f"{word.title()} now"),
                                                    "shop", named=None)


@pytest.mark.parametrize("label", ["Top-up", "Check out", "Place order", "Pay"])
def test_transaction_pairs_and_phrases_are_refused(label):
    assert spa.form_refusal(_form(CONTACT["controls"], label), "shop", named=None)


@pytest.mark.parametrize("form,route,expect", [
    (CONTACT, "delete-account", "destructive route"),
    (_form(CONTACT["controls"], "Delete"), "contact", "destructive button"),
    (_form(CONTACT["controls"], "Log out"), "contact", "destructive button"),
    (CONTACT, "settings/language", "settings-like route"),
    (_form(CONTACT["controls"], "Change theme"), "contact", "settings-like button"),
    (_form([("theme", "select"), ("q", "text")]), "contact", "settings control"),
    (_form([("drop_table", "text")]), "contact", "destructive control"),
    (_form(CONTACT["controls"], action="http://h/api/logout"), "contact",
     "destructive or transaction action"),
    (_form(CONTACT["controls"], action="http://h/#/wallet"), "contact",
     "destructive or transaction action"),
    (_form([("f", "file"), ("title", "text")], "Upload"), "upload", "file input"),
    (_form([("email", "email"), ("password", "password"), ("passwordRepeat", "password")],
           "Register"), "register", "credential-change"),
    (_form([("current", "password"), ("next", "text")], "Go"), "x", "credential-change"),
    (_form([("username", "text"), ("password", "password")], "Log in"), "register",
     "credential-change"),
    (_form([("totp", "text")], "Verify"), "2fa", "one-time-code"),
    (_form([("x", "text")], "Verify", autocomplete=["one-time-code"]), "verify",
     "one-time-code"),
    (_form([("initialToken", "text")], "Go"), "verify-device", "one-time-code"),
])
def test_each_refusal(form, route, expect):
    assert expect in (spa.form_refusal(form, route, named=None) or "")


@pytest.mark.parametrize("label,aria,refused", [
    ("Log in", "Login", None),                      # Juice Shop's login, icon text removed
    ("", "Log out", "destructive button aria-label"),
    ("Remove", "", "destructive button"),
    ("Save", "Delete account", "destructive button aria-label"),
    ("Go", "Change theme", "settings-like button aria-label"),
    ("Go", "Pay now", "transaction button aria-label"),
    ("Search", "", None),
])
def test_the_button_is_refused_on_its_text_or_its_aria_label(label, aria, refused):
    """Live Juice Shop run: the gate judges the cleaned text and the aria-label / title;
    either one refuses."""
    form = _form(CONTACT["controls"], label)
    form["button_aria"] = aria
    why = spa.form_refusal(form, "contact", named=None)
    assert (why is None) if refused is None else (refused in (why or "")), why


@pytest.mark.parametrize("icons,refused", [
    ("exit_to_app", False),                 # Juice Shop's login icon: not a verdict
    ("delete", True), ("delete_forever", True), ("logout", True),
    ("person search", False), ("", False),
])
def test_a_destructive_glyph_refuses_the_button_whatever_its_text(icons, refused):
    """Reviewer B: icon ligatures are removed from the text, so a destructive glyph is
    judged on its own (``<button><mat-icon>delete</mat-icon> Item 3</button>``)."""
    form = _form(CONTACT["controls"], "Item 3")
    form["button_icons"] = icons
    why = spa.form_refusal(form, "contact", named=None) or ""
    assert ("destructive button icon" in why) is refused, why


def test_fillers_are_ours_and_a_password_never_a_real_one():
    from fuzzlab.tools.store_adapter import _FILLERS, _TEXT_FILLER, is_filler
    assert spa.filler("text") == _TEXT_FILLER and spa.filler("email") == _FILLERS["email"]
    assert spa.filler("number") == "1" and is_filler(spa.filler("textarea"))
    assert spa.filler("password") == spa.PASSWORD_FILLER
    assert not spa.fillable("hidden") and not spa.fillable("file")
    assert not spa.fillable("checkbox") and spa.fillable("password")


def test_the_session_check_fails_closed(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:8080/", db_name=str(tmp_path / "s.db"),
                     engine="requests")

    class Ctx:
        jar = [{"name": "token", "value": "T"}]

        def cookies(self):
            return self.jar

    class Manager:
        live = True

        def verify_live(self, host, identity, base):
            if self.live is None:
                raise RuntimeError("cannot reach")
            return self.live
    try:
        sp._context, sp._session_manager, sp._identity = Ctx(), Manager(), "alice"
        sp._injected_cookies = [("token", "T")]
        assert sp._session_intact() == (True, None)
        Ctx.jar = [{"name": "token", "value": ""}]
        assert sp._session_intact()[0] is False
        Ctx.jar = [{"name": "token", "value": "T"}]
        sp._session_manager.live = False
        assert sp._session_intact()[0] is False
        sp._session_manager.live = None
        assert sp._session_intact()[0] is False
    finally:
        sp.storage.close()


def test_route_names_are_parsed_from_the_cli():
    from fuzzlab.tools.spider import build_parser, spa_route_names
    p = build_parser()
    assert spa_route_names(p.parse_args([]).submit_spa_forms) is None          # off
    assert spa_route_names(p.parse_args(["--submit-spa-forms"]).submit_spa_forms) == []
    args = p.parse_args(["--submit-spa-forms", "login", "search,contact"])
    assert spa_route_names(args.submit_spa_forms) == ["login", "search", "contact"]
    assert spa_route_names(["login search"]) == ["login", "search"]             # web form
    assert p.parse_args(["--no-spa-routes"]).no_spa_routes is True
    assert p.parse_args([]).no_dry_submit is False                       # FR-CRAWL-26
    assert p.parse_args(["--no-dry-submit"]).no_dry_submit is True


# =====================================================================================
# Real browser
# =====================================================================================
@pytest.fixture
def lab(monkeypatch):
    chromium_or_skip(monkeypatch)
    other = Recorder()
    spa_lab = HashSpa(other_port=other.server.server_address[1])
    try:
        yield spa_lab, other
    finally:
        spa_lab.close()
        other.close()


TOKEN = "tok-SECRETCOOKIE-7"
BEARER = "Bearer SECRETHEADER"


class _State:
    cookies = {"token": TOKEN}
    headers = {"Authorization": BEARER}


class _Manager:
    """A session manager that hands out a cookie and a bearer header."""

    def __init__(self):
        self.verified = 0

    def ensure(self, host, identity, base_url, operator=False):
        return _State()

    def verify_live(self, host, identity, base_url):
        self.verified += 1
        return True


def _crawl(spa_lab, tmp_path, **kw):
    from fuzzlab.tools.spider import LocalSpider
    db = str(tmp_path / "s.db")
    sp = LocalSpider(spa_lab.base, max_depth=2, db_name=db, engine="playwright",
                     timeout_ms=10000, **kw)
    run_crawl(sp)
    return sp, db


def _requests(db):
    return {(m, u.split("/", 3)[-1]): (json.loads(b), s) for m, u, b, s in db_rows(
        db, "SELECT method, url, body_json, source FROM discovered_requests")}


def test_passive_capture_is_on_by_default_and_redacted(lab, tmp_path):
    spa_lab, _other = lab
    sp, db = _crawl(spa_lab, tmp_path)
    got = _requests(db)
    assert got[("POST", "rest/track")] == ({
        "event": "view", "email": "user@example.invalid", "password": "",
        "authToken": {}, "tokens": [], "ref": "", "count": 3, "pin": None}, "passive")
    assert got[("POST", "api/form")] == ({"name": "alice", "api_key": "", "ref": ""},
                                         "passive")
    assert not any("socket.io" in u for _m, u in got)            # a transport: excluded
    assert not any(u in ("rest/big", "rest/deep") for _m, u in got)   # 64 KiB / depth 8
    assert sp.spa_counts["requests_not_recorded"] == 2
    text = db_text(db)
    assert not [s for s in SECRETS if s in text] and IDENT not in text


def test_submission_is_off_by_default(lab, tmp_path):
    spa_lab, _other = lab
    sp, _db = _crawl(spa_lab, tmp_path)
    assert spa_lab.seen("POST", "/rest/user/login") == []
    assert spa_lab.seen("POST", "/api/Feedbacks") == []
    assert spa_lab.seen("POST", "/api/questions") == []
    assert sp.spa_counts["forms_submitted"] == 0


def test_bare_submission_in_an_anonymous_crawl(lab, tmp_path, monkeypatch):
    from fuzzlab.tools.spider import LocalSpider
    spa_lab, other = lab
    blocked = []
    monkeypatch.setattr(LocalSpider, "_note_out_of_scope",
                        lambda self, url: blocked.append(url))
    sp, db = _crawl(spa_lab, tmp_path, submit_spa_forms=[])
    # both contexts are guarded: the anonymous one's off-origin fetch is refused by the
    # route guard itself (not only by the launch arguments' resolver rules)
    assert any(u.endswith("/leak-anon") for u in blocked)
    assert any(u.endswith("/leak") for u in blocked)
    got = _requests(db)
    assert got[("POST", "api/Feedbacks")] == ({"comment": "fuzzlab", "rating": 1,
                                               "captchaId": "", "UserId": 7}, "submit")
    assert got[("POST", "rest/user/login")] == ({"email": "fuzzlab", "password": ""},
                                                "submit")
    # the password filler went out, and is never stored
    (login,) = spa_lab.seen("POST", "/rest/user/login")
    assert json.loads(login[4])["password"] == spa.PASSWORD_FILLER
    assert spa.PASSWORD_FILLER not in db_text(db)
    # one submission per signature: the footer form is on every route
    assert len(spa_lab.seen("POST", "/api/questions")) == 1
    # refused: transaction route, file input, 2FA-only, registration (credential change)
    assert sp.spa_counts["forms_refused"] == 4
    assert spa_lab.seen("POST", "/checkout") == [] and spa_lab.seen("DELETE") == []
    # the submission's own requests stay in scope (contact's cross-origin fetch)
    assert other.requests == []


def test_a_password_form_is_submitted_only_in_a_fresh_unauthenticated_context(lab,
                                                                             tmp_path):
    """Revision 1 + the fake SPA whose failed login clears the token: the login request
    is sent (and captured) from the anonymous context, so the crawl's session survives;
    token, password and Authorization never reach the spider DB."""
    spa_lab, _other = lab
    manager = _Manager()
    sp, db = _crawl(spa_lab, tmp_path, submit_spa_forms=[], session_manager=manager,
                    identity="alice")
    (login,) = spa_lab.seen("POST", "/rest/user/login")
    assert TOKEN not in login[2] and login[3] == ""          # no cookie, no bearer
    assert ("POST", "rest/user/login") in _requests(db)
    # the crawl's own requests (they carry the bearer) still carry the token afterwards
    at = next(i for i, r in enumerate(spa_lab.requests) if r is login)
    after = [r for r in spa_lab.requests[at + 1:] if r[3] == BEARER]
    assert after and all(f"token={TOKEN}" in r[2] for r in after)
    assert sp.spa_submit_stopped is None
    text = db_text(db)
    for secret in (TOKEN, "SECRETHEADER", BEARER, spa.PASSWORD_FILLER, *SECRETS):
        assert secret not in text, secret


def test_a_named_login_route_is_still_submitted_only_unauthenticated(lab, tmp_path):
    """Naming a route lifts the authenticated-context rule for ordinary forms, never for
    a password form: the login (whose failure clears the token) still goes out from a
    fresh context, the crawl's session survives, and the named contact form after it is
    submitted authenticated (the mutation check found this case untested)."""
    spa_lab, _other = lab
    sp, _db = _crawl(spa_lab, tmp_path, submit_spa_forms=["login", "contact"],
                     session_manager=_Manager(), identity="alice")
    (login,) = spa_lab.seen("POST", "/rest/user/login")
    assert login[3] == "" and TOKEN not in login[2]
    (post,) = spa_lab.seen("POST", "/api/Feedbacks")
    assert post[3] == BEARER and f"token={TOKEN}" in post[2]
    assert sp.spa_submit_stopped is None
    # the crawl context's background DELETEs (the login view polls) are refused even
    # while the anonymous context is clicking the named login route (lane S review)
    assert spa_lab.seen("DELETE", "/api/poll") == []
    assert sp.spa_counts["deletes_blocked"] >= 1


def test_an_authenticated_bare_flag_never_submits_in_the_crawls_context(lab, tmp_path):
    """Revision 4 (B must-fix 1): profile / contact forms change the operator's account
    without a password control; a bare flag submits them only unauthenticated."""
    spa_lab, _other = lab
    sp, _db = _crawl(spa_lab, tmp_path, submit_spa_forms=[],
                     session_manager=_Manager(), identity="alice")
    submitted = (spa_lab.seen("PATCH", "/api/profile") + spa_lab.seen("POST", "/api/Feedbacks")
                 + spa_lab.seen("POST", "/api/questions"))
    assert submitted and all(r[3] == "" and TOKEN not in r[2] for r in submitted)
    assert sp.spa_submit_stopped is None


def test_a_named_route_is_submitted_authenticated_and_session_loss_stops_it(lab,
                                                                           tmp_path):
    """The profile form clears the session cookie: the check after the submission sees
    it, stops submitting (contact, also named, is never submitted) and reports it."""
    spa_lab, _other = lab
    manager = _Manager()
    sp, _db = _crawl(spa_lab, tmp_path, submit_spa_forms=["profile", "contact"],
                     session_manager=manager, identity="alice")
    (patch,) = spa_lab.seen("PATCH", "/api/profile")
    assert patch[3] == BEARER                                   # the crawl's context
    assert spa_lab.seen("POST", "/api/Feedbacks") == []
    assert sp.spa_submit_stopped and "token" in sp.spa_submit_stopped
    assert any("stopped" in ln for ln in sp.spa_summary())


def test_a_named_route_keeps_submitting_while_the_session_holds(lab, tmp_path):
    spa_lab, _other = lab
    manager = _Manager()
    sp, _db = _crawl(spa_lab, tmp_path, submit_spa_forms=["contact"],
                     session_manager=manager, identity="alice")
    (post,) = spa_lab.seen("POST", "/api/Feedbacks")
    assert post[3] == BEARER and f"token={TOKEN}" in post[2]
    assert manager.verified >= 1 and sp.spa_submit_stopped is None
    assert spa_lab.seen("POST", "/rest/user/login") == []      # login: not named
    assert spa_lab.seen("PATCH", "/api/profile") == []


def test_icon_text_never_decides_a_button_label(monkeypatch, tmp_path):
    """Live Juice Shop run (4476e93): ``<button aria-label="Login"><mat-icon>exit_to_app
    </mat-icon> Log in</button>`` was refused as ``destructive button ('exit')``. Icon
    elements' text is removed, the aria-label is judged too, and an icon-only button
    with no aria-label keeps its raw text (fail closed)."""
    from tests._spa_fixture import IconSpa
    chromium_or_skip(monkeypatch)
    icons = IconSpa()
    try:
        sp, _db = _crawl(icons, tmp_path, submit_spa_forms=[])
    finally:
        icons.close()
    clicked = {r[1] for r in icons.seen("POST", "/api/clicked/")}
    assert clicked == {"/api/clicked/signin", "/api/clicked/find"}
    # account, leave, basket, icononly; hidden, hidden2 (aria-hidden text is judged),
    # rowdel (a destructive glyph) -- reviewer B
    assert sp.spa_counts["forms_refused"] == 7
    # visible to layout but never actionable and not covered: never dispatched
    assert sp.spa_counts["forms_not_submittable"] >= 1
    assert sp.spa_counts["clicks_dispatched"] == 0
    # the submission signature uses the cleaned label too
    labels = {json.loads(s)[1] for s in sp._submitted_sigs}
    assert {"Log in", "Search", "Remove", "delete", "Delete", "Delete item",
            "Item 3"} <= labels
    assert not any("exit_to_app" in lab for lab in labels)


def test_a_covered_button_is_still_clicked_exactly_once(monkeypatch, tmp_path):
    """Live Juice Shop run (70c2aca): the login click timed out behind the first-visit
    welcome dialog in the fresh unauthenticated context. A covered vetted button gets
    Escape once, then its own click(); the overlay's buttons are never clicked, and a
    destructive button behind an overlay is still refused (the gate runs first)."""
    from tests._spa_fixture import OverlaySpa
    chromium_or_skip(monkeypatch)
    lab = OverlaySpa()
    try:
        sp, db = _crawl(lab, tmp_path, submit_spa_forms=[])
    finally:
        lab.close()
    posts = [r[1] for r in lab.seen("POST")]
    assert posts.count("/api/submit/signin") == 1           # Escape cleared the overlay
    assert posts.count("/api/submit/signin-stuck") == 1     # the dispatch path
    assert "/api/submit/danger" not in posts                 # refused before any click
    assert "/api/overlay-dismissed" not in posts             # never the overlay's button
    assert sp.spa_counts["clicks_dispatched"] == 1
    assert sp.spa_counts["forms_submitted"] == 2 and sp.spa_counts["forms_refused"] == 1
    # the labels are read again right before the click: a re-rendered node is not
    # clicked (reviewer B)
    assert "/api/submit/swap" not in posts
    assert sp.spa_counts["forms_label_changed"] == 1
    stats = dict(db_rows(db, "SELECT name, value FROM crawl_stats"))
    assert stats["clicks_dispatched"] == 1


def test_submissions_are_capped_and_the_cap_is_reported(lab, tmp_path, monkeypatch):
    spa_lab, _other = lab
    monkeypatch.setattr(spa, "MAX_SUBMISSIONS", 2)
    sp, _db = _crawl(spa_lab, tmp_path, submit_spa_forms=[])
    assert sp.spa_counts["forms_submitted"] == 2
    assert sp.spa_counts["submissions_over_cap"] >= 1
    assert any("over the cap" in ln for ln in sp.spa_summary())


# =====================================================================================
# Dry submission (FR-CRAWL-26): clicked inside the write-blocking window, nothing sent
# =====================================================================================
def _dry(db):
    return {k: body for k, (body, src) in _requests(db).items() if src == "dry-submit"}


def test_dry_submission_records_each_forms_write_and_sends_nothing(lab, tmp_path):
    """Measured on Juice Shop (2026-10-19): with submission off, the login form's JSON
    request was never made, so its ``email`` point never existed and its SQL injection
    was never probed. Each eligible form is now filled and clicked inside the window:
    the write is recorded and aborted -- the server never sees it."""
    spa_lab, other = lab
    sp, db = _crawl(spa_lab, tmp_path)
    for method, path in (("POST", "/rest/user/login"), ("POST", "/api/Feedbacks"),
                         ("POST", "/api/questions"), ("PATCH", "/api/profile")):
        assert spa_lab.seen(method, path) == [], path
    dry = _dry(db)
    assert dry[("POST", "rest/user/login")] == {"email": "fuzzlab", "password": ""}
    assert dry[("POST", "api/Feedbacks")] == {"comment": "fuzzlab", "rating": 1,
                                              "captchaId": "", "UserId": 7}
    assert ("PATCH", "api/profile") in dry
    # the counter counts what was stored, never the click (PA-0502)
    assert sp.spa_counts["requests_captured_dry"] == len(dry_rows(db))
    assert sp.spa_counts["forms_dry_submitted"] >= 4
    assert sp.spa_counts["forms_submitted"] == 0
    # the gate runs first: transaction, upload, 2FA and registration forms are refused
    assert sp.spa_counts["forms_refused"] == 4 and ("POST", "checkout") not in dry
    assert spa_lab.seen("DELETE") == [] and other.requests == []
    assert spa.PASSWORD_FILLER not in db_text(db)
    assert any("dry-submitted" in ln for ln in sp.spa_summary())


def dry_rows(db):
    return db_rows(db, "SELECT url FROM discovered_requests WHERE source = 'dry-submit'")


def test_dry_submission_keeps_an_authenticated_crawls_session(lab, tmp_path):
    """The profile form's handler clears the session cookie before its request (an
    app's own code runs even when nothing is sent): the client state is rolled back
    inside the window, so the crawl keeps its session; the login form, whose failure
    clears the token, is dry-submitted only in a fresh unauthenticated context."""
    spa_lab, _other = lab
    sp, db = _crawl(spa_lab, tmp_path, session_manager=_Manager(), identity="alice")
    assert sp.spa_submit_stopped is None
    dry = _dry(db)
    assert ("PATCH", "api/profile") in dry and ("POST", "rest/user/login") in dry
    assert spa_lab.seen("PATCH", "/api/profile") == []
    assert spa_lab.seen("POST", "/rest/user/login") == []
    # the login route was loaded without the session: the fresh context's view
    assert any(r[1] == "/rest/marker/login" and TOKEN not in r[2] and r[3] == ""
               for r in spa_lab.requests)
    authed = [r for r in spa_lab.requests if r[3] == BEARER]
    assert authed and f"token={TOKEN}" in authed[-1][2]       # still there at the end
    text = db_text(db)
    for secret in (TOKEN, "SECRETHEADER", BEARER, spa.PASSWORD_FILLER):
        assert secret not in text, secret


def test_no_dry_submit_records_no_dry_write(lab, tmp_path):
    spa_lab, _other = lab
    sp, db = _crawl(spa_lab, tmp_path, dry_submit=False)
    assert _dry(db) == {} and sp.spa_counts["forms_dry_submitted"] == 0
    assert not any("dry-submitted" in ln for ln in sp.spa_summary())


def test_the_crawl_records_the_path_segments_its_scripts_hold(lab, tmp_path):
    """FR-CRAWL-28 (BUG-0507): the names the app's code holds are the variation rule's
    evidence that a segment is a route; an identifier-like segment is never stored."""
    spa_lab, _other = lab
    sp, db = _crawl(spa_lab, tmp_path)
    segments = {s for (s,) in db_rows(db, "SELECT segment FROM script_segments")}
    assert {"rest", "marker", "user", "login"} <= segments, sorted(segments)
    assert IDENT not in segments
    assert sp.spa_counts["script_segments"] == len(segments)
