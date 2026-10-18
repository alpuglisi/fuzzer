"""Phase 1's pure parts (D70): layout fingerprints, valid-first form values, and the
schema synthesizer (FR-CRAWL-19, FR-CRAWL-20). No browser, no traffic."""

from __future__ import annotations

import json

from fuzzlab.core.redaction import PLACEHOLDER
from fuzzlab.disco import formfill
from fuzzlab.disco.capture import make_record
from fuzzlab.disco.fingerprint import element_signature, normalise_route, state_fingerprint
from fuzzlab.disco.synth import (SLUG_MIN_DISTINCT, endpoints, segment_kind, synthesize,
                                 template_paths)

U1 = "0f8e7d6c-5b4a-4928-8170-6f5e4d3c2b1a"
U2 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
BASE = "http://127.0.0.1:8080"


# --- fingerprints ----------------------------------------------------------------------

def test_a_state_ignores_text_and_ids_digits_but_not_layout():
    a = [{"tag": "button", "type": "submit", "id": "mat-input-3", "label": "Buy now"},
         {"tag": "div", "cls": "nav", "ancestry": "div<div#root", "listeners": ["click"]}]
    b = [{**a[0], "id": "mat-input-7", "label": "Acheter"}, a[1]]
    assert state_fingerprint(f"{BASE}/p?id=1", a) == state_fingerprint(f"{BASE}/p?id=2", b)
    dialog = a + [{"tag": "input", "name": "title", "ancestry": "form<div#root"}]
    assert state_fingerprint(f"{BASE}/p", dialog) != state_fingerprint(f"{BASE}/p", a)
    panel = a + [{**a[1], "ancestry": "div#plist<div#root"}]      # same shape, new place
    assert state_fingerprint(f"{BASE}/p", panel) != state_fingerprint(f"{BASE}/p", a)


def test_state_classes_never_change_a_signature():
    """BUG-0501: frameworks toggle classes as UI state changes; the signature keeps
    only identity classes (BEM modifiers and state-word parts dropped)."""
    from fuzzlab.disco.fingerprint import stable_classes
    pristine = {"tag": "input", "name": "q", "cls": "ng-untouched.ng-pristine.search-input",
                "ancestry": "div.search-container<app-bar#search"}
    touched = {**pristine, "cls": "ng-touched.ng-dirty.search-input",
               "ancestry": "div.search-container.search-container--visible<app-bar#search"}
    assert element_signature(pristine) == element_signature(touched)
    assert stable_classes("sign-in-button.error-message.btn--primary.is-active") == \
        "sign-in-button.error-message"


def test_routes_fold_values_keep_query_names_and_spa_fragments():
    assert normalise_route(f"{BASE}/users/17/orders?page=2&q=x") == \
        normalise_route("http://localhost:8080/users/42/orders?q=y&page=9")
    assert normalise_route(f"{BASE}/#/search") != normalise_route(f"{BASE}/#/basket")
    assert "label" not in element_signature({"tag": "a", "label": "Home",
                                             "href": f"{BASE}/u/1"})


# --- valid-first values ----------------------------------------------------------------

def test_candidates_follow_type_name_pattern_and_bounds():
    assert formfill.candidates({"type": "email", "name": "contact"})[0] == \
        "disco.user@example.com"
    code = formfill.candidates({"type": "text", "name": "ref", "pattern": "[A-Z]{3}-[0-9]{2}"})
    assert code[0] == "AAA-00"
    assert formfill.candidates({"type": "number", "min": "5", "max": "9"})[0] == "5"
    short = formfill.candidates({"type": "text", "name": "nick", "maxlength": "5"})
    assert len(short[0]) <= 5
    assert formfill.candidates({"type": "password", "name": "pw"}) == [formfill.PASSWORD_FILLER]


def test_patterns_with_escaped_classes_and_open_ranges_get_candidates():
    """Measured on Juice Shop: a `-?[\\d]*` control got "" (`*` as zero, `[\\d]` read
    as a backslash), and a number field whose range only a script enforced got "1"."""
    assert formfill._from_pattern(r"-?[\d]*") == "1"
    assert formfill._from_pattern(r"[\w]{3}") == "aaa"
    assert formfill.candidates({"type": "text", "pattern": r"-?[\d]*",
                                "required": True})[0] == "1"
    wide = formfill.candidates({"type": "number"})
    assert wide[0] == "1" and "1000000" in wide and "1000000000" in wide
    assert formfill.candidates({"type": "number", "min": "1", "max": "10"}) == ["1", "10"]


def test_page_set_or_optional_sensitive_controls_are_left_alone():
    """A CSRF token the page filled is never overwritten; a required empty control is
    filled whatever its name, or the browser refuses the form (measured on the fixture)."""
    assert formfill.skip_reason({"type": "text", "name": "csrf_token", "value": "abc"}) \
        == "sensitive"
    assert formfill.skip_reason({"type": "text", "name": "otp_code"}) == "sensitive"
    assert formfill.skip_reason({"type": "text", "name": "code", "required": True}) is None
    for t in ("hidden", "file", "submit"):
        assert formfill.skip_reason({"type": t, "name": "x"}) == t


def test_perturbations_are_one_coverage_pass_per_control():
    assert formfill.perturbations({"type": "text", "name": "t", "maxlength": "4"}, "ab") == \
        [("empty", ""), ("boundary-length", "xxxx")]
    assert formfill.perturbations({"type": "number", "max": "10"}, "1") == \
        [("empty", ""), ("boundary-max", "10")]
    assert formfill.perturbations({"tag": "select", "options": ["", "a", "b"]}, "a") == \
        [("alternate-option", "b")]


def test_a_captcha_form_is_submitted_and_a_credential_change_is_not():
    """D71: a CAPTCHA control is filled like any other (a filler answer) and the form is
    submitted -- only reported; a form that changes a credential stays refused."""
    from fuzzlab.disco.explore import form_refusal, has_captcha
    contact = [{"tag": "textarea", "name": "comment"},
               {"tag": "input", "type": "text", "id": "captchaControl", "label": "Result"}]
    assert form_refusal(contact, {"label": "Submit"}) is None and has_captcha(contact)
    assert not has_captcha([{"name": "capture_mode"}, {"label": "Captain"}])
    change = [{"type": "password", "name": "current"}, {"type": "password", "name": "new"},
              {"type": "password", "name": "repeat"}]
    assert form_refusal(change, {"label": "Change password"}) == "credential-change"


def test_enter_is_pressed_where_no_submit_control_would_send_the_form():
    from fuzzlab.disco.explore import enter_submits
    box = {"tag": "input", "type": "search", "last_typed": True, "typed": 1}
    assert enter_submits(dict(box, submitters=0, form_tag=False))
    assert enter_submits(dict(box, submitters=6, form_tag=False))    # a toolbar's box
    assert not enter_submits(dict(box, submitters=1, form_tag=True))  # click submits it
    many = dict(box, typed=3, submitters=1, form_tag=False)
    assert not enter_submits(many)                     # its button is its submitter
    assert enter_submits(dict(many, submitters=0, form_tag=True))
    assert not enter_submits(dict(many, submitters=0, last_typed=False))
    assert not enter_submits(dict(box, type="checkbox", submitters=0))
    assert not enter_submits(dict(box, submitters=0, disabled=True))


def test_a_submission_is_sent_only_when_a_distinctive_filled_value_reaches_a_request():
    from fuzzlab.disco.explore import carries_value, is_distinctive

    class Req:
        def __init__(self, url, body=None):
            self.url, self._body = url, body

        @property
        def post_data(self):
            if self._body == b"bin":
                raise UnicodeDecodeError("utf-8", b"", 0, 1, "x")
            return self._body

    assert is_distinctive("Hello from disco") and not is_distinctive("test")
    assert not is_distinctive("12345") and not is_distinctive("1")
    vals = ["Hello from disco", "disco.user@example.com"]
    assert carries_value(Req("http://h/api?q=Hello+from+disco"), vals)
    assert carries_value(Req("http://h/api", '{"email": "disco.user@example.com"}'), vals)
    assert not carries_value(Req("http://h/api/lang"), vals)
    assert not carries_value(Req("http://h/api/up", b"bin"), vals)


# --- network quiescence (the explorer's settle rule) -------------------------------------

def test_quiet_is_measured_from_the_action_not_the_last_request():
    """A click whose fetch starts after a debounce: with nothing in flight and the last
    request long ago, the settle still waits ``idle_ms`` from the action (measured: a
    120 ms debounce otherwise lost the dialog's subtree)."""
    from fuzzlab.disco.explore import ExploreOptions, Explorer
    clock = {"t": 100.0}
    ex = Explorer("http://127.0.0.1:1/", scope_urls=["http://127.0.0.1:1/"],
                  proxy="127.0.0.1:2", options=ExploreOptions(idle_ms=500, max_quiet_ms=8000),
                  clock=lambda: clock["t"])
    waited = []

    class Page:
        def wait_for_timeout(self, ms):
            waited.append(ms)
            clock["t"] += ms / 1000

    ex._last_change = 10.0                          # the last request: long ago
    ex.mark_activity()                              # the click
    assert ex.wait_quiet(Page()) is True
    assert sum(waited) >= 500
    ex._on_request(type("Req", (), {"url": "http://127.0.0.1:1/x"})())                            # a request starts inside the wait...
    waited.clear()
    clock["t"] += 0.1
    ex._on_done(None)                               # ...and ends: quiet from its end
    assert ex.wait_quiet(Page()) and sum(waited) >= 500


def test_an_app_under_a_subpath_is_explored_from_its_whole_start_url(monkeypatch):
    """PA-0300 / PA-0113(3): the start URL is navigated as given, path and all, never
    truncated to its origin; a sibling path on the origin stays in scope (scope is an
    origin) and another port does not."""
    from fuzzlab.disco import explore
    start = "http://127.0.0.1:8092/shop/app/"
    ex = explore.Explorer(start, scope_urls=[start], proxy="127.0.0.1:2")
    assert ex._in_scope("http://127.0.0.1:8092/other") and \
        not ex._in_scope("http://127.0.0.1:8093/shop/app/")
    seen = []

    class Stop(Exception):
        pass

    def navigate(page, url, **kw):
        seen.append(url)
        raise Stop
    monkeypatch.setattr(explore.navguard, "navigate", navigate)
    ctx = type("Ctx", (), {"new_page": lambda self: object()})()
    ex._ctx = ctx
    ex._shared.busy = 1                     # as run() marks the seeding worker
    try:
        ex._work(browser=None, pw=None, seed=True)
    except Stop:
        pass
    assert seen == [start]


# --- the synthesizer -------------------------------------------------------------------

def rec(method, path, *, status=200, body=None, res=None, t=0.0, action="act-1",
        ctype="application/json", headers=None, res_ctype="application/json", profile=None):
    return make_record(
        kind="http", t=t, action_id=action, method=method, url=BASE + path,
        req_headers={**({"Content-Type": ctype} if body is not None else {}),
                     "Accept": "*/*", **(headers or {})},
        req_body=(json.dumps(body) if not isinstance(body, str) else body).encode()
        if body is not None else None,
        status=status, res_headers={"Content-Type": res_ctype},
        res_body=(json.dumps(res) if not isinstance(res, (str, bytes)) else res).encode()
        if res is not None else None, latency_ms=5, profile=profile)


def test_segments_are_classified_and_slugs_need_siblings():
    assert [segment_kind(s) for s in ("17", U1, "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                                      "deadbeefdeadbeef0011", "orders")] == \
        ["int", "uuid", "id", "id", None]
    paths = [(BASE, f"/u/{n}/orders") for n in (17, 42)] + \
        [(BASE, f"/blog/{s}") for s in ("alpha", "beta", "gamma")[:SLUG_MIN_DISTINCT]] + \
        [(BASE, "/blog/feed/extra")]
    t = template_paths(paths, frozenset({"alpha", "beta", "gamma"}))
    assert t[(BASE, "/u/17/orders")] == ("/u/{p1}/orders", ["int"])
    assert t[(BASE, "/blog/alpha")] == ("/blog/{p1}", ["slug"])
    assert t[(BASE, "/blog/feed/extra")][0] == "/blog/feed/extra"
    # BUG-0501: names never seen as data, and first segments, stay literal
    names = [(BASE, f"/api/{n}/") for n in ("Users", "Products", "Feedbacks")] + \
        [(BASE, f"/{n}") for n in ("profile", "redirect", "file-upload")]
    t = template_paths(names, frozenset({"profile", "redirect", "file-upload"}))
    assert {v[0] for v in t.values()} == {"/api/Users/", "/api/Products/",
                                          "/api/Feedbacks/", "/profile", "/redirect",
                                          "/file-upload"}


def test_an_inventory_templates_merges_and_links_dependencies():
    records = [
        rec("GET", "/api/projects", res=[{"id": 101}, {"id": 102}], t=1),
        rec("GET", "/api/projects/101/tasks", res=[], t=2),
        rec("GET", "/api/projects/102/tasks", res=[], t=3),
        *[rec("POST", "/api/projects/101/tasks", body={"title": "a", "prio": p, "n": i},
              res={"id": u, "title": "a", "owner": "x"}, status=201, t=4 + i)
          for i, (p, u) in enumerate([("low", U1), ("high", U2), ("low", U1), ("high", U2)])],
        rec("PUT", f"/api/tasks/{U2}", body={"done": True}, res={"id": U2}, t=10),
        rec("GET", "/static/app.js", res_ctype="application/javascript",
            res="fetch('/api/hidden/report'); axios.post('/api/secret/ping')", t=0),
        rec("GET", "/logo.png", res_ctype="image/png", res="x", t=0),
    ]
    inv = synthesize(records)
    ops = {(m, t): op for t, m, op in endpoints(inv)}
    assert set(ops) == {("GET", "/api/projects"), ("GET", "/api/projects/{p1}/tasks"),
                        ("POST", "/api/projects/{p1}/tasks"), ("PUT", "/api/tasks/{p1}")}
    post = ops[("POST", "/api/projects/{p1}/tasks")]
    schema = post["requestBody"]["content"]["application/json"]["schema"]
    assert schema["required"] == ["n", "prio", "title"]
    assert schema["properties"]["prio"]["enum"] == ["high", "low"]      # 2 strings, 4 samples
    assert "enum" not in schema["properties"]["title"]                 # one constant
    assert "enum" not in schema["properties"]["n"]                     # numbers: a range
    assert schema["properties"]["n"]["x-observed"] == {"minimum": 0, "maximum": 3}
    assert post["x-disco"]["response_only_fields"] == ["id", "owner"]
    put = ops[("PUT", "/api/tasks/{p1}")]["x-disco"]["dependencies"]
    assert put == [{"producer": post["operationId"], "extract": "$.id", "target": "path.p1",
                    "count": 1}]
    tasks = ops[("GET", "/api/projects/{p1}/tasks")]["x-disco"]["dependencies"]
    assert tasks[0]["extract"] == "$[0].id" and tasks[0]["target"] == "path.p1"
    cands = {c["path"]: c["method"] for c in inv["x-disco"]["candidates"]}
    assert cands == {"/api/hidden/report": None, "/api/secret/ping": "POST"}
    assert inv["openapi"] == "3.1.0" and inv["servers"] == [{"url": BASE}]


def test_small_numbers_link_only_through_an_id_slot():
    records = [rec("GET", "/api/cart", res={"id": 7, "qty": 1}, t=1),
               rec("POST", "/api/note", body={"count": 7, "flag": 1}, res={}, t=2),
               rec("GET", "/api/items/7", res={}, t=3)]
    ops = {(m, t): op for t, m, op in endpoints(synthesize(records))}
    assert ops[("POST", "/api/note")]["x-disco"]["dependencies"] == []
    assert ops[("GET", "/api/items/{p1}")]["x-disco"]["dependencies"][0]["target"] == "path.p1"


def test_headers_are_classed_and_auth_is_read_from_sessions():
    records = [rec("GET", "/api/me", headers={"Cookie": "sid=s1", "X-Req": str(i)},
                   res={"u": 1}, t=i) for i in range(2)] + \
        [rec("GET", "/api/me", res={"u": 1}, t=5, status=401)]
    op = next(op for _t, _m, op in endpoints(synthesize(records)))
    hdrs = op["x-disco"]["headers"]
    assert hdrs["cookie"] == {"class": "session"}
    assert hdrs["x-req"] == {"class": "varies"}
    assert hdrs["accept"] == {"class": "static", "value": "*/*"}
    assert op["x-disco"]["auth"] == "required"          # the anonymous call got a 401


def test_redacted_truncated_and_form_bodies():
    records = [rec("POST", "/login", body="user=a&password=s", ctype=
                   "application/x-www-form-urlencoded", res={}, t=i) for i in range(4)]
    op = next(op for _t, _m, op in endpoints(synthesize(records)))
    props = op["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"][
        "properties"]
    assert props["password"].get("x-redacted") is True
    assert PLACEHOLDER not in json.dumps(props["password"].get("examples", []))
    big = rec("POST", "/api/x", body={"a": "b" * 300_000}, res={}, t=1)
    assert big.req_truncated
    op = next(op for _t, _m, op in endpoints(synthesize([big])))
    assert "requestBody" not in op                       # no schema from half a document
