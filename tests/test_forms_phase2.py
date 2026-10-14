"""Forms phase 2 (lane A): link siblings, header points, value-shape rules, POST
selectors, and BUG-0115 (a probe is never relocated).

Generic mechanisms (FR-FUZZ-43, FR-AUD-20, FR-CRAWL-10, FR-CORE-32), agreed with
reviewers A/B over three rounds (scratchpad p2-a draft v1-v3). The few bWAPP option
labels pinned below are inlined; no bWAPP file is copied (it is CC BY-NC-ND).
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest
from bs4 import BeautifulSoup

from fuzzlab.audit import InjectionPoint, evaluate, load_rules
from fuzzlab.audit import value_shape as vs
from fuzzlab.audit.rules import Rule, RuleError, validate_rule
from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.forms import first_link_set, form_record, is_link_set
from fuzzlab.core.http import (HEADER_POINT_DENY, HeaderPointRefused, HttpClient,
                               header_point_refusal)
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import (header_point_cost, header_points_from_store,
                                  injection_points_from_store, points_from_ground_truth,
                                  run_auto)
from fuzzlab.oracle.probe import Candidate, HeaderPointsStopped, Probe
from fuzzlab.tools import formnav
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender
from fuzzlab.tools.store_adapter import (_FILLERS, _TEXT_FILLER, form_skip_reason,
                                         import_spider, is_filler)

ROOT = Path(__file__).resolve().parents[1]
GT_DIRS = sorted(p for p in (ROOT / "lab").glob("ground-truth*")
                 if (p / "labels.json").exists())
HEX32 = "0123456789abcdef0123456789abcdef"


# --- helpers -----------------------------------------------------------------------------
def _rec(html, page="http://h/app/p.php"):
    return form_record(BeautifulSoup(html, "html.parser").find("form"), page)


def _spider_db(path, pages=(), forms=(), verdicts=()):
    """A spider DB with the real spider's schema (`StorageManager`)."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(path))
    sm.reset()
    for p in pages:
        url, status = (p, 200) if isinstance(p, str) else p
        sm.mark_visited(url, status, 0)
    for f in forms:
        sm.record_form(f)
    for sig, verdict in verdicts:
        sm.record_verdict(sig, verdict)
    sm.close()


def _import(tmp_path, pages=(), forms=(), verdicts=(), base="http://h/app/"):
    _spider_db(tmp_path / "s.db", pages, forms, verdicts)
    store = Store(tmp_path / "u.db")
    run = store.start_run("auto", "h")
    counts = import_spider(tmp_path / "s.db", store, run)
    return store, run, counts


def _points(tmp_path, pages=(), forms=(), verdicts=(), base="http://h/app/"):
    store, run, counts = _import(tmp_path, pages, forms, verdicts, base)
    with store:
        skipped = []
        return injection_points_from_store(store, run, base, skipped=skipped), skipped, counts


class _App:
    """A fake target behind the `Sender` seam. ``handler(req)`` answers a request view:
    ``method``, ``path``, ``query``/``body``/``headers`` dicts. Every request is
    recorded, so a test can search everything that was sent."""

    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        body, headers = {}, {}
        if location == "query":
            query = dict(entries) if entries is not None else {**query, param: value}
        elif location == "body":
            body = dict(entries) if entries is not None else {param: value}
        elif location == "header":
            headers = {param: value}
        req = dict(method=method, path=parts.path, query=query, body=body,
                   headers=headers, location=location, param=param, value=value)
        self.requests.append(req)
        return self.handler(req)

    def sent_text(self) -> str:
        return json.dumps(self.requests)


def _ok(text="<html>ok</html>"):
    return Probe(200, text)


# =========================================================================================
# (a) Link query siblings
# =========================================================================================
FRAME = "http://h/app/frame.php?u=robots.txt&w=250&h=250"


def test_link_query_siblings_are_bound(tmp_path):
    pts, _s, counts = _points(tmp_path, pages=[FRAME])
    by = {p.param: p for p in pts}
    want = (("u", "robots.txt"), ("w", "250"), ("h", "250"))
    assert {by[n].base_entries for n in "uwh"} == {want}
    assert counts["link_set"] == 1 and counts["link_set_bound"] == 3


def test_a_three_field_link_gate_confirms_only_with_siblings(tmp_path):
    def handler(req):
        q = req["query"]
        if not {"u", "w", "h"} <= set(q):
            return Probe(302, "", headers={"Location": "frame.php?u=robots.txt"})
        return _ok(f'<html><iframe src="{q["u"]}" height="{q["h"]}"></iframe></html>')
    app = _App(handler)
    store, run, _c = _import(tmp_path, pages=[FRAME])
    with store:
        result = run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                          mode="manual", selected_categories=["xss"],
                          points_source="crawl")
        params = {r["param"] for r in store.conn.execute(
            "SELECT param FROM finding WHERE run_id=?", (run,))}
    assert result.findings >= 1 and "u" in params


def test_a_form_sibling_set_wins_over_a_link_query(tmp_path):
    form = _rec("<form method=get action='/app/s.php'><input name=title>"
                "<button name=action value=search>Go</button></form>")
    pts, _s, _c = _points(tmp_path, pages=["http://h/app/s.php?title=a&page=2"],
                          forms=[form])
    title = next(p for p in pts if p.param == "title")
    assert ("action", "search") in title.base_entries          # the form's, not the link's
    page = next(p for p in pts if p.param == "page")
    assert page.base_entries == (("title", "a"), ("page", "2"))  # no form covers it


def test_the_first_crawled_link_wins_for_a_shared_parameter(tmp_path):
    pts, _s, _c = _points(tmp_path, pages=["http://h/app/l.php?a=1&b=2",
                                           "http://h/app/l.php?a=9&c=3"])
    by = {p.param: p.base_entries for p in pts}
    assert by["a"] == by["b"] == (("a", "1"), ("b", "2"))
    assert by["c"] == (("a", "9"), ("c", "3"))


@pytest.mark.parametrize("url,refused", [
    ("http://h/app/c.php?user=bob&password_new=x", "credential"),
    ("http://h/app/c.php?user=bob&do=purge", "destructive"),
])
def test_link_sets_with_a_credential_or_destructive_entry_are_not_bound(tmp_path, url,
                                                                        refused):
    pts, skipped, counts = _points(tmp_path, pages=[url])
    assert counts["link_set_refused"] == 1 and counts["link_set"] == 0
    assert all(p.base_entries is None for p in pts)              # lone points, as before
    if refused == "credential":
        assert "password_new" not in {p.param for p in pts}
        assert any(s[2] == "password_new" for s in skipped)


def _all_rows_text(store, exclude=()) -> str:
    out = []
    for (table,) in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        for row in store.conn.execute(f"SELECT * FROM {table}").fetchall():
            for col in row.keys():
                if (table, col) not in exclude:
                    out.append(str(row[col]))
    return "\n".join(out)


def test_identifier_like_link_values_are_blanked_and_never_stored(tmp_path):
    app = _App(lambda req: _ok())
    store, run, _c = _import(tmp_path, pages=[f"http://h/app/p.php?u=bob&t={HEX32}"])
    with store:
        pts = injection_points_from_store(store, run, "http://h/app/")
        u = next(p for p in pts if p.param == "u")
        assert u.base_entries == (("u", "bob"), ("t", ""))
        hdr = header_points_from_store(store, run, "http://h/app/", ["User-Agent"])
        # the representative query comes only from the (already redacted) link-set row,
        # so the token is sent blank there too -- never its value
        assert [p.url for p in hdr] == ["http://h/app/p.php?u=bob&t="]
        run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                 mode="manual", selected_categories=["xss"], points_source="crawl",
                 header_names=["User-Agent"])
        # the first send is the pipeline's fingerprint probe (no siblings, by design);
        # every oracle probe of `u` carries the token blank
        u_probes = [r for r in app.requests if r["param"] == "u"][1:]
        assert u_probes and all(r["query"].get("t") == "" for r in u_probes)
        # excluded: parameter.example, BUG-0120 (raw crawl values stored in
        # parameter.example; reserved, not fixed in this lane). Asserted still needed,
        # so this exclusion fails loudly once BUG-0120 is fixed.
        assert HEX32 in _all_rows_text(store)
        assert HEX32 not in _all_rows_text(store, exclude={("parameter", "example")})


def test_a_sensitive_link_sibling_is_blanked_by_its_name(tmp_path):
    pts, _s, _c = _points(tmp_path, pages=["http://h/app/p.php?u=bob&csrf_token=abc"])
    u = next(p for p in pts if p.param == "u")
    assert dict(u.base_entries)["csrf_token"] == ""


def test_the_identifier_predicate_sees_plus_signs(tmp_path):
    """The caller contract: the raw value, percent-decoded, never form-decoded (a form
    decode turns base64's '+' into a space and the token into short words)."""
    token = "Qm9i+ZW5jb2RlZC+dG9rZW4+dmFsdWU"           # base64 with '+'
    store, run, _c = _import(tmp_path, pages=[f"http://h/app/p.php?u=bob&t={token}"])
    with store:
        u = next(p for p in injection_points_from_store(store, run, "http://h/app/")
                 if p.param == "u")
        assert dict(u.base_entries)["t"] == ""
        rows = _all_rows_text(store, exclude={("parameter", "example")})   # BUG-0120
        assert token.replace("+", " ") not in rows and token not in rows


def test_single_name_links_are_not_bound(tmp_path):
    pts, _s, counts = _points(tmp_path, pages=["http://h/app/e.php?date=Date()"])
    assert [p.base_entries for p in pts] == [None]
    assert counts["link_set"] == 1 and counts["link_set_bound"] == 0


def test_link_siblings_under_a_sub_path(tmp_path):
    pts, _s, _c = _points(tmp_path, pages=["http://h/app/sub/f.php?x=1&y=2"],
                          base="http://h/app/")
    assert {p.url for p in pts} == {"http://h/app/sub/f.php"}
    assert all(p.base_entries == (("x", "1"), ("y", "2")) for p in pts)


@pytest.mark.parametrize("value", ["robots.txt", "message.txt", "documents", "portal.php",
                                   "www.nsa.gov", "lang_en.php",
                                   "The Fellowship of the Ring"])
def test_ordinary_link_values_stay_bound_unchanged(tmp_path, value):
    """S5 (final predicate): none of these is identifier-like."""
    from urllib.parse import urlencode
    pts, _s, _c = _points(tmp_path, pages=[
        "http://h/app/v.php?" + urlencode([("a", "1"), ("b", value)])])
    a = next(p for p in pts if p.param == "a")
    sent = dict(a.base_entries)["b"]
    assert sent == vs.neutral_value(value)           # only an ip/host/url is neutralised


def test_a_link_set_never_reaches_form_skip_logic(tmp_path, monkeypatch):
    from fuzzlab.tools import store_adapter
    seen = []
    real = store_adapter.form_skip_reason
    monkeypatch.setattr(store_adapter, "form_skip_reason",
                        lambda form: seen.append(form) or real(form))
    _s, _r, counts = _import(tmp_path, pages=[FRAME], forms=[
        _rec("<form method=get action='/app/q.php'><input name=q></form>")])
    _s.close()
    assert [f["action_url"] for f in seen] == ["http://h/app/q.php"]
    assert counts["form"] == 1 and counts["form_skipped"] == 0 and counts["link_set"] == 1


def test_a_link_set_is_never_treated_as_a_form(tmp_path):
    rec = _rec("<form method=get action='/app/q.php'><input name=q></form>")
    rec["enctype"] = None                                     # a NULL from the spider
    store, run, _c = _import(tmp_path, pages=[FRAME], forms=[rec])
    with store:
        rows = store.conn.execute("SELECT enctype, entries FROM form").fetchall()
        kinds = sorted(is_link_set(r) for r in rows)
        assert kinds == [False, True]
        assert {r["enctype"] for r in rows if not is_link_set(r)} == {""}
        assert first_link_set(store.conn, run, "/app/frame.php") == [
            ("u", "robots.txt"), ("w", "250"), ("h", "250")]
        assert first_link_set(store.conn, run, "/app/q.php") is None
    assert form_skip_reason({**rec, "enctype": None}) is None      # NULL-safe


def _enctype_readers(root: Path) -> list[str]:
    """Modules (other than core/forms.py) whose SQL reads ``enctype`` from the store's
    ``form`` table."""
    out = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "forms.py" and path.parent.name == "core":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                sql = node.value
                if (re.search(r"\bSELECT\b", sql, re.I) and "enctype" in sql
                        and re.search(r"\b(FROM|JOIN)\s+form\b", sql, re.I)):
                    out.append(f"{path.name}")
    return out


def test_only_core_forms_reads_form_enctype(tmp_path):
    assert _enctype_readers(ROOT / "fuzzlab") == []
    (tmp_path / "rogue.py").write_text(
        'Q = "SELECT f.enctype FROM form f WHERE f.run_id = ?"\n')
    assert _enctype_readers(tmp_path) == ["rogue.py"]


def test_the_link_set_producer_goes_through_redaction():
    """PA-0100: the function that INSERTs link sets calls redact_sibling."""
    tree = ast.parse((ROOT / "fuzzlab/tools/store_adapter.py").read_text())
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        names = {getattr(n, "id", None) for n in ast.walk(fn)}
        consts = [n.value for n in ast.walk(fn) if isinstance(n, ast.Constant)
                  and isinstance(n.value, str)]
        if "LINK_SET_ENCTYPE" in names and any("INSERT INTO form" in c for c in consts):
            called = {getattr(c.func, "id", getattr(c.func, "attr", None))
                      for c in ast.walk(fn) if isinstance(c, ast.Call)}
            assert "redact_sibling" in called
            return
    pytest.fail("no link-set producer found")


# =========================================================================================
# (b) Header injection points
# =========================================================================================
def test_header_points_are_off_by_default(tmp_path):
    app = _App(lambda req: _ok())
    store, run, _c = _import(tmp_path, pages=["http://h/app/a.php?id=1"])
    with store:
        result = run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                          mode="manual", selected_categories=["xss"],
                          points_source="crawl")
    assert result.metrics["header_points"] == 0
    assert all(r["location"] != "header" for r in app.requests)


def test_header_points_turn_on_and_are_observable(tmp_path):
    app = _App(lambda req: _ok())
    store, run, _c = _import(tmp_path, pages=["http://h/app/a.php?id=1"])
    with store:
        result = run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                          mode="manual", selected_categories=["xss"],
                          points_source="crawl", header_names=["User-Agent", "Referer"])
    assert result.metrics["header_points"] == 2
    assert {r["param"] for r in app.requests if r["location"] == "header"} == \
        {"User-Agent", "Referer"}


def test_one_header_point_per_crawled_2xx_page_and_name(tmp_path):
    pages = ["http://h/app/sub/a.php?x=1&y=2", ("http://h/app/sub/err.php", 500),
             ("http://h/app/sub/moved.php", 302), "http://h/app/sub/reset.php",
             "http://h/app/sub/a.php?x=9&y=9", "http://h/app/sub/b.php"]
    store, run, _c = _import(tmp_path, pages=pages)
    with store:
        skipped = []
        crawl = injection_points_from_store(store, run, "http://h/app/")
        hdr = header_points_from_store(store, run, "http://h/app/", ["User-Agent", "X-Mine"],
                                       skipped=skipped)
    assert [(p.url, p.param) for p in hdr] == [
        ("http://h/app/sub/a.php?x=1&y=2", "User-Agent"),
        ("http://h/app/sub/a.php?x=1&y=2", "X-Mine"),
        ("http://h/app/sub/b.php", "User-Agent"), ("http://h/app/sub/b.php", "X-Mine")]
    assert all(p.location == "header" and p.method == "GET" and p.origin == "crawl"
               for p in hdr)
    assert {(s[0], s[2]) for s in skipped} == {("/app/sub/reset.php", "User-Agent"),
                                               ("/app/sub/reset.php", "X-Mine")}
    assert crawl and all(p.location != "header" for p in crawl)


def test_header_points_come_after_every_other_point(tmp_path):
    app = _App(lambda req: _ok())
    store, run, _c = _import(tmp_path, pages=["http://h/app/a.php?id=1&q=2"])
    with store:
        run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                 mode="manual", selected_categories=["xss", "sql-injection"],
                 points_source="crawl", header_names=["User-Agent"])
        locs = [json.loads(r["evidence"])["location"] for r in store.conn.execute(
            "SELECT evidence FROM candidate WHERE run_id=? ORDER BY id", (run,))]
    first_header = locs.index("header")
    assert all(loc == "header" for loc in locs[first_header:])


def test_a_single_name_link_gives_a_header_query_but_no_binding(tmp_path):
    store, run, _c = _import(tmp_path, pages=["http://h/app/e.php?date=Date()",
                                              f"http://h/app/k.php?p={HEX32}"])
    with store:
        hdr = {urlsplit(p.url).path: p.url for p in header_points_from_store(
            store, run, "http://h/app/", ["User-Agent"])}
        pts = injection_points_from_store(store, run, "http://h/app/")
    assert hdr["/app/e.php"] == "http://h/app/e.php?date=Date%28%29"
    assert hdr["/app/k.php"] == "http://h/app/k.php?p="            # blank, never the token
    assert all(p.base_entries is None for p in pts)


def test_a_header_point_url_never_carries_the_apps_own_host(tmp_path):
    store, run, _c = _import(tmp_path, pages=[
        "http://h/app/n.php?h=www.example.com&u=http%3A%2F%2Fevil.example%2Fx&q=1"])
    with store:
        (pt,) = header_points_from_store(store, run, "http://h/app/", ["User-Agent"])
    assert pt.url == ("http://h/app/n.php?h=127.0.0.1&u=http%3A%2F%2F127.0.0.1%2F&q=1")
    assert "example" not in pt.url


def _rules_without(*ids):
    return [r for r in load_rules() if r.id not in ids]


def _candidate_set(store, run):
    return sorted((e["url"], e["param"], e["location"], e["category"]) for e in (
        json.loads(r["evidence"]) for r in store.conn.execute(
            "SELECT evidence FROM candidate WHERE run_id=?", (run,))))


def test_header_rules_fire_only_on_crawl_header_points(tmp_path):
    header = InjectionPoint(url="http://h/a.php", param="User-Agent", location="header",
                            origin="crawl")
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("audit", "h")
        evaluate([header], store, run)
        cats = {c[3] for c in _candidate_set(store, run)}
    assert cats == {"sql-injection", "xss"}


@pytest.mark.parametrize("gt", GT_DIRS, ids=lambda p: p.name)
def test_ground_truth_candidates_are_unchanged_by_the_new_rules(tmp_path, gt):
    """Ground-truth points (header ones included) gain no candidate: the header rules
    need a crawl origin and the value rules an example (PA-0001: derived, not literal)."""
    from fuzzlab.labels import contract
    pts, _ = points_from_ground_truth(contract.load(str(gt)), "http://h")
    new = ("R-SQLI-HEADER", "R-XSS-HEADER", "R-COMMAND-INJECTION-VALUE",
           "R-FILE-INCLUSION-VALUE")
    with Store(tmp_path / "u.db") as store:
        a, b = store.start_run("a", "h"), store.start_run("b", "h")
        evaluate(pts, store, a)
        evaluate(pts, store, b, rules=_rules_without(*new))
        assert _candidate_set(store, a) == _candidate_set(store, b)


def _auto_cli(tmp_path, *extra):
    from fuzzlab.harness import auto_cli
    return auto_cli.main(["--base-url", "http://h/app/", "--store", str(tmp_path / "u.db"),
                          "--spider-db", str(tmp_path / "s.db"), "--authorized",
                          "--mode", "manual", *extra])


REFUSED_NAMES = sorted(n for names in HEADER_POINT_DENY.values() for n in names) + [
    "X-Auth-Token", "X-Api-Key", "bad name", "a" * 65]


@pytest.mark.parametrize("name", REFUSED_NAMES + [n.upper() for n in (
    "cookie", "x-forwarded-proto", "x-http-host-override")])
def test_header_point_names_are_validated(tmp_path, capsys, name):
    _spider_db(tmp_path / "s.db", pages=["http://h/app/a.php"])
    with pytest.raises(SystemExit) as exc:
        _auto_cli(tmp_path, "--points", "crawl", "--header-points", f"User-Agent,{name}")
    assert exc.value.code == 2 and not (tmp_path / "u.db").exists()
    assert header_point_refusal(name) is not None


@pytest.mark.parametrize("name", ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
                                  "Client-IP", "bWAPP"])
def test_ordinary_header_names_are_allowed(name):
    assert header_point_refusal(name) is None


def test_header_points_need_crawl_points(tmp_path):
    with pytest.raises(SystemExit) as exc:
        _auto_cli(tmp_path, "--points", "ground-truth", "--ground-truth", "lab/ground-truth",
                  "--header-points")
    assert exc.value.code == 2 and not (tmp_path / "u.db").exists()


def test_header_points_over_budget_are_refused_before_the_store(tmp_path, capsys,
                                                                monkeypatch):
    _spider_db(tmp_path / "s.db", pages=[f"http://h/app/p{i}.php" for i in range(4)])
    monkeypatch.setenv("FUZZLAB_BUDGET_TOTAL", "10")
    with pytest.raises(SystemExit) as exc:
        _auto_cli(tmp_path, "--points", "crawl", "--identity", "admin", "--header-points")
    err = capsys.readouterr().err
    cost = 4 * 2 * header_point_cost()
    assert exc.value.code == 2 and not (tmp_path / "u.db").exists()
    assert f"at least {cost} requests" in err and "budget_total=10" in err


def _deny_names():
    return sorted(n for names in HEADER_POINT_DENY.values() for n in names)


class _FakeSession:
    def __init__(self):
        self.calls = []
        self.cookies = {}

    def request(self, method, url, **kw):
        self.calls.append(dict(method=method, url=url, **kw))

        class R:
            status_code, text, headers = 200, "ok", {}
        return R()


def _seam(transport, *, manager=None, identity="anonymous"):
    client = HttpClient(RequestBudget(500), ["h", "localhost"], session=manager,
                        transport=transport)
    return SeamProbeSender(client, identity, manager=manager,
                           base_url="http://localhost/" if manager else None)


@pytest.mark.parametrize("name", _deny_names() + ["X-Auth-Token"])
def test_every_sender_refuses_a_denied_header_unless_explicit(name):
    from fuzzlab.greybox.run import RequestsCorrelatingSender
    sent = []

    def transport(method, url, headers, body, timeout):
        sent.append(url)
        return 200, {}, b"ok"
    session, grey = _FakeSession(), _FakeSession()
    senders = [(_seam(transport), lambda s, u: s.send(u, name, "x", location="header")),
               (RequestsProbeSender(session=session),
                lambda s, u: s.send(u, name, "x", location="header")),
               (RequestsCorrelatingSender(session=grey),
                lambda s, u: s.send_correlated(u, name, "x", location="header"))]
    for sender, call in senders:
        with pytest.raises(HeaderPointRefused):
            call(sender, "http://h/a.php")
        sender.allow_explicit(["http://h/gt.php"])            # ground truth's own point
        call(sender, "http://h/gt.php")
    assert sent == ["http://h/gt.php"]                          # counted sends (PA-0083(2))
    assert [c["url"] for c in session.calls] == ["http://h/gt.php"]
    assert [c["url"] for c in grey.calls] == ["http://h/gt.php"]


def _header_gate_offenders(root: Path) -> list[str]:
    """A probe-sender method with a ``location == "header"`` branch that never calls
    `check_send_header`."""
    out = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            for fn in cls.body:
                if not (isinstance(fn, ast.FunctionDef)
                        and [a.arg for a in fn.args.args][:4] == ["self", "url", "param",
                                                                  "value"]):
                    continue
                header_branch = any(isinstance(n, ast.Compare) and any(
                    isinstance(c, ast.Constant) and c.value == "header"
                    for c in n.comparators) for n in ast.walk(fn))
                calls = {getattr(c.func, "id", getattr(c.func, "attr", None))
                         for c in ast.walk(fn) if isinstance(c, ast.Call)}
                wrapper = any(isinstance(n, ast.Attribute) and n.attr == "send"
                              and isinstance(n.value, ast.Attribute)
                              and n.value.attr == "_inner" for n in ast.walk(fn))
                if header_branch and not wrapper and "check_send_header" not in calls:
                    out.append(f"{path.name}:{cls.name}.{fn.name}")
    return out


def test_every_header_branch_calls_the_header_gate(tmp_path):
    """PA-0083(1) / PA-0034(2): wrappers (which delegate to ``self._inner.send``) are
    exempt; every sender that places a header itself calls `check_send_header`."""
    assert _header_gate_offenders(ROOT / "fuzzlab") == []
    (tmp_path / "rogue.py").write_text(
        "class Rogue:\n"
        "    def send(self, url, param, value, location='query'):\n"
        "        if location == 'header':\n"
        "            return requests.get(url, headers={param: value})\n")
    assert _header_gate_offenders(tmp_path) == ["rogue.py:Rogue.send"]


def test_a_header_probe_keeps_the_session_cookie_and_the_query():
    from tests.test_session_manager import CookieLoginFetcher, _factory, _store
    from fuzzlab.session.manager import SessionManager
    seen = []

    def transport(method, url, headers, body, timeout):
        seen.append((url, dict(headers)))
        return 200, {}, b"<html>welcome admin</html>"
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    sender = _seam(transport, manager=mgr, identity="admin")
    sender.send("http://localhost/a.php?x=1&y=2", "User-Agent", "<zq>", location="header")
    url, headers = seen[-1]
    assert url == "http://localhost/a.php?x=1&y=2"
    assert headers["User-Agent"] == "<zq>" and headers["Cookie"] == "PHPSESSID=sess1"


def test_ua_reflection_and_ua_sql_error_confirm_end_to_end(tmp_path):
    def handler(req):
        ua = req["headers"].get("User-Agent", "Mozilla")
        if req["path"].endswith("ua.php"):
            return _ok(f"<html><p>Your browser: <i>{ua}</i></p></html>")
        if req["path"].endswith("log.php") and "'" in ua:
            return _ok("Error: You have an error in your SQL syntax; check the manual "
                       "that corresponds to your MySQL server version")
        return _ok()
    app = _App(handler)
    store, run, _c = _import(tmp_path, pages=["http://h/app/ua.php", "http://h/app/log.php"])
    with store:
        run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                 mode="manual", selected_categories=["xss", "sql-injection"],
                 points_source="crawl", header_names=["User-Agent"])
        found = {(r["url"], r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT url, param, vuln_class FROM finding WHERE run_id=?", (run,))}
    assert ("/app/ua.php", "User-Agent", "xss-reflected") in found
    assert ("/app/log.php", "User-Agent", "sqli") in found


def test_no_sqli_or_xss_payload_is_unsendable_in_a_header():
    """No payload a header point can receive has CR, LF, NUL or non-printable ASCII
    (`requests` would refuse it). Derived from the strategies' own lists (PA-0001)."""
    from fuzzlab.oracle.context import Reflection, xss_breakouts
    from fuzzlab.oracle.strategies import (_TIMING_TEMPLATES, SqliBooleanStrategy,
                                           SqliErrorStrategy, SqliEvaluationMarkerStrategy)
    payloads = list(SqliErrorStrategy._probes)
    for family in SqliBooleanStrategy._FAMILIES:          # FR-FUZZ-45's families
        base = family.base()
        payloads += [base, family.keep(base), family.disc(base)]
    payloads.append(SqliEvaluationMarkerStrategy._value(123, 456))
    payloads += [t.format(d=d) for t in _TIMING_TEMPLATES for d in (2, 4)]
    for ctx in ("html", "attribute", "script"):
        for quote in ('"', "'", ""):
            try:
                ref = Reflection(ctx, quote=quote)
            except TypeError:
                ref = Reflection(ctx)
            payloads += [frag for _k, frag, _c in xss_breakouts(ref, "zqxbabcdef")]
    payloads.append("zqxmabcdef")
    assert payloads and all(p.isprintable() and p.isascii() for p in payloads)


# --- the header breaker (M1) --------------------------------------------------------------
class _UaBoundSite:
    """A target whose session dies on any request carrying a User-Agent other than the
    one it logged in with (here: none). Logins go through CookieLoginFetcher."""

    def __init__(self):
        from tests.test_session_manager import CookieLoginFetcher
        site = self

        class Fetcher(CookieLoginFetcher):
            def post(self, url, data=None, headers=None):
                resp = super().post(url, data, headers)
                site.alive = self.logged_in
                return resp
        self.fetcher = Fetcher()
        self.alive = False
        self.requests = []

    def transport(self, method, url, headers, body, timeout):
        from tests.test_session_manager import LOGIN_HTML
        names = {k.lower() for k in headers}
        self.requests.append((url, dict(headers)))
        if "user-agent" in names:
            self.alive = False                     # a hijack, as the app sees it
        if not self.alive or "cookie" not in names:
            return 200, {}, LOGIN_HTML.encode()
        return 200, {}, b"<html>welcome admin</html>"


def _ua_bound_sender():
    from tests.test_session_manager import _factory, _store
    from fuzzlab.session.manager import SessionManager
    site = _UaBoundSite()
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(site.fetcher))
    return site, _seam(site.transport, manager=mgr, identity="admin")


def test_a_session_bound_to_user_agent_trips_the_breaker_after_one_relogin(tmp_path):
    site, sender = _ua_bound_sender()
    pages = [f"http://localhost/p{i}.php?id=1" for i in range(3)]
    store, run, _c = _import(tmp_path, pages=pages)
    with store:
        result = run_auto(base_url="http://localhost/", store=store, run_id=run,
                          sender=sender, mode="manual",
                          selected_categories=["sql-injection", "xss"],
                          points_source="crawl", header_names=["User-Agent", "Referer"])
        statuses = [(json.loads(r["evidence"])["location"], r["oracle_status"])
                    for r in store.conn.execute(
                        "SELECT evidence, oracle_status FROM candidate WHERE run_id=?",
                        (run,))]
    reason = result.metrics["header_breaker"]
    assert reason.startswith("session bound to a probed header (User-Agent on /p0.php")
    header_sends = [r for r in site.requests if "User-Agent" in r[1] or "Referer" in r[1]]
    assert len(header_sends) == 1                       # no header probe after the trip
    stopped = [s for s in result.metrics["skipped_points"] if s[3] == reason]
    assert {(s[0], s[2]) for s in stopped} == {(f"/p{i}.php", n) for i in range(3)
                                               for n in ("User-Agent", "Referer")}
    assert {st for loc, st in statuses if loc == "header"} == {"pending"}
    # a stopped key is neither checked nor a rejection (6 header points x 2 categories)
    m = result.metrics
    assert m["oracle_checked_keys"] == m["confirmable_keys"] - 12
    logins = site.fetcher.post_count
    assert logins == 1                                  # nothing re-logged in yet
    probe = sender.send("http://localhost/p0.php", "id", "1")   # the next main send
    assert site.fetcher.post_count == 2 and b"welcome" in probe.text.encode()
    sender.send("http://localhost/p1.php", "id", "1")
    assert site.fetcher.post_count == 2                 # exactly one re-login, still valid


def test_a_logout_seen_on_the_first_main_send_after_a_header_probe_trips():
    site, sender = _ua_bound_sender()
    sender.send("http://localhost/a.php", "id", "1")                # login, fine

    def transport(method, url, headers, body, timeout):           # dies, shows it later
        if "User-Agent" in headers:
            site.alive = False
            return 200, {}, b"<html>welcome admin</html>"
        return site.transport(method, url, headers, body, timeout)
    sender._client._transport = transport
    sender.send("http://localhost/a.php", "User-Agent", "x", location="header")
    assert sender.header_stop_reason is None
    sender.send("http://localhost/b.php", "id", "1")               # logout observed here
    assert sender.header_stop_reason.startswith("session bound to a probed header")
    with pytest.raises(HeaderPointsStopped):
        sender.send("http://localhost/b.php", "Referer", "x", location="header")


def test_a_logout_with_no_header_probe_before_it_does_not_trip():
    site, sender = _ua_bound_sender()
    sender.send("http://localhost/a.php", "id", "1")
    sender.send("http://localhost/a.php", "Referer", "x", location="header")  # harmless
    sender.send("http://localhost/a.php", "id", "1")                # a main send between
    site.alive = False                                              # an ordinary expiry
    sender.send("http://localhost/a.php", "id", "1")
    assert sender.header_stop_reason is None


def test_a_logout_after_an_isolated_copy_login_does_not_trip():
    """Lane B's copy logins: the sender reads ``isolated_copy_logins()`` (a stand-in
    here); a logout that follows one is lane B's breaker's, not this one's."""
    site, sender = _ua_bound_sender()
    copies = [0]
    sender.isolated_copy_logins = lambda: copies[0]
    sender.send("http://localhost/a.php", "id", "1")

    def transport(method, url, headers, body, timeout):
        if "User-Agent" in headers:
            copies[0] += 1                        # a copy login happened meanwhile
        return site.transport(method, url, headers, body, timeout)
    sender._client._transport = transport
    sender.send("http://localhost/a.php", "User-Agent", "x", location="header")
    assert sender.header_stop_reason is None


def test_the_logout_listener_never_raises_and_the_probe_response_is_kept():
    from tests.test_session_manager import LOGIN_HTML
    site, sender = _ua_bound_sender()
    sender.send("http://localhost/a.php", "id", "1")
    probe = sender.send("http://localhost/a.php", "User-Agent", "x", location="header")
    assert probe.text == LOGIN_HTML and sender.header_stop_reason


def test_a_trip_on_the_last_header_probe_is_still_reported(tmp_path):
    """Reviewer A: a trip that raises nothing (no header probe follows) still reaches
    `metrics["header_breaker"]`."""
    site, sender = _ua_bound_sender()
    store, run, _c = _import(tmp_path, pages=["http://localhost/only.php"])
    with store:
        result = run_auto(base_url="http://localhost/", store=store, run_id=run,
                          sender=sender, mode="manual", selected_categories=["xss"],
                          points_source="crawl", header_names=["User-Agent"])
    assert result.metrics["header_breaker"].startswith("session bound to a probed header")
    assert len([r for r in site.requests if "User-Agent" in r[1]]) == 1


def test_a_logout_on_another_host_does_not_trip():
    site, sender = _ua_bound_sender()
    sender.send("http://localhost/a.php", "id", "1")
    sender._current = ("header", "User-Agent", "http://localhost/a.php")
    sender._on_logout("elsewhere.example", "admin")
    assert sender.header_stop_reason is None
    sender._on_logout("localhost", "admin")
    assert sender.header_stop_reason


def test_the_breaker_exception_passes_through_every_wrapper():
    from fuzzlab.harness.auto import _CountingSender
    from fuzzlab.oracle.oracle import _CostCounter, _FormBoundSender

    class Stopped:
        def send(self, *a, **k):
            raise HeaderPointsStopped("stop")
    cand = Candidate(url="http://h/x", param="p", base_entries=(("p", ""),))
    for wrapper in (_CountingSender(Stopped()), _CostCounter(Stopped()),
                    _FormBoundSender(Stopped(), cand)):
        with pytest.raises(HeaderPointsStopped):
            wrapper.send("http://h/x", "User-Agent", "v", location="header")


@pytest.mark.skipif(not hasattr(SeamProbeSender, "isolated_copy_logins"),
                    reason="needs lane B's SeamProbeSender.isolated_copy_logins (merges "
                           "first); activates at merge")
def test_isolated_copy_logins_never_trip_the_header_breaker():
    """Joint (lanes A and B; the full merged-tree cases are in
    `tests/test_forms_phase2_joint.py`): a UA-bound session still trips the header
    breaker after exactly one re-login when no isolated path exists."""
    site2, sender2 = _ua_bound_sender()
    sender2.send("http://localhost/a.php", "id", "1")
    sender2.send("http://localhost/a.php", "User-Agent", "x", location="header")
    assert sender2.header_stop_reason
    sender2.send("http://localhost/a.php", "id", "1")
    assert site2.fetcher.post_count == 2
    assert sender2.isolated_copy_logins() == 0


# =========================================================================================
# (c) Value-shape rules
# =========================================================================================
@pytest.mark.parametrize("value,shape", [
    ("www.nsa.gov", "hostname"), ("example.com", "hostname"), ("localhost", "hostname"),
    ("user.id", "hostname"), ("order.by", "hostname"),       # accepted false positives
    ("10.0.0.1", "ip"), ("::1", "ip"), ("[::1]", "ip"),
    ("lang_en.php", "filename"), ("message.txt", "filename"), ("robots.txt", "filename"),
    ("readme.md", "filename"),
    ("../x", "path"), ("/etc/hosts", "path"), ("docs/x.pdf", "path"), ("C:\\x\\y", "path"),
    ("http://a/b", "url"), ("https://x.example/p?q=1", "url"),
    ("john.doe", None), ("v1.2.3", None), ("fuzzlab", None), ("1", None), ("test", None),
    ("", None), ("text/html", None), ("10/14/2026", None), ("Date()", None),
    ("fuzzlab@example.invalid", None), ("a b.com", None), ("-a.com", None),
])
def test_value_shape_table(value, shape):
    assert vs.value_shape(value) == shape


@pytest.mark.parametrize("value,sent", [
    ("www.nsa.gov", vs.SAFE_HOST), ("10.0.0.1", vs.SAFE_HOST),
    ("10.0.0.1:8080", vs.SAFE_HOST), ("www.example.com:8080", vs.SAFE_HOST),
    ("[::1]:8080", vs.SAFE_HOST),
    ("//itsecgames.blogspot.com/", vs.SAFE_URL), ("gopher://h/_x", vs.SAFE_URL),
    ("dict://host:11211/", vs.SAFE_URL), ("www.example.com/page", vs.SAFE_URL),
    ("www.example.com:8080/x", vs.SAFE_URL), ("http://a/" + "x" * 3000, vs.SAFE_URL),
    ("http://itsecgames.blogspot.com", vs.SAFE_URL),
    # unchanged: not a network location
    ("lang_en.php", "lang_en.php"), ("docs/x.pdf", "docs/x.pdf"), ("text/html", "text/html"),
    ("12:00", "12:00"), ("2020-01-01T00:00", "2020-01-01T00:00"), ("fuzzlab", "fuzzlab"),
    # stated residual (reviewer B): an e-mail default is sent as is
    ("user@mail.example.com", "user@mail.example.com"),
])
def test_neutral_value_errs_toward_loopback(value, sent):
    assert vs.neutral_value(value) == sent


@pytest.mark.parametrize("value", [None, b"www.nsa.gov", 1, 1e400, float("nan"), True,
                                   ["a.com"], "x" * 10_000_000, "\x00.com", "\U0001F600.com",
                                   "a" * 64 + ".com", "[", "]", "[::1", "http://"])
def test_value_shape_is_total(value):
    assert vs.value_shape(value) in (None, *vs.SHAPES)


def test_value_shape_is_linear_on_near_misses(monkeypatch):
    calls = []
    real = vs._is_hostname
    monkeypatch.setattr(vs, "_is_hostname", lambda v: calls.append(len(v)) or real(v))
    for n in (100, 500, 1000):
        for value in ("a." * n + "-", "a-" * n + "!", "a" * n + ".com", "b" * 63 + "." * n):
            start = time.perf_counter()
            vs.value_shape(value)
            assert time.perf_counter() - start < 0.05
    for value in ("a." * 20_000 + "-", "a-" * 20_000 + "!"):     # past the cap: unscanned
        n = len(calls)
        start = time.perf_counter()
        assert vs.value_shape(value) is None
        assert time.perf_counter() - start < 0.01 and len(calls) == n


def _nested_quantifiers(module) -> list[str]:
    """Compiled patterns in ``module`` with a quantified group containing a quantifier."""
    bad = []
    for name, obj in vars(module).items():
        if isinstance(obj, re.Pattern) and re.search(r"\([^()]*[+*}][^()]*\)[+*{]",
                                                     obj.pattern):
            bad.append(name)
    return bad


def test_value_shape_patterns_have_no_nested_quantifiers():
    import types
    assert _nested_quantifiers(vs) == []
    synthetic = types.ModuleType("synthetic")
    synthetic.BAD = re.compile(r"(a+)+$")
    assert _nested_quantifiers(synthetic) == ["BAD"]


def test_fillers_never_have_an_injection_shape():
    for filler in [_TEXT_FILLER, *_FILLERS.values()]:
        assert vs.value_shape(filler) not in ("ip", "hostname", "filename", "path")
        assert is_filler(filler)
    assert not is_filler("fuzzlab ") and not is_filler("http://fuzzlab.invalid")  # exact


COMMANDI = ("<form method=post action='/app/commandi.php'><label for=target>DNS lookup"
            "</label><input id=target name=target value='www.nsa.gov'>"
            "<input name=note><button name=form value=submit>Lookup</button></form>")
RLFI = ("<form method=get action='/app/rlfi.php'><select name=language>"
        "<option value='lang_en.php'>English</option><option value='lang_fr.php'>French"
        "</option></select><button name=action value=go>Go</button></form>")


def test_example_flows_from_crawl_to_point_and_rule(tmp_path):
    store, run, _c = _import(tmp_path, forms=[_rec(COMMANDI), _rec(RLFI)])
    with store:
        pts = injection_points_from_store(store, run, "http://h/app/")
        by = {p.param: p for p in pts}
        assert by["target"].value_shapes == {"hostname"}
        assert by["target"].base_value == vs.SAFE_HOST
        assert by["language"].value_shapes == {"filename"} and by["language"].base_value is None
        evaluate(pts, store, run)
        rules = {(e["param"], e["rule_id"]) for e in (json.loads(r["evidence"]) for r in
                 store.conn.execute("SELECT evidence FROM candidate WHERE run_id=?", (run,)))}
    assert ("target", "R-COMMAND-INJECTION-VALUE") in rules
    assert ("language", "R-FILE-INCLUSION-VALUE") in rules


def test_name_and_value_rule_on_one_point_confirm_once(tmp_path):
    """PA-0073: a `host` field defaulting to a host name fires both command-injection
    rules; the oracle confirms its key once."""
    from fuzzlab.harness.pipeline import run_pipeline
    from fuzzlab.core.runmode import resolve_run
    point = InjectionPoint(url="http://h/n.php", param="host", origin="crawl",
                           value_shapes=frozenset({"hostname"}), base_value=vs.SAFE_HOST)
    calls = []
    app = _App(lambda req: calls.append(req) or _ok())
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        plan = resolve_run("manual", selected_categories=["command-injection"],
                           all_categories=["command-injection"])
        run_pipeline([point], store, run, app, plan)
        rows = store.conn.execute("SELECT evidence FROM candidate WHERE run_id=?",
                                  (run,)).fetchall()
    assert {json.loads(r["evidence"])["rule_id"] for r in rows} == {
        "R-COMMAND-INJECTION", "R-COMMAND-INJECTION-VALUE"}
    from fuzzlab.oracle.strategies import _CMDI_TIMING_TEMPLATES, CommandInjectionStrategy
    one = CommandInjectionStrategy.baseline_samples + len(_CMDI_TIMING_TEMPLATES)
    assert len(calls) == 1 + one                  # the fingerprint probe + one confirmation


@pytest.mark.parametrize("when,why", [
    ({"value_shap_in": ["ip"]}, "unknown 'when' key"),
    ({"value_shape_in": ["hostnames"]}, "unknown value"),
    ({"origin_in": ["spider"]}, "unknown value"),
    ({"location_in": "query"}, "list of strings"),
    ({"name_regex": "(a"}, "does not compile"),
])
def test_unknown_when_keys_and_values_are_rejected(tmp_path, when, why):
    rules = {"version": 1, "rules": [{"id": "R-X", "category": "xss",
                                      "transaction_type": "t", "when": when}]}
    (tmp_path / "r.json").write_text(json.dumps(rules))
    with pytest.raises(RuleError, match=why):
        load_rules(tmp_path / "r.json")
    for rule in load_rules():
        validate_rule(rule)                                    # the bundled file loads


def test_an_invalid_plugin_rule_is_left_out_and_counted(tmp_path, capsys):
    from fuzzlab.plugins import PluginManager

    class RulePlugin:
        name = "rules"

        def register_rules(self):
            return [Rule(id="ok", category="xss", transaction_type="t",
                         when={"always": True}),
                    Rule(id="typo", category="xss", transaction_type="t",
                         when={"alway": True}), "not-a-rule"]
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        counts = evaluate([InjectionPoint("http://h/p.php", "id")], store, run, rules=[],
                          plugins=PluginManager(plugins=[RulePlugin()]))
    assert counts["candidate"] == 1 and counts["invalid_plugin_rules"] == 2
    # ... and it reaches the run's metrics, its run_metrics row and the summary
    from fuzzlab.core.runmode import resolve_run
    from fuzzlab.harness import auto_cli
    from fuzzlab.harness.pipeline import run_pipeline
    with Store(tmp_path / "v.db") as store:
        run = store.start_run("auto", "h")
        plan = resolve_run("manual", selected_categories=["xss"], all_categories=["xss"])
        result = run_pipeline([InjectionPoint("http://h/p.php", "id")], store, run,
                              _App(lambda req: _ok()), plan,
                              plugins=PluginManager(plugins=[RulePlugin()]))
        row = store.conn.execute("SELECT value FROM run_metrics WHERE run_id=? AND "
                                 "key='pipeline_invalid_plugin_rules'", (run,)).fetchone()
    assert result.metrics["invalid_plugin_rules"] == 2 and row["value"] == 2.0
    args = auto_cli.build_parser().parse_args(["--base-url", "http://h/", "--store", "x"])
    auto_cli._print_summary(args, {}, result)
    assert "plugin rules left out (invalid): 2" in capsys.readouterr().out


def _shell_app(lookups):
    """commandi-shaped: ``target`` goes to a shell (``nslookup <target>``); a ``; sleep
    d`` makes the response slow; ``language`` is include()d."""
    def handler(req):
        data = {**req["query"], **req["body"]}
        if req["path"].endswith("commandi.php") and "target" in data:
            command = data["target"]
            host = re.split(r"[;|&`$]", command, maxsplit=1)[0].strip()
            if host:
                lookups.append(host)
            m = re.search(r"sleep (\d+)", command)
            return Probe(200, "<html>Server: x</html>", elapsed=float(m.group(1)) if m
                         else 0.01)
        if req["path"].endswith("rlfi.php") and "/etc/passwd" in data.get("language", ""):
            return _ok("root:x:0:0:root:/root:/bin/bash")
        return _ok()
    return handler


def test_cmdi_timing_and_lfi_confirm_end_to_end(tmp_path):
    lookups = []
    app = _App(_shell_app(lookups))
    store, run, _c = _import(tmp_path, forms=[_rec(COMMANDI), _rec(RLFI)])
    with store:
        run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                 mode="manual", selected_categories=["command-injection", "file-inclusion"],
                 points_source="crawl")
        found = {(r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT param, vuln_class FROM finding WHERE run_id=?", (run,))}
    assert ("target", "command-injection") in found
    assert ("language", "file-inclusion") in found


def test_a_crawled_hostname_is_never_sent(tmp_path):
    """FR-AUD-20 / M2: the app's own host defaults (an ip/host field, a url sibling) are
    sent as loopback; our .invalid filler as is."""
    lookups = []
    app = _App(_shell_app(lookups))
    form = _rec("<form method=post action='/app/commandi.php'>"
                "<input name=target value='www.nsa.gov'>"
                "<input type=hidden name=ref value='http://itsecgames.example.org/'>"
                "<input type=url name=site><input name=note>"
                "<button name=form value=submit>Lookup</button></form>")
    store, run, _c = _import(tmp_path, forms=[form])
    with store:
        run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                 mode="manual", selected_categories=["command-injection", "xss",
                                                     "sql-injection"],
                 points_source="crawl")
        found = {(r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT param, vuln_class FROM finding WHERE run_id=?", (run,))}
    text = app.sent_text()
    assert ("target", "command-injection") in found
    sleeps = [r["value"] for r in app.requests if r["param"] == "target"
              and "sleep" in r["value"]]
    assert sleeps and all(v.startswith(vs.SAFE_HOST) for v in sleeps)   # base-value prefix
    assert "www.nsa.gov" not in text and "itsecgames" not in text
    assert "www.nsa.gov" not in lookups and set(lookups) <= {vs.SAFE_HOST, "1", "zqxm"} | {
        h for h in lookups if not vs.value_shape(h)}
    note = [r for r in app.requests if r["param"] == "note"]
    assert note and all(r["body"]["target"] == vs.SAFE_HOST
                        and r["body"]["ref"] == vs.SAFE_URL
                        and r["body"]["site"] == "http://fuzzlab.invalid/" for r in note)


def test_ground_truth_cmdi_probes_are_unchanged():
    from fuzzlab.oracle.strategies import _CMDI_TIMING_TEMPLATES, CommandInjectionStrategy
    app = _App(lambda req: _ok())
    CommandInjectionStrategy().confirm(Candidate(url="http://h/c.php", param="cmd"), app)
    sent = [r["value"] for r in app.requests]
    base = CommandInjectionStrategy.baseline_samples
    assert sent[:base] == ["1"] * base
    assert sent[base:] == [t.format(d=2) for t in _CMDI_TIMING_TEMPLATES]


def test_an_empty_field_inherits_the_shape_of_its_namesake(tmp_path):
    blind = ("<form method=post action='/app/commandi_blind.php'>"
             "<input name=target value=''><button name=form value=submit>Ping</button></form>")
    pts, _s, _c = _points(tmp_path, forms=[_rec(COMMANDI), _rec(blind)])
    blind_target = next(p for p in pts if p.url.endswith("commandi_blind.php")
                        and p.param == "target")
    assert blind_target.value_shapes == {"hostname"}
    assert blind_target.base_value == vs.SAFE_HOST


def test_a_real_example_is_never_overridden(tmp_path):
    other = ("<form method=post action='/app/other.php'>"
             "<input name=target value='plain words'><button>Go</button></form>")
    pts, _s, _c = _points(tmp_path, forms=[_rec(COMMANDI), _rec(other)])
    t = next(p for p in pts if p.url.endswith("other.php") and p.param == "target")
    assert t.value_shapes == frozenset() and t.base_value is None


def test_inheritance_is_a_single_query(tmp_path):
    forms = [_rec(f"<form method=post action='/app/f{i}.php'><input name=f{i % 7} "
                  f"value='{'h%d.example.com' % i if i % 3 else ''}'></form>")
             for i in range(200)]
    store, run, _c = _import(tmp_path, forms=forms)
    with store:
        statements = []
        store.conn.set_trace_callback(statements.append)
        pts = injection_points_from_store(store, run, "http://h/app/")
        store.conn.set_trace_callback(None)
    assert len(pts) == 200
    # one query reads the parameters (lane B's login-path lookup is a separate one)
    assert len([s for s in statements if s.lstrip().upper().startswith("SELECT")
                and "FROM parameter" in s]) == 1


# =========================================================================================
# (d) POST selector forms
# =========================================================================================
SQLI_13 = ("<form method=post action='/app/sqli_13.php'><select name=movie>"
           "<option value=1>G.I. Joe</option><option value=2>Iron Man</option></select>"
           "<button name=action value=go>Go</button></form>")


def test_a_post_selector_without_settings_words_becomes_a_point_with_siblings(tmp_path):
    pts, _s, counts = _points(tmp_path, forms=[_rec(SQLI_13)])
    (movie,) = pts
    assert (movie.param, movie.method, movie.location) == ("movie", "POST", "body")
    assert movie.base_entries == (("movie", "1"), ("action", "go"))
    assert counts["form"] == 1


@pytest.mark.parametrize("name", sorted(formnav.SETTINGS_WORDS) + [
    "per_page", "perPage", "per-page", "zz", "t", "tz"])
def test_settings_named_post_selectors_are_skipped(name):
    rec = _rec(f"<form method=post action='/app/p.php'><select name='{name}'>"
               "<option value=1>A</option></select><button name=go value=1>Go</button></form>")
    assert form_skip_reason(rec)


def test_get_selectors_ignore_settings_words(tmp_path):
    pts, _s, _c = _points(tmp_path, forms=[_rec(RLFI)])
    assert [p.param for p in pts] == ["language"]


def test_a_site_wide_post_picker_is_fuzzed_once(tmp_path):
    forms = [_rec(SQLI_13.replace("/app/sqli_13.php", f"/app/page{i}.php"),
                  page=f"http://h/app/page{i}.php") for i in range(3)]
    pts, _s, counts = _points(tmp_path, forms=forms)
    assert [p.url for p in pts] == ["http://h/app/page0.php"]
    assert counts["form_duplicate_selector"] == 2


def test_a_picker_seen_setting_a_cookie_is_not_fuzzed(tmp_path, monkeypatch):
    from tests.test_forms_phase1 import _Resp, _Site
    from fuzzlab.tools import spider as spider_mod
    chooser = ("<form method=post action='/app/portal.php'><select name=chooser>"
               "<option value=a>A</option><option value=b>B</option></select>"
               "<button name=go value=1>Go</button></form>")

    class Site(_Site):
        def get(self, url, timeout=None, allow_redirects=True, params=None):
            if url.endswith("portal.php"):
                return _Resp(200, "<html>" + chooser + "</html>", url=url)
            return super().get(url, timeout, allow_redirects, params)

        def post(self, url, data=None, allow_redirects=True, timeout=None):
            return _Resp(302, headers={"Location": "x.php", "Set-Cookie": "skin=b"})
    sp = spider_mod.LocalSpider("http://h/app/portal.php", max_depth=1,
                                db_name=str(tmp_path / "s.db"), engine="requests",
                                selector_forms=["chooser"])
    site = Site()
    sp.session = site
    monkeypatch.setattr(spider_mod.requests, "Session", lambda: site)
    sp.crawl()
    verdicts = dict(sqlite3.connect(tmp_path / "s.db").execute(
        "SELECT sig, verdict FROM selector_verdicts").fetchall())
    assert list(verdicts.values()) == ["settings"]
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        counts = import_spider(tmp_path / "s.db", store, run)
        assert injection_points_from_store(store, run, "http://h/app/") == []
    assert counts["form_skipped"] == 1


#: The six bWAPP bug-picker option labels Phase 1 already refused (measured offline over
#: all 159 options of the local build; the extended word set adds none), plus two that
#: must stay navigable. Inlined: no bWAPP file is copied (CC BY-NC-ND).
BWAPP_REFUSED_LABELS = [
    "Cross-Site Scripting - Reflected (phpMyAdmin)", "/ A5 - Security Misconfiguration /",
    "/ A7 - Missing Functional Level Access Control /", "phpMyAdmin BBCode Tag XSS",
    "A.I.M. - No-authentication Mode", "Unprotected Admin Portal"]
BWAPP_ALLOWED_LABELS = ["Evil 666 Fuzzing Page", "SQL Injection (POST/Select)",
                        "Don't Click (a synthetic contraction)"]


def test_bwapp_bug_picker_navigation_is_unchanged():
    assert all(formnav.option_refusal(str(i), label) for i, label in
               enumerate(BWAPP_REFUSED_LABELS))
    assert not any(formnav.option_refusal(str(i), label) for i, label in
                   enumerate(BWAPP_ALLOWED_LABELS))
    for name in ("bug", "form_bug", "form"):
        assert formnav.settings_word(name) is None
    assert formnav.settings_word("security_level") and formnav.settings_word(
        "form_security_level")


def test_page_alone_is_not_a_settings_word():
    assert formnav.settings_word("page") is None
    assert formnav.settings_word("Evil 666 Fuzzing Page") is None
    assert formnav.settings_word("Don't") is None
    assert formnav.settings_word("per_page") == "per_page"


def test_sqli_in_a_post_select_confirms_end_to_end(tmp_path):
    def handler(req):
        movie = req["body"].get("movie")
        if req["path"].endswith("sqli_13.php") and movie is not None and "'" in movie:
            return _ok("Error: You have an error in your SQL syntax; check the manual that "
                       "corresponds to your MySQL server version")
        return _ok()
    app = _App(handler)
    store, run, _c = _import(tmp_path, forms=[_rec(SQLI_13)])
    with store:
        run_auto(base_url="http://h/app/", store=store, run_id=run, sender=app,
                 mode="manual", selected_categories=["sql-injection"], points_source="crawl")
        found = {(r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT param, vuln_class FROM finding WHERE run_id=?", (run,))}
    assert ("movie", "sqli") in found


# =========================================================================================
# BUG-0115: a probe meant for one location is never sent at another
# =========================================================================================
def test_greybox_places_header_probes_in_headers():
    from fuzzlab.greybox.run import RequestsCorrelatingSender
    session = _FakeSession()
    sender = RequestsCorrelatingSender(session=session, id_factory=lambda: "cid")
    sender.send_correlated("http://h/a.php", "User-Agent", "<zq>", location="header")
    call = session.calls[0]
    assert call["headers"]["User-Agent"] == "<zq>" and "params" not in call
    from fuzzlab.oracle.probe import UnplaceableLocation
    with pytest.raises(UnplaceableLocation):
        sender.send_correlated("http://h/a.php", "p", "v", location="fragment")
    assert len(session.calls) == 1


def test_dom_xss_never_relocates_a_body_or_header_payload():
    from fuzzlab.oracle.strategies import DomXssStrategy
    runs = []

    class Executor:
        def run(self, request, token):
            runs.append(request)
            from fuzzlab.oracle.browser import ExecObservation
            return ExecObservation(False)
    strategy = DomXssStrategy(Executor())
    for location in ("body", "header"):
        cand = Candidate(url="http://h/a.php", param="p", method="POST", location=location,
                         category="xss")
        assert not strategy.applies(cand)
        assert strategy.confirm(cand, _App(lambda r: _ok())) is None
    assert runs == []
    assert strategy.applies(Candidate(url="http://h/a.php", param="p", category="xss"))


def test_the_browser_executor_refuses_an_unplaceable_location():
    """Checked before any browser starts, so it runs without Playwright."""
    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    ex = PlaywrightBrowserExecutor()
    assert not ex.run(ExecRequest(url="http://h/a", param="p", value="v",
                                  location="header"), "t").executed
    assert not ex.run(ExecRequest(url="http://h/a", store=StoreStep(
        url="http://h/s", param="p", value="v", location="header")), "t").executed


def test_no_ground_truth_dom_point_has_another_location():
    """BUG-0115 sweep, instance 5 (`points_from_ground_truth`'s DOM rewrite): unreachable
    today; this fails the day a contract adds one (PA-0054(3))."""
    from fuzzlab.labels import contract
    for gt in GT_DIRS:
        for gp in contract.load(str(gt)).points:
            dom = gp.client_only or (gp.rendering or "") == "js" or gp.location == "fragment"
            assert not dom or gp.location in ("query", "fragment"), (gt.name, gp)


def test_the_fingerprint_probe_goes_where_its_point_says():
    """BUG-0115 sweep, instance 6: the pipeline's baseline probe used to send any first
    point's parameter as a GET query (a header or POST field included)."""
    from fuzzlab.core.runmode import resolve_run
    from fuzzlab.harness.pipeline import run_pipeline
    header = InjectionPoint("http://h/a.php", "User-Agent", location="header", origin="crawl")
    body = InjectionPoint("http://h/b.php", "title", method="POST", location="body",
                          base_entries=(("title", "x"), ("form", "submit")))
    query = InjectionPoint("http://h/c.php", "id", base_entries=(("id", "7"), ("cat", "2")))
    plan = resolve_run("manual", selected_categories=["open-redirect"],
                       all_categories=["open-redirect"])        # no candidate fires
    for points, first in (([header, body, query], ("query", {"id": "1", "cat": "2"})),
                          ([header, body], ("body", {"title": "1", "form": "submit"}))):
        app = _App(lambda req: _ok())
        with Store(":memory:") as store:
            run = store.start_run("auto", "h")
            run_pipeline(points, store, run, app, plan)
            assert store.conn.execute("SELECT COUNT(*) c FROM target").fetchone()["c"] == 1
        req = app.requests[0]
        got = req["query"] if first[0] == "query" else req["body"]
        assert (req["location"], got) == first
    app = _App(lambda req: _ok())
    with Store(":memory:") as store:
        run = store.start_run("auto", "h")
        run_pipeline([header], store, run, app, plan)
        # still one target row (ML's same-target key, BUG-0104), unprobed (reviewer A, L2)
        rows = store.conn.execute("SELECT base_url, dbms, fingerprint FROM target").fetchall()
        assert [tuple(r) for r in rows] == [("http://h", None, None)]
        # so its rows keep their target for training and holdout sealing (reviewer B:
        # without it a sealed target's header-only run leaked into training, PA-0092)
        from fuzzlab.ml import holdout
        from fuzzlab.ml.dataset import target_of
        assert target_of(store, run) == "http://h"
        assert holdout._run_origins(store)[run] == "http://h:80"   # canonical origin
    assert app.requests == []                       # never fingerprinted through a header
