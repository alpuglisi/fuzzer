"""Audit defect 7 (BUG-0544): a stored value redaction blanked is evidence, never a replay
value (FR-FUZZ-67).

The importer records each stored sibling set's replay recipe (the page it came from and
the entries whose stored value is a placeholder, migration 25); before each send the
oracle's binder fetches that page on the probe's own session route and binds those
entries' current values, in memory only (D12). When it cannot, the test is inconclusive
with its reason, never a negative, and nothing is sent. A sibling naming a host outside
the lab is never sent and never replaced by a stand-in (FR-AUD-20).

Each test drives the real importer, point builder, pipeline and oracle; the target is a
fake behind the `Sender` seam, except one real loopback server for the anonymous
sender's session jar (PA-0130's `require_loopback`).
"""

from __future__ import annotations

import html
import itertools
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.runmode import RunPlan
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import injection_points_from_store
from fuzzlab.harness.pipeline import run_pipeline
from fuzzlab.oracle.probe import Probe
from tests.test_forms_phase2 import _App, _rec
from tests.test_json_points import _spider_db

APP = "http://h/app/"
_XSS = RunPlan(mode="manual", categories=["xss"], scored=False, source="manual")
_CSRF_FORM = ("<form method=post action='/app/do.php'><input type=hidden "
              "name=csrf_token value={token}><input name=q></form>")


class _Site:
    """A fake target behind the seam that can fetch (FR-FUZZ-67). ``pages`` maps a path
    to a function of a fresh counter giving its HTML; ``handler(req, site)`` answers a
    send. Every fetch and send is recorded in order (``events``)."""

    fetch_capable = True

    def __init__(self, pages, handler):
        self.pages, self.handler = pages, handler
        self.events: list[tuple[str, dict]] = []
        self.issued: list[str] = []
        self._n = itertools.count(1)

    def fetch(self, url, *, route_url):
        page = self.pages.get(urlsplit(url).path)
        self.events.append(("fetch", {"url": url, "route": route_url}))
        if page is None:
            return Probe(404, "<html>not found</html>")
        return Probe(200, page(self, next(self._n)))

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        body = {}
        if location == "query":
            query = dict(entries) if entries is not None else {**query, param: value}
        elif location == "body":
            body = dict(entries) if entries is not None else {param: value}
        req = dict(method=method, path=parts.path, query=query, body=body, param=param,
                   value=value, location=location)
        self.events.append(("send", req))
        return self.handler(req, self)

    def sends(self, path):
        return [r for kind, r in self.events if kind == "send" and r["path"] == path]


def _token_page(site, n):
    token = f"TOKEN-{n}-zq"
    site.issued.append(token)
    return f"<html><body>{_CSRF_FORM.format(token=token)}</body></html>"


def _token_checked_echo(req, site):
    """``/app/do.php`` reflects ``q`` raw only with the token issued last (a one-time
    token); otherwise it refuses the request before its handler runs."""
    if req["path"] != "/app/do.php":
        return Probe(200, "<html>ok</html>")
    if not site.issued or req["body"].get("csrf_token") != site.issued[-1]:
        return Probe(200, "<html>invalid token</html>")
    return Probe(200, f"<html><p>{req['body'].get('q', '')}</p></html>",
                 headers={"Content-Type": "text/html"})


def _run(tmp_path, sender, *, forms=(), pages=(), plan=_XSS):
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", requests=(), pages=pages, forms=forms)
    store = Store(tmp_path / "u.db")
    run = store.start_run("auto", "h")
    import_spider(tmp_path / "s.db", store, run)
    with store:
        points = injection_points_from_store(store, run, APP, skipped=[])
        result = run_pipeline(points, store, run, sender, plan)
        statuses = {r[0] for r in store.conn.execute(
            "SELECT oracle_status FROM candidate WHERE run_id=?", (run,))}
    return result, statuses, points


def _csrf_form(token="one-time"):
    return _rec(_CSRF_FORM.format(token=token), page="http://h/app/p.php")


# --- the reproduction: `csrf_token=one-time` stored blank ------------------------------
def test_the_stored_csrf_token_is_a_blank_placeholder_with_a_recipe(tmp_path):
    """What the store holds: the token blanked (PA-0100), and the recipe that names it
    and its page -- never its value (D12)."""
    from fuzzlab.tools.store_adapter import import_spider
    _spider_db(tmp_path / "s.db", requests=(), forms=[_csrf_form()])
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        import_spider(tmp_path / "s.db", store, run)
        (row,) = store.conn.execute("SELECT entries, source_page, fresh FROM form "
                                    "WHERE run_id=?", (run,)).fetchall()
    assert dict(json.loads(row["entries"]))["csrf_token"] == ""
    assert (row["source_page"], json.loads(row["fresh"])) == ("/app/p.php", ["csrf_token"])


def test_a_blanked_csrf_token_is_bound_fresh_before_each_send(tmp_path):
    """Each send of the form point carries the token its page issued just before it,
    never the stored blank; the vulnerability behind the token check is confirmed."""
    site = _Site({"/app/p.php": _token_page}, _token_checked_echo)
    result, _statuses, _points = _run(tmp_path, site, forms=[_csrf_form()])
    posts = site.sends("/app/do.php")
    assert posts and all(r["body"]["csrf_token"] for r in posts)
    for i, (kind, req) in enumerate(site.events):
        if kind == "send" and req["path"] == "/app/do.php":
            before = site.events[i - 1]
            assert before[0] == "fetch" and before[1]["url"] == "http://h/app/p.php"
            assert before[1]["route"] == "http://h/app/do.php"
    tokens = [r["body"]["csrf_token"] for r in posts]
    assert len(set(tokens)) == len(tokens)                       # fresh per send
    assert result.findings == 1


def test_a_token_that_cannot_be_fetched_is_inconclusive_never_negative(tmp_path):
    """The page no longer offers the form: nothing is sent, and the rows are
    inconclusive with the reason -- never `checked` (a negative)."""
    site = _Site({"/app/p.php": lambda s, n: "<html>no form</html>"}, _token_checked_echo)
    result, statuses, _points = _run(tmp_path, site, forms=[_csrf_form()])
    assert site.sends("/app/do.php") == []
    assert statuses == {"inconclusive"}
    assert result.findings == 0
    assert result.inconclusive and all("csrf_token" in i["reason"]
                                       and "no matching form" in i["reason"]
                                       for i in result.inconclusive)
    assert result.metrics.get("oracle_inconclusive_unbound")


def test_a_sender_that_cannot_fetch_never_sends_the_blank(tmp_path):
    """A sender without the fetch capability: the token cannot be rebuilt, so the test
    is inconclusive and the blank is never sent."""
    app = _App(lambda req: Probe(200, "<html>ok</html>"))
    result, statuses, _points = _run(tmp_path, app, forms=[_csrf_form()])
    assert [r for r in app.requests if r["path"] == "/app/do.php"] == []
    assert statuses == {"inconclusive"}
    assert all("cannot fetch" in i["reason"] for i in result.inconclusive)


def test_no_fresh_value_reaches_the_store(tmp_path):
    """D12: the tokens the binder bound live in memory only -- no table, trace event
    included, holds one."""
    site = _Site({"/app/p.php": _token_page}, _token_checked_echo)
    _run(tmp_path, site, forms=[_csrf_form()])
    assert site.issued
    with Store(tmp_path / "u.db") as store:
        tables = [r[0] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        dump = json.dumps([[list(r) for r in store.conn.execute(f'SELECT * FROM "{t}"')]
                           for t in tables], default=str)
    assert "TOKEN-" not in dump


def test_the_fingerprint_baseline_never_sends_a_placeholder(tmp_path):
    """The pipeline's baseline probe skips a point that needs a fresh binding."""
    site = _Site({"/app/p.php": _token_page}, _token_checked_echo)
    _run(tmp_path, site, forms=[_csrf_form()])
    assert all(r["body"].get("csrf_token") for r in site.sends("/app/do.php"))


# --- identifier-like siblings: bound from the page the link was found on ---------------
_UUID = "550e8400-e29b-41d4-a716-446655440000"


def _link_page(site, n):
    fresh = f"6ba7b810-9dad-11d1-80b4-00c04fd430c{n % 10}"
    site.issued.append(fresh)
    return f"<html><a href='/app/item.php?op=view&id={fresh}'>item</a></html>"


def test_a_blanked_identifier_sibling_is_bound_from_its_links_page(tmp_path):
    """``?op=view&id=<uuid>``: the id is blanked in storage (PA-0100) and was sent blank;
    now each send of ``op`` carries the id the listing page links to at that moment."""
    from fuzzlab.tools.spider import StorageManager
    db = tmp_path / "s.db"
    _spider_db(db, requests=())
    sm = StorageManager(str(db))
    sm.mark_visited(APP + "list.php", 200, 0)
    sm.mark_visited(APP + f"item.php?op=view&id={_UUID}", 200, 1,
                    found_from=APP + "list.php")
    sm.close()

    def handler(req, site):
        if req["path"] != "/app/item.php" or req["query"].get("id") not in site.issued:
            return Probe(404, "<html>no such item</html>")
        return Probe(200, f"<html><p>{req['query'].get('op', '')}</p></html>",
                     headers={"Content-Type": "text/html"})

    site = _Site({"/app/list.php": _link_page}, handler)
    from fuzzlab.tools.store_adapter import import_spider
    store = Store(tmp_path / "u.db")
    run = store.start_run("auto", "h")
    import_spider(db, store, run)
    with store:
        points = injection_points_from_store(store, run, APP, skipped=[])
        result = run_pipeline(points, store, run, site, _XSS)
    op_sends = [r for r in site.sends("/app/item.php") if r["param"] == "op"]
    assert op_sends and all(r["query"]["id"] in site.issued for r in op_sends)
    assert not [r for r in site.sends("/app/item.php") if r["query"].get("id") == ""]
    assert result.findings >= 1


# --- a sibling naming a host: sent as the app gave it on loopback, never off it --------
@pytest.mark.parametrize("next_value, sent", [
    ("http://example.com/after", None),                  # outside the lab: never sent
    ("http://127.0.0.1:8080/after", "http://127.0.0.1:8080/after"),   # the lab itself
])
def test_a_sibling_naming_a_host_is_sent_as_given_on_loopback_and_never_off_it(
        tmp_path, next_value, sent):
    form = _rec("<form method=post action='/app/go.php'><input type=hidden name=next "
                f"value='{next_value}'><input name=q></form>", page="http://h/app/p.php")
    site = _Site({}, lambda req, s: Probe(200, f"<html>{html.escape(str(req))}</html>"))
    result, _statuses, _points = _run(tmp_path, site, forms=[form])
    q_posts = [r for r in site.sends("/app/go.php") if r["param"] == "q"]
    # ``next`` is a point too: its own probes replace it, so only ``q``'s carry it
    assert "example.com" not in json.dumps(site.events)
    if sent is None:
        assert q_posts == []
        (why,) = [i for i in result.inconclusive if i["param"] == "q"]
        assert why["mechanism"] == "unbound" and "next" in why["reason"] \
            and "outside the lab" in why["reason"]
    else:
        assert q_posts and {r["body"]["next"] for r in q_posts} == {sent}


# --- the page's session: carried into the one bound send, or the test is unbound ----------
class _SessionForm:
    """A loopback app whose CSRF token is tied to an anonymous session cookie set by the
    form page: ``/do`` answers 200 only with the cookie and that session's token.
    ``/noform`` sets a cookie and offers no form. ``/once`` sets no cookie; its token is
    accepted once. Every request's cookie is logged."""

    def __init__(self):
        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")                      # PA-0130
        self.tokens: dict[str, str] = {}
        self.answers: list[int] = []
        self.seen: list[tuple[str, str, str | None]] = []   # (method, target, cookie)
        self.once: set[str] = set()       # `/once` tokens: single-use, tied to no cookie
        counter = itertools.count(1)
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                app.seen.append(("GET", self.path, self.headers.get("Cookie")))
                n = next(counter)
                sid, token = f"s{n}", f"t{n}"
                app.tokens[sid] = token
                if self.path.startswith("/once"):
                    app.once.add(token)
                form = (f"<form method=post action='/do'><input type=hidden "
                        f"name=csrf_token value={token}><input name=q></form>")
                body = (form if self.path.startswith(("/form", "/once"))
                        else "<p>ok</p>").encode()
                self.send_response(200)
                if self.path.startswith(("/form", "/noform")):
                    self.send_header("Set-Cookie", f"sid={sid}; Path=/")
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                app.seen.append(("POST", self.path, self.headers.get("Cookie")))
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode(),
                                      keep_blank_values=True))
                cookie = (self.headers.get("Cookie") or "").removeprefix("sid=")
                ok = cookie in app.tokens and form.get("csrf_token") == app.tokens[cookie]
                if form.get("csrf_token") in app.once:          # single use
                    app.once.discard(form["csrf_token"])
                    ok = True
                status = 200 if ok else 403
                app.answers.append(status)
                self.send_response(status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _anonymous_sender(kind):
    from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender
    if kind == "requests":
        return RequestsProbeSender(timeout=5)
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    return SeamProbeSender(HttpClient(RequestBudget(100), ["127.0.0.1"], timeout=5))


def _csrf_candidate(base, page="/form"):
    from fuzzlab.oracle.probe import Candidate
    return Candidate(url=base + "/do", param="q", method="POST", location="body",
                     base_entries=(("csrf_token", ""), ("q", "x")),
                     bindings={"page": base + page, "fresh": ["csrf_token"]})


@pytest.mark.parametrize("kind", ["requests", "seam"])
def test_the_pages_session_is_carried_into_the_bound_send_only_or_the_test_is_unbound(kind):
    """Measured on a real socket: the token is valid only with the cookie its page set.
    The anonymous `RequestsProbeSender` carries that cookie into the bound send and no
    other. The authenticated seam's routes carry no response cookie (BUG-0544 review
    R2-B1): its fetch refuses such a page, so nothing is sent -- unbound, never a 403
    read as the handler's answer."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import PrerequisiteUnavailable
    site = _SessionForm()
    try:
        sender = _anonymous_sender(kind)
        bound = _FormBoundSender(sender, _csrf_candidate(site.base))
        if kind == "requests":
            for _ in range(2):
                bound.send(site.base + "/do", "q", "M", method="POST", location="body")
            sender.send(site.base + "/do", "q", "M", method="POST", location="body",
                        entries=[("csrf_token", "t1"), ("q", "M")])
        else:
            with pytest.raises(PrerequisiteUnavailable, match="sets a cookie"):
                bound.send(site.base + "/do", "q", "M", method="POST", location="body")
    finally:
        site.close()
    if kind == "requests":
        assert site.answers == [200, 200, 403]
    else:
        assert site.answers == [] and [m for m, _t, _c in site.seen] == ["GET"]


def test_a_refused_binding_never_lends_its_pages_cookie_to_another_probe():
    """BUG-0544 review B2: the page answers and sets a cookie, the binding is refused (no
    form); the next, unrelated anonymous probe carries no cookie (BUG-0112)."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import PrerequisiteUnavailable
    from fuzzlab.tools.probesender import RequestsProbeSender
    site = _SessionForm()
    try:
        sender = RequestsProbeSender(timeout=5)
        bound = _FormBoundSender(sender, _csrf_candidate(site.base, "/noform"))
        with pytest.raises(PrerequisiteUnavailable, match="no matching form"):
            bound.send(site.base + "/do", "q", "M", method="POST", location="body")
        sender.send(site.base + "/other?x=1", "x", "payload")
        sender.send(site.base + "/do", "q", "M", method="POST", location="body",
                    entries=[("csrf_token", "t1"), ("q", "M")])
    finally:
        site.close()
    assert [(m, t.split("?")[0], c) for m, t, c in site.seen] == [
        ("GET", "/noform", None), ("GET", "/other", None), ("POST", "/do", None)]


def test_the_seams_page_fetch_goes_through_its_pooled_transport_on_the_probes_identity():
    """After POOL24 (FR-CORE-509), measured on a real socket: the seam's page fetch is a
    GET on the default pooled transport under the probe route's own pool key (origin,
    identity, generation), and the bound send (a body, so a session of its own) carries
    each fresh single-use token. No cookie reaches the target: the pool's jar keeps none."""
    from fuzzlab.core.http import PooledTransport
    from fuzzlab.core.urls import canonical_origin
    from fuzzlab.oracle.oracle import _FormBoundSender
    site = _SessionForm()
    try:
        sender = _anonymous_sender("seam")
        transport = sender._client._transport
        assert isinstance(transport, PooledTransport)
        bound = _FormBoundSender(sender, _csrf_candidate(site.base, "/once"))
        for _ in range(2):
            bound.send(site.base + "/do", "q", "M", method="POST", location="body")
        keys = list(transport._entries)
    finally:
        site.close()
    assert site.answers == [200, 200]
    assert [(m, t, c) for m, t, c in site.seen] == [
        ("GET", "/once", None), ("POST", "/do", None)] * 2
    assert keys == [(canonical_origin(site.base), "anonymous", None)]


# --- the source page never stores, nor puts on the wire, a target's value (review B1) ---
_SECRET = "SECRETKEY123zq"


def test_a_source_page_holding_a_secret_or_an_identifier_is_never_stored(tmp_path):
    """A disco Referer with a sensitive-named and an identifier-like query value, and a
    crawl's ``found_from`` with an identifier: neither value reaches any table (candidate
    evidence included; `page` and `parameter.example` hold crawled URLs and examples by
    design, BUG-0120); such a set has no page, so its test is inconclusive (PA-0100)."""
    from fuzzlab.audit import evaluate
    from fuzzlab.disco.capture import append_record, make_record
    from fuzzlab.tools import store_adapter
    from fuzzlab.tools.spider import StorageManager
    referer = f"http://127.0.0.1:3000/acct?api_key={_SECRET}&ref={_UUID}"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    append_record(run_dir / "capture.jsonl", make_record(
        kind="http", t=1.0, action_id="act-1", method="POST",
        url="http://127.0.0.1:3000/do",
        req_headers={"Content-Type": store_adapter.FORM_URLENCODED, "Referer": referer},
        req_body=b"csrf_token=one-time&q=hello", status=200,
        res_headers={"Content-Type": "text/html"}, res_body=b"ok"))
    (run_dir / "actions.jsonl").write_text("")
    hexed = "0123456789abcdef0123456789abcdef"
    db = tmp_path / "s.db"
    _spider_db(db, requests=())
    sm = StorageManager(str(db))
    sm.mark_visited(APP + "item.php?op=view&id=7", 200, 1,
                    found_from=APP + f"list.php?u=bob&t={hexed}")
    sm.close()
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        store_adapter.import_disco(run_dir, store, run)
        run2 = store.start_run("auto", "h")
        store_adapter.import_spider(db, store, run2)
        for r, base in ((run, "http://127.0.0.1:3000/"), (run2, APP)):
            evaluate(injection_points_from_store(store, r, base, skipped=[]), store, r)
        dump = json.dumps([[list(row) for row in store.conn.execute(f'SELECT * FROM "{t}"')]
                           for (t,) in store.conn.execute(
                               "SELECT name FROM sqlite_master WHERE type='table' AND "
                               "name NOT IN ('page', 'parameter', 'trace_event', "
                               "'dg_entity', 'dg_flow', 'dg_evidence')")], default=str)
    assert _SECRET not in dump and _UUID not in dump and hexed not in dump


def test_a_page_whose_url_holds_a_redacted_value_is_never_fetched():
    """Defence in depth at the binder: a stored page carrying a redaction placeholder or a
    blanked value is never put on the wire; the test is unbound."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate, PrerequisiteUnavailable
    for page in ("http://h/app/p.php?token=__REDACTED__", "http://h/app/p.php?t=&u=bob"):
        site = _Site({"/app/p.php": _token_page}, _token_checked_echo)
        cand = Candidate(url="http://h/app/do.php", param="q", method="POST",
                         location="body", base_entries=(("csrf_token", ""), ("q", "x")),
                         bindings={"page": page, "fresh": ["csrf_token"]})
        with pytest.raises(PrerequisiteUnavailable, match="redacted"):
            _FormBoundSender(site, cand).send("http://h/app/do.php", "q", "M",
                                              method="POST", location="body")
        assert site.events == []


# --- FR-AUD-20, fail closed (review B3) --------------------------------------------------
@pytest.mark.parametrize("value", [
    "127.0.0.1:80@evil.example/",
    "localhost:1@evil.example",
    "http://evil.example\\@127.0.0.1/",
    "http://127.0.0.1:8080/r?next=http://evil.example/",
])
def test_a_value_that_names_a_host_beyond_loopback_to_any_reader_is_outside_the_lab(value):
    from fuzzlab.audit.value_shape import names_outside_lab
    from fuzzlab.harness.auto import _send_value
    assert names_outside_lab(value)
    assert _send_value(value) != value                  # never sent as given


@pytest.mark.parametrize("value", ["http://127.0.0.1:8080/after", "http://localhost:3/x?a=1",
                                   "http://[::1]:80/x"])
def test_a_value_naming_only_loopback_is_the_lab(value):
    from fuzzlab.audit.value_shape import names_outside_lab
    assert not names_outside_lab(value)


# --- every send of the candidate's own request is bound or refused (review B4) -----------
def test_a_json_point_needing_a_fresh_leaf_sends_nothing_and_is_unbound(tmp_path):
    """A captured JSON body with a redacted identifier leaf: no page holds it, so no
    mechanism may send -- NoSqlOperatorStrategy's own-body sends included."""
    from fuzzlab.tools.store_adapter import import_spider
    from tests.test_json_points import _req
    _spider_db(tmp_path / "s.db", requests=[_req(
        APP + "api/search", {"productId": _UUID, "q": "shoes"}, page=APP + "shop")])
    site = _Site({"/app/shop": lambda s, n: "<html></html>"},
                 lambda req, s: Probe(200, "<html>no such product</html>"))
    store = Store(tmp_path / "u.db")
    run = store.start_run("auto", "h")
    import_spider(tmp_path / "s.db", store, run)
    with store:
        points = injection_points_from_store(store, run, APP, skipped=[])
        result = run_pipeline(points, store, run, site,
                              RunPlan(mode="manual", categories=["nosql-injection"],
                                      scored=False, source="manual"))
        statuses = {r[0] for r in store.conn.execute(
            "SELECT oracle_status FROM candidate WHERE run_id=?", (run,))}
    assert site.sends("/app/api/search") == []
    assert statuses == {"inconclusive"} and result.findings == 0
    assert result.inconclusive and all(i["mechanism"] == "unbound"
                                       for i in result.inconclusive)


def test_the_binder_refuses_a_raw_or_built_send_to_its_own_request():
    """A strategy sending the candidate's own URL and method with its own body (a
    content type, entries it built) never bypasses the fresh binding."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate, PrerequisiteUnavailable
    site = _Site({"/app/p.php": _token_page}, _token_checked_echo)
    cand = Candidate(url="http://h/app/do.php", param="q", method="POST", location="body",
                     base_entries=(("csrf_token", ""), ("q", "x")),
                     bindings={"page": "http://h/app/p.php", "fresh": ["csrf_token"]})
    bound = _FormBoundSender(site, cand)
    for kw in ({"content_type": "application/json"},
               {"entries": [("csrf_token", ""), ("q", "M")]}):
        with pytest.raises(PrerequisiteUnavailable):
            bound.send("http://h/app/do.php", "q", "M", method="POST", location="body",
                       **kw)
    assert site.sends("/app/do.php") == []


# --- the seam fetches a page only on the session its probe carries (review B5, B6) -------
class _FakeManager:
    def __init__(self, auth):
        self.auth = auth

    def ensure(self, *a, **k):
        pass

    def is_auth_endpoint(self, url):
        return urlsplit(url).path in self.auth


class _Recording:
    def __init__(self):
        self.sent = []

    def send(self, req):
        self.sent.append(req.url)
        raise AssertionError("nothing may be sent")


@pytest.mark.parametrize("gate", ["auth endpoint", "isolated path"])
def test_the_seam_never_fetches_a_login_page_with_the_runs_session(gate):
    from fuzzlab.oracle.probe import PrerequisiteUnavailable
    from fuzzlab.tools.probesender import SeamProbeSender
    client = _Recording()
    sender = SeamProbeSender(client, identity="alice",
                             manager=_FakeManager({"/app/login.php"} if gate ==
                                                  "auth endpoint" else set()))
    if gate == "isolated path":
        sender.isolate(["http://h/app/login.php"])
    with pytest.raises(PrerequisiteUnavailable, match=gate):
        sender.fetch("http://h/app/login.php", route_url="http://h/app/item.php")
    assert client.sent == []


def test_a_source_page_on_another_origin_is_never_bound(tmp_path):
    """A form found on :4000 that posts to the run's :3000: the token is another
    origin's session's, so there is no page and the test is unbound; and the binder
    refuses a page whose fetch went without the probe's session."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate, PrerequisiteUnavailable
    from fuzzlab.tools.store_adapter import import_spider
    form = _rec("<form method=post action='http://127.0.0.1:3000/do'><input type=hidden "
                "name=csrf_token value=x><input name=q></form>",
                page="http://127.0.0.1:4000/page")
    _spider_db(tmp_path / "s.db", requests=(), forms=[form])
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        import_spider(tmp_path / "s.db", store, run, base_url="http://127.0.0.1:3000/")
        (q,) = [p for p in injection_points_from_store(store, run, "http://127.0.0.1:3000/",
                                                       skipped=[]) if p.param == "q"]
    assert q.bindings == (None, ("csrf_token",))

    class _OutOfOrigin(_Site):
        def fetch(self, url, *, route_url):
            page = super().fetch(url, route_url=route_url)
            page.session = "anonymous (out of origin)"
            return page
    site = _OutOfOrigin({"/app/p.php": _token_page}, _token_checked_echo)
    cand = Candidate(url="http://h/app/do.php", param="q", method="POST", location="body",
                     base_entries=(("csrf_token", ""), ("q", "x")),
                     bindings={"page": "http://h/app/p.php", "fresh": ["csrf_token"]})
    with pytest.raises(PrerequisiteUnavailable, match="without the probe's session"):
        _FormBoundSender(site, cand).send("http://h/app/do.php", "q", "M", method="POST",
                                          location="body")
    assert site.sends("/app/do.php") == []
