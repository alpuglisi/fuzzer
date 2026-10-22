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
from pathlib import Path
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


# --- the bound send takes the route its page was fetched on, or is unbound (review R2-2) --
class _CookieBoundForm:
    """A loopback app whose CSRF token is tied to the session cookie the form page's
    request carries (with none, the page sets a new one); ``POST /do`` reflects ``q`` raw
    only past the cookie-and-token check, else 403. Every request is logged."""

    def __init__(self):
        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")                      # PA-0130
        self.tokens: dict[str, str] = {}
        self.seen: list[tuple[str, str, str | None]] = []   # (method, path, cookie)
        counter = itertools.count(1)
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self, status, body, cookie=None):
                self.send_response(status)
                if cookie:
                    self.send_header("Set-Cookie", f"sid={cookie}; Path=/")
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                cookie = self.headers.get("Cookie")
                app.seen.append(("GET", self.path, cookie))
                n = next(counter)
                sid, new = ((cookie.removeprefix("sid="), None) if cookie
                            else (f"s{n}", f"s{n}"))
                app.tokens[sid] = f"t{n}"
                self._answer(200, (f"<html><body><form method=post action='/do'><input "
                                   f"type=hidden name=csrf_token value=t{n}><input "
                                   "name=q></form></body></html>").encode(), new)

            def do_POST(self):
                cookie = self.headers.get("Cookie")
                app.seen.append(("POST", self.path, cookie))
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode(),
                                      keep_blank_values=True))
                sid = (cookie or "").removeprefix("sid=")
                if sid not in app.tokens or form.get("csrf_token") != app.tokens[sid]:
                    self._answer(403, b"<html>invalid token</html>")
                    return
                self._answer(200, f"<html><body><p>{form.get('q', '')}</p></body></html>"
                             .encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _CopySession:
    """An isolated copy's session (FR-FUZZ-44) as its client's session addon: each
    login gives it a new cookie and the next session generation; ``logged_out`` is a
    probe having logged it out, so its next request logs in again first and records the
    generation it applied (as `SessionManager.prepare` does)."""

    label = "alice (isolated 1)"

    def __init__(self):
        self.logins, self.logged_out, self.sid = 0, False, None

    def login_attempts(self):
        return self.logins

    def ensure(self, *a, **k):
        self.logins += 1
        self.sid, self.logged_out = f"copy{self.logins}", False

    def prepare(self, request, identity):
        if self.logged_out:
            self.ensure()
        request.headers = {**request.headers, "Cookie": f"sid={self.sid}"}
        request.session_generation = self.logins

    def observe(self, request, response, identity):
        pass


class _RunSession:
    """The run's session manager, as far as the seam's isolation reads it: ``alive`` is
    what `verify_live` answers after a copy login (False: a single-session app)."""

    def __init__(self, copy):
        self.copy, self.alive, self.released = copy, True, []

    def ensure(self, *a, **k):
        pass

    def is_auth_endpoint(self, url):
        return False

    def add_logout_listener(self, listener):
        pass

    def isolated_copy(self, identity, *, ordinal):
        return self.copy

    def release_copy(self, manager):
        self.released.append(manager)

    def verify_live(self, host, identity, base):
        return self.alive


def test_a_bound_send_never_leaves_on_another_route_than_its_pages_fetch():
    """Review R2-2 (its N3 path), on a real socket: ``/do`` is an isolated path, so its
    page is fetched on the path's copy and the token is the copy cookie's. A probe logged
    the copy out; the fetch's re-login logs the run's session out (a single-session app),
    so `_on_copy`'s verify trips the breaker during the fetch and the path goes
    anonymous. The bound send would leave without the copy's cookie and be refused
    before the handler (403, read as a negative): it is not sent, and the test is unbound."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.oracle.oracle import UNBOUND, Oracle
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    from fuzzlab.tools.probesender import SeamProbeSender
    app = _CookieBoundForm()
    copy = _CopySession()
    run = _RunSession(copy)
    try:
        sender = SeamProbeSender(
            HttpClient(RequestBudget(200), ["127.0.0.1"], timeout=5), identity="alice",
            manager=run, isolated_client=lambda m: HttpClient(
                RequestBudget(200), ["127.0.0.1"], session=m, timeout=5))
        sender.isolate([app.base + "/do"])
        cand = Candidate(url=app.base + "/do", param="q", method="POST", location="body",
                         category="xss", base_entries=(("csrf_token", ""), ("q", "x")),
                         bindings={"page": app.base + "/form", "fresh": ["csrf_token"]})
        oracle = Oracle(strategies=[ReflectedXssStrategy()])
        control, _ = oracle.confirm_outcome(cand, sender)    # the copy's route holds
        before = len(app.seen)
        copy.logged_out, run.alive = True, False
        verdict, unsure = oracle.confirm_outcome(cand, sender)
    finally:
        app.close()
    assert control is not None and control.confirmed
    assert all(c == "sid=copy1" for _m, _p, c in app.seen[:before])
    assert sender.isolation_report()["breaker"]["trip"] == "single-session"
    assert app.seen[before:] == [("GET", "/form", "sid=copy2")]     # no POST went out
    assert verdict is None and unsure is not None and unsure.mechanism == UNBOUND
    assert "route" in unsure.evidence["reason"]


# --- the bound send keeps its fetch's session generation, or is unbound (review R3-2) ------
class _BetweenFetchAndSend:
    """A sender wrapper that runs ``between()`` once, after the next page fetch has
    returned and before the bound send that carries it: what a time expiry, a pause or
    another worker's send can do to the session in that window."""

    fetch_capable = True

    def __init__(self, inner):
        self._inner, self.between = inner, None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def fetch(self, url, *, route_url):
        page = self._inner.fetch(url, route_url=route_url)
        between, self.between = self.between, None
        if between is not None:
            between()
        return page

    def send(self, *a, **k):
        return self._inner.send(*a, **k)


def test_a_bound_send_on_a_copy_relogged_in_after_its_fetch_is_unbound_and_verified():
    """Review R3-2 on an isolated copy: the page is fetched on the copy's first session
    (generation 1); the copy is then logged out, so the bound send's ``prepare`` logs it
    in again (generation 2) and the token is the old session's. That answer (403) is
    never read as a negative: the test is unbound. The copy's re-login is still
    verified, so a single-session app trips the breaker."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.oracle.oracle import UNBOUND, Oracle
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    from fuzzlab.tools.probesender import SeamProbeSender
    app = _CookieBoundForm()
    copy = _CopySession()
    run = _RunSession(copy)
    try:
        seam = SeamProbeSender(
            HttpClient(RequestBudget(200), ["127.0.0.1"], timeout=5), identity="alice",
            manager=run, isolated_client=lambda m: HttpClient(
                RequestBudget(200), ["127.0.0.1"], session=m, timeout=5))
        seam.isolate([app.base + "/do"])
        sender = _BetweenFetchAndSend(seam)
        cand = Candidate(url=app.base + "/do", param="q", method="POST", location="body",
                         category="xss", base_entries=(("csrf_token", ""), ("q", "x")),
                         bindings={"page": app.base + "/form", "fresh": ["csrf_token"]})
        oracle = Oracle(strategies=[ReflectedXssStrategy()])
        control, _ = oracle.confirm_outcome(cand, sender)
        before = len(app.seen)

        def lose_the_copy():
            copy.logged_out, run.alive = True, False
        sender.between = lose_the_copy
        verdict, unsure = oracle.confirm_outcome(cand, sender)
    finally:
        app.close()
    assert control is not None and control.confirmed
    assert app.seen[before:][0] == ("GET", "/form", "sid=copy1")
    assert verdict is None and unsure is not None and unsure.mechanism == UNBOUND
    assert "generation" in unsure.evidence["reason"]
    assert seam.isolation_report()["breaker"]["trip"] == "single-session"


class _PhpLikeApp:
    """A PHP-like loopback app (review R3-2's real-SessionManager path). A session id is
    kept after its user is logged out, and its pages then show the login box next to
    their own content; a login regenerates the id. ``GET /`` is the welcome page or the
    login page; ``GET /form``'s CSRF token is tied to the id the request carries;
    ``POST /do`` reflects ``q`` raw only for a logged-in id with that id's current
    token, else 403. Every request is logged as ``(method, path, sid)``."""

    def __init__(self):
        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")                      # PA-0130
        self.users: dict[str, str | None] = {}             # sid -> user (None: logged out)
        self.tokens: dict[str, str] = {}
        self.seen: list[tuple[str, str, str | None]] = []
        self._n = itertools.count(1)
        self._lock = threading.Lock()
        #: residual N-R3-2: the next logged-in ``GET /`` rotates the id once (the old id
        #: stays valid; its tokens do not move to the new one)
        self.rotate_on_root = False
        app = self
        login_box = ("<form method=post action='/login'><input name=username>"
                     "<input type=password name=password>"
                     "<input type=submit value=Login></form>")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _sid(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    name, _sep, value = part.strip().partition("=")
                    if name == "sid":
                        return value
                return None

            def _answer(self, status, body, headers=()):
                body = body.encode()
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _session(self):
                """``(sid, user, set_cookie headers)``: PHP's session_start()."""
                sid = self._sid()
                with app._lock:
                    if sid in app.users:
                        return sid, app.users[sid], []
                    sid = f"s{next(app._n)}"
                    app.users[sid] = None
                return sid, None, [("Set-Cookie", f"sid={sid}; Path=/")]

            def do_GET(self):  # noqa: N802 - http.server API
                path = urlsplit(self.path).path
                app.seen.append(("GET", path, self._sid()))
                sid, user, cookie = self._session()
                if path == "/" and user and app.rotate_on_root:
                    with app._lock:
                        app.rotate_on_root = False
                        new = f"s{next(app._n)}"
                        app.users[new] = user
                    cookie = [("Set-Cookie", f"sid={new}; Path=/")]
                if path == "/":
                    return self._answer(200, f"<h1>Welcome {user}</h1>" if user
                                        else f"<html><body>{login_box}</body></html>", cookie)
                if path == "/form":
                    with app._lock:
                        token = app.tokens[sid] = f"tok{next(app._n)}"
                    form = ("<form method=post action='/do'><input type=hidden "
                            f"name=csrf_token value={token}><input name=q></form>")
                    return self._answer(200, f"<html><body>{form}"
                                        f"{'' if user else login_box}</body></html>", cookie)
                return self._answer(404, "not found", cookie)

            def do_POST(self):  # noqa: N802 - http.server API
                path = urlsplit(self.path).path
                app.seen.append(("POST", path, self._sid()))
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode(),
                                      keep_blank_values=True))
                sid, user, cookie = self._session()
                if path == "/login":
                    if (form.get("username"), form.get("password")) != ("alice", "pw-0544"):
                        return self._answer(200, f"<html><body>{login_box}</body></html>",
                                            cookie)
                    with app._lock:
                        app.users.pop(sid, None)                 # the id is regenerated
                        new = f"s{next(app._n)}"
                        app.users[new] = "alice"
                    return self._answer(302, "", [("Location", "/"),
                                                  ("Set-Cookie", f"sid={new}; Path=/")])
                if path == "/do":
                    with app._lock:
                        good = user is not None and form.get("csrf_token") == \
                            app.tokens.get(sid)
                    if not good:
                        return self._answer(403, "<html>invalid token</html>", cookie)
                    return self._answer(200, f"<html><body><p>{form.get('q', '')}</p>"
                                        "</body></html>", cookie)
                return self._answer(404, "not found", cookie)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def log_everyone_out(self):
        """Server-side logout of every id, the ids kept (as a probe could do without the
        session manager noticing)."""
        with self._lock:
            for sid in self.users:
                self.users[sid] = None

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _php_seam(app):
    """The real `SessionManager` (requests login, no browser; credentials in memory, D12),
    a real `HttpClient` on it and the seam for ``alice``."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.core.http import HttpClient
    from fuzzlab.session.manager import SessionManager
    from fuzzlab.tools.probesender import SeamProbeSender
    from tests.test_credentials import FakeBackend
    creds = CredentialStore(backend=FakeBackend())
    creds.set("127.0.0.1", "alice", "alice", "pw-0544")
    mgr = SessionManager(creds, scope_hosts=["127.0.0.1"], browser_login=False)
    client = HttpClient(RequestBudget(500), ["127.0.0.1"], session=mgr, timeout=5)
    return SeamProbeSender(client, "alice", manager=mgr, base_url=app.base + "/"), client


def _php_candidate(app):
    from fuzzlab.oracle.probe import Candidate
    return Candidate(url=app.base + "/do", param="q", method="POST", location="body",
                     category="xss", base_entries=(("csrf_token", ""), ("q", "x")),
                     bindings={"page": app.base + "/form", "fresh": ["csrf_token"]})


def test_a_page_whose_own_answer_lost_the_session_is_never_bound_on_the_next_login():
    """Review R3-2, the checker's path on the real `SessionManager`: the session was
    logged out server-side, the id kept. The page fetch goes out on it and its answer
    shows the login box next to the form, so the manager marks the session lost on that
    very answer (its ``prepare`` flag on the fetch is still False). At 3959dfc the bound
    send's ``prepare`` logged in again (a new id) and posted the old id's token: a 403,
    read as a negative. Now nothing is sent after the page and the test is unbound."""
    from fuzzlab.oracle.oracle import UNBOUND, Oracle
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    app = _PhpLikeApp()
    try:
        sender, _client = _php_seam(app)
        cand = _php_candidate(app)
        oracle = Oracle(strategies=[ReflectedXssStrategy()])
        control, _ = oracle.confirm_outcome(cand, sender)
        app.log_everyone_out()
        before = len(app.seen)
        verdict, unsure = oracle.confirm_outcome(cand, sender)
    finally:
        app.close()
    assert control is not None and control.confirmed
    after = app.seen[before:]
    assert after[0][:2] == ("GET", "/form")
    assert [r for r in after if r[1] in ("/do", "/login")] == []   # no re-login, no POST
    assert verdict is None and unsure is not None and unsure.mechanism == UNBOUND
    assert "lost" in unsure.evidence["reason"]


def test_a_bound_send_on_a_session_relogged_in_after_its_fetch_is_unbound():
    """Review R3-2, the generation half, on the real `SessionManager`: the page is
    fetched on a live session (its answer shows no loss); before the bound send, another
    send sees the session lost, so the bound send's ``prepare`` logs in again and applies
    a new generation. At 7393c90 that send went out (the old id's token on the new id:
    403) and only its answer was left unread (a stated residual); since BUG-0557 its own
    ``prepare`` refuses the new session material before anything is sent: no POST, and
    the test is unbound."""
    from fuzzlab.core.http import Request
    from fuzzlab.oracle.oracle import UNBOUND, Oracle
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    app = _PhpLikeApp()
    try:
        seam, client = _php_seam(app)
        sender = _BetweenFetchAndSend(seam)
        cand = _php_candidate(app)
        oracle = Oracle(strategies=[ReflectedXssStrategy()])
        control, _ = oracle.confirm_outcome(cand, sender)

        def lose_the_session():
            app.log_everyone_out()
            client.send(Request("GET", app.base + "/form", identity="alice"))
        sender.between = lose_the_session
        before = len(app.seen)
        verdict, unsure = oracle.confirm_outcome(cand, sender)
    finally:
        app.close()
    assert control is not None and control.confirmed
    fetched = app.seen[before]
    posts = [r for r in app.seen[before:] if r[:2] == ("POST", "/do")]
    assert fetched[:2] == ("GET", "/form")
    assert any(r[:2] == ("POST", "/login") for r in app.seen[before:])   # logged in again
    assert posts == []                       # BUG-0557: refused before it was sent
    assert verdict is None and unsure is not None and unsure.mechanism == UNBOUND
    assert "generation" in unsure.evidence["reason"]


def test_a_live_health_check_that_adopts_a_rotated_cookie_after_the_fetch_unbinds_the_send():
    """BUG-0544 residual N-R3-2 (BUG-0557), on the real `SessionManager`: the page is
    fetched on a live session; before the bound send, a health check (`verify_live`,
    which `_verify_main` runs after any copy login or re-login) answers LIVE and the app
    rotates its id on it. The manager adopts the new id in the same generation, so at
    7393c90 the bound send carried the token minted for the old id on the new one and
    its 403 was read as a negative (pinned by a strict xfail). Now the send's own
    ``prepare`` sees other session material than its fetch's and refuses it before
    anything is sent: no POST, and the test is unbound."""
    from fuzzlab.oracle.oracle import UNBOUND, Oracle
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    app = _PhpLikeApp()
    try:
        seam, _client = _php_seam(app)
        sender = _BetweenFetchAndSend(seam)
        cand = _php_candidate(app)
        oracle = Oracle(strategies=[ReflectedXssStrategy()])
        control, _ = oracle.confirm_outcome(cand, sender)

        def a_live_check_adopts_a_rotation():
            app.rotate_on_root = True
            assert seam._manager.verify_live("127.0.0.1", "alice", app.base + "/")
        sender.between = a_live_check_adopts_a_rotation
        before = len(app.seen)
        verdict, unsure = oracle.confirm_outcome(cand, sender)
    finally:
        app.close()
    assert control is not None and control.confirmed
    fetched = app.seen[before]
    assert fetched[:2] == ("GET", "/form")
    assert ("GET", "/", fetched[2]) in app.seen[before:]           # the live check
    assert [r for r in app.seen[before:] if r[:2] == ("POST", "/do")] == []
    assert verdict is None and unsure is not None and unsure.mechanism == UNBOUND
    assert "session material" in unsure.evidence["reason"]


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


# --- FR-AUD-20, fail closed (reviews B3, R2-1, R3-1) -------------------------------------
#: Values that name a host beyond loopback to some reader. Review B3's four, then review
#: R2-1's: a host and a port, or a scheme and ':' with or without '//', in the path, query
#: or fragment (`new URL("https:evil.example", "http://127.0.0.1/")` is
#: https://evil.example/ in node 22; a reader that puts 'http://' before a token reads
#: evil.example:8080 and 8.8.8.8:53 as host and port), then the same class spelled with a
#: bracketed literal, one slash, an underscore label, a hex or trailing-dot quad, and
#: fullwidth letters (each measured as a host in node 22).
_OUTSIDE_LAB = [
    "127.0.0.1:80@evil.example/",
    "localhost:1@evil.example",
    "http://evil.example\\@127.0.0.1/",
    "http://127.0.0.1:8080/r?next=http://evil.example/",
    "http://127.0.0.1/?next=evil.example:8080",
    "http://127.0.0.1/?next=8.8.8.8:53",
    "http://127.0.0.1/?next=https:evil.example",
    "127.0.0.1/go?to=evil.example:443",
    "localhost:3000/r?u=evil.example:80/x",
    "http://127.0.0.1/#evil.example:8080",
    "http://127.0.0.1/?h=[::ffff:8.8.8.8]:53",
    "http://127.0.0.1/?next=https:/evil.example",
    "http://127.0.0.1/?u=a_b.evil.example",
    "http://127.0.0.1/?h=0x8.8.8.8",
    "http://127.0.0.1/?h=8.8.8.8.",
    "http://127.0.0.1/?next=ｅｖｉｌ.example",
]
#: Review R3-1's check of round 2: a bare host whose TLD is not in `GENERIC_TLDS`, and a
#: short-form IPv4 address (`new URL("http://" + t).host` is 8.8.8.8 for each, node 22),
#: each sent verbatim at 3959dfc.
_OUTSIDE_LAB_R3 = [
    "http://127.0.0.1/?next=evil.top",
    "http://127.0.0.1/?next=evil.shop",
    "http://127.0.0.1/?next=attacker.tech/x",
    "http://127.0.0.1/?next=evil.mov",
    "http://127.0.0.1/go/evil.top",
    "127.0.0.1/?u=evil.store",
    "localhost:3000/r?u=evil.live",
    "http://127.0.0.1/#evil.zip",
    "http://127.0.0.1/?next=134744072",
    "http://127.0.0.1/?next=8.8.2056",
    "http://127.0.0.1/?next=8.526344",
    "http://127.0.0.1/?next=0x8080808",
    "http://127.0.0.1/?next=0x08.0x08.0x0808",
]
#: The loopback controls that keep their tail: plain word segments only.
_LAB_ONLY = ["http://127.0.0.1/", "http://127.0.0.1:3000/login?next=/account",
             "http://127.0.0.1:8080/after", "http://[::1]:80/x",
             "http://localhost:3000/account/settings",
             "http://localhost/app/login?next=/home&tab=profile#top",
             "localhost:3000/my-page/sub_page?mode=edit", "http://127.0.0.1/~alice/"]
#: Accepted false positives (the owner's allow-list, 2026-10-21): a loopback value whose
#: tail holds a number, a '.' or ':' token, or any character outside the grammar is
#: replaced by plain loopback, as a value naming another host is.
_ACCEPTED_FALSE_POSITIVES = [
    "http://127.0.0.1:3000/list?page=2&sort=name", "http://127.0.0.1/app.js?v=1.2.3",
    "http://localhost:3/x?a=1", "http://127.0.0.1/?at=10:30", "http://127.0.0.1/?q=a+b",
    "http://127.0.0.1/2fa", "http://127.0.0.1/a;b", "http://127.0.0.1/x?ids=a,b",
]


def _ipv4_spellings(a, b, c, d):
    """Every one- to four-part spelling of a.b.c.d, each part decimal, hex (``0x``,
    ``0X``) or leading-zero octal, and the first part hex with the rest decimal: what
    WHATWG's and inet_aton's IPv4 parsers read as that address."""
    n = (a << 24) | (b << 16) | (c << 8) | d
    out = set()
    for parts in ([n], [a, (b << 16) | (c << 8) | d], [a, b, (c << 8) | d], [a, b, c, d]):
        for radix in (str, hex, lambda x: "0X%x" % x, lambda x: "0%o" % x):
            out.add(".".join(radix(p) for p in parts))
        out.add(".".join([hex(parts[0])] + [str(p) for p in parts[1:]]))
    return sorted(out)


def _r3_sweep():
    """Review R3-1's generated sweep, every token in every position: gTLDs that are not in
    `GENERIC_TLDS` (bare, nested, trailing dot, with a path), the one- to four-part and
    integer IPv4 spellings of an outside address and of loopback, a scheme and ':', a
    host and a port, a bracketed literal, a network-path reference, a percent escape,
    and fullwidth or other non-ASCII spellings."""
    from fuzzlab.audit.value_shape import GENERIC_TLDS
    tlds = [t for t in ("top", "shop", "tech", "mov", "zip", "store", "live", "club", "blog",
                        "museum", "photography", "bank", "google", "page", "new", "foo",
                        "ninja", "rocks", "win", "loan", "work", "mobi", "name", "pro",
                        "jobs", "asia", "cat", "tel", "post", "travel", "xn--p1ai")
            if t not in GENERIC_TLDS]
    tokens = []
    for tld in tlds:
        tokens += [f"evil.{tld}", f"a.b.evil.{tld}", f"evil.{tld}.", f"evil.{tld}/x"]
    for quad in ((8, 8, 8, 8), (1, 2, 3, 4), (127, 0, 0, 1)):
        tokens += _ipv4_spellings(*quad)
    tokens += ["https:evil", "https:/evil.top", "http:8.8.8.8", "javascript:alert",
               "evil:8080", "evil.top:443", "8.8.8.8:53", "localhost:22",
               "[::ffff:8.8.8.8]", "[2001:db8::1]:443", "[::1]",
               "//evil", "///evil", "/\\evil", "evil%2Etop",
               "ｅｖｉｌ．ｔｏｐ", "evil。top",
               "evil．top", "evil｡top", "évil", "evil​top"]
    positions = ("http://127.0.0.1/?next={}", "http://127.0.0.1/go/{}",
                 "http://127.0.0.1/#{}", "127.0.0.1/?u={}", "localhost:3000/r?u={}",
                 "http://[::1]:8080/x?u={}&v=w", "https://localhost/a/{}/b")
    return [pos.format(t) for t in tokens for pos in positions]


@pytest.mark.parametrize("value",
                         _OUTSIDE_LAB + _OUTSIDE_LAB_R3 + _ACCEPTED_FALSE_POSITIVES)
def test_a_value_that_names_a_host_beyond_loopback_to_any_reader_is_outside_the_lab(value):
    from fuzzlab.audit.value_shape import names_outside_lab
    from fuzzlab.harness.auto import _send_value
    assert names_outside_lab(value)
    assert _send_value(value) != value                  # never sent as given


def test_every_spelling_of_the_generated_sweep_is_outside_the_lab():
    """Review R3-1: the tail rule is an allow-list, so no spelling a recogniser's lists
    miss is kept: every value of the sweep is outside, and loopback stands in for it."""
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _send_value
    sweep = _r3_sweep()
    assert len(sweep) > 1000
    kept = [v for v in sweep
            if not names_outside_lab(v) or _send_value(v) not in (SAFE_URL, SAFE_HOST)]
    assert kept == []


def test_the_tail_rule_is_an_allow_list_never_a_recogniser_of_hosts():
    """The owner's design (2026-10-21, review R3-1): the tail predicate reads its own
    grammar only -- no shape classifier, TLD or extension list, or address parser."""
    import ast
    import inspect

    from fuzzlab.audit import value_shape
    tree = ast.parse(inspect.getsource(value_shape._tail_in_grammar))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not names & {"value_shape", "GENERIC_TLDS", "FILE_EXTENSIONS", "ipaddress",
                        "_is_hostname", "_is_ip", "_is_url", "_is_filename", "_is_path",
                        "urlsplit"}
    assert {"_TAIL_SEPARATORS", "_TAIL_WORD"} <= names


@pytest.mark.parametrize("value", _LAB_ONLY)
def test_a_value_naming_only_loopback_is_the_lab(value):
    from fuzzlab.audit.value_shape import names_outside_lab
    from fuzzlab.harness.auto import _send_value
    assert not names_outside_lab(value)
    assert _send_value(value) == value


@pytest.mark.parametrize("value, sent",
                         [(v, False) for v in _OUTSIDE_LAB + _OUTSIDE_LAB_R3
                          + _ACCEPTED_FALSE_POSITIVES] + [(v, True) for v in _LAB_ONLY])
def test_the_binder_never_binds_a_fresh_value_that_names_a_host_beyond_loopback(value, sent):
    """Reviews R2-1, R3-1: the same predicate gates the fresh values a page offers now
    (`_FormBoundSender._bind_fresh`): one outside the safe grammar is refused and nothing
    is sent (unbound); one naming only loopback is bound as given."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate, PrerequisiteUnavailable
    form = ("<html><form method=post action='/app/go.php'><input type=hidden name=next "
            f"value=\"{html.escape(value, quote=True)}\"><input name=q></form></html>")
    site = _Site({"/app/p.php": lambda s, n: form},
                 lambda req, s: Probe(200, "<html>ok</html>"))
    cand = Candidate(url="http://h/app/go.php", param="q", method="POST", location="body",
                     base_entries=(("next", ""), ("q", "x")),
                     bindings={"page": "http://h/app/p.php", "fresh": ["next"]})
    bound = _FormBoundSender(site, cand)
    if sent:
        bound.send("http://h/app/go.php", "q", "M", method="POST", location="body")
        assert [r["body"]["next"] for r in site.sends("/app/go.php")] == [value]
    else:
        with pytest.raises(PrerequisiteUnavailable, match="outside the lab"):
            bound.send("http://h/app/go.php", "q", "M", method="POST", location="body")
        assert site.sends("/app/go.php") == []


#: BUG-0544 residual N-R3-1 (after the final round, 8fee220; the same at dcc7091), fixed
#: by BUG-0555: a loopback authority the recogniser in `neutral_value` missed -- no '/'
#: before '?' or '#', a trailing dot, a short-form or integer IPv4 spelling -- whose tail
#: names another host. WHATWG (node 22) reads each host as loopback and the tail as
#: naming evil.top, evil.example or 8.8.8.8; `names_outside_lab` returned early on
#: `neutral_value(value) == value` and they were sent verbatim.
_OUTSIDE_LAB_N_R3_1 = [
    "127.0.0.1?next=evil.top", "localhost?next=evil.example",
    "127.0.0.1#evil.example:8080", "localhost?u=134744072",
    "127.0.0.1?next=https:evil.example", "127.0.0.1?next=//evil.top/x",
    "LOCALHOST?next=8.8.8.8:53",
    "127.0.0.1./?next=evil.top", "localhost./?next=evil.example", "127.1/?next=evil.top",
    "2130706433/?next=evil.top", "0x7f000001/?next=evil.example:8080",
]


@pytest.mark.parametrize("value", _OUTSIDE_LAB_N_R3_1)
def test_a_loopback_authority_the_recogniser_misses_is_still_outside_the_lab(value):
    from fuzzlab.audit.value_shape import names_outside_lab
    from fuzzlab.harness.auto import _send_value
    assert names_outside_lab(value)
    assert _send_value(value) != value                  # never sent as given


@pytest.mark.parametrize("value", _OUTSIDE_LAB_N_R3_1)
def test_the_binder_never_binds_a_loopback_authority_the_recogniser_misses(value):
    """N-R3-1 through `_FormBoundSender._bind_fresh`: a page offering such a value now is
    refused (unbound) and nothing is sent."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate, PrerequisiteUnavailable
    form = ("<html><form method=post action='/app/go.php'><input type=hidden name=next "
            f"value=\"{html.escape(value, quote=True)}\"><input name=q></form></html>")
    site = _Site({"/app/p.php": lambda s, n: form},
                 lambda req, s: Probe(200, "<html>ok</html>"))
    cand = Candidate(url="http://h/app/go.php", param="q", method="POST", location="body",
                     base_entries=(("next", ""), ("q", "x")),
                     bindings={"page": "http://h/app/p.php", "fresh": ["next"]})
    bound = _FormBoundSender(site, cand)
    with pytest.raises(PrerequisiteUnavailable, match="outside the lab"):
        bound.send("http://h/app/go.php", "q", "M", method="POST", location="body")
    assert site.sends("/app/go.php") == []


# --- FR-AUD-20's lab predicate is an allow-list of loopback authorities (BUG-0555) -------
def _bind_offered(value) -> bool:
    """`_FormBoundSender._bind_fresh` on a page whose form offers ``value`` now for the
    fresh entry: True when it is bound and sent as given, False when it is refused as
    outside the lab and nothing is sent."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate, PrerequisiteUnavailable
    form = ("<html><form method=post action='/app/go.php'><input type=hidden name=next "
            f"value=\"{html.escape(value, quote=True)}\"><input name=q></form></html>")
    site = _Site({"/app/p.php": lambda s, n: form},
                 lambda req, s: Probe(200, "<html>ok</html>"))
    cand = Candidate(url="http://h/app/go.php", param="q", method="POST", location="body",
                     base_entries=(("next", ""), ("q", "x")),
                     bindings={"page": "http://h/app/p.php", "fresh": ["next"]})
    try:
        _FormBoundSender(site, cand).send("http://h/app/go.php", "q", "M", method="POST",
                                          location="body")
    except PrerequisiteUnavailable as exc:
        assert "outside the lab" in str(exc) and site.sends("/app/go.php") == []
        return False
    assert [r["body"]["next"] for r in site.sends("/app/go.php")] == [value]
    return True


def _in_lab_set(host: str) -> bool:
    """The explicit loopback set, restated: ``localhost`` in any case, ``[::1]``, and
    ``127.a.b.c`` in canonical dotted decimal."""
    parts = host.split(".")
    return host.lower() in ("localhost", "[::1]") or (
        len(parts) == 4 and parts[0] == "127"
        and all(p.isdigit() and str(int(p)) == p and int(p) <= 255 for p in parts))


def _name_spellings(name):
    """``name`` in other cases, with a trailing dot or two, percent-encoded, with an IDNA,
    fullwidth or halfwidth full stop, an ignorable character, and fullwidth letters."""
    return {name, name.upper(), name.title(), name + ".", name + "..",
            name.replace(".", "%2E"), name.replace(".", "%2e"),
            name.replace(".", "。"), name.replace(".", "．"),
            name.replace(".", "｡"), "%" + name[0].encode().hex() + name[1:],
            name[:2] + "​" + name[2:], name[:2] + "­" + name[2:],
            "".join(chr(ord(c) + 0xFEE0) if c.isalpha() else c for c in name)}


#: Bare (unbracketed) IPv6 literals (BUG-0555 review R2/B1): global unicast, IPv4-mapped
#: (``::ffff:8.8.8.8`` is 8.8.8.8), IPv4-compatible, NAT64 (``64:ff9b::808:808`` is
#: 8.8.8.8 through a NAT64 gateway), the full form, link-local with a zone, loopback and
#: the unspecified address. WHATWG reads none of them after ``http://`` (node 22: an
#: invalid port); `getaddrinfo(AI_NUMERICHOST)` reads each as that address but
#: ``fe80::1%25lo`` (a URL's encoded zone, kept for the syntax), and `inet_pton` each
#: without a zone (measured on the test host).
_BARE_IPV6 = ("2001:4860:4860::8888", "2606:4700:4700::1111", "2001:db8::1", "1::2",
              "::ffff:8.8.8.8", "::ffff:808:808", "::8.8.8.8", "64:ff9b::808:808",
              "2001:4860:4860:0:0:0:0:8888", "0:0:0:0:0:ffff:808:808", "fe80::1%eth0",
              "fe80::1%25lo", "::ffff:127.0.0.1", "::1", "0:0:0:0:0:0:0:1", "::")


def _authority_spellings():
    """The host spellings of the BUG-0555 sweep: every one- to four-part, integer, hex
    and octal IPv4 spelling of an outside address and of loopback (each also with a
    trailing dot and upper case), names whose last label is a delegated TLD and
    ``localhost`` in `_name_spellings` (``localhost.`` and ``localhost..`` are reserved
    names, `_reserved_spellings`), IPv6 literals in brackets (IPv4-mapped included) and
    bare (`_BARE_IPV6`, review R2)."""
    out = set()
    for quad in ((8, 8, 8, 8), (127, 0, 0, 1), (10, 0, 0, 1), (1, 2, 3, 4)):
        for s in _ipv4_spellings(*quad):
            out |= {s, s + ".", s.upper()}
    for name in ("evil.top", "a.b.evil.top", "evil.zip", "localhost"):
        out |= _name_spellings(name)
    out -= {"localhost.", "localhost.."}
    out |= {"[::1]", "[0:0:0:0:0:0:0:1]", "[::0:1]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]",
            "[::ffff:8.8.8.8]", "[::ffff:808:808]", "[2001:db8::1]", "[::]",
            "[::127.0.0.1]", "[fe80::1%25lo]", "[::1%25lo]", *_BARE_IPV6}
    return sorted(out)


def _reserved_spellings():
    """Spellings of names whose last label is not delegated in the DNS root (reserved:
    ``.example``, ``.test``, ``.invalid``, ``.localhost``, ``.local``; undelegated:
    ``.corp``; a file extension, ``.txt``), and ``localhost.``: a host to WHATWG, but no
    public resolver answers it."""
    out = {"localhost.", "localhost..", "LOCALHOST."}
    for name in ("evil.example", "intranet.corp", "lab.test", "a.b.evil.invalid",
                 "evil.localhost", "printer.local", "robots.txt"):
        out |= _name_spellings(name)
    return sorted(out)


#: The positions of the sweep where a spelling stands as a bare token (no path, query,
#: fragment or scheme: BUG-0555 review, the bare-token rule).
_BARE_POSITIONS = ("{}", "{};x")


#: Where the sweep puts each spelling: bare, with a port, path, query or fragment,
#: absolute in any case, scheme-relative, backslashed, a special scheme without '//', a
#: lab authority as userinfo before it and it as userinfo before a lab authority.
_SWEEP_POSITIONS = ("{}", "{}/", "{}/x", "{}?a=b", "{}#f", "{}:8080", "{}:8080/x",
                    "{};x", "http://{}/", "https://{}:3000/x?y=z#w", "HTTP://{}",
                    "//{}/x", "\\\\{}/x", "/\\{}/x", "http:\\\\{}/x", "https:{}/x",
                    "http:/{}/", "user@{}/x", "user:pw@{}:80/", "127.0.0.1@{}/",
                    "localhost:80@{}", "{}@127.0.0.1/", "{}\\@127.0.0.1/")
#: Review round 2 (N2): where a bare IPv6 literal sits beside a character outside its
#: alphabet (`_IPV6_BESIDE_READ`'s readers): after ``=``, in a list, quoted, in
#: parentheses, before a shell operator, and before a word after a tab, LF or CR.
_IPV6_BESIDE_POSITIONS = ("dns={}", "{0},{0}", '"{}"', "({})", "{}|id", "{}&", "{};id",
                          "{}\tis the server", "{}\nis the server", "{}\ris the server",
                          "{}\r\nis the server")


def test_every_authority_spelling_outside_the_lab_set_is_outside_the_lab():
    """BUG-0555 (N-R3-1's class): a value whose authority is not one of the explicit
    loopback spellings is outside the lab, however the authority is spelled and wherever
    it stands -- short, integer, hex and octal IPv4 forms (WHATWG reads ``127.1`` and
    ``0x7f000001`` as 127.0.0.1, and ``0x08.0x08.0x0808`` as 8.8.8.8: node 22), trailing
    dots, case, userinfo, percent-encoding, IDNA and fullwidth full stops, IPv6 literals
    (``::ffff:127.0.0.1`` and ``::ffff:8.8.8.8``), scheme-relative and backslashed --
    and loopback stands in for it. Loopback spellings outside the set are accepted false
    positives. Review R2: an unbracketed IPv6 literal (`_BARE_IPV6`) in every position
    too, and (review round 2) beside a character outside its alphabet
    (`_IPV6_BESIDE_POSITIONS`). A reserved or undelegated name (`_reserved_spellings`)
    is outside in every position but a bare token's (`_BARE_POSITIONS`, and before a
    port, where WHATWG reads a letter-led name as a scheme)."""
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _send_value
    spellings = _authority_spellings()
    values = [pos.format(s) for s in spellings for pos in _SWEEP_POSITIONS
              if not (_in_lab_set(s) and "@" not in pos and "\\" not in pos
                      and pos not in ("{};x", "https:{}/x", "http:/{}/"))]
    values += [pos.format(s) for s in _reserved_spellings() for pos in _SWEEP_POSITIONS
               if pos not in _BARE_POSITIONS + ("{}:8080",)]
    values += [pos.format(s) for s in _BARE_IPV6 for pos in _IPV6_BESIDE_POSITIONS]
    assert len(spellings) > 150 and len(values) > 5000
    kept = [v for v in values
            if not names_outside_lab(v) or _send_value(v) not in (SAFE_URL, SAFE_HOST)]
    assert kept == []


def test_the_binder_never_binds_an_authority_spelling_outside_the_lab_set():
    """BUG-0555 through `_FormBoundSender._bind_fresh`: a page offering any spelling of
    the sweep outside the explicit set, bare, before a path and as an absolute URL, is
    refused (unbound) and nothing is sent; a reserved name before a path or as an
    absolute URL too. Review R2: bare IPv6 literals included; review round 2: beside a
    character outside the IPv6 alphabet (`_IPV6_BESIDE_POSITIONS`, tab and newlines
    included: an HTML attribute keeps them)."""
    bound = [v for s in _authority_spellings() if not _in_lab_set(s)
             for v in (s, s + "/x", f"http://{s}/") if v.isprintable() and _bind_offered(v)]
    bound += [v for s in _reserved_spellings() for v in (s + "/x", f"http://{s}/")
              if v.isprintable() and _bind_offered(v)]
    bound += [v for s in _BARE_IPV6 for pos in _IPV6_BESIDE_POSITIONS
              for v in (pos.format(s),) if _bind_offered(v)]
    assert bound == []


def test_a_bare_token_naming_no_delegated_host_is_the_lab():
    """BUG-0555 review (LA-6), the bare-token rule: a bare token whose host (WHATWG,
    after its mapping) is a dotted name whose last label is not delegated in the DNS root
    -- a reserved name (``.example``, ``.test``, ``.invalid``, ``.localhost``,
    ``.local``), an undelegated one (``.corp``) or a file name (``robots.txt``) -- names
    no host a public resolver answers, and is the lab: sent and bound as given, however
    it is spelled. So a lab's e-mail (``user@lab.test``) and a file name stay siblings
    (Mongection's /login, bWAPP's ``ParamUrl=robots.txt``)."""
    from fuzzlab.audit.value_shape import names_outside_lab
    from fuzzlab.harness.auto import _outside_lab, _send_value
    values = [pos.format(s) for s in _reserved_spellings() for pos in _BARE_POSITIONS]
    values += [f"user@{s}" for s in _reserved_spellings()]
    assert len(values) > 200
    outside = [v for v in values if names_outside_lab(v) or _send_value(v) != v
               or _outside_lab([("a", v), ("q", "x")], "q") is not None]
    assert outside == []
    unbound = [s for s in _reserved_spellings() if s.isprintable() and not _bind_offered(s)]
    assert unbound == []


#: The loopback controls of the sweep: every spelling in the explicit set, before only
#: a port and a tail in the safe grammar, is the lab, sent and bound as given.
_LAB_SET_CONTROLS = [pos.format(host) for host in (
    "127.0.0.1", "127.0.0.2", "127.255.0.10", "localhost", "LOCALHOST", "LocalHost", "[::1]")
    for pos in ("{}", "{}:3000", "{}/", "{}/a/b", "{}?next=home&tab=x", "{}#top",
                "{}:8080/login?next=/account", "http://{}/", "HTTPS://{}:443/x?y=z#w",
                "//{}/x")]


@pytest.mark.parametrize("value", _LAB_SET_CONTROLS)
def test_a_lab_set_authority_with_a_grammar_tail_is_the_lab(value):
    from fuzzlab.audit.value_shape import names_outside_lab
    from fuzzlab.harness.auto import _send_value
    assert not names_outside_lab(value)
    assert _send_value(value) == value
    assert _bind_offered(value)


#: Rule (2) of BUG-0555, each reading measured in node 22 (`new URL("http://" + v).host`,
#: or `new URL(v).host` for a scheme): a value of no other shape whose token a reader
#: takes for a non-loopback host -- an IPv4 address in any radix or short form, or, in a
#: bare token, a name whose last label is delegated in the DNS root (the bare-token
#: rule, BUG-0555 review: ``evil.zip``, ``gmail.com``, ``com.``, an internationalised TLD;
#: before a path, query or fragment any dotted token) -- is outside the lab, whatever
#: `value_shape`'s TLD list holds.
_MEASURED_OUTSIDE = {
    "evil.zip": "evil.zip", "user@gmail.com": "gmail.com", "user@evil.top": "evil.top",
    "x@8.8.8.8": "8.8.8.8", "com.": "com.", "a;b.top": "a;b.top",
    "evil.xn--p1ai": "evil.xn--p1ai", "evil.рф": "evil.xn--p1ai", "19.99": "19.0.0.99",
    "1.": "0.0.0.1", "robots.txt/x": "robots.txt",
    "evil.top": "evil.top", "evil.shop": "evil.shop", "a.b.evil.top": "a.b.evil.top",
    "evil.top.": "evil.top.", "134744072": "8.8.8.8", "0x8080808": "8.8.8.8",
    "8.8.2056": "8.8.8.8", "8.526344": "8.8.8.8", "0x08.0x08.0x0808": "8.8.8.8",
    "8.8.8.8.": "8.8.8.8", "16777216": "1.0.0.0", "1.2.3": "1.2.0.3", "2.5": "2.0.0.5",
    "ｅｖｉｌ．ｔｏｐ": "evil.top", "evil%2Etop": "evil.top",
    "evil​.top": "evil.top", "evil。top": "evil.top", "evil.top\x00": "evil.top",
    "disco.user@example.com": "example.com", "127.1": "127.0.0.1",
    "2130706433": "127.0.0.1",
    "0x7f000001": "127.0.0.1", "0177.0.0.1": "127.0.0.1", "127.0.0.1.": "127.0.0.1",
    "[::ffff:8.8.8.8]": "[::ffff:808:808]", "[::ffff:127.0.0.1]": "[::ffff:7f00:1]",
    "[2001:db8::1]": "[2001:db8::1]", "evil.top:8080": "evil.top:8080",
    "https:evil.example": "evil.example", "/evil.top": "evil.top",
    "\\\\evil.top/x": "evil.top", "/\\evil.top/x": "evil.top",
    "0:3000/?next=evil.top": "0.0.0.0:3000", "/0:3000/x": "0.0.0.0:3000",
    "/8.8.8.8:53/x": "8.8.8.8:53", "/127.0.0.1/?next=evil.top": "127.0.0.1",
}


@pytest.mark.parametrize("value", sorted(_MEASURED_OUTSIDE))
def test_a_value_a_reader_takes_for_a_host_beyond_the_lab_set_is_outside(value):
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _send_value
    assert names_outside_lab(value)
    assert _send_value(value) in (SAFE_URL, SAFE_HOST)
    if value.isprintable():
        assert not _bind_offered(value)


#: What stays the lab (BUG-0555, the stated residuals), measured in node 22: a pure word
#: and a number of 2**32 or more are single-label names (`fuzzlab`, `intranet`; WHATWG
#: refuses 4294967296), a small number reads as 0.0.0.0/8 (`42` is 0.0.0.42), free text
#: with a space is no host (WHATWG refuses `hello world`), whatever follows such a
#: single-label host (`text/html`, `12:00` is 0.0.0.12:0, `intranet/?next=evil.top`),
#: and a reference to the page's own origin whose first segment is no host
#: (`/account`; `/?next=evil.top` gives no host at all).
_MEASURED_LAB = {
    "fuzzlab": "fuzzlab", "intranet": "intranet", "42": "0.0.0.42", "0": "0.0.0.0",
    "16777215": "0.255.255.255", "4294967296": None, "2000": "0.0.7.208",
    "hello world": None, "a b.top": None, "The Fellowship of the Ring": None,
    "text/html": "text", "12:00": "0.0.0.12:0", "N/A": "n", "and/or": "and",
    "/account": "account", "/": None, "#top": None, "?": None, "John Smith": None,
    "2020-01-01T00:00": "2020-01-01t00:0", "intranet/?next=evil.top": "intranet",
    "42/?next=evil.top": "0.0.0.42", "docs/x.pdf": "docs", "/static/app.js": "static",
    "/users/42": "users", "/?next=evil.top": None, "?page=2": None, "#evil.zip": None,
    # BUG-0555 review (LA-6), the bare-token rule: a bare token whose host's last label is
    # not delegated in the DNS root (reserved, undelegated, a file extension) names no
    # host a public resolver answers
    "lang_en.php": "lang_en.php", "robots.txt": "robots.txt", "Hello.": "hello.",
    "portal.php": "portal.php", "message.txt": "message.txt",
    "getting-started.html": "getting-started.html", "user@lab.test": "lab.test",
    "a@b.example": "b.example", "user@evil.example": "evil.example",
    "evil.example": "evil.example", "intranet.corp": "intranet.corp",
    "evil.local": "evil.local", "evil.localhost": "evil.localhost",
    "evil.invalid": "evil.invalid", "localhost.": "localhost.",
    # and a time of day is no IPv6 literal (review R2: fewer than six ':' and no '::')
    "12:00:00": None, "23:59:59": None,
}


@pytest.mark.parametrize("value", sorted(_MEASURED_LAB))
def test_a_pure_word_a_small_number_and_free_text_are_the_lab(value):
    from fuzzlab.audit.value_shape import names_outside_lab
    from fuzzlab.harness.auto import _send_value
    assert not names_outside_lab(value)
    assert _send_value(value) == value
    assert _bind_offered(value)


#: An ASP.NET view state (its serialised form always starts ``/wE``) and standard base64
#: holding a '/' or '+': no reader takes a host from them (BUG-0555's measured cost of
#: holding a reference to the tail grammar: 99.9% of view states, 21.5% of tokens).
_VIEW_STATE = "/wEPDwUKLTk2MjU2MjQ4MA9kFgJmD2QWAgIDD2QWAgIBDw8WAh4EVGV4dAUFSGVsbG9kZGTq+abc/de=="


@pytest.mark.parametrize("value, outside", [
    ("/evil.top", True), ("/8.8.8.8:53/x", True), ("/127.0.0.1/?next=evil.top", True),
    ("/0:3000/x", True), ("//evil.top/x", True), ("/\\evil.top", True),
    ("/127.0.0.1/", True), ("intranet:8080/x?y=z", True), ("Note: see x", True),
    ("/account", False), ("/static/app.js", False), ("/users/42", False),
    ("?page=2", False), ("#evil.zip", False), ("/?next=evil.top", False),
    ("intranet/?next=evil.top", False), ("docs/x.pdf", False), (_VIEW_STATE, False),
    ("Ab3+xYz/9kQ+abc/def=", False), ("text/html", False),
])
def test_a_reference_is_outside_only_when_a_reader_takes_a_host_from_it(value, outside):
    """BUG-0555: a reader that puts ``http://`` before a value skips its leading slashes
    (WHATWG reads ``/evil.top`` as evil.top and ``/8.8.8.8:53/x`` as 8.8.8.8:53, node 22),
    so a reference whose first segment is a host token is an authority shape, proven or
    outside (``/127.0.0.1/`` is an accepted false positive: no explicit authority). A word
    before ``:`` is a URL scheme to WHATWG (``intranet:8080/x``, ``Note: see x``):
    outside. Stated residual: a value naming no host of its own whose path, query or
    fragment does (``/?next=evil.top``, ``intranet/?next=evil.top``) is the lab."""
    from fuzzlab.audit.value_shape import names_outside_lab
    assert names_outside_lab(value) is outside


# --- BUG-0555 review round 1 ---------------------------------------------------------
#: Review R1 (LA-1): a value holding ``://`` after a prefix that is no scheme. 7393c90's
#: `neutral_value` gate put every one outside; 1338d7a sent and bound each verbatim
#: (``_authority_shaped`` saw a host only at a scheme-shaped start). WHATWG resolves
#: ``?next=http://evil.top`` against the lab to a lab URL whose query names evil.top
#: (node 22), N-R3-1's own shape. With the backslashed spellings WHATWG reads as ``//``
#: after a special scheme (``http:\\evil.top``, ``http:/\\evil.top``: node 22). And the
#: same once percent-decoded, as an application that decodes the value reads it (a
#: triple-encoded ``/go?ret=https://host.example/cb?x=1`` is in 54 recorded points).
_AUTHORITY_ANYWHERE = [
    "/login?next=https://evil.example/", "?next=http://evil.top", "url=http://evil.top",
    '{"u":"http://evil.top"}', "see http://evil.top", "(http://evil.top)",
    "/redirect?url=http://evil.top/", "return=https://8.8.8.8/",
    "?next=http:\\\\evil.top", "x=http:/\\evil.top", "go=https:\\evil.top/x",
    "http%3A%2F%2Fevil.top", "next=https%3A%2F%2F8.8.8.8%2F",
    "%2Fgo%3Fret%3Dhttps%25253A%25252F%25252Fevil.top%25252Fcb",
    # review round 2 (N1): a special scheme and ':' after a character that cannot be part
    # of a scheme, with ':/' or nothing before the host. WHATWG reads `https:evil.top`
    # and `https:/evil.top` as https://evil.top/, `ws:evil.top` as ws://evil.top/ and
    # `ftp:evil.top` as ftp://evil.top/; each value's last piece, used as a Location
    # against http://127.0.0.1/ or read on its own (`Http:8.8.8.8` is relative only to an
    # http: base, and http://8.8.8.8/ on its own), goes there (node 22;
    # `scratchpad/lanes/LABAUTH/r2/check_tables_r2.py`). Raw and percent-decoded: `go
    # to\thttps:evil.top` holds the mark only
    # in the raw value (WHATWG's tab removal joins `tohttps:`), and `https%3Aevil.top`
    # only once decoded. Each was sent and bound verbatim at d3cb339.
    "go=https:/evil.top/x", "go=https:evil.top/x", "?next=https:evil.top",
    "?next=https:/evil.top", "/login?next=https:evil.example/", "see https:evil.top",
    "url=ws:evil.top", "(https:evil.top)", '{"u":"https:/evil.top"}',
    "?next=https%3Aevil.top", "?next=https%3A%2Fevil.top", "?next=HTTPS:evil.top",
    "?next=ftp:evil.top", "?next=wss:/evil.top", "next=Http:8.8.8.8",
    "go to\thttps:evil.top",
]


@pytest.mark.parametrize("value", _AUTHORITY_ANYWHERE)
def test_a_value_holding_an_authority_mark_anywhere_is_outside_the_lab(value):
    """Review R1 through all three callers of SP-73: `_send_value` stands loopback in,
    `_outside_lab` refuses the request it is a sibling of, and the binder refuses it
    (unbound, nothing sent)."""
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _outside_lab, _send_value
    assert names_outside_lab(value)
    assert _send_value(value) in (SAFE_URL, SAFE_HOST)
    assert "sibling a names a host outside the lab" in _outside_lab([("a", value),
                                                                     ("q", "x")], "q")
    assert not _bind_offered(value)


def _scheme_anywhere_corpus():
    """Values holding ``scheme://`` after every kind of prefix, before every kind of host
    and tail: 7393c90's '://'-anywhere rule put each one outside, but for the loopback
    URLs its proof admitted (no prefix, an http(s) scheme, a loopback authority, a tail
    in the grammar)."""
    prefixes = ("", "/login?next=", "?next=", "#", "url=", "x=1&u=", "see ", "(", '{"u":"',
                "/r/", "a", "/", "go to: ", "\t", "%20")
    schemes = ("http", "https", "HTTP", "ftp", "javascript", "x-y")
    hosts = ("evil.top", "evil.example", "lab.test", "8.8.8.8", "134744072",
             "[::ffff:8.8.8.8]", "2001:db8::1", "127.0.0.1", "localhost", "[::1]",
             "127.0.0.1:3000")
    tails = ("", "/", "/x?y=z", "#f", ")", '"}', "/?next=evil.top")
    lab_hosts = ("127.0.0.1", "localhost", "[::1]", "127.0.0.1:3000")
    corpus = {}
    for p in prefixes:
        for s in schemes:
            for h in hosts:
                for t in tails:
                    lab = (p == "" and s.lower() in ("http", "https")
                           and h in lab_hosts and t in ("", "/", "/x?y=z", "#f"))
                    corpus[f"{p}{s}://{h}{t}"] = lab
    return corpus


def test_every_value_the_old_scheme_anywhere_rule_put_outside_is_still_outside():
    """Review R1's non-regression: every value of the corpus that 7393c90's
    '://'-anywhere rule put outside is outside (loopback stands in for it), and the
    loopback URLs it admitted are still the lab."""
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _send_value
    corpus = _scheme_anywhere_corpus()
    assert len(corpus) > 6000 and sum(corpus.values()) == 48
    wrong = [v for v, lab in corpus.items()
             if names_outside_lab(v) is lab
             or (not lab and _send_value(v) not in (SAFE_URL, SAFE_HOST))]
    assert wrong == []


#: Review round 2 (N1): what may stand before a special scheme -- nothing, or any
#: character that cannot be part of a scheme (a query or key separator, a space, a tab, a
#: bracket, a quote, a slash, a non-ASCII letter) -- and every spelling of the mark.
_SPECIAL_PREFIXES = ("", "?next=", "/login?next=", "go=", "x=1&u=", "see ", "(", '{"u":"',
                     "#", "/r/", "go to\t", "a\n", "é", "%20", "[", "<", "'", ",", ";", "|")
_SPECIAL_SPELLINGS = ("http", "https", "HTTPS", "Http", "ws", "WSS", "ftp", "file")
_SPECIAL_AFTER = ("", "/", "\\", "%2F", "%5C")
#: Controls: a scheme character right before it makes another scheme (``xhttps``,
#: ``web+https``, ``a.ftp``: WHATWG reads no host from them, node 22) or none
#: (``1https:`` is a path to WHATWG): the lab, sent and bound as given.
_SPECIAL_CONTROLS = ["?next=xhttps:evil.example", "?next=web+https:evil.example",
                     "?q=1https:evil.example", "?next=a.ftp:evil.example"]


def test_a_special_scheme_after_a_non_scheme_character_is_outside_the_lab():
    """Review round 2 (N1, the owner's scope): a special scheme (http, https, ws, wss,
    ftp, file; any case) and ':' after any character that cannot be part of a scheme is
    an authority mark in every reader text, raw and percent-decoded, so the value is
    outside unless `_names_only_lab` proves it loopback -- whatever comes between the
    ':' and the host (``//``, ``/``, ``\\``, nothing, or their percent-encodings), and
    wherever the host names loopback (no spelling of this mark is in the proof's
    grammar). Loopback stands in for each. A scheme character right before the scheme
    makes another scheme, and is the lab."""
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _send_value
    values = [f"{p}{s}:{a}{h}{t}" for p in _SPECIAL_PREFIXES for s in _SPECIAL_SPELLINGS
              for a in _SPECIAL_AFTER
              for h in ("evil.top", "8.8.8.8", "evil.example", "127.0.0.1", "localhost")
              for t in ("", "/x", ")", '"}')]
    values += [v.replace(":", "%3A", 1) for v in values if v.count(":") == 1]
    assert len(values) > 30000
    kept = [v for v in values
            if not names_outside_lab(v) or _send_value(v) not in (SAFE_URL, SAFE_HOST)]
    assert kept == []
    controls = [v for v in _SPECIAL_CONTROLS
                if names_outside_lab(v) or _send_value(v) != v or not _bind_offered(v)]
    assert controls == []


#: Review R2 (LA-2, LA-5): bare IPv6 literals as the measured readers take them
#: (`getaddrinfo(v, None, flags=AI_NUMERICHOST)` on the test host; WHATWG refuses each
#: after ``http://``: node 22), alone, before a path, query or port and after userinfo.
_BARE_IPV6_READ = {
    "2001:4860:4860::8888": "2001:4860:4860::8888", "::ffff:8.8.8.8": "::ffff:8.8.8.8",
    "::ffff:808:808": "::ffff:8.8.8.8", "64:ff9b::808:808": "64:ff9b::808:808",
    "2001:db8::1": "2001:db8::1", "::8.8.8.8": "::8.8.8.8", "1::2": "1::2",
    "2606:4700:4700::1111": "2606:4700:4700::1111",
    "2001:4860:4860:0:0:0:0:8888": "2001:4860:4860::8888", "fe80::1%eth0": "fe80::1",
    "::1": "::1", "::": "::",
}


#: Review round 2 (N2): an IPv6 literal beside a character outside its alphabet, as a
#: named reader takes it -- Python's ``str.split`` (tab, LF, CR), a shell's word
#: splitting and operators (`shlex` with punctuation characters: tab, LF, a quote, a
#: parenthesis, ``|``, ``&``, ``;``), a ``key=value`` reader, a DNS-server list split at
#: ``,``, `json.loads` -- and `getaddrinfo(piece, None, flags=AI_NUMERICHOST)` reads
#: the piece as the address (the test host; the whole value it refuses;
#: `scratchpad/lanes/LABAUTH/r2/ipv6_readers.py`). Each was the lab at d3cb339 while its
#: IPv4 form (``dns=8.8.8.8``, ``8.8.8.8,8.8.4.4``, ``"8.8.8.8"``, ``8.8.8.8|id``) was
#: outside; WHATWG's tab and newline removal had joined the literal to the next word.
_IPV6_BESIDE_READ = {
    "2001:db8::1\tis the server": ("split", "2001:db8::1"),
    "2001:db8::1\nis the server": ("split", "2001:db8::1"),
    "2001:db8::1\ris the server": ("split", "2001:db8::1"),
    "2001:db8::1\r\nis the server": ("split", "2001:db8::1"),
    "2001:4860:4860::8888\tx": ("shell", "2001:4860:4860::8888"),
    "2001:4860:4860::8888\nx": ("shell", "2001:4860:4860::8888"),
    "dns=2001:4860:4860::8888": ("key=value", "2001:4860:4860::8888"),
    "2001:4860:4860::8888,2001:4860:4860::8844": ("list", "2001:4860:4860::8888"),
    '"2001:4860:4860::8888"': ("json", "2001:4860:4860::8888"),
    "(2001:4860:4860::8888)": ("shell", "2001:4860:4860::8888"),
    "2001:4860:4860::8888|id": ("shell", "2001:4860:4860::8888"),
    "2001:4860:4860::8888&": ("shell", "2001:4860:4860::8888"),
    "2001:4860:4860::8888;id": ("shell", "2001:4860:4860::8888"),
}


@pytest.mark.parametrize("value", sorted(
    [*_BARE_IPV6_READ, *_IPV6_BESIDE_READ, "::/evil.top", "2001:db8::1/x",
     "2001:4860:4860::8888?x=y", "2001:db8::1;x", "user@2001:db8::1", "/2001:db8::1/x",
     "2001:db8::1 is the server"]))
def test_a_bare_ipv6_literal_is_outside_the_lab(value):
    """Review R2: a reader that is not WHATWG (``ping6``, ``getaddrinfo``, ``inet_pton``)
    takes an unbracketed IPv6 literal for a host, and `value_shape` calls it ``ip`` (a
    command-injection default): outside, through all three callers. Only ``[::1]`` is
    the lab (``::1`` bare is an accepted false positive). Review round 2: beside any
    character outside its alphabet too (`_IPV6_BESIDE_READ`), the raw value judged as
    well as WHATWG's texts."""
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _outside_lab, _send_value
    assert names_outside_lab(value)
    assert _send_value(value) in (SAFE_URL, SAFE_HOST)
    assert _outside_lab([("dns", value), ("q", "x")], "q") is not None
    assert not _bind_offered(value)


#: Every character outside the IPv6 alphabet (hex digits, ':' and '.'): printable ASCII,
#: the whitespace and controls a reader may split at, NUL, and non-ASCII.
_NOT_IPV6 = sorted({chr(i) for i in range(0x20, 0x7F)} - set("0123456789abcdefABCDEF:.")
                   | set("\t\n\r\x0b\x0c\x00\xa0　é"))


def test_an_ipv6_literal_ends_at_any_character_outside_its_alphabet():
    """Review round 2 (N2, the owner's scope): an IPv6 literal ends at any character
    outside its alphabet, on either side, so every bare literal (`_BARE_IPV6`) beside
    every such character -- before it, after it, both, and between two words -- is
    outside, like its IPv4 form, and loopback stands in for it; the binder refuses it.
    Controls: a time of day, a date-time and a MAC address (no '::', fewer than six ':')
    beside a space, a tab, LF, a parenthesis, a quote or a comma stay the lab."""
    from fuzzlab.audit.value_shape import SAFE_HOST, SAFE_URL, names_outside_lab
    from fuzzlab.harness.auto import _send_value
    positions = ("{c}{v}", "{v}{c}", "{c}{v}{c}", "k{c}{v}{c}word")
    values = [p.format(c=c, v=v) for v in _BARE_IPV6 for c in _NOT_IPV6 for p in positions]
    assert len(values) > 4000
    kept = [v for v in values
            if not names_outside_lab(v) or _send_value(v) not in (SAFE_URL, SAFE_HOST)]
    assert kept == []
    bound = [v for c in _NOT_IPV6 if c not in "\x00\r"
             for v in (f"dns{c}2001:4860:4860::8888", f"2001:4860:4860::8888{c}x")
             if _bind_offered(v)]
    assert bound == []
    controls = [p.format(t) for t in ("12:00:00", "2020-01-01T00:00:00", "10:1a:2b:3c:4d:5e")
                for p in ("{}", "{} x", "x {}", "({})", '"{}"', "{0},{0}", "{}\tx", "{}\nx")]
    assert [v for v in controls if names_outside_lab(v)] == []


#: Review R3 (LA-3): a JSON integer leaf, judged by its JSON text. Each reading measured
#: in node 22 as an app that does ``"http://" + body.host`` takes the parsed number;
#: ``2130706433`` (127.0.0.1) is a loopback spelling outside the explicit set (an
#: accepted false positive, as the string is). The controls: a small number
#: (0.0.0.0/8), a negative one or one of 2**32 or more names no host to any reader (as
#: its string does), and a bool, null or empty container names nothing. A float with an
#: integral value is that integer (review round 2: JavaScript's `JSON.parse` reads
#: ``134744072.0`` as 134744072, 8.8.8.8 after ``http://``, node 22); any other JSON
#: float is the stated residual of review round 2 (`_JSON_FLOAT_RESIDUAL`).
_JSON_LEAVES = [(134744072, "8.8.8.8"), (3232235777, "192.168.1.1"),
                (16777216, "1.0.0.0"), (2130706433, "127.0.0.1"), (134744072.0, "8.8.8.8"),
                (42, None), (0, None), (-134744072, None), (4294967296, None),
                (True, None), (False, None), (None, None), ([], None), ({}, None)]


@pytest.mark.parametrize("value, reading", _JSON_LEAVES)
def test_a_json_number_leaf_is_judged_by_its_json_text(value, reading):
    """Review R3: the JSON number ``134744072`` is the text ``134744072`` to a reader,
    8.8.8.8 to WHATWG. `_send_value` and `neutral_value` stand ``127.0.0.1`` in for it,
    and a JSON body holding it as a sibling is never rebuilt (`_outside_lab` on the
    body's leaves, as `points_from_ground_truth` and the crawled-JSON points read them).
    A leaf naming no host is sent as given."""
    from fuzzlab.audit.value_shape import SAFE_HOST, names_outside_lab, neutral_value
    from fuzzlab.core import jsonbody
    from fuzzlab.harness.auto import _outside_lab, _send_value
    refusal = _outside_lab(jsonbody.leaves({"host": value, "q": "x"}), "q")
    if reading is None:
        assert not names_outside_lab(value)
        assert _send_value(value) is value and neutral_value(value) is value
        assert refusal is None
    else:
        assert names_outside_lab(value)
        assert _send_value(value) == SAFE_HOST and neutral_value(value) == SAFE_HOST
        assert refusal is not None
        assert "sibling host names a host outside the lab" in refusal


#: Review round 2 (the owner's decision): a JSON float leaf is a decimal (a price, a
#: ratio, a coordinate), never judged as a host. Stated residual, with its WHATWG
#: reading measured in node 22 (``"http://" + 2.5`` is http://2.0.0.5/): an app that
#: builds a URL from a decimal leaf reads one. Measured gain, per point: 196 recorded
#: points beside the float leaf ``2.5`` are bound again against d3cb339 (140 when review
#: round 1 measured it), all from `tests/test_json_points.py`'s adversarial body; no lab
#: answer key or external lab source holds one (`scratchpad/lanes/LABAUTH/r2/`
#: `point_cost.txt`, `float_points.txt`).
_JSON_FLOAT_RESIDUAL = [(2.5, "2.0.0.5"), (8.8, "8.0.0.8"), (19.99, "19.0.0.99"),
                        (0.5, "0.0.0.5"), (134744072.5, None)]


@pytest.mark.parametrize("value, reading", _JSON_FLOAT_RESIDUAL)
def test_a_json_float_leaf_is_the_lab_a_stated_residual(value, reading):
    """Review round 2: `names_outside_lab` judges a JSON number only when it is an integer
    (an IPv4 integer form such as ``134744072``, or ``134744072.0``); a decimal leaf is
    sent as given, and a JSON body holding it as a sibling is rebuilt."""
    from fuzzlab.audit.value_shape import names_outside_lab, neutral_value
    from fuzzlab.core import jsonbody
    from fuzzlab.harness.auto import _outside_lab, _send_value
    assert not names_outside_lab(value)
    assert _send_value(value) is value and neutral_value(value) is value
    assert _outside_lab(jsonbody.leaves({"price": value, "q": "x"}), "q") is None


def test_an_answer_keys_json_number_sibling_leaves_its_point_unbound():
    """Review R3 through `points_from_ground_truth` (a JSON-leaf point, FR-FUZZ-54): the
    point beside a number leaf naming 8.8.8.8 carries a `replay_refusal`, and the
    number's own point has loopback in its slot."""
    from fuzzlab.harness.auto import points_from_ground_truth
    from fuzzlab.labels.contract import GroundTruth, InjectionPoint
    body = {"host": 134744072, "q": "x"}
    gt = GroundTruth(target="t", points=[
        InjectionPoint(url="/api/ping", method="POST", param=p, location="body",
                       rendering="server", json_body=body) for p in ("host", "q")])
    points, _skipped = points_from_ground_truth(gt, "http://127.0.0.1:4000")
    by = {p.param: p for p in points}
    refusal = by["q"].replay_refusal
    assert refusal is not None and "sibling host names a host outside the lab" in refusal
    assert by["host"].replay_refusal is None
    assert dict((name[0], v) for name, v in by["q"].base_entries)["host"] == "127.0.0.1"


#: IANA's root-zone TLD list as downloaded on 2026-10-22 (FR-AUD-32): the SHA-256 of
#: https://data.iana.org/TLD/tlds-alpha-by-domain.txt, version 2026102100.
_IANA_TLDS_SHA256 = "ef731da5bd52d570d5fdf7b8737e06ed661ed65fbef60f7ad9f26063a49efb6f"


def test_the_bare_token_rule_reads_ianas_root_zone_and_nothing_else():
    """The bare-token rule's delegation is the bundled IANA snapshot's, label for label:
    every listed TLD is outside after a name, and every label it does not list -- each
    two-letter label, reserved names, file extensions -- is the lab (so no hand-made rule,
    two letters or `GENERIC_TLDS`, decides). The file is IANA's download byte for byte
    (its digest and version line), and without it every label counts as delegated."""
    import hashlib
    import string
    from importlib import resources

    from fuzzlab.audit import value_shape as vs
    raw = resources.files("fuzzlab.audit.tld_data").joinpath(
        "tlds-alpha-by-domain.txt").read_bytes()
    lines = raw.decode("ascii").splitlines()
    tlds = {line.lower() for line in lines[1:]}
    labels = tlds | {a + b for a in string.ascii_lowercase for b in string.ascii_lowercase}
    labels |= {"test", "example", "invalid", "localhost", "local", "corp", "internal",
               "lan", "home", "onion", "lab", "txt", "php", "html", "json", "js", "css",
               "pdf", "png", "bak", "log", "ini", "xml", "aspx", "jsp"}
    wrong = sorted(label for label in labels
                   if vs.names_outside_lab("evil." + label) is not (label in tlds))
    assert wrong == []
    assert {"top", "zip", "com", "md", "py", "xn--p1ai"} <= tlds and len(tlds) > 1000
    assert hashlib.sha256(raw).hexdigest() == _IANA_TLDS_SHA256
    assert lines[0].startswith(f"# Version {vs.DELEGATED_TLDS_VERSION}, Last Updated ")
    assert vs.DELEGATED_TLDS_SOURCE == "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    assert len(lines) - 1 == len(tlds) and lines[1:] == sorted(lines[1:])
    saved = vs._DELEGATED_TLDS_FILE
    vs._delegated_tlds.cache_clear()
    vs._DELEGATED_TLDS_FILE = "missing.txt"
    try:
        assert vs.names_outside_lab("evil.test") and vs.names_outside_lab("robots.txt")
    finally:
        vs._DELEGATED_TLDS_FILE = saved
        vs._delegated_tlds.cache_clear()
    assert not vs.names_outside_lab("robots.txt")


#: Every lab answer key (review LA-6: measured per point, not per value).
_LAB = Path(__file__).resolve().parents[1] / "lab"


def test_no_expected_vulnerable_answer_key_point_is_unbound_by_the_lab_predicate():
    """Review LA-6: in ground-truth mode no point a lab's answer key marks
    ``expected_vulnerable`` carries a `replay_refusal` from FR-AUD-20 (on 1338d7a,
    Mongection's SDLMG-0002, /login password, was refused for its sibling
    ``email=user@lab.test`` and read inconclusive without a send). With writes and
    without, every answer key, JSON-leaf and stored-XSS store points included."""
    from fuzzlab.harness.auto import points_from_ground_truth
    from fuzzlab.labels.contract import load
    base = "http://127.0.0.1:4000"
    keys = sorted(p.parent for p in _LAB.glob("ground-truth*/labels.json"))
    refused, checked = [], 0
    for key in keys:
        gt = load(key)
        positive = {((c.origin or base) + (c.url if c.url.startswith("/") else "/" + c.url),
                     c.method.upper(), c.param): c.case_id
                    for c in gt.cases if c.expected_vulnerable}
        for writes in (False, True):
            points, _skipped = points_from_ground_truth(gt, base, browser_available=True,
                                                        writes=writes)
            for p in points:
                checked += 1
                case = positive.get((p.url, p.method.upper(), p.param))
                if case and p.replay_refusal:
                    refused.append((key.name, case, writes, p.replay_refusal))
    assert len(keys) >= 20 and checked > 300
    assert refused == []


#: The recognisers of hosts that must never decide admission (PA-0544(7), PA-0555): the
#: shape classifier and its closed lists, the stand-in, the scope predicate and the
#: address parser. (`urlsplit` is read only to refuse: both splits must agree.)
_HOST_RECOGNISERS = frozenset({
    "value_shape", "neutral_value", "_host_prefix", "_is_hostname", "_is_ip", "_is_url",
    "_is_filename", "_is_path", "GENERIC_TLDS", "FILE_EXTENSIONS", "is_loopback_origin",
    "ipaddress", "redirect_seed"})


def _reached_names(source: str, root: str) -> set[str]:
    """Every name the module-level function ``root`` of ``source`` reads or imports,
    followed through each module-level function of ``source`` it reaches."""
    import ast
    tree = ast.parse(source)
    defs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    names, seen, todo = set(), set(), [root]
    while todo:
        name = todo.pop()
        if name in seen or name not in defs:
            continue
        seen.add(name)
        for node in ast.walk(defs[name]):
            if isinstance(node, ast.Name):
                names.add(node.id)
                todo.append(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names |= {a.asname or a.name for a in node.names}
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.add(node.module.rsplit(".", 1)[-1])
    return names


def test_the_lab_predicate_reaches_no_recogniser_of_hosts():
    """BUG-0555 (N-R3-1's root cause): admission was decided by `neutral_value`'s
    recogniser (an early return). Nothing `names_outside_lab` reaches is one. The stated
    reason is asserted first (review R4: on 7393c90 it fails naming `neutral_value`,
    `value_shape` and `_host_prefix`); the one list the predicate reads is IANA's root
    zone (`_delegated_tlds`, FR-AUD-32), whose source a test of its own checks."""
    import inspect

    from fuzzlab.audit import value_shape
    names = _reached_names(inspect.getsource(value_shape), "names_outside_lab")
    found = sorted(names & _HOST_RECOGNISERS)
    assert found == [], f"names_outside_lab reaches recognisers of hosts: {found}"
    assert {"_names_only_lab", "_lab_authority", "_tail_in_grammar", "_host_token",
            "_named_host", "_delegated_tlds", "_ipv6_shaped", "_judged_text",
            "_special_scheme_mark"} <= names


def test_the_recogniser_guard_catches_a_synthetic_offender():
    """The guard is proven on offenders: N-R3-1's own early return, and a recogniser
    reached three calls down (`_names_only_lab` -> `_lab_authority` -> `_lab_ipv4`). A
    guard of the guard, not a reproduction: on the old code its head is not there."""
    import inspect

    from fuzzlab.audit import value_shape
    source = inspect.getsource(value_shape)
    head = ("    text = _judged_text(value)\n    if text is None:\n        return False\n"
            "    texts = _reader_texts(text)\n")
    assert source.count(head) == 1
    early = source.replace(head, "    text = _judged_text(value)\n"
                                 "    if text is None or neutral_value(text) == text:\n"
                                 "        return False\n    texts = _reader_texts(text)\n")
    assert "neutral_value" in _reached_names(early, "names_outside_lab")
    deep = source.replace("def _lab_ipv4(host: str) -> bool:\n",
                          "def _lab_ipv4(host: str) -> bool:\n"
                          "    return value_shape(host) == 'ip'\n")
    assert deep != source
    assert "value_shape" in _reached_names(deep, "names_outside_lab")


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0555 residual (pre-existing at 7393c90 for an ip or host-name id, wider now: an "
    "8- to 10-digit id is an IPv4 address to WHATWG): the point builder puts loopback in "
    "a point's own slot when its value names a host outside the lab (FR-AUD-20: the "
    "payload's slot), but the access-control replay (`CrossAccountReplayStrategy`, a "
    "SEED category) sends that slot as the object key, so it replays the stand-in and "
    "reads the answer as a negative; owned by FUZZ (FR-FUZZ-67: such a replay is "
    "inconclusive, never made with a stand-in)"))
@pytest.mark.parametrize("own", ["10.0.0.5", "100000001"])
def test_an_access_control_replay_never_reads_a_stand_in_for_its_own_value(tmp_path, own,
                                                                           monkeypatch):
    from fuzzlab.oracle.oracle import Oracle
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import CrossAccountReplayStrategy, PeerAccounts
    from tests import test_cross_account as xa
    from tests.test_forms_phase2 import _points
    pts, _s, _c = _points(tmp_path, pages=[f"http://h/app/record.php?record_id={own}&v=a"])
    point = next(p for p in pts if p.param == "record_id")
    cand = Candidate(url=point.url, param="record_id", method="GET", location="query",
                     category="access-control", base_entries=point.base_entries,
                     replay_refusal=point.replay_refusal)
    monkeypatch.setattr(xa, "RECORDS", {**xa.RECORDS, own: "alice"})   # alice's record
    accounts = PeerAccounts(sender=xa._App("broken", "bob"), owner="alice",
                            peer_name="bob", anonymous=xa._App("broken", None))
    confirmed, inconclusive = Oracle(strategies=[CrossAccountReplayStrategy(
        accounts)]).confirm_outcome(cand, xa._App("broken", "alice"))
    assert confirmed is not None or inconclusive is not None    # never read as a negative


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


# --- the bound send carries its fetch's session material, or is never sent (BUG-0557) -----
class _RotatingPhpApp(_PhpLikeApp):
    """`_PhpLikeApp` in N-R3-2's second layout (BUG-0557): the login box is at
    ``/login``, and ``GET /`` redirects an id that is not logged in there, so ``/`` is
    the session's stable protected resource (the first layout has none: its login page
    is ``/``, an auth endpoint). ``GET /waf`` is a policy block (403) for any id, and
    while ``busy_root`` is positive each ``GET /`` answers 503 with ``Retry-After: 1``
    (one per count) first."""

    def __init__(self):
        super().__init__()
        self.busy_root = 0
        app, base = self, self.server.RequestHandlerClass
        box = ("<html><body><form method=post action='/login'><input name=username>"
               "<input type=password name=password><input type=submit value=Login>"
               "</form></body></html>")

        class Handler(base):
            def do_GET(self):  # noqa: N802 - http.server API
                path = urlsplit(self.path).path
                if path not in ("/waf", "/login") and not (path == "/" and (
                        app.busy_root > 0 or app.users.get(self._sid()) is None)):
                    return super().do_GET()
                app.seen.append(("GET", path, self._sid()))
                if path == "/waf":
                    return self._answer(403, "<html>blocked</html>")
                if path == "/" and app.busy_root > 0:
                    app.busy_root -= 1
                    return self._answer(503, "busy", [("Retry-After", "1")])
                _sid, _user, cookie = self._session()
                if path == "/":
                    return self._answer(302, "", [("Location", "/login"), *cookie])
                return self._answer(200, box, cookie)
        self.server.RequestHandlerClass = Handler


class _VirtualClock:
    """The manager's injectable clock and sleep: a pause is waited out at once."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _php_seam_with(app, *, isolated=False, **manager_kw):
    """`_php_seam` with the manager's keywords, and isolated copies on their own clients
    when ``isolated``."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.core.http import HttpClient
    from fuzzlab.session.manager import SessionManager
    from fuzzlab.tools.probesender import SeamProbeSender
    from tests.test_credentials import FakeBackend
    creds = CredentialStore(backend=FakeBackend())
    creds.set("127.0.0.1", "alice", "alice", "pw-0544")
    mgr = SessionManager(creds, scope_hosts=["127.0.0.1"], browser_login=False,
                         **manager_kw)
    client = HttpClient(RequestBudget(500), ["127.0.0.1"], session=mgr, timeout=5)
    copies = (lambda m: HttpClient(RequestBudget(500), ["127.0.0.1"], session=m,
                                   timeout=5)) if isolated else None
    return SeamProbeSender(client, "alice", manager=mgr, base_url=app.base + "/",
                           isolated_client=copies), client


def _run_between(app, seam, between):
    """The control run, then a run whose page fetch is followed by ``between()``:
    ``(control, verdict, unsure, the requests after the control)``."""
    from fuzzlab.oracle.oracle import Oracle
    from fuzzlab.oracle.strategies import ReflectedXssStrategy
    sender = _BetweenFetchAndSend(seam)
    cand = _php_candidate(app)
    oracle = Oracle(strategies=[ReflectedXssStrategy()])
    control, _ = oracle.confirm_outcome(cand, sender)
    before = len(app.seen)
    sender.between = between
    verdict, unsure = oracle.confirm_outcome(cand, sender)
    return control, verdict, unsure, app.seen[before:]


def _refused_before_it_was_sent(control, verdict, unsure, after):
    from fuzzlab.oracle.oracle import UNBOUND
    assert control is not None and control.confirmed
    assert after[0][:2] == ("GET", "/form")
    assert [r for r in after if r[:2] == ("POST", "/do")] == []      # nothing sent
    assert verdict is None and unsure is not None and unsure.mechanism == UNBOUND
    assert "session material" in unsure.evidence["reason"]


def test_another_sends_policy_block_whose_check_adopts_a_rotation_unbinds_the_bound_send():
    """N-R3-2's N1 (BUG-0557): between the page fetch and the bound send, another send of
    the identity meets a policy block (403), so the manager checks the session's health;
    the check answers LIVE and the app rotates its id on it, adopted in place in the same
    generation. At 7393c90 the bound send carried the old id's token on the new id and
    its 403 was a negative. Now its own ``prepare`` refuses the changed material before
    anything is sent."""
    from fuzzlab.core.http import Request
    app = _RotatingPhpApp()
    try:
        seam, client = _php_seam_with(app)

        def a_policy_blocks_check_rotates():
            app.rotate_on_root = True
            client.send(Request("GET", app.base + "/waf", identity="alice"))
        outcome = _run_between(app, seam, a_policy_blocks_check_rotates)
        sid = seam._manager._state[("127.0.0.1", "alice")].cookies["sid"]
    finally:
        app.close()
    after = outcome[3]
    fetched = after[0][2]
    assert after[1:3] == [("GET", "/waf", fetched), ("GET", "/", fetched)]
    assert sid != fetched and not app.rotate_on_root            # rotated and adopted
    _refused_before_it_was_sent(*outcome)


def test_a_pauses_live_recheck_that_adopts_a_rotation_unbinds_the_bound_send():
    """N-R3-2's N3 (BUG-0557): another send's policy block starts a health check that
    answers 503, so the identity is paused; the bound send's own ``prepare`` waits the
    pause out (a virtual clock), checks again, gets LIVE and adopts the id the app
    rotated on that check. FR-FUZZ-67 covered that re-check only when it found a loss.
    Now the changed material is refused before anything is sent."""
    from fuzzlab.core.http import Request
    clock = _VirtualClock()
    app = _RotatingPhpApp()
    try:
        seam, client = _php_seam_with(app, clock=clock, sleep=clock.sleep)

        def a_pause_then_a_rotation():
            app.busy_root, app.rotate_on_root = 1, True
            client.send(Request("GET", app.base + "/waf", identity="alice"))
        outcome = _run_between(app, seam, a_pause_then_a_rotation)
        report = seam._manager.health_report()
    finally:
        app.close()
    after = outcome[3]
    fetched = after[0][2]
    assert after[1:4] == [("GET", "/waf", fetched), ("GET", "/", fetched),
                          ("GET", "/", fetched)]                # 503, then the re-check
    assert not app.rotate_on_root and clock.now > 1000.0        # waited, rotated
    assert report["127.0.0.1/alice"].get("pauses") == 1 and report["paused_s"] > 0
    _refused_before_it_was_sent(*outcome)


def test_a_bound_send_on_a_real_copy_relogged_in_after_its_fetch_is_never_sent():
    """An isolated copy's re-login (BUG-0557), on the real `SessionManager` and its
    copy: the page is fetched on the copy's session; the app then logs that id out and
    the copy sees the loss, so the bound send's ``prepare`` logs the copy in again. At
    7393c90 that send went out on the new copy id with the old id's token, and only its
    answer was left unread. Now it is refused before it is sent; the copy's re-login is
    still verified against the run's session."""
    from fuzzlab.core.http import Request
    app = _RotatingPhpApp()
    try:
        seam, _client = _php_seam_with(app, isolated=True)
        seam.isolate([app.base + "/do"])

        def lose_the_copy():
            (copy,) = seam._copies.values()
            sid = app.seen[-1][2]                       # the page fetch's: the copy's id
            with app._lock:
                app.users[sid] = None                   # logged out, the id kept
            copy.client.send(Request("GET", app.base + "/form", identity=copy.label))
        outcome = _run_between(app, seam, lose_the_copy)
        (copy,) = seam._copies.values()
        attempts = copy.manager.login_attempts()
        report = seam.isolation_report()
    finally:
        app.close()
    after = outcome[3]
    assert attempts == 2                                # it logged in again for the send
    assert any(r[:2] == ("POST", "/login") for r in after)
    assert report["verifications"] >= 2                 # the re-login was verified
    _refused_before_it_was_sent(*outcome)
