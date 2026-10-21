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


# --- the anonymous sender carries the page's session into the bound send only ----------
class _SessionForm:
    """A loopback app whose CSRF token is tied to an anonymous session cookie set by the
    form page: ``/do`` answers 200 only with the cookie and that session's token."""

    def __init__(self):
        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")                      # PA-0130
        self.tokens: dict[str, str] = {}
        self.answers: list[int] = []
        counter = itertools.count(1)
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                n = next(counter)
                sid, token = f"s{n}", f"t{n}"
                app.tokens[sid] = token
                body = (f"<form method=post action='/do'><input type=hidden "
                        f"name=csrf_token value={token}><input name=q></form>").encode()
                self.send_response(200)
                self.send_header("Set-Cookie", f"sid={sid}; Path=/")
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                form = dict(parse_qsl(self.rfile.read(length).decode(),
                                      keep_blank_values=True))
                cookie = (self.headers.get("Cookie") or "").removeprefix("sid=")
                ok = cookie in app.tokens and form.get("csrf_token") == app.tokens[cookie]
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


def test_the_anonymous_sender_carries_the_pages_session_into_the_bound_send_only():
    """Measured on a real socket: the token is valid only with the cookie its page set.
    The binder's fetch and its send share that cookie; the next plain send does not."""
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.tools.probesender import RequestsProbeSender
    site = _SessionForm()
    try:
        sender = RequestsProbeSender(timeout=5)
        candidate = Candidate(url=site.base + "/do", param="q", method="POST",
                              location="body",
                              base_entries=(("csrf_token", ""), ("q", "x")),
                              bindings={"page": site.base + "/form",
                                        "fresh": ["csrf_token"]})
        bound = _FormBoundSender(sender, candidate)
        for _ in range(2):
            bound.send(site.base + "/do", "q", "M", method="POST", location="body")
        sender.send(site.base + "/do", "q", "M", method="POST", location="body",
                    entries=[("csrf_token", "t1"), ("q", "M")])
    finally:
        site.close()
    assert site.answers == [200, 200, 403]
