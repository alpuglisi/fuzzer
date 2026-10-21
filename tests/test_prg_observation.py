"""FR-FUZZ-49: post/redirect/get (PRG) observation for the server-side confirmers.

Juice Shop answers ``POST /profile username=#{11*13}`` with ``302 /profile`` and no
``143`` in its body; ``GET /profile`` shows ``143``. The confirmers read only the
probe's own response and probes never follow redirects, so this SSTI was never
confirmed. Now an opt-in strategy's whole run (M4 SSTI/SpEL, M5 reflected-context, M2
error signature, the path-traversal markers) asks its sender for PRG observation: a
PRG redirect to a target that passes every send gate gets one plain GET on the probe's
own session route, attached as the separate object ``probe.followed``; the strategy
reads ``probe.followed or probe`` whole. The follow-up is counted and budgeted.

Every app here is an in-process fixture: a loopback ``ThreadingHTTPServer`` on port 0,
or a transport function (no socket at all). Nothing reaches a running lab.
"""

from __future__ import annotations

import html
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlsplit

import pytest

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient
from fuzzlab.harness.auto import _CountingSender
from fuzzlab.oracle import Oracle
from fuzzlab.oracle.oracle import PRG_COUNTERS, _PrgRun
from fuzzlab.oracle.probe import (PRG_OBSERVED, PRG_UNOBSERVED, Candidate, Probe,
                                  accepts_prg)
from fuzzlab.oracle.strategies import (OpenRedirectStrategy,
                                       SqliBooleanStrategy, SqliErrorStrategy,
                                       SqliTimingStrategy, SstiStrategy,
                                       default_strategies)
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender

SQL_ERROR = "You have an error in your SQL syntax; check the manual"
#: What an RFC 3986 path-segment encoder leaves raw beyond the unreserved characters
#: (``pchar``: sub-delims, ``:`` and ``@``), so ``{pchar}`` respells ``%2A`` as ``*``.
PCHAR_RAW = "!$&'()*+,;=:@"


# --- a loopback PRG app -------------------------------------------------------------
class PrgSite:
    """``POST /profile`` stores its fields and answers ``status`` (303) to ``location``
    (``/profile``); ``GET /profile`` renders the stored ``username`` per ``render``:

    * ``evaluate`` -- ``#{a*b}`` evaluated (Juice Shop's shape), the rest escaped;
    * ``history`` -- the result of every ``#{}`` username ever posted (a history page);
    * ``escape`` / ``raw`` -- HTML-escaped / unescaped in a ``<p>``;
    * ``json`` -- ``application/json`` echo of the raw value;
    * ``sqlerr-always`` -- a SQL error on every render;
    * ``sqlerr-quote`` -- a SQL error when the stored username has a quote (a
      second-order SQLi).
    ``reject_plain``: a POST whose value has no quote is refused with a 400 (no
    redirect), as an app validating its input would refuse a control.

    A path point (FR-FUZZ-69): ``POST /p/<seg>/view`` stores ``<seg>`` as the username
    and answers ``status`` to ``location``, built from the request as an app redirecting
    to the resource it was posted does: ``{base}`` is the site's origin, ``{seg}`` the
    segment as received, ``{pchar}`` the segment decoded and re-encoded as an RFC 3986
    path segment (sub-delimiters such as ``$`` and ``*`` raw); ``GET /p/<seg>/<any>``
    renders its **own** segment with ``#{a*b}`` evaluated -- what it shows comes from the
    request itself, never from a POST."""

    def __init__(self, render="evaluate", status=303, location="/profile",
                 reject_plain=False, set_cookie=False, with_location=True):
        self.render, self.status, self.location = render, status, location
        self.reject_plain, self.set_cookie = reject_plain, set_cookie
        self.with_location = with_location
        self.values = {"username": "fuzzlab", "bio": "hi"}
        self.history: list[str] = []
        self.log: list[tuple[str, str, dict]] = []
        self.headers: list[dict[str, str]] = []          # each request's headers
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, status, body=b"", ctype="text/html", headers=()):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802 - http.server API
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                data = dict(parse_qsl(raw.decode(), keep_blank_values=True))
                site.log.append(("POST", self.path, data))
                site.headers.append(dict(self.headers))
                segs = urlsplit(self.path).path.split("/")
                if len(segs) == 4 and segs[1] == "p" and segs[3] == "view":
                    site.values["username"] = unquote(segs[2])
                    site.history.append(site.values["username"])
                    where = site.location.replace("{base}", site.base).replace(
                        "{seg}", segs[2]).replace(
                        "{pchar}", quote(unquote(segs[2]), safe=PCHAR_RAW))
                    return self._reply(site.status, b"<html>See Other</html>",
                                       headers=[("Location", where)])
                if urlsplit(self.path).path != "/profile":
                    return self._reply(404, b"no")
                if site.reject_plain and not any("'" in v for v in data.values()):
                    return self._reply(400, b"<html>invalid input</html>")
                site.values.update(data)
                if "username" in data:
                    site.history.append(data["username"])
                extra = [("Location", site.location)] if site.with_location else []
                if site.set_cookie:
                    extra.append(("Set-Cookie", "flash=zqcookie; Path=/"))
                self._reply(site.status, b"<html>See Other</html>", headers=extra)

            def do_GET(self):  # noqa: N802 - http.server API
                parts = urlsplit(self.path)
                query = dict(parse_qsl(parts.query, keep_blank_values=True))
                site.log.append(("GET", self.path, query))
                site.headers.append(dict(self.headers))
                if parts.path == "/profile":
                    return self._reply(*site.page())
                segs = parts.path.split("/")
                if len(segs) == 4 and segs[1] == "p":    # its own segment, evaluated
                    own = html.escape(site._evaluate(unquote(segs[2])))
                    return self._reply(200, f"<html><p>{own}</p></html>".encode())
                if parts.path == "/again":               # one more hop
                    return self._reply(302, b"", headers=[("Location", "/profile")])
                if parts.path == "/redir":               # an open redirect (M9)
                    return self._reply(302, b"", headers=[("Location",
                                                           query.get("to", "/"))])
                if parts.path == "/search":              # GET -> 302 -> results
                    return self._reply(302, b"", headers=[(
                        "Location", "/results?" + parts.query)])
                if parts.path == "/results":
                    return self._reply(200, f"<p>{query.get('q', '')}</p>".encode())
                self._reply(200, b"<html>other page</html>")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    @staticmethod
    def _evaluate(value: str) -> str:
        return re.sub(r"#\{(\d+)\*(\d+)\}", lambda m: str(int(m[1]) * int(m[2])), value)

    def page(self):
        name = self.values["username"]
        if self.render == "json":
            return 200, json.dumps({"username": name}).encode(), "application/json"
        if self.render == "evaluate":
            body = html.escape(self._evaluate(name))
        elif self.render == "history":                   # the results of every #{}
            body = " | ".join(html.escape(self._evaluate(n)) for n in self.history
                              if "#{" in n)
        elif self.render == "raw":
            body = name
        elif self.render == "editform":     # Juice Shop's /profile shape (BUG-0133)
            return 200, (f'<html><body><form><input id="username" name="username" '
                         f'value="{html.escape(name, quote=True)}"></form>'
                         f'<p class="name">{html.escape(self._evaluate(name))}</p>'
                         f'</body></html>').encode(), "text/html"
        elif self.render == "sqlerr-always":
            body = SQL_ERROR + " " + html.escape(name)
        elif self.render == "sqlerr-quote" and ("'" in name or '"' in name):
            body = SQL_ERROR
        else:
            body = html.escape(name)
        return 200, f"<html><body><h1>Profile</h1><p>{body}</p></body></html>".encode()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def site():
    made: list[PrgSite] = []

    def make(**kw):
        made.append(PrgSite(**kw))
        return made[-1]
    yield make
    for s in made:
        s.close()


def _post(site_, category, param="username", **kw):
    return Candidate(url=site_.base + "/profile", param=param, method="POST",
                     location="body", category=category, **kw)


class _NoPrg:
    """A sender wrapper that does not declare PRG capability: the oracle never asks it
    (the behaviour before FR-FUZZ-49)."""

    def __init__(self, inner):
        self._inner = inner

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        return self._inner.send(url, param, value, timing=timing, method=method,
                                location=location, content_type=content_type,
                                entries=entries)


class _Spy:
    """Records the ``prg`` property of every send that reaches the real sender."""
    prg_capable = True

    def __init__(self, inner):
        self._inner = inner
        self.prg: list[bool] = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        self.prg.append(prg)
        return self._inner.send(url, param, value, timing=timing, method=method,
                                location=location, content_type=content_type,
                                entries=entries, prg=prg)


# --- M4: the PRG SSTI confirms only through the follow-up ------------------------------
def test_prg_ssti_confirms_only_through_the_follow_up(site):
    app = site(render="evaluate")
    cand = _post(app, "server-side-template-injection")
    sender = RequestsProbeSender()
    # the strategy alone, with no PRG run: the 303's own body never shows the product
    assert SstiStrategy().confirm(cand, sender) is None
    assert Oracle().confirm(cand, _NoPrg(sender)) is None
    verdict = Oracle().confirm(cand, sender)
    assert verdict is not None and verdict.vuln_class == "ssti"
    assert verdict.evidence["observation"] == "prg"
    assert verdict.evidence["payload"].startswith("#{")
    # the raw probe stays the 3xx; the follow-up is its own whole object
    probe = sender.send(cand.url, "username", "#{11*13}", method="POST", location="body",
                        prg=True)
    assert probe.status == 303 and "143" not in probe.text
    assert probe.headers["Location"] == "/profile"
    assert probe.prg == PRG_OBSERVED and probe.follow_up_sends == 1
    assert probe.followed.status == 200 and "143" in probe.followed.text
    assert probe.followed.url == app.base + "/profile"
    assert probe.followed.followed is None


def test_every_send_of_a_prg_run_asks_for_the_follow_up(site):
    """P1: the property belongs to the strategy run, so probes and second samples (and
    M2's controls, below) are observed alike."""
    app = site(render="evaluate")
    spy = _Spy(RequestsProbeSender())
    assert Oracle(strategies=[SstiStrategy()]).confirm(
        _post(app, "server-side-template-injection"), spy) is not None
    *run, restore = spy.prg                     # the last send is the P9 restore
    assert len(run) >= 2 and all(run) and restore is False


def test_a_history_page_still_showing_product_1_is_no_attribution(site):
    """P5 / BUG-0117: product 2 must be in probe 2's follow-up and product 1 absent."""
    app = site(render="history")
    assert Oracle().confirm(_post(app, "server-side-template-injection"),
                            RequestsProbeSender()) is None


def test_the_restore_leaves_the_forms_own_default(site):
    """P9: after a candidate's PRG run, one benign send of the form's own default (or
    the filler) at the point; counted."""
    app = site(render="evaluate")
    oracle = Oracle()
    cand = _post(app, "server-side-template-injection",
                 base_entries=(("username", "alice"), ("bio", "hi")))
    assert oracle.confirm(cand, RequestsProbeSender()) is not None
    assert app.values["username"] == "alice"
    assert app.log[-1] == ("POST", "/profile", {"username": "alice", "bio": "hi"})
    # every probe carried its siblings; no sibling is ever bound into a follow-up
    assert all(d == {} for m, _p, d in app.log if m == "GET")
    assert all(d.get("bio") == "hi" for m, _p, d in app.log if m == "POST")
    assert oracle.prg_counts["prg_restores"] == 1
    oracle2 = Oracle()
    oracle2.confirm(_post(app, "server-side-template-injection"), RequestsProbeSender())
    assert app.values["username"] == "fuzzlab" and oracle2.prg_counts["prg_restores"] == 1


def test_the_restore_value_is_the_fields_own_string_default_or_the_filler():
    from fuzzlab.oracle.oracle import _restore_value
    from fuzzlab.tools.store_adapter import LADDER_TEXT

    def cand(param, location, entries):
        return Candidate(url="http://h/p", param=param, method="POST",
                         location=location, base_entries=entries)
    assert _restore_value(cand("u", "body", (("u", "alice"), ("b", "x")))) == "alice"
    assert _restore_value(cand("u", "body", (("u", ""),))) == LADDER_TEXT
    assert _restore_value(cand("u", "body", None)) == LADDER_TEXT
    leaves = ((["user", "name"], "bob"), (["user", "age"], 5))
    assert _restore_value(cand("user.name", "json", leaves)) == "bob"
    assert _restore_value(cand("user.age", "json", leaves)) == LADDER_TEXT   # not a str
    assert _restore_value(cand("a.b[", "json", leaves)) == LADDER_TEXT       # malformed


class _RestoreRaises:
    """Evaluates ``#{a*b}`` in its follow-ups (a PRG SSTI); the restore send (a POST
    without ``prg``) raises ``error``."""
    prg_capable = True

    def __init__(self, error):
        self.error = error

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        if not prg:
            raise self.error
        probe = Probe(303, "", headers={"Location": "/show"})
        probe.followed = Probe(200, "<p>" + PrgSite._evaluate(value) + "</p>",
                               headers={"Content-Type": "text/html"}, url="http://h/show")
        probe.prg = PRG_OBSERVED
        return probe


def test_a_restore_that_raises_never_changes_the_outcome(tmp_path):
    """Reviewers A S1 / B must-fix 1: the restore is total. Its failure is counted and
    logged; the confirming verdict (and its finding) stands. An interrupt is not
    contained (PA-0106(2): one contained, one propagated)."""
    from fuzzlab.core.store import Store
    from fuzzlab.oracle.probe import UnplaceableLocation
    cand = Candidate(url="http://h/p", param="v", method="POST", location="body",
                     category="server-side-template-injection")
    for error in (ConnectionError("down"), UnplaceableLocation("no"),
                  RuntimeError("seam session")):
        with Store(tmp_path / f"{type(error).__name__}.db") as store:
            run_id = store.start_run("auto", "h")
            oracle = Oracle(store=store, run_id=run_id)
            verdict, unsure = oracle.confirm_outcome(cand, _RestoreRaises(error))
            assert verdict is not None and verdict.confirmed and unsure is None
            assert oracle.prg_counts["prg_restore_failed"] == 1
            assert oracle.prg_counts["prg_restores"] == 0
            assert store.conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1
    with pytest.raises(KeyboardInterrupt):
        Oracle().confirm_outcome(cand, _RestoreRaises(KeyboardInterrupt()))


def test_the_sender_chain_run_auto_builds_accepts_prg(tmp_path, monkeypatch):
    """Reviewer B's nit: the chain `run_auto` hands the pipeline (ground truth:
    `_CountingSender`; crawl: `_FragmentGuard` over it) reports the real sender's PRG
    capability."""
    from fuzzlab.core.store import Store
    from fuzzlab.harness import auto
    from fuzzlab.labels import contract
    from tests.test_auto import GT_DIR
    seen = []

    class Stop(Exception):
        pass

    def capture(points, store, run_id, sender, plan, **kw):
        seen.append(sender)
        raise Stop
    monkeypatch.setattr(auto, "run_pipeline", capture)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("auto", "h")
        for source in ("ground-truth", "crawl"):
            with pytest.raises(Stop):
                auto.run_auto(base_url="http://127.0.0.1:1/", store=store, run_id=run_id,
                              sender=RequestsProbeSender(), mode="automatic",
                              ground_truth=contract.load(GT_DIR), points_source=source)
    assert [type(s).__name__ for s in seen] == ["_CountingSender", "_FragmentGuard"]
    assert all(accepts_prg(s) is True for s in seen)
    assert accepts_prg(auto._CountingSender(_NoPrg(RequestsProbeSender()))) is False


# --- M5 ------------------------------------------------------------------------------
def test_a_reflection_confirmed_only_through_the_follow_up_is_stored_xss(site):
    """P6: the value rendered on another request is stored XSS, evidence ``prg``."""
    app = site(render="raw")
    verdict = Oracle().confirm(_post(app, "xss"), RequestsProbeSender())
    assert verdict is not None and verdict.mechanism == "reflected-context"
    assert verdict.vuln_class == "xss-stored"
    assert verdict.evidence["observation"] == "prg"


def test_a_payload_that_rode_the_redirect_is_reflected_xss(site):
    """P6 refined: a GET probe whose 302 target carries the payload in its query, and
    whose rendered follow-up executes it structurally, is reflected XSS (``prg-redirect``),
    never stored."""
    app = site()
    verdict = Oracle().confirm(Candidate(url=app.base + "/search", param="q",
                                         category="xss"), RequestsProbeSender())
    assert verdict is not None and verdict.vuln_class == "xss-reflected"
    assert verdict.evidence["observation"] == "prg-redirect"
    assert any(p == "/results" and q.get("q") == verdict.evidence["signature"]
               for _m, p, q in [(m, urlsplit(x).path, d) for m, x, d in app.log])


@pytest.mark.parametrize("sender_name", ["anonymous", "seam"])
@pytest.mark.parametrize("location", [
    "edit", "#top", "?tab=2", "/p/{seg}/edit", "{base}/p/{seg}/edit", "/p/{pchar}/edit"],
    ids=["relative", "fragment", "query", "absolute-path", "absolute-url",
         "absolute-path-re-encoded"])
def test_a_path_points_follow_up_that_would_re_send_the_payload_never_confirms(
        site, sender_name, location):
    """FR-FUZZ-69 (BUG-0542): ``POST /p/<payload>/view`` -> ``303 <location>``. A browser
    would fetch ``/p/<payload>/edit`` (or the placed URL again), a page that evaluates its
    own path. On c483dc1 the sender made that request for ``edit``/``#top``/``?tab=2``,
    and on 9d0e819 still for an absolute path or URL the server built from the request
    (``/p/<payload>/edit``, the same browser request as ``edit``); M4 confirmed through
    it with ``observation: "prg"``, as if it were the page the POST led to. The
    follow-up is refused instead, however the server spelled the segment: no request
    after the POSTs, no confirmation."""
    app = site(location=location)
    cand = Candidate(url=app.base + "/p/{id}/view", param="id", method="POST",
                     location="path", category="server-side-template-injection")
    sender = RequestsProbeSender() if sender_name == "anonymous" else _client_sender()
    assert Oracle(strategies=[SstiStrategy()]).confirm(cand, sender) is None
    assert {m for m, _p, _d in app.log} == {"POST"}, app.log


def test_a_path_points_follow_up_that_leaves_its_segment_still_confirms(site):
    """The control: the same path point redirected to ``/profile``, which renders the
    stored value, is confirmed through its follow-up (a PRG observation)."""
    app = site(location="/profile")
    cand = Candidate(url=app.base + "/p/{id}/view", param="id", method="POST",
                     location="path", category="server-side-template-injection")
    verdict = Oracle(strategies=[SstiStrategy()]).confirm(cand, RequestsProbeSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.evidence["observation"] == "prg"
    assert {p for m, p, _d in app.log if m == "GET"} == {"/profile"}


@pytest.mark.parametrize("encode", [
    lambda v: v, lambda v: quote(v, safe=""), lambda v: quote_plus(v),
    lambda v: html.escape(v), lambda v: json.dumps(v)[1:-1]])
def test_a_follow_up_url_carrying_any_form_of_the_token_rode_the_redirect(encode):
    from fuzzlab.oracle.strategies import _rode_the_redirect
    token, fragment = "zqxbab12cd34", "\"><script>zqxbab12cd34</script>"
    probe = Probe(302, "", followed=Probe(200, "", url="http://h/r?x=" + encode(
        fragment) + "&y=1"))
    assert _rode_the_redirect(probe, [fragment, token])
    # the payload alone, in this encoding (not only its plain token), is recognised
    value = "\"><svg onload=1>\\x"            # a quote and a backslash: every form differs
    bare = Probe(302, "", followed=Probe(200, "", url="http://h/r?x=" + encode(value)))
    assert _rode_the_redirect(bare, [value])
    clean = Probe(302, "", followed=Probe(200, "", url="http://h/profile"))
    assert not _rode_the_redirect(clean, [fragment, token])
    assert not _rode_the_redirect(Probe(302, ""), [fragment, token])


def test_a_json_follow_up_echoing_the_payload_never_confirms_m5(site):
    """B1/P4: the HTML check and the structure come from the same (follow-up)
    response; a JSON echo never executes (BUG-0127)."""
    app = site(render="json")
    assert Oracle().confirm(_post(app, "xss"), RequestsProbeSender()) is None


def test_an_escaped_render_never_confirms_m5(site):
    app = site(render="escape")
    assert Oracle().confirm(_post(app, "xss"), RequestsProbeSender()) is None


def test_a_get_probe_redirect_is_followed_and_counted_apart(site):
    """P2: a 302 after a GET is followed too, counted ``prg_follow_ups_get``."""
    app = site()
    oracle = Oracle()
    cand = Candidate(url=app.base + "/search", param="q", category="xss")
    assert oracle.confirm(cand, RequestsProbeSender()) is not None
    assert oracle.prg_counts["prg_follow_ups_get"] >= 2
    assert oracle.prg_counts["prg_follow_ups"] == 0
    assert oracle.prg_counts["prg_restores"] == 0          # a GET point is not restored


# --- M2 ------------------------------------------------------------------------------
def test_a_second_order_sql_error_confirms_only_through_the_follow_up(site):
    app = site(render="sqlerr-quote")
    verdict = Oracle().confirm(_post(app, "sql-injection"), RequestsProbeSender())
    assert verdict is not None and verdict.mechanism == "error-signature"
    assert verdict.evidence["observation"] == "prg"
    assert verdict.evidence["second_order"] is True
    assert SqliErrorStrategy().confirm(_post(app, "sql-injection"),
                                       RequestsProbeSender()) is None


def test_a_page_always_showing_a_sql_error_is_not_m2(site):
    app = site(render="sqlerr-always")
    assert SqliErrorStrategy().confirm(_post(app, "sql-injection"), _PrgRun(
        RequestsProbeSender(), dict.fromkeys(PRG_COUNTERS, 0))) is None


def test_a_rejected_control_refuses_m2(site):
    """P5: the control is sent with PRG too; an app that rejects it (a 400, no
    follow-up) leaves the signature unattributed."""
    app = site(render="sqlerr-quote", reject_plain=True)
    assert SqliErrorStrategy().confirm(_post(app, "sql-injection"), _PrgRun(
        RequestsProbeSender(), dict.fromkeys(PRG_COUNTERS, 0))) is None
    assert any(m == "POST" and "'" not in d["username"] for m, _p, d in app.log)


def test_a_stored_quote_from_an_earlier_strategy_never_confirms_m4_m5_m2(site):
    """B4: a value an earlier strategy left in the account (the username's quote, which
    the profile page renders as a SQL error) never makes another field confirm."""
    app = site(render="sqlerr-quote")
    app.values["username"] = "'"
    for category in ("sql-injection", "server-side-template-injection", "xss"):
        cand = _post(app, category, param="bio")
        assert Oracle().confirm(cand, RequestsProbeSender()) is None, category
        assert app.values["username"] == "'"              # never touched by bio's run


# --- path traversal marker ------------------------------------------------------------
def test_a_passwd_marker_only_through_the_follow_up_confirms_and_its_control_is_alike():
    class Fake:
        """POST stores; the page shows the marker for a traversal value only."""
        prg_capable = True

        def __init__(self, reject_control=False):
            self.stored, self.reject_control = "", reject_control

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            if self.reject_control and "/" not in value:
                return Probe(400, "bad")
            self.stored = value
            probe = Probe(303, "", headers={"Location": "/file"})
            if prg:
                text = "root:x:0:0:root" if "passwd" in value and "/" in value else "-"
                probe.followed, probe.prg = Probe(200, text, url="http://h/file"), \
                    PRG_OBSERVED
            return probe
    cand = Candidate(url="http://h/f", param="file", method="POST", location="body",
                     category="file-inclusion")
    verdict = Oracle().confirm(cand, Fake())
    assert verdict is not None and verdict.evidence["observation"] == "prg"
    assert Oracle().confirm(cand, Fake(reject_control=True)) is None


# --- the trigger, one hop, the gates --------------------------------------------------
def test_a_307_after_post_is_not_followed_but_after_get_it_is(site):
    app = site(status=307)
    sender = RequestsProbeSender()
    probe = sender.send(app.base + "/profile", "username", "x", method="POST",
                        location="body", prg=True)
    assert probe.followed is None and probe.prg.startswith("skipped: a 307 after POST")
    assert [m for m, _p, _d in app.log] == ["POST"]
    app2 = site()
    probe = sender.send(app2.base + "/redir", "to", "/profile", prg=True)
    assert probe.status == 302 and probe.prg == PRG_OBSERVED


def test_a_second_redirect_is_no_observation(site):
    app = site(location="/again")
    oracle = Oracle()
    probe = RequestsProbeSender().send(app.base + "/profile", "username", "x",
                                       method="POST", location="body", prg=True)
    assert probe.prg == PRG_UNOBSERVED and probe.followed is None
    assert probe.follow_up_sends == 1
    assert [p for _m, p, _d in app.log] == ["/profile", "/again"]   # one hop only
    oracle.confirm(_post(app, "server-side-template-injection"), RequestsProbeSender())
    assert oracle.prg_counts["prg_unobserved"] == oracle.prg_counts["prg_follow_ups"] > 0


@pytest.mark.parametrize("location,why", [
    ("http://127.0.0.2:1/profile", "another origin"),
    ("https://example.com/profile", "another origin"),
    ("/logout.php", "destructive target"),
    ("/checkout", "transaction target"),
    ("/account/password", "account target"),
    ("/login", "login page"),
    ("javascript:alert(1)", "another origin"),
])
def test_a_refused_target_is_never_fetched(site, location, why):
    app = site(location=location)
    probe = RequestsProbeSender().send(app.base + "/profile", "username", "x",
                                       method="POST", location="body", prg=True)
    assert probe.prg == f"skipped: {why}" and probe.followed is None
    assert probe.follow_up_sends == 0
    assert [m for m, _p, _d in app.log] == ["POST"]


def test_open_redirect_reads_the_raw_location(site):
    """M9 is never opted in: it reads the raw ``Location``, and no PRG is asked."""
    app = site()
    spy = _Spy(RequestsProbeSender())
    verdict = Oracle().confirm(Candidate(url=app.base + "/redir", param="to",
                                         category="open-redirect"), spy)
    assert verdict is not None and verdict.evidence["sink"] == "location-header"
    assert spy.prg and not any(spy.prg)
    assert OpenRedirectStrategy.prg is False


# --- P7: timing, boolean and differential engines never follow ------------------------
#: The opt-in set, pinned (P1/P7): a new opt-in is a reviewed change.
PRG_STRATEGIES = {"SqliErrorStrategy", "ReflectedXssStrategy", "SstiStrategy",
                  "GoTemplateSstiStrategy", "SpelInjectionStrategy",
                  "PathTraversalStrategy", "PathTraversalFsPathReadStrategy"}


def test_only_the_reviewed_strategies_opt_in():
    opted = {type(s).__name__ for s in default_strategies() if s.prg}
    assert opted == PRG_STRATEGIES
    for cls in (SqliTimingStrategy, SqliBooleanStrategy, OpenRedirectStrategy):
        assert cls.prg is False


def test_sqli_timing_and_boolean_never_cause_a_follow_up(monkeypatch):
    class Redirecting:
        prg_capable = True

        def __init__(self):
            self.prg = []

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            self.prg.append(prg)
            return Probe(303, "", 0.01, {"Location": "/p"})
    cand = Candidate(url="http://h/p", param="q", method="POST", location="body",
                     category="sql-injection")
    for strategy in (SqliTimingStrategy(), SqliBooleanStrategy()):
        sender = Redirecting()
        Oracle(strategies=[strategy]).confirm(cand, sender)
        assert sender.prg and not any(sender.prg), type(strategy).__name__


def test_a_timing_send_never_follows(site):
    app = site(render="evaluate")
    for sender in (RequestsProbeSender(), _client_sender()):
        probe = sender.send(app.base + "/profile", "username", "x", timing=True,
                            method="POST", location="body", prg=True)
        assert probe.status == 303 and probe.prg is None and probe.followed is None
    assert [m for m, _p, _d in app.log] == ["POST", "POST"]


def _client_sender(budget=None):
    """An anonymous `SeamProbeSender` over the real requests transport (loopback)."""
    return SeamProbeSender(HttpClient(budget or RequestBudget(500), ["127.0.0.1"]))


# --- P8: counted in the run's requests and the budget ---------------------------------
def test_a_follow_up_is_counted_in_requests_and_spends_the_budget(site):
    app = site(render="evaluate")
    budget = RequestBudget(500)
    counting = _CountingSender(_client_sender(budget))
    assert accepts_prg(counting)
    oracle = Oracle()
    assert oracle.confirm(_post(app, "server-side-template-injection"), counting)
    follow_ups = oracle.prg_counts["prg_follow_ups"]
    assert follow_ups >= 2
    assert counting.count == len(app.log) == budget.used()
    assert len([1 for m, _p, _d in app.log if m == "GET"]) == follow_ups


def test_the_pipeline_reports_prg_counts_and_requests(site, tmp_path):
    from fuzzlab.audit import InjectionPoint
    from fuzzlab.core.runmode import RunPlan
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import run_pipeline
    app = site(render="evaluate")
    counting = _CountingSender(RequestsProbeSender())
    plan = RunPlan(mode="manual", categories=["server-side-template-injection"],
                   scored=False, source="manual")
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("auto", "127.0.0.1")
        result = run_pipeline([InjectionPoint(url=app.base + "/profile", param="username",
                                              method="POST", location="body")],
                              store, run_id, counting, plan, budget=counting)
    m = result.metrics
    assert m["findings"] == 1 and m["prg_follow_ups"] >= 2 and m["prg_restores"] == 1
    assert m["requests"] == len(app.log) == counting.count


def test_golden_impact_is_zero_with_prg_enabled(tmp_path, monkeypatch, capsys):
    """B3/P8: with a PRG-capable sender, a ground-truth run whose app never answers a PRG
    redirect prints the byte-identical golden summary (no follow-up, no new metric)."""
    from tests import test_auto_budget
    from tests.test_auto import AutoSender
    from tests.test_auto_plugins import CASES, GOLDEN, _run
    asked: list[bool] = []

    class PrgAutoSender(AutoSender):
        prg_capable = True

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            asked.append(prg)
            return super().send(url, param, value, timing=timing, method=method,
                                location=location)
    monkeypatch.setattr(test_auto_budget, "AutoSender", PrgAutoSender)
    rc, out = _run(tmp_path, monkeypatch, capsys, *CASES["score_only"])
    assert f"rc={rc}\n" + out == (GOLDEN / "score_only.txt").read_text()
    assert any(asked) and not all(asked)


def test_the_auto_summary_reports_prg_follow_ups(tmp_path, monkeypatch, capsys):
    from tests import test_auto_budget
    from tests.test_auto import AutoSender
    from tests.test_auto_plugins import _run

    class PrgAutoSender(AutoSender):
        prg_capable = True

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            probe = super().send(url, param, value, timing=timing, method=method,
                                 location=location)
            if prg and method == "POST":
                return Probe(303, "", headers={"Location": "/x"}, followed=probe,
                             prg=PRG_OBSERVED)
            return probe
    monkeypatch.setattr(test_auto_budget, "AutoSender", PrgAutoSender)
    rc, out = _run(tmp_path, monkeypatch, capsys, "--score", earlier=False)
    assert rc == 0
    line = next(x for x in out.splitlines() if "post/redirect/get follow-ups" in x)
    assert re.search(r"follow-ups: [1-9]\d* after POST, 0 after GET, 0 without an "
                     r"observation; restores: [1-9]", line), line


# --- P3: the session route, isolation, the login page, the header breaker -------------
from tests.test_login_form_isolation import BASE, FakeApp, _seam  # noqa: E402

ISO = BASE + "iso_form.php"


class PrgFakeApp(FakeApp):
    """`FakeApp` plus a per-session stored value: ``POST /app/profile.php`` and the
    isolated ``POST /app/iso_form.php`` store it for the submitting session and redirect
    to ``redirect`` (``/app/show.php``, which evaluates it for that session only)."""

    def __init__(self, redirect="/app/show.php", anonymous_ok=False, **kw):
        super().__init__(**kw)
        self.redirect = redirect
        self.anonymous_ok = anonymous_ok        # the PRG pages need no session
        self.stored: dict[str | None, str] = {}

    def page(self, method, url, sid, data):
        path = urlsplit(url).path
        ok = self.anonymous_ok or sid in self.sessions
        if path in ("/app/profile.php", "/app/iso_form.php") and method == "POST" and ok:
            self.stored[sid] = data.get("name", "")
            return 303, {"Location": self.redirect}, b""
        if path == "/app/show.php" and ok:
            shown = PrgSite._evaluate(self.stored.get(sid, ""))
            return 200, {"Content-Type": "text/html"}, f"<p>{shown}</p>".encode()
        return super().page(method, url, sid, data)


def test_an_isolated_post_is_followed_on_the_same_copy():
    app = PrgFakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([ISO])
    sender.send(BASE + "portal.php", "x", "1")              # the run's own session
    main_sid = app.requests[-1][2]
    verdict = Oracle().confirm(Candidate(url=ISO, param="name", method="POST",
                                         location="body",
                                         category="server-side-template-injection"),
                               sender)
    assert verdict is not None and verdict.evidence["observation"] == "prg"
    posts = [r for r in app.requests if r[1] == "/app/iso_form.php"]
    gets = [r for r in app.requests if r[1] == "/app/show.php"]
    copy_sids = {r[2] for r in posts}
    assert len(copy_sids) == 1 and main_sid not in copy_sids
    assert gets and {r[2] for r in gets} == copy_sids        # the copy, never the run's


def test_a_main_session_probe_redirected_to_an_isolated_path_is_not_followed():
    app = PrgFakeApp(redirect="/app/iso_form.php")
    _mgr, _client, sender = _seam(app)
    sender.isolate([ISO])
    probe = sender.send(BASE + "profile.php", "name", "#{11*13}", method="POST",
                        location="body", prg=True)
    assert probe.status == 303 and probe.prg == "skipped: isolated path"
    assert probe.followed is None
    assert not [r for r in app.requests if r[1] == "/app/iso_form.php"]


@pytest.mark.parametrize("redirect", ["/app/login.php", "/app/signin"])
def test_a_redirect_to_the_login_page_is_not_followed(redirect):
    app = PrgFakeApp(redirect=redirect)
    _mgr, _client, sender = _seam(app)
    probe = sender.send(BASE + "profile.php", "name", "x", method="POST",
                        location="body", prg=True)
    assert probe.prg == "skipped: login page" and probe.followed is None
    assert [r[1] for r in app.requests] == ["/app/profile.php"]


def test_a_redirect_to_an_auth_endpoint_is_not_followed(monkeypatch):
    """The session's own auth endpoints (whatever their name) are never fetched by a
    follow-up; a probe to one goes anonymously already (BUG-0112)."""
    app = PrgFakeApp(redirect="/app/gate.php")
    mgr, _client, sender = _seam(app)
    sender.send(BASE + "portal.php", "x", "1")              # discovers the login
    real = mgr.is_auth_endpoint
    monkeypatch.setattr(mgr, "is_auth_endpoint",
                        lambda url: urlsplit(url).path == "/app/gate.php" or real(url))
    probe = sender.send(BASE + "profile.php", "name", "x", method="POST",
                        location="body", prg=True)
    assert probe.prg == "skipped: auth endpoint" and probe.followed is None
    assert "/app/gate.php" not in [r[1] for r in app.requests]


def test_an_anonymous_probe_follows_anonymously():
    app = PrgFakeApp(anonymous_ok=True)
    _mgr, _client, sender = _seam(app, identity="anonymous")
    probe = sender.send(BASE + "profile.php", "name", "#{11*13}", method="POST",
                        location="body", prg=True)
    assert probe.prg == PRG_OBSERVED and "143" in probe.followed.text
    assert [r[1] for r in app.requests] == ["/app/profile.php", "/app/show.php"]
    assert {r[2] for r in app.requests} == {None}            # no session on either


def test_no_follow_up_once_the_header_breaker_stopped_header_probes():
    """The breaker gate (P3): a header probe whose own send stopped header probing (a
    logout attributed to it, e.g. seen by the listener during the send) gets no
    follow-up."""
    from tests.test_forms_phase2 import _ua_bound_sender
    site_, sender = _ua_bound_sender()
    sender.send("http://localhost/a.php", "id", "1")              # logs in
    sent = []

    def transport(method, url, headers, body, timeout):
        sent.append(urlsplit(url).path)
        if "User-Agent" in headers:
            sender.header_stop_reason = "session bound to a probed header (test)"
            return 303, {"Location": "/show.php"}, b""
        return site_.transport(method, url, headers, body, timeout)
    sender._client._transport = transport
    probe = sender.send("http://localhost/a.php", "User-Agent", "x", location="header",
                        prg=True)
    assert probe.prg == "skipped: header breaker" and sent == ["/a.php"]


def test_a_header_probes_follow_up_is_part_of_the_probe_for_the_breaker():
    from tests.test_forms_phase2 import _ua_bound_sender
    site_, sender = _ua_bound_sender()
    sender.send("http://localhost/a.php", "id", "1")              # logs in
    real = site_.transport

    def transport(method, url, headers, body, timeout):
        if "User-Agent" in headers:                   # the probe kills the session,
            site_.alive = False                       # which only its follow-up shows
            return 303, {"Location": "/show.php"}, b""
        return real(method, url, headers, body, timeout)
    sender._client._transport = transport
    probe = sender.send("http://localhost/a.php", "User-Agent", "x", location="header",
                        prg=True)
    assert probe.prg == PRG_OBSERVED
    assert sender.header_stop_reason.startswith(
        "session bound to a probed header (User-Agent on /a.php")


# --- PA-0117 / PA-0129: the follow-up is an evidence channel, fed noise ----------------
class _PrgNoise:
    """Every probe is answered 303 with an empty body; its follow-up shows ``page``,
    which never depends on the probe -- or, ``lagging``, the previous probe's value
    rendered by an evaluator (a stale page one request behind)."""
    prg_capable = True

    def __init__(self, page="", lagging=False):
        self.page, self.lagging, self.previous = page, lagging, ""

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        probe = Probe(303, "", headers={"Location": "/show", "Content-Type": "text/html"})
        if prg:
            shown = self.page
            if self.lagging:
                shown = "<p>" + PrgSite._evaluate(re.sub(
                    r"(?:\$\{\{|\$\{|\{\{|<%= )(\d+)\*(\d+)(?:\}\}|\}| %>)", r"#{\1*\2}",
                    self.previous)) + "</p>"
                self.previous = value
            probe.followed = Probe(200, shown, headers={"Content-Type": "text/html"},
                                   url="http://h/show")
            probe.prg = PRG_OBSERVED
        return probe


_PRG_NOISE = {
    "constant": lambda: _PrgNoise("<html><p>hello</p></html>"),
    "signature-always": lambda: _PrgNoise(f"<p>{SQL_ERROR}</p>"),
    "passwd-always": lambda: _PrgNoise("<pre>root:x:0:0:root:/root:/bin/sh</pre>"),
    "markup-always": lambda: _PrgNoise("<p><script>zqxb</script><img src=x></p>"),
    "lagging": lambda: _PrgNoise(lagging=True),
}


def _prg_noise_confirmations(strategies) -> list:
    found = []
    for name, make in _PRG_NOISE.items():
        for strategy in strategies:
            cand = Candidate(url="http://h/p", param="v", method="POST", location="body",
                             category=strategy.category)
            verdict = Oracle(strategies=[strategy]).confirm(cand, make())
            if verdict is not None:
                found.append((type(strategy).__name__, name))
    return found


def test_payload_independent_follow_ups_never_confirm_an_opt_in_strategy():
    strategies = [s for s in default_strategies() if s.prg]
    assert {type(s).__name__ for s in strategies} == PRG_STRATEGIES
    assert _prg_noise_confirmations(strategies) == []


def test_the_follow_up_noise_guard_catches_a_synthetic_offender():
    """PA-0034(2): a strategy that trusts a follow-up's signature with no control, or a
    product without attribution, is caught."""
    from fuzzlab.oracle.probe import Verdict
    from fuzzlab.oracle.strategies import (SQL_ERROR_SIGNATURES, ConfirmationStrategy,
                                           _observed)

    class ControlLess(ConfirmationStrategy):
        vuln_class, mechanism, category, prg = "sqli", "x", "sql-injection", True

        def confirm(self, candidate, sender):
            text = _observed(self._send(sender, candidate, "'")).text
            if any(rx.search(text) for rx, _ in SQL_ERROR_SIGNATURES):
                return Verdict(True, "sqli", self.mechanism)
            return None

    class Unattributed(SstiStrategy):
        def confirm(self, candidate, sender):
            for payload in ("#{101*103}", "#{107*109}"):
                text = _observed(self._send(sender, candidate, payload)).text
                if "10403" in text:                  # product 1, seen one probe late
                    return Verdict(True, "ssti", self.mechanism)
            return None
    found = _prg_noise_confirmations([ControlLess(), Unattributed()])
    assert ("ControlLess", "signature-always") in found
    assert ("Unattributed", "lagging") in found


# --- PA-0111: the emulated redirect behaviour, rule by rule -----------------------------
def _fx_303(site):
    app = site(status=303)
    probe = _probe_post(app)
    assert probe.prg == PRG_OBSERVED and app.log[-1][0] == "GET"


def _fx_302_post(site):
    """The captured Juice Shop shape (live, 2026-10-14, FR-FUZZ-49's evidence):
    ``POST /profile username=#{11*13}`` -> ``302 Location: /profile`` with no 143 in
    its body; ``GET /profile`` shows 143."""
    app = site(status=302, location="/profile")
    probe = _probe_post(app, "#{11*13}")
    assert probe.status == 302 and "143" not in probe.text
    assert probe.prg == PRG_OBSERVED and "143" in probe.followed.text
    assert [m for m, _p, _d in app.log] == ["POST", "GET"]


def _fx_get_stays_get(site):
    app = site()
    probe = RequestsProbeSender().send(app.base + "/redir", "to", "/profile", prg=True)
    assert probe.prg == PRG_OBSERVED and [m for m, _p, _d in app.log] == ["GET", "GET"]


def _fx_307_308(site):
    for status in (307, 308):
        app = site(status=status)
        assert _probe_post(app).prg.startswith(f"skipped: a {status} after POST")
        assert [m for m, _p, _d in app.log] == ["POST"]
        assert RequestsProbeSender().send(
            app.base + "/redir", "to", "/profile", prg=True).prg == PRG_OBSERVED


def _fx_relative(site):
    app = site(location="profile")                       # relative to /profile
    probe = _probe_post(app)
    assert probe.followed.url == app.base + "/profile"


def _fx_own_segment(site):
    """A path point's ``Location`` is resolved against its template (FR-FUZZ-69):
    ``#done`` keeps the point's segment, and ``/p/zqpayload/edit`` (written by the
    server) holds the placed value, where a browser would fetch the payload again, so
    nothing follows; ``../../profile`` leaves it and is fetched where a browser goes."""
    def send(app):
        return RequestsProbeSender().send(app.base + "/p/{id}/view", "id", "zqpayload",
                                          method="POST", location="path", prg=True)
    for where in ("#done", "/p/{seg}/edit"):
        app = site(location=where)
        probe = send(app)
        assert probe.prg == "skipped: the follow-up would re-send the payload"
        assert [m for m, _p, _d in app.log] == ["POST"] and probe.prg_sends == 0
    app = site(location="../../profile")
    probe = send(app)
    assert probe.prg == PRG_OBSERVED and probe.followed.url == app.base + "/profile"
    assert app.log[-1][:2] == ("GET", "/profile")


def _fx_fragment(site):
    app = site(location="/profile#done")
    probe = _probe_post(app)
    assert probe.followed.url == app.base + "/profile" and app.log[-1][1] == "/profile"


def _fx_no_location(site):
    app = site(with_location=False)
    probe = _probe_post(app)
    assert probe.prg == "skipped: no Location" and [m for m, _p, _d in app.log] == ["POST"]


def _fx_no_body(site):
    app = site()
    _probe_post(app, "zqpayload")
    method, path, query = app.log[-1]
    assert (method, path, query) == ("GET", "/profile", {})
    headers = {k.lower() for k in app.headers[-1]}
    assert "content-type" not in headers and int(app.headers[-1].get(
        "Content-Length", "0")) == 0


def _fx_one_hop(site):
    app = site(location="/again")
    assert _probe_post(app).prg == PRG_UNOBSERVED
    assert [p for _m, p, _d in app.log] == ["/profile", "/again"]


def _fx_same_origin(site):
    app = site(location="http://localhost:1/profile")    # another origin (host differs)
    assert _probe_post(app).prg == "skipped: another origin"


def _fx_no_cookie(site):
    app = site(set_cookie=True)
    assert _probe_post(app).prg == PRG_OBSERVED
    assert "cookie" not in {k.lower() for k in app.headers[-1]}


def _probe_post(app, value="x"):
    return RequestsProbeSender().send(app.base + "/profile", "username", value,
                                      method="POST", location="body", prg=True)


PRG_RULE_FIXTURES = {
    "303-becomes-get": _fx_303, "301-302-post-becomes-get": _fx_302_post,
    "get-redirect-stays-get": _fx_get_stays_get, "307-308-keep-the-body": _fx_307_308,
    "location-relative": _fx_relative, "location-fragment-not-sent": _fx_fragment,
    "own-segment-never-refetched": _fx_own_segment,
    "no-location-no-redirect": _fx_no_location, "no-body-no-payload": _fx_no_body,
    "one-hop": _fx_one_hop, "same-origin-only": _fx_same_origin,
    "no-response-cookie-adopted": _fx_no_cookie,
}


def test_every_prg_rule_has_a_fixture():
    from fuzzlab.tools.probesender import PRG_RULES
    assert set(PRG_RULE_FIXTURES) == set(PRG_RULES)


@pytest.mark.parametrize("rule", sorted(PRG_RULE_FIXTURES))
def test_prg_rule(site, rule):
    PRG_RULE_FIXTURES[rule](site)
