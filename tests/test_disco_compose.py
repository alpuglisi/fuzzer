"""The explorer's composed read (FR-CRAWL-39, FR-CRAWL-40; BUG-0551), in a real browser.

A loopback app served by the test, shaped like no particular lab:

* a web component (``<search-box>``) whose **open** shadow root holds a search form, a
  ``Go`` button shaped exactly like one in the light tree, and an ``Advanced`` button
  that adds an ``Apply filter`` button to the shadow tree (reached only by replaying
  ``Advanced`` through the shadow root);
* a web component (``<closed-box>``) whose **closed** shadow root holds a button that is
  never reachable: counted, never claimed;
* a same-origin **settings frame** that renders only when embedded (a widget's frame),
  with ``Save settings`` and ``More options`` (which adds ``Apply options``: reached
  only by replaying ``More options`` through the frame);
* a frame from another in-scope origin (cross-origin: counted, not read) and one from
  an origin outside the scope (counted, never loaded);
* tiles under a **document-level click listener**, no pointer cursor, no listener of
  their own: ``Open report`` fetches, ``Just a note`` does nothing, and three more
  shapes exceed the per-read and per-run delegated bounds (counted).

Every request the app receives is recorded: the independent evidence each counter is
reconciled with (PA-0502(2)). Under ``FUZZLAB_REQUIRE_BROWSER=1`` a missing browser
fails instead of skipping (PA-0065).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests._browser import skip_or_fail

MAIN = """<!doctype html><html><head><title>Console</title></head><body>
<h1>Console</h1>
<button class="go">Go</button>
<search-box id="sb"></search-box>
<closed-box id="cb"></closed-box>
<iframe id="settings" src="/settings.html" width="520" height="140"></iframe>
<iframe id="peer" src="PEER/peer.html" width="160" height="60"></iframe>
<iframe id="ext" src="OTHER/x.html" width="160" height="60"></iframe>
<div id="tiles">
  <div class="tile" data-k="7">Open report</div>
  <div class="note">Just a note</div>
  <div class="extra-a">Extra A</div>
  <div class="extra-b">Extra B</div>
  <div class="extra-c">Extra C</div>
</div>
<script>
document.querySelector('body > button.go').addEventListener('click', () => fetch('/api/light/go'));
customElements.define('search-box', class extends HTMLElement {
  constructor() {
    super();
    const root = this.attachShadow({mode: 'open'});
    root.innerHTML = '<form id="f"><input name="q" required minlength="5" placeholder="Search">'
      + '<button type="submit">Search</button></form>'
      + '<button class="go">Go</button><button class="adv">Advanced</button>'
      + '<div class="panel"></div>';
    root.getElementById('f').addEventListener('submit', (e) => {
      e.preventDefault();
      fetch('/api/shadow/search', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({q: root.querySelector('input').value})});
    });
    root.querySelector('.go').addEventListener('click', () => fetch('/api/shadow/go'));
    root.querySelector('.adv').addEventListener('click', () => {
      const panel = root.querySelector('.panel');
      if (panel.firstChild) return;
      const b = document.createElement('button');
      b.textContent = 'Apply filter';
      b.addEventListener('click', () => fetch('/api/shadow/apply'));
      panel.appendChild(b);
    });
  }
});
customElements.define('closed-box', class extends HTMLElement {
  constructor() {
    super();
    const root = this.attachShadow({mode: 'closed'});
    root.innerHTML = '<button>Hidden action</button>';
    root.querySelector('button').addEventListener('click', () => fetch('/api/closed'));
  }
});
document.addEventListener('click', (e) => {
  const tile = e.target.closest('.tile');
  if (tile) fetch('/api/tile/' + tile.dataset.k);
});
</script></body></html>"""

#: A widget's frame: it renders its controls only when embedded, so a top-level load of
#: its URL (the harvest's) offers nothing -- only the frame read reaches them.
SETTINGS = """<!doctype html><html><body><div class="panel"></div>
<script>
if (window.top !== window) {
  const panel = document.querySelector('.panel');
  panel.innerHTML = '<button id="save">Save settings</button> '
    + '<button id="more">More options</button><div id="extra"></div>';
  document.getElementById('save').addEventListener('click',
    () => fetch('/api/frame/save', {method: 'POST'}));
  document.getElementById('more').addEventListener('click', () => {
    const extra = document.getElementById('extra');
    if (extra.firstChild) return;
    const b = document.createElement('button');
    b.textContent = 'Apply options';
    b.addEventListener('click', () => fetch('/api/frame/apply'));
    extra.appendChild(b);
  });
}
</script></body></html>"""

#: The forms page for the spider's form read (`spa.FORMS_JS`).
FORMS = """<!doctype html><html><body>
<form id="plain"><input name="email"><button>Go</button></form>
<shadow-search></shadow-search>
<shadow-login></shadow-login>
<form id="mixed"><input name="nick"><pw-field></pw-field><button>Save</button></form>
<script>
const shadow = (tag, html) => customElements.define(tag, class extends HTMLElement {
  constructor() { super(); this.attachShadow({mode: 'open'}).innerHTML = html; } });
shadow('shadow-search', '<form><input name="term"><button type="submit">Find</button></form>');
shadow('shadow-login', '<form><input name="user"><input name="pass" type="password">'
  + '<button>Log in</button></form>');
shadow('pw-field', '<input name="pw" type="password">');
</script></body></html>"""


class _Server:
    """A loopback server answering ``pages`` (path -> HTML) and recording every request;
    anything else under ``/api/`` answers ``{}``."""

    def __init__(self, pages: dict[str, str]):
        from fuzzlab.core.net import require_loopback
        require_loopback("127.0.0.1")                  # PA-0130
        self.pages = dict(pages)
        self.hits: list[tuple[str, str, str]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self, method: str) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                server.hits.append((method, self.path, body))
                page = server.pages.get(self.path.split("?", 1)[0])
                if page is not None:
                    data, ctype, code = page.encode(), "text/html", 200
                elif self.path.startswith("/api/"):
                    data, ctype, code = b"{}", "application/json", 200
                else:
                    data, ctype, code = b"", "text/plain", 404
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802 - http.server API
                self._answer("GET")

            def do_POST(self):  # noqa: N802 - http.server API
                self._answer("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def paths(self, method: str | None = None) -> list[str]:
        return [p for m, p, _b in self.hits if method is None or m == method]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _require_playwright():
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")


@pytest.fixture(scope="module")
def explored(tmp_path_factory):
    """One exploration of the app, with small delegated bounds (3 per read, 2 trials)."""
    import glob

    _require_playwright()
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.disco import compose
    from fuzzlab.disco.explore import Explorer, ExploreOptions
    out = tmp_path_factory.mktemp("compose")
    other = _Server({"/x.html": "<button>outside</button>"})
    peer = _Server({"/peer.html": "<p>peer</p>"})
    app = _Server({"/": MAIN.replace("PEER", peer.url).replace("OTHER", other.url),
                   "/settings.html": SETTINGS, "/forms.html": FORMS})
    try:
        with pytest.MonkeyPatch.context() as mp:
            exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
            if exe:
                mp.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])
            mp.setattr(compose, "MAX_DELEGATED", 3)
            mp.setattr(compose, "MAX_DELEGATED_TRIALS", 2)
            ex = Explorer(app.url + "/", scope_urls=[app.url + "/", peer.url + "/"],
                          proxy=None, actions_log=out / "actions.jsonl",
                          options=ExploreOptions(idle_ms=150, max_quiet_ms=3000,
                                                 max_actions=60, deadline_s=150,
                                                 max_harvest=4))
            try:
                report = ex.run()
            except PlaywrightError as exc:
                if "Executable doesn't exist" in str(exc) or "launch" in str(exc).lower():
                    skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
                raise
        actions = [json.loads(ln) for ln in (out / "actions.jsonl").open()]
        yield {"app": app, "other": other, "report": report, "actions": actions}
    finally:
        for server in (app, peer, other):
            server.close()


def test_a_form_in_an_open_shadow_root_is_found_filled_and_sent(explored):
    """BUG-0551: the search form inside ``<search-box>``'s open shadow root is a
    candidate: filled valid-first (its ``minlength``) and submitted, and the request
    carries the value (a distinctive one: counted sent). Before:
    ``document.querySelectorAll`` never saw it."""
    app = explored["app"]
    sent = [json.loads(b) for m, p, b in app.hits if (m, p) == ("POST", "/api/shadow/search")]
    assert sent, app.paths()
    assert len(sent[0]["q"]) >= 5
    assert explored["report"].submissions_sent >= 1
    assert explored["report"].shadow_roots >= 1


def test_an_element_in_a_shadow_root_has_its_own_identity_and_is_replayed_there(explored):
    """The light ``Go`` and the shadow ``Go`` are the same shape; the shadow one's
    ancestry names its host, so both are acted on, each once. ``Apply filter`` exists
    only after ``Advanced`` (in the shadow root) was clicked: its request proves the
    state was restored by replaying a step located through the shadow root."""
    app = explored["app"]
    assert "/api/shadow/go" in app.paths() and "/api/light/go" in app.paths()
    goes = [a for a in explored["actions"] if a["label"] == "Go"]
    assert len(goes) == 2 and len({a["signature"] for a in goes}) == 2, goes
    assert sum("^shadow<search-box#sb" in a["signature"] for a in goes) == 1
    assert "/api/shadow/apply" in app.paths()


def test_a_same_origin_frames_controls_are_explored_and_replayed_through_the_frame(explored):
    """The settings frame is read in its own context: ``Save settings`` is clicked there
    (a top-level load of its URL renders nothing), and ``Apply options``, which exists
    only after ``More options``, proves a replay through the frame. The action's
    identity names the frame."""
    app = explored["app"]
    assert "/api/frame/save" in app.paths("POST"), app.paths()
    assert "/api/frame/apply" in app.paths()
    saves = [a for a in explored["actions"] if a["label"] == "Save settings"]
    assert saves and all("^frame<iframe#settings<@/settings.html" in a["signature"]
                         for a in saves)
    assert explored["report"].frames >= 1


def test_a_document_delegated_action_is_kept_and_an_inert_candidate_dropped(explored):
    """The ``Open report`` tile has no listener of its own and no pointer cursor; the
    document's click listener serves it. It is tried, its click makes a request, so it
    is kept (an action in the log); ``Just a note`` is tried, does nothing, and is
    dropped (never in the log). The counters match the server and the log."""
    app, report = explored["app"], explored["report"]
    assert "/api/tile/7" in app.paths(), app.paths()
    labels = [a["label"] for a in explored["actions"]]
    assert "Open report" in labels and "Just a note" not in labels
    assert report.delegated_live >= 1 and report.delegated_inert >= 1
    assert report.delegated_trials == report.delegated_live + report.delegated_inert


def test_what_was_not_read_is_counted_never_claimed(explored):
    """The closed shadow root's button is never reached; the closed root is counted.
    The cross-origin and out-of-scope frames are counted, the out-of-scope one never
    loaded. The delegated bounds (3 per read, 2 trials per run) leave candidates out:
    counted as budget-limited and unexplored, never acted on."""
    app, report = explored["app"], explored["report"]
    assert "/api/closed" not in app.paths()
    assert report.closed_shadow_roots >= 1
    assert report.frames_cross_origin >= 1 and report.frames_out_of_scope >= 1
    assert explored["other"].paths() == []
    # 5 tile shapes, 3 kept per read; a container (the shadow panel holding a button,
    # the tiles' wrapper) is never a candidate, so exactly 2 are left out, and of the 3
    # kept, the third is never tried (2 trials)
    assert report.budget_limited.get("delegated") == 2, report.budget_limited
    assert report.delegated_unexplored == 1
    labels = {a["label"] for a in explored["actions"]}
    assert not labels & {"Hidden action", "Extra A", "Extra B", "Extra C"}


# --- the spider's form read (spa.FORMS_JS) in a real browser ------------------------------
def test_the_spiders_form_read_finds_a_form_in_an_open_shadow_root():
    """BUG-0551 in `spa.FORMS_JS` (both the spider and the browser login read forms
    with it): a form inside an open shadow root is found and its controls are locatable
    by their ``data-fuzzlab-id``. A password control in a shadow root is never described
    (FR-CRAWL-40's pinned gap): the shadow login form is left out, and a light form whose
    password field is a component's shadow input keeps its light controls only."""
    _require_playwright()
    from playwright.sync_api import sync_playwright

    from fuzzlab.tools import spa
    from tests._browser import launch_browser_or_skip
    app = _Server({"/forms.html": FORMS})
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                page = browser.new_page()
                page.goto(app.url + "/forms.html")
                forms = page.evaluate(spa.FORMS_JS, 20)
                names = {tuple(n for n, _k in f["controls"]): f for f in forms}
                assert ("term",) in names, list(names)
                term = names[("term",)]
                page.fill(f'[data-fuzzlab-id="{term["ids"][0]}"]', "abcde")
                typed = page.evaluate("() => document.querySelector('shadow-search')"
                                      ".shadowRoot.querySelector('input').value")
                assert typed == "abcde"
                assert term["button"] == "Find"
                assert ("email",) in names and ("nick",) in names
                assert not any(k == "password" for f in forms for _n, k in f["controls"])
                assert not any("user" in n for n in names)
            finally:
                browser.close()
    finally:
        app.close()


# --- offline ---------------------------------------------------------------------------
def test_a_frame_is_read_only_when_visible_same_origin_and_in_scope():
    from fuzzlab.disco.compose import classify_frame

    def in_scope(url):
        return url.startswith("http://127.0.0.1:1/")

    base = {"visible": True, "same": True, "src": "http://127.0.0.1:1/s.html",
            "url": "http://127.0.0.1:1/s.html"}
    assert classify_frame(base, in_scope) == "read"
    assert classify_frame({**base, "src": "", "url": "about:srcdoc"}, in_scope) == "read"
    assert classify_frame({**base, "visible": False}, in_scope) is None
    assert classify_frame({**base, "same": False}, in_scope) == "cross_origin"
    # an out-of-scope src is refused by the guard, so its document stays about:blank
    # (same-origin): the src decides
    assert classify_frame({**base, "src": "http://127.0.0.1:2/x", "url": "about:blank"},
                          in_scope) == "out_of_scope"
    assert classify_frame({**base, "same": False, "src": "http://127.0.0.1:2/x",
                           "url": None}, in_scope) == "out_of_scope"


def test_coverage_counts_a_page_read_again_once():
    from fuzzlab.disco.compose import Coverage, PageRead
    cov = Coverage()
    first = PageRead(counts={"shadow_roots": 2, "budget.delegated": 3},
                     distinct={"frames": {"f1"}})
    assert cov.add("r", first) == {"shadow_roots": 2, "budget.delegated": 3, "frames": 1}
    assert cov.add("r", first) == {}
    more = PageRead(counts={"shadow_roots": 3}, distinct={"frames": {"f1", "f2"}})
    assert cov.add("r", more) == {"shadow_roots": 1, "frames": 1}
    assert cov.add("r2", first) == {"shadow_roots": 2, "budget.delegated": 3, "frames": 1}


def test_a_delegated_candidate_is_tried_once_within_the_runs_budget():
    from fuzzlab.disco.compose import Trials
    t = Trials(budget=2)
    assert t.claim("a") == "trial" and t.claim("a") == "trying"
    t.decide("a", True)
    assert t.claim("a") == "live"
    assert t.claim("b") == "trial"
    t.release("b")                       # never clicked: untried, its budget back
    assert t.verdict("b") is None and not t.spent()
    assert t.claim("b") == "trial"
    t.decide("b", False)
    assert t.claim("b") == "inert" and t.spent()
    assert t.claim("c") == "spent" and t.unexplored == {"c"}


@pytest.mark.xfail(strict=True, reason=(
    "FR-CRAWL-40 known gap, owner: the spider's G1 read (spa.G1_READ_JS) finds a "
    "FORMS_JS control by document.querySelector, which no shadow root answers; a shadow "
    "form's invalid control reads as missing. Fix it through SP-70 (tools.composed), then "
    "drop this marker."))
def test_the_g1_read_resolves_a_control_through_open_shadow_roots():
    from fuzzlab.tools import spa
    assert "document.querySelector(" not in spa.G1_READ_JS


@pytest.mark.xfail(strict=True, reason=(
    "FR-CRAWL-40 known gap, owner: SESS (session/browserlogin.py _CLEAR_IF_PRESENT, the "
    "X3 password clear) finds the password field by document.querySelector; until it "
    "resolves through SP-70, spa.FORMS_JS never describes a password control in a shadow "
    "root. Needs a CC-SESS entry; then drop this marker and FORMS_JS's exclusion."))
def test_the_browser_logins_password_clear_reaches_a_shadow_root():
    from fuzzlab.session import browserlogin
    assert "document.querySelector(" not in browserlogin._CLEAR_IF_PRESENT
