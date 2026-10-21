"""The explorer's composed read (FR-CRAWL-39, FR-CRAWL-40; BUG-0551), in a real browser.

A loopback app served by the test, shaped like no particular lab:

* a web component (``<search-box>``) whose **open** shadow root holds a search form, a
  ``Go`` button shaped exactly like one in the light tree, and an ``Advanced`` button
  that adds an ``Apply filter`` button to the shadow tree (reached only by replaying
  ``Advanced`` through the shadow root);
* a web component (``<closed-box>``) whose **closed** shadow root holds a button that is
  never reachable: counted, never claimed; and two more closed roots the census must
  count too (review B4): one on a built-in ``<div>`` and one on a component that slots
  a visible light child (``<x-card>``);
* a same-origin **settings frame** that renders only when embedded (a widget's frame),
  with ``Save settings`` and ``More options`` (which adds ``Apply options``: reached
  only by replaying ``More options`` through the frame);
* a frame from another in-scope origin (cross-origin: counted, not read) and one from
  an origin outside the scope (counted, never loaded);
* tiles under a **document-level click listener**, no pointer cursor, no listener of
  their own: ``Open report`` fetches, ``Just a note`` does nothing, and three more
  shapes exceed the per-read and per-run delegated bounds (counted).

A second app (`WIDGET`, review round 1) is an ordinary light page with a document-level
click listener and a background poll every 100 ms, holding a form-less search widget
whose input and button sit directly under its open shadow root (review B1), a Refresh
button that only swaps static text (review B2), and two delegated tiles, one of which
does nothing (review B3).

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
<div id="vault" style="min-height: 20px"></div>
<x-card><b>Card</b></x-card>
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
// a closed root on a built-in host, and one that slots its visible light child
document.getElementById('vault').attachShadow({mode: 'closed'}).innerHTML =
  '<form><input name="u"><button>Vault login</button></form>';
customElements.define('x-card', class extends HTMLElement {
  constructor() {
    super();
    const root = this.attachShadow({mode: 'closed'});
    root.innerHTML = '<slot></slot><button>Card action</button>';
    root.querySelector('button').addEventListener('click', () => fetch('/api/card'));
  }
});
</script></body></html>"""

#: Review round 1 (B1-B3): an ordinary light page with a document click listener (a
#: dismiss handler, a data-api, a framework root) and a background poll.
WIDGET = """<!doctype html><html><head><title>Inbox</title></head><body>
<h1>Inbox</h1>
<search-widget></search-widget>
<button id="refresh">Refresh</button>
<div id="list"><p class="empty">No messages</p></div>
<div id="tiles">
  <div class="tile" data-k="7">Open report</div>
  <div class="note">Just a note</div>
</div>
<script>
customElements.define('search-widget', class extends HTMLElement {
  constructor() {
    super();
    const root = this.attachShadow({mode: 'open'});
    root.innerHTML = '<input name="q" placeholder="Search"><button>Find</button>';
    root.querySelector('button').addEventListener('click', () =>
      fetch('/api/search?q=' + encodeURIComponent(root.querySelector('input').value)));
  }
});
document.getElementById('refresh').addEventListener('click', () => {
  fetch('/api/list').then(() => {
    document.getElementById('list').innerHTML = '<ul><li class="msg">Hello</li></ul>';
  });
});
document.addEventListener('click', (e) => {
  const tile = e.target.closest('.tile');
  if (tile) fetch('/api/tile/' + tile.dataset.k);
});
setInterval(() => fetch('/api/notifications'), 100);
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
    assert "/api/closed" not in app.paths() and "/api/card" not in app.paths()
    # review B4: every closed root is counted -- the custom element that renders nothing
    # light, the built-in <div> host, and the component slotting a visible light child
    assert report.closed_shadow_roots == 3, report
    assert report.frames_cross_origin >= 1 and report.frames_out_of_scope >= 1
    assert explored["other"].paths() == []
    # 5 tile shapes, 3 kept per read; a container (the shadow panel holding a button,
    # the tiles' wrapper) is never a candidate, so exactly 2 are left out, and of the 3
    # kept, the third is never tried (2 trials)
    assert report.budget_limited.get("delegated") == 2, report.budget_limited
    assert report.delegated_unexplored == 1
    labels = {a["label"] for a in explored["actions"]}
    assert not labels & {"Hidden action", "Extra A", "Extra B", "Extra C", "Vault login",
                         "Card action"}


@pytest.fixture(scope="module")
def widget_run(tmp_path_factory):
    """One exploration of `WIDGET` (review round 1): quiet waits never settle under the
    100 ms poll, so each lasts ``max_quiet_ms``."""
    import glob

    _require_playwright()
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.disco.explore import Explorer, ExploreOptions
    out = tmp_path_factory.mktemp("widget")
    app = _Server({"/": WIDGET})
    try:
        with pytest.MonkeyPatch.context() as mp:
            exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
            if exe:
                mp.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])
            ex = Explorer(app.url + "/", scope_urls=[app.url + "/"], proxy=None,
                          actions_log=out / "actions.jsonl",
                          options=ExploreOptions(idle_ms=150, max_quiet_ms=700,
                                                 max_actions=20, deadline_s=120,
                                                 max_harvest=1))
            try:
                report = ex.run()
            except PlaywrightError as exc:
                if "Executable doesn't exist" in str(exc) or "launch" in str(exc).lower():
                    skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
                raise
        actions = [json.loads(ln) for ln in (out / "actions.jsonl").open()]
        yield {"app": app, "report": report, "actions": actions}
    finally:
        app.close()


def test_a_formless_widget_at_a_shadow_roots_top_is_filled_and_sent(widget_run):
    """Review B1: the search widget's input and button sit directly under its open
    shadow root (Lit's and Stencil's usual layout), so ``parentElement`` ends at the
    root. The root is their container: the input gets its Enter step, the button its
    submit step, and the request carries the filled value. Before: the button was
    clicked bare and the server received ``q=`` empty."""
    app = widget_run["app"]
    searches = [p for p in app.paths() if p.startswith("/api/search")]
    assert searches and all(p != "/api/search?q=" for p in searches), searches
    kinds = {(a["kind"], a["label"]) for a in widget_run["actions"]}
    assert ("submit", "Find") in kinds and ("enter", "Search") in kinds, kinds
    assert widget_run["report"].submissions >= 2


def test_a_click_that_only_swaps_static_text_keeps_the_state(widget_run):
    """Review B2: a document click listener makes every labelled text leaf a delegated
    candidate; they never count toward a state's identity. Refresh replaces
    ``p.empty`` with ``ul > li.msg`` -- static text only -- so the page stays one state,
    as before BUG-0551. Before: Refresh made a second state."""
    report = widget_run["report"]
    refresh = [a for a in widget_run["actions"] if a["label"] == "Refresh"]
    assert refresh and all(a["new_state"] == a["state"] for a in refresh), refresh
    assert report.states == 1, report


def test_a_background_poll_never_makes_an_inert_candidate_live(widget_run):
    """Review B3: the page polls ``/api/notifications`` every 100 ms, so every trial's
    window holds poll requests. Only a request the click caused counts (one the
    control window before it did not see): ``Open report`` fetches its tile and is
    kept; ``Just a note`` stays inert, never logged. Before: the poll made it live."""
    app, report = widget_run["app"], widget_run["report"]
    assert "/api/tile/7" in app.paths() and "/api/notifications" in app.paths()
    labels = [a["label"] for a in widget_run["actions"]]
    assert "Open report" in labels and "Just a note" not in labels, labels
    assert report.delegated_live == 1 and report.delegated_inert >= 1, report


# --- the spider's form read (spa.FORMS_JS) in a real browser ------------------------------
def test_the_spiders_form_read_finds_a_formless_widget_at_a_shadow_roots_top():
    """Review B1 in `spa.FORMS_JS`: a form-less widget whose input and button sit
    directly under its open shadow root is a form-like container (the root), its
    control locatable by its ``data-fuzzlab-id``. Before: none was found."""
    _require_playwright()
    from playwright.sync_api import sync_playwright

    from fuzzlab.tools import spa
    from tests._browser import launch_browser_or_skip
    app = _Server({"/": WIDGET})
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                page = browser.new_page()
                page.goto(app.url + "/")
                forms = page.evaluate(spa.FORMS_JS, 20)
                assert [(f["controls"], f["button"]) for f in forms] == \
                    [([["q", "text"]], "Find")], forms
                page.fill(f'[data-fuzzlab-id="{forms[0]["ids"][0]}"]', "abcde")
                page.click(f'[data-fuzzlab-id="{forms[0]["button_id"]}"]')
                page.wait_for_timeout(300)
                assert "/api/search?q=abcde" in app.paths(), app.paths()
            finally:
                browser.close()
    finally:
        app.close()


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


def test_the_composed_read_carries_the_execution_keys_markers():
    """The merge of BUG-0539's markers with BUG-0551's composed read: a control's
    ``sel`` and the page-level markers (a named hidden input, a non-described
    ``aria-current``) are read across open shadow roots in the same read as the
    elements; a delegated candidate's ``aria-current`` stays a page marker (its own
    flags are no part of the key), so a stepper served by a document listener still
    tells its steps apart."""
    _require_playwright()
    from playwright.sync_api import sync_playwright

    from fuzzlab.disco import compose
    from fuzzlab.disco.fingerprint import element_signature, workflow_markers
    from tests._browser import launch_browser_or_skip
    page_html = (
        "<!doctype html><html><body><step-box id=sb></step-box>"
        "<ol class=steps><li aria-current=step>Cart</li><li>Pay</li></ol><script>"
        "customElements.define('step-box', class extends HTMLElement { constructor() {"
        " super(); this.attachShadow({mode: 'open'}).innerHTML = '<form>"
        "<input type=hidden name=step value=2><select name=plan><option value=a>A</option>"
        "<option value=b selected>B</option></select><button>Next</button></form>'; } });"
        "document.addEventListener('click', () => {});</script></body></html>")
    app = _Server({"/": page_html})
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                ctx = browser.new_context()
                page = ctx.new_page()
                page.goto(app.url + "/")
                read = compose.read_page(page, ctx, lambda url: True)
            finally:
                browser.close()
    finally:
        app.close()
    els = read.elements
    for el in els:
        el["signature"], el["occurrence"] = element_signature(el), 0
    plan = [e for e in els if e["tag"] == "select"]
    assert plan and plan[0]["sel"] == "value=b" and "^shadow" in plan[0]["ancestry"], els
    cart = [e for e in els if e.get("label") == "Cart"]
    assert cart and cart[0]["how"] == "delegated", els
    assert ["hidden", "step", "2"] in read.marks, read.marks
    assert ["current", "li<ol.steps", 0, "step"] in read.marks, read.marks
    markers = workflow_markers(els, read.marks)
    assert "hidden:step=2" in markers and "current:li<ol.steps@0=step" in markers
    assert any(m.startswith("el:") and m.endswith(":value=b") for m in markers), markers


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


def test_a_delegated_candidate_is_no_part_of_a_states_identity():
    """Review B2: the state key and a state's core read every element but a delegated
    candidate, whose membership depends on text and order."""
    from fuzzlab.disco.fingerprint import state_fingerprint, state_signatures
    button = {"how": "native", "tag": "button", "ancestry": "div#app"}
    empty = {"how": "delegated", "tag": "p", "cls": "empty", "ancestry": "div#list"}
    msg = {"how": "delegated", "tag": "li", "cls": "msg", "ancestry": "ul<div#list"}
    url = "http://127.0.0.1:1/"
    assert state_fingerprint(url, [button, empty]) == state_fingerprint(url, [button, msg])
    assert state_fingerprint(url, [button, empty]) == state_fingerprint(url, [button])
    assert state_signatures([button, empty, msg]) == state_signatures([button])
    listener = {**empty, "how": "listener", "listeners": ["click"]}
    assert state_fingerprint(url, [button, listener]) != state_fingerprint(url, [button])


def test_a_delegated_candidate_is_no_part_of_the_execution_key_or_a_contract():
    """R7, at the merge with BUG-0539: the execution key (SP-62), its element multiset,
    its workflow markers and the restore contract built on them leave a delegated
    candidate out -- its membership and its flags -- as the structural key does. A
    listener element still counts, and so does a native control's marker."""
    from fuzzlab.disco.explore import Reading, State, contract_mismatch
    from fuzzlab.disco.fingerprint import (element_multiset, execution_key,
                                           state_fingerprint, workflow_markers)
    button = {"how": "native", "tag": "button", "ancestry": "div#app"}
    empty = {"how": "delegated", "tag": "p", "cls": "empty", "ancestry": "div#list"}
    msg = {"how": "delegated", "tag": "li", "cls": "msg", "ancestry": "ul<div#list",
           "sel": "aria-selected=true", "disabled": True}
    url = "http://127.0.0.1:1/"
    assert element_multiset([button, empty, msg, dict(msg)]) == element_multiset([button])
    assert workflow_markers([button, msg]) == workflow_markers([button]) == ()
    assert execution_key(url, [button, empty]) == execution_key(url, [button, msg]) == \
        execution_key(url, [button])
    listener = {**empty, "how": "listener", "listeners": ["click"]}
    assert execution_key(url, [button, listener]) != execution_key(url, [button])
    chosen = {"how": "native", "tag": "select", "name": "plan", "sel": "value=b"}
    assert workflow_markers([chosen]) != ()

    def reading(els):
        markers = workflow_markers(els)
        return Reading(execution_key(url, els, markers), state_fingerprint(url, els), url,
                       els, element_multiset(els), markers)
    recorded = State.read(reading([button, empty]), entry_url=url)
    assert contract_mismatch(recorded, reading([button, msg])) is None
    assert contract_mismatch(recorded, reading([button, listener])) == "extra"


def test_a_request_is_keyed_by_method_and_route():
    """Review B3: a poll's next request is the key of its last (query values and digit
    runs folded), so a control window that saw one explains the next."""
    from fuzzlab.disco.explore import request_key
    assert request_key("get", "http://127.0.0.1:1/api/n?t=1") == \
        request_key("GET", "http://127.0.0.1:1/api/n?t=2")
    assert request_key("GET", "http://127.0.0.1:1/api/tile/7") == \
        request_key("GET", "http://127.0.0.1:1/api/tile/8")
    assert request_key("POST", "http://127.0.0.1:1/api/n") != \
        request_key("GET", "http://127.0.0.1:1/api/n")


class _FakeReader:
    """A `compose.Reader` stand-in for the census: a page URL and a DevTools tree."""

    def __init__(self, tree, url="http://127.0.0.1:1/app"):
        from fuzzlab.disco.compose import Reader
        self.page = type("P", (), {"url": url})()
        self.cdp = type("C", (), {"send": lambda _s, _m, _p: {"root": tree}})()
        self.calls = 0
        self._closed = Reader.closed_hosts

    def closed_hosts(self):
        self.calls += 1
        return self._closed(self)


def _el(tag, attrs=(), children=(), roots=(), doc=None):
    node = {"localName": tag, "attributes": list(attrs), "children": list(children),
            "shadowRoots": list(roots)}
    if doc is not None:
        node["contentDocument"] = doc
    return node


def test_the_census_counts_every_closed_root_of_the_documents_read():
    """Review B4: every element hosting a closed shadow root is counted -- a built-in
    host, a nested one inside an open root, one in a frame read -- attributed to its
    frame; a frame not read is left out; a page already checked in this shape is not
    checked again; a page past the node bound is not checked, counted unchecked."""
    from fuzzlab.disco import compose
    closed = {"shadowRootType": "closed", "children": [_el("button")]}
    inner = _el("section", ("id", "deep"), roots=[closed])
    frame_doc = {"children": [_el("html", children=[_el("span", ("class", "b a"),
                                                              roots=[closed])])]}
    other_doc = {"children": [_el("div", roots=[closed])]}
    tree = {"children": [_el("html", children=[
        _el("div", ("id", "vault"), roots=[closed]),
        _el("x-card", children=[_el("b")], roots=[closed]),
        _el("open-box", roots=[{"shadowRootType": "open", "children": [inner]}]),
        _el("input", roots=[{"shadowRootType": "user-agent", "children": []}]),
        _el("iframe", ("id", "f", "data-disco-frame", "1"), doc=frame_doc),
        _el("iframe", ("id", "g", "data-disco-frame", "2"), doc=other_doc),
    ])]}
    reader = _FakeReader(tree)
    links = ["^frame", "iframe#f", "@/f.html"]
    docs = {"": ([], 40, 7), "1": (links, 5, 9)}
    censused: set = set()
    read = compose.PageRead()
    compose._census(reader, read, docs, censused)
    assert read.distinct["closed_shadow_roots"] == {
        "div#vault", "x-card", "section#deep", "<".join(["span.a.b", *links])}
    assert "budget.census" not in read.counts
    again = compose.PageRead()
    compose._census(reader, again, docs, censused)
    assert reader.calls == 1 and again.distinct == {} and again.counts == {}
    big = compose.PageRead()
    compose._census(reader, big, {"": ([], compose.MAX_NODES + 1, 3)}, censused)
    assert reader.calls == 1 and big.counts == {"budget.census": compose.MAX_NODES + 1}


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
