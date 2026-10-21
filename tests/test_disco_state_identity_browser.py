"""The disco explorer's state identity, work and restore contract in a real browser
(BUG-0539: audit defects 1, 2 and 3; FR-CRAWL-31..33). The pure parts are in
`tests/test_disco_state_identity.py`.

Each test explores one loopback page served from here (`_FlowSite`) with one guarded
Chromium (no capture proxy, no harvest) and fails on the pre-fix explorer: this module
imports nothing the fix added, so the old code runs it to its assertions. Under
``FUZZLAB_REQUIRE_BROWSER=1`` a missing browser fails instead of skipping (PA-0065)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.disco import explore

# --- the real browser ----------------------------------------------------------------------

_PAGE = "<!doctype html><html><head><title>Flow</title></head><body>{body}" \
        "<script>{script}</script></body></html>"

WIZARD = _PAGE.format(body="<h1>Wizard</h1><p id=s></p><button id=next>Next</button>", script="""
const step = Number(new URLSearchParams(location.search).get('step') || '1');
document.getElementById('s').textContent = 'Step ' + step;
document.getElementById('next').addEventListener('click', () => {
  if (step < 3) location.href = '/wizard?step=' + (step + 1);   // in no link: no harvest
  else fetch('/api/wizard/finish');
});""")

DIALOG = _PAGE.format(body="<button id=open>Open</button><div id=dlg></div>", script="""
const dlg = document.getElementById('dlg');
function stage(n) {                       // the same Next in both stages
  dlg.innerHTML = '';
  const p = document.createElement('p');
  p.textContent = n === 1 ? 'Choose account' : 'Confirm transfer';
  dlg.appendChild(p);
  if (n === 2) {
    const back = document.createElement('button'); back.id = 'back'; back.textContent = 'Back';
    back.addEventListener('click', () => stage(1)); dlg.appendChild(back);
  }
  const next = document.createElement('button'); next.id = 'next'; next.textContent = 'Next';
  next.addEventListener('click', () => {
    if (n === 1) stage(2); else fetch('/api/dialog/confirm', {method: 'POST'});
  });
  dlg.appendChild(next);
}
document.getElementById('open').addEventListener('click', () => stage(1));""")

FLAKY = _PAGE.format(body="<button id=load>Load</button>", script="""
document.getElementById('load').addEventListener('click', () => fetch('/api/flaky/load'));""")

SHOP = _PAGE.format(body="<button id=start>Start</button><div id=cart></div>", script="""
document.getElementById('start').addEventListener('click', () =>
  fetch('/api/cart').then(r => r.json()).then(items => {
    const cart = document.getElementById('cart'); cart.innerHTML = '';
    for (const it of items) {
      const b = document.createElement('button'); b.id = it; b.textContent = it;
      b.addEventListener('click', () => fetch('/api/' + it)); cart.appendChild(b);
    }
  }));""")

ORDER = _PAGE.format(body="<button id=begin>Begin</button><div id=o></div>", script="""
const o = document.getElementById('o');
document.getElementById('begin').addEventListener('click', () =>
  fetch('/api/order', {method: 'POST'}).then(() => {
    o.innerHTML = '';
    const c = document.createElement('button'); c.id = 'confirm'; c.textContent = 'Confirm';
    c.addEventListener('click', () => fetch('/api/order/confirm'));
    const d = document.createElement('button'); d.id = 'details'; d.textContent = 'Details';
    d.addEventListener('click', () => {
      const x = document.createElement('button'); x.id = 'close'; x.textContent = 'Close';
      x.addEventListener('click', () => x.remove()); o.appendChild(x);
    });
    o.appendChild(c); o.appendChild(d);
  }));""")

MODAL = _PAGE.format(body="<button id=open>Open</button><div id=modal></div>", script="""
const m = document.getElementById('modal');
document.getElementById('open').addEventListener('click', () =>
  fetch('/api/modal').then(r => { if (!r.ok) return;     // expired: no modal opens
    m.innerHTML = '';
    const c = document.createElement('button'); c.id = 'close'; c.textContent = 'Close';
    c.addEventListener('click', () => { m.innerHTML = ''; });
    const p = document.createElement('button'); p.id = 'pay'; p.textContent = 'Pay';
    p.addEventListener('click', () => fetch('/api/pay'));
    m.appendChild(c); m.appendChild(p); }));""")


def _flow(stage: int) -> str:
    """The server's workflow stage decides the page: stage 2 adds Confirm."""
    confirm = "<button id=confirm>Confirm</button>" if stage == 2 else ""
    return _PAGE.format(body=f"<button id=next>Next</button><button id=help>Help</button>"
                        f"{confirm}", script="""
document.getElementById('next').addEventListener('click', () =>
  fetch('/api/advance', {method: 'POST'}).then(() => location.reload()));
document.getElementById('help').addEventListener('click', () => fetch('/api/help'));
const c = document.getElementById('confirm');
if (c) c.addEventListener('click', () => fetch('/api/confirm'));""")


PAGES = {"/wizard": WIZARD, "/dialog": DIALOG, "/flaky": FLAKY, "/shop": SHOP,
         "/order": ORDER, "/modal": MODAL}


class _FlowSite:
    """Loopback pages for the flows; ``hits`` lists ``(method, path)`` received.
    ``/api/cart`` answers ``["pay", "terms"]`` the first time and ``["pay"]`` after:
    the terms control is consumed, so a restore of the cart cannot show it again.
    ``/api/modal`` answers 409 from its third call (the workflow expired: the modal no
    longer opens). ``/flow`` shows the server's stage, which ``POST /api/advance``
    moves to 2 for good."""

    def __init__(self):
        self.hits: list[tuple[str, str]] = []
        self.cart_calls = 0
        self.modal_calls = 0
        self.stage = 1
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body: bytes, ctype: str):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _route(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                path = self.path.split("?", 1)[0]
                site.hits.append((method, path))
                if method == "GET" and path in PAGES:
                    return self._send(200, PAGES[path].encode(), "text/html; charset=utf-8")
                if method == "GET" and path == "/flow":
                    return self._send(200, _flow(site.stage).encode(),
                                      "text/html; charset=utf-8")
                if path == "/api/advance":
                    site.stage = 2
                if path == "/api/modal":
                    site.modal_calls += 1
                    return self._send(200 if site.modal_calls <= 2 else 409, b"{}",
                                      "application/json")
                if path == "/api/cart":
                    site.cart_calls += 1
                    items = ["pay", "terms"] if site.cart_calls == 1 else ["pay"]
                    return self._send(200, json.dumps(items).encode(), "application/json")
                if path.startswith("/api/"):
                    return self._send(200, b"{}", "application/json")
                return self._send(404, b"not found", "text/plain")

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def count(self, method: str, path: str) -> int:
        return sum(1 for hit in self.hits if hit == (method, path))

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site():
    s = _FlowSite()
    try:
        yield s
    finally:
        s.close()


def _explore(site, path, tmp_path, monkeypatch):
    """One real exploration of ``path`` (one worker, no capture proxy, no harvest)."""
    from playwright.sync_api import Error as PlaywrightError

    from tests._browser import skip_or_fail
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    log = tmp_path / "actions.jsonl"
    ex = explore.Explorer(site.base + path.lstrip("/"), scope_urls=[site.base], proxy=None,
                          options=explore.ExploreOptions(idle_ms=150, max_quiet_ms=3000,
                                                         deadline_s=120, max_harvest=0),
                          actions_log=log)
    try:
        report = ex.run()
    except PlaywrightError as exc:
        if "Executable doesn't exist" in str(exc) or "launch" in str(exc).lower():
            skip_or_fail(f"chromium unavailable: {str(exc).splitlines()[0]}")
        raise
    actions = [json.loads(ln) for ln in log.open()] if log.exists() else []
    return report, actions


def test_a_wizard_step_with_the_same_layout_is_explored_to_its_end(site, tmp_path,
                                                                    monkeypatch):
    """Defect 1, in a real browser: steps 1-3 of ``/wizard?step=N`` share one layout and
    one Next button. Pre-fix, step 2 hashed like step 1, was taken as known, and the
    finish request was never made."""
    report, _actions = _explore(site, "/wizard?step=1", tmp_path, monkeypatch)
    assert site.count("GET", "/api/wizard/finish") >= 1, site.hits
    assert report.states >= 3


def test_a_dialogs_second_stage_takes_the_same_next_again(site, tmp_path, monkeypatch):
    """Defect 2, in a real browser: the dialog's second stage keeps its Next, which now
    confirms. Pre-fix the step was keyed by the route, already seen in the first stage,
    and the confirmation was never sent."""
    _report, actions = _explore(site, "/dialog", tmp_path, monkeypatch)
    assert site.count("POST", "/api/dialog/confirm") >= 1, site.hits
    nexts = [(a["state"], a["occurrence"]) for a in actions if a["label"] == "Next"]
    assert len(nexts) >= 2 and len(set(nexts)) == len(nexts)   # per state, once each


def test_a_transient_playwright_error_never_consumes_an_action(site, tmp_path,
                                                                monkeypatch):
    """Defect 2: the first attempt of the only action raises a Playwright error. Pre-fix
    the step was marked seen before it ran and never tried again."""
    from playwright.sync_api import Error as PlaywrightError
    real, failed = explore.Explorer.act, []

    def flaky_act(self, page, ctx, el, step):
        if el.get("label") == "Load" and not failed:
            failed.append(step)
            raise PlaywrightError("transient: element is not attached to the DOM")
        return real(self, page, ctx, el, step)

    monkeypatch.setattr(explore.Explorer, "act", flaky_act)
    report, _actions = _explore(site, "/flaky", tmp_path, monkeypatch)
    assert failed, "the injected failure never ran"
    assert site.count("GET", "/api/flaky/load") == 1, site.hits
    assert report.actions_retried == 1 and report.actions_failed == 0


def test_a_restore_that_lost_a_core_control_is_unresolved_and_its_contract_kept(
        site, tmp_path, monkeypatch):
    """Defect 3, in a real browser: the cart state was recorded with pay and terms; its
    restore shows pay only (terms was consumed). Pre-fix the restore was accepted, the
    core shrunk to what was left, and pay was explored as that state."""
    real, restores = explore.Explorer.restore, []

    def watched(self, page, ctx, state):
        before = state.core
        ok = real(self, page, ctx, state)
        restores.append((before, state.core, ok))
        return ok

    monkeypatch.setattr(explore.Explorer, "restore", watched)
    report, actions = _explore(site, "/shop", tmp_path, monkeypatch)
    assert all(before == after for before, after, _ok in restores), restores
    assert any(ok is False for _b, _a, ok in restores)
    assert site.count("GET", "/api/pay") == 0, site.hits      # nothing done in a wrong state
    assert report.unresolved == {"core": 1}
    assert not [a for a in actions if a["label"] in ("pay", "terms")]


def test_a_state_reached_by_a_post_is_explored_in_place_and_never_replayed(
        site, tmp_path, monkeypatch):
    """Defect 3, in a real browser: Begin sends a POST and reveals Confirm and Details.
    Pre-fix every restore of that state replayed Begin (another order each time); now
    the state is explored where it was reached and never restored by a replay."""
    report, actions = _explore(site, "/order", tmp_path, monkeypatch)
    assert site.count("POST", "/api/order") == 1, site.hits
    assert site.count("GET", "/api/order/confirm") >= 1, site.hits
    assert report.live_states >= 1 and report.unresolved.get("unsafe-step", 0) >= 1
    begin = [a for a in actions if a["label"] == "Begin"]
    assert begin and begin[0]["replay_safe"] is False


def test_a_modal_closed_by_its_own_control_that_does_not_reopen_is_unresolved(
        site, tmp_path, monkeypatch):
    """Review B1, in a real browser: Open shows a modal (Close, Pay); the explorer closes
    it with its own Close, then restores the modal state to take Pay, and the modal no
    longer opens. Pre-fix the Close click declared Close and Pay optional run-wide, the
    restore showing no modal was accepted, and the failure surfaced only as a failed
    action."""
    report, actions = _explore(site, "/modal", tmp_path, monkeypatch)
    assert any(a["label"] == "Close" for a in actions), actions
    assert report.unresolved == {"core": 1}, report.unresolved
    assert "dismissed" not in report.optional_declared
    assert site.count("GET", "/api/pay") == 0, site.hits


def test_a_restore_that_lands_on_a_later_stage_is_unresolved_never_that_stage(
        site, tmp_path, monkeypatch):
    """Review B2, in a real browser: Next POSTs and the server's workflow moves to stage
    2, which shows stage 1's controls and Confirm on the same URL. Pre-fix a restore of
    stage 1 landed on stage 2, was accepted as a superset, and stage 1's Help ran there
    and was logged under stage 1's key."""
    report, actions = _explore(site, "/flow", tmp_path, monkeypatch)
    [stage1] = {a["state"] for a in actions if a["label"] == "Next" and a["replay_safe"]
                is False and a["new_state"] != a["state"]}
    assert not [a for a in actions if a["label"] == "Help" and a["state"] == stage1]
    assert report.unresolved == {"extra": 1}, report.unresolved
