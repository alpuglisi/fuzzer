"""D72 (owner, 2026-10-16): the page-visit word rules are gone; destructive-looking
visits and clicks come last, never refused (CC-CRAWL-0042..0044).

The reveal click of a Logout menu item is deferred to the end of the crawl
(`LocalSpider._deferred_reveals`): measured on Juice Shop after CC-CRAWL-0043, clicking
it in place cleared the session token, and the second loss stopped every later reveal
and query load (W4/S10) -- reveals fell from 42 to 2. Every server here is loopback.
"""

from __future__ import annotations

from tests._spa_fixture import _HASH_INDEX, _Lab, chromium_or_skip, run_crawl

#: A Juice-Shop-like shell: an account menu on every route (Profile, and a Logout that
#: clears the session token client-side), and a Details toggle on routes a, b and c.
_NAV_JS = r"""
const routes = [{path:'a'}, {path:'b'}, {path:'c'}];
const mark = code => fetch('/rest/marker/' + code).catch(() => {});
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  document.getElementById('app').innerHTML =
    "<button id='acct' aria-haspopup='menu' aria-label='Show account menu'>Account" +
    "</button>" + (name ? "<button id='d' aria-haspopup='dialog' " +
    "aria-label='Show details'>Details</button>" : '');
  document.getElementById('acct').onclick = () => {
    if (document.getElementById('m')) return;
    const m = document.createElement('div');
    m.id = 'm';
    m.innerHTML = "<div role='menu'><button role='menuitem' id='p'>Profile</button>" +
      "<button role='menuitem' id='lo'><mat-icon>exit_to_app</mat-icon> Logout" +
      "</button></div>";
    document.body.appendChild(m);
    document.getElementById('p').onclick = () => mark('profile');
    document.getElementById('lo').onclick = () => { mark('logout');
      window.localStorage.removeItem('token'); };
    document.addEventListener('keydown', e => { if (e.key === 'Escape') m.remove(); });
  };
  const d = document.getElementById('d');
  if (d) d.onclick = () => mark('opened-' + name);
}
window.addEventListener('hashchange', render);
render();
"""


class _NavSpa(_Lab):
    index = _HASH_INDEX.replace("/main.js", "/nav.js")
    script = ("/nav.js", _NAV_JS)


def test_a_logout_menu_item_is_clicked_last_and_stops_nothing_before_it(monkeypatch,
                                                                       tmp_path):
    """Real Chromium, an authenticated crawl with its session in localStorage: every
    route's Details reveal and the Profile item are clicked; the Logout item is not
    refused but deferred, and clicked after every other reveal; no session is lost
    before it, so no reveal is stopped early."""
    from fuzzlab.tools.spider import LocalSpider
    from tests.test_forms_phase4 import _LsManager
    chromium_or_skip(monkeypatch)
    lab = _NavSpa()
    try:
        sp = LocalSpider(lab.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=10000,
                         session_manager=_LsManager(lab.base), identity="user")
        run_crawl(sp)
    finally:
        lab.close()
    marks = [r[1].rsplit("/", 1)[1] for r in lab.requests if "/rest/marker/" in r[1]]
    for route in ("a", "b", "c"):
        assert f"opened-{route}" in marks, marks
    assert "profile" in marks and "logout" in marks, marks
    first_logout = marks.index("logout")
    assert all(i < first_logout for i, m in enumerate(marks) if m.startswith("opened-"))
    assert sp.spa_counts["reveals_deferred"] >= 1
    # the only session loss is the deferred logout's, at the end
    assert sp.spa_counts["session_losses_after_reveal"] <= 2
    assert all(m != "logout" for m in marks[:first_logout])


def test_what_a_reveal_looks_destructive_for():
    """The ordering predicate: a logout text or glyph, judged text-first (Juice Shop's
    ``exit_to_app`` LOGIN button is not one); it refuses nothing (`reveal_refusal`)."""
    from fuzzlab.tools import spa
    assert spa.reveal_looks_destructive(["Logout", "", "exit_to_app"])
    assert spa.reveal_looks_destructive(["", "", "power_settings_new"])
    assert spa.reveal_looks_destructive(["Delete all", "", ""])
    assert spa.reveal_looks_destructive(["Items removed", "", ""])        # folded
    assert not spa.reveal_looks_destructive(["Log in", "Login", "exit_to_app"])
    assert not spa.reveal_looks_destructive(["Account", "Show account menu", ""])
    assert not spa.reveal_looks_destructive(["Orders & Payment", "", ""])  # not destructive
    for labels in (["Logout", "", ""], ["Delete all", "", "delete"]):
        assert spa.reveal_refusal(labels) is None
