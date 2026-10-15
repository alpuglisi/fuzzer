"""Fake single-page apps for the FR-CRAWL-17 tests (SPA route query parameters).

Served by the forms-phase-3 recording loopback server (`tests._spa_fixture._Lab`);
nothing here talks to any other host. The script is shaped like Juice Shop's minified
Angular bundle (backtick literals, ``navigate([`/r`],{queryParams:{id:t}})``,
``route.snapshot.queryParams.x``, ``queryParamMap.get(`x`)``): it is only *read* by the
crawler's scan; the hash router at its end renders each view from ``location.hash``.

* ``QuerySpa``: every FR-CRAWL-17 behaviour -- paired routes (``track`` with an
  ``innerHTML`` sink, ``search`` / ``score-board`` sharing ``q``, ``poster`` POSTing
  its ``msg`` on load, ``hop`` setting ``location.hash`` on load, ``away`` navigating
  to ``/plain``, ``login`` following its ``redirectUrl``, a destructive ``logout``, a
  dynamic-segment ``chat``, a sensitive ``token``), and unpaired names (``term``,
  ``extra``, the redirect-ish ``next``) on routes that reflect, ignore, self-echo
  (``location.href`` in a link), stash and replay (``save`` / ``show``: a stale marker;
  ``memo`` reflects ``term`` and replays the stash, so its seed after the probe shows a
  stale marker), forward in a GET query under another name (``fetcher``) or the same
  name (``forward``), in a path (``pathy``), or POST it (``beacon``).
  Its shell writes on every load (a socket.io polling POST and WebSocket pings, P1).
* ``SessionQuerySpa``: an authenticated crawl (the session in localStorage) whose
  ``fade`` seed clears the token client-side (S10).
* ``TrackSpa``: Juice Shop's ``#/track-result?id=`` shape alone, for the end-to-end M6
  test.
"""

from __future__ import annotations

from tests._spa_fixture import _HASH_INDEX, _Lab

#: The app shell's start-up writes on EVERY document load, as Juice Shop's socket.io
#: client makes them (FR-CRAWL-17 P1): an engine.io polling POST, then a WebSocket that
#: pings at once and every 100 ms. Never caused by a query parameter.
_SHELL_WRITES_JS = r"""
fetch('/socket.io/?EIO=4&transport=polling&t=' + Date.now(), {method: 'POST', body: '40'})
  .catch(() => {});
(() => { const s = new WebSocket('ws://' + location.host +
  '/socket.io/?EIO=4&transport=websocket');
  s.onopen = () => { s.send('2probe'); setInterval(() => s.send('3'), 100); }; })();
"""


def _socketio(handler):
    """``/socket.io/``: the shell's WebSocket (its pings are recorded in
    ``ws_messages``), else a polling answer."""
    if (handler.headers.get("Upgrade") or "").lower() == "websocket":
        handler._websocket()
        return
    handler._send(200, "text/plain", b"ok")


_QUERY_JS = _SHELL_WRITES_JS + r"""
const routes = [{path:'track'}, {path:'search'}, {path:'score-board'}, {path:'poster'},
  {path:'hop'}, {path:'away'}, {path:'login'}, {path:'logout'}, {path:'reflect'},
  {path:'ignore'}, {path:'echohref'}, {path:'save'}, {path:'show'}, {path:'memo'},
  {path:'fetcher'}, {path:'forward'}, {path:'pathy'}, {path:'beacon'}, {path:'autopost'},
  {path:'wsping'}, {path:'txn'}, {path:'hopper'}];
// read by the crawler's scan only (never called): Angular-style navigations and reads
class Navigations{go(t){this.router.navigate([`/track`],{queryParams:{id:t}});
this.router.navigate([`/search`],{queryParams:{q:t}});
this.router.navigate([`/score-board`],{queryParams:{q:t}});
this.router.navigate([`/poster`],{queryParams:{msg:t}});
this.router.navigate([`/hop`],{queryParams:{go:t}});
this.router.navigate([`/away`],{queryParams:{page:t}});
this.router.navigate([`/login`],{queryParams:{redirectUrl:`/basket`}});
this.router.navigate([`/logout`],{queryParams:{bye:t}});
this.router.navigate([`/chat`,t],{queryParams:{initialMessage:t}});
this.router.navigate([`/vault`],{queryParams:{token:t}});
this.router.navigate([`/autopost`],{queryParams:{go2:t}});
this.router.navigate([`/wsping`],{queryParams:{ping:t}});
this.router.navigate([`/txn`],{queryParams:{ref:t}});
this.router.navigate([`/hopper`],{queryParams:{x:t}});
this.router.navigate([`./rel`],{queryParams:{dot:t}})}
read(){return[this.route.snapshot.queryParams.term,this.route.queryParams.subscribe(n=>n),
this.route.snapshot.queryParamMap.get(`extra`),this.route.snapshot.queryParamMap.get(`next`)]}}
const P = () => new URLSearchParams(location.hash.split('?')[1] || '');
const mark = c => fetch('/rest/marker/' + c).catch(() => {});
function render() {
  const name = location.hash.replace(/^#!?\/?/, '').split('?')[0];
  const p = P();
  const app = document.getElementById('app');
  app.textContent = '';
  const text = s => { const e = document.createElement('p'); e.textContent = s;
    app.appendChild(e); };
  mark(name || 'home');
  if (name === 'track') app.innerHTML = p.get('id') ? 'Order ' + p.get('id') : 'no order';
  else if (name === 'search' || name === 'score-board')
    text('Results for ' + (p.get('q') || ''));
  else if (name === 'poster') { text('poster');
    if (p.get('msg')) fetch('/api/send', {method: 'POST', headers: {'Content-Type':
      'application/json'}, body: JSON.stringify({msg: p.get('msg')})}).catch(() => {}); }
  else if (name === 'hop') { text('hop'); if (p.get('go')) location.hash = '#/landed'; }
  else if (name === 'landed') text('landed');
  else if (name === 'away') { text('away'); if (p.get('page')) location.assign('/plain'); }
  else if (name === 'login') { text('login');
    if (p.get('redirectUrl')) location.href = p.get('redirectUrl'); }
  else if (name === 'reflect') text('Term: ' + (p.get('term') || ''));
  else if (name === 'echohref') { const a = document.createElement('a');
    a.href = location.href; a.textContent = 'share this page'; app.appendChild(a); }
  else if (name === 'save') { if (p.get('term')) localStorage.setItem('memo', p.get('term'));
    text('saved'); }
  else if (name === 'show') text('Last: ' + (localStorage.getItem('memo') || ''));
  else if (name === 'memo') { text('Term: ' + (p.get('term') || ''));
    text('Last: ' + (localStorage.getItem('memo') || '')); }
  else if (name === 'forward') { text('forward');
    if (p.get('term')) fetch('/api/search?term=' + encodeURIComponent(p.get('term')))
      .catch(() => {}); }
  else if (name === 'fetcher') { text('fetcher');
    if (p.get('term')) fetch('/rest/lookup?k=' + encodeURIComponent(p.get('term')))
      .catch(() => {}); }
  else if (name === 'pathy') { text('pathy');
    if (p.get('term')) fetch('/rest/item/' + encodeURIComponent(p.get('term')))
      .catch(() => {}); }
  else if (name === 'beacon') { text('beacon');
    if (p.get('term')) fetch('/api/beacon', {method: 'POST', body: 'v=' + p.get('term')})
      .catch(() => {}); }
  else if (name === 'autopost') { text('autopost');
    // an auto-submitted form: a POST navigation on load (U1)
    if (p.get('go2')) { const f = document.createElement('form'); f.method = 'post';
      f.action = '/api/autopost'; const i = document.createElement('input');
      i.name = 'v'; i.value = p.get('go2'); f.appendChild(i);
      document.body.appendChild(f); f.submit(); } }
  else if (name === 'wsping') { text('wsping');
    // a page-to-server WebSocket message on load (U1)
    if (p.get('ping')) { const ws = new WebSocket('ws://' + location.host + '/ws');
      ws.onopen = () => ws.send('ping-' + p.get('ping')); } }
  else if (name === 'txn') { text('txn');
    // a transaction GET the window's word rules refuse (U1)
    if (p.get('ref')) fetch('/api/order/confirm?ref=' + p.get('ref')).catch(() => {}); }
  else if (name === 'hopper') { text('hopper');
    // a GET whose redirect hop is a transaction GET the window refuses (Y1)
    if (p.get('x')) fetch('/api/go').catch(() => {}); }
  else if (name === 'logout') mark('LOGOUT');
  else text(name || 'home');
}
window.addEventListener('hashchange', render);
render();
"""

_QUERY_INDEX = _HASH_INDEX.replace("/main.js", "/q.js").replace(
    "<a href='#/about'>About</a>",
    "<a href='#/search?q=fuzzlab'>Search</a> <a href='#/search?q=hello'>Hello</a>")


def _go(handler):
    """``/api/go``: a redirect to a transaction GET (Y1)."""
    handler.send_response(302)
    handler.send_header("Location", "/api/order/confirm?via=go")
    handler.send_header("Content-Length", "0")
    handler.end_headers()


class QuerySpa(_Lab):
    """Its shell writes on every load (`_SHELL_WRITES_JS`, P1)."""
    index = _QUERY_INDEX
    responders = {"/api/go": _go, "/socket.io/": _socketio}
    script = ("/q.js", _QUERY_JS)
    pages = {"/plain": ("<!doctype html><html><head><title>plain</title></head>"
                        "<body><p>plain page</p></body></html>")}


_TRACK_JS = r"""
const routes = [{path:'track-result'}];
class TrackOrder{find(t){return this.ngZone.run(()=>L$1(this,null,function*(){return yield
this.router.navigate([`/track-result`],{queryParams:{id:t}})}))}}
function render() {
  const name = location.hash.replace(/^#!?\/?/, '').split('?')[0];
  const id = new URLSearchParams(location.hash.split('?')[1] || '').get('id');
  const app = document.getElementById('app');
  // the server would echo the order id; trusted as HTML (Juice Shop's
  // bypassSecurityTrustHtml), here an innerHTML sink
  if (name === 'track-result') app.innerHTML = id ? 'Order ' + id : 'no order';
  else app.innerHTML = '<p>home</p>';
}
window.addEventListener('hashchange', render);
render();
"""


class TrackSpa(_Lab):
    index = _HASH_INDEX.replace("/main.js", "/track.js").replace("#/about", "#/")
    script = ("/track.js", _TRACK_JS)


_SESSION_QUERY_JS = r"""
const routes = [{path:'calm'}, {path:'fade'}, {path:'after1'}];
class Nav{go(t){this.router.navigate([`/calm`],{queryParams:{z:t}});
this.router.navigate([`/fade`],{queryParams:{mode:t}});
this.router.navigate([`/after1`],{queryParams:{x:t}})}}
const mark = c => fetch('/rest/marker/' + c).catch(() => {});
function render() {
  const name = location.hash.replace(/^#!?\/?/, '').split('?')[0];
  const p = new URLSearchParams(location.hash.split('?')[1] || '');
  document.getElementById('app').textContent = name || 'home';
  mark((name || 'home') + (location.hash.indexOf('?') >= 0 ? '-query' : ''));
  if (name === 'fade' && p.get('mode')) window.localStorage.removeItem('token');
}
window.addEventListener('hashchange', render);
render();
"""


class SessionQuerySpa(_Lab):
    index = _HASH_INDEX.replace("/main.js", "/sq.js").replace("#/about", "#/after1")
    script = ("/sq.js", _SESSION_QUERY_JS)


_COOKIE_QUERY_JS = r"""
const routes = [{path:'chill'}, {path:'after2'}];
class Nav{go(t){this.router.navigate([`/chill`],{queryParams:{c:t}});
this.router.navigate([`/after2`],{queryParams:{x:t}})}}
const mark = c => fetch('/rest/marker/' + c).catch(() => {});
function render() {
  const name = location.hash.replace(/^#!?\/?/, '').split('?')[0];
  const p = new URLSearchParams(location.hash.split('?')[1] || '');
  document.getElementById('app').textContent = name || 'home';
  mark((name || 'home') + (location.hash.indexOf('?') >= 0 ? '-query' : ''));
  // a slow GET whose answer expires the session cookie (U4)
  if (name === 'chill' && p.get('c')) fetch('/rest/expire').catch(() => {});
}
window.addEventListener('hashchange', render);
render();
"""


def _expire(handler):
    """``/rest/expire``: answers after a delay, clearing the ``sid`` session cookie."""
    import time
    time.sleep(1.0)
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Set-Cookie", "sid=; Max-Age=0; Path=/")
    handler.send_header("Content-Length", "2")
    handler.end_headers()
    handler.wfile.write(b"{}")


class SessionCookieSpa(_Lab):
    """An authenticated crawl whose session is a ``sid`` cookie: the ``chill`` seed's slow
    GET clears it (U4)."""
    index = _HASH_INDEX.replace("/main.js", "/sc.js").replace("#/about", "#/after2")
    script = ("/sc.js", _COOKIE_QUERY_JS)
    responders = {"/rest/expire": _expire}


_REDIRECT_SEED_JS = _SHELL_WRITES_JS + r"""
// the declarations are read by the scan, never run (no VueRouter on the page)
function declare() { return new VueRouter({mode: 'history', routes: [
  { path: '/goaway', component: Goaway },
  { path: '/next1', component: Next1 },
  { path: '/late1', component: Late1 },
]}); }
class Nav{go(t){this.router.navigate([`/goaway`],{queryParams:{x:t}});
this.router.navigate([`/next1`],{queryParams:{y:t}});
this.router.navigate([`/late1`],{queryParams:{z:t}})}}
const q = location.search;
fetch('/rest/marker/' + location.pathname.replace(/\//g, '_') + (q ? '-query' : ''))
  .catch(() => {});
// a page without a query keeps POSTing (M7: never the next query load's write)
if (!q) setInterval(() => fetch('/api/tick', {method: 'POST', body: 't'})
  .catch(() => {}), 50);
// a slow GET still in flight when the load is read (M8)
if (location.pathname === '/late1' && q) fetch('/rest/late').catch(() => {});
"""

_REDIRECT_SEED_INDEX = ("<!doctype html><html><head><title>redir</title><base href='/'>"
                        "<script src='/redir.js'></script></head><body><p>shell</p>"
                        "</body></html>")


def _goaway(handler):
    """``/goaway?x=``: the seed's own document redirects to a transaction GET, a hop
    the window refuses (M4, M7); a bare ``/goaway`` is the app shell."""
    if "x=" in handler.path:
        handler.send_response(302)
        handler.send_header("Location", "/api/order/confirm?via=hop")
        handler.send_header("Content-Length", "0")
        handler.end_headers()
        return
    body = _REDIRECT_SEED_INDEX.encode()
    handler._send(200, "text/html", body)


def _late(handler):
    """``/rest/late``: answers after 6 s (M8: still in flight when a 3 s-timeout load
    is read)."""
    import time
    time.sleep(6.0)
    handler._send(200, "application/json", b'{"late":true}')


class RedirectSeedSpa(_Lab):
    """A history-mode app whose ``/goaway`` seed's own document redirect is refused by
    its window (M4, M7), then ``/next1`` and ``/late1`` seeds; pages without a query
    POST on an interval; the ``/late1`` seed's GET answers late (M8). Its shell writes on
    every load, a history-mode seed's included (P1(b))."""
    index = _REDIRECT_SEED_INDEX
    script = ("/redir.js", _REDIRECT_SEED_JS)
    history = True
    responders = {"/goaway": _goaway, "/rest/late": _late, "/socket.io/": _socketio}


_BASELINE_JS = r"""
const routes = [{path:'poster'}, {path:'search'}, {path:'find'}, {path:'talk'},
  {path:'calm'}];
class Navigations{go(t){this.router.navigate([`/poster`],{queryParams:{msg:t}});
this.router.navigate([`/search`],{queryParams:{q:t}});
this.router.navigate([`/find`],{queryParams:{q:t}});
this.router.navigate([`/talk`],{queryParams:{q:t}});
this.router.navigate([`/calm`],{queryParams:{q:t}})}}
// the shell, on EVERY load: an analytics POST to /api/events, a socket.io polling POST,
// then a socket that pings every 100 ms (the baseline's endpoints, B1/B2)
const post = (path, body) => fetch(path, {method: 'POST', headers: {'Content-Type':
  'application/json'}, body: JSON.stringify(body)}).catch(() => {});
post('/api/events', {page: 'load'});
fetch('/socket.io/?EIO=4&transport=polling&t=' + Date.now(), {method: 'POST', body: '40'})
  .catch(() => {});
window.__sock = new WebSocket('ws://' + location.host +
  '/socket.io/?EIO=4&transport=websocket');
__sock.onopen = () => { __sock.send('2probe'); setInterval(() => __sock.send('3'), 100); };
const emit = m => __sock.readyState === 1 ? __sock.send(m)
  : __sock.addEventListener('open', () => __sock.send(m));
function render() {
  const name = location.hash.replace(/^#!?\/?/, '').split('?')[0];
  const p = new URLSearchParams(location.hash.split('?')[1] || '');
  const q = p.get('q'), app = document.getElementById('app');
  app.textContent = name || 'home';
  fetch('/rest/marker/' + (name || 'home') + (location.hash.indexOf('?') >= 0 ? '-query' : ''))
    .catch(() => {});
  // B1: a query-caused POST to an endpoint of its own
  if (name === 'poster' && p.get('msg')) post('/api/send', {msg: p.get('msg')});
  if (name === 'search' && q) post('/api/s', {q: q});
  // B2: a query-caused write to the shell's own endpoints
  if (name === 'find' && q) post('/api/events', {q: q});
  if (name === 'talk' && q) emit('42["search","' + q + '"]');
  if (name === 'calm') app.textContent = 'calm ' + (q || '');
}
window.addEventListener('hashchange', render);
render();
"""

_BASELINE_INDEX = _HASH_INDEX.replace("/main.js", "/b.js").replace(
    "<a href='#/about'>About</a>", "<a href='#/calm'>Calm</a>")


class BaselineSpa(_Lab):
    """The write baseline's holes (FR-CRAWL-17, D60). The crawl starts at ``/start``, a
    plain page whose links ``#/poster?msg=hi`` and ``#/search?q=foo`` are crawled before
    any seed: their query-caused POSTs (``/api/send``, ``/api/s``) are never a baseline
    (B1). The shell POSTs ``/api/events`` and pings a socket.io WebSocket on every load;
    ``#/find?q=`` POSTs ``{"q": q}`` to ``/api/events`` and ``#/talk?q=`` emits ``q`` on
    the shell's socket: writes carrying the seed's filler on baseline endpoints (B2).
    ``#/calm?q=`` only renders ``q``."""
    index = _BASELINE_INDEX
    script = ("/b.js", _BASELINE_JS)
    responders = {"/socket.io/": _socketio}
    pages = {"/start": ("<!doctype html><html><head><title>start</title></head><body>"
                        "<a href='/#/poster?msg=hi'>poster</a> "
                        "<a href='/#/search?q=foo'>search</a> <a href='/'>app</a>"
                        "</body></html>")}
