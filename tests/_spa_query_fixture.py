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
  (``location.href`` in a link), stash and replay (``save`` / ``show``: a stale marker),
  forward in a GET query (``fetcher``) or path (``pathy``), or POST (``beacon``).
* ``TrackSpa``: Juice Shop's ``#/track-result?id=`` shape alone, for the end-to-end M6
  test.
"""

from __future__ import annotations

from tests._spa_fixture import _HASH_INDEX, _Lab

_QUERY_JS = r"""
const routes = [{path:'track'}, {path:'search'}, {path:'score-board'}, {path:'poster'},
  {path:'hop'}, {path:'away'}, {path:'login'}, {path:'logout'}, {path:'reflect'},
  {path:'ignore'}, {path:'echohref'}, {path:'save'}, {path:'show'}, {path:'fetcher'},
  {path:'pathy'}, {path:'beacon'}];
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
this.router.navigate([`/vault`],{queryParams:{token:t}})}
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
  else if (name === 'fetcher') { text('fetcher');
    if (p.get('term')) fetch('/rest/lookup?k=' + encodeURIComponent(p.get('term')))
      .catch(() => {}); }
  else if (name === 'pathy') { text('pathy');
    if (p.get('term')) fetch('/rest/item/' + encodeURIComponent(p.get('term')))
      .catch(() => {}); }
  else if (name === 'beacon') { text('beacon');
    if (p.get('term')) fetch('/api/beacon', {method: 'POST', body: 'v=' + p.get('term')})
      .catch(() => {}); }
  else if (name === 'logout') mark('LOGOUT');
  else text(name || 'home');
}
window.addEventListener('hashchange', render);
render();
"""

_QUERY_INDEX = _HASH_INDEX.replace("/main.js", "/q.js").replace(
    "<a href='#/about'>About</a>",
    "<a href='#/search?q=fuzzlab'>Search</a> <a href='#/search?q=hello'>Hello</a>")


class QuerySpa(_Lab):
    index = _QUERY_INDEX
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
