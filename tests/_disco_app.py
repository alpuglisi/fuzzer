"""A generic client-rendered app for the disco discovery tests (D70, FR-CRAWL-18..20).

Served by a test-started loopback ``ThreadingHTTPServer``; every request it receives is
recorded. A plain project/task tracker written in vanilla JavaScript, shaped like no
particular lab, built to exercise what static crawling cannot see:

* the shell is an empty ``<div id=root>``; every view is rendered by ``/app.js``;
* navigation entries are ``<div>``s with ``addEventListener('click')`` only: no ``href``,
  no ``role``, no ``onclick`` attribute, no pointer cursor -- only DevTools' listener
  query finds them;
* a project list (``GET /api/projects``, fetched 120 ms after its click: a debounce, so
  quiet must be measured from the action, not from the last request) and per-project tasks
  (``GET /api/projects/<int>/tasks``) -- two numeric ids, so path templating has work;
* a "New task" dialog inserted into the DOM on click, with a form that the browser's
  own validation blocks unless filled validly (``required``, ``minlength``, ``type=email``,
  ``min``/``max``, a ``pattern``, a ``-?[\\d]*`` pattern, and a range only its script
  enforces -- ``aria-invalid`` after blur, the button disabled until it holds: both
  measured on Juice Shop); its submit sends ``POST /api/projects/<int>/tasks``
  (JSON) and the answer carries a UUID that a later ``PUT /api/tasks/<uuid>`` and a
  ``POST /api/hooks/notify`` body reuse -- a producer -> consumer edge;
* third-party SPA shapes the explorer must survive (measured on Juice Shop): a one-time
  welcome overlay (first visit only), a notice bar gone for good once dismissed, a hash
  router (`#/` and `#/projects`: a restore between them is a same-document change), and
  state classes toggled as the UI changes (`toolbar--active`, `is-touched`);
* a toolbar on every route (chrome) holding a search box submitted by Enter only
  (``GET /api/search``) beside its buttons: the buttons share the search box's
  container, so each looks like that "form"'s submitter (measured on Juice Shop,
  BUG-0502);
* a "Help" link to a page whose script navigates away 30 ms after it loads (reads of a
  page that moves on under the explorer);
* a "Delete account" control and a "Log out" control that must never be acted on;
* an image from ``OTHER`` (another loopback port: out of scope) that must never be
  fetched;
* resources only a harvest reaches (CC-CRAWL-0038): an image named only by a stylesheet
  rule nothing matches, and a page named only by ``robots.txt``, whose button's request
  happens only if that page is explored;
* a route only the script declares (a route table entry and a ``navigate("/track?id=")``
  bound to a key the explorer never presses): ``#/track?id=<v>`` fetches
  ``GET /api/track?id=<v>``, so it is reached only from the script (BUG-0505, measured
  on Juice Shop's ``#/track-result``);
* a catch-all: any other non-API ``GET`` answers with the shell (as an SPA server's
  fallback route does; measured on Juice Shop's ``/sitemap.xml``), so a harvest load of
  ``/sitemap.xml`` is the same app under another path -- an alias, never a second app
  to explore (BUG-0505).
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHELL = b"""<!doctype html><html><head><title>Tracker</title>
<link rel="stylesheet" href="/style.css"></head>
<body><div id=root></div><img id=ext><script src="/app.js"></script></body></html>"""

#: A rule for a selector nothing matches: the browser never fetches its image.
STYLE = b".never-used { background: url(/img/unused.png) }"
ROBOTS = b"User-agent: *\nDisallow: /hidden/report.html\n"
#: Linked from robots.txt only; its button's request happens only if it is explored.
HIDDEN = b"""<!doctype html><html><body><button id=go>Refresh report</button>
<script>document.getElementById('go').addEventListener('click',
  () => fetch('/api/hidden/click'));</script></body></html>"""

HELP = b"""<!doctype html><html><body><p>Help</p><button id=b>Ok</button>
<script>setTimeout(() => { location.href = '/'; }, 30);</script></body></html>"""

APP_JS = r"""
const root = document.getElementById('root');
document.getElementById('ext').src = '__OTHER__/pixel.png';
const api = (url, method, body) => fetch(url, {method: method || 'GET',
  headers: body ? {'Content-Type': 'application/json'} : {},
  body: body ? JSON.stringify(body) : undefined}).then(r => r.json());
function nav(label, fn) {
  const d = document.createElement('div');
  d.className = 'nav'; d.textContent = label;
  d.addEventListener('click', fn);
  return d;
}
function welcome() {                       // one-time UI: shown on the first visit only
  if (localStorage.getItem('welcomed')) return;
  localStorage.setItem('welcomed', '1');
  const w = document.createElement('div'); w.className = 'overlay overlay--shown';
  w.innerHTML = '<h2>Welcome</h2><a href="https://example.org/about">About</a>';
  const b = document.createElement('button'); b.textContent = 'Dismiss';
  b.addEventListener('click', () => w.remove());
  w.appendChild(b); document.body.appendChild(w);
}
function notice() {                        // dismissible: gone for good once dismissed
  if (document.cookie.includes('notice=ok')) return;
  const n = document.createElement('div'); n.className = 'notice';
  const b = document.createElement('button'); b.textContent = 'Got it';
  b.addEventListener('click', () => { document.cookie = 'notice=ok; path=/'; n.remove(); });
  n.appendChild(b); document.body.appendChild(n);
}
function home() {
  root.innerHTML = '';
  const bar = document.createElement('div');
  bar.className = location.hash === '#/projects' ? 'toolbar toolbar--active' : 'toolbar';
  bar.appendChild(nav('Projects', () => { location.hash = '#/projects'; }));
  bar.appendChild(nav('Settings', settings));
  const search = document.createElement('input');          // submitted by Enter only
  search.type = 'search'; search.placeholder = 'Search tasks';
  search.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') api('/api/search?q=' + encodeURIComponent(search.value));
  });
  bar.appendChild(search);
  const theme = document.createElement('button');         // a toolbar button: chrome
  theme.textContent = 'Theme';
  theme.addEventListener('click', () => bar.classList.toggle('toolbar--dark'));
  bar.appendChild(theme);
  const help = document.createElement('a'); help.href = '/help'; help.textContent = 'Help';
  bar.appendChild(help);
  const top = document.createElement('a'); top.href = '#/'; top.textContent = 'Home';
  bar.appendChild(top);
  const danger = document.createElement('button');
  danger.textContent = 'Delete account';
  danger.addEventListener('click', () => api('/api/account/remove', 'POST', {}));
  bar.appendChild(danger);
  const out = document.createElement('button');
  out.textContent = 'Log out';
  out.addEventListener('click', () => { location.href = '/logout'; });
  bar.appendChild(out);
  root.appendChild(bar);
}
function settings() {
  api('/api/settings').then(s => {
    const p = document.createElement('p'); p.textContent = 'Theme: ' + s.theme;
    root.appendChild(p);
  });
}
function projects() {
  setTimeout(() => api('/api/projects').then(list => {      // a 120 ms debounce
    const ul = document.createElement('div'); ul.id = 'plist';
    list.forEach(p => ul.appendChild(nav(p.name, () => tasks(p.id))));
    root.appendChild(ul);
  }), 120);
}
function tasks(pid) {
  api('/api/projects/' + pid + '/tasks').then(list => {
    const box = document.createElement('div'); box.className = 'tasks';
    list.forEach(t => { const s = document.createElement('span'); s.textContent = t.title;
                        box.appendChild(s); });
    const add = document.createElement('button'); add.textContent = 'New task';
    add.addEventListener('click', () => dialog(pid));
    box.appendChild(add);
    root.appendChild(box);
  });
}
function dialog(pid) {
  const f = document.createElement('form');
  f.innerHTML = '<input name="title" required minlength="3">'
    + '<input name="owner_email" type="email" required>'
    + '<input name="estimate" type="number" min="1" max="10" required>'
    + '<input name="code" pattern="[A-Z]{3}-[0-9]{2}" required placeholder="ABC-12">'
    + '<select name="priority"><option value="">-</option><option value="low">low</option>'
    + '<option value="high">high</option></select>'
    + '<input name="phone" type="number" required aria-invalid="false">'
    + '<input name="check" pattern="-?[\\d]*" required>'
    + '<button type="submit">Create</button>';
  // a range only the script enforces: shown as aria-invalid once the field is touched
  // (blurred), and the button stays disabled until it holds (measured on Juice Shop)
  const btn = f.querySelector('button');
  const phoneOk = () => Number(f.phone.value) >= 1000000 && Number(f.phone.value) <= 9999999999;
  f.phone.addEventListener('blur', () => f.phone.setAttribute('aria-invalid', String(!phoneOk())));
  const gate = () => { btn.disabled = !(f.checkValidity() && phoneOk()); };
  f.addEventListener('input', gate); gate();
  f.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const body = {title: f.title.value, owner_email: f.owner_email.value,
                  estimate: Number(f.estimate.value), code: f.code.value,
                  priority: f.priority.value, phone: f.phone.value, check: f.check.value};
    api('/api/projects/' + pid + '/tasks', 'POST', body).then(t => {
      const edit = document.createElement('button'); edit.textContent = 'Mark done';
      edit.addEventListener('click', () => api('/api/tasks/' + t.id, 'PUT', {done: true}));
      const hook = nav('Notify watchers', () => api('/api/hooks/notify', 'POST', {task_id: t.id}));
      root.appendChild(edit); root.appendChild(hook);
    });
  });
  f.addEventListener('input', (ev) => ev.target.classList.add('is-touched', 'field--dirty'));
  root.appendChild(f);
}
function track() {                         // reads its id from the route's query
  const id = new URLSearchParams(location.hash.split('?')[1] || '').get('id');
  if (id) api('/api/track?id=' + encodeURIComponent(id));
}
const ROUTES = [{path: 'projects'}, {path: 'track'}];
function navigate(url) { location.hash = '#' + url; }
window.addEventListener('keydown', (ev) => {   // a shortcut the explorer never presses
  if (ev.key === 'F9') navigate("/track?id=" + ev.code);
});
function route() {                         // a hash router: '#/', '#/projects', '#/track'
  home();
  if (location.hash === '#/projects') projects();
  if (location.hash.startsWith('#/track')) track();
}
window.addEventListener('hashchange', route);
welcome(); notice(); route();
"""


class DiscoApp:
    """``with DiscoApp(other='http://127.0.0.1:PORT') as app: app.url`` -- ``app.hits``
    lists ``(method, path, headers, body)`` of every request received."""

    def __init__(self, other: str = "http://127.0.0.1:9"):
        self.other = other.rstrip("/")
        self.hits: list[tuple[str, str, dict, str]] = []
        self.tasks: dict[str, dict] = {}
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _body(self) -> str:
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n).decode("utf-8", "replace") if n else ""

            def _send(self, code: int, body, ctype: str = "application/json"):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _route(self, method: str):
                body = self._body()
                app.hits.append((method, self.path, dict(self.headers), body))
                path = self.path.split("?", 1)[0]
                if method == "GET" and path == "/":
                    return self._send(200, SHELL, "text/html; charset=utf-8")
                if method == "GET" and path == "/help":
                    return self._send(200, HELP, "text/html; charset=utf-8")
                if method == "GET" and path == "/style.css":
                    return self._send(200, STYLE, "text/css")
                if method == "GET" and path == "/robots.txt":
                    return self._send(200, ROBOTS, "text/plain")
                if method == "GET" and path == "/hidden/report.html":
                    return self._send(200, HIDDEN, "text/html; charset=utf-8")
                if method == "GET" and path == "/img/unused.png":
                    return self._send(200, b"\x89PNG\r\n", "image/png")
                if path == "/api/hidden/click":
                    return self._send(200, {"ok": True})
                if method == "GET" and path == "/app.js":
                    js = APP_JS.replace("__OTHER__", app.other).encode()
                    return self._send(200, js, "application/javascript")
                if method == "GET" and path == "/api/projects":
                    return self._send(200, [{"id": 101, "name": "Alpha"},
                                            {"id": 102, "name": "Beta"}])
                if method == "GET" and path == "/api/search":
                    return self._send(200, [])
                if method == "GET" and path == "/api/settings":
                    return self._send(200, {"theme": "light", "page_size": 20})
                if method == "GET" and path == "/api/track":
                    return self._send(200, {"status": "unknown"})
                parts = path.strip("/").split("/")
                if parts[:2] == ["api", "projects"] and len(parts) == 4 and parts[3] == "tasks":
                    if method == "GET":
                        return self._send(200, [{"id": str(uuid.uuid4()), "title": "seed",
                                                 "done": False}])
                    if method == "POST":
                        doc = json.loads(body or "{}")
                        tid = str(uuid.uuid4())
                        task = {"id": tid, "project_id": int(parts[2]), "done": False,
                                "created_by": "system", **doc}
                        app.tasks[tid] = task
                        return self._send(201, task)
                if parts[:2] == ["api", "tasks"] and len(parts) == 3 and method == "PUT":
                    task = app.tasks.get(parts[2])
                    if task is None:
                        return self._send(404, {"error": "no such task"})
                    task.update(json.loads(body or "{}"))
                    return self._send(200, task)
                if path == "/api/hooks/notify" and method == "POST":
                    return self._send(202, {"queued": True})
                if path == "/api/account/remove":
                    return self._send(200, {"removed": True})
                if method == "GET" and not path.startswith("/api/"):
                    return self._send(200, SHELL, "text/html; charset=utf-8")  # catch-all
                return self._send(404, {"error": "not found"})

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

            def do_PUT(self):
                self._route("PUT")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "DiscoApp":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()

    def paths(self, method: str | None = None) -> list[str]:
        return [p.split("?", 1)[0] for m, p, _h, _b in self.hits if method in (None, m)]
