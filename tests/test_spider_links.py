"""The legacy spider follows every URL a response links (CC-CRAWL-0038,
`core.linkextract`): HTML attributes beyond ``<a href>``, a stylesheet's ``url()`` and
``@import``, header targets -- while the scope and destructive-URL gates still refuse
what they refused, and a write target (a form's action, a ping, a script's string
literal: BUG-0503) is never fetched. Static engine, a local server."""

from __future__ import annotations

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fuzzlab.tools import spider as sp

PAGES = {
    "/": ("text/html", '<html><body><img src="/img/a.png"><iframe src="/frame.html">'
                       '</iframe><link rel=stylesheet href="/s.css">'
                       '<script>fetch("/api/after-close", {method: "POST"});</script>'
                       '<form action="/api/send" method="post"><input name=q></form>'
                       '<a href="/a.html" ping="/beacon">a</a>'
                       '<meta http-equiv="refresh" content="9; url=/later.html">'
                       '<a href="/logout">out</a><img src="http://other.test/x.png">'
                       '</body></html>', {"Link": "</preload.js>; rel=preload"}),
    "/s.css": ("text/css", '@import "/more.css"; body{background:url(/bg.gif)}', {}),
    "/more.css": ("text/css", "p{}", {}),
    "/frame.html": ("text/html", "<html><body>frame</body></html>", {}),
}


class _Site:
    def __init__(self):
        self.hits: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                site.hits.append(self.path)
                ctype, body, headers = PAGES.get(self.path, ("text/plain", "ok", {}))
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def test_every_linked_resource_is_followed_and_the_gates_still_refuse(tmp_path):
    site = _Site()
    try:
        db = tmp_path / "s.db"
        sp.LocalSpider(site.url, max_depth=3, db_name=str(db), engine="requests").crawl()
        conn = sqlite3.connect(db)
        visited = {u.split(":", 2)[2].split("/", 1)[1] for (u,) in
                   conn.execute("SELECT url FROM discovered_pages")}
        conn.close()
        for path in ("img/a.png", "frame.html", "s.css", "a.html", "later.html",
                     "preload.js", "more.css", "bg.gif"):
            assert path in visited, (path, sorted(visited))
        assert "/logout" not in site.hits               # destructive: never fetched
        for write in ("/api/after-close", "/api/send", "/beacon"):     # BUG-0503
            assert not any(h.split("?", 1)[0] == write for h in site.hits), write
    finally:
        site.server.shutdown()
        site.server.server_close()
