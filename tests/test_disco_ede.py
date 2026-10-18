"""`fuzzlab disco ede` (FR-CRAWL-25): excessive data exposure by response mutation,
after EDEFuzz. Pure cases first, then a real browser against a local app whose page
shows some of its API answer's fields and not others."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.disco import ede
from fuzzlab.disco.capture import append_record, make_record, read_capture


# --- pure -----------------------------------------------------------------------------
def test_fields_are_named_by_shape_once():
    body = {"name": "a", "items": [{"id": 1, "t": "x"}, {"id": 2, "t": "y", "extra": 1}],
            "tags": ["p", "q"], "nested": {"deep": {"k": True}}}
    assert ede.field_paths(body) == [("name",), ("items", "*", "id"), ("items", "*", "t"),
                                     ("items", "*", "extra"), ("tags", "*"),
                                     ("nested", "deep", "k")]
    assert ede.path_text(("items", "*", "id")) == "$.items[*].id"


def test_a_field_is_removed_everywhere_it_occurs_and_nothing_else():
    body = {"a": 1, "items": [{"id": 1, "t": "x"}, {"id": 2}], "tags": ["p"]}
    assert ede.without(body, ("items", "*", "id")) == {"a": 1, "items": [{"t": "x"}, {}],
                                                       "tags": ["p"]}
    assert ede.without(body, ("a",)) == {"items": body["items"], "tags": ["p"]}
    assert ede.without(body, ("tags", "*")) == {"a": 1, "items": body["items"], "tags": []}
    assert ede.without(body, ("missing",)) == body
    assert body["items"][0] == {"id": 1, "t": "x"}                 # never mutated in place


def test_value_types_never_carry_the_value():
    body = {"items": [{"id": 3, "secret": "s3cr3t"}], "ok": True, "n": None}
    assert ede.value_type(body, ("items", "*", "id")) == "number"
    assert ede.value_type(body, ("items", "*", "secret")) == "string"
    assert ede.value_type(body, ("ok",)) == "boolean"
    assert ede.value_type(body, ("n",)) == "null"


def test_baseline_noise_is_ignored_and_a_varying_structure_is_refused():
    a = ["0|BODY||", "1|P||12:00:01|", "1|P||Ada|"]
    b = ["0|BODY||", "1|P||12:00:02|", "1|P||Ada|"]
    assert ede.noise_mask([a, b, a]) == {1}
    assert ede.same_page(a, ["0|BODY||", "1|P||12:00:09|", "1|P||Ada|"], {1})
    assert not ede.same_page(a, ["0|BODY||", "1|P||12:00:09|", "1|P|||"], {1})
    assert ede.noise_mask([a, a + ["1|P||x|"]]) is None
    assert ede.noise_mask([a, ["0|BODY||", "1|DIV||12:00:01|", "1|P||Ada|"]]) is None


def _rec(method, path, *, status=200, ctype="application/json", body="{}", **kw):
    return make_record(kind="http", t=1.0, action_id="nav-1", method=method,
                       url=BASE + path, req_headers={}, req_body=None, status=status,
                       res_headers={"Content-Type": ctype}, res_body=body.encode(), **kw)


BASE = "http://127.0.0.1:9"


def test_only_whole_2xx_json_get_answers_are_replayed():
    from fuzzlab.disco.capture import MAX_BODY_CHARS
    recs = [_rec("GET", "/api/a", body='{"x":1}'),
            _rec("POST", "/api/b", body='{"x":1}'),
            _rec("GET", "/api/c", status=404, body='{"x":1}'),
            _rec("GET", "/c.css", ctype="text/css", body="p{}"),
            _rec("GET", "/api/big", body=json.dumps({"x": "y" * (MAX_BODY_CHARS + 5)}))]
    assert list(ede.replayable(recs)) == [("GET", BASE + "/api/a")]


def test_a_live_url_matches_its_redacted_capture():
    rec = _rec("GET", "/api/me?token=abc123secret&page=2")
    assert "abc123secret" not in rec.url                           # the capture redacts
    key = ede.replay_key("get", BASE + "/api/me?token=abc123secret&page=2#frag")
    assert key in ede.replayable([rec])


# --- real browser ---------------------------------------------------------------------
_PAGE = """<!doctype html><html><body><h1 id=name></h1><p id=email></p><ul id=items></ul>
<p id=clock></p><script>
document.getElementById('clock').textContent = String(Date.now() + Math.random());
fetch('/api/user').then(r => r.json()).then(u => {
  document.getElementById('name').textContent = u.name;
  document.getElementById('email').textContent = u.email;
  for (const it of u.items) {
    const li = document.createElement('li'); li.textContent = it.title;
    document.getElementById('items').appendChild(li);
  }
});
</script></body></html>"""
_NOISY = """<!doctype html><html><body><script>
const n = 1 + Math.floor(Math.random() * 1000);
for (let i = 0; i < n; i++) document.body.appendChild(document.createElement('p'));
fetch('/api/user');
</script></body></html>"""
_USER = {"name": "Ada", "email": "ada@example.test", "passwordHash": "x" * 20,
         "role": "admin", "items": [{"id": 1, "title": "First", "internal": "k1"},
                                     {"id": 2, "title": "Second", "internal": "k2"}]}


class _App:
    def __init__(self):
        self.hits: list[str] = []
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                app.hits.append(self.path)
                body, ctype = {"/": (_PAGE, "text/html"), "/noisy": (_NOISY, "text/html"),
                               "/api/user": (json.dumps(_USER), "application/json")
                               }.get(self.path, ("no", "text/plain"))
                data = body.encode()
                self.send_response(200 if body != "no" else 404)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def app_run(tmp_path, monkeypatch):
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    app = _App()
    run = tmp_path / "run"
    run.mkdir()
    for path, ctype, body in (("/", "text/html", _PAGE), ("/noisy", "text/html", _NOISY),
                              ("/api/user", "application/json", json.dumps(_USER))):
        append_record(run / "capture.jsonl", make_record(
            kind="http", t=1.0, action_id="nav-1", method="GET", url=app.url + path,
            req_headers={}, req_body=None, status=200,
            res_headers={"Content-Type": ctype}, res_body=body.encode()))
    try:
        yield app, run
    finally:
        app.close()


def test_fields_the_page_never_shows_are_reported_and_the_api_is_never_called(app_run):
    app, run = app_run
    records = read_capture(run / "capture.jsonl").records
    report = ede.EdeRunner(records, scope_urls=[app.url]).run()
    unused = {f["field"] for f in report.findings if f["page"] == app.url + "/"}
    assert unused == {"$.passwordHash", "$.role", "$.items[*].id", "$.items[*].internal"}
    hashed = next(f for f in report.findings if f["field"] == "$.passwordHash")
    assert hashed["sensitive_name"] is True and hashed["type"] == "string"
    assert "x" * 20 not in json.dumps(report.findings)                 # never a value
    assert report.pages_skipped_nondeterministic == 1                   # /noisy
    assert report.fields_tested == 7
    assert "/api/user" not in app.hits                                  # replayed only
    assert app.hits.count("/") == ede.BASELINE_LOADS + 7


def test_the_cli_refuses_without_authorized_and_plans_on_dry_run(app_run, capsys):
    from fuzzlab.disco import cli
    app, run = app_run
    assert cli.main(["ede", "--run", str(run), "--scope", app.url]) == 2
    assert "--authorized" in capsys.readouterr().err
    assert cli.main(["ede", "--run", str(run), "--scope", app.url, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "pages: 2" in out and "replayable answers: 1" in out
    assert app.hits == [] and not (run / "ede.json").exists()


def test_the_cli_writes_the_report(app_run, capsys):
    from fuzzlab.disco import cli
    app, run = app_run
    assert cli.main(["ede", "--run", str(run), "--scope", app.url, "--authorized"]) == 0
    doc = json.loads((run / "ede.json").read_text())
    assert doc["fields_unused"] == 4 and "4 unused at load" in capsys.readouterr().out
    assert cli.main(["ede", "--run", str(run), "--scope", app.url, "--authorized"]) == 2
