"""A disco run consolidates into the store as a crawl does (D70, FR-AUD-23), so
`fuzzlab auto --disco-run DIR` confirms what the explorer found.

Synthetic run directories in the exact formats disco writes (`disco.capture.
make_record` / `append_record`, the explorer's ``actions.jsonl`` lines), imported by
`store_adapter.import_disco`, then turned into points by `harness.auto`. No browser."""

from __future__ import annotations

import json

import pytest

from fuzzlab.core.store import Store
from fuzzlab.disco.capture import append_record, make_record
from fuzzlab.tools import store_adapter

BASE = "http://127.0.0.1:3000"


def _rec(method, path, *, body=None, ctype=None, status=200, res_ctype="application/json",
         kind="http", action_id="act-1", **extra):
    headers = {"Content-Type": ctype} if ctype else {}
    return make_record(kind=kind, t=1.0, action_id=action_id, method=method,
                       url=BASE + path, req_headers=headers,
                       req_body=body.encode() if isinstance(body, str) else body,
                       status=status, res_headers={"Content-Type": res_ctype},
                       res_body=b"{}", **extra)


def _run_dir(tmp_path, records, actions=(), forms=()):
    """``actions``: page URLs (click steps); ``forms``: ``(seq, [[name, type]])`` form
    steps, as the explorer logs them."""
    run = tmp_path / "run"
    run.mkdir()
    for rec in records:
        append_record(run / "capture.jsonl", rec)
    with open(run / "actions.jsonl", "w", encoding="utf-8") as fh:
        for url in actions:
            fh.write(json.dumps({"seq": 1, "kind": "click", "url": url}) + "\n")
        for seq, fields in forms:
            fh.write(json.dumps({"seq": seq, "kind": "submit", "url": None,
                                 "fields": fields}) + "\n")
        fh.write("not json\n")
    return run


def _params(store, run_id):
    return {(r[0], r[1], r[2], r[3]) for r in store.conn.execute(
        "SELECT e.method, e.url, p.name, p.location FROM parameter p "
        "JOIN endpoint e ON p.endpoint_id = e.id WHERE p.run_id = ?", (run_id,))}


@pytest.fixture
def imported(tmp_path):
    records = [
        _rec("GET", "/", res_ctype="text/html; charset=utf-8"),
        _rec("GET", "/main.js", res_ctype="application/javascript"),        # an asset
        _rec("GET", "/rest/products/search?q=disco"),
        _rec("POST", "/api/Feedbacks/", ctype="application/json",
             body=json.dumps({"comment": "Hello from disco", "rating": 2,
                              "captcha": "1", "captchaId": 4})),
        _rec("POST", "/profile", ctype="application/x-www-form-urlencoded",
             body="username=disco_user1&userId=7", action_id="act-9"),
        _rec("POST", "/rest/user/login", ctype="application/json",
             body=json.dumps({"email": "a@b.co", "password": "x"})),
        _rec("PUT", "/api/Users/1", ctype="application/json",
             body=json.dumps({"email": "a@b.co"})),
        _rec("DELETE", "/api/Feedbacks/1"),
        _rec("POST", "/api/Products", ctype="multipart/form-data; boundary=x", body="--x--"),
        _rec("POST", "/api/none", ctype="application/json", body="{}", status=None,
             error="ConnectionRefused"),
        _rec("GET", "/socket.io/", kind="ws", ws_direction="client", res_ctype=None),
    ]
    run = _run_dir(tmp_path, records, actions=[
        BASE + "/#/search?q=disco", BASE + "/#/track-result?id=5", BASE + "/#/about", None],
        forms=[(9, [["username", "text"], ["userId", "hidden"]])])
    store = Store(tmp_path / "u.db")
    run_id = store.start_run("disco-import", "hash")
    counts = store_adapter.import_disco(run, store, run_id)
    yield store, run_id, counts, run
    store.close()


def test_query_body_and_fragment_points_come_from_a_disco_run(imported):
    store, run_id, counts, _run = imported
    params = _params(store, run_id)
    assert ("GET", "/rest/products/search", "q", "query") in params
    assert ("POST", "/api/Feedbacks/", "comment", "json") in params
    assert ("POST", "/profile", "username", "body") in params
    assert ("GET", "/#/search", "q", "fragment") in params
    assert ("GET", "/#/track-result", "id", "fragment") in params
    pages = {r[0] for r in store.conn.execute(
        "SELECT url FROM page WHERE run_id = ? AND source = 'disco'", (run_id,))}
    assert "/" in pages and "/main.js" not in pages
    assert counts["quarantined"] == 1                 # the malformed actions line


def test_an_object_selector_is_a_point_only_where_the_explorer_saw_it(imported, tmp_path):
    """A visible ``username`` input (the explorer's form step listed it) is a point, as
    a crawled form's visible field is; the hidden ``userId`` stays pinned; without the
    explorer's field list, a captured request's object selector is pinned (FR-AUD-22)."""
    store, run_id, _counts, _run = imported
    params = _params(store, run_id)
    assert ("POST", "/profile", "username", "body") in params
    assert not any(p[2] == "userId" for p in params)
    other = tmp_path / "other"
    other.mkdir()
    run = _run_dir(other, [_rec("POST", "/profile",
                                ctype="application/x-www-form-urlencoded",
                                body="username=disco_user1", action_id="act-3")])
    with Store(other / "u.db") as s2:
        rid = s2.start_run("unseen", "hash")
        store_adapter.import_disco(run, s2, rid)
        assert not any(p[2] == "username" for p in _params(s2, rid))


def test_the_captured_request_gates_apply_to_a_disco_run(imported):
    """FR-AUD-22's refusals, unchanged: DELETE, PUT without --fuzz-json-writes, an
    unsupported body; a password leaf is never a point."""
    store, run_id, counts, _run = imported
    params = _params(store, run_id)
    assert not any(p[1] == "/api/Users/1" for p in params)
    assert not any(p[1] == "/api/Products" for p in params)
    assert not any(p[2] == "password" for p in params)
    assert counts["request"] == 6                     # the ws and the no-answer skipped
    assert counts["request_refused"] >= 3


def test_put_is_imported_only_with_json_writes(tmp_path):
    run = _run_dir(tmp_path, [_rec("PUT", "/api/Users/1", ctype="application/json",
                                   body=json.dumps({"email": "a@b.co"}))])
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("w", "hash")
        store_adapter.import_disco(run, store, run_id, fuzz_json_writes=True)
        assert ("PUT", "/api/Users/1", "email", "json") in _params(store, run_id)


def test_a_truncated_body_is_refused(tmp_path):
    from fuzzlab.disco.capture import MAX_BODY_CHARS
    big = json.dumps({"comment": "x" * (MAX_BODY_CHARS + 10)})
    run = _run_dir(tmp_path, [_rec("POST", "/api/Feedbacks/", ctype="application/json",
                                   body=big)])
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("t", "hash")
        counts = store_adapter.import_disco(run, store, run_id)
        assert counts["request_refused"] == 1 and not _params(store, run_id)


def test_auto_builds_crawl_points_from_the_imported_run(imported):
    """The harness's own point builder reads them: what `fuzzlab auto --disco-run`
    fuzzes and confirms."""
    from fuzzlab.harness.auto import injection_points_from_store
    store, run_id, _counts, _run = imported
    skipped: list = []
    points = injection_points_from_store(store, run_id, BASE + "/", skipped=skipped,
                                         browser_available=True)
    got = {(p.method, p.url, p.param, p.location) for p in points}
    assert ("GET", BASE + "/rest/products/search", "q", "query") in got
    assert ("POST", BASE + "/api/Feedbacks/", "comment", "json") in got
    assert ("GET", BASE + "/#/search", "q", "fragment") in got


def test_auto_refuses_a_disco_run_without_a_capture(tmp_path, capsys):
    from fuzzlab.harness import auto_cli
    with pytest.raises(SystemExit):
        auto_cli.main(["--base-url", BASE, "--store", str(tmp_path / "s.db"),
                       "--disco-run", str(tmp_path), "--categories", "sql-injection",
                       "--authorized"])
    assert "holds no capture.jsonl" in capsys.readouterr().err


def _calls(source: str, func: str) -> set[str]:
    """Names called inside the module-level function ``func`` of ``source``."""
    import ast
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == func)
    return {c.func.id for c in ast.walk(fn)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}


#: SP-37: the one path from a discovered request or URL to store points.
SHARED_PATH = {"import_spider": {"_import_page_url"},
               "_import_requests": {"captured_request", "_store_request"},
               "import_disco": {"_import_page_url", "captured_request", "_store_request"}}


def _offenders(source: str) -> list[str]:
    out = []
    for func, needed in SHARED_PATH.items():
        calls = _calls(source, func)
        out += [f"{func} does not call {n}" for n in sorted(needed - calls)]
        if "INSERT INTO parameter" in source.split(f"def {func}(", 1)[1].split("\ndef ", 1)[0]:
            out.append(f"{func} writes parameter rows itself")
    return out


def test_both_importers_share_the_one_point_path():
    """SP-37 (PA-0003): a spider DB and a disco run reach the store through the same
    functions -- the page/query step, the captured-request decision and its writer --
    and neither importer writes parameter rows itself. Proven on a synthetic
    offender: an import_disco with its own INSERT."""
    from pathlib import Path
    src = (Path(store_adapter.__file__)).read_text()
    assert _offenders(src) == []
    bad = src.replace("def import_disco(", "def import_disco_old(", 1) + '''

def import_disco(run_dir, store, run_id):
    store.conn.execute("INSERT INTO parameter (run_id) VALUES (?)", (run_id,))
'''
    assert "import_disco does not call captured_request" in _offenders(bad)
    assert "import_disco writes parameter rows itself" in _offenders(bad)
