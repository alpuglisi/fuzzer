"""Phase 6 T6.3: migration 6 (flow raw bytes + FTS5 + repeater_tab) and history."""

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.redact import redact

REQ = (b"GET /product.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
       b"Cookie: PHPSESSID=supersecretvalue\r\n\r\n")
RESP = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Puppy</h1>"


def _writer(tmp_path, batch_size=50):
    store = Store(tmp_path / "u.db")
    run_id = store.start_run("proxy", "127.0.0.1:8080")
    return store, HistoryWriter(store, run_id, batch_size=batch_size)


def test_migration_6_schema(tmp_path):
    with Store(tmp_path / "u.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 6
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(flow)")}
        assert {"host", "in_scope", "req_raw_sha", "resp_raw_sha"} <= cols
        # flow_fts virtual table and repeater_tab exist
        names = {r["name"] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
        assert "flow_fts" in names and "repeater_tab" in names


def test_batching_defers_then_flushes(tmp_path):
    store, w = _writer(tmp_path, batch_size=3)
    for _ in range(2):
        w.record(FlowRecord("GET", "http://h/a", "h", raw_request=b"GET /a HTTP/1.1\r\n\r\n"))
    # under the batch size → nothing written yet
    assert store.conn.execute("SELECT COUNT(*) c FROM flow").fetchone()["c"] == 0
    w.record(FlowRecord("GET", "http://h/a", "h", raw_request=b"GET /a HTTP/1.1\r\n\r\n"))
    # third record hits batch_size → auto-flush
    assert store.conn.execute("SELECT COUNT(*) c FROM flow").fetchone()["c"] == 3
    store.close()


def test_raw_bytes_are_byte_exact_when_no_secrets(tmp_path):
    store, w = _writer(tmp_path)
    w.record(FlowRecord("GET", "http://127.0.0.1:8080/product.php?id=1",
                        "127.0.0.1:8080", status=200,
                        raw_request=b"GET /product.php?id=1 HTTP/1.1\r\nHost: x\r\n\r\n",
                        raw_response=RESP))
    w.flush()
    fid = store.conn.execute("SELECT id FROM flow").fetchone()["id"]
    assert w.raw_request(fid) == b"GET /product.php?id=1 HTTP/1.1\r\nHost: x\r\n\r\n"
    assert w.raw_response(fid) == RESP
    store.close()


def test_secrets_redacted_on_write(tmp_path):
    store, w = _writer(tmp_path)
    w.record(FlowRecord("GET", "http://127.0.0.1:8080/product.php?id=1",
                        "127.0.0.1:8080", raw_request=REQ))
    w.flush()
    fid = store.conn.execute("SELECT id FROM flow").fetchone()["id"]
    stored = w.raw_request(fid)
    assert b"supersecretvalue" not in stored
    assert b"__REDACTED__" in stored
    # and the secret is not searchable in the FTS index either
    assert w.search("supersecretvalue") == []
    store.close()


def test_fts_search_by_url_and_host_and_header(tmp_path):
    store, w = _writer(tmp_path)
    w.record(FlowRecord("GET", "http://127.0.0.1:8080/product.php?id=1",
                        "127.0.0.1:8080", raw_request=REQ, raw_response=RESP))
    w.record(FlowRecord("POST", "http://127.0.0.1:8080/login.php",
                        "127.0.0.1:8080", raw_request=b"POST /login.php HTTP/1.1\r\n\r\n"))
    hits = w.search("product.php")
    assert len(hits) == 1 and hits[0]["method"] == "GET"
    assert len(w.search("login.php")) == 1
    assert len(w.search("127.0.0.1")) == 2         # host indexed on both
    store.close()


def test_raw_bytes_are_content_addressed_deduped(tmp_path):
    store, w = _writer(tmp_path)
    raw = b"GET /same HTTP/1.1\r\nHost: h\r\n\r\n"
    w.record(FlowRecord("GET", "http://h/same", "h", raw_request=raw))
    w.record(FlowRecord("GET", "http://h/same", "h", raw_request=raw))
    w.flush()
    # two flows, but the identical raw request is stored once
    assert store.conn.execute("SELECT COUNT(*) c FROM flow").fetchone()["c"] == 2
    shas = {r["req_raw_sha"] for r in store.conn.execute("SELECT req_raw_sha FROM flow")}
    assert len(shas) == 1
    store.close()


def test_redact_helper_preserves_structure():
    out = redact(REQ)
    assert b"supersecretvalue" not in out
    assert out.startswith(b"GET /product.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8080")
    assert out.endswith(b"\r\n\r\n")
