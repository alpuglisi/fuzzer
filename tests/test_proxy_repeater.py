"""Engine-level Repeater tests: byte-exact replay (R3 gap confirmation).

docs/UI_REVAMP_PLAN.md's Phase 2 named "replay must use live in-memory bytes, not
stored history" as one of two engineering gaps to close honestly. `Repeater.send`
already forwards the tab's saved/edited raw bytes verbatim (no reserialization through
`h11`/the parsed path) -- these tests confirm that byte-exactness directly at the
engine level, the same way `test_proxy_response_intercept.py` confirmed the other named
gap (the response-intercept hook). A reserializing implementation would normalize or
drop a duplicate `Content-Length` header; this proves fuzzlab's Repeater does not.
"""

from __future__ import annotations

from fuzzlab.core.store import Store
from fuzzlab.proxy.history import HistoryWriter
from fuzzlab.proxy.repeater import Repeater


def _store(path):
    return Store(path)


def test_send_forwards_saved_bytes_verbatim(tmp_path):
    """No edit given: the exact bytes stored in the tab go on the wire."""
    seen = {}

    def sender(host, port, tls, raw):
        seen["raw"] = raw
        return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    with _store(tmp_path / "r.db") as store:
        run_id = store.start_run("repeater", "127.0.0.1")
        rep = Repeater(store, run_id, sender)
        # A duplicate, *conflicting* Content-Length: a re-serializing replay path
        # (parse -> normalize -> re-emit) would collapse or reorder this; the raw path
        # must not.
        raw = (b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n"
               b"Content-Length: 5\r\n\r\nhello")
        tab = rep.create_tab("dup-cl", "127.0.0.1", 80, raw)
        rep.send(tab.id)
        assert seen["raw"] == raw, "replay must send the exact stored bytes, unmodified"


def test_send_with_edit_forwards_exact_edited_bytes_and_persists_them(tmp_path):
    """An edited replay sends exactly the edited bytes (not a merge/reparse of them
    with the previous saved request), and the tab is updated to the new bytes so a
    second, unedited send repeats the edit -- not the original."""
    sent = []

    def sender(host, port, tls, raw):
        sent.append(raw)
        return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    with _store(tmp_path / "r.db") as store:
        run_id = store.start_run("repeater", "127.0.0.1")
        rep = Repeater(store, run_id, sender)
        original = b"GET /orig HTTP/1.1\r\nHost: h\r\n\r\n"
        tab = rep.create_tab("t", "127.0.0.1", 80, original)

        edited = b"GET /edited HTTP/1.1\r\nHost: h\r\nX-Weird:  no-strip-here\r\n\r\n"
        rep.send(tab.id, edited)
        assert sent[-1] == edited

        # unedited resend now replays the *edited* bytes, byte-for-byte
        rep.send(tab.id)
        assert sent[-1] == edited
        assert rep.get_tab(tab.id).raw_request == edited


def test_send_records_history_with_the_same_bytes_that_went_on_the_wire(tmp_path):
    """When a HistoryWriter is attached, the recorded request is the same raw bytes
    that were actually sent -- not a reconstruction from parsed fields."""
    def sender(host, port, tls, raw):
        return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    with _store(tmp_path / "r.db") as store:
        run_id = store.start_run("repeater", "127.0.0.1")
        history = HistoryWriter(store, run_id, batch_size=1)
        rep = Repeater(store, run_id, sender, history=history)
        raw = b"GET /a?x=1&x=1 HTTP/1.1\r\nHost: h\r\n\r\n"  # a duplicated query param
        tab = rep.create_tab("t", "127.0.0.1", 80, raw)
        rep.send(tab.id)
        row = store.conn.execute(
            "SELECT req_raw_sha FROM flow ORDER BY id DESC LIMIT 1").fetchone()
        assert store.get_body(row["req_raw_sha"]) == raw


def test_send_unknown_tab_raises_keyerror(tmp_path):
    with _store(tmp_path / "r.db") as store:
        run_id = store.start_run("repeater", "127.0.0.1")
        rep = Repeater(store, run_id, sender=lambda *a: b"")
        try:
            rep.send(99999)
        except KeyError:
            pass
        else:
            raise AssertionError("expected KeyError for an unknown tab id")
