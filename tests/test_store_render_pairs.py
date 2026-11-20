"""Store -> render pairs from a disco capture (FR-CRAWL-672, FR-AUD-691, FR-FUZZ-691).

A write whose stored value a later page shows becomes a stored-XSS point at that page,
its store step the write itself. Synthetic captures of an invented app (a guestbook);
nothing names a lab."""

from __future__ import annotations

import json

from fuzzlab.core.store import Store
from fuzzlab.disco.capture import append_record, make_record
from fuzzlab.disco.storerender import MIN_VALUE_CHARS, store_render_pairs
from fuzzlab.harness.auto import STORED_DECIDER, injection_points_from_store
from fuzzlab.tools import store_adapter

BASE = "http://127.0.0.1:3000"
VALUE = "Greetings traveller"


def _rec(method, path, *, body=None, ctype=None, res=b"{}", res_ctype="application/json",
         referer=None, status=200, t=1.0):
    headers = {"Content-Type": ctype} if ctype else {}
    if referer:
        headers["Referer"] = BASE + referer
    return make_record(kind="http", t=t, action_id="a1", method=method, url=BASE + path,
                       req_headers=headers,
                       req_body=body.encode() if isinstance(body, str) else body,
                       status=status, res_headers={"Content-Type": res_ctype},
                       res_body=res)


def _write(value=VALUE, path="/api/entries"):
    return _rec("POST", path, ctype="application/json",
                body=json.dumps({"entry": {"text": value, "mood": 1}}),
                res=json.dumps({"ok": True, "text": value}).encode(), referer="/sign")


def _html_render(value=VALUE, path="/book"):
    return _rec("GET", path, res=f"<ul><li>{value}</li></ul>".encode(),
                res_ctype="text/html")


def _xhr_render(value=VALUE):
    return _rec("GET", "/api/entries", res=json.dumps([{"text": value}]).encode(),
                referer="/wall")


def test_a_later_html_page_showing_the_written_value_pairs_with_the_write():
    pairs = store_render_pairs([_rec("GET", "/sign", res=b"<form></form>",
                                     res_ctype="text/html"), _write(), _html_render()])
    assert [(p.write_index, p.param, p.render_url) for p in pairs] == \
        [(1, "entry.text", BASE + "/book")]


def test_a_fetch_showing_the_value_pairs_with_the_page_that_fetched_it():
    pairs = store_render_pairs([_write(), _xhr_render()])
    assert [p.render_url for p in pairs] == [BASE + "/wall"]


def test_the_writes_own_response_is_no_render():
    assert store_render_pairs([_write()]) == []


def test_a_value_shown_before_any_write_is_no_evidence():
    assert store_render_pairs([_html_render(), _write(), _html_render(path="/x")]) == []


def test_another_write_echoing_the_same_value_is_no_render():
    assert store_render_pairs([_write(), _write(path="/api/other")]) == []


def test_short_or_letterless_values_are_never_tracked():
    for value in ("a" * (MIN_VALUE_CHARS - 1), "1234567890"):
        assert store_render_pairs([_write(value), _html_render(value)]) == []


def test_a_cross_origin_referer_is_no_render_page():
    rec = _rec("GET", "/api/entries", res=json.dumps([VALUE]).encode())
    rec = rec.__class__(**{**rec.__dict__,
                           "req_headers": {"Referer": "http://other.invalid/wall"}})
    assert store_render_pairs([_write(), rec]) == []


def test_failed_writes_and_failed_renders_count_for_nothing():
    assert store_render_pairs([_write().__class__(**{**_write().__dict__, "status": 500}),
                               _html_render()]) == []
    bad = _html_render()
    assert store_render_pairs([_write(), bad.__class__(**{**bad.__dict__,
                                                          "status": 404})]) == []


def test_hostile_records_never_raise():
    junk = _rec("POST", "/api", ctype="application/json", body="{not json")
    surrogate = _rec("POST", "/api", ctype="application/json", body='{"a": "\\ud800abcdef"}')
    assert store_render_pairs([junk, surrogate, _rec("GET", "/", res=None)]) == []


def _imported(tmp_path, records):
    run = tmp_path / "run"
    run.mkdir()
    for rec in records:
        append_record(run / "capture.jsonl", rec)
    (run / "actions.jsonl").write_text("", encoding="utf-8")
    st = Store(tmp_path / "s.db")
    run_id = st.start_run("auto", "localhost")
    counts = store_adapter.import_disco(run, st, run_id, base_url=BASE)
    return st, run_id, counts


def test_import_makes_a_stored_point_whose_store_step_is_the_write(tmp_path):
    st, run_id, counts = _imported(tmp_path, [_write(), _html_render()])
    with st:
        assert counts["store_render"] == 1
        skipped: list = []
        points = injection_points_from_store(st, run_id, BASE, skipped=skipped,
                                             browser_available=True)
        stored = [p for p in points if p.store_url]
        assert len(stored) == 1
        p = stored[0]
        assert (p.url, p.method, p.param) == (BASE + "/book", "GET", "entry.text")
        assert (p.store_url, p.store_method, p.store_location) == \
            (BASE + "/api/entries", "POST", "json")
        assert dict((tuple(n), v) for n, v in p.store_entries)[("entry", "mood")] == 1
        assert p.decided_by == STORED_DECIDER and p.origin == "crawl"
        # without a browser the point is reported, never built
        skipped = []
        none = injection_points_from_store(st, run_id, BASE, skipped=skipped)
        assert not [q for q in none if q.store_url]
        assert any("stored XSS" in why for *_x, why in skipped)


def test_a_pinned_leaf_never_becomes_a_stored_point(tmp_path):
    write = _rec("POST", "/api/entries", ctype="application/json",
                 body=json.dumps({"password": VALUE, "note": "x"}), referer="/sign")
    st, run_id, counts = _imported(tmp_path, [write, _html_render()])
    with st:
        # the capture blanks a password when it is written, so no pair forms at all;
        # never a stored point either way
        assert counts["store_render"] == 0
        points = injection_points_from_store(st, run_id, BASE, browser_available=True)
        assert not [p for p in points if p.store_url]
