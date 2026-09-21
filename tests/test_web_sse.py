"""Tests for the SSE helper (`fuzzlab/web/sse.py`)."""

from __future__ import annotations

from fuzzlab.web.sse import format_event


def test_format_event_string_payload():
    assert format_event("hello") == "data: hello\n\n"


def test_format_event_json_payload():
    out = format_event({"a": 1, "b": "x"})
    assert out == 'data: {"a":1,"b":"x"}\n\n'


def test_format_event_with_event_and_id():
    out = format_event("line", event="output", id="7")
    assert out == "id: 7\nevent: output\ndata: line\n\n"


def test_format_event_multiline_splits_each_line():
    out = format_event("one\ntwo\nthree")
    assert out == "data: one\ndata: two\ndata: three\n\n"


def test_format_event_terminates_with_blank_line():
    # every SSE message ends with a blank line so the client dispatches it
    assert format_event("x").endswith("\n\n")
