"""Reflected-XSS confirmation is structural (BUG-0083, FR-FUZZ-15, PA-0084).

A break-out fragment appearing "unescaped" somewhere used to confirm: `javascript:TOK`
mid-URL in an html-escaped href, and `';TOK;//` inside a json_encode'd (double-quoted)
JS string, were both false findings. The fixtures below render the lab generator's own
four XSS sinks (`fuzzlab/labgen/modules/sinks/*_echo.php.j2`), each vulnerable and as its
context-correct secure twin, so a regression either way fails here.
"""

from __future__ import annotations

import ast
import html
import json
from pathlib import Path

import pytest

from fuzzlab.oracle.context import UNSURE, js_states, js_token_in_code
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import ReflectedXssStrategy


def _js_string_escape(v: str) -> str:
    return (v.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
            .replace("<", "\\x3c").replace("\n", "\\n"))


# (sink, transform, page builder, vulnerable?)
SINKS = {
    "html_body_echo": lambda v: f'<div class="c">{v}</div>',
    "html_attribute_quoted_echo":
        lambda v: f'<form method="get" action=""><input type="text" name="q" value="{v}">'
                  f'</form>',
    "html_attribute_unquoted_echo": lambda v: f'<div class="c" data-q={v}></div>',
    "html_js_url_echo": lambda v: f'<a class="c" href="javascript:{v}">continue</a>',
}
CASES = [
    ("html_body_echo", lambda v: v, True),
    ("html_body_echo", html.escape, False),
    ("html_attribute_quoted_echo", lambda v: v, True),
    ("html_attribute_quoted_echo", html.escape, False),
    ("html_attribute_unquoted_echo", lambda v: v, True),
    # escaping-context mismatch: entities do not stop whitespace in an unquoted value
    ("html_attribute_unquoted_echo", html.escape, True),
    ("html_js_url_echo", lambda v: v, True),
    ("html_js_url_echo", html.escape, True),     # entities decode before the JS runs
]


class _Page:
    def __init__(self, render):
        self.render, self.sent = render, []

    def send(self, url, param, value, timing=False, **kw):
        self.sent.append(value)
        return Probe(200, f"<html><body>{self.render(value)}</body></html>")


def _confirm(render):
    page = _Page(render)
    v = ReflectedXssStrategy().confirm(
        Candidate("http://127.0.0.1/s", "q", category="xss"), page)
    return v, page


@pytest.mark.parametrize("sink,transform,vulnerable", CASES)
def test_the_lab_sinks(sink, transform, vulnerable):
    v, page = _confirm(lambda val: SINKS[sink](transform(val)))
    assert (v is not None) is vulnerable
    assert len(page.sent) <= 4                       # the typing probe + at most 3 tries


@pytest.mark.parametrize("render", [
    # the context-correct secure twins the templates' own comments name
    lambda v: f'<div class="c" data-q="{html.escape(v)}"></div>',          # quoted
    lambda v: f"<a href=\"javascript:go('{html.escape(_js_string_escape(v))}')\">x</a>",
])
def test_the_secure_twins_never_confirm(render):
    assert _confirm(render)[0] is None


@pytest.mark.parametrize("name,render", [
    ("review repro: escaped value mid-URL",
     lambda v: f'<a href="/search?q={html.escape(v)}&page=2">next</a>'),
    ("review repro: json_encode in a script",
     lambda v: f"<script>var q = {json.dumps(v)};</script>"),
    ("single-quoted attribute, quotes escaped",
     lambda v: f"<input value='{html.escape(v)}'>"),
    ("textarea (RCDATA), escaped", lambda v: f"<textarea>{html.escape(v)}</textarea>"),
    ("title (RCDATA), escaped", lambda v: f"<title>{html.escape(v)}</title>"),
    ("template content is inert", lambda v: f"<template>{v.replace('</', '')}</template>"),
    ("JS comment", lambda v: f"<script>// {v.replace(chr(10), ' ')}\nvar a=1;</script>"),
    ("image src never runs javascript:", lambda v: f'<img src="{html.escape(v)}">'),
])
def test_non_exploitable_reflections_never_confirm(name, render):
    assert _confirm(render)[0] is None, name


@pytest.mark.parametrize("name,render,breakout", [
    ("JS single-quoted string", lambda v: f"<script>var q = '{v}';</script>", "js"),
    ("JS double-quoted string", lambda v: f'<script>var q = "{v}";</script>', "js"),
    ("JS template literal", lambda v: f"<script>var q = `{v}`;</script>", "js"),
    ("JS code position", lambda v: f"<script>var q = {v};</script>", "js"),
    ("single-quoted attribute, raw", lambda v: f"<input value='{v}'>", "attribute-injection"),
    ("href value at the scheme position", lambda v: f'<a href="{v}">x</a>', "url-scheme"),
    ("textarea, raw: closing tag breaks out", lambda v: f"<textarea>{v}</textarea>",
     "element"),
])
def test_exploitable_reflections_confirm(name, render, breakout):
    v, _ = _confirm(render)
    assert v is not None and v.evidence["breakout"] == breakout, name


def test_the_lexer_fails_closed():
    assert js_states("var a = 'open") == [UNSURE] * len("var a = 'open")
    assert js_states("var r = /open") == [UNSURE] * len("var r = /open")
    assert not js_token_in_code("var a = 'TOK", "TOK")
    assert not js_token_in_code("var a = 'open\nTOK;", "TOK")      # string open at EOL
    assert js_token_in_code("var r = /a'b/; TOK;", "TOK")          # quote inside a regex
    assert js_token_in_code("var d = a / 2; TOK;", "TOK")          # division, not regex
    assert not js_token_in_code("var s = \"it's TOK\";", "TOK")


def test_no_strategy_reads_the_declared_sink_context():
    """Item 11 (BUG-0083): `_candidate_of` omits `sink_context` deliberately, which is
    sound only while no confirmation strategy reads it."""
    src = (Path(__file__).resolve().parent.parent / "fuzzlab" / "oracle"
           / "strategies.py").read_text(encoding="utf-8")
    assert sink_context_reads(src) == []


def sink_context_reads(source: str) -> list[int]:
    return [n.lineno for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.Attribute) and n.attr == "sink_context"]


def test_the_guard_catches_an_offender():
    offender = ("class S:\n    def confirm(self, candidate, sender):\n"
                "        return candidate.sink_context or 'html'\n")
    assert sink_context_reads(offender) == [3]
