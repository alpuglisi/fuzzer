"""Reflected-XSS confirmation is structural (BUG-0083, FR-FUZZ-39, PA-0084).

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


# --- BUG-0093 / PA-0094: the container's executability is part of the structure -------

def _in_script(open_tag: str, close: str = "</script>", wrap=("", "")):
    return lambda v: f"{wrap[0]}{open_tag}var x='{v}';{close}{wrap[1]}"


INERT_SCRIPTS = {
    # the finding's four shapes
    "json": _in_script('<script type="application/json">'),
    "ld+json": _in_script('<script type="application/ld+json">'),
    "template": _in_script("<script>", wrap=("<template>", "</template>")),
    "external src": _in_script('<script src="/a.js">'),
    # the rest of the spec's non-running scripts
    "empty src": _in_script('<script src="">'),
    "importmap": _in_script('<script type="importmap">'),
    "text/template": _in_script('<script type="text/template">'),
    "text/plain": _in_script('<script type="text/plain">'),
    "type with parameters": _in_script('<script type="text/javascript;charset=utf-8">'),
    "whitespace-only type": _in_script('<script type=" ">'),
    "vbscript language": _in_script('<script language="vbscript">'),
    "nomodule": _in_script("<script nomodule>"),
    "noscript": _in_script("<script>", wrap=("<noscript>", "</noscript>")),
}

EXECUTING_SCRIPTS = {
    "no type": _in_script("<script>"),
    "text/javascript": _in_script('<script type="text/javascript">'),
    "upper-case, padded": _in_script('<script type=" TEXT/JavaScript ">'),
    "module": _in_script('<script type="module">'),
    "empty type": _in_script('<script type="">'),
    "x-ecmascript": _in_script('<script type="application/x-ecmascript">'),
    "language javascript": _in_script('<script language="javascript">'),
    "language JavaScript1.2": _in_script('<script language="JavaScript1.2">'),
    "empty language": _in_script('<script language="">'),
    "nomodule on a module": _in_script('<script type="module" nomodule>'),
}


@pytest.mark.parametrize("name", sorted(INERT_SCRIPTS))
def test_a_reflection_in_a_script_that_never_runs_does_not_confirm(name):
    """The finding: CONFIRMED for JSON, ld+json, template and src scripts. A raw
    reflection there is still tried with the `</script>` break-out, which these pages
    entity-escape `<` for, so nothing confirms."""
    def render(v):
        return INERT_SCRIPTS[name](v.replace("<", "&lt;"))
    v, page = _confirm(render)
    assert v is None, (name, page.sent)


@pytest.mark.parametrize("name", sorted(EXECUTING_SCRIPTS))
def test_a_reflection_in_a_running_script_confirms(name):
    assert _confirm(EXECUTING_SCRIPTS[name])[0] is not None, name


def test_a_data_block_that_reflects_a_raw_close_tag_is_real_xss():
    """`</script>` ends a data block too: a real break-out of a JSON block is XSS."""
    v, page = _confirm(_in_script('<script type="application/json">'))
    assert v is not None and any("</script>" in s for s in page.sent)


def test_an_escaped_close_tag_in_json_does_not_confirm():
    """json_encode's `<\\/script>` keeps the data block closed."""
    v, _ = _confirm(lambda val: '<script type="application/json">{"q":%s}</script>'
                    % json.dumps(val).replace("</", "<\\/"))
    assert v is None


def test_a_break_out_under_template_does_not_confirm():
    """`</script><TOK>` inside a <template> still lands in an inert subtree."""
    v, _ = _confirm(_in_script("<script>", wrap=("<template>", "</template>")))
    assert v is None


def test_a_javascript_url_under_an_inert_ancestor_does_not_confirm():
    v, _ = _confirm(lambda val: f'<template><a href="javascript:{val}">x</a></template>')
    assert v is None


def test_script_executes_is_the_one_predicate():
    from bs4 import BeautifulSoup

    from fuzzlab.oracle.context import script_executes, type_reflection
    for name, render in INERT_SCRIPTS.items():
        tag = BeautifulSoup(render("x"), "html.parser").find("script")
        assert not script_executes(tag), name
        assert type_reflection(render("MARK"), "MARK") != "js", name
    for name, render in EXECUTING_SCRIPTS.items():
        tag = BeautifulSoup(render("x"), "html.parser").find("script")
        assert script_executes(tag), name


# --- BUG-0102 / PA-0103: regex versus division is decided by grammar context --------

@pytest.mark.parametrize("src", [
    "function f(){ return /TOK/; }",             # after a keyword
    "x = typeof /TOK/;",
    "if (x) /TOK/.test(y)",                      # after a statement head's ')'
    "while (a) /TOK/g.exec(s)",
    "switch (v) { case /TOK/: 1 }",
    "export default /TOK/",
    "f(() => /TOK/)",                            # after '=>'
    "x = [/TOK/]",
    "y = /[/]TOK/",                              # a slash inside a character class
    "y = /a\\/TOK/",                             # an escaped slash
])
def test_a_token_inside_a_regex_literal_is_not_code(src):
    assert not js_token_in_code(src, "TOK"), src


@pytest.mark.parametrize("src", [
    "x = a / TOK",                               # after an identifier
    "x = this / TOK",
    "x = f(a) / TOK",                            # after a call's ')'
    "x = arr[0] / TOK",                          # after ']'
    "x = 10 / TOK",                              # after a number
    "x = a\n/TOK/g",                             # JS reads division across the newline
    "x = i++ / TOK",
    "x = 'a' / TOK",
])
def test_a_token_after_a_division_is_code(src):
    assert js_token_in_code(src, "TOK"), src


def test_a_slash_after_a_closing_brace_is_unsure():
    """`}` ends a block or an object literal: the grammar alone cannot decide."""
    assert js_states("if (a) {} /TOK/.test(s)") == [UNSURE] * len(
        "if (a) {} /TOK/.test(s)")
    assert js_token_in_code("var o = {}; TOK", "TOK")       # no '/' after it: fine


def test_the_audits_regex_reflection_never_confirms():
    import re

    def render(v):
        return "<script>function f(){ return /" + re.escape(v).replace("/", r"\/") + \
            "/; }</script>"
    v, page = _confirm(render)
    assert v is None, page.sent
