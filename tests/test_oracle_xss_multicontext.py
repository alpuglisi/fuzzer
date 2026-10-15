"""Reflected XSS is tried in every context a value reflects in (BUG-0154, FR-FUZZ-54,
PA-0160), and an attribute's quote is its own (BUG-0155, PA-0161).

A server-rendered page often shows one value in more than one place: an edit form
shows the stored value escaped in its ``<input value>`` and raw in a paragraph; a
search page echoes the term in its box and in a heading. M5 used to type only the
first reflection (script, then attribute, then text) and try only that context's
break-outs, so the raw place was never tried. Every app here is a synthetic fixture
on a loopback ``ThreadingHTTPServer`` (port 0): no lab's routes, fields or markup.
"""

from __future__ import annotations

import ast
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

import pytest

from fuzzlab.core.store import Store
from fuzzlab.oracle import Oracle
from fuzzlab.oracle import context as ctx
from fuzzlab.oracle import strategies as strat
from fuzzlab.oracle.context import (
    Reflection,
    locate_reflection,
    locate_reflections,
    xss_breakouts,
)
from fuzzlab.oracle.probe import Candidate
from fuzzlab.oracle.strategies import ReflectedXssStrategy
from fuzzlab.tools.probesender import RequestsProbeSender

ROOT = Path(__file__).resolve().parent.parent
esc = html.escape


def _js_json(v: str) -> str:
    """A JSON string literal safe inside a ``<script>`` (``<`` / ``>`` escaped)."""
    return json.dumps(v).replace("<", "\\u003c").replace(">", "\\u003e")


def _js_single(v: str) -> str:
    return (v.replace("\\", "\\\\").replace("'", "\\'").replace("<", "\\x3c")
            .replace("\n", "\\n"))


#: How a page lays out one value. Each is a generic server-rendering shape.
LAYOUTS = {
    # an edit form: the stored value escaped in its control, raw in the read-only view
    "edit-attr-escaped-text-raw":
        lambda v: f'<form method="post"><input name="note" value="{esc(v)}"></form>'
                  f'<p class="note">{v}</p>',
    "edit-text-raw-attr-escaped":            # the same, raw place first in the document
        lambda v: f'<p class="note">{v}</p>'
                  f'<form method="post"><input name="note" value="{esc(v)}"></form>',
    "edit-both-escaped":
        lambda v: f'<form method="post"><input name="note" value="{esc(v)}"></form>'
                  f'<p class="note">{esc(v)}</p>',
    # a search page: the term in its box and in a heading
    "search-box-escaped-heading-raw":
        lambda v: f'<form><input name="term" value="{esc(v)}"></form>'
                  f'<h1>Results for {v}</h1>',
    "script-escaped-text-raw":
        lambda v: f"<script>var note = {_js_json(v)};</script><p>{v}</p>",
    "script-raw-text-escaped":
        lambda v: f"<script>var note = '{v}';</script><p>{esc(v)}</p>",
    "script-escaped-text-escaped":
        lambda v: f"<script>var note = {_js_json(v)};</script><p>{esc(v)}</p>",
    # BUG-0155: a raw value after an '=' inside a quoted attribute (a query link)
    "link-query-raw": lambda v: f'<a href="/find?term={v}&amp;page=2">next</a>',
    "link-query-encoded": lambda v: f'<a href="/find?term={quote(v)}&amp;page=2">next</a>',
    # one value, escaped correctly in many distinct contexts (the cap's fixture)
    "many-escaped":
        lambda v: (f'<input value="{esc(v)}"><input value=\'{esc(v)}\'>'
                   f"<script>var a = {_js_json(v)}; var b = '{_js_single(v)}';"
                   f" var c = `{_js_single(v).replace('`', chr(92) + '`')}`;</script>"
                   f"<textarea>{esc(v)}</textarea><title>{esc(v)}</title>"
                   f"<style>/* {esc(v)} */</style><p>{esc(v)}</p>"),
    "text-raw": lambda v: f"<p>{v}</p>",
}


class NotesSite:
    """``POST /notes/7`` stores ``note`` and answers 303 to ``/notes/7``, which renders
    it with ``layout`` (post/redirect/get); ``GET /find?term=`` renders the term with
    the same layout directly. ``log`` records every request's (method, value)."""

    def __init__(self, layout: str):
        self.layout = LAYOUTS[layout]
        self.value = "first note"
        self.log: list[tuple[str, str]] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _page(self, status, body: str, headers=()):
                data = f"<html><body>{body}</body></html>".encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                data = dict(parse_qsl(raw.decode(), keep_blank_values=True))
                site.log.append(("POST", data.get("note", "")))
                if urlsplit(self.path).path != "/notes/7":
                    return self._page(404, "no")
                site.value = data.get("note", site.value)
                self._page(303, "See Other", headers=[("Location", "/notes/7")])

            def do_GET(self):
                parts = urlsplit(self.path)
                query = dict(parse_qsl(parts.query, keep_blank_values=True))
                site.log.append(("GET", query.get("term", "")))
                if parts.path == "/notes/7":
                    return self._page(200, site.layout(site.value))
                if parts.path == "/find":
                    return self._page(200, site.layout(query.get("term", "")))
                self._page(404, "no")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def probes(self) -> list[str]:
        """The values the strategy sent (its marker and break-outs carry ``zqx``)."""
        return [v for _m, v in self.log if "zqx" in v]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def site():
    made: list[NotesSite] = []

    def make(layout):
        made.append(NotesSite(layout))
        return made[-1]
    yield make
    for s in made:
        s.close()


def _stored(app: NotesSite) -> Candidate:
    return Candidate(url=app.base + "/notes/7", param="note", method="POST",
                     location="body", category="xss")


def _search(app: NotesSite) -> Candidate:
    return Candidate(url=app.base + "/find", param="term", category="xss")


def _confirm_and_record(app, candidate, tmp_path):
    with Store(tmp_path / "f.db") as store:
        run_id = store.start_run("xss-multictx", "h")
        verdict = Oracle(strategies=[ReflectedXssStrategy()], store=store,
                         run_id=run_id).confirm(candidate, RequestsProbeSender())
        rows = [dict(r) for r in store.conn.execute(
            "SELECT vuln_class, confidence, evidence FROM finding WHERE run_id=?",
            (run_id,))]
    return verdict, rows


# --- the defect: an escaped first context hid a raw second one ------------------------
@pytest.mark.parametrize("layout", ["edit-attr-escaped-text-raw",
                                    "edit-text-raw-attr-escaped"])
def test_a_prg_edit_page_escaped_in_its_control_and_raw_in_text_is_a_stored_finding(
        site, tmp_path, layout):
    app = site(layout)
    verdict, rows = _confirm_and_record(app, _stored(app), tmp_path)
    assert verdict is not None and verdict.vuln_class == "xss-stored"
    assert verdict.evidence["observation"] == "prg"
    # the finding records the context that confirmed, among the contexts typed
    assert verdict.evidence["context"] == "html"
    assert verdict.evidence["breakout"] == "element"
    assert verdict.evidence["reflection"] == {"context": "html"}
    assert verdict.evidence["contexts"] == 2
    assert len(rows) == 1 and rows[0]["vuln_class"] == "xss-stored"
    assert rows[0]["confidence"] == "reflected-context"
    assert json.loads(rows[0]["evidence"])["observation"] == "prg"
    # the attribute context's break-out was tried first, then the text's
    assert [v.startswith('"') for v in app.probes()[1:3]] == [True, False]


def test_an_edit_page_escaped_in_both_places_is_no_finding_and_tries_each(site,
                                                                           tmp_path):
    app = site("edit-both-escaped")
    verdict, rows = _confirm_and_record(app, _stored(app), tmp_path)
    assert verdict is None and rows == []
    sent = app.probes()
    assert len(sent) == 3                      # the marker, then one try per context
    assert sent[1].startswith('"') and sent[2].startswith("<")


def test_a_search_box_and_heading_echo_confirms_the_raw_heading(site):
    app = site("search-box-escaped-heading-raw")
    verdict = Oracle(strategies=[ReflectedXssStrategy()]).confirm(
        _search(app), RequestsProbeSender())
    assert verdict is not None and verdict.vuln_class == "xss-reflected"
    assert "observation" not in verdict.evidence
    assert verdict.evidence["context"] == "html" and verdict.evidence["contexts"] == 2


@pytest.mark.parametrize("layout,context,breakout", [
    ("script-escaped-text-raw", "html", "element"),
    ("script-raw-text-escaped", "script", "js"),
])
def test_a_script_context_beside_a_text_context(site, layout, context, breakout):
    app = site(layout)
    verdict = Oracle(strategies=[ReflectedXssStrategy()]).confirm(
        _search(app), RequestsProbeSender())
    assert verdict is not None
    assert (verdict.evidence["context"], verdict.evidence["breakout"]) == (context,
                                                                           breakout)
    assert verdict.evidence["contexts"] == 2
    if context == "script":
        assert verdict.evidence["reflection"] == {"context": "script", "js_state": "'"}


def test_a_script_and_text_both_escaped_is_no_finding(site):
    app = site("script-escaped-text-escaped")
    assert Oracle(strategies=[ReflectedXssStrategy()]).confirm(
        _search(app), RequestsProbeSender()) is None
    assert len(app.probes()) == 3


def test_typing_only_the_first_context_misses_the_raw_place(site, monkeypatch):
    """Mutation check: the old behaviour (the first context only) fails these
    fixtures, so they test the fix."""
    monkeypatch.setattr(strat, "locate_reflections",
                        lambda h, m: ctx.locate_reflections(h, m)[:1])
    for layout in ("edit-attr-escaped-text-raw", "edit-text-raw-attr-escaped",
                   "search-box-escaped-heading-raw", "script-escaped-text-raw"):
        app = site(layout)
        assert ReflectedXssStrategy().confirm(_search(app), RequestsProbeSender()) \
            is None, layout


# --- the send cap ---------------------------------------------------------------------
def test_the_send_count_cap_is_respected(site):
    app = site("many-escaped")
    marker = "zqxmab12cd34"
    refs = locate_reflections(LAYOUTS["many-escaped"](marker), marker)
    tries = ReflectedXssStrategy._tries(refs, "zqxbab12cd34")
    cap = ReflectedXssStrategy.MAX_BREAKOUTS
    assert len(tries) > cap                    # non-vacuous: the cap binds here
    assert Oracle(strategies=[ReflectedXssStrategy()]).confirm(
        _search(app), RequestsProbeSender()) is None
    assert len(app.probes()) == 1 + cap        # the typing probe, then the cap


def test_a_single_context_page_costs_what_it_did(site):
    app = site("text-raw")
    verdict = Oracle(strategies=[ReflectedXssStrategy()]).confirm(
        _search(app), RequestsProbeSender())
    assert verdict is not None and verdict.evidence["contexts"] == 1
    assert len(app.probes()) == 2              # the marker and the one text break-out


def test_tries_go_in_rounds_and_send_a_fragment_once():
    """Every context's most specific try comes before any context's second, so the
    cap never starves a later context; an equal fragment is not sent twice."""
    exec_attr = Reflection("attribute", attr_exec=True, js_state="code",
                           attr_at_start=True, quote='"')
    plain_attr = Reflection("attribute", quote='"')
    text = Reflection("html")
    tries = ReflectedXssStrategy._tries([exec_attr, plain_attr, text], "T")
    # round 1: each context's first; round 2: the javascript: attribute's second;
    # its third (attribute injection, quote ") equals the plain attribute's first
    assert [(r, k) for r, k, _f, _c in tries] == [
        (exec_attr, "js-url"), (plain_attr, "attribute-injection"), (text, "element"),
        (exec_attr, "url-scheme")]
    frags = [f for _r, _k, f, _c in tries]
    assert len(frags) == len(set(frags))
    # one context: exactly `xss_breakouts`' own order and count
    assert [t[1:3] for t in ReflectedXssStrategy._tries([exec_attr], "T")] == \
        [t[:2] for t in xss_breakouts(exec_attr, "T")]


# --- locate_reflections ---------------------------------------------------------------
def test_locate_reflections_types_every_distinct_context_in_a_fixed_order():
    m = "zqxm1"
    page = (f'<p>{m}</p><input value="{m}"><script>var a = "{m}"; b = {m};</script>'
            f"<textarea>{m}</textarea><p>{m}</p><input value='{m}'>"
            f'<input value="{m}">')
    assert locate_reflections(page, m) == [
        Reflection("script", js_state='"'), Reflection("script", js_state="code"),
        Reflection("attribute", attr_at_start=True, quote='"'),
        Reflection("attribute", attr_at_start=True, quote="'"),
        Reflection("html"), Reflection("html", inert_parent="textarea")]
    assert locate_reflection(page, m) == locate_reflections(page, m)[0]
    assert locate_reflections("<p>nothing</p>", m) == []
    assert locate_reflection("<p>nothing</p>", m) is None
    assert locate_reflections(f"<{m}x>", m) == [Reflection("html")]


def test_an_inert_script_is_a_text_context_and_a_running_one_is_not():
    m = "zqxm1"
    running = f"<script>var a = '{m}';</script>"
    assert locate_reflections(running, m) == [Reflection("script", js_state="'")]
    inert = f'<script type="application/json">{{"a": "{m}"}}</script>'
    assert locate_reflections(inert, m) == [Reflection("html", inert_parent="script")]


def test_no_oracle_module_types_a_single_reflection():
    """PA-0160: a confirmer types every reflection; `locate_reflection` (one) is a
    wrapper for other callers, never called inside `fuzzlab/oracle/`."""
    offenders = []
    for path in sorted((ROOT / "fuzzlab" / "oracle").rglob("*.py")):
        if path.name != "context.py":
            offenders += [f"{path.name}:{n}" for n in
                          single_reflection_calls(path.read_text(encoding="utf-8"))]
    assert offenders == []


def single_reflection_calls(source: str) -> list[int]:
    out = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else \
                f.attr if isinstance(f, ast.Attribute) else None
            if name == "locate_reflection":
                out.append(node.lineno)
        elif isinstance(node, ast.ImportFrom) and any(
                a.name == "locate_reflection" for a in node.names):
            out.append(node.lineno)
    return out


def test_the_single_reflection_guard_catches_an_offender():
    offender = ("from fuzzlab.oracle.context import locate_reflection\n"
                "def confirm(text, m):\n"
                "    return context.locate_reflection(text, m)\n")
    assert single_reflection_calls(offender) == [1, 3]
    assert single_reflection_calls("x = locate_reflections(t, m)\n") == []


# --- BUG-0155: an attribute's quote is read from its own start tag ---------------------
def test_a_raw_value_after_an_equals_sign_in_a_quoted_attribute_confirms(site):
    app = site("link-query-raw")
    verdict = Oracle(strategies=[ReflectedXssStrategy()]).confirm(
        _search(app), RequestsProbeSender())
    assert verdict is not None and verdict.evidence["breakout"] == "attribute-injection"
    assert verdict.evidence["reflection"]["quote"] == '"'
    assert verdict.evidence["signature"].startswith('" ')


def test_an_encoded_value_in_a_query_link_is_no_finding(site):
    app = site("link-query-encoded")
    assert Oracle(strategies=[ReflectedXssStrategy()]).confirm(
        _search(app), RequestsProbeSender()) is None


def test_the_nearest_equals_reading_was_the_defect(site, monkeypatch):
    """Mutation check: the old reading (the quote after the nearest ``=``) types the
    query link as unquoted, sends an unquoted break-out and misses."""
    m = "zqxm1"
    assert ctx._raw_attr_quote(f'<a href="/find?term={m}">x</a>', m) == ""
    monkeypatch.setattr(ctx, "_attr_quote",
                        lambda html_, tag, attr, marker, starts:
                        ctx._raw_attr_quote(html_, marker))
    app = site("link-query-raw")
    assert ReflectedXssStrategy().confirm(_search(app), RequestsProbeSender()) is None


def test_each_attribute_gets_its_own_quote():
    m = "zqxm1"
    page = (f"<script>if (a<b) x = 1;</script><!-- <a title='{m}'> -->"
            f"<div title='a=b {m}' data-x={m} id=\"{m}\" class=\"c\">x</div>")
    refs = locate_reflections(page, m)
    assert [r.quote for r in refs if r.context == "attribute"] == ["'", "", '"']
    assert refs[-1] == Reflection("html")          # the comment is text, as before


@pytest.mark.parametrize("page,quote", [
    ('<a\r\n  class="c"\r\n  href="/x?a=1&b=zqxm1">x</a>', '"'),       # CRLF, lines
    ("<p>é ü</p>\n<i data-v='é=zqxm1'>x</i>", "'"),                   # non-ASCII
    ('<i title="a > b" data-v=\'zqxm1\'>x</i>', "'"),                 # '>' in a value
    ('<i =x data-v = "zqxm1">x</i>', '"'),                            # spaces round '='
    ('<i data-v="1" data-v="zqxm1">x</i>', '"'),                      # a duplicate
])
def test_the_quote_is_lexed_from_the_parsers_source_position(page, quote):
    (ref,) = locate_reflections(page, "zqxm1")
    assert ref.context == "attribute" and ref.quote == quote


def test_start_tag_attrs_follows_the_tokenizer():
    page = "<input  type=text value='a>b' data-x = \"q=1\" checked/>"
    assert ctx._start_tag_attrs(page, 0) == [
        ("type", "", "text"), ("value", "'", "a>b"), ("data-x", '"', "q=1"),
        ("checked", None, "")]


def test_no_oracle_module_reads_markup_by_scanning_back():
    """PA-0161: a markup position is lexed from the element's own start, never found
    by scanning back for the nearest delimiter. The one allowance is the documented
    fallback for a tag with no source position."""
    offenders = []
    for path in sorted((ROOT / "fuzzlab" / "oracle").rglob("*.py")):
        offenders += [f"{path.name}:{fn}" for fn in
                      backward_scans(path.read_text(encoding="utf-8"))
                      if (path.name, fn) not in _BACKWARD_SCAN_ALLOWED]
    assert offenders == []


_BACKWARD_SCAN_ALLOWED = {("context.py", "_raw_attr_quote")}


def backward_scans(source: str) -> list[str]:
    """Names of the functions calling ``rfind`` / ``rindex`` (module level: ``<module>``)."""
    out = []

    def visit(node, owner):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child.name)
                continue
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) \
                    and child.func.attr in ("rfind", "rindex") and owner not in out:
                out.append(owner)
            visit(child, owner)
    visit(ast.parse(source), "<module>")
    return out


def test_the_backward_scan_guard_catches_an_offender():
    offender = ("def quote_of(html, i):\n"
                "    eq = html.rfind('=', 0, i)\n"
                "    return html[eq + 1]\n")
    assert backward_scans(offender) == ["quote_of"]
    assert backward_scans("def ok(s):\n    return s.find('=')\n") == []
