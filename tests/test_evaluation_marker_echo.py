"""BUG-0133: an edit form that echoes the stored input hid an evaluated SSTI.

Juice Shop's ``/profile`` shows the evaluated product in ``<p>647192</p>`` and the raw
stored value in ``<input id="username" value="#{728*889}">``. M4's "evaluated, not just
reflected" rule (``expr in text`` disqualifies, M4 since its first version) read the
edit field's echo as a reflection and refused. Now the probe's literal disqualifies
only where it is echoed outside a form control's value (an ``<input value>``, a
``<textarea>``, a selected ``<option>``), and the number must appear outside every form
control; the second-sample causality check (BUG-0117) is unchanged. The same rule
applies to SpEL, the Go template marker and the SQL evaluation marker (PA-0002 sweep).

Every page here is a fake sender or a loopback port-0 fixture; nothing reaches a lab.
"""

from __future__ import annotations

import html
import re

import pytest

from fuzzlab.oracle import Oracle
from fuzzlab.oracle.context import split_form_control_values
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import (GoTemplateSstiStrategy, SpelInjectionStrategy,
                                       SqliEvaluationMarkerStrategy, SstiStrategy,
                                       _evaluated)


# --- each strategy's evaluator, as a vulnerable sink would compute it ------------------
def _ssti(value: str) -> str:
    return re.sub(r"#\{(\d+)\*(\d+)\}", lambda m: str(int(m[1]) * int(m[2])), value)


def _spel(value: str) -> str:
    return re.sub(r"T\(java\.lang\.Math\)\.abs\(-(\d+)\)", lambda m: m[1], value)


def _go(value: str) -> str:
    return re.sub(r'\{\{ len "(A+)" \}\}', lambda m: str(len(m[1])), value)


def _sql(value: str) -> str:
    return re.sub(r"0'\+\(SELECT (\d+)\*(\d+)\)\+'0", lambda m: str(int(m[1]) * int(m[2])),
                  value)


STRATEGIES = {"ssti": (SstiStrategy, _ssti), "spel": (SpelInjectionStrategy, _spel),
              "go": (GoTemplateSstiStrategy, _go), "sql": (SqliEvaluationMarkerStrategy, _sql)}


def _attr(v: str) -> str:
    return html.escape(v, quote=True)


#: Page shapes: (raw value, evaluated value) -> HTML. ``True``: it must confirm.
SHAPES = {
    # the edit-form echo (BUG-0133): confirms
    "input-value": (True, lambda v, e: f'<form><input name="u" value="{_attr(v)}"></form>'
                                       f'<p>{html.escape(e)}</p>'),
    "textarea": (True, lambda v, e: f"<textarea>{html.escape(v)}</textarea>"
                                    f"<p>{html.escape(e)}</p>"),
    "selected-option": (True, lambda v, e: f'<select><option selected value="{_attr(v)}">'
                                           f"{html.escape(v)}</option></select>"
                                           f"<p>{html.escape(e)}</p>"),
    # the reflections the literal rule protects against ("evaluated, not just
    # reflected"): the literal echoed where a sink shows it, the number beside it
    "text-echo-and-number": (False, lambda v, e: f"<p>You entered {html.escape(v)}</p>"
                                                 f"<p>{html.escape(e)}</p>"),
    "attribute-echo-and-number": (False, lambda v, e: f'<a title="{_attr(v)}">x</a>'
                                                      f"<p>{html.escape(e)}</p>"),
    "comment-echo-and-number": (False, lambda v, e: f"<!-- {v} --><p>{html.escape(e)}</p>"),
    "unselected-option-and-number": (False, lambda v, e: f'<select><option value="1">a'
                                                         f'</option><option value="'
                                                         f'{_attr(v)}">{html.escape(v)}'
                                                         f"</option></select>"
                                                         f"<p>{html.escape(e)}</p>"),
    # the number only inside the edit field: not shown by the page itself
    "number-only-in-the-control": (False, lambda v, e: f'<input value="{_attr(v)} '
                                                       f'{_attr(e)}">'),
    # an echo with no evaluation at all (SpEL's literal holds its own canary)
    "input-echo-no-evaluation": (False, lambda v, e: f'<input value="{_attr(v)}">'
                                                     f"<p>hello</p>"),
    "text-echo-no-evaluation": (False, lambda v, e: f"<p>{html.escape(v)}</p>"),
}


class _Page:
    """A non-PRG sink: the response to each probe is its page (BUG-0133's shapes)."""

    def __init__(self, shape, evaluate):
        self.shape, self.evaluate = SHAPES[shape][1], evaluate

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        return Probe(200, "<html><body>" + self.shape(value, self.evaluate(value))
                     + "</body></html>", headers={"Content-Type": "text/html"})


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("name", sorted(STRATEGIES))
def test_each_evaluation_marker_judges_the_echo_by_where_it_is(name, shape):
    cls, evaluate = STRATEGIES[name]
    want = SHAPES[shape][0]
    cand = Candidate(url="http://h/p", param="u", method="POST", location="body",
                     category=cls.category)
    for _ in range(3):                                # fresh random values each time
        verdict = cls().confirm(cand, _Page(shape, evaluate))
        assert (verdict is not None) is want, (name, shape)


def test_the_prg_edit_form_confirms_like_juice_shops_profile(tmp_path):
    """The live shape: POST -> 302 -> the profile page with the raw value in its edit
    field and the product in a ``<p>`` -- through PRG observation (FR-FUZZ-49)."""
    from tests.test_prg_observation import PrgSite
    from fuzzlab.tools.probesender import RequestsProbeSender
    app = PrgSite(render="editform", status=302)
    try:
        cand = Candidate(url=app.base + "/profile", param="username", method="POST",
                         location="body", category="server-side-template-injection")
        verdict = Oracle(strategies=[SstiStrategy()]).confirm(cand, RequestsProbeSender())
        assert verdict is not None and verdict.evidence["observation"] == "prg"
        assert verdict.evidence["payload"].startswith("#{")
    finally:
        app.close()


def test_the_second_sample_still_decides_on_an_edit_form():
    """BUG-0117's causality check is unchanged: an edit form whose page always shows
    the *first* product (a stale render) does not confirm."""
    first: list[str] = []

    class Stale:
        def send(self, url, param, value, timing=False, method="GET",
                 location="query", content_type=None, entries=None):
            if "#{" in value and not first:
                first.append(_ssti(value))
            shown = first[0] if first else "0"
            return Probe(200, f'<input value="{_attr(value)}"><p>{shown}</p>',
                         headers={"Content-Type": "text/html"})
    cand = Candidate(url="http://h/p", param="u", category="server-side-template-injection")
    assert SstiStrategy().confirm(cand, Stale()) is None


def test_the_split_is_by_parsed_role():
    controls, rest = split_form_control_values(
        '<input value="a"><textarea>b</textarea><select><option selected value="c">d'
        '</option><option value="e">f</option></select><p title="g">h</p><!-- i -->'
        "<script>j</script>")
    assert sorted(controls) == ["a", "b", "c", "d"]
    assert {"e", "f", "g", "h", " i ", "j"} <= set(rest)


def test_the_unchanged_cases_keep_their_old_answer():
    """No literal in the page: exactly the old rule (the number anywhere, raw)."""
    assert _evaluated("<p>647192</p>", "728*889", 647192)
    assert not _evaluated("<p>6471920</p>", "728*889", 647192)
    assert not _evaluated("728*889 647192", "728*889", 647192)      # a text echo


# --- PA-0133: no evaluation marker judges its own literal by a raw substring ----------
import ast                                                  # noqa: E402
from pathlib import Path                                    # noqa: E402

#: The names the evaluation markers give their own probe literal.
_LITERAL_NAMES = {"expr", "expr1", "expr2", "payload", "payload1", "payload2", "literal"}
#: The one place a literal is judged (by parsed role, BUG-0133).
_JUDGES = {"_echo"}


def _raw_literal_tests(source: str) -> list[str]:
    """``<literal> in <text>`` / ``not in`` comparisons outside `_echo`: a probe's own
    literal judged as a substring of a response."""
    tree = ast.parse(source)
    exempt = {id(n) for f in ast.walk(tree)
              if isinstance(f, ast.FunctionDef) and f.name in _JUDGES for n in ast.walk(f)}
    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Compare) and id(node) not in exempt
                and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
                and isinstance(node.left, ast.Name) and node.left.id in _LITERAL_NAMES):
            right = ast.unparse(node.comparators[0])
            if "text" in right or "body" in right:
                found.append(ast.unparse(node))
    return found


def test_no_strategy_judges_its_literal_by_a_raw_substring():
    src = (Path(__file__).resolve().parents[1] / "fuzzlab" / "oracle" /
           "strategies.py").read_text()
    assert _raw_literal_tests(src) == []


def test_the_literal_guard_catches_the_old_rule():
    """PA-0034(2): BUG-0133's own line, and a variant, are flagged."""
    assert _raw_literal_tests("if not _contains_number(text, n) or expr in text:\n"
                              "    pass\n")
    assert _raw_literal_tests("ok = payload2 not in (probe.text or '')\n")
    assert not _raw_literal_tests("def _echo(text, literal):\n    return literal in text\n")
