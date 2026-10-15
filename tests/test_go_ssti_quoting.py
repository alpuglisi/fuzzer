"""BUG-0139's PA-0002 sweep: Go-template SSTI is never one quoting shape either.

`GoTemplateSstiStrategy` probed only ``{{ len "AAA…" }}``: a data path that filters or
escapes ``"`` before the template is parsed made it a guaranteed miss. Go's raw string
(``{{ len `AAA…` }}``) evaluates the same, so a second round with backticks runs when
the interpreted-string round did not confirm. It is just as strict: fresh lengths, both
probes evaluated, no cross-bleed, and the BUG-0133 echo rules.
"""

from __future__ import annotations

import html
import re

import pytest

from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import GoTemplateSstiStrategy
from tests.test_evaluation_marker_echo import SHAPES

_CAND = Candidate(url="http://h/p", param="u", method="POST", location="body",
                  category=GoTemplateSstiStrategy.category)


def _go_raw_only(value: str) -> str:
    """A Go sink behind a filter that HTML-escapes ``"`` before the template is parsed:
    ``{{ len &#34;AAA&#34; }}`` does not parse; a raw string evaluates."""
    escaped = value.replace('"', "&#34;")
    if "&#34;" in escaped and "{{" in escaped:
        return "template: page:1: unexpected \"&\" in operand"
    return re.sub(r"\{\{ len `(A+)` \}\}", lambda m: str(len(m[1])), escaped)


def _go_both(value: str) -> str:
    """An ordinary Go sink: both string forms evaluate."""
    return re.sub(r"\{\{ len [\"`](A+)[\"`] \}\}", lambda m: str(len(m[1])), value)


class _Sink:
    """The response to each probe is a page showing ``evaluate(value)``; counts sends."""

    def __init__(self, evaluate, shape=None):
        self.evaluate, self.shape, self.sent = evaluate, shape, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        self.sent.append(value)
        shown = self.evaluate(value)
        body = SHAPES[self.shape][1](value, shown) if self.shape else \
            f"<p>{html.escape(shown)}</p>"
        return Probe(200, "<html><body>" + body + "</body></html>",
                     headers={"Content-Type": "text/html"})


def test_a_filtered_double_quote_is_confirmed_by_the_raw_string():
    """The sweep's finding, fixed: ``"`` is escaped upstream, the template still
    evaluates; the backtick round confirms (4 requests)."""
    sink = _Sink(_go_raw_only)
    verdict = GoTemplateSstiStrategy().confirm(_CAND, sink)
    assert verdict is not None and verdict.confirmed
    assert verdict.evidence["string_form"] == "raw (backtick)"
    assert len(sink.sent) == 4
    assert all("`" in p for p in sink.sent[2:]) and '"' not in "".join(sink.sent[2:])


def test_a_confirmation_by_the_double_quoted_form_costs_what_it_did():
    """Cost: an ordinary Go sink confirms on the first round, 2 requests, as before,
    with no raw-string probe sent."""
    sink = _Sink(_go_both)
    verdict = GoTemplateSstiStrategy().confirm(_CAND, sink)
    assert verdict is not None and "string_form" not in verdict.evidence
    assert len(sink.sent) == 2 and all('"' in p for p in sink.sent)


def test_an_echo_only_page_is_never_confirmed_in_either_form():
    """No evaluation, the probe echoed back: no verdict, 4 requests (the worst case)."""
    sink = _Sink(lambda v: v)
    assert GoTemplateSstiStrategy().confirm(_CAND, sink) is None
    assert len(sink.sent) == 4


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_raw_string_round_keeps_the_echo_rules(shape):
    """BUG-0117 / BUG-0133, for the raw-string round: the same page shapes give the
    same answer as for the double-quoted form. An edit-form echo of the literal
    neither disqualifies nor confirms by itself; any other echo of the literal next to
    the number disqualifies."""
    want = SHAPES[shape][0]
    for _ in range(3):                                # fresh random lengths each time
        verdict = GoTemplateSstiStrategy().confirm(_CAND, _Sink(_go_raw_only, shape))
        assert (verdict is not None) is want, shape


def test_a_stale_raw_string_render_is_never_confirmed():
    """BUG-0117's causality check in the raw-string round: a page that always shows
    the first raw-string length (a stale render) gives no verdict."""
    first: list[str] = []

    def stale(value):
        shown = _go_raw_only(value)
        if "`" in value and not first:
            first.append(shown)
        return first[0] if ("`" in value and first) else shown
    assert GoTemplateSstiStrategy().confirm(_CAND, _Sink(stale)) is None
