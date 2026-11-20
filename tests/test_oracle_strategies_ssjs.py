"""Server-side JavaScript injection (FR-FUZZ-610..612, CC-FUZZ-0610): the evaluation
marker and the boolean differential, against fake servers that model the real sinks
measured on NodeGoat (CC-LAB-0331): an ``eval`` that renders its result, a ``$where``
built inside a single-quoted string, Juice Shop's unquoted ``$where``, and the safe
twins (``parseInt``, a value stored as text, a SQL-ish sink, a noisy page).

Every probe is also run through a JavaScript-context checker: no probe may be a syntax
or reference error in an unquoted, single- or double-quoted context (the property that
keeps Juice Shop's in-process ``$where`` alive, ERROR_LOG 2026-10-19). Node evaluates
them when it is installed; the structural check always runs."""

from __future__ import annotations

import json
import random
import re
import shutil
import subprocess

import pytest

from fuzzlab.oracle import strategies as S
from fuzzlab.oracle.probe import Candidate, Probe

_ABS = re.compile(r"Math\.abs\(-(\d+)\)")


def _js_eval(expr: str):
    """A tiny evaluator for exactly the probe grammar: numbers, ``Math.abs(-n)``, ``/``,
    ``==``, ``||``, ``&&``, ``+`` and quoted strings (enough to model the sinks)."""
    py = _ABS.sub(r"\1", expr).replace("||", " or ").replace("&&", " and ")
    py = py.replace("==", " == ")
    return eval(py, {"__builtins__": {}}, {})                  # noqa: S307 - test model


def _cand(param="v", category="server-side-javascript-injection", method="GET",
          location="query", content_type=None):
    return Candidate(url="http://127.0.0.1:9/p", param=param, method=method,
                     location=location, category=category, content_type=content_type)


class _EvalServer:
    """NodeGoat's contributions: ``eval(value)``, a number 0..30 rendered in a cell;
    ``safe`` parses it with parseFloat instead; ``echo`` reflects the raw text."""

    def __init__(self, mode="eval"):
        self.mode, self.sent = mode, []

    def send(self, url, param, value, timing=False, **kw):
        self.sent.append(value)
        if self.mode == "echo":
            return Probe(200, f"<td>{value} %</td>", 0.0)
        if self.mode == "safe":
            m = re.match(r"[-+]?\d+(\.\d+)?", value)
            n = float(m.group(0)) if m else float("nan")
        else:
            try:
                n = _js_eval(value)
            except Exception:                                   # noqa: BLE001
                return Probe(500, "error", 0.0)
        if not isinstance(n, (int, float)) or n != n:
            return Probe(200, "Invalid contribution percentages", 0.0)
        if n > 30 or n < 0:
            return Probe(200, "Contribution percentages cannot exceed 30 %", 0.0)
        shown = repr(n) if isinstance(n, float) else str(n)
        return Probe(200, f"<td>{shown} %</td>", 0.0)


class _WhereServer:
    """A MongoDB ``$where`` over three documents. ``quote`` is the context the value
    lands in (``'`` NodeGoat's ``this.stocks > '<v>'``, ``""`` Juice Shop's
    ``this.product == <v>``). ``mode``: ``where`` evaluates; ``text`` compares the value
    as a plain string (no injection); ``shuffle`` evaluates and lists the matches in a
    random order (NodeGoat's callbacks); ``strict`` raises on any probe that is not
    valid in its context (Juice Shop's crash)."""

    DOCS = [{"id": 1, "stocks": 10}, {"id": 2, "stocks": 20}, {"id": 3, "stocks": 30}]

    def __init__(self, quote="'", mode="where"):
        self.quote, self.mode, self.sent, self.crashed = quote, mode, [], False

    def send(self, url, param, value, timing=False, **kw):
        self.sent.append(value)
        if self.mode == "text":
            hits = []
        else:
            try:
                hits = [d for d in self.DOCS if self._matches(d, value)]
            except Exception:                                   # noqa: BLE001
                self.crashed = True
                return Probe(500, "ReferenceError", 0.0)
        if not hits:
            return Probe(500, "ERROR: No allocations found for the user", 0.0)
        if self.mode == "shuffle":
            hits = random.sample(hits, len(hits))
        return Probe(200, "".join(f"<p>allocation {d['id']}: {d['stocks']} %</p>"
                                  for d in hits), 0.0)

    def _matches(self, doc, value) -> bool:
        if self.quote:
            return self._quoted(value)
        if "'" in value or '"' in value:
            # number + string + number is a string: `id == "…"` is false (valid JS)
            if not re.fullmatch(r"\d+\+(['\"])\|\|.+?&&\1\+\d+", value):
                raise SyntaxError(value)
            return False
        return bool(_js_eval(f"{doc['id']} == {value}"))

    def _quoted(self, value):
        """``this.stocks > '<value>'`` with JavaScript's precedence, for the probe
        grammar: a value that leaves the string is ``A+q||C&&q+B``."""
        q = self.quote
        if q not in value:
            return False                          # a plain string: no stocks > NaN
        m = re.fullmatch(rf"(\d+)\+{re.escape(q)}\|\|(.+?)&&{re.escape(q)}\+(\d+)", value)
        if not m:
            raise SyntaxError(value)
        return bool(_js_eval(m.group(2)))


# --- the evaluation marker --------------------------------------------------------------

def test_the_marker_confirms_an_eval_that_renders_its_result():
    server = _EvalServer("eval")
    v = S.SsjsEvaluationMarkerStrategy().confirm(_cand(), server)
    assert v is not None and v.confirmed and v.vuln_class == "ssjs"
    assert len(server.sent) == 2 and v.evidence["results"][0] != v.evidence["results"][1]
    assert all(p.startswith("Math.abs(-") and p.endswith(")/1000") for p in server.sent)


@pytest.mark.parametrize("mode", ["safe", "echo"])
def test_the_marker_never_confirms_a_parsed_or_reflected_value(mode):
    server = _EvalServer(mode)
    assert S.SsjsEvaluationMarkerStrategy().confirm(_cand(), server) is None
    assert len(server.sent) == 1                  # one request when unconfirmed


def test_the_marker_result_is_javascripts_own_decimal():
    """``n/1000`` for n not a multiple of 10 prints with three places in JavaScript and
    Python alike (shortest round-trip), so `_result` names what the page shows."""
    for _ in range(2000):
        n = S.SsjsEvaluationMarkerStrategy._draw()
        assert 1001 <= n <= 9999 and n % 10
        assert S.SsjsEvaluationMarkerStrategy._result(n) == repr(n / 1000)


def test_the_marker_needs_the_second_result_from_its_own_probe():
    """A page that always shows the same decimal (the first probe's, stored) is no
    evaluator: the second result must appear in the second response."""
    class Sticky(_EvalServer):
        def send(self, url, param, value, timing=False, **kw):
            if not self.sent:
                self.first = super().send(url, param, value)
                return self.first
            self.sent.append(value)
            return self.first
    assert S.SsjsEvaluationMarkerStrategy().confirm(_cand(), Sticky()) is None


def test_the_marker_skips_a_raw_whole_body_point():
    server = _EvalServer("eval")
    cand = _cand(method="POST", location="body", content_type="application/json")
    assert S.SsjsEvaluationMarkerStrategy().confirm(cand, server) is None
    assert server.sent == []


# --- the boolean differential -----------------------------------------------------------

@pytest.mark.parametrize("quote,mode,family", [
    ("'", "where", "js-single-quoted"),
    ("'", "shuffle", "js-single-quoted"),              # NodeGoat's order, measured
    ('"', "where", "js-double-quoted"),
    ("", "where", "js-unquoted"),                      # Juice Shop's reviews
])
def test_the_differential_confirms_a_where_in_its_context(quote, mode, family):
    server = _WhereServer(quote, mode)
    v = S.SsjsBooleanDifferentialStrategy().confirm(_cand(), server, rng=random.Random(7))
    assert v is not None and v.confirmed and v.evidence["family"] == family
    assert not server.crashed


@pytest.mark.parametrize("quote", ["'", '"', ""])
def test_no_probe_crashes_a_strict_evaluator_in_any_context(quote):
    """Every family's every probe is valid JavaScript in every context: a strict
    evaluator (Juice Shop's in-process ``$where``) never throws on one."""
    server = _WhereServer(quote, "where")
    S.SsjsBooleanDifferentialStrategy().confirm(_cand(), server, rng=random.Random(3))
    S.SsjsEvaluationMarkerStrategy().confirm(_cand(), server)
    assert not server.crashed and server.sent


def test_the_differential_never_confirms_a_value_compared_as_text():
    server = _WhereServer("'", "text")
    assert S.SsjsBooleanDifferentialStrategy().confirm(
        _cand(), server, rng=random.Random(1)) is None
    assert len(server.sent) == 9                  # three failed screens


def test_the_differential_never_confirms_a_noisy_page():
    class Noise:
        def send(self, url, param, value, timing=False, **kw):
            return Probe(200, "x" * random.choice([10, 500, 2000]), 0.0)
    verdicts = [S.SsjsBooleanDifferentialStrategy().confirm(
        _cand(), Noise(), rng=random.Random(i)) for i in range(200)]
    # a later family the cap stops after an earlier screen passed is inconclusive,
    # never a confirmation (SqliBooleanStrategy's rule)
    assert not any(v is not None and v.confirmed for v in verdicts)
    assert all(v is None or v.inconclusive for v in verdicts)


def test_keep_and_disc_differ_only_in_the_compared_number():
    for quote in ("", "'", '"'):
        keep, disc = S._ssjs_keep(quote)("12345"), S._ssjs_disc(quote)("12345")
        assert len(keep) == len(disc)
        assert re.sub(r"\d", "0", keep) == re.sub(r"\d", "0", disc)
        assert _js_eval(_ABS.sub(r"\1", keep.split("||")[1].split("&&")[0])) is False
        assert _js_eval(_ABS.sub(r"\1", disc.split("||")[1].split("&&")[0])) is True


def _all_probes() -> list[str]:
    out = [S.SsjsEvaluationMarkerStrategy._value(S.SsjsEvaluationMarkerStrategy._draw())]
    for fam in S._SSJS_FAMILIES:
        b = fam.base()
        out += [b, fam.keep(b), fam.disc(b)]
    return out


_FORBIDDEN = re.compile(r"while|for\s*\(|process|require|exit|sleep|constructor|"
                        r"Function|eval|import|this\.|;|\{|\}|`|\$\{|\\")


def test_no_probe_names_anything_but_math_abs():
    for _ in range(50):
        for p in _all_probes():
            assert not _FORBIDDEN.search(p), p
            assert set(re.findall(r"[A-Za-z_][A-Za-z_.]*", p)) <= {"Math.abs"}, p


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_every_probe_is_valid_javascript_in_every_context_by_node():
    """Measured with a real JavaScript engine: each probe, wrapped as each context
    (``this.x == <v>``, ``this.x > '<v>'``, ``this.x > "<v>"``, ``eval``), compiles
    and runs without throwing."""
    probes = [p for _ in range(5) for p in _all_probes()]
    script = ("const probes = JSON.parse(process.argv[1]); const self = {x: 1};"
              "let bad = [];"
              "for (const v of probes) {"
              "  for (const w of ['this.x == ' + v, \"this.x > '\" + v + \"'\","
              "                   'this.x > \"' + v + '\"', v]) {"
              "    try { new Function('return (' + w + ')').call(self); }"
              "    catch (e) { bad.push(w + ' :: ' + e.name); } } }"
              "console.log(JSON.stringify(bad));")
    res = subprocess.run(["node", "-e", script, json.dumps(probes)], capture_output=True,
                         text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout) == []


def test_the_category_is_ruled_mapped_and_registered():
    from fuzzlab.audit.rules import load_rules
    from fuzzlab.core.runmode import to_category
    cat = "server-side-javascript-injection"
    assert to_category("ssjs") == cat
    assert S.category_to_oracle_class(cat) == "ssjs"
    assert any(r.category == cat for r in load_rules())
    names = {type(s).__name__ for s in S.default_strategies()}
    assert {"SsjsEvaluationMarkerStrategy", "SsjsBooleanDifferentialStrategy"} <= names


# --- BUG-0610: an echoed operator leaf ---------------------------------------------------

def test_nosql_confirms_a_login_that_echoes_the_submitted_leaf():
    """NodeGoat's login renders the submitted userName back into its form: an operator
    leaf echoes as ``[object Object]`` in V and D alike, the B token as itself. The
    echo is the sent value's reflection (BUG-0610); measured live 2026-11-20."""
    users = ["admin", "user1"]

    class EchoLogin:
        def send(self, url, param, value, timing=False, **kw):
            body = json.loads(value)
            u = body["userName"]
            shown = "[object Object]" if isinstance(u, dict) else u
            if isinstance(u, dict):
                hit = any(x != u["$ne"] for x in users) if "$ne" in u else False
            else:
                hit = u in users
            msg = "Invalid password" if hit else "Invalid username"
            return Probe(200, f'{msg}<input name="userName" value="{shown}">', 0.0)
    cand = Candidate(url="http://127.0.0.1:9/login", param="userName", method="POST",
                     location="json", category="nosql-injection",
                     base_entries=((("userName",), "user1"), (("password",), "x")))
    v = S.NoSqlOperatorStrategy().confirm(cand, EchoLogin())
    assert v is not None and v.confirmed


def test_nosql_still_refuses_a_server_that_stringifies_every_object():
    """The echo normalization keeps the differential's soundness: a server that turns
    every object into ``[object Object]`` and matches it as text answers V and D alike."""
    class Stringify:
        def send(self, url, param, value, timing=False, **kw):
            u = json.loads(value)["userName"]
            shown = "[object Object]" if isinstance(u, dict) else u
            return Probe(200, f'Invalid username<input value="{shown}">', 0.0)
    cand = Candidate(url="http://127.0.0.1:9/login", param="userName", method="POST",
                     location="json", category="nosql-injection",
                     base_entries=((("userName",), "user1"), (("password",), "x")))
    assert S.NoSqlOperatorStrategy().confirm(cand, Stringify()) is None
