"""String-context SQL-injection confirmation (FR-FUZZ-45) and BUG-0117 / PA-0117.

Offline: every target is a fake `Sender` backed by an in-memory stdlib `sqlite3`
database that builds each statement the way the page's source does (bWAPP sqli_11,
sqli_14, sqli_12, the sqli_4 text simulated on SQLite; the lab's string sink templates),
each with a secure twin (a bound parameter). No traffic leaves the process.
"""

from __future__ import annotations

import html
import json
import math
import random
import re
import shlex
import sqlite3
import xml.etree.ElementTree as ET
from fractions import Fraction
from hashlib import md5
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.core.oracle_status import CHECKED, INCONCLUSIVE, UNLABELLED
from fuzzlab.mutation.catalog import refuse_destructive
from fuzzlab.oracle import Oracle
from fuzzlab.oracle import strategies as S
from fuzzlab.oracle.probe import Candidate, Probe, Verdict
from fuzzlab.oracle.strategies import (
    ENGINE_BOUND, ENGINE_ROUNDS, FAMILY_COST, SQL_ERROR_SIGNATURES,
    ConfirmationStrategy, GoTemplateSstiStrategy, PathTraversalStrategy,
    SpelInjectionStrategy, SqliBooleanStrategy, SqliErrorStrategy,
    SqliEvaluationMarkerStrategy, SqliTimingStrategy, SstiStrategy,
    default_strategies)

URL = "http://127.0.0.1:8090/bWAPP/page.php"
CAND = Candidate(URL, "title", category="sql-injection")
MOVIES = ["G.I. Joe: Retaliation", "Iron Man", "Man of Steel", "Terminator Salvation",
          "The Amazing Spider-Man", "The Cabin in the Woods", "The Dark Knight Rises",
          "The Fast and the Furious", "The Incredible Hulk", "World War Z"]
HEAD = "<html><body><h1>bWAPP</h1><form><input name=title></form>"


class _SqliteSite:
    """A page that runs one SQL statement built from the probed value."""

    def __init__(self, shape: str, secure: bool = False):
        self.shape, self.secure = shape, secure
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE movies (title TEXT)")
        self.db.executemany("INSERT INTO movies VALUES (?)", [(m,) for m in MOVIES])
        self.db.execute("CREATE TABLE codes (code TEXT, name TEXT)")
        self.db.execute("INSERT INTO codes VALUES ('1', 'first')")
        self.db.execute("CREATE TABLE blog (id INTEGER PRIMARY KEY, entry TEXT, owner TEXT)")
        self.db.execute("CREATE TABLE users (username TEXT, password TEXT)")
        self.db.execute("INSERT INTO users VALUES ('bee', 'bug')")
        self.sent: list[str] = []

    def _run(self, sql: str, args=()):
        return self.db.execute(sql, args).fetchall()

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        self.sent.append(value)
        return getattr(self, "_" + self.shape)(value)

    # bWAPP sqli_11: SQLite LIKE search; a failed query prints only PDO's errorCode
    def _sqli_11(self, v):
        try:
            rows = (self._run("SELECT title FROM movies WHERE title LIKE ?", (f"%{v}%",))
                    if self.secure else
                    self._run(f"SELECT title FROM movies WHERE title LIKE '%{v}%'"))
        except sqlite3.Error:
            return Probe(200, HEAD + "<table>Error: HY000")
        cells = "".join(f"<tr><td>{html.escape(r[0])}</td></tr>" for r in rows)
        return Probe(200, HEAD + f"<table>{cells}</table></body></html>")

    # bWAPP sqli_14 (and the sqli_4 text, simulated): blind, errors masked
    def _blind(self, v, collate):
        tail = " COLLATE NOCASE" if collate else ""
        try:
            rows = (self._run(f"SELECT title FROM movies WHERE title = ?{tail}", (v,))
                    if self.secure else
                    self._run(f"SELECT title FROM movies WHERE title = '{v}'{tail}"))
        except sqlite3.Error:
            return Probe(200, HEAD + "<p>Incorrect syntax detected!</p></body></html>")
        word = "exists" if rows else "does not exist"
        return Probe(200, HEAD + f"<p>The movie {word} in our database!</p></body></html>")

    def _sqli_14(self, v):
        return self._blind(v, True)

    def _sqli_4(self, v):
        return self._blind(v, False)

    # a lookup whose errors render exactly like "not found" (string-evaluation's case)
    def _code(self, v):
        try:
            rows = (self._run("SELECT name FROM codes WHERE code = ?", (v,)) if self.secure
                    else self._run(f"SELECT name FROM codes WHERE code = '{v}'"))
        except sqlite3.Error:
            rows = []
        body = f"<p>Name: {rows[0][0]}</p>" if rows else "<p>No such code.</p>"
        return Probe(200, HEAD + body + "</body></html>")

    # bWAPP sqli_12: INSERT then list every blog row in the same response
    def _sqli_12(self, v):
        try:
            if self.secure:
                self._run("INSERT INTO blog (entry, owner) VALUES (?, 'bee')", (v,))
            else:
                self._run(f"INSERT INTO blog (entry, owner) VALUES ('{v}','bee')")
        except sqlite3.Error:
            return Probe(200, HEAD + "Error: HY000")
        rows = self._run("SELECT id, entry FROM blog ORDER BY id")
        cells = "".join(f"<tr><td>{i}</td><td>{html.escape(str(e))}</td></tr>"
                        for i, e in rows)
        return Probe(200, HEAD + f"<table>{cells}</table></body></html>")

    # the lab's `sql_string_literal_like` (PFF /search.php): generic 500 on error
    def _lab_like(self, v):
        try:
            rows = (self._run("SELECT title FROM movies WHERE title LIKE ?", (f"%{v}%",))
                    if self.secure else
                    self._run(f"SELECT title FROM movies WHERE title LIKE '%{v}%'"))
        except sqlite3.Error:
            return Probe(500, "<html><body>Server Error</body></html>")
        return Probe(200, HEAD + f"<p>{len(rows)} result(s)</p></body></html>")

    # the lab's `sql_string_literal_lookup` with the password condition (/login.php)
    def _lab_login(self, v):
        try:
            rows = (self._run("SELECT 1 FROM users WHERE username = ? AND password = ?",
                              (v, "x")) if self.secure else
                    self._run(f"SELECT 1 FROM users WHERE username = '{v}' "
                              f"AND password = 'x'"))
        except sqlite3.Error:
            return Probe(500, "<html><body>Server Error</body></html>")
        return Probe(200, HEAD + ("<p>Welcome</p>" if rows else "<p>Invalid login</p>"))


def _confirm(strategy, sender, candidate=CAND):
    return strategy.confirm(candidate, sender)


# --- T1-T6: the vulnerable shapes confirm ------------------------------------------

def test_string_grammar_confirms_sqlite_like_that_prints_only_an_errorcode():
    v = _confirm(SqliBooleanStrategy(), _SqliteSite("sqli_11"))
    assert v and v.confirmed and v.evidence["family"] == "string-grammar"
    assert "HY000" in v.evidence["corroboration"]


def test_string_grammar_confirms_masked_blind_sqlite():
    v = _confirm(SqliBooleanStrategy(), _SqliteSite("sqli_14"))
    assert v and v.evidence["family"] == "string-grammar"


def test_string_grammar_confirms_masked_blind_mysql_shape():
    """The sqli_4 text, simulated on SQLite; MySQL semantics need on-host proof."""
    v = _confirm(SqliBooleanStrategy(), _SqliteSite("sqli_4"))
    assert v and v.evidence["family"] == "string-grammar"


def test_string_evaluation_confirms_when_errors_render_as_not_found():
    v = _confirm(SqliBooleanStrategy(), _SqliteSite("code"))
    assert v and v.evidence["family"] == "string-evaluation"


def test_evaluation_marker_confirms_stored_sqlite_insert():
    site = _SqliteSite("sqli_12")
    v = _confirm(SqliEvaluationMarkerStrategy(), site)
    assert v and v.confirmed and v.mechanism == "evaluation-marker"
    assert len(site.sent) == 2


@pytest.mark.parametrize("shape", ["lab_like", "lab_login"])
def test_lab_string_sinks_confirm_the_vulnerable_twin(shape):
    assert _confirm(SqliBooleanStrategy(), _SqliteSite(shape))


# --- T13: every secure twin, through the full Oracle -------------------------------

@pytest.mark.parametrize("shape", ["sqli_11", "sqli_14", "sqli_4", "code", "sqli_12",
                                   "lab_like", "lab_login"])
def test_secure_twins_are_never_confirmed(shape):
    oracle = Oracle(strategies=[s for s in default_strategies()
                                if s.category == "sql-injection"
                                and not isinstance(s, SqliTimingStrategy)])
    assert oracle.confirm(CAND, _SqliteSite(shape, secure=True)) is None


# --- BUG-0117: error signatures need a clean control --------------------------------

class _AlwaysWarns:
    """A page whose benign state already prints a MySQL warning (display_errors on)."""

    def send(self, url, param, value, **kw):
        return Probe(200, "<b>Warning</b>: mysql_num_rows() expects parameter 1 "
                          f"<p>{html.escape(value)}</p>")


class _StrictInt:
    """A bound parameter into a strict-mode INT column: any non-numeric value errors."""

    def send(self, url, param, value, **kw):
        if value.isdigit():
            return Probe(200, "<p>row</p>")
        return Probe(200, "Warning: mysqli_query(): (HY000/1366): Incorrect integer value")


def test_error_signature_needs_absence_in_a_benign_control():
    assert SqliErrorStrategy().confirm(CAND, _AlwaysWarns()) is None


def test_strict_int_bound_sink_that_rejects_any_non_numeric_input_is_not_confirmed():
    assert SqliErrorStrategy().confirm(CAND, _StrictInt()) is None


def test_error_signature_still_confirms_a_real_quote_error():
    class Real:
        def send(self, url, param, value, **kw):
            if "'" in value:
                return Probe(200, "You have an error in your SQL syntax near ''")
            return Probe(200, "<p>ok</p>")
    v = SqliErrorStrategy().confirm(CAND, Real())
    assert v and v.confirmed and v.evidence["controls"]


# --- T8 / T8b / T8c: payload-independent noise never confirms (PA-0117 (3)) ----------

_X, _Y = "<p>" + "a" * 100 + "</p>", "<p>" + "b" * 300 + "</p>"


class _Periodic:
    def __init__(self, pattern):
        self.pattern, self.i = pattern, 0

    def send(self, url, param, value, **kw):
        state = self.pattern[self.i % len(self.pattern)]
        self.i += 1
        return Probe(200, _Y if state else _X)


class _Constant:
    def __init__(self, text):
        self.text = text

    def send(self, url, param, value, **kw):
        return Probe(200, self.text)


def _periodic_patterns(max_period=10):
    for p in range(1, max_period + 1):
        for bits in range(2 ** p):
            yield tuple((bits >> i) & 1 for i in range(p))


def _noise_senders(seeds):
    yield "constant", lambda: _Constant(_X)
    yield "signature-always", lambda: _Constant("You have an error in your SQL syntax")
    for pattern in _periodic_patterns():
        yield f"periodic{pattern}", (lambda pat=pattern: _Periodic(pat))


def _noise_confirmations(strategies, seeds=range(5)) -> list:
    """Every (strategy, sender, seed) that confirms on payload-independent noise."""
    found = []
    for name, make in _noise_senders(seeds):
        for strategy in strategies:
            for seed in seeds:
                rng = random.Random(seed)
                if isinstance(strategy, SqliBooleanStrategy):
                    verdict = strategy.confirm(CAND, make(), rng=rng)
                else:
                    verdict = strategy.confirm(CAND, make())
                if verdict is not None and verdict.confirmed:
                    found.append((type(strategy).__name__, name, seed))
    return found


def _sqli_strategies():
    return [s for s in default_strategies()
            if s.category == "sql-injection" and s.mechanism != "differential-timing"]


def _binomial_upper(n: int, p: Fraction, tail: float = 1e-6) -> int:
    """The smallest k with P[Binomial(n, p) > k] <= tail."""
    pf, cumulative = float(p), 0.0
    for k in range(n + 1):
        cumulative += math.comb(n, k) * pf ** k * (1 - pf) ** (n - k)
        if 1 - cumulative <= tail:
            return k
    return n


def test_payload_independent_noise_never_confirms_any_sqli_strategy():
    strategies = _sqli_strategies()
    assert {type(s) for s in strategies} >= {SqliErrorStrategy, SqliBooleanStrategy,
                                            SqliEvaluationMarkerStrategy}
    found = _noise_confirmations(strategies)
    trials = 2048 * 5 * len(SqliBooleanStrategy._FAMILIES)
    assert len(found) <= _binomial_upper(trials, ENGINE_BOUND), found[:5]


class _ControlLessError(ConfirmationStrategy):
    vuln_class, mechanism, category = "sqli", "control-less", "sql-injection"

    def confirm(self, candidate, sender):
        text = self._send(sender, candidate, "'").text
        if any(rx.search(text) for rx, _ in SQL_ERROR_SIGNATURES):
            return Verdict(True, "sqli", self.mechanism)
        return None


class _SingleSample(ConfirmationStrategy):
    """The ad352db `SqliBooleanStrategy`: one unreplicated sample of each probe."""
    vuln_class, mechanism, category = "sqli", "single-sample", "sql-injection"

    def confirm(self, candidate, sender):
        benign = self._send(sender, candidate, "1").text
        true_p = self._send(sender, candidate, "1 AND 1=1").text
        false_p = self._send(sender, candidate, "1 AND 1=2").text
        if self._similar(benign, true_p) and not self._similar(true_p, false_p):
            return Verdict(True, "sqli", self.mechanism)
        return None


def test_noise_discovery_guard_flags_a_control_less_signature_strategy():
    found = _noise_confirmations([_ControlLessError()], seeds=[0])
    assert ("_ControlLessError", "signature-always", 0) in found


def test_noise_discovery_guard_flags_a_single_sample_differential():
    found = _noise_confirmations([_SingleSample()], seeds=[0])
    assert ("_SingleSample", "periodic(0, 0, 1)", 0) in found


# --- T9 / T9b: the engine's bound, exactly, over its own randomness ------------------

class _Fork(Exception):
    def __init__(self, n):
        self.n = n


class _ScriptedRng:
    """Follows a prefix of choice indexes, then forks (DFS over the engine's draws)."""

    def __init__(self, prefix):
        self.prefix, self.draws = list(prefix), 0

    def choice(self, seq):
        if self.draws < len(self.prefix):
            pick = self.prefix[self.draws]
            self.draws += 1
            return seq[pick]
        raise _Fork(len(seq))


def _exact_probability(engine, family, make_sender) -> Fraction:
    """P[confirm] summed exactly over every draw sequence; also checks the draw
    contract (one draw per round reached)."""
    total = Fraction(0)
    stack = [((), Fraction(1))]
    while stack:
        prefix, weight = stack.pop()
        rng = _ScriptedRng(prefix)
        sender = make_sender()
        try:
            evidence, count = engine._differential(sender, CAND, family, rng=rng)
        except _Fork as fork:
            for i in range(fork.n):
                stack.append((prefix + (i,), weight / fork.n))
            continue
        assert rng.draws == len(prefix)
        assert count == 1 + 2 + 3 * (rng.draws - 1)      # one draw per round reached
        if evidence is not None:
            total += weight
    return total


def _families():
    return [f for f in SqliBooleanStrategy._FAMILIES]


def test_engine_bound_holds_over_its_own_randomness_for_every_periodic_two_state_pattern():
    """The bound is a property of the engine's draws, for any comparison predicate:
    exhaustive over every period <= 10 (2046 patterns, every phase) and 2000 aperiodic
    length-21 sequences with the numeric family's predicate, and over every period <= 4
    with each string family's exact predicate (the worst case, period 3, included)."""
    engine, worst = SqliBooleanStrategy(), {}
    for family in _families():
        worst[family.name] = Fraction(0)
        for pattern in _periodic_patterns(4 if family.exact else 10):
            p = _exact_probability(engine, family, lambda pat=pattern: _Periodic(pat))
            assert p <= ENGINE_BOUND, (family.name, pattern, p)
            worst[family.name] = max(worst[family.name], p)
    assert set(worst.values()) == {ENGINE_BOUND} and ENGINE_BOUND == Fraction(1, 1458)
    rand = random.Random(0)                                 # and aperiodic sequences
    for _ in range(2000):
        seq = tuple(rand.randint(0, 1) for _ in range(FAMILY_COST))
        p = _exact_probability(engine, _families()[0], lambda s=seq: _Periodic(s))
        assert p <= ENGINE_BOUND


def test_a_fixed_order_engine_is_flagged_by_the_same_exact_search():
    """PA-0034(2): an engine with a fixed order confirms a noise sequence aligned to
    its D slots with probability 1; the same exact search must flag it."""
    class Fixed(SqliBooleanStrategy):
        def _differential(self, sender, candidate, family, rng=None):
            class First:
                def choice(self, seq):
                    rng.choice(seq)                          # keep the draw count
                    return seq[0] if len(seq) == 2 else ("V", "D", "B")
            return super()._differential(sender, candidate, family, rng=First())
    d_slots = {2} | {3 + 3 * k + 1 for k in range(ENGINE_ROUNDS)}   # (V, D, B) rounds
    aligned = tuple(int(i in d_slots) for i in range(FAMILY_COST))
    p = _exact_probability(Fixed(), _families()[0], lambda: _Periodic(aligned))
    assert p == 1 > ENGINE_BOUND
    assert _exact_probability(SqliBooleanStrategy(), _families()[0],
                              lambda: _Periodic(aligned)) <= ENGINE_BOUND


def test_confirmation_rate_over_many_seeds_stays_within_the_bound():
    worst = (0, 0, 1)
    n, hits = 5000, 0
    for seed in range(n):
        evidence, _ = SqliBooleanStrategy()._differential(
            _Periodic(worst), CAND, _families()[0], rng=random.Random(seed))
        hits += evidence is not None
    assert hits <= _binomial_upper(n, ENGINE_BOUND)


# --- T10: every new probe matches a closed template ---------------------------------

_TEMPLATES = [
    r"1 AND 1=[12]", r"1", r"fz[0-9a-f]{6}", r"1fz[0-9a-f]{6}",
    r"fz[0-9a-f]{6}' AND '(q[0-9a-f]{6})' LIKE '\1",
    r"fz[0-9a-f]{6}' AND '(q[0-9a-f]{6})' LIKE \1'",
    r"1' AND '(q[0-9a-f]{6})' LIKE '\1",
    r"1' AND '(q[0-9a-f]{6})' LIKE '(?!\1)q[0-9a-f]{6}",
    r"0'\+\(SELECT [1-9]\d{2}\*[1-9]\d{2}\)\+'0",
    r"'", r'"', r"'\)", r"1'",                                # SqliError's own probes
]


class _Recorder:
    def __init__(self, inner):
        self.inner, self.values = inner, []

    def send(self, url, param, value, **kw):
        self.values.append(value)
        return self.inner.send(url, param, value, **kw)


def test_every_new_sqli_probe_matches_its_closed_template_exactly():
    values = []
    for seed in range(200):           # 200 seeded draws: the runtime cap (reviewer B)
        for shape in ("sqli_11", "sqli_14", "code", "sqli_12", "lab_like"):
            rec = _Recorder(_SqliteSite(shape))
            SqliBooleanStrategy().confirm(CAND, rec, rng=random.Random(seed))
            SqliEvaluationMarkerStrategy().confirm(CAND, rec)
            if seed < 20:
                SqliErrorStrategy().confirm(CAND, rec)
            values += rec.values
    for value in set(values):
        assert sum(bool(re.fullmatch(t, value)) for t in _TEMPLATES) == 1, value
        for token in re.findall(r"(?:fz|q)[0-9a-f]+", value):
            assert re.fullmatch(r"(fz|q)[0-9a-f]{6}", token), value
        for bad in ("\\", "--", "#", "/*", "||", ";"):
            assert bad not in value, value
        assert not re.search(r"\bOR\b", value, re.I), value
        assert not refuse_destructive(value), value


def test_the_grammar_pair_compiles_and_fails_as_designed():
    db = sqlite3.connect(":memory:")
    for _ in range(200):
        family = _families()[1]
        base = family.base()
        keep, disc = family.keep(base), family.disc(base)
        db.execute(f"SELECT 1 WHERE 'a' = '{keep}'")                   # V is valid SQL
        with pytest.raises(sqlite3.OperationalError):
            db.execute(f"SELECT 1 WHERE 'a' = '{disc}'")              # D never executes
        ev = _families()[2]
        db.execute(f"SELECT 1 WHERE 'a' = '{ev.keep('1')}'")
        db.execute(f"SELECT 1 WHERE 'a' = '{ev.disc('1')}'")


# --- T11: raw whole-body points get no string probes ---------------------------------

def test_whole_body_candidates_get_no_string_probes():
    rec = _Recorder(_Constant(_X))
    body = Candidate(URL, "body", method="POST", location="body",
                     category="sql-injection", content_type="application/json")
    SqliBooleanStrategy().confirm(body, rec, rng=random.Random(0))
    assert SqliEvaluationMarkerStrategy().confirm(body, rec) is None
    assert rec.values == ["1", "1 AND 1=1", "1 AND 1=2"] or set(rec.values) <= {
        "1", "1 AND 1=1", "1 AND 1=2"}
    assert len(rec.values) == 3


# --- T14-T22: false-positive classes -------------------------------------------------

class _Escaping(_SqliteSite):
    """Escapes by doubling the quote: the value stays a literal."""

    def send(self, url, param, value, **kw):
        return super().send(url, param, value.replace("'", "''"), **kw)


class _QuoteValidator:
    def send(self, url, param, value, **kw):
        if "'" in value:
            return Probe(400, "<p>Invalid characters</p>")
        return Probe(200, "<p>No results</p>")


class _Reflecting:
    """Reflects the value in many encodings, and the previous value too."""

    def __init__(self):
        self.last = ""

    def send(self, url, param, value, **kw):
        page = (f"<p>You searched {html.escape(value)} / {value.replace(chr(39), '&#39;')}"
                f" / {value.replace(chr(39), '&#x27;')} (last: {html.escape(self.last)})"
                f"</p>")
        self.last = value
        return Probe(200, page)


class _Shell:
    def send(self, url, param, value, **kw):
        try:
            words = shlex.split(f"grep {value} file.txt")
        except ValueError:
            return Probe(200, "<p>sh: syntax error</p>")
        return Probe(200, f"<p>{len(words)} words</p>")


class _XPath:
    def send(self, url, param, value, **kw):
        doc = ET.fromstring("<r><m t='Iron Man'/></r>")
        try:
            hits = doc.findall(f".//m[@t='{value}']")
        except SyntaxError:
            return Probe(200, "<p>XPath error</p>")
        return Probe(200, f"<p>{len(hits)} hits</p>")


class _Hash:
    def send(self, url, param, value, **kw):
        return Probe(200, f"<p>{md5(value.encode()).hexdigest()}</p>")


class _Guestbook:
    """An escaped guestbook: every request adds a row, every response lists all."""

    def __init__(self):
        self.rows = []

    def send(self, url, param, value, **kw):
        self.rows.append(html.escape(value))
        return Probe(200, "".join(f"<li>{r}</li>" for r in self.rows))


class _RateLimited:
    def __init__(self, inner, k):
        self.inner, self.k, self.n = inner, k, 0

    def send(self, url, param, value, **kw):
        self.n += 1
        if self.n >= self.k:
            return Probe(429, "<p>Too many requests</p>")
        return self.inner.send(url, param, value, **kw)


@pytest.mark.parametrize("make", [
    lambda: _Escaping("sqli_14"), lambda: _Escaping("sqli_11"), _QuoteValidator,
    _Reflecting, _Shell, _XPath, _Hash, _Guestbook,
    lambda: _RateLimited(_SqliteSite("sqli_14"), 8)],
    ids=["escape-14", "escape-11", "validator", "reflection", "shell", "xpath", "hash",
         "guestbook", "429"])
def test_false_positive_classes_are_not_confirmed(make):
    for seed in range(5):
        assert SqliBooleanStrategy().confirm(CAND, make(), rng=random.Random(seed)) is None


def test_evaluation_marker_rejects_reflection_and_evaluation_that_also_reflects():
    assert SqliEvaluationMarkerStrategy().confirm(CAND, _Reflecting()) is None

    class EvalAndReflect:
        def send(self, url, param, value, **kw):
            m = re.search(r"(\d+)\*(\d+)", value)
            return Probe(200, f"<p>{value} = {int(m[1]) * int(m[2])}</p>")
    assert SqliEvaluationMarkerStrategy().confirm(CAND, EvalAndReflect()) is None


# --- T25 / T26: cost --------------------------------------------------------------------

class _Counter:
    def __init__(self, inner):
        self.inner, self.n = inner, 0

    def send(self, url, param, value, **kw):
        self.n += 1
        return self.inner.send(url, param, value, **kw)


@pytest.mark.parametrize("make", [
    lambda: _Constant(_X), _Reflecting, lambda: _SqliteSite("lab_like", secure=True),
    lambda: _QuoteValidator()], ids=["constant", "reflecting", "secure", "quote-error"])
def test_a_candidate_whose_screens_all_fail_costs_at_most_ten_requests(make):
    counter = _Counter(make())
    SqliBooleanStrategy().confirm(CAND, counter, rng=random.Random(0))
    SqliEvaluationMarkerStrategy().confirm(CAND, counter)
    assert counter.n <= 10


class _NumericThenBreaks:
    """Injectable in the numeric family until its ``n``-th D, which answers like B;
    string values run on sqli_14."""

    def __init__(self, n):
        self.n, self.d, self.site = n, 0, _SqliteSite("sqli_14")

    def send(self, url, param, value, **kw):
        if value in ("1", "1 AND 1=1"):
            return Probe(200, _Y)
        if value == "1 AND 1=2":
            self.d += 1
            return Probe(200, _Y if self.d >= self.n else _X)
        return self.site.send(url, param, value, **kw)


def test_sqli_boolean_never_exceeds_its_hard_cap():
    cap = SqliBooleanStrategy.HARD_CAP
    assert cap == 10 * len(SqliBooleanStrategy._FAMILIES)
    # non-vacuous: numeric fails at round 3 (9 requests); string-grammar confirms (21)
    counter = _Counter(_NumericThenBreaks(3))
    verdict = SqliBooleanStrategy().confirm(CAND, counter, rng=random.Random(1))
    assert verdict.confirmed and verdict.evidence["family"] == "string-grammar"
    assert counter.n == cap == 30 == verdict.evidence["requests"]
    for name, make in list(_noise_senders([0]))[:200] + [
            ("sqli_14", lambda: _SqliteSite("sqli_14")),
            ("code", lambda: _SqliteSite("code"))]:
        for strategy, limit in ((SqliErrorStrategy(), SqliErrorStrategy.MAX_REQUESTS),
                                (SqliBooleanStrategy(), cap),
                                (SqliEvaluationMarkerStrategy(),
                                 SqliEvaluationMarkerStrategy.MAX_REQUESTS)):
            counter = _Counter(make())
            strategy.confirm(CAND, counter)
            assert counter.n <= limit, (name, type(strategy).__name__)
    assert (SqliErrorStrategy.MAX_REQUESTS, SqliEvaluationMarkerStrategy.MAX_REQUESTS) \
        == (6, 2)


def test_cap_exhaustion_is_an_inconclusive_verdict_naming_the_families_not_started():
    counter = _Counter(_NumericThenBreaks(7))               # numeric fails at round 7
    verdict = SqliBooleanStrategy().confirm(CAND, counter, rng=random.Random(2))
    assert counter.n == FAMILY_COST == 21
    assert verdict is not None and not verdict.confirmed and verdict.inconclusive
    assert verdict.evidence["families_not_started"] == ["string-grammar",
                                                        "string-evaluation"]


def test_an_unconfirmed_candidate_with_no_passing_screen_is_not_inconclusive():
    assert SqliBooleanStrategy().confirm(CAND, _Constant(_X), rng=random.Random(0)) is None


# --- the oracle's outcome channel ------------------------------------------------------

def test_oracle_reports_inconclusive_only_when_nothing_confirms():
    oracle = Oracle(strategies=[SqliBooleanStrategy()])
    verdict, unsure = oracle.confirm_outcome(CAND, _NumericThenBreaks(7))
    assert verdict is None and unsure is not None and unsure.inconclusive
    assert oracle.confirm(CAND, _NumericThenBreaks(7)) is None       # thin wrapper

    class Confirms(ConfirmationStrategy):
        vuln_class, mechanism, category = "sqli", "always", "sql-injection"

        def confirm(self, candidate, sender):
            return Verdict(True, "sqli", self.mechanism)
    verdict, unsure = Oracle(strategies=[SqliBooleanStrategy(), Confirms()]) \
        .confirm_outcome(CAND, _NumericThenBreaks(7))
    assert verdict is not None and unsure is None


def test_other_non_confirming_verdicts_are_still_ignored():
    class Declines(ConfirmationStrategy):
        vuln_class, mechanism, category = "sqli", "declines", "sql-injection"

        def confirm(self, candidate, sender):
            return Verdict(False, "sqli", self.mechanism, {"why": "no"})
    assert Oracle(strategies=[Declines()]).confirm_outcome(CAND, _Constant(_X)) \
        == (None, None)


# --- T12, T27: the PA-0002 sweep -------------------------------------------------------

def test_file_inclusion_marker_needs_absence_in_a_control():
    always = _Constant("root:x:0:0:root:/root:/bin/bash")
    cand = Candidate(URL, "file", category="file-inclusion")
    assert PathTraversalStrategy().confirm(cand, always) is None

    class Real:
        def send(self, url, param, value, **kw):
            return Probe(200, "root:x:0:0:root:/root:/bin/bash" if ".." in value
                         else "<p>not found</p>")
    assert PathTraversalStrategy().confirm(cand, Real())


@pytest.fixture(scope="module")
def dense_page():
    """Every number from 10000 to 999999 (about 7 MB): any product appears."""
    return " ".join(str(n) for n in range(100, 999999))


def test_ssti_and_spel_markers_need_a_two_sample_cross_check(dense_page):
    dense = _Constant(dense_page)
    ssti = Candidate(URL, "name", category="server-side-template-injection")
    spel = Candidate(URL, "expr", category="spel-injection")
    assert SstiStrategy().confirm(ssti, dense) is None
    assert SpelInjectionStrategy().confirm(spel, dense) is None

    class Jinja:
        def send(self, url, param, value, **kw):
            m = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", value)
            return Probe(200, f"<p>Hello {int(m[1]) * int(m[2])}</p>" if m
                         else f"<p>Hello {html.escape(value)}</p>")

    class Spel:
        def send(self, url, param, value, **kw):
            m = re.fullmatch(r"T\(java\.lang\.Math\)\.abs\(-(\d+)\)", value)
            return Probe(200, f"<p>{m[1]}</p>" if m else "<p>?</p>")
    assert SstiStrategy().confirm(ssti, Jinja())
    assert SpelInjectionStrategy().confirm(spel, Spel())
    assert GoTemplateSstiStrategy._contains_token("a 142 b", 142)


# --- T24: sqli_12's real form; C's `+` on the wire ------------------------------------

_SQLI12_FORM = """
<form action="/bWAPP/sqli_12.php" method="POST">
  <textarea name="entry"></textarea>
  <button type="submit" name="entry_add" value="add">Add Entry</button>
  <button type="submit" name="entry_delete" value="delete">Delete Entries</button>
</form>"""


def test_bwapp_sqli12_form_sends_entry_add_and_never_entry_delete():
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    from fuzzlab.tools.store_adapter import form_skip_reason
    form = BeautifulSoup(_SQLI12_FORM, "html.parser").form
    record = form_record(form, "http://127.0.0.1:8090/bWAPP/sqli_12.php")
    entries = [tuple(e) for e in record["entries"]]
    assert [n for n, _v in entries] == ["entry", "entry_add"]
    assert ("entry_add", "add") in entries
    assert form_skip_reason(record) is None

    class Rec(_SqliteSite):
        def __init__(self):
            super().__init__("sqli_12")
            self.entries = []

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None):
            self.entries.append(list(entries or []))
            return super().send(url, param, value)
    site = Rec()
    cand = Candidate("http://127.0.0.1:8090/bWAPP/sqli_12.php", "entry", method="POST",
                     location="body", category="sql-injection",
                     base_entries=tuple(entries))
    assert Oracle(strategies=[SqliEvaluationMarkerStrategy()]).confirm(cand, site)
    assert site.entries and all(("entry_add", "add") in e for e in site.entries)
    assert not any(n == "entry_delete" for e in site.entries for n, _v in e)


def test_evaluation_marker_plus_reaches_the_wire_as_2B():
    """Every probe sender form-encodes the value, so C's ``+`` is ``%2B`` on the wire
    and decodes back to the exact payload (a raw ``+`` would decode to a space)."""
    import requests

    value = SqliEvaluationMarkerStrategy._value(123, 456)
    for location in ("query", "body"):
        prepared = requests.Request(
            "POST" if location == "body" else "GET", URL,
            params={"entry": value} if location == "query" else None,
            data=[("entry", value), ("entry_add", "add")] if location == "body"
            else None).prepare()
        wire = urlsplit(prepared.url).query if location == "query" else prepared.body
        assert wire.count("%2B") == value.count("+") == 2      # C's `+`, encoded
        assert dict(parse_qsl(wire))["entry"] == value          # decodes back exactly


# --- T28: writes on an INSERT sink -----------------------------------------------------

def _rows(site):
    return site.db.execute("SELECT COUNT(*) FROM blog").fetchone()[0]


def test_write_counts_on_an_insert_sink_match_the_stated_table():
    site = _SqliteSite("sqli_12")
    oracle = Oracle(strategies=[s for s in default_strategies()
                                if s.category == "sql-injection"
                                and not isinstance(s, SqliTimingStrategy)])
    assert oracle.confirm(CAND, site)
    # SqliError: `"` is valid SQL (1 row); `'`, `')`, `1'` fail, and "Error: HY000" is
    # no signature, so no control is sent. Boolean: every screen fails on a growing
    # listing: numeric 3 + grammar 2 (D never executes) + evaluation 3. C: 2.
    assert _rows(site) == 1 + 3 + 2 + 3 + 2 == 11

    class AlwaysDifferential(_SqliteSite):
        """Writes every probe and answers so every screen and round passes."""

        def send(self, url, param, value, **kw):
            super().send(url, param, value, **kw)
            disc = value.endswith(("1=2",)) or re.search(r"LIKE q[0-9a-f]{6}'$", value) \
                or re.search(r"'(q[0-9a-f]{6})' LIKE '(?!\1)", value)
            return Probe(200, _X if disc else _Y)
    site = AlwaysDifferential("sqli_12")
    for strategy in (SqliErrorStrategy(), SqliBooleanStrategy(),
                     SqliEvaluationMarkerStrategy()):
        strategy.confirm(CAND, site)
    assert _rows(site) <= 6 + 30 + 2


# --- pipeline: an inconclusive key is unlabelled, never a negative ---------------------

@pytest.mark.parametrize("budgeted", [False, True])
def test_cap_exhaustion_is_inconclusive_never_a_negative(tmp_path, budgeted, capsys):
    from fuzzlab.core.runmode import RunPlan
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import run_pipeline
    from fuzzlab.ml.active import Prioritized
    from fuzzlab.ml.dataset import build_dataset

    plan = RunPlan(mode="manual", categories=["sql-injection"], scored=False,
                   source="manual")
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8090")
        evidence = json.dumps({"url": URL, "param": "title", "category": "sql-injection",
                               "method": "GET", "location": "query"})
        for _ in range(2):                                  # two rows, one key
            store.conn.execute("INSERT INTO candidate (run_id, rule, evidence) "
                               "VALUES (?,?,?)", (run_id, "R", evidence))
        store.conn.commit()
        kw = ({"confirm_budget": 5,
               "prioritizer": lambda s, r, ids: Prioritized(order=list(ids), method="stub")}
              if budgeted else {})
        sender = _NumericThenBreaks(7)
        result = run_pipeline([], store, run_id, sender, plan, **kw)
        rows = store.conn.execute("SELECT oracle_status, evidence FROM candidate "
                                  "WHERE run_id=?", (run_id,)).fetchall()
        assert [r["oracle_status"] for r in rows] == [INCONCLUSIVE, INCONCLUSIVE]
        assert all(r["evidence"] == evidence for r in rows)     # the row is untouched
        assert INCONCLUSIVE in UNLABELLED and CHECKED not in UNLABELLED
        m = result.metrics
        assert m["oracle_inconclusive"] == 2 and m["oracle_rejected"] == 0
        assert m["oracle_checked_keys"] == 1 and result.findings == 0
        assert result.inconclusive == [{
            "url": URL, "param": "title", "location": "query",
            "mechanism": "boolean-differential",
            "families_not_started": ["string-grammar", "string-evaluation"]}]
        assert build_dataset(store, run_id).ids == []           # never a training label
        stored = {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,))}
        assert stored["pipeline_oracle_inconclusive"] == 2.0


# --- what each engine and marker check is for (mutation-checked) -----------------------

class _ReflectingSqli14(_SqliteSite):
    """sqli_14 that also echoes the submitted title: injectable, and reflecting."""

    def __init__(self):
        super().__init__("sqli_14")

    def send(self, url, param, value, **kw):
        probe = super().send(url, param, value, **kw)
        return Probe(probe.status, probe.text.replace(
            "<p>", f"<p>You searched for {html.escape(value)}. ", 1))


def test_an_injectable_page_that_reflects_the_value_still_confirms():
    """Reflection stripping is what lets a reflecting page confirm (V must equal B)."""
    for seed in range(3):
        v = SqliBooleanStrategy().confirm(CAND, _ReflectingSqli14(), rng=random.Random(seed))
        assert v and v.evidence["family"] == "string-grammar"


class _StatusOnly(_SqliteSite):
    """Errors render the very same body, only with status 500."""

    def __init__(self):
        super().__init__("sqli_14")

    def send(self, url, param, value, **kw):
        probe = super().send(url, param, value, **kw)
        if "Incorrect syntax" in probe.text:
            return Probe(500, HEAD + "<p>The movie does not exist in our database!</p>"
                              "</body></html>")
        return probe


def test_a_status_only_differential_confirms():
    assert SqliBooleanStrategy().confirm(CAND, _StatusOnly(), rng=random.Random(0))


class _DriftingBaseline(_SqliteSite):
    """Injectable, but the base value's own page changes after its first request
    (a "first visit" banner): the re-sent baseline no longer matches B0."""

    def __init__(self):
        super().__init__("sqli_14")
        self.seen: set[str] = set()

    def send(self, url, param, value, **kw):
        probe = super().send(url, param, value, **kw)
        if value in self.seen and re.fullmatch(r"fz[0-9a-f]{6}|1", value):
            return Probe(probe.status, probe.text + "<p>Welcome back</p>")
        self.seen.add(value)
        return probe


def test_a_baseline_that_drifts_fails_the_bracket():
    for seed in range(3):
        assert SqliBooleanStrategy().confirm(CAND, _DriftingBaseline(),
                                             rng=random.Random(seed)) is None


class _FreshErrorEachTime:
    """V looks like B; every D is a different page, in content and in length."""

    def __init__(self):
        self.n = 0

    def send(self, url, param, value, **kw):
        if value.endswith("'") or value.endswith("1=2"):
            self.n += 1
            return Probe(200, "<p>Error " + "e" * (200 * self.n) + "</p>")
        return Probe(200, _X)


def test_d_responses_must_agree_with_each_other():
    for seed in range(3):
        v = SqliBooleanStrategy().confirm(CAND, _FreshErrorEachTime(),
                                          rng=random.Random(seed))
        assert v is None or (not v.confirmed and v.inconclusive)


def test_corroboration_lists_only_what_the_baseline_did_not_show():
    class Footer(_SqliteSite):
        def send(self, url, param, value, **kw):
            probe = super().send(url, param, value, **kw)
            return Probe(probe.status, probe.text + "<footer>last error: HY000</footer>")
    v = SqliBooleanStrategy().confirm(CAND, Footer("sqli_11"), rng=random.Random(0))
    assert v and v.evidence["corroboration"] == []


class _FirstReplyCached:
    """A cache keyed on the path: every request gets the first response."""

    def __init__(self):
        self.first = None

    def send(self, url, param, value, **kw):
        if self.first is None:
            m = re.search(r"(\d+)\*(\d+)", value)
            self.first = Probe(200, f"<p>{int(m[1]) * int(m[2])}</p>")
        return self.first


class _LiteralOnceThenEvaluates:
    """Evaluates every product, but shows the first submission's literal text too."""

    def __init__(self):
        self.n = 0

    def send(self, url, param, value, **kw):
        self.n += 1
        m = re.search(r"(\d+)\*(\d+)", value)
        echo = f" ({m[1]}*{m[2]})" if self.n == 1 else ""
        return Probe(200, f"<p>{int(m[1]) * int(m[2])}{echo}</p>")


def test_evaluation_marker_needs_both_samples_and_no_literal_in_either():
    assert SqliEvaluationMarkerStrategy().confirm(CAND, _FirstReplyCached()) is None
    assert SqliEvaluationMarkerStrategy().confirm(CAND, _LiteralOnceThenEvaluates()) is None
