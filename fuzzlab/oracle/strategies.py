"""Per-class confirmation strategies (Phase 2 T2.1).

Each strategy declares its `vuln_class` and the `mechanism` it uses, and confirms a
candidate deterministically or returns None (fail-closed — never a guess). New
classes are added as new strategies (and, later, plugin `register_oracle` hooks).
"""

from __future__ import annotations

import re
import secrets

from fuzzlab.oracle.baseline import build_baseline
from fuzzlab.oracle.context import breakout_for, is_unescaped, type_reflection
from fuzzlab.oracle.probe import Candidate, Sender, Verdict

# --- error signatures (M2) ---------------------------------------------------
SQL_ERROR_SIGNATURES = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
    (re.compile(r"warning:\s*mysqli?_", re.I), "MySQL"),
    (re.compile(r"sql syntax.*mariadb", re.I), "MariaDB"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    (re.compile(r"pg_query\(\)|postgresql.*error|syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"sqlite_error|sqlite3?::|unrecognized token", re.I), "SQLite"),
]

# --- timing templates (M1); {d} = requested delay in seconds ------------------
_TIMING_TEMPLATES = [
    "1 AND (SELECT 1 FROM (SELECT(SLEEP({d})))x)",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP({d})))x)-- -",
    "1) AND (SELECT 1 FROM (SELECT(SLEEP({d})))x)-- -",
    "1' OR SLEEP({d})-- -",
]


def _token() -> str:
    return secrets.token_hex(4)


class ConfirmationStrategy:
    vuln_class: str = ""
    mechanism: str = ""

    def applies(self, candidate: Candidate) -> bool:
        return candidate.vuln_class in (None, self.vuln_class)

    def confirm(self, candidate: Candidate, sender: Sender) -> Verdict | None:  # pragma: no cover
        raise NotImplementedError


class SqliErrorStrategy(ConfirmationStrategy):
    vuln_class = "sqli"
    mechanism = "error-signature"
    _probes = ("'", '"', "')", "1'")

    def confirm(self, candidate, sender):
        for payload in self._probes:
            probe = sender.send(candidate.url, candidate.param, payload)
            for rx, dbms in SQL_ERROR_SIGNATURES:
                match = rx.search(probe.text or "")
                if match:
                    return Verdict(True, self.vuln_class, self.mechanism,
                                   {"dbms": dbms, "payload": payload,
                                    "match": match.group(0)[:120]})
        return None


class SqliBooleanStrategy(ConfirmationStrategy):
    vuln_class = "sqli"
    mechanism = "boolean-differential"

    @staticmethod
    def _similar(a: str, b: str, rel: float = 0.05, absolute: int = 24) -> bool:
        return abs(len(a) - len(b)) <= max(absolute, rel * max(len(a), len(b), 1))

    def confirm(self, candidate, sender):
        benign = sender.send(candidate.url, candidate.param, "1")
        true_p = sender.send(candidate.url, candidate.param, "1 AND 1=1")
        false_p = sender.send(candidate.url, candidate.param, "1 AND 1=2")
        # A true condition looks like the benign page; a false condition does not.
        if self._similar(benign.text, true_p.text) and not self._similar(true_p.text, false_p.text):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"len_benign": len(benign.text), "len_true": len(true_p.text),
                            "len_false": len(false_p.text)})
        return None


class SqliTimingStrategy(ConfirmationStrategy):
    vuln_class = "sqli"
    mechanism = "differential-timing"
    delays = (2, 4)
    baseline_samples = 3
    k = 3.0
    floor = 1.5           # seconds of added delay required above baseline
    tolerance = 0.6       # measured latency may fall this far short of the request

    def confirm(self, candidate, sender):
        base = build_baseline([
            sender.send(candidate.url, candidate.param, "1", timing=True).elapsed
            for _ in range(self.baseline_samples)
        ])
        for template in _TIMING_TEMPLATES:
            measured, ok = {}, True
            for d in self.delays:
                probe = sender.send(candidate.url, candidate.param,
                                    template.format(d=d), timing=True)
                measured[d] = probe.elapsed
                if not base.exceeds(probe.elapsed, k=self.k, floor=self.floor):
                    ok = False
                    break
                if probe.elapsed < d - self.tolerance:      # latency tracks the request
                    ok = False
                    break
            # Rising-delay: more requested delay -> more measured latency.
            if ok and measured[self.delays[-1]] > measured[self.delays[0]]:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"baseline_median": round(base.median, 4),
                                "measured": {str(k): round(v, 4) for k, v in measured.items()},
                                "template": template})
        return None


class ReflectedXssStrategy(ConfirmationStrategy):
    vuln_class = "xss-reflected"
    mechanism = "reflected-context"

    def confirm(self, candidate, sender):
        token = _token()
        marker = f"zqxm{token}"
        first = sender.send(candidate.url, candidate.param, marker)
        context = candidate.sink_context or type_reflection(first.text, marker)
        if context == "none":
            return None
        breakout = breakout_for(context, f"zqxb{token}")
        if breakout is None:
            return None
        fragment, signature = breakout
        second = sender.send(candidate.url, candidate.param, fragment)
        if is_unescaped(second.text, signature):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"context": context, "signature": signature})
        return None


def default_strategies() -> list[ConfirmationStrategy]:
    """Cheapest/strongest first: error signature, boolean, timing, then XSS."""
    return [SqliErrorStrategy(), SqliBooleanStrategy(), SqliTimingStrategy(),
            ReflectedXssStrategy()]


# Reference-style category -> the oracle vuln_class we currently have a strategy for.
# Categories absent here have no confirmer yet (candidate emitted, not confirmed).
_CATEGORY_TO_CLASS = {"sql-injection": "sqli", "xss": "xss-reflected"}


def category_to_oracle_class(category: str) -> str | None:
    return _CATEGORY_TO_CLASS.get(category)
