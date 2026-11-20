"""Per-class confirmation strategies (Phase 2 T2.1).

Each strategy declares its `vuln_class` and the `mechanism` it uses, and confirms a
candidate deterministically or returns None (fail-closed — never a guess). New
classes are added as new strategies (and, later, plugin `register_oracle` hooks).
"""

from __future__ import annotations

import base64
import html
import itertools
import re
import secrets
from dataclasses import dataclass
from fractions import Fraction
from typing import Callable
from urllib.parse import quote, quote_plus

from fuzzlab.core import trace
from fuzzlab.oracle.baseline import build_baseline
from fuzzlab.oracle.browser import (
    SENTINEL,
    BrowserExecutor,
    ExecObservation,
    ExecRequest,
    NotObserved,
    StoreStep,
)
from fuzzlab.greybox.confirm import greybox_confirms, m10_evidence
from fuzzlab.greybox.coverage import CoverageSource, app_lines, endpoint_file
from fuzzlab.greybox.dbfault import DbFaultSource
from fuzzlab.greybox.reward import GreyboxSignal
from fuzzlab.oracle.context import (locate_reflection, split_form_control_values,
                                    xss_breakouts)
from fuzzlab.oracle.oob import OobListener
from fuzzlab.core.comparability import APPLICATION, POLICY_BLOCK
from fuzzlab.oracle.probe import (APPLICATION_ONLY, PRG_UNOBSERVED, Candidate, NotComparable,
                                  Probe, ProbeUnobserved, Sender, UnplaceableLocation,
                                  Verdict, require_comparable, require_observed)

#: What a control may answer when its strategy declares the application's own denial a
#: comparable answer too (FR-FUZZ-63): an API that hides a foreign id with 403 (the
#: cross-account control), a SQL family's D whose characters V shares (no lexical filter
#: can single it out).
APPLICATION_OR_POLICY = frozenset({APPLICATION, POLICY_BLOCK})

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

#: Each template's structural control (FR-FUZZ-711, BUG-0733): the same group, the same
#: character class and the same `$` anchor, minus the nested or ambiguous quantifier
#: that makes the template catastrophic -- the probe minus what it tests (PA-0117(1),
#: PA-0630(1)). A backtracking engine runs each control in linear time per start
#: position, so anything the target does with *a* regex of this shape and length
#: (compiling it, scanning its content, an error path) is on both sides, and only the
#: ambiguity is not. Shapes: OWASP, "Regular expression Denial of Service - ReDoS"
#: ("Evil Regexes": `(a+)+`, `([a-zA-Z]+)*`, `(a|aa)+`, `(a|a?)+`); CWE-1333; Davis et
#: al., "The Impact of Regular Expression Denial of Service (ReDoS) in Practice"
#: (ESEC/FSE 2018: nested quantifiers and quantified overlapping alternation).
_REDOS_CONTROLS = {
    r"(a+)+$": r"(a+)$",
    r"(a|a)*$": r"(a)*$",
    r"(a|aa)+$": r"(a)+$",
    r"([a-zA-Z]+)*$": r"([a-zA-Z])*$",
    r"(\d+)+$": r"(\d)+$",
}

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


def _contains_number(text: str, n: int) -> bool:
    """``n`` appears in ``text`` as a whole decimal token (``142`` not inside
    ``31420``) -- the digit-bounded rule every evaluation marker uses."""
    return re.search(rf"(?<!\d){n}(?!\d)", text or "") is not None


def _echo(text: str, literal: str) -> tuple[bool, bool, list[str]]:
    """``(present, outside, rest)`` for an evaluation probe's own ``literal`` in a page
    (BUG-0133). Judged on the parsed page (`split_form_control_values`), so an
    entity-encoded echo counts too, and on the raw text: a raw occurrence the parser
    shows in no form control is outside. ``rest`` is every part outside the form
    controls."""
    text = text or ""
    controls, rest = split_form_control_values(text)
    in_controls = any(literal in part for part in controls)
    outside = any(literal in part for part in rest) or (literal in text and not in_controls)
    return outside or in_controls, outside, rest


def _echoed_outside_form_controls(text: str, literal: str) -> bool:
    """Does the page show ``literal`` (an evaluation probe's own expression) anywhere
    but in a form control's value? An echo there is the sink reflecting the input, so
    a number beside it is not evidence of evaluation ("evaluated, not just reflected",
    M4 since its first version). An echo **only** in an ``<input value>``, a
    ``<textarea>`` or a selected ``<option>`` is an edit form showing the stored value
    back, not that sink (BUG-0133)."""
    return _echo(text, literal)[1]


def _evaluated(text: str, literal: str, n: int) -> bool:
    """An evaluation marker's test (M4 and its kin, BUG-0133): ``n`` appears as a whole
    number and the probe's ``literal`` is not echoed outside form controls. When the
    literal is in the page at all, ``n`` must appear outside every form control (and so
    outside every literal occurrence: SpEL's literal holds its own canary). With no
    literal in the page the rule is the old one. The probe-causality checks (a second
    value, BUG-0117) are the callers'."""
    present, outside, rest = _echo(text, literal)
    if not present:
        return _contains_number(text or "", n)
    if outside:
        return False
    return any(_contains_number(part, n) for part in rest)


# --- the bracketed, replicated response differential (FR-FUZZ-45 (a)) ----------
#: The screen sends V and D in one of these orders; each later round sends V, D and
#: a re-sent baseline B in one of the six permutations. Exactly one draw per round,
#: from these fixed tables (the bound below is computed over exactly these draws).
_SCREEN_ORDERS = (("V", "D"), ("D", "V"))
_ROUND_ORDERS = tuple(itertools.permutations(("V", "D", "B")))
#: Rounds after the screen.
ENGINE_ROUNDS = 6
#: Requests one family spends to confirm: B0 + the screen (2) + 3 per later round.
FAMILY_COST = 3 + 3 * ENGINE_ROUNDS
#: For any response sequence that does not depend on the probe values (fixed before
#: the engine's draws) and any comparison predicate: a round passes only when the
#: one slot whose response is not ``same`` as B0 is the slot the draw gave D, so at
#: most 1 of 2 screen orders and 2 of 6 round orders pass. P[confirm] <= this.
ENGINE_BOUND = Fraction(1, 2) * Fraction(1, 3) ** ENGINE_ROUNDS      # = 1/1458


def _engine_rng():
    """The engine's order source (tests monkeypatch it). Tokens never come from it."""
    return secrets.SystemRandom()


def _reflection_forms(value: str) -> set[str]:
    """``value`` as a page may echo it: raw, HTML-escaped, quote-entity or
    quote-doubled/backslashed, and URL-encoded."""
    forms = {value, html.escape(value, quote=True), html.escape(value, quote=False),
             quote(value), quote_plus(value), quote(value, safe="")}
    for rep_ in ("&#39;", "&#039;", "&#x27;", "&apos;", "\\'", "''"):
        forms.add(value.replace("'", rep_))
        forms.add(html.escape(value, quote=False).replace("'", rep_))
    forms.discard("")
    return forms


def _strip_forms(text: str, forms: list[str]) -> str:
    for form in forms:                       # longest first
        text = text.replace(form, "\x00")
    return text


def _strip_reflections(text: str, values: list[str]) -> str:
    """``text`` with every reflected form of ``values`` replaced by one placeholder,
    longest first (so a value never leaves a partial copy of a longer one)."""
    forms = set()
    for value in values:
        forms |= _reflection_forms(value)
    return _strip_forms(text, sorted(forms, key=len, reverse=True))


@dataclass(frozen=True)
class _Family:
    """One differential: a base value B, a value V that must look like B, and a
    value D that must not. ``keep``/``disc`` draw fresh tokens each round."""
    name: str
    base: Callable[[], str]
    keep: Callable[[str], str]          # (base) -> V
    disc: Callable[[str], str]          # (base) -> D
    exact: bool                         # True: `_same_page`; False: `_similar` lengths
    strings: bool                       # a string-literal probe (skipped on raw bodies)


def _observed(probe) -> Probe:
    """The response an opt-in strategy judges (FR-FUZZ-49, P4): the probe's PRG
    follow-up when the sender made one, **whole** (status, headers, body), else the
    probe itself. Never a mix of the two."""
    followed = getattr(probe, "followed", None)
    return followed if followed is not None else probe


def _via_prg(probe) -> bool:
    return getattr(probe, "followed", None) is not None


def _rode_the_redirect(probe, values: list[str]) -> bool:
    """Does the PRG follow-up's own URL carry one of ``values`` (the payload or its
    token), in any reflected form: raw, percent, form ``+``, HTML-entity or
    JSON-escaped (FR-FUZZ-49, P6)? Then the payload travelled in the redirect, not in
    stored state. Compared case-insensitively (``%3c`` / ``%3C``)."""
    import json
    url = (getattr(getattr(probe, "followed", None), "url", None) or "").lower()
    if not url:
        return False
    for value in values:
        forms = _reflection_forms(value) | {json.dumps(value)[1:-1]}
        if any(form and form.lower() in url for form in forms):
            return True
    return False


class ConfirmationStrategy:
    vuln_class: str = ""
    mechanism: str = ""
    category: str = ""
    #: FR-FUZZ-49 (P1): this strategy's whole run asks for post/redirect/get
    #: observation and reads `_observed(probe)`. Opt-in only: a strategy reading the
    #: raw 3xx (open redirect, header injection), timing or a differential engine never
    #: sets it (P7).
    prg: bool = False

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

    @classmethod
    def _compared(cls, sender: Sender, candidate: Candidate, value: str, *, role: str,
                  admits=APPLICATION_ONLY, timing: bool = False,
                  location: str | None = None, content_type: str | None = None,
                  credentialed: bool | None = None, label: str | None = None) -> Probe:
        """Send a response the strategy **compares** -- a control, a baseline sample, a
        differential slot, a replay -- and require it to be one its strategy admits
        (FR-FUZZ-63, SP-56: `require_comparable` on the response the strategy judges,
        `_observed`). Otherwise `NotComparable`: the mechanism gives no verdict. Marks the
        send's ``role`` (FR-FUZZ-60). ``location``/``content_type`` place a raw body
        (NoSQL's JSON); ``credentialed`` overrides the probe's own fact (a replay's
        sender is known by its role); ``label`` names it in the reason.

        Layer 1 (`require_observed`, FR-FUZZ-63, FR-FUZZ-65) is applied here too, before
        the class is read: the oracle wraps only the run's own sender in `_ObservedOnly`,
        and a compared send may go through another one (a cross-account replay's peer or
        anonymous sender). So an answer to a request sent on a session known to be lost
        is not comparable whichever sender made it (CC-FUZZ-0107)."""
        with trace.role(role):
            if location is not None or content_type is not None:
                probe = sender.send(candidate.url, candidate.param, value, timing=timing,
                                    method=candidate.method,
                                    location=location or candidate.location,
                                    content_type=content_type)
            else:
                probe = cls._send(sender, candidate, value, timing=timing)
        require_observed(probe, timing=timing)
        judged = _observed(probe)
        if credentialed is None and getattr(judged, "credentialed", None) is None:
            # a PRG follow-up is sent by the same sender as its request: its fact
            credentialed = getattr(probe, "credentialed", None)
        require_comparable(judged, url=candidate.url, candidate=candidate,
                           role=label or role, admits=admits, credentialed=credentialed)
        return probe

    # --- shared bracketed, replicated differential (FR-FUZZ-45 (a), PA-0117) ----
    @staticmethod
    def _similar(a: str, b: str, rel: float = 0.05, absolute: int = 24) -> bool:
        return abs(len(a) - len(b)) <= max(absolute, rel * max(len(a), len(b), 1))

    def _differential(self, sender: Sender, candidate: Candidate, family: _Family,
                      rng=None) -> tuple[dict | None, int]:
        """Run one family: B0, a screen (V and D in a drawn order), then
        ``ENGINE_ROUNDS`` rounds of (V, D, B) in a drawn permutation, with fresh tokens
        each round. Confirms only if every V and B is ``same`` as B0, every D is not,
        and every D is ``same`` as the first D. A round is judged after all of it is
        sent. Returns (evidence or None, requests sent).

        The bound (``ENGINE_BOUND``, 1/1458) holds over this engine's own draws for
        any probe-independent response sequence and any predicate; see the constant."""
        rng = rng if rng is not None else _engine_rng()
        base = family.base()
        sent_values: list[str] = [base]
        responses: dict[str, list[Probe]] = {"B": [], "V": [], "D": []}
        form_cache: dict[str, set[str]] = {}

        def send(value: str, slot: str) -> Probe:
            """Every slot is compared (FR-FUZZ-63): B and V are the engine's controls
            (application answers only); D admits a policy answer too -- each SQL family's
            V carries D's characters, so no lexical filter can single D out, and an app
            that answers a false condition with 403 is evaluating it."""
            if slot != "B":
                sent_values.append(value)
            return self._compared(sender, candidate, value, role=_SLOT_ROLE[slot],
                                  admits=_SLOT_ADMITS[slot])

        def judge():
            """A comparison for one decision point: every value sent so far (but the
            bare ``1``) is stripped, in all its reflected forms, from both sides."""
            if not family.exact:
                return lambda a, b: self._similar(a.text or "", b.text or "")
            forms: set[str] = set()
            for value in sent_values:
                if value != "1":
                    if value not in form_cache:
                        form_cache[value] = _reflection_forms(value)
                    forms |= form_cache[value]
            ordered = sorted(forms, key=len, reverse=True)
            memo: dict[int, str] = {}

            def norm(p: Probe) -> str:
                if id(p) not in memo:
                    memo[id(p)] = _strip_forms(p.text or "", ordered)
                return memo[id(p)]
            return lambda a, b: a.status == b.status and norm(a) == norm(b)

        b0 = send(base, "B")                          # FR-FUZZ-60: B0, the baseline
        count = 1
        order = rng.choice(_SCREEN_ORDERS)
        got, values = {}, {"V": family.keep(base), "D": family.disc(base)}
        for slot in order:
            got[slot] = send(values[slot], slot)
        count += 2
        same = judge()
        if not same(got["V"], b0) or same(got["D"], b0):
            return None, count
        d1 = got["D"]
        responses["V"].append(got["V"])
        responses["D"].append(d1)
        for _ in range(ENGINE_ROUNDS):
            order = rng.choice(_ROUND_ORDERS)
            got = {}
            for slot in order:
                got[slot] = send(base if slot == "B" else family.keep(base)
                                 if slot == "V" else family.disc(base), slot)
            count += 3
            same = judge()
            if (not same(got["V"], b0) or not same(got["B"], b0)
                    or same(got["D"], b0) or not same(got["D"], d1)):
                return None, count
            for slot in ("B", "V", "D"):
                responses[slot].append(got[slot])
        return {"family": family.name, "rounds": 1 + ENGINE_ROUNDS,
                "base": base, "keep": values["V"], "disc": values["D"],
                "status": {"base": b0.status, "keep": responses["V"][0].status,
                           "disc": d1.status},
                "len": {"base": len(b0.text or ""), "keep": len(responses["V"][0].text or ""),
                        "disc": len(d1.text or "")},
                "_d_texts": [p.text or "" for p in responses["D"]],
                "_b0_text": b0.text or ""}, count

    # --- shared rising-delay timing confirmation (M1) ------------------------
    delays = (2, 4)
    baseline_samples = 3
    k = 3.0
    floor = 1.5           # seconds of added delay required above baseline
    tolerance = 0.6       # measured latency may fall this far short of the request

    def _confirm_timing(self, candidate: Candidate, sender: Sender,
                        templates: list[str], baseline_value: str = "1") -> Verdict | None:
        """Confirm a time-based injection: latency must rise with the requested delay.

        Shared by SQLi (SQL SLEEP) and command injection (shell sleep). Robust
        baseline (median/MAD), a floor above jitter, and a rising-delay check across
        two requested delays — never one slow response.
        """
        # FR-FUZZ-60: the samples; FR-FUZZ-63: each an application answer, or the
        # mechanism gives no verdict (a fast refusal lowers the threshold; a timed-out
        # sample was never observed)
        base = build_baseline([
            self._compared(sender, candidate, baseline_value, role="baseline",
                           timing=True).elapsed
            for _ in range(self.baseline_samples)
        ])
        for template in templates:
            measured, ok = {}, True
            for d in self.delays:
                with trace.role("mutation"):
                    probe = self._send(sender, candidate, template.format(d=d),
                                       timing=True)
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


#: FR-FUZZ-60: what each differential slot is -- B the base value, V the benign variant
#: (a control: it must behave like the base), D the payload (the mutation).
_SLOT_ROLE = {"B": "baseline", "V": "control", "D": "mutation"}
#: FR-FUZZ-63: the classes each slot admits (see `ConfirmationStrategy._differential`).
_SLOT_ADMITS = {"B": APPLICATION_ONLY, "V": APPLICATION_ONLY, "D": APPLICATION_OR_POLICY}


def _signature(text: str):
    """The first SQL error signature in ``text``: (match, dbms) or None."""
    for rx, dbms in SQL_ERROR_SIGNATURES:
        match = rx.search(text or "")
        if match:
            return match, dbms
    return None


def _sqli_token() -> str:
    """A quote-free, non-numeric control or base value: ``fz`` + 6 hex. The ``fz``/``q``
    prefixes never form a SQL literal prefix or introducer (``X''``, ``B''``, ``N''``,
    ``E''``, ``U&''``, ``_charset''``, ``0x``), so the grammar D is always an
    identifier followed by a literal: a syntax error."""
    return "fz" + secrets.token_hex(3)


def _q_token() -> str:
    return "q" + secrets.token_hex(3)


class SqliErrorStrategy(ConfirmationStrategy):
    """M2: a quote makes the database report a syntax error.

    BUG-0117 / PA-0117: a signature counts only when it is **absent** from a benign
    control of the same point -- a quote-free, non-numeric token (and, for a
    digit-led probe, ``1`` + that token): a page that always shows ``Warning:
    mysql_num_rows()``, or a strict-mode INT column that errors on any non-numeric
    input, is not confirmed. At most 4 probes + 2 controls per candidate."""
    vuln_class = "sqli"
    mechanism = "error-signature"
    category = "sql-injection"
    prg = True                                       # FR-FUZZ-49
    _probes = ("'", '"', "')", "1'")
    MAX_REQUESTS = len(_probes) + 2

    def confirm(self, candidate, sender):
        """FR-FUZZ-49: each response is read as observed (`_observed`). A signature seen
        only through a PRG follow-up needs every control observed through its own
        follow-up too, without the signature: a control the app rejected (no
        follow-up) or a page that still shows it after the control is a refusal, and
        the verdict is flagged second-order.

        FR-FUZZ-63: each control is an application answer (`_compared`), or the
        mechanism gives no verdict. When the signature was seen through a follow-up and
        a control's own follow-up got no observation (`PRG_UNOBSERVED`), the controls
        were not observed alike: not comparable, never a negative (B2). A direct
        signature never needs a control's follow-up."""
        # value -> (signature, via PRG, follow-up unobserved)
        controls: dict[str, tuple[bool, bool, bool]] = {}
        token = _sqli_token()
        for payload in self._probes:
            with trace.role("mutation"):              # FR-FUZZ-60
                probe = self._send(sender, candidate, payload)
            found = _signature(_observed(probe).text)
            if found is None:
                continue
            needed = [token] + ([f"1{token}"] if payload[:1].isdigit() else [])
            for value in needed:
                if value not in controls:
                    control = self._compared(sender, candidate, value, role="control")
                    controls[value] = (_signature(_observed(control).text) is not None,
                                       _via_prg(control),
                                       getattr(control, "prg", None) == PRG_UNOBSERVED)
            if any(controls[v][0] for v in needed):
                return None                          # the signature is not the quote's
            prg = _via_prg(probe)
            if prg and not all(controls[v][1] for v in needed):
                if any(controls[v][2] for v in needed):
                    raise NotComparable(
                        "not comparable: the control's follow-up got no observation")
                return None                          # a control without its follow-up
            match, dbms = found
            evidence = {"dbms": dbms, "payload": payload,
                        "match": match.group(0)[:120], "controls": needed}
            if prg:
                evidence.update(observation="prg", second_order=True)
            return Verdict(True, self.vuln_class, self.mechanism, evidence)
        return None


def _numeric_family() -> _Family:
    return _Family("numeric", base=lambda: "1", keep=lambda b: "1 AND 1=1",
                   disc=lambda b: "1 AND 1=2", exact=False, strings=False)


def _grammar_keep(base: str) -> str:
    t = _q_token()
    return f"{base}' AND '{t}' LIKE '{t}"


def _grammar_disc(base: str) -> str:
    t = _q_token()
    return f"{base}' AND '{t}' LIKE {t}'"


def _evaluation_disc(base: str) -> str:
    t = _q_token()
    u = _q_token()
    while u == t:
        u = _q_token()
    return f"{base}' AND '{u}' LIKE '{t}"


#: The families, tried in this fixed order; the first to confirm wins.
_FAMILIES = (
    _numeric_family(),
    _Family("string-grammar", base=_sqli_token, keep=_grammar_keep,
            disc=_grammar_disc, exact=True, strings=True),
    _Family("string-evaluation", base=lambda: "1", keep=_grammar_keep,
            disc=_evaluation_disc, exact=True, strings=True),
)


class SqliBooleanStrategy(ConfirmationStrategy):
    """M3: a condition the database evaluates changes the page (FR-FUZZ-45 (a)(b)).

    Three families, each run by the bracketed, replicated engine
    (`ConfirmationStrategy._differential`):

    * ``numeric``: ``1`` / ``1 AND 1=1`` / ``1 AND 1=2``, lengths compared (`_similar`);
    * ``string-grammar``: ``v`` / ``v' AND 't' LIKE 't`` / ``v' AND 't' LIKE t'`` -- V
      and D have the same characters, length and quotes; only a SQL string tokenizer
      tells them apart (D is a syntax error). Needs no matching row;
    * ``string-evaluation``: ``1`` / ``1' AND 't' LIKE 't`` / ``1' AND 'u' LIKE 't``,
      for pages that render errors like "not found".

    ``'t' LIKE 't`` works in ``= '…'`` and ``LIKE '%…%'`` contexts alike. Every probe
    is quote-balanced and AND-only: no comment, ``OR``, ``||``, ``;`` or backslash.
    In a predicate context V selects the baseline's rows; in a value context
    (INSERT/UPDATE) V and the evaluation probes are written as a coerced value to the
    baseline's own row; the grammar D never executes.

    **Bound:** P[confirm] <= ``ENGINE_BOUND`` (1/1458) per family for any
    probe-independent response sequence, < 3/1458 per candidate.

    **Cost:** a family starts only when ``FAMILY_COST`` (21) requests remain under
    ``HARD_CAP`` (30); a candidate whose screens all fail costs 9. When the cap stops
    a later family from starting after an earlier one passed its screen, the verdict
    is **inconclusive** (unlabelled), never a negative. String families are skipped
    on a raw whole-body point."""
    vuln_class = "sqli"
    mechanism = "boolean-differential"
    category = "sql-injection"
    _FAMILIES = _FAMILIES
    HARD_CAP = 10 * len(_FAMILIES)

    def confirm(self, candidate, sender, rng=None):
        rng = rng if rng is not None else _engine_rng()
        spent, exhausted = 0, []
        for family in self._FAMILIES:
            if family.strings and candidate.content_type:
                continue
            if self.HARD_CAP - spent < FAMILY_COST:
                exhausted.append(family.name)
                continue
            evidence, cost = self._differential(sender, candidate, family, rng=rng)
            spent += cost
            if evidence is not None:
                d_texts, b0_text = evidence.pop("_d_texts"), evidence.pop("_b0_text")
                evidence["corroboration"] = sorted({
                    m for text in d_texts
                    for m in re.findall(r"\bHY000\b|SQLSTATE\[\w+\]", text)
                    if m not in b0_text})
                evidence["requests"] = spent
                return Verdict(True, self.vuln_class, self.mechanism, evidence)
        if exhausted:
            return Verdict(False, self.vuln_class, self.mechanism,
                           {"cap_exhausted": True, "families_not_started": exhausted,
                            "requests": spent}, inconclusive=True)
        return None


class SqliEvaluationMarkerStrategy(ConfirmationStrategy):
    """M4 for SQL (FR-FUZZ-45 (c)): ``0'+(SELECT a*b)+'0`` makes the database compute
    a product that the page then shows (a stored listing, sqli_12's shape).

    Probe 1's product must appear (digit-bounded) and its literal ``a*b`` must not;
    then probe 2, with a different product that was absent before, must likewise
    appear in the response to the probe that computed it (temporal attribution,
    PA-0090). ``(SELECT …)`` is not template, shell or script syntax; a bound or
    escaped sink stores the literal text. 1 request when unconfirmed, at most 2.
    Never the ``||`` form (MySQL's ``||`` is OR). Skipped on a raw whole-body point."""
    vuln_class = "sqli"
    mechanism = "evaluation-marker"
    category = "sql-injection"
    MAX_REQUESTS = 2

    @staticmethod
    def _draw() -> tuple[int, int]:
        return secrets.randbelow(900) + 100, secrets.randbelow(900) + 100

    @staticmethod
    def _value(a: int, b: int) -> str:
        return f"0'+(SELECT {a}*{b})+'0"

    def confirm(self, candidate, sender):
        if candidate.content_type:
            return None
        a1, b1 = self._draw()
        text1 = self._send(sender, candidate, self._value(a1, b1)).text or ""
        if not _evaluated(text1, f"{a1}*{b1}", a1 * b1):        # BUG-0133
            return None
        for _ in range(32):                         # a product absent from response 1
            a2, b2 = self._draw()
            if a2 * b2 != a1 * b1 and not _contains_number(text1, a2 * b2):
                break
        else:
            return None                             # a page full of numbers: no attribution
        text2 = self._send(sender, candidate, self._value(a2, b2)).text or ""
        if _evaluated(text2, f"{a2}*{b2}", a2 * b2):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"products": [a1 * b1, a2 * b2],
                            "payloads": [self._value(a1, b1), self._value(a2, b2)]})
        return None


class SqliTimingStrategy(ConfirmationStrategy):
    vuln_class = "sqli"
    mechanism = "differential-timing"
    category = "sql-injection"

    def confirm(self, candidate, sender):
        return self._confirm_timing(candidate, sender, _TIMING_TEMPLATES)


#: Content types a browser renders as a document that can run script (BUG-0127).
_HTML_TYPES = ("text/html", "application/xhtml+xml")


def _header_value(probe, name: str) -> str:
    return next((v for k, v in (probe.headers or {}).items() if k.lower() == name), "")


def _renders_as_html(probe) -> bool:
    """Would a browser render this response as HTML? A ``text/html`` or
    ``application/xhtml+xml`` content type, or none at all (a browser may sniff one),
    and not served as a download (``Content-Disposition: attachment``; reviewer B).
    A JSON, plain-text or other typed body never executes, however its text reads
    (BUG-0127: Juice Shop's ``application/json`` error echoed a tag). Stated limits:
    script-capable XML / SVG types are not rendered here (false negatives); an
    untyped ``nosniff`` response is still treated as rendered."""
    if _header_value(probe, "content-disposition").strip().lower().startswith("attachment"):
        return False
    main = _header_value(probe, "content-type").split(";", 1)[0].strip().lower()
    return main == "" or main in _HTML_TYPES


class ReflectedXssStrategy(ConfirmationStrategy):
    vuln_class = "xss-reflected"
    mechanism = "reflected-context"
    category = "xss"
    prg = True                                       # FR-FUZZ-49

    def confirm(self, candidate, sender):
        """Type where a marker reflects, then try the break-outs that context allows
        (at most 3) and confirm only on their **structural** effect in the parsed
        response: an element outside any inert element, an injected attribute, or the
        token in JavaScript code state (BUG-0083, FR-FUZZ-39), in a response a browser
        renders as HTML (`_renders_as_html`, BUG-0127). The context is always
        observed: no strategy reads the auditor's coarse ``sink_context`` (``html``,
        ``sql``, …), which keeps one confirmation per key sound (BUG-0072; guarded by
        ``tests/test_oracle_xss_structural.py``).

        FR-FUZZ-49: each response is read as observed (`_observed`, whole: the HTML
        check and the structure from the same response). A break-out confirmed only
        in a PRG follow-up is the stored value rendered on another request: recorded
        as ``xss-stored`` with ``observation: "prg"`` -- unless the follow-up's own URL
        carries the payload or its token (`_rode_the_redirect`): the payload rode the
        redirect, so it is ``xss-reflected`` with ``observation: "prg-redirect"``."""
        token = _token()
        marker = f"zqxm{token}"
        first = _observed(self._send(sender, candidate, marker))
        ref = locate_reflection(first.text, marker)
        if ref is None:
            return None
        probe_token = f"zqxb{token}"
        for kind, fragment, check in xss_breakouts(ref, probe_token):
            probe = self._send(sender, candidate, fragment)
            second = _observed(probe)
            if check(second.text) and _renders_as_html(second):        # BUG-0127
                evidence = {"context": ref.context, "breakout": kind,
                            "signature": fragment}
                if _via_prg(probe):
                    if _rode_the_redirect(probe, [fragment, probe_token]):
                        evidence["observation"] = "prg-redirect"
                        return Verdict(True, self.vuln_class, self.mechanism, evidence)
                    evidence["observation"] = "prg"
                    return Verdict(True, StoredXssStrategy.vuln_class, self.mechanism,
                                   evidence)
                return Verdict(True, self.vuln_class, self.mechanism, evidence)
        return None


def _one_trailing_dot_off(host: str) -> str:
    """``host`` without one trailing dot (a fully qualified spelling), never more."""
    return host[:-1] if host.endswith(".") else host


class OpenRedirectStrategy(ConfirmationStrategy):
    """M9: the parameter controls the redirect target (Location or meta refresh).

    ``vuln_class`` is underscored (``open_redirect``), not hyphenated, to match
    this project's own established ground-truth/manifest convention for this
    class (``lab/safety_matrix.yaml``'s `open_redirect` concern, `labels.
    schema.json`'s `vuln_class` enum, and every `open_redirect` manifest's own
    `class:` field) -- ``category`` stays hyphenated (`open-redirect`), the
    separate, deliberately-hyphenated category namespace every other strategy
    also uses (`sql-injection`, `server-side-template-injection`, ...),
    matching every other strategy in this file (`AccessControlIdorStrategy.
    vuln_class == "access_control"`, `InsecureDeserializationTypeConfusion
    Strategy.vuln_class == "insecure_deserialization"`, etc.). This field was
    originally hyphenated to match `category` (a real bug, BUG-0045/PA-0047:
    the mismatch against ground truth's underscored spelling made every
    `open_redirect` positive an unconditional false positive/false negative
    pair in `fuzzlab.harness.scoring.score`'s exact-tuple key match, found
    empirically via a real `run_targets` pipeline run against this stack's
    own `TWCH-0014`/`CC-LAB-0199` page -- the same root cause also silently
    affected category 5's own Booking.com `BKNG-0001` case, independently
    found and fixed via `BUG-0040`)."""
    vuln_class = "open_redirect"
    mechanism = "redirect-target-control"
    category = "open-redirect"

    @staticmethod
    def _header(probe, name):
        return next((v for k, v in probe.headers.items() if k.lower() == name), "")

    @staticmethod
    def _lands_on(target, page_url, host) -> bool:
        """Does a redirect target lead to our canary? Parsed, never a prefix test
        (PA-0122): resolved against the probed URL (scheme-relative included), an http(s)
        URL whose host is our token host and whose path is ``/cb`` (or ``/cb/``, as an
        app may normalise it). The host is the
        signal; ``https://github.com/x?u=https://oracle….example/cb`` is not."""
        from urllib.parse import urljoin, urlsplit
        try:
            parts = urlsplit(urljoin(page_url, (target or "").strip()))
        except ValueError:
            return False
        return (parts.scheme.lower() in ("http", "https")
                and _one_trailing_dot_off(parts.hostname or "") == host
                and parts.path in ("/cb", "/cb/"))

    def _probe(self, sender, candidate, value, host):
        probe = self._send(sender, candidate, value)
        location = self._header(probe, "location")
        if location and self._lands_on(location, candidate.url, host):
            return {"sink": "location-header", "location": location[:200]}
        # a meta refresh is followed only in a document a browser renders (BUG-0127)
        m = _META_REFRESH.search(probe.text or "") if _renders_as_html(probe) else None
        if m and self._lands_on(m.group(1), candidate.url, host):
            return {"sink": "meta-refresh", "url": m.group(1)[:200]}
        return None

    def confirm(self, candidate, sender):
        """A plain canary first. Only when it did not land and the candidate carries a
        crawled URL seed (FR-AUD-21): one more probe whose canary embeds the seed in its
        query, for an allowlist that checks containment (BUG-0124). The seed's host is
        never a request host, and probes never follow redirects."""
        host = f"oracle{_token()}.example"
        hit = self._probe(sender, candidate, f"https://{host}/cb", host)
        if hit is None and candidate.redirect_seed:
            host = f"oracle{_token()}.example"
            value = f"https://{host}/cb?fzlb={candidate.redirect_seed}"
            hit = self._probe(sender, candidate, value, host)
            if hit is not None:
                hit = {**hit, "variant": "allowlist-containment", "probe": value[:300]}
        if hit is None:
            return None
        return Verdict(True, self.vuln_class, self.mechanism, hit)


class SstiStrategy(ConfirmationStrategy):
    """M4: a template expression is evaluated server-side (product appears, not the literal)."""
    vuln_class = "ssti"
    mechanism = "evaluation-marker"
    category = "server-side-template-injection"
    prg = True                                       # FR-FUZZ-49

    @staticmethod
    def _draw() -> tuple[int, int]:
        return secrets.randbelow(900) + 100, secrets.randbelow(900) + 100

    def confirm(self, candidate, sender):
        """A template's product must appear (digit-bounded) with its literal absent,
        then the same template with a second product, absent from the first response,
        must appear in the response to the probe that computed it (BUG-0117 sweep: a
        page full of numbers is not an evaluator). Response 2 may still show product 1
        (a stored listing). +1 request, only after a match.

        FR-FUZZ-49: each response is read as observed (`_observed`). When response 2 is
        a PRG follow-up, product 1 must be absent from it (each POST overwrote the
        value: product 2 is attributed to its own probe, P5)."""
        a, b = self._draw()
        expr = f"{a}*{b}"
        for index, payload in enumerate(_ssti_payloads(expr)):
            first = self._send(sender, candidate, payload)
            text = _observed(first).text or ""
            if not _evaluated(text, expr, a * b):           # BUG-0133
                continue
            for _ in range(32):                     # a product absent from response 1
                c, d = self._draw()
                if c * d != a * b and not _contains_number(text, c * d):
                    break
            else:
                return None                         # a page full of numbers
            expr2 = f"{c}*{d}"
            payload2 = _ssti_payloads(expr2)[index]
            second = self._send(sender, candidate, payload2)
            text2 = _observed(second).text or ""
            if _via_prg(second) and _contains_number(text2, a * b):
                return None                         # product 1 still shown: no attribution
            if _evaluated(text2, expr2, c * d):
                evidence = {"payload": payload, "product": str(a * b),
                            "cross_check": [payload2, str(c * d)]}
                if _via_prg(first) or _via_prg(second):
                    evidence["observation"] = "prg"
                return Verdict(True, self.vuln_class, self.mechanism, evidence)
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
    prg = True                                       # FR-FUZZ-49

    def confirm(self, candidate, sender):
        """Two independent canaries, the second absent from the first response, each
        seen (digit-bounded) in the response to its own probe and never reflected
        (BUG-0117 sweep). +1 request, only after a match. FR-FUZZ-49: read as observed;
        a PRG follow-up of probe 2 must not still show canary 1 (P5)."""
        n = secrets.randbelow(900) + 100
        payload = f"T(java.lang.Math).abs(-{n})"
        first = self._send(sender, candidate, payload)
        text = _observed(first).text or ""
        if not _evaluated(text, payload, n):                # BUG-0133
            return None
        for _ in range(32):                         # a canary absent from response 1
            m = secrets.randbelow(900) + 100
            if m != n and not _contains_number(text, m):
                break
        else:
            return None                             # a page full of numbers
        payload2 = f"T(java.lang.Math).abs(-{m})"
        second = self._send(sender, candidate, payload2)
        text2 = _observed(second).text or ""
        if _via_prg(second) and _contains_number(text2, n):
            return None                             # canary 1 still shown: no attribution
        if _evaluated(text2, payload2, m):
            evidence = {"payload": payload, "result": str(n),
                        "cross_check": [payload2, str(m)]}
            if _via_prg(first) or _via_prg(second):
                evidence["observation"] = "prg"
            return Verdict(True, self.vuln_class, self.mechanism, evidence)
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

    **Canary has three decimal places**, so it cannot coincide with an
    ordinary two-decimal price the page already shows.

    **Match is anchored to a price context**, not a bare substring: the canary
    must follow, within 40 characters, a currency symbol or a price word
    (`_PRICE_CONTEXT`: the same words `R-PRICE-INTEGRITY` nominates on --
    amount, price, total, cost, charge -- OWASP WSTG v4.2 WSTG-BUSL-01, and the
    PortSwigger Web Security Academy lab "Excessive trust in client-side
    controls", whose request carries `price`), and be digit-bounded. A plain
    reflection of the value somewhere else on the page is not a charged
    amount. (PA-0660, BUG-0661: until 2026-11-20 this matched one labgen
    page's own attribute name and excluded that app's own rate table.)"""
    vuln_class = "price_integrity_bypass"
    mechanism = "trusted-client-amount-echo"
    category = "price-integrity-bypass"

    #: A currency symbol or price word, then at most 40 characters, then the canary.
    _PRICE_CONTEXT = r"(?:[$\u00a3\u20ac\u00a5]|amount|price|total|cost|charge)[^\n]{0,40}?"

    def confirm(self, candidate, sender):
        whole = secrets.randbelow(9000) + 100
        frac = secrets.randbelow(900) + 100
        canary = f"{whole}.{frac}"
        text = (self._send(sender, candidate, canary).text or "").replace(" ", "")
        anchored = re.compile(self._PRICE_CONTEXT + r"(?<![\d.])" + re.escape(canary)
                              + r"(?![\d])", re.IGNORECASE)
        if anchored.search(text):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"payload": canary, "echoed": canary})
        return None


class CsvFormulaInjectionStrategy(ConfirmationStrategy):
    """A value containing an OWASP CSV-formula trigger character is embedded
    unescaped into an exported CSV cell (CWE-1236, category 5's
    `csv_formula_injection`, Booking.com pilot).

    **Tries all four OWASP trigger characters** (`=`, `+`, `-`, `@`), not
    just `=` -- a real neutralizer could plausibly escape only a subset,
    which a single-character canary would silently miss (a false negative
    on a genuinely vulnerable target), caught by this component's own
    pre-change adequacy review before implementation. (The real secure
    twin this shape was modeled on, `CsvFormulaNeutralizeTransform`, also
    neutralizes leading tab/CR, per that same review -- not exercised here,
    matching the four-character scope this project's own OWASP-grounded
    test payload set already established, not a new gap this strategy
    introduces.)

    **Match is anchored to the CSV cell boundary**, not merely "right after
    a newline": both the unmodified-echo check and the not-secure check
    require the payload to be immediately followed by the field separator
    (`,`) -- `f"\\n{payload},"` / a leading `{payload},`. A bare
    `f"\\n{payload}"` check (an earlier draft) would false-positive-confirm
    on any response that merely echoes the raw payload right after a
    newline for an unrelated reason (a debug/error page, a differently-
    shaped reflection) -- rejected pre-implementation by the same review."""
    vuln_class = "csv_formula_injection"
    mechanism = "unescaped-formula-trigger-echo"
    category = "csv-formula-injection"

    #: OWASP's four named CSV-formula trigger characters.
    _TRIGGER_CHARS = ("=", "+", "-", "@")

    def confirm(self, candidate, sender):
        for trigger in self._TRIGGER_CHARS:
            n = secrets.randbelow(900) + 100
            payload = f"{trigger}{n}+{n}"
            text = self._send(sender, candidate, payload).text or ""
            anchored = f"{payload},"
            if text.startswith(anchored) or f"\n{anchored}" in text:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"payload": payload, "trigger": trigger})
        return None


class GoTemplateSstiStrategy(ConfirmationStrategy):
    """M4b: confirms SSTI on Go's `text/template` syntax, which `SstiStrategy`'s
    own arithmetic-marker payloads cannot reach (CC-LAB-0196/CC-FUZZ-0042).

    `SstiStrategy`'s `_ssti_payloads()` wraps an infix arithmetic expression
    (`a*b`) in five template-engine delimiter styles (Jinja2/FreeMarker/OGNL/
    EL/ERB-ish). That marker technique is structurally incompatible with
    Go's `text/template`: its action grammar has NO infix arithmetic
    operators at all (a hard syntax restriction, empirically verified via a
    real `go run` check and a real booted target -- see
    `tests/test_labgen_go_live_boot.py::test_ssti_go_text_template_syntax_
    mismatch`/`test_ssti_strategy_does_not_generalize_to_go_text_template`),
    so `{{a*b}}`/`${{a*b}}` fail to parse and the other three delimiter
    styles contain no `{{`/`}}` at all and are echoed back as inert literal
    text. This is a genuine syntax-family gap, not a tunable threshold, so
    it needs a different marker technique entirely rather than a wider
    `_ssti_payloads()` list.

    **The marker.** `text/template`'s own built-in functions
    (https://pkg.go.dev/text/template#hdr-Functions) include `len`, `index`,
    `printf`/`print`, and the comparison functions (`eq`/`ne`/`lt`/`le`/
    `gt`/`ge`) -- none need an infix arithmetic operator. `len` is the
    simplest: `{{ len "AAAA...A" }}` (a literal string of `N` `A`
    characters) evaluates to the decimal integer `N` if, and only if, the
    template engine actually parses the `{{ }}` action and invokes the
    built-in -- a target that merely echoes the payload as literal text (or
    HTML-escapes/reflects it, or rejects it) never produces the decimal
    string `N` in its response body. `N` is randomized fresh per probe (this
    project's own randomized-marker convention -- `SstiStrategy`'s own
    `a`/`b` are `secrets.randbelow(900) + 100`; this strategy mirrors that
    same 3-digit range so the produced value is short enough to embed
    cheaply but long enough that its exact decimal value coincidentally
    appearing in an unrelated part of a normal response is very unlikely
    for any *one* probe).

    **Why one probe alone is not enough (false-positive risk, thought
    through the same way `PriceTrustDifferentialStrategy`'s/
    `UnrestrictedFileUploadContentTypeTrustStrategy`'s own docstrings do).**
    A single `{{ len "..." }}` probe whose expected 3-digit `N` happens to
    already appear somewhere in a normal, unrelated response (a timestamp,
    a byte count, a session field, an unrelated numeric ID) would
    false-positive on a target that isn't evaluating anything at all. This
    project's own established defense against exactly that shape of risk
    is a differential, not a tighter single-probe heuristic (the same
    "differential over single-probe heuristic" preference
    `InsecureDeserializationTypeConfusionStrategy`'s own docstring states
    explicitly). So this strategy sends TWO independent probes with two
    distinct, freshly randomized lengths `N1 != N2`, and confirms only when
    ALL of: (a) neither probe's own literal template-source payload is
    echoed back verbatim (rules out dumb reflection); (b) probe 1's
    response contains `N1` as a whole decimal token (word-boundary
    matched, so `N1=142` doesn't false-match inside `31420`); (c) probe 2's
    response contains `N2` likewise; (d) NEITHER response also contains the
    OTHER probe's length as a whole token (`N2` must not leak into probe
    1's response, and `N1` must not leak into probe 2's) -- a
    cross-contamination guard against a cached/stale/echo-everything
    response that would otherwise pass (a) and (b)/(c) independently but
    isn't actually computing a fresh, request-specific `len()` each time.
    Requiring two independent random values to each land correctly, with no
    cross-bleed, before confirming is astronomically less likely to
    coincidence-match than a single probe (each length is a fresh 3-digit
    draw out of 900 possibilities; both matching by pure coincidence AND
    landing on the correct probe's own value is the product of two already
    small per-probe odds).

    **Design decision: a new strategy, not a widened `SstiStrategy`
    (checked against this project's own established architecture before
    deciding).** `default_strategies()`'s own registration order already
    establishes a "cheaper/broader mechanism first, specialized fallback
    for a syntax family the first one structurally cannot reach next"
    layering for exactly this shape of gap -- `SsrfInBandMarkerStrategy`
    before `SsrfOobStrategy`, M1 timing before `CommandInjectionOobStrategy`
    -- and `Oracle.confirm()` already tries every strategy whose `category`
    matches a candidate in order, stopping at the first confirming verdict,
    with NO code change needed to add a second strategy under the same
    `category`. Folding this into `SstiStrategy.confirm()` itself would mean
    every non-Go target pays for two additional wasted requests (the `len`
    marker) on top of its own five, and would conflate two structurally
    different marker techniques (arithmetic-infix vs. builtin-function-call)
    in one method -- against this project's own one-mechanism-per-strategy
    convention every other multi-mechanism-per-category case (SSRF, command
    injection) already follows. Registered directly after `SstiStrategy` in
    `default_strategies()`: `SstiStrategy` is tried first (it is already the
    established, broader-coverage mechanism across the arithmetic-evaluating
    engines this lab already has -- Jinja2/OGNL/FreeMarker/EL), and this
    strategy runs as the fallback specifically for the syntax family
    `SstiStrategy` cannot parse into evaluation at all, exactly the
    "cheaper/broader first, specialized fallback next" shape.
    """
    vuln_class = "ssti"
    mechanism = "go-template-len-marker"
    category = "server-side-template-injection"
    prg = True                                       # FR-FUZZ-49 (an M4 marker)

    _LEN_RANGE = 900   # 3-digit lengths (100-999), matching SstiStrategy's own range

    # Known limitation, not silently swept under the rug (the same per-target
    # field-name-hardcoding convention `PriceTrustDifferentialStrategy`'s/
    # `MassAssignmentPrivilegedFieldStrategy`'s own docstrings already use):
    # A JSON whole-body point (`content_type == "application/json"`) carries the
    # expression in every string leaf of the app's own captured body
    # (`candidate.base_entries`, as `NoSqlOperatorStrategy` places its operators):
    # the field the template is read from is the target's, never a name this
    # strategy assumes (PA-0660, BUG-0661 -- until 2026-11-20 it sent one labgen
    # sink's own field name). With no captured body there is nothing to place the
    # expression in, so the strategy gives no verdict (a stated miss). A plain
    # named query/form param needs no wrapping: the payload is its raw value.

    def _random_length(self) -> int:
        return secrets.randbelow(self._LEN_RANGE) + 100

    #: The string literal's quoting forms, tried in order (BUG-0139, PA-0139): Go's
    #: interpreted string ``"..."``, then its raw string ```...```, for a data path
    #: that filters or escapes ``"`` before the template is parsed. The second runs only
    #: when the first did not confirm.
    QUOTES = ('"', "`")

    @staticmethod
    def _expr(n: int, quote: str = '"') -> str:
        return "{{ len %s%s%s }}" % (quote, "A" * n, quote)

    def _payload(self, candidate: Candidate, n: int, quote: str = '"') -> str | None:
        expr = self._expr(n, quote)
        if candidate.content_type == "application/json":
            from fuzzlab.core import jsonbody
            try:
                base = jsonbody.normalize_entries(candidate.base_entries or ())
                strings = [jsonbody.display_name(p) for p, v in base if isinstance(v, str)]
                if not strings:
                    return None
                return jsonbody.body_with(base, {n_: expr for n_ in strings}).decode("utf-8")
            except jsonbody.JsonPlacementError:
                return None
        return expr

    @staticmethod
    def _contains_token(text: str, n: int) -> bool:
        return _contains_number(text, n)

    def confirm(self, candidate, sender):
        """One two-probe round per quoting form (`QUOTES`), each with fresh lengths and
        the same rules; the raw-string round runs only when the interpreted-string
        round did not confirm (BUG-0139). Requests: 2 to confirm by ``"``, 4 to
        confirm by a backtick or to give no verdict."""
        for delim in self.QUOTES:
            verdict = self._round(candidate, sender, delim)
            if verdict is not None:
                return verdict
        return None

    def _round(self, candidate, sender, delim):
        n1 = self._random_length()
        n2 = self._random_length()
        while n2 == n1:                            # degenerate collision; redraw rather than reuse
            n2 = self._random_length()
        expr1, expr2 = self._expr(n1, delim), self._expr(n2, delim)
        payload1 = self._payload(candidate, n1, delim)
        payload2 = self._payload(candidate, n2, delim)
        if payload1 is None or payload2 is None:
            return None                            # nowhere to place it (no captured body)
        first = self._send(sender, candidate, payload1)
        text1 = _observed(first).text or ""
        second = self._send(sender, candidate, payload2)
        text2 = _observed(second).text or ""          # FR-FUZZ-49: as observed
        if _echoed_outside_form_controls(text1, expr1) or \
                _echoed_outside_form_controls(text2, expr2):
            return None                            # literal reflection, not evaluation
        own1, own2 = _evaluated(text1, expr1, n1), _evaluated(text2, expr2, n2)  # BUG-0133
        cross1, cross2 = self._contains_token(text1, n2), self._contains_token(text2, n1)
        if own1 and own2 and not cross1 and not cross2:
            evidence = {"lengths": [n1, n2], "payloads": [payload1, payload2]}
            if delim != '"':
                evidence["string_form"] = "raw (backtick)"          # BUG-0139
            if _via_prg(first) or _via_prg(second):
                evidence["observation"] = "prg"
            return Verdict(True, self.vuln_class, self.mechanism, evidence)
        return None


class PathTraversalStrategy(ConfirmationStrategy):
    """M7: a file-content marker (/etc/passwd) appears in the response -- and is
    absent from a control with no traversal (``passwd``), as in
    `PathTraversalFsPathReadStrategy` (BUG-0117 sweep: a page that always shows
    ``root:x:0:0:`` is not confirmed). +1 request, only after a match."""
    vuln_class = "file-inclusion"
    mechanism = "file-content-marker"
    category = "file-inclusion"
    prg = True                                       # FR-FUZZ-49
    _CONTROL_VALUE = "passwd"

    def confirm(self, candidate, sender):
        """FR-FUZZ-49: read as observed; a marker seen only through a PRG follow-up
        needs the control observed through its own follow-up, without it. FR-FUZZ-63:
        the control is an application answer (`_compared`); a control whose follow-up
        got no observation, when the marker was seen through one, is not comparable."""
        for payload in _TRAVERSAL_PAYLOADS:
            with trace.role("mutation"):              # FR-FUZZ-60
                probe = self._send(sender, candidate, payload)
            if _PASSWD_MARKER.search(_observed(probe).text or ""):
                control = self._compared(sender, candidate, self._CONTROL_VALUE,
                                         role="control")
                if _PASSWD_MARKER.search(_observed(control).text or ""):
                    return None                     # shown without traversal
                if _via_prg(probe) and not _via_prg(control):
                    if getattr(control, "prg", None) == PRG_UNOBSERVED:
                        raise NotComparable(
                            "not comparable: the control's follow-up got no observation")
                    return None                     # the control was not observed alike
                evidence = {"payload": payload}
                if _via_prg(probe):
                    evidence["observation"] = "prg"
                return Verdict(True, self.vuln_class, self.mechanism, evidence)
        return None


class PathTraversalFsPathReadStrategy(ConfirmationStrategy):
    """Confirms `path_traversal` (CWE-22, `fs_path_read` sink context --
    `CC-LAB-0190`'s own deliberately-deferred detection follow-on, Twitch's
    `TWCH-0011`, `GET /clips/export?filename=`) with a real, live-verified
    `/etc/passwd`-content differential.

    **This is NOT the "plant a canary on the target's filesystem" design a
    prior verbal note in this project's own history dismissed as unsafe/
    unrealistic (the same mischaracterization `docs/
    LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`'s §9.4/§9.5 row for category
    4 originally recorded, corrected by this same change).** That reasoning
    applies only to a design that needs to *write* a marker file into the
    target's filesystem first, the way an SSRF/XXE strategy plants a
    canary via an `OobListener`. This strategy plants nothing: it sends a
    `../`-traversal payload as the `filename` value and checks whether the
    response body contains content that could only appear if the target
    actually resolved and read a real, PRE-EXISTING OS file
    (`/etc/passwd`, present on essentially every Linux/Unix target this
    project's labs run on) -- the same standard, safe, purely-READ,
    black-box technique this project's own `fuzzlab/labgen/nuclei_oracle.py`
    already bundles for a different sub-purpose (`lab/nuclei-templates/
    path-traversal-etc-passwd.yaml`, same `root:.*:0:0:`-shaped match), just
    reimplemented here as a real, pure-Python `ConfirmationStrategy` for the
    runtime oracle rather than invoked via Nuclei.

    **Verified empirically against the real, live-booted vulnerable/secure
    twins before writing this class** (`GoLiveBootHarness`, per this
    change's own task instructions -- not guessed): the confinement depth
    this lab's `UnconfinedPathSink` needs to escape is shallow enough that
    the existing, already-escalating `_TRAVERSAL_PAYLOADS` list (reused
    verbatim from `PathTraversalStrategy` above, whose own similarly-shaped
    but differently-`vuln_class`/uncontrolled `file-inclusion` strategy
    predates this one and is left untouched, matching no current ground
    truth) already reaches real `/etc/passwd` content: the vulnerable twin
    (`LABGEN-GO-0021`) returned the requested OS file's own real
    `root:x:0:0:...` line verbatim for `filename=../../../../../../../../
    etc/passwd` (HTTP 200), while the secure twin (`LABGEN-GO-0022`,
    `realpath_confine`) rejected the identical payload outright (HTTP 403,
    no such content anywhere in the body) -- confirming the plain
    `/etc/passwd`-content differential transfers to this lab's real
    confinement-bypass shape with no new traversal-depth tuning needed.

    **Differential design (a control probe defends against a false
    positive)**: a target that always echoes `root:...:0:0:`-shaped text
    back regardless of input (a pathological or coincidental case, not
    this bug) must not be confirmed. The control probe sends a filename
    with no traversal separators at all (`"passwd"`, no `../`) -- a
    legitimate-shaped but non-existent/out-of-directory-escaping filename
    value that carries no traversal semantics whatsoever. Confirmation
    requires the marker to be PRESENT for a genuine traversal payload AND
    ABSENT for that control -- if the control also shows the marker, this
    payload is skipped (not attributable to path traversal specifically)
    and the next escalating payload in `_TRAVERSAL_PAYLOADS` is tried.
    """
    vuln_class = "path_traversal"
    mechanism = "passwd-file-content-marker-differential"
    category = "path-traversal"
    prg = True                                       # FR-FUZZ-49

    _CONTROL_VALUE = "passwd"    # no traversal separators -- rules out an
                                  # always-echoes-marker-content target

    def confirm(self, candidate, sender):
        """FR-FUZZ-63: the control is an application answer (`_compared`); a control
        whose follow-up got no observation, when the marker was seen through one, is
        not comparable (no verdict, never a negative)."""
        for payload in _TRAVERSAL_PAYLOADS:
            with trace.role("mutation"):              # FR-FUZZ-60
                probe = self._send(sender, candidate, payload)
            if not _PASSWD_MARKER.search(_observed(probe).text or ""):   # FR-FUZZ-49
                continue
            control = self._compared(sender, candidate, self._CONTROL_VALUE,
                                     role="control")
            if _PASSWD_MARKER.search(_observed(control).text or ""):
                continue    # marker present even without traversal -- not attributable, try next payload
            if _via_prg(probe) and not _via_prg(control):
                if getattr(control, "prg", None) == PRG_UNOBSERVED:
                    raise NotComparable(
                        "not comparable: the control's follow-up got no observation")
                continue    # the control was not observed alike (FR-FUZZ-49)
            evidence = {"payload": payload}
            if _via_prg(probe):
                evidence["observation"] = "prg"
            return Verdict(True, self.vuln_class, self.mechanism, evidence)
        return None


#: The value a command-injection timing baseline sends when the point has none of its own.
_CMDI_BASELINE = "1"


def cmdi_timing_payloads(base: str | None) -> list[str]:
    """The timing payloads for a point: each is the baseline's own value followed by a
    template (BUG-0630), the base value when the point has one, else `_CMDI_BASELINE`; a
    template that already starts with that value is not prefixed twice."""
    prefix = _CMDI_BASELINE if base is None else base
    out: list[str] = []
    for t in _CMDI_TIMING_TEMPLATES:
        p = t if base is None and t.startswith(prefix) else prefix + t
        if p not in out:
            out.append(p)
    return out


class CommandInjectionStrategy(ConfirmationStrategy):
    """M1 (timing): a shell `sleep` executes, latency rising with the requested delay."""
    vuln_class = "command-injection"
    mechanism = "differential-timing"
    category = "command-injection"

    def confirm(self, candidate, sender):
        # FR-AUD-20: a point whose default was a host starts from loopback, so the app
        # never receives its own (third-party) host from us
        base = candidate.base_value
        # BUG-0630: every payload carries the value the baseline sent, so the command the
        # baseline runs (VulnerableApp's `ping -c 2 <value>`: ~1 s) runs in the payload too
        # and the added latency is the requested sleep's alone; a payload replacing it
        # measured ~1 s short and never confirmed
        return self._confirm_timing(candidate, sender, cmdi_timing_payloads(base),
                                    baseline_value=_CMDI_BASELINE if base is None else base)


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
    templates to each measure latency above every non-evil answer -- the
    benign baseline and each template's structural control
    (`_REDOS_CONTROLS`: the same pattern minus its nested or ambiguous
    quantifier) -- by that pool's own measured jitter, in **every** one of
    ``rounds`` re-sends (FR-FUZZ-711; the fixed ``floor=0.02 s``/``k=4``
    of CC-FUZZ-0025 was calibrated on this project's own lab cells and is
    withdrawn, BUG-0733) -- the ReDoS analogue of "two escalating
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

    # FR-FUZZ-711 (BUG-0733, CC-FUZZ-0711): the threshold comes from the target's own
    # answers, not from a figure calibrated on one lab's cells (the former fixed
    # floor=0.02 s / k=4 over 3 samples). Every template is sent in `rounds` rounds
    # beside its structural control (`_REDOS_CONTROLS`), in alternating order, and
    # confirms only when **every** one of its samples clears the slowest non-evil answer
    # measured so far (the benign baseline samples and every control) by that pool's
    # own jitter: its spread (max - min) or `k` robust sigmas, whichever is larger.
    # `resolution_floor` is the client's measurement resolution, never a target
    # figure: loopback HTTP on the build host measured p50 1.46 ms, p99 6.24 ms,
    # max 8.24 ms over 500 requests (CC-FUZZ-0711 "Measured"), so a gap under 5 ms is
    # not read as a difference whatever the pool's spread.
    baseline_samples = 5
    rounds = 3
    k = 4.0
    resolution_floor = 0.005   # seconds
    min_confirming_templates = 2
    benign_probe = "ordinary-search-term"

    @classmethod
    def _margin(cls, pool: list[float]) -> float:
        """The jitter a sample must clear above the slowest non-evil answer: the pool's
        spread or ``k`` robust sigmas, at least the client's resolution."""
        sigma = build_baseline(pool).robust_sigma()
        return max(cls.resolution_floor, max(pool) - min(pool), cls.k * sigma)

    def confirm(self, candidate, sender):
        # FR-FUZZ-63: each sample an application answer, or no verdict (a fast refusal
        # lowers the threshold; a connect timeout is no latency, M7)
        pool = [self._compared(sender, candidate, self.benign_probe, role="baseline",
                               timing=True).elapsed
                for _ in range(self.baseline_samples)]
        base = build_baseline(pool)
        confirming = []
        for template in _REDOS_TEMPLATES:
            control = _REDOS_CONTROLS[template]
            evil_samples: list[float] = []
            control_samples: list[float] = []
            for r in range(self.rounds):
                # alternate the order, so a warm-up or caching effect lands on each side
                order = ("control", "evil") if r % 2 == 0 else ("evil", "control")
                evil_elapsed = 0.0
                for side in order:
                    if side == "control":
                        c = self._compared(sender, candidate, control, role="control",
                                           timing=True).elapsed
                        control_samples.append(c)
                        pool.append(c)
                    else:
                        with trace.role("mutation"):          # FR-FUZZ-60
                            evil_elapsed = self._send(sender, candidate, template,
                                                      timing=True).elapsed
                evil_samples.append(evil_elapsed)
                if evil_elapsed < max(pool) + self._margin(pool):
                    break                    # not above every non-evil answer: next shape
            else:
                confirming.append({
                    "template": template, "control": control,
                    "elapsed": [round(e, 4) for e in evil_samples],
                    "control_elapsed": [round(c, 4) for c in control_samples],
                    "threshold": round(max(pool) + self._margin(pool), 4)})
                if len(confirming) >= self.min_confirming_templates:
                    return Verdict(True, self.vuln_class, self.mechanism,
                                   {"baseline_median": round(base.median, 4),
                                    "confirming_templates": confirming})
        return None



def _canary(listener: OobListener, token: str) -> str:
    """The listener's callback URL for ``token``. A listener that is not running is no
    verdict (as a browser that cannot start, PA-0126(3)), never the end of the run
    (BUG-0147, PA-0153)."""
    if not getattr(listener, "running", True):
        raise UnplaceableLocation("out-of-band listener not running")
    return listener.callback_url(token)


def _send_blind(send: Callable[[], object]) -> bool:
    """Send an out-of-band probe whose HTTP response is never read. True when it got no
    response: the payload may still have reached the target, so the caller still waits
    for the callback, and raises `ProbeUnobserved` only if none came (BUG-0147)."""
    try:
        send()
    except ProbeUnobserved:
        return True
    return False

def _await_callback(listener, token: str, canary: str, timeout: float):
    """Wait for ``token``'s callback exactly as before (`OobListener.wait_for`) and, with
    an active recorder, record what the wait saw as one ``oob.wait`` step (FR-FUZZ-62):
    on the strategy's own thread, where the trace context is visible (the listener's
    handler thread has none). One clock, ``time.time()``, the one behind
    `OobHit.received_at`; a hit without ``received_at`` (a test double) has no
    ``after_wait_ms``. The record is contained: it never changes the hit returned."""
    if trace.active() is None:
        return listener.wait_for(token, timeout=timeout)
    import time
    started = time.time()
    hit = listener.wait_for(token, timeout=timeout)
    ended = time.time()
    try:
        received = getattr(hit, "received_at", None) if hit is not None else None
        test, strategy, _role = trace.current()
        trace.emit_step("oob.wait", {
            "test": test, "strategy": strategy, "url": trace.safe_ref(canary),
            "window_ms": round(timeout * 1000, 1),
            "waited_ms": round((ended - started) * 1000, 1),
            "outcome": "received" if hit is not None else "none",
            "after_wait_ms": round((received - started) * 1000, 1)
            if isinstance(received, (int, float)) else None,
            "remote": getattr(hit, "remote_addr", None) if hit is not None else None},
            t=received if isinstance(received, (int, float)) else ended)
    except Exception as exc:  # noqa: BLE001 - the trace never changes the confirmation
        from fuzzlab.core.obs import get_logger
        get_logger("trace").warning("out-of-band step not recorded",
                                    extra={"error": type(exc).__name__})
    return hit


#: What an out-of-band mechanism raises when a probe got no response and no callback came.
_OOB_UNOBSERVED = "no response: an out-of-band probe got no response and no callback"

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
        unobserved = False
        for template in _CMDI_OOB_TEMPLATES:
            token = self._listener.register()
            canary = _canary(self._listener, token)
            value = (candidate.base_value or "") + template.format(url=canary)
            unobserved |= _send_blind(lambda v=value: self._send(sender, candidate, v))
            hit = _await_callback(self._listener, token, canary, self._timeout)
            if hit is not None:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"canary": canary, "template": template,
                                "hit_path": hit.path, "remote_addr": hit.remote_addr})
        if unobserved:
            raise ProbeUnobserved(_OOB_UNOBSERVED)
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
        canary = _canary(self._listener, token)
        probe = self._send(sender, candidate, canary)
        # the fetched body's proof, never the token (which the URL itself carries, so a
        # page reflecting the URL would confirm; BUG-0089)
        if self._listener.proof(token) in (probe.text or ""):
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
        canary = _canary(self._listener, token)
        unobserved = _send_blind(lambda: self._send(sender, candidate, canary))
        hit = _await_callback(self._listener, token, canary, self._timeout)
        if hit is not None:
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"canary": canary, "hit_path": hit.path,
                            "remote_addr": hit.remote_addr})
        if unobserved:
            raise ProbeUnobserved(_OOB_UNOBSERVED)
        return None


class AccessControlIdorStrategy(ConfirmationStrategy):
    """Confirms broken object-level authorization (IDOR/BOLA, CWE-639/862) by a
    differential over the target's **own** object id and its neighbour: does the
    target hand back another object's data when the id it gave us is incremented or
    decremented, with nothing rejecting it?

    FR-FUZZ-712 (BUG-0734, CC-FUZZ-0712): the id is the value the target itself put in
    this point -- the crawled link's, form's or path segment's captured value
    (`Candidate.base_entries`, as `CrossAccountReplayStrategy` reads it) -- and the
    probe is its numeric neighbour (+1, else -1), the manipulation OWASP WSTG-ATHZ-04
    ("Testing for Insecure Direct Object References": change the value of the
    parameter that references an object) and OWASP API Security Top 10 2023 API1
    ("Broken Object Level Authorization": sequential ids replaced) describe. The fixed
    synthetic ids of CC-FUZZ-0033 (``50172``/``88190475``, each required echoed back)
    were fitted to lab cells that echo any id and are withdrawn. **No verdict**
    (`UnplaceableLocation`) when the point carries no captured value or a value with
    no numeric neighbour (a UUID, a slug): a stated miss, never a guessed id. A
    ground-truth-point run carries no captured value, so it gives this mechanism no
    verdict (an oracle diagnostic, PA-0660(4)); a crawl run carries it for query
    links, forms and path segments the crawl saw a value for.

    Confirms only when all of these hold (fp=0 safeguards):

    * the captured id answers 200 **twice with the same body** -- the answer is keyed
      by the id, not a page that differs on every load (PA-0117(2): the differential
      replicates);
    * the neighbour answers 200 with a body that is not empty (nor an empty JSON
      value: ``null``, ``{}``, ``[]``, ``""``) and **differs** from the captured id's --
      another object, not the same page;
    * neither body carries a generic denial phrase.

    Known limitation, not silently swept under the rug: this cannot authenticate as
    two different real identities (`CrossAccountReplayStrategy` does, given peer
    accounts), so it proves "the neighbouring object is served with no ownership
    check", not a cross-tenant proof. It can also false-positive on a legitimately
    public object keyed by id (a public profile or catalogue item);
    `R-ACCESS-CONTROL` bounds that, it does not eliminate it.
    """
    vuln_class = "access_control"
    mechanism = "identity-differential"
    category = "access-control"

    # \b-anchored per PA-0022 (avoid an accidental substring hit, e.g.
    # "unauthorized" inside "preauthorized"); a false collision here only
    # costs a false negative (fails closed), never a false positive. "does not exist" /
    # "no such": a neighbour that is no object (FR-FUZZ-712) answered 200 with a message.
    _DENIAL_MARKERS = re.compile(
        r"\bforbidden\b|\bunauthorized\b|\baccess denied\b|\bnot found\b"
        r"|\bpermission denied\b|\bdoes not exist\b|\bno such\b",
        re.I,
    )
    #: A captured id with a numeric neighbour: decimal digits (a zero-padded width is kept).
    _NUMERIC_ID = re.compile(r"[0-9]{1,18}")
    _EMPTY_BODIES = frozenset({"", "null", "{}", "[]", '""'})

    def __init__(self, anonymous: Sender | None = None):
        #: The unauthenticated sender (`PeerAccounts.anonymous`): the public-object
        #: control (FR-FUZZ-714). None: no verdict, never a guess.
        self._anonymous = anonymous

    @classmethod
    def neighbours(cls, value: str) -> list[str]:
        """The captured id's numeric neighbours, +1 first, at its own width."""
        if not cls._NUMERIC_ID.fullmatch(value or ""):
            return []
        n, width = int(value), len(value)
        return [str(m).zfill(width) for m in (n + 1, n - 1) if m >= 0]

    def _denied_or_empty(self, probe) -> bool:
        text = probe.text or ""
        return (probe.status != 200 or text.strip() in self._EMPTY_BODIES
                or bool(self._DENIAL_MARKERS.search(text)))

    def confirm(self, candidate, sender):
        captured = dict(candidate.base_entries or ()).get(candidate.param)
        if not isinstance(captured, str) or not captured:
            raise UnplaceableLocation(
                "access-control: the target gave this point no id value to start from")
        neighbours = self.neighbours(captured)
        if not neighbours:
            raise UnplaceableLocation(
                "access-control: the target's id has no numeric neighbour")
        a = self._send(sender, candidate, captured)
        if self._denied_or_empty(a):
            return None
        again = self._send(sender, candidate, captured)
        if again.status != 200 or (again.text or "") != (a.text or ""):
            return None                  # not keyed by the id alone: no differential
        for neighbour in neighbours:
            with trace.role("mutation"):              # FR-FUZZ-60
                b = self._send(sender, candidate, neighbour)
            if b.status != 200:
                continue                 # e.g. 404 past the last object: try the other
            if self._denied_or_empty(b) or (b.text or "") == (a.text or ""):
                return None
            # FR-FUZZ-714 (BUG-0735): the neighbour is an object the run's session may not
            # be meant to see only if the endpoint protects it at all: the same request
            # without a session must be refused (non-200, empty or a denial). A public
            # object keyed by id (a catalogue item, a public profile) answers it alike --
            # no verdict. OWASP WSTG-ATHZ-04 tests access to objects that require
            # authorisation; OWASP API1:2023 BOLA concerns objects a user must not reach.
            if self._anonymous is None:
                raise UnplaceableLocation(
                    "access-control: no unauthenticated sender for the public-object "
                    "control")
            from fuzzlab.oracle.oracle import _FormBoundSender
            with trace.role("control"):          # the point's other fields bound, as
                anon = self._send(_FormBoundSender(self._anonymous, candidate),  # SP-57
                                  candidate, neighbour)
            if not self._denied_or_empty(anon):
                return None              # served without a session: public, or no auth
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"value_a": captured, "value_b": neighbour,
                            "anonymous_status": anon.status,
                            "probe_a": a.text[:120], "probe_b": b.text[:120]})
        return None


#: How a JavaScript server renders an object it was sent (``String({...})``): the echo
#: of a NoSQL operator leaf in a form value or a message (BUG-0610).
_JS_OBJECT_STRING = "[object Object]"


class NoSqlOperatorStrategy(ConfirmationStrategy):
    """NoSQL operator injection (FR-FUZZ-54): a JSON leaf that reaches a document
    query unchanged (MongoDB / Mongoose ``find({email: <leaf>})``) takes a JSON
    **object** as a query operator. The probe sends the point's whole JSON body (its
    leaves as the app sent them, `core.jsonbody.body_with`) with:

    * **B** -- every string leaf a fresh random literal (matches nothing);
    * **V** -- the target leaf ``{"$in": []}`` (an operator that matches nothing);
    * **D** -- the target leaf ``{"$ne": <random>}`` (an operator that matches
      anything);

    with every *other* string leaf ``{"$ne": <random>}`` in V and D, so the target
    leaf alone decides whether a document matches (a login checks email **and**
    password). Confirms only when V looks like B (an operator that matches nothing is
    treated as a value that matches nothing) and D does not, in the same replicated,
    randomly ordered rounds as the shared differential engine (``ENGINE_ROUNDS``; its
    bound holds for the same reason), each D like the first. A server that rejects
    or stringifies any object answers V and D alike (``[object Object]`` matches
    nothing): no verdict.

    Only a JSON-leaf point with its captured body (``location == "json"``) carries
    this probe: a form field cannot hold an object. Both operators only read; a point
    that writes with a query (an update by filter) is as exposed as it is to SQL
    injection's boolean probe, under the same lab-only posture."""
    vuln_class = "nosqli"
    mechanism = "operator-differential"
    category = "nosql-injection"

    def confirm(self, candidate, sender):
        from fuzzlab.core import jsonbody
        if candidate.location != jsonbody.LOCATION or not candidate.base_entries:
            return None
        try:
            base = jsonbody.normalize_entries(candidate.base_entries)
        except jsonbody.JsonPlacementError:
            return None
        strings = [jsonbody.display_name(p) for p, v in base if isinstance(v, str)]
        if candidate.param not in strings:
            return None                       # only a string leaf becomes an operator
        rng = _engine_rng()
        sent: list[str] = []

        def body(slot: str) -> str:
            tok = "zqns" + _token()
            sent.append(tok)
            if slot == "B":
                values = {n: f"{tok}{i}" for i, n in enumerate(strings)}
                sent.extend(values.values())
            else:
                values = {n: {"$ne": tok} for n in strings}
                values[candidate.param] = {"$in": []} if slot == "V" else {"$ne": tok}
            return jsonbody.body_with(base, values).decode("utf-8")

        def send(slot: str) -> Probe:
            # FR-FUZZ-63: every slot compared, application answers only ($ne and $in
            # can be singled out, so a policy answer to D is no evaluation)
            return self._compared(sender, candidate, body(slot), role=_SLOT_ROLE[slot],
                                  location="body", content_type=jsonbody.ENCTYPE)

        def same(a: Probe, b: Probe) -> bool:
            # an operator leaf echoed back is JavaScript's String(object): it is the
            # sent value's reflection as the B token's echo is (BUG-0610)
            forms = sorted({f for t in [*sent, _JS_OBJECT_STRING]
                            for f in _reflection_forms(t)}, key=len, reverse=True)
            return a.status == b.status and \
                _strip_forms(a.text or "", forms) == _strip_forms(b.text or "", forms)

        b0 = send("B")
        got = {slot: send(slot) for slot in rng.choice(_SCREEN_ORDERS)}
        if not same(got["V"], b0) or same(got["D"], b0):
            return None
        d1 = got["D"]
        for _ in range(ENGINE_ROUNDS):
            got = {slot: send(slot) for slot in rng.choice(_ROUND_ORDERS)}
            if (not same(got["V"], b0) or not same(got["B"], b0)
                    or same(got["D"], b0) or not same(got["D"], d1)):
                return None
        return Verdict(True, self.vuln_class, self.mechanism,
                       {"rounds": 1 + ENGINE_ROUNDS, "always": '{"$ne": …}',
                        "never": '{"$in": []}',
                        "status": {"base": b0.status, "always": d1.status},
                        "len": {"base": len(b0.text or ""), "always": len(d1.text or "")}})


#: How a cross-account replay is named in a not-comparable reason (FR-FUZZ-63).
_REPLAY_LABEL = {"peer": "peer replay", "anonymous": "unauthenticated replay"}


@dataclass(frozen=True)
class PeerAccounts:
    """A second account for cross-account access checks (FR-FUZZ-55): its sender
    (``sender``), the run's own account's username (``owner``) and the peer's
    (``peer_name``) -- the markers that tell whose data a response holds -- and an
    unauthenticated sender (``anonymous``) as the control. ``sender`` is None in a
    `--no-login` run (FR-FUZZ-58): no account has a session, so only the
    unauthenticated replay is made."""
    sender: Sender | None
    owner: str
    peer_name: str
    anonymous: Sender | None = None


class CrossAccountReplayStrategy(ConfirmationStrategy):
    """Broken object-level authorization, checked with two real accounts (FR-FUZZ-55;
    after Autorize): the run's own account (A) requests its object with the value the
    crawl saw A use; the same request is replayed as the peer account (B) and
    unauthenticated.

    A response is *A's view* when it answers 200, names A's username and not B's.
    Confirms only when: A's own request is A's view; the same request with another
    value is not (the data is keyed by this value, not a page that always shows A);
    and B -- or the unauthenticated control -- gets A's view twice. Evidence names who
    got it and the statuses, never the data.

    Runs only when a peer account is given (`fuzzlab auto --peer-identity`), or with
    `--no-login` (only the unauthenticated replay); otherwise no-ops. Known false
    positive, not swept under the rug: a resource that is meant to be shared and shows
    its owner's name to others (a public post and its author) looks the same; the
    finding names the URL for a person to judge. Scoped by `R-ACCESS-CONTROL` (GET
    query parameters with id-shaped names) and `R-ACCESS-CONTROL-PATH` (an id-shaped
    path segment, FR-FUZZ-57)."""
    vuln_class = "access_control"
    mechanism = "cross-account-replay"
    category = "access-control"

    def __init__(self, peer: PeerAccounts | None = None):
        self._peer = peer

    def confirm(self, candidate, sender):
        peer = self._peer
        if peer is None or not peer.owner or candidate.method != "GET" \
                or candidate.location not in ("query", "path"):
            return None
        value = dict(candidate.base_entries or ()).get(candidate.param)
        if not value:
            return None                          # no value the crawl saw A use
        from fuzzlab.oracle.oracle import _FormBoundSender

        def view_of_owner(p: Probe) -> bool:
            text = p.text or ""
            return p.status == 200 and peer.owner in text and \
                not (peer.peer_name and peer.peer_name in text)

        # FR-FUZZ-63: A's own request, the other-value control and every replay are
        # compared, so each must be the application's answer -- or a policy block, an
        # API's own denial of a foreign id. A refused credential (A's, or the peer's), a
        # gateway, a throttle or an incomplete answer gives no verdict, never "denied".
        # The unauthenticated replay carries no credential: its 401 is the endpoint's.
        if not view_of_owner(self._compared(sender, candidate, value, role="baseline",
                                            admits=APPLICATION_OR_POLICY)):
            return None                          # not A's own private view
        if view_of_owner(self._compared(sender, candidate, "zqac" + _token(),
                                        role="control", admits=APPLICATION_OR_POLICY)):
            return None                          # A's name whatever the value: no object
        for who, other in (("peer", peer.sender), ("anonymous", peer.anonymous)):
            if other is None:
                continue
            bound = _FormBoundSender(other, candidate)
            got = [self._compared(bound, candidate, value, role="mutation",
                                  label=_REPLAY_LABEL[who], admits=APPLICATION_OR_POLICY,
                                  credentialed=who == "peer")
                   for _ in range(2)]
            if all(view_of_owner(g) for g in got):
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"who": who, "param": candidate.param,
                                "status": [g.status for g in got]})
        return None


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
#: The entity is referenced in the root element's text: an external entity is
#: fetched when the parser expands its reference, wherever it appears (W3C XML 1.0
#: §4.4.3 "Included If Validating" / §4.4.2 "Included"; PortSwigger Web Security
#: Academy, "XXE injection": `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "...">]>` then
#: `&xxe;` in any text node). Until 2026-11-20 a first wrapper named one labgen
#: app's own extracted element (PA-0660, BUG-0661).
_XXE_ENTITY_WRAPPERS = [
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
        canary = _canary(self._listener, token)
        for wrapper in _XXE_ENTITY_WRAPPERS:
            probe = sender.send(candidate.url, candidate.param,
                                _xxe_payload(canary, wrapper),
                                method=candidate.method, location=candidate.location,
                                content_type="application/xml")
            if self._listener.proof(token) in (probe.text or ""):     # BUG-0089
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
        canary = _canary(self._listener, token)
        unobserved = _send_blind(lambda: sender.send(
            candidate.url, candidate.param, _xxe_payload(canary, _XXE_ENTITY_WRAPPERS[0]),
            method=candidate.method, location=candidate.location,
            content_type="application/xml"))
        hit = _await_callback(self._listener, token, canary, self._timeout)
        if hit is not None:
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"canary": canary, "hit_path": hit.path})
        if unobserved:
            raise ProbeUnobserved(_OOB_UNOBSERVED)
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
    freshly-minted per-run marker in the standard identity claims a
    black-box tester can expect a server to read: RFC 7519 §4.1.2 `sub`
    and OpenID Connect Core 1.0 §5.1 `name` / `preferred_username`
    (`STANDARD_CLAIMS`; PA-0660, BUG-0661 -- until 2026-11-20 the marker
    travelled in one labgen app's own claim name, which no black-box
    target can be expected to read). Confirms only if this returns HTTP
    200 with that exact marker echoed back -- proof the target trusted the
    unsigned token's own forged claims. A target that reads only an
    app-specific claim is a stated miss, not a guess.

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

    #: Claims the marker travels in: RFC 7519 §4.1.2 (`sub`, the registered subject
    #: claim) and OpenID Connect Core 1.0 §5.1 standard claims (`name`,
    #: `preferred_username`). Never an app's own claim name (PA-0660).
    STANDARD_CLAIMS = ("sub", "name", "preferred_username")

    def _claims(self, token: str) -> dict:
        return {claim: token for claim in self.STANDARD_CLAIMS}

    def confirm(self, candidate, sender):
        token = _token()
        alg_none_jwt = (
            _jwt_b64url({"alg": "none", "typ": "JWT"}) + "."
            + _jwt_b64url(self._claims(token)) + "."
        )
        probe_a = self._send(sender, candidate, f"Bearer {alg_none_jwt}")
        if probe_a.status != 200 or token not in (probe_a.text or ""):
            return None
        garbage_hs256_jwt = (
            _jwt_b64url({"alg": "HS256", "typ": "JWT"}) + "."
            + _jwt_b64url(self._claims(token)) + "."
            + "garbage-not-a-real-signature"
        )
        probe_b = self._send(sender, candidate, f"Bearer {garbage_hs256_jwt}")
        if probe_b.status not in (401, 403):
            return None
        return Verdict(True, self.vuln_class, self.mechanism, {"marker": token})


#: Units per second a clock-derived token may count in: seconds, milliseconds,
#: microseconds, nanoseconds (POSIX `time` / `clock_gettime`, JavaScript `Date.now`,
#: Go `time.Now().UnixNano`, Java `System.currentTimeMillis` / `System.nanoTime`).
_CLOCK_UNITS = (("s", 1), ("ms", 1_000), ("us", 1_000_000), ("ns", 1_000_000_000))
#: An epoch reading lies within a day of this host's clock.
_EPOCH_SLACK_S = 86_400
#: The smallest step a nanosecond monotonic counter can show between two requests that
#: each make a network round trip (10 us): a sequence counter stepping by 1 is no clock.
_MONOTONIC_MIN_STEP_NS = 10_000


def _decimal_leaves(text: str | None) -> dict[tuple, int]:
    """Every JSON leaf of the response (any key path) whose value is an all-decimal
    integer of 9 to 20 digits, keyed by its path. The key's name is never read
    (PA-0660, BUG-0661)."""
    import json

    from fuzzlab.core import jsonbody
    try:
        leaves = jsonbody.leaves(json.loads(text or ""))
    except (ValueError, TypeError):
        return {}
    out: dict[tuple, int] = {}
    for path, value in leaves or []:
        if isinstance(value, bool):
            continue
        raw = str(value) if isinstance(value, (int, str)) else ""
        if raw.isascii() and raw.isdigit() and 9 <= len(raw) <= 20:
            out[path] = int(raw)
    return out


def _clock_reading(a: int, b: int, window_s: float, now: float) -> str | None:
    """How ``a`` then ``b`` (one leaf, read by two requests sent within ``window_s``
    seconds of this host's monotonic clock) read as a clock, or None: an epoch count
    in some unit near ``now`` that moved by no more than the window, or a nanosecond
    monotonic counter (Java `System.nanoTime`, CLOCK_MONOTONIC: no epoch origin) that
    moved by at least one round trip and no more than the window. The window is an
    upper bound by causality, never a jitter-sensitive estimate."""
    delta = b - a
    if delta < 0:
        return None
    for name, per_s in _CLOCK_UNITS:
        if abs(a / per_s - now) <= _EPOCH_SLACK_S and delta <= (window_s + 1) * per_s:
            return f"epoch-{name}"
    if _MONOTONIC_MIN_STEP_NS <= delta <= (window_s + 1) * 1_000_000_000:
        return "monotonic-ns"
    return None


class PredictableTokenSourceStrategy(ConfirmationStrategy):
    """Confirms a predictable, timestamp-derived session token (CWE-330,
    this project's own `CC-LAB-0181` cell) with a two-probe differential:
    send two ordinary probes, read every JSON leaf of each response whose value
    is an all-decimal integer, and confirm only if one key path reads as a
    clock in both (`_clock_reading`): an epoch count in seconds, milliseconds,
    microseconds or nanoseconds near this host's time that moved by no more
    than the measured window around the two sends (plus 1 s), or a nanosecond
    monotonic counter with no epoch origin that moved by at least one round
    trip and no more than that window. The key's name is never read (PA-0660,
    BUG-0661: until 2026-11-20 the strategy read one labgen app's own response
    key). The window is measured on this host's monotonic clock from before
    the first send to after the second answer, so it bounds the server's two
    readings by causality; jitter only widens it. A random token (hex, or a
    random decimal) essentially never lands in that window; a sequence counter
    stepping by 1 is below the monotonic minimum step and is not near the
    epoch, so it is not a clock either.

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

    def confirm(self, candidate, sender):
        import time

        start = time.monotonic()
        probe_a = self._send(sender, candidate, "{}")
        probe_b = self._send(sender, candidate, "{}")
        window = time.monotonic() - start
        now = time.time()
        values_a = _decimal_leaves(probe_a.text)
        values_b = _decimal_leaves(probe_b.text)
        for path, token_a in values_a.items():
            token_b = values_b.get(path)
            if token_b is None:
                continue
            clock = _clock_reading(token_a, token_b, window, now)
            if clock is not None:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"token_a_prefix": str(token_a)[:8],
                                "token_b_prefix": str(token_b)[:8],
                                "clock": clock, "delta": token_b - token_a})
        return None


class MassAssignmentPrivilegedFieldStrategy(ConfirmationStrategy):
    """Confirms unrestricted mass assignment (CWE-915; OWASP API Security Top 10
    2023 API3 "Broken Object Property Level Authorization"; OWASP Mass
    Assignment Cheat Sheet) on a JSON whole-body point, from the target's own
    response alone (PA-0660, BUG-0661: until 2026-11-20 this strategy sent one
    labgen app's own field names, which no black-box target can be expected to
    have).

    Probe A sends an empty JSON object. Requires HTTP 200 and a JSON object
    response; the record's own top-level boolean properties reading `false`
    that the request did not send are the candidates (the server reports them
    on its own, so the client was never asked for them).

    Probe B sends each candidate property set to `true`. Probe C, the control,
    sends one never-existing property (`zq<hex>`) set to `true`. Confirms only
    if probe B is HTTP 200 and at least one candidate now reads `true`, while
    probe C's property does not come back -- so an endpoint that merely
    reflects whatever JSON it is sent is never mistaken for one that binds the
    request into its record.

    Stated limits: a target whose privileged property is not a top-level
    boolean the response reports, or that answers an empty object with an
    error, gives no verdict (a miss, never a guess). A boolean the app's own
    client legitimately sets (a preference) is indistinguishable here from a
    privileged one: the evidence names the property so a reviewer can judge it.
    """
    vuln_class = "mass_assignment"
    mechanism = "privileged-field-injection"
    category = "mass-assignment"

    @staticmethod
    def _object(text: str | None) -> dict | None:
        import json
        try:
            value = json.loads(text or "")
        except (ValueError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    def confirm(self, candidate, sender):
        import json

        if candidate.content_type != "application/json":
            return None    # only a declared-JSON whole-body point can carry this format
        probe_a = self._send(sender, candidate, "{}")
        record = self._object(probe_a.text) if probe_a.status == 200 else None
        if not record:
            return None
        unsent = [k for k, v in record.items() if v is False]
        if not unsent:
            return None    # no property the server reports on its own to try
        probe_b = self._send(sender, candidate, json.dumps({k: True for k in unsent}))
        after = self._object(probe_b.text) if probe_b.status == 200 else None
        if not after:
            return None
        flipped = [k for k in unsent if after.get(k) is True]
        if not flipped:
            return None    # nothing the request set was bound into the record
        control = "zq" + _token()
        probe_c = self._send(sender, candidate, json.dumps({control: True}))
        if control in (probe_c.text or ""):
            return None    # the endpoint reflects any property: no binding evidence
        return Verdict(True, self.vuln_class, self.mechanism,
                       {"field": flipped[0], "fields": flipped})


# --- unrestricted file upload (CWE-434, this project's `CC-LAB-0186` cell) --
# A real, minimal, valid 1x1 transparent PNG (67 bytes) -- decoded once at
# import time, never constructed as a Python `str` with raw high bytes in it
# (that would round-trip incorrectly through utf-8 encoding). Used as the
# control probe's genuinely-real image content, so `UnrestrictedFileUpload
# ContentTypeTrustStrategy`'s differential has a real "this IS a real image"
# leg to compare its malicious, NOT-a-real-image leg against.
_MINIMAL_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY"
    "42YAAAAASUVORK5CYII="
)

# Raster image types a *sniffing* (real-bytes) implementation can honestly
# report for a real image upload -- this strategy's secure/control leg.
_SAFE_RASTER_CONTENT_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}

# Content types that let an uploaded file's bytes execute as active content
# when served back same-origin -- the real CWE-434-to-XSS chain
# `NoExtensionCheckSink`'s own docstring documents (`.html`/`.svg` -> `text/
# html`/`image/svg+xml`). Deliberately a named, bounded set (not "anything
# that isn't a safe raster type") -- an unusual-but-harmless type like
# `application/octet-stream` (forces a download, never executes) must not
# count as evidence, or this strategy would over-claim on a merely odd
# response rather than a genuinely dangerous one.
_SCRIPT_EXECUTABLE_CONTENT_TYPES = {
    "text/html", "application/xhtml+xml", "image/svg+xml",
    "text/xml", "application/xml",
}


def _multipart_body(field_name: str, filename: str, content: bytes,
                    declared_content_type: str) -> tuple[str, str]:
    """Build a real `multipart/form-data` body (one file part) as a `str`.

    Encoded via latin-1 (a lossless 1:1 byte<->codepoint mapping, the same
    convention `fuzzlab.proxy`/`fuzzlab.web` already use for raw bytes) so it
    survives `Sender`'s own `str`-only ``value`` parameter round trip intact
    even when ``content`` is genuinely binary (e.g. a real PNG's magic
    bytes, all >= 0x80) -- `RequestsProbeSender`/`SeamProbeSender` re-encode
    a multipart body via latin-1 too (see their own `content_type.startswith
    ("multipart/")` branch), never utf-8, which would corrupt any byte
    >= 0x80 into a multi-byte sequence.
    """
    boundary = "----FuzzLabUploadBoundary" + secrets.token_hex(8)
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {declared_content_type}\r\n\r\n"
    ).encode("ascii")
    footer = f"\r\n--{boundary}--\r\n".encode("ascii")
    return (header + content + footer).decode("latin-1"), boundary


def _response_content_type(probe: Probe) -> str:
    """Case-insensitive `Content-Type` lookup, header params stripped/lowered."""
    for k, v in (probe.headers or {}).items():
        if k.lower() == "content-type":
            return (v or "").split(";", 1)[0].strip().lower()
    return ""


class UnrestrictedFileUploadContentTypeTrustStrategy(ConfirmationStrategy):
    """Confirms unrestricted file upload / extension-trusted `Content-Type`
    (CWE-434, `CC-LAB-0186`'s deliberately-deferred detection follow-on) by a
    real `multipart/form-data` two-probe differential over Twitch's own
    emote-upload shape (`TWCH-0009`, `sink_context="fs_web_root_write"`):
    does the endpoint decide the response `Content-Type` it serves an
    uploaded file back with from the caller-supplied filename's *extension*,
    rather than the file's real bytes?

    Verified directly against the real templates before designing this
    (`fuzzlab/labgen/emitters/go_net_http/templates/sinks/
    no_extension_check.go.j2` / `extension_allowlist_mime_check.go.j2`):
    both twins write-and-serve in the *same* POST response -- there is no
    separate GET-the-served-file round trip to make, so this strategy reads
    the upload response's own `Content-Type` header directly.

    **Probe A (malicious)**: uploads a file named ``probe.svg`` (a
    plausible, image-*looking* extension -- svg is a real, commonly
    accepted upload extension) whose actual bytes are an inert, non-
    executing marker (``<!DOCTYPE html><p>FUZZLAB-MARKER-...</p>``, per
    `NFR-AUD-safe` -- never a real `<script>` tag, the same probe-safety
    convention `CC-LAB-0186`'s own live-boot test already uses) -- bytes
    that are NOT valid image content of any format. Confirms only a first
    condition from this leg: HTTP 2xx (the upload was accepted, not
    rejected for its bad content) with the marker echoed back in the body
    (proof the response is genuinely serving *this* upload, not an
    unrelated cached/canned page) and a response `Content-Type` in the
    named, bounded `_SCRIPT_EXECUTABLE_CONTENT_TYPES` set (not a bare
    "isn't a safe raster type" heuristic, which would over-claim on a
    harmless-but-unusual type like `application/octet-stream`).

    **Probe B (control, the false-positive defense)**: uploads a file named
    ``control.png`` whose bytes are a real, minimal, valid PNG
    (`_MINIMAL_PNG_BYTES`). Requires HTTP 2xx with a response `Content-Type`
    in `_SAFE_RASTER_CONTENT_TYPES`. This is the differential's real
    purpose, the same "two-probe, not a bare single-probe heuristic"
    reasoning `InsecureDeserializationTypeConfusionStrategy`'s own docstring
    argues for: it rules out a legitimate SVG/image-accepting endpoint that
    would *also* serve `image/svg+xml` for a genuine SVG upload (that alone
    is correct, unremarkable behavior, not a vulnerability) -- probe A only
    counts as evidence once probe B has independently shown this same
    endpoint DOES correctly report a real image's type when given real
    image bytes, proving the dangerous type on probe A came specifically
    from trusting the filename over content that was never actually image
    data, not from some generic "always echoes text/html" bug or a
    coincidentally-permissive but harmless SVG feature.

    Confirms only when both legs hold. A target that rejects probe A
    outright (a real allowlist/content-sniff, `ExtensionAllowlistMimeCheck
    Sink`'s own secure behavior) or that fails to correctly serve probe B's
    real image fails closed, never a guess.

    Known limitation, not silently swept under the rug: this assumes the
    vulnerable/secure difference is observable directly in the upload
    response itself (true for this project's own Go/Twitch lab shape,
    verified against the real templates above) -- a target that instead
    redirects to, or requires a separate GET of, the served file's own URL
    would have nothing for this strategy to read from a single POST
    response, so it fails closed rather than following a redirect this
    strategy was never designed to chase.
    """
    vuln_class = "unrestricted_file_upload"
    mechanism = "extension-content-type-trust-differential"
    category = "unrestricted-file-upload"

    def confirm(self, candidate, sender):
        marker = _token()
        malicious_field = candidate.param or "file"

        malicious_content = f"<!DOCTYPE html><p>FUZZLAB-MARKER-{marker}</p>".encode("utf-8")
        malicious_body, malicious_boundary = _multipart_body(
            malicious_field, "probe.svg", malicious_content,
            declared_content_type="application/octet-stream",
        )
        probe_a = sender.send(
            candidate.url, candidate.param, malicious_body,
            method=candidate.method, location=candidate.location,
            content_type=f"multipart/form-data; boundary={malicious_boundary}",
        )
        if probe_a.status < 200 or probe_a.status >= 300:
            return None    # rejected outright -- not trusting the extension over the bytes
        if marker not in (probe_a.text or ""):
            return None    # not served back verbatim -- can't attribute the type to this upload
        served_type = _response_content_type(probe_a)
        if served_type not in _SCRIPT_EXECUTABLE_CONTENT_TYPES:
            return None    # the extension-derived type isn't one that would execute in-browser

        control_body, control_boundary = _multipart_body(
            malicious_field, "control.png", _MINIMAL_PNG_BYTES,
            declared_content_type="image/png",
        )
        probe_b = sender.send(
            candidate.url, candidate.param, control_body,
            method=candidate.method, location=candidate.location,
            content_type=f"multipart/form-data; boundary={control_boundary}",
        )
        if probe_b.status < 200 or probe_b.status >= 300:
            return None    # can't even accept a genuine image -- no clean differential
        control_type = _response_content_type(probe_b)
        if control_type not in _SAFE_RASTER_CONTENT_TYPES:
            return None    # doesn't correctly report a real image's type either

        return Verdict(True, self.vuln_class, self.mechanism,
                       {"marker": marker, "served_content_type": served_type,
                        "control_content_type": control_type})


# Grey-box (M10) default confirmation-side probes: something that would reach the
# vulnerable sink (a SQLi syntax-breaker; an XSS canary) so the coverage/DB-fault
# side channel has something to observe. Distinct from the black-box strategies'
# own probes above -- this one probe is purely to *generate* the signal, not to
# read the HTTP response for a verdict (the verdict comes from coverage/db_fault).
_GREYBOX_PROBE_PAYLOADS = {
    "sqli": "1' OR '1'='1' -- -",
    "xss": "<fzlgbx>",
}


def _greybox_sink_file(url: str, coverage, app_root: str | None = None) -> str | None:
    """The covered file that serves a candidate's URL, read from the coverage
    (SP-145's `greybox.coverage.endpoint_file`, FR-FUZZ-710): no assumed document root;
    ``app_root`` only when the operator gave one; None when no covered file maps."""
    return endpoint_file(url, coverage, root=app_root)


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
                 app_root: str | None = None):
        self._coverage = coverage
        self._dbfault = dbfault
        self._app_root = app_root

    def applies(self, candidate: Candidate) -> bool:
        return candidate.category in self._CATEGORIES

    def confirm(self, candidate, sender):
        # Nothing to observe with is not an observation: such a run must never make the
        # point read as tested (forms phase 3 integration: an untested fragment point
        # was recorded as a negative). The oracle takes this as "no verdict from this
        # mechanism"; other mechanisms still decide.
        if self._coverage is None and self._dbfault is None:
            raise UnplaceableLocation("greybox: no coverage or DB-fault source attached")
        send_correlated = getattr(sender, "send_correlated", None)
        if send_correlated is None:
            raise UnplaceableLocation("greybox: the sender cannot mint a correlation id")
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
        sink_covered = _greybox_sink_file(candidate.url, coverage, self._app_root) \
            is not None
        db_fault = self._dbfault.fault_for(request_id).faulted \
            if self._dbfault is not None else False
        signal = GreyboxSignal(sink_covered=sink_covered, db_fault=db_fault)
        if greybox_confirms(vuln_class, signal):
            return Verdict(True, vuln_class, self.mechanism, m10_evidence(vuln_class, signal))
        return None


# --- browser-execution XSS (M6): stored + DOM. Need an injected BrowserExecutor. ---
#: The sentinel token's alphabet: safe inside a JS string of any quote (BUG-0139).
#: `_token` draws hex.
_SENTINEL_TOKEN = re.compile(r"[0-9A-Za-z]+")


def _xss_exec_payloads(token: str) -> list[str]:
    """Payloads that, if they execute, call the sentinel with the token.

    BUG-0139 (PA-0139): the sentinel call comes in three quoting shapes, so a sink
    whose data path breaks on one quote character is never a guaranteed miss (Juice
    Shop's ``/rest/track-order/:id`` evaluates the id inside a single-quoted string:
    a ``'`` answers 500 and nothing renders):
    - ``'TOKEN'``;
    - backticks, with no single quote;
    - ``String.fromCharCode(...)`` of the token: no quote character, no ``/``, no
      whitespace, in an unquoted attribute value. It survives a path-segment sink,
      where a ``/`` would cut the value (review A-S1).

    Ordered by reach (review A-S2): the quoted ``<img>`` first, as before, then the
    backtick and the ``fromCharCode`` forms, then the other three quoted wrappers. The
    token is still the one fresh, random token the sentinel binding checks."""
    if not _SENTINEL_TOKEN.fullmatch(token or ""):
        raise ValueError("the sentinel token must be alphanumeric")
    call = f"{SENTINEL}('{token}')"
    backtick = f"{SENTINEL}(`{token}`)"
    codes = ",".join(str(ord(c)) for c in token)
    bare = f"{SENTINEL}(String.fromCharCode({codes}))"
    return [
        f"<img src=x onerror=\"{call}\">",
        f"<img src=x onerror=\"{backtick}\">",          # no single quote
        f"<img src=x onerror={bare}>",                   # no quote, no /, no space
        f"\"><img src=x onerror=\"{call}\">",
        f"<svg onload=\"{call}\">",
        f"<script>{call}</script>",
    ]


def _quote_free(payload: str) -> bool:
    """No quote character of any kind (BUG-0139 review B-S1)."""
    return not set("'\"`") & set(payload)


class _BrowserXssStrategy(ConfirmationStrategy):
    """Shared M6 logic: place a tokened payload, execute in a browser, confirm on fire."""
    category = "xss"
    #: Payloads not observed in a row before the strategy stops trying (BUG-0137 review
    #: Z1): a page that cannot be loaded costs at most this many browser loads.
    MAX_NOT_OBSERVED = 2

    def __init__(self, executor: BrowserExecutor | None = None):
        self._executor = executor

    def _observe(self, candidate: Candidate, payload: str, token: str) -> ExecObservation:
        raise NotImplementedError

    def _last_try(self, candidate, payloads, tried, token, not_observed):
        """After `MAX_NOT_OBSERVED` unobserved payloads in a row: one more load, of the
        first untried quote-free payload, if any (at most 1 extra load). A hit
        confirms; anything else leaves the candidate inconclusive (Z4)."""
        nxt = next((i for i, p in enumerate(payloads)
                    if i not in tried and _quote_free(p)), None)
        if nxt is not None:
            try:
                obs = self._observe(candidate, payloads[nxt], token)
            except UnplaceableLocation:              # NotObserved, or no browser now
                obs = None
            if obs is not None and obs.executed:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"payload": payloads[nxt], "detail": obs.detail})
        return Verdict(False, self.vuln_class, self.mechanism,
                       {"not_observed": not_observed[:200]}, inconclusive=True)

    def confirm(self, candidate, sender):
        if self._executor is None:
            # no browser: this mechanism observed nothing, at any location, so it gives
            # no verdict -- never a negative (CC-FUZZ-0070; reviewer A: not only for a
            # fragment point). The oracle decides which mechanisms count (`decided_by`,
            # FR-AUD-30): a browser-only candidate is left inconclusive.
            raise UnplaceableLocation("no browser attached: browser XSS not observed"
                                      if candidate.location != "fragment" else
                                      "a fragment point is placed by the browser only")
        not_observed: str | None = None
        misses = 0                                   # payloads not observed in a row
        payloads = _xss_exec_payloads((token := _token()))
        tried: set[int] = set()
        for index, payload in enumerate(payloads):
            tried.add(index)
            try:
                obs = self._observe(candidate, payload, token)
            except NotObserved as exc:
                # BUG-0137 review (Z1): this payload's page could not be observed; the
                # next payload is still tried. A browser that cannot start
                # (`UnplaceableLocation`) or a placement refusal stops at once.
                not_observed = not_observed or str(exc)
                misses += 1
                if misses >= self.MAX_NOT_OBSERVED:  # cost bound (FR-FUZZ-48)
                    # still the first untried quote-free payload: a path that fails on
                    # a quote may fail the quoted payloads' loads (review B-S1)
                    return self._last_try(candidate, payloads, tried, token,
                                          not_observed)
                continue
            except UnplaceableLocation:
                # the browser cannot start (BUG-0126) after a payload went unobserved:
                # still the inconclusive verdict below, not "no verdict" (review B-N2)
                if not_observed is None:
                    raise
                break
            misses = 0
            if obs.executed:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"payload": payload, "detail": obs.detail})
        if not_observed is not None:
            # Z4 (D54): no hit, and a payload was not observed: inconclusive
            # (FR-FUZZ-45) -- never a negative, so it never enters the ML negatives
            return Verdict(False, self.vuln_class, self.mechanism,
                           {"not_observed": not_observed[:200]}, inconclusive=True)
        return None


class DomXssStrategy(_BrowserXssStrategy):
    """M6: payload in the URL (query/fragment) executes client-side (no server round-trip).

    Only a query or fragment point applies: a body or header payload is never moved
    into the URL (BUG-0115, PA-0115) -- that would record a URL-borne DOM XSS against
    a POST field or a header, and cost a browser load per probe for nothing."""
    vuln_class = "xss-dom"
    mechanism = "browser-execution"
    _PLACEABLE = ("query", "fragment")

    def applies(self, candidate: Candidate) -> bool:
        return super().applies(candidate) and candidate.location in self._PLACEABLE

    def _observe(self, candidate, payload, token):
        if candidate.location not in self._PLACEABLE:     # refuse, never relocate
            raise UnplaceableLocation(f"DOM XSS places query or fragment points only, "
                                      f"not {candidate.location!r}")
        # a query point's link set is loaded with it, bound as the HTTP senders bind it
        # (FR-FUZZ-64); the browser load is an observation, not a comparison control
        # (`_compared` is not involved)
        entries = candidate.base_entries if candidate.location == "query" else None
        if entries and candidate.bindings:
            # FR-FUZZ-67 (BUG-0544): a stored placeholder is never loaded as a value, and
            # the executor has no fetch of the page to bind a fresh one from
            from fuzzlab.oracle.probe import PrerequisiteUnavailable
            raise PrerequisiteUnavailable("the browser cannot bind fresh values for "
                                          + ", ".join(candidate.bindings.get("fresh")
                                                      or ()))
        return self._executor.run(
            ExecRequest(url=candidate.url, param=candidate.param, value=payload,
                        location=candidate.location,
                        entries=tuple(tuple(e) for e in entries) if entries else None),
            token)


class StoredXssStrategy(_BrowserXssStrategy):
    """M6: payload stored via one request, executes when the render page is loaded."""
    vuln_class = "xss-stored"
    mechanism = "browser-execution"

    def _observe(self, candidate, payload, token):
        if not candidate.store_url:            # need the store endpoint (source_url)
            raise UnplaceableLocation("stored XSS needs the candidate's store URL")
        store = StoreStep(url=candidate.store_url, param=candidate.store_param or candidate.param,
                          value=payload, method=candidate.store_method,
                          location=candidate.store_location,
                          entries=candidate.store_entries)
        return self._executor.run(ExecRequest(url=candidate.url, store=store), token)


class PriceTrustDifferentialStrategy(ConfirmationStrategy):
    """Confirms `price_integrity_bypass` (CWE-807; OWASP WSTG v4.2 WSTG-BUSL-01;
    PortSwigger Web Security Academy "Excessive trust in client-side controls")
    with a two-probe differential over the numeric leaves of the app's own
    captured JSON body (`candidate.base_entries`), never over a field name the
    strategy assumes (PA-0660, BUG-0661: until 2026-11-20 it sent one labgen
    endpoint's own field and tier names).

    For each numeric leaf of the captured body: probe A sends the body with that
    leaf set to an implausibly low amount (`0.01`), probe B with an implausibly
    high one (`999999.99`). Confirms only if both are HTTP 200 and the response's
    JSON leaf at the same path reads back exactly what each probe sent -- the
    server's amount tracks the client's, not merely "some number came back".

    Stated limits: with no captured JSON body (a point the answer key named but
    no crawl captured), or a response that does not echo the amount at the
    request's own path, there is no verdict (a miss, never a guess). At most
    `MAX_LEAVES` numeric leaves are tried.
    """
    vuln_class = "price_integrity_bypass"
    mechanism = "client-price-trust-differential"
    category = "price-integrity-bypass"

    _LOW_AMOUNT = 0.01
    _HIGH_AMOUNT = 999999.99
    MAX_LEAVES = 4

    @staticmethod
    def _reading(text: str | None, path: tuple):
        import json

        from fuzzlab.core import jsonbody
        try:
            leaves = jsonbody.leaves(json.loads(text or ""))
        except (ValueError, TypeError):
            return None
        for p, v in leaves or []:
            if p == path and isinstance(v, (int, float)) and not isinstance(v, bool):
                return v
        return None

    def confirm(self, candidate, sender):
        from fuzzlab.core import jsonbody

        if candidate.content_type != "application/json" or not candidate.base_entries:
            return None
        try:
            base = jsonbody.normalize_entries(candidate.base_entries)
        except jsonbody.JsonPlacementError:
            return None
        numeric = [p for p, v in base
                   if isinstance(v, (int, float)) and not isinstance(v, bool)]
        for path in numeric[:self.MAX_LEAVES]:
            name = jsonbody.display_name(path)
            readings = []
            for amount in (self._LOW_AMOUNT, self._HIGH_AMOUNT):
                try:
                    body = jsonbody.body_with(base, {name: amount}).decode("utf-8")
                except jsonbody.JsonPlacementError:
                    break
                probe = self._send(sender, candidate, body)
                reading = self._reading(probe.text, path) if probe.status == 200 else None
                if reading != amount:
                    break
                readings.append(reading)
            if len(readings) == 2:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"field": name, "low": readings[0], "high": readings[1]})
        return None


class HttpHeaderInjectionCrlfStrategy(ConfirmationStrategy):
    """Confirms `http_header_injection` (CWE-113, HTTP response splitting --
    `CC-LAB-0198`'s own deliberately-deferred detection follow-on, Twitch's
    `TWCH-0013`, `GET /channels/redirect?destination=`) with a real,
    live-verified CRLF-response-header-injection differential.

    Read `fuzzlab/labgen/emitters/go_net_http/templates/sinks/
    raw_socket_response_write.go.j2` (the vulnerable twin) before designing
    this: it hijacks the raw connection (`http.Hijacker.Hijack()`) and
    hand-writes ``"Location: " + destination + "\\r\\n"`` byte-for-byte,
    with no CR/LF stripping at all -- the honest reason this concern can
    exist on Go at all, since Go's *ordinary* `w.Header().Set()`/
    `w.WriteHeader()` path already silently replaces a bare CR/LF byte with
    a space before writing to the wire (verified empirically, see
    `CC-LAB-0198`'s own change-control entry) -- an "honest vulnerable
    instance" of this concern is impossible to build through that ordinary
    path in Go, which is exactly why this lab's vulnerable twin needs the
    hijack bypass.

    **How this was actually verified, not assumed** (per this change's own
    task): does a normal `requests`-based HTTP client actually observe a
    genuinely-spliced-in extra response header, or does something in
    `requests`/`urllib3`'s own header parsing normalize/merge/hide it
    first? Booted the real app (`GoLiveBootHarness`) and sent a raw
    `RequestsProbeSender` probe directly, before writing this class:
    ``destination="/ok\\r\\nX-Injected-Marker: abc123marker"`` against the
    vulnerable twin came back with `probe.headers == {"Location": "/ok",
    "X-Injected-Marker": "abc123marker", "Content-Length": "0"}`; the same
    payload against the secure twin (`allowlist_and_runtime_crlf_
    rejection`) came back HTTP 400 with no injected header at all. `requests`
    (via `urllib3` -> `http.client`'s own header parser) parses a genuinely
    well-formed extra header LINE exactly like any other real header --
    there is no merging/normalization defeating observation here, because
    this payload shape (one injected header, no second blank-line-
    terminated fake response) never triggers `requests`' own duplicate-
    header-folding behavior (which only applies to a header name repeated
    more than once, not a new header name). A raw-socket/`http.client`-level
    probe (the alternative this class's own docstring above was asked to
    consider) turned out to be unnecessary in practice -- confirmed
    empirically, not assumed, before ruling it out.

    **Differential design (a control probe defends against a false
    positive)**: both probes carry the SAME randomly-generated, per-call
    header name and token (never a name a real app would ever legitimately
    emit, e.g. `X-Fuzzlab-Hdrinj-<hex>`) -- the only difference between them
    is whether a real CR/LF byte pair precedes it.

    - **Probe A (malicious)**: ``f"fuzzlab-ok\\r\\n{header_name}: {token}"``.
      Confirms only if the response actually carries a header named
      `header_name` (case-insensitive, matching `OpenRedirectStrategy`'s own
      `_header` convention) whose value equals `token`.
    - **Probe B (control)**: the identical text with the CR/LF replaced by a
      single space (``f"fuzzlab-ok {header_name}: {token}"``) -- same bytes,
      same header name/token substring present in the submitted value, no
      CR/LF at all. Requires the injected header to be ABSENT here. This is
      the real point of the differential: it rules out a target that, for
      some unrelated reason, ever turns an arbitrary substring of an input
      value into its own response header regardless of CR/LF (which would
      be a different bug, not this one) -- probe A only counts once probe B
      independently shows the identical marker text, submitted without a
      CR/LF, produces no such header.

    Confirms only when probe A shows the injected header and probe B does
    not. A target that rejects probe A outright (a real allowlist/CRLF
    rejection, `AllowlistAndRuntimeCrlfRejectionSink`'s own secure
    behavior) fails closed, correctly, never a guess.

    Known limitation, not silently swept under the rug: this detects CRLF
    injection observable as an EXTRA response header on the very same
    response the probe's own request received. A genuine full response-
    splitting attack (a second CRLF CRLF sequence terminating the current
    response and starting an entirely separate, fully attacker-controlled
    fake response smuggled to a downstream cache/proxy) is a related but
    distinct, stronger primitive this strategy does not attempt to detect
    separately -- this project's own lab shape (`CC-LAB-0198`) only
    instantiates the single-extra-header variant, so that is the only
    variant verified live and is treated here as this concern's full
    ground-truth scope, not silently narrowed."""
    vuln_class = "http_header_injection"
    mechanism = "crlf-response-header-injection-differential"
    category = "http-header-injection"

    @staticmethod
    def _header(probe, name):
        return next((v for k, v in probe.headers.items() if k.lower() == name), None)

    def confirm(self, candidate, sender):
        token = _token()
        header_name = f"X-Fuzzlab-Hdrinj-{token}"

        malicious = f"fuzzlab-ok\r\n{header_name}: {token}"
        with trace.role("mutation"):                  # FR-FUZZ-60
            probe_a = self._send(sender, candidate, malicious)
        injected = self._header(probe_a, header_name.lower())
        if injected != token:
            return None    # no genuinely spliced-in header -- fails closed

        control = f"fuzzlab-ok {header_name}: {token}"
        # FR-FUZZ-63: the control is the application's answer, or no verdict
        probe_b = self._compared(sender, candidate, control, role="control")
        if self._header(probe_b, header_name.lower()) is not None:
            return None    # the same marker text, sans CRLF, ALSO produced the header
                            # -- not attributable to CRLF splitting specifically

        return Verdict(True, self.vuln_class, self.mechanism,
                       {"header": header_name, "value": token})


def default_strategies(browser: BrowserExecutor | None = None,
                       oob: OobListener | None = None,
                       coverage: CoverageSource | None = None,
                       dbfault: DbFaultSource | None = None,
                       peer: PeerAccounts | None = None) -> list[ConfirmationStrategy]:
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
    # FR-FUZZ-620/621: LDAP and XPath injection live in their own module, which
    # builds on this one (imported here, not at the top, for that reason)
    from fuzzlab.oracle.ldap_xpath import LdapFilterInjectionStrategy, XPathInjectionStrategy
    return [SqliErrorStrategy(), SqliBooleanStrategy(), SqliEvaluationMarkerStrategy(),
            SqliTimingStrategy(), NoSqlOperatorStrategy(),
            ReflectedXssStrategy(), DomXssStrategy(browser), StoredXssStrategy(browser),
            OpenRedirectStrategy(), SstiStrategy(), GoTemplateSstiStrategy(),
            SpelInjectionStrategy(),
            PriceIntegrityBypassStrategy(), CsvFormulaInjectionStrategy(),
            PathTraversalStrategy(), CommandInjectionStrategy(),
            CommandInjectionOobStrategy(oob), RegexDosStrategy(),
            SsrfInBandMarkerStrategy(oob), SsrfOobStrategy(oob),
            CrossAccountReplayStrategy(peer),
            AccessControlIdorStrategy(peer.anonymous if peer is not None else None),
            InsecureDeserializationTypeConfusionStrategy(),
            XxeInBandMarkerStrategy(oob), XxeOobStrategy(oob),
            JwtAlgNoneConfusionStrategy(),
            PredictableTokenSourceStrategy(),
            MassAssignmentPrivilegedFieldStrategy(),
            UnrestrictedFileUploadContentTypeTrustStrategy(),
            PriceTrustDifferentialStrategy(),
            HttpHeaderInjectionCrlfStrategy(),
            PathTraversalFsPathReadStrategy(),
            *_follow_on_strategies(),
            LdapFilterInjectionStrategy(), XPathInjectionStrategy(),
            GreyboxConfirmationStrategy(coverage, dbfault),
            SsjsEvaluationMarkerStrategy(), SsjsBooleanDifferentialStrategy()]


def _follow_on_strategies() -> list[ConfirmationStrategy]:
    """Strategies that run after their category's own (CC-FUZZ-0630/0632): the JVM read
    sinks (FR-FUZZ-630/631) and the open-redirect filter bypass (FR-FUZZ-632). Imported
    here, as their modules import this one."""
    from fuzzlab.oracle.strategies_filters import OpenRedirectFilterBypassStrategy
    from fuzzlab.oracle.strategies_jvm import (PathTraversalClasspathResourceStrategy,
                                              SsrfFileSchemeStrategy)
    return [PathTraversalClasspathResourceStrategy(), SsrfFileSchemeStrategy(),
            OpenRedirectFilterBypassStrategy()]


# Reference-style category -> the oracle vuln_class we have a strategy for.
# Categories absent here have no confirmer yet (candidate emitted, not confirmed).
# Categories the oracle can confirm -> a representative class (the value is a hint;
# the pipeline scopes strategies by `category`, and 'xss' fans out to reflected +
# stored + DOM). A category absent here has no confirmer yet.
_CATEGORY_TO_CLASS = {
    "sql-injection": "sqli",
    "nosql-injection": "nosqli",
    "xss": "xss-reflected",
    "open-redirect": "open_redirect",
    "server-side-template-injection": "ssti",
    "spel-injection": "spel_injection",
    "price-integrity-bypass": "price_integrity_bypass",
    "csv-formula-injection": "csv_formula_injection",
    "file-inclusion": "file-inclusion",
    "command-injection": "command-injection",
    "regular-expression": "redos",
    "ssrf": "ssrf",
    "access-control": "access_control",
    "insecure-deserialization": "insecure_deserialization",
    "xxe": "xxe",
    "jwt-algorithm-confusion": "jwt_algorithm_confusion",
    "weak-token-entropy": "weak_token_entropy",
    "mass-assignment": "mass_assignment",
    "unrestricted-file-upload": "unrestricted_file_upload",
    "http-header-injection": "http_header_injection",
    "path-traversal": "path_traversal",
    "ldap-injection": "ldap_injection",            # FR-FUZZ-620
    "xpath-injection": "xpath_injection",          # FR-FUZZ-621
    "server-side-javascript-injection": "ssjs",
}


def category_to_oracle_class(category: str) -> str | None:
    return _CATEGORY_TO_CLASS.get(category)


# --- server-side JavaScript injection (FR-FUZZ-610..612, CC-FUZZ-0610) -----------------
#: Every probe below is a valid JavaScript expression in an unquoted, a single-quoted
#: and a double-quoted context alike (and plain text in a template literal), so a sink
#: that evaluates it where it lands -- Juice Shop's in-process ``$where``, which kills
#: Node on an uncaught ReferenceError or SyntaxError (ERROR_LOG 2026-10-19) -- never
#: throws on one. No probe loops, sleeps, exits, allocates, requires a module or names
#: anything but ``Math.abs``: a computed marker or a boolean, never a side effect.

def _ssjs_number() -> str:
    """A base value: a five-digit literal (a valid expression everywhere; in a quoted
    context a numeric string, compared numerically by ``>`` / ``==``)."""
    return str(secrets.randbelow(90000) + 10000)


def _ssjs_pair() -> tuple[int, int]:
    """``(k, j)``: two different two-digit numbers. ``Math.abs(-k)==j`` is false,
    ``Math.abs(-k)==k`` true, and the two probes have the same length."""
    k = secrets.randbelow(90) + 10
    j = secrets.randbelow(89) + 10
    return k, (j + 1 if j >= k else j)


def _ssjs_keep(quote: str) -> Callable[[str], str]:
    """V: the false condition. Unquoted: ``b||Math.abs(-k)==j``; quoted (``'``/``"``):
    ``b+'||Math.abs(-k)==j&&'+b``, which closes the app's string, ORs the condition
    and reopens it; unquoted it is a number plus a string plus a number."""
    def keep(base: str) -> str:
        k, j = _ssjs_pair()
        cond = f"Math.abs(-{k})=={j}"
        return f"{base}||{cond}" if not quote else f"{base}+{quote}||{cond}&&{quote}+{base}"
    return keep


def _ssjs_disc(quote: str) -> Callable[[str], str]:
    """D: the same shape with the true condition ``Math.abs(-k)==k``."""
    def disc(base: str) -> str:
        k, _j = _ssjs_pair()
        cond = f"Math.abs(-{k})=={k}"
        return f"{base}||{cond}" if not quote else f"{base}+{quote}||{cond}&&{quote}+{base}"
    return disc


#: Tried in this order; the first to confirm wins. Unquoted first: in a quoted context
#: its probes are inert strings. Compared by length (``exact=False``, `_similar`), not
#: text: a ``$where`` that matches several documents lists them in the order their
#: lookups finish -- NodeGoat's allocations page showed its three users in three
#: different orders over six identical requests (measured 2026-11-20, CC-FUZZ-0610).
_SSJS_FAMILIES = (
    _Family("js-unquoted", base=_ssjs_number, keep=_ssjs_keep(""), disc=_ssjs_disc(""),
            exact=False, strings=False),
    _Family("js-single-quoted", base=_ssjs_number, keep=_ssjs_keep("'"),
            disc=_ssjs_disc("'"), exact=False, strings=True),
    _Family("js-double-quoted", base=_ssjs_number, keep=_ssjs_keep('"'),
            disc=_ssjs_disc('"'), exact=False, strings=True),
)


class SsjsBooleanDifferentialStrategy(ConfirmationStrategy):
    """Server-side JavaScript injection, boolean (FR-FUZZ-611): a JavaScript condition
    the server evaluates -- a MongoDB ``$where`` built from the value (NodeGoat's
    allocations ``threshold``, Juice Shop's product reviews) -- changes the answer.

    Three families, each run by the bracketed, replicated engine
    (`ConfirmationStrategy._differential`): base ``b`` (five digits); V adds
    ``Math.abs(-k)==j`` (false), D ``Math.abs(-k)==k`` (true), joined with ``||``
    unquoted, or as ``b+'||…&&'+b`` to leave and re-enter a single- or double-quoted
    string. V and D have the same characters but the digits, the same length and the
    same operators: only an evaluator of JavaScript's ``Math.abs`` tells them apart. A
    SQL, template or shell sink errors (or stores the text) alike for both; a sink that
    takes the value as data answers both like B.

    Non-destructive by construction (CC-LAB-0317's open item): every probe is a valid
    expression in all three contexts (see the section comment), so no family's probe
    throws where another family's context holds.

    **Bound:** P[confirm] <= ``ENGINE_BOUND`` per family for any probe-independent
    response sequence. **Cost:** 3 requests per family whose screen fails (9 for a
    candidate that confirms nothing); ``HARD_CAP`` and an inconclusive verdict as
    `SqliBooleanStrategy`'s. Quoted families are skipped on a raw whole-body point."""
    vuln_class = "ssjs"
    mechanism = "js-boolean-differential"
    category = "server-side-javascript-injection"
    _FAMILIES = _SSJS_FAMILIES
    HARD_CAP = 10 * len(_SSJS_FAMILIES)

    def confirm(self, candidate, sender, rng=None):
        rng = rng if rng is not None else _engine_rng()
        spent, exhausted = 0, []
        for family in self._FAMILIES:
            if family.strings and candidate.content_type:
                continue
            if self.HARD_CAP - spent < FAMILY_COST:
                exhausted.append(family.name)
                continue
            evidence, cost = self._differential(sender, candidate, family, rng=rng)
            spent += cost
            if evidence is not None:
                evidence.pop("_d_texts")
                evidence.pop("_b0_text")
                evidence["requests"] = spent
                return Verdict(True, self.vuln_class, self.mechanism, evidence)
        if exhausted:
            return Verdict(False, self.vuln_class, self.mechanism,
                           {"cap_exhausted": True, "families_not_started": exhausted,
                            "requests": spent}, inconclusive=True)
        return None


def _ssjs_shows(text: str, literal: str, result: str) -> bool:
    """Does ``text`` show ``result`` (a decimal like ``4.817``, not inside a longer
    number) once every reflected form of the probe's own ``literal`` is removed? An
    echo of the expression is the sink reflecting input, never its value."""
    rest = _strip_reflections(text or "", [literal])
    return re.search(rf"(?<![\d.]){re.escape(result)}(?![\d])", rest) is not None


class SsjsEvaluationMarkerStrategy(ConfirmationStrategy):
    """Server-side JavaScript injection, evaluation marker (FR-FUZZ-610): the value is
    run as JavaScript (``eval``, ``new Function``, ``vm``) and its result shown --
    NodeGoat's contributions form ``eval``s each percentage and renders it.

    Probe 1 is ``Math.abs(-n)/1000`` (n in 1001..9999, not a multiple of 10): its
    result ``n/1000`` (``4.817``) must appear, not inside a longer number, once every
    reflected form of the expression is removed; then probe 2, with a result absent from
    response 1, must likewise appear in the response to the probe that computed it
    (temporal attribution, PA-0090 / BUG-0117's sweep). A small decimal so an app that
    range-checks the number (NodeGoat: 0..30 %) still shows it; ``Math.abs`` so a SQL,
    template, Python, PHP or Ruby evaluator raises instead (a JVM scripting engine with
    ``java.lang.Math`` -- Groovy -- would compute it too: still code evaluation). The
    expression has no side effect and is valid in every JavaScript context.
    1 request when unconfirmed, at most 2. Skipped on a raw whole-body point."""
    vuln_class = "ssjs"
    mechanism = "js-evaluation-marker"
    category = "server-side-javascript-injection"
    MAX_REQUESTS = 2

    @staticmethod
    def _draw() -> int:
        while True:
            n = secrets.randbelow(8999) + 1001
            if n % 10:
                return n

    @staticmethod
    def _value(n: int) -> str:
        return f"Math.abs(-{n})/1000"

    @staticmethod
    def _result(n: int) -> str:
        """JavaScript's (and Python's) shortest decimal for ``n/1000``: three places."""
        return f"{n // 1000}.{n % 1000:03d}"

    def confirm(self, candidate, sender):
        if candidate.content_type:
            return None
        n1 = self._draw()
        with trace.role("mutation"):
            text1 = self._send(sender, candidate, self._value(n1)).text or ""
        if not _ssjs_shows(text1, self._value(n1), self._result(n1)):
            return None
        for _ in range(32):                         # a result absent from response 1
            n2 = self._draw()
            if n2 != n1 and not _ssjs_shows(text1, self._value(n1), self._result(n2)):
                break
        else:
            return None                             # a page full of such numbers
        with trace.role("mutation"):
            text2 = self._send(sender, candidate, self._value(n2)).text or ""
        if _ssjs_shows(text2, self._value(n2), self._result(n2)):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"results": [self._result(n1), self._result(n2)],
                            "payloads": [self._value(n1), self._value(n2)]})
        return None
