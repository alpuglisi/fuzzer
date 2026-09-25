"""Tests for the additional deterministic oracle vectors (open-redirect, SSTI,
path traversal, command injection). Each confirms the true case and stays
fail-closed on a benign/secure one."""

import re

from fuzzlab.oracle import Candidate, category_to_oracle_class
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import (
    CommandInjectionStrategy,
    CsvFormulaInjectionStrategy,
    GoTemplateSstiStrategy,
    OpenRedirectStrategy,
    PathTraversalStrategy,
    PriceIntegrityBypassStrategy,
    SpelInjectionStrategy,
    SstiStrategy,
)


def _cand(vuln_class):
    return Candidate(url="http://h/x", param="p", vuln_class=vuln_class)


# --- open redirect (M9) ------------------------------------------------------

def test_open_redirect_confirmed_via_location_header():
    class RedirectSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(302, "", headers={"Location": value})   # echoes target -> redirect
    v = OpenRedirectStrategy().confirm(_cand("open-redirect"), RedirectSender())
    assert v is not None and v.confirmed and v.evidence["sink"] == "location-header"


def test_open_redirect_confirmed_via_meta_refresh():
    class MetaSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            html = f'<meta http-equiv="refresh" content="0;url={value}">'
            return Probe(200, html, headers={})
    v = OpenRedirectStrategy().confirm(_cand("open-redirect"), MetaSender())
    assert v is not None and v.evidence["sink"] == "meta-refresh"


def test_open_redirect_not_confirmed_on_mere_reflection():
    class LinkSender:  # canary only appears as a link href, not a redirect sink
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, f'<a href="{value}">next</a>', headers={})
    assert OpenRedirectStrategy().confirm(_cand("open-redirect"), LinkSender()) is None


# --- SSTI (M4) ---------------------------------------------------------------

def test_ssti_confirmed_when_expression_evaluated():
    class EvalSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            m = re.search(r"(\d+)\*(\d+)", value)              # evaluate the arithmetic
            out = str(int(m.group(1)) * int(m.group(2))) if m else value
            return Probe(200, f"<p>{out}</p>", headers={})
    v = SstiStrategy().confirm(_cand("ssti"), EvalSender())
    assert v is not None and v.confirmed and v.mechanism == "evaluation-marker"


def test_ssti_not_confirmed_on_reflection_without_eval():
    class ReflectSender:  # echoes the payload literally (not evaluated)
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, f"<p>{value}</p>", headers={})
    assert SstiStrategy().confirm(_cand("ssti"), ReflectSender()) is None


# --- SpEL injection (CWE-917) -------------------------------------------------

def test_spel_injection_confirmed_when_type_reference_evaluated():
    class UnrestrictedContextSender:
        """Models a real `StandardEvaluationContext` sink: a `T(...)` type
        reference genuinely evaluates -- `T(java.lang.Math).abs(-N)` -> `N`."""
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            m = re.search(r"T\(java\.lang\.Math\)\.abs\(-(\d+)\)", value)
            if m:
                return Probe(200, f"Sort result: {m.group(1)}", headers={})
            return Probe(400, "Sort expression error", headers={})
    v = SpelInjectionStrategy().confirm(_cand("spel-injection"), UnrestrictedContextSender())
    assert v is not None and v.confirmed and v.mechanism == "type-reference-evaluation"


def test_spel_injection_not_confirmed_when_type_reference_rejected():
    class RestrictedContextSender:
        """Models a real `SimpleEvaluationContext` sink: a `T(...)` type
        reference is rejected outright, the real documented fix."""
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(400, "Sort expression error: EL1053E", headers={})
    assert SpelInjectionStrategy().confirm(_cand("spel-injection"), RestrictedContextSender()) is None


def test_spel_injection_arithmetic_alone_would_have_been_a_false_positive():
    """Documents the exact pitfall this component's own pre-change review
    gate caught before implementation: a restricted `SimpleEvaluationContext`
    still evaluates bare literal arithmetic (only type/method/bean access is
    restricted) -- so a bare-arithmetic canary like `SstiStrategy`'s own
    would confirm on a SECURE twin too. This test proves the real strategy's
    own `T(...)`-based canary does NOT fall into that trap: a sender that
    evaluates bare arithmetic but rejects type references (the real
    SimpleEvaluationContext differential) must not be confirmed."""
    class ArithmeticOnlyRestrictedSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            m = re.fullmatch(r"(\d+)\*(\d+)", value)
            if m:
                return Probe(200, f"Sort result: {int(m.group(1)) * int(m.group(2))}", headers={})
            return Probe(400, "Sort expression error", headers={})   # T(...) rejected
    assert SpelInjectionStrategy().confirm(_cand("spel-injection"), ArithmeticOnlyRestrictedSender()) is None


# --- price integrity bypass (category 5, no CWE -- business-logic/trust-boundary) --

def test_price_integrity_bypass_confirmed_when_client_amount_echoed_back():
    class TrustedAmountSender:
        """Models the real vulnerable twin (`LABGEN-BC-0005`, empty transform
        pipeline): the submitted amount is echoed back verbatim in the
        checkout confirmation page's `data-charged-amount` attribute
        (`CC-LAB-0239`/`CC-FUZZ-0047`: a real HTML page since this step,
        not the JSON body this fixture modeled before it)."""
        def send(self, url, param, value, timing=False, method="POST", location="body"):
            return Probe(200, f'<p data-charged-amount="{value}">Charged: ${value}</p>', headers={})
    v = PriceIntegrityBypassStrategy().confirm(_cand("price-integrity-bypass"), TrustedAmountSender())
    assert v is not None and v.confirmed and v.mechanism == "trusted-client-amount-echo"


def test_price_integrity_bypass_not_confirmed_when_server_recomputes_amount():
    class RateTableSender:
        """Models the real secure twin (`LABGEN-BC-0006`, `server_recomputed_amount`):
        the response always reflects the server's own rate-table lookup,
        regardless of what the client submitted."""
        def send(self, url, param, value, timing=False, method="POST", location="body"):
            return Probe(200, '<p data-charged-amount="89.00">Charged: $89.00</p>', headers={})
    assert PriceIntegrityBypassStrategy().confirm(_cand("price-integrity-bypass"), RateTableSender()) is None


def test_price_integrity_bypass_canary_cannot_collide_with_the_real_rate_table():
    """Documents the pitfall this component's own pre-change adequacy review
    caught before implementation: a random two-decimal-place canary has a
    real, non-negligible chance of coincidentally equaling one of the real
    rate-table values (89.00/149.00/249.00), which would make even the
    SECURE twin's own genuine rate-table echo look like a confirmation. The
    real strategy's canary always has three decimal places -- structurally
    incompatible with the two-decimal-place rate table -- so a sender that
    echoes back exactly the (two-decimal) rate-table value it was sent must
    never be confirmed, run many times to rule out flakiness from the
    strategy's own randomness."""
    class EchoExactlyWhatItReceivedSender:
        def __init__(self):
            self.last_value = None

        def send(self, url, param, value, timing=False, method="POST", location="body"):
            self.last_value = value
            return Probe(200, f'<p data-charged-amount="{value}">Charged: ${value}</p>', headers={})

    for _ in range(50):
        strategy = PriceIntegrityBypassStrategy()
        sender = EchoExactlyWhatItReceivedSender()
        strategy.confirm(_cand("price-integrity-bypass"), sender)
        assert sender.last_value is not None
        assert sender.last_value not in PriceIntegrityBypassStrategy._RATE_TABLE_AMOUNTS
        whole, _, frac = sender.last_value.partition(".")
        assert len(frac) == 3, sender.last_value


# --- CSV formula injection (CWE-1236) -----------------------------------------

def test_csv_formula_injection_confirmed_when_trigger_echoed_unescaped():
    class UnescapedCsvSender:
        """Models the real vulnerable twin (`LABGEN-BC-0003`, empty
        transform pipeline): the value is embedded verbatim as a CSV cell,
        followed by the row's own trailing field."""
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, f"label,amount\n{value},129.00\n", headers={})
    v = CsvFormulaInjectionStrategy().confirm(_cand("csv-formula-injection"), UnescapedCsvSender())
    assert v is not None and v.confirmed and v.mechanism == "unescaped-formula-trigger-echo"


def test_csv_formula_injection_not_confirmed_when_neutralized():
    class QuotePrefixingCsvSender:
        """Models the real secure twin (`CsvFormulaNeutralizeTransform`):
        a leading single quote is prepended before any trigger character."""
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, f"label,amount\n'{value},129.00\n", headers={})
    assert CsvFormulaInjectionStrategy().confirm(_cand("csv-formula-injection"), QuotePrefixingCsvSender()) is None


def test_csv_formula_injection_match_is_anchored_to_the_cell_boundary():
    """Documents the pitfall this component's own pre-change adequacy
    review caught before implementation: an earlier design matched any
    occurrence of the payload right after a newline, with no check that it
    is actually followed by the row's own field separator -- a debug/error
    page that happens to echo the raw payload on its own line (with no
    trailing CSV cell) would have false-positive-confirmed. The real
    strategy requires an immediate trailing "," after the payload, so a
    sender that echoes the payload on its own line with nothing else after
    it must not be confirmed."""
    class BareEchoNoCsvRowSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, f"Received label: {value}\n(no CSV row follows)", headers={})
    assert CsvFormulaInjectionStrategy().confirm(_cand("csv-formula-injection"), BareEchoNoCsvRowSender()) is None


def test_csv_formula_injection_tries_every_owasp_trigger_character():
    """A neutralizer that only escapes a subset of the OWASP trigger
    characters (e.g. only "=") is still genuinely vulnerable via the
    others -- the strategy must not stop after the first (=) canary alone,
    per the adequacy review's own false-negative concern."""
    class OnlyEqualsNeutralizedSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            if value.startswith("="):
                return Probe(200, f"label,amount\n'{value},129.00\n", headers={})
            return Probe(200, f"label,amount\n{value},129.00\n", headers={})
    v = CsvFormulaInjectionStrategy().confirm(_cand("csv-formula-injection"), OnlyEqualsNeutralizedSender())
    assert v is not None and v.evidence["trigger"] != "="


# --- Go text/template SSTI (M4b, CC-FUZZ-0042) --------------------------------

def test_go_template_ssti_confirmed_when_len_evaluated():
    """A fake sender that genuinely evaluates `{{ len "..." }}` (mirroring
    real Go `text/template` behavior) is confirmed."""
    class GoTemplateSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            m = re.search(r'\{\{\s*len\s+"(A*)"\s*\}\}', value)
            if m:
                return Probe(200, str(len(m.group(1))), headers={})
            return Probe(200, value, headers={})
    v = GoTemplateSstiStrategy().confirm(_cand("ssti"), GoTemplateSender())
    assert v is not None and v.confirmed and v.mechanism == "go-template-len-marker"
    n1, n2 = v.evidence["lengths"]
    assert n1 != n2 and 100 <= n1 <= 999 and 100 <= n2 <= 999


def test_go_template_ssti_not_confirmed_on_reflection_without_eval():
    """Mirrors the real go_net_http vulnerable twin's own SstiStrategy false
    negative in reverse: a target that just echoes the literal payload back
    (never evaluates it) must not confirm."""
    class ReflectSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, f"<p>{value}</p>", headers={})
    assert GoTemplateSstiStrategy().confirm(_cand("ssti"), ReflectSender()) is None


def test_go_template_ssti_not_confirmed_when_response_is_static():
    """A target that always returns the same fixed page regardless of input
    (e.g. Go's secure `file_loaded_template_name` twin, which only ever does
    a fixed-map lookup) must not confirm even if that static page happens to
    contain some unrelated decimal digits."""
    class StaticSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, "unknown variable (build 500, uptime 342h)", headers={})
    assert GoTemplateSstiStrategy().confirm(_cand("ssti"), StaticSender()) is None


def test_go_template_ssti_not_confirmed_on_stale_cross_contaminated_response():
    """A target that always echoes back the FIRST probe's own result (a
    cached/stale-response bug, or one that doesn't actually vary per
    request) must not confirm: probe 2's response would contain N1 (a
    cross-contamination leak) instead of, or in addition to, its own N2."""
    calls = []

    class StaleSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            m = re.search(r'\{\{\s*len\s+"(A*)"\s*\}\}', value)
            n = len(m.group(1)) if m else 0
            calls.append(n)
            # Always answers with the FIRST call's own length, regardless of
            # what was actually sent this time -- a stale/cached response.
            return Probe(200, str(calls[0]), headers={})

    assert GoTemplateSstiStrategy().confirm(_cand("ssti"), StaleSender()) is None


def test_go_template_ssti_not_confirmed_on_single_probe_coincidental_digit_match():
    """The false-positive class this strategy's own docstring names
    explicitly: a normal, non-evaluating response that happens to already
    contain SOME decimal digits (an unrelated build/status number) must not
    confirm just because one of the two probes' random lengths happens not
    to appear -- both must independently match, and this response never
    contains either fresh random length at all."""
    class BoilerplateSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, "status 200, build 42", headers={})
    assert GoTemplateSstiStrategy().confirm(_cand("ssti"), BoilerplateSender()) is None


# --- path traversal / LFI (M7) ----------------------------------------------

def test_path_traversal_confirmed_on_passwd_marker():
    class FileSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            if "etc/passwd" in value or "etc%2fpasswd" in value.lower():
                return Probe(200, "root:x:0:0:root:/root:/bin/bash\n", headers={})
            return Probe(200, "home page", headers={})
    v = PathTraversalStrategy().confirm(_cand("file-inclusion"), FileSender())
    assert v is not None and v.confirmed and v.mechanism == "file-content-marker"


def test_path_traversal_not_confirmed_without_marker():
    class SafeSender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            return Probe(200, "no file here", headers={})
    assert PathTraversalStrategy().confirm(_cand("file-inclusion"), SafeSender()) is None


# --- command injection (differential timing) --------------------------------

class _SleepSender:
    def __init__(self, honor):
        self.honor = honor

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        m = re.search(r"sleep (\d+)", value)
        d = int(m.group(1)) if (m and self.honor) else 0
        return Probe(200, "ok", elapsed=d + 0.05, headers={})


def test_command_injection_confirmed_on_rising_delay():
    v = CommandInjectionStrategy().confirm(_cand("command-injection"), _SleepSender(honor=True))
    assert v is not None and v.confirmed and v.vuln_class == "command-injection"


def test_command_injection_not_confirmed_when_sleep_ignored():
    assert CommandInjectionStrategy().confirm(
        _cand("command-injection"), _SleepSender(honor=False)) is None


# --- category wiring ---------------------------------------------------------

def test_new_categories_map_to_oracle_classes():
    assert category_to_oracle_class("open-redirect") == "open_redirect"
    assert category_to_oracle_class("server-side-template-injection") == "ssti"
    assert category_to_oracle_class("file-inclusion") == "file-inclusion"
    assert category_to_oracle_class("command-injection") == "command-injection"
    assert category_to_oracle_class("unknown-thing") is None
