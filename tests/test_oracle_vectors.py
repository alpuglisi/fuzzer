"""Tests for the additional deterministic oracle vectors (open-redirect, SSTI,
path traversal, command injection). Each confirms the true case and stays
fail-closed on a benign/secure one."""

import re

from fuzzlab.oracle import Candidate, category_to_oracle_class
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import (
    CommandInjectionStrategy,
    GoTemplateSstiStrategy,
    OpenRedirectStrategy,
    PathTraversalStrategy,
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


# --- Go text/template SSTI (M4b, CC-FUZZ-0038) --------------------------------

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
    assert category_to_oracle_class("open-redirect") == "open-redirect"
    assert category_to_oracle_class("server-side-template-injection") == "ssti"
    assert category_to_oracle_class("file-inclusion") == "file-inclusion"
    assert category_to_oracle_class("command-injection") == "command-injection"
    assert category_to_oracle_class("unknown-thing") is None
