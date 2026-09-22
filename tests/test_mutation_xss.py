"""Phase 8 T8.2: context-typed XSS generation, filter-aware."""

import json
import re
from pathlib import Path

from fuzzlab.mutation.xss import (all_contexts, context_from_sink, xss_payloads)


def _php_to_py(pattern: str) -> str:
    """Convert a PHP ``/regex/flags`` pattern to a Python regex (inline flags)."""
    body = pattern[1:pattern.rindex("/")]
    flags = pattern[pattern.rindex("/") + 1:]
    return ("(?i)" + body) if "i" in flags else body


# The lab WAF's XSS signatures (shared ruleset) — the filter to avoid.
# `L-P3.3c-CUT`: moved from `puppy-fort-factory/config/waf-rules.json`.
_RULES = json.loads((Path(__file__).resolve().parents[1] /
                     "lab/waf-rules.json").read_text())
XSS_PATTERNS = [_php_to_py(r["pattern"]) for r in _RULES["rules"]
                if r["category"] == "xss"]


def test_context_mapping():
    assert context_from_sink("html-attribute") == "html-attribute"
    assert context_from_sink("js") == "js"
    assert context_from_sink("none") == "html"        # unclassified → html
    assert context_from_sink("bogus") == "html"
    assert context_from_sink(None) == "html"


def test_payloads_are_context_appropriate():
    html = xss_payloads("html")
    assert any("<svg onload=" in p for p in html)
    js = xss_payloads("js")
    assert any(p.endswith(";//") or p.startswith("'-") for p in js)  # JS string break-out
    urlattr = xss_payloads("url-attribute")
    assert all(p.lower().startswith("javascript:") for p in urlattr)
    attr = xss_payloads("html-attribute")
    assert any(p.startswith('">') or p.startswith("'>") or p.startswith('" ')
               for p in attr)


def test_filter_aware_drops_blocked_keeps_working():
    survivors = xss_payloads("html", blocked=XSS_PATTERNS)
    # nothing surviving may contain a blocked signature ...
    assert all("<script" not in p.lower() for p in survivors)
    assert not any(_has_blocked_event(p) for p in survivors)
    # ... but there is still at least one working candidate (e.g. onfocus/ontoggle)
    assert survivors and any("onfocus=" in p or "ontoggle=" in p or "onpageshow=" in p
                             for p in survivors)


def test_all_blocked_falls_back_to_full_list():
    # a pattern that blocks every candidate → return the full list to still try to evade
    everything = [r".+"]
    assert xss_payloads("html", blocked=everything) == xss_payloads("html")


def test_deterministic_and_marker():
    assert xss_payloads("html") == xss_payloads("html")
    assert any("pwn()" in p for p in xss_payloads("html", marker="pwn()"))


def test_all_contexts_have_templates():
    for ctx in all_contexts():
        assert xss_payloads(ctx)


def _has_blocked_event(p: str) -> bool:
    return any(re.search(pat, p) for pat in XSS_PATTERNS)
