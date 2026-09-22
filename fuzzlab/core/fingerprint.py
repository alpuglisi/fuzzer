"""Target fingerprinting: DBMS / framework / WAF / server (Phase 2 T2.5), and web
application/service technology fingerprinting (server, language, framework, CMS,
JS libraries, WAF/CDN, DBMS) via `identify_technologies()`.

Fingerprint-before-fuzz lets the scheduler and oracle scope payloads to the target
(e.g. MySQL SLEEP vs Postgres pg_sleep) instead of trying everything. `fingerprint()`
and `Fingerprint` are the original, narrow, single-value-per-category detector (pure
and accumulative: build a fingerprint over one or more responses) and are left exactly
as they were — every caller and `tests/test_fewer_requests.py`'s exact precedence
semantics (e.g. the MySQL error pattern matching before a literal "MariaDB" mention)
depend on that.

`identify_technologies()` is a separate, additive detector: it returns every matching
`Signal` (not just one per category) from a first-party signature table, each with a
category, an optional version, a confidence, and human-readable evidence — closer to
what a dedicated web-technology fingerprinting tool (Wappalyzer/WhatWeb-style) reports.
It is intentionally not a refactor of `fingerprint()` into a shared implementation:
unifying them risked subtly changing `fingerprint()`'s existing match-precedence
behavior for a DRY benefit not worth that regression risk. Passive only — every
signature matches against the one response already fetched by the caller; it sends no
additional requests (CC-FUZZ-0022 / CC-AUD-0016 note the deferred, explicitly
out-of-scope-for-now active marker-path probing that could improve CMS-detection
recall further).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# framework hints by cookie name
_COOKIE_FRAMEWORK = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "connect.sid": "Node/Express",
    "_rails_session": "Rails",
    "sessionid": "Django",           # with csrftoken; weak on its own
}

# WAF hints by response header name (lowercased)
_WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-amz-cf-id": "AWS CloudFront",
    "x-iinfo": "Imperva/Incapsula",
}

# DBMS hints from error text (fingerprinting, distinct from the oracle's confirm set)
_DBMS_ERRORS = [
    (re.compile(r"you have an error in your sql syntax|warning:\s*mysqli?_", re.I), "MySQL"),
    (re.compile(r"mariadb", re.I), "MariaDB"),
    (re.compile(r"postgresql|pg_query|syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"sqlite_error|sqlite3?::|unrecognized token", re.I), "SQLite"),
    (re.compile(r"microsoft sql server|unclosed quotation mark", re.I), "MSSQL"),
    (re.compile(r"ora-\d{5}|quoted string not properly terminated", re.I), "Oracle"),
]


@dataclass
class Fingerprint:
    server: str | None = None
    framework: str | None = None
    dbms: str | None = None
    waf: str | None = None

    def merge(self, other: "Fingerprint") -> "Fingerprint":
        """Fill any unknown field from ``other`` (first observation wins)."""
        return Fingerprint(
            server=self.server or other.server,
            framework=self.framework or other.framework,
            dbms=self.dbms or other.dbms,
            waf=self.waf or other.waf,
        )

    def as_dict(self) -> dict[str, str | None]:
        return {"server": self.server, "framework": self.framework,
                "dbms": self.dbms, "waf": self.waf}


def _cookie_names(headers_low: dict[str, str], cookies: dict[str, str] | None) -> set[str]:
    names = {c.lower() for c in (cookies or {})}
    setc = headers_low.get("set-cookie", "")
    for part in setc.split(","):
        name = part.split("=", 1)[0].strip().lower()
        if name:
            names.add(name)
    return names


def fingerprint(headers: dict[str, str], body: str = "",
                cookies: dict[str, str] | None = None) -> Fingerprint:
    low = {k.lower(): v for k, v in (headers or {}).items()}
    fp = Fingerprint()

    fp.server = low.get("server")

    powered = low.get("x-powered-by", "")
    if powered:
        fp.framework = powered
    else:
        for name in _cookie_names(low, cookies):
            if name in _COOKIE_FRAMEWORK:
                fp.framework = _COOKIE_FRAMEWORK[name]
                break

    for rx, dbms in _DBMS_ERRORS:
        if rx.search(body or ""):
            fp.dbms = dbms
            break

    for header, waf in _WAF_HEADERS.items():
        if header in low:
            fp.waf = waf
            break
    if fp.waf is None and "cloudflare" in (fp.server or "").lower():
        fp.waf = "Cloudflare"

    return fp


# --- web application/service technology fingerprinting (additive) -----------

@dataclass(frozen=True)
class Signal:
    """One matched technology signal, independent of any other match."""
    category: str          # server|language|framework|cms|js-library|waf-cdn|dbms
    name: str
    version: str | None
    confidence: float      # 0.0-1.0; see _Sig.confidence for the scale
    evidence: str          # short, human-readable: what matched
    source_url: str | None = None


@dataclass(frozen=True)
class _Sig:
    """One signature: how to recognize `name` from a single HTTP response."""
    category: str
    name: str
    kind: str               # "header" | "cookie" | "body"
    key: str | None         # header name (lowercased) for kind="header"; else None
    pattern: "re.Pattern[str]"
    confidence: float
    version_group: int | None = None   # regex group holding the version, if any


def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.I)


# Confidence scale (deterministic, not learned): 0.95 = an explicit version string or
# generator tag naming the technology; 0.85-0.9 = a technology-specific header, asset
# path, or well-known marker file/text; 0.6-0.75 = a plausible but not exclusive body
# pattern; 0.5-0.6 = a cookie name alone (several frameworks share generic cookie
# names, e.g. plain "sessionid", so this is the weakest tier).
_SIGNATURES: tuple[_Sig, ...] = (
    # --- server ---------------------------------------------------------
    _Sig("server", "Apache", "header", "server", _rx(r"apache(?:/([\d.]+))?"), 0.9, 1),
    _Sig("server", "nginx", "header", "server", _rx(r"nginx(?:/([\d.]+))?"), 0.9, 1),
    _Sig("server", "Microsoft-IIS", "header", "server", _rx(r"microsoft-iis(?:/([\d.]+))?"), 0.9, 1),
    _Sig("server", "LiteSpeed", "header", "server", _rx(r"litespeed"), 0.85, None),
    _Sig("server", "Caddy", "header", "server", _rx(r"caddy"), 0.85, None),

    # --- language / framework --------------------------------------------
    _Sig("language", "PHP", "header", "x-powered-by", _rx(r"php(?:/([\d.]+))?"), 0.9, 1),
    _Sig("language", "PHP", "cookie", "phpsessid", _rx(r".*"), 0.55, None),
    _Sig("framework", "ASP.NET", "header", "x-powered-by", _rx(r"asp\.net"), 0.9, None),
    _Sig("framework", "ASP.NET", "header", "x-aspnet-version", _rx(r"([\d.]+)"), 0.9, 1),
    _Sig("framework", "ASP.NET", "cookie", "asp.net_sessionid", _rx(r".*"), 0.55, None),
    _Sig("framework", "Express", "header", "x-powered-by", _rx(r"express"), 0.9, None),
    _Sig("framework", "Express", "cookie", "connect.sid", _rx(r".*"), 0.55, None),
    _Sig("framework", "Ruby on Rails", "cookie", "_rails_session", _rx(r".*"), 0.6, None),
    _Sig("framework", "Ruby on Rails", "header", "x-runtime", _rx(r".*"), 0.7, None),
    _Sig("framework", "Django", "body", None, _rx(r"csrfmiddlewaretoken"), 0.75, None),
    _Sig("framework", "Django", "cookie", "sessionid", _rx(r".*"), 0.5, None),
    _Sig("framework", "Laravel", "cookie", "laravel_session", _rx(r".*"), 0.7, None),
    _Sig("framework", "CodeIgniter", "cookie", "ci_session", _rx(r".*"), 0.65, None),
    _Sig("framework", "Flask", "cookie", "session", _rx(r"^eyj"), 0.55, None),  # signed itsdangerous cookie

    # --- CMS --------------------------------------------------------------
    _Sig("cms", "WordPress", "body", None,
         _rx(r'name="generator"\s+content="wordpress\s*([\d.]+)?'), 0.95, 1),
    _Sig("cms", "WordPress", "body", None, _rx(r"/wp-content/"), 0.85, None),
    _Sig("cms", "WordPress", "body", None, _rx(r"/wp-includes/"), 0.85, None),
    _Sig("cms", "Drupal", "header", "x-generator", _rx(r"drupal\s*([\d.]+)?"), 0.9, 1),
    _Sig("cms", "Drupal", "body", None,
         _rx(r'name="generator"\s+content="drupal\s*([\d.]+)?'), 0.95, 1),
    _Sig("cms", "Drupal", "body", None, _rx(r"/sites/default/files/"), 0.8, None),
    _Sig("cms", "Joomla!", "body", None,
         _rx(r'name="generator"\s+content="joomla!?\s*([\d.]+)?'), 0.95, 1),
    _Sig("cms", "Joomla!", "body", None, _rx(r"/media/system/js/core\.js"), 0.8, None),
    _Sig("cms", "Magento", "body", None, _rx(r"mage\.cookies|/skin/frontend/"), 0.8, None),
    _Sig("cms", "Shopify", "header", "x-shopify-stage", _rx(r".*"), 0.9, None),
    _Sig("cms", "Shopify", "body", None, _rx(r"cdn\.shopify\.com"), 0.8, None),
    _Sig("cms", "Wix", "header", "x-wix-request-id", _rx(r".*"), 0.9, None),
    _Sig("cms", "Wix", "body", None, _rx(r"static\.wixstatic\.com"), 0.8, None),
    _Sig("cms", "Squarespace", "body", None, _rx(r"static1\.squarespace\.com"), 0.8, None),
    _Sig("cms", "TYPO3", "body", None, _rx(r"/typo3conf/|/typo3temp/"), 0.8, None),
    _Sig("cms", "Ghost", "body", None, _rx(r'name="generator"\s+content="ghost\s*([\d.]+)?'), 0.95, 1),

    # --- JS libraries / front-end frameworks ------------------------------
    _Sig("js-library", "jQuery", "body", None, _rx(r"jquery[.-]([\d.]+)(?:\.min)?\.js"), 0.85, 1),
    _Sig("js-library", "jQuery", "body", None, _rx(r"jquery(?:\.min)?\.js"), 0.6, None),
    _Sig("js-library", "React", "body", None, _rx(r"data-reactroot"), 0.8, None),
    _Sig("js-library", "Vue.js", "body", None, _rx(r"data-v-[0-9a-f]{6,8}"), 0.75, None),
    _Sig("js-library", "Angular", "body", None, _rx(r'ng-version="([\d.]+)"'), 0.9, 1),
    _Sig("js-library", "Angular", "body", None, _rx(r"\bng-app\b"), 0.55, None),
    _Sig("js-library", "Bootstrap", "body", None,
         _rx(r"bootstrap(?:\.min)?\.(?:css|js)"), 0.65, None),
    _Sig("framework", "Next.js", "body", None, _rx(r"__next_data__"), 0.9, None),

    # --- WAF / CDN ----------------------------------------------------------
    _Sig("waf-cdn", "Cloudflare", "header", "cf-ray", _rx(r".*"), 0.9, None),
    _Sig("waf-cdn", "Cloudflare", "header", "server", _rx(r"cloudflare"), 0.85, None),
    _Sig("waf-cdn", "Sucuri", "header", "x-sucuri-id", _rx(r".*"), 0.9, None),
    _Sig("waf-cdn", "Akamai", "header", "x-akamai-transformed", _rx(r".*"), 0.9, None),
    _Sig("waf-cdn", "AWS CloudFront", "header", "x-amz-cf-id", _rx(r".*"), 0.85, None),
    _Sig("waf-cdn", "Imperva/Incapsula", "header", "x-iinfo", _rx(r".*"), 0.9, None),
    _Sig("waf-cdn", "Fastly", "header", "x-fastly-request-id", _rx(r".*"), 0.85, None),
    _Sig("waf-cdn", "ModSecurity", "body", None,
         _rx(r"mod_security|this error was generated by mod_security"), 0.9, None),

    # --- DBMS (error-text hints; same patterns as `fingerprint()`, listed so
    #     every matching class is reported rather than only the first) --------
    _Sig("dbms", "MySQL", "body", None,
         _rx(r"you have an error in your sql syntax|warning:\s*mysqli?_"), 0.85, None),
    _Sig("dbms", "MariaDB", "body", None, _rx(r"mariadb"), 0.85, None),
    _Sig("dbms", "PostgreSQL", "body", None,
         _rx(r"postgresql|pg_query|syntax error at or near"), 0.85, None),
    _Sig("dbms", "SQLite", "body", None,
         _rx(r"sqlite_error|sqlite3?::|unrecognized token"), 0.85, None),
    _Sig("dbms", "MSSQL", "body", None,
         _rx(r"microsoft sql server|unclosed quotation mark"), 0.85, None),
    _Sig("dbms", "Oracle", "body", None,
         _rx(r"ora-\d{5}|quoted string not properly terminated"), 0.85, None),
)


def identify_technologies(headers: dict[str, str], body: str = "",
                          cookies: dict[str, str] | None = None,
                          source_url: str | None = None) -> list[Signal]:
    """Every matching technology signal from one HTTP response (passive; no new
    requests — the caller supplies a response it already fetched).

    Unlike `fingerprint()`, this returns every match, not one value per category, so
    e.g. jQuery and React can both be reported for the same page, or two mutually-
    exclusive-looking DBMS hints can both surface as low-confidence leads for a human
    (or a later, more targeted probe) to disambiguate — deduplicated only when the
    same (category, name) matches more than once, keeping the highest-confidence
    (and, on a tie, the one carrying a version) match.
    """
    low = {k.lower(): v for k, v in (headers or {}).items()}
    body = body or ""
    cookie_names = _cookie_names(low, cookies)
    best: dict[tuple[str, str], Signal] = {}

    for sig in _SIGNATURES:
        if sig.kind == "header":
            value = low.get(sig.key or "")
            if value is None:
                continue
            m = sig.pattern.search(value)
            if not m:
                continue
            evidence = f"header {sig.key}: {value[:120]}"
        elif sig.kind == "cookie":
            if (sig.key or "") not in cookie_names:
                continue
            m = None
            evidence = f"cookie name: {sig.key}"
        else:                                                  # kind == "body"
            m = sig.pattern.search(body)
            if not m:
                continue
            evidence = f"body pattern matched: {sig.pattern.pattern[:80]}"

        version = None
        if sig.version_group is not None and m is not None:
            try:
                version = m.group(sig.version_group)
            except (IndexError, AttributeError):               # group absent/optional
                version = None

        signal = Signal(category=sig.category, name=sig.name, version=version,
                        confidence=sig.confidence, evidence=evidence,
                        source_url=source_url)
        key = (sig.category, sig.name)
        prev = best.get(key)
        if prev is None or signal.confidence > prev.confidence or \
                (signal.confidence == prev.confidence and version and not prev.version):
            best[key] = signal

    return list(best.values())
