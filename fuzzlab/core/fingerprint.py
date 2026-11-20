"""Target fingerprinting: DBMS / framework / WAF / server (Phase 2 T2.5).

Fingerprint-before-fuzz lets the scheduler and oracle scope payloads to the target
(e.g. MySQL SLEEP vs Postgres pg_sleep) instead of trying everything. Pure and
accumulative: build a fingerprint over one or more responses.
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

#: The languages `server_language` can name (the ``server_language_in`` predicate's
#: closed set, FR-AUD-706 / FR-CORE-671).
LANGUAGES = ("javascript", "php", "java", "python", "ruby", "dotnet")

#: What names a server-side language in an answer's own headers, each cited (PA-0660):
#: an ``X-Powered-By`` product token (lower-cased, the product name before any ``/``
#: version) and a session cookie's default name.
#:  - ``Express``: Express sends ``X-Powered-By: Express`` by default (expressjs.com,
#:    "Production Best Practices: Security", `app.disable('x-powered-by')`; OWASP WSTG
#:    v4.2 WSTG-INFO-08 lists ``X-Powered-By`` as a framework fingerprint).
#:  - ``Next.js``: ``poweredByHeader`` (nextjs.org docs, next.config.js) defaults on.
#:  - ``connect.sid``: express-session's default cookie name (the express-session
#:    README, option ``name``); ``koa.sess``: koa-session's default ``key`` (its README);
#:    ``sails.sid``: Sails' default session cookie (sailsjs.com docs, config.session).
#:  - ``PHP/x.y``: PHP's ``expose_php`` header (php.net, ini.core ``expose_php``);
#:    ``PHPSESSID``: PHP's default ``session.name`` (php.net, session configuration).
#:  - ``JSESSIONID``: the Servlet specification's default session cookie name (Jakarta
#:    Servlet 6.0 §7.1.1); ``ASP.NET`` / ``ASP.NET_SessionId``: IIS/ASP.NET defaults
#:    (Microsoft Learn, "Remove unwanted HTTP response headers"; `sessionState`).
_POWERED_BY_LANGUAGE = {
    "express": "javascript", "next.js": "javascript", "nuxt": "javascript",
    "php": "php", "asp.net": "dotnet", "servlet": "java", "jsp": "java",
    "phusion passenger": "ruby", "django": "python",
}
_COOKIE_LANGUAGE = {
    "connect.sid": "javascript", "koa.sess": "javascript", "sails.sid": "javascript",
    "phpsessid": "php", "jsessionid": "java", "asp.net_sessionid": "dotnet",
    "_rails_session": "ruby",
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


def server_language(headers: dict[str, str] | None,
                    cookies: dict[str, str] | None = None) -> str | None:
    """The server-side language an answer's own headers name, one of `LANGUAGES`, or
    ``None`` when they name none or name two (FR-CORE-671). Read from the
    ``X-Powered-By`` product tokens and the session cookie names set or held
    (`_POWERED_BY_LANGUAGE`, `_COOKIE_LANGUAGE`, each cited); never from a URL, a path
    or a page's text. Total: never raises."""
    try:
        low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        found: set[str] = set()
        for product in low.get("x-powered-by", "").split(","):
            token = product.strip().split("/", 1)[0].strip().lower()
            if token in _POWERED_BY_LANGUAGE:
                found.add(_POWERED_BY_LANGUAGE[token])
        for name in _cookie_names(low, cookies):
            if name in _COOKIE_LANGUAGE:
                found.add(_COOKIE_LANGUAGE[name])
        return found.pop() if len(found) == 1 else None
    except Exception:                         # total (PA-0096)
        return None
